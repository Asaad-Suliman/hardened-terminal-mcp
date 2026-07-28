"""MCP server: exposes the policy engine + sandboxed executor over stdio.

Phase 3 wires Phase 1 (``policy.explain``) and Phase 2 (``executor.run``) behind
two FastMCP tools. It does not redesign either. Every tool returns a uniform
:class:`CommandResult` envelope — errors are *data*, never exceptions: no Python
traceback ever reaches the MCP client.

Audit logging and secret redaction are intentionally out of scope here
(Phases 4 and 5).

Startup config (env vars, both optional):
- ``HTMCP_POLICY_FILE`` — path to policy.toml (default: ``policy.toml``).
- ``HTMCP_JAIL_ROOT``   — directory commands are jailed to (default: process cwd).
"""

from __future__ import annotations

import os
import sys
from enum import Enum
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel

from hardened_terminal_mcp import executor
from hardened_terminal_mcp.config import Policy, PolicyConfigError, load_policy
from hardened_terminal_mcp.policy import Verdict, explain

__all__ = ["ResultCode", "CommandResult", "run_command", "explain_command", "main"]


class ResultCode(str, Enum):
    """Outcome taxonomy. Each value maps to exactly one condition.

    | Code             | Condition                                                |
    |------------------|----------------------------------------------------------|
    | OK               | Command executed and returned (exit_code carries result).|
    | POLICY_DENIED    | Policy denied it (denylist, deny-by-default, arg rule,   |
    |                  | shell metacharacter, or empty command). Not executed.    |
    | PARSE_ERROR      | shlex could not parse the command into argv.             |
    | TIMEOUT          | Wall-clock timeout; the process was killed.              |
    | OUTPUT_TRUNCATED | Executed, but stdout/stderr hit the output cap.          |
    | CWD_ESCAPE       | Requested cwd escaped the jail root (traversal, symlink, |
    |                  | or absolute path outside the root). Not executed.        |
    | EXECUTOR_ERROR   | Executor could not run an allowed command (e.g. not      |
    |                  | found, permission denied, cwd vanished).                 |
    | INTERNAL_ERROR   | Unexpected server-side exception. Generic message only.  |
    """

    OK = "OK"
    POLICY_DENIED = "POLICY_DENIED"
    PARSE_ERROR = "PARSE_ERROR"
    TIMEOUT = "TIMEOUT"
    OUTPUT_TRUNCATED = "OUTPUT_TRUNCATED"
    CWD_ESCAPE = "CWD_ESCAPE"
    EXECUTOR_ERROR = "EXECUTOR_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class CommandResult(BaseModel):
    """Uniform envelope returned by both tools."""

    ok: bool
    code: ResultCode
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    duration_ms: int = 0
    policy_reason: str | None = None


mcp = FastMCP("hardened-terminal-mcp")

# Configured once at startup by main() (or by tests via configure()).
_POLICY: Policy | None = None
_JAIL_ROOT: Path | None = None


def configure(policy: Policy, jail_root: str | Path) -> None:
    """Set the active policy and jail root. Jail root is resolved to an absolute,
    symlink-free path so cwd checks compare like against like."""
    global _POLICY, _JAIL_ROOT
    _POLICY = policy
    _JAIL_ROOT = Path(jail_root).resolve()


def _require_config() -> tuple[Policy, Path]:
    """Return the active policy and jail root, or fail if not configured."""
    if _POLICY is None or _JAIL_ROOT is None:
        raise RuntimeError("server not configured: call configure() or main() first")
    return _POLICY, _JAIL_ROOT


def _denial_code(verdict: Verdict) -> ResultCode:
    """Map a denying verdict to its ResultCode. Only a shlex parse failure is a
    PARSE_ERROR; every other denial (metacharacter, empty, list, arg rule) is a
    policy decision."""
    if verdict.rule_fired == "parse-error":
        return ResultCode.PARSE_ERROR
    return ResultCode.POLICY_DENIED


def _resolve_cwd(cwd: str | None, jail_root: Path) -> Path | None:
    """Resolve ``cwd`` to an absolute path confined to ``jail_root``.

    Returns the resolved path, or None if it escapes the jail. ``resolve()``
    normalizes ``..`` and follows symlinks, so traversal, symlink, and
    absolute-path escapes all collapse to a simple containment check.
    """
    if cwd is None:
        return jail_root
    candidate = Path(cwd)
    base = candidate if candidate.is_absolute() else jail_root / candidate
    resolved = base.resolve()
    if resolved == jail_root or resolved.is_relative_to(jail_root):
        return resolved
    return None


def _map_execution(result: executor.ExecutionResult, reason: str) -> CommandResult:
    """Map a Phase 2 ExecutionResult onto the CommandResult envelope."""
    duration_ms = int(result.duration_seconds * 1000)
    if result.timed_out:
        return CommandResult(
            ok=False, code=ResultCode.TIMEOUT, stdout=result.stdout,
            stderr=result.stderr, exit_code=None, duration_ms=duration_ms,
            policy_reason=reason,
        )
    # Executor sentinel: -1 without a timeout means it could not run the command
    # (not found, permission denied, cwd vanished between check and exec).
    if result.exit_code == -1:
        return CommandResult(
            ok=False, code=ResultCode.EXECUTOR_ERROR, stdout=result.stdout,
            stderr=result.stderr, exit_code=None, duration_ms=duration_ms,
            policy_reason=reason,
        )
    code = ResultCode.OUTPUT_TRUNCATED if result.truncated else ResultCode.OK
    return CommandResult(
        ok=True, code=code, stdout=result.stdout, stderr=result.stderr,
        exit_code=result.exit_code, duration_ms=duration_ms, policy_reason=reason,
    )


@mcp.tool()
def run_command(command: str, cwd: str | None = None) -> CommandResult:
    """Evaluate ``command`` against policy and, if allowed, run it sandboxed.

    Denied commands are never executed. ``cwd`` (if given) must resolve inside
    the jail root; any traversal/symlink/absolute escape returns CWD_ESCAPE.
    Any unexpected error becomes INTERNAL_ERROR with a generic message.
    """
    try:
        policy, jail_root = _require_config()
        verdict = explain(command, policy)
        if verdict.decision != "allow":
            return CommandResult(
                ok=False, code=_denial_code(verdict), exit_code=None,
                policy_reason=verdict.reason,
            )

        resolved = _resolve_cwd(cwd, jail_root)
        if resolved is None:
            return CommandResult(
                ok=False, code=ResultCode.CWD_ESCAPE, exit_code=None,
                policy_reason=f"cwd escapes jail root: {cwd!r}",
            )

        result = executor.run(command, policy, cwd=resolved)
        return _map_execution(result, verdict.reason)
    except Exception:
        return CommandResult(
            ok=False, code=ResultCode.INTERNAL_ERROR, stderr="internal error",
        )


def main() -> None:
    """Console entry point: load config once, fail loudly, then serve over stdio."""
    policy_path = os.environ.get("HTMCP_POLICY_FILE", "policy.toml")
    jail_root = Path(os.environ.get("HTMCP_JAIL_ROOT", os.getcwd()))

    try:
        policy = load_policy(policy_path)
    except PolicyConfigError as exc:
        print(f"fatal: could not load policy: {exc}", file=sys.stderr)
        raise SystemExit(1)

    if not jail_root.is_dir():
        print(f"fatal: jail root is not a directory: {jail_root}", file=sys.stderr)
        raise SystemExit(1)

    configure(policy, jail_root)
    mcp.run()
