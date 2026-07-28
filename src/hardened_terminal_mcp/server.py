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
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel

from hardened_terminal_mcp import executor
from hardened_terminal_mcp.audit import AuditError, AuditLogger, AuditRecord
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
    | AUDIT_UNAVAILABLE| Audit record could not be written under fail-closed; the |
    |                  | command was NOT executed (no unlogged execution).        |
    | INTERNAL_ERROR   | Unexpected server-side exception. Generic message only.  |
    """

    OK = "OK"
    POLICY_DENIED = "POLICY_DENIED"
    PARSE_ERROR = "PARSE_ERROR"
    TIMEOUT = "TIMEOUT"
    OUTPUT_TRUNCATED = "OUTPUT_TRUNCATED"
    CWD_ESCAPE = "CWD_ESCAPE"
    EXECUTOR_ERROR = "EXECUTOR_ERROR"
    AUDIT_UNAVAILABLE = "AUDIT_UNAVAILABLE"
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
_AUDIT: AuditLogger | None = None
_AUDIT_FAIL_MODE: str = "closed"


class _AuditUnavailable(Exception):
    """Internal: raised when a required audit write failed under fail-closed."""


def configure(
    policy: Policy,
    jail_root: str | Path,
    *,
    audit_logger: AuditLogger | None = None,
) -> None:
    """Set the active policy, jail root, and audit logger.

    Jail root is resolved to an absolute, symlink-free path so cwd checks compare
    like against like. The audit logger defaults to one built from
    ``policy.audit_log``; tests may inject their own. The fail mode always comes
    from ``policy.audit_fail_mode``.
    """
    global _POLICY, _JAIL_ROOT, _AUDIT, _AUDIT_FAIL_MODE
    _POLICY = policy
    _JAIL_ROOT = Path(jail_root).resolve()
    _AUDIT = audit_logger if audit_logger is not None else AuditLogger(policy.audit_log)
    _AUDIT_FAIL_MODE = policy.audit_fail_mode


def _require_config() -> tuple[Policy, Path]:
    """Return the active policy and jail root, or fail if not configured."""
    if _POLICY is None or _JAIL_ROOT is None:
        raise RuntimeError("server not configured: call configure() or main() first")
    return _POLICY, _JAIL_ROOT


def _new_record(
    tool: str,
    command: str,
    verdict: Verdict,
    code: ResultCode,
    *,
    cwd: str | None = None,
    exit_code: int | None = None,
    duration_ms: int = 0,
    stdout_bytes: int = 0,
    stderr_bytes: int = 0,
    event_id: str | None = None,
) -> AuditRecord:
    """Build one audit record. Byte counts only — never stdout/stderr content."""
    return AuditRecord(
        ts=datetime.now(timezone.utc).isoformat(),
        event_id=event_id or str(uuid.uuid4()),
        tool=tool,
        command_raw=command,
        argv=verdict.parsed_command,
        cwd=cwd,
        verdict=verdict.decision,
        rule_fired=verdict.rule_fired,
        code=code.value,
        exit_code=exit_code,
        duration_ms=duration_ms,
        stdout_bytes=stdout_bytes,
        stderr_bytes=stderr_bytes,
    )


def _audit(record: AuditRecord) -> None:
    """Write one record honoring the fail mode.

    fail-closed: a write failure raises _AuditUnavailable so the caller can refuse
    to execute. fail-open: it warns on STDERR (never stdout — stdio carries
    JSON-RPC) and returns, letting execution proceed.
    """
    if _AUDIT is None:
        raise _AuditUnavailable("audit logger not configured")
    try:
        _AUDIT.write(record)
    except AuditError as exc:
        if _AUDIT_FAIL_MODE == "open":
            print(f"warning: audit unavailable, proceeding (fail-open): {exc}",
                  file=sys.stderr)
            return
        raise _AuditUnavailable(str(exc)) from exc


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


def _serve(tool: str, command: str, cwd: str | None, *, execute: bool) -> CommandResult:
    """Single audit write point for both tools.

    Every path — denial, parse error, cwd escape, execution, dry run — writes an
    audit record here, so auditing can't be forgotten when a tool is added later.
    On the executing path two records share one event_id: an ATTEMPT record
    written BEFORE the executor runs (the fail-closed gate against unlogged
    execution) and an OUTCOME record written after. All other paths write one.

    When ``execute`` is False (explain_command) the executor branch is
    unreachable — the dry run cannot run a command.
    """
    policy, jail_root = _require_config()
    verdict = explain(command, policy)

    # Non-executing: a denial, a parse error, or a dry run. One record, no exec.
    if verdict.decision != "allow" or not execute:
        if verdict.decision == "allow":
            code, ok = ResultCode.OK, True
        else:
            code, ok = _denial_code(verdict), False
        _audit(_new_record(tool, command, verdict, code, cwd=cwd))
        return CommandResult(ok=ok, code=code, exit_code=None,
                             policy_reason=verdict.reason)

    resolved = _resolve_cwd(cwd, jail_root)
    if resolved is None:
        _audit(_new_record(tool, command, verdict, ResultCode.CWD_ESCAPE, cwd=cwd))
        return CommandResult(ok=False, code=ResultCode.CWD_ESCAPE, exit_code=None,
                             policy_reason=f"cwd escapes jail root: {cwd!r}")

    event_id = str(uuid.uuid4())
    # ATTEMPT record before execution: the fail-closed gate. If this write fails
    # under fail-closed, _audit raises and the executor is never reached.
    _audit(_new_record(tool, command, verdict, ResultCode.OK, cwd=cwd,
                       event_id=event_id))

    result = _map_execution(executor.run(command, policy, cwd=resolved), verdict.reason)

    # OUTCOME record after execution (same event_id). Byte counts only.
    _audit(_new_record(tool, command, verdict, result.code, cwd=cwd,
                       exit_code=result.exit_code, duration_ms=result.duration_ms,
                       stdout_bytes=len(result.stdout.encode("utf-8")),
                       stderr_bytes=len(result.stderr.encode("utf-8")),
                       event_id=event_id))
    return result


def _finish(tool: str, command: str, cwd: str | None, *, execute: bool) -> CommandResult:
    """Wrap _serve with the error taxonomy: audit failure -> AUDIT_UNAVAILABLE,
    any other exception -> INTERNAL_ERROR. No traceback ever reaches the client."""
    try:
        return _serve(tool, command, cwd, execute=execute)
    except _AuditUnavailable as exc:
        return CommandResult(ok=False, code=ResultCode.AUDIT_UNAVAILABLE, exit_code=None,
                             policy_reason=f"audit log unavailable: {exc}")
    except Exception:
        return CommandResult(ok=False, code=ResultCode.INTERNAL_ERROR,
                             stderr="internal error")


@mcp.tool()
def run_command(command: str, cwd: str | None = None) -> CommandResult:
    """Evaluate ``command`` against policy and, if allowed, run it sandboxed.

    Denied commands are never executed. ``cwd`` (if given) must resolve inside
    the jail root; any traversal/symlink/absolute escape returns CWD_ESCAPE.
    Every invocation is audited; under fail-closed an unwritable audit log
    returns AUDIT_UNAVAILABLE without executing.
    """
    return _finish("run_command", command, cwd, execute=True)


@mcp.tool()
def explain_command(command: str) -> CommandResult:
    """Dry run: return the policy verdict without executing anything.

    stdout/stderr are always empty and exit_code is always None. It routes
    through _serve with execute=False, so the executor branch is unreachable —
    the dry run cannot run a command (see test_explain_command_cannot_execute).
    """
    return _finish("explain_command", command, None, execute=False)


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
