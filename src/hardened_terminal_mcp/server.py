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

from hardened_terminal_mcp.config import Policy, PolicyConfigError, load_policy

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
