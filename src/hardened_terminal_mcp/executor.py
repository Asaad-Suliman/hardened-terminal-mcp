"""Sandboxed command executor.

Phase 2: runs a *policy-approved* command safely. Defense in depth — this module
re-checks the policy itself (never trusts the caller), executes only an ``argv``
list with ``shell=False``, enforces a wall-clock timeout, caps output, scrubs the
environment so parent secrets can't leak into the child, and jails execution to a
required, validated working directory.
"""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from hardened_terminal_mcp.config import Policy
from hardened_terminal_mcp.policy import explain

__all__ = ["ExecutionResult", "run"]

# Only these env vars reach the child. Everything else in the parent environment
# (API keys, tokens, ambient secrets) is dropped so a subprocess can't exfiltrate
# them. PATH has a safe fallback so command resolution still works if the parent
# somehow lacks one.
_ENV_ALLOWLIST: tuple[str, ...] = ("PATH", "HOME", "LANG")
_PATH_FALLBACK = "/usr/bin:/bin"

_TRUNCATION_MARKER = b"...[truncated]"


@dataclass(frozen=True)
class ExecutionResult:
    """Outcome of an execution attempt. Immutable."""

    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool
    truncated: bool
    duration_seconds: float


def _refused(reason: str) -> ExecutionResult:
    """Build a result for a command that was never executed."""
    return ExecutionResult(
        stdout="",
        stderr=reason,
        exit_code=-1,
        timed_out=False,
        truncated=False,
        duration_seconds=0.0,
    )


def _cap(data: bytes, limit: int) -> tuple[bytes, bool]:
    """Truncate ``data`` to ``limit`` bytes, appending a marker if it was cut."""
    if len(data) <= limit:
        return data, False
    return data[:limit] + _TRUNCATION_MARKER, True


def _child_env() -> dict[str, str]:
    """Minimal environment for the child: allowlisted vars only."""
    env = {k: os.environ[k] for k in _ENV_ALLOWLIST if k in os.environ}
    env.setdefault("PATH", _PATH_FALLBACK)
    return env


def run(
    raw: str,
    policy: Policy,
    *,
    cwd: str | Path,
    timeout: float = 30,
    max_output_bytes: int = 65536,
) -> ExecutionResult:
    """Evaluate ``raw`` against ``policy`` and, if allowed, execute it safely.

    Belt-and-suspenders: the policy is re-checked here even though the caller may
    already have done so — this module never trusts its input. A denied command,
    or a missing/invalid ``cwd``, returns a refused result and runs nothing.
    """
    verdict = explain(raw, policy)
    if verdict.decision != "allow":
        return _refused(verdict.reason)

    cwd_path = Path(cwd)
    if not cwd_path.is_dir():
        return _refused(f"cwd is not a directory: {cwd_path}")

    argv = verdict.parsed_command
    # explain() populates parsed_command for any allowed command; guard anyway so
    # a future policy change can never hand subprocess a None.
    if not argv:
        return _refused("internal error: allowed verdict had no parsed command")

    start = time.monotonic()
    timed_out = False
    try:
        # shell=False (default): argv is executed directly, no shell parsing.
        proc = subprocess.run(
            argv,
            shell=False,
            cwd=cwd_path,
            env=_child_env(),
            capture_output=True,
            timeout=timeout,
        )
        stdout_raw, stderr_raw, exit_code = proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired as exc:
        # subprocess.run has already killed the child. Surface whatever partial
        # output was captured before the kill.
        timed_out = True
        stdout_raw = exc.stdout or b""
        stderr_raw = exc.stderr or b""
        exit_code = -1
    except (FileNotFoundError, PermissionError, OSError) as exc:
        return _refused(f"failed to execute command: {exc}")

    duration = time.monotonic() - start

    stdout_bytes, stdout_cut = _cap(stdout_raw, max_output_bytes)
    stderr_bytes, stderr_cut = _cap(stderr_raw, max_output_bytes)

    return ExecutionResult(
        stdout=stdout_bytes.decode("utf-8", errors="replace"),
        stderr=stderr_bytes.decode("utf-8", errors="replace"),
        exit_code=exit_code,
        timed_out=timed_out,
        truncated=stdout_cut or stderr_cut,
        duration_seconds=duration,
    )
