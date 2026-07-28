"""Server (MCP wiring) tests. tmp_path isolated: a real subprocess may run, but
only allowlisted commands, jailed to a temp root. Executor-internal outcomes
(timeout, truncation, crash) are injected by patching executor.run so the tests
exercise the server's *mapping*, not the executor internals (Phase 2 covers those).
"""

import textwrap
from pathlib import Path
from unittest.mock import Mock

import pytest

from hardened_terminal_mcp import server
from hardened_terminal_mcp.audit import AuditLogger
from hardened_terminal_mcp.config import load_policy
from hardened_terminal_mcp.executor import ExecutionResult
from hardened_terminal_mcp.server import CommandResult, ResultCode

# "ghost_cmd_zzz" is allowlisted but not installed → real FileNotFoundError path
# for EXECUTOR_ERROR without patching.
_POLICY_TOML = textwrap.dedent(
    """
    [allowlist]
    commands = ["echo", "ls", "cat", "ghost_cmd_zzz"]

    [denylist]
    commands = ["rm"]

    [[rules]]
    command = "echo"
    deny_args = ["--boom"]
    reason = "boom arg is denied"
    """
)


@pytest.fixture
def jail(tmp_path):
    """Configure the server with a fresh policy and a tmp jail root; return root."""
    policy_file = tmp_path / "policy.toml"
    policy_file.write_text(_POLICY_TOML)
    server.configure(
        load_policy(policy_file), tmp_path,
        audit_logger=AuditLogger(tmp_path / "audit.jsonl"),
    )
    return tmp_path


def _fake_result(**kw) -> ExecutionResult:
    base = dict(
        stdout="", stderr="", exit_code=0,
        timed_out=False, truncated=False, duration_seconds=0.01,
    )
    base.update(kw)
    return ExecutionResult(**base)


# --- one test per ResultCode ---------------------------------------------

def test_ok(jail):
    r = server.run_command("echo hi")
    assert (r.ok, r.code, r.exit_code) == (True, ResultCode.OK, 0)
    assert "hi" in r.stdout


def test_policy_denied(jail):
    r = server.run_command("rm file")
    assert (r.ok, r.code) == (False, ResultCode.POLICY_DENIED)
    assert r.exit_code is None
    assert "denylist" in r.policy_reason


def test_parse_error(jail):
    r = server.run_command('echo "unterminated')  # unbalanced quote
    assert (r.ok, r.code) == (False, ResultCode.PARSE_ERROR)
    assert r.exit_code is None


def test_timeout(jail, monkeypatch):
    monkeypatch.setattr(server.executor, "run",
                        lambda *a, **k: _fake_result(timed_out=True, exit_code=-1))
    r = server.run_command("echo hi")
    assert (r.ok, r.code, r.exit_code) == (False, ResultCode.TIMEOUT, None)


def test_output_truncated(jail, monkeypatch):
    monkeypatch.setattr(server.executor, "run",
                        lambda *a, **k: _fake_result(stdout="x...[truncated]", truncated=True))
    r = server.run_command("echo hi")
    assert (r.ok, r.code, r.exit_code) == (True, ResultCode.OUTPUT_TRUNCATED, 0)


def test_cwd_escape(jail):
    r = server.run_command("echo hi", cwd="..")
    assert (r.ok, r.code) == (False, ResultCode.CWD_ESCAPE)
    assert r.exit_code is None


def test_executor_error(jail):
    r = server.run_command("ghost_cmd_zzz")  # allowlisted but not installed
    assert (r.ok, r.code, r.exit_code) == (False, ResultCode.EXECUTOR_ERROR, None)


def test_internal_error(jail, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("boom /secret/path leaked")
    monkeypatch.setattr(server.executor, "run", boom)
    r = server.run_command("echo hi")
    assert (r.ok, r.code) == (False, ResultCode.INTERNAL_ERROR)
    # Generic message only: no exception text, no paths.
    assert r.stderr == "internal error"
    assert "boom" not in r.stderr and "/secret" not in r.stderr


# --- cwd escape attempts (traversal, absolute, symlink) -------------------

def test_cwd_absolute_escape(jail):
    r = server.run_command("echo hi", cwd="/etc")
    assert r.code == ResultCode.CWD_ESCAPE


def test_cwd_symlink_escape(jail):
    link = jail / "escape"
    link.symlink_to("/etc")
    r = server.run_command("echo hi", cwd="escape")
    assert r.code == ResultCode.CWD_ESCAPE


def test_cwd_none_uses_jail_root(jail):
    r = server.run_command("echo hi")  # cwd omitted → runs in jail root
    assert r.code == ResultCode.OK


def test_cwd_within_jail_allowed(jail):
    (jail / "sub").mkdir()
    r = server.run_command("echo hi", cwd="sub")
    assert r.code == ResultCode.OK


# --- explain_command ------------------------------------------------------

def test_explain_allow(jail):
    r = server.explain_command("echo hi")
    assert (r.ok, r.code, r.exit_code) == (True, ResultCode.OK, None)
    assert r.stdout == "" and r.stderr == ""


def test_explain_deny(jail):
    r = server.explain_command("rm file")
    assert (r.ok, r.code) == (False, ResultCode.POLICY_DENIED)
    assert r.stdout == "" and r.stderr == ""


def test_explain_command_cannot_execute(jail, monkeypatch):
    """explain_command must never reach the executor, for any input."""
    fake_run = Mock()
    monkeypatch.setattr(server.executor, "run", fake_run)
    for cmd in ["echo hi", "rm file", 'echo "bad', "ghost_cmd_zzz"]:
        server.explain_command(cmd)
    assert fake_run.call_count == 0


# --- envelope shape stability --------------------------------------------

def test_envelope_shape_stable(jail):
    expected = {
        "ok", "code", "stdout", "stderr", "exit_code", "duration_ms", "policy_reason",
    }
    for r in (server.run_command("echo hi"), server.explain_command("rm file")):
        assert isinstance(r, CommandResult)
        assert set(r.model_dump().keys()) == expected
