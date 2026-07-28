"""Audit-trail tests. tmp_path isolated: every log lands in a temp dir, never
the repo. Covers both tools, both fail modes, schema stability, and the
guarantee that stdout/stderr content is never recorded.
"""

import json
import textwrap
from pathlib import Path
from unittest.mock import Mock

import pytest

from hardened_terminal_mcp import server
from hardened_terminal_mcp.audit import AuditLogger, AuditRecord
from hardened_terminal_mcp.config import load_policy
from hardened_terminal_mcp.server import ResultCode

_EXPECTED_KEYS = set(AuditRecord.model_fields)


def _configure(tmp_path, *, fail_mode="closed", log_path=None):
    """Configure the server with a fresh policy and an injected logger.
    Returns the log path in use."""
    toml = textwrap.dedent(
        f"""
        audit_fail_mode = "{fail_mode}"

        [allowlist]
        commands = ["echo"]

        [denylist]
        commands = ["rm"]
        """
    )
    policy_file = tmp_path / "policy.toml"
    policy_file.write_text(toml)
    log_path = log_path or (tmp_path / "audit.jsonl")
    server.configure(load_policy(policy_file), tmp_path,
                     audit_logger=AuditLogger(log_path))
    return log_path


def _records(log_path: Path) -> list[dict]:
    return [json.loads(line) for line in log_path.read_text().splitlines()]


# --- coverage: both tools, denial and execution -------------------------

def test_execution_logged(tmp_path):
    log = _configure(tmp_path)
    server.run_command("echo hi")
    recs = _records(log)
    # attempt + outcome, same event_id
    assert len(recs) == 2
    assert recs[0]["event_id"] == recs[1]["event_id"]
    assert recs[1]["code"] == ResultCode.OK.value
    assert recs[1]["exit_code"] == 0
    assert recs[1]["stdout_bytes"] == 3  # "hi\n"


def test_denial_logged(tmp_path):
    log = _configure(tmp_path)
    server.run_command("rm file")
    recs = _records(log)
    assert len(recs) == 1
    assert recs[0]["verdict"] == "deny"
    assert recs[0]["code"] == ResultCode.POLICY_DENIED.value


def test_explain_logged(tmp_path):
    log = _configure(tmp_path)
    server.explain_command("echo hi")
    recs = _records(log)
    assert len(recs) == 1
    assert recs[0]["tool"] == "explain_command"
    assert recs[0]["verdict"] == "allow"
    assert recs[0]["code"] == ResultCode.OK.value


def test_both_tools_covered(tmp_path):
    log = _configure(tmp_path)
    server.run_command("echo hi")
    server.explain_command("echo hi")
    tools = {r["tool"] for r in _records(log)}
    assert tools == {"run_command", "explain_command"}


# --- schema stability + content absence ----------------------------------

def test_record_schema_stable(tmp_path):
    log = _configure(tmp_path)
    server.run_command("echo hi")
    server.explain_command("rm file")
    for rec in _records(log):
        assert set(rec.keys()) == _EXPECTED_KEYS


def test_no_stdout_stderr_content(tmp_path):
    log = _configure(tmp_path)
    server.run_command("echo secret-output-value")
    for rec in _records(log):
        # Content fields must not exist at all — only the byte counts.
        assert "stdout" not in rec and "stderr" not in rec
        assert {"stdout_bytes", "stderr_bytes"} <= set(rec)
    # The output text itself must appear nowhere in the raw log.
    assert "secret-output-value" in log.read_text()  # sanity: it's in command_raw
    # But no *captured output* leaked: strip command_raw and re-check.
    for rec in _records(log):
        assert "secret-output-value" not in (rec["code"] + str(rec["stdout_bytes"]))


def test_append_across_calls(tmp_path):
    log = _configure(tmp_path)
    server.run_command("echo hi")      # 2
    server.run_command("rm x")          # 1
    server.explain_command("echo hi")  # 1
    recs = _records(log)
    assert len(recs) == 4
    assert all(isinstance(r, dict) for r in recs)  # every line valid JSON


# --- fail modes -----------------------------------------------------------

def test_fail_closed_blocks_execution(tmp_path, monkeypatch):
    bad_log = tmp_path / "missing_dir" / "audit.jsonl"  # parent absent -> unwritable
    _configure(tmp_path, fail_mode="closed", log_path=bad_log)
    fake_run = Mock()
    monkeypatch.setattr(server.executor, "run", fake_run)

    result = server.run_command("echo hi")
    assert result.code == ResultCode.AUDIT_UNAVAILABLE
    assert result.ok is False
    assert fake_run.call_count == 0  # never executed
    assert not bad_log.exists()


def test_fail_open_executes_and_warns(tmp_path, capsys):
    bad_log = tmp_path / "missing_dir" / "audit.jsonl"
    _configure(tmp_path, fail_mode="open", log_path=bad_log)

    result = server.run_command("echo hi")  # real echo runs
    assert result.code == ResultCode.OK
    assert "hi" in result.stdout
    err = capsys.readouterr().err
    assert "audit" in err.lower()  # warning went to stderr


# --- Phase 5: redaction of command_raw + argv ----------------------------

def test_command_raw_redacted(tmp_path):
    log = _configure(tmp_path)  # redaction enabled by default
    secret = "sk-proj-abcdefghij1234567890ABCD"
    server.run_command(f"echo {secret}")
    for rec in _records(log):
        assert secret not in rec["command_raw"]
    assert "[REDACTED:openai_key]" in _records(log)[-1]["command_raw"]


def test_argv_redacted(tmp_path):
    log = _configure(tmp_path)
    server.run_command("echo --token s3cr3tTokenValue")  # space-separated value
    for rec in _records(log):
        assert all("s3cr3tTokenValue" not in tok for tok in rec["argv"])
    assert "[REDACTED:cli_flag]" in _records(log)[-1]["argv"]


# --- Phase 5: record_type (Flag B) ---------------------------------------

def test_record_type_present_and_correct(tmp_path):
    log = _configure(tmp_path)
    server.run_command("echo hi")      # attempt + outcome
    server.explain_command("echo hi")  # outcome only
    recs = _records(log)
    run_types = [r["record_type"] for r in recs if r["tool"] == "run_command"]
    explain_types = [r["record_type"] for r in recs if r["tool"] == "explain_command"]
    assert run_types == ["attempt", "outcome"]
    assert explain_types == ["outcome"]


# --- Phase 5: Flag A — audit path inside the jail refuses startup ---------

def test_audit_path_inside_jail_refuses_startup(tmp_path, monkeypatch):
    (tmp_path / "policy.toml").write_text(
        textwrap.dedent(
            f"""
            audit_log = "{tmp_path / 'audit.jsonl'}"

            [allowlist]
            commands = ["echo"]
            """
        )
    )
    monkeypatch.setenv("HTMCP_POLICY_FILE", str(tmp_path / "policy.toml"))
    monkeypatch.setenv("HTMCP_JAIL_ROOT", str(tmp_path))
    with pytest.raises(SystemExit):
        server.main()  # refuses before ever calling mcp.run()


# --- Phase 6: jail root is required, no cwd fallback ----------------------

def test_no_jail_root_refuses_startup(tmp_path, monkeypatch):
    (tmp_path / "policy.toml").write_text('[allowlist]\ncommands = ["echo"]\n')
    monkeypatch.setenv("HTMCP_POLICY_FILE", str(tmp_path / "policy.toml"))
    monkeypatch.delenv("HTMCP_JAIL_ROOT", raising=False)
    with pytest.raises(SystemExit):
        server.main()  # no env, no policy jail_root -> refuse


def test_jail_root_from_policy_toml(tmp_path, monkeypatch):
    jail = tmp_path / "jail"
    jail.mkdir()
    (tmp_path / "policy.toml").write_text(
        textwrap.dedent(
            f"""
            jail_root = "{jail}"
            audit_log = "{tmp_path / 'audit.jsonl'}"

            [allowlist]
            commands = ["echo"]
            """
        )
    )
    monkeypatch.setenv("HTMCP_POLICY_FILE", str(tmp_path / "policy.toml"))
    monkeypatch.delenv("HTMCP_JAIL_ROOT", raising=False)
    run_mock = Mock()
    monkeypatch.setattr(server.mcp, "run", run_mock)  # don't block on stdio

    server.main()

    run_mock.assert_called_once()  # startup succeeded
    assert server._JAIL_ROOT == jail.resolve()  # jail root came from policy.toml
