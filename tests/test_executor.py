"""Executor tests. Fully tmp_path isolated — a real subprocess runs, but only
allowlisted commands, always inside a temp cwd with a scrubbed environment.
"""

import textwrap
from pathlib import Path

import pytest

from hardened_terminal_mcp.config import load_policy
from hardened_terminal_mcp.executor import run

_POLICY_TOML = textwrap.dedent(
    """
    [allowlist]
    commands = ["echo", "sleep", "cat", "printenv"]

    [denylist]
    commands = ["rm"]
    """
)


@pytest.fixture
def policy(tmp_path):
    path = tmp_path / "policy.toml"
    path.write_text(_POLICY_TOML)
    return load_policy(path)


# --- refusal: denied command is never executed ----------------------------

def test_denied_command_refused(policy, tmp_path):
    result = run("rm -rf /", policy, cwd=tmp_path)
    assert result.exit_code == -1
    assert "denylist" in result.stderr
    assert result.stdout == ""
    assert result.duration_seconds == 0.0  # never ran


# --- happy path -----------------------------------------------------------

def test_allowed_command_runs(policy, tmp_path):
    result = run("echo hi", policy, cwd=tmp_path)
    assert result.exit_code == 0
    assert "hi" in result.stdout
    assert not result.timed_out
    assert not result.truncated


# --- timeout kills the process --------------------------------------------

def test_timeout_kills_process(policy, tmp_path):
    result = run("sleep 5", policy, cwd=tmp_path, timeout=0.5)
    assert result.timed_out is True
    assert result.exit_code == -1


# --- output cap + truncation marker ---------------------------------------

def test_output_truncated_with_marker(policy, tmp_path):
    result = run("echo abcdefghijklmnop", policy, cwd=tmp_path, max_output_bytes=5)
    assert result.truncated is True
    assert result.stdout.endswith("...[truncated]")


# --- environment scrub: parent secret must not reach the child ------------

def test_child_env_lacks_parent_secret(policy, tmp_path, monkeypatch):
    monkeypatch.setenv("SUPER_SECRET_TOKEN", "leaked-value")
    result = run("printenv SUPER_SECRET_TOKEN", policy, cwd=tmp_path)
    # printenv exits non-zero and prints nothing when the var is absent.
    assert "leaked-value" not in result.stdout
    assert result.exit_code != 0


# --- cwd jail: missing directory is refused -------------------------------

def test_missing_cwd_refused(policy, tmp_path):
    result = run("echo hi", policy, cwd=tmp_path / "does_not_exist")
    assert result.exit_code == -1
    assert "cwd is not a directory" in result.stderr
    assert result.stdout == ""


# --- shell=False everywhere: no shell=True in the source tree -------------

def test_no_shell_true_in_source():
    src = Path(__file__).resolve().parent.parent / "src"
    offenders = [
        p for p in src.rglob("*.py") if "shell=True" in p.read_text()
    ]
    assert offenders == [], f"shell=True found in: {offenders}"
