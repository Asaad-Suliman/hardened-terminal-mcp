_SLACK = "xoxb" + "-123456789012-abcdefghijklmnop"

"""Redaction tests: one case per pattern, no-false-positives, entropy fallback,
redaction-before-truncation, and loud failure on an invalid operator regex.
"""

import textwrap
from pathlib import Path

import pytest

from hardened_terminal_mcp import executor
from hardened_terminal_mcp.config import PolicyConfigError, load_policy
from hardened_terminal_mcp.redact import (
    BUILTIN_PATTERNS,
    make_redactor,
    shannon_entropy,
)

_redact = make_redactor(BUILTIN_PATTERNS)


# --- one test per pattern class ------------------------------------------

# (label, input, placeholder_name, the secret substring that must disappear)
_POSITIVES = [
    ("openai_key", "use sk-proj-abcdefghij1234567890ABCD now", "openai_key",
     "sk-proj-abcdefghij1234567890ABCD"),
    ("github_token", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456 x", "github_token",
     "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456"),
    ("slack_token", "t " + _SLACK + " z", "slack_token",
     _SLACK),
    ("langsmith_key", "lsv2_pt_abcdef1234567890abcdef12 end", "langsmith_key",
     "lsv2_pt_abcdef1234567890abcdef12"),
    ("aws_access_key", "AKIAIOSFODNN7EXAMPLE done", "aws_access_key",
     "AKIAIOSFODNN7EXAMPLE"),
    ("aws_secret_key",
     'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
     "aws_secret_key", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("private_key_block",
     "-----BEGIN RSA PRIVATE KEY-----\nMIIsecret\n-----END RSA PRIVATE KEY-----",
     "private_key_block", "MIIsecret"),
    ("jwt",
     "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6y",
     "jwt", "SflKxwRJSMeKKF2QT4fwpMeJf36POk6y"),
    ("assignment", "password=hunter2secretvalue x", "assignment",
     "hunter2secretvalue"),
    ("cli_flag", "tool --password s3cr3tValue --verbose", "cli_flag",
     "s3cr3tValue"),
    ("auth_header", "Authorization: Bearer abcdef123456TOKEN", "auth_header",
     "abcdef123456TOKEN"),
]


@pytest.mark.parametrize("label,text,name,secret", _POSITIVES, ids=[p[0] for p in _POSITIVES])
def test_pattern_redacts(label, text, name, secret):
    out = _redact(text)
    assert f"[REDACTED:{name}]" in out
    assert secret not in out


# --- no false positives ---------------------------------------------------

_NEGATIVES = [
    ("unix_path", "/usr/local/bin/python3.12 -> ./src/module.py"),
    ("git_sha", "commit 9f2a1c4b8e7d6a5f3c2b1a0e9d8c7b6a5f4e3d2c merged"),
    ("uuid", "request id 550e8400-e29b-41d4-a716-446655440000 ok"),
    ("prose", "The quick brown fox jumps over the lazy dog by the river."),
    ("version", "package v2.34.1 build 12345 released"),
    # Regression: bare -p must NOT trigger cli_flag (it means preserve / port).
    ("cp_p", "cp -p a b"),
    ("ssh_p", "ssh -p 22 host"),
]


@pytest.mark.parametrize("label,text", _NEGATIVES, ids=[n[0] for n in _NEGATIVES])
def test_no_false_positive(label, text):
    assert _redact(text) == text


# --- entropy fallback: off by default, works when enabled -----------------

def test_entropy_off_by_default():
    token = "Zx9Kq2Lm8Wp4Rt6Yv0Bn3Hd5Fg7Jk1Cs"
    assert token in _redact(f"blob {token} end")  # untouched


def test_entropy_on_when_enabled():
    token = "Zx9Kq2Lm8Wp4Rt6Yv0Bn3Hd5Fg7Jk1Cs"
    r = make_redactor(BUILTIN_PATTERNS, entropy_fallback=True)
    out = r(f"blob {token} end")
    assert "[REDACTED:high_entropy]" in out
    assert token not in out
    assert shannon_entropy(token) >= 4.0


# --- redaction BEFORE truncation (secret can't straddle the cap) ---------

@pytest.fixture
def echo_policy(tmp_path):
    (tmp_path / "policy.toml").write_text(
        textwrap.dedent(
            """
            [allowlist]
            commands = ["echo", "cat"]
            """
        )
    )
    return load_policy(tmp_path / "policy.toml")


def test_secret_straddling_cap_is_redacted_not_split(echo_policy, tmp_path):
    secret = "sk-proj-" + "S" * 40  # 48 chars, self-identifying
    payload = "P" * 5 + " " + secret  # secret straddles a 40-byte cap
    r = make_redactor(BUILTIN_PATTERNS)

    # Without redaction the secret would be split and partially leak.
    bare = executor.run(f"echo {payload}", echo_policy, cwd=tmp_path,
                        max_output_bytes=40)
    assert bare.truncated is True
    assert "SSSSSSSS" in bare.stdout  # raw secret bytes leaked past no redaction

    # With redaction (before the cap) the secret is gone, placeholder intact.
    red = executor.run(f"echo {payload}", echo_policy, cwd=tmp_path,
                      max_output_bytes=40, redactor=r)
    assert "SSSSSSSS" not in red.stdout
    assert "[REDACTED:openai_key]" in red.stdout


def test_redaction_applies_to_stderr(echo_policy, tmp_path):
    # `cat` of a missing path echoes the (key-shaped) filename to stderr; the
    # redactor must scrub it there too, not just on stdout.
    r = make_redactor(BUILTIN_PATTERNS)
    missing = "/tmp/AKIAIOSFODNN7EXAMPLE"  # not a real file; AKIA at a word boundary
    res = executor.run(f"cat {missing}", echo_policy, cwd=tmp_path, redactor=r)
    assert "AKIAIOSFODNN7EXAMPLE" not in res.stderr
    assert "[REDACTED:aws_access_key]" in res.stderr


# --- invalid operator regex fails loudly at load --------------------------

def test_invalid_extra_pattern_fails_at_load(tmp_path):
    (tmp_path / "policy.toml").write_text(
        textwrap.dedent(
            """
            [allowlist]
            commands = ["ls"]

            [redaction]
            extra_patterns = [{ name = "bad", regex = "([unclosed" }]
            """
        )
    )
    with pytest.raises(PolicyConfigError):
        load_policy(tmp_path / "policy.toml")
