"""Policy engine tests, including bypass attempts. Fully tmp_path isolated —
these never read the repo's real policy.toml.
"""

import textwrap

import pytest

from hardened_terminal_mcp.config import PolicyConfigError, load_policy
from hardened_terminal_mcp.policy import explain

# `clean` sits on BOTH lists on purpose, to prove deny-wins precedence.
_POLICY_TOML = textwrap.dedent(
    """
    [allowlist]
    commands = ["ls", "cat", "git", "clean"]

    [denylist]
    commands = ["rm", "shutdown", "clean"]

    [[rules]]
    command = "git"
    deny_args = ["push --force", "push -f"]
    reason = "force-push rewrites shared history"
    """
)


@pytest.fixture
def policy(tmp_path):
    path = tmp_path / "policy.toml"
    path.write_text(_POLICY_TOML)
    return load_policy(path)


# --- name-level matching + bypass attempts -------------------------------

def test_denylisted_command_denied(policy):
    assert explain("rm file", policy).decision == "deny"


@pytest.mark.parametrize("raw", ["RM file", "  rm   file ", "Rm file"])
def test_case_and_spacing_bypass_denied(policy, raw):
    v = explain(raw, policy)
    assert v.decision == "deny"
    assert v.rule_fired == "denylist"


def test_unlisted_command_denied_by_default(policy):
    v = explain("wget http://x", policy)
    assert v.decision == "deny"
    assert v.rule_fired == "deny-by-default"


def test_deny_wins_when_on_both_lists(policy):
    v = explain("clean up", policy)
    assert v.decision == "deny"
    assert v.rule_fired == "denylist"


def test_allowlisted_command_allowed(policy):
    v = explain("ls -la", policy)
    assert v.decision == "allow"
    assert v.rule_fired == "allowlist"


# --- shell-metacharacter rejection (never reaches policy) -----------------

@pytest.mark.parametrize(
    "raw",
    [
        "rm foo; rm bar",
        "cat $(whoami)",
        "ls | grep x",
        "echo hi && rm x",
        "cat < /etc/passwd",
        "echo hi > /tmp/x",
        "echo `id`",
    ],
)
def test_shell_metacharacters_rejected_before_policy(policy, raw):
    v = explain(raw, policy)
    assert v.decision == "deny"
    assert v.rule_fired == "shell-metacharacter"
    # Rejected at the sanitize stage — never parsed into an argv.
    assert v.parsed_command is None


# --- argument-level rules -------------------------------------------------

def test_git_allowed_generally(policy):
    assert explain("git status", policy).decision == "allow"


@pytest.mark.parametrize("raw", ["git push --force", "git --force push", "git push -f"])
def test_git_force_push_denied_including_reorder(policy, raw):
    v = explain(raw, policy)
    assert v.decision == "deny"
    assert v.rule_fired == "argument-rule"
    assert v.reason == "force-push rewrites shared history"


# --- explain() structured verdict -----------------------------------------

def test_explain_structured_allow(policy):
    v = explain("git status", policy)
    assert v.parsed_command == ["git", "status"]
    assert (v.decision, v.rule_fired) == ("allow", "allowlist")


def test_explain_structured_deny(policy):
    v = explain("git push --force", policy)
    assert v.parsed_command == ["git", "push", "--force"]
    assert (v.decision, v.rule_fired) == ("deny", "argument-rule")


# --- malformed config fails loudly ----------------------------------------

def test_malformed_config_raises(tmp_path):
    bad = tmp_path / "bad.toml"
    bad.write_text('[allowlist]\ncommands = "notalist"\n')
    with pytest.raises(PolicyConfigError):
        load_policy(bad)


def test_missing_file_raises(tmp_path):
    with pytest.raises(PolicyConfigError):
        load_policy(tmp_path / "does_not_exist.toml")
