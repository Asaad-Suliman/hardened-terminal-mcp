"""Policy engine — decides whether a command is allowed. Executes nothing.

The pipeline is: parse (shlex) -> sanitize (reject shell metacharacters) ->
name match -> argument rules -> structured verdict. Deny-by-default is the
fallthrough: anything not explicitly allowed is denied.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass

from hardened_terminal_mcp.config import Policy

# Shell control operators. Presence of any of these in the raw input means the
# caller is trying to chain, redirect, or substitute — reject before any policy
# match so such input never reaches allow/deny evaluation.
# `||` and `&&` are covered by `|` and `&`; `$(` covers command substitution.
_METACHARACTERS: tuple[str, ...] = (";", "|", "&", "<", ">", "`", "$(")


@dataclass(frozen=True)
class Verdict:
    """Structured, execution-free result of evaluating one command."""

    parsed_command: list[str] | None  # argv, or None if parsing failed
    decision: str  # "allow" | "deny"
    rule_fired: str  # stage or rule that produced the decision
    reason: str


def _find_metacharacter(raw: str) -> str | None:
    """Return the first shell metacharacter found in ``raw``, else None.

    Conservative raw scan: it flags metacharacters even inside quotes. For a
    deny-by-default hardening layer that trade-off is acceptable — there is no
    quoting trick that can smuggle an operator past it.
    """
    # ponytail: raw substring scan, known ceiling — rejects quoted metachars
    # too (e.g. echo "a;b"); upgrade to quote-aware scanning only if needed.
    for meta in _METACHARACTERS:
        if meta in raw:
            return meta
    return None


def explain(raw: str, policy: Policy) -> Verdict:
    """Run the pipeline built so far and return a structured verdict.

    Executes nothing. Later phases insert argument-level matching ahead of the
    deny-by-default fallthrough.
    """
    meta = _find_metacharacter(raw)
    if meta is not None:
        return Verdict(
            parsed_command=None,
            decision="deny",
            rule_fired="shell-metacharacter",
            reason=f"rejected: shell metacharacter {meta!r}",
        )

    try:
        argv = shlex.split(raw)
    except ValueError as exc:
        return Verdict(
            parsed_command=None,
            decision="deny",
            rule_fired="parse-error",
            reason=f"could not parse command: {exc}",
        )

    if not argv:
        return Verdict(
            parsed_command=argv,
            decision="deny",
            rule_fired="empty-command",
            reason="no command given",
        )

    # Name-level matching. Case-insensitive so `RM` can't slip past `rm`.
    name = argv[0].lower()

    # DENY ALWAYS WINS: a command on both lists is denied.
    if name in policy.denylist:
        return Verdict(
            parsed_command=argv,
            decision="deny",
            rule_fired="denylist",
            reason=f"command {name!r} is on the denylist",
        )

    # Deny-by-default: anything not explicitly allowed is denied.
    if name not in policy.allowlist:
        return Verdict(
            parsed_command=argv,
            decision="deny",
            rule_fired="deny-by-default",
            reason=f"command {name!r} is not on the allowlist",
        )

    return Verdict(
        parsed_command=argv,
        decision="allow",
        rule_fired="allowlist",
        reason=f"command {name!r} is allowed",
    )
