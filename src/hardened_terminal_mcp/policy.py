"""Policy engine — decides whether a command is allowed. Executes nothing.

The pipeline is: parse (shlex) -> sanitize (reject shell metacharacters) ->
name match -> argument rules -> structured verdict. Deny-by-default is the
fallthrough: anything not explicitly allowed is denied.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass

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


def explain(raw: str) -> Verdict:
    """Run the pipeline built so far and return a structured verdict.

    Executes nothing. Later phases insert name-level and argument-level
    matching ahead of the deny-by-default fallthrough.
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

    return Verdict(
        parsed_command=argv,
        decision="deny",
        rule_fired="deny-by-default",
        reason="command not in allowlist",
    )
