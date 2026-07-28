"""Load and validate ``policy.toml`` into a typed, immutable policy object.

This module only *reads* configuration — it makes no execution decisions and
runs no commands. Malformed config fails loudly via :class:`PolicyConfigError`
rather than silently degrading to an insecure default.
"""

from __future__ import annotations

import os
import shlex
import tomllib
from dataclasses import dataclass
from pathlib import Path


class PolicyConfigError(Exception):
    """Raised when policy.toml is missing, unparseable, or malformed."""


@dataclass(frozen=True)
class ArgumentRule:
    """A deny rule scoped to a single command's arguments.

    ``deny_args`` holds one or more token patterns. A command is denied when
    *all* tokens of any single pattern are present among its arguments
    (order-independent). Patterns are pre-split into token tuples at load time.
    """

    command: str  # normalized lowercase command name
    deny_args: tuple[tuple[str, ...], ...]
    reason: str


@dataclass(frozen=True)
class Policy:
    """Typed, immutable view of a validated policy.toml."""

    allowlist: frozenset[str]  # lowercased command names
    denylist: frozenset[str]  # lowercased command names
    rules: tuple[ArgumentRule, ...]
    audit_log: str = "audit.jsonl"  # path to the JSONL audit trail
    audit_fail_mode: str = "closed"  # "closed" (block on log failure) | "open"


def _require_str_list(value: object, where: str) -> list[str]:
    """Validate that ``value`` is a list of strings, else fail loudly."""
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise PolicyConfigError(f"{where} must be a list of strings")
    return value


def _parse_rule(raw: object, index: int) -> ArgumentRule:
    """Validate and normalize a single ``[[rules]]`` entry."""
    where = f"rules[{index}]"
    if not isinstance(raw, dict):
        raise PolicyConfigError(f"{where} must be a table")

    command = raw.get("command")
    if not isinstance(command, str) or not command.strip():
        raise PolicyConfigError(f"{where}.command must be a non-empty string")

    deny_args_raw = _require_str_list(raw.get("deny_args", []), f"{where}.deny_args")
    # Split each pattern into tokens so matching is token-level, not substring.
    deny_args = tuple(tuple(shlex.split(pattern)) for pattern in deny_args_raw)

    reason = raw.get("reason")
    if not isinstance(reason, str):
        raise PolicyConfigError(f"{where}.reason must be a string")

    return ArgumentRule(command=command.lower(), deny_args=deny_args, reason=reason)


def load_policy(path: str | Path) -> Policy:
    """Load, validate, and normalize ``policy.toml`` into a :class:`Policy`.

    Raises :class:`PolicyConfigError` on any missing file, TOML syntax error,
    or shape/type violation. Command names are lowercased so matching is
    case-insensitive. An empty or absent allowlist is legal and yields an empty
    set — deny-by-default then falls out naturally at evaluation time.
    """
    path = Path(path)
    try:
        with path.open("rb") as f:
            data = tomllib.load(f)
    except FileNotFoundError as exc:
        raise PolicyConfigError(f"policy file not found: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise PolicyConfigError(f"policy file is not valid TOML: {exc}") from exc

    allowlist_section = data.get("allowlist", {})
    denylist_section = data.get("denylist", {})
    if not isinstance(allowlist_section, dict) or not isinstance(denylist_section, dict):
        raise PolicyConfigError("[allowlist] and [denylist] must be tables")

    allow = _require_str_list(
        allowlist_section.get("commands", []), "allowlist.commands"
    )
    deny = _require_str_list(denylist_section.get("commands", []), "denylist.commands")

    rules_raw = data.get("rules", [])
    if not isinstance(rules_raw, list):
        raise PolicyConfigError("[[rules]] must be an array of tables")
    rules = tuple(_parse_rule(r, i) for i, r in enumerate(rules_raw))

    # Audit settings. Env overrides win over the file so ops can redirect the log
    # or flip the fail mode without editing policy.toml. One config system: these
    # live on Policy alongside the allow/deny lists, not in a separate loader.
    audit_log = os.environ.get("HTMCP_AUDIT_LOG") or data.get("audit_log", "audit.jsonl")
    if not isinstance(audit_log, str) or not audit_log:
        raise PolicyConfigError("audit_log must be a non-empty string")

    audit_fail_mode = os.environ.get("HTMCP_AUDIT_FAIL_MODE") or data.get(
        "audit_fail_mode", "closed"
    )
    if audit_fail_mode not in ("closed", "open"):
        raise PolicyConfigError('audit_fail_mode must be "closed" or "open"')

    return Policy(
        allowlist=frozenset(c.lower() for c in allow),
        denylist=frozenset(c.lower() for c in deny),
        rules=rules,
        audit_log=audit_log,
        audit_fail_mode=audit_fail_mode,
    )
