"""Load and validate ``policy.toml`` into a typed, immutable policy object.

This module only *reads* configuration — it makes no execution decisions and
runs no commands. Malformed config fails loudly via :class:`PolicyConfigError`
rather than silently degrading to an insecure default.
"""

from __future__ import annotations

import os
import re
import shlex
import tomllib
from dataclasses import dataclass, field
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
    jail_root: str = ""  # required at startup; "" means "not configured"
    audit_log: str = "audit.jsonl"  # path to the JSONL audit trail
    audit_fail_mode: str = "closed"  # "closed" (block on log failure) | "open"
    redaction_enabled: bool = True
    redaction_entropy_fallback: bool = False
    # Operator-defined extra patterns, validated (compilable) at load time.
    redaction_extra_patterns: tuple[tuple[str, str], ...] = field(default_factory=tuple)


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


def _parse_extra_patterns(raw: object) -> tuple[tuple[str, str], ...]:
    """Validate ``[redaction].extra_patterns`` — a list of {name, regex} tables.

    Each regex is compiled here purely to fail loudly on an invalid one; the
    compiled objects are rebuilt by the redactor. Returns (name, regex) pairs.
    """
    if not isinstance(raw, list):
        raise PolicyConfigError("redaction.extra_patterns must be a list of tables")
    out: list[tuple[str, str]] = []
    for i, item in enumerate(raw):
        where = f"redaction.extra_patterns[{i}]"
        if not isinstance(item, dict):
            raise PolicyConfigError(f"{where} must be a table")
        name, regex = item.get("name"), item.get("regex")
        if not isinstance(name, str) or not name.strip():
            raise PolicyConfigError(f"{where}.name must be a non-empty string")
        if not isinstance(regex, str) or not regex:
            raise PolicyConfigError(f"{where}.regex must be a non-empty string")
        try:
            re.compile(regex)
        except re.error as exc:
            raise PolicyConfigError(f"{where}.regex is not a valid regex: {exc}") from exc
        out.append((name, regex))
    return tuple(out)


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

    # Jail root. Required at startup (see server.main), but validated as a string
    # here; "" means "not configured" and is resolved/enforced by the entry point.
    jail_root = data.get("jail_root", "")
    if not isinstance(jail_root, str):
        raise PolicyConfigError("jail_root must be a string")

    # Redaction settings.
    redaction_section = data.get("redaction", {})
    if not isinstance(redaction_section, dict):
        raise PolicyConfigError("[redaction] must be a table")
    redaction_enabled = redaction_section.get("enabled", True)
    redaction_entropy = redaction_section.get("entropy_fallback", False)
    if not isinstance(redaction_enabled, bool):
        raise PolicyConfigError("redaction.enabled must be a boolean")
    if not isinstance(redaction_entropy, bool):
        raise PolicyConfigError("redaction.entropy_fallback must be a boolean")
    extra_patterns = _parse_extra_patterns(redaction_section.get("extra_patterns", []))

    return Policy(
        allowlist=frozenset(c.lower() for c in allow),
        denylist=frozenset(c.lower() for c in deny),
        rules=rules,
        jail_root=jail_root,
        audit_log=audit_log,
        audit_fail_mode=audit_fail_mode,
        redaction_enabled=redaction_enabled,
        redaction_entropy_fallback=redaction_entropy,
        redaction_extra_patterns=extra_patterns,
    )
