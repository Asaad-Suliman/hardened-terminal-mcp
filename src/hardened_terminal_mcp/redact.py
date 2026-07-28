"""Secret redaction — pure functions, no file or config I/O.

Regexes are compiled once at import (``BUILTIN_PATTERNS``), never per call. Each
pattern is named and yields a typed placeholder ``[REDACTED:<name>]``. For
keyed secrets (``token=…``, ``--password …``, ``Authorization: …``) only the
*value* is replaced — the key stays visible so an operator can still see THAT a
secret appeared and which kind.

Callers compose a redactor with :func:`make_redactor` and apply it via
:func:`redact`. The optional Shannon-entropy fallback is off unless a caller
enables it; it is noisy on hashes/UUIDs/base64 (documented in the README).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass

__all__ = [
    "Pattern",
    "BUILTIN_PATTERNS",
    "redact",
    "compile_extra",
    "build_patterns",
    "shannon_entropy",
    "entropy_redact",
    "make_redactor",
]


@dataclass(frozen=True)
class Pattern:
    """A named, compiled redaction rule."""

    name: str
    regex: re.Pattern[str]
    repl: Callable[[re.Match[str]], str]


def _whole(name: str) -> Callable[[re.Match[str]], str]:
    """Replacement that redacts the entire match (match == the secret value)."""
    placeholder = f"[REDACTED:{name}]"
    return lambda _m: placeholder


def _keep_prefix(name: str) -> Callable[[re.Match[str]], str]:
    """Replacement that keeps group(1) (the key/prefix) and redacts the value."""
    placeholder = f"[REDACTED:{name}]"
    return lambda m: m.group(1) + placeholder


def _p(name: str, pattern: str, *, keep_prefix: bool = False, flags: int = 0) -> Pattern:
    repl = _keep_prefix(name) if keep_prefix else _whole(name)
    return Pattern(name=name, regex=re.compile(pattern, flags), repl=repl)


# Order matters only for which placeholder a value gets when two rules overlap;
# every rule still redacts. Keyed rules run first so a keyed secret keeps its key.
BUILTIN_PATTERNS: tuple[Pattern, ...] = (
    _p(
        "private_key_block",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        flags=re.DOTALL,
    ),
    _p(
        "auth_header",
        r"(Authorization:\s*\S+\s+)\S+",
        keep_prefix=True,
        flags=re.IGNORECASE,
    ),
    _p(
        "cli_flag",
        r"(?<!\S)((?:--password|--token|-p)(?:=|\s+))\S+",
        keep_prefix=True,
    ),
    _p(
        "assignment",
        r"((?i:api[_-]?key|secret|token|password|passwd|pwd)\s*=\s*)\S+",
        keep_prefix=True,
    ),
    _p("openai_key", r"\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b"),
    _p("github_token", r"\bgh[posru]_[A-Za-z0-9]{20,}\b"),
    _p("slack_token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    _p("langsmith_key", r"\blsv2_[A-Za-z0-9_-]{20,}\b"),
    _p("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b"),
    _p(
        "aws_secret_key",
        r"((?i:aws)[^\n]{0,40}?(?i:secret)[^\n]{0,20}?['\"\s:=]+)[A-Za-z0-9/+]{40}\b",
        keep_prefix=True,
    ),
    _p("jwt", r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"),
)


def redact(text: str, patterns: Iterable[Pattern]) -> str:
    """Apply every pattern to ``text``, returning the redacted string."""
    for pat in patterns:
        text = pat.regex.sub(pat.repl, text)
    return text


def compile_extra(name: str, regex: str) -> Pattern:
    """Compile one operator-defined pattern. Raises ``re.error`` on a bad regex so
    the config loader can fail loudly rather than silently skip it."""
    return Pattern(name=name, regex=re.compile(regex), repl=_whole(name))


def build_patterns(extra: Iterable[tuple[str, str]] = ()) -> tuple[Pattern, ...]:
    """Built-in patterns plus any operator-defined ``(name, regex)`` extras."""
    return BUILTIN_PATTERNS + tuple(compile_extra(n, r) for n, r in extra)


# --- entropy fallback (off by default) -----------------------------------

# Tokens that could plausibly be a secret: base64/base64url-ish, reasonably long.
_TOKEN = re.compile(r"[A-Za-z0-9+/=_-]{20,}")


def shannon_entropy(s: str) -> float:
    """Shannon entropy of ``s`` in bits per character."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def entropy_redact(text: str, *, min_len: int = 20, threshold: float = 4.0) -> str:
    """Redact unrecognised high-entropy tokens as ``[REDACTED:high_entropy]``.

    Noisy by design (hashes, UUIDs, base64 payloads trip it) — the caller opts in.
    """
    def _sub(m: re.Match[str]) -> str:
        tok = m.group(0)
        if len(tok) >= min_len and shannon_entropy(tok) >= threshold:
            return "[REDACTED:high_entropy]"
        return tok

    return _TOKEN.sub(_sub, text)


def make_redactor(
    patterns: Iterable[Pattern],
    *,
    entropy_fallback: bool = False,
) -> Callable[[str], str]:
    """Build a reusable text->text redactor from pre-compiled patterns."""
    patterns = tuple(patterns)

    def _redactor(text: str) -> str:
        text = redact(text, patterns)
        if entropy_fallback:
            text = entropy_redact(text)
        return text

    return _redactor
