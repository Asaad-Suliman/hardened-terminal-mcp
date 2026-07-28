"""Append-only JSONL audit trail.

Phase 4: one JSON object per line, one line per audited event. The logger writes
open-per-append (open, write, flush, fsync, close) under a lock, so records
cannot be lost to buffering on a crash and an unwritable path fails loudly on the
very next write rather than silently.

NEVER logs stdout/stderr *content* — byte counts only. Secret redaction is a
separate concern (Phase 5); the safe default here is to record nothing that could
contain a secret.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

from pydantic import BaseModel

__all__ = ["AuditRecord", "AuditLogger", "AuditError"]


class AuditError(Exception):
    """Raised when an audit record cannot be durably written."""


class AuditRecord(BaseModel):
    """One audited event. Content-free: stdout/stderr are counted, never stored."""

    ts: str  # ISO-8601 UTC
    event_id: str  # uuid4; the attempt and outcome records of one run share it
    tool: str  # "run_command" | "explain_command"
    command_raw: str
    argv: list[str] | None  # parsed argv, or null if parsing failed
    cwd: str | None
    verdict: str | None  # policy decision: "allow" | "deny"
    rule_fired: str | None  # policy stage/rule that decided
    code: str  # ResultCode value
    exit_code: int | None
    duration_ms: int
    stdout_bytes: int
    stderr_bytes: int


class AuditLogger:
    """Thread-safe append-only JSONL writer."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path

    def write(self, record: AuditRecord) -> None:
        """Append one record as a single JSON line, durably. Raises AuditError on
        any I/O failure so the caller can apply its fail mode."""
        line = record.model_dump_json() + "\n"
        try:
            with self._lock:
                # Open-per-append: a fresh handle each write means an unwritable
                # path (or a since-deleted parent dir) surfaces here, not at
                # startup, and there is no long-lived buffer to lose on a crash.
                with open(self._path, "a", encoding="utf-8") as fh:
                    fh.write(line)
                    fh.flush()
                    os.fsync(fh.fileno())
        except OSError as exc:
            raise AuditError(f"could not write audit record: {exc}") from exc
