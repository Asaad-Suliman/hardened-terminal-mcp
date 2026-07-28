# Phase 4 — Audit Log: Progress Log

Append one block per completed step. On restart, read this file first and
resume from the last incomplete step. Never redo completed steps.

## Key design decisions (locked)

- Two audit records on the executing path (attempt BEFORE exec + outcome AFTER),
  one record on non-executing paths, linked by a shared event_id. The attempt
  record is the fail-closed gate: if it can't be written, the command never runs.
- Single write point: both tools route through `_serve()` in server.py so audit
  can't be forgotten. (A pure outer decorator can't gate execution before the
  executor runs, which fail-closed requires.)
- AuditLogger writes open-per-append (open, write line, flush, fsync, close under
  a lock) so an unwritable path fails per-call as AUDIT_UNAVAILABLE.

## Plan (ordered steps)

1. audit.py — AuditRecord schema + AuditLogger + AuditError
2. Config wiring — Policy.audit_log / audit_fail_mode + env overrides + policy.toml + .gitignore
3. server.py — AUDIT_UNAVAILABLE code, _serve single write point, fail mode; update test_server fixture
4. tests/test_audit.py
5. Docs (README) + summary

---

### Step 1 — DONE (commit 2cdcd52)

- **Files:** src/hardened_terminal_mcp/audit.py.
- AuditRecord (13-field content-free Pydantic) + AuditLogger (open-per-append,
  lock, flush+fsync, AuditError on OSError).
- **Status:** smoke-tested: 2 appended lines, 13 keys, unwritable path raises.
- **Next:** Step 2 — config wiring.

### Step 2 — DONE (commit 41ca257)

- **Files:** config.py, policy.toml, .gitignore.
- Policy.audit_log / audit_fail_mode + env overrides (HTMCP_AUDIT_LOG /
  HTMCP_AUDIT_FAIL_MODE) + fail-mode validation. policy.toml keys added.
  audit.jsonl / *.jsonl gitignored.
- **Status:** verified file value, env override, bad-value rejection.
- **Next:** Step 3 — server.py single write point + fail mode.

### Step 3 — DONE (commit c498992)

- **Files:** server.py, tests/test_server.py (fixture injects tmp AuditLogger).
- AUDIT_UNAVAILABLE code + table row; _serve single write point (2 records on
  exec path w/ shared event_id, 1 elsewhere); _audit fail mode; _finish taxonomy
  wrapper; configure() gains audit_logger param.
- **Status:** 46 existing tests green; end-to-end smoke confirms 2/1/1 records,
  content-free.
- **Next:** Step 4 — tests/test_audit.py.

### Step 4 — DONE (commit db4c865)

- **Files:** tests/test_audit.py (9 tests).
- Both tools, denial/execution/dry-run, attempt+outcome pairing, schema-key
  stability, content absence, append/valid-JSON, fail-closed blocks exec
  (AUDIT_UNAVAILABLE, executor Mock 0 calls), fail-open executes + warns.
- **Status:** `uv run pytest` → 55 passed (46 prior + 9 new).
- **Next:** Step 5 — docs + summary.

### Step 5 — DONE

- **Files:** README.md (audit section, AUDIT_UNAVAILABLE row, env vars),
  PHASE4_PROGRESS.md.
- **Status:** Phase 4 complete. 55 tests green. Not pushed (per instruction).

---
