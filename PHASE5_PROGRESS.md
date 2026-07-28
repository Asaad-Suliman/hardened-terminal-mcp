# Phase 5 — Secret Redaction + Phase 4 Flag Fixes: Progress Log

Append one block per completed step. On restart, read this file first and
resume from the last incomplete step. Never redo completed steps.

## Key design decisions (locked)

- Truncation point is `executor._cap` (byte-cap before decode). To redact BEFORE
  truncation (4a), executor.run gains an optional `redactor` param and redacts the
  full decoded text before capping. This is the real cap, so a secret can never be
  split. Executor's security model (shell=False, env scrub, cwd jail, timeout) is
  untouched — only decode/redact/cap ordering changes.
- Redaction of audit command_raw + argv (4b) happens in server._new_record.
- Redactor is built once in configure() from policy.redaction (patterns compiled
  once at import in redact.py; extra patterns compiled once at build). Disabled →
  redactor is None and nothing is redacted.
- Flag A (audit path inside jail) is checked in main() on policy.audit_log vs
  jail_root — NOT in configure(), because Phase 3/4 tests legitimately inject an
  audit logger inside their tmp jail. Keeps 55 tests green.
- Flag B: record_type "attempt"|"outcome" on AuditRecord. Single-record paths
  (denial/parse/cwd/explain) are "outcome" (terminal); only the pre-exec gate is
  "attempt".

## Plan (ordered steps)

1. redact.py — patterns (compile once), redact(), entropy fallback, make_redactor
2. Config wiring — [redaction] on Policy + validation (fail loud on bad regex) + policy.toml
3. Application points — executor redactor param; server plumbing + audit redaction
   4a. Flag A — refuse start if audit path inside jail
   4b. Flag B — record_type on AuditRecord
4. Tests — test_redact.py + test_audit.py additions
5. Docs (README) + summary

---

### Step 1 — DONE (commit 85b3673)

- **Files:** redact.py. 11 named patterns (compile-once), keyed-value preservation,
  entropy fallback (off by default), make_redactor/build_patterns/compile_extra.
- **Status:** true/false-positive smoke passed.
- **Next:** Step 2 — config wiring.

### Step 2 — DONE (commit 4815e9a)

- **Files:** config.py, policy.toml. Policy gains redaction_enabled /
  entropy_fallback / extra_patterns; invalid extra regex -> PolicyConfigError.
- **Status:** verified defaults, valid+invalid extra pattern; 55 tests green.
- **Next:** Step 3 — application points (executor redactor + server plumbing).

### Step 3 — DONE (commit 28f8425)

- **Files:** executor.py (redactor param, _finalize decode→redact→cap), server.py
  (_REDACTOR built in configure, passed to executor, audit cmd/argv redaction +
  flag-lookahead for space-separated secret values).
- **Status:** 55 tests green; e2e smoke redacts stdout, command_raw, argv.
- **Next:** Step 4a — Flag A.

### Step 4a — DONE (commit 89d73aa)

- **Files:** server.py (_audit_within_jail + main() refusal).
- **Status:** helper verified inside/outside/equal; startup refuses with both paths.
- **Next:** Step 4b — Flag B.

### Step 4b — DONE (commit b0fd575)

- **Files:** audit.py (record_type field + docstring), server.py (_new_record
  record_type param + 4 call sites: attempt vs outcome).
- **Status:** 55 tests green; smoke shows attempt+outcome / outcome / outcome.
- **Next:** Step 5 — tests.

### Step 5 — DONE (commit 520da4a)

- **Files:** tests/test_redact.py (21), tests/test_audit.py (+4).
- Per-pattern, no-false-positive, entropy on/off, stdout/stderr redaction,
  straddle-not-split, invalid-extra-regex fails at load, command_raw/argv
  redaction, record_type, audit-path-inside-jail refuses startup.
- **Status:** `uv run pytest` → 80 passed (55 prior + 25 new).
- **Next:** Step 6 — docs + summary.

### Step 6 — DONE

- **Files:** README.md (redaction section, guarantees, record_type note),
  PHASE5_PROGRESS.md.
- **Status:** Phase 5 complete. 80 tests green. Not pushed (per instruction).

---
