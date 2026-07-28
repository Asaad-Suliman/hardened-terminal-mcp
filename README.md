# hardened-terminal-mcp

A security-hardened terminal MCP server. It exposes a small, policy-gated shell
surface to an MCP client over stdio — allowlisted commands only, no shell, jailed
to a single directory.

## Guarantees

- **Deny by default.** A command whose name is not on the allowlist is refused.
  Deny wins: a name on both lists is denied.
- **No shell.** Commands run via `subprocess` with `shell=False` on a parsed
  argv. Shell metacharacters (`; | & < > \` $(...)`) are rejected before any
  policy check — no chaining, redirection, or substitution.
- **Jailed cwd.** Execution is confined to a configured jail root; traversal
  (`..`), symlink, and absolute-path escapes are refused.
- **Scrubbed environment.** The child gets a minimal env (`PATH`, `HOME`, `LANG`)
  so parent-process secrets can't leak into it.
- **Bounded.** Wall-clock timeout with process kill; stdout/stderr are capped.
- **Errors are data.** No Python traceback ever reaches the client; every result
  is a `CommandResult` envelope with a typed `ResultCode`.
- **Audited.** Every invocation of both tools is appended to a JSONL trail
  (byte counts only, never output content). Under fail-closed, a command that
  can't be logged is not run. The audit log must live outside the jail root or
  startup is refused.
- **Redacted.** Secrets (API keys, tokens, private keys, JWTs, auth headers,
  `KEY=value`/`--password X` values) are stripped from tool output and from
  audit `command_raw`/`argv`. Output is redacted _before_ truncation, so a
  secret can never be split across the cap and left half-visible.

## How it works

`policy.py` decides (`explain`), `executor.py` runs (`run`), `server.py` wires
both behind two FastMCP tools and maps every outcome onto one envelope.

## Install

```sh
uv sync
```

## Run

```sh
uv run hardened-terminal-mcp        # serves over stdio
```

Configuration (env vars, both optional):

- `HTMCP_POLICY_FILE` — path to `policy.toml` (default: `policy.toml`).
- `HTMCP_JAIL_ROOT` — directory commands are jailed to (default: process cwd).
- `HTMCP_AUDIT_LOG` — path to the JSONL audit trail (default: `audit.jsonl`).
- `HTMCP_AUDIT_FAIL_MODE` — `closed` (default) or `open` (see Audit trail).

Startup fails loudly if the policy is missing/invalid or the jail root is not a
directory. Edit `policy.toml` to change the allow/deny lists and argument rules.

## Tool reference

Both tools return a `CommandResult`:
`{ ok, code, stdout, stderr, exit_code, duration_ms, policy_reason }`.

- **`run_command(command, cwd=None)`** — evaluate against policy and, if allowed,
  run it sandboxed. `cwd` (if given) must resolve inside the jail root.
- **`explain_command(command)`** — dry run: return the verdict only, with empty
  output and `exit_code=None`. Never executes.

`ResultCode` values:

| Code                | Meaning                                                     |
| ------------------- | ----------------------------------------------------------- |
| `OK`                | Executed and returned (`exit_code` carries the result).     |
| `POLICY_DENIED`     | Denied by policy (list, arg rule, metacharacter, empty).    |
| `PARSE_ERROR`       | Command could not be parsed into an argv.                   |
| `TIMEOUT`           | Wall-clock timeout; process killed.                         |
| `OUTPUT_TRUNCATED`  | Ran, but output hit the cap.                                |
| `CWD_ESCAPE`        | `cwd` escaped the jail root.                                |
| `EXECUTOR_ERROR`    | Allowed command couldn't run (not found, permission, etc.). |
| `AUDIT_UNAVAILABLE` | Fail-closed: the audit record couldn't be written; not run. |
| `INTERNAL_ERROR`    | Unexpected server error; generic message only.              |

## Audit trail

Every call to either tool is appended to `audit_log` (one JSON object per line).
Records carry byte counts (`stdout_bytes`, `stderr_bytes`) but **never** the
output content — secret redaction is a separate concern.

An executed command writes two records sharing one `event_id`: an **attempt**
record before execution and an **outcome** record after — told apart by the
explicit `record_type` field (`"attempt"` | `"outcome"`), not by inference. The
attempt record is written first so a crash mid-execution can never leave a
silently-unlogged command. Denials, parse errors, cwd escapes, and dry runs
write a single `"outcome"` record.

`command_raw` and `argv` are redacted (see Redaction); output content is still
never recorded — only byte counts.

`audit_fail_mode` controls what happens when a record can't be written:

- **`closed`** (default) — refuse to execute; return `AUDIT_UNAVAILABLE`.
- **`open`** — execute anyway and emit a warning to stderr.

## Redaction

`[redaction]` in `policy.toml` scrubs secrets from tool output and audit records:

```toml
[redaction]
enabled = true
entropy_fallback = false
extra_patterns = []   # e.g. [{ name = "internal_id", regex = "INT-[0-9]{8}" }]
```

Built-in patterns cover OpenAI/GitHub/Slack/LangSmith keys, AWS access and secret
keys, private-key blocks, JWTs, `Authorization:` headers, `KEY=value` assignments,
and `--password/--token/-p` flag values. Each secret becomes
`[REDACTED:<pattern_name>]`; for keyed secrets only the _value_ is replaced, so an
operator still sees that a secret appeared and which kind. Operator
`extra_patterns` are validated at startup — an invalid regex fails loudly rather
than being silently skipped.

`entropy_fallback` (off by default) additionally redacts unrecognised
high-entropy tokens. It is **noisy**: it trips on hashes, UUIDs, and base64 data,
so enable it only when false positives are acceptable.

## Tests

```sh
uv run pytest
```

## License

MIT
