# hardened-terminal-mcp

A security-hardened [MCP](https://modelcontextprotocol.io) server that lets an AI
model run a **small, explicitly allowlisted** set of terminal commands — safely.

Giving a model raw shell access is dangerous: one crafted string can chain
commands, read secrets, or escape the working directory. This server exists to
make "let the model run commands" a bounded, auditable operation instead of an
open door. Commands are matched against a deny-by-default policy, executed with
**no shell**, jailed to one directory, time- and output-bounded, run with a
scrubbed environment, redacted of secrets, and recorded to an append-only audit
trail — before any command is allowed to run.

## Security guarantees

| Guarantee             | How it is enforced                                                                                                                        | Where in code                                                        |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| **Deny by default**   | Command name must be on the allowlist; denylist always wins; a name not listed is denied                                                  | `policy.explain` (`policy.py`), lists in `config.py` / `policy.toml` |
| **No shell**          | `subprocess.run(argv, shell=False)` on a parsed argv; shell metacharacters (`; \| & < > \` $(...)`) rejected before any policy check      | `executor.run` (`executor.py`), `_find_metacharacter` (`policy.py`)  |
| **cwd jail**          | Requested cwd is resolved (normalising `..`, following symlinks) and must stay inside the jail root; else `CWD_ESCAPE`                    | `_resolve_cwd` (`server.py`)                                         |
| **Timeout**           | Wall-clock `timeout=` on the subprocess; on expiry the process is killed and `TIMEOUT` returned                                           | `executor.run` (`executor.py`)                                       |
| **Output caps**       | stdout/stderr byte-capped with a truncation marker; redaction runs _before_ the cap so a secret can't be split                            | `_finalize` / `_cap` (`executor.py`)                                 |
| **Env scrub**         | Child gets only an allowlisted env (`PATH`, `HOME`, `LANG`); parent secrets are dropped                                                   | `_child_env` (`executor.py`)                                         |
| **Audit fail-closed** | An attempt record is written _before_ execution; if it can't be written under fail-closed, the command does not run (`AUDIT_UNAVAILABLE`) | `_serve` / `_audit` (`server.py`), `AuditLogger` (`audit.py`)        |
| **Redaction**         | Secrets in output and in audit `command_raw`/`argv` are replaced with `[REDACTED:<kind>]`                                                 | `redact.py`, `_REDACTOR` wiring in `server.py`                       |

## Architecture

```mermaid
flowchart LR
    client([MCP client / model]) -->|run_command / explain_command| server[server.py]
    server -->|explain| policy[policy engine<br/>deny-by-default, no shell]
    policy -->|deny| result[CommandResult envelope]
    policy -->|allow| jail{cwd inside jail?}
    jail -->|escape| result
    jail -->|ok| exec[executor<br/>shell=False, env scrub, timeout, cap]
    exec --> redact[redaction<br/>before truncation]
    redact --> result
    result --> client

    server -. attempt record<br/>BEFORE execution .-> audit[(append-only<br/>audit.jsonl)]
    server -. outcome record<br/>AFTER execution .-> audit
```

The audit log is a side branch, not on the return path: the **attempt** record is
written before the executor runs (the fail-closed gate), and the **outcome**
record after. `explain_command` follows the same path with execution skipped.

## Threat model

**Defends against:**

- **Command injection / chaining.** No shell is ever invoked; metacharacters are
  rejected pre-policy, so `;`, `|`, `$(...)`, backticks and redirection can't
  smuggle a second command.
- **Running unlisted commands.** Deny-by-default: anything not explicitly
  allowlisted is refused, and the denylist overrides the allowlist.
- **Directory escape.** A command can't `cd` or path-traverse (`..`, symlinks,
  absolute paths) out of the configured jail root.
- **Runaway / resource exhaustion.** Wall-clock timeout with process kill; output
  is byte-capped.
- **Ambient secret leakage.** The child process environment is scrubbed to a tiny
  allowlist, so API keys/tokens in the parent env never reach the command.
- **Secret echo.** Recognised secrets are redacted from output and from the audit
  record before either is stored or returned.
- **Silent/unlogged execution.** Under fail-closed, a command that can't be
  audited does not run.

**Does NOT defend against (out of scope by design):**

- **A dangerous command you allowlisted.** If you allow an interpreter or a
  shell-like tool (`bash`, `python`, `sh`, `find -exec`, `awk`, `env`, …), the
  model can do anything that tool can. Policy strength is entirely the operator's
  allowlist.
- **Kernel / sandbox escapes.** The jail is a path-containment check, not a
  kernel sandbox — there are no namespaces, cgroups, or seccomp. A local-privilege
  or kernel exploit reachable from an allowlisted binary is not contained.
- **Host access to the audit log.** The trail is tamper-_evident_ to the server,
  not tamper-_proof_. Anyone with filesystem access to `audit.jsonl` can read,
  alter, or delete it.
- **Redaction completeness.** Redaction is pattern-based and best-effort; a
  novel secret format the patterns don't recognise can pass through.

## Compared to a naive terminal MCP server

Many quick MCP servers wrap `subprocess.run(cmd, shell=True)`. That is convenient
and unsafe. This table is factual, not a claim of perfect security.

| Concern                | `subprocess.run(shell=True)`                | hardened-terminal-mcp                           |
| ---------------------- | ------------------------------------------- | ----------------------------------------------- |
| Command surface        | Any command the shell can parse             | Only allowlisted names; denylist wins           |
| Shell metacharacters   | Interpreted (`;`, `\|`, `$()`, redirection) | Rejected before evaluation; no shell            |
| Argument handling      | Re-parsed by the shell                      | Pre-parsed argv, passed verbatim                |
| Working directory      | Wherever the process is                     | Pinned to a required jail root; escapes refused |
| Runaway commands       | Runs until it finishes                      | Wall-clock timeout + kill                       |
| Output size            | Unbounded                                   | Byte-capped with a marker                       |
| Environment            | Full parent env (secrets included)          | Scrubbed to `PATH`/`HOME`/`LANG`                |
| Secrets in output/args | Passed through                              | Pattern-redacted before return and before audit |
| Auditability           | None by default                             | Append-only JSONL; fail-closed by default       |
| Failure surface        | Tracebacks may reach the client             | Errors are typed data; no traceback leaks       |

## Install & configuration

Requires Python 3.12+. Install with [uv](https://docs.astral.sh/uv/):

```sh
uv sync
```

### policy.toml

```toml
# jail_root is REQUIRED (here or via HTMCP_JAIL_ROOT). Keep the audit log OUTSIDE it.
jail_root = "/srv/htmcp/sandbox"

audit_log = "/var/log/htmcp/audit.jsonl"
audit_fail_mode = "closed"   # "closed" = don't run if unloggable; "open" = run + warn

[allowlist]
commands = ["ls", "cat", "echo", "git"]

[denylist]
commands = ["rm", "shutdown", "curl"]   # denylist always wins

# Allowed in general, denied for specific argument patterns (order-independent).
[[rules]]
command = "git"
deny_args = ["push --force", "push -f"]
reason = "force-push rewrites shared history"

[redaction]
enabled = true
entropy_fallback = false   # noisy on hashes/UUIDs/base64 — see Caveats
extra_patterns = []        # e.g. [{ name = "internal_id", regex = "INT-[0-9]{8}" }]
```

### Environment variables

| Variable                | Meaning                                               | Default                     |
| ----------------------- | ----------------------------------------------------- | --------------------------- |
| `HTMCP_POLICY_FILE`     | Path to `policy.toml`                                 | `policy.toml`               |
| `HTMCP_JAIL_ROOT`       | Jail directory (**required** via this or `jail_root`) | — (refuse if unset)         |
| `HTMCP_AUDIT_LOG`       | Audit trail path                                      | `audit.jsonl` (from policy) |
| `HTMCP_AUDIT_FAIL_MODE` | `closed` or `open`                                    | `closed` (from policy)      |

Env values override the file. Startup fails loudly on a missing/invalid policy, an
unset or non-directory jail root, an invalid operator regex, or an audit log
located inside the jail root.

### MCP client config

Register it like any stdio MCP server (example shape):

```json
{
  "mcpServers": {
    "hardened-terminal": {
      "command": "uv",
      "args": ["run", "hardened-terminal-mcp"],
      "env": {
        "HTMCP_JAIL_ROOT": "/srv/htmcp/sandbox",
        "HTMCP_POLICY_FILE": "/etc/htmcp/policy.toml"
      }
    }
  }
}
```

## Tool reference

Both tools return a `CommandResult`:

```
CommandResult {
  ok: bool                 # true only for OK / OUTPUT_TRUNCATED
  code: ResultCode         # see taxonomy below
  stdout: str              # redacted; empty for explain / non-executing paths
  stderr: str              # redacted
  exit_code: int | null    # process exit code; null when nothing ran
  duration_ms: int
  policy_reason: str | null  # human-readable allow/deny reason
}
```

- **`run_command(command: str, cwd: str | None = None)`** — evaluate `command`
  against policy and, if allowed, run it sandboxed. `cwd` (if given) must resolve
  inside the jail root, else `CWD_ESCAPE`. Every call is audited.
- **`explain_command(command: str)`** — dry run: return the policy verdict only,
  with empty `stdout`/`stderr` and `exit_code = null`. It never reaches the
  executor.

### ResultCode taxonomy

Each code maps to exactly one condition.

| Code                | Meaning                                                        |
| ------------------- | -------------------------------------------------------------- |
| `OK`                | Executed and returned (`exit_code` carries the process result) |
| `POLICY_DENIED`     | Denied by policy (list, arg rule, shell metacharacter, empty)  |
| `PARSE_ERROR`       | Command could not be parsed into an argv                       |
| `TIMEOUT`           | Wall-clock timeout; the process was killed                     |
| `OUTPUT_TRUNCATED`  | Ran, but output hit the byte cap                               |
| `CWD_ESCAPE`        | Requested cwd escaped the jail root                            |
| `EXECUTOR_ERROR`    | Allowed command couldn't run (not found, permission, etc.)     |
| `AUDIT_UNAVAILABLE` | Fail-closed: the audit record couldn't be written; not run     |
| `INTERNAL_ERROR`    | Unexpected server error; generic message only, no traceback    |

## Honest caveats

This is a hardening layer, not a vault. Read these before deploying.

- **Redaction is best-effort, not a guarantee.** It is regex/pattern-based. It
  catches common secret shapes (see the pattern list) but a novel or unusual
  format will pass through. Do not rely on it as your only secret control, and do
  not allowlist commands that print secrets you can't afford to leak.
- **The audit log is tamper-evident, not tamper-proof.** The server writes
  append-only with per-record flush+fsync, so it won't lose records to a crash.
  But anyone with host filesystem access can read, edit, or delete `audit.jsonl`.
  Protect it with OS permissions and ship it off-host if you need integrity.
- **No log rotation.** The audit trail grows without bound; rotating, compressing,
  and retaining it is the operator's responsibility (e.g. `logrotate`).
- **The jail is a path check, not a kernel sandbox.** Containment is a resolve +
  `is_relative_to` check on the cwd. There are no namespaces, cgroups, or seccomp.
  A process that can escape via a kernel bug or an allowlisted escape hatch is not
  contained. For stronger isolation, run the whole server inside a container/VM.
- **Policy strength is entirely the operator's allowlist.** The engine faithfully
  enforces what you configure. Allow `bash`, `python`, `env`, `find`, or any tool
  with `-exec`/eval semantics and you have handed over a general-purpose shell.
  Keep the allowlist minimal and argument-scoped.
- **Short flags aren't redacted by default.** `cli_flag` matches long forms only
  (`--password`, `--token`, `--secret`, `--api-key`, `--apikey`) because a bare
  `-p` means something else in `cp`/`ssh`/etc. Re-add short flags for your tools
  via `redaction.extra_patterns`.

## Testing

```sh
uv run pytest
```

84 tests, isolated with `tmp_path` (they never touch a real policy or audit log):

| Suite                  | Covers                                                                                                                                                |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `test_policy.py` (22)  | Deny-by-default, denylist-wins, case/spacing bypasses, metacharacter rejection, argument rules                                                        |
| `test_executor.py` (7) | shell=False, timeout+kill, output cap, env scrub, cwd validation, refused commands                                                                    |
| `test_server.py` (16)  | One test per `ResultCode`, both tools, envelope shape, cwd escapes, explain-never-executes                                                            |
| `test_audit.py` (15)   | Attempt/outcome records, fail-closed vs fail-open, schema, no output content, redacted `command_raw`/`argv`, jail-root rules                          |
| `test_redact.py` (23)  | One case per pattern, no-false-positives (paths, SHAs, UUIDs, `cp -p`), entropy on/off, redaction before truncation, invalid extra-regex fails loudly |
| `test_smoke.py` (1)    | Import/health smoke                                                                                                                                   |

CI runs the suite plus [gitleaks](https://github.com/gitleaks/gitleaks) on every
push and pull request (see `.github/workflows/ci.yml`).

## Related work

- [Asaad-Suliman/MCP-file-organizer](https://github.com/Asaad-Suliman/MCP-file-organizer)
  — a companion safe-MCP-server project applying the same deny-by-default,
  audited, least-privilege approach to filesystem operations.

## License

MIT — see [LICENSE](LICENSE).
