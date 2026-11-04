# hardened-terminal-mcp

> **Newer project:** [safe-mcp-suite](https://github.com/Asaad-Suliman/safe-mcp-suite) combines this terminal server and the file organizer.

A security-hardened [MCP](https://modelcontextprotocol.io) server that lets an AI model run a small, explicitly allowlisted set of terminal commands — safely.

[![CI](https://github.com/Asaad-Suliman/hardened-terminal-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/Asaad-Suliman/hardened-terminal-mcp/actions/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests: 84 passing](https://img.shields.io/badge/tests-84%20passing-brightgreen)](tests/)
[![MCP](https://img.shields.io/badge/MCP-compatible-blueviolet)](https://modelcontextprotocol.io)

## Why

Giving a model raw shell access is dangerous: one crafted string can chain
commands, read secrets, or escape the working directory. This server turns
"let the model run commands" into a bounded, auditable operation instead of
an open door. Every command is checked against a deny-by-default policy,
run with no shell, jailed to one directory, time- and output-bounded, and
logged to an append-only audit trail before it is allowed to run.

## Demo

Real output, captured from a jail with `ls`, `cat`, `echo` allowlisted and `rm` denied:

```
>>> explain_command("ls -la")
{
  "ok": true,
  "code": "OK",
  "stdout": "",
  "stderr": "",
  "exit_code": null,
  "duration_ms": 0,
  "policy_reason": "command 'ls' is allowed"
}

>>> run_command("ls -la")
{
  "ok": true,
  "code": "OK",
  "stdout": "total 44\ndrwxrwxr-x  2 asaad asaad  4096 Jul 30 18:36 .\ndrwxrwxrwt 24 root  root  36864 Jul 30 18:36 ..\n",
  "stderr": "",
  "exit_code": 0,
  "duration_ms": 4,
  "policy_reason": "command 'ls' is allowed"
}

>>> run_command("rm -rf /")
{
  "ok": false,
  "code": "POLICY_DENIED",
  "stdout": "",
  "stderr": "",
  "exit_code": null,
  "duration_ms": 0,
  "policy_reason": "command 'rm' is on the denylist"
}

>>> run_command("cat /etc/passwd", cwd="/etc")
{
  "ok": false,
  "code": "CWD_ESCAPE",
  "stdout": "",
  "stderr": "",
  "exit_code": null,
  "duration_ms": 0,
  "policy_reason": "cwd escapes jail root: '/etc'"
}
```

## Quickstart

Requires Python 3.12+. Install with [uv](https://docs.astral.sh/uv/):

```sh
uv sync
```

Write a minimal `policy.toml`:

```toml
jail_root = "/srv/htmcp/sandbox"   # commands are jailed here; REQUIRED

[allowlist]
commands = ["ls", "cat", "echo"]

[denylist]
commands = ["rm"]
```

Register it with your MCP client:

```json
{
  "mcpServers": {
    "hardened-terminal": {
      "command": "uv",
      "args": ["run", "hardened-terminal-mcp"],
      "env": {
        "HTMCP_JAIL_ROOT": "/srv/htmcp/sandbox",
        "HTMCP_POLICY_FILE": "/srv/htmcp/policy.toml"
      }
    }
  }
}
```

## How it works

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

The audit log is a side branch, not on the return path: the attempt record is
written before the executor runs, and the outcome record after. `explain_command`
follows the same path with execution skipped.

## Security guarantees

| Guarantee | How it is enforced |
| --- | --- |
| Deny by default | Command name must be on the allowlist; denylist always wins; a name not listed is denied |
| No shell | `subprocess.run(argv, shell=False)` on a parsed argv; shell metacharacters (`; \| & < > \` $(...)`) rejected before any policy check |
| cwd jail | Requested cwd is resolved (normalising `..`, following symlinks) and must stay inside the jail root; else `CWD_ESCAPE` |
| Timeout | Wall-clock `timeout=` on the subprocess; on expiry the process is killed and `TIMEOUT` returned |
| Output caps | stdout/stderr byte-capped with a truncation marker; redaction runs before the cap so a secret can't be split |
| Env scrub | Child gets only an allowlisted env (`PATH`, `HOME`, `LANG`); parent secrets are dropped |
| Audit fail-closed | An attempt record is written before execution; if it can't be written under fail-closed, the command does not run (`AUDIT_UNAVAILABLE`) |
| Redaction | Secrets in output and in audit `command_raw`/`argv` are replaced with `[REDACTED:<kind>]` |

## Threat model

**Does not defend against (out of scope by design):**

- **A dangerous command you allowlisted.** If you allow an interpreter or a
  shell-like tool (`bash`, `python`, `sh`, `find -exec`, `awk`, `env`, …), the
  model can do anything that tool can. Policy strength is entirely the operator's
  allowlist.
- **Kernel / sandbox escapes.** The jail is a path-containment check, not a
  kernel sandbox — there are no namespaces, cgroups, or seccomp. A local-privilege
  or kernel exploit reachable from an allowlisted binary is not contained.
- **Host access to the audit log.** The trail is tamper-evident to the server,
  not tamper-proof. Anyone with filesystem access to `audit.jsonl` can read,
  alter, or delete it.
- **Redaction completeness.** Redaction is pattern-based and best-effort; a
  novel secret format the patterns don't recognise can pass through.

## Compared to a naive terminal MCP server

Many quick MCP servers wrap `subprocess.run(cmd, shell=True)`. That is convenient
and unsafe. This table is factual, not a claim of perfect security.

| Concern | `subprocess.run(shell=True)` | hardened-terminal-mcp |
| --- | --- | --- |
| Command surface | Any command the shell can parse | Only allowlisted names; denylist wins |
| Shell metacharacters | Interpreted (`;`, `\|`, `$()`, redirection) | Rejected before evaluation; no shell |
| Working directory | Wherever the process is | Pinned to a required jail root; escapes refused |
| Environment | Full parent env (secrets included) | Scrubbed to `PATH`/`HOME`/`LANG` |
| Secrets in output/args | Passed through | Pattern-redacted before return and before audit |
| Auditability | None by default | Append-only JSONL; fail-closed by default |

## Reference

<details>
<summary>Tool reference</summary>

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

</details>

<details>
<summary>ResultCode taxonomy</summary>

Each code maps to exactly one condition.

| Code | Meaning |
| --- | --- |
| `OK` | Executed and returned (`exit_code` carries the process result) |
| `POLICY_DENIED` | Denied by policy (list, arg rule, shell metacharacter, empty) |
| `PARSE_ERROR` | Command could not be parsed into an argv |
| `TIMEOUT` | Wall-clock timeout; the process was killed |
| `OUTPUT_TRUNCATED` | Ran, but output hit the byte cap |
| `CWD_ESCAPE` | Requested cwd escaped the jail root |
| `EXECUTOR_ERROR` | Allowed command couldn't run (not found, permission, etc.) |
| `AUDIT_UNAVAILABLE` | Fail-closed: the audit record couldn't be written; not run |
| `INTERNAL_ERROR` | Unexpected server error; generic message only, no traceback |

</details>

<details>
<summary>Environment variables</summary>

| Variable | Meaning | Default |
| --- | --- | --- |
| `HTMCP_POLICY_FILE` | Path to `policy.toml` | `policy.toml` |
| `HTMCP_JAIL_ROOT` | Jail directory (**required** via this or `jail_root`) | — (refuse if unset) |
| `HTMCP_AUDIT_LOG` | Audit trail path | `audit.jsonl` (from policy) |
| `HTMCP_AUDIT_FAIL_MODE` | `closed` or `open` | `closed` (from policy) |

Env values override the file. Startup fails loudly on a missing/invalid policy, an
unset or non-directory jail root, an invalid operator regex, or an audit log
located inside the jail root.

</details>

<details>
<summary>Full policy.toml reference</summary>

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

</details>

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
- **The jail is a path check, not a kernel sandbox.** Containment is a resolve +
  `is_relative_to` check on the cwd. There are no namespaces, cgroups, or seccomp.
  A process that can escape via a kernel bug or an allowlisted escape hatch is not
  contained. For stronger isolation, run the whole server inside a container/VM.
- **Policy strength is entirely the operator's allowlist.** The engine faithfully
  enforces what you configure. Allow `bash`, `python`, `env`, `find`, or any tool
  with `-exec`/eval semantics and you have handed over a general-purpose shell.
  Keep the allowlist minimal and argument-scoped.

## Testing

```sh
uv run pytest
```

84 tests, isolated with `tmp_path` (they never touch a real policy or audit log):

- `test_policy.py` (22) — deny-by-default, denylist-wins, case/spacing bypasses,
  metacharacter rejection, argument rules
- `test_executor.py` (7) — shell=False, timeout+kill, output cap, env scrub,
  cwd validation, refused commands
- `test_server.py` (16) — one test per `ResultCode`, both tools, envelope shape,
  cwd escapes, explain-never-executes
- `test_audit.py` (15) — attempt/outcome records, fail-closed vs fail-open,
  schema, no output content, redacted `command_raw`/`argv`, jail-root rules
- `test_redact.py` (23) — one case per pattern, no-false-positives (paths,
  SHAs, UUIDs, `cp -p`), entropy on/off, redaction before truncation
- `test_smoke.py` (1) — import/health smoke

CI runs the suite plus [gitleaks](https://github.com/gitleaks/gitleaks) on every
push and pull request (see `.github/workflows/ci.yml`).

## Related work

- [Asaad-Suliman/MCP-file-organizer](https://github.com/Asaad-Suliman/MCP-file-organizer)
  — a companion safe-MCP-server project applying the same deny-by-default,
  audited, least-privilege approach to filesystem operations.
- [Asaad-Suliman/safe-mcp-suite](https://github.com/Asaad-Suliman/safe-mcp-suite)
  — this server's successor: the terminal server and the file organizer
  rebuilt together on one shared, deny-by-default safety core.

## License

MIT — see [LICENSE](LICENSE).
