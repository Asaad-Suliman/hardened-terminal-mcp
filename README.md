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

| Code               | Meaning                                                     |
| ------------------ | ----------------------------------------------------------- |
| `OK`               | Executed and returned (`exit_code` carries the result).     |
| `POLICY_DENIED`    | Denied by policy (list, arg rule, metacharacter, empty).    |
| `PARSE_ERROR`      | Command could not be parsed into an argv.                   |
| `TIMEOUT`          | Wall-clock timeout; process killed.                         |
| `OUTPUT_TRUNCATED` | Ran, but output hit the cap.                                |
| `CWD_ESCAPE`       | `cwd` escaped the jail root.                                |
| `EXECUTOR_ERROR`   | Allowed command couldn't run (not found, permission, etc.). |
| `INTERNAL_ERROR`   | Unexpected server error; generic message only.              |

## Tests

```sh
uv run pytest
```

## License

MIT
