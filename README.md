# bash-rs-mcp

A background-bash MCP server in Rust — the sibling of
[browser-rs-mcp](https://github.com/maestrojeong/browser-rs-mcp), same
`rmcp` + `axum` + HMAC-capability stack, different domain (shell processes
instead of a CDP-driven browser).

## What it does

Four tools:

- `bash_run` — start a shell command in the background, get a `bash_id` back immediately.
- `bash_output` — poll incremental stdout/stderr for a `bash_id` since the last call.
- `bash_watch` — start a command and stop it the moment a regex matches a line of output.
- `bash_kill` — SIGTERM (then SIGKILL after 5s) a running job.

Jobs are addressed by `bash_id` and live in a process-global registry —
independent of whatever MCP connection started them. That's the whole point
of a *background* bash server: the job outlives the request.

## Transports

| Path | Transport | Mode |
|---|---|---|
| `/mcp` | Streamable HTTP | **stateless** (`NeverSessionManager`, no `mcp-session-id`) |
| `/sse` + `/message` | legacy SSE | session-based (inherent to the transport — see below) |
| stdio | stdio | n/a (one process per client) |

`/mcp` is stateless because nothing this server does actually needs an MCP
session: every tool call re-authenticates itself via the `x-bash-capability`
header, and the real state (running processes) lives in a registry keyed by
`bash_id`, not by session.

`/sse` exists only for clients that don't yet speak Streamable HTTP. Legacy
SSE has no stateless variant — the open `GET /sse` stream *is* the session by
construction — so that path is authenticated once at connect time and then
guarded by a random per-session `message_token` instead of re-checking the
capability on every `POST /message`.

Both transports share one process-wide `Registry`, so a job started through
one is visible (and killable) through the other.

## Security

Set `BASHRS_HTTP_CAPABILITY` to a root secret before binding to anything but
loopback. Every caller then also sends `X-Bash-Owner: <tenant>`; the
capability they must present is `HMAC-SHA256(root, owner)` in
`X-Bash-Capability`. This is deliberately request-scoped, not
session-scoped — see `crates/bashrs-mcp/src/security.rs`.

## Build

```sh
cargo build --release -p bashrs-mcp
```

Binary: `target/release/bash-rs`.

```sh
bash-rs            # stdio
bash-rs 9800        # http, binds 127.0.0.1:9800
bash-rs 0.0.0.0:9800  # http, explicit bind address
```
