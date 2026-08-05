//! The MCP surface.
//!
//! Deliberately stateless at the transport layer: `stateful_mode` is off in
//! `main.rs`'s HTTP server, so there is no `mcp-session-id` and no
//! server-initiated push over a kept-open stream. Every tool call is a
//! self-contained HTTP request authenticated by the `x-bash-capability`
//! header (see `security.rs`). The actual state this server exists to hold
//! — running processes — lives in `process::Registry`, addressed by
//! `bash_id`, and outlives any single request or "session" by design: a job
//! started in one request is still running (and pollable/killable) from a
//! completely unrelated later request, possibly on a different transport
//! connection. That is the whole point of a *background* bash server, and it
//! was never a property of the MCP session in the first place.

use std::sync::Arc;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ContentBlock, ListToolsResult, PaginatedRequestParams,
    ServerCapabilities, ServerInfo,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{tool, tool_router, ErrorData as McpError};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::process::{Registry, WatchRequest, WatchTarget};
use crate::security::Security;

tokio::task_local! {
    /// The caller's owner string for the request currently being handled,
    /// scoped in for the duration of one `tool_router.call()` future. Not a
    /// session: re-derived from the request header on every single call.
    static REQUEST_OWNER: Option<String>;
}

fn current_owner() -> Option<String> {
    REQUEST_OWNER.try_with(Clone::clone).ok().flatten()
}

fn ok(s: impl Into<String>) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(s.into())])
}

fn fail(message: impl Into<String>) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message.into())])
}

#[derive(Debug, Deserialize, JsonSchema)]
struct RunArgs {
    /// Shell command, executed via `bash -c`.
    command: String,
    /// Working directory (absolute path). Omit to inherit the server's cwd.
    #[serde(default)]
    cwd: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct OutputArgs {
    /// `bash_id` returned by `bash_run` or `bash_watch`.
    bash_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct WatchArgs {
    /// Shell command, executed via `bash -c`.
    command: String,
    /// Regular expression tested against each output line.
    pattern: String,
    #[serde(default)]
    cwd: Option<String>,
    /// Which stream(s) to test: "stdout" | "stderr" | "both" (default "both").
    #[serde(default)]
    stream: Option<String>,
    /// Give up after this many seconds (default 3600, max 86400).
    #[serde(default)]
    timeout_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct KillArgs {
    /// `bash_id` to terminate.
    bash_id: String,
}

#[derive(Clone)]
pub struct BashServer {
    registry: Arc<Registry>,
    security: Security,
    tool_router: ToolRouter<Self>,
    /// Set once, at session-creation time, for transports that don't carry
    /// per-request `http::request::Parts` — i.e. the legacy `/sse` session
    /// (see `main.rs::sse_get`). The stateless `/mcp` path never needs this:
    /// it always has fresh `Parts` on every request instead.
    default_owner: Option<String>,
}

impl BashServer {
    pub fn new(registry: Arc<Registry>, security: Security) -> Self {
        Self::with_default_owner(registry, security, None)
    }

    pub fn with_default_owner(
        registry: Arc<Registry>,
        security: Security,
        default_owner: Option<String>,
    ) -> Self {
        Self {
            registry,
            security,
            tool_router: Self::tool_router(),
            default_owner,
        }
    }
}

#[tool_router(router = tool_router)]
impl BashServer {
    #[tool(
        description = "Start a long-running shell command in the background. Returns bash_id immediately. \
        Use only for commands expected to outlive the current turn/request. Poll with bash_output; \
        terminate early with bash_kill."
    )]
    async fn bash_run(
        &self,
        Parameters(a): Parameters<RunArgs>,
    ) -> Result<CallToolResult, McpError> {
        let owner = current_owner().unwrap_or_default();
        match self.registry.spawn(&owner, a.command, a.cwd, None).await {
            Ok(bash_id) => Ok(ok(
                serde_json::json!({ "bash_id": bash_id, "status": "started" }).to_string(),
            )),
            Err(e) => Ok(fail(spawn_error_message(e))),
        }
    }

    #[tool(
        description = "Poll incremental stdout/stderr since the last call for a background job. \
        Returns only new bytes plus exited/exitCode. dropped_bytes counts bytes that scrolled out of \
        the live window; read the spill file path for the complete output when that happens."
    )]
    async fn bash_output(
        &self,
        Parameters(a): Parameters<OutputArgs>,
    ) -> Result<CallToolResult, McpError> {
        let owner = current_owner().unwrap_or_default();
        let Some(handle) = self.registry.get(&a.bash_id).await else {
            return Ok(fail(format!("unknown bash_id: {}", a.bash_id)));
        };
        if handle.proc.owner != owner {
            return Ok(fail(format!("unknown bash_id: {}", a.bash_id)));
        }
        let stdout_from = *handle.stdout_cursor.lock().unwrap();
        let stderr_from = *handle.stderr_cursor.lock().unwrap();
        let (out, stdout_path) = {
            let stream = handle.proc.stdout.lock().await;
            (stream.read_since(stdout_from), stream.spill_path.clone())
        };
        let (err, stderr_path) = {
            let stream = handle.proc.stderr.lock().await;
            (stream.read_since(stderr_from), stream.spill_path.clone())
        };
        *handle.stdout_cursor.lock().unwrap() = out.next_cursor;
        *handle.stderr_cursor.lock().unwrap() = err.next_cursor;
        let exited = handle.proc.exited.load(std::sync::atomic::Ordering::SeqCst);
        let exit_code = *handle.proc.exit_code.lock().unwrap();
        Ok(ok(serde_json::json!({
            "bash_id": a.bash_id,
            "exited": exited,
            "exit_code": exit_code,
            "stdout": out.text,
            "stderr": err.text,
            "stdout_dropped": out.dropped_bytes,
            "stderr_dropped": err.dropped_bytes,
            // Only useful once dropped_bytes > 0 (the live window doesn't
            // hold the full history), but always returned when the spill
            // file exists so a caller doesn't have to guess the path.
            "stdout_path": stdout_path,
            "stderr_path": stderr_path,
        })
        .to_string()))
    }

    #[tool(
        description = "Start a background shell command and watch stdout/stderr for a regex match, \
        line by line. Stops the process as soon as `pattern` matches (or on timeout / natural exit) \
        and reports the outcome via bash_output. One-shot only; poll bash_output for the result."
    )]
    async fn bash_watch(
        &self,
        Parameters(a): Parameters<WatchArgs>,
    ) -> Result<CallToolResult, McpError> {
        let owner = current_owner().unwrap_or_default();
        let target = match a.stream.as_deref() {
            Some("stdout") => WatchTarget::Stdout,
            Some("stderr") => WatchTarget::Stderr,
            _ => WatchTarget::Both,
        };
        let watch = WatchRequest {
            pattern: a.pattern,
            target,
            timeout_seconds: a.timeout_seconds,
        };
        match self
            .registry
            .spawn(&owner, a.command, a.cwd, Some(watch))
            .await
        {
            Ok(bash_id) => Ok(ok(
                serde_json::json!({ "bash_id": bash_id, "status": "watching" }).to_string(),
            )),
            Err(e) => Ok(fail(spawn_error_message(e))),
        }
    }

    #[tool(
        description = "Terminate a background process (SIGTERM, then SIGKILL after 5s). Idempotent."
    )]
    async fn bash_kill(
        &self,
        Parameters(a): Parameters<KillArgs>,
    ) -> Result<CallToolResult, McpError> {
        let owner = current_owner().unwrap_or_default();
        let Some(handle) = self.registry.get(&a.bash_id).await else {
            return Ok(fail(format!("unknown bash_id: {}", a.bash_id)));
        };
        if handle.proc.owner != owner {
            return Ok(fail(format!("unknown bash_id: {}", a.bash_id)));
        }
        let killed = self.registry.kill(&a.bash_id).await.unwrap_or(false);
        Ok(ok(
            serde_json::json!({ "bash_id": a.bash_id, "killed": killed }).to_string(),
        ))
    }
}

fn spawn_error_message(e: crate::process::SpawnError) -> String {
    match e {
        crate::process::SpawnError::InvalidRegex(msg) => {
            format!("invalid regex in `pattern`: {msg}")
        }
        crate::process::SpawnError::Io(msg) => format!("failed to start process: {msg}"),
    }
}

impl rmcp::ServerHandler for BashServer {
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        // The `/mcp` (Streamable HTTP, stateless) path has fresh
        // `http::request::Parts` on every single call — rmcp injects them
        // into `context.extensions` regardless of stateful/stateless mode —
        // so every call re-authenticates itself from scratch here.
        //
        // The legacy `/sse` path has no per-call `Parts` at all (it's a bare
        // (Sink, Stream) transport fed by the axum SSE/`/message` handlers in
        // `main.rs`): that session was already authenticated once, at
        // `GET /sse` time, by the same middleware that guards `/mcp`, and
        // `self.default_owner` carries the owner that check approved. There
        // is nothing left to check per-call in that case.
        let owner = match context.extensions.get::<http::request::Parts>() {
            Some(parts) => {
                let identity = crate::security::resolve_identity(&parts.headers, parts.uri.query());
                if let Err(msg) = self
                    .security
                    .authorize(identity.capability.as_deref(), identity.owner.as_deref())
                {
                    return Ok(fail(msg));
                }
                identity.owner
            }
            None => self.default_owner.clone(),
        };

        REQUEST_OWNER
            .scope(owner, async {
                self.tool_router
                    .call(rmcp::handler::server::tool::ToolCallContext::new(
                        self, request, context,
                    ))
                    .await
            })
            .await
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult {
            tools: self.tool_router.list_all(),
            ..Default::default()
        })
    }

    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::new(ServerCapabilities::builder().enable_tools().build());
        info.server_info.name = "bash-rs".to_string();
        info.server_info.version = env!("CARGO_PKG_VERSION").to_string();
        info
    }
}
