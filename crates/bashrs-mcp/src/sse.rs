//! Legacy SSE transport (`GET /sse` + `POST /message`).
//!
//! Unlike `/mcp` (Streamable HTTP, stateless — see `main.rs::serve_http`),
//! this transport is *inherently* session-based: the open `GET /sse` stream
//! **is** the session by construction, there is no stateless variant of it.
//! Clients that only implement the older MCP SSE transport (Claude, Maestro
//! — see negotium's `mcp-config.ts::backgroundBashTransport`) go through
//! here.
//!
//! Security model: the capability header is checked once, by the same
//! `authorize_http` middleware that guards every other route, when the
//! stream is opened. From then on the session is protected by a random
//! per-session `message_token` handed to the client only inside that
//! already-authenticated stream (as the `endpoint` SSE event) — `/message`
//! itself is exempt from the capability check (see `security.rs`) precisely
//! because it is guarded by this token instead. This is the same shape as
//! `browser-rs-mcp`'s legacy SSE endpoint.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{OriginalUri, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use futures::channel::mpsc;
use futures::StreamExt;
use rand::RngCore;
use rmcp::model::{ClientJsonRpcMessage, ServerJsonRpcMessage};
use rmcp::ServiceExt;
use tokio::sync::Mutex;

use crate::process::Registry;
use crate::security::{request_owner, Security};
use crate::server::BashServer;

#[derive(Clone)]
struct SseSession {
    sender: mpsc::UnboundedSender<ClientJsonRpcMessage>,
    message_token: String,
}

type SseSessions = Arc<Mutex<HashMap<String, SseSession>>>;

#[derive(Clone)]
pub struct SseState {
    sessions: SseSessions,
    registry: Arc<Registry>,
    security: Security,
}

impl SseState {
    pub fn new(registry: Arc<Registry>, security: Security) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            registry,
            security,
        }
    }
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.as_bytes()
        .iter()
        .zip(right.as_bytes())
        .fold(0u8, |diff, (l, r)| diff | (l ^ r))
        == 0
}

struct SessionCleanup {
    sessions: SseSessions,
    session_id: String,
}

impl Drop for SessionCleanup {
    fn drop(&mut self) {
        let sessions = self.sessions.clone();
        let session_id = self.session_id.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                sessions.lock().await.remove(&session_id);
            });
        }
    }
}

struct SseSessionStream {
    inner: std::pin::Pin<
        Box<dyn futures::Stream<Item = Result<Event, std::convert::Infallible>> + Send>,
    >,
    _cleanup: SessionCleanup,
}

impl futures::Stream for SseSessionStream {
    type Item = Result<Event, std::convert::Infallible>;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

pub async fn sse_get(
    State(state): State<SseState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Sse<impl futures::Stream<Item = Result<Event, std::convert::Infallible>>> {
    // The auth middleware already rejected this request if the capability
    // was wrong; here we only need the owner it approved, to scope the new
    // session's `bash_id` registry access (see `server.rs::default_owner`).
    let owner = {
        let mut req = axum::extract::Request::new(axum::body::Body::empty());
        *req.headers_mut() = headers.clone();
        *req.uri_mut() = uri.clone();
        request_owner(&req)
    };

    let session_id = random_token();
    let message_token = random_token();

    // server -> client (rmcp writes here; the SSE stream drains it to the client)
    let (to_client_tx, to_client_rx) = mpsc::unbounded::<ServerJsonRpcMessage>();
    // client -> server (POST /message pushes here; rmcp reads it as the client's half)
    let (from_client_tx, from_client_rx) = mpsc::unbounded::<ClientJsonRpcMessage>();

    state.sessions.lock().await.insert(
        session_id.clone(),
        SseSession {
            sender: from_client_tx,
            message_token: message_token.clone(),
        },
    );

    let registry = state.registry.clone();
    let security = state.security.clone();
    let sid = session_id.clone();
    tokio::spawn(async move {
        let server = BashServer::with_default_owner(registry, security, owner);
        match server.serve((to_client_tx, from_client_rx)).await {
            Ok(running) => {
                let _ = running.waiting().await;
            }
            Err(e) => tracing::warn!("sse session {sid} serve error: {e}"),
        }
    });

    let endpoint_session_id = session_id.clone();
    let endpoint = futures::stream::once(async move {
        Ok::<_, std::convert::Infallible>(Event::default().event("endpoint").data(format!(
            "/message?sessionId={endpoint_session_id}&token={message_token}"
        )))
    });
    let messages = to_client_rx.map(|msg| {
        let data = serde_json::to_string(&msg).unwrap_or_default();
        Ok::<_, std::convert::Infallible>(Event::default().event("message").data(data))
    });

    let stream = SseSessionStream {
        inner: Box::pin(endpoint.chain(messages)),
        _cleanup: SessionCleanup {
            sessions: state.sessions,
            session_id,
        },
    };
    Sse::new(stream).keep_alive(KeepAlive::default())
}

pub async fn sse_post(
    State(state): State<SseState>,
    Query(params): Query<HashMap<String, String>>,
    body: String,
) -> StatusCode {
    let Some(session_id) = params.get("sessionId") else {
        return StatusCode::BAD_REQUEST;
    };
    let Some(token) = params.get("token") else {
        return StatusCode::UNAUTHORIZED;
    };
    let session = state.sessions.lock().await.get(session_id).cloned();
    let Some(session) = session else {
        return StatusCode::NOT_FOUND;
    };
    if !constant_time_eq(token, &session.message_token) {
        return StatusCode::UNAUTHORIZED;
    }
    let msg: ClientJsonRpcMessage = match serde_json::from_str(&body) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("sse /message bad payload: {e}");
            return StatusCode::BAD_REQUEST;
        }
    };
    if session.sender.unbounded_send(msg).is_err() {
        state.sessions.lock().await.remove(session_id);
        return StatusCode::GONE;
    }
    StatusCode::ACCEPTED
}
