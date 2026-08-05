//! Stateless request auth.
//!
//! There is no session concept in this server (see `server.rs` module docs
//! for why). Every single request must carry a valid capability header; there
//! is nothing to bind a session to, and nothing to hijack, because nothing
//! persists between requests except the process/registry state addressed by
//! `bash_id` — which itself is only reachable by a caller who already holds
//! the right capability.

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub const CAPABILITY_HEADER: &str = "x-bash-capability";
pub const OWNER_HEADER: &str = "x-bash-owner";

/// Root secret the process was started with. `None` means "no auth" — only
/// acceptable when bound to loopback (enforced by `main.rs` at startup).
#[derive(Clone)]
pub struct Security {
    root_capability: Option<std::sync::Arc<str>>,
}

impl Security {
    pub fn from_env() -> anyhow::Result<Self> {
        let root_capability = std::env::var("BASHRS_HTTP_CAPABILITY")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .map(std::sync::Arc::<str>::from);
        // Prevent child processes (the spawned bash commands themselves) from
        // inheriting the server's own credential.
        std::env::remove_var("BASHRS_HTTP_CAPABILITY");
        Ok(Self { root_capability })
    }

    pub fn requires_auth(&self) -> bool {
        self.root_capability.is_some()
    }

    /// Every owner gets its own derived capability so one topic/tenant cannot
    /// address another topic's `bash_id`s even if it guesses them.
    pub fn owner_capability(&self, owner: &str) -> Option<String> {
        self.root_capability
            .as_deref()
            .map(|root| derive_owner_capability(root, owner))
    }

    pub fn authorize(&self, provided: Option<&str>, owner: Option<&str>) -> Result<(), &'static str> {
        let Some(root) = self.root_capability.as_deref() else {
            return Ok(()); // unmanaged / loopback-only mode
        };
        let owner = owner.ok_or("x-bash-owner is required in managed mode")?;
        let expected = derive_owner_capability(root, owner);
        if provided.is_some_and(|value| constant_time_eq(value, &expected)) {
            Ok(())
        } else {
            Err("invalid bash capability")
        }
    }
}

pub fn derive_owner_capability(root: &str, owner: &str) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(root.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(owner.as_bytes());
    hex_lower(&mac.finalize().into_bytes())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.as_bytes()
        .iter()
        .zip(right.as_bytes())
        .fold(0_u8, |diff, (l, r)| diff | (l ^ r))
        == 0
}

pub fn request_owner(request: &Request) -> Option<String> {
    let header_owner = request
        .headers()
        .get(OWNER_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let query_owner = request.uri().query().and_then(|query| {
        url::form_urlencoded::parse(query.as_bytes())
            .find(|(key, _)| key == "owner")
            .map(|(_, value)| value.into_owned())
    });
    header_owner
        .or(query_owner)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty() && v.len() <= 256)
}

fn unauthorized(message: &'static str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "ok": false, "error": message })),
    )
        .into_response()
}

/// Per-request auth for everything except `/health` (public) and `/message`
/// (protected instead by the per-SSE-session `message_token` handed out only
/// over an already-authenticated `/sse` stream — see `main.rs::sse_get`).
///
/// No session binding here: unlike `browser-rs-mcp`, there is nothing that
/// needs a `mcp-session-id` -> owner map, because the Streamable HTTP side
/// (`/mcp`) runs `NeverSessionManager` (no session id exists to bind) and the
/// legacy SSE side (`/sse`) already gets an equivalent guarantee from the
/// unguessable `message_token`.
pub async fn authorize_http(security: Security, request: Request, next: Next) -> Response {
    let path = request.uri().path().to_string();
    if path == "/health" || path == "/message" {
        return next.run(request).await;
    }
    let provided = request
        .headers()
        .get(CAPABILITY_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let owner = request_owner(&request);
    if let Err(message) = security.authorize(provided.as_deref(), owner.as_deref()) {
        return unauthorized(message);
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_owner_same_capability() {
        let a = derive_owner_capability("root", "topic-1");
        let b = derive_owner_capability("root", "topic-1");
        assert_eq!(a, b);
    }

    #[test]
    fn different_owner_different_capability() {
        let a = derive_owner_capability("root", "topic-1");
        let b = derive_owner_capability("root", "topic-2");
        assert_ne!(a, b);
    }

    #[test]
    fn authorize_rejects_wrong_capability() {
        let sec = Security {
            root_capability: Some("root-secret".into()),
        };
        assert!(sec.authorize(Some("nope"), Some("owner-a")).is_err());
        let good = derive_owner_capability("root-secret", "owner-a");
        assert!(sec.authorize(Some(&good), Some("owner-a")).is_ok());
    }
}
