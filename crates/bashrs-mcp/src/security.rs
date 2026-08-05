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

// Three call conventions are accepted, checked in this priority order — see
// each block in `resolve_identity` for which host uses which:
//
// 1. negotium: `X-Background-Bash-User` + `X-Background-Bash-Topic` headers
//    (or, when the client can't set custom SSE headers — maestro-agent-sdk —
//    the same two values as `?user=&topic=` query params instead), owner =
//    `${user}\0${topic}` (NUL-joined, byte-for-byte the same input negotium's
//    own `deriveBgBashContextCapability` hashes — see
//    `packages/core/src/platform/background-bash/context.ts` — so a root
//    secret shared with that daemon produces an identical capability here).
// 2. clawgram: `?topic=&groupId=` query params, no capability required (that
//    host runs one bash-rs-mcp process per user and relies on the OS process
//    boundary for isolation instead of a per-request secret).
// 3. generic / standalone: `X-Bash-Owner` header or `?owner=` query param —
//    what you get running this server directly, e.g. by hand over curl.
pub const CAPABILITY_HEADER: &str = "x-bash-capability";
pub const OWNER_HEADER: &str = "x-bash-owner";
const NEGOTIUM_USER_HEADER: &str = "x-background-bash-user";
const NEGOTIUM_TOPIC_HEADER: &str = "x-background-bash-topic";
const NEGOTIUM_CAPABILITY_HEADER: &str = "x-background-bash-capability";

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

    pub fn authorize(
        &self,
        provided: Option<&str>,
        owner: Option<&str>,
    ) -> Result<(), &'static str> {
        let Some(root) = self.root_capability.as_deref() else {
            return Ok(()); // unmanaged / loopback-only mode
        };
        let owner = owner.ok_or("an owner (see resolve_identity) is required in managed mode")?;
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

pub struct Identity {
    pub owner: Option<String>,
    pub capability: Option<String>,
}

fn header_str<'a>(headers: &'a http::HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn query_param(query: Option<&str>, key: &str) -> Option<String> {
    query.and_then(|q| {
        url::form_urlencoded::parse(q.as_bytes())
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
    })
}

fn clean(value: String) -> Option<String> {
    let value = value.trim().to_string();
    (!value.is_empty() && value.len() <= 256).then_some(value)
}

/// Resolve (owner, provided-capability) from a request's headers + raw query
/// string, trying each supported call convention in turn. See the constants
/// above for what each convention looks like on the wire.
pub fn resolve_identity(headers: &http::HeaderMap, query: Option<&str>) -> Identity {
    // 1. negotium
    if let (Some(user), Some(topic)) = (
        header_str(headers, NEGOTIUM_USER_HEADER),
        header_str(headers, NEGOTIUM_TOPIC_HEADER),
    ) {
        let owner = format!("{user}\0{topic}");
        let capability = header_str(headers, NEGOTIUM_CAPABILITY_HEADER)
            .or_else(|| header_str(headers, CAPABILITY_HEADER))
            .map(str::to_string);
        return Identity {
            owner: clean(owner),
            capability,
        };
    }

    // 1b. negotium, via query params instead of headers — maestro-agent-sdk
    // can't set custom SSE headers, so negotium's `backgroundBashTransport`
    // puts the same three values in `?user=&topic=&capability=` for that
    // agent only. Must be checked before clawgram's query-param branch
    // below: clawgram never sends `user`, so its presence disambiguates.
    if let (Some(user), Some(topic)) = (query_param(query, "user"), query_param(query, "topic")) {
        let owner = format!("{user}\0{topic}");
        return Identity {
            owner: clean(owner),
            capability: query_param(query, "capability"),
        };
    }

    // 2. clawgram
    if let Some(topic) = query_param(query, "topic") {
        let owner = match query_param(query, "groupId") {
            Some(group_id) => format!("{topic}\0{group_id}"),
            None => topic,
        };
        let capability = header_str(headers, CAPABILITY_HEADER).map(str::to_string);
        return Identity {
            owner: clean(owner),
            capability,
        };
    }

    // 3. generic / standalone
    let owner = header_str(headers, OWNER_HEADER)
        .map(str::to_string)
        .or_else(|| query_param(query, "owner"));
    let capability = header_str(headers, CAPABILITY_HEADER).map(str::to_string);
    Identity {
        owner: owner.and_then(clean),
        capability,
    }
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
    let query = request.uri().query().map(str::to_string);
    let identity = resolve_identity(request.headers(), query.as_deref());
    if let Err(message) =
        security.authorize(identity.capability.as_deref(), identity.owner.as_deref())
    {
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

    /// Cross-checked against `openssl dgst -sha256 -hmac root-secret` over
    /// the literal bytes `user-1\x00topic-1`, i.e. exactly what negotium's
    /// `deriveBgBashContextCapability(root, "user-1", "topic-1")` hashes
    /// (`packages/core/src/platform/background-bash/context.ts`). If this
    /// ever fails, the negotium and bash-rs-mcp daemons have silently
    /// diverged on the wire format and no shared root secret will work.
    #[test]
    fn negotium_owner_capability_matches_node_hmac_sha256() {
        assert_eq!(
            derive_owner_capability("root-secret", "user-1\0topic-1"),
            "bd08aabfab02b1ccf1d5b67ade6e55c628b2e9b27d40cfd480376640613fbb7e"
        );
    }

    fn headers(pairs: &[(&str, &str)]) -> http::HeaderMap {
        let mut map = http::HeaderMap::new();
        for (k, v) in pairs {
            map.insert(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                http::HeaderValue::from_str(v).unwrap(),
            );
        }
        map
    }

    #[test]
    fn resolve_identity_negotium_convention() {
        let h = headers(&[
            (NEGOTIUM_USER_HEADER, "user-1"),
            (NEGOTIUM_TOPIC_HEADER, "topic-1"),
            (NEGOTIUM_CAPABILITY_HEADER, "cap-abc"),
        ]);
        let id = resolve_identity(&h, None);
        assert_eq!(id.owner.as_deref(), Some("user-1\0topic-1"));
        assert_eq!(id.capability.as_deref(), Some("cap-abc"));
    }

    #[test]
    fn resolve_identity_negotium_convention_via_query_params() {
        // maestro-agent-sdk can't set custom SSE headers, so negotium falls
        // back to `?user=&topic=&capability=` for that agent only.
        let h = headers(&[]);
        let id = resolve_identity(&h, Some("user=user-1&topic=topic-1&capability=cap-abc"));
        assert_eq!(id.owner.as_deref(), Some("user-1\0topic-1"));
        assert_eq!(id.capability.as_deref(), Some("cap-abc"));
    }

    #[test]
    fn resolve_identity_negotium_query_params_take_priority_over_clawgram() {
        // clawgram never sends `user`; its presence here must not be
        // misread as the clawgram (topic-only) convention.
        let h = headers(&[]);
        let id = resolve_identity(&h, Some("user=u&topic=t"));
        assert_eq!(id.owner.as_deref(), Some("u\0t"));
    }

    #[test]
    fn resolve_identity_clawgram_convention() {
        let h = headers(&[]);
        let id = resolve_identity(&h, Some("topic=t1&groupId=42"));
        assert_eq!(id.owner, Some(format!("t1\0{}", 42)));
        assert_eq!(id.capability, None);
    }

    #[test]
    fn resolve_identity_clawgram_convention_without_group() {
        let h = headers(&[]);
        let id = resolve_identity(&h, Some("topic=t1"));
        assert_eq!(id.owner.as_deref(), Some("t1"));
    }

    #[test]
    fn resolve_identity_generic_convention() {
        let h = headers(&[(OWNER_HEADER, "owner-a"), (CAPABILITY_HEADER, "cap-xyz")]);
        let id = resolve_identity(&h, None);
        assert_eq!(id.owner.as_deref(), Some("owner-a"));
        assert_eq!(id.capability.as_deref(), Some("cap-xyz"));
    }

    #[test]
    fn resolve_identity_generic_convention_via_query() {
        let h = headers(&[]);
        let id = resolve_identity(&h, Some("owner=owner-b"));
        assert_eq!(id.owner.as_deref(), Some("owner-b"));
    }
}
