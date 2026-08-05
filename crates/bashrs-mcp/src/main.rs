mod journal;
mod process;
mod security;
mod server;
mod sse;

use std::sync::Arc;

use process::Registry;
use security::Security;
use server::BashServer;
use sse::SseState;

fn spill_root() -> std::path::PathBuf {
    std::env::var("BASHRS_SPILL_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("bash-rs-mcp"))
}

fn bind_address_is_loopback(bind: &str) -> bool {
    let Some((host, _port)) = bind.rsplit_once(':') else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|addr| addr.is_loopback())
}

async fn serve_stdio() -> anyhow::Result<()> {
    use rmcp::ServiceExt;
    let registry = Registry::new(spill_root());
    registry.recover().await;
    let security = Security::from_env()?;
    let server = BashServer::new(registry, security);
    let service = server.serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}

async fn serve_http(addr: &str) -> anyhow::Result<()> {
    use rmcp::transport::streamable_http_server::{
        session::never::NeverSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    };

    let bind = if addr.contains(':') {
        addr.to_string()
    } else {
        format!("127.0.0.1:{addr}")
    };

    let security = Security::from_env()?;
    if !security.requires_auth() && !bind_address_is_loopback(&bind) {
        anyhow::bail!("BASHRS_HTTP_CAPABILITY is required when binding outside loopback");
    }

    let registry = Registry::new(spill_root());
    registry.recover().await;

    // Stateless by design: no `mcp-session-id`, no server-initiated push
    // over a kept-open stream. Every request re-authenticates itself and
    // reaches the same process-global `registry` — see `server.rs`.
    let config = StreamableHttpServerConfig::default().with_stateful_mode(false);

    let factory_registry = registry.clone();
    let factory_security = security.clone();
    let service: StreamableHttpService<BashServer, NeverSessionManager> =
        StreamableHttpService::new(
            move || {
                Ok(BashServer::new(
                    factory_registry.clone(),
                    factory_security.clone(),
                ))
            },
            Arc::new(NeverSessionManager::default()),
            config,
        );

    // `/mcp` is stateless (above); `/sse` + `/message` is the legacy,
    // inherently session-based transport for clients that don't speak
    // Streamable HTTP yet (Claude, Maestro — see negotium's
    // `mcp-config.ts::backgroundBashTransport`). Both are served by this one
    // process against the same `registry`, so a job started through either
    // transport is visible (and killable) through the other.
    let sse_state = SseState::new(registry, security.clone());

    let auth_security = security.clone();
    let auth_layer = axum::middleware::from_fn(move |request, next| {
        let security = auth_security.clone();
        async move { security::authorize_http(security, request, next).await }
    });

    let router = axum::Router::new()
        .route(
            "/health",
            axum::routing::get(|| async {
                // Optional: a caller that spawned this process can pass an
                // identity here and read it back, to tell "the instance I
                // spawned" apart from a stale process squatting the same
                // port. Purely a courtesy — nothing in this server itself
                // depends on it.
                let instance_id = std::env::var("BASHRS_INSTANCE_ID").ok();
                axum::Json(serde_json::json!({
                    "ok": true,
                    "name": "bash-rs",
                    "version": env!("CARGO_PKG_VERSION"),
                    "instance_id": instance_id,
                }))
            }),
        )
        .route("/sse", axum::routing::get(sse::sse_get))
        .route("/message", axum::routing::post(sse::sse_post))
        .with_state(sse_state)
        .nest_service("/mcp", service)
        .layer(auth_layer);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(
        "bash-rs MCP server on http://{bind}/mcp (stateless) + http://{bind}/sse (legacy SSE)"
    );
    axum::serve(listener, router).await?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    if let Some(first) = args.next() {
        if first == "--version" || first == "-V" {
            println!("bash-rs {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let bind = std::env::args().nth(1).filter(|a| a != "stdio");

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        match bind {
            Some(addr) => serve_http(&addr).await,
            None => serve_stdio().await,
        }
    })
}
