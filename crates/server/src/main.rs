// All modules live in lib.rs; this binary is a thin entry point.
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::connect_info::IntoMakeServiceWithConnectInfo;
use axum::http::HeaderValue;
use axum::{Router, routing::{delete, get, post}};
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use server::{auth, gc, notifier, rate_limit, routes, state::AppState, ws};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "solarplex=debug,tower_http=debug".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // No fallback. A missing DATABASE_URL used to fall back silently to
    // postgres://localhost/solarplex, which meant a misconfigured production
    // deploy didn't fail, it just started against the wrong (or an empty
    // local) database. Fail fast instead, same posture as the OIDC config
    // check below.
    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| anyhow::anyhow!("DATABASE_URL is not set. Refusing to start: there is no safe default for a production database connection."))?;

    let pool = db::connect(&database_url).await?;
    db::migrate(&pool).await?;

    // Initialise OIDC client if configured.  Fail fast on misconfiguration so
    // the operator discovers the problem at startup rather than at first login.
    let oidc = match auth::OidcConfig::from_env() {
        Some(cfg) => {
            let oidc_state = auth::init_oidc(cfg).await?;
            tracing::info!("OIDC initialized");
            Some(oidc_state)
        }
        None => {
            tracing::info!("OIDC not configured (OIDC_ISSUER_URL unset) — human auth via sp_token disabled");
            None
        }
    };

    // Read NUMA_NODES from env (default 1 = single-node, all sessions local).
    // On real multi-socket hardware set NUMA_NODES to the physical node count;
    // the FNV-1a hash in `session_numa_node` distributes sessions stably across
    // nodes without any runtime coordination.
    let numa_nodes: u8 = std::env::var("NUMA_NODES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let state = Arc::new(AppState::new(pool.clone(), oidc).with_numa_nodes(numa_nodes));

    // Spawn background GC tasks (cap row compaction + snapshot ring-buffer).
    gc::spawn_gc_tasks(pool);

    // Spawn LISTEN/NOTIFY subscriber — wakes hub clients on Tier-1 commits.
    notifier::spawn_event_notifier(Arc::clone(&state));

    // Spawn the approval timeout sweeper
    let sweeper_state = state.clone();
    tokio::spawn(async move {
        ws::sweep_expired_approvals(sweeper_state).await;
    });

    // Spawn the scheduled ownership-transfer sweeper
    let transfer_sweeper_state = state.clone();
    tokio::spawn(async move {
        ws::sweep_scheduled_transfers(transfer_sweeper_state).await;
    });

    // Spawn the stale-agent sweeper — detects shim processes that stopped
    // heartbeating (crashed, killed, missing guardian binary, etc.) and
    // marks them detached instead of leaving them "active" forever.
    let agent_sweeper_state = state.clone();
    tokio::spawn(async move {
        ws::sweep_stale_agents(agent_sweeper_state).await;
    });

    // Spawn the rate-limit bucket sweeper — reclaims idle Tier-1/Tier-2
    // buckets so memory doesn't grow unbounded over the process lifetime.
    let rate_limit_sweeper_state = state.clone();
    tokio::spawn(async move {
        rate_limit::sweep_rate_limits(rate_limit_sweeper_state).await;
    });

    let app = Router::new()
        .nest("/api", routes::router())
        // OIDC auth routes at top-level /auth (not under /api — different auth semantics)
        .route("/auth/oidc/start",    get(auth::oidc_start))
        .route("/auth/oidc/callback", get(auth::oidc_callback))
        .route("/auth/oidc/logout",   post(auth::oidc_logout))
        .route("/auth/me",            get(auth::me).patch(auth::update_me))
        .route("/auth/sessions",      get(auth::list_sessions))
        .route("/auth/sessions/:id",  delete(auth::revoke_session))
        .route("/sessions/:session_id/stream", get(ws::handler))
        .layer(cors_layer())
        // 10 MiB request body cap — generous for artifact content and DSL
        // s-expressions, small enough that no handler can be used to hold
        // an unbounded amount of memory open per request. Previously
        // unbounded (tower-http's `limit` feature wasn't even enabled).
        .layer(RequestBodyLimitLayer::new(10 * 1024 * 1024))
        // 30s per-request wall clock. The one long-lived exception is the
        // approval long-poll (`GET /api/approvals/:id/resolution`), which
        // manages its own internal deadline (capped at 60s) and returns a
        // normal response well before this would fire regardless.
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();

    let addr: SocketAddr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".into())
        .parse()
        .map_err(|e| anyhow::anyhow!("BIND_ADDR is not a valid address: {e}"))?;

    serve(addr, app).await
}

/// Origins allowed to make cross-origin requests. Previously
/// `CorsLayer::permissive()` — any origin, unconditionally — which is fine
/// for a same-origin-only browser client but means nothing stops a
/// malicious page from reading responses if a caller's sp_token ever ends
/// up somewhere script-accessible. Defaults to the local frontend dev
/// server so `cargo run` keeps working out of the box; anything other than
/// local dev must set `CORS_ALLOWED_ORIGINS` explicitly.
///
/// Methods and headers are still left open (`Any`) — the origin allowlist
/// is the actual security boundary here; a browser will not honor a
/// response to a disallowed origin regardless of what methods/headers the
/// server says it would have accepted.
fn cors_layer() -> CorsLayer {
    let origins: Vec<HeaderValue> = match std::env::var("CORS_ALLOWED_ORIGINS") {
        Ok(list) => list
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .filter_map(|o| o.parse().ok())
            .collect(),
        Err(_) => {
            tracing::warn!(
                "CORS_ALLOWED_ORIGINS not set — defaulting to http://localhost:3000 only. \
                 Set it to a comma-separated list of allowed origins (e.g. https://app.example.com) \
                 before deploying anywhere other than local dev."
            );
            vec![HeaderValue::from_static("http://localhost:3000")]
        }
    };
    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods(Any)
        .allow_headers(Any)
}

type App = IntoMakeServiceWithConnectInfo<Router, SocketAddr>;

/// Binds and serves `app`, with TLS if `TLS_CERT_PATH`/`TLS_KEY_PATH` are
/// both set, plain HTTP otherwise (the expected shape when a reverse proxy
/// in front of this process terminates TLS — see deploy/nginx/ for a
/// reference config). Either way, drains in-flight connections on
/// SIGTERM/SIGINT instead of dropping them: a deploy or restart used to
/// hard-kill whatever HTTP requests and WS connections happened to be live.
async fn serve(addr: SocketAddr, app: App) -> anyhow::Result<()> {
    let cert = std::env::var("TLS_CERT_PATH").ok();
    let key = std::env::var("TLS_KEY_PATH").ok();

    match (cert, key) {
        (Some(cert), Some(key)) => {
            let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key)
                .await
                .map_err(|e| anyhow::anyhow!("failed to load TLS cert/key ({cert}, {key}): {e}"))?;
            tracing::info!(%addr, "listening (TLS)");

            let handle = axum_server::Handle::new();
            let shutdown_handle = handle.clone();
            tokio::spawn(async move {
                shutdown_signal().await;
                // 30s grace period, matching the plain-HTTP path's
                // TimeoutLayer ceiling — long enough for an in-flight
                // request to finish, not so long a stuck one blocks
                // shutdown indefinitely.
                shutdown_handle.graceful_shutdown(Some(Duration::from_secs(30)));
            });

            axum_server::bind_rustls(addr, config)
                .handle(handle)
                .serve(app)
                .await?;
        }
        (None, None) => {
            tracing::info!(%addr, "listening (no TLS — set TLS_CERT_PATH + TLS_KEY_PATH, or terminate TLS at a reverse proxy; see deploy/nginx/)");
            let listener = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal())
                .await?;
        }
        _ => anyhow::bail!("TLS_CERT_PATH and TLS_KEY_PATH must both be set, or neither"),
    }
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received, draining in-flight connections");
}
