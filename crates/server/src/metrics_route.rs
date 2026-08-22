//! `GET /metrics` — Prometheus scrape endpoint, same "unauthenticated,
//! outside `/api`" posture as `health.rs`, next to which this is registered.
//!
//! Layer 1 of two: this crate installs one global `metrics`-crate recorder
//! (`metrics_exporter_prometheus::PrometheusBuilder`) at startup and renders
//! its current snapshot here on every scrape. Everywhere else in this crate
//! that calls `metrics::counter!`/`gauge!`/`histogram!`, or carries an
//! `#[autometrics]` attribute (Layer 2 -- see `main.rs`'s setup and
//! `sidecar::proxy`'s equivalent), feeds this same recorder; nothing else
//! needs to know a Prometheus exporter exists.
//!
//! Deliberately unauthenticated to stay scrapeable by infrastructure with no
//! session/cap context (same reasoning `health.rs` documents) -- production
//! deployments should restrict who can reach this at the network layer
//! (`deploy/nftables/solarplex.nft`), not behind application auth, the same
//! way a real Prometheus deployment restricts scrape access today.
//!
//! # Version alignment
//!
//! `autometrics`'s `metrics-0_24` Cargo feature must match the `metrics`
//! crate's own major version exactly (`Cargo.toml`'s three observability
//! deps are pinned together for this reason) -- a mismatch doesn't fail to
//! compile, it silently drops every `#[autometrics]`-instrumented function's
//! output from what this endpoint renders, the worst kind of silent failure
//! for an observability feature to have.

use std::sync::{Arc, OnceLock};

use axum::{extract::State, response::IntoResponse};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

use crate::state::AppState;

/// `GET /metrics` — the current Prometheus exposition-format snapshot.
pub async fn metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    state.prometheus_handle.render()
}

/// Install the global `metrics`-crate recorder exactly once per process and
/// return a handle to render from. `main.rs` calls this exactly once at
/// real startup; it's also safe to call from every test that constructs its
/// own `AppState` (`session_task.rs`'s test helper does), since the
/// underlying `metrics` facade only ever allows one global recorder per
/// process -- a second real `install_recorder()` call would return `Err`,
/// which callers have no good way to distinguish from an actual failure.
/// `OnceLock` sidesteps that: every caller in this process gets the same
/// handle, regardless of how many `AppState`s get built.
pub fn install_or_reuse_recorder() -> PrometheusHandle {
    static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();
    HANDLE
        .get_or_init(|| {
            PrometheusBuilder::new()
                .install_recorder()
                .expect("failed to install Prometheus recorder")
        })
        .clone()
}
