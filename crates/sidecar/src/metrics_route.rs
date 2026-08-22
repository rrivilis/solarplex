//! Recorder install for this process. See `crates/server/src/metrics_route.rs`
//! for the full reasoning (same posture, same version-pinning caveat) -- this
//! is deliberately the short form, not a shared crate: the two files are a
//! few lines each and diverge on their state type (`ProxyState` here,
//! `AppState` there), so a shared abstraction would cost more than it saves
//! for two call sites.
//!
//! The `GET /metrics` handler itself lives in `proxy.rs`, next to `intercept`
//! and the rest of this process's HTTP surface, rather than here.

use std::sync::OnceLock;

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

/// Install the global `metrics`-crate recorder exactly once per process.
/// `OnceLock`-guarded for the same reason as the server's version: safe to
/// call more than once (e.g. from tests), always returns the same handle.
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
