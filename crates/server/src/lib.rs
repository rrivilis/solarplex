//! `server` — Solarplex runtime library.
//!
//! All server modules are declared here so they compile as a single library
//! crate.  The `solarplex` binary (`src/main.rs`) depends on this lib and
//! calls into it; bench targets in `benches/` also depend on this lib so they
//! can import internal types (e.g. `reflector::Reflector`) without duplicating
//! module declarations.

pub mod auth;
pub mod authz;
pub mod event_visibility;
pub mod gc;
pub mod health;
pub mod lease;
pub mod metrics_route;
pub mod notifier;
pub mod numa;
pub mod rate_limit;
pub mod reflector;
pub mod routes;
pub mod session_broadcast;
pub mod session_task;
pub mod state;
pub mod ws;
