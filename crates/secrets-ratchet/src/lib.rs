//! Forward-secret rotation ratchet for Solarplex's static secrets
//! (`DATABASE_URL`, `OIDC_CLIENT_ID`/`OIDC_CLIENT_SECRET` — the complete
//! list; everything else the app uses is runtime-issued and self-rotating,
//! out of scope for this crate entirely).
//!
//! Deliberately tiny and I/O-free: this is the pure, testable core —
//! `state_{N+1} = HKDF(state_N || fresh_random)` plus domain-separated
//! per-credential derivation and explicit zeroization. It has no opinion
//! on age encryption, systemd, Ansible, Postgres, or the OIDC console;
//! those live in the rotation script that calls this crate. See
//! `state`'s module doc for exactly what security properties this design
//! does and doesn't provide.

mod entropy;
mod state;

pub use entropy::fresh_entropy;
pub use state::RatchetState;
