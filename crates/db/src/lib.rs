pub mod pool;
pub mod persist_plan;
pub mod sessions;
pub mod actors;
pub mod epochs;
pub mod events;
pub mod approvals;
pub mod artifacts;
pub mod snapshots;
pub mod tokens;
pub mod human_sessions;
pub mod invites;
pub mod mailbox;
pub mod descriptors;
pub mod authority_arena;
pub mod authority_import;
pub mod methods;
pub mod receipts;
pub mod proposals;
pub mod artifact_reputation;
pub mod session_links;
pub mod session_remotes;
pub mod cross_session_delegations;
pub mod artifact_imports;
pub mod search;
pub mod session_connections;

pub use pool::*;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("not found")]
    NotFound,
    #[error("unauthorized")]
    Unauthorized,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type DbResult<T> = Result<T, DbError>;
