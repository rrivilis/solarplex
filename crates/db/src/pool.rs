use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

/// Read a `u32`/`u64` env var, warning and falling back to `default` if unset
/// or unparseable. Same posture as `REPLICA_ID`/`NUMA_NODES` in `main.rs`:
/// a pool-sizing misconfiguration should degrade to a sane default, not
/// refuse to start the way a missing `DATABASE_URL` does — there's no
/// "unsafe to guess" value here the way there is for a DB connection target.
fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    match std::env::var(key) {
        Ok(raw) => raw.trim().parse().unwrap_or_else(|_| {
            tracing::warn!("{key} is set but not a valid number ({raw:?}) — using the default");
            default
        }),
        Err(_) => default,
    }
}

/// Pool sizing is env-driven instead of the hardcoded `max_connections(20)`
/// this replaced — a single-value cap made sense while there was exactly one
/// deployment shape, but it can't be right for every host, and changing it
/// used to mean a code edit + rebuild instead of a config change.
///
/// - `DB_POOL_MAX_CONNECTIONS` (default 20, preserving prior behavior)
/// - `DB_POOL_MIN_CONNECTIONS` (default 0, sqlx's own default — connections
///   are opened on demand rather than eagerly)
/// - `DB_POOL_ACQUIRE_TIMEOUT_SECS` (default 30, sqlx's own default)
/// - `DB_POOL_IDLE_TIMEOUT_SECS` (default 600 = 10 minutes, sqlx's own
///   default; `0` explicitly disables idle reaping — connections are kept
///   open indefinitely once opened)
pub async fn connect(database_url: &str) -> anyhow::Result<PgPool> {
    let max_connections   = env_or("DB_POOL_MAX_CONNECTIONS", 20u32);
    let min_connections   = env_or("DB_POOL_MIN_CONNECTIONS", 0u32);
    let acquire_timeout   = env_or("DB_POOL_ACQUIRE_TIMEOUT_SECS", 30u64);
    let idle_timeout_secs = env_or("DB_POOL_IDLE_TIMEOUT_SECS", 600u64);
    let idle_timeout = if idle_timeout_secs == 0 {
        None
    } else {
        Some(Duration::from_secs(idle_timeout_secs))
    };

    tracing::info!(
        max_connections, min_connections, acquire_timeout,
        idle_timeout_secs, "db pool: configured",
    );

    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .min_connections(min_connections)
        .acquire_timeout(Duration::from_secs(acquire_timeout))
        .idle_timeout(idle_timeout)
        .connect(database_url)
        .await?;
    Ok(pool)
}

pub async fn migrate(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::migrate!("../../migrations").run(pool).await?;

    // Belt-and-suspenders: drop the legacy artifacts.type CHECK constraint
    // if it is still present.  `sqlx::migrate!` embeds SQL files at compile
    // time, so adding 003 won't take effect until the binary is rebuilt.
    // Running this DROP here guarantees the constraint is gone regardless of
    // whether the embedded migration list was stale.  IF EXISTS makes it
    // idempotent — safe to run on every startup.
    sqlx::query(
        "ALTER TABLE artifacts DROP CONSTRAINT IF EXISTS artifacts_type_check",
    )
    .execute(pool)
    .await
    .map_err(|e| anyhow::anyhow!("startup: drop artifact type constraint: {e}"))?;

    // Same pattern for sessions.status: replace the narrow three-value check
    // with the full operational-state set (004_session_statuses.sql).
    // Running it unconditionally means it takes effect even if the migration
    // binary was compiled before 004 was added to the migrations/ folder.
    sqlx::query(
        "ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_status_check",
    )
    .execute(pool)
    .await
    .map_err(|e| anyhow::anyhow!("startup: drop sessions status constraint: {e}"))?;

    sqlx::query(
        "ALTER TABLE sessions ADD CONSTRAINT sessions_status_check \
         CHECK (status IN ('active','attention_requested','action_needed','policy_update','suspended','archived'))",
    )
    .execute(pool)
    .await
    .map_err(|e| anyhow::anyhow!("startup: add sessions status constraint: {e}"))?;

    Ok(())
}
