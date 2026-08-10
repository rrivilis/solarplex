use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

pub async fn connect(database_url: &str) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(20)
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
