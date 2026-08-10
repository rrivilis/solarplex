//! Server-wide LISTEN/NOTIFY subscriber.
//!
//! A single background task holds one dedicated Postgres connection subscribed
//! to the `session_events` channel.  When a Tier-1 commit fires `pg_notify`,
//! this task wakes up, looks up the session hub, and broadcasts a lightweight
//! `session.events_available` message to all connected WebSocket clients.
//!
//! Payload convention (set by `db::events::notify_session`):
//!   `{session_id}:{seq}`
//!
//! The broadcast lets `sp watch` (and future SSE subscribers) drop their poll
//! interval to 0 — they receive an immediate push and fetch only when there is
//! something new.

use std::sync::Arc;
use std::time::Duration;

use crate::state::AppState;

/// Spawn the server-wide event notifier task.  Call once at startup.
pub fn spawn_event_notifier(state: Arc<AppState>) {
    let pool = state.db.clone();
    tokio::spawn(async move {
        loop {
            if let Err(e) = run_listener(&pool, &state).await {
                tracing::warn!("event notifier disconnected ({e}), reconnecting in 1s");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    });
}

/// Inner loop — returns on any error so the outer loop can reconnect.
async fn run_listener(
    pool:  &sqlx::PgPool,
    state: &AppState,
) -> anyhow::Result<()> {
    let mut listener = sqlx::postgres::PgListener::connect_with(pool).await?;
    listener.listen("session_events").await?;
    tracing::info!("event notifier: listening on session_events");

    loop {
        let notification = listener.recv().await?;
        let payload = notification.payload();

        // Payload: "{session_id}:{seq}" — split on the first colon.
        let Some((session_id, seq_str)) = payload.split_once(':') else {
            tracing::warn!("event notifier: malformed payload: {payload}");
            continue;
        };
        let seq: i64 = match seq_str.parse() {
            Ok(n)  => n,
            Err(_) => { tracing::warn!("event notifier: bad seq in payload: {payload}"); continue; }
        };

        if let Some(hub) = state.hubs.get(session_id) {
            let msg = format!(r#"{{"type":"session.events_available","seq":{seq}}}"#);
            hub.broadcast(Arc::new(msg));
            tracing::debug!(session_id, seq, "event notifier: wakeup broadcast");
        }
        // No hub means no connected clients — drop silently.
    }
}
