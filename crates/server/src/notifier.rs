//! Server-wide LISTEN/NOTIFY subscriber.
//!
//! A single background task holds one dedicated Postgres connection subscribed
//! to the `session_events` channel.  When a Tier-1 commit fires `pg_notify`,
//! this task wakes up and re-delivers that event to any WebSocket clients
//! connected to *this* replica's copy of the session's hub.
//!
//! Payload convention (set by `db::events::notify_session`):
//!   `{session_id}:{seq}`
//!
//! # Why this matters beyond a single process
//!
//! `emit_to_session` (`ws.rs`) already durably commits every event and fires
//! this notify from whichever replica handled the write, then does its own
//! same-process broadcast if it happens to have a local hub for the session.
//! Before this file re-delivered real content, every *other* replica's
//! listener only ever broadcast a content-less `{"type":"session.events_available"}`
//! wakeup -- and `frontend/lib/ws.ts` explicitly no-ops on that message (by
//! design, to avoid triple-counting events in the Activity Log). The
//! practical effect: a client attached to a different replica than whichever
//! one handled a given write saw nothing live, ever -- not just for
//! cross-session composition, for *any* session, the moment more than one
//! replica exists. Fetching the real event and replaying it through the
//! exact same `apply_event` + `store_and_broadcast` pipeline same-replica
//! delivery already uses closes that gap: cross-replica delivery is now
//! indistinguishable from same-replica delivery from the frontend's point of
//! view, and needs no frontend changes at all.

use std::sync::Arc;
use std::time::Duration;

use protocol::messages::WsMessage;

use crate::state::AppState;
use crate::ws::{apply_event, store_and_broadcast, warm_snap};

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
    state: &Arc<AppState>,
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

        // Clone the hub Arc (if any) before any await, same reasoning
        // `emit_to_session` already documents: never hold a DashMap ref
        // across an await point.
        let Some(hub) = state.hubs.get(session_id).map(|e| e.value().clone()) else {
            // No locally connected clients for this session on this
            // replica -- nothing to deliver to. Expected and correct: not
            // every replica has every session's hub warm.
            continue;
        };

        deliver(state, &hub, session_id, seq, pool).await;
    }
}

/// Fetch the event this notify announced, reconstruct the exact `WsMessage`
/// it durably persisted, and replay it through the same pipeline
/// same-replica delivery uses. Best-effort: any failure here just means
/// this replica's clients miss one live update (same fallback posture the
/// old wakeup-only path already had, and their next full sync catches up).
async fn deliver(
    state:      &Arc<AppState>,
    hub:        &Arc<crate::state::SessionHub>,
    session_id: &str,
    seq:        i64,
    pool:       &sqlx::PgPool,
) {
    let rows = match db::events::list(pool, session_id, Some(seq - 1), 1).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(session_id, seq, "event notifier: failed to fetch event row: {e}");
            return;
        }
    };
    let Some(row) = rows.into_iter().next() else {
        tracing::warn!(session_id, seq, "event notifier: no event row found at notified seq");
        return;
    };

    // `payload` already holds the complete originally-broadcast WsMessage
    // (see `ws.rs`'s `stamp_append_snapshot`: `serde_json::to_value(&stamped)`
    // serializes the whole message, not just the variant's own fields) --
    // the separate `type` column exists for SQL filtering, not because the
    // full message needs reassembling from it.
    let msg: WsMessage = match serde_json::from_value(row.payload) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(session_id, seq, "event notifier: failed to deserialize event payload: {e}");
            return;
        }
    };

    let Some(current) = warm_snap(state, hub, session_id).await else {
        tracing::warn!(session_id, seq, "event notifier: no snapshot to apply onto, dropping");
        return;
    };
    let new_snap = apply_event(&current, &msg);
    store_and_broadcast(hub, seq, new_snap, &msg).await;
    tracing::debug!(session_id, seq, "event notifier: cross-replica delivery");
}
