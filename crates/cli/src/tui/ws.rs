//! `spsh`'s live WS connection: subscribes to one session's `/stream` while
//! its detail view is open, mirroring `frontend/lib/ws.ts`'s `useSession`
//! connection shape (same endpoint, same `sp_token` auth query param) rather
//! than `sp watch`'s HTTP-polling loop. This is the piece that makes drilling
//! into a session feel live instead of a fancier `sp ask`.

use futures_util::StreamExt;
use protocol::messages::WsMessage;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message as TungsteniteMessage;

use crate::config::Ctx;

/// A live signal bridged out of the WS task into `tui::run`'s loop.
/// Deliberately coarse: this drives "something about this session changed,
/// refetch it" rather than a per-`WsPayload`-variant incremental UI update --
/// the latter would need to track and merge every event type `SessionDetail`
/// might care about individually, a much bigger surface than Step 3's scope
/// (proving live push works at all) calls for. Comes free with reusing the
/// same `refresh_detail` fetch `Msg::EnterSession` already does.
pub enum WsEvent {
    /// A recognized `WsMessage` frame arrived.
    Changed,
    /// The connection ended -- server close, or a read error. Carries a
    /// short reason for the connection-status indicator in the detail view.
    Closed(String),
}

pub struct WsConnection {
    pub rx: mpsc::UnboundedReceiver<WsEvent>,
    task:   JoinHandle<()>,
}

impl Drop for WsConnection {
    /// Ends the background read loop the moment the view navigates away
    /// (`Back`, or entering a different session) -- there's nothing left
    /// that wants these events once nobody's looking at this session.
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Open a WS connection to `session_id`'s `/stream`. Returns `None` without
/// attempting a connection when there's no `sp_token` -- `sp shell` only
/// ever runs as a signed-in human (there's no agent/join_token path here,
/// unlike the frontend's fallback), so no token means the server would just
/// 401 the upgrade anyway.
pub fn connect(ctx: &Ctx, session_id: &str) -> Option<WsConnection> {
    let token = ctx.token.clone()?;
    let url = build_url(&ctx.server, session_id, &token)?;

    let (tx, rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        let (stream, _response) = match tokio_tungstenite::connect_async(url.as_str()).await {
            Ok(pair) => pair,
            Err(e) => {
                let _ = tx.send(WsEvent::Closed(format!("connect failed: {e}")));
                return;
            }
        };
        let (_write, mut read) = stream.split();
        while let Some(msg) = read.next().await {
            match msg {
                Ok(TungsteniteMessage::Text(text)) => {
                    // Only need to know *that* a real frame arrived, not
                    // decode every field -- but parsing as `WsMessage`
                    // still keeps a malformed/unexpected frame from
                    // silently counting as "something changed".
                    if serde_json::from_str::<WsMessage>(&text).is_ok()
                        && tx.send(WsEvent::Changed).is_err()
                    {
                        break; // receiver dropped -- the view moved on
                    }
                }
                Ok(TungsteniteMessage::Close(_)) => {
                    let _ = tx.send(WsEvent::Closed("server closed the connection".to_string()));
                    break;
                }
                Ok(_) => {} // ping/pong/binary -- nothing to act on here
                Err(e) => {
                    let _ = tx.send(WsEvent::Closed(format!("read error: {e}")));
                    break;
                }
            }
        }
    });

    Some(WsConnection { rx, task })
}

/// `http(s)://host` -> `ws(s)://host/sessions/<id>/stream?sp_token=<token>`,
/// same shape as `frontend/lib/ws.ts`'s `useSession` (`WS_BASE +
/// "/sessions/${sessionId}/stream?sp_token=${encodeURIComponent(spToken)}"`).
/// `ctx.server` is always `http://` or `https://` (`Ctx::load`'s default and
/// every override are plain HTTP URLs); anything else is a misconfigured
/// `--server`/`SOLARPLEX_SERVER`, not something to guess at.
fn build_url(server: &str, session_id: &str, token: &str) -> Option<url::Url> {
    let ws_base = if let Some(rest) = server.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = server.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        return None;
    };
    let mut url = url::Url::parse(&format!("{ws_base}/sessions/{session_id}/stream")).ok()?;
    url.query_pairs_mut().append_pair("sp_token", token);
    Some(url)
}
