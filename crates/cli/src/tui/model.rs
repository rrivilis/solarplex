//! `spsh`'s Model/Update: the pure-ish reducer half of the Model/Update/View
//! split, mirroring `crates/session`'s `transition()` shape (state in, event
//! in, state out) as closely as a stateful terminal app allows -- `Update`
//! here still owns `tuirealm`'s `Application`, so it is not literally pure,
//! but the message-in/state-out discipline is the same one used server-side.

use std::time::Duration;

use anyhow::Result;
// `ActArgs` derives clap's `Args` (embeddable within a parent `Parser`), not
// `Parser` itself -- there's no `try_parse_from` to call directly. Building
// a bare `Command`, augmenting it with `ActArgs::augment_args`, then getting
// matches and calling `from_arg_matches` is the equivalent without touching
// `ActArgs`'s existing derive (it's still embedded as-is in `Commands::Act`
// via `main.rs`).
use clap::{Args as ClapArgs, Command, FromArgMatches};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tuirealm::application::Application;
use tuirealm::event::NoUserEvent;
use tuirealm::listener::EventListenerCfg;
use tuirealm::props::{AttrValue, Attribute};
use tuirealm::ratatui::layout::Rect;
use tuirealm::terminal::{CrosstermTerminalAdapter, TerminalAdapter};

use crate::client::Client;
use crate::cmd::act::ActArgs;
use crate::config::Ctx;

use super::command_line::CommandLine;
use super::intent_suggest;
use super::session_detail::SessionDetail;
use super::session_list::{SessionList, SessionRow};
use super::ws::{self, WsEvent};

/// How long to wait after the last keystroke before firing the intent-parse
/// request -- long enough that a normal typing burst doesn't spam
/// `/intent/parse`, short enough that the suggestion still feels live.
const INTENT_DEBOUNCE: Duration = Duration::from_millis(300);

/// A debounced intent-suggestion lookup in flight. `Drop`ping this (replacing
/// it with a newer one on every keystroke, same as `ws::WsConnection`) aborts
/// the sleep-then-fetch task -- a stale request for text the user has since
/// changed or deleted must never land after a newer one.
struct SuggestionTask {
    rx:   mpsc::UnboundedReceiver<Option<String>>,
    task: JoinHandle<()>,
}

impl Drop for SuggestionTask {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub enum Id {
    SessionList,
    SessionDetail,
    CommandLine,
}

#[derive(Debug, PartialEq)]
pub enum Msg {
    AppClose,
    /// A component changed internal state that needs a repaint but doesn't
    /// need `update()` to do anything else (e.g. list navigation, tab cycling).
    Redraw,
    /// Enter pressed on a session row in `SessionList` -- drill in.
    EnterSession(String),
    /// Esc pressed inside `SessionDetail` -- go back to the list, don't quit.
    Back,
    /// `a`/`d` pressed on a highlighted approval -- `(approval_id, "grant" | "deny")`.
    VoteApproval(String, &'static str),
    /// Enter submitted on the Chat compose line -- the message text.
    SendMessage(String),
    /// `:` pressed from `SessionList` or `SessionDetail` (Navigate mode) --
    /// open the command-line overlay.
    OpenCommandLine,
    /// Esc pressed inside the command-line overlay -- close without running
    /// anything.
    CloseCommandLine,
    /// Enter submitted on the command line -- the typed text.
    RunCommand(String),
    /// The command-line buffer changed -- carries the new text so a debounced
    /// intent-suggestion lookup can be (re)scheduled against it.
    CommandLineChanged(String),
}

/// Which full-screen view is currently showing. Distinct from tuirealm's own
/// focus stack (`Application::active`/`blur`, used below for keyboard
/// routing) -- this is purely "which mounted component occupies the whole
/// screen right now", the nav-stack concept the plan borrowed from
/// `output::backtrace_links`, just flattened to depth 1 for this first cut.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    List,
    Detail,
}

pub struct Model {
    pub app:      Application<Id, Msg, NoUserEvent>,
    pub quit:     bool,
    pub redraw:   bool,
    pub terminal: CrosstermTerminalAdapter,
    ctx:          Ctx,
    client:       Client,
    screen:       Screen,
    /// Which session `SessionDetail` is currently showing, if any -- needed
    /// so a live WS push (which arrives outside any component's `on()`, see
    /// `poll_live`) knows what to refetch.
    current_session_id: Option<String>,
    /// The live connection for `current_session_id`, if one is open. `None`
    /// while on the list, while `sp login` was never run (no `sp_token` to
    /// authenticate with), or after the connection has dropped.
    ws: Option<ws::WsConnection>,
    /// Whether the `:`-triggered command-line overlay is currently showing.
    /// Separate from `screen` -- it draws *on top of* whichever screen is
    /// active rather than replacing it.
    command_line_open: bool,
    /// In-flight debounced intent-suggestion lookup for the command line's
    /// current buffer, if any. `None` between keystrokes' debounce windows
    /// and whenever the overlay is closed.
    intent_task: Option<SuggestionTask>,
    /// Mirrors what's been pushed into `CommandLine` via `attr()` -- kept
    /// here too so `view()` can size the overlay's own Rect (one extra row
    /// when a suggestion is showing) *before* asking `CommandLine` to draw
    /// into it, without needing to ask the mounted component what it thinks
    /// its own height should be.
    command_line_suggestion: Option<String>,
}

impl Model {
    /// Fetch the initial session list over HTTP (via the same `client.rs`
    /// every one-shot `sp` command already uses), mount it as the sole
    /// component, and take over the terminal. The WS connection itself only
    /// opens once a session is drilled into (`Msg::EnterSession`) -- the
    /// list view has no single "all sessions" stream to subscribe to.
    pub async fn new(ctx: &Ctx) -> Result<Self> {
        let client = Client::new(ctx)?;
        let sessions = client.list_sessions(ctx.actor_id.as_deref()).await?;
        let rows: Vec<SessionRow> = sessions
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(SessionRow::from_json)
            .collect();

        let mut app: Application<Id, Msg, NoUserEvent> = Application::init(
            EventListenerCfg::default().crossterm_input_listener(Duration::from_millis(20), 3),
        );
        app.mount(Id::SessionList, Box::new(SessionList::new(rows)), Vec::default())
            .map_err(|e| anyhow::anyhow!("spsh: failed to mount session list: {e}"))?;
        app.active(&Id::SessionList)
            .map_err(|e| anyhow::anyhow!("spsh: failed to focus session list: {e}"))?;

        let mut terminal = CrosstermTerminalAdapter::new()
            .map_err(|e| anyhow::anyhow!("spsh: failed to init terminal: {e}"))?;
        terminal
            .enable_raw_mode()
            .map_err(|e| anyhow::anyhow!("spsh: failed to enable raw mode: {e}"))?;
        terminal
            .enter_alternate_screen()
            .map_err(|e| anyhow::anyhow!("spsh: failed to enter alternate screen: {e}"))?;
        terminal
            .enable_mouse_capture()
            .map_err(|e| anyhow::anyhow!("spsh: failed to enable mouse capture: {e}"))?;

        Ok(Self {
            app, quit: false, redraw: true, terminal,
            ctx: ctx.clone(), client, screen: Screen::List,
            current_session_id: None, ws: None, command_line_open: false,
            intent_task: None, command_line_suggestion: None,
        })
    }

    pub fn view(&mut self) {
        let _ = self.terminal.draw(|f| {
            let id = match self.screen {
                Screen::List   => &Id::SessionList,
                Screen::Detail => &Id::SessionDetail,
            };
            self.app.view(id, f, f.area());

            if self.command_line_open {
                // 3 rows (bordered input) normally, 4 when a suggestion is
                // showing -- `CommandLine::view` mirrors this exact split
                // (unchanged input box size, one extra row below it), so the
                // two must stay in agreement about when that extra row exists.
                let height: u16 = if self.command_line_suggestion.is_some() { 4 } else { 3 };
                let area = f.area();
                let overlay = Rect {
                    x:      area.x,
                    y:      area.y + area.height.saturating_sub(height),
                    width:  area.width,
                    height: height.min(area.height),
                };
                self.app.view(&Id::CommandLine, f, overlay);
            }
        });
    }

    /// Non-blocking check of the live WS channel, if a session detail view
    /// is open. Called every loop iteration in `tui::run` alongside
    /// `app.tick()` -- WS events arrive on a plain `tokio::sync::mpsc`
    /// channel from a background task (see `super::ws`), not through
    /// tuirealm's own crossterm-driven event listener, so they need their
    /// own drain point rather than flowing through any component's `on()`.
    pub async fn poll_live(&mut self) {
        let Some(conn) = self.ws.as_mut() else { return };
        match conn.rx.try_recv() {
            Ok(WsEvent::Changed) => {
                if let Some(session_id) = self.current_session_id.clone() {
                    self.refresh_detail(&session_id, true).await;
                }
            }
            Ok(WsEvent::Closed(reason)) => {
                tracing::warn!("spsh: WS connection closed: {reason}");
                self.ws = None;
                if let Some(session_id) = self.current_session_id.clone() {
                    self.refresh_detail(&session_id, false).await;
                }
            }
            Err(_) => {} // nothing pending this tick, or the task already ended
        }
    }

    /// Non-blocking check of the debounced intent-suggestion channel, same
    /// drain-outside-tuirealm's-own-loop shape as `poll_live` and for the
    /// same reason: the result arrives from a plain background task, not
    /// through any component's `on()`.
    pub async fn poll_intent_suggestion(&mut self) {
        let Some(t) = self.intent_task.as_mut() else { return };
        let Ok(suggestion) = t.rx.try_recv() else { return };
        self.command_line_suggestion = suggestion.clone();
        let _ = self.app.attr(
            &Id::CommandLine,
            Attribute::Text,
            AttrValue::String(suggestion.unwrap_or_default()),
        );
        self.redraw = true;
    }

    /// Fetch `session_id`'s detail (best-effort on artifacts/approvals,
    /// mirrors `cmd::session::inspect`'s existing precedent) and mount or
    /// remount `Id::SessionDetail` with it. Shared by the initial drill-in
    /// and every live-triggered refresh after it. Returns `false` (and
    /// leaves any previously-mounted detail untouched) if the *session*
    /// fetch itself fails -- there's nothing sensible to show without it.
    async fn refresh_detail(&mut self, session_id: &str, connected: bool) -> bool {
        // `list_events` is `ORDER BY seq ASC LIMIT N` server-side (see
        // `db::events::list`) -- it returns the *oldest* N events, not the
        // most recent. There's no "give me the tail" query on this endpoint,
        // so this over-fetches and `SessionDetail` takes the actual tail of
        // the (much smaller) message-only subset after filtering.
        let (session, artifacts, approvals, events) = tokio::join!(
            self.client.get_session(session_id),
            self.client.list_artifacts(session_id),
            self.client.list_approvals(session_id),
            self.client.list_events(session_id, 500),
        );
        let session = match session {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("spsh: failed to fetch session {session_id}: {e}");
                return false;
            }
        };

        let detail = SessionDetail::new(
            &session, artifacts.ok().as_ref(), approvals.ok().as_ref(), events.ok().as_ref(), connected,
        );
        let mount_result = if self.app.mounted(&Id::SessionDetail) {
            self.app.remount(Id::SessionDetail, Box::new(detail), Vec::default())
        } else {
            self.app.mount(Id::SessionDetail, Box::new(detail), Vec::default())
        };
        if let Err(e) = mount_result {
            tracing::warn!("spsh: failed to mount session detail: {e}");
            return false;
        }
        self.redraw = true;
        true
    }

    pub async fn update(&mut self, msg: Msg) {
        self.redraw = true;
        match msg {
            Msg::AppClose => self.quit = true,
            Msg::Redraw   => {}

            Msg::Back => {
                // Restores focus to whatever `active()` pushed onto tuirealm's
                // own stack when we entered the detail view below -- correct
                // regardless of nav depth, unlike hardcoding `active(&Id::SessionList)`.
                let _ = self.app.blur();
                self.screen = Screen::List;
                self.current_session_id = None;
                self.ws = None; // drops -> aborts the background read task
            }

            Msg::EnterSession(session_id) => {
                self.current_session_id = Some(session_id.clone());
                self.ws = ws::connect(&self.ctx, &session_id);
                let connected = self.ws.is_some();
                if !self.refresh_detail(&session_id, connected).await {
                    self.current_session_id = None;
                    self.ws = None;
                    return;
                }
                if let Err(e) = self.app.active(&Id::SessionDetail) {
                    tracing::warn!("spsh: failed to focus session detail: {e}");
                    return;
                }
                self.screen = Screen::Detail;
            }

            Msg::VoteApproval(approval_id, decision) => {
                let Some(actor_id) = self.ctx.actor_id.clone() else {
                    tracing::warn!("spsh: no actor set (--actor / SOLARPLEX_ACTOR_ID) -- can't vote");
                    return;
                };
                if let Err(e) = self.client.vote(&approval_id, &actor_id, decision).await {
                    tracing::warn!("spsh: vote {decision} on {approval_id} failed: {e}");
                    return;
                }
                // Refetch so the now-resolved approval drops out of the
                // pending list -- same reuse of `refresh_detail` a live WS
                // push uses, just triggered by our own action instead of
                // someone else's.
                if let Some(session_id) = self.current_session_id.clone() {
                    self.refresh_detail(&session_id, self.ws.is_some()).await;
                }
            }

            Msg::SendMessage(text) => {
                let Some(session_id) = self.current_session_id.clone() else { return };
                let actor_id = self.ctx.actor_id.clone().unwrap_or_else(|| "anon".to_string());
                if let Err(e) = self.client.post_message(&session_id, &actor_id, &text).await {
                    tracing::warn!("spsh: post_message failed: {e}");
                    return;
                }
                self.refresh_detail(&session_id, self.ws.is_some()).await;
            }

            Msg::OpenCommandLine => {
                let mount_result = if self.app.mounted(&Id::CommandLine) {
                    self.app.remount(Id::CommandLine, Box::new(CommandLine::new()), Vec::default())
                } else {
                    self.app.mount(Id::CommandLine, Box::new(CommandLine::new()), Vec::default())
                };
                if let Err(e) = mount_result {
                    tracing::warn!("spsh: failed to mount command line: {e}");
                    return;
                }
                if let Err(e) = self.app.active(&Id::CommandLine) {
                    tracing::warn!("spsh: failed to focus command line: {e}");
                    return;
                }
                self.command_line_open = true;
            }

            Msg::CloseCommandLine => {
                let _ = self.app.blur();
                self.command_line_open = false;
                self.intent_task = None;
                self.command_line_suggestion = None;
            }

            Msg::RunCommand(text) => {
                let _ = self.app.blur();
                self.command_line_open = false;
                self.intent_task = None;
                self.command_line_suggestion = None;
                self.run_command(&text).await;
            }

            Msg::CommandLineChanged(text) => {
                // Replacing (rather than just overwriting) drops and aborts
                // whatever lookup was in flight for the previous text --
                // see `SuggestionTask`'s `Drop`.
                self.intent_task = None;

                let trimmed = text.trim();
                if trimmed.is_empty() {
                    self.command_line_suggestion = None;
                    let _ = self.app.attr(&Id::CommandLine, Attribute::Text, AttrValue::String(String::new()));
                    return;
                }

                let ctx = self.ctx.clone();
                let text = trimmed.to_string();
                let (tx, rx) = mpsc::unbounded_channel();
                let task = tokio::spawn(async move {
                    tokio::time::sleep(INTENT_DEBOUNCE).await;
                    let suggestion = match Client::new(&ctx) {
                        Ok(client) => match client.parse_intent(&text).await {
                            Ok(parsed) => intent_suggest::format_suggestion(&parsed),
                            Err(e) => {
                                tracing::debug!("spsh: parse_intent failed: {e}");
                                None
                            }
                        },
                        Err(e) => {
                            tracing::debug!("spsh: parse_intent: failed to build client: {e}");
                            None
                        }
                    };
                    let _ = tx.send(suggestion);
                });
                self.intent_task = Some(SuggestionTask { rx, task });
            }
        }
    }

    /// Parse and execute a typed command-line command. Reuses `ActArgs`'s
    /// clap parsing (same entity-ref/flag syntax the CLI already teaches),
    /// but dispatches to a small curated match here instead of
    /// `cmd::act::run()` -- its own dispatch interleaves `println!` output
    /// with its `client.rs` calls, which would corrupt or vanish while spsh
    /// holds the alternate screen (see the plan's "Command-line escape
    /// hatch" section). Unrecognized transitions get a clear error, never a
    /// silent no-op -- adding one later is one match arm, not a redesign.
    async fn run_command(&mut self, text: &str) {
        let text = text.trim();
        if text.is_empty() { return; }

        let mut tokens: Vec<String> = text.split_whitespace().map(String::from).collect();
        // In Detail context the open session is implicit -- typed commands
        // start directly with the transition name, not an entity ref.
        if self.screen == Screen::Detail {
            if let Some(session_id) = &self.current_session_id {
                tokens.insert(0, format!("session/{session_id}"));
            }
        }

        let mut argv = vec!["spsh".to_string()];
        argv.extend(tokens);

        let cmd = ActArgs::augment_args(Command::new("spsh"));
        let args = match cmd.try_get_matches_from(&argv).and_then(|m| ActArgs::from_arg_matches(&m)) {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!("spsh: command parse error: {e}");
                return;
            }
        };

        let (kind, id_opt) = match args.entity.split_once('/') {
            Some((k, id)) => (k, Some(id).filter(|s| !s.is_empty())),
            None => (args.entity.as_str(), None),
        };
        let transition = args.transition.as_str();
        let actor_id = self.ctx.actor_id.clone();

        let result: anyhow::Result<()> = match (kind, transition) {
            ("session", "OwnershipTransfer") | ("session", "Handoff") => {
                match (id_opt, args.to.as_deref(), actor_id.as_deref()) {
                    (Some(id), Some(to), Some(from)) => {
                        self.client.transfer_ownership(id, from, to).await
                    }
                    (_, _, None) => Err(anyhow::anyhow!("no actor set (--actor / SOLARPLEX_ACTOR_ID)")),
                    _ => Err(anyhow::anyhow!("OwnershipTransfer needs an entity id and --to <actor_id>")),
                }
            }
            ("session", "Rename") => match (id_opt, args.name.as_deref()) {
                (Some(id), Some(name)) => {
                    self.client.rename_session(id, name, actor_id.as_deref()).await.map(|_| ())
                }
                _ => Err(anyhow::anyhow!("Rename needs an entity id and --name <new-name>")),
            },
            ("session", "Pause") => self.set_status(id_opt, "suspended").await,
            ("session", "Resume") => self.set_status(id_opt, "active").await,
            ("session", "Archive") => self.set_status(id_opt, "archived").await,
            ("session", "AddContext") => match (id_opt, actor_id.as_deref()) {
                (Some(id), Some(actor)) if !args.words.is_empty() => {
                    let content = args.words.join(" ");
                    self.client.add_context(id, actor, &args.kind, &content).await
                }
                (_, None) => Err(anyhow::anyhow!("no actor set (--actor / SOLARPLEX_ACTOR_ID)")),
                _ => Err(anyhow::anyhow!("AddContext needs an entity id and content words")),
            },
            _ => Err(anyhow::anyhow!(
                "`{transition}` isn't wired into spsh's command line yet -- run \
                 `sp act {}/{} {transition} ...` directly",
                kind, id_opt.unwrap_or("<id>"),
            )),
        };

        if let Err(e) = result {
            tracing::warn!("spsh: command failed: {e}");
        }

        if let Some(session_id) = self.current_session_id.clone() {
            self.refresh_detail(&session_id, self.ws.is_some()).await;
        }
    }

    async fn set_status(&self, id_opt: Option<&str>, status: &str) -> anyhow::Result<()> {
        let id = id_opt.ok_or_else(|| anyhow::anyhow!("`{status}` needs an entity id"))?;
        self.client.update_session_status(id, status).await.map(|_| ())
    }
}
