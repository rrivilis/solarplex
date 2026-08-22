//! `spsh`'s session-detail component: shown after drilling into a session
//! from the list. Tab cycles Members/Artifacts/Approvals/Chat sections; Esc
//! goes back to the session list (this component never quits the app --
//! only the root list's Esc does that). Up/Down move the row highlight
//! within whichever section is active; `a`/`d` grant/deny the highlighted
//! approval -- only meaningful (and only handled) while on the Approvals
//! section.
//!
//! No "claim" hotkey: `crates/cli/src/client.rs` has no claim endpoint to
//! call (only `vote`), so it isn't in scope here -- not stubbed, just absent.
//!
//! Chat has its own `Navigate | Composing` sub-mode (vim normal/insert
//! style): `i` or Enter on the Chat section starts composing and routes
//! subsequent keys to the embedded `TextInput` instead of hotkey dispatch --
//! typing "a" to write a message must not also fire a grant. Esc while
//! composing returns to Navigate, not `Msg::Back` (that would exit the
//! whole detail view).

use serde_json::Value;
use std::collections::HashMap;
use tuirealm::command::{Cmd, CmdResult, Direction as CmdDirection};
use tuirealm::component::{AppComponent, Component};
use tuirealm::event::{Event, Key, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind, NoUserEvent};
use tuirealm::props::{AttrValue, Attribute, Props, QueryResult};
use tuirealm::ratatui::Frame;
use tuirealm::ratatui::layout::{Constraint, Direction as LayoutDirection, Layout, Rect};
use tuirealm::ratatui::style::{Color, Modifier, Style};
use tuirealm::ratatui::widgets::{Block, Borders, List, ListItem, ListState, Tabs};
use tuirealm::state::{State, StateValue};

use crate::output::sanitize_terminal;

use super::model::Msg;
use super::text_input::{TextInput, TextInputEvent};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    Members,
    Artifacts,
    Approvals,
    Chat,
}

impl Section {
    const ALL: [Section; 4] = [Section::Members, Section::Artifacts, Section::Approvals, Section::Chat];

    fn label(self) -> &'static str {
        match self {
            Section::Members   => "Members",
            Section::Artifacts => "Artifacts",
            Section::Approvals => "Approvals",
            Section::Chat      => "Chat",
        }
    }

    fn next(self) -> Self {
        let idx = Self::ALL.iter().position(|s| *s == self).unwrap_or(0);
        Self::ALL[(idx + 1) % Self::ALL.len()]
    }
}

#[derive(PartialEq, Eq)]
enum Mode {
    Navigate,
    Composing,
}

/// A row already reduced down to just the (sanitized) strings we render, so
/// `view()` never has to touch a raw `Value` or re-sanitize on every frame.
/// `id` doubles as the approval id for `Section::Approvals` rows -- the same
/// field, no separate copy, since it's already exactly that value there.
struct Row {
    primary:   String,
    secondary: String,
    id:        String,
}

pub struct SessionDetail {
    props:     Props,
    name:      String,
    /// Whether the live WS connection for this session is currently up --
    /// shown as a small status dot next to the title, same signal
    /// `SessionPaneWindow`'s `state.connected` drives client-side.
    connected: bool,
    section:   Section,
    mode:      Mode,
    /// Row highlight within whichever section is active. Reset to 0 on
    /// every section switch so it can't point past a shorter list.
    selected:  usize,
    members:   Vec<Row>,
    artifacts: Vec<Row>,
    approvals: Vec<Row>,
    /// `primary` = sanitized message content, `secondary` = resolved author
    /// name (or actor_id if unresolved), `id` = event seq as a string.
    messages:  Vec<Row>,
    chat_input: TextInput,
    /// The tab-bar and body areas `view()` last rendered into -- `on()`
    /// needs these to turn a mouse click's absolute (row, column) back into
    /// "which tab" or "which row". Updated at the top of every `view()` call.
    tabs_area: Rect,
    body_area: Rect,
}

impl SessionDetail {
    /// Build from raw `get_session` / `list_artifacts` / `list_approvals` /
    /// `list_events` responses. `artifacts`/`approvals`/`events` are
    /// `Option` -- best-effort, mirroring `cmd::session::inspect`'s existing
    /// precedent: a failed fetch renders as an empty section rather than
    /// failing the whole drill-in. `session` itself is required (the caller
    /// already bailed out before constructing this if that fetch failed).
    pub fn new(
        session:   &Value,
        artifacts: Option<&Value>,
        approvals: Option<&Value>,
        events:    Option<&Value>,
        connected: bool,
    ) -> Self {
        let name = sanitize_terminal(session["name"].as_str().unwrap_or("?"));

        // actor_id -> display name, resolved once from the session snapshot's
        // members list -- same principle as `cmd::session`'s chat mode
        // (`actor_names`) and the frontend's actorNames map. Events store the
        // raw actor_id forever; this is a render-time-only lookup.
        let actor_names: HashMap<String, String> = session["members"].as_array().cloned().unwrap_or_default()
            .iter()
            .filter_map(|m| {
                let id   = m["actor_id"].as_str()?;
                let name = m["name"].as_str().filter(|n| !n.is_empty())?;
                Some((id.to_string(), name.to_string()))
            })
            .collect();

        // FOREIGN fields (actor-supplied at some point) are sanitized before
        // ever reaching a terminal, same rule `cmd::session::print_session_full`
        // already follows for these exact fields.
        let members = session["members"].as_array().cloned().unwrap_or_default()
            .iter()
            .map(|m| Row {
                primary:   sanitize_terminal(m["name"].as_str().filter(|n| !n.is_empty())
                    .unwrap_or_else(|| m["actor_id"].as_str().unwrap_or("?"))),
                secondary: sanitize_terminal(m["role"].as_str().unwrap_or("?")),
                id:        sanitize_terminal(m["actor_id"].as_str().unwrap_or("?")),
            })
            .collect();

        let artifacts = artifacts.and_then(|v| v.as_array()).cloned().unwrap_or_default()
            .iter()
            .map(|a| Row {
                primary:   sanitize_terminal(a["name"].as_str().unwrap_or("?")),
                secondary: sanitize_terminal(a["created_by"].as_str().unwrap_or("?")),
                id:        a["id"].as_str().unwrap_or("?").to_string(), // ULID, safe
            })
            .collect();

        let approvals = approvals.and_then(|v| v.as_array()).cloned().unwrap_or_default()
            .iter()
            .map(|a| Row {
                primary:   sanitize_terminal(a["tool_name"].as_str().unwrap_or("?")),
                secondary: sanitize_terminal(a["actor_id"].as_str().unwrap_or("?")),
                id:        a["id"].as_str().unwrap_or("?").to_string(), // ULID, safe
            })
            .collect();

        // Events store the FULL serialized WsMessage in the `payload` column,
        // so type-specific fields live at `e["payload"]["payload"]` (doubly
        // nested) -- same shape `cmd::session::print_feed_event` reads,
        // matched here rather than guessed. `events` itself is the *oldest*
        // N events (see the caller's comment on the `list_events` call) --
        // filter to messages first, then take the tail of that much smaller
        // set, not the tail of the raw event list.
        const MAX_MESSAGES_SHOWN: usize = 50;
        let mut messages: Vec<Row> = events.and_then(|v| v.as_array()).cloned().unwrap_or_default()
            .iter()
            .filter(|e| e["type"].as_str().unwrap_or("").contains("message.posted"))
            .map(|e| {
                let raw_actor = e["actor_id"].as_str().unwrap_or("?");
                let author = actor_names.get(raw_actor).map(String::as_str).unwrap_or(raw_actor);
                Row {
                    primary:   sanitize_terminal(e["payload"]["payload"]["content"].as_str().unwrap_or("")),
                    secondary: sanitize_terminal(author),
                    id:        e["seq"].as_i64().map(|s| s.to_string()).unwrap_or_default(),
                }
            })
            .collect();
        if messages.len() > MAX_MESSAGES_SHOWN {
            messages.drain(0..messages.len() - MAX_MESSAGES_SHOWN);
        }

        // Always opens on Members, including on a live-triggered refresh --
        // preserving whichever tab was open (or an in-progress chat draft)
        // across a `remount` would need Model to read the mounted
        // component's state back out before rebuilding it, more machinery
        // than this scope justifies. Known, minor rough edge, not an
        // oversight: a live update while composing a message discards the
        // draft along with the tab. Worth revisiting if it turns out to bite.
        Self {
            props: Props::default(), name, connected,
            section: Section::Members, mode: Mode::Navigate, selected: 0,
            members, artifacts, approvals, messages,
            chat_input: TextInput::new(" message ", "type and press Enter to send"),
            tabs_area: Rect::default(), body_area: Rect::default(),
        }
    }

    fn rows_for(&self, section: Section) -> &[Row] {
        match section {
            Section::Members   => &self.members,
            Section::Artifacts => &self.artifacts,
            Section::Approvals => &self.approvals,
            Section::Chat      => &self.messages,
        }
    }

    fn empty_label(section: Section) -> &'static str {
        match section {
            Section::Members   => "No members.",
            Section::Artifacts => "No artifacts.",
            Section::Approvals => "No pending approvals.",
            Section::Chat      => "No messages yet.",
        }
    }

    /// The approval id under the highlight, if the Approvals section is
    /// active and non-empty. `None` for any other section -- `a`/`d` are
    /// simply no-ops there, not an error.
    fn selected_approval_id(&self) -> Option<&str> {
        if self.section != Section::Approvals { return None; }
        self.approvals.get(self.selected).map(|r| r.id.as_str())
    }

    fn move_selection(&mut self, dir: CmdDirection) -> CmdResult {
        let len = self.rows_for(self.section).len();
        if len == 0 { return CmdResult::NoChange; }
        self.selected = match dir {
            CmdDirection::Up   => (self.selected + len - 1) % len,
            CmdDirection::Down => (self.selected + 1) % len,
            _                  => self.selected,
        };
        CmdResult::Changed(State::Single(StateValue::Usize(self.selected)))
    }

    /// A left click's absolute (row, column) -> which body row it landed on,
    /// accounting for the 1-cell border `view()`'s body `Block` always
    /// draws. `None` for a click outside the body (border, or past the last
    /// row) -- not every click in the body area is meaningful. Not used for
    /// the Chat section (its body is split into a message list plus a
    /// compose line, not a single bordered list).
    fn row_at(&self, mouse: &MouseEvent) -> Option<usize> {
        let area = self.body_area;
        let top    = area.y + 1;
        let bottom = area.y + area.height.saturating_sub(1);
        if mouse.row < top || mouse.row >= bottom { return None; }
        if mouse.column <= area.x || mouse.column + 1 >= area.x + area.width { return None; }
        let idx = (mouse.row - top) as usize;
        (idx < self.rows_for(self.section).len()).then_some(idx)
    }

    fn start_composing(&mut self) {
        self.mode = Mode::Composing;
        self.chat_input.set_focused(true);
    }

    fn stop_composing(&mut self) {
        self.mode = Mode::Navigate;
        self.chat_input.set_focused(false);
    }
}

impl Component for SessionDetail {
    fn view(&mut self, frame: &mut Frame, area: Rect) {
        let [tabs_area, body_area] = Layout::default()
            .direction(LayoutDirection::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(1)])
            .areas(area);
        self.tabs_area = tabs_area;
        self.body_area = body_area;

        let titles: Vec<&str> = Section::ALL.iter().map(|s| s.label()).collect();
        let selected_idx = Section::ALL.iter().position(|s| *s == self.section).unwrap_or(0);
        let status_dot = if self.connected { "\u{25cf}" } else { "\u{25cb}" }; // ● live / ○ disconnected
        let status_color = if self.connected { Color::Green } else { Color::DarkGray };
        let hint = match (self.section, &self.mode) {
            (Section::Approvals, _)                 => "Tab switch, a grant, d deny, Esc back",
            (Section::Chat, Mode::Navigate)          => "Tab switch, i compose, Esc back",
            (Section::Chat, Mode::Composing)         => "Enter send, Esc cancel",
            _                                         => "Tab switch, Esc back",
        };
        let tabs = Tabs::new(titles)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" {status_dot} {} ({hint}) ", self.name))
                    .title_style(Style::default().fg(status_color)),
            )
            .select(selected_idx)
            .highlight_style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan));
        frame.render_widget(tabs, tabs_area);

        if self.section == Section::Chat {
            let [messages_area, compose_area] = Layout::default()
                .direction(LayoutDirection::Vertical)
                .constraints([Constraint::Min(1), Constraint::Length(3)])
                .areas(body_area);

            let items: Vec<ListItem> = if self.messages.is_empty() {
                vec![ListItem::new(Self::empty_label(Section::Chat))]
            } else {
                self.messages.iter()
                    .map(|m| ListItem::new(format!("{:<16} {}", m.secondary, m.primary)))
                    .collect()
            };
            frame.render_widget(List::new(items).block(Block::default().borders(Borders::ALL)), messages_area);
            self.chat_input.render(frame, compose_area);
            return;
        }

        let rows = self.rows_for(self.section);
        if rows.is_empty() {
            let items = vec![ListItem::new(Self::empty_label(self.section))];
            frame.render_widget(List::new(items).block(Block::default().borders(Borders::ALL)), body_area);
            return;
        }

        let items: Vec<ListItem> = rows.iter()
            .map(|r| ListItem::new(format!("{:<28} {:<20} {}", r.primary, r.secondary, r.id)))
            .collect();
        let mut state = ListState::default();
        state.select(Some(self.selected));

        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
        frame.render_stateful_widget(list, body_area, &mut state);
    }

    fn query<'a>(&'a self, attr: Attribute) -> Option<QueryResult<'a>> {
        self.props.get_for_query(attr)
    }

    fn attr(&mut self, attr: Attribute, value: AttrValue) {
        self.props.set(attr, value);
    }

    fn state(&self) -> State {
        State::None
    }

    fn perform(&mut self, cmd: Cmd) -> CmdResult {
        match cmd {
            Cmd::Custom("next_section") => {
                self.section = self.section.next();
                self.selected = 0;
                CmdResult::Visual
            }
            Cmd::Move(dir) => self.move_selection(dir),
            _ => CmdResult::Invalid(cmd),
        }
    }
}

impl AppComponent<Msg, NoUserEvent> for SessionDetail {
    fn on(&mut self, ev: &Event<NoUserEvent>) -> Option<Msg> {
        if let Some(key) = ev.as_keyboard() {
            // While composing, every key except Esc goes to the input, not
            // hotkey dispatch -- typing "a" to write "grant it" must not
            // also grant an approval on some other tab.
            if self.mode == Mode::Composing {
                if matches!(key, KeyEvent { code: Key::Esc, modifiers: KeyModifiers::NONE }) {
                    self.stop_composing();
                    return Some(Msg::Redraw);
                }
                return match self.chat_input.handle_key(key) {
                    Some(TextInputEvent::Changed) => Some(Msg::Redraw),
                    Some(TextInputEvent::Submitted(text)) => {
                        self.chat_input.clear();
                        self.stop_composing();
                        let text = text.trim().to_string();
                        if text.is_empty() { Some(Msg::Redraw) } else { Some(Msg::SendMessage(text)) }
                    }
                    None => None,
                };
            }

            return match key {
                KeyEvent { code: Key::Tab, modifiers: KeyModifiers::NONE } => {
                    self.perform(Cmd::Custom("next_section"));
                    Some(Msg::Redraw)
                }
                KeyEvent { code: Key::Up, modifiers: KeyModifiers::NONE } => {
                    self.perform(Cmd::Move(CmdDirection::Up));
                    Some(Msg::Redraw)
                }
                KeyEvent { code: Key::Down, modifiers: KeyModifiers::NONE } => {
                    self.perform(Cmd::Move(CmdDirection::Down));
                    Some(Msg::Redraw)
                }
                KeyEvent { code: Key::Char('a'), modifiers: KeyModifiers::NONE } => {
                    self.selected_approval_id().map(|id| Msg::VoteApproval(id.to_string(), "grant"))
                }
                KeyEvent { code: Key::Char('d'), modifiers: KeyModifiers::NONE } => {
                    self.selected_approval_id().map(|id| Msg::VoteApproval(id.to_string(), "deny"))
                }
                KeyEvent { code: Key::Char('i') | Key::Enter, modifiers: KeyModifiers::NONE }
                    if self.section == Section::Chat =>
                {
                    self.start_composing();
                    Some(Msg::Redraw)
                }
                KeyEvent { code: Key::Char(':'), modifiers: KeyModifiers::NONE } => Some(Msg::OpenCommandLine),
                KeyEvent { code: Key::Esc, modifiers: KeyModifiers::NONE } => Some(Msg::Back),
                _ => None,
            };
        }

        if self.mode == Mode::Navigate {
            if let Some(mouse) = ev.as_mouse() {
                if matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
                    // Any click in the tab bar advances to the next section,
                    // mirroring the Tab key exactly -- resolving an exact tab
                    // index would mean duplicating ratatui's `Tabs` widget's
                    // own internal title/divider spacing, not verified and
                    // not worth it for what's meant to be a small, bounded
                    // feature.
                    if mouse.row >= self.tabs_area.y && mouse.row < self.tabs_area.y + self.tabs_area.height {
                        self.perform(Cmd::Custom("next_section"));
                        return Some(Msg::Redraw);
                    }
                    // A body click only selects -- same as landing on a row
                    // via Up/Down, not an action. Grant/deny stay
                    // deliberately keyboard-only so a stray click can never
                    // resolve an approval. Not handled for Chat -- its body
                    // is a message list plus a compose line, not a single
                    // bordered list `row_at` understands.
                    if self.section != Section::Chat {
                        if let Some(idx) = self.row_at(mouse) {
                            self.selected = idx;
                            return Some(Msg::Redraw);
                        }
                    }
                }
            }
        }

        None
    }
}
