//! `spsh`'s session-list component: renders the list of sessions this actor
//! can see, and handles Up/Down navigation plus Esc to quit.

use serde_json::Value;
use tuirealm::command::{Cmd, CmdResult, Direction as CmdDirection};
use tuirealm::component::{AppComponent, Component};
use tuirealm::event::{
    Event, Key, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind, NoUserEvent,
};
use tuirealm::props::{AttrValue, Attribute, Props, QueryResult};
use tuirealm::ratatui::layout::Rect;
use tuirealm::ratatui::style::{Color, Modifier, Style};
use tuirealm::ratatui::widgets::{Block, Borders, List, ListItem, ListState};
use tuirealm::ratatui::Frame;
use tuirealm::state::{State, StateValue};

use crate::output::sanitize_terminal;

use super::model::Msg;

/// One row in the session list, holding only what we render.
pub struct SessionRow {
    pub id: String,
    pub name: String,
    pub status: String,
}

impl SessionRow {
    pub fn from_json(v: &Value) -> Self {
        let id = v["id"].as_str().unwrap_or("").to_string();
        // `name` is actor-supplied at session-creation time -- sanitize before
        // it ever reaches a terminal, same rule `sp session ls`
        // (crates/cli/src/cmd/session.rs) already follows for the exact same field.
        let name = sanitize_terminal(v["name"].as_str().unwrap_or("?"));
        let status = v["status"].as_str().unwrap_or("active").to_string();
        Self { id, name, status }
    }
}

pub struct SessionList {
    props: Props,
    rows: Vec<SessionRow>,
    selected: usize,
    /// The area `view()` last rendered into -- `on()` needs this to turn a
    /// mouse click's absolute (row, column) back into a list index. Updated
    /// at the top of every `view()` call.
    last_area: Rect,
}

impl SessionList {
    pub fn new(rows: Vec<SessionRow>) -> Self {
        Self {
            props: Props::default(),
            rows,
            selected: 0,
            last_area: Rect::default(),
        }
    }

    /// The currently-highlighted session's id, if the list is non-empty.
    pub fn selected_id(&self) -> Option<&str> {
        self.rows.get(self.selected).map(|r| r.id.as_str())
    }

    fn move_selection(&mut self, dir: CmdDirection) -> CmdResult {
        if self.rows.is_empty() {
            return CmdResult::NoChange;
        }
        let len = self.rows.len();
        self.selected = match dir {
            CmdDirection::Up => (self.selected + len - 1) % len,
            CmdDirection::Down => (self.selected + 1) % len,
            _ => self.selected,
        };
        CmdResult::Changed(State::Single(StateValue::Usize(self.selected)))
    }

    /// A left click's absolute (row, column) -> which row it landed on,
    /// accounting for the 1-cell border `view()`'s `Block` always draws.
    /// `None` for a click outside the list body (border, title, or past the
    /// last row) -- not every click is meaningful.
    fn row_at(&self, mouse: &MouseEvent) -> Option<usize> {
        let area = self.last_area;
        let top = area.y + 1;
        let bottom = area.y + area.height.saturating_sub(1);
        if mouse.row < top || mouse.row >= bottom {
            return None;
        }
        if mouse.column <= area.x || mouse.column + 1 >= area.x + area.width {
            return None;
        }
        let idx = (mouse.row - top) as usize;
        (idx < self.rows.len()).then_some(idx)
    }
}

impl Component for SessionList {
    fn view(&mut self, frame: &mut Frame, area: Rect) {
        self.last_area = area;
        if self.rows.is_empty() {
            let block = Block::default()
                .borders(Borders::ALL)
                .title(" sessions (Esc to quit) ");
            frame.render_widget(
                List::new(vec![ListItem::new("No sessions.")]).block(block),
                area,
            );
            return;
        }

        let items: Vec<ListItem> = self
            .rows
            .iter()
            .map(|r| {
                let status_style = match r.status.as_str() {
                    "active" => Style::default().fg(Color::Green),
                    "suspended" => Style::default().fg(Color::Yellow),
                    "archived" => Style::default().fg(Color::DarkGray),
                    _ => Style::default(),
                };
                ListItem::new(format!("{:<28} {}", r.name, r.status)).style(status_style)
            })
            .collect();

        let mut state = ListState::default();
        state.select(Some(self.selected));

        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" sessions (\u{2191}/\u{2193} navigate, Esc quit) "),
            )
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

        frame.render_stateful_widget(list, area, &mut state);
    }

    fn query<'a>(&'a self, attr: Attribute) -> Option<QueryResult<'a>> {
        self.props.get_for_query(attr)
    }

    fn attr(&mut self, attr: Attribute, value: AttrValue) {
        self.props.set(attr, value);
    }

    fn state(&self) -> State {
        State::Single(StateValue::Usize(self.selected))
    }

    fn perform(&mut self, cmd: Cmd) -> CmdResult {
        match cmd {
            Cmd::Move(dir) => self.move_selection(dir),
            _ => CmdResult::Invalid(cmd),
        }
    }
}

impl AppComponent<Msg, NoUserEvent> for SessionList {
    fn on(&mut self, ev: &Event<NoUserEvent>) -> Option<Msg> {
        if let Some(key) = ev.as_keyboard() {
            return match key {
                // `perform`'s CmdResult must bubble back up as a `Msg` -- tuirealm
                // only re-renders in response to a returned `Msg` (see `demo`'s own
                // Counter component), not merely because internal component state
                // changed. Returning `None` here would move the selection but never
                // repaint it.
                KeyEvent {
                    code: Key::Up,
                    modifiers: KeyModifiers::NONE,
                } => {
                    self.perform(Cmd::Move(CmdDirection::Up));
                    Some(Msg::Redraw)
                }
                KeyEvent {
                    code: Key::Down,
                    modifiers: KeyModifiers::NONE,
                } => {
                    self.perform(Cmd::Move(CmdDirection::Down));
                    Some(Msg::Redraw)
                }
                KeyEvent {
                    code: Key::Enter,
                    modifiers: KeyModifiers::NONE,
                } => self
                    .selected_id()
                    .map(|id| Msg::EnterSession(id.to_string())),
                KeyEvent {
                    code: Key::Char(':'),
                    modifiers: KeyModifiers::NONE,
                } => Some(Msg::OpenCommandLine),
                KeyEvent {
                    code: Key::Esc,
                    modifiers: KeyModifiers::NONE,
                } => Some(Msg::AppClose),
                _ => None,
            };
        }

        // Click-to-select-and-enter: a single left click on a row is the
        // mouse equivalent of highlighting it (Up/Down) and pressing Enter
        // in one motion, not a separate select-then-confirm gesture.
        if let Some(mouse) = ev.as_mouse() {
            if matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
                if let Some(idx) = self.row_at(mouse) {
                    self.selected = idx;
                    return self
                        .selected_id()
                        .map(|id| Msg::EnterSession(id.to_string()));
                }
            }
        }

        None
    }
}
