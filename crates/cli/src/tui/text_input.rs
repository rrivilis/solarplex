//! A small wrapper around `tuirealm-stdlib`'s `Input` component, embedded
//! (not separately mounted) inside whichever screen owns it. `SessionDetail`'s
//! Chat section and `Model`'s command-line overlay both need the same thing:
//! a single-line text buffer with cursor, insert/backspace/submit/cancel.
//! Neither fits tuirealm's mount/focus model cleanly (Chat is one section of
//! an already-monolithic component; the command line is a transient overlay
//! drawn over whichever screen is showing, not a screen of its own) -- so
//! this is driven manually rather than mounted as its own `Id`.

use tuirealm::command::{Cmd, CmdResult, Direction, Position};
use tuirealm::component::Component;
use tuirealm::event::{Key, KeyEvent, KeyModifiers};
use tuirealm::props::{AttrValue, Attribute, Borders};
use tuirealm::ratatui::layout::Rect;
use tuirealm::ratatui::Frame;
use tuirealm::state::State;
// Package name is `tui-realm-stdlib`; Cargo maps the hyphen to an
// underscore for the Rust import path. Components live under its
// `components` module, not re-exported at the crate root.
use tui_realm_stdlib::components::Input;

pub struct TextInput {
    inner: Input,
}

/// What happened as a result of one keypress handed to a focused `TextInput`.
pub enum TextInputEvent {
    /// Buffer changed (typed a char, backspace, cursor moved, ...) -- caller
    /// should redraw.
    Changed,
    /// Enter pressed -- carries the submitted text (may be empty; callers
    /// decide whether an empty submit is a no-op).
    Submitted(String),
}

impl TextInput {
    pub fn new(title: &str, placeholder: &str) -> Self {
        let inner = Input::default()
            .borders(Borders::default())
            .title(title.to_string())
            .placeholder(placeholder.to_string());
        Self { inner }
    }

    /// Toggles the cursor being drawn -- `Input::view()` only positions a
    /// cursor when its internal `common.focused` flag is set, and this is
    /// the only way to set it since `TextInput` is never mounted (and so
    /// never goes through `Application::active()`, which would otherwise
    /// set this attribute automatically).
    pub fn set_focused(&mut self, focused: bool) {
        self.inner.attr(Attribute::Focus, AttrValue::Flag(focused));
    }

    pub fn clear(&mut self) {
        self.inner
            .attr(Attribute::Value, AttrValue::String(String::new()));
    }

    /// The buffer's current content. Same `state()` -> `unwrap_string()` path
    /// `handle_key`'s `Submitted` case already trusts for the same `Input`.
    pub fn text(&self) -> String {
        self.inner.state().unwrap_single().unwrap_string()
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect) {
        self.inner.view(frame, area);
    }

    /// Translate a raw keyboard event into an `Input` `Cmd` and perform it.
    /// `None` for keys `Input` itself doesn't handle -- notably Esc, which
    /// is deliberately left to the caller (it means "stop composing", not
    /// anything `Input` should know about).
    pub fn handle_key(&mut self, key: &KeyEvent) -> Option<TextInputEvent> {
        let cmd = match key {
            KeyEvent {
                code: Key::Char(c),
                modifiers: KeyModifiers::NONE | KeyModifiers::SHIFT,
            } => Cmd::Type(*c),
            KeyEvent {
                code: Key::Backspace,
                ..
            } => Cmd::Delete,
            KeyEvent {
                code: Key::Delete, ..
            } => Cmd::Cancel,
            KeyEvent {
                code: Key::Left, ..
            } => Cmd::Move(Direction::Left),
            KeyEvent {
                code: Key::Right, ..
            } => Cmd::Move(Direction::Right),
            KeyEvent {
                code: Key::Home, ..
            } => Cmd::GoTo(Position::Begin),
            KeyEvent { code: Key::End, .. } => Cmd::GoTo(Position::End),
            KeyEvent {
                code: Key::Enter, ..
            } => Cmd::Submit,
            _ => return None,
        };
        match self.inner.perform(cmd) {
            CmdResult::Submit(State::Single(value)) => {
                Some(TextInputEvent::Submitted(value.unwrap_string()))
            }
            CmdResult::Changed(_) | CmdResult::Visual => Some(TextInputEvent::Changed),
            _ => None,
        }
    }
}
