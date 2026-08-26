//! `spsh`'s command-line escape hatch: a `:`-triggered modal overlay,
//! rendered on top of whichever screen is showing, not tied to any one
//! screen -- reaches things the current screen doesn't have a hotkey for.
//!
//! Mounted as its own top-level tuirealm component, unlike the chat compose
//! line in `SessionDetail`: this needs genuine global exclusive focus while
//! open (nothing else should react to keys while you're typing a command),
//! which is exactly what `Application::active()`/`blur()` already give you
//! -- the chat input doesn't need that, it's one section of an
//! already-monolithic component, not a screen-wide overlay.

use tuirealm::command::{Cmd, CmdResult};
use tuirealm::component::{AppComponent, Component};
use tuirealm::event::{Event, Key, KeyEvent, KeyModifiers, NoUserEvent};
use tuirealm::props::{AttrValue, Attribute, Props, QueryResult};
use tuirealm::ratatui::layout::{Constraint, Direction as LayoutDirection, Layout, Rect};
use tuirealm::ratatui::style::{Color, Style};
use tuirealm::ratatui::widgets::Paragraph;
use tuirealm::ratatui::Frame;
use tuirealm::state::State;

use super::model::Msg;
use super::text_input::{TextInput, TextInputEvent};

pub struct CommandLine {
    props: Props,
    input: TextInput,
    /// The intent-parser's ghost-text suggestion for the current buffer, if
    /// any -- pushed in from `Model` via `attr(Attribute::Text, ...)` (see
    /// that method below for why this is the mechanism: components are
    /// type-erased once mounted, this is tuirealm's own sanctioned way to
    /// push data into one from outside). `None` clears the line entirely
    /// rather than leaving a stale suggestion for text that's since changed.
    suggestion: Option<String>,
}

impl CommandLine {
    pub fn new() -> Self {
        let mut input = TextInput::new(
            " : ",
            "OwnershipTransfer --to bob   (Esc cancel -- session/<id> auto-filled when a session is open)",
        );
        input.set_focused(true);
        Self {
            props: Props::default(),
            input,
            suggestion: None,
        }
    }
}

impl Default for CommandLine {
    fn default() -> Self {
        Self::new()
    }
}

impl Component for CommandLine {
    fn view(&mut self, frame: &mut Frame, area: Rect) {
        let Some(ref suggestion) = self.suggestion else {
            self.input.render(frame, area);
            return;
        };
        // One extra row below the (unchanged-size) bordered input box for
        // the suggestion line -- `Model::view` grows the overlay's own Rect
        // by the same one row exactly when a suggestion is present, so this
        // never has to squeeze the input box itself to make room.
        let [input_area, suggestion_area] = Layout::default()
            .direction(LayoutDirection::Vertical)
            .constraints([
                Constraint::Length(area.height.saturating_sub(1)),
                Constraint::Length(1),
            ])
            .areas(area);
        self.input.render(frame, input_area);
        frame.render_widget(
            Paragraph::new(format!(" \u{2192} {suggestion}"))
                .style(Style::default().fg(Color::DarkGray)),
            suggestion_area,
        );
    }

    fn query<'a>(&'a self, attr: Attribute) -> Option<QueryResult<'a>> {
        self.props.get_for_query(attr)
    }

    fn attr(&mut self, attr: Attribute, value: AttrValue) {
        // Repurposed as the one channel `Model` has to push the intent
        // suggestion in -- `CommandLine` has no other use for `Attribute::Text`
        // (its actual content is `TextInput`'s own buffer, driven directly
        // through `handle_key`, not through this trait method at all).
        if attr == Attribute::Text {
            self.suggestion = value
                .as_string()
                .filter(|s| !s.is_empty())
                .map(String::from);
        }
        self.props.set(attr, value);
    }

    fn state(&self) -> State {
        State::None
    }

    fn perform(&mut self, cmd: Cmd) -> CmdResult {
        CmdResult::Invalid(cmd) // key handling goes through `TextInput` directly in `on()`, not `perform`
    }
}

impl AppComponent<Msg, NoUserEvent> for CommandLine {
    fn on(&mut self, ev: &Event<NoUserEvent>) -> Option<Msg> {
        let key = ev.as_keyboard()?;
        if matches!(
            key,
            KeyEvent {
                code: Key::Esc,
                modifiers: KeyModifiers::NONE
            }
        ) {
            return Some(Msg::CloseCommandLine);
        }
        match self.input.handle_key(key) {
            // Carries the buffer, not just a bare redraw signal -- `Model`
            // needs the current text to (re)schedule the debounced intent-
            // suggestion lookup; see `Msg::CommandLineChanged`.
            Some(TextInputEvent::Changed) => Some(Msg::CommandLineChanged(self.input.text())),
            Some(TextInputEvent::Submitted(text)) => Some(Msg::RunCommand(text)),
            None => None,
        }
    }
}
