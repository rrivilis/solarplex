//! `spsh` -- the `sp shell` TUI dashboard.
//!
//! Runs alongside the existing one-shot `sp <verb>` commands and the
//! fish-integrated shell (OSC-133, the credential seatbelt), it does not
//! replace either. No typed command-input line (out of scope for v1
//! entirely, see the approved plan at the time this was written).
//!
//! Step 1: static skeleton -- session list, Up/Down navigation, Esc to quit.
//! Step 2: drill-in navigation -- Enter on a session opens Members/Artifacts/
//! Approvals (Tab to switch, Esc to go back to the list, not quit).
//! Step 3: live WS push while a session's detail view is open -- see
//! `model::Model::poll_live` for why this is drained outside tuirealm's own
//! tick loop rather than through a component's `on()`.
//! Mouse: click-to-select/activate (session rows, detail rows, tabs) -- see
//! `enable_mouse_capture` in `model::Model::new`.
//! Chat: a 4th `SessionDetail` section, using `text_input::TextInput`
//! (wraps `tui-realm-stdlib`'s `Input`) for the compose line.
//! Command line: `:`-triggered overlay (`command_line`), debounced
//! `/api/intent/parse` suggestions shown as ghost text underneath it (see
//! `model::Model::poll_intent_suggestion` and `intent_suggest`).

mod command_line;
mod intent_suggest;
mod model;
mod session_detail;
mod session_list;
mod text_input;
mod ws;

use anyhow::Result;
use tuirealm::application::PollStrategy;

use crate::config::Ctx;
use model::Model;

pub async fn run(ctx: &Ctx) -> Result<()> {
    let mut model = Model::new(ctx).await?;

    while !model.quit {
        match model
            .app
            .tick(PollStrategy::Once(std::time::Duration::from_millis(20)))
        {
            Err(e) => {
                tracing::warn!("spsh: tick error: {e}");
            }
            Ok(messages) if !messages.is_empty() => {
                for msg in messages {
                    model.update(msg).await;
                }
            }
            _ => {}
        }
        model.poll_live().await;
        model.poll_intent_suggestion().await;
        if model.redraw {
            model.view();
            model.redraw = false;
        }
    }

    Ok(())
}
