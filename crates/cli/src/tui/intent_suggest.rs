//! Formats a `GET /api/intent/parse` response (see `client::Client::parse_intent`
//! and `crates/intent/src/intent.rs`'s `Intent` enum, `#[serde(tag = "kind",
//! rename_all = "snake_case")]`) into the ghost-text line the command-line
//! overlay shows under the input. Display-only for now -- every recognized
//! `Intent` kind gets shown, but only the subset `model::Model::run_command`
//! already understands is worth auto-filling into the buffer, so autofill
//! is a natural fast-follow, not part of this first cut.

use serde_json::Value;

/// `None` when nothing was recognized (empty/unparseable input) -- callers
/// should clear any previously-shown suggestion in that case, not leave a
/// stale one on screen.
pub fn format_suggestion(parsed: &Value) -> Option<String> {
    let intent = parsed.get("intent")?;
    if intent.is_null() {
        return None;
    }
    let kind = intent.get("kind")?.as_str()?;

    let resolved_actor = describe_resolution(parsed.pointer("/resolution/actor"));
    let resolved_session = describe_resolution(parsed.pointer("/resolution/target_session"));

    let action = match kind {
        "pause"   => "Pause the session".to_string(),
        "resume"  => "Resume the session".to_string(),
        "archive" => "Archive the session".to_string(),
        "approve" => "Approve".to_string(),
        "deny"    => "Deny".to_string(),
        "claim"   => "Claim".to_string(),
        "navigate" => "Go to a session".to_string(),
        "transfer_ownership" => {
            let to = intent.get("to").and_then(|v| v.as_str()).unwrap_or("?");
            format!("Transfer ownership to {}", resolved_actor.clone().unwrap_or_else(|| to.to_string()))
        }
        "invite" => {
            let invitee = intent.get("invitee").and_then(|v| v.as_str()).unwrap_or("someone");
            let role = intent.get("role").and_then(|v| v.as_str()).unwrap_or("collaborator");
            format!("Invite {} as {role}", resolved_actor.clone().unwrap_or_else(|| invitee.to_string()))
        }
        "attach_agent" => {
            let name = intent.get("name").and_then(|v| v.as_str()).unwrap_or("a new agent");
            format!("Attach agent \"{name}\"")
        }
        _ => return None,
    };

    let target = resolved_session.map(|s| format!(" in {s}")).unwrap_or_default();
    Some(format!("understood as: {action}{target}"))
}

/// Reads a `NameResolution`-shaped value (`routes/intent.rs`'s
/// `#[serde(tag = "status", rename_all = "snake_case")]` enum): `Matched`
/// carries the resolved display name, `Ambiguous`/`NotFound` get a short
/// parenthetical rather than silently vanishing from the suggestion --
/// worth knowing the parser recognized a name it couldn't pin down, not just
/// the names it could.
fn describe_resolution(res: Option<&Value>) -> Option<String> {
    let res = res?;
    match res.get("status")?.as_str()? {
        "matched"   => res.get("name").and_then(|v| v.as_str()).map(String::from),
        "ambiguous" => Some("(ambiguous)".to_string()),
        "not_found" => Some("(not found)".to_string()),
        _           => None,
    }
}
