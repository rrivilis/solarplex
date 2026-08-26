//! Slot extraction: the two intents that take an actor argument (invite,
//! transfer-ownership), plus the target-session clause every verb accepts.
//! Deliberately *not* part of the compiled grammar — see compile.rs's doc
//! comment. This is plain string/token manipulation over whatever text
//! follows the matched verb prefix: single-word (or un-delimited multi-word)
//! names only, no quoting, no real NLP. Good enough to prove the pipeline;
//! not a claim of general natural-language slot filling.
//!
//! ## Target-session marker word
//!
//! "in <session>" is the universal target-session clause ("pause session in
//! roman-room1", "transfer ownership to bob in roman-room1") — chosen
//! because "to" is already spoken for on transfer (the recipient). Invite is
//! the one exception: its actor slot has no competing use for "to" ("invite
//! bob to roman-room1" — "bob" is delimited by "as"/"to" either way), and
//! "to" is the more natural preposition for a destination there, so invite
//! recognizes "to <session>" instead of "in <session>". Neither marker
//! resolves the name against a real session — see `ParsedIntent`'s doc
//! comment for why that's server-side.
//!
//! ## Duration clause
//!
//! A bare `<number> <unit>` pair ("1 day", "15 minutes") is recognized
//! anywhere in invite's remainder as a TTL and stripped before the
//! invitee/role/target-session logic runs, so "invite bob@x.com 1 day"
//! extracts invitee "bob@x.com" and ttl_secs 86400, not an invitee of
//! "bob@x.com 1 day".

use std::str::FromStr;

use protocol::MemberRole;

/// Word position of the first case-insensitive match for `marker`, if any.
fn find(words: &[&str], marker: &str) -> Option<usize> {
    words.iter().position(|w| w.eq_ignore_ascii_case(marker))
}

fn join_range(words: &[&str], range: std::ops::Range<usize>) -> Option<String> {
    if range.start >= range.end {
        return None;
    }
    let joined = words[range].join(" ");
    if joined.is_empty() {
        None
    } else {
        Some(joined)
    }
}

/// `remainder` is the raw text after the matched "(please) invite" prefix,
/// e.g. "alice as owner", "bob to roman-room1", "bob 1 day", or just "alice".
/// Returns `(role, invitee, target_session, ttl_secs)`.
pub fn extract_invite(
    remainder: &str,
) -> (MemberRole, Option<String>, Option<String>, Option<i64>) {
    let all_words: Vec<&str> = remainder.split_whitespace().collect();
    let (ttl_secs, words) = extract_duration_secs(&all_words);

    let as_pos = find(&words, "as");
    let to_pos = find(&words, "to");
    let invitee_end = [as_pos, to_pos]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(words.len());

    let role = as_pos
        .and_then(|p| words.get(p + 1))
        .and_then(|w| MemberRole::from_str(&w.to_lowercase()).ok())
        .unwrap_or(MemberRole::Collaborator);
    let invitee = join_range(&words, 0..invitee_end);

    // "to <session>" — bounded by "as" on whichever side of "to" it falls,
    // so "bob to roman-room1 as owner" and "bob as owner to roman-room1"
    // both extract target_session "roman-room1", not "roman-room1 as owner".
    let target_session = to_pos.and_then(|tp| {
        let end = as_pos.filter(|&ap| ap > tp).unwrap_or(words.len());
        join_range(&words, tp + 1..end)
    });

    (role, invitee, target_session, ttl_secs)
}

/// Finds the first `<number> <unit>` duration clause anywhere in `words`
/// (`"1 day"`, `"15 minutes"`, `"3 hrs"`, ...) and returns it in seconds
/// alongside `words` with that two-token clause removed — so callers can
/// run their normal slot extraction on what's left without the duration
/// clause getting misread as part of a name. `None`/unchanged `words` if no
/// such clause is present.
pub fn extract_duration_secs<'a>(words: &[&'a str]) -> (Option<i64>, Vec<&'a str>) {
    for i in 0..words.len().saturating_sub(1) {
        if let Ok(n) = words[i].parse::<i64>() {
            if let Some(mult) = duration_unit_secs(words[i + 1]) {
                let mut rest: Vec<&str> = words[..i].to_vec();
                rest.extend_from_slice(&words[i + 2..]);
                return (Some(n * mult), rest);
            }
        }
    }
    (None, words.to_vec())
}

/// Seconds per unit for a single duration-unit word, singular or plural
/// (`"day"`/`"days"`, `"hr"`/`"hrs"`, ...) — matched case-insensitively by
/// stripping one trailing `s` before comparing.
fn duration_unit_secs(word: &str) -> Option<i64> {
    let lower = word.to_lowercase();
    let singular = lower.strip_suffix('s').unwrap_or(&lower);
    match singular {
        "second" | "sec" => Some(1),
        "minute" | "min" => Some(60),
        "hour" | "hr" => Some(3600),
        "day" => Some(86_400),
        "week" => Some(604_800),
        _ => None,
    }
}

/// `remainder` is the raw text after the matched "(please) transfer
/// (ownership)" prefix, e.g. "to bob", "to bob in roman-room1", or just "bob".
pub fn extract_transfer(remainder: &str) -> (Option<String>, Option<String>) {
    let words: Vec<&str> = remainder.split_whitespace().collect();
    let to_pos = find(&words, "to");
    let in_pos = find(&words, "in");

    let recipient = match to_pos {
        Some(tp) => {
            let end = in_pos.filter(|&ip| ip > tp).unwrap_or(words.len());
            join_range(&words, tp + 1..end)
        }
        // No "to" at all — bare "transfer ownership bob" (no target-session
        // marker to worry about colliding with; if "in" appears with no
        // "to", it's the target-session clause, not part of the recipient).
        None => in_pos
            .map(|ip| join_range(&words, 0..ip))
            .unwrap_or_else(|| join_range(&words, 0..words.len())),
    };

    let target_session = in_pos.and_then(|ip| {
        let end = to_pos.filter(|&tp| tp > ip).unwrap_or(words.len());
        join_range(&words, ip + 1..end)
    });

    (recipient, target_session)
}

/// `remainder` for the six verbs with no actor slot of their own
/// (pause/resume/archive/approve/deny/claim) — just looks for "in
/// <session>" anywhere in the trailing text.
pub fn extract_target_session_only(remainder: &str) -> Option<String> {
    let words: Vec<&str> = remainder.split_whitespace().collect();
    let in_pos = find(&words, "in")?;
    join_range(&words, in_pos + 1..words.len())
}

/// `remainder` is the raw text after the matched "(please) attach" prefix,
/// e.g. "agent-x 15 minutes", "agent-x in roman-room1", or just "agent-x".
/// Returns `(name, ttl_secs, target_session)`. No actor-name resolution
/// happens here or server-side — unlike invite/transfer, this name isn't
/// looked up against an existing actor, it's what the *new* agent identity
/// gets called.
pub fn extract_attach(remainder: &str) -> (Option<String>, Option<i64>, Option<String>) {
    let all_words: Vec<&str> = remainder.split_whitespace().collect();
    let (ttl_secs, words) = extract_duration_secs(&all_words);

    let in_pos = find(&words, "in");
    let name = join_range(&words, 0..in_pos.unwrap_or(words.len()));
    let target_session = in_pos.and_then(|ip| join_range(&words, ip + 1..words.len()));

    (name, ttl_secs, target_session)
}
