//! `GET /api/search?q=...` — cross-session search. Sessions/artifacts/
//! events are scoped to the caller's own membership, same visibility
//! boundary as `GET /api/activity`; actors are scoped to the caller's
//! co-membership network, same boundary as the Teammates directory — see
//! `db::search`'s module doc comment for the full reasoning.
//!
//! Structured filter syntax on top of free-text: `type:artifact`,
//! `session:<name>`, `actor:<name>` (quote a value to include spaces,
//! e.g. `session:"weekly sync"`), any of which can mix with free text —
//! `type:artifact session:standup logo` means "artifacts named/referencing
//! 'logo', in sessions named like 'standup'". This is a small, local
//! `key:value` tokenizer, not a reuse of the `intent` crate's NFST grammar
//! machinery — that crate matches a small closed vocabulary of *command
//! verbs* ("pause this session"), a fundamentally different shape than an
//! open `key:value` filter language, so parsing it here directly is more
//! honest than bending the wrong tool to fit. What *is* reused: the same
//! membership-scoped name-matching data sources `routes/intent.rs` already
//! resolves names against (`sessions::list_by_actor`, `actors::
//! list_teammates`) — just consumed as "all matches, to filter by" rather
//! than intent's "resolve to exactly one, or ask" semantics, since a search
//! filter narrowing to zero or several sessions/actors is a normal result,
//! not an error requiring disambiguation the way an action-triggering
//! command does.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;

use db::{actors, search, sessions};

use crate::state::AppState;
use autometrics::autometrics;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/", get(search_all))
}

#[derive(Deserialize)]
struct SearchQuery {
    q: String,
    limit: Option<i64>,
}

fn empty_results() -> Json<serde_json::Value> {
    Json(json!({ "sessions": [], "artifacts": [], "actors": [], "events": [] }))
}

#[autometrics]
async fn search_all(
    headers:      HeaderMap,
    Query(q):     Query<SearchQuery>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let actor_id = match crate::auth::require_sp_auth(&state.db, &headers).await {
        Ok(id)   => id,
        Err(res) => return res,
    };

    let raw_query = q.q.trim();
    if raw_query.is_empty() {
        return empty_results().into_response();
    }
    let parsed = parse_query(raw_query);

    // A 1-2 char free-text search against a real column/table would still
    // be an expensive, low-value scan even indexed — same floor a
    // mention-picker/autocomplete would use. Doesn't apply to a
    // structured-filter-only query (`type:artifact` alone has no free text
    // at all, and is still a perfectly good, cheap, indexed search).
    let has_filters = parsed.type_filter.is_some() || parsed.session_filter.is_some() || parsed.actor_filter.is_some();
    let free_text_usable = parsed.free_text.as_deref().is_some_and(|t| t.chars().count() >= 2);
    if !has_filters && !free_text_usable {
        return empty_results().into_response();
    }

    let limit = q.limit.unwrap_or(10).clamp(1, 50);

    let member_sessions = match sessions::list_by_actor(&state.db, &actor_id).await {
        Ok(s)  => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let session_names: HashMap<String, String> =
        member_sessions.iter().map(|s| (s.id.clone(), s.name.clone())).collect();

    // `session:` narrows the searchable session set by a case-insensitive
    // substring match on name — same tier-2 fallback `resolve_by_name` in
    // routes/intent.rs uses, but keeping every match instead of requiring
    // exactly one. No matches means an empty `session_ids`, which every
    // `db::search::*` function below already treats as "search nothing"
    // (not "no filter applied") — a `session:` filter that matches no real
    // session should return no results, not silently fall back to
    // searching everything.
    let session_ids: Vec<String> = match &parsed.session_filter {
        Some(filter) => {
            let needle = filter.to_lowercase();
            member_sessions.iter()
                .filter(|s| s.name.to_lowercase().contains(&needle))
                .map(|s| s.id.clone())
                .collect()
        }
        None => member_sessions.iter().map(|s| s.id.clone()).collect(),
    };

    // `actor:` narrows events/artifacts to those attributed to a matching
    // co-member — same membership boundary `actors::list_teammates` already
    // draws for the Teammates directory and for intent's actor resolution.
    // `Some(vec![])` (filter given, zero teammates matched) is preserved
    // deliberately, same reasoning as session_ids above: a real filter that
    // matches nobody should search nobody, not fall through to unfiltered.
    let actor_ids: Option<Vec<String>> = match &parsed.actor_filter {
        Some(filter) => {
            let needle = filter.to_lowercase();
            let teammates = actors::list_teammates(&state.db, &actor_id).await.unwrap_or_default();
            Some(teammates.into_iter()
                .filter(|t| t.name.to_lowercase().contains(&needle))
                .map(|t| t.id)
                .collect())
        }
        None => None,
    };

    // The "actors" results section is driven by whichever of actor:/free
    // text is more specific — an explicit `actor:` filter takes priority
    // (it's what the caller is actually asking to find), free text is the
    // fallback for a plain "find someone by name" search. A structured
    // query with neither (e.g. bare `type:artifact`) has nothing to search
    // actors by, so that section just comes back empty rather than
    // matching every co-member via an accidental empty-string ILIKE.
    let actor_query_term = parsed.actor_filter.clone().or_else(|| parsed.free_text.clone());

    let (sessions_hit, artifacts_hit, actors_hit, events_hit) = tokio::join!(
        search::search_sessions(&state.db, &session_ids, parsed.free_text.as_deref(), limit),
        search::search_artifacts(
            &state.db, &session_ids, parsed.free_text.as_deref(),
            parsed.type_filter.as_deref(), actor_ids.as_deref(), limit,
        ),
        async {
            match &actor_query_term {
                Some(term) => search::search_actors(&state.db, &actor_id, term, limit).await,
                None       => Ok(vec![]),
            }
        },
        search::search_events(
            &state.db, &session_ids, parsed.free_text.as_deref(),
            parsed.type_filter.as_deref(), actor_ids.as_deref(), limit,
        ),
    );

    let sessions_hit  = sessions_hit.unwrap_or_default();
    let artifacts_hit = artifacts_hit.unwrap_or_default();
    let actors_hit    = actors_hit.unwrap_or_default();
    let events_hit    = events_hit.unwrap_or_default();

    // Enrich artifact/event rows with the session name for display — the
    // same "resolve at render time, from an already-fetched map" pattern
    // activity.rs uses, not a per-row extra query.
    let actor_name_map: HashMap<String, String> = {
        let ids: Vec<String> = events_hit.iter().map(|e| e.actor_id.clone())
            .chain(artifacts_hit.iter().map(|a| a.created_by.clone()))
            .collect();
        actors::get_many(&state.db, &ids).await.unwrap_or_default()
            .into_iter().map(|(id, a)| (id, a.name)).collect()
    };

    Json(json!({
        "sessions": sessions_hit,
        "artifacts": artifacts_hit.iter().map(|a| json!({
            "id": a.id, "session_id": a.session_id,
            "session_name": session_names.get(&a.session_id).cloned().unwrap_or_else(|| "(unknown session)".to_string()),
            "name": a.name, "type": a.r#type,
            "created_by": a.created_by,
            "created_by_name": actor_name_map.get(&a.created_by).cloned().unwrap_or_else(|| a.created_by.clone()),
        })).collect::<Vec<_>>(),
        "actors": actors_hit,
        "events": events_hit.iter().map(|e| json!({
            "id": e.id, "session_id": e.session_id,
            "session_name": session_names.get(&e.session_id).cloned().unwrap_or_else(|| "(unknown session)".to_string()),
            "actor_id": e.actor_id,
            "actor_name": actor_name_map.get(&e.actor_id).cloned().unwrap_or_else(|| e.actor_id.clone()),
            "type": e.r#type, "payload": e.payload, "timestamp": e.timestamp,
        })).collect::<Vec<_>>(),
    })).into_response()
}

// ── Structured query syntax ──────────────────────────────────────────────

#[derive(Debug, Default, PartialEq)]
struct ParsedQuery {
    free_text:      Option<String>,
    type_filter:    Option<String>,
    session_filter: Option<String>,
    actor_filter:   Option<String>,
}

/// Splits `input` into `type:`/`session:`/`actor:` filters plus a free-text
/// remainder. Filter keys are matched case-insensitively; the last
/// occurrence of a given key wins if it's repeated (simplest well-defined
/// behavior, not expected to matter in practice). A later structured
/// upgrade — quoted phrase search, OR/exclusion — belongs in
/// `websearch_to_tsquery`'s own syntax (it already supports quotes and `-`
/// exclusion), not here; this tokenizer's only job is separating the
/// three filter keys from everything that isn't one.
fn parse_query(input: &str) -> ParsedQuery {
    let mut out = ParsedQuery::default();
    let mut free_words: Vec<String> = Vec::new();

    for tok in tokenize_with_quotes(input) {
        if let Some(v) = strip_filter_prefix(&tok, "type:") {
            out.type_filter = Some(v);
        } else if let Some(v) = strip_filter_prefix(&tok, "session:") {
            out.session_filter = Some(v);
        } else if let Some(v) = strip_filter_prefix(&tok, "actor:") {
            out.actor_filter = Some(v);
        } else {
            free_words.push(tok);
        }
    }

    out.free_text = if free_words.is_empty() { None } else { Some(free_words.join(" ")) };
    out
}

/// Case-insensitive prefix match on a `key:` marker — returns the rest of
/// the token (the filter value) if `tok` starts with it, `None` otherwise.
/// A bare `"type:"` with nothing after it (`tok.len() == key.len()`)
/// deliberately does not match — an empty filter value isn't a real filter,
/// it'd just fall through and get treated as free text instead, which is
/// the more useful behavior for an accidental trailing colon.
fn strip_filter_prefix(tok: &str, key: &str) -> Option<String> {
    (tok.len() > key.len() && tok.as_bytes()[..key.len()].eq_ignore_ascii_case(key.as_bytes()))
        .then(|| tok[key.len()..].to_string())
}

/// Whitespace-splits `input`, except a double-quoted span counts as one
/// token with the quotes stripped — so `session:"weekly sync" bug` yields
/// `["session:weekly sync", "bug"]`, letting a filter value contain spaces.
/// An unterminated quote just runs to the end of input rather than erroring
/// — best-effort, not a strict parser.
fn tokenize_with_quotes(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        let mut tok = String::new();
        while let Some(&c) = chars.peek() {
            if c.is_whitespace() { break; }
            if c == '"' {
                chars.next();
                while let Some(&c) = chars.peek() {
                    chars.next();
                    if c == '"' { break; }
                    tok.push(c);
                }
                continue;
            }
            tok.push(c);
            chars.next();
        }
        if !tok.is_empty() { tokens.push(tok); }
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_free_text_only() {
        let p = parse_query("logo bug");
        assert_eq!(p, ParsedQuery { free_text: Some("logo bug".into()), ..Default::default() });
    }

    #[test]
    fn single_structured_filter_no_free_text() {
        let p = parse_query("type:artifact");
        assert_eq!(p, ParsedQuery { type_filter: Some("artifact".into()), ..Default::default() });
    }

    #[test]
    fn mixed_filters_and_free_text_any_order() {
        let p = parse_query("logo type:artifact session:standup");
        assert_eq!(p, ParsedQuery {
            free_text: Some("logo".into()),
            type_filter: Some("artifact".into()),
            session_filter: Some("standup".into()),
            ..Default::default()
        });
    }

    #[test]
    fn quoted_multi_word_filter_value() {
        let p = parse_query(r#"session:"weekly sync" bug"#);
        assert_eq!(p, ParsedQuery {
            free_text: Some("bug".into()),
            session_filter: Some("weekly sync".into()),
            ..Default::default()
        });
    }

    #[test]
    fn filter_keys_are_case_insensitive() {
        let p = parse_query("TYPE:artifact Session:standup Actor:alice");
        assert_eq!(p, ParsedQuery {
            type_filter: Some("artifact".into()),
            session_filter: Some("standup".into()),
            actor_filter: Some("alice".into()),
            ..Default::default()
        });
    }

    #[test]
    fn bare_key_with_no_value_falls_back_to_free_text() {
        let p = parse_query("type: artifact");
        assert_eq!(p, ParsedQuery { free_text: Some("type: artifact".into()), ..Default::default() });
    }

    #[test]
    fn unterminated_quote_runs_to_end_of_input() {
        let p = parse_query(r#"session:"weekly sync"#);
        assert_eq!(p, ParsedQuery { session_filter: Some("weekly sync".into()), ..Default::default() });
    }

    #[test]
    fn empty_input_produces_no_tokens() {
        assert_eq!(parse_query(""), ParsedQuery::default());
        assert_eq!(parse_query("   "), ParsedQuery::default());
    }
}
