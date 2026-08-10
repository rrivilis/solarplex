//! Deterministic, non-LLM parser for governance commands typed into
//! CommandPalette or the message composer — "pause this session", "invite
//! alice as owner" — into a structured [`Intent`], without an agent/LLM
//! round-trip. See the architecture discussion this crate came out of: the
//! value isn't better free-text understanding than an LLM would give you,
//! it's determinism and auditability for exactly the high-stakes actions
//! this app's approval-policy model already centers on (pause/archive/
//! approve/transfer-ownership) — a parse failure always falls back to
//! normal behavior (send as a plain chat message / let fuzzy palette
//! matching run), it never guesses.
//!
//! Pipeline: grammar source in `grammar/*.xre` → parsed by `nfst_xre` into
//! an AST → compiled by `compile.rs` into a `rustfst` acceptor (the bridge
//! neither crate ships) → matched against tokenized input by `matcher.rs`'s
//! NFA simulation. Deliberately a small xre subset (`compile.rs`'s doc
//! comment) covering exactly the CLI's governance verb set, not general
//! natural-language understanding.
//!
//! Wired into `crates/server`'s `GET /intent/parse` (not reused by
//! `splx-ir` — see the `authority-ir`-vs-`intent` scoping discussion for why
//! these stay two crates). A parsed [`ParsedIntent`] still goes through
//! every existing authz check on the actual REST/WS path; this crate has no
//! opinion on who's allowed to do what, only on what a human typed — it
//! doesn't even resolve the actor/session *names* it extracts into real
//! IDs, since that needs DB access this crate deliberately doesn't have
//! (see `ParsedIntent`'s doc comment).

mod compile;
mod error;
mod intent;
mod matcher;
mod slots;
mod vocab;

pub use error::IntentError;
pub use intent::{Intent, ParsedIntent};

use std::sync::OnceLock;

use rustfst::fst_impls::VectorFst;
use rustfst::semirings::TropicalWeight;

use vocab::Vocab;

struct Grammars {
    vocab: Vocab,
    pause: VectorFst<TropicalWeight>,
    resume: VectorFst<TropicalWeight>,
    archive: VectorFst<TropicalWeight>,
    approve: VectorFst<TropicalWeight>,
    deny: VectorFst<TropicalWeight>,
    claim: VectorFst<TropicalWeight>,
    invite: VectorFst<TropicalWeight>,
    transfer: VectorFst<TropicalWeight>,
    goto_: VectorFst<TropicalWeight>,
    attach: VectorFst<TropicalWeight>,
}

macro_rules! grammar_src {
    ($name:literal) => {
        include_str!(concat!("../grammar/", $name, ".xre"))
    };
}

impl Grammars {
    fn build() -> Result<Self, IntentError> {
        let mut vocab = Vocab::new();
        Ok(Grammars {
            pause: compile::compile_grammar(grammar_src!("pause"), &mut vocab, "pause")?,
            resume: compile::compile_grammar(grammar_src!("resume"), &mut vocab, "resume")?,
            archive: compile::compile_grammar(grammar_src!("archive"), &mut vocab, "archive")?,
            approve: compile::compile_grammar(grammar_src!("approve"), &mut vocab, "approve")?,
            deny: compile::compile_grammar(grammar_src!("deny"), &mut vocab, "deny")?,
            claim: compile::compile_grammar(grammar_src!("claim"), &mut vocab, "claim")?,
            invite: compile::compile_grammar(grammar_src!("invite"), &mut vocab, "invite")?,
            transfer: compile::compile_grammar(grammar_src!("transfer"), &mut vocab, "transfer")?,
            goto_: compile::compile_grammar(grammar_src!("goto"), &mut vocab, "goto")?,
            attach: compile::compile_grammar(grammar_src!("attach"), &mut vocab, "attach")?,
            vocab,
        })
    }

    /// (grammar name, fst) pairs in a fixed priority order — used to break
    /// ties when more than one grammar happens to accept the same prefix
    /// length (not expected given today's disjoint vocabularies, but a
    /// defined tie-break beats an arbitrary one if that ever changes).
    fn candidates(&self) -> [(&'static str, &VectorFst<TropicalWeight>); 10] {
        [
            ("pause", &self.pause),
            ("resume", &self.resume),
            ("archive", &self.archive),
            ("approve", &self.approve),
            ("deny", &self.deny),
            ("claim", &self.claim),
            ("invite", &self.invite),
            ("transfer", &self.transfer),
            ("goto", &self.goto_),
            ("attach", &self.attach),
        ]
    }
}

fn grammars() -> &'static Grammars {
    static GRAMMARS: OnceLock<Grammars> = OnceLock::new();
    GRAMMARS.get_or_init(|| Grammars::build().expect("bundled grammar/*.xre files failed to compile"))
}

/// Lowercase, split on whitespace, strip a small set of trailing
/// punctuation from each token — enough for short command-style input,
/// not a real tokenizer.
fn tokenize(text: &str) -> Vec<String> {
    text.split_whitespace()
        .map(|w| w.trim_matches(|c: char| matches!(c, '.' | ',' | '!' | '?' | ';' | ':')).to_lowercase())
        .filter(|w| !w.is_empty())
        .collect()
}

/// Parse `text` into a [`ParsedIntent`], or `None` if it doesn't match any
/// known governance-command phrasing — callers should treat `None` as "not
/// a command," not as an error.
pub fn parse_intent(text: &str) -> Option<ParsedIntent> {
    let g = grammars();
    let tokens = tokenize(text);
    // Slot values (names, roles — "alice", "owner") are legitimately absent
    // from every grammar's vocabulary; they only ever appear *after* a
    // verb phrase, never inside one. A sentinel label that can't match any
    // real arc keeps `labels` positionally aligned with `tokens` (so
    // `longest_matching_prefix`'s indices stay meaningful) while still
    // correctly halting the walk the moment an unknown word is reached —
    // whatever prefix was already final by that point is still returned.
    const UNKNOWN: vocab::Label = vocab::Label::MAX;
    let labels: Vec<vocab::Label> = tokens.iter().map(|t| g.vocab.lookup(t).unwrap_or(UNKNOWN)).collect();

    let mut best: Option<(&'static str, usize)> = None;
    for (name, fst) in g.candidates() {
        if let Some(len) = matcher::longest_matching_prefix(fst, &labels) {
            if len == 0 {
                continue; // matching zero tokens (an all-optional grammar) isn't a real command
            }
            match best {
                Some((_, best_len)) if best_len >= len => {}
                _ => best = Some((name, len)),
            }
        }
    }

    let (name, consumed) = best?;
    let remainder = tokens[consumed..].join(" ");
    let (intent, target_session) = match name {
        "pause"   => (Intent::Pause,   slots::extract_target_session_only(&remainder)),
        "resume"  => (Intent::Resume,  slots::extract_target_session_only(&remainder)),
        "archive" => (Intent::Archive, slots::extract_target_session_only(&remainder)),
        "approve" => (Intent::Approve, slots::extract_target_session_only(&remainder)),
        "deny"    => (Intent::Deny,    slots::extract_target_session_only(&remainder)),
        "claim"   => (Intent::Claim,   slots::extract_target_session_only(&remainder)),
        "invite" => {
            let (role, invitee, target_session, ttl_secs) = slots::extract_invite(&remainder);
            (Intent::Invite { role, invitee, ttl_secs }, target_session)
        }
        "transfer" => {
            let (recipient, target_session) = slots::extract_transfer(&remainder);
            (Intent::TransferOwnership { to: recipient? }, target_session)
        }
        // Unlike every other verb, "go to <session>" has nothing to do
        // without a session name — the whole remainder *is* the name (no
        // "in"/"to" marker to strip), and an empty one means this wasn't
        // really a navigation command at all (fail the parse, don't
        // fabricate a Navigate with no destination).
        "goto" => {
            let target = remainder.trim();
            if target.is_empty() { return None; }
            (Intent::Navigate, Some(target.to_string()))
        }
        "attach" => {
            let (name, ttl_secs, target_session) = slots::extract_attach(&remainder);
            (Intent::AttachAgent { name, ttl_secs }, target_session)
        }
        _ => unreachable!("candidates() is a fixed, exhaustive list"),
    };
    Some(ParsedIntent { intent, target_session })
}
