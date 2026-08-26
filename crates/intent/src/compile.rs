//! Compiles the deliberately-small subset of `nfst_xre::XreExpr` this crate
//! supports — `Symbol`, `Binary(Concatenate)`, `Binary(Union)`, `Optional`,
//! `Group` — into a `rustfst` acceptor (NFA). This is the "compiler bridge
//! AST → rustfst::Fst" that neither `nfst-xre` nor `rustfst` ship on their
//! own. Deliberately not a general xre compiler: no `Any`/wildcard, no
//! repeat counts, no transducer pair/replace/restriction support. Slot
//! values (invitee name, transfer recipient) are extracted separately in
//! `slots.rs` from the raw text *after* this Fst identifies which verb
//! matched — this Fst's only job is "which intent, if any, does this
//! token prefix match."

use nfst_xre::{BinaryOp, XreExpr};
use rustfst::algorithms::rm_epsilon::rm_epsilon;
use rustfst::fst_impls::VectorFst;
use rustfst::fst_traits::MutableFst;
use rustfst::semirings::{Semiring, TropicalWeight};
use rustfst::StateId;

use crate::error::IntentError;
use crate::vocab::{Vocab, EPSILON};

/// Recursively compile `expr` starting from `start`, returning the state
/// reached after matching it. Callers thread one `start`/end state per
/// concatenation step; `Union`/`Optional` fan in via epsilon arcs.
fn compile_expr(
    fst: &mut VectorFst<TropicalWeight>,
    vocab: &mut Vocab,
    expr: &XreExpr,
    start: StateId,
    grammar: &'static str,
) -> Result<StateId, IntentError> {
    match expr {
        XreExpr::Symbol(s) => {
            // A quoted literal's whitespace-separated words become a linear
            // chain of one arc per word — confirmed empirically that
            // `"pause session"` (one quoted symbol) and `"pause" "session"`
            // (two concatenated symbols) should behave identically for
            // word-level matching, so both are compiled the same way here.
            let mut cur = start;
            for word in s.as_str().split_whitespace() {
                let label = vocab.intern(word);
                let next = fst.add_state();
                fst.emplace_tr(cur, label, label, TropicalWeight::one(), next)
                    .map_err(|e| IntentError::Fst(e.to_string()))?;
                cur = next;
            }
            Ok(cur)
        }
        XreExpr::Binary(BinaryOp::Concatenate, a, b) => {
            let mid = compile_expr(fst, vocab, &a.value, start, grammar)?;
            compile_expr(fst, vocab, &b.value, mid, grammar)
        }
        XreExpr::Binary(BinaryOp::Union, a, b) => {
            let end_a = compile_expr(fst, vocab, &a.value, start, grammar)?;
            let end_b = compile_expr(fst, vocab, &b.value, start, grammar)?;
            let end = fst.add_state();
            fst.emplace_tr(end_a, EPSILON, EPSILON, TropicalWeight::one(), end)
                .map_err(|e| IntentError::Fst(e.to_string()))?;
            fst.emplace_tr(end_b, EPSILON, EPSILON, TropicalWeight::one(), end)
                .map_err(|e| IntentError::Fst(e.to_string()))?;
            Ok(end)
        }
        XreExpr::Optional(inner) => {
            let end_inner = compile_expr(fst, vocab, &inner.value, start, grammar)?;
            let end = fst.add_state();
            // "Do the thing" branch.
            fst.emplace_tr(end_inner, EPSILON, EPSILON, TropicalWeight::one(), end)
                .map_err(|e| IntentError::Fst(e.to_string()))?;
            // "Skip it" branch.
            fst.emplace_tr(start, EPSILON, EPSILON, TropicalWeight::one(), end)
                .map_err(|e| IntentError::Fst(e.to_string()))?;
            Ok(end)
        }
        XreExpr::Group(inner) => compile_expr(fst, vocab, &inner.value, start, grammar),
        other => Err(IntentError::UnsupportedConstruct {
            grammar,
            detail: format!("{other:?}"),
        }),
    }
}

/// Parse `source` as xre and compile it into a standalone acceptor: single
/// start state, single final state (the expression's end state), epsilons
/// removed so runtime matching only ever has to follow real-word arcs.
pub fn compile_grammar(
    source: &str,
    vocab: &mut Vocab,
    grammar: &'static str,
) -> Result<VectorFst<TropicalWeight>, IntentError> {
    let spanned = nfst_xre::parse(source).map_err(|e| IntentError::GrammarParse {
        grammar,
        detail: format!("{e:?}"),
    })?;
    let mut fst = VectorFst::<TropicalWeight>::new();
    let start = fst.add_state();
    fst.set_start(start)
        .map_err(|e| IntentError::Fst(e.to_string()))?;
    let end = compile_expr(&mut fst, vocab, &spanned.value, start, grammar)?;
    fst.set_final(end, TropicalWeight::one())
        .map_err(|e| IntentError::Fst(e.to_string()))?;
    rm_epsilon(&mut fst).map_err(|e| IntentError::Fst(e.to_string()))?;
    Ok(fst)
}
