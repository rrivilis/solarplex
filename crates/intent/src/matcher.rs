//! NFA state-set simulation over a compiled (epsilon-free) grammar Fst.
//! `Union`/`Optional` make these genuinely nondeterministic — e.g. "please
//! pause session" and "pause the session" both need to reach the same
//! final state via different paths — so this tracks a *set* of current
//! states rather than assuming a single deterministic walk, same idea as
//! the textbook NFA-simulation algorithm. rustfst has determinization
//! available, but hand-rolling this over a handful of small, hand-built
//! acceptors is simpler than getting weighted determinization's tie-break
//! semantics right for a case that doesn't need it.

use std::collections::BTreeSet;

use rustfst::fst_impls::VectorFst;
use rustfst::fst_traits::CoreFst;
use rustfst::semirings::TropicalWeight;
use rustfst::{StateId, Trs};

use crate::vocab::Label;

/// Returns the longest prefix length (in tokens) for which `fst` reaches a
/// final state, or `None` if no prefix (including the empty one) does.
pub fn longest_matching_prefix(fst: &VectorFst<TropicalWeight>, tokens: &[Label]) -> Option<usize> {
    let start = fst.start()?;
    let mut current: BTreeSet<StateId> = BTreeSet::from([start]);
    let mut best: Option<usize> = None;
    if current.iter().any(|&s| fst.is_final(s).unwrap_or(false)) {
        best = Some(0);
    }
    for (i, &tok) in tokens.iter().enumerate() {
        let mut next: BTreeSet<StateId> = BTreeSet::new();
        for &s in &current {
            for tr in fst.get_trs(s).unwrap().trs() {
                if tr.ilabel == tok {
                    next.insert(tr.nextstate);
                }
            }
        }
        if next.is_empty() {
            break;
        }
        current = next;
        if current.iter().any(|&s| fst.is_final(s).unwrap_or(false)) {
            best = Some(i + 1);
        }
    }
    best
}
