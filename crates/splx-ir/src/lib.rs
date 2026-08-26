//! Rust-side reader for `sp-dsl`'s `authority-dsl` — specifically the
//! s-expression wire format `authority-dsl/serializer` (sp-dsl/src/serializer.lisp)
//! emits: `(:type-tag :slot value ...)`, pure lists/keywords/strings/numbers,
//! "nothing that requires a running image to read back" (the Lisp file's
//! own words). This crate is the previously-missing other half of that
//! contract — the Lisp side built and tested its emitter; nothing on the
//! Rust side ever read it. See docs/dsl-guide.md for the DSL itself.
//!
//! Scope: deserialize only, matching what serializer.lisp actually
//! serializes (entries/delegations/capabilities, effects/deltas, saga
//! receipts/logs — not the graph/node/principal containers, which aren't
//! wire types on the Lisp side either). This crate does not re-verify
//! authority-subset-p or re-implement any lattice logic from algebra.lisp —
//! it reads already-computed, already-verified output. Re-verifying in Rust
//! would be duplicating the one thing the Lisp side is supposed to be
//! authoritative for.
//!
//! Not wired into `crates/guardian` or `crates/session` yet — that's a
//! separate, deliberate integration decision for whoever picks a concrete
//! consumer, not assumed here.

pub mod algebra;
pub mod ir;
pub mod operational;
pub mod parse;
pub mod resource;
pub mod saga;

pub use algebra::{ConditionSet, ConditionValue, OpSet, PathGlob};
pub use ir::{AuthorityEntry, CapAction, Capability, Delegation};
pub use operational::{Delta, Effect};
pub use parse::{AnyOrInt, IrError};
pub use resource::Resource;
pub use saga::{SagaLog, SagaLogEntry, SagaLogPayload, SendReceipt, TransferReceipt};

/// Parse any one of the top-level tagged forms serializer.lisp emits,
/// dispatching on its `:tag`. Use this when the wire message's type isn't
/// known ahead of time (e.g. reading a heterogeneous stream); call the
/// specific `T::from_value`/`from_str` directly when it is.
#[derive(Debug, Clone, PartialEq)]
pub enum SplxValue {
    Entry(AuthorityEntry),
    Delegation(Delegation),
    Capability(Capability),
    Effect(Effect),
    Delta(Delta),
    TransferReceipt(TransferReceipt),
    SendReceipt(SendReceipt),
    SagaLogEntry(SagaLogEntry),
    SagaLog(SagaLog),
}

impl std::str::FromStr for SplxValue {
    type Err = IrError;
    fn from_str(s: &str) -> Result<Self, IrError> {
        let v = parse::parse_root(s)?;
        Self::from_value(&v)
    }
}

impl SplxValue {
    pub fn from_value(v: &lexpr::Value) -> Result<Self, IrError> {
        let tag = parse::TaggedList::parse(v)?.tag.to_string();
        match tag.as_str() {
            "entry" => Ok(SplxValue::Entry(AuthorityEntry::from_value(v)?)),
            "delegation" => Ok(SplxValue::Delegation(Delegation::from_value(v)?)),
            "capability" => Ok(SplxValue::Capability(Capability::from_value(v)?)),
            "effect" => Ok(SplxValue::Effect(Effect::from_value(v)?)),
            "delta" => Ok(SplxValue::Delta(Delta::from_value(v)?)),
            "transfer-receipt" => Ok(SplxValue::TransferReceipt(TransferReceipt::from_value(v)?)),
            "send-receipt" => Ok(SplxValue::SendReceipt(SendReceipt::from_value(v)?)),
            "saga-log-entry" => Ok(SplxValue::SagaLogEntry(SagaLogEntry::from_value(v)?)),
            "saga-log" => Ok(SplxValue::SagaLog(SagaLog::from_value(v)?)),
            other => Err(IrError::WrongTag {
                expected: "a known splx-ir wire tag",
                actual: other.to_string(),
            }),
        }
    }
}
