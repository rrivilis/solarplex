//! Mirrors `sp-dsl/src/operational.lisp`'s `effect`/`delta` — the
//! description/execution split the Lisp side's own comment names directly:
//! "An effect... does not execute anything — it is a pure data description.
//! This separates description (effect) from execution (the runtime that
//! receives the delta and carries out the action, potentially after human
//! approval)." This crate *is* that runtime's read side.

use lexpr::Value;

use crate::ir::AuthorityEntry;
use crate::parse::{as_kw, is_lisp_nil, require_i64, IrError, TaggedList};

#[derive(Debug, Clone, PartialEq)]
pub struct Effect {
    pub kind: String,
    /// "string or structured" per operational.lisp — a path for fs-effect,
    /// an AnyOrInt-shaped value for process/ipc-effect, a host/url string
    /// for net/http-effect. Kept opaque rather than guessing one shape.
    pub resource_spec: Value,
    pub payload: Option<Value>,
}

impl Effect {
    pub fn from_value(v: &Value) -> Result<Self, IrError> {
        let list = TaggedList::parse(v)?;
        list.expect_tag("effect")?;
        let kind = as_kw(list.require("kind")?)
            .ok_or_else(|| IrError::BadValue { key: "kind", detail: "expected keyword".into() })?
            .to_string();
        let payload = match list.get("payload") {
            Some(p) if !is_lisp_nil(p) => Some(p.clone()),
            _ => None,
        };
        Ok(Effect { kind, resource_spec: list.require("resource-spec")?.clone(), payload })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Delta {
    pub effect: Effect,
    pub authority: AuthorityEntry,
    pub epoch: i64,
    /// `nil` outside a saga context.
    pub saga_id: Option<String>,
    pub sequence: i64,
    /// Opaque: a hash, a state-id, or the symbol `:unknown`.
    pub before: Value,
    pub after: Value,
    pub timestamp: i64,
}

impl Delta {
    pub fn from_value(v: &Value) -> Result<Self, IrError> {
        let list = TaggedList::parse(v)?;
        list.expect_tag("delta")?;
        let saga_id = match list.get("saga-id") {
            Some(sv) if sv.is_string() => Some(sv.as_str().unwrap().to_string()),
            _ => None,
        };
        Ok(Delta {
            effect: Effect::from_value(list.require("effect")?)?,
            authority: AuthorityEntry::from_value(list.require("authority")?)?,
            epoch: require_i64(list.require("epoch")?, "epoch")?,
            saga_id,
            sequence: require_i64(list.require("sequence")?, "sequence")?,
            before: list.require("before")?.clone(),
            after: list.require("after")?.clone(),
            timestamp: require_i64(list.require("timestamp")?, "timestamp")?,
        })
    }
}
