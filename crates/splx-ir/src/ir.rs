//! Mirrors the entry/delegation/capability types in `sp-dsl/src/ir.lisp` —
//! the wire-serialized subset only (graph/node/principal containers aren't
//! serialized by serializer.lisp; a consumer receives entries/delegations/
//! capabilities as a stream and assembles its own local view from them).

use lexpr::Value;

use crate::algebra::{ConditionSet, OpSet};
use crate::parse::{as_kw, is_lisp_nil, require_str, IrError, TaggedList};
use crate::resource::Resource;

#[derive(Debug, Clone, PartialEq)]
pub struct AuthorityEntry {
    pub resource: Resource,
    pub ops: OpSet,
    pub conditions: Option<ConditionSet>,
}

impl AuthorityEntry {
    pub fn from_value(v: &Value) -> Result<Self, IrError> {
        let list = TaggedList::parse(v)?;
        list.expect_tag("entry")?;
        let conditions = match list.get("conditions") {
            Some(cv) if !is_lisp_nil(cv) => Some(ConditionSet::from_plist_value(cv)?),
            _ => None,
        };
        Ok(AuthorityEntry {
            resource: Resource::from_value(list.require("resource")?)?,
            ops: OpSet::from_value(list.require("ops")?)?,
            conditions,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Delegation {
    pub grantor: String,
    pub grantee: String,
    pub authority: Vec<AuthorityEntry>,
}

impl Delegation {
    pub fn from_value(v: &Value) -> Result<Self, IrError> {
        let list = TaggedList::parse(v)?;
        list.expect_tag("delegation")?;
        Ok(Delegation {
            grantor: require_str(list.require("grantor")?, "grantor")?.to_string(),
            grantee: require_str(list.require("grantee")?, "grantee")?.to_string(),
            authority: parse_entry_list(list.require("authority")?)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum CapAction {
    Delegate,
    Invoke,
    Other(String),
}

impl CapAction {
    fn from_value(v: &Value) -> Result<Self, IrError> {
        match as_kw(v) {
            Some("delegate") => Ok(CapAction::Delegate),
            Some("invoke") => Ok(CapAction::Invoke),
            Some(other) => Ok(CapAction::Other(other.to_string())),
            None => Err(IrError::BadValue {
                key: "action",
                detail: format!("expected keyword, got {v}"),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Capability {
    pub action: CapAction,
    pub subject: String,
    pub authority: Vec<AuthorityEntry>,
    pub derived_from: Option<String>,
    pub conditions: Option<ConditionSet>,
    /// Opaque plist per ir.lisp's own doc comment — kept as the raw parsed
    /// value rather than typed, matching that it's genuinely open-ended.
    pub metadata: Option<Value>,
}

impl Capability {
    pub fn from_value(v: &Value) -> Result<Self, IrError> {
        let list = TaggedList::parse(v)?;
        list.expect_tag("capability")?;
        let conditions = match list.get("conditions") {
            Some(cv) if !is_lisp_nil(cv) => Some(ConditionSet::from_plist_value(cv)?),
            _ => None,
        };
        let derived_from = match list.get("derived-from") {
            Some(dv) if !is_lisp_nil(dv) => Some(require_str(dv, "derived-from")?.to_string()),
            _ => None,
        };
        let metadata = match list.get("metadata") {
            Some(mv) if !is_lisp_nil(mv) => Some(mv.clone()),
            _ => None,
        };
        Ok(Capability {
            action: CapAction::from_value(list.require("action")?)?,
            subject: require_str(list.require("subject")?, "subject")?.to_string(),
            authority: parse_entry_list(list.require("authority")?)?,
            derived_from,
            conditions,
            metadata,
        })
    }
}

fn parse_entry_list(v: &Value) -> Result<Vec<AuthorityEntry>, IrError> {
    if is_lisp_nil(v) {
        return Ok(Vec::new());
    }
    v.list_iter()
        .ok_or_else(|| IrError::BadValue {
            key: "authority",
            detail: format!("expected a list, got {v}"),
        })?
        .map(AuthorityEntry::from_value)
        .collect()
}
