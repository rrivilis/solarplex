//! Mirrors `sp-dsl/src/algebra.lisp`'s primitive lattice types, as consumed
//! from the wire — not the lattice/subset predicates themselves (those are
//! verification logic that stays authoritative on the Lisp side; this crate
//! reads already-verified output, it doesn't re-verify it).

use lexpr::Value;

use crate::parse::{as_kw, is_lisp_nil, keyword_list, IrError};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OpSet(pub Vec<String>);

impl OpSet {
    pub fn from_value(v: &Value) -> Result<Self, IrError> {
        Ok(OpSet(keyword_list(v, "ops")?))
    }

    pub fn contains(&self, op: &str) -> bool {
        self.0.iter().any(|o| o == op)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathGlob(pub String);

/// The open condition plist (`:ttl`, `:quorum`, `:single-use`, `:audit`,
/// `:expires-at`, `:epoch`, and whatever else a future provider adds) —
/// modeled generically rather than as fixed fields, matching how
/// serializer.lisp itself walks it: `(loop for (key val) on conditions ...)`
/// with no hardcoded key list.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ConditionSet(pub Vec<(String, ConditionValue)>);

#[derive(Debug, Clone, PartialEq)]
pub enum ConditionValue {
    Int(i64),
    /// Covers the boolean-ish `t` symbol Common Lisp uses for true, plus
    /// non-numeric quorum role names like `guardian`.
    Symbol(String),
    SymbolList(Vec<String>),
    Nil,
}

impl ConditionValue {
    pub fn from_value(v: &Value) -> Result<Self, IrError> {
        if is_lisp_nil(v) {
            return Ok(ConditionValue::Nil);
        }
        if let Some(i) = v.as_i64() {
            return Ok(ConditionValue::Int(i));
        }
        if let Some(s) = as_kw(v).or_else(|| v.as_symbol()) {
            return Ok(ConditionValue::Symbol(s.to_string()));
        }
        if let Some(iter) = v.list_iter() {
            let syms = iter
                .map(|item| {
                    as_kw(item)
                        .or_else(|| item.as_symbol())
                        .map(str::to_string)
                        .ok_or_else(|| IrError::BadValue {
                            key: "condition-value",
                            detail: format!("expected symbol in list, got {item}"),
                        })
                })
                .collect::<Result<Vec<_>, IrError>>()?;
            return Ok(ConditionValue::SymbolList(syms));
        }
        Err(IrError::BadValue { key: "condition-value", detail: format!("unrecognized shape: {v}") })
    }

    /// True for the Lisp `t` symbol specifically — the boolean-condition
    /// convention `:single-use t` / `:audit t` uses.
    pub fn is_true(&self) -> bool {
        matches!(self, ConditionValue::Symbol(s) if s == "t")
    }
}

impl ConditionSet {
    pub fn from_plist_value(v: &Value) -> Result<Self, IrError> {
        if is_lisp_nil(v) {
            return Ok(ConditionSet::default());
        }
        let items: Vec<&Value> = v
            .list_iter()
            .ok_or_else(|| IrError::BadValue { key: "conditions", detail: format!("expected a plist, got {v}") })?
            .collect();
        if !items.len().is_multiple_of(2) {
            return Err(IrError::BadValue { key: "conditions", detail: "odd-length condition plist".into() });
        }
        let mut out = Vec::with_capacity(items.len() / 2);
        for pair in items.chunks(2) {
            let key = as_kw(pair[0]).ok_or_else(|| IrError::BadValue {
                key: "conditions",
                detail: format!("non-keyword condition key: {}", pair[0]),
            })?;
            out.push((key.to_string(), ConditionValue::from_value(pair[1])?));
        }
        Ok(ConditionSet(out))
    }

    pub fn get(&self, key: &str) -> Option<&ConditionValue> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }
}
