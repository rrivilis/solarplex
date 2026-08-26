//! Shared helpers for reading the `(:tag :key value ...)` shape every
//! authority-dsl `serialize` method in `sp-dsl/src/serializer.lisp` produces.
//!
//! Depends on `lexpr` directly rather than `serde-lexpr`'s derive path: the
//! Lisp side's format is a hand-rolled tagged property list, not the shape
//! serde's derive macros assume for structs/enums (`serde-lexpr` builds on
//! the same `lexpr::Value` this module uses, so nothing is lost — this just
//! walks the AST explicitly instead of fighting serde's data model for a
//! convention it wasn't designed to express).

use lexpr::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IrError {
    #[error("lexpr parse error: {0}")]
    Parse(#[from] lexpr::parse::Error),
    #[error("expected a tagged list, got: {0}")]
    NotATaggedList(String),
    #[error("expected tag :{expected}, got :{actual}")]
    WrongTag {
        expected: &'static str,
        actual: String,
    },
    #[error("missing required key :{0}")]
    MissingKey(&'static str),
    #[error("key :{key} has wrong shape: {detail}")]
    BadValue { key: &'static str, detail: String },
}

/// `lexpr`'s default parser (CL/elisp-flavored, no explicit keyword syntax
/// configured) reads Common Lisp's leading-colon keywords as an ordinary
/// `Value::Symbol` whose text still has the colon — `:pid` comes back as
/// `Symbol(":pid")`, not `Value::Keyword("pid")`. Checking `as_keyword()`
/// first still covers a differently-configured parser; the symbol-with-
/// colon-prefix branch is what this crate's default `from_str` actually
/// hits in practice (confirmed empirically, not assumed).
pub fn as_kw(v: &Value) -> Option<&str> {
    if let Some(k) = v.as_keyword() {
        return Some(k);
    }
    v.as_symbol().and_then(|s| s.strip_prefix(':'))
}

/// Common Lisp's `nil` is simultaneously "false" and "the empty list" — one
/// object. `lexpr`'s default parser doesn't collapse that: `nil` comes back
/// as `Symbol("nil")`, and only literal `()` comes back as `Value::Null`
/// (confirmed empirically, same as the `as_kw` situation above). Every
/// `(when (foo x) (serialize (foo x)))` conditional-field in serializer.lisp
/// — i.e. every optional field in this whole wire format — depends on
/// recognizing both shapes as "absent," so this one check is load-bearing
/// everywhere, not a one-off.
pub fn is_lisp_nil(v: &Value) -> bool {
    v.is_nil() || v.is_null() || matches!(v.as_symbol(), Some("nil"))
}

/// Split `(:tag :k1 v1 :k2 v2 ...)` into its tag keyword and the flat
/// `(keyword, value)` pairs that follow — mirrors serializer.lisp's own
/// `(loop for (key val) on plist by #'cddr ...)` walk.
pub struct TaggedList<'a> {
    pub tag: &'a str,
    pairs: Vec<(&'a str, &'a Value)>,
}

impl<'a> TaggedList<'a> {
    pub fn parse(v: &'a Value) -> Result<Self, IrError> {
        let mut items = v
            .list_iter()
            .ok_or_else(|| IrError::NotATaggedList(format!("{v}")))?;
        let tag = items
            .next()
            .and_then(as_kw)
            .ok_or_else(|| IrError::NotATaggedList(format!("{v}")))?;
        let rest: Vec<&Value> = items.collect();
        if !rest.len().is_multiple_of(2) {
            return Err(IrError::NotATaggedList(format!(
                "odd number of plist elements after tag :{tag}"
            )));
        }
        let pairs = rest
            .chunks(2)
            .map(|pair| {
                let key = as_kw(pair[0]).ok_or_else(|| {
                    IrError::NotATaggedList(format!("non-keyword plist key: {}", pair[0]))
                })?;
                Ok((key, pair[1]))
            })
            .collect::<Result<Vec<_>, IrError>>()?;
        Ok(TaggedList { tag, pairs })
    }

    pub fn expect_tag(&self, expected: &'static str) -> Result<(), IrError> {
        if self.tag != expected {
            return Err(IrError::WrongTag {
                expected,
                actual: self.tag.to_string(),
            });
        }
        Ok(())
    }

    pub fn get(&self, key: &'static str) -> Option<&'a Value> {
        self.pairs.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
    }

    pub fn require(&self, key: &'static str) -> Result<&'a Value, IrError> {
        self.get(key).ok_or(IrError::MissingKey(key))
    }

    /// All (key, value) pairs, in order — used by ConditionSet, which is an
    /// open plist rather than a fixed set of fields.
    pub fn all_pairs(&self) -> &[(&'a str, &'a Value)] {
        &self.pairs
    }
}

/// A value that's either the keyword `:any` or an integer — the shape
/// `pid-resource-ref` and `ipc-fd-resource-fd` both use (ir.lisp).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyOrInt {
    Any,
    Id(i64),
}

impl AnyOrInt {
    pub fn from_value(v: &Value) -> Result<Self, IrError> {
        if as_kw(v) == Some("any") {
            return Ok(AnyOrInt::Any);
        }
        v.as_i64()
            .map(AnyOrInt::Id)
            .ok_or_else(|| IrError::BadValue {
                key: "ref/fd",
                detail: format!("expected :any or integer, got {v}"),
            })
    }
}

pub fn require_str<'a>(v: &'a Value, key: &'static str) -> Result<&'a str, IrError> {
    v.as_str().ok_or_else(|| IrError::BadValue {
        key,
        detail: format!("expected string, got {v}"),
    })
}

pub fn require_i64(v: &Value, key: &'static str) -> Result<i64, IrError> {
    v.as_i64().ok_or_else(|| IrError::BadValue {
        key,
        detail: format!("expected integer, got {v}"),
    })
}

/// `:ops (:read :write)` — a list of keywords, each stripped of its `:`.
pub fn keyword_list(v: &Value, key: &'static str) -> Result<Vec<String>, IrError> {
    if is_lisp_nil(v) {
        return Ok(Vec::new());
    }
    v.list_iter()
        .ok_or_else(|| IrError::BadValue {
            key,
            detail: format!("expected a list, got {v}"),
        })?
        .map(|item| {
            as_kw(item)
                .map(str::to_string)
                .ok_or_else(|| IrError::BadValue {
                    key,
                    detail: format!("expected keyword in list, got {item}"),
                })
        })
        .collect()
}

pub fn parse_root(s: &str) -> Result<Value, IrError> {
    Ok(lexpr::from_str(s)?)
}
