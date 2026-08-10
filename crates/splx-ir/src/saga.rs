//! Mirrors `sp-dsl/src/saga.lisp` — transfer/send receipts and the saga
//! log they're recorded in. Note what this crate does *not* attempt: the
//! Lisp side's `reflector` (multi-log merge into a deterministic global
//! order, cross-session `reflector-observe`) is coordination *logic*, not
//! wire data — conceptually the same job as `crates/server/src/reflector.rs`
//! already does at runtime. This module only reads the log data off the
//! wire; which reflector actually owns merging it is a call for whoever
//! wires this crate into `guardian`/`session`, not something to presume here.

use lexpr::Value;

use crate::ir::AuthorityEntry;
use crate::operational::Delta;
use crate::parse::{as_kw, is_lisp_nil, require_i64, require_str, IrError, TaggedList};

#[derive(Debug, Clone, PartialEq)]
pub struct TransferReceipt {
    pub saga_id: String,
    pub sequence: i64,
    pub grantor: String,
    pub recipient: String,
    pub authority: Vec<AuthorityEntry>,
    pub timestamp: i64,
}

impl TransferReceipt {
    pub fn from_value(v: &Value) -> Result<Self, IrError> {
        let list = TaggedList::parse(v)?;
        list.expect_tag("transfer-receipt")?;
        Ok(TransferReceipt {
            saga_id: require_str(list.require("saga-id")?, "saga-id")?.to_string(),
            sequence: require_i64(list.require("sequence")?, "sequence")?,
            grantor: require_str(list.require("grantor")?, "grantor")?.to_string(),
            recipient: require_str(list.require("recipient")?, "recipient")?.to_string(),
            authority: match list.require("authority")? {
                v if is_lisp_nil(v) => Vec::new(),
                v => v
                    .list_iter()
                    .ok_or_else(|| IrError::BadValue { key: "authority", detail: format!("{v}") })?
                    .map(AuthorityEntry::from_value)
                    .collect::<Result<Vec<_>, IrError>>()?,
            },
            timestamp: require_i64(list.require("timestamp")?, "timestamp")?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SendReceipt {
    pub saga_id: String,
    pub sequence: i64,
    pub sender: String,
    pub recipient: String,
    /// `:delta | :transfer-receipt | :capability | :value` (saga.lisp's `send!`).
    pub message_kind: String,
    pub timestamp: i64,
}

impl SendReceipt {
    pub fn from_value(v: &Value) -> Result<Self, IrError> {
        let list = TaggedList::parse(v)?;
        list.expect_tag("send-receipt")?;
        let message_kind = as_kw(list.require("message-kind")?)
            .ok_or_else(|| IrError::BadValue { key: "message-kind", detail: "expected keyword".into() })?
            .to_string();
        Ok(SendReceipt {
            saga_id: require_str(list.require("saga-id")?, "saga-id")?.to_string(),
            sequence: require_i64(list.require("sequence")?, "sequence")?,
            sender: require_str(list.require("sender")?, "sender")?.to_string(),
            recipient: require_str(list.require("recipient")?, "recipient")?.to_string(),
            message_kind,
            timestamp: require_i64(list.require("timestamp")?, "timestamp")?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum SagaLogPayload {
    Commit(Delta),
    Transfer(TransferReceipt),
    Send(SendReceipt),
}

#[derive(Debug, Clone, PartialEq)]
pub struct SagaLogEntry {
    pub kind: String,
    pub sequence: i64,
    pub payload: SagaLogPayload,
    pub timestamp: i64,
}

impl SagaLogEntry {
    pub fn from_value(v: &Value) -> Result<Self, IrError> {
        let list = TaggedList::parse(v)?;
        list.expect_tag("saga-log-entry")?;
        let kind = as_kw(list.require("kind")?)
            .ok_or_else(|| IrError::BadValue { key: "kind", detail: "expected keyword".into() })?
            .to_string();
        let payload_value = list.require("payload")?;
        let payload = match kind.as_str() {
            "commit" => SagaLogPayload::Commit(Delta::from_value(payload_value)?),
            "transfer" => SagaLogPayload::Transfer(TransferReceipt::from_value(payload_value)?),
            "send" => SagaLogPayload::Send(SendReceipt::from_value(payload_value)?),
            other => {
                return Err(IrError::BadValue {
                    key: "kind",
                    detail: format!("unknown saga-log-entry kind :{other}"),
                })
            }
        };
        Ok(SagaLogEntry {
            kind,
            sequence: require_i64(list.require("sequence")?, "sequence")?,
            payload,
            timestamp: require_i64(list.require("timestamp")?, "timestamp")?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SagaLog {
    pub saga_id: String,
    pub entries: Vec<SagaLogEntry>,
}

impl SagaLog {
    pub fn from_value(v: &Value) -> Result<Self, IrError> {
        let list = TaggedList::parse(v)?;
        list.expect_tag("saga-log")?;
        let entries = match list.require("entries")? {
            v if is_lisp_nil(v) => Vec::new(),
            v => v
                .list_iter()
                .ok_or_else(|| IrError::BadValue { key: "entries", detail: format!("{v}") })?
                .map(SagaLogEntry::from_value)
                .collect::<Result<Vec<_>, IrError>>()?,
        };
        Ok(SagaLog { saga_id: require_str(list.require("saga-id")?, "saga-id")?.to_string(), entries })
    }
}
