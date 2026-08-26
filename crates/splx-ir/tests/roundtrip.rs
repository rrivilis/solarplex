//! Reference strings here are hand-derived from sp-dsl/src/serializer.lisp's
//! actual `serialize` method bodies (read directly, method by method) — NOT
//! captured from a real running Lisp image. No sbcl/ecl/ccl/clisp is
//! available in this environment, so this proves "the Rust side correctly
//! parses the format the Lisp source says it emits," not "the Rust side
//! correctly parses what the Lisp side emits in practice." Worth a real
//! sbcl round-trip (serialize-to-string on live objects, fed into these
//! same parsers) before trusting this against a live authority-dsl image.

use splx_ir::algebra::ConditionValue;
use splx_ir::parse::AnyOrInt;
use splx_ir::resource::Resource;
use splx_ir::saga::{SagaLog, SagaLogPayload, SendReceipt, TransferReceipt};
use splx_ir::{AuthorityEntry, CapAction, Capability, Delegation, Delta, Effect};

fn parse_value(s: &str) -> lexpr::Value {
    lexpr::from_str(s).unwrap_or_else(|e| panic!("lexpr parse failed for {s:?}: {e}"))
}

#[test]
fn fs_authority_entry_no_conditions() {
    // (fs "/data/**" :read :write) after entry-resource/entry-ops serialize.
    let s = r#"(:entry :resource (:fs :path "/data/**") :ops (:read :write) :conditions nil)"#;
    let v = parse_value(s);
    let entry = AuthorityEntry::from_value(&v).expect("parse authority-entry");
    assert_eq!(
        entry.resource,
        Resource::Fs {
            path: "/data/**".into()
        }
    );
    assert_eq!(entry.ops.0, vec!["read", "write"]);
    assert!(entry.conditions.is_none());
}

#[test]
fn fs_authority_entry_with_conditions() {
    let s = r#"(:entry :resource (:fs :path "/secrets/**") :ops (:read)
                :conditions (:ttl 900 :quorum guardian :single-use t))"#;
    let entry = AuthorityEntry::from_value(&parse_value(s)).unwrap();
    let cond = entry.conditions.expect("conditions present");
    assert_eq!(cond.get("ttl"), Some(&ConditionValue::Int(900)));
    assert_eq!(
        cond.get("quorum"),
        Some(&ConditionValue::Symbol("guardian".into()))
    );
    assert!(cond.get("single-use").unwrap().is_true());
}

#[test]
fn net_resource_defaults() {
    // net-resource-port-min/-max default to 0/65535 in ir.lisp when absent.
    let s = r#"(:net :host "db.internal" :port-min 0 :port-max 65535 :path-prefix "/")"#;
    let r = Resource::from_value(&parse_value(s)).unwrap();
    assert_eq!(
        r,
        Resource::Net {
            host: "db.internal".into(),
            port_min: 0,
            port_max: 65535,
            path_prefix: "/".into(),
        }
    );
    assert_eq!(r.provider(), "linux-net");
}

#[test]
fn pid_resource_any_and_exact() {
    let any = Resource::from_value(&parse_value(r#"(:pid :ref :any)"#)).unwrap();
    assert_eq!(
        any,
        Resource::Pid {
            pid_ref: AnyOrInt::Any
        }
    );

    let exact = Resource::from_value(&parse_value(r#"(:pid :ref 1234)"#)).unwrap();
    assert_eq!(
        exact,
        Resource::Pid {
            pid_ref: AnyOrInt::Id(1234)
        }
    );
}

#[test]
fn delegation_with_two_entries() {
    let s = r#"(:delegation
                  :grantor "SHIM"
                  :grantee "worker"
                  :authority
                    ((:entry :resource (:fs :path "/app/**") :ops (:read :exec) :conditions nil)
                     (:entry :resource (:net :host "api.internal" :port-min 0 :port-max 65535 :path-prefix "/")
                             :ops (:connect) :conditions nil)))"#;
    let d = Delegation::from_value(&parse_value(s)).unwrap();
    assert_eq!(d.grantor, "SHIM");
    assert_eq!(d.grantee, "worker");
    assert_eq!(d.authority.len(), 2);
    assert_eq!(
        d.authority[0].resource,
        Resource::Fs {
            path: "/app/**".into()
        }
    );
}

#[test]
fn capability_delegate_with_derived_from() {
    let s = r#"(:capability
                  :action :delegate
                  :subject "payments-agent"
                  :authority ((:entry :resource (:fs :path "/data/payments/**") :ops (:read) :conditions nil))
                  :derived-from "payments-worker"
                  :conditions nil
                  :metadata nil)"#;
    let cap = Capability::from_value(&parse_value(s)).unwrap();
    assert_eq!(cap.action, CapAction::Delegate);
    assert_eq!(cap.subject, "payments-agent");
    assert_eq!(cap.derived_from.as_deref(), Some("payments-worker"));
    assert_eq!(cap.authority.len(), 1);
}

#[test]
fn effect_and_delta() {
    let effect_s = r#"(:effect :kind :read :resource-spec "/data/x" :payload nil)"#;
    let effect = Effect::from_value(&parse_value(effect_s)).unwrap();
    assert_eq!(effect.kind, "read");
    assert_eq!(effect.resource_spec.as_str(), Some("/data/x"));
    assert!(effect.payload.is_none());

    let delta_s = format!(
        r#"(:delta :effect {effect_s}
             :authority (:entry :resource (:fs :path "/data/**") :ops (:read) :conditions nil)
             :epoch 3 :saga-id "saga-1" :sequence 2 :before :unknown :after :unknown :timestamp 3900000000)"#
    );
    let delta = Delta::from_value(&parse_value(&delta_s)).unwrap();
    assert_eq!(delta.epoch, 3);
    assert_eq!(delta.saga_id.as_deref(), Some("saga-1"));
    assert_eq!(delta.sequence, 2);
    assert_eq!(splx_ir::parse::as_kw(&delta.before), Some("unknown"));
    assert_eq!(delta.timestamp, 3_900_000_000);
}

#[test]
fn delta_saga_id_nil_outside_saga() {
    let s = r#"(:delta :effect (:effect :kind :read :resource-spec "/x" :payload nil)
                 :authority (:entry :resource (:fs :path "/x") :ops (:read) :conditions nil)
                 :epoch 0 :saga-id nil :sequence 0 :before :unknown :after :unknown :timestamp 100)"#;
    let delta = Delta::from_value(&parse_value(s)).unwrap();
    assert!(delta.saga_id.is_none());
}

#[test]
fn transfer_and_send_receipts() {
    let t_s = r#"(:transfer-receipt :saga-id "s1" :sequence 0 :grantor "alice" :recipient "bob"
                   :authority ((:entry :resource (:fs :path "/x/**") :ops (:read) :conditions nil))
                   :timestamp 200)"#;
    let t = TransferReceipt::from_value(&parse_value(t_s)).unwrap();
    assert_eq!(t.grantor, "alice");
    assert_eq!(t.recipient, "bob");
    assert_eq!(t.authority.len(), 1);

    let sr_s = r#"(:send-receipt :saga-id "s1" :sequence 1 :sender "alice" :recipient "bob"
                    :message-kind :value :timestamp 201)"#;
    let sr = SendReceipt::from_value(&parse_value(sr_s)).unwrap();
    assert_eq!(sr.message_kind, "value");
}

#[test]
fn saga_log_with_commit_entry() {
    let s = r#"(:saga-log :saga-id "s1"
                 :entries
                   ((:saga-log-entry :kind :commit :sequence 0
                     :payload
                       (:delta :effect (:effect :kind :read :resource-spec "/x" :payload nil)
                               :authority (:entry :resource (:fs :path "/x") :ops (:read) :conditions nil)
                               :epoch 0 :saga-id "s1" :sequence 0 :before :unknown :after :unknown :timestamp 100)
                     :timestamp 100)))"#;
    let log = SagaLog::from_value(&parse_value(s)).unwrap();
    assert_eq!(log.saga_id, "s1");
    assert_eq!(log.entries.len(), 1);
    match &log.entries[0].payload {
        SagaLogPayload::Commit(delta) => assert_eq!(delta.sequence, 0),
        other => panic!("expected Commit payload, got {other:?}"),
    }
}

#[test]
fn splx_value_dispatches_on_tag() {
    use splx_ir::SplxValue;
    use std::str::FromStr;
    let s = r#"(:entry :resource (:fs :path "/x") :ops (:read) :conditions nil)"#;
    match SplxValue::from_str(s).unwrap() {
        SplxValue::Entry(e) => assert_eq!(e.resource, Resource::Fs { path: "/x".into() }),
        other => panic!("expected Entry, got {other:?}"),
    }
}

#[test]
fn malformed_input_is_an_error_not_a_panic() {
    assert!(AuthorityEntry::from_value(&parse_value(r#"(:not-an-entry :foo 1)"#)).is_err());
    assert!(lexpr::from_str("(unterminated").is_err());
}
