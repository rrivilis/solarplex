//! Translates `splx_ir` (the Rust reader for `sp-dsl`'s wire IR) into
//! Solarplex's own `AuthorityArena`/`Authority` model — the concrete
//! backend consumer for the Lisp `authority-dsl` toolchain.
//!
//! This is deliberately an *import*, not a new enforcement path: a
//! Lisp-authored capability or delegation runs through exactly the same
//! primitives (`AuthorityArena::alloc`, `Authority::delegate`) as any
//! capability minted from inside the app, so it's subject to the exact
//! same invariants — attenuation (a delegation can only narrow what its
//! parent already held), epoch-scoped revocation, the full audit trail via
//! `session_tokens`/`events`. Nothing here talks to `crates/guardian`'s
//! live Landlock enforcement, which stays on its own native
//! `protocol::effects::DeclaredEffects` path — see THREAT_MODEL.md and
//! this module's own commit history for why that boundary is deliberate,
//! not an oversight.
//!
//! The DSL was designed to describe authority in a form that "travels
//! beyond the runtime" (see docs/dsl-guide.md) — this module is what makes
//! that concrete for the one runtime that does exist today: a definition
//! authored entirely outside Solarplex (no Rust, no running server, just
//! the Lisp toolchain) can be handed to this import path and come out the
//! other side as a real, attenuation-checked, revocable Solarplex cap.

use chrono::Duration;
use splx_ir::{AnyOrInt, AuthorityEntry, Capability, Delegation, Resource};

use crate::authority_arena::{Authority, AuthorityArena};
use crate::DbResult;

/// One `(resource, op)` pair becomes one permission string:
/// `"{provider}:{resource}:{op}"`, e.g. `"linux-fs:/data/**:read"`,
/// `"linux-net:db.internal:connect"`. Solarplex's native cap model has no
/// resource/op structure of its own — `permissions` is a flat allow-list of
/// opaque strings (see `authority_arena.rs`) — so this is the translation
/// boundary between the DSL's structured authority-entry shape and that
/// flat vocabulary. Deterministic and lossless enough to round-trip through
/// string comparison, which is all `Authority::delegate`'s attenuation
/// check needs.
pub fn entry_to_permissions(entry: &AuthorityEntry) -> Vec<String> {
    let provider = entry.resource.provider();
    let repr = resource_repr(&entry.resource);
    entry
        .ops
        .0
        .iter()
        .map(|op| format!("{provider}:{repr}:{op}"))
        .collect()
}

fn resource_repr(resource: &Resource) -> String {
    match resource {
        Resource::Fs { path } => path.clone(),
        Resource::Net {
            host,
            port_min,
            port_max,
            path_prefix,
        } => {
            let port = if *port_min == 0 && *port_max == 65535 {
                String::new()
            } else {
                format!(":{port_min}-{port_max}")
            };
            format!("{host}{port}{path_prefix}")
        }
        Resource::Pid { pid_ref } => any_or_int_repr(pid_ref),
        Resource::IpcFd { fd } => format!("fd:{}", any_or_int_repr(fd)),
        Resource::Http { url_pattern, .. } => url_pattern.clone(),
        Resource::Wasm { module } => module.clone(),
    }
}

fn any_or_int_repr(v: &AnyOrInt) -> String {
    match v {
        AnyOrInt::Any => "any".to_string(),
        AnyOrInt::Id(id) => id.to_string(),
    }
}

/// Permission strings for a full authority-entry list — deduplicated and
/// sorted so two DSL definitions that describe the same authority in a
/// different entry order still produce byte-identical `permissions`.
pub fn authority_to_permissions(authority: &[AuthorityEntry]) -> Vec<String> {
    let mut perms: Vec<String> = authority.iter().flat_map(entry_to_permissions).collect();
    perms.sort();
    perms.dedup();
    perms
}

/// Import a `splx_ir::Capability` with no grantor as a new root capability
/// (`define-capability` with no `:derived-from` — see dsl-guide.md).
/// `derived_from`/`action`/`conditions`/`metadata` aren't consumed here:
/// this crate has no DB-backed notion of "resolve this Lisp principal name
/// to a parent cap in this session" (that's the caller's job, same
/// division of labor as `crates/intent`'s name slots — see
/// `import_delegation` below for the case where the caller *has* already
/// resolved a parent).
pub async fn import_capability(
    arena: &AuthorityArena,
    actor_id: &str,
    cap: &Capability,
    ttl: Duration,
) -> DbResult<Authority> {
    let perms = authority_to_permissions(&cap.authority);
    arena.alloc(actor_id, &perms, ttl).await
}

/// Import a `splx_ir::Delegation` against an already-resolved parent
/// `Authority` in this session. Attenuation is enforced by
/// `Authority::delegate` itself, so an imported delegation can only ever
/// narrow what `parent` already holds here — never expand it, regardless
/// of what the DSL source claims.
pub async fn import_delegation(
    parent: &Authority,
    grantee_actor_id: &str,
    delegation: &Delegation,
    ttl: Duration,
) -> DbResult<Authority> {
    let perms = authority_to_permissions(&delegation.authority);
    parent.delegate(grantee_actor_id, &perms, ttl).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use splx_ir::{OpSet, Resource};

    fn entry(resource: Resource, ops: &[&str]) -> AuthorityEntry {
        AuthorityEntry {
            resource,
            ops: OpSet(ops.iter().map(|s| s.to_string()).collect()),
            conditions: None,
        }
    }

    #[test]
    fn fs_entry_becomes_one_permission_per_op() {
        let e = entry(
            Resource::Fs {
                path: "/data/**".to_string(),
            },
            &["read", "write"],
        );
        let mut perms = entry_to_permissions(&e);
        perms.sort();
        assert_eq!(
            perms,
            vec!["linux-fs:/data/**:read", "linux-fs:/data/**:write"]
        );
    }

    #[test]
    fn net_entry_with_default_port_range_omits_port_suffix() {
        let e = entry(
            Resource::Net {
                host: "db.internal".to_string(),
                port_min: 0,
                port_max: 65535,
                path_prefix: "/".to_string(),
            },
            &["connect"],
        );
        assert_eq!(
            entry_to_permissions(&e),
            vec!["linux-net:db.internal/:connect"]
        );
    }

    #[test]
    fn net_entry_with_narrowed_port_range_includes_it() {
        let e = entry(
            Resource::Net {
                host: "db.internal".to_string(),
                port_min: 5432,
                port_max: 5432,
                path_prefix: "/".to_string(),
            },
            &["connect"],
        );
        assert_eq!(
            entry_to_permissions(&e),
            vec!["linux-net:db.internal:5432-5432/:connect"]
        );
    }

    #[test]
    fn pid_any_and_exact() {
        let any = entry(
            Resource::Pid {
                pid_ref: AnyOrInt::Any,
            },
            &["signal"],
        );
        assert_eq!(entry_to_permissions(&any), vec!["linux-pid:any:signal"]);
        let exact = entry(
            Resource::Pid {
                pid_ref: AnyOrInt::Id(1234),
            },
            &["signal"],
        );
        assert_eq!(entry_to_permissions(&exact), vec!["linux-pid:1234:signal"]);
    }

    #[test]
    fn authority_to_permissions_is_deduplicated_and_order_independent() {
        let a = vec![
            entry(
                Resource::Fs {
                    path: "/data/**".to_string(),
                },
                &["read"],
            ),
            entry(
                Resource::Fs {
                    path: "/data/**".to_string(),
                },
                &["read"],
            ), // duplicate entry
        ];
        let b = vec![entry(
            Resource::Fs {
                path: "/data/**".to_string(),
            },
            &["read"],
        )];
        assert_eq!(authority_to_permissions(&a), authority_to_permissions(&b));
        assert_eq!(authority_to_permissions(&a), vec!["linux-fs:/data/**:read"]);
    }
}
