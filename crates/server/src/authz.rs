//! Authorization checks — one named predicate per action, expressed as plain
//! Rust rather than a policy-engine DSL.
//!
//! This is deliberately the same shape a declarative policy language (Rego,
//! Cedar) would use — one composable rule per action — so that if this ever
//! needs to generalize across many more actions/resources, promoting it is
//! a natural migration, not a rewrite. It isn't worth that machinery yet for
//! a handful of checks on one endpoint.
//!
//! `authenticated(actor)` and `member(actor, session)` are NOT re-checked
//! here — those are the caller's job (verified `sp_token` +
//! `sessions::require_membership`) before a function in this module ever
//! runs. Everything here only needs the caller's *role*, not their identity.

use protocol::types::MemberRole;

/// permit(actor, CreateInvite(request)) iff
///   actor.role.can_invite_as(request.role)
///   ∧ (request.cap.is_none() ∨ actor.role == Owner)
///
/// The cap clause is deliberately narrower than "request.scope ⊆
/// actor.invitable_scope": humans aren't nodes in the cap DAG (they
/// authenticate via sp_token, not a held cap), so there's no existing
/// authority object to attenuate against for a non-owner inviter. Owners are
/// already treated as unconstrained root elsewhere (`issue_attach_token`
/// mints root caps the same way) — restricting cap-staging invites to
/// Owner-only reuses that existing trust boundary instead of inventing a new
/// definition of "invitable scope" for roles that don't hold caps.
pub fn can_create_invite(
    caller_role: &MemberRole,
    target_role: &MemberRole,
    stages_cap: bool,
) -> Result<(), String> {
    if !caller_role.can_invite_as(target_role) {
        return Err(format!(
            "{caller_role:?} cannot invite a member in as {target_role:?} — \
             you can't delegate authority you don't hold"
        ));
    }
    if stages_cap && *caller_role != MemberRole::Owner {
        return Err("only session owners may stage a cap grant on an invite".to_string());
    }
    Ok(())
}
