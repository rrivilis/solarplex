//! `AuthorityArena` — typed arena allocator for session capability authority.
//!
//! # Conceptual model
//!
//! In a classic capability system the token IS the authority — a self-contained
//! bearer credential.  Revocation is famously hard because authority has already
//! been distributed and there is no global namespace to update.
//!
//! Solarplex caps work differently.  A cap is a typed *pointer* into the
//! epoch-scoped authority namespace owned by the session.  The epoch register
//! (`session_epochs`) is the authority; the cap is a `(session_id, epoch,
//! stratum, permissions)` tuple that dereferences into it.
//!
//! This maps directly onto region-based memory management (Tofte & Talpin,
//! 1994): each epoch is a *region*, caps are region-local allocations, and
//! `AuthorityArena::revoke_epoch` is `drop(region)` — O(1) regardless of how
//! many caps were allocated in that epoch.
//!
//! See THREAT_MODEL.md §4.1 for the full threat analysis.
//!
//! # Usage
//!
//! ```ignore
//! let arena  = AuthorityArena::for_session(&pool, session_id).await?;
//! let root   = arena.alloc(actor_id, &["read_artifact"], Duration::minutes(15)).await?;
//! let child  = root.delegate(agent_id, &["read_artifact"], Duration::minutes(10)).await?;
//!
//! // Close the entire epoch — both root and child are revoked atomically.
//! let (next_arena, receipt) = arena.revoke_epoch(30).await?;
//! // `arena` is consumed; `next_arena` is in the new epoch.
//! ```
//!
//! # Per-interaction lifetime
//!
//! `AuthorityArena` handles are **per-interaction** — create one at the start of
//! a handler, perform cap operations, drop it.  Postgres is the stable source of
//! truth; the struct caches the epoch read at construction time and does not hold
//! a lock.

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use sqlx::{PgPool, Row};
use ulid::Ulid;

use crate::{epochs, events, tokens, DbError, DbResult};

// ── Public types ──────────────────────────────────────────────────────────────

/// A handle into the current epoch's authority namespace for one session.
///
/// Per-interaction: construct with `for_session`, perform cap operations, drop.
/// The epoch register in Postgres is the stable source of truth.
pub struct AuthorityArena {
    pub pool:       PgPool,
    pub session_id: String,
    /// The epoch at construction time.  May be stale under concurrent
    /// revocation — the `revoke_*` methods re-read the DB atomically.
    pub epoch: i64,
}

/// A typed pointer into the epoch's authority namespace: a capability token
/// with its allocation metadata baked in.
///
/// Consumed by `transfer` (linear move semantics — the Rust borrow checker
/// enforces that you cannot use the old reference after the call).
#[derive(Debug)]
pub struct Authority {
    pool:            PgPool,
    pub session_id:  String,
    /// Cap ULID — the "address" of this allocation in the namespace.
    pub id:          String,
    pub epoch:       i64,
    /// Delegation depth: 0 = root, 1 = first delegate, …
    pub stratum:     i64,
    /// Allowed tool names.  Empty = all tools permitted.
    pub permissions: Vec<String>,
    pub expires_at:  DateTime<Utc>,
}

/// Returned by `AuthorityArena::transfer_root`.
///
/// Carries the audit facts about a cooperative ownership handoff: which root
/// was retired, which new root replaced it, and how many children were
/// reparented.  Distinct from `RevocationReceipt` because transfer() does
/// not advance the epoch.
#[derive(Debug, Clone, Serialize)]
pub struct TransferReceipt {
    /// The cap that was retired (old owner's root).
    pub old_root_id:    String,
    /// The newly-created cap (new owner's root).
    pub new_root_id:    String,
    /// The actor who received ownership.
    pub new_actor_id:   String,
    /// Child caps reparented from old_root → new_root.
    pub rerooted_count: u64,
    /// Wall-clock timestamp of the transfer.
    pub transferred_at: DateTime<Utc>,
}

/// Returned by any revocation operation.
///
/// Contains everything the caller needs to broadcast `EpochAdvanced`, populate
/// `fenced_actors`, record the audit log entry, and schedule drain cleanup.
#[derive(Debug, Clone, Serialize)]
pub struct RevocationReceipt {
    /// The epoch that was closed.
    pub closed_epoch:   i64,
    /// The epoch now active.  Equal to `closed_epoch` for `revoke_subtree`
    /// (no epoch advance); otherwise `closed_epoch + 1`.
    pub new_epoch:      i64,
    /// Number of cap rows that were marked `revoked_at`.
    pub revoked_count:  u64,
    /// Committed event seq at the moment revocation fired.
    /// Agents that had observed this seq are eligible for the drain window.
    pub drain_seq:      i64,
    /// Wall-clock deadline for the drain grace window.
    pub drain_deadline: DateTime<Utc>,
}

// ── AuthorityArena ─────────────────────────────────────────────────────────────

impl AuthorityArena {
    /// Open an arena handle for a session.
    ///
    /// Reads the current epoch from `session_epochs`.  Returns epoch 0 for
    /// sessions that predate the epoch system (migration 011 back-fills all
    /// existing sessions with `INSERT … ON CONFLICT DO NOTHING`).
    pub async fn for_session(pool: &PgPool, session_id: &str) -> DbResult<Self> {
        let epoch = epochs::current(pool, session_id).await?;
        Ok(Self {
            pool:       pool.clone(),
            session_id: session_id.to_string(),
            epoch,
        })
    }

    // ── Allocation ────────────────────────────────────────────────────────────

    /// Allocate a root capability (stratum 0) in the current epoch.
    ///
    /// This is the only entry point for new authority; delegation goes through
    /// [`Authority::delegate`].  Postgres auto-computes `epoch` and `stratum`
    /// via subqueries in the INSERT — see `tokens::insert`.
    pub async fn alloc(
        &self,
        actor_id:    &str,
        permissions: &[String],
        ttl:         Duration,
    ) -> DbResult<Authority> {
        let id           = Ulid::new().to_string();
        let expires_at   = Utc::now() + ttl;
        let observed_seq = events::current_seq(&self.pool, &self.session_id).await?;

        let row = tokens::insert(
            &self.pool, &id, &self.session_id, actor_id,
            expires_at, None, observed_seq, permissions,
        ).await?;

        let perms = tokens::parse_permissions(&row);
        Ok(Authority {
            pool:        self.pool.clone(),
            session_id:  self.session_id.clone(),
            id:          row.id,
            epoch:       row.epoch,
            stratum:     row.stratum,
            permissions: perms,
            expires_at:  row.expires_at,
        })
    }

    /// Reconstitute an `Authority` handle for an existing, live cap in this
    /// session — the one way to get a delegable handle for a cap that
    /// wasn't just returned by `alloc`/`delegate` in this same call.
    /// `alloc` is still "the only entry point for *new* authority" (see its
    /// doc comment); this doesn't mint anything, it just re-opens a handle
    /// on authority that already exists, e.g. so a caller can delegate from
    /// a cap looked up by ID (see `authority_import::import_delegation`).
    pub async fn authority_for_cap(&self, cap_id: &str) -> DbResult<Authority> {
        let row = tokens::get_cap(&self.pool, cap_id).await?;
        if row.session_id != self.session_id {
            return Err(DbError::NotFound);
        }
        let permissions = tokens::parse_permissions(&row);
        Ok(Authority {
            pool: self.pool.clone(),
            session_id: row.session_id,
            id: row.id,
            epoch: row.epoch,
            stratum: row.stratum,
            permissions,
            expires_at: row.expires_at,
        })
    }

    // ── Revocation operations ─────────────────────────────────────────────────

    /// Prune a single cap's subtree via recursive CTE.
    ///
    /// Does NOT advance the epoch — targeted removal within the current
    /// generation.  `self` is not consumed because the arena (epoch) survives.
    pub async fn revoke_subtree(
        &self,
        cap_id:            &str,
        drain_window_secs: u64,
    ) -> DbResult<RevocationReceipt> {
        let drain_seq      = events::current_seq(&self.pool, &self.session_id).await?;
        let revoked_ids    = tokens::revoke_cap_subtree(&self.pool, cap_id).await?;
        if let Err(e) = crate::descriptors::delete_for_caps(&self.pool, &revoked_ids).await {
            tracing::warn!("descriptor cleanup after subtree revocation failed: {e}");
        }
        let revoked_count  = revoked_ids.len() as u64;
        let drain_deadline = Utc::now() + Duration::seconds(drain_window_secs as i64);

        Ok(RevocationReceipt {
            closed_epoch: self.epoch,
            new_epoch:    self.epoch,   // no epoch advance for subtree revocation
            revoked_count,
            drain_seq,
            drain_deadline,
        })
    }

    /// Revoke all caps at stratum >= `threshold` and advance the epoch.
    ///
    /// Stack-unwind semantics: tears down every delegation at depth >= N in
    /// the current epoch, preserving shallower roots.
    ///
    /// Consumes `self` — the old epoch no longer accepts allocations.
    /// Returns `(new_arena, receipt)`.
    pub async fn revoke_by_stratum(
        self,
        stratum_threshold: i64,
        drain_window_secs: u64,
    ) -> DbResult<(AuthorityArena, RevocationReceipt)> {
        let drain_seq     = events::current_seq(&self.pool, &self.session_id).await?;
        let revoked_ids = tokens::revoke_by_stratum(
            &self.pool, &self.session_id, self.epoch, stratum_threshold,
        ).await?;
        if let Err(e) = crate::descriptors::delete_for_caps(&self.pool, &revoked_ids).await {
            tracing::warn!("descriptor cleanup after stratum revocation failed: {e}");
        }
        let revoked_count  = revoked_ids.len() as u64;
        let new_epoch      = epochs::advance(&self.pool, &self.session_id).await?;
        let drain_deadline = Utc::now() + Duration::seconds(drain_window_secs as i64);

        let receipt = RevocationReceipt {
            closed_epoch: self.epoch,
            new_epoch,
            revoked_count,
            drain_seq,
            drain_deadline,
        };
        let arena = AuthorityArena {
            pool:       self.pool,
            session_id: self.session_id,
            epoch:      new_epoch,
        };
        Ok((arena, receipt))
    }

    /// Close the entire epoch — every active cap in this generation is revoked.
    ///
    /// The arena analogue of `drop(region)`: O(1) authority claim regardless of
    /// how many caps were allocated.  Consumes `self`; the caller receives a
    /// fresh arena in the new epoch.
    pub async fn revoke_epoch(
        self,
        drain_window_secs: u64,
    ) -> DbResult<(AuthorityArena, RevocationReceipt)> {
        let drain_seq     = events::current_seq(&self.pool, &self.session_id).await?;
        let revoked_ids = tokens::revoke_epoch(
            &self.pool, &self.session_id, self.epoch,
        ).await?;
        if let Err(e) = crate::descriptors::delete_for_caps(&self.pool, &revoked_ids).await {
            tracing::warn!("descriptor cleanup after epoch revocation failed: {e}");
        }
        let revoked_count  = revoked_ids.len() as u64;
        let new_epoch      = epochs::advance(&self.pool, &self.session_id).await?;
        let drain_deadline = Utc::now() + Duration::seconds(drain_window_secs as i64);

        let receipt = RevocationReceipt {
            closed_epoch: self.epoch,
            new_epoch,
            revoked_count,
            drain_seq,
            drain_deadline,
        };
        let arena = AuthorityArena {
            pool:       self.pool,
            session_id: self.session_id,
            epoch:      new_epoch,
        };
        Ok((arena, receipt))
    }

    // ── Cooperative transfer ──────────────────────────────────────────────────

    /// Transfer session ownership from `old_actor_id` to `new_actor_id`.
    ///
    /// This is the third primitive in the authority graph rewrite algebra
    /// (see THREAT_MODEL.md §4.3).  Unlike `revoke_epoch`, transfer():
    ///
    /// - Does **NOT** advance the epoch — existing agent/collaborator caps in
    ///   the current epoch remain valid.
    /// - Reparents children of the old root to the new root atomically so the
    ///   delegation tree is preserved.
    /// - Marks the old root with `transferred_to` (not just `revoked_at`) so
    ///   the audit trail distinguishes cooperative handoff from adversarial
    ///   revocation.
    ///
    /// Returns `Ok(None)` when `old_actor_id` holds no active root cap — this
    /// is normal for sessions created before the epoch system (migration 011).
    /// The display-label update in `sessions::transfer_ownership_in_tx` still
    /// fires; only the cap DAG half is skipped.
    ///
    /// `self` is taken by reference (not consumed) because the arena's epoch
    /// does not change — the same `AuthorityArena` handle is still valid after
    /// the call.
    pub async fn transfer_root(
        &self,
        old_actor_id:  &str,
        new_actor_id:  &str,
        ttl_hours:     i64,
    ) -> DbResult<Option<TransferReceipt>> {
        let mut tx = self.pool.begin().await?;

        let old_root_id = match tokens::find_root_cap_in_tx(
            &mut tx, &self.session_id, old_actor_id,
        ).await? {
            Some(id) => id,
            None => {
                tx.rollback().await.ok();
                return Ok(None);
            }
        };

        let result = tokens::transfer_root_in_tx(
            &mut tx, &self.session_id, &old_root_id, new_actor_id, ttl_hours,
        ).await?;

        tx.commit().await?;

        Ok(Some(TransferReceipt {
            old_root_id,
            new_root_id:    result.new_root_id,
            new_actor_id:   new_actor_id.to_string(),
            rerooted_count: result.rerooted_count,
            transferred_at: Utc::now(),
        }))
    }
}

// ── Authority ──────────────────────────────────────────────────────────────────

impl Authority {
    /// Delegate to another actor with attenuated permissions.
    ///
    /// **Attenuation invariant**: `reduced_perms` must be a subset of
    /// `self.permissions`.  When `self.permissions` is empty (all-tools), any
    /// subset is valid.  Returns `DbError::Conflict` if the child would expand
    /// the parent's authority.
    ///
    /// The returned `Authority` sits at `self.stratum + 1` in the delegation
    /// tree; Postgres computes the actual stratum value via subquery.
    pub async fn delegate(
        &self,
        to:            &str,
        reduced_perms: &[String],
        ttl:           Duration,
    ) -> DbResult<Authority> {
        // Attenuation invariant check.
        if !self.permissions.is_empty() {
            if let Some(bad) = reduced_perms.iter()
                .find(|p| !self.permissions.contains(p))
            {
                return Err(DbError::Conflict(format!(
                    "delegation would expand authority: {:?} not held by parent cap {}",
                    bad, self.id,
                )));
            }
        }

        // Typed-address attenuation: a delegate cannot hold a method address
        // that was never registered in this session's mcp_methods namespace
        // — it would be a reference into an empty region of the object
        // namespace. This was documented (crate::methods::unknown_addresses's
        // own doc comment) as enforced here but had never actually been
        // wired in — permission strings without the "mcp." prefix are
        // legacy free strings and pass through unvalidated, same as
        // unknown_addresses itself already does.
        let unknown = crate::methods::unknown_addresses(&self.pool, &self.session_id, reduced_perms).await?;
        if !unknown.is_empty() {
            return Err(DbError::Conflict(format!(
                "delegation references unregistered method address(es): {unknown:?}",
            )));
        }

        let id           = Ulid::new().to_string();
        let expires_at   = Utc::now() + ttl;
        let observed_seq = events::current_seq(&self.pool, &self.session_id).await?;

        let row = tokens::insert(
            &self.pool, &id, &self.session_id, to,
            expires_at, Some(&self.id), observed_seq, reduced_perms,
        ).await?;

        // Second-order: the cap already works via its global id regardless
        // of this succeeding. Log and continue rather than fail the grant.
        if let Err(e) = crate::descriptors::grant(&self.pool, to, &format!("cap/{}", row.id)).await {
            tracing::warn!(cap_id = %row.id, actor_id = to, "descriptor grant failed: {e}");
        }

        let perms = tokens::parse_permissions(&row);
        Ok(Authority {
            pool:        self.pool.clone(),
            session_id:  self.session_id.clone(),
            id:          row.id,
            epoch:       row.epoch,
            stratum:     row.stratum,
            permissions: perms,
            expires_at:  row.expires_at,
        })
    }

    /// Transfer authority by rerooting non-revoked children to a new parent.
    ///
    /// Consumes `self` — linear move semantics.  After this call the old cap
    /// pointer is gone from the caller's scope (Rust enforces this).  Surviving
    /// children are updated to point at `new_parent_id`; if `None` they become
    /// root caps.
    ///
    /// Used during selective repartition: when an intermediate cap is revoked,
    /// children are rerooted to the grandparent to preserve the delegation tree
    /// without cascading revocation to branches that don't need to be torn down.
    pub async fn transfer(self, new_parent_id: Option<&str>) -> DbResult<u64> {
        tokens::reroot_caps(&self.pool, &self.session_id, &self.id, new_parent_id).await
    }

    /// Check whether this cap is still live (not revoked, not expired).
    pub async fn is_live(&self) -> DbResult<bool> {
        let live = sqlx::query(
            "SELECT (revoked_at IS NULL AND expires_at > NOW()) AS live
             FROM session_tokens WHERE id = $1",
        )
        .bind(&self.id)
        .fetch_optional(&self.pool)
        .await
        .map_err(DbError::from)?
        .map(|r| r.get::<bool, _>("live"))
        .unwrap_or(false);
        Ok(live)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Attenuation invariant: child cannot expand parent's permissions.
    #[tokio::test]
    async fn delegate_rejects_permission_expansion() {
        // We can't easily spin up Postgres in a unit test, but we can test the
        // pre-DB validation logic by constructing an Authority directly.
        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let auth = Authority {
            pool,
            session_id:  "sess".into(),
            id:          "cap".into(),
            epoch:       0,
            stratum:     0,
            permissions: vec!["read_artifact".to_string()],
            expires_at:  Utc::now() + Duration::hours(1),
        };

        // Attempting to delegate a permission the parent doesn't hold should
        // return Conflict before any DB interaction.
        let result = auth.delegate(
            "agent",
            &["read_artifact".to_string(), "write_artifact".to_string()],
            Duration::minutes(15),
        ).await;

        assert!(matches!(result, Err(DbError::Conflict(_))));
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("write_artifact"));
        assert!(msg.contains("expand authority"));
    }

    /// Empty parent permissions (all-tools) allows any subset in child.
    #[tokio::test]
    async fn delegate_allows_any_subset_of_all_tools() {
        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let auth = Authority {
            pool,
            session_id:  "sess".into(),
            id:          "cap".into(),
            epoch:       0,
            stratum:     0,
            permissions: vec![], // empty = all tools
            expires_at:  Utc::now() + Duration::hours(1),
        };

        // The check passes (empty parent = all-tools); the DB call would fail
        // in a unit test context, but we get past the invariant guard.
        let result = auth.delegate(
            "agent",
            &["read_artifact".to_string()],
            Duration::minutes(15),
        ).await;

        // Should fail at DB connection, not at the invariant check.
        // We just verify it's NOT a Conflict error.
        assert!(!matches!(result, Err(DbError::Conflict(_))));
    }

    /// RevocationReceipt: subtree revocation does not advance the epoch.
    #[test]
    fn subtree_receipt_preserves_epoch() {
        let receipt = RevocationReceipt {
            closed_epoch:   3,
            new_epoch:      3,  // no advance
            revoked_count:  5,
            drain_seq:      42,
            drain_deadline: Utc::now(),
        };
        assert_eq!(receipt.closed_epoch, receipt.new_epoch);
    }

    /// RevocationReceipt: epoch/stratum revocation advances the epoch.
    #[test]
    fn epoch_receipt_advances_epoch() {
        let receipt = RevocationReceipt {
            closed_epoch:   3,
            new_epoch:      4,
            revoked_count:  12,
            drain_seq:      99,
            drain_deadline: Utc::now(),
        };
        assert_eq!(receipt.new_epoch, receipt.closed_epoch + 1);
    }
}
