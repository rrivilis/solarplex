-- Durable relay for cross-replica saga-bundle forwarding. When
-- Reflector::dispatch (crates/server/src/reflector.rs) determines that a
-- bundle's required conflict-class claims are held by a *different*
-- replica (Plan::Forward), it can no longer just append locally and call
-- it delivered -- the target session almost certainly isn't running on
-- this replica at all. This table is the durable handoff: a row addressed
-- to owner_replica, picked up by that replica's own
-- spawn_reflector_forward_listener (woken via pg_notify on the
-- 'reflector_bundles' channel, payload = owner_replica), which appends it
-- to its own in-memory reflector log and attempts local delivery from
-- there -- the same path a bundle dispatched natively on that replica
-- would take.
--
-- consumed_at is set atomically at claim time (see
-- db::reflector_forwarding::claim_pending) so a duplicate notify delivery
-- (pg_notify has no exactly-once guarantee) can't double-append the same
-- bundle.
CREATE TABLE reflector_forwarded_bundles (
    id            TEXT PRIMARY KEY,
    owner_replica TEXT NOT NULL,
    bundle        JSONB NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consumed_at   TIMESTAMPTZ
);

CREATE INDEX reflector_forwarded_bundles_pending
    ON reflector_forwarded_bundles(owner_replica)
    WHERE consumed_at IS NULL;
