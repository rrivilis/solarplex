-- Seed a permanent "system" actor row.
--
-- `crates/session::session_task::actor_of()` attributes several
-- machine-generated SessionEvent kinds (ApprovalExpired, ApprovalInterrupted,
-- and the entire saga sub-algebra) to the literal actor_id "system" — but
-- `events.actor_id` has REFERENCES actors(id) (migration 001), so every
-- real_persist() write for one of these event kinds was failing its INSERT
-- with a foreign-key violation and silently falling back to shadow_persist
-- (memory-only, no durable row) — discovered via a live test exercising the
-- ApprovalExpired path end-to-end, not by design.
INSERT INTO actors (id, type, name)
VALUES ('system', 'agent', 'System')
ON CONFLICT (id) DO NOTHING;
