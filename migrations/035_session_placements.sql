-- Durable cross-replica session-ownership directory. Replaces the
-- in-process-only LeaseManager (crates/server/src/lease.rs) for
-- ConflictClass::Session/SagaStep once more than one replica exists -- a
-- lease that only lives in one process's DashMap can't arbitrate between
-- two actual processes. ReflectorEpoch/ReflectorSegment (log compaction)
-- stay purely local/single-writer; they aren't about a session at all, so
-- they have no directory entry here (see reflector.rs's module doc).
--
-- A row's absence, or a heartbeat older than ttl_secs, both mean "up for
-- grabs" -- there is no separate "released" state to track, matching
-- LeaseRecord's own expired()-means-free semantics.
--
-- fencing_token increments on every successful claim (fresh, re-claim after
-- staleness, or a renewal by the same owner alike) -- a monotonically
-- increasing token a future durable writer can compare against to reject a
-- stale replica that lost its claim without yet realizing it.
CREATE TABLE session_placements (
    session_id    TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    replica_id    TEXT NOT NULL,
    fencing_token BIGINT NOT NULL DEFAULT 1,
    heartbeat_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ttl_secs      INT NOT NULL DEFAULT 30
);

CREATE INDEX session_placements_replica ON session_placements(replica_id);
