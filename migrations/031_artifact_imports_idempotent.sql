-- Idempotency for cross-session artifact import: re-importing the same
-- exact source artifact content into the same target session must not spam
-- duplicate copies. Keyed on (target_session_id, source_artifact_id,
-- content_hash) rather than just (target_session_id, source_artifact_id) so
-- that if the source artifact is later edited and re-published, the new
-- content (different hash) is still importable as a fresh copy — only a
-- byte-for-byte repeat of something already imported is blocked.
--
-- Pre-existing duplicates (from manual testing before this constraint
-- existed) would make the ALTER TABLE below fail outright — Postgres won't
-- add a UNIQUE constraint over data that already violates it. Keep the
-- earliest import per (target_session_id, source_artifact_id, content_hash)
-- group and drop the rest; this only removes redundant *receipt* rows, the
-- artifact copies themselves (and the sessions/actors they reference) are
-- untouched.
DELETE FROM artifact_imports
WHERE id IN (
    SELECT id FROM (
        SELECT id, ROW_NUMBER() OVER (
            PARTITION BY target_session_id, source_artifact_id, content_hash
            ORDER BY imported_at ASC, id ASC
        ) AS rn
        FROM artifact_imports
    ) ranked
    WHERE rn > 1
);

-- Guarded, not a plain ALTER TABLE ADD CONSTRAINT: this migration's text
-- was edited after an earlier version of it had already run successfully
-- elsewhere, which poisoned sqlx's checksum tracking for it (see 032's
-- comment). Recovering means clearing that stale tracking row and letting
-- this file run again — at which point the constraint already exists from
-- the original run, so a plain ADD CONSTRAINT would fail with "constraint
-- already exists". This makes a replay a safe no-op instead.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'artifact_imports_dedup'
    ) THEN
        ALTER TABLE artifact_imports
            ADD CONSTRAINT artifact_imports_dedup
                UNIQUE (target_session_id, source_artifact_id, content_hash);
    END IF;
END $$;
