-- 031's dedup key — (target_session_id, source_artifact_id, content_hash) —
-- had a round-trip hole: re-importing a copy back to its origin session
-- computes the same content_hash against a *different* source_artifact_id
-- (every import creates a fresh artifact row with its own id), so the old
-- key let a round-trip re-import (A -> B, then drag the copy back B -> A)
-- through as a "new" duplicate. Rekey on (target_session_id, content_hash)
-- alone — a later edit-and-republish of the source still produces a
-- different hash and is still importable as a fresh copy.
ALTER TABLE artifact_imports DROP CONSTRAINT artifact_imports_dedup;

-- Same reasoning as 031's own dedup step: real duplicate content already
-- sitting in the table under different source_artifact_ids (including any
-- produced by the very round-trip bug this migration closes) would make
-- the new, broader constraint fail otherwise. Only removes redundant
-- *receipt* rows — the artifact copies themselves are untouched.
DELETE FROM artifact_imports
WHERE id IN (
    SELECT id FROM (
        SELECT id, ROW_NUMBER() OVER (
            PARTITION BY target_session_id, content_hash
            ORDER BY imported_at ASC, id ASC
        ) AS rn
        FROM artifact_imports
    ) ranked
    WHERE rn > 1
);

ALTER TABLE artifact_imports
    ADD CONSTRAINT artifact_imports_dedup
        UNIQUE (target_session_id, content_hash);
