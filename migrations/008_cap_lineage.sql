-- Capability lineage.
-- Recursive CTE answers delegation, provenance,
-- and authorization ancestry in one query.

-- parent_cap:   the token this cap was delegated from (NULL = root, human-issued)
-- observed_seq: the session seq the issuer observed at delegation time — the causal anchor
-- permissions:  JSON array of allowed tool names; empty array = all tools permitted

ALTER TABLE session_tokens
    ADD COLUMN parent_cap    TEXT        REFERENCES session_tokens(id),
    ADD COLUMN observed_seq  BIGINT      NOT NULL DEFAULT 0,
    ADD COLUMN permissions   JSONB       NOT NULL DEFAULT '[]';

-- cap_id on events: which capability authorized this effect.
-- NULL for events emitted via the WS path (human clients, legacy).
ALTER TABLE events
    ADD COLUMN cap_id TEXT REFERENCES session_tokens(id);

CREATE INDEX IF NOT EXISTS session_tokens_parent_cap ON session_tokens(parent_cap);
CREATE INDEX IF NOT EXISTS events_cap_id             ON events(cap_id);

-- Lineage query (for reference — used as a prepared query in db/tokens.rs):
--
-- WITH RECURSIVE lineage AS (
--     SELECT * FROM session_tokens WHERE id = $1
--     UNION ALL
--     SELECT t.* FROM session_tokens t
--     JOIN lineage l ON t.id = l.parent_cap
-- )
-- SELECT * FROM lineage ORDER BY observed_seq ASC;
