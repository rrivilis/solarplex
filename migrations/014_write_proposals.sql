-- 014_write_proposals.sql — Three-tier commitment model
--
-- Tier 1 — Solarplex-managed state: server-side atomic CAS via Postgres transaction.
--          Proposals cannot land against stale state.
--
-- Tier 2 — Filesystem writes: authorize-and-attest.  Receipt arg-binding with
--          before/after hashes; sidecar emits attestation recorded in event log.
--          Mismatch = security event detectable at audit time.
--
-- Tier 3 — Shell commands: approval gate + sandboxed egress (no table here).
--
-- See THREAT_MODEL.md §4.2 (three-tier commitment model) for full analysis.

-- ── Tier 1: write_proposals ───────────────────────────────────────────────────

CREATE TABLE write_proposals (
    id                   TEXT        PRIMARY KEY,

    -- Authorization linkage: every proposal is bound to the receipt that
    -- authorized the underlying tool call.  The receipt is NOT consumed at
    -- proposal time; it is consumed atomically when the proposal commits.
    -- UNIQUE enforces one-proposal-per-receipt — no double-submission.
    receipt_id           TEXT        NOT NULL REFERENCES execution_receipts(id)
                                     ON DELETE CASCADE,
    receipt_id_unique    TEXT        UNIQUE GENERATED ALWAYS AS (receipt_id) STORED,

    cap_id               TEXT        NOT NULL REFERENCES session_tokens(id)
                                     ON DELETE CASCADE,
    session_id           TEXT        NOT NULL REFERENCES sessions(id)
                                     ON DELETE CASCADE,

    -- Method address that generated this proposal (mcp.{slug}.{tool}).
    method               TEXT        NOT NULL,

    -- SHA-256 of the canonical args the receipt bound (ties proposal to receipt).
    -- Format: "sha256:<hex>".
    canonical_args_hash  TEXT        NOT NULL,

    -- Effect type: one of 'artifact_patch', 'context_entry'.
    -- Restricted to effects the commit path can atomically verify and apply.
    -- File writes are NOT in this table — they go through authorize-and-attest.
    effect_type          TEXT        NOT NULL,
    CONSTRAINT effect_type_valid CHECK (
        effect_type IN ('artifact_patch', 'context_entry')
    ),

    -- Declarative effect payload (type-dependent):
    --   artifact_patch: { "artifact_id": "...", "content": "<full replacement>" }
    --   context_entry:  { "kind": "hypothesis|decision|...", "content": "..." }
    effect_payload       JSONB       NOT NULL,

    -- CAS precondition: the target state MUST hash to this before the effect
    -- is applied.  Format: "sha256:<hex>".
    -- For context_entry (append-only), this field carries the current event seq
    -- as an ordering anchor but is not a hard blocker — commit always succeeds
    -- for append-only effects.
    expected_hash_before TEXT        NOT NULL,

    -- Claimed postcondition: commit path verifies after applying.
    -- Mismatch between claimed and actual H_after → proposal rejected.
    claimed_hash_after   TEXT        NOT NULL,

    -- Lifecycle
    proposed_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at           TIMESTAMPTZ NOT NULL,

    -- Resolution (at most one is set)
    committed_at         TIMESTAMPTZ,
    rejected_at          TIMESTAMPTZ,
    rejection_reason     TEXT,

    -- FK to the session event that recorded the committed transition.
    commit_event_id      TEXT,

    CONSTRAINT proposal_not_both_resolved CHECK (
        NOT (committed_at IS NOT NULL AND rejected_at IS NOT NULL)
    )
);

-- Indexes
CREATE INDEX write_proposals_session_pending ON write_proposals (session_id, proposed_at DESC)
    WHERE committed_at IS NULL AND rejected_at IS NULL;

CREATE INDEX write_proposals_cap ON write_proposals (cap_id);
CREATE INDEX write_proposals_receipt ON write_proposals (receipt_id);

-- GC index: find expired unresolved proposals
CREATE INDEX write_proposals_expires ON write_proposals (expires_at)
    WHERE committed_at IS NULL AND rejected_at IS NULL;

-- ── Tier 2: file_write_attestations ──────────────────────────────────────────

CREATE TABLE file_write_attestations (
    id                    TEXT        PRIMARY KEY,

    -- The execution receipt that authorized this file write.
    -- The receipt's args contain the approved hashes for comparison.
    receipt_id            TEXT        NOT NULL REFERENCES execution_receipts(id),
    session_id            TEXT        NOT NULL REFERENCES sessions(id)
                                      ON DELETE CASCADE,
    cap_id                TEXT        NOT NULL REFERENCES session_tokens(id)
                                      ON DELETE CASCADE,
    actor_id              TEXT        NOT NULL,

    -- The MCP tool that performed the write (e.g. "write_file").
    tool                  TEXT        NOT NULL,
    -- Filesystem path the write targeted.
    path                  TEXT        NOT NULL,

    -- What the sidecar approved (from receipt args) — what was shown to the human.
    approved_hash_before  TEXT        NOT NULL,
    approved_hash_after   TEXT        NOT NULL,

    -- What the sidecar actually observed — read before and after the write.
    observed_hash_before  TEXT        NOT NULL,
    actual_hash_after     TEXT        NOT NULL,

    -- True when attested hashes diverge from approved hashes.
    -- This is a security event: the world was different from what the human saw,
    -- or the write produced a different result than declared.
    -- Stored as a generated column so queries against it hit the index without
    -- any application-layer computation.
    hash_mismatch         BOOLEAN     NOT NULL GENERATED ALWAYS AS (
        observed_hash_before <> approved_hash_before
        OR actual_hash_after <> approved_hash_after
    ) STORED,

    attested_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX file_write_attestations_session  ON file_write_attestations (session_id, attested_at DESC);
CREATE INDEX file_write_attestations_mismatch ON file_write_attestations (session_id)
    WHERE hash_mismatch;
CREATE INDEX file_write_attestations_receipt  ON file_write_attestations (receipt_id);
