-- 015_security_hardening.sql — DB-layer security invariants for the cap DAG
--
-- Two triggers enforce structural invariants that the application layer
-- can observe but not reliably prevent at Rust level alone.
--
-- Trigger 1 — Field immutability on session_tokens
-- -------------------------------------------------
-- `permissions`, `epoch`, and `stratum` are set at INSERT time and must
-- never change.  They encode the authority tuple (what may the bearer do,
-- in which epoch, at which depth?).  Mutation at the DB layer would be a
-- hostile engineer attack vector: "change_permissions / become_root without
-- going through the graph rewrite algebra."
--
-- Allowed mutations: `used_at`, `revoked_at`, `transferred_to` (lifecycle).
-- All other fields including permissions/epoch/stratum are immutable.
--
-- Trigger 2 — Cross-epoch parent-child coherence on INSERT
-- --------------------------------------------------------
-- Every cap's `epoch` must match its parent's `epoch` at insert time.
-- Violating this means a child cap lives in a different epoch from its
-- parent, which breaks the revocation algebra: `revoke_epoch(N)` would
-- leave children from epoch N+1 dangling under a ghost parent.
--
-- See THREAT_MODEL.md §4.3, §4.4 for the authority graph rewrite algebra.

-- ── Trigger 1: field immutability ─────────────────────────────────────────────

CREATE FUNCTION enforce_token_field_immutability()
RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    -- permissions is a JSONB column; compare as text to handle key-order variance.
    IF OLD.permissions::text IS DISTINCT FROM NEW.permissions::text THEN
        RAISE EXCEPTION
            'session_tokens.permissions is immutable after insert (cap %, old: %, new: %)',
            OLD.id, OLD.permissions, NEW.permissions;
    END IF;

    IF OLD.epoch IS DISTINCT FROM NEW.epoch THEN
        RAISE EXCEPTION
            'session_tokens.epoch is immutable after insert (cap %, old: %, new: %)',
            OLD.id, OLD.epoch, NEW.epoch;
    END IF;

    IF OLD.stratum IS DISTINCT FROM NEW.stratum THEN
        RAISE EXCEPTION
            'session_tokens.stratum is immutable after insert (cap %, old: %, new: %)',
            OLD.id, OLD.stratum, NEW.stratum;
    END IF;

    -- parent_cap rerooting (reroot_caps) is a legitimate DB operation.
    -- Session-scoped rerooting is now enforced at the application layer
    -- (reroot_caps takes session_id); we don't block it at the trigger level.

    RETURN NEW;
END;
$$;

CREATE TRIGGER session_tokens_immutable_fields
    BEFORE UPDATE ON session_tokens
    FOR EACH ROW
    EXECUTE FUNCTION enforce_token_field_immutability();

-- ── Trigger 2: cross-epoch coherence ─────────────────────────────────────────

CREATE FUNCTION enforce_token_epoch_coherence()
RETURNS TRIGGER
LANGUAGE plpgsql AS $$
DECLARE
    parent_epoch BIGINT;
    parent_session TEXT;
BEGIN
    IF NEW.parent_cap IS NULL THEN
        -- Root cap (stratum = 0): no parent to check.
        RETURN NEW;
    END IF;

    SELECT epoch, session_id
    INTO parent_epoch, parent_session
    FROM session_tokens
    WHERE id = NEW.parent_cap;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'parent cap % not found (child %, epoch %)',
            NEW.parent_cap, NEW.id, NEW.epoch;
    END IF;

    -- Session isolation: a child must belong to the same session as its parent.
    IF parent_session IS DISTINCT FROM NEW.session_id THEN
        RAISE EXCEPTION
            'cross-session delegation rejected: child session % does not match parent session % (child %, parent %)',
            NEW.session_id, parent_session, NEW.id, NEW.parent_cap;
    END IF;

    -- Epoch coherence: child must be in the same epoch as its parent.
    -- A child in epoch N+1 would survive revoke_epoch(N) as an orphan, breaking
    -- the revocation algebra.
    IF parent_epoch IS DISTINCT FROM NEW.epoch THEN
        RAISE EXCEPTION
            'cross-epoch delegation rejected: child epoch % does not match parent epoch % (child %, parent %)',
            NEW.epoch, parent_epoch, NEW.id, NEW.parent_cap;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER session_tokens_epoch_coherence
    BEFORE INSERT ON session_tokens
    FOR EACH ROW
    EXECUTE FUNCTION enforce_token_epoch_coherence();
