-- 013_authority_transfer.sql — Authority transfer function
--
-- Adds `transferred_to` to session_tokens so the audit trail can distinguish
-- the two ways a root cap is retired:
--
--   revoke()   → revoked_at IS NOT NULL, transferred_to IS NULL
--                Adversarial teardown.  Epoch is advanced.
--                Surviving children are left dangling (invalidated with the epoch).
--
--   transfer() → revoked_at IS NOT NULL, transferred_to IS NOT NULL
--                Cooperative ownership handoff.  Epoch is NOT advanced.
--                Children are reparented to the new root before old root is retired.
--
-- This distinction matters for threat analysis: a revoke in the audit log is
-- a security event (compromised agent, trust violation, explicit operator action).
-- A transfer in the audit log is a normal lifecycle event (human hands off session
-- to a colleague, scheduled delegation handoff fires).
--
-- See THREAT_MODEL.md §4.3 for the full graph rewrite algebra.

ALTER TABLE session_tokens
    ADD COLUMN transferred_to TEXT REFERENCES session_tokens(id);

-- Partial index — only retired-by-transfer rows; keeps the index tiny.
CREATE INDEX session_tokens_transferred ON session_tokens (transferred_to)
    WHERE transferred_to IS NOT NULL;
