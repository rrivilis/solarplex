-- Extend the sessions.status CHECK constraint to allow richer
-- operational state values for multi-level alerting.
ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_status_check;
ALTER TABLE sessions
  ADD CONSTRAINT sessions_status_check
  CHECK (status IN (
    'active',
    'attention_requested',
    'action_needed',
    'policy_update',
    'suspended',
    'archived'
  ));
