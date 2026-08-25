-- Add a join token to sessions so that only humans with the invite link can attach.
-- Existing sessions get a random token backfilled via gen_random_uuid().
ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS join_token TEXT NOT NULL DEFAULT '';

UPDATE sessions
    SET join_token = gen_random_uuid()::text
    WHERE join_token = '';

-- Tighten the default so future inserts without an explicit token get a UUID automatically.
ALTER TABLE sessions
    ALTER COLUMN join_token SET DEFAULT gen_random_uuid()::text;
