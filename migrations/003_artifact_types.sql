-- Drop the closed CHECK constraint on artifacts.type so arbitrary artifact
-- types (whiteboard, voice_memo, scheduled_transfer, etc.) are accepted.
-- The type column remains NOT NULL; validation is the application's concern.
ALTER TABLE artifacts DROP CONSTRAINT IF EXISTS artifacts_type_check;
