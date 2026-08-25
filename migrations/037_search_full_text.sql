-- Full-text search vectors for events and artifacts, replacing the plain
-- `::text ILIKE '%q%'` / `name ILIKE ... OR storage_ref ILIKE ...` scans in
-- db::search. Same fields searched before (payload::text for events,
-- name+storage_ref for artifacts) -- upgrading the technology (indexed,
-- word-aware, rankable) not the scope.
--
-- Two-argument to_tsvector('english', text), not the one-argument form: the
-- one-arg form depends on the `default_text_search_config` GUC, which
-- Postgres correctly refuses to call IMMUTABLE, so it can't back a
-- generated column. The two-arg form with a literal config name has no such
-- dependency. Concatenation uses `||`, not `concat()` -- `concat()` is not
-- immutable either and hits the same error.
--
-- left(..., 100000) before to_tsvector: tsvector has a hard ~1MB cap on its
-- own internal representation and *errors* rather than truncating past it
-- ("string is too long for tsvector") -- hit for real against this
-- project's own dev data (an events.payload over 1.1MB, presumably
-- something with embedded base64 content). 100,000 characters is already
-- far more searchable text than any real message/tool-arg payload needs;
-- anything past that is exactly the kind of large embedded blob that isn't
-- meaningfully full-text-searchable anyway. Applied to artifacts too, for
-- consistency, even though name/storage_ref are realistically never that
-- long.

ALTER TABLE events
    ADD COLUMN search_vector tsvector
    GENERATED ALWAYS AS (to_tsvector('english', left(payload::text, 100000))) STORED;

CREATE INDEX events_search_vector ON events USING GIN (search_vector);

ALTER TABLE artifacts
    ADD COLUMN search_vector tsvector
    GENERATED ALWAYS AS (
        to_tsvector('english', left(coalesce(name, '') || ' ' || coalesce(storage_ref, ''), 100000))
    ) STORED;

CREATE INDEX artifacts_search_vector ON artifacts USING GIN (search_vector);
