-- Cross-session sync v1 (single-artifact propose/approve, migration 022) is
-- superseded by session_links' full live multiplex (migration 023) — one
-- mechanism instead of two, per product decision.
DROP TABLE IF EXISTS session_object_refs;
