-- Per-actor capability descriptor table — doors-style local references.
--
-- A session_tokens row (cap) is addressed globally today: the raw ULID *is*
-- a bearer credential — whoever holds the string has the authority it
-- encodes. This table adds a second, local layer of indirection on top,
-- scoped per actor: `local_index` is meaningless outside that one actor's
-- own table, the same way a Solaris door descriptor or a Unix fd is
-- meaningless outside the process that holds it. Resolving one always goes
-- through the actor's own row set — there is no global lookup path for a
-- bare local_index, by design.
--
-- entity_uri reuses EntityHandle::uri()'s existing format ("cap/01J...")
-- rather than inventing a new addressing scheme. Scoped to caps only for
-- this pass — see crates/db/src/descriptors.rs's module doc for why
-- approvals were deliberately left out.
CREATE TABLE actor_descriptors (
    id          TEXT        PRIMARY KEY,
    actor_id    TEXT        NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    local_index INT         NOT NULL,
    entity_uri  TEXT        NOT NULL,
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (actor_id, local_index)
);

CREATE INDEX actor_descriptors_actor ON actor_descriptors(actor_id);
