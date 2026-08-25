-- Mailbox routes — a thin edge relation, not a new store. Connects a
-- receiver-specific address (an actor's mailbox) to a sender-owned fact by
-- reference: (who, what), resolved back to the real object on read via
-- EntityHandle::from_uri. No invite/cap/session data is duplicated here.
CREATE TABLE mailbox_routes (
    id               TEXT PRIMARY KEY,
    mailbox_actor_id TEXT NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    entity_uri       TEXT NOT NULL,   -- EntityHandle::uri(), e.g. "invite/01J..."
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Read/dismiss state lives here, not on the sender-owned fact — dismissing
    -- your own mailbox entry has no reason to touch the invite row itself.
    seen_at          TIMESTAMPTZ,
    UNIQUE (mailbox_actor_id, entity_uri)
);

CREATE INDEX mailbox_routes_actor ON mailbox_routes(mailbox_actor_id, created_at DESC);
