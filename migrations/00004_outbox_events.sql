-- 00004_outbox_events.sql — the transactional outbox.
--
-- NOTE ON PROVENANCE: the packet for this migration cited
-- cafaye/core@master:docs/event-outbox.md. That file does not exist in core —
-- core ships docs/{event-naming,manifest-conventions,openapi-conventions}.md and
-- schemas/{event-envelope,cafaye.manifest}.schema.json, and nothing mentions an
-- outbox. The table below is therefore designed here, from the two things that
-- do exist and are authoritative:
--
--   schemas/event-envelope.schema.json  the wire shape, reproduced in
--                                       internal/outbox/envelope.go
--   docs/event-naming.md#Delivery        at-least-once; `id` is the dedupe key;
--                                       every consumer must be idempotent
--
-- If core later publishes docs/event-outbox.md, this migration is the
-- reconciliation list. It is a manager decision, not a silent follow-through.
--
-- The shape is the standard one and the reasoning is short:
--
--   * `envelope` holds the whole serialized event as jsonb. What gets published
--     is byte-identical to what was committed, and it is exactly the document
--     core's schema validates, so the store and the contract cannot drift.
--   * `type`, `source` and `occurred_at` are lifted out as columns because the
--     publisher filters on them. Reading the envelope's own columns out of jsonb
--     for every row of every batch is a choice nobody makes twice.
--   * `published_at` NULL means "not yet on the bus". The partial index below
--     keeps the publisher's working set proportional to the backlog, not to the
--     table.
--   * `attempts` and `last_error` exist so a poison event is visible instead of
--     being retried forever in silence. The give-up policy is a later packet.

-- +goose Up

CREATE TABLE outbox_events (
    -- The envelope `id`. Primary key *and* the consumer's dedupe key: the same
    -- UUID that goes on the wire is the one that makes re-inserting a batch
    -- idempotent, so a replayed transaction cannot mint a second copy of an
    -- event consumers have already seen.
    id          uuid        PRIMARY KEY,

    type        text        NOT NULL,
    source      text        NOT NULL,
    subject     text,
    occurred_at timestamptz NOT NULL,
    payload     jsonb       NOT NULL,
    envelope    jsonb       NOT NULL,

    published_at timestamptz,
    attempts     integer     NOT NULL DEFAULT 0,
    last_error   text,

    created_at  timestamptz NOT NULL DEFAULT now(),

    -- The two patterns below are copied from core's event-envelope.schema.json
    -- ($defs.eventType and $defs.serviceName). Reproducing them as CHECK
    -- constraints means a malformed type is rejected where it is written,
    -- instead of being published and then rejected by every consumer.
    CONSTRAINT outbox_events_type_format CHECK (
        type ~ '^[a-z][a-z0-9]*(_[a-z0-9]+)*(\.[a-z][a-z0-9]*(_[a-z0-9]+)*){1,2}$'
    ),
    CONSTRAINT outbox_events_source_format CHECK (
        source ~ '^[a-z][a-z0-9]*(-[a-z0-9]+)*$'
    ),

    -- core allows 1-2 additional dot-separated segments; these bound the two
    -- fields the publisher reads on every row.
    CONSTRAINT outbox_events_type_length CHECK (char_length(type) BETWEEN 5 AND 120),
    CONSTRAINT outbox_events_source_length CHECK (char_length(source) BETWEEN 2 AND 40),

    -- core caps subject at 200 characters.
    CONSTRAINT outbox_events_subject_length CHECK (subject IS NULL OR char_length(subject) BETWEEN 1 AND 200),

    CONSTRAINT outbox_events_attempts_non_negative CHECK (attempts >= 0)
);

-- The publisher's claim query is
--   SELECT ... WHERE published_at IS NULL ORDER BY created_at, id LIMIT $1 FOR UPDATE SKIP LOCKED
-- so the index is (created_at, id) and partial on the unpublished rows. Ordering
-- by id as well as created_at keeps the order total: created_at has microsecond
-- resolution and a batch of rows written in one transaction shares it.
CREATE INDEX outbox_events_unpublished_idx ON outbox_events (created_at, id) WHERE published_at IS NULL;

-- +goose Down

DROP TABLE outbox_events;
