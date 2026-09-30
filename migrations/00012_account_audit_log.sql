-- 00012_account_audit_log.sql — the admin surface's audit trail.
--
-- The first table in this service whose rows are written ONLY by a service use
-- case and can never be changed afterwards. Every other table here has an
-- UPDATE and a DELETE somewhere in the codebase, and the ones that are
-- credentials keep a revoked row precisely so that "was this withdrawn, or was
-- it always broken?" is answerable. This one has no second state at all: an
-- entry is a statement that something happened, and a statement that can be
-- edited is not a statement.
--
-- WHY IT HAS NO FOREIGN KEY ON accounts, AND THAT IS THE POINT
--
-- Every other table in this schema cascades from `accounts`. This one does not,
-- and it is the single most deliberate line in the file. A CASCADE is a DELETE,
-- and a DELETE is what the trigger below refuses — so a cascading account
-- deletion would be blocked, and `DELETE /v1/accounts/{accountID}` is a shipped
-- route that a tenant may legitimately call.
--
-- The alternative to a bare uuid is to let the cascade through and exempt it,
-- which cannot be done reliably: a trigger cannot tell a cascading delete from a
-- deliberate one. So the reference is dropped instead, and what that buys is the
-- property the packet asks for in the strongest available form:
--
--     THE ADMIN SURFACE CANNOT DELETE ITS OWN AUDIT LOG BY DELETING THE ACCOUNT.
--
-- The rows become unreachable through the API — no route serves an account that
-- does not exist — and they are retained for an operator reading the table
-- directly or importing it elsewhere. A trail that an admin can remove by
-- deleting the tenant is a trail with a documented expiry.
--
-- WHY THERE IS NO FOREIGN KEY ON THE ACTOR EITHER
--
-- actor_key_id is a bare uuid for the same reason, and here the failure it
-- prevents is the more embarrassing one. If the audit row referenced api_keys
-- with ON DELETE RESTRICT, then revoking is fine but any future hard delete of
-- a credential would be refused by the database — the audit trail would be
-- holding the credential table hostage. With SET NULL it is worse: the record
-- would lose the identity of who acted, which is the only part anybody reads.
--
-- So the actor is recorded as two plain uuids and survives everything the actor
-- does next, including deleting their own credentials and leaving the account.
--
-- WHAT IS NOT HERE
--
-- NOT HERE  the token value    nowhere, and never. `api_keys.TokenDigest` is a
--                              field on the struct a handler holds, so a careless
--                              `fmt.Sprintf("%+v", caller.Key)` in an audit path
--                              writes a credential's SHA-256 into a table an
--                              admin can read. The actor is the row's id.
-- NOT HERE  the request body  a DELETE has none and the bulk route's body is an
--                              array of ids; the array's length is a number and
--                              the ids are the target column, bounded.
-- NOT HERE  a CHECK on action the closed set of admin actions is a CODE fact, for
--                              exactly the reason api_keys.scopes has no CHECK:
--                              adding an action must not be a migration.

-- +goose Up

CREATE TABLE account_audit_log (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- NO REFERENCES accounts (id). See the file header: a cascade is a delete,
    -- and this table does not delete.
    account_id   uuid        NOT NULL,

    -- WHAT HAPPENED, from the closed set in internal/adminaudit. The set is
    -- validated in Go, not here, and a row holding an action this build does not
    -- know about is refused at the point of use rather than by the schema.
    action       text        NOT NULL,

    -- WHO DID IT, as two ids and no more.
    --
    -- actor_user_id is the human the token was minted for; actor_key_id is WHICH
    -- token, because "somebody in the account" is not an answer an incident
    -- review can use. Neither is a foreign key, so the record outlives both.
    actor_user_id uuid       NOT NULL,
    actor_key_id  uuid       NOT NULL,

    -- WHAT IT WAS DONE TO, and HOW MUCH OF IT.
    --
    -- affected is a count rather than a list so the row is bounded no matter how
    -- large the request was. target is a short label — one invitation id for the
    -- single route, the collection name for the bulk one — and the CHECK below
    -- is what keeps "short" a database fact rather than a convention.
    target      text        NOT NULL,
    affected    integer     NOT NULL,

    -- The request's trace id, so a log line and an audit row can be joined
    -- without either carrying a timestamp comparison.
    trace_id    text        NOT NULL,

    -- The service's clock, passed in like every other timestamp here so the row
    -- and the event announcing it agree and only one is under test control.
    occurred_at timestamptz NOT NULL,

    CONSTRAINT account_audit_log_affected_not_negative CHECK (affected >= 0),
    CONSTRAINT account_audit_log_target_length
        CHECK (char_length(target) BETWEEN 1 AND 64),
    -- 64 is the widest a trace id gets in this service; a longer one means
    -- something is writing a paragraph into an id column.
    CONSTRAINT account_audit_log_trace_id_length
        CHECK (char_length(trace_id) BETWEEN 1 AND 64)
);

-- The read order. "What has this account's admin surface done, newest first",
-- which is the audit-log route's whole query, and a keyset page over
-- (occurred_at DESC, id DESC) needs the index in that order to be an index
-- range rather than a sort of the whole table.
CREATE INDEX account_audit_log_account_idx
	ON account_audit_log (account_id, occurred_at DESC, id DESC);

-- THE APPEND-ONLY TRIGGER, which is the actual security property.
--
-- It lives in the DATABASE and not in the service, and that placement is the
-- whole argument. A service that refuses to UPDATE its own audit rows is a
-- service with a bug-shaped hole in it: the next packet adds an endpoint, or an
-- operator runs a repair script, or somebody connects with psql and fixes a row
-- "just to check", and the trail is editable by the admin whose action is in it.
-- The packet's requirement is that the record cannot be edited BY THE ADMIN WHO
-- PERFORMED IT, and a constraint in Go cannot say that about a psql session.
--
-- It fires on UPDATE and DELETE, never on INSERT, and never on TRUNCATE — a
-- TRUNCATE does not fire row-level triggers, which is how dbtest.Reset can still
-- wipe the table between deliberate runs.
--
-- The StatementBegin/End pair is not decoration: goose splits a migration on
-- semicolons, and a plpgsql body is full of them. Without the markers the body
-- is cut in half and the migration fails with "unterminated dollar-quoted
-- string", which reads like a quoting mistake rather than a missing marker.
-- +goose StatementBegin
CREATE FUNCTION account_audit_log_is_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'account_audit_log is append-only; % is not permitted', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER account_audit_log_append_only
    BEFORE UPDATE OR DELETE ON account_audit_log
    FOR EACH ROW EXECUTE FUNCTION account_audit_log_is_append_only();

-- +goose Down

DROP TRIGGER account_audit_log_append_only ON account_audit_log;
DROP FUNCTION account_audit_log_is_append_only();
DROP TABLE account_audit_log;
