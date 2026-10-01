-- 00014_user_email_verified_at.sql — the one column that says an address has
-- been proved.
--
-- WHY IT IS A SEPARATE FILE: the convention is one logical change per file, and
-- "a user may own a verified address" is a different change from "a one-time
-- token is delivered to an address". They are always applied together, and both
-- roll back separately.
--
-- IT IS NULL ON EVERY ROW THAT EXISTS TODAY, and that is the honest answer rather
-- than a backfill problem. There is no column to backfill FROM: identity has never
-- proved an address, and a migration that stamped `now()` onto existing rows would
-- be a claim this service has no evidence for — the same reason the OIDC
-- `email_verified` claim has been `false` rather than absent (internal/oidc/
-- profiles.go). Every existing user is therefore unverified until they redeem a
-- link, which is the true state of the world.
--
-- The semantics are deliberately narrow:
--
--   NULL            nobody has proved this address
--   a timestamptz   somebody received a link at this address and followed it
--
-- There is no `false`, no `revoked`, and no reason for either: a verification
-- proves control of the address that is on the row NOW, and the only way the row's
-- address changes is an email change, which clears the column back to NULL in the
-- same transaction that moves it (see internal/users.Store.SetEmail).

-- +goose Up

ALTER TABLE users
    ADD COLUMN email_verified_at timestamptz;

-- The read is "this user's verification state", which is on the primary key, and
-- the sweep is "every unverified account older than N", which is the only query
-- that is not a primary-key lookup. A partial index rather than a full one
-- because verified rows are the majority the moment the verification packet is
-- live, and an index over them answers no query this service asks.
CREATE INDEX users_email_unverified_idx
    ON users (created_at)
    WHERE email_verified_at IS NULL;

-- +goose Down

DROP INDEX users_email_unverified_idx;

-- The column goes with it. There is no data to preserve and no migration to
-- reverse: a rollback of this file returns the service to a state in which it has
-- no opinion about verification, which is exactly where it was.
ALTER TABLE users
    DROP COLUMN email_verified_at;