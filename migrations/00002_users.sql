-- 00002_users.sql — the users table.
--
-- One table, one job: the credential. Tenancy (accounts, memberships) is a later
-- migration and deliberately not bundled here (migrations/README.md: one logical
-- change per file).
--
-- Two columns beyond the obvious ones, both there for the brute-force lockout
-- (5 consecutive failures locks the account for 15 minutes):
--
--   failed_login_attempts  the current consecutive-failure run, reset to 0 by a
--                          successful login. A CHECK keeps it non-negative so a
--                          bug that decrements it fails loudly instead of
--                          silently disarming the lockout.
--   locked_until           when set and in the future, login is refused with 423.
--                          NULL means not locked. A null rather than a
--                          zero-time sentinel, because 'never' and 'epoch' are
--                          not the same answer.
--
-- Passwords are argon2id digests (see internal/users/password.go). The digest is
-- the only thing stored: there is no plaintext column, and no column that could
-- hold one.

-- +goose Up

CREATE TABLE users (
    id                    uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    email                 text        NOT NULL,
    password_digest       text        NOT NULL,
    failed_login_attempts integer     NOT NULL DEFAULT 0,
    locked_until          timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),

    -- Email is normalised to lower case by the application before it ever
    -- reaches this table, and the CHECK makes that a database guarantee rather
    -- than a convention. citext was the alternative; a plain text column plus a
    -- constraint is one fewer extension to install and one less implicit
    -- behaviour to reason about in a query plan.
    CONSTRAINT users_email_is_normalized CHECK (email = lower(email)),

    -- 320 is the RFC 5321 maximum length. Without an upper bound a caller could
    -- park a megabyte-long string in a UNIQUE index.
    CONSTRAINT users_email_length CHECK (char_length(email) BETWEEN 3 AND 320),

    CONSTRAINT users_failed_login_attempts_non_negative CHECK (failed_login_attempts >= 0)
);

-- The uniqueness that makes "one account per address" true. It is an index
-- rather than a UNIQUE constraint so the violation surfaces as 23505
-- (unique_violation) on users_email_key, which is what the store maps to a 409.
CREATE UNIQUE INDEX users_email_key ON users (email);

-- +goose Down

DROP TABLE users;
