-- 00005_accounts.sql — the accounts table: the tenant.
--
-- An account is a workspace. It is the thing every other service scopes its data
-- by, and it is the subject of `identity.account.created`, `identity.member.*`
-- and (later) `identity.customer.created` in billing. The column set is the one
-- jumpstart's accounts table has, minus the parts this packet explicitly does not
-- build:
--
--   NOT HERE  owner_id      ownership is a role on account_users, not a column.
--                           One source of truth for "who runs this account"; a
--                           second column is a second answer to the same question
--                           and they would drift.
--   NOT HERE  domain        custom domains are out of scope for this packet.
--   NOT HERE  billing_email billing is a different service's concern.
--   NOT HERE  avatar        media is darkroom's concern.
--
-- `personal` marks the account a registration creates for its own user, as
-- opposed to a team account somebody created deliberately. It is what lets a
-- later packet say "you always have exactly one personal account" without
-- inventing a second table, and it is why the column defaults to false: a row
-- nobody asked for is a team account, and team is the ordinary case.

-- +goose Up

CREATE TYPE account_role AS ENUM ('owner', 'admin', 'member');

CREATE TABLE accounts (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text        NOT NULL,
    slug        text        NOT NULL,
    personal    boolean     NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),

    -- A name is 120 characters, the same bound the application enforces
    -- (accounts.MaxNameLength). The CHECK is the database's half of that promise:
    -- the application validates so it can answer 422, this guarantees it.
    CONSTRAINT accounts_name_length CHECK (char_length(name) BETWEEN 1 AND 120),

    -- A slug is one DNS label: lower-case ASCII alphanumerics separated by single
    -- dashes, never leading or trailing. This is exactly what
    -- accounts.Slugify produces, so a slug that reaches this table is one a later
    -- packet can put in a hostname without re-normalising it.
    CONSTRAINT accounts_slug_format CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),

    -- 63 is the length of a single DNS label, which is where the number comes
    -- from rather than from taste.
    CONSTRAINT accounts_slug_length CHECK (char_length(slug) BETWEEN 1 AND 63)
);

-- The uniqueness that makes a slug a handle. It is an index rather than a UNIQUE
-- constraint for the same reason users_email_key is: the violation surfaces as
-- 23505 on accounts_slug_key, which is what the store maps to a 409.
--
-- A slug is derived from the name at creation and never changes afterwards (see
-- accounts.Account.Slug), so this is a create-time conflict and not a rename-time
-- one. Two people who both want "acme" get 409 on the second, which is a
-- deliberate refusal rather than a silent disambiguation: quietly appending -2
-- would hand out a handle nobody chose.
CREATE UNIQUE INDEX accounts_slug_key ON accounts (slug);

-- +goose Down

-- The membership table references this one, so the type goes last and only after
-- account_users and account_invitations are gone. goose runs Down in file order,
-- so 00006 and 00007 must be rolled back first; that is the same requirement as
-- rolling back 00002 before 00001.
DROP INDEX accounts_slug_key;
DROP TABLE accounts;
DROP TYPE account_role;
