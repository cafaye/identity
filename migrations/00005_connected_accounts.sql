-- 00005_connected_accounts.sql — a social identity linked to a user.
--
-- "Continue with Google/GitHub" needs exactly one new fact: the provider's own
-- identifier for a person, and the credential this service holds on their behalf.
-- That is this table, and nothing else. The people are rows in `users` already.
--
-- `provider` is a real Postgres enum rather than a CHECK on text. The values are
-- a closed set that the service itself is the authority for, the column is read
-- on every login, and a value that is not one of the two cannot be cast into the
-- column at all — so an unknown provider fails at the database boundary instead
-- of becoming a row nothing can route.
--
-- `provider_uid` is the provider's stable id for the account (Google's `sub`,
-- GitHub's numeric user id). It is NOT an email: a provider may let a person
-- change their email, and two accounts on the same provider can hold the same
-- address. The uniqueness that matters is therefore
--
--     UNIQUE (provider, provider_uid)
--
-- and not anything involving `user_id`: one user may link several providers, and
-- several users must never end up owning one provider identity. That single index
-- is what turns the concurrent-link race into a 23505 rather than into two rows.
--
-- `user_id` cascades. A deleted user has no connected accounts; leaving them
-- would keep the provider uid reserved forever and block that person from ever
-- signing in again with the same social account.
--
-- The two token columns hold CIPHERTEXT, never a token. They are named
-- `_ciphertext` for the same reason `sessions` stores `token_digest` rather than
-- `token`: a column called `access_token` can be filled with a plaintext token by
-- one bad code path and nothing would notice, whereas a column called
-- `access_token_ciphertext` fails the moment that happens. The format is
-- internal/oauth/cipher.go — AES-256-GCM, `v1.<base64url(nonce||ciphertext||tag)>`.
--
-- `expires_at` is NULL when the provider issues no expiry (GitHub's default), and
-- a timestamp when it does (Google's one-hour tokens). It is the *provider
-- token's* expiry, not the session's; `sessions.expires_at` is the other one and
-- the two are unrelated.

-- +goose Up

CREATE TYPE oauth_provider AS ENUM ('google', 'github');

CREATE TABLE connected_accounts (
    id                       uuid            PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                  uuid            NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    provider                 oauth_provider  NOT NULL,
    provider_uid             text            NOT NULL,

    -- NOT NULL: a connected account without a credential is not a connected
    -- account. The whole row exists because the provider issued us something.
    access_token_ciphertext  text            NOT NULL,
    -- NULL rather than "": a provider that issues no refresh token (GitHub) and
    -- one whose refresh is pending a re-consent (Google) are different states and
    -- an empty string cannot tell them apart.
    refresh_token_ciphertext text,
    expires_at               timestamptz,

    created_at               timestamptz    NOT NULL DEFAULT now(),
    updated_at               timestamptz    NOT NULL DEFAULT now(),

    -- provider_uid is bounded because it goes into the unique index below, and
    -- an unbounded value there is a megabyte per row of index. 255 is well above
    -- both providers' real identifiers (Google's `sub` is 21 digits; GitHub's is
    -- a bigint rendered in decimal).
    CONSTRAINT connected_accounts_provider_uid_length
        CHECK (char_length(provider_uid) BETWEEN 1 AND 255),

    -- A sealed token is `v1.` plus base64url of a 12-byte nonce, a ciphertext
    -- and a 16-byte tag. The bound stops a caller parking a megabyte in a text
    -- column that a provider can write to.
    CONSTRAINT connected_accounts_access_token_ciphertext_length
        CHECK (char_length(access_token_ciphertext) BETWEEN 4 AND 4096)
);

CREATE UNIQUE INDEX connected_accounts_provider_uid_key
    ON connected_accounts (provider, provider_uid);

-- "Which accounts has this user linked?" — the settings page, and the check that
-- a link is not already there.
CREATE INDEX connected_accounts_user_id_idx ON connected_accounts (user_id);

-- +goose Down

DROP TABLE connected_accounts;
DROP TYPE oauth_provider;