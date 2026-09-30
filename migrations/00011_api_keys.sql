-- 00011_api_keys.sql — the scoped API token: the credential that is not a
-- browser session.
--
-- ONE TABLE, and it holds four different kinds of fact:
--
--   who it is          id, account_id, user_id, name
--   what it proves     token_digest
--   what it may do     scopes
--   how it ends        expires_at, revoked_at
--
-- Plus last_used_at, which is the only column here that is written on the READ
-- path rather than by a human, and the comment on it says why that is bounded.
--
-- NAMED api_keys, NOT api_tokens, because core's event catalog calls these
-- `identity.api_key.created` / `identity.api_key.revoked` and the published
-- vocabulary is the one thing in this file that another repository has already
-- committed to.

-- +goose Up

CREATE TABLE api_keys (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- ON DELETE CASCADE for both, and the two deletions are different facts:
    --
    --   a deleted user   takes their credentials with them. An api key for a
    --                    user who no longer exists is a key that can only ever be
    --                    refused, and leaving the rows behind would grow the
    --                    table for accounts that are already gone.
    --   a deleted account takes its tokens with it. A credential scoped to a
    --                    tenant that has been deleted is a credential into
    --                    nothing, and the CASCADE is what stops the resolution
    --                    query from having to reason about a dangling account.
    user_id         uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    account_id      uuid        NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,

    -- What an operator calls this credential in a settings page, a CI variable
    -- description and an incident.
    --
    -- REQUIRED, and the reason is revocation rather than presentation: an
    -- operator revokes by what they can read, and a token with no name is a
    -- token they can only revoke by copying a uuid out of a list. The same rule
    -- the OIDC registration's `name` carries, for the same reason — a login page
    -- that cannot name the application asking for a password is the setup for a
    -- credential-phishing page.
    name            text        NOT NULL,

    -- THE SECRET AT REST.
    --
    -- The lower-case hex SHA-256 of the presented value, never the value. The
    -- argument is internal/sessions/token.go's and it is unchanged here: argon2id
    -- exists to make GUESSING expensive, and 256 bits of crypto/rand has no
    -- guessable structure for a memory-hard function to slow down. What would be
    -- different on this table rather than on sessions is the LIFETIME — an api
    -- key lives for months where a session lives for weeks — and the answer to
    -- that is not a slower hash. It is that the presented value is never stored,
    -- so a dump is not a set of credentials, and that the token is revocable and
    -- expires without anybody having to rotate a key for the platform to be
    -- clean. The stored column is the only thing a dump yields, and one SHA-256
    -- of a 256-bit value is not invertible.
    --
    -- The presented value INCLUDES the `cafaye_` prefix and the whole string is
    -- what is hashed, so a digest is bound to the format it was minted in. That
    -- is not needed for security — nothing here compares a digest to a guess —
    -- and it is here because it removes a question: two credential types can
    -- never produce the same digest for the same random bytes.
    token_digest    text        NOT NULL,

    -- WHAT THIS CREDENTIAL MAY DO, and nothing else.
    --
    -- Deliberately a text array with no CHECK, and the reason is the same one
    -- internal/oidc's `scopes` column carries: the closed set of scopes is a CODE
    -- fact, and putting it in the schema would mean adding a scope is a
    -- migration. A row that somehow holds a scope this build does not know about
    -- is refused at the point of use, which is the fail-closed direction — the
    -- alternative, treating an unknown scope as "and so anything goes", is the
    -- bug that a future migration would introduce silently.
    --
    -- The CHECK below is only "not empty". A token with no scopes is a session
    -- that never expires, and it is refused at creation rather than defaulted to
    -- something.
    scopes          text[]      NOT NULL,

    -- When the credential stops working whether anybody revokes it or not.
    --
    -- The instant the credential came into being, and the reference the lifetime
    -- CHECK below is measured against. It is the SERVICE's clock rather than
    -- now(), for the reason every other table here is: the row and the event
    -- announcing it have to agree, and only one of the two is under test control.
    created_at      timestamptz NOT NULL DEFAULT now(),

    -- NOT NULL, and the invariant that makes it NOT NULL is a CHECK rather than
    -- a convention in Go. A token that cannot expire is a permanent credential,
    -- and the one place that would be introduced is a future migration adding a
    -- nullable column and a handler that leaves it empty for "no preference". It
    -- is 422 to ask for one at the API.
    expires_at      timestamptz NOT NULL,

    -- The upper bound is enforced HERE as well as in Go, for the reason the OIDC
    -- access-token migration enforces its fifteen-minute cap in a CHECK: a
    -- constant in one file and a policy in another drift, and the drift is always
    -- in the direction of a credential that outlives its own policy. A token
    -- cannot be created with a year-and-a-bit lifetime even by a caller that
    -- skipped the service layer.
    CONSTRAINT api_keys_expires_after_creation
        CHECK (expires_at > created_at),
    CONSTRAINT api_keys_maximum_lifetime
        CHECK (expires_at <= created_at + INTERVAL '365 days'),

    -- WHEN IT WAS LAST USED, and the only column here written on the read path.
    --
    -- Nullable on purpose: "never used" and "used at the epoch" are different
    -- answers and a token nobody has ever presented is exactly the one an
    -- operator wants to notice.
    --
    -- It is NOT written on every request. A CI token at a thousand requests a
    -- second would put a thousand UPDATE round trips a second on one row, and a
    -- single row's lock is a queue. The write is conditional on the stored value
    -- being at least five minutes stale, which is one statement, needs no
    -- read-modify-write, and makes this column accurate to within five minutes —
    -- a resolution stated here rather than discovered by somebody who needed the
    -- exact second.
    last_used_at    timestamptz,

    -- Revocation. Set together or not at all, and the CHECK says so.
    --
    -- A revoked row is KEPT rather than deleted, for the same reason an OIDC
    -- registration is kept: "was this token revoked, or was it always broken?" is
    -- a support question and a deleted row answers neither. The token stops
    -- working the moment revoked_at is set, because the resolution query filters
    -- on it.
    revoked_at      timestamptz,
    revoked_by      uuid        REFERENCES users (id) ON DELETE RESTRICT,

    -- Why it was withdrawn, when the operator gave a reason. Nullable, and the
    -- empty string is stored as NULL rather than as '': "no reason given" and
    -- "the reason is the empty string" are not the same fact.
    --
    -- It is NOT in the revocation event, and the omission is the same decision
    -- internal/oidc's RevokeClient makes: a field whose values vary per operator
    -- is a field every consumer learns to ignore. It is here because this
    -- service's own support answers "why was this withdrawn" with it, which is a
    -- different consumer with a different need.
    revoke_reason   text,

    CONSTRAINT api_keys_token_digest_length
        CHECK (char_length(token_digest) = 64),
    CONSTRAINT api_keys_name_length
        CHECK (char_length(name) BETWEEN 1 AND 80),
    CONSTRAINT api_keys_scopes_not_empty
        CHECK (cardinality(scopes) > 0),
    CONSTRAINT api_keys_revocation_is_whole
        CHECK ((revoked_at IS NULL) = (revoked_by IS NULL)),
    -- The reason is the operator's to give or not, but a reason on a LIVE token
    -- is a half-written revocation that the constraint above cannot see.
    CONSTRAINT api_keys_reason_only_when_revoked
        CHECK (revoked_at IS NOT NULL OR revoke_reason IS NULL)
);

-- The lookup every authenticated machine request performs. It is an equality on
-- a fixed-width hex column, so it is the same shape as sessions.token_digest's
-- index and the same reasoning covers it: the digest's length is not a secret
-- and an unmatched probe is an ordinary indexed read.
CREATE UNIQUE INDEX api_keys_token_digest_key ON api_keys (token_digest);

-- "Every credential this account holds", newest first, which is the settings
-- page's query. Revoked rows are included on purpose — see the column comment.
CREATE INDEX api_keys_account_idx ON api_keys (account_id, created_at DESC, id DESC);

-- "Every credential this user holds", which is the sweep that answers "enabling
-- MFA should not leave a long-lived credential behind" and the one a future
-- admin API's "revoke everything" would use.
CREATE INDEX api_keys_user_idx ON api_keys (user_id);

-- ONE LIVE TOKEN PER NAME PER ACCOUNT.
--
-- The index is partial on revoked_at IS NULL, which is what makes rotation
-- possible: a revoked "ci-deploy" and the live one that replaced it coexist, so
-- "revoke the old, mint the new" is two requests rather than a transaction that
-- has to find a name free first. What it forbids is two LIVE tokens with one
-- name, because "revoke ci-deploy" would then be ambiguous and an operator
-- picking the wrong one is the failure this index removes.
CREATE UNIQUE INDEX api_keys_one_live_name_per_account
    ON api_keys (account_id, lower(name))
    WHERE revoked_at IS NULL;

-- The sweep that removes credentials nobody is going to use again. It is an index
-- rather than a job in this packet — the README's "Not built yet" says so — but
-- the index is here so the job is one statement when it lands.
CREATE INDEX api_keys_expires_at_idx ON api_keys (expires_at);

-- +goose Down

DROP TABLE api_keys;