-- 00003_sessions.sql — server-side sessions.
--
-- The cookie and the API token are the same row and the same value: login mints
-- one 256-bit random token, hands it to the client twice (as the __Host-session
-- cookie and as a JSON field for API callers), and stores only its SHA-256.
--
-- Why SHA-256 and not argon2id for the digest, when the password column is
-- argon2id: argon2id exists to slow down guessing of a *low-entropy* secret.
-- This token is 256 bits from crypto/rand, so there is nothing to guess, and a
-- slow hash would only add latency to every authenticated request and a read
-- amplification factor on the table. The rule that matters is the same in both
-- cases: the presented value is never stored.
--
-- Sessions are revoked by DELETE, not by a revoked_at flag, because a revoked
-- session is indistinguishable from one that never existed as far as
-- authentication is concerned and there is no audit requirement on this surface
-- yet. If one arrives, the flag moves here rather than the callers changing.

-- +goose Up

CREATE TABLE sessions (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_digest text        NOT NULL,
    expires_at   timestamptz NOT NULL,
    user_agent   text,
    ip           inet,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

-- There is deliberately no CHECK tying expires_at to created_at. expires_at is
-- computed from the service's injected Clock while created_at is the database's
-- now(), so such a constraint would assert that two clocks agree — which is
-- false under test, false under a frozen system clock, and not a property worth
-- enforcing anyway. A session whose expiry has already passed is simply an
-- already-expired session: the store refuses to authenticate it, which is the
-- behaviour that actually matters.

CREATE UNIQUE INDEX sessions_token_digest_key ON sessions (token_digest);

-- Lookups by user: "sign out everywhere" and the cascade on user delete.
CREATE INDEX sessions_user_id_idx ON sessions (user_id);

-- Reaper support. Not yet written; the index is here so that when it is, it is
-- an index scan and not a sequential one over a table that grows forever.
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

-- +goose Down

DROP TABLE sessions;
