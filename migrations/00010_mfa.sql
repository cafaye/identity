-- 00010_mfa.sql — the second factor: a TOTP credential, the recovery codes that
-- stand in for a lost phone, and the challenge a login waits on.
--
-- FOUR TABLES, because they have four different lifetimes and four different
-- rules about what a reader may do with them.
--
--   mfa_credentials      years, one live row per enrolled user
--   mfa_recovery_codes   years, ten rows, single-use
--   mfa_used_totp_steps  seconds, at most four rows per credential
--   mfa_challenges       ten minutes, one row per login waiting on a factor
--
-- `mfa_credentials` is the only one a human ever sees, and only through a
-- response body that does not contain the secret.

-- +goose Up

-- ---------------------------------------------------------------------------
-- mfa_credentials: a second factor, confirmed or not.
-- ---------------------------------------------------------------------------

CREATE TABLE mfa_credentials (
    id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    -- 'totp' and nothing else today. A column rather than a fact in the Go type
    -- because the row outlives this release: the day SMS or WebAuthn lands, a
    -- second method is a new row and not a rewrite of a table that holds live
    -- credentials. One method per row, so a user has one credential per method
    -- and the partial unique index below is on (user_id, method).
    method              text        NOT NULL,

    -- THE SECRET AT REST.
    --
    -- AES-256-GCM under a key derived from MFA_ENCRYPTION_KEY, base64url with a
    -- `v1.` prefix, and it CANNOT be a hash. A TOTP secret has to be recovered,
    -- not verified: the authenticator computes HMAC(secret, counter) and so does
    -- this service, so a one-way function over the secret would make the
    -- credential unverifiable. Encryption is the only transformation that
    -- satisfies both halves, and the key lives in the environment rather than in
    -- the row, so a dump of this table plus this schema yields no working second
    -- factor. The trade-off is recorded in README.md and reported: a lost key
    -- means every enrolled user must fall back to recovery codes, so the key
    -- belongs in the same secret store as OIDC_SIGNING_KEY and nowhere else.
    secret_ciphertext   text        NOT NULL,

    -- What the authenticator is told to do, kept on the row rather than assumed
    -- by the code, because a verifier that hardcodes them and a provisioning URI
    -- that advertises them can drift. Changing any of these invalidates every
    -- code a user's authenticator has ever produced, so they are read and
    -- honoured rather than re-derived.
    digits              smallint    NOT NULL,
    period_seconds      integer     NOT NULL,
    algorithm           text        NOT NULL,

    -- What the authenticator app displays, so a user with two accounts in two
    -- apps can tell them apart. Never a credential and never rendered back to a
    -- caller who did not create it.
    label               text        NOT NULL,

    -- NULL until the user proves they can produce a code from the secret.
    --
    -- An unconfirmed row authenticates NOTHING: it has no place in the login
    -- path, which reads only confirmed rows. It exists so the user has something
    -- to confirm against. A stored-but-never-confirmed secret is exactly the
    -- state that locks somebody out of their own account, which is why
    -- confirmation is the event that makes this row live and not the insert.
    confirmed_at        timestamptz,

    -- Only ever set on an UNCONFIRMED row: how long a half-finished enrollment
    -- is worth keeping. Cleared on confirmation. An unconfirmed secret nobody
    -- comes back for is a secret at rest for no reason, and a pending row with
    -- no bound is a table that grows by one row per abandoned setup.
    expires_at          timestamptz,

    -- The per-factor brute-force state.
    --
    -- THESE COLUMNS ARE NOT THE PASSWORD'S. internal/auth keeps the password's
    -- run on users.failed_login_attempts; this is a separate counter on a
    -- separate row, and that separation is the security property: an attacker
    -- who exhausts five TOTP guesses has not spent a password guess, and five
    -- wrong passwords have not moved this. The arithmetic is sessions.Lockout's
    -- — one implementation of the policy, two counters to run it on.
    failed_attempts     integer     NOT NULL DEFAULT 0,
    locked_until        timestamptz,

    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT mfa_credentials_method_is_totp
        CHECK (method = 'totp'),
    -- 6 and 8 are the two widths RFC 6238 authenticator apps actually speak.
    -- Nothing else can be written, so a stored digit count is never a value the
    -- verifier has no branch for.
    CONSTRAINT mfa_credentials_digits
        CHECK (digits IN (6, 8)),
    -- 30 seconds is what every authenticator app defaults to and what
    -- otpauth:// says when the period is omitted. The bounds exist so a row
    -- cannot name a period of zero (a division by zero in the counter
    -- arithmetic) or of a day (a code valid for a day is not a second factor).
    CONSTRAINT mfa_credentials_period
        CHECK (period_seconds BETWEEN 15 AND 300),
    -- HMAC-SHA1, because RFC 6238 mandates it for the interoperable case and
    -- because every phone's authenticator app supports it and no phone's
    -- supports anything else. Refused rather than defaulted so a row can never
    -- claim a stronger algorithm than the app that holds the secret can do.
    CONSTRAINT mfa_credentials_algorithm_is_sha1
        CHECK (algorithm = 'SHA1'),
    CONSTRAINT mfa_credentials_secret_present
        CHECK (char_length(secret_ciphertext) BETWEEN 1 AND 512),
    CONSTRAINT mfa_credentials_label_length
        CHECK (char_length(label) BETWEEN 1 AND 200),
    -- A confirmation is whole: the instant it was confirmed and the expiry that
    -- bounded the wait for it are set and cleared together. A row with a
    -- confirmed_at and a live expires_at is one the enrollment code would have
    -- to guess about, and a row with an expires_at and no confirmed_at is a
    -- pending one with no deadline.
    CONSTRAINT mfa_credentials_confirmation_is_whole
        CHECK ((confirmed_at IS NULL) = (expires_at IS NOT NULL)),
    CONSTRAINT mfa_credentials_failed_attempts_not_negative
        CHECK (failed_attempts >= 0)
);

-- AT MOST ONE LIVE CREDENTIAL PER USER PER METHOD.
--
-- The partial unique index IS the "MFA is on" invariant, and it is in the
-- database rather than in a read-then-write because a read-then-write has a
-- window between the two statements that two concurrent enrollments both walk
-- through. A user with two confirmed TOTP credentials is a state the rest of
-- this service has no answer for.
--
-- Pending rows are deliberately outside it: rotation keeps the confirmed secret
-- live until the replacement is confirmed, so two unconfirmed rows at once is a
-- supported state, not a bug.
CREATE UNIQUE INDEX mfa_credentials_one_live_per_user
    ON mfa_credentials (user_id, method)
    WHERE confirmed_at IS NOT NULL;

-- The sweep that removes abandoned enrollments. Without it, mfa_credentials
-- grows by one row per user who opened the setup page and closed it, and each
-- of those is an encrypted secret nobody will ever use.
CREATE INDEX mfa_credentials_expires_at_idx
    ON mfa_credentials (expires_at)
    WHERE confirmed_at IS NULL;

-- ---------------------------------------------------------------------------
-- mfa_recovery_codes: the codes that stand in for a lost phone.
-- ---------------------------------------------------------------------------

CREATE TABLE mfa_recovery_codes (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- ON DELETE CASCADE: disabling MFA removes the codes in the same write, and
    -- a set of recovery codes belonging to no credential is a set of live
    -- credentials to a credential that no longer exists.
    credential_id   uuid        NOT NULL REFERENCES mfa_credentials (id) ON DELETE CASCADE,

    -- The lower-case hex SHA-256 of the normalised code. Never the code.
    --
    -- SHA-256 and not argon2id, for the reason sessions.token_digest gives and
    -- the reason is the same one: a recovery code is 80 bits of crypto/rand
    -- output with no structure to guess, so a memory-hard hash would cost
    -- seconds of work per login to make a search that cannot succeed any slower.
    -- The invariant that matters is the one both columns share — the presented
    -- value is never stored, so this table is not a set of credentials.
    code_digest     text        NOT NULL,

    created_at      timestamptz NOT NULL DEFAULT now(),

    -- Set by a conditional UPDATE the first time the code is spent. This is what
    -- makes it single-use: the UPDATE's WHERE clause is the check, so two
    -- requests carrying the same code arriving at the same instant resolve to
    -- one winner and one refusal, with no lock and no read-then-write.
    used_at         timestamptz,

    CONSTRAINT mfa_recovery_codes_digest_length
        CHECK (char_length(code_digest) = 64)
);

-- A code is unique within its credential, which is what makes "one row per
-- code" and the conditional UPDATE above the same fact.
CREATE UNIQUE INDEX mfa_recovery_codes_digest_key
    ON mfa_recovery_codes (credential_id, code_digest);

-- "How many are left?" is a counted scan of the unused set, and it is asked on
-- every sign-in and by GET /v1/mfa, so it gets its own partial index rather
-- than counting ten rows.
CREATE INDEX mfa_recovery_codes_unused_idx
    ON mfa_recovery_codes (credential_id)
    WHERE used_at IS NULL;

-- ---------------------------------------------------------------------------
-- mfa_used_totp_steps: the replay guard.
-- ---------------------------------------------------------------------------
--
-- Replay is the standard attack against TOTP. A code is a six-digit string that
-- is valid for ninety seconds — thirty for its own step, thirty either side for
-- skew — and an attacker who photographs it has all that time to use it. So
-- "has this code been used" has to be remembered, and this table is the memory.
--
-- IT IS A SET, NOT A HIGH-WATER MARK, AND THAT IS THE WHOLE DESIGN.
--
-- The obvious implementation is one bigint on the credential: store the step that
-- was last accepted, refuse anything less than or equal to it. It refuses steps
-- that were never spent, because it cannot tell "step N was spent" from "step N
-- is old" — and inside a three-step window a step can be unspent and still be
-- below the mark whenever codes arrive out of order. A phone whose clock is
-- corrected backwards, a user who switches to a backup authenticator that is
-- behind, a device that re-syncs time mid-window: each is a user told their
-- correct code is wrong, and the cure they have is turning MFA off.
--
-- Remembering the exact steps consumed has no such case. It refuses a step that
-- was spent and accepts one that was not, whatever order they arrive in, which is
-- a property rather than a hope about what phones do.
--
-- BOUNDED BY CONSTRUCTION. Every acceptance prunes the steps below the current
-- window in the same transaction, so a credential holds at most (skew+2) rows
-- and this table is the same size as the number of enrolled users rather than
-- the number of logins.

CREATE TABLE mfa_used_totp_steps (
    credential_id   uuid        NOT NULL REFERENCES mfa_credentials (id) ON DELETE CASCADE,

    -- floor(unix / period). bigint because a Unix timestamp in seconds already
    -- needs one and a period short enough to overflow int32 is not something a
    -- supported configuration permits; the CHECK below keeps it honest anyway.
    step            bigint      NOT NULL,

    used_at         timestamptz NOT NULL DEFAULT now(),

    -- The primary key IS the replay check. `INSERT ... ON CONFLICT DO NOTHING`
    -- against it is a single atomic statement: exactly one concurrent request
    -- inserts the row and the others get zero rows back and are refused, with
    -- no explicit lock and nothing to roll back on a failure path.
    PRIMARY KEY (credential_id, step),

    CONSTRAINT mfa_used_totp_steps_step_not_negative
        CHECK (step >= 0)
);

-- ---------------------------------------------------------------------------
-- mfa_challenges: a login that has a correct password and no session yet.
-- ---------------------------------------------------------------------------
--
-- A row here is the proof that a password was correct and a second factor has
-- not been presented. It is the reason the credential a challenge names can be
-- any session token could not be: this row does not authenticate anybody, it
-- records that authentication is half finished, and the only thing that turns
-- it into a session is a second factor.

CREATE TABLE mfa_challenges (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- ON DELETE CASCADE: a challenge for a user who no longer exists is a
    -- challenge that can only ever be refused, and leaving it behind would keep
    -- the row count growing for accounts that were deleted.
    user_id         uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    -- The lower-case hex SHA-256 of the presented challenge token. Never the
    -- token, for the same reason sessions.token_digest is a digest: it goes in a
    -- cookie and in an access log, and a log aggregator is a place secrets go to
    -- be read by people who should not read them.
    token_digest    text        NOT NULL,

    -- Evidence for an incident, not identity. Nothing in this service makes an
    -- authorization decision on either, and both are absent for a plain API
    -- client. Same shape and same reason as the sessions table's two columns.
    user_agent      text,
    ip              inet,

    created_at      timestamptz NOT NULL DEFAULT now(),

    -- Ten minutes, the same window as the OIDC login form's sealed state. A
    -- challenge is a thing somebody is typing a six-digit code into right now;
    -- one that outlives the coffee break it was interrupted by is a credential
    -- waiting to be found in a log.
    expires_at      timestamptz NOT NULL,

    -- Set by a conditional UPDATE the first time a second factor is accepted
    -- against it. A challenge is not consumed by a wrong code: the per-factor
    -- lockout is what bounds a wrong code, and consuming the challenge as well
    -- would turn five guesses into one.
    consumed_at     timestamptz,

    CONSTRAINT mfa_challenges_token_digest_length
        CHECK (char_length(token_digest) = 64)
);

-- The challenge lookup is an equality test on a digest, on the hot path of every
-- sign-in by an enrolled user, and the token is 256 bits so a collision would
-- hand one login another's session.
CREATE UNIQUE INDEX mfa_challenges_token_digest_key ON mfa_challenges (token_digest);

-- The sweep that removes abandoned challenges.
CREATE INDEX mfa_challenges_expires_at_idx ON mfa_challenges (expires_at);

-- +goose Down

-- mfa_recovery_codes and mfa_used_totp_steps both reference mfa_credentials, and
-- mfa_challenges stands alone, so the credential table goes before them.
DROP TABLE mfa_challenges;
DROP TABLE mfa_used_totp_steps;
DROP TABLE mfa_recovery_codes;
DROP TABLE mfa_credentials;
