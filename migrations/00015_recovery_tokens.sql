-- 00015_recovery_tokens.sql — the one-time, time-bounded tokens identity mails
-- to prove somebody controls an address.
--
-- ONE TABLE FOR THREE FLOWS, and the reason is that the three share a lifecycle
-- rather than merely a topic:
--
--   password_reset  mint -> mail -> redeem once -> the password changes
--   verify_email    mint -> mail -> redeem once -> the address is marked proved
--   email_change    mint -> mail -> confirm the CURRENT address
--                                    -> mint a second token -> mail it to the NEW
--                                    -> confirm it -> the address changes
--
-- Every row is a 256-bit random value stored as a SHA-256 digest, expires on a
-- deadline, and is spent by a CONDITIONAL UPDATE so that two requests carrying the
-- same token resolve to one winner. Those three facts are the security properties,
-- and they are the schema's job rather than the code's, exactly as `sessions` and
-- `mfa_challenges` already do it.
--
-- `purpose` IS A CLOSED SET IN GO AND A CHECK HERE, for the reason 00011 gives for
-- api_keys.scopes and 00012 for account_audit_log.action: a closed vocabulary is a
-- code fact, and putting it in the schema would make adding a purpose a migration.
-- The CHECK is a second opinion, not the definition — a row naming a purpose this
-- build does not know about is refused when it is read, which is the fail-closed
-- direction.

-- +goose Up

CREATE TABLE recovery_tokens (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- ON DELETE CASCADE: a token for a user who no longer exists is a token that
    -- can only ever be refused, and leaving it behind would keep the table growing
    -- for accounts that were deleted.
    user_id         uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    purpose         text        NOT NULL,

    -- The lower-case hex SHA-256 of the token that was mailed. Never the token:
    -- it travels in a URL that ends up in a browser history, a proxy log and a
    -- support ticket, and those are places secrets go to be read by people who
    -- should not read them. Same construction as sessions.token_digest.
    token_digest    text        NOT NULL,

    -- The address being moved TO, and it is present on exactly one purpose: the
    -- email_change row. Everything else is NULL, and the CHECK below makes
    -- "present iff the purpose wants it" a database fact rather than a convention.
    target_email    text,

    -- THE SECOND TOKEN OF AN EMAIL CHANGE, and the whole reason this table is one
    -- row and not two.
    --
    -- NULL until the CURRENT address has been confirmed, and the CHECK enforces
    -- that: a token for an address nobody has yet proved they control cannot exist.
    -- That is the property that makes a hijacked session harmless here — the
    -- attacker who starts an email change gets a link in the VICTIM's inbox and
    -- nowhere else, and the request stalls until the victim either follows it or
    -- does not.
    target_token_digest text,

    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,

    -- Set by a conditional UPDATE the first time each side is confirmed. The
    -- WHERE clause IS the single-use check, so two requests carrying the same
    -- token resolve to one winner and one refusal, with no lock and no
    -- read-then-write.
    token_consumed_at  timestamptz,
    target_consumed_at timestamptz,

    CONSTRAINT recovery_tokens_purpose_is_known
        CHECK (purpose IN ('password_reset', 'email_change', 'verify_email')),

    CONSTRAINT recovery_tokens_digest_length
        CHECK (char_length(token_digest) = 64),

    -- An expiry at or before the instant it was minted is a token that was never
    -- usable, and every read filters on expires_at > now, so such a row is
    -- indistinguishable from an absent one and can never be spent.
    CONSTRAINT recovery_tokens_expiry_is_after_creation
        CHECK (expires_at > created_at),

    -- The target half is the whole of the email change, and nothing else carries
    -- one. The equality rather than two implications is the point: it also refuses
    -- an email_change row with no target, which is a request that can never
    -- complete.
    CONSTRAINT recovery_tokens_target_is_for_an_email_change
        CHECK ((purpose = 'email_change') = (target_email IS NOT NULL)),

    -- No second token before the first is spent. This is the hijack property as a
    -- database guarantee rather than as a comment in the Go.
    CONSTRAINT recovery_tokens_target_needs_a_confirmed_first_side
        CHECK (target_token_digest IS NULL OR token_consumed_at IS NOT NULL),

    -- And the new address cannot be confirmed before the old one either, which is
    -- the other half of the same sentence.
    CONSTRAINT recovery_tokens_target_confirmation_needs_the_first
        CHECK (target_consumed_at IS NULL OR token_consumed_at IS NOT NULL),

    CONSTRAINT recovery_tokens_target_digest_length
        CHECK (target_token_digest IS NULL OR char_length(target_token_digest) = 64),

    -- The target address is stored the way users.email is stored, and the users
    -- table's own CHECK is the model: a query that joins the two must not have to
    -- normalise on the way.
    CONSTRAINT recovery_tokens_target_email_is_normalized
        CHECK (target_email IS NULL OR target_email = lower(target_email))
);

-- Both digests are 256 bits of crypto/rand, so a collision would hand one person's
-- password change to another. The first is unique across every purpose on purpose:
-- a token is one value, and a lookup that had to know which purpose it belonged to
-- would be a lookup that could be pointed at the wrong one.
CREATE UNIQUE INDEX recovery_tokens_token_digest_key
    ON recovery_tokens (token_digest);

-- The second token is unique only among the rows that have one, so the index is
-- partial rather than allowing every email_change row to collide on NULL.
CREATE UNIQUE INDEX recovery_tokens_target_digest_key
    ON recovery_tokens (target_token_digest)
    WHERE target_token_digest IS NOT NULL;

-- The cooldown read: "does this user already have a live token for this purpose,
-- and how old is it". Both halves of the answer are columns of this table and the
-- lookup is an equality on (user_id, purpose), which is what keeps a password
-- reset endpoint from being a mail cannon. See internal/recovery's RequestWindow.
CREATE INDEX recovery_tokens_user_purpose_idx
    ON recovery_tokens (user_id, purpose, created_at DESC);

-- The sweep. Nothing in this service runs one — see README.md, "Not built yet" —
-- but the index is here so that the job which removes expired rows is one
-- statement when it lands, rather than a scan.
CREATE INDEX recovery_tokens_expires_at_idx
    ON recovery_tokens (expires_at);

-- +goose Down

-- Standalone: nothing references recovery_tokens.
DROP TABLE recovery_tokens;