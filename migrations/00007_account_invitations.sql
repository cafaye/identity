-- 00007_account_invitations.sql — the invitations.
--
-- An invitation is a pending membership: an account, an email address, the role
-- the invitee would get, and a token that redeems it. Accepting one is a
-- transaction that creates the membership and marks the invitation accepted;
-- the two are the same transaction or the invite is a bug — either a membership
-- nobody was invited to hold, or an invitation that has already been used and
-- can be used again.
--
-- THE TOKEN IS STORED AS A DIGEST
--
-- token_digest, not token. The raw token exists exactly once, in the response to
-- the create call, and there is no column here that could hold it afterwards. A
-- database dump therefore yields no usable invitation, which is the same rule
-- that governs sessions.token_digest and users.password_digest. The digest is
-- SHA-256, not argon2id, for the same reason sessions uses SHA-256: a
-- 256-bit random token has no guessable structure, so a memory-hard hash would
-- buy nothing and would cost every acceptance tens of milliseconds. The rule
-- that matters on all three columns is that the presented value is never stored.
--
-- WHY invites carry a narrower role
--
-- role is account_invitation_role with only admin and member. Ownership is
-- granted by an existing owner, never carried by a link: an account whose owner
-- appears because somebody forwarded an email is an account with an owner nobody
-- chose. The narrower enum makes that unrepresentable in the schema rather than
-- checked in three places.
--
-- WHY token_digest IS UNIQUE
--
-- A redemption looks the invitation up by digest, so a duplicate would make
-- "which one did I get" ambiguous. 256 bits of entropy makes a collision
-- impossible in practice, and the unique index turns the impossible case into an
-- error rather than a nondeterministic accept.
--
-- WHAT IS NOT HERE
--
-- NOT HERE  name          jumpstart carries the invitee's display name. This
--                         service has one name field (on the user), so the
--                         invitation names nobody.
--   NOT HERE  roles jsonb   see 00006: one enum value, not a set of booleans.
--   NOT HERE  token         see above.

-- The Down section is at the bottom of this file, and it drops the type only
-- after the table that uses it.

-- +goose Up

CREATE TYPE account_invitation_role AS ENUM ('admin', 'member');

CREATE TABLE account_invitations (
    id           uuid                      PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id   uuid                      NOT NULL,
    email        text                      NOT NULL,
    role         account_invitation_role   NOT NULL,
    token_digest text                      NOT NULL,
    -- Set to now() + 7 days by the application, from the injected clock. A
    -- timestamptz and not an integer day count, so "expires at" is a value the
    -- database can compare and a test can move time against.
    expires_at   timestamptz               NOT NULL,
    -- NULL until redeemed. Not a zero timestamp: "never accepted" and "accepted
    -- at the epoch" are different answers and only one of them is true.
    accepted_at  timestamptz,
    invited_by   uuid                      NOT NULL,
    created_at   timestamptz               NOT NULL DEFAULT now(),
    updated_at   timestamptz               NOT NULL DEFAULT now(),

    -- CASCADE: deleting the account deletes its pending invitations. A user
    -- deletion is RESTRICT rather than CASCADE, because an invitation outlives
    -- the person who sent it — the account still wants the invitee, and silently
    -- dropping the invitation because an admin left is not something the account
    -- asked for. Deleting a user with pending invitations is therefore refused by
    -- the database until they are revoked, which is a later packet.
    CONSTRAINT account_invitations_account_id_fkey
        FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE,

    CONSTRAINT account_invitations_invited_by_fkey
        FOREIGN KEY (invited_by) REFERENCES users (id) ON DELETE RESTRICT,

    -- Normalised to lower case by the application, exactly as users.email is, and
    -- the same CHECK makes it a database guarantee rather than a convention.
    CONSTRAINT account_invitations_email_is_normalized CHECK (email = lower(email)),
    CONSTRAINT account_invitations_email_length CHECK (char_length(email) BETWEEN 3 AND 320),

    -- 64 hex characters, lower case: SHA-256 rendered by hex.EncodeToString.
    CONSTRAINT account_invitations_token_digest_length
        CHECK (char_length(token_digest) = 64),

    -- An invitation that is already past its expiry at insert time is a bug in the
    -- caller rather than a state worth storing, and it would be indistinguishable
    -- from a legitimate expired one when redeemed.
    --
    -- There is deliberately NO equivalent constraint on accepted_at. expires_at is
    -- the caller's clock plus seven days, so there is a week of margin against any
    -- drift between this process and the server. accepted_at is the caller's clock
    -- right now, compared against a created_at the server stamped: any host whose
    -- clock runs even slightly behind Postgres fails every redemption with a 500 on
    -- a constraint nobody asked for. The invariant actually worth having --
    -- accepted_at is only ever set once -- is enforced by the conditional UPDATE in
    -- Store.MarkInvitationAccepted, which is the one place it can be enforced
    -- atomically.
    CONSTRAINT account_invitations_expires_after_creation
        CHECK (expires_at > created_at)
);

-- Redemption looks the invitation up by digest. This index is that lookup.
CREATE UNIQUE INDEX account_invitations_token_digest_key ON account_invitations (token_digest);

-- "Which addresses has this account already invited, and is any of them still
-- pending" is both a listing and a duplicate check, so the index is UNIQUE on
-- (account_id, email) and partial on the pending rows.
--
-- Partial rather than a full unique constraint on (account_id, email), because a
-- full one would make an account permanently un-invitable: accepting an
-- invitation consumes it, and without the partial predicate the address could
-- never be invited again. The predicate is what makes "one *pending* invitation
-- per address" the rule rather than "one invitation ever".
--
-- The account_id leading column also covers "who is still waiting for this
-- account" as a prefix, which is why there is no separate index for the listing.
CREATE UNIQUE INDEX account_invitations_pending_idx
	ON account_invitations (account_id, email) WHERE accepted_at IS NULL;

-- +goose Down

DROP INDEX account_invitations_token_digest_key;
DROP TABLE account_invitations;
DROP TYPE account_invitation_role;
