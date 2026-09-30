-- 00013_account_invitation_revocation.sql — the revoked_at column the admin
-- surface's invitation routes need.
--
-- WHY A NEW MIGRATION AND NOT A LINE IN 00012
--
-- 00012 is applied. Never edit an applied migration: a deployment that ran it
-- has a database that believes it matches the file, and an edit is then a
-- migration that silently does not run. This is also one concern per file, which
-- is what the migrations README asks for: 00012 is the audit trail, this is the
-- thing the audit trail records somebody doing.
--
-- WHY A COLUMN AND NOT A DELETE
--
-- The obvious implementation of "revoke an invitation" is DELETE FROM
-- account_invitations. The schema argues against it in 00007's own words:
-- "Deleting a user with pending invitations is therefore refused by the
-- database until they are revoked, which is a later packet." This is that
-- packet's schema half, and a DELETE would have left that RESTRICT in place
-- forever with no way to satisfy it.
--
-- It also argues against it on the question this service asks about every
-- credential: a deleted invitation cannot answer "was this revoked, or was it
-- always broken?" — which is the same support question api_keys.revoked_at and
-- oidc_clients.revoked_at are both there to answer. A revoked row is kept, the
-- token stops working, and the row says which happened.
--
-- THE PARTIAL INDEX BELOW IS THE POINT OF THE COLUMN
--
-- account_invitations_pending_idx is UNIQUE on (account_id, email) WHERE
-- accepted_at IS NULL. Widening that predicate to `accepted_at IS NULL AND
-- revoked_at IS NULL` is what lets an account re-invite an address it has just
-- revoked. Without the widening, revoking an invitation is a one-way door for
-- that address until the pending one is accepted or expires seven days later,
-- and "we sent it to the wrong list, revoke it and send it again" — the entire
-- reason this surface exists — would still be a seven-day wait.
--
-- The predicate is changed in the SAME migration that adds the column, because
-- the column does not exist without it: a new column with the old index would
-- make every revocation a unique violation, which is the failure mode that makes
-- a feature look broken rather than wrong.

-- +goose Up

ALTER TABLE account_invitations ADD COLUMN revoked_at timestamptz;

-- Nullable, and a NULL is "not revoked" rather than "revoked at the epoch": the
-- column is about the overwhelming majority of rows that have never been touched,
-- and a sentinel timestamp would make "never revoked" indistinguishable from
-- "revoked in 1970".
--
-- No CHECK pairs revoked_at with anything, and deliberately so. The obvious one
-- would be "not both accepted and revoked", and it would be WRONG to write here
-- rather than merely redundant: the two are set by different statements, and a
-- CHECK would turn a race between an acceptance and a revocation into a 500
-- instead of a lost update. The conditional UPDATE in
-- Store.RevokePendingInvitation already makes the two mutually exclusive by
-- requiring accepted_at IS NULL, and that is the one place it can be enforced
-- atomically.
--
-- A revoked_at BEFORE expires_at is allowed, and it is the normal case: the
-- whole point is to stop an invitation that is still live.

-- The pending-invitation uniqueness predicate, widened. See the file header: a
-- revocation must release the address for re-invitation or the admin surface
-- cannot do the one thing it exists for.
--
-- Recreated rather than altered because the old predicate is part of the index's
-- definition and DROP-then-CREATE is the only way to change it. The name is kept
-- so that 00007's Down, which drops it, still drops something.
DROP INDEX account_invitations_pending_idx;

CREATE UNIQUE INDEX account_invitations_pending_idx
	ON account_invitations (account_id, email)
	WHERE accepted_at IS NULL AND revoked_at IS NULL;

-- The admin surface's bulk query: "which of these ids are pending invitations of
-- this account". It is the account_id-leading prefix of a new index on
-- (account_id, id) — the revocation statements filter on id and scope on
-- account_id, and without this the planner reads a hint-bits scan of the account's
-- invitations to answer a question about fifty specific rows.
CREATE INDEX account_invitations_account_id_idx ON account_invitations (account_id, id);

-- +goose Down

DROP INDEX account_invitations_account_id_idx;

DROP INDEX account_invitations_pending_idx;
CREATE UNIQUE INDEX account_invitations_pending_idx
	ON account_invitations (account_id, email) WHERE accepted_at IS NULL;

ALTER TABLE account_invitations DROP COLUMN revoked_at;
