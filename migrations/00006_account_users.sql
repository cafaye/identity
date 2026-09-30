-- 00006_account_users.sql — the memberships.
--
-- One row per (account, user), carrying that user's role. This is the whole of
-- the authorization state: there is no separate admins table, no boolean on
-- accounts, and no per-permission grants. A role is one value from the enum
-- declared in 00005, and "may this user do this" is a comparison against a
-- minimum — see accounts.Role.AtLeast.
--
-- WHY AN ENUM AND NOT A BOOLEAN PAIR
--
-- jumpstart stores roles as a JSON object of booleans, so "owner but not admin"
-- is representable. Every check then has to decide what that combination means,
-- and there is no answer that is right in every case: is an owner who is not an
-- admin allowed to manage billing? Reassign a role? The enum makes the question
-- disappear — a membership is exactly one of three states, ordered.
--
-- WHY THE ENUM LIVES IN ITS OWN TYPE
--
-- It is shared with account_invitations, which is a *subset* (admin, member —
-- see 00007). One type with a CHECK would have to repeat "and not owner", and the
-- repetition is where a future migration adds owner to the wrong table.
--
-- The composite primary key IS the unique constraint the packet asks for. A
-- surrogate id plus a unique index would be the same guarantee with an extra
-- column, an extra sequence and a second thing to get wrong in a join.

-- +goose Up

CREATE TABLE account_users (
    account_id uuid          NOT NULL,
    user_id    uuid          NOT NULL,
    role       account_role  NOT NULL,
    created_at timestamptz   NOT NULL DEFAULT now(),
    updated_at timestamptz   NOT NULL DEFAULT now(),

    CONSTRAINT account_users_pkey PRIMARY KEY (account_id, user_id),

    -- CASCADE, not RESTRICT, on both sides.
    --
    -- Deleting an account deletes its memberships: that is what deleting the
    -- tenant means. Deleting a user deletes their memberships across every
    -- account, because a membership for a user who no longer exists is a row
    -- every query would have to filter out, and the alternative — leaving them —
    -- turns "list my accounts" into a join against a table that is supposed to
    -- be gone.
    CONSTRAINT account_users_account_id_fkey
        FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE,

    CONSTRAINT account_users_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- The authorization path is "everything this user is a member of" and "who is in
-- this account". The primary key covers the first as a prefix, so only the second
-- needs an index.
CREATE INDEX account_users_user_id_idx ON account_users (user_id);

-- Counting owners to enforce "an account keeps at least one owner" runs
-- `WHERE account_id = $1 AND role = 'owner'`. The primary key's leading column
-- narrows to one account; this index narrows to its owners, so the check stays a
-- near-constant number of rows however large the account is.
CREATE INDEX account_users_owners_idx ON account_users (account_id, role);

-- +goose Down

DROP TABLE account_users;
