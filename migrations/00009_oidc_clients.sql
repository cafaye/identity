-- 00009_oidc_clients.sql — the OIDC registrations, and the three tables the
-- authorization-code flow writes while it runs.
--
-- FOUR TABLES, because they have four different lifetimes. A registration lives
-- for years, an authorization request for the length of one login, an
-- authorization code for a minute, and an access token for fifteen. Collapsing
-- them into one row would mean either keeping codes for years or expiring
-- registrations after a minute, and both are wrong in a way that shows up in an
-- incident.
--
-- `oidc_clients` is the only one a human reads.

-- +goose Up

-- ---------------------------------------------------------------------------
-- oidc_clients: the registrations.
-- ---------------------------------------------------------------------------

CREATE TABLE oidc_clients (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- The account that owns the registration, and the account whose OWNER is the
    -- only caller who may create or revoke one. See the note on authorization
    -- below.
    account_id      uuid        NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,

    -- The public, protocol-visible handle: 32 random bytes, base64url. NOT NULL
    -- and UNIQUE because every token request looks one up by equality and a
    -- collision would hand one product another's tokens.
    client_id       text        NOT NULL,

    -- The product's name, as a person would recognise it: "Anytalk", "Courier".
    --
    -- It is here because the login page renders it, and a login page that cannot
    -- name the application asking for a password is the setup for every
    -- credential-phishing page ever hosted on an OIDC provider's own domain. The
    -- client_id cannot do this job: it is 43 characters of base64url chosen for
    -- entropy, so displaying it tells a user nothing they could recognise or
    -- check.
    name            text        NOT NULL,

    -- The lower-case hex SHA-256 of the client secret. Never the secret.
    --
    -- It is SHA-256 and not argon2id because the secret is 32 random bytes with
    -- no structure to guess: a memory-hard hash here would cost tens of
    -- milliseconds on every token request on the platform and buy nothing. The
    -- invariant is the one that holds on every credential column in this
    -- service — the presented value is never stored, so a dump of this table is
    -- not a set of credentials. Same reasoning, same column shape, as
    -- sessions.token_digest.
    secret_digest   text        NOT NULL,

    -- The allow-list. Matched EXACTLY, never by prefix and never by glob: the
    -- library offers a glob-matching client interface and nothing in this
    -- service implements it. See oidc.Client.AllowsRedirectURI.
    redirect_uris   text[]      NOT NULL,

    -- What this client may ask for. One value today (authorization_code); the
    -- column is an array so adding a grant is a validation change and not a
    -- migration, and so a consumer of the created event reads the registration
    -- as registered rather than as this version of the service understands it.
    grant_types     text[]      NOT NULL,
    scopes          text[]      NOT NULL,

    -- NULL until revoked. A revoked registration is KEPT rather than deleted: an
    -- audit of which credentials existed is worth more than a tidier table, and
    -- revoked_at is what makes the difference readable. A DELETE here would also
    -- lose the record of which redirect URIs a compromised product held.
    revoked_at      timestamptz,
    revoked_by      uuid        REFERENCES users (id) ON DELETE RESTRICT,
    revoke_reason   text,

    created_at      timestamptz NOT NULL DEFAULT now(),
    created_by      uuid        REFERENCES users (id) ON DELETE RESTRICT,

    CONSTRAINT oidc_clients_client_id_length
        CHECK (char_length(client_id) BETWEEN 32 AND 64),
    -- 120 is accounts.MaxNameLength, restated so the two cannot drift: a
    -- registration's name and an account's name are both "what a person would
    -- call this" and there is no reason for the limits to differ.
    CONSTRAINT oidc_clients_name_length
        CHECK (char_length(name) BETWEEN 1 AND 120),
    CONSTRAINT oidc_clients_secret_digest_length
        CHECK (char_length(secret_digest) = 64),
    CONSTRAINT oidc_clients_redirect_uris_present
        CHECK (cardinality(redirect_uris) BETWEEN 1 AND 10),
    CONSTRAINT oidc_clients_grant_types_present
        CHECK (cardinality(grant_types) >= 1),
    CONSTRAINT oidc_clients_scopes_present
        CHECK (cardinality(scopes) >= 1),
    -- Revocation is a single fact with a single actor. A row that is revoked with
    -- no `revoked_by` could not be attributed, and a row revoked twice is a
    -- second revocation of something already dead.
    CONSTRAINT oidc_clients_revocation_is_whole
        CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);

CREATE UNIQUE INDEX oidc_clients_client_id_key ON oidc_clients (client_id);

-- "Which products have registered themselves against this account?" — the list
-- endpoint, and the check a revocation has to make sure it is acting on a
-- registration this account owns.
CREATE INDEX oidc_clients_account_id_idx ON oidc_clients (account_id);

-- ---------------------------------------------------------------------------
-- oidc_auth_requests: one row per /oidc/authorize, from the moment the request
-- is validated to the moment its code is spent.
-- ---------------------------------------------------------------------------

CREATE TABLE oidc_auth_requests (
    id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- The client the request is for. ON DELETE CASCADE: revoking a registration
    -- has to make every authorization request against it worthless, and a
    -- dangling request that still completes would mint tokens for a client that
    -- no longer exists.
    client_row_id       uuid        NOT NULL REFERENCES oidc_clients (id) ON DELETE CASCADE,

    -- The protocol's own request, kept field by field rather than as a blob
    -- because three of them are checked again at the token endpoint
    -- (redirect_uri) or at redemption (code_challenge) and a blob would make
    -- those checks string surgery.
    redirect_uri        text        NOT NULL,
    state               text        NOT NULL,
    nonce               text        NOT NULL,
    response_type       text        NOT NULL,
    response_mode       text        NOT NULL,
    scopes              text[]      NOT NULL,
    code_challenge      text        NOT NULL,
    -- 'S256' or nothing else. The CHECK is the database's half of "PKCE with
    -- S256 is required": a row with 'plain' cannot be written, so the token
    -- endpoint's refusal is a defence in depth rather than the only thing
    -- standing between a captured code and a stolen token.
    code_challenge_method text      NOT NULL,
    login_hint          text        NOT NULL DEFAULT '',

    -- NULL until the login UI completes the request. An auth request with a
    -- subject is one the user has authenticated; the library refuses to build a
    -- response for one without.
    subject             uuid        REFERENCES users (id) ON DELETE CASCADE,
    auth_time           timestamptz,

    created_at          timestamptz NOT NULL DEFAULT now(),
    expires_at          timestamptz NOT NULL,

    -- The code, as a digest. NULL until /oidc/authorize/callback mints it.
    code_digest         text,
    code_expires_at     timestamptz,
    -- Set the moment the code is redeemed, by a conditional UPDATE. This column
    -- is what makes a code single-use even when two requests carrying it arrive
    -- at the same instant: see oidc.Store.ConsumeAuthCode.
    code_consumed_at    timestamptz,

    CONSTRAINT oidc_auth_requests_code_challenge_method_is_s256
        CHECK (code_challenge_method = 'S256'),
    -- A code is either absent or whole. A row with a digest and no expiry, or an
    -- expiry and no digest, is a state the token endpoint would have to guess at.
    CONSTRAINT oidc_auth_requests_code_is_whole
        CHECK ((code_digest IS NULL) = (code_expires_at IS NULL)),
    CONSTRAINT oidc_auth_requests_code_digest_length
        CHECK (code_digest IS NULL OR char_length(code_digest) = 64),
    -- Authenticating is what sets the subject, and the moment it happened is what
    -- the id_token's auth_time claim reports. Half a pair is a request whose
    -- auth_time is invented.
    CONSTRAINT oidc_auth_requests_subject_is_whole
        CHECK ((subject IS NULL) = (auth_time IS NULL))
);

-- AuthRequestByID is a primary-key read and needs no index. This one is for
-- AuthRequestByCode, which is an equality lookup on a digest that has no index
-- without it — and that lookup is on the hot path of every token request.
CREATE UNIQUE INDEX oidc_auth_requests_code_digest_key
    ON oidc_auth_requests (code_digest)
    WHERE code_digest IS NOT NULL;

-- Expired requests are deleted rather than left to accumulate. The index is what
-- makes "delete everything older than an hour" a bounded scan on a table that
-- otherwise grows by one row per login.
CREATE INDEX oidc_auth_requests_expires_at_idx ON oidc_auth_requests (expires_at);

-- ---------------------------------------------------------------------------
-- oidc_access_tokens: the `jti` of every JWT access token this service issued.
-- ---------------------------------------------------------------------------

CREATE TABLE oidc_access_tokens (
    -- The JWT's jti. It IS the identifier: the library mints the token from the
    -- row and hands this value back as the claim, and userinfo reads the claim to
    -- find the row. A surrogate key here would mean two ids for one token and a
    -- join to get from one to the other.
    id                  uuid        PRIMARY KEY,

    client_row_id       uuid        NOT NULL REFERENCES oidc_clients (id) ON DELETE CASCADE,
    subject             uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    scopes              text[]      NOT NULL,
    issued_at           timestamptz NOT NULL DEFAULT now(),
    expires_at          timestamptz NOT NULL,
    revoked_at          timestamptz,

    -- A token with no expiry is a permanent credential, and core's conventions
    -- cap access tokens at fifteen minutes. The CHECK makes the cap a property
    -- of the table rather than of the code path that happened to write the row.
    CONSTRAINT oidc_access_tokens_expiry_is_bounded
        CHECK (expires_at <= issued_at + interval '15 minutes')
);

-- userinfo reads one row by primary key, so this index is for the sweep that
-- removes expired tokens. Without it that sweep is a sequential scan of a table
-- that grows by one row per token request.
CREATE INDEX oidc_access_tokens_expires_at_idx ON oidc_access_tokens (expires_at);

-- +goose Down

-- oidc_access_tokens and oidc_auth_requests both reference oidc_clients, so the
-- clients table goes last.
DROP TABLE oidc_access_tokens;
DROP TABLE oidc_auth_requests;
DROP TABLE oidc_clients;

-- ---------------------------------------------------------------------------
-- A note on the authorization rule this table encodes, because it is a decision
-- and not an obvious consequence of the columns.
--
-- A registration belongs to an ACCOUNT, and the only caller who may create or
-- revoke one is that account's OWNER. A member may not: adding a client is
-- adding a new way for code to arrive in this product and get a token back out,
-- and "can read the member list" is not authority to widen the perimeter.
--
-- The alternative was a platform-admin role, and there isn't one. identity's
-- roadmap puts the admin API after the scoped API tokens, and a rule this
-- service cannot yet express would have been a rule with a bypass in it. The
-- owner role is the one privilege this service already has that means "may
-- change what can enter this account", and reusing it keeps the authorization
-- decision in RequireAccountRole where every other one already is.
--
-- The consequence to be honest about: a PRODUCT cannot register itself without
-- an account owner doing it. A service-to-service credential lands with the
-- scoped API tokens packet. See README.md, "Not built yet".
-- ---------------------------------------------------------------------------
