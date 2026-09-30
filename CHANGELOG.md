# Changelog

All notable changes to identity are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `internal/apikeys` — the scoped API token: the credential that is **not** a
  browser session, for a script, a CI job or another service. `cafaye_` plus 32
  bytes of `crypto/rand`; the row holds the SHA-256 of the presented value and
  nothing else.
  - **A token carries a scope set, not a role.** Its authority is re-read on every
    request against the owner's *current* membership, so a demotion or a removal
    takes effect on the very next request with no cache to expire and nothing to
    sweep. The store's resolution query inner-joins `account_users` and reads the
    role in the same statement — that join is the whole packet.
  - **A removed member's credentials are revoked, in the same transaction as the
    membership delete** — and this is the part that took two attempts. Re-evaluating
    the role is not enough on its own: the same user re-invited to the same
    account at the same role satisfies the join again, so a contractor's CI
    credential that died at offboarding quietly starts working the day somebody
    re-adds them. `TestARemovedMembershipStopsTheTokenOnTheNextRequest` in
    `internal/httpapi` is the test, and its *last* assertion is the one that failed
    first. `accounts.Service.RemoveMember` now calls
    `apikeys.Store.RevokeAllForMember`, through an interface declared in
    `accounts` — `apikeys` imports `accounts` for `accounts.Role`, so a direct
    import back would be a cycle. The sweep may be `nil`, and then a removal still
    removes: refusing to offboard anybody because a table that does not exist is
    unavailable is an availability bug dressed as a safety one.
  - **The capability set is published under BOTH claim names, and that is a
    deliberate interim, not the contract.** `POST /v1/introspections` emits
    `scopes` (core's name, `docs/openapi-conventions.md:134`) and `scope` (guard's
    name, `src/middleware/jwt.ts:32`), **byte for byte identical**, both
    space-separated strings. The fleet has not agreed and the question is open as
    **MD7** in the manager's `DECISIONS.md`; it has been recorded twice before and
    answered neither time. Emitting both is a deliberate interim **to avoid
    rotating credentials already in a customer's hand** — it is **not the
    contract**, and the flip is **a one-line removal** from
    `internal/apikeys/claims.go` once MD7 is ruled, with no credential reissued.
    Two names is not a contract; it is the cost of not rotating credentials over an
    unanswered question. `TestTheTwoScopeClaimNamesAreEqual` holds them together in
    a struct and `TestIntrospectionPublishesBothScopeClaimNames` holds them
    together on the wire, which is the only place a consumer sees them. The shape
    is a **string**, not an array: guard splits on whitespace and refuses a
    non-string claim, so an array is a token the gateway will not parse.
  - **`account_id` is required and nothing falls back to `sub`.** `sub` is the
    *user* a token names; `account_id` is the tenancy boundary and is always
    present, and a token with no account is answered `{"active": false}` rather
    than issued a subject to guess a tenancy key from. Falling back to `sub` — as
    guard's `limitKey` does today — would give a service-to-service token a user
    as its tenancy key, so a bug in one service that keys on `sub` becomes a
    cross-tenant read rather than a `403`. Whether guard's fallback is safe is
    **MD8** and is not decided here; what is decided is that identity never
    produces a token that needs it.
  - **The vocabulary is four names and every one is a capability an existing route
    already enforces**: `accounts:read`, `accounts:write`, `accounts:delete`,
    `oidc_clients:write`, in core's `resource:action` shape and read off this
    service's own route table rather than invented. There is deliberately **no**
    scope for the second factor, for sessions, for the api keys themselves, for
    the account *collection* routes, and none that means "everything" — and a
    route with no declared scope is **closed to tokens**, so a new account route
    added by a later packet is unreachable by a machine credential on the day it
    lands. `TestEveryAccountRouteDeclaresItsScope` and
    `TestEveryScopeIsEnforcedOnItsRoutes` walk the router in both directions, and
    `TestScopeEnforcementIsWiredToTheRoutes` makes real requests with a real token
    holding exactly one scope.
  - **Expiry is optional with a default and a ceiling: 90 days, 365 maximum, and
    `0` is a 422.** That is where "never expires" would have gone and it is not
    something this build offers. The cost is real and is stated: a CI credential
    has to be replaced every quarter, which is friction on precisely the use case
    that motivates the feature. What it buys is a moment at which a credential
    nobody is using gets noticed, and `last_used_at` — accurate to within five
    minutes, because a busy token must not be a write per request — is how that
    moment is acted on.
  - **The secret is shown once, and the test that proves it searches the database.**
    `TestTheSecretIsOnTheWireOnceAndNowhereElse` checks the wire, then renders the
    whole row, the whole table and every outbox envelope and searches them for the
    plaintext, for the plaintext without its prefix, and for its digest. The digest
    has to be *found*, or the test would pass on a table storing nothing.
  - **Every refusal is the same refusal**, and the timing answer is structural: the
    store never sees the presented value, `Digest` turns anything into a well-formed
    64-character hex string, and the lookup is an indexed equality on that. There is
    no length comparison on the path to branch on.
  - One live credential per name per account, enforced by a partial unique index —
    so "revoke ci-deploy" is never ambiguous and rotation is two requests rather
    than a transaction that has to find a name free first.
  - `identity.api_key.created` and `identity.api_key.revoked`, both core's catalog
    names, each written inside the transaction that changed the row. The subject is
    the credential's own id, and no payload carries a credential or a digest.

- `POST /v1/introspections` — what a presented token may do, and for which account.
  It exists because the token is **opaque**: no claims inside it, no published key
  set, so asking identity is the only way a resource server can learn a scope.
  RFC 7662's response shape, on a `/v1` path because core's rule puts every path
  in this document there. An unusable token answers `200 {"active": false}` and
  nothing else — unknown, revoked, expired and orphaned are indistinguishable, which
  is the point. The caller's own standing is a separate question with separate
  statuses: a token may introspect itself, a session may read a token in an account
  it owns.

- **A scoped token is refused with 403 on the surfaces it has no scope for** — the
  second factor, the session surface, the api-key surface, and the three account
  *collection* routes. 403 and not 401, because the token is authenticated and a 401
  would send a developer looking for a login problem. Three of these are changes to
  existing routes: `DELETE /v1/session` used to answer **204** to a token, because
  `Logout` treats an unknown token as a success so that logging out twice is not an
  error — nothing was revoked and the caller was told it had been. The MFA routes
  used to answer **401 "authentication is required"** to a live token, which is a
  lie.

- `internal/mfa` — the second factor: TOTP enrollment, the challenge a login waits
  on, recovery codes, and the lockout that stops somebody who has stolen a password
  from finishing the job with six digits of guessing. `github.com/pquerna/otp`
  v1.4.0 owns RFC 6238; this package owns the three decisions the specification
  does not make, which are which steps are candidates, how long a code is
  accepted, and whether a step has been spent.
  - **A correct password does not mint a session.** `POST /v1/session` answers
    `202 {mfa_required, challenge, expires_at}` for an account with a second
    factor and `200 {token, expires_at}` for one without. The 202 body has no
    `token` key at all — not an empty one — and `LoginResult.Token` is the empty
    string, so a caller that ignores `MFARequired` gets nothing rather than a
    working credential. `POST /v1/session/mfa` is the only route in this service
    that turns a second factor into a session, and it goes through
    `auth.Service.CompleteSecondFactor`, which mints the session inside the same
    transaction that consumes the challenge.
  - Enrollment is two steps and the first is not MFA. `POST /v1/mfa/enrollments`
    generates a secret with `crypto/rand` through the library, returns it once
    with its `otpauth://` URI, and stores it **unconfirmed**. A pending row
    authenticates nothing, the login path reads only confirmed rows, and it
    expires in ten minutes. Confirmation requires a code from that secret, and a
    confirm that arrives twice does not confirm twice or mint a second set of
    recovery codes.
  - **A code cannot be accepted twice, and the guard is a SET.** The obvious
    implementation — one "highest step accepted" bigint — refuses steps it cannot
    distinguish from spent-but-old ones, which is a user with a phone whose clock
    moved backwards being told their correct code is wrong. A primary key on
    `(credential_id, step)` plus `INSERT ... ON CONFLICT DO NOTHING` refuses a step
    that was spent and accepts one that was not, in any order, atomically without a
    lock, and is pruned to a handful of rows per credential by a `DELETE` in the
    same transaction. `TestClaimStepIsAtomicUnderConcurrency` puts fifty
    simultaneous claims on one step and requires exactly one winner.
  - **The skew window is one step either side**, so a code is live for ninety
    seconds rather than thirty. Zero would refuse a code typed near a step
    boundary, which is the user with the worst thumbs and the worst network — and a
    second factor with a visible failure rate gets turned off rather than retried.
    Two steps or more is ninety more seconds of a phished code's life and one more
    six-digit value to guess, and the window is the only thing that grows with skew.
    What one step does not buy is stated in `mfa.SkewSteps`: it tolerates thirty
    seconds of drift and no more, and a phone forty-five seconds fast waits fifteen
    seconds every period.
  - Recovery codes: ten, each 80 bits of `crypto/rand`, shown once and stored only
    as a SHA-256 digest. Eighty bits is a **floor**, not a round number — a
    six-digit code hashed with SHA-256 is walked in microseconds, which would make
    a database dump a set of credentials. Accepted in place of a TOTP code,
    single-use under concurrency, and the response says how many are left, which is
    the packet's "tell them before they get there".
  - **Adding a factor is authorized by a session; removing or replacing one
    requires a factor.** An enrollment makes the account harder to get into and
    there is nothing to prove beyond being signed in — a thief holding the session
    adds one and is locked out of the account they are in. Disabling, rotating the
    secret and regenerating the codes all take a TOTP code or a recovery code, and
    there is no route to any of them without one.
  - **Enabling MFA revokes every session**, including the caller's own. That answers
    the question of what happens to a session issued before MFA was: it stops
    working. A session minted under a one-factor policy was minted on a password
    alone, and leaving it alive means the attacker holding it does not have to
    solve the new problem. Disabling revokes every session too, because a user who
    turns MFA off has very often had it turned off *for* them.
  - Rotation keeps the old secret **live until the replacement is confirmed**, so
    an abandoned rotation costs the user nothing; on confirmation the old credential
    is deleted rather than superseded, because not having the secret is the only
    reliable way to stop its codes being accepted.
  - A login that is halfway through while the user enables, rotates or disables MFA
    on another device is handled by reading the credential **at verification time**
    rather than caching its id: disabling means no session, rotating means the old
    code is refused, and enabling means the pending row is still not a factor.
  - `identity.mfa.enabled` and `identity.mfa.disabled` — core's catalog names,
    three-segment, subject the user. Neither payload carries a secret, a digest of
    one, a code or an `otpauth://` URI, and `TestMFAEventPayloadsCarryNoCredential`
    asserts the absence of each plus the exact key set.
  - The OIDC login page has a second step. A correct password for an enrolled user
    renders a code form, mints no authorization code, and sets no session cookie.
  - `MFA_ENCRYPTION_KEY` seals the TOTP secret, and `MFA_ISSUER` names the account
    in an authenticator app. The key is read from the environment and **never
    generated**: a key generated at boot would mean every restart invalidates every
    enrolled user's secret, and a restart is not something anybody decides to do.

### Fixed

- The HTTP layer called `time.Now()` when resolving a credential, so the test suite
  could not age one out without sleeping and the expiry cases were silently testing
  nothing. It takes a clock from `options` now — the same seam every use case reads
  time through.

### Changed

- **`accounts.NewService` takes a `CredentialRevoker`.** It may be `nil`, and then a
  member removal changes only the membership — the supported configuration for a
  deployment with no api key table.
- `auth.NewService` takes a **required** `SecondFactor`. A login that cannot ask
  whether an account has a second factor now returns `ErrNoSecondFactor` instead
  of minting a session — that failure is silent by construction otherwise, since
  every login works and every login is one factor short.
- `POST /v1/session` may answer `202`. Clients that switch on the status code see
  the difference; clients that read `token` find no key on that response.
- `sessions.LockedError` moved to `internal/sessions`, next to the `Lockout` that
  produces it, with `auth.LockedError` kept as a type alias. The second factor's
  lockout is the same type, so the HTTP layer matches one error for both factors
  rather than two it has to know the origin of.
- `sessions.Store` gained `RevokeAllForUser`, one statement rather than a loop.
- `httpapi.WithMFA` mounts the management routes and **requires**
  `MFA_ENCRYPTION_KEY`. `POST /v1/session/mfa` is mounted with the auth surface and
  does not, because a deployment with a database and no key must still refuse a
  user who enrolled elsewhere rather than letting them in on their password.
- `CodeServiceUnavailable` (`service_unavailable`) is the one problem code this
  service adds to core's set, used only for "this deployment cannot verify a second
  factor". Flagged in `openapi/v1.yaml`.

### Not built

- No "trust this device" cookie, and no re-authentication grace period. A trusted
  device is a real feature and a real attack surface, and it belongs in its own
  packet with the trade-off written down.

- `internal/oidc` — `identity` as a first-class OpenID Connect **provider**, so
  any product signs users in against cafaye itself rather than configuring Google
  OAuth per product, and the JWT verification every other cafaye service already
  does against identity's JWKS becomes a standard, interoperable surface.
  `github.com/zitadel/oidc/v3` v3.51.10 owns the protocol; this package supplies
  the two things a library cannot have, which are a storage implementation over
  this service's own tables and a login UI bound to this service's own sessions.
  - Discovery at `/.well-known/openid-configuration`, and at
    `/.well-known/oauth-authorization-server` as well — RFC 8414 names a second
    path for the same metadata and the library registers only one, so identity
    mounts the alias itself.
  - Authorization Code with PKCE, `S256` only. `state` and `nonce` are the
    client's, echoed back untouched, and `nonce` is asserted in the ID token.
    `redirect_uri` is matched **exactly**: nothing in this service implements the
    library's glob client interface, so a registration can only ever be matched by
    equality.
  - The token endpoint issues **RS256** access tokens and ID tokens from the ONE
    configured signing key — the same key whose public half is published at
    `/.well-known/jwks.json` and which `guard` already verifies against. The
    `kid` in the document is the `kid` in every token header.
  - UserInfo returns `sub`, `email`, `email_verified`, `name` and the account and
    role claims from `account_users`, and nothing that is not already in the
    token. `email_verified` is present and always `false` — this service has no
    email-verification column, so there is nothing it could prove.
  - `clients` are account-scoped and managed through
    `/v1/accounts/{account_id}/oidc-clients` at **owner only**, reusing
    `RequireAccountRole`. `identity` has no platform-admin role yet and a rule it
    cannot express would be a rule with a bypass in it. The `client_secret` is
    returned once and stored only as a SHA-256 digest, the same construction and
    the same reasoning as `sessions.token_digest`.
  - Scopes are a closed set of four: `openid`, `email`, `profile`, `accounts`. An
    unknown one is a 400 naming it, because the library's own validator silently
    deletes a scope it does not recognise and a product would get a token with
    nothing in it and no indication anything was dropped.
  - A login page at `/oidc/login/{request_id}`, against this service's own
    sessions and cookie. A separate sign-in for OIDC would be a second credential
    store. It names the product asking, because a login page that cannot is the
    setup for a phishing page on this service's own domain, and its CSRF state is
    `internal/oauth`'s own `NewState`/`VerifyState`, reused unchanged.
  - `identity.oidc_client.created` and `identity.oidc_client.revoked`, in the same
    transaction as the write each describes — and the revocation transaction also
    bulk-revokes every access token issued against the registration, because a
    JWT is verifiable by anybody holding the published key set until its `exp` and
    revoking the registration is not by itself enough.
- `migrations/00009_oidc_clients.sql` — `oidc_clients`, `oidc_auth_requests` and
  `oidc_access_tokens`, with a `Down` that reverses all three. Four tables because
  they have four different lifetimes: a registration for years, an authorization
  request for one login, a code for sixty seconds, a token for fifteen. The
  single-use gate for a code is one conditional `UPDATE`, and eight goroutines
  racing one code produce exactly one winner.
- `openid/openid.yaml` — the provider's contract, as a SECOND document beside
  `openapi/v1.yaml`. Two documents because the two sets of paths cannot be
  reconciled: core puts every path under a single `/v1` prefix and RFC 8414 fixes
  discovery at `/.well-known/openid-configuration`. The error envelope differs for
  the same reason — an off-the-shelf OIDC client library cannot parse a problem
  document, and interop with one is the point of the surface.
- Four rows in the authorization matrix — the OIDC registrations, all
  owner-only — taking it to 15 endpoints × 6 caller columns, asserted explicitly.
  The non-member column is 404 on every one of them and never 403.

- `internal/users`, `internal/sessions`, `internal/auth` — the account and
  session substrate and the four use cases on top of it: `Register`, `Login`,
  `Authenticate`, `Logout`. Argon2id digests, per-account lockout on repeated
  failed sign-ins, and a `401` for every unusable credential alike so the login
  endpoint is not an account-enumeration oracle.
- `internal/outbox` — the event envelope, a transactional store, `SKIP LOCKED`
  claim and a publisher loop. `identity.user.created` is written in the same
  transaction as the user row, which is the reason the store methods take a
  `Querier` rather than the pool.
- `internal/httpapi` — the v1 surface: `POST /v1/users`, `POST /v1/session`,
  `DELETE /v1/session`, `GET /v1/me`. The session token travels in an
  `__Host-session` cookie *and* in the login body; a cookie is a browser
  mechanism and an API client cannot use one. Request bodies are capped at 4 KB
  and rejected at the reader, and unknown fields are refused rather than
  silently dropped.
- The core error envelope — every non-2xx is `application/problem+json` with
  core's `code` and `trace_id` extensions, including `404` and `405`, which
  previously carried a bespoke JSON body. Codes beyond core's reserved list
  (`account_locked` 423, `invalid_json` 400, `payload_too_large` 413) are this
  service's extension and are flagged for the manager.
- `internal/httpapi/trace.go` — a trace id on every request and every response.
  An inbound id is reused so a trace survives a hop through guard or a proxy;
  an unusable one is replaced rather than rejected.
- `internal/httpapi/recover.go` — a panic in a handler becomes a logged 500
  with a quotable trace id instead of a closed connection and a bare log line.
  `http.ErrAbortHandler` is re-panicked, and a response that is already
  committed is left alone rather than appended to.
- `migrations/00002`–`00004` — the `users`, `sessions` and `outbox_events`
  tables, each with a `Down`.
- `cmd/identity` wiring tests — the auth surface driven through the real
  handler `newApp` builds, with and without a database, and a case proving an
  unreachable database is a readiness failure rather than a startup failure.

### Changed

- `migrations/00008_connected_accounts.sql` — **renumbered from `00005`.** The
  identity-03 and identity-04 packets both claimed version 5, and goose refuses to
  collect two migrations with one version, so `goose up` panicked with "duplicate
  version 5 detected" and no integration test in this service could ever have run:
  `dbtest.Schema` clones from `public.*`, which was never created. The social table
  moves to 00008 because its only foreign key is `users` at 00002, so the move
  introduces no forward reference and 00005/00006/00007 keep the versions they
  were applied under anywhere.
- The OIDC surface is mounted only when all three `OIDC_*` variables AND
  `DATABASE_URL` are set. An issuer with no key can sign nothing and a key with no
  issuer has no `iss` to put in a token, and both would otherwise be discovered as
  a 500 by the first user to try to sign in. An unparseable key fails startup.
- `POST /v1/users` and `POST /v1/session` are mounted only when
  `DATABASE_URL` is set. Without it they are absent, so a missing database is
  a clear `404` rather than a pile of `500`s.
- `golang.org/x/oauth2` moves from `// indirect` to a direct requirement. It was
  already imported by `internal/oauth` from the identity-03 packet, so
  `go mod tidy` on clean HEAD still edits `go.mod` — which AGENTS.md says it must
  not. A second pre-existing tidy violation, fixed here because this packet runs
  tidy.
- Two more direct dependencies arrive with the OIDC provider. `zitadel/oidc` is
  the library the packet names. `go-jose/v4` is **forced rather than chosen**:
  `op.SigningKey` returns a `jose.SignatureAlgorithm` and `op.Key.Key()` holds a
  `jose` key, so the library's storage interface cannot be implemented without
  importing it. It brings 21 indirect modules with it. `go mod tidy` is idempotent
  and `go.sum` is committed.
- The access token's capability claim is spelled `scope`, not `scopes`. RFC 9068
  registers that name and `guard`'s verifier splits on exactly that string; core's
  prose says `scopes`. One line in `internal/oidc/storage.go` either way, and the
  divergence is recorded there.
- A third direct dependency, `alexedwards/argon2id`, arrives with the password
  hashing. It is the one case the standard library cannot cover — `x/crypto`
  ships the raw primitive but no encoded-digest format — and the cause is now
  stated in the README, as `AGENTS.md` requires. The scaffold had `chi` and
  `pgx` only.

### Notes

- `writeJSON` lives in `problem.go` beside `writeProblem`, not in the router
  file. The two are the pair core's "no service invents its own error body"
  rule describes, so a handler has exactly two writers and nowhere else to
  reach for a third.
- A `logout` with no credential presented is `401`, not `204`: a `204` would
  tell a client its request succeeded when nothing happened.
- `go test ./...` is still green with no database and no Docker. The Postgres
  integration tests skip unless `TEST_DATABASE_URL` is set.

## [0.1.0] - 2026-09-30

The v0 scaffold (packet identity-01). Structure before features: the shape every
later identity packet builds on, with no auth logic in it.

### Added

- `internal/config` — environment-driven configuration read once at startup and
  never mutated: `PORT` (default 8080, 1-65535), `DATABASE_URL` (optional in v0),
  `LOG_LEVEL` (default info, mapped to `log/slog`). A variable that is present but
  invalid fails startup with a wrapped sentinel rather than falling back to a
  default. Covered by table-driven tests for the defaults and the overrides.
- `internal/httpapi` — the chi router with `GET /healthz` → `200
  {"status":"ok"}` always, and `GET /readyz` → `200` when every dependency
  answers, `503 {"status":"unavailable",...}` otherwise, with each probe bounded
  at 2s. With no `DATABASE_URL` readiness reports `{"status":"ok","deps":"none"}`.
  Unknown routes and wrong methods answer JSON 404/405 rather than chi's plain
  text. Probe failures are logged by dependency name and never returned to the
  caller; a panicking dependency is a failed probe, not a dead process.
- `internal/platform/db` — a lazy pgx pool constructor that parses and sizes the
  pool without dialling, so a database that is down at startup surfaces as a
  failing readiness probe instead of a crash loop. `Ping` is wired to readiness
  only when `DATABASE_URL` is set.
- `cmd/identity` — a thin entrypoint: load config, build the app, serve, drain
  in-flight requests for up to 15s on SIGTERM, then close the pool. The socket,
  the drain and the signal handling live in an `app` type the tests drive
  directly, including a child-process test that sends a real SIGTERM and requires
  a clean exit.
- `migrations/` — the goose convention: `NNNNN_snake_case.sql`, annotations
  required, a `Down` (or a comment saying why not), one logical change per file,
  and a README covering dev and prod. `00001_init.sql` creates nothing.
- `Dockerfile` — two stages, `CGO_ENABLED=0`, `gcr.io/distroless/static-debian12:nonroot`.
  No compiler and no shell in the shipped image.
- `docker-compose.yml` — `postgres:17-alpine` plus the service, with the service
  gated on a `pg_isready` healthcheck so pgx never races Postgres in its init phase.
- `bin/prime` (the kit Go gate: `go mod download && go build ./... && go test
  ./...`), `mise.toml` pinning Go 1.26, and `.gitignore`.
- `cafaye.yml` as a clearly marked manifest draft, with guessed fields flagged
  `# GUESS` for reconciliation once core freezes the schema.
- `AGENTS.md` — the conventions this repository follows.

### Notes

- No auth logic, no JWT or OIDC code, no user tables. Those are later packets and
  none of it is stubbed to look finished.
- The only dependencies are `chi` (routing) and `pgx` (Postgres); reasoning in
  the README.
- `go test ./...` is green with no database and no Docker. The two Postgres
  integration tests skip unless `TEST_DATABASE_URL` is set.
