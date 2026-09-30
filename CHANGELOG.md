# Changelog

All notable changes to identity are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
