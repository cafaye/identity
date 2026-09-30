# identity

`identity` is the cafaye service that knows who someone is: auth, sessions,
MFA, OAuth, accounts and tenancy, and OIDC. Every other cafaye service — billing,
courier, guard, parlor — asks this one who is calling and what they may do. It
is the platform's security boundary, and the reason `PLAN.md` §3 singles it out
for a user-run security review before the phase closes.

**v0 is a skeleton.** There is no auth logic here yet, on purpose: the
scaffolding *is* this packet's deliverable. What exists is the shape every later
packet builds on — configuration, liveness and readiness, a Postgres pool, the
migration convention, and an image. What it does today:

```
$ curl -s localhost:8080/healthz
{"status":"ok"}

$ curl -s localhost:8080/readyz
{"status":"ok","deps":"none"}
```

## Why chi

Chi over echo: same five routing features, a fraction of the dependencies, and
`net/http` is the type it serves, so a handler is a plain
`func(http.ResponseWriter, *http.Request)` with no framework types in the
signature. It is a router, not a framework — nothing in `internal/` needs to
know chi exists to be tested.

## Dependencies

Four direct dependencies, each with a cause:

- `chi` — routing, above.
- `pgx` — Postgres. The pool and the `SKIP LOCKED` claim in the outbox.
- `alexedwards/argon2id` — password hashing. Go's standard library has no
  password KDF and `x/crypto` ships only the raw primitive with no encoded-digest
  format or parameter handling, so this is the one case where the standard
  library genuinely cannot do the job. It is not a framework, it has no
  transitive dependencies of its own, and reimplementing argon2id in `internal/`
  would be far more dangerous than depending on it. It arrives with the auth
  packet; the scaffold had only the first two.
- `zitadel/oidc` — the OpenID Connect **provider**. The protocol is not
  reimplemented here: the library owns the OAuth 2.0 and OIDC state machines, and
  `internal/oidc` supplies the two things a library cannot have, which are a
  storage implementation over this service's own tables and a login UI bound to
  this service's own sessions. `refs/oidc` (v3.51.10) is the library, read for
  its examples.
- `go-jose/v4` — **forced, not chosen.** `op.SigningKey` returns a
  `jose.SignatureAlgorithm` and `op.Key.Key()` holds a `jose` key, so the
  library's storage interface cannot be implemented without importing it. It
  arrives with 21 other indirect modules (`rs/cors`, `zitadel/schema`,
  `bmatcuk/doublestar`, `otel`, `gorilla/securecookie` and their closures).
  `go mod tidy` is idempotent and `go.sum` is committed.

## Running it

Nothing but Go is needed, and no database is required — v0 supports an unset
`DATABASE_URL`:

```sh
mise install          # or use any Go >= 1.25
go run ./cmd/identity # http://localhost:8080
```

Or the gate, which is what CI runs:

```sh
bin/prime   # go mod download && go build ./... && go test ./...
```

With the database:

```sh
docker compose up -d
curl -s localhost:8080/readyz    # {"status":"ok","deps":"postgres"}
```

## Configuration

Read from the environment at startup, validated, and never mutated afterwards.
A value that is present but invalid fails startup rather than falling back to a
default, so a typo in a deployment is a crash with a message instead of a
service quietly listening on the wrong port.

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8080` | TCP port to bind. Must be 1-65535. |
| `DATABASE_URL` | *(unset)* | Postgres DSN. Optional in v0; unset means no pool and no readiness dependency. |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. Drives `log/slog`. |
| `OIDC_ISSUER` | *(unset)* | The OpenID Connect issuer. All three OIDC variables are required together or not at all. |
| `OIDC_SIGNING_KEY` | *(unset)* | PEM-encoded RSA private key, ≥ 2048 bits. PKCS#1 and PKCS#8 both load. |
| `OIDC_SIGNING_KEY_ID` | *(unset)* | The `kid` published in the JWKS and signed into every token. 1-64 characters of `A-Z a-z 0-9 . _ -`. |
| `OIDC_ALLOW_INSECURE` | `false` | Permits an `http` issuer. For `localhost` and compose stacks only. |

## Endpoints

| Route | Response | Meaning |
|---|---|---|
| `GET /healthz` | `200 {"status":"ok"}` | Liveness. Always 200 while the process serves — it never touches a dependency, so a database outage cannot get the process restarted out from under in-flight work. |
| `GET /readyz` | `200 {"status":"ok","deps":"postgres"}` | Readiness. 200 when every dependency answers, `503 {"status":"unavailable",...}` otherwise, with each probe bounded at 2s. |
| `POST /v1/users` | `201 {"id","email"}` | Register. `409 conflict` if the address is taken, `422 validation_failed` with `errors[]` on a bad field, `400 invalid_json` on a malformed body, `413 payload_too_large` past 4 KB. |
| `POST /v1/session` | `200 {"token","expires_at"}` | Log in. Sets the `__Host-session` cookie to the same token. `401 unauthorized` for any unusable credential, `423 account_locked` with `Retry-After` while locked. |
| `DELETE /v1/session` | `204` | Revoke the current session and clear the cookie. `401` if no credential was presented. |
| `GET /v1/me` | `200 {"id","email"}` | The authenticated user. `401` with no usable credential. |
| `POST /v1/accounts/:id/oidc-clients` | `201 {id, client_id, client_secret, …}` | Register a relying party. **Owner only.** `client_secret` is returned here and never again. |
| `GET /v1/accounts/:id/oidc-clients` | `200 [{id, client_id, name, …}]` | The account's registrations, newest first. `[]` and not `null`. **Owner only.** |
| `GET /v1/accounts/:id/oidc-clients/:clientId` | `200 {id, client_id, …}` | One registration. `clientId` is the row id, not the `client_id` the product presents. **Owner only.** |
| `DELETE /v1/accounts/:id/oidc-clients/:clientId` | `204` | Revoke a registration, and every access token issued against it, in one transaction. `409 conflict` if already revoked. **Owner only.** |
| anything else on `/v1` | `404 not_found` | A problem document, not chi's default plain text. |

Every non-2xx is `application/problem+json` per core's error envelope, including
`404` and `405`. The `trace_id` in the body always matches the `X-Trace-Id`
response header, and internal failures are logged with that id rather than
described to the caller.

The `/v1` routes exist only when `DATABASE_URL` is set. Without it they are
absent, so a missing database is a clear `404` rather than a pile of `500`s.

With no `DATABASE_URL`, readiness is `200 {"status":"ok","deps":"none"}` — there
is nothing to check, and saying so is more useful to an operator than an empty
list or a 200 that looks identical to a healthy probe.

Probe failures are logged with the underlying error and **never** returned to the
caller: an unauthenticated request to `/readyz` must not be a way to learn that
a database host is `10.0.0.5` or that a password was rejected.

### The OpenID Connect provider

`identity` is a first-class OIDC **provider**, so any product signs users in
against cafaye itself rather than configuring Google OAuth per product — and the
JWT verification every other cafaye service already does against identity's JWKS
becomes a standard, interoperable surface.

These routes exist only when the three `OIDC_*` variables above are all set AND
`DATABASE_URL` is set. Without them they are absent, so the failure is a clear
`404` rather than a pile of `500`s.

| Route | Response | Meaning |
|---|---|---|
| `GET /.well-known/openid-configuration` | `200` | OpenID Connect Discovery. |
| `GET /.well-known/oauth-authorization-server` | `200` | RFC 8414. The same document; the library does not register it, identity does. |
| `GET /.well-known/jwks.json` | `200 {"keys":[…]}` | RFC 7517. One key, `use: sig`, `alg: RS256`. Public half only. |
| `GET,POST /oidc/authorize` | `302` | The authorization endpoint. Requires PKCE with `S256`. `redirect_uri` matched **exactly**. |
| `GET /oidc/authorize/callback` | `302` | The login page's return leg. Mints the code. |
| `GET,POST /oidc/login/:requestId` | `200` / `302` | The sign-in page. This service's own sessions and cookie. |
| `POST /oidc/token` | `200 {access_token, id_token, …}` | `grant_type=authorization_code` and nothing else. HTTP Basic client auth. |
| `GET,POST /oidc/userinfo` | `200 {sub, email, …}` | The claims the token was granted, and only those. |
| `GET /oidc/introspect`, `/oidc/revoke`, `/oidc/end-session`, `/oidc/device_authorization` | `404 not_found` | Not built. Absent from the discovery document too. |

**TWO ERROR SHAPES, AND THE SPLIT IS DELIBERATE.** `/v1/*` and the
`/oidc/authorize` pre-checks answer `application/problem+json`; everything else
under `/oidc/*` answers RFC 6749's `{"error": …}`. An off-the-shelf OIDC client
library cannot parse a problem document, and interop with one is the entire
point of the surface. The two documents that describe the two — `openapi/v1.yaml`
and `openid/openid.yaml` — exist for the same reason.

The claims:

- `sub` — the user. The same for every client.
- `email`, `email_verified` — on the `email` scope. **`email_verified` is always
  `false`**: this service has no email-verification column yet, so there is
  nothing it could prove, and `true` would be a claim about something nobody has
  checked. It is present and false rather than absent, because a relying party
  that cannot see the field has to assume it is verified.
- `name` — on the `profile` scope. The personal account's name, derived from the
  email's local part. A stand-in, not a user-chosen name.
- `accounts` — on the `accounts` scope. An **array** of `{account_id, name, slug,
  role, personal}`. An array and not a single `account_id` because a user of a
  cafaye product is in a personal account and usually several team accounts, and a
  token carrying one of them would be wrong for the others. core's conventions ask
  for `account_id`; this is the multi-account form of that fact.
- `scope` — the capability scopes, space-delimited. `email` and `profile` are
  userinfo scopes and live in the ID token and at userinfo instead; an address is
  not a capability.

Two decisions the manager may want to rule on, both recorded in the code:

- The `scope` claim is spelled `scope`, not `scopes`. RFC 9068 registers that
  name and `guard`'s verifier splits on exactly that string; core's prose says
  `scopes`. One line in `internal/oidc/storage.go` either way.
- An unknown scope at `/oidc/authorize` is **400** with a problem envelope, as
  the packet specifies. core scopes 400 to "malformed syntax the client could not
  have known" and 422 to "semantically wrong", so this is a deliberate departure
  and it is listed under "Known gaps" in `openid/openid.yaml`.

## Layout

```
cmd/identity/main.go   thin entrypoint: load config, build the app, serve, drain on SIGTERM
internal/config/       environment in, validated Config out
internal/httpapi/      the router, the probes, and the v1 auth surface
internal/auth/         register, login, resolve — the use cases and their ordering
internal/users/        accounts and the email-uniqueness rules
internal/sessions/     session tokens, hashing and revocation
internal/oidc/         the OIDC provider: storage adapter, registrations, the key
internal/accounts/     the tenancy use cases: accounts, memberships, invitations
internal/oauth/        the social-login client side: state, token cipher, registry
internal/outbox/       transactional event envelope, SKIP LOCKED claim, publisher
internal/platform/db/  the pgx pool, and the readiness ping
migrations/            goose SQL files
```

`cmd/` + `internal/` is the layout from `refs/goreleaser`. `main` owns nothing
but process lifetime: everything testable lives in `internal/`, and the pieces
`main` does own — the socket, the drain, the signal handling — are in an `app`
type that the tests drive directly.

## Testing

`go test ./...` passes on a machine with no database and no Docker. The
integration tests skip themselves unless `TEST_DATABASE_URL` is set:

```sh
docker compose up -d postgres
TEST_DATABASE_URL="postgres://identity:identity@localhost:5432/identity?sslmode=disable" go test ./...
```

SIGTERM handling is not asserted through a mock: `TestMainHandlesSIGTERM` runs
the real `main()` in a child process, waits for it to report that it is serving,
sends the signal, and requires a clean exit. There are no `time.Sleep` calls in
this repository — every wait is on a channel the code under test signals, or on
a failure deadline (PLAN.md §3).

## Migrations

goose SQL files in `migrations/`, numbered and annotated. `goose` is a CLI
tool, not a module dependency. `00001_init.sql` establishes the convention and
`00002`–`00004` create `users`, `sessions` and `outbox_events`. Migrations are a
deploy step, not a boot step — see [migrations/README.md](migrations/README.md).

## Image

Multi-stage, `CGO_ENABLED=0`, `gcr.io/distroless/static-debian12:nonroot`. No
compiler and no shell in the shipped image:

```sh
docker build -t identity .
docker run --rm -p 8080:8080 identity
```

## Not built yet

Everything below is a later packet, and none of it is stubbed to look finished:
email verification, password reset, MFA, scoped API tokens, the admin API, and
key rotation. No self-service password recovery — a user who forgets a password
today has no path back in.

Inside the OIDC provider, specifically not built: refresh tokens (access tokens
live fifteen minutes and cannot be renewed), the implicit flow, client
credentials, the JWT profile grant, `private_key_jwt` client authentication,
dynamic client registration, token introspection, the revocation endpoint,
end-session, the device flow, and a consent screen. Each one is a refusal at the
point a client would reach for it, and each is absent from the discovery
document, rather than a stub that looks finished.

**A product cannot register itself.** Client management is owner-gated on an
account, reusing `RequireAccountRole`, because `identity` has no platform-admin
role yet — the admin API is a later packet, and a rule this service cannot
express would be a rule with a bypass in it. A service-to-service credential for
a product arrives with the scoped API tokens packet.

## Roadmap

- [x] Skeleton: config, `/healthz`, `/readyz`, pgx pool, graceful shutdown
- [x] Migration convention, image, compose stack
- [x] Password auth, sessions, lockout
- [x] Error envelope, trace ids, panic recovery
- [x] Outbox: transactional events, SKIP LOCKED claim, publisher loop
- [ ] Email verification, password reset
- [x] OAuth (social login) via goth
- [x] Accounts, memberships, roles, invitations
- [x] OIDC provider (zitadel/oidc)
- [ ] MFA: TOTP + recovery codes
- [ ] Scoped API tokens
- [ ] Admin API
- [x] Authorization matrix suite (route table × role × anonymous)

See [AGENTS.md](AGENTS.md) for the conventions this repository follows and
[CHANGELOG.md](CHANGELOG.md) for what has landed.
