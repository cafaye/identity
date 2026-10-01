# identity

`identity` is the cafaye service that knows who someone is: auth, sessions,
MFA, accounts and tenancy, and OIDC. Every other cafaye service — billing,
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

The scoped API token packet added **none**, which is the point worth stating: a
credential that is a random value in a column, hashed with `crypto/sha256` and
looked up by an indexed equality, needs nothing from outside the standard library.
There is no signing key to load, no key to rotate and no trust anchor to publish —
which is one of the reasons this credential is a row lookup rather than a JWT, and
one of the reasons it has no cost at boot.

Direct dependencies, each with a cause:

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
- `github.com/pquerna/otp` — TOTP, RFC 6238. The algorithm is the specification, and a
  private implementation of a specification is a vulnerability with tests: this
  library owns the base32 of the shared secret, the HMAC, the dynamic truncation,
  the six-digit zero-padding and the constant-time comparison, and `internal/mfa`
  never computes any of them. What `internal/mfa` owns is the three decisions the
  specification does not make: which steps are candidates (the library's own
  windowed `ValidateCustom` returns a bool and the replay guard needs to know which
  step matched), how long a code is accepted, and whether a step has been spent.
  It brings `github.com/boombuler/barcode` indirectly, for a QR-code method this
  service does not call. Arrives with the MFA packet.
- `github.com/oapi-codegen/runtime` — **for the generated client only, and this is
  the one that corrects MD6.** MD6 said the Go client "reaches `identity`'s existing
  stack with no new dependency at runtime", on the grounds that oapi-codegen is a
  `go:generate` tool rather than a library a user imports. **The GENERATOR is right
  and is not a dependency**: the `//go:generate` line is pinned to `v2.8.0` and
  `go run <module>@<version>` resolves in module-aware mode, so oapi-codegen never
  appears in `go.mod` at all. **The code it EMITS is a dependency**, and it imports
  this module for parameter binding and for its `UUID` and `Email` types. That brings
  two more (`apapsch/go-jsonmerge/v2` and `google/uuid`), so three in total.

  **None of the three reaches the service's binary.** `client/` is not imported by
  `./cmd/identity` and never should be: a service that called its own API over HTTP
  would add a network hop to itself and depend on a client to do what its own stores
  already do. `go list -deps ./cmd/identity | grep oapi-codegen` is empty, and
  `TestTheServiceBinaryDoesNotReachTheGeneratedClient` holds that as a check rather
  than a claim. The full reasoning, including what it costs the coverage floor, is
  [DECISIONS.md](DECISIONS.md) D6 — and what it costs is answered there now: the
  generated client is **excluded from the coverage measurement** by a declared path,
  with the floor left where it was. See "The coverage floor, and what it is a
  percentage of" below.

- `go-jose/v4` — **forced, not chosen.** `op.SigningKey` returns a
  `jose.SignatureAlgorithm` and `op.Key.Key()` holds a `jose` key, so the
  library's storage interface cannot be implemented without importing it. It
  arrives with 21 other indirect modules (`rs/cors`, `zitadel/schema`,
  `bmatcuk/doublestar`, `otel`, `gorilla/securecookie` and their closures).
  `go mod tidy` is idempotent and `go.sum` is committed.

Two more, and both are the floor rather than a choice among alternatives:

- `go.opentelemetry.io/otel/sdk` and
  `go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp` (v1.46.0) —
  identity emits OpenTelemetry spans into the collector that ships with kit's
  stack, so "where did that 500 come from" is a question with an answer rather
  than a log tail. Without these two, identity cannot emit a span at all.
  **grpc, the protobuf runtime and grpc-gateway arrive transitively**, through
  `otlpconfig`; that is a cost of the OTLP exporter's own configuration path, not
  a second transport this service asked for.
  - **Deliberately not `go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp`.**
    Its handler records `url.path`, `url.query` and request headers as its own
    span attributes. Those are exactly the values a redacting collector strips,
    and stripping them downstream is one control; `internal/httpapi/telemetry.go`
    is hand-rolled so that what identity records is *only* what
    `internal/telemetry`'s allowlist permits. Two controls beat one, and the
    second one is the one this repository tests.
  - **Deliberately not `otel/sdk/metric`.** Metrics come from kit's collector's
    `spanmetrics` connector, which derives them from spans *after* redaction — so
    a derived metric can never carry a dimension the allowlist stripped, and
    there is no second definition of the same series anywhere in the fleet.
  - **Deliberately not `otel/log`.** Logs are the container's stdout: compose's
    `logging:` driver ships them to the collector's `syslog/crash` receiver, which
    makes a panic a log record with a `service.name` on it and adds no
    per-language dependency to this module.

## Running it

Nothing but Go is needed, and no database is required — v0 supports an unset
`DATABASE_URL`:

```sh
mise install          # or use any Go >= 1.26
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
| `MFA_ENCRYPTION_KEY` | *(unset)* | base64url, **exactly 32 bytes**. Seals the TOTP secret at rest. Never generated. Unset means MFA is not turned on: the management routes are absent and the login challenge is still enforced. A value of the wrong length is a startup failure. |
| `MFA_ISSUER` | `cafaye identity` | The account label an authenticator app displays. A display string, not a secret; changing it does not affect any confirmed credential. |
| `IDENTITY_OTEL_ENDPOINT` | `http://otel-collector:4318` | The OTLP endpoint spans go to. **The only contract** (core D16), and the collector that ships with kit's stack is just its default value — so tracing is on by default and a deployer who already runs Datadog or Grafana sets one variable and kit's stack goes quiet. Unset costs spans and nothing else: no queue, no retry loop, no dial at boot. |
| `IDENTITY_TENANT_ID` | *(unset)* | The `tenant_id` **resource** attribute. Never a span attribute — see the allowlist rule in [AGENTS.md](AGENTS.md). Unset by default, because an empty one shows up as a second service row in every collector's service list. |
| `DEPLOYMENT_ENVIRONMENT` | *(unset)* | The `deployment.environment` resource attribute. An enum in core's resource schema (`development`/`test`/`staging`/`production`), so there is no fourth spelling to invent. |
| `OTEL_SERVICE_VERSION` | *(detected)* | The `service.version` resource attribute. Absent is treated as "unknown" rather than defaulted to a string, because a configured-but-empty version renders as a second service row in a collector's service list. |

## Endpoints

| Route | Response | Meaning |
|---|---|---|
| `POST /v1/accounts` | `201 {…}` | Create an account. **Not in `openapi/v1.yaml` — see the gap below.** |
| `GET /v1/accounts` | `200 [{…}]` | The accounts this **user** belongs to. **Not in `openapi/v1.yaml` — see the gap below.** |
| `GET /v1/accounts/:id` | `200 {…}` | One account. **Not in `openapi/v1.yaml` — see the gap below.** |
| `PATCH /v1/accounts/:id` | `200 {…}` | Rename. **Not in `openapi/v1.yaml` — see the gap below.** |
| `DELETE /v1/accounts/:id` | `204` | Delete, with everything under it. **Not in `openapi/v1.yaml` — see the gap below.** |
| `GET /v1/accounts/:id/members` | `200 [{…}]` | The account's members. **Not in `openapi/v1.yaml` — see the gap below.** |
| `POST /v1/accounts/:id/invitations` | `201 {…}` | Invite somebody. **Not in `openapi/v1.yaml` — see the gap below.** |
| `PATCH /v1/accounts/:id/members/:userId` | `200 {…}` | Change a role. **Not in `openapi/v1.yaml` — see the gap below.** |
| `DELETE /v1/accounts/:id/members/:userId` | `204` | Remove somebody. **Not in `openapi/v1.yaml` — see the gap below.** |
| `POST /v1/invitations/accept` | `200 {…}` | Accept an invitation, signed in as the invited user. **Not in `openapi/v1.yaml` — see the gap below.** |
| `GET /healthz` | `200 {"status":"ok"}` | Liveness. Always 200 while the process serves — it never touches a dependency, so a database outage cannot get the process restarted out from under in-flight work. |
| `GET /readyz` | `200 {"status":"ok","deps":"postgres"}` | Readiness. 200 when every dependency answers, `503 {"status":"unavailable",...}` otherwise, with each probe bounded at 2s. |
| `POST /v1/users` | `201 {"id","email"}` | Register. `409 conflict` if the address is taken, `422 validation_failed` with `errors[]` on a bad field, `400 invalid_json` on a malformed body, `413 payload_too_large` past 4 KB. |
| `POST /v1/session` | `200 {"token","expires_at"}` | Log in. Sets the `__Host-session` cookie to the same token. `401 unauthorized` for any unusable credential, `423 account_locked` with `Retry-After` while locked. |
| `POST /v1/session/mfa` | `200 {"token","expires_at"}` | Answer a second factor and **only then** get the session. `{challenge?, code}` — the challenge from a `202`, and a TOTP code or a recovery code. | |
| `DELETE /v1/session` | `204` | Revoke the current session and clear the cookie. `401` if no credential was presented. |
| `GET /v1/me` | `200 {"id","email"}` | The authenticated user. `401` with no usable credential. |
| `POST /v1/accounts/:id/oidc-clients` | `201 {id, client_id, client_secret, …}` | Register a relying party. **Owner only.** `client_secret` is returned here and never again. |
| `GET /v1/accounts/:id/oidc-clients` | `200 [{id, client_id, name, …}]` | The account's registrations, newest first. `[]` and not `null`. **Owner only.** |
| `GET /v1/accounts/:id/oidc-clients/:clientId` | `200 {id, client_id, …}` | One registration. `clientId` is the row id, not the `client_id` the product presents. **Owner only.** |
| `DELETE /v1/accounts/:id/oidc-clients/:clientId` | `204` | Revoke a registration, and every access token issued against it, in one transaction. `409 conflict` if already revoked. **Owner only.** |
| `GET /v1/mfa` | `200 {"enabled", …}` | Whether the caller has a second factor, when they enrolled, and how many recovery codes are left. `200` with `{"enabled":false}` when they have none — not a 404. |
| `POST /v1/mfa/enrollments` | `201 {"enrollment_id","secret","provisioning_uri",…}` | Generate a TOTP secret and store it **unconfirmed**. `secret` and `provisioning_uri` are returned here and never again. `{code}` is required to **replace** an existing factor. |
| `POST /v1/mfa/enrollments/:id/confirm` | `200 {"enabled","recovery_codes",…}` | Prove you can produce a code, which makes MFA live and **revokes every session the user holds**. `recovery_codes` is returned here and never again. |
| `POST /v1/mfa/recovery-codes` | `200 {"recovery_codes",…}` | Issue a new set and destroy the old one, in one transaction. Requires a factor. |
| `DELETE /v1/mfa` | `204` | Turn MFA off. Requires a factor, and revokes every session. `409 conflict` if MFA is not on. |
| `POST /v1/accounts/:id/api-keys` | `201 {id, name, scopes, …, token}` | Mint a scoped API token. **Owner only.** `token` is returned here and never again. `409 conflict` if this account already has a live key of that name. |
| `GET /v1/accounts/:id/api-keys` | `200 [{id, name, scopes, …}]` | The account's credentials, newest first, **revoked ones included**. `[]` and not `null`. **Owner only.** |
| `DELETE /v1/accounts/:id/api-keys/:keyId` | `204` | Revoke a credential. The row is kept. `409 conflict` if already revoked, `404` for an id that is not there or not in this account. **Owner only.** |
| `POST /v1/introspections` | `200 {active, …}` or `200 {"active":false}` | What a presented token may do, and for which account. Needed because the token is opaque. |
| `GET /v1/accounts/:id/admin/audit-log` | `200 {entries, next?}` | The account's admin audit trail, newest first, **append-only**. Bounded: `limit` defaults to 25 and is refused above 100; `before` is an opaque cursor. **Admin, `audit_log:read`, scoped api key only.** |
| `DELETE /v1/accounts/:id/admin/invitations/:invitationId` | `204` | Revoke one pending invitation. The row is kept with `revoked_at`, and the address is freed to be invited again. `409 conflict` if already accepted or revoked, `404` for an id not in this account. **Admin, `account_invitations:write`, scoped api key only.** |
| `POST /v1/accounts/:id/admin/invitation-revocations` | `200 {requested, revoked}` | Revoke up to 50 pending invitations in one transaction, **one** audit record for the lot. `confirm: true` and a non-empty array are both required. **Owner, `account_invitations:write`, scoped api key only.** |
| `POST /v1/password-resets` | `202 {"status":"accepted"}` | Mail a single-use link, valid 30 minutes. **The same body for every address** — registered, unregistered, or inside the one-minute cooldown — so it cannot be used to discover who has an account. `503` when the deployment cannot send mail. |
| `POST /v1/password-resets/confirm` | `204` | Set the new password and **revoke every session and every live access token**, in one transaction. Mints no session; sign in again. `404` for anything that is not a live token — never existed, expired, spent, or another flow's. |
| `POST /v1/email-verifications` | `202 {"status":"accepted"}` | Mail a link proving the address **already on the account**. Registration does not send one. `409 conflict` once the address is already verified. |
| `POST /v1/email-verifications/confirm` | `204` | Mark the address proved. **Revokes nothing and mints nothing** — a verification is a fact about an address, not a credential. |
| `GET /v1/email-verification` | `200 {email, email_verified, email_verified_at?}` | Whether the caller's own address is proved. `email_verified_at` is **absent** when it was never proved, which is a different state from a proved address that has since been changed. |
| `POST /v1/email-changes` | `201 {current_email, new_email, expires_at}` | Start a move. A link goes to the address the account has **now**; nothing moves until two addresses have each confirmed. `409 conflict` if the new address is taken, `422 already_current` if it is the one already there. |
| `POST /v1/email-changes/current-address` | `202 {"status":"accepted"}` | Prove the current address; a second link is then minted for the **new** one. The body deliberately does not say where it went. |
| `POST /v1/email-changes/new-address` | `200 {…, email_verified:false}` | Complete the move: the address changes, the verification is **cleared**, and every session and access token is revoked. `email_verified` is false on purpose — reading an inbox is not proof the address is yours. |
| anything else on `/v1` | `404 not_found` | A problem document, not chi's default plain text. |

**Every route in that block refuses a scoped API token with 403**, and two of them
require a session. A credential that could start an email change could move an
account's recovery path, and a credential that could mint a password reset is a
takeover with a delay rather than a break-in — so there is no scope in the machine
vocabulary for any of it, and there is not going to be one. The four redemption
routes are anonymous, because the token in the body **is** the credential.

### Recovery: one token machine, three flows

Password reset, address verification and address change are three features and one
lifecycle: mint 256 bits, store only their SHA-256, mail them, expire them, and
spend them with a conditional write that makes a second presentation a refusal. So
they are one package (`internal/recovery`) and one table with a `purpose` CHECK,
rather than three packages with three token formats and three answers to "is this
still live". A `password_reset` token presented to the verification route is a 404,
not a different error.

**The email change has two sides and the second token does not exist until the first
is redeemed.** A stolen session can start one, and what it produces is a link in the
victim's inbox and nowhere else — the attacker cannot advance it, and the victim gets
the one warning they would otherwise never get.

**Delivery goes through one seam with two methods, and this repository does not
implement the delivery.** `recovery.Mailer` is `Send` and `Ready`; the second exists
so a request flow can ask whether a message *can* be delivered before it mints
anything, which is what keeps a deployment without mail from turning "503" into an
account-existence oracle. `main` wires `recovery.Unavailable{}`, which **fails** —
every path that needs to send answers `503` with a sentence saying why. That is
deliberately not a mailer that logs: a reset token in a log aggregator is a reset
token anybody who can read the logs can redeem. courier is the platform's mail
service and its delivery path is unfinished; wiring it is three lines in
`buildRecovery` (see DECISIONS.md D7).

**Email bodies carry no URL.** identity does not know the product's route shapes, so
the body carries the token, the address and the deadline, and the product builds the
link. The token is never in a subject line.

**A cooldown is not a rate limiter.** `RequestWindow` is one minute per address per
purpose, and a request inside it mints nothing, sends nothing, and answers
identically. It does not supersede a live link: a request route that invalidated one
would let anybody invalidate a victim's pending reset. It does nothing about a flood
spread across a thousand addresses and is not per-client. Per-source throttling
belongs to courier, which is in the path of every message this service sends — this
is a declared gap, not an oversight.

**A reset and an email change end sessions and OIDC access tokens, and not scoped
API keys.** Same rule and same reasoning as MFA: a key is a credential somebody
deliberately created for a script, and silently revoking one breaks a CI job with
nothing in the response saying why. Verification revokes nothing.

**No message is ever logged**, and `TestNoRecoveryTokenReachesTheLogs` drives all
three flows through a logger that keeps everything to prove it.

### The admin surface, and why it is a separate thing

Three operations, and the privilege boundary is one sentence:

> An account admin may revoke pending invitations to their own account and read
> that account's admin audit log — authority over other people's pending access,
> and nothing else.

It is a sentence rather than a paragraph because a role checked in thirty places
is a role that will be checked in twenty-nine of them. So the sentence is not
documentation of a boundary, it is the boundary, and the code says exactly it:
three rows in `accountRouteScopes`, two scopes, and a new row without a new scope
fails a test.

**A browser session cannot reach any of it, and a machine credential is the point
rather than a limitation.** Every action is recorded against the api key's **row
id**, so a token is something an audit record can name and a session is not. This
is the mirror image of the session-only surfaces above, and the two together mean
no route in this service is reachable by both kinds of credential unless somebody
wrote that down deliberately.

**Every action is recorded in the same transaction as the mutation.** A revocation
that commits and an audit row that does not is a revocation nobody can account
for, so `admin.Service` has no method that mutates without recording: the mutation
is a callback run inside the transaction that writes the record. Both failure
directions are tested against a real database with a trigger that raises.

**The record cannot be edited, including by the admin whose action is in it.**
`GET` is the only method mounted on that path, the store has no update or delete,
and — the one that settles it — **the table refuses `UPDATE` and `DELETE`** in the
database. A guarantee written in Go does not bind a `psql` session or a future
packet. The table also has **no foreign key to `accounts`**, so the admin surface
cannot delete its own audit log by deleting the account.

**Bulk and single do not share a shape**, because a bulk operation is where an
off-by-one becomes an outage:

| | single | bulk |
|---|---|---|
| confirmation | none — the URL names the one row | **`confirm: true`, in the body** |
| minimum | admin | **owner** |
| response | `204` | `{requested, revoked}`, and they differ |

The reasoning, the rejected alternatives and the two OIDC-shaped consequences
(the anonymous column is `403` here rather than `401`, and the authorization
matrix has no positive cell for a token-only surface) are in
[DECISIONS.md D2–D5](DECISIONS.md).

Every non-2xx is `application/problem+json` per core's error envelope, including
`404` and `405`. The `trace_id` in the body always matches the `X-Trace-Id`
response header, and internal failures are logged with that id rather than
described to the caller.

### **Ten rows of the table above are still bigger than the OpenAPI document, and that is a known gap**

The three admin rows added by this packet are **documented** — they are in
`openapi/v1.yaml` under the `admin` tag, with operationIds, request and response
schemas, and `info.version` is 1.4.0 because of them. `knownDrift` did not grow.

The ten rows marked *"Not in `openapi/v1.yaml`"* are served, gated, in the
authorization matrix and — for seven of them — carry a declared scope, and they
appear in **no committed document**. Neither `openapi/v1.yaml` nor
`openid/openid.yaml` describes them, and before this packet they were not in this
table either. Two OIDC operations are in the same position: `POST /oidc/authorize`
and `POST /oidc/userinfo` are mounted deliberately, and `openid/openid.yaml`
declares only the `GET` on each.

`internal/httpapi/openapi_drift_test.go` is the check that found this, and it holds
the documents to the router in both directions by **method and path**. It is
recorded as **[D1](DECISIONS.md)** and the question is open: these are contract
surface to document, or routes to rule out of the contract in writing. Until that
is answered, `knownDrift` in that file holds all twelve, pinned so the list can
neither grow nor be emptied — a new undocumented route is a failing test whether
or not anybody remembers the file.

What this means for a caller, plainly: **a client generated from this service's
documents has no method for any of those twelve operations.** They work; they are
just not in the menu. That is the gap, and it is the reason the check exists.

**Adding a route and not growing `knownDrift` is a normal operation here**, and
the admin surface is the worked example: three new operations, three documented
operations, a list that stayed at twelve. A packet that finds itself tempted to
bump that count is being told the truth by the tripwire — the answer is to
document the route, never to name it.

The `/v1` routes exist only when `DATABASE_URL` is set. Without it they are
absent, so a missing database is a clear `404` rather than a pile of `500`s.

With no `DATABASE_URL`, readiness is `200 {"status":"ok","deps":"none"}` — there
is nothing to check, and saying so is more useful to an operator than an empty
list or a 200 that looks identical to a healthy probe.

Probe failures are logged with the underlying error and **never** returned to the
caller: an unauthenticated request to `/readyz` must not be a way to learn that
a database host is `10.0.0.5` or that a password was rejected.

### Multi-factor authentication

TOTP with recovery codes. The only thing MFA is for is being hostile to somebody
who has stolen a password, so every decision below is about that.

**A correct password does not mint a session.** `POST /v1/session` answers **202**
for an account with a second factor and **200** for one without:

```
POST /v1/session {"email","password"}
  → 200 {"token","expires_at"}                  no second factor; here is your session
  → 202 {"mfa_required":true,"challenge","expires_at"}   one is required

POST /v1/session/mfa {"challenge","code"}
  → 200 {"token","expires_at"}
```

The `202` body has **no `token` key at all**, not an empty one, and no session
cookie is set. `POST /v1/session/mfa` is the only route in this service that turns
a second factor into a session, and it mints the session inside the same
transaction that consumes the challenge — so a challenge cannot be answered twice
and a code cannot buy two sessions.

The challenge travels in **the cookie or the body**, and both are supported on
purpose: core's conventions say "no cookies for API traffic" and
`POST /v1/session` already returns the token in the body as well as the cookie, so
a second step that read the challenge only from a cookie would leave every
non-browser client unable to finish a two-factor login.

#### Enrolling

Four requests, and the middle one is the point.

1. `GET /v1/mfa` — is there already a second factor, and how many recovery codes
   are left? The count is here so a client can say "2 left — print a new set"
   while there are still two.
2. `POST /v1/mfa/enrollments` — generates a secret and stores it **unconfirmed**,
   returning the base32 `secret` and an `otpauth://` `provisioning_uri`. Neither is
   ever returned again: a user who loses them starts a new enrollment, which mints
   a new secret. The enrollment expires in ten minutes and is **not MFA** — the
   login path reads only confirmed rows, which is what makes "stored but never
   confirmed" mean "authenticates nothing".
3. `POST /v1/mfa/enrollments/{id}/confirm {"code"}` — proves you can produce a
   code. This makes MFA live, issues ten recovery codes (returned once, and there is
   no endpoint that re-reads them), emits `identity.mfa.enabled`, and **revokes
   every session the user holds**, including the one this was done from.
4. Done. Every later `POST /v1/session` answers 202 until a code is presented.

**Why enabling revokes every session.** A session minted under a one-factor policy
was minted on a password alone. Leaving it alive after the user opts into a second
factor means the attacker holding it does not have to solve the new problem at all.
It costs the user every other device they were signed in on, and that is the price
of the change meaning something. Disabling revokes every session for the mirror
reason: a user who turns MFA off has very often had it turned off *for* them.

#### Replacing the secret

`POST /v1/mfa/enrollments` on an account that already has a credential starts a
**rotation**, and it takes a second factor. The old secret stays **live until the
replacement is confirmed**, so an abandoned rotation costs nothing; on confirmation
the old credential is deleted, its recovery codes go with it, and both
`identity.mfa.enabled` events fire — a rotation is a genuine change, and a consumer
that only heard about the first enrollment would be holding a stale picture.

#### Disabling

`DELETE /v1/mfa {"code"}` requires a second factor. A password is not accepted and
there is no path through this service that would let one be. A recovery code works,
which is the escape hatch a user with a lost phone needs and the reason recovery
codes exist.

#### The skew window

**One step either side**, so a TOTP code is live for **90 seconds** rather than 30.

Zero skew would be tighter and is wrong in practice: it refuses any code typed in
the seconds either side of a step boundary, which is exactly when a user is most
likely to be reading digits off a screen — and the users it refuses are the ones
with the worst network and the least accurate autocorrect. A second factor with a
visible failure rate does not get retried; it gets turned off, and a user with MFA
off is worse off than a user with MFA and a support ticket.

Two steps or more is the other error, and it is the one RFC 6238's implementers
drift towards. Every step of skew is thirty more seconds during which a phished or
shoulder-surfed code still works, and one more six-digit value an attacker gets to
guess. The window is the *only* thing that grows with skew, so it is held at the
smallest value that tolerates real drift.

What one step does not buy is worth stating rather than hiding: it tolerates up to
**thirty seconds of clock drift in either direction and no more**. A phone
forty-five seconds fast spends half of every period showing a code two steps ahead,
and that code is refused — a fifteen-second wait, every thirty seconds, for that
phone. No skew value fixes it without a window wide enough to be a security
decision rather than a tolerance. What makes the ninety seconds survivable is the
replay guard: a captured code is good for **exactly one use**, however long it
stays inside the window.

#### Replay, and why the guard is a set

The standard attack against TOTP is a photograph of the code and a race to use it,
and it is the thing most implementations get wrong. This service remembers the
**exact steps consumed**, in a table whose primary key is
`(credential_id, step)`:

- It refuses a step that was **spent** and accepts one that was **not**, in any
  order. A single "highest step accepted" bigint cannot make that distinction: below
  its mark it does not know whether a step was spent or merely old, so it refuses
  correct codes whenever a phone's clock is corrected backwards, a user switches to
  a backup authenticator that is behind, or a device re-syncs time mid-window.
- It is atomic without a lock. `INSERT … ON CONFLICT DO NOTHING` is one statement,
  so fifty requests carrying the same code resolve to one winner and forty-nine
  refusals with nothing to roll back.
- It is bounded. Every acceptance prunes the steps below the window in the same
  transaction, so the table is the size of the enrolled population rather than the
  size of the login history.

The cost of claiming the step *before* the session exists is stated where it is
paid, in `mfa.VerifyFactor`: a database failure between the claim and the session
write leaves the step spent and the user waiting thirty seconds for the next code.
The alternative — claiming only inside the session's transaction — means a replayed
code never reaches the failure counter at all, because the claim and the refusal
would roll back together, and a code that cannot be counted is one an attacker may
present without limit.

#### The lockout is per-factor

`mfa_credentials.failed_attempts` is the second factor's counter.
`users.failed_login_attempts` is the password's. They are separate rows, and that
separation is the property: **five TOTP guesses have not spent five password
guesses, and five wrong passwords have not moved the second factor's.** Both run
`sessions.Lockout`'s arithmetic — one implementation, two counters — because a
second implementation in `internal/mfa` would be a second place for the thresholds
to drift, and the drift would be invisible until a user was locked out for the
wrong number of minutes.

Both are five attempts and fifteen minutes, deliberately the same numbers: a user
who mistypes three times should not be punished differently depending on which
field they got wrong. What differs is the counter. The second factor's lockout is
`423 account_locked` with `Retry-After`, exactly as the password's is.

One honest interaction: the challenge lives ten minutes and the lock lasts fifteen,
so a user who trips the lockout waits longer than their challenge lives and has to
start the login again. The alternative — a challenge TTL longer than the lockout —
would mean holding a permission to finish a sign-in for a quarter of an hour.

#### What is stored, and what a database dump yields

| Column | Stored | A dump alone yields |
|---|---|---|
| `mfa_credentials.secret_ciphertext` | AES-256-GCM under `MFA_ENCRYPTION_KEY`, with the user id as AAD, `v1`-prefixed base64url | Nothing presentable. The key is in the environment, not in the row. |
| `mfa_recovery_codes.code_digest` | SHA-256 of an 80-bit `crypto/rand` value | Nothing. 2⁸⁰ candidates is not a computation. |
| `mfa_challenges.token_digest` | `sessions.Digest` — SHA-256 of a 256-bit token | Nothing. Same construction as every other credential column here. |

**There is no column in this schema that holds a working second factor**, and
`TestADatabaseDumpYieldsNoWorkingSecondFactor` is the test that says so over a real
Postgres rather than in a comment.

**Why the TOTP secret is encrypted and not hashed.** Every other credential column
in this service is a one-way function of the presented value, and a TOTP secret is
the exception. The authenticator computes `HMAC(secret, counter)` and so does this
service, so the secret has to be **recovered**, not verified: a digest of it would
verify against nothing, exactly as a digest of a password is useless when the
protocol asks for the password itself. Encryption is the only transformation that
satisfies both halves.

**The trade-off, stated because it is the cost of that choice.** Encryption is
recoverable by anyone holding the key, so the boundary is the key and not the row.
A hash has no such boundary — it is one-way forever. What this service gives up is
the ability to survive losing `MFA_ENCRYPTION_KEY`: on a lost key every sealed
secret is unreadable, every enrolled user fails **closed** at their second factor,
and the only way back is a recovery code or a support ticket. That is a real
operational cost, and it is why the key belongs in the same secret store as
`OIDC_SIGNING_KEY` and is **never generated at boot** — a generated key would mean
every restart invalidates every enrolled user's secret, and a restart is not
something anybody decides to do. `MFAEncryptionKeyConfigured` and
`ErrNoMFAEncryptionKey` keep the absent case a supported state rather than a
silent one.

**Why recovery codes are SHA-256 and not argon2id.** Eighty bits of `crypto/rand`
has no structure to guess, so a memory-hard hash would buy nothing the entropy has
not already bought and would cost tens of milliseconds on every sign-in that
reaches for it. Argon2id exists to make **guessing** expensive and there is nothing
here to guess. Eighty bits is a **floor**: a six-digit recovery code hashed with
SHA-256 would be walked in microseconds, and the dump would be a set of working
second factors.

#### Configuring it

`MFA_ENCRYPTION_KEY` is base64url, **exactly 32 bytes**, read from the environment.
Present-but-unreadable is a startup failure and not a warning, because an operator
who pasted a 16-byte key believes they have 128 bits of entropy protecting every
second factor on the platform.

Absent is a supported state, and it degrades in **one direction only**:

- The management routes (`/v1/mfa` and everything under it) are **absent** — a
  `404`. A user must not be talked into enrolling a factor this process could not
  later verify.
- `POST /v1/session/mfa` is **still mounted**, because it needs no key: deciding
  that an account has a second factor is a query on a boolean column. A user who
  enrolled elsewhere is refused at their second factor rather than being let in on
  their password, and the absence of the management routes says nothing about
  whether this one exists.

A third outcome — a user with MFA trying to disable it on a keyless deployment —
gets `503 service_unavailable` with a sentence saying what is wrong, because a user
told only "try later" retries forever and an operator told `internal` goes looking
for a database problem that is not there.

#### What is NOT built

No **"trust this device"** cookie and no re-authentication grace period. A trusted
device is a real feature and a real attack surface — it is a bearer token with no
expiry and no second factor behind it — and it belongs in its own packet with the
trade-off written down. Until then, every sign-in needs both factors.

### Scoped API tokens

The credential that is **not** a browser session. For a script, a CI job, or
another service.

There are three credentials here and they are not interchangeable, because their
failure modes are genuinely different. A session is browser-shaped and dies in
weeks. An OIDC access token is a JWT for a *third party holding a browser*,
verifiable against the published JWKS with no call back here. A scoped API token is
a first-party machine credential: opaque, long-lived, revocable, and carrying a
scope set. Routing one through another's machinery would give each of them the
wrong properties — a JWT cannot be revoked before its `exp` arrives, and a session
cannot carry a scope set an operator curated.

**The wire format** is `cafaye_` plus 43 base64url characters:

```
cafaye_Zq3vK7mXpR2tY8wB4cN6dF0gH1jK5lM9oP3qS7uV2wX4yZ8
└──────┘└──────────────────────────────────────────────────┘
  7              43 characters of 32 bytes of crypto/rand
```

The prefix is a feature and the feature is **recognition**. A secret that leaks
into a CI log, a shell history, a support ticket or a paste buffer is recognised
as a cafaye credential by its first seven characters, which turns "somebody has to
work out which of these strings is working" into a `grep`. It is the prefix rather
than a marker in the middle because a scanner — and a truncated log line — looks at
the first bytes.

The same prefix is the **discriminator** at the door: a session token is looked up
in `sessions` and an api key in `api_keys`, and the shape decides which table is
touched before any query runs. A value of the wrong kind is never looked up in the
wrong place, so "is this token live" cannot be answered by the response time of the
wrong index.

**What is stored** is the SHA-256 of the presented value and nothing else. The
plaintext exists once, in the `201`. Not argon2id, and the reasoning is
`internal/sessions/token.go`'s with the difference this credential's lifetime makes:
a slow hash would cost every authenticated machine request tens of milliseconds
across the platform, and what it buys is nothing — 256 bits of `crypto/rand` has
no structure to guess. The hash is a **deterministic** function because the lookup
is "hash what was presented and find the row", and a salted password hash cannot be
looked up at all.

#### A token carries a scope set, not a role

**This is the property worth reading twice.** A token names a user and an account.
Its authority is re-evaluated on **every request** against that user's *current*
membership, so:

- **removing somebody from an account stops their tokens on the next request**,
  with no cache to expire and nothing to sweep;
- **a demotion takes effect immediately** — the route's 403 appears on the request
  after it, and only on the routes the new role cannot reach;
- **re-inviting them does not bring the tokens back.** The removal also revoked
  what they held, in the same transaction, because re-evaluation alone was not
  enough: the same person re-invited at the same role satisfies the membership join
  again, and a contractor's CI credential that died at offboarding would quietly
  start working the day somebody re-added them. That is a bug this service's own
  test found and the assertion to read is the *last* one in
  `TestARemovedMembershipStopsTheTokenOnTheNextRequest`.

The difference between a credential and a permission is exactly this. A token
stores no role, so there is no stored role to go stale.

#### The scope vocabulary

Four names, a closed set, and every one of them is a capability an existing route
already enforces a different way. That is the test of a real scope: removing it
removes access to something that exists. The shape is core's
(`resource:action`, from `docs/openapi-conventions.md`'s `invoices:write`), and
`darkroom` already publishes `assets:read` / `assets:write` in the same form.

| Scope | Routes it is enforced on |
|---|---|
| `accounts:read` | `GET /v1/accounts/:id`, `GET /v1/accounts/:id/members` |
| `accounts:write` | `PATCH /v1/accounts/:id`, `POST /v1/accounts/:id/invitations`, `PATCH` and `DELETE /v1/accounts/:id/members/:userId` |
| `accounts:delete` | `DELETE /v1/accounts/:id`, and nothing else |
| `oidc_clients:write` | all four `/v1/accounts/:id/oidc-clients` routes |

**Where the vocabulary came from:** `openapi/v1.yaml` and the route table, read
rather than invented. `accounts:delete` is separate from `accounts:write` because
it is the only one of them that cannot be undone, and because its route's minimum
is `owner` where everything else is `admin` — a token carrying `accounts:write`
and held by somebody who later becomes a member is already refused on the role
check, so the extra scope is for the owner case, where the role gate alone would
let it through. `oidc_clients:read` does not exist: both `GET`s are owner-only
routes whose response *is* the integration's configuration, so a separate read
scope would be a name nobody in this service has a use for.

**What is deliberately absent, and every absence is a refusal rather than an
oversight:**

- **no scope for the second factor.** A token cannot read whether an account has
  MFA, enrol one, rotate one or turn one off. A machine credential that could
  disable a second factor is a credential whose theft is a *downgrade* rather than
  a break-in, so the routes refuse a token outright rather than consulting a list.
- **no scope for sessions.** A token cannot mint, read or revoke a browser session.
- **no scope for the api keys themselves.** A credential that can mint more
  credentials is a privilege-escalation path with a nice UI.
- **no scope that means "everything."** Not `*`, not `accounts:*`, not one named
  `admin`. "Read this account" and "delete this account" are two decisions a person
  makes twice.
- **no scope for the account *collection* routes.** `GET /v1/accounts` answers
  "which accounts does this **user** belong to", and a token is bound to one
  account. A CI job holding a credential for one tenant is not entitled to an
  inventory of every other tenant its owner is in.

**A session carries no scopes and is not refused for that.** A session is a human's
credential with the full authority of its role; a token is a narrowed one. That
asymmetry is the whole difference between the two, and it is why the scope check is
skipped for a session rather than failing it.

A route with **no declared scope is closed to tokens** — `Allows("")` is false for
every granted set — so a new account route added by a later packet is unreachable
by a machine credential on the day it lands, not on the day somebody notices it was
never gated. `TestEveryAccountRouteDeclaresItsScope` and
`TestEveryScopeIsEnforcedOnItsRoutes` walk the router in both directions.

#### Expiry

**Optional, with a default, and a ceiling.** Omit `expires_in` and the credential
lives **90 days**. Ask for more and the ceiling is **365**. Ask for `0` or a
negative number and you get a `422`, because that is where "never expires" would
have gone and it is not something this build offers.

The 90 is a judgement about two failure modes rather than a round number: long
enough that a CI job somebody set up in a hurry does not fail on a Tuesday three
months later, and short enough that "we rotated our tokens" happens without anybody
having to decide to make it happen. A permanent credential has no such moment, and
that is the whole of the decision.

**What it costs, stated because it is real:** a CI credential has to be replaced
every quarter, and that is friction on precisely the use case that motivates the
feature. What it buys is a moment at which a credential nobody is using gets
noticed — and `last_used_at` is how that moment is acted on rather than guessed at.
Rotation is two requests, not a maintenance window: revoke, then mint. Mint the new
one first if you cannot afford the gap, and revoke the old one when it works.

`last_used_at` is accurate to within **five minutes**, deliberately. A CI token at a
thousand requests a second must not put a thousand `UPDATE`s a second on one row,
and a single row's lock is a queue. The write is conditional on the stored value
being stale, so there is no read-modify-write and zero rows updated is a success.

#### One-time display

`token` is in the `201` body and **nowhere else, ever**. Not in the list, not in a
single-token read, not in the introspection response, not in the log, not in the
event payload. A caller that loses it mints another.

`TestTheSecretIsOnTheWireOnceAndNowhereElse` asserts it on the wire, and then
searches at rest: the whole row as JSON, the whole table, and every event payload
in the outbox, for the plaintext, for the plaintext without its prefix, and for its
digest. The digest has to be *found* in that search, or the test would pass on a
table that stored nothing at all.

There is no "reveal" endpoint, and there is no "rotate" endpoint either — changing
a token's authority means minting a new one, which means a new secret and a revoked
old one, so "change the scopes" is exactly "rotate" spelled two ways and a second
spelling is a second way to get the security property wrong.

#### Refusals are all the same refusal

Unknown, revoked, expired, and one whose owner has been removed from the account
are all **401** with the same body. `TestEveryRefusalIsTheSameResponse` also
covers the things a machine will present at this endpoint by accident — a session
token, a JWT, a truncated paste, the digest itself, binary noise — and asserts the
`type`, `title`, `status`, `code` and `detail` are identical across all of them.

**The timing story is structural rather than a promise about
`subtle.ConstantTimeCompare`.** The store never sees the presented value: `Digest`
turns *anything* into a well-formed 64-character hex string, and the query is an
ordinary indexed equality on that. So there is no length comparison anywhere on the
path for an early return to skip, and no function whose runtime reveals how much of a
guess was right. A constant-time compare is what you reach for when a stored secret
is compared byte by byte, and nothing here does that.

#### Introspection, and the two claim names

A token is opaque: it has no claims inside it and there is no published key set to
verify it against. So `POST /v1/introspections` is how a resource server learns
what a token may do. The response is RFC 7662's shape, and the path is under `/v1`
because core's rule says every path in this document is — if core fixes an
introspection path, that is the row to change.

An unusable token answers **`200 {"active": false}`** and nothing else. The status
is 200 rather than 404 because the endpoint succeeded; the answer is that the token
is not active. Unknown, revoked, expired and orphaned are indistinguishable, which
is the whole point: a caller who can tell them apart learns whether a leaked value
was live.

The caller's *own* standing is a different question with different statuses, because
it is a different fact about the request: `401` with no credential, `403` for a
token asking about somebody else's. A token may introspect **itself** — the case a
CI job needs when it wants to know why it is being refused — and a session may read
a token in an account it owns.

> **The capability set is emitted TWICE, as `scopes` and as `scope`, byte for byte
> identical.** That is a deliberate interim and it is not this service's contract.
> core's `docs/openapi-conventions.md:134` requires a claim named `scopes`;
> `guard/src/middleware/jwt.ts:32` reads `scope`, splits it on whitespace, and
> treats an absent claim as an empty set. The fleet has not agreed, the question is
> open as **MD7**, and picking a side here would mean rotating every credential
> already in a customer's hand. Emitting both means whichever name wins, the other
> is a one-line removal from `internal/apikeys/claims.go` and **nothing has to be
> reissued**. Two names is not a contract.
>
> The shape is a space-separated **string**, not an array: that is the one shape
> both sides can read. guard's verifier does `raw.split(/\s+/)` and refuses a
> non-string claim, so an array is a token the gateway will not parse at all.

**`account_id` is required and there is no `sub` fallback.** `sub` is the **user**
the token names; `account_id` is the tenancy boundary and it is always present. A
token with no account cannot be used against any account, so it is answered
`{"active": false}` rather than issued a subject to guess a tenancy key from. The
alternative — falling back to `sub`, as guard's `limitKey` does today — would give a
service-to-service token a *user* as its tenancy key, and a bug in one service that
keys on `sub` becomes a cross-tenant read rather than a `403`. Whether guard's
fallback is safe is **MD8** and is not decided here; what is decided here is that
identity never produces a token that needs it.

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
| `/oidc/introspect`, `/oidc/revoke`, `/oidc/end-session`, `/oidc/device_authorization` | `404 not_found` | Not built, on any method — the row carries no method because there is nothing behind it to answer one. Absent from the discovery document too. |

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
internal/mfa/          the second factor: credentials, challenges, codes, lockout
internal/users/        accounts and the email-uniqueness rules
internal/sessions/     session tokens, hashing and revocation
internal/oidc/         the OIDC provider: storage adapter, registrations, the key
internal/accounts/     the tenancy use cases: accounts, memberships, invitations
internal/admin/        the admin surface: invitation revocation, and the audit trail
                       that records it. The two are one package because no method
                       here mutates without recording — see DECISIONS.md D3
internal/apikeys/      scoped API tokens: the wire format, the scopes, the claims
internal/oauth/        the social-login client side — WRITTEN AND NOT MOUNTED. State,
                       token cipher, registry, code-for-token exchange and the
                       connected_accounts store, with no route and no handler. Only
                       the state half is live, reused by the OIDC login. See
                       "Not built yet"
internal/outbox/       transactional event envelope, SKIP LOCKED claim, publisher
internal/platform/db/  the pgx pool, and the readiness ping
internal/platform/ci/  the test that keeps .github/workflows/ci.yml honest
client/               THE GO CLIENT — a generated transport and the wrapper over it
migrations/            goose SQL files
```

`cmd/` + `internal/` is the layout from `refs/goreleaser`. `main` owns nothing
but process lifetime: everything testable lives in `internal/`, and the pieces
`main` does own — the socket, the drain, the signal handling — are in an `app`
type that the tests drive directly.

`client/` is the one directory that is not under `internal/`, and that is the whole
reason for it: **`internal/` is by definition unimportable, and a client no consumer
can import is not a client.** It is not reachable from `./cmd/identity` either, which
is what keeps the client's dependencies out of the service's binary.

## The Go client

`client/` is the third of the fleet's clients, after `cafaye-ts` and `cafaye-py`, and
the one where the generator is right. Two layers, and the split is MD6's:

```
client/generated/api.gen.go   GENERATED, COMMITTED. oapi-codegen v2.8.0 over
                              openapi/v1.yaml: 20 typed operations and a Client
client/generate.go            the //go:generate line, pinned to v2.8.0
client/oapi-codegen.yaml      the generator's configuration
client/transport.go           the interface the generated client satisfies
client/client.go              the hand-written client: 20 typed methods
client/credentials.go         which credential this is, and where it may be sent
client/baseurl.go             where requests go, in a documented order
client/errors.go              RFC 9457 problem to typed error, typed fallback
client/redact.go              the scrubber, and the all-or-nothing rule
client/safetolog.go           a redacting formatter for the generated secret types
```

**Why Go generates and Python does not is a ruling, not an accident**, and it is
written down in [DECISIONS.md](DECISIONS.md) D6 so the next person does not read the
inconsistency as a mistake. In short: Go has a mature OpenAPI 3.1 generator whose
output is ordinary Go — structs, an interface, an `*http.Response` — so generation is
a build-time concern. Python's generators impose a runtime one: hey-api's is v0.0.24
and emits parameterless methods with unsubstituted path templates, and
openapi-generator's Python output is beta on 3.1 and inverts `const` discriminants to
`any`. A hand-written Python client has the smaller attack surface, and it is not a
close call.

**Four things the wrapper owns**, because the generated client cannot: which credential
this is, where requests go, RFC 9457 mapping, and being the public surface.

**Base URLs have no default.** `ResolveBaseURL` consults, in order: the `BaseURL`
option, `$CAFAYE_IDENTITY_BASE_URL`, `$CAFAYE_BASE_URL`, and then **throws**. The
document's own `servers:` entry is deliberately not a default — it would send a
self-hoster's traffic to somebody else's deployment and it would *succeed*, so nothing
would look wrong until somebody read a log.

**A credential reaches no string a human reads.** Every string the client builds out
of anything a caller or a service supplied goes through `Redactor.String`, redaction is
all-or-nothing, and the credential lives inside **closures** rather than in struct
fields — `fmt` prints an exported field by value under `%#v`, and that verb does not
consult `String()`, so a `token string` field is a leak no method can intercept.

**An unknown problem code is a typed error**, so `errors.As(err, &ProblemError)` works
against every code including the four this document already describes that core's
reserved list does not have.

**Regenerating is a gate, not a suggestion:**

```sh
go generate ./client/     # writes client/generated/api.gen.go
```

`TestTheCommittedGeneratedFileIsWhatThePinnedGeneratorProduces` runs that same
generator over the same document into a temporary directory and fails when the
committed file differs, and CI fails the build when four named security tests do not
PASS by name — among them the credential-leak test, the unknown-problem-code test, the
regeneration gate and the lint-exclusion narrowness check.

## Testing

**`go test ./...` is red on a machine with no database, and that is the design.**
`internal/mfa`'s `TestTheDatabaseTierActuallyRan` FAILS rather than skips when
`TEST_DATABASE_URL` is unset, because every test in that file is a database test
and a skip there reads like coverage. A green suite that never touched Postgres
verified nothing, so the suite says so.

The database tier, once the schema is applied:

```sh
docker compose up -d --wait postgres
goose -dir migrations postgres "$DATABASE_URL" up
TEST_DATABASE_URL="postgres://identity:identity@localhost:5432/identity?sslmode=disable" go test ./...
```

Migrations are a deploy step, so they are not a test step — `goose up` is its own
command above the suite, and a suite run against an unmigrated database fails
loudly with `relation "public.users" does not exist` rather than skipping.

**`internal/courier`'s live tier SKIPS loudly instead, and the difference is
deliberate.** Three tests in that package drive a real courier process, and they
read `TEST_COURIER_URL` and `TEST_COURIER_TOKEN`. Without them they **skip**, and
the skip message names what would have been proven and how to run it — it is not a
bare `t.Skip`, because a skip that says nothing is a test that silently passes
without proving anything, which is the thing this section is about.

The reason is the same one `TestTheDatabaseTierActuallyRan` gives for failing,
applied to the tier it actually applies to: **CI supplies a database and cannot
supply a courier.** The `gate` job declares postgres as a service container and
applies the migrations above the gate, so an absent `TEST_DATABASE_URL` there is a
misconfigured *run* and failing is honest. A courier would need a second service
with its own database, its own migrations and its own principal resolver — the same
seam that keeps the database tier in a separate `gate` job at all — so an absent
`TEST_COURIER_URL` is an environment that *cannot run* the test, and skipping with a
name is honest. A test that hard-failed on it would make the package unrunnable
everywhere, and a permanently red gate is a red gate nobody reads.

So the e2e file is not deleted, and what it cannot prove offline is proved offline
instead: `wiring_test.go` holds the request identity, the closed body, and the
**stable `Idempotency-Key`** (the property that stops a double-clicked reset mailing
twice); `client_test.go` holds courier's request contract; `recorded_test.go` holds
courier's byte-for-byte answers. What is left for the live tier is the one claim a
fixture cannot make about itself: that a real implementation of courier's document
accepts these bytes.

CI knows about the skip rather than discovering it. `E2E_SKIP_EXCEPTIONS` in the
`gate` job names exactly those three tests; both no-skip checks subtract them by
whole name and still fail on any other skip. `internal/platform/ci` holds that list
to those three names in **both** directions — it cannot grow, and it cannot be
emptied — so the exemption cannot widen by accident, and a real skip cannot be
hidden by deleting an entry.

With no `TEST_DATABASE_URL`: **961 PASS lines, 364 SKIP, and 2 FAIL** — both
fails are `TestTheDatabaseTierActuallyRan`, one in `internal/mfa` and one in
`internal/apikeys`, and both are the point. With it:
**1544 PASS lines, 0 SKIP, 0 FAIL**, no data races under `-race`.

(Those figures were measured on this tree. The numbers this section used to
carry — 776/309/1 and 1254 — were already stale before the tripwire packet: at
`bff6333`, the same commands gave 923/364/2 and 1506. A stale count in a
document about what the suite proves is the same class of problem as a stale
route list, so it is worth writing down that it happened.)

### **The document-versus-router tripwire**

`internal/httpapi/openapi_drift_test.go` is the check that holds
`openapi/v1.yaml` and `openid/openid.yaml` to the router, in both directions, by
**method and path** — never by count, because one operation added and one removed
leaves the count alone. It is the last such check owed in the fleet, and it is the
one that found the twelve undocumented operations described above.

Four things about it are worth knowing before you touch a route:

- **The method comes from chi's own walk of the tree `New` assembles**, never
  from the path string. billing's first drift check compared paths and never
  `route.verb`, so `PUT /v1/customers/{id}` was served in a money-handling
  service with nothing written down about it — one path on each side, and the
  comparison reported agreement. That shape is live here today.
- **Both documents are read** and the union is the contract. Nine of the eleven
  `/oidc/*` and `/.well-known/*` routes are documented in the sibling document,
  so a check reading only `openapi/v1.yaml` would have had to declare all eleven
  undocumented, which is false about nine of them.
- **There is no prefix filter.** Every route is either in a document or named,
  and a route that is neither fails the suite. `strings.HasPrefix(path, "/v1")`
  is a guess about intent, and it cannot see a method.
- **The document is parsed without a YAML dependency.** `go.mod` has none and
  this adds none; the reader takes the `paths:` block by indentation, states the
  subset it understands, and raises on every way it could under-read. Two empty
  sets agree, and that is how a check over nothing goes green.

So adding a route means adding its document entry, with an `operationId` — that
is the name of the method on every generated client in the fleet. The gate says so.

### **The claims-versus-router tripwire, and the tripwire's own tripwire**

A perfect OpenAPI document is not the same as an honest repository. `README.md`
said this service does OAuth social login, its roadmap checked the box off, and
`cafaye.yml` — the manifest a customer is handed — claimed the capability. The
documents were **honest the whole time**: not one of them ever declared a
social-login operation, because there is no route for one. Every claim was in
prose, and `openapi_drift_test.go` reads `paths:` blocks, so it could not see any of
it.

`internal/httpapi/claims_test.go` closes that, holding three more places to the
same router walk, **in both directions**:

| Claim | Held by |
|---|---|
| README endpoint tables | `TestTheReadmeEndpointTablesAreTheRoutesTheRouterServes` |
| README roadmap checkboxes | `TestEveryCheckedRoadmapItemIsBackedByTheRouter` |
| `cafaye.yml` capability list | `TestTheManifestDescribesOnlyCapabilitiesThisServiceHas` |

It **found the manifest claim and the roadmap claim by name on its first run**,
which is the evidence that it would have found them before. A fourth file,
`claims_reader_test.go`, injects faults into the readers themselves — a malformed
route row, a block-scalar description, an emptied roadmap — because a check over
nothing is green, and a reader that under-reads reports agreement over a subset.

`claims_faults_test.go` holds the walk itself: it asserts a route from **each**
conditional surface is visible (not that a field was set, which passes against a
registrar that mounts nothing), that two options literals stay in step, and that
each claim check goes **red** on a route that does not exist.

`internal/httpapi/oauth_absent_test.go` is the inverse — it asserts the social-login
surface is still unmounted, and **its failure message is the work order** for
whoever mounts it. Finishing that work means deleting that file, because an absence
test that outlives the absence is the repository lying to itself in a file nobody
reads.

That difference is the only thing that tells "ran" from "skipped" from the
outside, and the wall-clock is where it shows. Same command, same machine, only
`TEST_DATABASE_URL` differing:

| package | no database | with the tier |
|---|---|---|
| `internal/accounts` | 0.36s | 83s |
| `internal/httpapi` | 1.4s | 110s |
| `internal/mfa` | 2.0s | 90s |
| `internal/auth` | 1.8s | 55s |
| `internal/outbox` | 2.5s | 46s |

SIGTERM handling is not asserted through a mock: `TestMainHandlesSIGTERM` runs
the real `main()` in a child process, waits for it to report that it is serving,
sends the signal, and requires a clean exit. There are no `time.Sleep` calls in
this repository — every wait is on a channel the code under test signals, or on
a failure deadline (PLAN.md §3).

## CI

`.github/workflows/ci.yml` calls kit's reusable workflow for the shared half and
runs this repository's own for the rest:

```yaml
uses: cafaye/kit/.github/workflows/ci.reusable.yml@master
```

`ci (kit: go)` is **expected red**, and that is a conflict with kit's own rules
rather than a choice made here: kit's checklist ends with "The workflow is green
on the adoption PR" and kit's AGENTS.md says "Never weaken a check to make the
gate green". Two steps are red, both structurally.

- `test` runs `go test` with no Postgres, and a caller cannot hand a reusable
  workflow a service container (`services:` is not one of the keys GitHub accepts
  on a calling job). `TestTheDatabaseTierActuallyRan` fails the moment
  `TEST_DATABASE_URL` is absent, so making this step green from here would mean
  un-failing that test — the weakening kit forbids.
- `lint` runs golangci-lint, and this tree has no `.golangci.yml`, so it is the
  default set: 31 issues (errcheck 13, unused 9, staticcheck 6, ineffassign 3).
  With kit's config it is 83, so copying the config makes it redder, not greener.

The caller cannot even mark the job non-blocking: `continue-on-error` is not one
of the keys GitHub accepts on a job that calls a reusable workflow. **Require
`gate` in branch protection.** Delete the `ci` job when kit's Go job grows a
`services`/`env` seam, and not before on the strength of a green run.

`gate` is the job to read. Postgres 17.11 as a service, `goose up` as its own step
above the gate, `bin/prime` unmodified, and then the assertions: the database tier
**derived from the tree**, a floor on its PASS count, zero `--- SKIP:` lines, 23
named security tests that have to appear in the log by name, `go vet`, `gofmt -l`,
a `git diff --exit-code` on `go.mod`/`go.sum`, and a coverage floor. `MFA_ENCRYPTION_KEY`
is generated from `/dev/urandom` per run, masked, and printed nowhere.

The floors are decrease detectors, not targets: a green run means nothing was
deleted, skipped or excluded since they were measured. They are currently 1254
for the suite and 1166 for the tier, both measured from a complete run with the
tier applied.

`internal/platform/ci` is the test for that file. It parses no YAML — a YAML
dependency would move `go.mod`, and AGENTS.md's rule is that `go.mod` moves only
for a stated cause — and it is what catches the `uses:` path drifting back to a
directory GitHub cannot resolve, the `versions:` literal drifting away from
`go.mod`, migrations moving below the suite, the SKIP check disappearing, and a
named security test being renamed.

### The coverage floor, and what it is a percentage of

`gate`'s `coverage` step runs `bin/coverage-floor`, and this is the one number in
this repository whose denominator is a decision rather than a fact.

Go's `go tool cover -func` prints a `total:` over **every** block in the profile,
and it has no flag to leave a path out. `client/generated/api.gen.go` is 12,284
lines of committed oapi-codegen output with **3,001 statements and no test**, so it
drags module coverage from **73.6% to 44.6%** — measured, both ways, on this tree,
by `go test -count=1 -race -coverprofile=coverage.out ./...` against Postgres.

Two things that would have been one-line edits, and neither was taken:

- **Lowering the floor to 45.** A floor catches a *decrease*, and 70 was measured
  against hand-written code. Lowering it admits a real 29-point regression in
  hand-written code permanently, because the generated file's weight in the
  denominator never changes.
- **Adding tests to the generated code.** They would be deleted by the next
  `go generate`, so the coverage would not survive a week.

So `client/generated` is excluded, by a **declared** path in
[`coverage-exclusions`](coverage-exclusions) at the repository root:

```
excluded coverage client/generated files=1 lines=12284 coverage-fail-under=70 \
  reason="oapi-codegen v2.8.0 output …" owner=identity since=2026-09-30 until=2027-03-31
```

**Declared, never inferred.** The alternative — skipping any file whose header says
`// Code generated … DO NOT EDIT.` — fails toward *less* coverage: the header is
written by whichever generator ran, and one that stops writing it silently
un-excludes a quarter of the module while the floor stays at 70. An inferred
exclusion that fails toward *more* coverage is safe. One that fails toward less is
not.

**A directory, because the tool takes a package and not a file.** That is coarser
than the anchored regex the lint exclusion uses for the same file, and the
coarseness is paid for by
`TestTheCoverageExclusionIsOnlyGeneratedCode`, which enumerates every `.go` file
under `client/generated` and fails if one is not itself generated.
`client/` would be a perfectly legal declaration and it would exempt `baseurl.go`,
`credentials.go`, `errors.go`, `redact.go` and every test in the package.

**The entry must earn its place.** Reason, owner, `since`, `until`, the `files=`
and `lines=` it covers, and the floor — and **an entry matching nothing is a
failure** (kit's rule 4, from ESLint's `reportUnusedDisableDirectives`). The
`files=`/`lines=` fingerprint is what turns "a file appeared under the excluded
directory" into a red build instead of a silent change of denominator.

**The three facts are printed together, on a green run too.** `bin/coverage-floor`
emits the measured number, the excluded set with its reason and owner, and the
floor, in one block, before it compares them:

```
coverage 73.6% of 4628 statements, over the profile minus 2257 block(s) this file excludes
excluded — 1 declared entry/entries in coverage-exclusions:
  client/generated  files=1 lines=12284  owner=identity since=2026-09-30 until=2027-03-31
      reason: oapi-codegen v2.8.0 output for openapi/v1.yaml, …
floor 70%  (coverage-fail-under, restated here so the measured number, the excluded set and the floor are read together)
coverage 73.6% at or above the 70% floor
```

"coverage 73.6% (floor 70%)" on its own is decoration: a reader cannot tell 70% of
what. **No percentage is written into `ci.yml`**, which is why the one that used to
be there is gone rather than updated.

**The floor is still the floor.** `TestTheCoverageFilterCanFail` runs the real
script over twenty-two broken declarations and profiles, and includes a module at
**69.9%** (red) and one at **70.1%** (green), with the exclusion in place and
unchanged. It also includes **699 of 999 statements — 69.97%, which prints as
"70.0"** — and that one is red, because the comparison is
`covered * 100 < floor * total` in integers rather than against the printed number.
Go's own tool rounds the same way and kit's step compares the rounded value, so this
is stricter than the tool it replaces: that tool's job is to report and this one's is
to refuse. An exclusion that made coverage unrestrictable would fail that test.

**Where the mechanism lives, and the disagreement it leaves.** It lives here, not
in kit — identity's *enforcing* coverage step is its own, in `gate`, because kit's
`test` step runs with no database and dies before reaching a coverage step at all.
kit is untouched. The consequence, stated rather than hidden: kit's coverage step
computes `total:` over the whole profile and cannot be told about this declaration,
so `coverage-fail-under: '70'` is still passed to it and it would read 44.6%. That
input is left alone on purpose — 45 is the rejected option and 0 is a weakened gate
— and the threshold is checked in three places by
`TestTheCoverageFloorInTheDeclarationIsTheFloorsFloor`. The full reasoning is in
[DECISIONS.md](DECISIONS.md) D6.

**What is still open.** Generating the client into its own Go module, which makes
the boundary a compile-time fact rather than a config entry. It changes the import
path of a published client, so it waits; the signal is a second repository asking
for a generated client, and `until=2027-03-31` fails the build in the meantime.

## Migrations

goose SQL files in `migrations/`, numbered and annotated. `goose` is a CLI
tool, not a module dependency. `00001_init.sql` establishes the convention and
`00002`–`00004` create `users`, `sessions` and `outbox_events`, `00005`–`00008`
the tenancy and social-login tables (`00008`'s `connected_accounts` is defined and
unused — the social-login surface is not mounted, see "Not built yet"), `00009` the
OIDC ones, `00010` the four MFA
tables, and `00011` the `api_keys` table. Migrations are a deploy step, not a boot
step — see [migrations/README.md](migrations/README.md).

## Image

Multi-stage, `CGO_ENABLED=0`, `gcr.io/distroless/static-debian12:nonroot`. No
compiler and no shell in the shipped image:

```sh
docker build -t identity .
docker run --rm -p 8080:8080 identity
```

## Not built yet

Everything below is a later packet, and none of it is stubbed to look finished: the
admin API, and key rotation.

## Social login is not built, and the code that looks like it is

**There is no "Continue with Google" or "Continue with GitHub".** No route, no
handler, no use case, and nothing in either OpenAPI document. The path a social
callback would use is `/v1/auth/oauth/{provider}/callback`, built by
`Provider.RedirectURI` in `internal/oauth/provider.go` — and **nothing serves it.**
A product that integrates against it gets a `404`, a clean one from a router that
never had the route, rather than a `500` from a half-built flow. This section exists
because
`internal/oauth/` is a complete, well-tested package and a dead `connected_accounts`
table, and **a reader who opens the tree will reasonably conclude the feature
ships.** It does not, and the three places that used to say it did are now corrected
rather than deleted: the roadmap box is unchecked, the manifest's `description` no
longer names OAuth, and this paragraph is the record.

What exists, and what each piece is:

| Piece | State |
|---|---|
| `internal/oauth/state.go` | **Live.** `NewState`/`VerifyState` guard the OIDC login's round trip. |
| `internal/oauth/provider.go` | Written. Google and GitHub endpoint definitions, the configured-provider `Registry`, and `RedirectURI`. No route calls them. |
| `internal/oauth/client.go` | Written. The code-for-token exchange and the userinfo calls, with a real timeout and a response cap. |
| `internal/oauth/cipher.go` | Written. AES-256-GCM for the provider tokens, with a versioned prefix. |
| `internal/oauth/store.go` | Written and tested against a real database. `connected_accounts` — **nothing writes to it.** |
| `internal/oauth/settings.go` | Written and validating. **`internal/config` does not read it**; there is no `OAUTH_*` variable and no deployment can turn this on. |
| `migrations/00008_connected_accounts.sql` | Applied. The table and its `oauth_provider` enum exist and are empty. |
| `internal/httpapi/oauth.go` | **Does not exist.** It never has. |

The honest reading of that table is *written and unmounted*, not *half-built*: the
parts that are hard — the exchange, the state, the ciphertext format, the
uniqueness constraint, the provider-specific email resolution — are the parts that
are done. What is missing is the part that is a **product decision**, and it is the
reason this is a separate packet rather than a couple of hours of wiring.

### Four places said it shipped, and all four are now wrong in the other direction

The claim was not subtle. It was in the opening paragraph, in the roadmap, in
`cafaye.yml`'s `description`, and — implicitly, and worst of all — in a directory
of correct, well-tested, database-backed code. `internal/httpapi/openapi_drift_test.go`
could not see any of it, because **none of it is in a `paths:` block**: the OpenAPI
documents were honest the whole time, and a service can have a perfect contract and
still advertise an endpoint that does not exist.

So there is now a second check, `internal/httpapi/claims_test.go`, holding the
README's endpoint tables, the roadmap's checkboxes and the manifest's capability
list to the same router walk — **in both directions**. It found the manifest claim
and the roadmap claim by name on its first run, which is the evidence that it
would have found them before. `internal/httpapi/oauth_absent_test.go` is the
inverse: it asserts the surface is *still* not mounted, and **its failure message is
the work order** for whoever mounts it. Deleting that file is part of finishing the
work, because an absence test that outlives the absence is the repository lying to
itself in a file nobody reads.

### Why the remaining work is a decision and not a handler

A callback has to answer one question: *which user of this service is the person who
just came back from Google?* There are four answers and only some of them are
obvious. Jumpstart Pro — the parity baseline — makes all four explicit, and its
callback is the reference for the shape:

- the provider identity is already linked → sign that user in;
- someone is signed in and has not linked this provider → attach the link;
- **the provider returns an email that matches an existing user who has never linked
  this provider → refuse**, and send them to the password flow;
- the provider identity is new and no user holds the address → create the user.

The third is the one that matters, and it is a **product decision, not an
implementation detail**: refusing means a person who signed up with a password
cannot later use "Continue with Google" until they set a password, and permitting it
means an email assertion from a third party is enough to take over an account. The
wrong choice here is silent and permanent, and this service is the security
boundary.

Two more things have to be settled before any of it mounts, and both are recorded
because they are the kind of thing that is easiest to get subtly wrong:

- **The callback is cross-site browser navigation, and this service has none.** A
  social sign-in is a `302` out to a provider and a `302` back, and the failure path
  is half the feature — a person whose provider declined consent, or whose callback
  was rejected, has to be told something. Every surface here answers
  `application/problem+json` to a programmatic client, and the one exception is the
  OIDC login page. Where a social callback renders, and what it redirects to on
  failure, is a contract decision this repository has not made.
- **Google's `email_verified` is not read.** `internal/oauth/client.go` decodes
  `sub`, `email` and `name` from Google's userinfo and never checks
  `email_verified`, which that document carries and which exists precisely because
  an address from a provider is not by itself proof of ownership. GitHub's path is
  stricter already — `githubEmail` refuses an unverified address — so the two
  providers are not held to the same bar, and the weaker one is Google's. That has
  to be closed before a provider's address is ever allowed to match an existing
  `users.email`.

`connected_accounts` is left in place rather than dropped, and that is a decision
with a reason: an applied migration is not edited, the table is a correct and
carefully-constrained schema for the packet that will use it, and a `DROP TABLE` on
the security boundary to tidy up an unused table is a bigger intervention than
leaving it. What it must never be is *invisible* — and it is not, because this
section, the unchecked roadmap box, the manifest and
`TestTheSocialLoginSurfaceIsNotMounted` all say the same thing in four places.

Three things on the recovery surface are **not** here, and each is a decision rather
than an oversight:

- **No mail delivery.** The `Mailer` seam is one interface with two methods and
  `main` wires `Unavailable{}`, so every route that needs to send a message answers
  `503 service_unavailable` with a sentence naming the deployment problem. The flows
  are complete and tested over a recording double; the delivery path is courier's,
  and courier has not finished it. **A user who forgets a password today cannot
  recover**, because there is nowhere for the link to go — which is the honest state,
  and the alternative (a mailer that logs, so an operator can see it "worked") would
  put a live credential in a searchable log.
- **No registration-time verification mail.** `POST /v1/users` sends nothing and a
  client that wants an address proved calls `POST /v1/email-verifications`
  afterwards. Registration is the one request that must not start failing because a
  mail provider is unavailable, and the cost is one extra call in a product.
- **No sweeper for expired recovery tokens.** `recovery_tokens_expires_at_idx` is in
  the migration so the job is one statement when somebody wants it; in the meantime
  the read query filters on `expires_at`, so an unswept row is harmless.

**A single logout emits no event.** `identity.session.revoked` is declared and
emitted only where *every* credential the account holds is gone — a password reset
or an email change. `DELETE /v1/session` ends one session and announces nothing, so a
subscriber cannot tell "this person signed out" from "this person's credentials are
all gone". That gap is named rather than papered over by emitting the wrong type for
a single revocation.

Three things in the scoped-api-token area are specifically **not** here, and each
is a decision rather than an oversight:

- **No sweep revokes a user's api keys when MFA is enabled.** `sessions` is swept
  when a second factor goes on and off, and the argument for sweeping a token is
  stronger — a token is long-lived, named, visible in a settings page, and is
  exactly what an attacker with a stolen password would mint before the user
  notices. It is not wired because doing it **silently breaks a CI job**: the user
  turns on MFA and an unrelated service starts answering 401, with nothing in the
  MFA response saying why. Doing it honestly needs the count of what was revoked in
  that response, which changes a landed contract and belongs to whichever packet
  owns the MFA surface. The index is already there
  (`api_keys_user_idx`) and the one-statement sweep is written; the *decision* to
  call it is not made here.
- **No sweeper emits `identity.api_key.revoked` for an expiry.** core's catalog
  row says "A scoped API token is revoked or expired" and the expiry half of that
  has no producer: there is no job. `api_keys_expires_at_idx` is in the migration
  so the job is one statement when it lands, and an expired token is already
  refused on resolution.
- **No rotation endpoint and no reveal endpoint.** "Rotate" is revoke-then-mint,
  two requests, deliberately: a rotation endpoint that has to preserve the name
  would be a second spelling of the same security property. And there is nothing to
  reveal.

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
express would be a rule with a bypass in it.

## Roadmap

- [x] Skeleton: config, `/healthz`, `/readyz`, pgx pool, graceful shutdown
- [x] Migration convention, image, compose stack
- [x] Password auth, sessions, lockout
- [x] Error envelope, trace ids, panic recovery
- [x] Outbox: transactional events, SKIP LOCKED claim, publisher loop
- [x] Email verification, password reset, email change (flows complete; the mail
      delivery path is courier's and is not wired)
- [ ] OAuth (social login) — the provider client is written and unmounted; see
      [Not built yet](#not-built-yet)
- [x] Accounts, memberships, roles, invitations
- [x] OIDC provider (zitadel/oidc)
- [x] MFA: TOTP + recovery codes
- [x] Scoped API tokens (`cafaye_`-prefixed, four scopes, revocable, expiring)
- [ ] Admin API
- [x] Authorization matrix suite (route table × role × anonymous)

See [AGENTS.md](AGENTS.md) for the conventions this repository follows and
[CHANGELOG.md](CHANGELOG.md) for what has landed.
