# AGENTS.md

Conventions for `identity`, the cafaye security boundary. Read this before
changing anything; the house rules in `moon/PLAN.md` §1 and §3 apply on top of it.

## What this repository is

`module github.com/cafaye/identity`, Go >= 1.25, one static binary. It owns auth,
sessions, MFA, OAuth, accounts and tenancy, and OIDC — it is what every other
cafaye service asks to identify a caller. The contracts are owned by
`cafaye/core`; CI and lint config come from `cafaye/kit`. Neither lives here.

Because this is the security boundary, `PLAN.md` §3 applies a higher bar here:
TDD throughout, an authorization matrix suite (route table × role × anonymous)
before the phase closes, and a security checklist reviewed by the user. That
suite does not exist yet — it arrives with the auth packets.

## Layout

```
cmd/identity/main.go   thin entrypoint: load config, build the app, serve, drain on SIGTERM
internal/config/       environment in, validated Config out
internal/httpapi/      the router, the probes, the /v1 surface and the OIDC routes
internal/oidc/         the OpenID Connect provider: storage, registrations, the key
internal/platform/db/  the pgx pool, and the readiness ping
migrations/            goose SQL files
client/                THE GO CLIENT: a generated transport and the hand-written wrapper
bin/prime              the gate: go mod download && go build ./... && go test ./...
```

`client/` is deliberately NOT under `internal/`, and that is the only reason it is
where it is: `internal/` is by definition unimportable, and a client no consumer can
import is not a client. It is not reachable from `./cmd/identity` either, which is
what keeps the service's binary free of the client's dependencies — see
[DECISIONS.md](DECISIONS.md) D2 and `TestTheServiceBinaryDoesNotReachTheGeneratedClient`.

`cmd/` + `internal/` is the layout from `refs/goreleaser`. `main` owns nothing
but process lifetime; the pieces it does own — the socket, the drain, the signal
handling — live in an `app` type the tests drive directly, because a signal path
is not worth testing through a mock.

`internal/platform/` is where infrastructure that is not a cafaye concept goes.
If a package is a cafaye concept (accounts, sessions, OIDC), it sits at
`internal/<concept>/`. Do not create a new platform package per dependency; one
per substrate.

## Rules

**Tests first.** Write the table, watch it fail, then implement until green
(PLAN.md §3). Every handler change needs an httptest case asserting the status
code *and* the JSON shape — `/readyz` returning 200 with the wrong body is a
failure, not a pass.

**Table-driven, in the same package.** Tests are `package <pkg>`, so they reach
unexported machinery. Prefer a table with a `name` field over a sequence of
asserts.

**No globals, no init-time state.** Configuration is read once by `config.Load`
and threaded as a value. `main` is the only place that reads the environment and
installs a logger. `config.Load` takes a `Lookup` so tests never mutate the
process environment.

**Invalid config is an error, not a fallback.** A variable that is present but
unparseable fails startup with a wrapped sentinel (`ErrInvalidPort`,
`ErrInvalidLogLevel`, `ErrInvalidDatabaseURL`) matched by `errors.Is`. Silently
defaulting a typo is how a service ends up listening on the wrong port in
production. The one exception is *absent*, which is a supported state: an unset
`DATABASE_URL` means no pool and no readiness dependency.

**Liveness never touches a dependency.** `/healthz` is unconditional. A database
outage must not get the process restarted out from under in-flight work; that is
`/readyz`'s job. Keep the split.

**Probe failures are logged, never returned.** `/readyz` reports which
dependencies failed by name; the underlying error goes to the log. An
unauthenticated request must not be a way to learn that a database host is
`10.0.0.5` or that a password was rejected. Every probe is bounded
(`DefaultReadinessTimeout`), and a panicking dependency is a failed probe, not a
dead process.

**The pool is lazy.** `db.Open` parses and constructs but does not dial, so a
database that is down at startup shows up as a failing readiness probe instead of
a crash loop. Do not add a `Ping` inside `Open`.

**Migrations are a deploy step, not a boot step.** The service never migrates
itself. Never edit an applied migration; write a new one. Every migration needs
a `Down`, or a comment saying why it cannot be reversed. The rules and the
dev/prod commands are in [migrations/README.md](migrations/README.md).

**`cafaye.yml` is a draft.** The schema belongs to `cafaye/core` and is still in
flight. Fields marked `# GUESS` in that file are a reconciliation list, not
precedent — when core freezes the manifest, `caf init` regenerates the file and
guessed fields are dropped, not migrated.

**Deps are the ones with a stated cause, plus nothing.** `chi` for routing,
`pgx` for Postgres, `argon2id` for password hashing, `zitadel/oidc` for the
OpenID Connect provider, with reasoning in
[README.md](README.md#dependencies). `go-jose/v4` is an exception that is not a
choice: `op.SigningKey` returns a `jose.SignatureAlgorithm` and `op.Key.Key()`
holds a `jose` key, so the library's storage interface cannot be implemented
without it. Logging is `log/slog`. No zap, no logrus, no ORM, no CLI framework, no
dependency without a cause stated in review. `go mod tidy` must leave `go.mod` and
`go.sum` unchanged.

**The OIDC surface has two error shapes, and the split is not a detail.**
`/v1/*` and the `/oidc/authorize` pre-checks answer
`application/problem+json`; everything else under `/oidc/*` answers RFC 6749's
`{"error": …}` and nothing else. An off-the-shelf OIDC client library cannot
parse a problem document, and interop with one is the entire point of the
surface. The same reason there are two OpenAPI documents: core puts every path
under one `/v1` prefix and RFC 8414 fixes discovery at
`/.well-known/openid-configuration`. A handler under `/oidc/*` that reaches for
`problemFor` is a bug unless it is the login page or one of the four
pre-checks.

**A protocol decision the library already makes is delegated, not restated.**
`internal/oidc` implements `op.Storage` and `op.Client` and owns the data; it does
not re-implement PKCE verification, redirect-URI matching, the code response or
the id_token. Where this service disagrees with the library's default, the
disagreement is a refusal with a reason at its own definition — `requireS256`,
the absence of `op.HasRedirectGlobs`, the narrowing in `Provider.discovery` — not
a branch inside a handler.

**Redirect URIs are matched exactly, always.** Nothing in this service implements
`op.HasRedirectGlobs`, and the registration validator refuses a wildcard, so a
`redirect_uri` can only ever be matched by equality. A prefix comparison turns
this service into an open redirector for every product registered on it, and
`TestOIDCRedirectURINotOnTheAllowList` is the test that holds the line.

**One signing key, and it is configured.** `OIDC_SIGNING_KEY` is read from the
environment and never generated. A key generated at boot publishes a document no
caching verifier has seen, and two processes behind a load balancer would each
publish a different one. The library's 32-byte token-encryption key is DERIVED
from it with a domain-separated SHA-256 rather than configured separately — it is
one secret to rotate, and it is genuinely used, because the userinfo handler
decrypts an access token before it verifies one.

**There are three credentials, and the prefix is how two of them are told apart.**
A session token and a scoped api key are both opaque bearer values, and
`apikeys.Prefix` decides which table a presented value is looked up in before any
query runs. Nothing else may: not a length, not a character class, not a "does it
look like a JWT" check. A credential's shape is a public fact, and the whole
security property is that a value of the wrong kind never reaches the wrong index.

**A token carries a scope set, never a role.** There is no `role` column on
`api_keys` and there must not be one. A role on a token is a permission that goes
stale, and a stale permission is the thing this table exists to avoid — so the
resolution query inner-joins `account_users` and re-reads the role on every
request. A second place that could *store* authority is a second thing to get
stale, and the sweep in `accounts.Service.RemoveMember` exists precisely because
re-evaluation alone lets a re-invitation resurrect a credential: the join is
satisfied again. If you add a column that would let a token answer "what may I do"
without a membership read, the packet's reason has been undone.

**A route with no declared scope is closed to tokens.** The scope table in
`internal/httpapi/accounts.go` is keyed by the chi pattern, `scopeRequiredBy`
returns `""` for a route that is not in it, and `Allows("")` is false for every
granted set. So a new account route is unreachable by a machine credential on the
day it lands rather than the day somebody notices it was never gated. The failure
direction is the whole point: a route that needs a scope and does not have one is
closed, never open.

**`accountRouteScopes` is the only scope table, and the OpenAPI document is its
mirror.** Two lists that have to agree, because a scope that gates a route nobody
documented is invisible to a generated client and a scope documented on a route
that does not gate it is a promise this service does not keep. Both directions are
walked by a test in `internal/httpapi`.

**The documents are held to the router, in both directions, by method AND path.**
`internal/httpapi/openapi_drift_test.go` is the check, and it is the last one
missing in the fleet. Three things about it are not negotiable:

- **The method is read from chi's own walk of the tree `New` assembles, never
  inferred from a path.** billing's first drift check compared paths and never
  `route.verb`, so `PUT /v1/customers/{id}` was served in a money-handling
  service and written down nowhere — one path on each side, and the comparison
  reported agreement. **This repository has that bug already**, in the shape of
  `POST /oidc/authorize` and `POST /oidc/userinfo`, and the check is what finds
  it. If you find yourself deriving a method from a path, you are writing the
  check that already failed once.
- **The comparison is over sets, never over counts.** One operation added and one
  removed leaves the count alone and is a completely ordinary way for a document
  to drift.
- **There is no prefix filter, and `knownDrift` is not an exclusion list.** Every
  route is either in a document or in `knownDrift`, and
  `TestEveryServedRouteIsDocumentedOrNamed` fails on anything that is neither —
  without that check the list is where the next forgotten route goes, and the
  tripwire becomes decoration. `knownDrift` is pinned at its exact contents: it
  **cannot grow** (that is how a check gets made green by not checking) and
  **cannot be emptied** (that is somebody deleting the list instead of fixing the
  routes). Shrinking it is the only legal change, and it happens by documenting
  an operation. It currently holds twelve routes and is open as D1 in
  [DECISIONS.md](DECISIONS.md).

The check reads **both** documents and treats the union as the contract. That is
not tidiness: nine of the eleven `/oidc/*` and `/.well-known/*` routes are
documented, in `openid/openid.yaml`, so a check reading only `openapi/v1.yaml`
would have to declare all eleven "not client operations" — false about nine of
them, and a list of omissions is where a false claim does the most damage.

**A document is read by a reader that refuses rather than under-reads, and the
reader has no YAML dependency behind it.** `go.mod` has none and this stays true:
a library already in the module graph as a *transitive* dependency of
`zitadel/schema` would become this service's direct requirement, with its
versions and its CVEs, for the sake of forty lines of structure. So
`openapi_reader_test.go` reads the `paths:` block by indentation, states the
subset it understands, and turns every way it could come back with less than it
should — no `paths:`, an empty block, a path item with no operation, two
operations that normalise onto one, a missing file — into an error. **A reader
that finds nothing agrees with another reader that finds nothing, and that is how
a check over nothing goes green.** A new test in that file is a test of the
rule the reader applies, not of a document.

**Stubs stay honest.** A packet that is not written yet is absent, not a
`not implemented` fake that looks finished. The README's "Not built yet" list is
the source of truth for what v0 does not claim. A method the library's interface
requires but this packet does not mount is still implemented correctly rather than
returning a plausible-looking success, because a fake is a lie waiting for the day
somebody mounts the endpoint. **A tested but unwired method is the same lie from
the other side** — and this repository had one: an `apikeys.Store` sweep for
"revoke everything this user holds", with a test, for an MFA sweep this service
does not perform. It was deleted rather than left, because an unwired method is an
invitation to wire it without reading why it was not wired, and the honest state
for "we decided not to do this" is a paragraph in the README and no code.

**The generated client is committed, and regeneration is a gate rather than a
suggestion.** `client/generated/api.gen.go` is oapi-codegen v2.8.0's output and it is
in the tree, because **a generated file that is not committed cannot be reviewed, and
a diff nobody reads is a change nobody notices.** The generator's version is pinned in
`client/generate.go`, so the file is reproducible without being built in CI.

Two consequences, both of which are load-bearing:

- **`TestTheCommittedGeneratedFileIsWhatThePinnedGeneratorProduces` runs the real
  generator, over the real document, into a temporary directory, and compares.** It
  is a TEMP directory rather than a regenerate-in-place `git diff` because the second
  destroys the evidence: a regenerate-in-place failure leaves the tree modified, so
  the next run passes and the failure is visible exactly once.
- **The generated file is excluded from lint, narrowly and with the exclusion under
  test.** `.golangci.yml` exempts `^client/generated/api\.gen\.go$` and nothing else,
  because the file is not hand-written code and holding it to hand-written standards
  measures the generator rather than this repository.
  `TestTheLintExclusionIsOneFileAndNotAPrefix` walks every `.go` file in the tree and
  fails if the pattern matches one of them — a broad exclusion is how a real file
  stops being linted, and the comment in that config is not a control.

**The client is inside this module so that it is gated.** It is not a separate module
because a nested module is excluded from `./...`, and `bin/prime` runs `go build
./... && go test ./...` — a client in its own module would be built by nothing and
tested by nothing, which is the failure mode this repository treats as a false claim.
The cost of that choice is recorded in [DECISIONS.md](DECISIONS.md) D2: three extra
modules in `go.mod` and a coverage number that moves.

**A credential must reach no string a human reads, and that is structural.** The
client holds the token for its whole life and `err.Error()` is the single most likely
thing in a process to end up in a log. So the rule is not care: every string the
client builds out of anything a caller or a service supplied goes through
`Redactor.String`, redaction is **all or nothing**, and the credential lives inside
**closures** rather than in struct fields — because `fmt` prints an exported field by
value under `%#v` and that verb does not consult `String()`, so a `token string` field
is a leak no method can intercept. `TestTheClientNeverPrintsACredential` drives a real
request against an `httptest.Server` that echoes the credential back in its body and
three of its headers, then sweeps `%v`, `%+v`, `%#v`, `%s`, `%q`, the reflected
fields and the serialised form.

**An unknown problem code is a typed error, never a silent one.** Every non-2xx from
this service is `application/problem+json`, and `code` is the contract while `status`
is advisory. A code this build has never seen produces `*UnknownProblemError`, carrying
the code, the status and the trace id — so `errors.As(err, &ProblemError)` works
against every code including ones identity has not documented yet, which it already has
four of. `ProblemError` is an INTERFACE and not a base struct for a concrete reason
recorded in `client/errors.go`: `errors.As` matches on assignability, and embedding
does not create one, so a hierarchy of structs would make the single catch work only
for the codes this build does not know — exactly backwards.

**Comments say why.** Explain the decision and the constraint, not the
mechanism. A comment restating the line below it is noise.

## Tests that need infrastructure

**`go test ./...` is red on a machine with no Postgres, and that is the design.**
`internal/mfa`'s `TestTheDatabaseTierActuallyRan` FAILS rather than skips when
`TEST_DATABASE_URL` is unset. Every test in that file is a database test, so
without the variable the file has proven nothing, and a suite that reports `ok`
has reported something false.

```sh
docker compose up -d --wait postgres
goose -dir migrations postgres "$DATABASE_URL" up
TEST_DATABASE_URL="postgres://identity:identity@localhost:5432/identity?sslmode=disable" go test ./...
```

`goose up` is a deploy step and is above the suite, never in the same command: a
suite run against an unmigrated database fails with
`relation "public.users" does not exist`, which is loud but reads like a code
failure rather than a broken pipeline.

A skip is honest; a test that silently passes without proving anything is not.
CI closes the second half of that — `.github/workflows/ci.yml` derives the tier
from the tree, fails on any `--- SKIP:` line, and holds a floor on the PASS count
so a deleted test is visible.

## Gates

```sh
bin/prime          # go mod download && go build ./... && go test ./...
go vet ./...
gofmt -l .         # must print nothing
go test -race ./...
```

All four before a commit lands. `bin/prime` is the kit Go template; if kit
changes it, follow kit.

CI runs the same four, in the same order, plus `goose up` above them — see
[`.github/workflows/ci.yml`](.github/workflows/ci.yml). A CI-only variant of
`bin/prime` would be a second gate, and a second gate is a second thing to be
wrong. `internal/platform/ci` is what keeps the two honest: it asserts that the
workflow really runs `bin/prime`, that the migrations really run before it, that
the toolchain pin matches `go.mod`, and that no secret is written down.

## Adding an endpoint

1. `internal/httpapi/` — the handler, the route, and JSON through `writeJSON`.
2. Tests first: status code, JSON shape, `Content-Type`, and the anonymous case.
3. Add the row to the README endpoint table, and to `openapi/v1.yaml` or
   `openid/openid.yaml` depending on which surface it is on. Both validate
   against OpenAPI 3.1 and `caf contract lint` validates the manifest.
   **The document entry is not optional and not a follow-up**:
   `TestEveryServedRouteIsDocumentedOrNamed` reads the route out of the router
   and fails when no document describes it, so a handler merged without its
   document entry does not go green — and `TestEveryOperationHasAnOperationId`
   fails if you forget the `operationId`, which is the name of the method on
   every generated client in the fleet. If the operation is genuinely not
   contract surface, that is a decision to record in the document and the
   README, not a route to drop into a list.
4. If it needs a dependency, add a `Check` to the slice `newApp` builds — never a
   bespoke health path.
5. An account-scoped route goes in `registerTenancyRoutes` AND gets a row in
   `matrixEndpoints()` AND a row in `accountRouteScopes` **if a token may reach
   it**. `TestEveryRouteIsInTheMatrix` and `TestEveryAccountRouteDeclaresItsScope`
   fail otherwise. A route with no scope row is closed to tokens, which is the safe
   direction, so "I did not add a row" is a decision and not an oversight. The
   matrix's fixture names its accounts with a counter and not with the test path,
   because `accounts.Slugify` truncates at 63 characters and two long names that
   share a prefix become one slug.
6. `bin/prime`, `go vet ./...`, `gofmt -l .`, `go test -race ./...`.
