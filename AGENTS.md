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
bin/prime              the gate: go mod download && go build ./... && go test ./...
```

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

**Stubs stay honest.** A packet that is not written yet is absent, not a
`not implemented` fake that looks finished. The README's "Not built yet" list is
the source of truth for what v0 does not claim. A method the library's interface
requires but this packet does not mount is still implemented correctly rather than
returning a plausible-looking success, because a fake is a lie waiting for the day
somebody mounts the endpoint.

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
4. If it needs a dependency, add a `Check` to the slice `newApp` builds — never a
   bespoke health path.
5. An account-scoped route goes in `registerTenancyRoutes` AND gets a row in
   `matrixEndpoints()`; `TestEveryRouteIsInTheMatrix` fails otherwise. The
   matrix's fixture names its accounts with a counter and not with the test path,
   because `accounts.Slugify` truncates at 63 characters and two long names that
   share a prefix become one slug.
6. `bin/prime`, `go vet ./...`, `gofmt -l .`.
