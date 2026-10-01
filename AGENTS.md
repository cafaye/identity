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
internal/telemetry/    OpenTelemetry: the allowlist, the exporter, and the install
internal/httpapi/telemetry.go  the request span, and the route TEMPLATE it records
migrations/            goose SQL files
client/                THE GO CLIENT: a generated transport and the hand-written wrapper
config/deploy.yml      the Kamal config, copied from kit's deploy.yml.erb. Its ONE
                       identity-specific change is healthcheck.path: /readyz, because
                       identity serves /healthz and /readyz and not kit's /up
config/kamal-backup.yml what identity backs up, where and for how long, copied from
                       kit's kamal-backup.yml.erb. Committed as a PAIR with
                       deploy.yml, and that pairing is the rule: the backup config is
                       read by nothing except deploy.yml's `backup` accessory, so a
                       file nobody references is the same defect one layer down — and
                       `kamal-backup validate` can only check their cross-file secret
                       contract with both present
kit.ref                the pinned kit commit the local stack comes from
bin/prime              the gate: go mod download && go build ./... && go test ./...
bin/migrate            migrations as a deploy step, for `bin/dev`
bin/dev                kit's, verbatim: fetch kit.ref, merge with our override, up
bin/coverage-floor     the coverage floor, over the profile minus coverage-exclusions
coverage-exclusions    DECLARED paths left out of that measurement: reason, owner, dates
gate.yml               WHAT THIS GATE IS WORTH, declared: the entrypoint, the proofs the
                       gate's own output must contain, and what the gate needs from the
                       machine. Checked by cafaye/core's harness/gate_check.py, NOT by
                       go test. Go prints no test count, so this file carries no
                       `minimum` floor and the decrease-detector is SUITE_FLOOR in
                       .github/workflows/ci.yml — read the report before changing it.
docker-compose.yml     an OVERRIDE on kit's stack: our service, our database, our
                       crash layer. No collector config, no postgres container of
                       our own, and no `depends_on: otel-collector`.
```

`client/` is deliberately NOT under `internal/`, and that is the only reason it is
where it is: `internal/` is by definition unimportable, and a client no consumer can
import is not a client. It is not reachable from `./cmd/identity` either, which is
what keeps the service's binary free of the client's dependencies — see
[DECISIONS.md](DECISIONS.md) D6 and `TestTheServiceBinaryDoesNotReachTheGeneratedClient`.

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

Two more have been approved since, with their cause stated here rather than
assumed: `go.opentelemetry.io/otel/sdk` and
`go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp` (v1.46.0).
Without them identity cannot emit a span, and kit's collector — which ships with
the stack and is what makes "where did that 500 come from" a question with an
answer — has nothing to receive. Note that grpc, the protobuf runtime and
grpc-gateway arrive **transitively**, through `otlpconfig`; that is a cost of the
HTTP exporter rather than a second transport we asked for, and the first draft of
this rule claimed otherwise and was wrong. What is deliberately **not** added:
`otelhttp`'s handler (it records `url.path`, `url.query` and headers as its own
attributes, so depending on the collector to strip them would make this boundary
one control where this repository insists on two — hence the hand-rolled
middleware), `otel/sdk/metric` (metrics come from kit's collector's `spanmetrics`
connector, which runs after redaction), and `otel/log` (logs come from the
container's stdout via compose `logging:`).

**One span-attribute allowlist, in `internal/telemetry`, and it is a choke point
rather than a convention.** Every attribute goes through `telemetry.Record/2`,
which drops anything not on the list, and the list is projected from
`core/schemas/telemetry/*.schema.json`. The realistic failure is not an attacker:
it is a well-meaning engineer in six months adding
`span.SetAttributes(attribute.String("email", user.Email))` because it would help
debug a login, in the service that holds every user's email and password digest.
`internal/telemetry/canary_test.go` is the proof — a canary in every field a
caller controls, asserted absent from everything exported — and every absence
assertion in it is paired with a presence one, because a boundary that deletes
everything passes "no canary" and is useless.

Three properties of the middleware are structural rather than lexical, and each
has a test that fails when it stops holding:

  * **`http.route` is chi's `RoutePattern()`, never `r.URL.Path`.** A template has
    one value per endpoint; a concrete path has one per request, and kit's
    collector derives metrics with a `spanmetrics` connector that mints a series
    per distinct value. The value is read from the `chi.RouteContext` **inside**
    the handler chain, because a middleware wrapped outside the router sees no
    route at all and a test that puts the assertion in the wrong place would pass
    against an empty string.
  * **A 404 carries NO route.** The path is caller-controlled text, so recording
    it is the cardinality bomb and the content leak in one move. The 404 status is
    the answer.
  * **Only 5xx is an error span.** A 401 or a 404 is identity refusing a caller,
    which is identity working; an error rate that counts it is a function of how
    much guessing the internet absorbs, and an alert on it pages somebody to turn
    off the protection doing its job.

No `tenant_id` on a span: it is a resource attribute, and
`internal/telemetry`'s tests hold the resource's own shape.

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

**A recovery link is configured PER PURPOSE, and a purpose with no template is a
refusal rather than a fallback.** `RECOVERY_LINK_TEMPLATE` is the *default* for
every purpose with no variable of its own; `PASSWORD_RESET_LINK_TEMPLATE` and
`EMAIL_VERIFICATION_LINK_TEMPLATE` override it. `internal/courier`'s
`RecoveryMailer` holds `LinkTemplates map[recovery.Purpose]LinkTemplate`, and
`NewRecoveryMailer` refuses to construct without one for **every purpose it can
deliver**.

The rule exists because of what happened when it did not. One template served four
messages, so a `welcome` mail's button said `https://app.example.com/reset?token=…`
and a user who clicked "Confirm your email address" landed on the password-reset
screen, where a verification token is a **404**. The token redeemed. The mail was
well-formed. **Every test in the repository was about the bytes, and the bytes were
correct** — which is why the whole failure was invisible until a real run found it
(identity-24). One template for two purposes is a template that must be wrong for one
of them.

Three properties, each with a check that fires:

- **A purpose with no template is REFUSED, never filled in from another purpose.**
  `resolveLinkTemplates` returns an error naming the purpose. Filling the gap is the
  defect, and it is the direction everything else here fails in: a mail that renders
  correctly and leads nowhere. Same rule as a route with no declared scope.
- **The key is `recovery.Purpose`, never a subject and never a courier
  `NotificationType`.** The purpose is what says which screen the link belongs on; a
  courier type would make that a fact about a delivery decision. And three closed
  sets have to agree — `linkPurposeFor`, `config`'s `linkTemplateVariables`, and
  `recovery.Purpose` — with nothing in the type system joining them, so
  `linkPurposeFor` is walked against the other two in both directions by
  `internal/courier/link_purpose_test.go`. **A fourth set, a fourth purpose, or a
  template for a purpose nothing delivers, is a completeness obligation on whoever
  writes it**, exactly like a struct literal that configures a check.
- **`ValidateLinkTemplate`'s three refusals apply per purpose, not once.** They were
  applied once because there was one template; there are two now.

**Nothing about a URL says which screen it opens, so the check reads the rendered
link and redeems what is in it.** `TestAVerificationLinkIsNotThePasswordResetLinkAndEachRedeemsAtItsOwnEndpoint`
builds the mailer from a `config.Load` of an **environment** rather than a Go
literal — a relationship between two links cannot be tested by something that cannot
express it — and asserts the two rendered links differ in **path**, and that each
purpose's token, read back out of the URL, is accepted by its own endpoint and
refused by the other. Its **negative control** is that one template really does
render one link for both messages, so the inequality is a comparison rather than a
tautology; and the inequality was shown to fire by injecting the real defect.

**The backwards-compatible default is announced, never silent.** `RECOVERY_LINK_TEMPLATE`
is honoured so no deployment breaks at boot (DECISIONS.md D8), which means an
unmigrated deployment's verification link still points wherever its one template
says. `buildMailer` therefore **warns on startup** when any purpose resolves to the
shared default, naming the purpose and the variable that would give it a link of its
own — because nothing else in the process can see it: the send succeeds, the token
redeems at its own endpoint, every test is green, and the reader is the only one who
finds out. **If you add a purpose, add it to that warning's inputs; do not let a new
purpose silently inherit the default.**

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

**The two deployment config files are ONE contract, and the commit that matters
is the one that only one of them is in.** `config/kamal-backup.yml` names its
credentials as `{ secret: NAME }`; `config/deploy.yml`'s `backup` accessory
carries an `env.secret` list, and kamal-backup builds that accessory's
environment from that list **and from nothing else**. So a secret named in the
backup config and missing from the accessory is valid YAML in both files, each
internally consistent, and a deployment that fails validation with both files
reading correctly in review. `kamal-backup validate` is the tool that catches
it, and it is **not in this repository's gate** — so
`internal/platform/ci/backup_config_test.go` asserts the same contract on every
commit, in the direction that fails loudly: every secret the backup config names
is declared by the accessory. An accessory may declare a secret the backup config
does not use; that is not a failure, and the test says so rather than comparing
as sets.

Four properties of that pair are checks and not comments, and each has been shown
to fire by injecting the fault it catches rather than by being assumed to bite:
the secret contract, the `files:` mount (`config/kamal-backup.yml` into the
accessory — an accessory that does not mount the file schedules backups against
a config it cannot read), `app:` naming `identity` (a mismatch writes snapshots
under one path and looks for them under another, which restic does not report as
an error because restic tracks by path), and the schedule agreeing with the
data-loss window README.md states. **That last one exists because "24 hours" is
a promise made to a customer**: shorten `backup.schedule` to `6h` and leave the
README alone and the test fails in the direction where the README is claiming
more loss than actually occurs.

**A committed config is a specification until somebody boots it.** Neither file
says a backup has been taken, and neither claims one has. The R2 bucket must
exist before the first backup — `init_if_missing: true` initialises the
*repository* inside a bucket you created — six secrets must be in
`.kamal/secrets`, and nobody has run a drill here. README.md § "Backups" states
that in the place an operator reads, and the runbook in `cafaye/docs` is the
procedure. **The template is copied, so a kit bump means re-copying and
re-applying identity's one change** (`healthcheck.path: /readyz`, because
identity does not serve kit's `/up`); both files say which kit ref they came
from.

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
The cost of that choice is recorded in [DECISIONS.md](DECISIONS.md) D6: three extra
modules in `go.mod` and a coverage number that moves.

**The generated code is also excluded from the coverage floor — declared, and
coarser than the lint one.** `coverage-exclusions` at the repository root declares
`client/generated`; `bin/coverage-floor` reads it, filters the profile, and compares
what is left against `COVERAGE_FAIL_UNDER`. Three rules are not negotiable here:

- **It is DECLARED, never inferred.** An exclusion derived from a
  `// Code generated … DO NOT EDIT.` header fails toward LESS coverage — a generator
  that stops writing the header silently un-excludes a quarter of the module while the
  floor stays at 70. An inferred exclusion that fails toward MORE coverage is safe;
  one that fails toward less is not, so the path is written down and reviewed.
- **It is a DIRECTORY, because Go's coverage step takes a package pattern and not a
  file.** That makes it coarser than the anchored regex above, and the coarseness is
  paid for by `TestTheCoverageExclusionIsOnlyGeneratedCode`: it enumerates every `.go`
  file under the excluded directory and fails if one is not itself generated.
  **`client/` would be a legal declaration and it would exempt `baseurl.go`,
  `credentials.go`, `errors.go`, `redact.go` and every test in the package** — code a
  reviewer is responsible for, in exchange for exempting code nobody is.
- **The floor did not move, and no test was added to the generated code.** A test
  written against `api.gen.go` is deleted by the next `go generate`. A floor is a
  decrease detector, and 70 was measured against hand-written code; lowering it to
  the number a generated file produces admits a real regression permanently, because
  the generated code's weight in the denominator never changes.

The entry carries a **reason, an owner, a `since`, an `until`, the `files=` and
`lines=` it covers, and the floor**, and **an entry matching nothing is a failure**
(kit's rule 4, ESLint's `reportUnusedDisableDirectives`). `files=`/`lines=` are what
make a change of the excluded set a red build rather than a silent change of
denominator. `bin/coverage-floor` prints the measured number, the excluded set and
the floor in one block on every run, **including a green one** — "coverage 73.6%
(floor 70%)" on its own is decoration, and a reader cannot tell 70% of what.

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

**A claim is only as good as the check that holds it to the router, and the
router walk every check reads is a shared mutable thing.** `servedRoutes` walks the
chi tree `newMux` assembles, and `newMux` records the pattern list it built into a
package variable for the observability canary. That variable is **mutex-guarded,
and the guard is load-bearing rather than tidiness**: unguarded, `go test -race`
reports a WRITE/WRITE from two parallel subtests both building a router, and the
failures are whichever tests happen to be running — **52 to 64 failing tests on a
clean checkout, varying between runs.** `TestTheClaimWalkSeesEveryConditionalSurface`
and `TestServedRoutesAndTheClaimWalkAgree` in `internal/httpapi/claims_faults_test.go`
assert the walk can SEE a route per conditional surface rather than that a field was
set, and `TestEveryClaimCheckFailsOnAnInjectedRoute` asserts the claim checks go red
on a route that does not exist — because a comparison that never fires is
indistinguishable from a correct one. Readers of `routeTable` go through
`recordedRouteTable`, which copies under the lock, because a slice returned under a
read lock still shares its backing array.

## Gates

```sh
bin/prime          # go mod download && go build ./... && go test ./...
go vet ./...
gofmt -l .         # must print nothing
go test -race ./...
```

All four before a commit lands. `bin/prime` is the kit Go template; if kit
changes it, follow kit.

**The coverage floor is not one of the four, and it is not `bin/prime`'s job.**
`bin/coverage-floor <profile>` is what enforces it, and it is only run in CI
because it needs a profile, which needs the whole suite with a database applied.
Running it locally is the way to see what the number is over before you commit:

```sh
go test -count=1 -coverprofile=/tmp/cov.out ./...
bin/coverage-floor /tmp/cov.out
```

**Never lower the floor to make it pass, and never add a test to generated code
to raise it.** `internal/platform/ci/coverage_exclusions_test.go` drives
`bin/coverage-floor` through twenty-two deliberately broken declarations and
profiles — including 69.9%, which is red, and 70.1%, which is green — so the floor
is known to bite rather than assumed to.

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

**A new route gets rows in BOTH documents and both walks, and the second one is
the one that bites.** A route is not finished when it is documented and gated: it
is finished when `servedRoutes` and `mountedAccountRoutes` both *see* it, and
those two are `options` struct literals listing a double per conditional surface.
A field left out of either is invisible, and the consequence is that the check
goes green by not checking — which happened here once, to
`TestEveryServedRouteIsDocumentedOrNamed` itself, while three undocumented
operations were mounted. `internal/httpapi/router_walk_test.go` holds it:
`TestEveryConditionalSurfaceIsVisibleToTheWalk` lists every surface field whose
absence can make a registrar skip its routes, and
`TestTheDriftWalkSeesTheAdminSurface` / `TestTheMatrixWalkSeesTheAdminSurface`
assert the walks actually find the routes rather than that a field was set.
**Treat a struct literal that configures a check as a completeness obligation**,
because nothing about it looks like one.

## The admin surface

Three routes, one sentence, and the reasoning is in
[DECISIONS.md](DECISIONS.md) D2–D5. What belongs in this file is the rule a
future packet could break without noticing.

**The privilege boundary is one sentence, and the code says exactly it.** An
account admin may revoke pending invitations to their own account and read that
account's admin audit log — authority over other people's pending access, and
nothing else. It is a sentence rather than a paragraph because a role checked in
thirty places is a role that will be checked in twenty-nine of them. The three
rows in `accountRouteScopes` ARE the boundary: there is no fourth without a new
scope in `internal/apikeys`, which is a file whose whole argument is that a token
is granted exactly what it names.

**No admin route is reachable with a user session, and the refusal is per route.**
`requireAdminToken` runs OUTSIDE `requireAccountRole`, which is what makes it a
property of the surface rather than of the handlers. A session is refused with
403 — the caller is authenticated, so 401 would send a client hunting a login
problem that does not exist. A token is not merely permitted here, it is the
*point*: every action is recorded against the api key's **row id**, so a token is
something an audit record can name and a session is not. This is the mirror of
`sessionCredentialOnly`, and the two together mean no route is reachable by both
kinds of credential unless somebody wrote that down deliberately.

**A mutation and its audit record are in one transaction, and there is no way to
express the first without the second.** `admin.Service` has no exported method
that mutates without recording: `Audited` takes the mutation as a callback and
runs it inside the transaction that writes the record. Adding an admin action
that skips it needs a new exported method, which is a review-visible change. The
proofs are negative and both directions matter — a failing audit write rolls the
mutation back, and a failing mutation leaves no record — because a service that
rolled back everything would pass a happy-path test perfectly.

**The audit record's immutability is in the DATABASE.** `GET` is the only method
mounted on the path, the store has `Append` and `List` and nothing else, and the
table refuses `UPDATE` and `DELETE` with a trigger. The third is the one that
settles it: the first two only describe *this codebase*, and a repair script, a
`psql` session or a future packet all bypass Go. The table also has **no foreign
key to `accounts`**, deliberately — a cascade is a `DELETE`, and the shortest
route from "an admin did something questionable" to "there is no record of it"
must not be one request.

**A bulk operation does not get the single operation's shape.** The bulk
revocation needs `confirm: true` **in the body**, a named array, and an owner
where the single one needs none of those and an admin. `confirm` is in the body
rather than the query string so that the request which performs the operation and
the one describing it are the same bytes. Both `requested` and `revoked` come
back, because `revoked` is frequently smaller and a client that cannot tell the
two cases apart reports a completed task over an incident.

**A bound that is refused beats a bound that is clamped.** Over the ceiling is a
422, never a silent truncation: a client that asked for 500 rows and received 100
has been told a lie about how much trail it has read. The audit trail's page
cursor is **opaque and carries `(occurred_at, id)` together** — a timestamp-only
cursor silently drops records sharing the boundary instant, which the service's
own clock makes the normal case, and which this repository's test found.

**An audit record names a credential; it never carries one.** `Actor` has the
api key's row id and the owner's user id, and there is no field in `internal/admin`
that a token could be written into.
`TestNothingOnThisSurfaceCanRecordAToken` reflects over the types that reach the
table, because `apikeys.Key` has a `TokenDigest` field a handler holds and an
audit log is exactly where a `%+v` of it ends up. A test asserting "we did not log
a token" is unfalsifiable; that one is not.

**The authorization matrix has a real hole on this surface and it is named, not
papered over.** Its six columns are six *sessions*, so on a token-only surface
every column is a 403 and the matrix carries no positive cell for these three
routes. The rows are in the matrix anyway so `TestEveryRouteIsInTheMatrix` still
demands them, and the token/session axis is covered by
`TestNoAdminRouteIsReachableWithASessionAlone`,
`TestAnAdminTokenHoldingNeitherScopeIsRefused` and `TestTheBulkRouteIsOwnerOnly`.
The anonymous column is `403` here rather than `401` on every other row, because
`requireAdminToken` runs first — which is also why `expectedStatus` consults a
row's `expect` override BEFORE its authentication check.
