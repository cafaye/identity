# Changelog

All notable changes to identity are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security (packet identity-16-d5)

- **`/oidc/login/{requestID}` no longer completes an authorization request for a
  browser that did not start it.** The silent sign-in path answered any request
  that carried a live session cookie, so the only thing standing between "the
  browser this flow was handed to" and "any browser signed in as the same user"
  was the request id being unguessable — and a uuid in a URL is not a secret in
  any way a user-agent boundary respects. Anyone who could get a signed-in
  user's browser to make a top-level `GET` of a login URL they chose (a link, an
  `<img>`, a redirect) had that browser complete the request with no interaction
  at all, and the code was redirected to the `redirect_uri` of the client that
  chose it. The attacker holds that client's secret and its PKCE verifier, so
  they exchange it and hold an `id_token` whose subject is the victim.
  `state` does not help here: state is the *client's* CSRF defence against the
  client's own callback, and in this attack the attacker is the client.
  `prompt=login` and `max_age` — the two levers a client has for demanding
  interaction — were both refused by `checkAuthorizeParams`, so there was
  nothing else to fall back on.

  The fix is a `__Host-oidc-flow` cookie set at `handleOIDCAuthorize`, which is
  the only point where the start of a flow is observable; the login page requires
  it before completing anything. `__Host-` is what makes it unforgeable from
  another origin. Two red proofs in
  `internal/httpapi/oidc_browser_binding_test.go`, one asserting the request is
  not completed without the cookie and one driving the whole attack end to end
  with two different users in it.

  The honest limit: the request id is still a bearer capability for *rendering a
  form* — an attacker can still show a victim a login page for the attacker's own
  client. What they cannot do is have the victim's existing session sign it
  without the victim seeing anything, which is the part that was silently
  crossing an account boundary. Consent remains absent by design
  (`openid/openid.yaml`, `README.md`); this closes the session-riding half.

### Fixed (packet identity-14-rename)

- **`core: ^0.1.0` → `^0.2.0`, and it is the whole of what the contract checker
  had to say about this service's version.** The bump and the rename travel in
  one commit because core 0.2.0's changelog requires it, and a rename that left
  the range at `^0.1.0` would be a rename nobody is allowed to ship. Before it,
  `harness/bin/cafaye-contract` reported `core.constraint-unmet`: core publishes
  0.2.0 and this service declared a range that does not contain it. After it,
  that finding is gone. Nothing about this service's behaviour changed — it has
  published three-segment, service-prefixed event types from the beginning, so
  the declaration was the stale half, not the code.

- **The two-segment `account.created` is gone from the repository, and it was
  never a published type.** The packet for this work said identity "publishes
  `account.created`, two segments, the forbidden form". It does not, and it
  never did: all twelve published event types in `internal/outbox` are
  three-segment and carry the `identity.` prefix, and `core`'s own
  `REPORT-core-17.md` measured and reported the same thing before this packet
  started. The bare string survived only in prose — two comments and the short
  labels of one test's map — and those are now written in the three-segment
  form, so `grep '\baccount\.created\b'` over the tree returns nothing outside a
  qualified `identity.account.created`.

- **`exposes.events` is checked against what the code emits, which no core rule
  does.** Every rule in core's `harness/rules.json` reads a declaration; none
  reads a service's source. So an event the code emits and the manifest never
  names is invisible to all of them at once — and in this repository five are:
  `identity.account.created`, `identity.member.invited`, `identity.member.accepted`,
  `identity.member.role_changed` and `identity.member.removed`, all emitted from
  `internal/accounts/service.go` and declared nowhere.
  `TestTheManifestDeclaresEveryEmittedEvent` compares the two as sets, which is
  how a single declare-and-drop pair is caught: a count would not move.
  `knownUndeclaredEvents` pins the current five, and **it can neither grow nor
  empty quietly** — a new undeclared event is red, and a declared event whose pin
  was left behind is red, so the list only shrinks by a packet declaring the
  event. The five are not declared because declaring them is blocked on **core**,
  not here: `event.payload-schema-missing` reads `schemas/events/…` out of the
  core checkout, and core ships one identity payload schema for twelve published
  types. Declaring them today would trade a silent gap for five loud reds.
  Each of the four rules is proved red, not assumed — see the report.

- **A stale claim about core in `cafaye.yml` is corrected.** The comment on
  `identity.user.created` said core's catalog "currently disagrees" and spells
  the event `user.created`, and recorded it as open decision D1. core 0.2.0
  closed D1, froze three segments with no exceptions, and its catalog row now
  reads `identity.user.created` — so the two halves of that disagreement now say
  the same thing, and the reason they do is this release's `core: ^0.2.0`. The
  note is kept because the failure it describes is still live for the OIDC types
  below it, where core's catalog has no row at all.

### Added (packet identity-13-gate)

- **`gate.yml`, so `bin/prime` means something here.** Six of thirteen services
  declared a gate; identity was one of seven that did not, so a developer running
  `bin/prime` saw a green result and learned nothing about whether the gate could
  detect anything. The format is `cafaye/core`'s `schemas/gate.schema.json` and the
  checker is its `harness/gate_check.py`.

  - **`bin/prime` could not be executed at all, and that was found by declaring it.**
    The file has the executable bit and no interpreter line, so `execve` fails with
    `ENOEXEC`: `FAIL gate.command-missing: … [Errno 8] Exec format error:
    'bin/prime'`. A developer and CI never saw it because `bash` and `zsh` fall
    back to interpreting a shebang-less file themselves; the checker runs the gate
    with `subprocess` and no shell, so it hit the real behaviour on the first
    attempt. Every other adopter ships a shebang and kit's Go template ships
    `#!/bin/sh`. Fixed with one line — see **Fixed** below.

  - **THE DECLARATION CARRIES NO FLOOR, and that is a property of Go, measured
    rather than assumed.** `minimum` is read from a capture group in the last
    matching line, and every other adopter's runner prints a count — ExUnit's
    `Result: 535 passed`, pytest's `898 passed`, minitest's `228 runs`, npm's
    `# pass 187`, cargo's `test result: ok. 7 passed`. **`go test` prints no test
    count**: it prints one line per package and the only number on it is a
    duration. Checked against a complete 5,225-line `go test -v -count=1 ./...`
    run of this suite — every candidate capture group yields a package path or a
    duration, and a search for any `<integer> passed|tests` line returns nothing.
    The schema sanctions this case exactly ("omit it only for a proof that reports
    nothing countable"), so the eight proofs are presence assertions and the
    expected counts are recorded in the file as measured facts — **1789 PASS / 0
    SKIP** whole suite (809 top-level + 980 subtest lines), **1590 PASS / 0 SKIP**
    database tier across 13 packages — while the actual decrease-detector stays in
    `ci.yml`, which counts a `-v` run.

  - **`bin/prime` ran no tests, and said `ok` 18 times while doing it.** It ended
    with a bare `go test ./...`, which Go serves from its test cache. Measured on
    this tree with a warm cache: **exit 0, wall 8s, 18 `ok` package lines, 16 of
    them `(cached)` — two packages actually executed.** Every proof in the
    declaration was satisfied by a `(cached)` line, so a developer who had just
    run the gate had verified nothing. **Fixed** — see **Fixed** below. The
    measured result after the fix: exit 0, 126s, 18 packages, 0 cached.

  - **The gate was observed red three times, on purpose, and all three are quoted
    in the file.** The important one is the packet's own premise tested directly: a
    copy of this tree whose `bin/prime` is `#!/bin/sh` + `exit 0` makes **all
    eight proofs go red and the checker's exit code 1**, with **no** `gate.nonzero`
    — the exit code really was 0. The proofs, not the exit code, are what tell a
    gate apart from a command that exits zero. With `TEST_DATABASE_URL` unset —
    the configuration behind identity's recorded "1430 tests against an unmigrated
    database" — `gate.nonzero` fires *and* the `mfa-tier-ran` and
    `apikeys-tier-ran` proofs disappear. With `internal/admin`'s test files
    removed, `admin-tests-passed` disappears *and* `ci-guard-ran` goes with it,
    because this repository's own `TestTheCoverageExclusionIsOnlyGeneratedCode` —
    written to catch a deleted generated file — walks the tree, finds the two files
    in git but not in the worktree, and fails.

- **Measured, reported, and NOT changed: CI's floors are 535 and 424 tests below
  this suite.** `SUITE_FLOOR: 1254` against a measured 1789, and
  `DATABASE_TIER_FLOOR: 1166` against a measured 1590. **535 tests — 30% of the
  suite — could be deleted and CI would still be green.** Two hand-written copies
  of measurements in the same file are stale the same way `REPORT-identity-12` was
  about: the comment says "11 packages that open a pool" and there are 13, and the
  run summary says "10 migrations applied" and there are 13. Reported for the
  manager with the numbers attached; `ci.yml` is untouched by this packet. The
  counts here were reproduced independently with `ci.yml`'s own awk against a fresh
  `-count=1` run, and agree to the test.

- **What was NOT exercised, named so the next reader knows.** The suite tier is
  gated on **`TEST_DATABASE_URL`** and was run with it set, against
  `postgres:17-alpine` with all 13 migrations applied: **0 skips, so the database
  tier did run** rather than silently passing. **`go test -race ./...` was not
  run** — this machine was at load 31–70 for the whole packet, and a race run
  under that load measures contention rather than races. `bin/coverage-floor` was
  not run; it needs a coverage profile and this packet changed no code.

- **The database tier is enforced by two packages out of thirteen, and one of the
  three copies of the guard that enforces it does not.** Measured by running the
  gate with the variable unset: **11 of the 13 database packages still print
  `ok`** — including `internal/httpapi`'s 669-test authorization matrix — because
  `dbtest.Pool`/`dbtest.Schema` skip silently and a package whose tests all skip
  still reports `ok`. `internal/mfa` and `internal/apikeys` call `t.Fatalf` when
  `TEST_DATABASE_URL` is unset; **`internal/admin`'s same-named
  `TestTheDatabaseTierActuallyRan` only guards `-short` and never reads the
  variable**, and `ci.yml`'s single `--- PASS: TestTheDatabaseTierActuallyRan (`
  grep cannot tell the three apart. Left as found and named in `gate.yml`, which
  weakens its own `admin` proof to match: it is documented as *not* evidence that
  admin's tier reached a database. Changing it means editing a test assertion, so
  it belongs to whoever owns the tier.

### Fixed (packet identity-13-gate)

- **`bin/prime` now passes `-count=1`, so a green gate means the tests ran.** One
  flag, and it is the difference between a gate and a replay. Before: `go test
  ./...` served from Go's test cache, measured at **exit 0, 8 seconds, 16 of 18
  packages cached, two executed** — every proof satisfied, nothing verified. After:
  18 packages, 0 cached, 126s. This is not a local preference either: kit's Go
  template ships `go test -count=1 ./...` and kit's validator **fails** a Go CI
  step that omits it (`tests/validate.sh:3014`), so identity's gate was the one
  place a fleet-wide rule did not hold. The header comment, which claimed this
  file was kit's template "unmodified", was false and now records the real
  divergence.

- **`bin/prime` is executable again.** Added the `#!/bin/sh` shebang it has been
  missing since the identity-01 scaffold, with a comment explaining that it is
  load-bearing. The body is `set -eu` and three commands, so behaviour is
  unchanged — but without it the file cannot be `exec`'d by anything that does not
  go through a shell, which is why `core`'s checker could not start the declared
  gate at all.

### Added (packet identity-12-coverage)

- **The coverage floor has an exclusion mechanism, declared, and the floor did not
  move.** `client/generated` is 12,284 lines of committed oapi-codegen output with
  3,001 statements and no test, and it took module coverage from **73.6% to 44.6%**
  against a floor of 70. The green move would have been to lower the floor to 45 or
  to write tests against a file that is deleted on the next `go generate`. Neither
  was taken; the generated client is now excluded by a **declared path** and the floor
  is still 70.

  - **`coverage-exclusions` at the repository root, in kit's allowlist dialect.**
    One entry, `client/generated`, carrying a reason, an owner, a `since`, an
    `until`, the `files=`/`lines=` it covers, and the floor it was justified against.
    **An entry matching nothing is a failure** — kit's rule 4, from ESLint's
    `reportUnusedDisableDirectives`. `files=`/`lines=` are what make a change of the
    excluded set a red build instead of a silent change of denominator.

  - **Declared, never inferred.** Skipping files by their `// Code generated … DO
    NOT EDIT.` header was rejected because it fails toward *less* coverage: the
    header is written by whichever generator ran, and one that stops writing it
    silently un-excludes a quarter of the module while the floor stays at 70.

  - **`bin/coverage-floor`, not a filter inside a workflow block.** `go tool cover
    -func` has no way to leave a path out of `total:`, so the exclusion has to filter
    the profile — and a filter written in YAML is a regular expression nothing but CI
    executes. The script is driven by
    `TestTheCoverageFilterCanFail` through twenty-two deliberately broken
    declarations and profiles, and
    `TestTheCoverageStepRunsTheCheckedInFilter` fails if the workflow stops calling
    it, so the tested filter and the enforcing one cannot drift apart.

  - **The exclusion is a directory, because Go takes a package and not a file**, and
    the coarseness is paid for by
    `TestTheCoverageExclusionIsOnlyGeneratedCode`: it enumerates every `.go` file
    under `client/generated` and fails if one is not itself generated.
    `TestEveryExcludedDirectoryIsNamedInTheDeclaration` holds the other direction —
    a generated directory that was never declared fails too. `client/` would be a
    legal declaration and would exempt `baseurl.go`, `credentials.go`, `errors.go`,
    `redact.go` and every test in the package.

  - **The measured number, the excluded set and the floor are printed together, on a
    green run as well as a red one**, because "coverage 73.6% (floor 70%)" on its own
    is decoration and a reader cannot tell 70% of what. **No percentage is written
    into `ci.yml`** — the copy that was there had already gone stale twice, once
    when `client/` arrived and once when the generated client was regenerated against
    a document that had gained three operations.

  - **The floor still bites, to one statement.** `TestTheCoverageFilterCanFail`
    proves 69.9% is red and 70.1% is green with the exclusion in place and
    unchanged. An exclusion that made coverage unrestrictable would fail that test,
    which is the only reason to believe it is a fix rather than a hole.

  - **`kit` is untouched.** The mechanism lives here because identity's *enforcing*
    coverage step is its own, in `gate` — kit's `test` step runs with no database and
    dies before reaching a coverage step at all, so a mechanism in kit would not be
    the one this repository uses. The disagreement that leaves behind is stated in
    [DECISIONS.md](DECISIONS.md) D6 and in the README: `coverage-fail-under: '70'` is
    still passed to kit, and kit would read 44.6% because its step computes `total:`
    over the whole profile. Left alone on purpose — 45 is the rejected option and 0
    is a weakened gate — and the threshold is checked in three places by
    `TestTheCoverageFloorInTheDeclarationIsTheFloorsFloor`.

  **Still open:** generating the client into its own Go module, which makes the
  boundary a compile-time fact rather than a config entry. It changes the import path
  of a published client, so it waits; the signal is a second repository asking for a
  generated client, and `until=2027-03-31` fails the build in the meantime.

### Fixed (packet identity-12-coverage, in this release)

- **The generated client was stale against the document, and the merge that proved it
  is the interesting part.** `identity-10` generated `client/generated/api.gen.go`
  from `openapi/v1.yaml` as it stood then; `identity-11` added three admin
  operations to that document on a branch of its own. Merging them left
  `TestTheCommittedGeneratedFileIsWhatThePinnedGeneratorProduces` and
  `TestTheTransportCoversEveryOperationInTheDocument` **red** — not because either
  packet was wrong, but because a committed generated file cannot be merged from two
  directions.

  The repair is mechanical and is what both tests asked for: `go generate ./client/`
  against the merged document (10,334 lines → 12,284), plus three methods on
  `Transport` and the three wrappers on `Client`
  (`ListAccountAuditLog`, `RevokeAccountInvitation`, `RevokeAccountInvitations`).

  It is recorded here rather than buried because **it is the cost of committing
  generated code**, and the next merge will hit it again: a generator's output is a
  function of its input, so two branches that each change the input cannot both have
  a correct output. The alternative — generating in CI — is the one this repository
  already rejects for the same file, because a generated file that is not committed
  cannot be reviewed.

### Added (from packet identity-10, in this release)

- **The Go client**, generated from `openapi/v1.yaml` and committed. `client/` is a
  hand-written wrapper over a committed oapi-codegen v2.8.0 transport, and it is the
  third of the fleet's clients after `cafaye-ts` and `cafaye-py` — generated for Go,
  hand-written for Python, and the asymmetry is a ruling with a reason recorded in
  [DECISIONS.md](DECISIONS.md) D6 rather than an accident to be tidied up.

  - **`client/generated/api.gen.go` is committed, 20 operations, and regeneration is
    a gate.** The generator is pinned in `client/generate.go` with
    `go run <module>@v2.8.0`, which keeps the GENERATOR out of `go.mod` entirely, and
    `TestTheCommittedGeneratedFileIsWhatThePinnedGeneratorProduces` runs the real
    generator over the real document into a temporary directory and compares. The
    temporary directory is the point: a regenerate-in-place `git diff` leaves the tree
    modified, so the next run passes and the failure is visible exactly once.

  - **The generated code is excluded from lint, by exactly one anchored path.**
    `.golangci.yml` exempts `^client/generated/api\.gen\.go$` and nothing else, and
    `TestTheLintExclusionIsOneFileAndNotAPrefix` walks every `.go` file in the tree
    and fails if the pattern matches one of them. `govet` is deliberately **not**
    excluded, because `go vet ./client/` passes on the generated file — a check that
    reports on correctness rather than style has no business being exempted.

  - **The credential reaches no string a human reads, and the rule is structural.**
    Every string the client builds goes through `Redactor.String`, redaction is all or
    nothing, and the credential lives inside **closures** rather than in struct
    fields: `fmt` prints an exported field by value under `%#v`, and that verb does not
    consult `String()`, so a `token string` field is a leak no method can intercept.
    `TestTheClientNeverPrintsACredential` runs a full request cycle — including a 422
    that echoes the caller's own token back in the body and three of its headers — and
    sweeps `%v`, `%+v`, `%#v`, `%s`, `%q`, every reflected field and the serialised
    form.

    **The generated types have no redacting `String()` and oapi-codegen does not emit
    one**, which the brief asks to check for and which is measured rather than assumed:
    `fmt.Sprintf("%v", IssuedAPIKey{...})` prints the plaintext of a scoped credential
    this service stores only a SHA-256 of. Go will not let one package define a method
    on another's type, so the answer is `client.SafeToLog(v)` and
    `(*Client).SafeToLog(v)`, the latter strictly stronger because it knows the
    client's own credential.

  - **An unknown problem code is a typed error.** `*UnknownProblemError` carries the
    code, the status and the trace id, so `errors.As(err, &ProblemError)` works for
    every code including the four identity already documents that core's reserved list
    does not have. `ProblemError` is an interface rather than a base struct because
    `errors.As` matches on assignability and embedding does not create one — a
    hierarchy of structs would make the single catch work only for codes this build
    does not know, which is exactly backwards. 202 is a typed error too: a 202 from
    `POST /v1/session` carries a challenge and **no session**, so returning a `Session`
    with an empty token would be the credential-shaped non-credential the document
    warns about.

  - **Base URLs resolve in a documented order and there is no default.** Explicit, then
    `$CAFAYE_IDENTITY_BASE_URL`, then `$CAFAYE_BASE_URL`, then **throw**. The document's
    own `servers:` entry is deliberately not used as a default: it would send a
    self-hoster's traffic to somebody else's deployment and it would *succeed*, so
    nothing would look wrong until somebody read a log.

  - **Two auth models, classified by identity's own prefix rule.** A `cafaye_` value
    goes in the `Authorization` header and **not** in a cookie; a session goes in
    both, because identity prefers the header when both are present and that is what
    lets one credential work against identity and against the other five services.
    Tested from the server's side, against a live `httptest.Server`, rather than from
    the helper's return value.

  - **This costs three modules and a coverage number, and both are recorded.**
    `github.com/oapi-codegen/runtime` is a real runtime dependency of the generated
    code — MD6 said the Go client would need none, and that is corrected in
    [DECISIONS.md](DECISIONS.md) D6 with the measurement. `./cmd/identity` does not
    reach it, and
    `TestTheServiceBinaryDoesNotReachTheGeneratedClient` holds that. Adding 10,334
    lines of generated code at 0% coverage takes the module from 74.7% to 45.9%
    against a 70% floor; **this packet did not move the floor**, and the options are
    written down in D2 for whoever owns it.

- **The admin surface** — three operations, and the privilege boundary is one
  sentence: *an account admin may revoke pending invitations to their own account
  and read that account's admin audit log, and nothing else.*

  | route | minimum | scope |
  |---|---|---|
  | `GET /v1/accounts/:id/admin/audit-log` | admin | `audit_log:read` |
  | `DELETE /v1/accounts/:id/admin/invitations/:invitationId` | admin | `account_invitations:write` |
  | `POST /v1/accounts/:id/admin/invitation-revocations` | **owner** | `account_invitations:write` |

  - **Reachable by a scoped api key only. A browser session is refused, per
    route.** A session is a browser credential and an admin surface a session
    cookie opens is one CSRF away from being somebody else's — and a token is the
    *right* credential here, because every action is recorded against the api
    key's row id, so an audit record can name the credential that acted.
  - **Every action is recorded in the same transaction as the mutation.**
    `admin.Service` exposes no method that mutates without recording: the mutation
    is a callback run inside the transaction that writes the record, so a
    revocation that commits and an audit row that does not is unrepresentable.
    Both failure directions are tested against real Postgres with a trigger that
    raises.
  - **The record cannot be edited, including by the admin whose action is in
    it.** `GET` is the only method on that path, the store has no update or
    delete, and **the table refuses `UPDATE` and `DELETE`** in the database — a
    guarantee written in Go does not bind a `psql` session or a future packet.
    The table has **no foreign key to `accounts`**, so the admin surface cannot
    delete its own audit log by deleting the account.
  - **Bulk and single do not share a request shape**, because a bulk operation is
    where an off-by-one becomes an outage: the bulk route needs `confirm: true` in
    the body, an array of at most 50, and an **owner**; the single route needs none
    of those. Both counts (`requested` and `revoked`) come back, and they differ.
  - **Every list is bounded and the bound is refused rather than clamped.** The
    trail defaults to 25 rows, refuses `limit` above 100, and pages with an opaque
    cursor carrying `(occurred_at, id)` together — a timestamp-only cursor drops
    records sharing the boundary instant, and the service's clock is a timestamp
    rather than a sequence.
  - **No route in this service may record or log a credential.** The audit entry
    carries `actor_user_id` and `actor_key_id` — row ids — and
    `TestNothingOnThisSurfaceCanRecordAToken` reflects over the types that reach
    the table and fails if any grows a field that could hold a value.

  `openapi/v1.yaml` is at **1.4.0** with all three operations, unique
  operationIds, and full request and response schemas. **`knownDrift` did not
  grow** — it is still twelve, still pinned — because the answer to "I added a
  route" is to document it. [D2](DECISIONS.md)–[D5](DECISIONS.md) record the
  boundary, the audit decision, the token-only ruling and the bulk/single split.

- **`account_audit_log` (00012) and `account_invitation_revocation` (00013).**
  The audit table carries **no foreign key to `accounts` on purpose**: a cascade
  is a `DELETE`, and this table does not delete, so allowing it would make the
  shortest route from "an admin did something questionable" to "there is no record
  of it" be one request to `DELETE /v1/accounts/:id`. Revoking an invitation now
  sets `revoked_at` rather than deleting the row, which answers "was this
  revoked, or was it always broken?" and **frees the address to be invited again**
  — the entire reason the operation exists. 00013 is the schema half of what
  00007's comment anticipated: *"Deleting a user with pending invitations is
  therefore refused by the database until they are revoked, which is a later
  packet."*

- **Two new scopes**, `audit_log:read` and `account_invitations:write`, and
  **deliberately no scope named `admin`.** The vocabulary's own comment rules that
  name out, because a category name is where a wildcard grows back. Reading the
  trail is not `accounts:read` — a record of authority being used over time is a
  different sensitivity from the account's current shape — and revoking is not
  `accounts:write`, which creates things the account wants.

### Fixed

- **The document-versus-router tripwire was blind to a whole surface.**
  `servedRoutes` in `internal/httpapi/openapi_drift_test.go` builds an `options`
  struct literal so every conditional surface takes its "configured" path, and the
  new `admin` field was not in it — so `registerAdminRoutes` returned early and
  the walk read a **smaller service than the one that runs**.
  `TestEveryServedRouteIsDocumentedOrNamed` — the reverse-direction check holding
  this repository's twelve findings — **passed green while three undocumented
  operations were mounted**. `TestEveryRouteIsInTheMatrix` was blinded the same
  way at the same time.

  The check went green **by not checking**, which is the one outcome AGENTS.md
  names as the failure mode the file exists to prevent, and it happened to the
  check written to catch precisely that.
  `internal/httpapi/router_walk_test.go` now holds the property:
  `TestTheDriftWalkSeesTheAdminSurface` and `TestTheMatrixWalkSeesTheAdminSurface`
  assert the walks **find** the routes, and
  `TestEveryConditionalSurfaceIsVisibleToTheWalk` keeps a list of every surface
  field whose absence can make a registrar skip its routes. The general lesson is
  in [D1](DECISIONS.md): **a struct literal used to configure a check is a
  completeness obligation, and nothing about it looks like one.**

### Changed

- **`expectedStatus` in the authorization matrix now consults a row's `expect`
  override before its authentication check.** It had them the other way round, on
  the stated grounds that "authentication is the one decision no endpoint
  overrides" — which is true where the credential is resolved first, and false on
  the admin surface, where the credential *kind* is resolved first by
  `requireAdminToken` outside `requireAccountRole`. A request with no credential
  there is answered `403`, and the three new matrix rows were silently being
  asserted `401` for a service that does not give that. The one pre-existing row
  with an override that relies on the old order now states its anonymous answer
  itself.

- `internal/platform/dbtest` clones `account_audit_log` **and re-creates its
  append-only trigger** in each test's private schema. `LIKE` does not copy
  triggers, so without it a test would run against a table the production one can
  never `UPDATE`.

### Added (from packet identity-09, in this release)

- **The document-versus-router tripwire**, the last one owed in the fleet.
  `internal/httpapi/openapi_drift_test.go` holds `openapi/v1.yaml` and
  `openid/openid.yaml` to the router in **both directions**, comparing sets of
  **(method, path)** and never counts.

  - **It fires on its first run: twelve operations are served and written down in
    no document.** The ten tenancy operations — the whole `/v1/accounts`
    collection, `/v1/accounts/{account_id}/members`,
    `/v1/accounts/{account_id}/invitations` and `/v1/invitations/accept` — are
    served since the accounts packet and appear in neither document nor the
    README's endpoint table. They are all in the authorization matrix and seven
    declare a scope, so they are gated and unrecorded as contract surface at the
    same time. And `POST /oidc/authorize` and `POST /oidc/userinfo` are served
    deliberately — `registerOIDCRoutes` says why in a comment — while
    `openid/openid.yaml` declares only the `GET`.

    **The second pair is billing's bug, already here.** billing's first drift
    check compared paths and never `route.verb`, so `PUT /v1/customers/{id}` was
    served in a money-handling service and written down nowhere: one path on each
    side, and the comparison reported agreement. The same shape is live on this
    service's OIDC surface, and the (method, path) key is what sees it.

    This packet adds a check and not operations, and calling twelve served
    routes "not client operations" would be false about all twelve, so they sit
    in `knownDrift` — named for what it is rather than for what it excuses, and
    pinned so it can neither grow nor be emptied. **Open as D1 in
    [DECISIONS.md](DECISIONS.md),** which is this repository's first; the
    question is whether these are contract surface to document or routes to rule
    out of the contract in writing, and this packet does not pick a side.
  - **The method is read from chi's own walk**, of the tree `New` assembles, and
    never inferred from a path. `New` now builds the mux through a `newMux`
    helper so the walk reads the production assembly rather than a second one
    written out in a test. Registering the same pattern under two methods is
    invisible to a path comparison and to a count comparison, and is the bug that
    has already cost billing one.
  - **A route that is neither documented nor named is a failure**, so the list
    cannot become the place a forgotten route goes. There is no prefix filter:
    `strings.HasPrefix(path, "/v1")` is a guess about intent and cannot see a
    method, which is exactly what let billing's `PUT` through.
  - **No exclusion list is needed, and `TestTheProbesAreDocumentedRatherThan-
    Excluded` holds that it is not needed.** `/healthz` and `/readyz` are
    documented here, under `liveness` and `readiness` — which is identity's
    answer to core's open D25, not a decision about it — and nine of the eleven
    `/oidc/*` and `/.well-known/*` routes are documented in the sibling
    document, so reading both is what keeps them out of a list of omissions that
    would have been false about nine of them. chi registers no error-handler
    route: `NotFound` and `MethodNotAllowed` are handlers, not routes.
  - **The document is read without a YAML dependency.** `go.mod` has none and
    this adds none; a library already in the module graph as a *transitive*
    dependency of `zitadel/schema` would become this service's direct
    requirement, with its versions and its CVEs, for the sake of forty lines of
    structure. The reader takes the `paths:` block by indentation, states the
    subset it understands, and turns every way it could under-read — no
    `paths:`, an empty block, a path item with no operation, two operations
    normalising onto one, a missing file — into an error, because two empty sets
    agree and that is how a check over nothing goes green.
  - **The tripwire is proved red four ways** in
    `openapi_reader_faults_test.go`, and the load-bearing one registers a second
    method on an already-documented path: the path set is then identical on both
    sides and both counts unchanged, and only the (method, path) key catches it.
- **[DECISIONS.md](DECISIONS.md)** — this repository's open-decision record,
  numbered from D1. It did not exist: `moon/DECISIONS.md` numbers workspace
  questions `MD…` and `cafaye.yml` carries the one callout this repository had.
  A packet that had to escalate something had nowhere to put it. A `DECISION
  NEEDED` callout for D1 is added to `cafaye.yml` as well, because
  `exposes.api` promises a document describes this service's HTTP surface and for
  twelve operations it does not.

- `.github/workflows/ci.yml` — CI, in two halves. `ci (kit: go)` calls
  `cafaye/kit/.github/workflows/ci.reusable.yml@master` for the shared half.
  `gate` is the service-specific half: Postgres 17.11 as a job service, `goose up`
  as its own step **above** the gate, `bin/prime` unmodified, and then the
  assertions. It is a separate job rather than steps inside kit's because GitHub
  accepts only `name`, `uses`, `with`, `secrets`, `strategy`, `needs`, `if`,
  `concurrency` and `permissions` on a job that calls a reusable workflow —
  `services:` is not reachable from the caller, so the database tier cannot live
  in kit's `go` job at all.
  - **The database tier cannot go quietly green.** `dbtest.Pool` returns a pool
    and *skips* the test when `TEST_DATABASE_URL` is unset, and
    `TestTheDatabaseTierActuallyRan` fails rather than skips — so the gate is red
    before any assertion runs. On top of that the gate **derives** the tier from
    the tree (every `_test.go` that calls `dbtest.Pool`, `dbtest.Schema` or reads
    the variable, comments stripped), requires each derived package to appear in
    the output with tests in it, fails on any `--- SKIP:` line, and holds floors
    of 1254 PASS lines for the suite and 1166 for the tier. The floors are
    decrease detectors, not targets. The suite floor moved from 1237 to 1254:
    1237 was 1254 minus the 17 tests in `internal/platform/ci`, so the old
    number had been measured from a log taken before this package's own tests
    were in the tree — a 17-test blind spot in the one package that guards the
    workflow.
  - **The ordering is the contract.** Migrations are a deploy step, so `goose up`
    is never in the same step as the suite, and `goose status` prints ten applied
    migrations before the first test runs. Without that ordering the suite fails
    on `relation "public.users" does not exist` — loud, but a red that reads like
    a code failure rather than a pipeline that is wired wrong.
  - 23 named MFA, session and matrix tests have to appear in the log by name, so
    "the security tests ran" is a measurement rather than a summary line.
  - `MFA_ENCRYPTION_KEY` is generated from `/dev/urandom` per run, masked, and
    printed nowhere. No test needs one — every one builds a `config.Config`
    literal — but no test covered the operator's path either, so the gate boots
    the binary three times: a 16-byte key refuses and names the variable, no key
    mounts no management surface (404), and a real key mounts it (401).
  - Beyond `bin/prime`: `go vet ./...`, `gofmt -l .`,
    `git diff --exit-code -- go.mod go.sum`, `go test -race` (AGENTS.md's fourth
    gate, which `bin/prime` does not run), and a coverage floor of 70% against a
    measured 73.2%.
  - **Known red on arrival, and the reasons are in kit's file, not this one.**
    `ci (kit: go)` fails on `lint` (golangci-lint's default set, 31 issues here)
    and on `test` (no Postgres). Delete the job when kit's Go job grows a
    `services`/`env` seam, and not before on the strength of a green run.
- `internal/platform/ci` — the test for the workflow file. `.github/workflows/ci.yml`
  is the artifact under test, and a workflow nobody has executed is a workflow
  nobody has tested. Seventeen tests, and each names the step it is about: the
  `uses:` path resolving, the inputs being kit's, the `versions` literal matching
  `go.mod`'s `go` directive, the gate running `bin/prime`, the migrations running
  before it, the tier being derived and skip-checked, the Postgres image being
  pinned, the lockfile guard naming `go.sum` on the same line as the `git diff`,
  `coverage-fail-under` being above zero, `telemetry` being a quoted string, no
  secret literal, every named security test existing in the tree, and every
  `run:` block parsing under `bash -n` — an apostrophe inside an awk program or a
  grep pattern ends the quoting and the shell re-parses the rest as commands. It
  parses no YAML: a YAML dependency would move `go.mod`, and AGENTS.md's rule is that
  `go.mod` moves only for a stated cause.

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

- Two defects in `.github/workflows/ci.yml`, both found by executing the steps
  rather than reading them, and both in the check that exists to prove the
  database tier ran:
  - **The step did not parse.** The awk program counting PASS lines per package
    sat inside a shell single-quoted string, and an apostrophe in a comment
    inside that string — `a package's tests` — closed the quote early. The shell
    re-parsed the rest as commands and the step died on a syntax error, so the
    one check in the job whose job is to prove the tier ran never ran. The prose
    moved out of the awk program into shell comments, where an apostrophe is
    free, and `internal/platform/ci` now runs `bash -n` over every `run:` block on
    every commit so the next one is caught before it ships. Reintroducing the
    apostrophe makes that test fail with the original error.
  - **The empty-tier guard never ran.** `grep -rl` exits 1 when it matches
    nothing, so under `set -e` an empty derivation aborted the step *before* the
    check that explains it. The step was still red, so no false green was
    possible, but the log carried no reason at all. `|| true` on the pipeline
    lets the empty list through to the check, which now prints
    `the database tier matched no test file.`
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
