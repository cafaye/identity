# Changelog

All notable changes to identity are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed (packet registry-identity-down-05: `goose up` could not succeed on CI, and seventeen Down sections had never been run)

**Two findings, and the first one is why the second one was possible.**

**1. CI could not apply this service's migrations at all.** Since packet
identity-account-scope-01 (`e323247`), `migrations/00016_account_isolation.sql`
ends its Up with `select cafaye.protect_table('account_users')`.
`protect_table` defaults its login role to `current_user || '_app'` and refuses
to write a policy for a role that cannot log in — so the migration asks the
cluster for a role named `identity_app`.

`docker compose up` has always provided it: kit's cluster init reads
`KIT_POSTGRES_DATABASES: identity` and provisions `<service>_app` beside each
`<service>`. **`.github/workflows/ci.yml` did not.** This repository's CI runs a
bare `postgres:17-alpine` *service container*, which has no init script and no
`KIT_POSTGRES_DATABASES`, so the only role on that cluster is the one
`POSTGRES_USER` made. Measured, not predicted — applying these migrations to a
cluster built exactly the way this job builds one:

```
ERROR:  cafaye.protect_table(account_users, identity_app):
        identity_app is not a LOGIN role on this cluster.
```

The gap was invisible locally and fatal in CI, which is the worst shape a gap
can have: every laptop run took the production path, so nothing looked wrong,
and the job that could not build the service was the job nobody runs by hand.

The role is provisioned now, in a step of its own **before** `goose up`, and
`TestTheLoginRoleTheMigrationsProtectTablesForIsProvisionedBeforeTheyAreApplied`
derives the name from the service container's `POSTGRES_USER` rather than
repeating it — so renaming the database in `docker-compose.yml` cannot quietly
un-provision it, and the assertion is on the ORDER, because a role created after
the migrations run cannot be one they used.

**The role stays out of the migrations, deliberately.**
`TestNoMigrationCreatesAClusterRole` fails on any migration that says `create
role`. A migration that provisioned its own roles would need `CREATEROLE`, would
recreate a role an operator had dropped on purpose, and would leave a role no
`goose down` could remove. Roles are the environment's; four homes provision
them (`docker-compose.yml`, kit's cluster init, this workflow, `bin/rollback`)
and the check is what says a fifth is not allowed.

**2. `bin/rollback` — a gate tier that undoes every migration, one at a time.**

```sh
for N in 00001..00017:
    apply Up N      -> census the schema as A_N
    apply Down N    -> census it as C_N
    assert C_N == A_{N-1}
    apply Up N      -> a rollback an operator cannot redeploy over is not a rollback
```

The property is per-migration, so one pass and one database carry it: after each
assertion the database is in the state the next migration's Up expects. Compared
across **tables, views, materialized views, sequences, types, functions (by full
signature, so overloads stay distinct), triggers, policies, indexes and
columns**, in every schema but the system's.

The first run was green — identity's seventeen Down sections are correct — and
getting there meant fixing three defects in the harness itself, each of which
had been reporting a clean tree:

- **The census looked only at schema `cafaye`.** `00016` is the only file that
  says `create schema`, and it says it for its eight functions. The eighteen
  tables, their indexes and their twenty policies are created by unqualified
  `CREATE TABLE`, which lands them in `public`. The first draft counted eight
  functions and nothing else. Deleting one `drop policy` from `00016`'s Down —
  the exact defect this packet exists to catch — left it green.

- **`00016`'s Down ended in `drop schema cafaye cascade`, which was hiding the
  gap.** A policy is a *dependent* object, not a member: each of the twenty
  policies names `cafaye.current_account_id()` in its expression, so `cascade`
  swept every policy whose own `drop` was missing. The cascade is gone, the
  eight functions are named and dropped in dependency order, and the schema goes
  last and bare — so a forgotten statement is now Postgres refusing to drop a
  schema something still depends on, which is an error naming itself.

- **The census tracked no columns.** A Down that drops a column a *different*
  migration added is invisible: `alter table sessions drop column user_agent;`
  in `00017`'s Down, `user_agent` belonging to `00003`, left the before and after
  censuses byte-identical and the harness called all seventeen clean.

It runs in CI after `goose up`, with `IDENTITY_ROLLBACK_REQUIRED=1` so the step
can never exit zero by standing down; with no server it prints a counted `skip:`
and exits 0, because a gate that also migrates is a gate whose result depends on
the state of a database.

**Sixteen mutations, each reverted, each caught by a named failure.** Ten against
the Go checks in `internal/platform/ci` (delete the provisioning step; move it
after `goose up`; build the role name from the service container's environment,
which the job does not have; drop `IDENTITY_ROLLBACK_REQUIRED`; delete the
rollback step; delete a migration's Down marker; put `create role` in a
migration; hardcode the role name in the script; drop the `rolcanlogin` half of
its role probe) and six against `bin/rollback` itself. Three **survived**, and
those three are the ones that earned the fixes above: restoring `cascade` hides a
forgotten policy drop; narrowing the census to `cafaye` hides a forgotten index
drop; and the re-apply step could not be made to go red on this tree at all —
every defect the census sees is caught before it — which is recorded rather than
papered over.

### Changed (packet polyglot-numeric: three numeric enums become counts, and the generated Go types with them)

**`caf contract lint` refuses numeric enums, and three fields in this document
carried one.** `RecoveryCodesResponse.recovery_codes_remaining` was
`enum: [10]`; `StartedEnrollment.digits` was `enum: [6]`; and
`StartedEnrollment.period_seconds` was `enum: [30]`. Kubernetes' API conventions
refuse these at `api-conventions.md:588` — adding an enum value is not a
compatible change, because a client that switches over the numbers has to be
recompiled and redeployed to learn a new one exists. cafaye is polyglot, and this
is the class of defect that bites TypeScript and not Go, or Ruby and not
Python, which is what a contract system exists to prevent.

Each of the three is really a **count with one legal value**, not an
enumeration, so each is now a plain `integer` carrying its bound as
`minimum`/`maximum` and saying so in its description.

- **Nothing on the wire moved.** `{"recovery_codes_remaining": 10}`,
  `{"digits": 6}` and `{"period_seconds": 30}` are byte-for-byte what this service
  sent before, and every value inside the new bounds was already the only value
  the service ever produced. `caf contract breaking --tiers all` calls this
  `enum-value-no-delete [SOURCE]` and nothing else: no JSON-tier break, no
  WIRE-tier break.

- **So this is a SOURCE-tier break only, and a Go consumer is what it costs.** A
  caller that wrote `client.N10` or `client.N6`, or that named
  `client.StartedEnrollmentDigits` in a signature, stops compiling and wants plain
  `int`. No client in any other language in the fleet can tell the difference, and
  the compiled client gets strictly simpler: three named types carrying exported
  case constants (`N10`, `N6`, `N30`) and `Valid()` methods are gone.

- **`const:` was tried first and is not the answer.** oapi-codegen v2.8.0 mints
  the same named type, the same exported case constant and the same `Valid()`
  method for a `const` as for a single-value `enum`, so the document would have
  stopped tripping the linter while every generated client in the fleet kept the
  shape the rule exists to prevent. The rule is about what a generator emits, so
  the fix has to be what the generator emits.

- **The "always N" is not lost — it moved where it can actually fail.** Each value
  is set from a compile-time constant (`mfa.RecoveryCodeCount`, `mfa.Digits`,
  `mfa.Period`) and asserted against it in `internal/httpapi`'s MFA tests. A
  document annotation fails a validator somebody may not run; that fails the
  build.

- **`RecoveryCodesResponse.recovery_codes_remaining` is now the same shape as
  `MFAStatus.recovery_codes_remaining`**, which was already a plain integer. Two
  fields with one name and one meaning had two different types in one document,
  and the document was the odd one out — the service has always implemented the
  count shape, in `internal/httpapi/mfa.go`, as a plain `int`.

### Added (packet identity-32: the image `config/deploy.yml` deploys is now built by a pipeline)

**Nothing in this repository built the image the deploy config names.**
`config/deploy.yml` says `image: <%= org %>/<%= repo %>` with
`registry.server: ghcr.io`, and `kamal deploy` pulls that image. Before this
packet the only build was the `docker build -t identity .` in the README, run by
hand on one machine — while CI stayed green throughout. A green CI and an unbuilt
image are not in tension; they are just both true, which is exactly what makes the
gap easy to miss. A deploy config describing a deploy nothing produces is a
document, not a plan.

- **`.github/workflows/publish.yml` calls kit, and does not copy the build.**
  The build lives at `cafaye/kit/.github/workflows/image.reusable.yml@master` and
  is shared across the fleet, so a fix to how an image is built lands here on
  kit's next push with no pull request against this repository. A copy would be a
  second pipeline to maintain and diverge — the same failure `ci.yml` is already
  written to avoid for the test half.

- **It runs on `master` pushes and `workflow_dispatch`, never on
  `pull_request`.** Only master holds deployable commits, so a branch build would
  publish images nobody deploys; and a PR build would run untrusted code — the
  Dockerfile, whatever a contributor changed — against a registry write. kit's
  reusable workflow refuses to publish on a pull request regardless of what a
  caller asks, so this is belt and braces: the guard is in both places because a
  caller written later should not have to remember.

- **`packages: write` is granted by the caller.** A reusable workflow can
  *request* a permission but cannot grant itself one, so this line is the
  caller's job and there is no way to get it from the other repository. Without
  it the push fails with a 401, which reads like a bad password rather than like
  the missing line it actually is.

- **The image name is derived, not passed.** The reusable workflow builds it from
  `github.repository` and lowercases it — `ghcr.io/Cafaye/Identity` 404s, because
  the registry requires lowercase paths. A name spelled at the call site would be
  a second place to get that rule wrong and a second spelling of a fact
  `deploy.yml` already states.

- **Tags are `sha-<commit>`, `master`, and `latest`. No semver.** Releasing is a
  decision; a workflow that cut a version tag on every merge would make "which
  version is on the host" unanswerable.

- **`internal/platform/ci/publish_test.go` checks the file, because nothing else
  could.** It never runs on a pull request, so a mistake in it cannot be caught
  by the mistake being noticed — only by a check, or by a deploy failing to find
  an image. Six claims, each of which fails silently when it stops being true:
  the file exists; it calls kit at the one path GitHub can resolve, exactly once;
  it carries no `docker/build-push-action@` of its own; it grants
  `packages: write`; it says `push: true` (which defaults to false, so a caller
  that stops saying it builds an image and pushes nothing); and no
  `pull_request` trigger reaches it.

  Each is proven able to fail — delete the file, misspell the path, add a second
  kit call, inline a build step, downgrade the permission, add the trigger, set
  `push: false` — and a comment *naming* `docker/build-push-action@` is proven
  **not** to fail it, because a check that punishes the warning it wants written
  is a check that gets deleted.

### Fixed (packet identity-31: `bin/migrate` applied every migration and then undid it)

**`bin/migrate` was a no-op that reported success.** It handed each migration to
`psql --file`, so psql ran the whole file — the `Up` section *and* the `Down`
section — and every table a migration created was dropped again in the same call.
Exit status zero. The script printed `migrations applied`. A developer running
`bin/dev` got an empty database and no error, and the next statement they ran
failed with `relation "users" does not exist`.

Measured on a fresh Postgres with nothing else applied, feeding it
`00002_users.sql` alone:

```
CREATE TABLE
CREATE INDEX
DROP TABLE
exit=0
```

- **The header asserted the opposite, and that is how it survived.** It said the
  "`-- +goose Up` and `-- +goose Down` annotations … are comments, so a plain
  `psql -f` runs exactly the Up section and ignores the Down one". The
  annotations *are* comments — that is the entire defect. psql has no idea they
  are annotations, so it runs both halves. A comment asserting a property of a
  tool it never checks is a comment that survives only because nobody ran the
  thing it describes.
- **CI never saw it, because CI runs `goose`, which honours the annotations.** The
  broken path was the fallback that exists for a machine without goose — the one
  a developer is actually running, and the one no automation touches.
- **The Up section is now extracted before psql sees anything**, by a new
  `bin/migration-up-section`. Extraction stops at `-- +goose Down` and never
  looks for `-- +goose Up`, so a migration with no Down section still applies
  forward instead of producing an empty file and a silent no-op. The marker is
  matched as `^--[[:space:]]*\+goose[[:space:]]+Down`, anchored at the start of a
  line so a mention of it inside a comment is not a cut.
- **It is a separate script so the test can reach it without a database.** An
  inline `awk … | psql` inside the loop is only testable against a real Postgres
  with a real `psql` present, and a test that skips when those are missing
  verifies nothing in the one environment a developer runs in.
- **The loop test puts a stub `psql` first on PATH and reads what it was handed**,
  so the assertion is about `bin/migrate` as a developer runs it rather than about
  a function beside it. Asserting on the extractor alone would pass with
  `bin/migrate` never calling it, which is precisely the regression that broke
  this once: a correct extractor, never invoked. There is a control in each
  direction — no `DROP TABLE` may reach psql, and `CREATE TABLE users` and two
  others must, so a "fix" that sent nothing cannot pass.
- **`TestEveryMigrationForwardsItsUpSectionIntact` checks all fifteen files**, for
  "no `DROP TABLE`" rather than for the word `DROP`, because
  `00013_account_invitation_revocation.sql` legitimately drops an index inside its
  own Up section — an index predicate cannot be altered, so it is
  DROP-then-CREATE — and a rule banning the word would have been wrong.

**Verified by reverting `bin/migrate` to `--file` with the tests in place:** the
test goes red and names the mechanism, printing every `psql` invocation as
`--file …/migrations/0000N_….sql` followed by an empty stdin.

**And verified end-to-end on a real database, which is what the Go test
deliberately does not need.** Two empty Postgres containers, the same fifteen
migrations, the same command, one script with `--file` and one with the Up
section extracted:

| | tables left in `public` | exit | last line |
| --- | --- | --- | --- |
| `bin/migrate` before | **0** | 0 | `migrations applied` |
| `bin/migrate` after | **17** | 0 | `migrations applied` |

The after-run's 17 tables are `users`, `sessions`, `accounts`, `account_users`,
`account_invitations`, `connected_accounts`, `api_keys`, `outbox_events`,
`account_audit_log`, `oidc_*`, `mfa_*` and `recovery_tokens` — the full schema.
The before-run left the database exactly as it found it while telling the
operator it had worked, which is the failure this is worth a packet for: there
was nothing to notice.

### Fixed (packet identity-30: a revoked invitation no longer redeems)

**A revoked invitation was a working credential.** An account's admin could
withdraw an invitation — "we sent it to the wrong list, revoke it and send it
again" — and the token in the withdrawn link still created the membership, still
marked the invitation accepted, and still emitted `member.accepted`. Measured
against a real Postgres before the fix: `Accepting a revoked invitation = <nil>`
followed by `a refused redemption left 1 membership row(s) behind`.

The cause was three omissions of the same column. `revoked_at` was not in
`invitationColumns`, so `Invitation` had no field to check; `Accept` checked
`AcceptedAt` and the expiry and nothing else; and `MarkInvitationAccepted`'s
conditional UPDATE required only `accepted_at IS NULL`, which stops two
redemptions racing each other and does nothing about a revocation.

- **The fix has an in-memory half and an atomic one, and both are load-bearing
  for a different reason.** `Accept` refuses a row whose `RevokedAt` is set, and
  `MarkInvitationAccepted` additionally requires `revoked_at IS NULL`. The first
  answers immediately and costs nothing; the second is the one that cannot be
  checked anywhere else, because the caller read the row *before* an admin could
  have withdrawn it, and that gap is a transaction rather than a fiction. With
  only the second in place the revocation still cannot be overwritten; with only
  the first, a revocation landing mid-transaction is silently lost and the admin
  who pressed the button is told it worked.
- **`MarkInvitationAccepted` now distinguishes three reasons for updating zero
  rows**, with one primary-key lookup, because they answer differently: the row
  is gone, somebody else redeemed it first (`ErrInvitationUsed` → 410), or an
  admin withdrew it while the transaction was open (`ErrInvitationRevoked`). The
  service maps that last one to `ErrInvitationNotFound` → **404**.
- **404 is the status the contract already promised and the code did not
  implement.** `openapi/v1.yaml`, on this route, says: "An invitation an admin
  revoked is also 404 — it is not redeemable and there is nothing to redeem." The
  handler has no `ErrInvitationRevoked` case of its own, and deliberately: one
  place decides what a withdrawn token looks like from outside, so a second one
  cannot disagree later. A distinct status would also tell whoever holds a stolen
  token that the invitation was once real, which is the one thing an enumeration
  of tokens is trying to extract.
- **`InvitationByToken` still returns a revoked row, and that is on purpose.**
  Filtering `revoked_at IS NULL` in the SELECT is the shorter fix and the wrong
  one: it would make "withdrawn" indistinguishable from "never existed" to the
  account's *own admin surface*, which is the one caller entitled to the
  difference, and would hide the withdrawal from the audit trail rather than from
  an attacker.
- **Migration 00013's comment states a half-true invariant and is left alone.**
  It says `RevokePendingInvitation` "already makes the two mutually exclusive by
  requiring accepted_at IS NULL, and that is the one place it can be enforced
  atomically" — true in one direction only. It stops a *revocation* from landing
  on a redeemed invitation; it never stopped a *redemption* from landing on a
  revoked one. Editing an applied migration is a silent no-op for every database
  that already ran it, so the correction lives on `MarkInvitationAccepted`, where
  the second half of the invariant actually is.
- **Tests, and the proof that they are tests.** `TestAcceptIsRefusedAfterRevocation`
  asserts three things, the third being that **no membership row was written** — a
  refusal that returned the right error while leaving the write behind would pass
  the first two and still be a bypass.
  `TestMarkInvitationAcceptedRefusesARevokedRow` asserts the store-level clause
  and reads the row back to prove it neither stamped `accepted_at` nor undid the
  withdrawal. `TestAcceptInvitationAnswersTheDocumentedStatuses` covers all four
  statuses `openapi/v1.yaml` documents for this route, which had **no** coverage
  at all before — the route had a happy path and a contract.

**Verified by reverting the fix, not by reading the diff.** With the three source
files back at `828df16` and the new tests in place:

```
--- FAIL: TestAcceptIsRefusedAfterRevocation
    Accepting a revoked invitation = <nil>, want ErrInvitationNotFound
    a refused redemption left 1 membership row(s) behind
--- FAIL: TestMarkInvitationAcceptedRefusesARevokedRow
    MarkInvitationAccepted on a revoked row = <nil>, want ErrInvitationRevoked
```

An intermediate measurement worth recording: **removing only the in-memory check
left both tests green.** The atomic clause alone is sufficient for correctness,
which is a fact about the design rather than about the tests — and the reason the
in-memory check is kept is that it fails closed without a database round trip,
and reads as what it is to the next person.

### Security (packet identity-27: identity joins kit's one shared cluster, and stops being its own superuser)

**identity's development database was a cluster superuser, and this packet is
the fix.** The `postgres` override in `docker-compose.yml` set `POSTGRES_USER:
identity`. On the cluster identity now shares with the rest of the fleet, that
variable is not a service's role — it is the **superuser the official image
creates**, the one role every other privilege is anchored to. Overriding it did
not give identity its own database; it gave the **auth service** credentials
that read every database on the cluster.

Measured on a real cluster built from kit's own stack, with those three lines
alone changed:

```
$ psql -U courier -d courier -c "insert into deliveries values (1,'courier-private')"
$ psql -U identity -d courier -c 'select * from deliveries;'
 id |      note
----+---------
  1 | courier-private
(1 row)

$ select rolname, rolsuper, rolconnlimit from pg_roles;
 rolname  | rolsuper | rolconnlimit
----------+----------+--------------
 courier  | f        |           10
 identity | t        |           -1        <-- superuser, no blast radius
```

**And the cluster reported itself healthy while it did.** `docker compose up
--wait` exited 0, the container was `healthy`, and kit's init script still
printed its closing sentence — *"done: 1 service database(s), one role each,
PUBLIC holds CONNECT on none of them"* — which was false of identity in two ways
at once: its database had been created by the image rather than by the script,
so it never got a `NOSUPERUSER` role, a `CONNECTION LIMIT` or the two timeouts,
and it was in no declared database list at all. This is the failure kit's own
`templates/database/README.md` calls the one that must not be papered over.

**kit's gate recommends the override that causes it.** `tests/fleet_check.py`
says, in two places, to "point it at its own database by overriding the
`postgres` service's environment (`POSTGRES_DB` / `POSTGRES_USER`)". That advice
was correct when each service ran its own container and is a boundary breach on
a shared one. Reported upstream; not fixed here, because kit is another
repository's gate and a service must not edit the gate that judges it.

- **`docker-compose.yml` now declares exactly one postgres variable:**
  `KIT_POSTGRES_DATABASES: ${KIT_POSTGRES_DATABASES:-identity}`, which becomes one
  `NOSUPERUSER` role owning one database. `POSTGRES_DB`, `POSTGRES_USER` and
  `POSTGRES_PASSWORD` are **deleted**. `DATABASE_URL` takes the cluster's
  password (`${KIT_POSTGRES_PASSWORD:-cafaye}`) because that is what the role's
  password now is.
- **`kit.ref` moves `a095992` → `1770009`.** The old pin had **no
  `templates/compose/postgres/` at all** — no `Dockerfile`, no
  `initdb/10-cluster.sh`, and a plain `postgres:17-alpine` in its place — so the
  shared cluster identity now joins did not exist at the pin this repository was
  running. 1770009 is kit's `master` and `origin/master`.
- **`KIT_POSTGRES_ROLE_CONNECTIONS` raised 10 → 50**, because the shared cluster's
  per-role cap is a *runtime* budget sized for one process and `bin/prime` is not
  one process. identity's pool defaults to `MaxConns = 8`, which fits; but `go
  test ./...` runs several package binaries concurrently and they share one
  per-role budget. At 10, the suite produced 34 failures, all reading
  `FATAL: too many connections for role "identity" (SQLSTATE 53300)`. At 50, the
  identical command is exit 0 with zero failures.
- **Production (`config/deploy.yml`) and CI (`.github/workflows/ci.yml`) are
  deliberately unchanged**, and both comments that had become untrue were
  corrected rather than left. Neither shares the development topology: CI's
  container is scoped to one job, and production's accessory is single-tenant on
  its own host, so there is no second service for either to be isolated from. The
  one rule that travels is that **neither may gain a `POSTGRES_USER` override**,
  and that is now written at each site with the reason.

### Added (packet identity-27)

- **`docker-compose.yml` records the measured isolation proof in the file that
  establishes it**, including the exact psql transcript above and the failure
  mode's shape. The reasoning sits at the top of the file because the next
  reader is one `grep` away from reintroducing the override, and until this
  packet the override looked like the safe answer.

### Changed (packet identity-29: identity serves no HTML, and the browser belongs to parlor)

**`identity` renders no views, and never did — it rendered one page, and that
page is gone.** The inline `html/template` literal in `internal/httpapi/oidc.go`
was the whole of this service's frontend: the password step and the TOTP
challenge step of the OpenID Connect sign-in. It is deleted, along with
`loginTemplate`, `renderLoginPage`, `oidcLoginPage`, `loginPageData` and
`writeHTML`. There is no `.html`, `.tmpl` or `.gohtml` file in the repository, and
now there is no markup in a Go string either.

**It moved rather than disappearing**, because the page is the authorization
server's user-agent interaction and OpenID Connect Core §3.1.2.1 makes
authenticating the end user part of an AS's job. Every authorization decision
stays here; the rendering goes to `parlor`.

- **New configuration: `OIDC_LOGIN_UI_URL`**, and it is **required** whenever the
  OIDC block is configured, with no default. A provider that cannot send a browser
  anywhere to authenticate **refuses to start** rather than mounting a surface
  that publishes a working discovery document and cannot complete a flow. The
  variable is named in the refusal and in the startup log.
- **`GET /oidc/login/{request_id}` answers `302` to the configured login UI** with
  `request_id`, `state`, `step`, `client_name` and — on a refusal — `error`,
  `error_detail` and `retry_after`. A user who already has a session still goes
  straight through with a code, and a signed-in browser with no flow cookie is
  still a `403`.
- **`POST /oidc/login/{request_id}`** is unchanged in shape: `{state, email,
  password}` or `{state, code}`, checked against the same `POST /v1/session` path,
  with the same MFA branch, the same per-factor lockout and the same account
  lockout.
- **The 401 and 423 answers now travel instead of being rendered.** A wrong
  password, an empty form, a refused code and a lockout are all a `302` back to
  the login UI with the reason, on a **fresh** state, so the form can be submitted
  again. The 423's wait is `retry_after` in whole seconds rather than a header,
  because a browser following a redirect does not read headers.
- **The state and MFA-challenge cookies are now `SameSite=None; Secure`**, because
  the form is a cross-site POST. They are `HttpOnly` and `__Host-`-prefixed as
  before, so the login UI's origin can neither read nor forge them, and the CSRF
  property — an unguessable value in a cookie the other origin cannot read — is
  unchanged. The flow cookie and the session cookie stay `Lax`.
- **No response in this service names a document**, including a redirect:
  `http.Redirect` writes a small HTML anchor body and `Content-Type: text/html`
  because RFC 9110 §15.4 recommends it for user agents that cannot follow a
  redirect, and this service has none.

**The contract a login UI implements against** is `internal/oidc/loginui.go` and
the `This provider renders no HTML` section of `openid/openid.yaml`. The reasoning,
the rejected alternatives and the one security header this changed are
[DECISIONS.md](DECISIONS.md) **D10**.

`client_name` and `login_hint` are **untrusted text** in that redirect — the first
is a row an account owner typed and the second is a string the client chose — so
the login UI must escape both. That was a real attack when the page was here, and
it is still one, one repository over.

**BREAKING for deployments:** a process with `OIDC_ISSUER`,
`OIDC_SIGNING_KEY` and `OIDC_SIGNING_KEY_ID` set and no `OIDC_LOGIN_UI_URL` now
fails to start. There is no backwards-compatible default, because the page this
change removes is the only one there was; the alternative is a boot failure versus
a mount that answers `503` for every sign-in, and the boot failure is the honest
one.

### Fixed (found by the red proofs: a redirect with an empty body and an HTML content type)

`delegateOIDC` copied the library's response headers verbatim and dropped only the
bytes, so `GET /oidc/authorize` answered `Content-Type: text/html; charset=utf-8`
with an **empty** body — the worst of both, because a client that believes the
header is told to parse a document and finds nothing. It now drops `Content-Type`
and `Content-Length` alongside the body on a redirect.

### Added (three checks, so "identity serves no HTML" is a claim and not a sentence)

`internal/platform/ci` — the package that guards the gate — now holds the rule:

- no `.html`, `.htm`, `.tmpl`, `.gohtml` or `.tpl` file is committed;
- no Go file carries a markup string literal or imports `html/template`, with four
  named allowances each carrying its reason, and **a stale allowance is a
  failure** — an allowance is a claim about the tree, and a claim nobody re-checks
  becomes a permission that outlives its reason;
- no response anywhere on the router answers with a `Content-Type` that names a
  document, or with a body on a redirect.

The markup check parses the syntax tree rather than grepping, and that is a
measured change rather than a preference: the first version grepped and went red
on five lines of prose this same change had written explaining the rule. A comment
cannot serve a response; a string literal can.

### Fixed (`go mod tidy` was not a no-op on master, which AGENTS.md says it is)

`go.opentelemetry.io/otel/exporters/otlp/otlptrace` was marked `// indirect` while
being a direct dependency of `internal/telemetry`, so `go mod tidy` wanted to
move it. Found while checking this packet's own gate and **pre-existing on
master** — the same edit is produced by tidying a clean checkout. CI's lockfile
guard runs `go mod download`, not `tidy`, so nothing caught it.

### Added (packet identity-28: the tenancy surface is in a document, and D1 is decided)

### Added (packet identity-28: the tenancy surface is in a document, and D1 is decided)

Ten operations the router has served since the accounts packet are now in
`openapi/v1.yaml`, under a new `tenancy` tag, with request and response schemas,
operationIds and the status table each route really answers:

| operationId | method and path | minimum role | token scope |
|---|---|---|---|
| `createAccount` | `POST /v1/accounts` | — (any session) | **refused, 403** |
| `listAccounts` | `GET /v1/accounts` | — (any session) | **refused, 403** |
| `getAccount` | `GET /v1/accounts/{account_id}` | member | `accounts:read` |
| `renameAccount` | `PATCH /v1/accounts/{account_id}` | admin | `accounts:write` |
| `deleteAccount` | `DELETE /v1/accounts/{account_id}` | owner | `accounts:delete` |
| `listMembers` | `GET /v1/accounts/{account_id}/members` | member | `accounts:read` |
| `inviteMember` | `POST /v1/accounts/{account_id}/invitations` | admin | `accounts:write` |
| `changeMemberRole` | `PATCH /v1/accounts/{account_id}/members/{user_id}` | owner | `accounts:write` |
| `removeMember` | `DELETE /v1/accounts/{account_id}/members/{user_id}` | admin | `accounts:write` |
| `acceptInvitation` | `POST /v1/invitations/accept` | — (any session) | **refused, 403** |

And two more on the OpenID Connect document, which mounted both methods and wrote
down only one of each: `POST /oidc/authorize` (`authorizeViaPost`) and
`POST /oidc/userinfo` (`userinfoViaPost`).

**What it cost before this packet:** a client generated from these documents could
list an account's API keys and register its OIDC clients, and had **no method at
all** for creating the account, inviting anybody into it, or accepting an
invitation. `cafaye-ts` had ten identity methods and none of them was
`createAccount`.

`openapi/v1.yaml` is at **1.7.0**. `knownDrift` in
`internal/httpapi/openapi_drift_test.go` is **empty** and pinned at empty, and
**D1 is decided** in [DECISIONS.md](DECISIONS.md): these are contract surface.

### Fixed (found by having to document the response: a member list identified nobody)

`GET /v1/accounts/{account_id}` and `GET /v1/accounts/{account_id}/members`
returned entries whose `user_id` was `""` and whose `created_at` was
`0001-01-01T00:00:00Z`. `membershipResponses` filled only `role`, because
`accounts.MemberSummary` is shaped for "which accounts does this user belong to"
and carries the account and the role and no user — so `Members`, which reuses the
same struct for the other direction, had nothing to project.

The wire looked like this, with three indistinguishable rows:

```json
[{"account_id":"","user_id":"","role":"admin","created_at":"0001-01-01T00:00:00Z"},
 {"account_id":"","user_id":"","role":"member","created_at":"0001-01-01T00:00:00Z"},
 {"account_id":"","user_id":"","role":"owner","created_at":"0001-01-01T00:00:00Z"}]
```

**Both operations that act on a member — `PATCH` and
`DELETE /v1/accounts/{account_id}/members/{user_id}` — need a user id the response
did not carry**, so nothing could render or remove a member. It went unnoticed
because these operations were in no document, so no generated client had a method
for either and there was no consumer whose complaint would have surfaced it.

`MemberSummary` now carries `UserID` and `JoinedAt`, the two membership columns
are selected, and every entry is the membership it claims to be.
`TestEveryMemberInAMemberListIdentifiesItself` holds it, on both routes.

**This is a behaviour change and it has no migration**, because there is nothing to
migrate: the operations were undocumented, so no client exists that reads the old
shape.

### Security (found while verifying the neighbouring gap, and NOT fixed here)

**A revoked invitation still redeems.** `POST /v1/invitations/accept` creates a
membership from a token an account admin explicitly withdrew, and leaves the row
with **both** `accepted_at` and `revoked_at` set — a state
`migrations/00013_account_invitation_revocation.sql`'s own header says cannot
happen.

Three statements, none of which mentions `revoked_at`:

- `Store.InvitationByToken` — `SELECT … FROM account_invitations WHERE token_digest = $1`
- `Service.Accept` — checks `AcceptedAt` and `ExpiresAt`, nothing else
- `Store.MarkInvitationAccepted` — `… WHERE id = $1 AND accepted_at IS NULL`

Reproduced against a real database on 2026-10-02: mint an invitation, revoke it
with the statement the admin route runs (one row affected), then redeem it as a
different signed-in user — **200, and a new membership**.

`TestTheRevokedInvitationIsActuallyDead` passes while this is true, because it
posts the redemption **with no credential** and reads the resulting 401 as the
refusal. The test asserts `accept.Code != 200`, and 401 satisfies that.

**Nothing in this packet fixes it and nothing in this packet's document change
depends on it.** It is the admin surface's whole reason for existing — recalling a
link that still works — so it belongs to its own packet. Recorded here and in
[DECISIONS.md](DECISIONS.md) D1 so it is not lost.

### Changed (the drift tripwire's admission list)

`knownDrift` is empty. The old pin said it could not grow **and could not be
emptied**; the second half is gone, because that clause was written against a list
of *known bugs* where deleting an entry could have meant deleting the memory of a
gap. The twelve and the commit that closed them are now in the list's own comment
and in DECISIONS.md D1, so the memory survives the removal.
`TestKnownDriftIsEmptyBecauseEveryServedOperationIsDocumented` pins it at zero and
its failure message is the argument for why a future entry is not the answer.

`internal/httpapi/known_drift_test.go` is new and is the proof the tripwire still
bites: it reads the **real** router walk and the **real** documents, removes this
packet's entries, and asserts all twelve come back unexplained — the same
expression `TestEveryServedRouteIsDocumentedOrNamed` evaluates, pointed at the
state the repository was in on 2026-09-30. Separately, a route was actually
reintroduced in `registerTenancyRoutes` during development and
`TestEveryServedRouteIsDocumentedOrNamed` named it and went red.

### Changed (the generated client)

`client/generated/api.gen.go` is regenerated, and `Transport` plus `Client` gain ten
methods to match: `CreateAccount`, `ListAccounts`, `GetAccount`, `RenameAccount`,
`DeleteAccount`, `ListMembers`, `InviteMember`, `ChangeMemberRole`, `RemoveMember`,
`AcceptInvitation`. Two of them return a one-time secret (`InviteMember.Token`,
`AcceptInvitation`'s body) and are documented as never being loggable.

### Re-confirmed, not changed (five emitted events are still declared nowhere)

`identity.account.created`, `identity.member.invited`, `identity.member.accepted`,
`identity.member.role_changed` and `identity.member.removed` are emitted and
undeclared, and **the blocker is unchanged**: core has no payload schema for
`identity/account/` or `identity/member/`, and `identity.member.accepted` has no
catalog row (core calls it `identity.member.joined`). Verified against core at
`5ec0cec` and again at `15a5df2`.

The five were declared on a scratch copy anyway and core's own checker run against
it: **five `event.payload-schema-missing` and one `event.unknown-published`**, which
is exactly what the reasons in `knownUndeclaredEvents` name. So the gap is left
open, pinned, and the evidence is a red build rather than a reading of a directory
listing. What core needs — five files plus a catalog row — is written down in
DECISIONS.md D1.

### Fixed (packet identity-27: the enumeration oracle on /v1/email-verifications)


- **`POST /v1/email-verifications` answered `409` when the address belonged to an
  account that had already proved its address, and the route requires no credential.**
  `security: []` is on the operation, so a caller posting a list of addresses could
  read the statuses back as a list of **verified accounts**. The 409 is gone from the
  service, from `openapi/v1.yaml` and from the generated client, and every address now
  gets the same `202 {"status":"accepted"}`.

- **The author named the threat eleven lines above the branch and then walked into
  it.** `internal/recovery/service.go`'s own comment reads *"IT HAS THE SAME SHAPE AND
  THE SAME ANSWER AS A RESET REQUEST — one status, one body, whatever the row says …
  only one of them being careful would leave the other as the oracle"*, and the body
  of that same function did `if user.IsVerified() { return ErrAlreadyVerified }`. The
  branch was argued for on user-experience grounds — a client told "we emailed you"
  on the strength of a refused request renders a confirmation screen the user cannot
  leave — and **never accounted for the route being unauthenticated**.

- **The information is still published, on an authenticated route.**
  `GET /v1/email-verification` requires a session cookie and answers `200` for every
  signed-in account, proved or not, with `email_verified` and `email_verified_at`. A
  client that needs to say "this address is already verified" asks the route that knows
  who is asking; the 409 published the same fact to a stranger. **`openapi/v1.yaml`
  is at `info.version` 1.6.0, which is the first bump here that removes a status
  rather than adding one** — a client with a branch on that 409 has to be rebuilt, and
  the version is what makes that visible.

- **No `return nil` branch either.** `if user.IsVerified() { return nil }` would keep
  the 202 honest while leaving the route's behaviour a function of the row's state —
  which is the shape the 409 came from and is one line away from being an oracle
  again. A proved account that asks for a link is **sent** one: the message confirms
  something already true, `users.Store.MarkEmailVerified` is conditional on the column
  still being null so `email_verified_at` records the first proof and does not move,
  and the cost is one message to the account's own inbox.

- **`recovery.ErrAlreadyVerified` is deleted rather than left unused.** Grep found no
  other caller: the HTTP layer's mapping was the only one, and a sentinel error that
  names a behaviour nobody implements is a trap for the next reader.

- **`openapi/v1.yaml:2467`'s `sub` example was `ab000000-0000-0000-0000-0000000000u1`,
  which is not a uuid** — `u` is not a hex digit, on a field declared `format: uuid`.
  It was in **four** places, not one (`sub`, `user_id` twice and `actor_user_id`), so
  fixing the line the finding named would have left three of the same defect in the
  tree. All four are hex now, and `TestEveryIdentifierInAnExampleIsAUuid` walks both
  committed documents so the next one is a red build. The check asserts hex digits and
  the canonical grouping and **not** the RFC 4122 version/variant nibbles, because
  these examples are mnemonic on purpose (`a1` api key, `b1` user, `c1` account, `d1`
  invitation). Its red proof was run: reinstating `u1` reds it with the file and line.

- **`parlor-23` measured a truncated token answering `404` where `minLength: 43` implies
  a `422`. Re-measured here rather than taken on trust, and confirmed: nothing between
  the handler and `tokens.Live` looks at the token's length.**
  `TestATruncatedTokenAnswers404Not422` drives a token
  truncated by one character, one far too short, one too long and one that never
  existed at all, at each of the three redemption routes, and asserts all four answer
  the same `404` byte for byte — and that the `422` the document really does list is
  reachable, for a field the endpoint does not accept.

- **The document is the side that changed, and the reason is worth stating.** The
  schema's own description already called the length "load-bearing **on the client
  side** … it is what tells a caller the value is complete before it is pasted into a
  URL"; what was missing was the sentence saying the service does not enforce it.
  Adding a length check in the handler was the other answer and was rejected:
  `recovery.ErrTokenNotFound`'s contract is **one answer for every token that is not
  live**, and a fifth case told apart by a property of the input buys a caller with a
  bug in its own link builder a prettier error at the cost of a branch on the
  anonymous surface whose whole argument is that it has none.

- **The sibling audit: one question per route a stranger can reach, answered in a test.**
  `internal/httpapi/anonymous_enumeration_test.go` walks the router and requires its
  table to be **exactly the mounted family in both directions**, so a route added under
  `/v1/users`, `/v1/me`, `/v1/session`, `/v1/password-resets`,
  `/v1/email-verification`, `/v1/email-changes` or `/v1/introspections` is red until
  somebody has answered *can the response distinguish "exists" from "does not"?* — 14
  routes, 14 rows. Both directions were shown to fire.

- **Two rows answer YES, and they are named rather than quietly reclassified.**
  `POST /v1/users` publishes "that address is taken" (one account per address is the
  unique index, and a caller registering has to be told) and `POST /v1/session`
  publishes "that account is locked" through a `423` the lock check reaches **before**
  the password. The first is pinned to one bit; the second is measured, held, and
  explained as strictly dominated by the first — one request instead of six, no state
  change. **Whether registration should publish it at all is a product decision, and
  it is DECISIONS.md D9.**

- **`POST /v1/introspections` is an oracle BY DESIGN and now says so in a test.**
  `TestIntrospectionIsAnOracleByDesignAndGatedOnACredential` asserts the answer differs
  for a live token and a dead one — that is the endpoint working — and then asserts
  what actually protects it: `401` with no credential, a token may read itself and not
  a peer, and a session outside the account is refused.

- **One flake was found by this packet's own gate run and fixed, because a gate that
  is red half the time is not a gate.** `internal/courier`'s
  `resolveLinkTemplates` ranged the `linkPurposeFor` MAP and returned on the first
  purpose with no template, so a deployment with **neither** link template configured
  was told to set a different variable on each boot — and
  `TestTheConstructorRefusesAPurposeWithNoLinkTemplate`'s "no template for either" row,
  which asserts which purpose gets named, failed roughly half of all runs. The order is
  now fixed and **sorted by purpose rather than by mail subject**, because the refusal
  is about a configuration variable and an answer that depends on courier's prose is
  not one identity can state. Ten consecutive runs, green.

- **One thing was found and deliberately not changed, and it is reported again here.**
  `go mod tidy` promotes `otlptrace` from indirect to direct on a clean HEAD. That is
  a pre-existing defect unrelated to this packet, and `go.mod` and `go.sum` are
  untouched by it so the diff stays reviewable. It needs its own packet.

### Fixed (packet identity-26: the verification link opened the password-reset screen)

- **A `welcome` mail's button said `https://app.example.com/reset?token=…`, so a
  user who clicked "Confirm your email address" landed on the password-reset screen,
  where a verification token answers 404.** identity-24 drove the flows end to end
  against a real courier and found it: the token itself was fine and redeemed
  correctly at `POST /v1/email-verifications/confirm`, and the mail was well-formed.
  **Nothing about a URL says which screen it opens**, so no assertion about bytes
  could ever have caught this — every test in the repository was about the request
  courier received, and the request was correct.

- **The cause was structural and defended at length.** `RecoveryMailer` held ONE
  `LinkTemplate` for all four of its messages. The single-template argument is sound
  *for a recovery link* — a template with `{token}` beats a base URL plus a
  platform-chosen convention — and it was applied to a verification link, which is
  not a recovery link. **One template for two purposes is a template that must be
  wrong for one of them.**

- **Two templates now, keyed by `recovery.Purpose`, and a purpose with none is a
  refusal rather than a fallback.** `RECOVERY_LINK_TEMPLATE` is the *default* for
  every purpose with no variable of its own; `PASSWORD_RESET_LINK_TEMPLATE` and
  `EMAIL_VERIFICATION_LINK_TEMPLATE` override it. `NewRecoveryMailer` refuses to
  construct without one for every purpose it can deliver, and refuses a template for a
  purpose no message carries — the same rule as a route with no declared scope, and a
  variable that is honoured nowhere is a promise this service does not keep.
  `ValidateLinkTemplate`'s three refusals (no `{token}`, not absolute, a fragment)
  apply per purpose rather than once.

- **`RECOVERY_LINK_TEMPLATE` still works, and a deployment that has only ever set it
  still boots with the links it had.** That is the compatibility promise and it is
  deliberate: the alternative is refusing to start every installation that exists, on
  the security boundary, to fix a defect introduced after they were configured. **The
  cost is that an unmigrated deployment's verification link still points wherever its
  one template says**, and identity does not hide it — `buildMailer` warns at startup
  when any purpose resolves to the shared default, naming the purpose, what a reader
  would find (a 404), and the variable that gives that purpose a link of its own.
  Adding `EMAIL_VERIFICATION_LINK_TEMPLATE` is the whole migration (DECISIONS.md D8).

- **The test that would have caught it.** Nothing about a URL says which screen it
  opens, so the check reads the **rendered link** and redeems what is in it:
  `TestAVerificationLinkIsNotThePasswordResetLinkAndEachRedeemsAtItsOwnEndpoint`
  builds the mailer from a `config.Load` of an environment rather than from a Go
  literal — a relationship between two links cannot be tested by something that
  cannot express it — sends a reset and a verification through the real flows over a
  real database, and asserts the two links differ in **path** and that each token is
  accepted by its own endpoint and refused by the other. Its **negative control**
  proves one template really does render one link for both messages, so the inequality
  is a comparison rather than a tautology, and the inequality was shown to fire by
  injecting the original defect (making the verification purpose read the reset
  variable).

- **Three closed sets that nothing in the type system joins** are now walked against
  each other in both directions: `internal/courier`'s `linkPurposeFor`, `internal/config`'s
  `linkTemplateVariables`, and `recovery`'s purposes. A purpose with a variable nothing
  renders, and a message with no variable at all, are both reachable by editing one
  map.

- **`validateMailBaseURL` no longer lies.** Its refusal said `want https` directly
  above code that accepts `http` and a test that requires `http://localhost:4003` to
  boot, so it told an operator a scheme this service starts up with is one it rejects.
  Both courier messages now name `http or https`, and
  `TestAnInsecureLinkTemplateIsDescribedAsThoughHTTPSWereTheOnlyOneAccepted` holds it
  there.
### Fixed (the OAuth social-login claim, and the check that stops the next one)

- **This service advertised OAuth social login in four places and served it in
  none.** `README.md`'s opening paragraph listed "OAuth" among the things identity
  owns, the roadmap carried `- [x] OAuth (social login) via goth`,
  `cafaye.yml`'s `description` claimed the capability in the manifest customers
  are handed, and a directory of correct, database-tested code said so by
  implication. **There is no route, no handler, no use case, no `internal/httpapi/oauth.go`,
  and no `OAUTH_*` configuration variable.** A customer integrating "Continue with
  Google" against this service got a `404`.

  All four claims are now false in the other direction, and
  `internal/httpapi/claims_test.go` is what holds them there. It found the manifest
  claim and the roadmap claim **by name on its first run**, which is the evidence
  that it would have found them before.

- **`internal/oauth` is written, tested against a real database, and unmounted —
  and now says so in its own package doc.** `NewState`/`VerifyState` are live (the
  OIDC login uses them); the registry, the code-for-token exchange, the token
  cipher and the `connected_accounts` store have no caller. `migrations/00008_connected_accounts.sql`
  is applied and nothing writes to it. The table is **left in place deliberately**:
  an applied migration is not edited, and a `DROP TABLE` on the security boundary to
  tidy an unused table is a bigger intervention than leaving it.

  Three comments in that package asserted things about the code that were not
  true, and each is now corrected in place rather than deleted:
  `client.go` pointed at `internal/httpapi/oauth.go`, a file that has never
  existed; `settings.go` said `internal/config` reads the environment into a
  `Settings`, and that package contains no `OAUTH_` string at all; and
  `provider.go` named `migrations/00005_connected_accounts.sql`, which was
  renumbered to `00008` when the accounts packet moved it.

- **Google's `email_verified` is not read, and is now recorded as a gap rather
  than left as a silent one.** `internal/oauth/client.go` decodes Google's `email`
  with no check on `email_verified`, while the GitHub path already refuses an
  unverified address. For a relying party deciding whether to sign somebody in,
  that is a takeover primitive. It is unreachable while the surface is unmounted,
  which is a weaker state than "closed", and the comment now says so and names it
  as the first task of the packet that mounts this.

- **A second tripwire: the README, the roadmap and the manifest are held to the
  router, in both directions.** `openapi_drift_test.go` answers "is the contract
  the router?"; this one answers "is everything the repository says about the
  router true?" — a service can have a perfect OpenAPI document and still
  advertise an endpoint that does not exist, and the prose is what a customer
  believes. Four files:

  - `claims_test.go` — the three claim sources above, both directions, plus a
    manifest capability→route table that is pinned in both directions and a
    roadmap table that **cannot grow** (growth is how a capability gets excused of
    having a route).
  - `claims_reader_test.go` — faults injected into the readers. A block-scalar
    `description`, a malformed route row, an emptied roadmap. Every way the reader
    could under-read is an error, because two readers that both find nothing agree.
  - `claims_faults_test.go` — the walk itself. It asserts a route from **each**
    conditional surface is visible rather than that a field was set (a field test
    passes against a registrar that mounts nothing), that the two options literals
    stay in step, and that each claim check goes **red** on a route that does not
    exist.
  - `oauth_absent_test.go` — the inverse, asserting the social-login surface is
    still unmounted, with **its failure message as the work order** for whoever
    mounts it. Finishing that work means deleting the file.

- **`go test -race` was failing on 52 to 64 tests per run, before this packet, and
  is now clean.** `newMux` recorded the pattern list it built into a package
  variable for the observability canary, and the variable was unguarded. This
  package builds routers from dozens of parallel subtests, so the race detector
  reported a WRITE/WRITE from two goroutines and failed whichever test happened to
  be running — a different set on every run, which is the shape of a flake nobody
  can chase. The variable is now mutex-guarded and read through
  `recordedRouteTable`, which copies under the lock. This is AGENTS.md's own rule
  — no globals, no init-time state — and it was a real violation, not a tidy-up.
  Verified as a **pre-existing** condition by running `go test -race` on a clean
  clone of HEAD: 62, 64 and 52 failing tests across three runs. `go test -race ./...`
  is green three times over.

- **One README row could not be read by a correct reader and was rewritten.**
  `| GET /oidc/introspect, /oidc/revoke, ... |` was one methoded path and three
  bare ones in a single cell — a promise and a refusal in one row. The method is
  gone, which is also more accurate: there is nothing behind those paths to answer
  a method.

**What was deliberately not done.** The surface was not mounted, and that is a
decision rather than an omission: the missing piece is a **product decision about
which user a callback resolves to** (a provider email matching an existing
`users.email` is a takeover if permitted and a support call if refused — Jumpstart
Pro refuses, and this repository has not chosen), and a cross-site browser surface
this service does not have. Wiring the routes without settling either would have
produced a plausible implementation with a subtle flaw, on the platform's security
boundary, and `PLAN.md` §3 puts identity behind a user-run security review. The
README's "Social login is not built" section records all of it, and the absence
test's failure message is the checklist for the packet that will do it properly.

### Changed (merge of the recovery and observability packets)

- **Both CI floors were remeasured on the merged tree**, and this is the third
  distinct pair these numbers have taken: `SUITE_FLOOR` 1254 → 1864 → 1939 →
  **1989**, `DATABASE_TIER_FLOOR` 1166 → 1609 → 1715 → **1732**.

  Neither incoming number was ever true of this tree. The recovery packet
  measured 1939 / 1715 on a branch without the telemetry tests; the observability
  packet measured 1864 / 1609 on a branch without the recovery tests. The two
  packets added tests in overlapping files rather than replacing each other, so
  the merged counts come out **higher than both** — 1989 and 1732, zero SKIP
  anywhere, across the 14 packages that open a pool.

  Taking either side's number would have installed a floor this tree does not
  meet, and the gate would have gone red on a healthy tree for a reason that had
  nothing to do with the code. A floor is a claim about the present, so the merge
  that made two incomplete claims produces one claim about the result.

  Measured with `go test -json -count=1 ./...` against a real `postgres:17-alpine`
  with migrations applied, counting per-package PASS events rather than reading a
  summary line — the same partition the check computes.

### Added (packet identity-17-mailer)

- **Password reset, email verification, and email change.** Three flows that can
  only be finished by proving you can read an inbox, on eight new routes and one
  package: `POST /v1/password-resets`, `POST /v1/password-resets/confirm`,
  `POST /v1/email-verifications`, `POST /v1/email-verifications/confirm`,
  `GET /v1/email-verification`, `POST /v1/email-changes`,
  `POST /v1/email-changes/current-address`, `POST /v1/email-changes/new-address`.
  `openapi/v1.yaml` is at **1.5.0** with a new `recovery` tag; the generated Go
  client and its wrapper were regenerated in the same commit.

  They are one package (`internal/recovery`) and one table (`recovery_tokens`,
  migration 00015, with a `purpose` CHECK) rather than three, because the token
  lifecycle is identical in all three: mint 256 bits, store only the SHA-256, mail
  it, expire it, spend it with a conditional write that makes a second presentation
  a refusal. Splitting them would have produced three token formats, three expiry
  rules and three answers to "is this still live". A `password_reset` token
  presented to the verification route is a **404**, not a different error.

- **The email change has two confirmed sides, and the second token does not exist
  until the first is redeemed.** A stolen session can start a change, and what it
  produces is a link in the victim's inbox and nowhere else: the attacker cannot
  advance it, and the victim gets the one warning they would otherwise never get.
  The schema enforces this rather than the code — `recovery_tokens` carries a
  `target_token_digest`, and a CHECK refuses a row with a target whose first side
  is not confirmed. Presenting either token to the other route is a 404, and so is
  presenting either one alone.

- **A password reset and an email change end every session and every live OIDC
  access token, in the same transaction that makes the change**, and mint nothing.
  Scoped API keys deliberately survive, which is the same rule and the same reason
  as MFA: a key is a credential somebody created for a script, and silently
  revoking one breaks a CI job with nothing in the response saying why. Address
  verification revokes nothing either — a verification is a fact about an address,
  not a credential.

- **The request routes cannot be told apart.** `POST /v1/password-resets` and
  `POST /v1/email-verifications` answer a registered address, an unregistered one
  and an address inside the cooldown with `202 {"status":"accepted"}` — identical
  bytes, asserted by byte comparison over HTTP. The body is a **constant** in the
  handler rather than a template with a field that happens to render the same
  either way, because a field is a field and the next person to add an `expires_at`
  reinstates the oracle without touching a test.

- **The delivery path is one seam, and this repository wires the implementation
  that fails.** `recovery.Mailer` is `Send` and `Ready`; the second exists so a
  request flow can ask whether a message can be delivered *before* it mints a
  token or looks the address up, which is what stops a deployment with no mail
  turning "503 against 202" into an account-existence oracle. `main` wires
  `recovery.Unavailable{}`, and every route that needs to send answers `503
  service_unavailable` with a sentence naming the deployment problem. **No message
  is ever logged**, and `TestNoRecoveryTokenReachesTheLogs` drives all three flows
  through a logger that keeps everything to prove it.

  **The honest limit: a user who forgets their password cannot recover today.**
  The flows are complete and tested over a recording double; courier's delivery
  path is unfinished, so there is nowhere for the link to go. Wiring it is three
  lines in `buildRecovery` (DECISIONS.md D7). The alternative considered and
  rejected was a mailer that logs, so an operator could see it "worked" — a live
  single-use credential in a searchable log aggregator is a credential anybody who
  can read the logs can redeem.

- **`users.email_verified_at` (migration 00014), and `GET /v1/me` did not grow a
  field for it.** `GET /v1/email-verification` is a separate route because
  `/v1/me`'s projection is asserted field-by-field to be exactly `id` and `email`.
  An email change **clears** the verification in the same statement that moves the
  address, so the `200` from the new-address confirmation says
  `email_verified: false` — clicking a link proves you can read an inbox, not that
  the address is yours. `identity.user.email_verified` is emitted for a real
  verification only.

- **Two events, declared in `cafaye.yml`:** `identity.user.email_verified` and
  `identity.session.revoked` (with a closed two-value `reason`). The second is
  emitted **only** where every credential the account holds is gone — never for a
  single `DELETE /v1/session`, which is a different fact with a different
  consequence for a consumer. That gap is recorded in README.md rather than
  papered over by emitting the wrong type.

- **Every route on the surface refuses a scoped API token with 403**, and two
  require a session. A credential that could start an email change could move an
  account's recovery path, and a credential that could mint a password reset is a
  takeover with a delay rather than a break-in — so there is no scope for any of it
  and there is not going to be one. The four redemption routes are anonymous
  because the token in the body **is** the credential, and
  `TestNoRecoveryRouteAcceptsASessionInPlaceOfItsToken` holds that they do not
  quietly require one.

- **A cooldown, not a rate limiter.** One minute per address per purpose; a request
  inside it mints nothing, sends nothing, and answers identically. It does **not**
  supersede a live link — a request route that invalidated one would let anybody
  invalidate a victim's pending reset. It is not per-client and does nothing about a
  flood spread across a thousand addresses; per-source throttling belongs to
  courier, which is in the path of every message this service sends. Declared as a
  gap rather than invented here.

- **`oidc.Store.RevokeAccessTokensForUser`** — the JWT half of "a reset ends the
  credentials issued before it", on the `Store` rather than on `Storage` so it
  works without a signing key. `Profile.EmailVerified` now reads
  `email_verified_at`, so `email_verified` in a `userinfo` response stops being a
  guess.

### Added (observability)

- **identity emits OpenTelemetry spans into the collector that ships with kit's
  stack.** `IDENTITY_OTEL_ENDPOINT` is the only contract (core D16) and it is
  **on by default** — unset, it is `http://otel-collector:4318`. Before this, a
  deployed identity produced no traces and no request timings, and the collector
  kit ships had nothing to receive.

  - **One request span per request, named `identity.http.request`**, with the
    status class, the method and — where one exists — the **route template**.
  - **`http.route` is chi's `RoutePattern()`, never `r.URL.Path`.** A template has
    one value per endpoint; a concrete path has one per request, and kit's
    collector derives metrics with a `spanmetrics` connector that mints a series
    per distinct value. It is read from the `chi.RouteContext` **inside** the
    handler chain, because a middleware outside the router sees no route at all —
    and an assertion placed in the wrong place passes against an empty string.
  - **A 404 carries NO route.** The path is caller-controlled text there, so
    recording it is the cardinality bomb and the content leak in one move. The
    404 status is the answer.
  - **Only 5xx is an error span.** A 401 or a 404 is identity refusing a caller,
    which is identity working; an error rate that counts them is a function of
    how much guessing the internet absorbs, and an alert on that pages somebody
    to switch off the protection doing its job.
  - **One allowlist, one choke point.** Every attribute goes through
    `telemetry.Record/2`, projected from `core/schemas/telemetry/*.schema.json`.
    The realistic failure is not an attacker; it is a well-meaning engineer in
    six months adding a user's email because it would help debug a login, in the
    service that holds every user's email and password digest.
  - **The redaction proof fails when the boundary leaks.**
    `internal/telemetry/canary_test.go` plants a canary in every field a caller
    controls — path, query, bearer token, API key, cookie, user-agent, a
    malformed `traceparent`, a login body, a TOTP code — drives real requests
    through the real router, and fails if that string reaches an exportable
    attribute. Every absence assertion is paired with a presence one, because a
    boundary that deletes everything passes "no canary" and is useless.
  - **Metrics come from the collector, not from identity.** `spanmetrics` runs
    after redaction, so a derived metric cannot carry a dimension the allowlist
    stripped, and there is no second definition of the same series in the fleet.
  - **Logs cost nothing.** compose `logging:` ships the container's stdout to the
    collector's `syslog/crash` receiver, which makes a panic a log record with a
    `service.name` on it and no per-language log SDK in the module.
- **Two dependencies, with their cause:** `go.opentelemetry.io/otel/sdk` and
  `go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp` (v1.46.0).
  grpc, protobuf and grpc-gateway arrive transitively through `otlpconfig`.
  Deliberately **not** added: `otelhttp`'s handler (it records `url.path`,
  `url.query` and headers itself — one control where this repository insists on
  two, which is why the middleware is hand-rolled), `otel/sdk/metric` (metrics
  come from the collector), and `otel/log` (logs come from the container).
- **`kit.ref`, kit's `bin/dev` verbatim, and `docker-compose.yml` reduced to an
  OVERRIDE** on kit's stack — this service, its database name and role, and the
  crash layer. No collector configuration (kit derives the redaction allowlist
  from core's schemas, and a service that owned that file would be shipping a
  telemetry boundary nobody derived), no postgres container of its own, and no
  `depends_on: otel-collector`: a service that waits for the collector serves no
  traffic while the collector is down, which is strictly worse than serving
  traffic with no traces.
- **`bin/migrate`,** so `bin/dev` has a migration step to call. Migrations stay a
  deploy step and are still above the suite, never inside it.
- **`-healthcheck` on the binary.** The image is distroless, so there is no
  `curl` and no shell for a `CMD-SHELL` probe; a flag the binary itself answers
  is the only healthcheck that works there.

### Changed (observability)

- **`internal/httpapi`'s router is now wrapped, not rebuilt.** Every route is
  registered through a `tracedRouter` decorator that wraps the handler, so a
  route added by any of the seven `register*` functions is traced without that
  function knowing telemetry exists. It is a decorator and not a chi `Use`
  middleware for a **measured** reason: chi fills `RoutePattern` in on the
  request it routes to, and neither an outer middleware nor a `Use` middleware
  ever sees it — only the matched handler does. No handler behaviour changed, no
  route moved, and the authorization matrix walk reads the undecorated tree so
  that a wrapper is not counted as a second route. The authorization matrix suite
  is unchanged and still green.
- **`New`'s middleware order is now `telemetry → trace id → recovery → mux`**, and
  recovery is deliberately *inside* telemetry: a panic recovered above the span
  would write its 500 with no span carrying the status, which is the one request
  an operator most wants to find.
- **Two test seams on `httpapi.options`,** both empty in every real process. A
  route that panics, and a *parameterised* route. The second exists because of a
  fault injection, and the finding is worth stating: replacing `traced`'s
  `RoutePattern()` with `r.URL.Path` made **every** observability test in this
  package pass. A suite of fixed requests cannot tell a template from a path,
  because for a request with no path parameters the two are the same string. The
  first version of the panic seam also swapped out the whole mux, which meant the
  request never passed through chi, never got a template, and produced a 500 on a
  span with no route on it — a test asserting about a service that is not the one
  that ships. Both seams replace exactly one route and change nothing else.
- **CI's `SUITE_FLOOR` 1254 → 1864 and `DATABASE_TIER_FLOOR` 1166 → 1609**, in the
  same commit as the tests that moved them and counted by CI's own awk rather
  than by hand: 1864 `--- PASS:` lines, 0 `--- SKIP:`, across 19 packages; the
  1609 is the whole of that inside the 13 packages that open a pool.
  `internal/httpapi` went 669 → 688 because the observability suite drives the
  **real** router and therefore runs inside the database-tier package, and the
  new `internal/telemetry` package opens no pool — so its tests are in
  `SUITE_FLOOR` and not in `DATABASE_TIER_FLOOR`, which is the partition working
  as intended rather than a rounding error.
  The 1254 was also **stale by 535** before this packet: `gate.yml`'s own measured
  line already read 1789. A floor nobody re-measures is a floor that only catches
  a very large deletion.

### Fixed (one postgres image fleet-wide)

- **CI runs the same postgres the dev stack does.** This workflow pinned
  `postgres:17.11-alpine` while `docker-compose.yml` floated at
  `postgres:17-alpine`. Both are now `postgres:17-alpine`, which is also what
  core declares fleet-wide.

  The minor pin was deliberate — pinned to the exact minor the numbers in this
  file's comments had been measured on — and that is what made it the wrong pin.
  Pinning a minor only buys a stronger guarantee when nothing else needs to
  agree with it, and here everything did: a machine running the dev stack and
  anything CI-shaped stored **two postgres builds**, and a developer and a runner
  could sit on different ones. The cost was invisible in the line that carried
  it.

  A digest is the stronger pin and is still not used, for the reason the previous
  comment gave and which survives: the digest that resolves on an arm64
  workstation is not the one that resolves on this linux/amd64 runner, so a digest
  would pin CI to a build no developer can run locally. `17-alpine` is the finest
  pin that still means "the fleet's image" on every platform, and it is what
  makes one pull serve both. No test behaviour changed.

### Fixed (kit-18 D12 sweep)

- **The `env:` caveat no longer explains itself with a limitation core no longer
  has.** This file named `gate.ci-disagrees` "reads `run:` bodies textually" as
  the reason a workflow's environment is invisible to the static phase. That
  reason was D12 — core's `RUN_KEY` matched only a `run: |` block — and core
  `63fd319` fixed it, so the sentence sent the next reader looking for a
  limitation that is gone.

  The caveat is unchanged and still true, because it is a *different*
  limitation: core reads a workflow's step bodies to confirm the gate is
  invoked, and reads no `env:` block at all. The comment now says exactly that,
  so both the claim and its reason are current. `tests/gate_declaration_check.py`
  (kit-18) sweeps the adopting repositories for precisely this shape and is what
  found it.

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
