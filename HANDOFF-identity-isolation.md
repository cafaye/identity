# HANDOFF — identity isolation (packet identity-isolation-01)

Branch `worker/identity-isolation-01` in `cafaye/identity`. Two commits, nothing
pushed, nothing merged, nothing tagged. Nothing outside `migrations/` and
`internal/tenancy/` was touched.

Read this before starting: **the substrate and the proof are done. But this branch
is NOT MERGEABLE, and the reason is the most important thing the pilot found:
applying the substrate alone makes registration return `500`.** Every account-scoped
`INSERT` now needs `cafaye.begin_account(...)`, and nothing in this service calls it
yet. The migration and the application wiring cannot be separated — which is the
opposite of how kit's README presents them as independent numbered steps.

There is also a blocker in core that has to be resolved by somebody who owns kit or
core before the declaration can be written honestly. Those are the two things left.

## THE BRANCH IS RED, AND THE RED IS 00016

`go test ./...` **with** a database, on this branch:

```
--- FAIL: TestNewAppServesTheAuthSurfaceWithADatabase (0.09s)
    wiring_test.go:58: POST /v1/users = 500, want 201
--- FAIL: TestNewAppMountsMFAWithAKey (0.10s)
    mfa_wiring_test.go:59: POST /v1/users = 500
--- FAIL: TestNewAppWithoutMFAKeyMountsNoManagementRoutesAndStillChallenges (0.07s)
    mfa_wiring_test.go:152: POST /v1/users = 500
--- FAIL: TestNewAppWithoutOIDCKeysIsNotAProvider (0.06s)
    oidc_wiring_test.go:137: POST /v1/users = 500, want 201
FAIL	github.com/cafaye/identity/cmd/identity	2.505s
--- FAIL: TestAResetDoesNotRevokeAScopedAPIKey (0.04s)
    password_reset_test.go:302: creating the fixture membership:
    ERROR: new row violates row-level security policy for table "account_users" (SQLSTATE 42501)
FAIL	github.com/cafaye/identity/internal/recovery	9.967s
--- FAIL: TestTheCoverageExclusionIsOnlyGeneratedCode (0.03s)   ← PRE-EXISTING, unrelated
FAIL	github.com/cafaye/identity/internal/platform/ci	3.113s
```

`POST /v1/users` is registration. It provisions a personal account and its owner
membership, and `account_users` is now protected, so the membership `INSERT` is
refused by `with check (account_id = (select cafaye.current_account_id()))` —
`current_account_id()` is NULL because nothing has called `begin_account`, and a
NULL identity is `not true`. `internal/recovery`'s failure is the same defect with
the error left visible.

**This is not a bug in the substrate.** It is the substrate refusing to work
without the caller, which is exactly what it is for. It is a bug in the *packet*,
which put the migration in this hour and the wiring in the next one.

### Your first move, then

Choose one, and this is the decision the packet could not make for itself:

- **(A) Land `begin_account/1` wiring first, then re-apply 00016.** One packet
  containing both. It touches every query's behaviour, which is why it deserves its
  own hour — so budget a full packet for it and treat 00016 as part of it.
- **(B) Revert 00016 and keep only the proof**, which then has to run against a
  database where the migration is applied by hand. Nothing in the rest of this
  branch depends on the migration being in the migration chain.

Do not merge as-is. Nothing else in this repository is in worse shape than before,
and the finding is worth more than the code — but a branch that 500s registration
is not a branch.

### And one more kit finding, which the same run produced

`internal/tenancy`'s own copy of kit's assertion set goes red **only when the whole
suite runs**, never when the package runs alone:

```
--- FAIL: TestTenancyAccountIsolation (0.04s)
    sweep/the-only-finding-is-the-control
      expected "cafaye_probe_unprotected:row level security is not enabled"
      actual   "…,account_audit_log:row level security is not enabled,
                account_invitations:…,account_users:…,api_keys:…,oidc_clients:…"
```

Those five are **not** the real tables — `pg_class.relforcerowsecurity` is `t` on
all five and the proof above reads the denials happening. They are the private
fixture schemas that `internal/platform/dbtest.Schema(t)` builds with
`LIKE ... INCLUDING ALL`, and **`LIKE` does not copy row-level security**, so every
one carries an `account_id` column and no policies. `go test ./...` runs packages
in parallel, so kit's sweep assertion — which is a *whole-database* assertion
expecting exactly one finding, its own control — sees a neighbour's fixtures.

**kit's assertion set assumes it owns the database.** A service whose tests create
private schemas cannot use it unmodified. The fix belongs in kit: scope
isolation.sql's sweep assertion to `pg_temp` (where its own fixture lives) rather
than to the whole database. This is a separate finding from the scanner one below
and it will bite every adopter that uses a private-schema fixture helper.


---

## Done, and verified

### 1. The substrate — `migrations/00016_account_isolation.sql`

kit's `templates/database/tenancy/substrate.sql` copied verbatim, plus five
`select cafaye.protect_table(...)` calls: `account_users`,
`account_invitations`, `oidc_clients`, `api_keys`, `account_audit_log`.

The table list was derived by grepping `account_id` across `migrations/` and
reading each declaration. It is not copied from the packet, though it happens to
match. The tables deliberately **absent** are named in the migration header,
because "not in this migration" otherwise reads as "not thought about":
`users`/`sessions`/`recovery_tokens`/`mfa_*` are global until a request is
authenticated and have no account column; `connected_accounts` is per-user;
`accounts` is the row the others point at.

Verified against `postgres:17-alpine` with kit's real
`initdb/10-cluster.sh` mounted (so `identity` and `identity_app` are provisioned
the way the dev cluster provisions them), all 16 migrations applied by `goose`:

```
select * from cafaye.unprotected_tables();
 table_schema | table_name | why
--------------+------------+-----
(0 rows)
```

### 2. The proof — `internal/tenancy/`

`isolation.sql` and `assertions.txt` copied from kit; `tenancy_test.go` is kit's
driver with three deliberate changes, each commented in the file:

| kit's template | here | why |
|---|---|---|
| `//go:build tier_db` | **no build tag** | this repo has no `tier_db` convention and `ci.yml` runs `go test ./...` with no tags, so a tagged test is never *compiled* in CI |
| `TestAccountIsolation` | `TestTenancyAccountIsolation` | so `-run Tenancy` selects it, which is the verification command in the packet |
| `t.Skip` on absent DSN | skip message that says **NOTHING WAS CHECKED** and gives the command; `REQUIRED_DB=1` turns it into `t.Fatal` | identity's house convention, and CI already fails on any undeclared `--- SKIP:` line |

Plus a second test kit's set cannot be —
`TestTenancyIdentityOwnsItsFiveTables` — because kit's `isolation.sql` protects
its own **temporary** fixture table and never names identity's five. It checks
the catalog half (enabled, and **FORCED**, plus an `account_id`-leading index and
policies) and the three-way denial half on real rows as **both** roles.

---

## The gates that ran, and their real output

```
$ go build ./...
build=0

$ go vet ./internal/tenancy/
vet=0

$ gofmt -l internal/tenancy/
(clean)

$ TEST_DATABASE_URL="postgres://identity:postgres@127.0.0.1:15999/identity?sslmode=disable" \
    go test ./internal/tenancy/ -run Tenancy -v -count=1
=== RUN   TestTenancyAccountIsolation
    tenancy_test.go:157: kit's assertion set returned 24 assertions
--- PASS: TestTenancyAccountIsolation (0.03s)
=== RUN   TestTenancyIdentityOwnsItsFiveTables
=== RUN   TestTenancyIdentityOwnsItsFiveTables/every_declared_table_is_enabled_and_FORCED
=== RUN   TestTenancyIdentityOwnsItsFiveTables/the_sweep_finds_nothing_unprotected
=== RUN   TestTenancyIdentityOwnsItsFiveTables/three-way_denial_as_identity_app
=== RUN   TestTenancyIdentityOwnsItsFiveTables/three-way_denial_as_identity
--- PASS: TestTenancyIdentityOwnsItsFiveTables (0.03s)
    --- PASS: .../every_declared_table_is_enabled_and_FORCED (0.00s)
    --- PASS: .../the_sweep_finds_nothing_unprotected (0.00s)
    --- PASS: .../three-way_denial_as_identity_app (0.01s)
    --- PASS: .../three-way_denial_as_identity (0.01s)
PASS
ok  	github.com/cafaye/identity/internal/tenancy	0.626s
```

Both skip paths verified too, because a skip that has not been seen skip is not a
skip:

```
$ go test ./internal/tenancy/ -count=1          # no TEST_DATABASE_URL
--- SKIP: TestTenancyAccountIsolation (0.00s)
    tenancy_test.go:114: TEST_DATABASE_URL is unset, so NOTHING WAS CHECKED HERE. …
ok  	github.com/cafaye/identity/internal/tenancy	0.372s

$ REQUIRED_DB=1 go test ./internal/tenancy/ -run Tenancy -count=1
--- FAIL: TestTenancyAccountIsolation (0.00s)
--- FAIL: TestTenancyIdentityOwnsItsFiveTables (0.00s)
FAIL	github.com/cafaye/identity/internal/tenancy	0.416s
```

---

## The proof output itself, both roles, measured

Taken by hand against the same cluster with `psql`, because a passing assertion
name is a filename and a reader wants the numbers.

**As the OWNER (`identity`), which is the role that matters — every service here
runs its migrations as its own role, so the owner owns every table:**

| | rows visible |
|---|---|
| no identity | **0** |
| ANOTHER tenant's VALID identity, on ITS rows | **1** (its own) |
| …of that tenant's rows specifically | **0** |
| its OWN identity, its own rows | **1** |
| its OWN identity, unqualified read | **1** (its own only) |
| cross-account `UPDATE` as the other tenant | matched **0** rows; the row came back `unchanged` |

**The FORCE-RLS control — the suite is proven able to fail:**

| | owner reads |
|---|---|
| FORCE removed, same owner, same identity, same query | **2** — every tenant's |
| FORCE on (the shipped state), same owner, same query | **1** — its own only |

**And the login role owns nothing:**

```
$ psql -U identity -d identity   (then: set role identity_app)
identity_app, no identity          -> 0 rows
identity_app, alter table account_audit_log disable row level security
  ERROR:  must be owner of table account_audit_log
```

That last line is the half no catalog reports: the application role cannot switch
its own policies off, because it does not own the table.

---

## Half-done, and why

### A. `tenancy.yml` is NOT written. This is the main thing left.

I ran out of hour, and I would rather hand over a correct explanation than a
guessed file. It is not a 20-minute job, and the reason is specific:

- The enumeration is **closed in both directions**. `entryPoints[]` must name
  every account-scoped statement in `scope.sources`, and every declaration must
  be findable on disk. With `scope.sources: [migrations]` the probe run below
  already found account-scoped statements in `00007`, `00011`, `00012` and
  `00013` that nobody declared.
- Each entry point needs an `enforced.file` + `enforced.line` **carrying the
  tenancy key on that exact line**, and **three** `negative` case lines in a test
  file, each carrying its token. That is four verified line numbers per entry
  point, against a service with 17 `internal/` packages.
- A line number that is off by one is `tenancy.scope-lost` or
  `tenancy.denial-missing`. Both are failures, which is the design working — but
  it means a hand-written file with guessed lines is a **red** file, and a file
  "fixed" by pointing `line:` at a line that merely mentions `account_id` is a
  **green lie**. Neither is worth shipping.

Start from `core/harness/tests/fixtures/tenancy/conforming/tenancy.yml`, which is
the format's worked example, and read `core/docs/tenancy.md` §"why the line is a
line" before the first line number.

### B. The blocker, measured — core's checker cannot see kit's substrate

This is the finding the pilot was for, and it is not a prediction: it is what
core's own checker prints.

`cafaye.protect_table` writes its DDL through `execute format(...)` inside
plpgsql. core's scanner matches `^create policy <name> on <table>` and
`^alter table <name> (enable|force) row level security` as **statement starts**
(`core/harness/tenancy_check.py:559` and `:547`). Neither matches a line that
begins with `execute format('create policy %I on %s …`.

So the checker reports the boundary as **absent** when it is present and verified:

```
$ cp tenancy.probe.yml tenancy.yml
$ /Users/kaka/Code/any/moon/cafaye/core/harness/bin/tenancy-check .
FAIL tenancy.rls-not-enabled: account_audit_log (migrations/00012_account_audit_log.sql:59)
      carries 0 policy/policies and no `alter table account_audit_log enable row
      level security`, so none of them is ever evaluated.
FAIL tenancy.rls-owner-bypass: account_audit_log … is NOT set FORCE ROW LEVEL SECURITY.
FAIL tenancy.rls-policy-absent: rls.tables names policy 'account_audit_log_cafaye_select'
      on account_audit_log and the migrations do not create it — they write no policy at all
   …and the same for _insert, _update, _delete
FAIL …: 13 failure(s), 1 warning(s)
```

**Seven of those thirteen are false negatives.** `pg_class.relforcerowsecurity` is
`t` on all five tables and `pg_policy` holds twenty policies; the proof above reads
the denials happening. Reproduce the contradiction directly:

```
$ psql -U identity -d identity -c "select count(*) from pg_policy;"
 20
```

This is a false negative in the direction that matters least (it cannot let a gap
through) and it blocks every service that adopts the template, so **it is kit's
or core's decision, not a service's.** Two candidate fixes:

- **(a) Teach the scanner about the template.** Resolve
  `execute format('create policy %I on %s …')` against the enclosing
  `protect_table` call, using the `<table>_cafaye_<command>` naming convention.
  This is the right fix and it keeps "one entry point" true.
- **(b) Write the DDL literally as well as calling `protect_table`.** Explicit
  `alter table … enable`/`force` plus four explicit `create policy` statements
  next to the call. `protect_table` drops and recreates by name, so it converges
  and the file becomes statically readable. **This forks the rule that the
  substrate has one entry point**, so it is kit's call, and I did not do it.

There is a **second, smaller** finding in the same probe run: the substrate's own
catalog introspection is flagged as service tenancy code —

```
FAIL tenancy.undeclared-entry: select on pg_attribute at migrations/00016_account_isolation.sql:290
      carries the tenancy key and nobody declared it
```

`protect_table` and `unprotected_tables` query `pg_attribute` and `pg_policy`, and
the `account_id` string in those queries trips the entry-point scanner. A service
cannot fix this by declaring them — they are the boundary mechanism, not service
queries — so either `scope.sources` is narrowed or the scanner skips the `cafaye`
schema. Whoever takes (a) should take this too; it is the same function.

### C. Gate wiring: DECIDED as "already wired", and nothing was changed

identity's CI **does** provision a database, and this is the reason no workflow
edit was needed:

- `.github/workflows/ci.yml`'s `gate` job runs a `postgres:17-alpine` service and
  exports `TEST_DATABASE_URL`.
- It runs `go test -v -count=1 -race ./...` with **no `-tags`**, so an untagged
  test in `internal/tenancy/` is compiled and run there.
- It fails the job on **any** `--- SKIP:` line not in `E2E_SKIP_EXCEPTIONS`, so a
  silently skipped proof is already fatal.
- Its "the database tier ran" step derives the package list from
  `grep -rlE 'dbtest\.(Pool|Schema|EnvVar)|TEST_DATABASE_URL'` rather than from a
  hand-written list, so `internal/tenancy` joins the tier with **no edit**.

The floors (`SUITE_FLOOR: 2020`, `DATABASE_TIER_FLOOR: 1732`) are decrease
detectors, so four new PASS lines raise the count and need no new number.

**`bin/prime` was deliberately left alone.** The packet suggested wiring
`REQUIRED_DB=1` there. Measured: `bin/prime` is `go mod download; go build ./...;
go test -count=1 ./...`, and that `go test` is **already red without a database**
— see below — because four packages assert `TestTheDatabaseTierActuallyRan`.
Adding `REQUIRED_DB=1` would change nothing observable and would couple the
developer's gate to an environment variable for no gain. If you want the account
proof to be non-optional for developers, the right place is that existing test,
not a new flag.

---

## The currently-failing command, with real output

`go test ./...` **with no database** is red on this branch. **This is
pre-existing and is not caused by these commits** — these commits add one
migration and one new package, and every failing test below is in a package
neither commit touches.

```
$ go test ./...          # no TEST_DATABASE_URL
--- FAIL: TestTheDatabaseTierActuallyRan (0.00s)
    store_test.go:790: TEST_DATABASE_URL is not set, so every test in this file skipped.
    A green run without it verifies nothing: `docker compose up -d postgres`,
    `goose -dir migrations postgres "$DATABASE_URL" up`, and re-run with TEST_DATABASE_URL set.
FAIL	github.com/cafaye/identity/internal/apikeys
--- FAIL: TestTheDatabaseTierActuallyRan (0.00s)   … internal/courier
--- FAIL: TestTheDatabaseTierActuallyRan (0.00s)   … internal/mfa
--- FAIL: TestTheDatabaseTierActuallyRan (0.00s)   … internal/recovery
--- FAIL: TestTheCoverageExclusionIsOnlyGeneratedCode (0.01s)
    coverage_exclusions_test.go:214: line 129: client/generated records lines=22435 and the tree holds 22411.
        The excluded set changed and the declaration was not restated.
FAIL	github.com/cafaye/identity/internal/platform/ci
```

**The packet's premise is wrong about this repository, and the successor should
know it.** The brief says *"`go test ./...` must stay green WITHOUT a database
(identity's tests are designed to run DB-less)"*. They are not: identity is
built the other way round, on purpose, and `TestTheDatabaseTierActuallyRan` exists
in four packages specifically to make a database-less green run impossible. My
contribution follows the repository rather than the brief — my package is green
DB-less with a loud skip — but it does **not** make the whole suite DB-less green
and cannot.

`TestTheCoverageExclusionIsOnlyGeneratedCode` is unrelated drift in
`coverage-exclusions` against `client/generated` and is somebody else's packet.

With a database the suite is red **because of 00016** — see "THE BRANCH IS RED" at
the top. That is the honest state of this branch, and it is not a regression a
shorter hour would have avoided: it is the finding.

---

## The successor's first move

1. **Decide (a) or (b) for the blocker above, and tell kit or core.** It is not
   yours to fix inside a service, and it blocks every adopter after identity. If
   the answer is (b), identity's migration is a five-line addition.
2. **Then write `tenancy.yml`**, starting from
   `core/harness/tests/fixtures/tenancy/conforming/tenancy.yml`. Enumerate
   `rls.tables` for all five tables × four policies with `constrained.file` =
   `migrations/00016_account_isolation.sql`, and expect to iterate against
   `core/harness/bin/tenancy-check .` several times — it is closed in both
   directions and it is a FAILURE-severity checker by design.
3. **The email-index question is answered and closed** — see the report. Nothing
   to do.

To bring the cluster back up:

```
docker run -d --name wt-m39-identity-pg \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=postgres \
  -e KIT_POSTGRES_DATABASES=identity -e KIT_POSTGRES_ROLE_CONNECTIONS=50 \
  -v "$PWD/../kit/templates/compose/postgres/initdb:/docker-entrypoint-initdb.d:ro" \
  -p 15999:5432 postgres:17-alpine
export PATH="$HOME/.local/share/mise/shims:$PATH"
goose -dir migrations postgres "postgres://identity:postgres@127.0.0.1:15999/identity?sslmode=disable" up
TEST_DATABASE_URL="postgres://identity:postgres@127.0.0.1:15999/identity?sslmode=disable" \
  go test ./internal/tenancy/ -run Tenancy -v -count=1
```
