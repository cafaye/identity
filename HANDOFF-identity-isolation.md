# HANDOFF — identity isolation (packet identity-isolation-02)

Branch `worker/identity-isolation-01` in `cafaye/identity`, worktree
`cafaye/wt-m39-identity-isolation-01`. Six commits total: the relay's three plus
the three below. Nothing pushed, nothing merged, nothing tagged.

**Read §1 before anything else. It is a measured production break that a green
suite cannot see, and it is more urgent than `tenancy.yml`.**

---

## 1. FIRST: the credential lookup has no identity to run under

**With 00016 applied, scoped-token authentication reads zero rows and every machine
credential is refused as 401.** Measured on the proof cluster, as the **owner**
role, against the **real protected table**:

| | rows seen |
|---|---|
| **no identity — the state a request presenting a scoped token is in** | **0** |
| identity = the credential's own account | 1 |
| identity = A, reading another tenant's credential | 0 |

`internal/apikeys/store.go:219` resolves a token with no `account_id` predicate,
**and cannot have one** — the account is what the query is *for*:

```sql
SELECT … FROM api_keys k JOIN account_users au ON …
 WHERE k.token_digest = $1 AND k.revoked_at IS NULL AND k.expires_at > $2
```

Per-request RLS cannot answer a query whose subject it does not yet know. The
failure is silent: `ByDigest` maps `pgx.ErrNoRows` to `ErrNotFound`, the HTTP layer
maps that to **401**, so a valid token is indistinguishable from a forged one.

Same shape in `account_invitations.InvitationByToken` and the `oidc_clients`
lookup by `client_id`. **One property, three sites: a table accessed by "find the
row by an unguessable secret, then learn the account from it" cannot be scoped by
an account you do not have yet.**

### Why the green suite does not catch it

`dbtest.Schema(t)` clones tables with `LIKE … INCLUDING ALL`, and **LIKE does not
copy row-level security.** Every integration test that drives an account-scoped
route uses it, so those fixtures have an `account_id` column and **no policies**.
They pass with the wiring and **they would pass with no wiring at all**. A green
`go test ./...` is therefore *not* evidence that token auth works in production.

### It is pinned

`internal/tenancy/credential_lookup_test.go` —
`TestTenancyACredentialLookupHasNoIdentityToRunUnder` asserts the measurement and
is **green while doing so**. It is a characterisation, not a claim that token auth
works. When this is fixed the test goes red and names exactly what changed.

### What NOT to do about it

- **Do not drop `FORCE`.** Kit measures it: an owner carrying another tenant's
  identity reads **1 row with FORCE, 3 without**. It would leave the fleet's only
  account boundary unenforced on the table holding every machine credential.
- **Do not reach for `SECURITY DEFINER`. It does not work.** `FORCE` applies to the
  *definer* too; only a role with `BYPASSRLS` bypasses RLS and no service role has
  one. This is the option most likely to be proposed — it is killed here so nobody
  spends an hour discovering it.
- **Do not write `00017` from inside a service.** Every candidate forks a kit rule.
  It is kit's or core's call. The honest option, if it is taken, is a *deliberate*
  owner exemption for credential tables with its cost written down — which is a
  statement about kit's rule, not about this service.

---

## 2. Done, and verified

### 2.1 The wiring — `00016` stays, registration answers 201

`internal/tenancy/scope.go` is the runtime seam; the proof lives beside it.

| Where | What it does |
|---|---|
| `requireAccountRole` (`internal/httpapi/accounts.go`) | puts the **resolved** account on the request context — the request path |
| `internal/tenancy.TxRunner` | sets it inside every transaction; **embeds `db.TxRunner`, adds no field**, so it satisfies all six `UnitOfWork` interfaces unchanged and no service can be wired unwired by accident |
| `tenancy.BeginAccount` | the three writes that create the account they act as: `auth.provisionTenancy`, `accounts.Create`, `accounts.Accept` |

Full reasoning, including why the context rather than a parameter and why the
boundary is set in middleware rather than in handlers, is in
`moon/logs/REPORT-identity-isolation-02.md` §1–2. The short version of the last
one: **a handler that forgot would still pass every authorization test in that
file**, because they drive doubles with no database and no RLS — which is exactly
how this branch shipped a 500 on registration.

**No query predicate was changed.** Every `where account_id = ?` stays; this packet
changed where the boundary is *set*.

### 2.2 The gates, with real output

```
$ go build ./...                          build=0
$ go vet ./...                            vet=0
$ gofmt -l .                              clean (excluding client/generated)

$ TEST_DATABASE_URL="postgres://identity:postgres@127.0.0.1:15999/identity?sslmode=disable" \
    go test ./cmd/identity/ -run '<the four wiring tests>' -count=1
ok  	github.com/cafaye/identity/cmd/identity	1.377s

$ TEST_DATABASE_URL=… go test ./internal/recovery/ -run TestAResetDoesNotRevokeAScopedAPIKey -count=1
ok  	github.com/cafaye/identity/internal/recovery	0.801s

$ TEST_DATABASE_URL=… go test ./internal/tenancy/ -run Tenancy -v -count=1
--- PASS: TestTenancyACredentialLookupHasNoIdentityToRunUnder (0.05s)
--- PASS: TestTenancyAccountIsolation (0.04s)          ← kit's 24 assertions
--- PASS: TestTenancyIdentityOwnsItsFiveTables (0.04s) ← 3-way denial, BOTH roles
ok  	github.com/cafaye/identity/internal/tenancy	0.544s
```

Both originally-red commands are green, and **the cross-tenant property is still
proven as BOTH roles** — the wire packet added a way to *set* the boundary and
changed nothing about what it *does*.

---

## 3. The currently-failing commands, and why

```
$ TEST_DATABASE_URL=… go test ./... -count=1
```

Green except **two** failures, both named, neither caused by this packet:

**A. `TestTheCoverageExclusionIsOnlyGeneratedCode` — PRE-EXISTING, UNRELATED, LEFT
ALONE.** Drift in `coverage-exclusions` against `client/generated`; another
packet's work. Fails identically before and after these three commits.

```
coverage_exclusions_test.go:214: line 129: client/generated records lines=22435
and the tree holds 22411. The excluded set changed and the declaration was not
restated.
```

**B. `TestTenancyAccountIsolation` — green alone, red only in a whole-suite run.**
This is the kit finding the relay recorded, and it is **not** a regression:

```
2 of 24 account-isolation assertions failed:
  sweep/the-only-finding-is-the-control
    expected "cafaye_probe_unprotected:row level security is not enabled"
    actual   "…,account_users:…,api_keys:…,oidc_clients:…"
```

Those are **not** the real tables — `relforcerowsecurity` is `t` on all five and
the three-way denial reads the refusals happening. They are other packages'
**private fixture schemas**, and kit's sweep assertion is a *whole-database*
assertion expecting exactly one finding, its own control. The count varies per run
(5 named on one run, 21 on the next) because it depends on how many neighbours
were mid-test — **which is the evidence that it is a race, not a defect here**.

**kit's assertion set assumes it owns the database.** A service whose tests create
private schemas cannot use it unmodified. The fix belongs in kit: scope
`isolation.sql`'s sweep assertion to `pg_temp`. It will bite every adopter with a
private-schema fixture helper.

I did **not** work around it. Loosening a copied assertion set inside a service to
make a parallel-test race green is the green lie this repository's rules refuse.

### `go test ./...` with NO database is red — the packet's premise is wrong again

```
$ go test ./...
FAIL	internal/apikeys     ← TestTheDatabaseTierActuallyRan
FAIL	internal/courier     ← TestTheDatabaseTierActuallyRan
FAIL	internal/mfa         ← TestTheDatabaseTierActuallyRan
FAIL	internal/recovery    ← TestTheDatabaseTierActuallyRan
FAIL	internal/platform/ci ← the coverage exclusion above
```

The brief says identity's suite "is designed to run DB-less". **It is not**, and
that is deliberate: `TestTheDatabaseTierActuallyRan` FAILS rather than skips so a
database-less green run is impossible. My work follows the repository, not the
brief. `internal/tenancy` — my package — **is** green DB-less with a loud skip, and
`REQUIRED_DB=1` still turns it into a failure.

---

## 4. The successor's first move

1. **Get the §1 decision made by whoever owns kit.** It blocks scoped tokens in
   every service that adopts `templates/database/tenancy/`, not just identity. If
   the answer is "credential tables keep the owner exemption", identity's migration
   is a small, deliberate change with its cost written down — and the pinning test
   tells you when you are there.
2. **Then write `tenancy.yml`**, once core's scanner fix lands (core cannot see
   `protect_table`'s `execute format` DDL; seven of its thirteen findings are false
   negatives against `pg_policy`'s twenty real policies). Start from
   `core/harness/tests/fixtures/tenancy/conforming/tenancy.yml`; enumerate all five
   tables × four policies with `constrained.file = migrations/00016_account_isolation.sql`;
   expect several iterations against `core/harness/bin/tenancy-check .` — it is
   closed in both directions and FAILURE-severity by design.
3. **Raise the kit sweep race separately** (§3B). It is a different finding from
   the scanner one and it is not a service's to fix.

---

## 5. Bringing the cluster back up

```sh
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

Docker needs OrbStack running (`orbctl status`); it was stopped when this packet
started.