# HANDOFF — identity isolation (packet identity-isolation-03)

Branch `worker/identity-isolation-01` in `cafaye/identity`, worktree
`cafaye/wt-m39-identity-isolation-01`. Seven commits: the relay's three, this
lineage's three, and `7a32eff` — **`tenancy.yml`, written honestly, and
`tenancy.probe.yml` deleted in the same commit.** Nothing pushed, nothing merged,
nothing tagged.

**§1 is still open and still the most urgent thing here.** §2 is what this packet
did. §3 is what is red. §4 is the successor's first move.

---

## 1. FIRST, unchanged: the credential lookup has no identity to run under

**With 00016 applied, scoped-token authentication reads zero rows and every
machine credential is refused as 401.** Measured on the proof cluster, as the
**owner** role, against the **real protected table**:

| | rows seen |
|---|---|
| **no identity — the state a request presenting a scoped token is in** | **0** |
| identity = the credential's own account | 1 |
| identity = A, reading another tenant's credential | 0 |

`internal/apikeys/store.go:219` resolves a token with no `account_id` predicate,
**and cannot have one** — the account is what the query is *for*. Per-request RLS
cannot answer a query whose subject it does not yet know. The failure is silent:
`ByDigest` maps `pgx.ErrNoRows` to `ErrNotFound`, the HTTP layer maps that to
**401**, so a valid token is indistinguishable from a forged one.

Same shape in `account_invitations.InvitationByToken` and the `oidc_clients`
lookup by `client_id`. **One property, three sites.**

It is pinned, and green while measuring it:
`internal/tenancy/credential_lookup_test.go` —
`TestTenancyACredentialLookupHasNoIdentityToRunUnder`, re-run green in §2's gate
output below.

### What NOT to do about it

- **Do not drop `FORCE`.** Kit measures it: an owner carrying another tenant's
  identity reads **1 row with FORCE, 3 without**.
- **Do not reach for `SECURITY DEFINER`. It does not work.** `FORCE` applies to
  the *definer* too; only `BYPASSRLS` bypasses RLS and no service role has one.
- **Do not write `00017` from inside a service.** Every candidate forks a kit rule.
  The honest option, if it is taken, is a *deliberate* owner exemption for
  credential tables with its cost written down — which is a statement about kit's
  rule, not about this service.

---

## 2. Done, and verified — `tenancy.yml`

### 2.1 What it says

`identity/tenancy.yml` exists, describes only what is true on this branch, and
passes core's checker. **It replaces `tenancy.probe.yml`, which is deleted** —
that file was the pilot's measurement parked under a name that could not redden
the fleet's gate (core reads exactly `tenancy.yml` at the repository root).

The `rls` block: five tables (`account_users`, `account_invitations`,
`api_keys`, `oidc_clients`, `account_audit_log`), twenty policies named the way
the substrate generates them (`<table>_cafaye_<command>`), `identity:
cafaye.current_account_id()`, `roles: [identity, identity_app]`, and every
`constrained` pointing at one of the **five `select cafaye.protect_table(…)`
calls** in `migrations/00016_account_isolation.sql` (lines 508/512/516/520/524)
— because that is the only place the template's shape is written down in this
tree.

`pg_catalog` confirms every one of those claims independently, and is in §2.3 of
the report: both bits true on all five tables, twenty policies under exactly
those names, `to identity,identity_app`, predicates
`account_id = ( SELECT cafaye.current_account_id() )`.

### 2.2 The judgment call: ONE declared entry point, and eleven named omissions

`entryPoints` declares `admin-audit-log-list` and nothing else, because
`negative.cases` requires three arms naming three assertion lines and **this
repository has a row-level three-way denial for `account_audit_log` only** —
00012 gives that table no foreign keys, which is exactly why its fixture cannot
collide with six other packages' tests.

Eleven account-scoped statements in `internal/accounts/store.go`,
`internal/apikeys/store.go` and `internal/oidc/store.go` all carry their own
`where account_id` and are **not** declared. Declaring them with arms borrowed
from the audit log's proof would have made the checker green and the declaration
false. Each one is named in the file with its `file:line` and the reason.

The three secret-addressed lookups cannot be declared **at all**: `operation:
call` still requires `enforced.line` to carry the tenancy key, and no line in
any of them does.

Full reasoning, and the two core-facing findings that come out of it
(§4-A and §4-B of the report), are in
`moon/logs/REPORT-identity-isolation-03.md` §2–4.

### 2.3 The gates, with real output

```
$ go build ./...                          build=0
$ go vet ./...                            vet=0
$ gofmt -l .                              clean (excluding client/generated)

$ /Users/kaka/Code/any/moon/cafaye/core/harness/bin/tenancy-check .
WARN tenancy.enumeration-partial: … could not classify 11 account-scoped site(s): …
OK /Users/kaka/Code/any/moon/cafaye/wt-m39-identity-isolation-01: 0 failure(s), 1 warning(s)
EXIT=0

$ TEST_DATABASE_URL="postgres://identity:postgres@127.0.0.1:15999/identity?sslmode=disable" \
    go test ./internal/tenancy/ -run Tenancy -v -count=1
--- PASS: TestTenancyACredentialLookupHasNoIdentityToRunUnder (0.06s)
--- PASS: TestTenancyAccountIsolation (0.04s)          ← kit's 24 assertions
--- PASS: TestTenancyIdentityOwnsItsFiveTables (0.04s)
    --- PASS: …/every_declared_table_is_enabled_and_FORCED
    --- PASS: …/the_sweep_finds_nothing_unprotected
    --- PASS: …/three-way_denial_as_identity_app
    --- PASS: …/three-way_denial_as_identity
ok  	github.com/cafaye/identity/internal/tenancy	0.739s
```

**The warning is accounted for, not ignored.** All eleven named sites are read
and classified in the declaration itself: five are column lists (three of them an
`insert`'s, which the schema excludes from `entryPoints[].operation` by its own
rule) and six are real account-scoped statements core's scanner cannot attribute
because Go raw-string SQL puts the verb and the predicate 3–8 lines apart while
`ATTRIBUTION_WINDOW` is 4.

### 2.4 Never a green that cannot fail

Four scratch copies, one mutation each, same checker; the real tree untouched by
any of them and `exit=0` after all four.

| | mutation | result |
|---|---|---|
| A | delete `select cafaye.protect_table('account_audit_log');` from 00016 | **exit 1, 6 failures** — `rls-not-enabled`, `rls-owner-bypass`, then `rls-policy-absent` naming all four policies |
| B | rename a declared policy to `api_keys_cafaye_truncate` | **exit 1, 2 failures** — `rls-policy-absent` + `rls-undeclared`, naming the four that are there |
| C | move `enforced.line` 127 → 126 | **exit 1** — `scope-lost`, quoting the line with no key on it |
| D | point the `own-account` arm at `tenancy_test.go:355` | **exit 1** — `denial-missing`, quoting the line with no token on it |

C and D are there because a checker that only fails on the `rls` block is half a
checker: C proves the entry point's line is read, D proves the three arms are.

---

## 3. The currently-failing commands, and why

```
$ TEST_DATABASE_URL=… go test ./... -count=1
```

Green except **two** named failures, both pre-existing, neither caused by this
packet and neither touched by it. Re-measured on this packet's cluster:

**A. `TestTheCoverageExclusionIsOnlyGeneratedCode` — PRE-EXISTING, UNRELATED.**

```
coverage_exclusions_test.go:214: line 129: client/generated records lines=22435
and the tree holds 22411. The excluded set changed and the declaration was not restated.
```

**B. `TestTenancyAccountIsolation` — green alone, red only in a whole-suite run.**
This is kit's known finding, not a regression, and it is kit's fix:

```
tenancy_test.go:161: 2 of 24 account-isolation assertions failed:
      sweep/every-account-scoped-table-is-protected
        expected "1"
        actual   "21"
        because   every account-scoped table in this database must be enabled, FORCED
                  and carrying policies. Exactly one is expected to be reported: the
                  control table this file created on purpose
```

Those 21 are **other packages' private fixture schemas**, not the real tables:
`dbtest.Schema(t)` clones with `LIKE … INCLUDING ALL`, LIKE does not copy
row-level security, and the count varies per run with how many neighbours were
mid-test. `relforcerowsecurity` is `t` on all five real tables and the three-way
denial reads the refusals happening (§2.3). kit's assertion set assumes it owns
the database; the fix belongs in kit — scope `isolation.sql`'s sweep assertion to
`pg_temp`. I did **not** work around it: loosening a copied assertion set inside a
service to make a parallel-test race green is the green lie this repository's
rules refuse.

### `go test ./...` with NO database is red — by design, and the brief was wrong

```
$ go test ./...
FAIL	internal/apikeys     ← TestTheDatabaseTierActuallyRan
FAIL	internal/courier     ← TestTheDatabaseTierActuallyRan
FAIL	internal/mfa         ← TestTheDatabaseTierActuallyRan
FAIL	internal/recovery    ← TestTheDatabaseTierActuallyRan
FAIL	internal/platform/ci ← the coverage exclusion above
```

`TestTheDatabaseTierActuallyRan` FAILS rather than skips so a database-less green
run is impossible. `internal/tenancy` **is** green DB-less with a loud skip, and
`REQUIRED_DB=1` turns it into a failure.

---

## 4. The successor's first move

1. **Adopt kit's credential-resolution mechanism once its packet lands** (§1). It
   blocks scoped tokens in every service that adopts
   `templates/database/tenancy/`, not just identity. If the answer is "credential
   tables keep the owner exemption", identity's migration is a small deliberate
   change with its cost written down, and
   `TestTenancyACredentialLookupHasNoIdentityToRunUnder` turns red and names
   exactly what changed.
2. **Raise the two core findings from the report with core, not with a patch
   here.** §4-A: `negative.cases` needs a per-statement denial proof, and a Go
   service with five protected tables cannot supply one per table — the fix is
   either a way for an entry point to name a *table's* proof and inherit it, or
   four more fixtures. §4-B: `ATTRIBUTION_WINDOW = 4` cannot attribute a
   multi-line Go statement, so six real account-scoped statements in this tree
   are invisible to closure in both directions. Both are measured, with
   file:line lists.
3. **Then add the four missing denial fixtures** and extend `entryPoints` to the
   eleven statements named in `tenancy.yml` §"WHAT IS NOT DECLARED". That is Go
   code and it was out of scope for this packet; the declaration is waiting for
   it and names every line that wants it.
4. **The kit sweep race separately** (§3B). A different finding from the scanner
   one, and not a service's to fix.

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

Docker needs OrbStack running (`orbctl status`). This packet's run is at version
16, and `pg_roles` shows the two principals the declaration names:
`identity`, `identity_app`.