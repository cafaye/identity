# HANDOFF — identity isolation (packet identity-isolation-04)

Branch `worker/identity-isolation-01` in `cafaye/identity`, worktree
`cafaye/wt-m39-identity-isolation-01`. Twelve commits: this packet's three
(`3450983` the migration, `3e976b1` the resolution path, `70b81c9` the flipped
test) on the nine from packets 01–03. Nothing pushed, nothing merged, nothing
tagged.

**§1 is CLOSED.** §2 is what changed. §3 is what is red, and one of the two reds
is a finding for core rather than a defect here. §4 is the successor's first move.

---

## 1. CLOSED: the credential lookup has no identity to run under — it no longer
##    needs one

Packets 01–03 left one thing standing, measured and pinned:

> a scoped token resolves by `where k.token_digest = $1`, with no `account_id`
> predicate and none it could carry, so under per-request RLS it read **zero
> rows**, `ErrNoRows` became `ErrNotFound`, and every machine credential in the
> fleet was refused as **401**.

Kit decided this upstream (MD24, merged to kit master at `fea8052`) and this packet
adopted the decision rather than redesigning it. `migrations/00016` now says

```sql
select cafaye.protect_credential_table('api_keys', 'token_digest');
```

and `internal/tenancy/credential.go`'s `CredentialResolver` opens the resolution:

```go
begin; select cafaye.begin_credential(digest); /* ByDigest */ commit;
```

The predicate lives in the **policy**, so the honest semantics are narrower than
"reads nothing" rather than wider: **a resolution session reads exactly the row
whose digest it presented, in either role, and cannot write at all.** Measured, as
the owner *and* as `identity_app`, with two tenants and two keys:

| | no digest | `begin_credential(digest)` |
|---|---|---|
| `where token_digest = $1` | 0 | **1** |
| `select * from api_keys` | 0 | **1** — that row, not the table (2 rows exist) |
| `select from account_users` | 0 | **0** |
| `insert into api_keys` | refused | **refused** — `new row violates row-level security` |
| wrong digest presented | — | 0 |
| after the transaction | 0 | **0** |

The three-denial property on every other table is unchanged, and `api_keys` keeps
it: own account 1, another tenant's credential 0.

**Pinned as a property, not as a measurement:**
`internal/tenancy/credential_lookup_test.go` —
`TestTenancyACredentialResolvesByTheDigestTheCallerPresentedAndNothingElse`,
eight assertions, three negative controls measured (see the report).

---

## 2. What changed, and the two judgment calls

### 2.1 **00016 was AMENDED, not superseded by 00017** — and the reason is free

00016 has never been applied outside this branch; `origin/master` stops at 00015.
Amending costs no deployed migration and no checksum to reconcile, and it keeps the
substrate copy and the call that uses it in **one** file. A 00017 that re-declared
the four functions MD24 added would be a fork of the shared substrate inside a
service, which is the one thing that migration exists to prevent. The copy was
refreshed from kit master's `templates/database/tenancy/substrate.sql` and is
**byte-identical** to it (measured: 39297 bytes both sides), so it also brings
kit's sweep scoping — see §3B.

### 2.2 `CredentialResolver` is a SECOND TYPE, not a flag on `TxRunner`

`apikeys.NewService` takes a second parameter. `uow` is `tenancy.TxRunner`, which
begins the request's **account** on every transaction it opens; a resolution
transaction that also began the account would have its read set be the union of
`account_id = …` and `token_digest = …` — "the row whose digest you presented"
unioned with "every row of the account you act as", which is a browsing session
wearing a narrower name. Today the two cannot overlap because
`requireAccountRole` resolves the credential before it calls `tenancy.WithAccount`
— and that is **call order in another package**, which is not a thing a security
property should rest on. Passing one rather than two makes the narrowing
structural: there is no spelling of the constructor that hands the resolution an
account.

Cost: three call sites (`cmd/identity/main.go`, two test fixtures) and one
signature. Deliberate — a seam that had been threaded quietly would not be
review-visible.

### 2.3 `Introspect` moved onto the same seam, and it was not tidiness

It is the second reader of `api_keys` by digest. Left on the bare pool it would
have made `/v1/introspections` answer `{"active": false}` for **every live token in
the fleet** — a silently wrong answer rather than a failure anybody is paged for.

---

## 3. What is red, with real output

### 3.A `tenancy-check` — 7 failures, ALL FALSE, all about `api_keys`

```
FAIL tenancy.rls-not-enabled:   api_keys (migrations/00011_api_keys.sql:21) carries 0 policy/policies …
FAIL tenancy.rls-owner-bypass:  api_keys (…) is NOT set FORCE ROW LEVEL SECURITY …
FAIL tenancy.rls-policy-absent: api_keys_cafaye_select   … do not create it — they write no policy at all
FAIL tenancy.rls-policy-absent: api_keys_cafaye_insert   … (same)
FAIL tenancy.rls-policy-absent: api_keys_cafaye_update   … (same)
FAIL tenancy.rls-policy-absent: api_keys_cafaye_delete   … (same)
FAIL tenancy.rls-policy-absent: api_keys_cafaye_resolve  … (same)
= 7 failure(s), 1 warning(s)
```

**Core cannot see the mechanism.** Its recogniser is

```python
_PROTECT_TABLE = re.compile(r"^select\s+(?:cafaye\.)?protect_table\s*\(\s*'(?P<table>…)'")
```

— a literal table name as the **first** argument — and this table's call is
`protect_credential_table('api_keys', 'token_digest')`.

**Measured, not asserted.** On a scratch copy of this worktree whose *only* change
is line 895 of 00016 spelling `select cafaye.protect_table('api_keys');`, **six of
the seven disappear** and only `api_keys_cafaye_resolve` remains red (correctly —
that policy genuinely is not created by `protect_table`). So the six are core's
recogniser and **not** this declaration's `constrained.line` values, which are
correct: `relrowsecurity` and `relforcerowsecurity` are both `true` on the table
and `pg_policy` holds all five policies.

**The fix is one regex in core**, and it is core's to make:

```python
r"^select\s+(?:cafaye\.)?protect_(?:credential_)?table\s*\(\s*'(?P<table>[a-z_][a-z0-9_]*…)'"
```

plus whatever it takes to resolve the **fifth** policy's predicate — the resolve
policy's qualifier is the digest, not the account, so a checker that assumes
`<table>_cafaye_<command>` means `account_id = current_account_id()` will read it
as an account policy and that is a second thing to fix, not one.

**What was deliberately NOT done:** deleting `api_keys` from `rls.tables`, or
narrowing the declared policies to four, to make the checker quiet. Either would
declare that Postgres does not protect the one table holding every machine
credential. Loosening a check to make a gate green is the green lie this
repository's rules refuse, and the previous packet's green was earned by the
declaration being true; this packet's red is the honest cost of the declaration
staying true.

### 3.B `TestTenancyAccountIsolation` — the sweep race is **GONE**

The last handoff named this as kit's finding: kit's assertion set assumes it owns
the database, and other packages' `dbtest.Schema` fixture schemas — cloned with
`LIKE … INCLUDING ALL`, which does not copy RLS — were reported by a
whole-database sweep (`expected "1"`, `actual "21"`). **Kit's fix has merged**
(`0e1d4c1`, "scope the sweep to the schemas the substrate was applied in") and
identity's 00016 now carries kit's current substrate, so the sweep is scoped.

`internal/tenancy` is `ok 1.683s` and then `ok 0.976s` in **two consecutive**
whole-suite runs — which is the number of runs that matters here, because the
failure it replaced was intermittent and depended on how many neighbours happened
to be mid-test.

### 3.C `TestTheCoverageExclusionIsOnlyGeneratedCode` — PRE-EXISTING, UNRELATED

```
coverage_exclusions_test.go: line 129: client/generated records lines=22435
and the tree holds 22411. The excluded set changed and the declaration was not restated.
```

Untouched by this packet and nothing in it moves.

### 3.D `go test ./...` with NO database is red **by design**

```
FAIL internal/apikeys     ← TestTheDatabaseTierActuallyRan
FAIL internal/courier     ← TestTheDatabaseTierActuallyRan
FAIL internal/mfa         ← TestTheDatabaseTierActuallyRan
FAIL internal/recovery    ← TestTheDatabaseTierActuallyRan
FAIL internal/platform/ci ← the coverage exclusion above
```

`TestTheDatabaseTierActuallyRan` FAILS rather than skips so a database-less green
run is impossible. `internal/tenancy` is green DB-less with a loud skip, and
`REQUIRED_DB=1` turns it into a failure.

---

## 4. The successor's first move

1. **`account_invitations` is the same change and it is half-made.** The call is

   ```sql
   select cafaye.protect_credential_table('account_invitations', 'token_digest');
   ```

   (note: the column is `token_digest`, not `token` — read `00007`) and the Go
   side is `internal/accounts/service.go:485`, where `InvitationByToken` is
   already inside `s.uow.Do`:

   ```go
   invitation, err := s.store.InvitationByToken(ctx, q, Digest(in.Token))
   ```

   — so add `tenancy.BeginCredential(ctx, q, Digest(in.Token))` before it. Both
   halves or neither: the migration half alone breaks redemption the same way this
   commit fixed `api_keys`. **Deliberately not taken here** — it is a second table,
   a second table's whole redemption path, and this packet's hour was spent
   proving the mechanism rather than extending it.
2. **`oidc_clients` must NOT get it, and the reason is not a preference.**
   `client_id` travels in the authorization URL, so it is a public identifier, and
   the mechanism widens a read to the row whose value the caller presented — on
   `client_id` it hands every anonymous requester one row of another tenant's
   client. kit's substrate says so itself ("it cannot tell a secret from a label").
   The open question is a **product** one and it is not this packet's to guess at:
   resolve on `client_secret` at the token endpoint (where the value is genuinely
   unguessable), and treat the authorization endpoint's `client_id` lookup as a
   different problem that needs an answer this mechanism does not provide.
3. **A silent zero-row write on the other side of this seam, NOT fixed here.**
   `apikeys.Service.Authenticate`'s best-effort `Touch` runs on the bare pool with
   no identity, so its UPDATE matches no row and **reports success** —
   `last_used_at` has been recording nothing under the enforced boundary, silently.
   It is not the resolution path, so it is out of this packet's scope. The fix is
   to run it under `tenancy.BeginAccount(ctx, q, key.AccountID)` — the account is
   known by then (`internal/apikeys/service.go`, the `Touch` call just before the
   return) — and it belongs in the packet that owns the write side. A test that
   catches it: assert the row's `last_used_at` actually moved, rather than that the
   call did not error.
4. **The two core findings from `REPORT-identity-isolation-03.md` §4 are still
   open** and still core's: §4-A (`negative.cases` needs a per-statement denial
   proof, and a five-table service cannot supply one per table) and §4-B
   (`ATTRIBUTION_WINDOW = 4` cannot attribute a multi-line Go statement, so eleven
   account-scoped statements in this tree are invisible to closure in both
   directions). This packet adds a **third**: `_PROTECT_TABLE` (§3.A above).

---

## 5. Gates, with real output

```
$ go build ./...                                        build=0
$ go vet ./...                                          vet=0
$ gofmt -l .                                            clean (excluding client/generated)

$ TEST_DATABASE_URL=… go test ./internal/tenancy/ -run Tenancy -v -count=1
--- PASS: TestTenancyACredentialResolvesByTheDigestTheCallerPresentedAndNothingElse (0.09s)
--- PASS: TestTenancyAccountIsolation (0.04s)          ← kit's 24 assertions
--- PASS: TestTenancyIdentityOwnsItsFiveTables (0.03s)
    --- PASS: …/every_declared_table_is_enabled_and_FORCED
    --- PASS: …/the_sweep_finds_nothing_unprotected
    --- PASS: …/three-way_denial_as_identity_app
    --- PASS: …/three-way_denial_as_identity
ok  	github.com/cafaye/identity/internal/tenancy	0.504s

$ TEST_DATABASE_URL=… go test ./... -count=1
  23 packages ok, ONE failure and it is §3.C: the coverage-exclusion declaration.
  internal/tenancy  ok  1.683s     ← §3.B: the sweep race is GONE
  internal/httpapi  ok  66.649s    (66 seconds beside thirteen other packages)
  EXIT=1
  …re-run, because the failure it replaced was intermittent:
  internal/tenancy  ok  0.976s     ← same single failure, second run
  EXIT=1
```

Three negative controls on the flipped test are in
`moon/logs/REPORT-identity-isolation-04.md` §3.2; the `tenancy-check` measurement
is in §4.1 of the same report.

**`go test -race ./...` was NOT run.** It is one of the four gates in AGENTS.md and
this packet did not reach it; that is a gap in the evidence, named here rather than
implied away.

---

## 6. The suite result, whole, with a database

```
ok  	client	4.328s          ok  	internal/config	3.439s
ok  	cmd/identity	2.495s      ok  	internal/courier	5.307s
ok  	internal/accounts	31.619s    ok  	internal/httpapi	66.649s
ok  	internal/admin	11.337s     ok  	internal/mfa	33.091s
ok  	internal/apikeys	29.994s    ok  	internal/oauth	11.051s
ok  	internal/auth	17.752s     ok  	internal/oidc	4.270s
ok  	internal/outbox	7.166s      ok  	internal/platform/db	0.751s
--- FAIL: TestTheCoverageExclusionIsOnlyGeneratedCode
    coverage_exclusions_test.go:214: line 129: client/generated records lines=22435
    and the tree holds 22411. The excluded set changed and the declaration was not restated.
ok  	internal/platform/clock	0.595s    ok  	internal/sessions	1.797s
ok  	internal/platform/id	0.956s      ok  	internal/telemetry	1.677s
ok  	internal/recovery	16.164s     ok  	internal/tenancy	1.683s
ok  	internal/users	1.961s
FAIL	EXIT=1        ← the coverage exclusion, §3.C, and nothing else
```

---

## 7. Bringing the cluster back up

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

Docker needs OrbStack running (`orbctl status`). `pg_roles` shows the two
principals the declaration names: `identity`, `identity_app`.

**Two fixture bugs were fixed in this packet's test file and are worth knowing
before anyone runs these tests against a dirty database:** the cleanup used to run
on a **closed** connection (`defer conn.Close` fires before any `t.Cleanup`), and
the seed never deleted its `users`. Both leaked rows into the next run, and the
leaked rows made two negative controls fail for the previous run's reasons. If a
tenancy test suddenly reports a fixture count you did not expect, check
`select count(*) from api_keys` before believing the assertion.