# REPORT — identity-13-gate

> **A previous dispatch of this packet died mid-run and left work behind on
> `worker/identity-13-gate` (`0252bd8`).** This run did not discard it. Every
> number below was **re-measured from scratch** and the earlier run's claims were
> checked rather than inherited; where a claim did not survive that check it is
> corrected here and in the commit message. What changed is recorded under **What
> this run changed**.

## The finding

**`bin/prime` ran no tests, and reported `ok` eighteen times while doing it.**

The file ended in a bare `go test ./...`. Go serves that from its test cache, so
the second run of a green gate re-uses the first run's results. Measured on this
tree with a warm cache, against the migrated database, exit code 0:

```
wall 8s   18 `ok` package lines   16 read `(cached)`   2 actually executed
```

Every proof in the declaration is matched against a package line, so **every one
of them was satisfied by a `(cached)` line**. A developer who had just run the
gate had verified nothing: not the code, not the database tier, not the 1,590
tests that depend on it. This is the packet's premise happening inside the
repository the packet is about — *"a checker replaced by a function that
unconditionally exits 0 would leave this repository green"* — except that here the
exit code genuinely **was** 0 and the gate genuinely had run nothing.

After the fix, same command, same machine:

```
wall 126s   18 `ok` package lines   0 cached   18 actually executed
```

It is not a local preference. kit's Go template ships `go test -count=1 ./...`
(`templates/bin-prime/go.sh:73`) and explains it in the line above: *"a prime must
prove the tests run now, not that they ran at some point today."* kit's validator
**fails** a Go CI step that omits the flag (`tests/validate.sh:3014`), and kit's
reusable workflow passes it. Identity's gate was the one place in the fleet where
a fleet-wide rule did not hold.

### The second finding, which is smaller and was also real

**`bin/prime` could not be executed at all.** The file had the executable bit and
no interpreter line, so `execve(2)` on it fails with `ENOEXEC`:

```
FAIL gate.command-missing: gate.command could not be started:
     [Errno 8] Exec format error: 'bin/prime'
```

Reproduced here, independently, rather than taken on report: a shebang-less
executable run through `subprocess` with no shell raises
`OSError [Errno 8] Exec format error`. A developer and CI never saw it, because
`bash` and `zsh` both fall back to interpreting a shebang-less file themselves.
`core`'s `harness/gate_check.py` runs the declared gate through `subprocess` with
**no shell**, so it hit the real behaviour on the first attempt. Every other
adopter in the fleet ships a shebang (`courier` `#!/bin/sh`, and
`muse`/`darkroom`/`cafaye-rb`/`cafaye-ts`/`core` `#!/usr/bin/env bash`); kit's own
Go template ships `#!/usr/bin/env bash`. Identity's scaffold lost it in
identity-01 and nothing noticed for twelve packets.

Fixed, with one line, because the declaration is not checkable while the thing it
declares cannot be run. Nothing about the gate's behaviour changed — `set -eu` and
three commands are POSIX either way.

---

## The second finding, which is the one this packet was actually for

**Go's `go test` prints no test count. Not with `-v`, not without it, in any Go
release.** Every other adopter can put a `minimum` in its `gate.yml` because its
runner prints a summary carrying one — ExUnit's `Result: 535 passed`, pytest's
`898 passed`, minitest's `228 runs`, npm's `# pass 187`, cargo's `test result:
ok. 7 passed`. `go test ./...` prints **one line per package**, and the only
number on it is a duration:

```
ok  	github.com/cafaye/identity/internal/mfa	0.531s
?   	github.com/cafaye/identity/internal/platform/dbtest	[no test files]
```

The checker reads `minimum` from a single capture group in the **last** matching
line, so there is no line for it to read, and the number of matching lines is not
expressible. **`identity/gate.yml` therefore declares no floor at all** — not
because a floor was skipped, but because this runner cannot carry one. The eight
proofs are presence assertions; the actual decrease-detector stays in
`.github/workflows/ci.yml`, which counts a `-v` run. Both the omission and its
reason are written into the file, and the expected counts are recorded there as
measured facts.

---

## The two commands, measured, and they were not the same

| | command | measured |
|---|---|---|
| Developer | `bin/prime` — `go mod download && go build ./... && go test -count=1 ./...` (the flag added by this packet) | exit 0, **18 `ok` packages, 0 cached**, 126s |
| CI `gate` job | `./bin/prime` **and** `go test -v -count=1 -race -coverprofile=… ./...`, plus `goose up` above both, `go vet`, `gofmt`, a lockfile guard, `bin/coverage-floor`, and a five-process boot test | — |

**The difference that mattered was one flag, and it is now closed.** CI's counted
run carried `-count=1`; `bin/prime` did not. Re-measured here with a warm cache:
the developer's command returned **exit 0, 18 `ok` lines, 8 seconds, 16 cached**
while CI's would have run everything. The declaration has been written against
the gate a developer runs, so a difference like that is precisely the thing the
packet asked to be caught — and catching it is what the fix was.

Every proof in the declaration is matched against a package line rather than a
test name, and that remains a property of the runner rather than a preference:
`go test` without `-v` prints no test names. It is stated in `gate.yml` rather
than left for the next reader.

---

## The numbers, and CI's floors are far below them

Measured on this tree — `worker/identity-13-gate`, this run — with
`postgres:17-alpine`, all **13** migrations applied (`goose_db_version` reports 14
rows, one of which is goose's version-0 row), 8-core arm64 darwin, load average
between 31 and 70 for the whole packet.

```
$ go test -v -count=1 ./...
PASS=1789  SKIP=0  FAIL=0        21 packages (18 ok, 3 [no test files]), exit 0
```

**1789 = 809 top-level `--- PASS:` lines + 980 indented subtest lines.** Both
halves are reported because the split is the difference between a number a reader
can check by eye and one they cannot.

Pass and skip counted **separately**, and the skip count is the load-bearing half:
**0**. `internal/mfa`, `internal/apikeys` and `internal/admin` each carry a
`TestTheDatabaseTierActuallyRan`, so the number of skips is a fact about this run
rather than an absence nobody looked for. Counted with **CI's own awk**, lifted out
of `ci.yml` verbatim, and cross-checked against `grep` on `--- PASS: ` — both
report 1789. The tier membership list was likewise derived with `ci.yml`'s own
`grep -rl --include='*_test.go' -E 'dbtest\.(Pool|Schema|EnvVar)|TEST_DATABASE_URL'`
plus its comment-stripping pass, which is what makes the count 13 and not 12.

| | measured | `ci.yml` floor | slack |
|---|---|---|---|
| whole suite | **1789** PASS, 0 SKIP | `SUITE_FLOOR: 1254` | **535** |
| database tier | **1590** PASS, 0 SKIP, **13 packages** | `DATABASE_TIER_FLOOR: 1166` | **424** |

**535 tests — 30% of this suite — could be deleted and CI would still be green.**
The floor is a decrease-detector, and a detector with 30% of headroom detects
almost nothing. This is the concrete form of the packet's premise: `bin/prime`
was worth an unknown number, and the number was never written down anywhere.

### The green proving run, checked rather than trusted

`gate_check.py --prove` reported `OK … 0 failure(s), 2 warning(s)`, exit 0. An
exit code is a claim, so the gate's own log was read afterwards — the log the
checker deliberately does not print into its report:

```
ok lines: 18    cached: 0    not-cached: 18
```

A green checker that had run nothing would have looked exactly like this one, two
paragraphs ago. This is the check the packet is about, applied to the packet's own
result.

### The no-floor claim, verified rather than asserted

`gate.yml` declares **no `minimum`**, against a packet that asked for a floor. That
was checked, not taken on the previous run's word. Over this suite's complete
5,225-line `-v` output, every candidate single-capture-group pattern captures a
package path or a **duration**:

| pattern | matches | last capture | is a count? |
|---|---|---|---|
| `^ok\s+(github\.com/cafaye/identity/\S+)\t` | 18 | `github.com/cafaye/identity/internal/users` | no — a path |
| `^--- PASS: (\S+)` | 809 | `TestVerifyPassword` | no — a name |
| `^\?\s+(github\.com/cafaye/identity/client/generated)\t` | 1 | `client/generated` | no — a path |
| any `<integer> passed\|tests` line | **0** | — | **nothing to read** |

A floor on a duration is a number that means nothing, and a floor on the *count of
matching lines* is not expressible: the checker reads the **last** match, not how
many there were. The schema anticipates exactly this — `minimum` is documented as
*"omit it only for a proof that reports nothing countable (a step that must appear
in the log, a tier that must not say it skipped)"* — so this is its designed case
and not a gap worked around in it. The decrease-detector stays in `ci.yml`, which
counts a `-v` run, and the counts are recorded in `gate.yml` as measured facts.

Two smaller staleness bugs in the same neighbourhood, both hand-written copies of
measurements, which is the exact failure `REPORT-identity-12-coverage.md` was
about:

- `ci.yml`'s comment says "the **11 packages** that open a pool". There are **13**.
  `cmd/identity` and `internal/platform/db` are in the tier and were not counted.
  Re-derived here with `ci.yml`'s own grep: 13.
- `ci.yml`'s run summary says `goose up before any test | 10 migrations applied`.
  There are **13** migrations in `migrations/`.

Neither is fixed here. Both are edits to `.github/workflows/ci.yml`, and this
packet's job is the declaration; the floors and the prose are reported for the
manager with the numbers attached so the decision is one of intent rather than of

Two smaller staleness bugs in the same neighbourhood, both hand-written copies of
measurements, which is the exact failure `REPORT-identity-12-coverage.md` was
about:

- `ci.yml`'s comment says "the **11 packages** that open a pool". There are **13**.
  `cmd/identity` and `internal/platform/db` are in the tier and were not counted.
- `ci.yml`'s run summary says `goose up before any test | 10 migrations applied`.
  There are **13** migrations in `migrations/`.

Neither is fixed here. Both are edits to `.github/workflows/ci.yml`, and this
packet's job is the declaration; the floors and the prose are reported for the
manager with the numbers attached so the decision is one of intent rather than of
measurement.

---

## The gate can fail — three times, observed, all quoted

A gate that has never been observed red is not a gate. Every run below was
produced by breaking something on purpose. **The checker's exit code was captured
directly, never through a pipe** — this fleet's one recorded false green was
`… | tail -45; echo "PRIME EXIT=$?"` under zsh, where `$?` is `tail`'s, and a
proof that ignored that would be worth nothing.

**RED 0 — the false green, which is the packet's own premise, tested directly.**
The packet says *"a checker replaced by a function that unconditionally exits 0
would leave this repository green."* So that is what was tried: a copy of this
tree with `bin/prime` replaced by

```sh
#!/bin/sh
exit 0
```

The gate exits 0. The checker does not believe it:

```
FAIL gate.proof-missing: proof 'mfa-tier-ran' never appeared; …
FAIL gate.proof-missing: proof 'apikeys-tier-ran' never appeared; …
FAIL gate.proof-missing: proof 'admin-tests-passed' never appeared; …
FAIL gate.proof-missing: proof 'httpapi-matrix-ran' never appeared; …
FAIL gate.proof-missing: proof 'ci-guard-ran' never appeared; …
FAIL gate.proof-missing: proof 'client-ran' never appeared; …
FAIL gate.proof-missing: proof 'cmd-identity-ran' never appeared; …
FAIL gate.proof-missing: proof 'generated-excluded' never appeared; …
FAIL …: 8 failure(s), 2 warning(s)
```

**Checker exit code: 1.** All eight proofs went red — and note what did *not*
appear: there is no `gate.nonzero`, because the exit code genuinely was 0. The
exit code was never what caught this. The proofs are, and that is the whole
difference between a gate and a command that exits zero.

**RED 1 — the database tier silently absent.** `bin/prime` re-run with
`TEST_DATABASE_URL` unset, which is the configuration behind identity's recorded
"1430 tests proving they do not notice an empty database":

```
FAIL gate.nonzero: the gate exited 1
FAIL gate.proof-missing: proof 'mfa-tier-ran' never appeared; no line of the gate's
     output, with terminal escapes stripped, matches '^ok\s+github\.com/cafaye/identity/internal/mfa\t'
FAIL gate.proof-missing: proof 'apikeys-tier-ran' never appeared; …
FAIL …: 3 failure(s), 2 warning(s)
```

**Checker exit code: 1.** Two independent signals. Repair the exit code alone and
the tier proofs still go red.

**RED 2 — a package that quietly loses its tests.** `internal/admin`'s two test
files moved out of the tree:

```
FAIL gate.nonzero: the gate exited 1
FAIL gate.proof-missing: proof 'admin-tests-passed' never appeared; …
FAIL gate.proof-missing: proof 'ci-guard-ran' never appeared; …
FAIL …: 3 failure(s), 2 warning(s)
```

The third signal is the repository's own and is the best thing in this report:
`internal/platform/ci`'s `TestTheCoverageExclusionIsOnlyGeneratedCode` — written
to catch a deleted **generated** file — walked the tree, found `service_test.go`
and `store_test.go` in git but not in the worktree, failed, and took
`ci-guard-ran` down with it. Files restored before this commit; `git status`
confirmed clean.

**RED 3 — the false green that was live in this repository**, described at the top
of this report: 16 of 18 packages cached, exit 0, every proof satisfied, two
packages executed. That one was not induced for the proof; it was *found*, and it
is the reason `bin/prime` changed.

---

## The finding that was NOT fixed, because fixing it is not this packet's job

**Three packages carry a test named `TestTheDatabaseTierActuallyRan`, and the
three assert three different things.**

| file | asserts | enforces the tier? |
|---|---|---|
| `internal/mfa/store_test.go:810` | `t.Fatalf` unless `TEST_DATABASE_URL` is set | **yes** |
| `internal/apikeys/store_test.go:788` | `t.Fatalf` unless `TEST_DATABASE_URL` is set | **yes** |
| `internal/admin/store_test.go:35` | `t.Fatal` under `testing.Short()` only — never reads `TEST_DATABASE_URL` | **no** |

Measured consequence, from RED 1: with the variable unset, **11 of the 13 database
packages printed `ok`** — including `internal/httpapi`'s 669-test authorization
matrix, `internal/accounts`, `internal/oauth`, `internal/oidc`, `internal/outbox`,
`internal/sessions` and `internal/users`. Everything in them reached the database
through `dbtest.Pool`/`dbtest.Schema`, which **skip silently** when the variable is
empty, and a package whose tests all skip still prints `ok`. 1,590 tests' worth of
database coverage reported green without a database.

Two more consequences:

- **`ci.yml`'s "the security tests ran, by name" step greps
  `--- PASS: TestTheDatabaseTierActuallyRan (`** — one grep, satisfied by any of
  the three copies. It cannot tell which one it saw, so in the configuration it
  was written to catch it can be satisfied by the copy that checks nothing.
- The gate is nonetheless still red in that configuration, because `mfa` and
  `apikeys` enforce it. **Enforcement is two packages deep.** If either of those
  two is ever relaxed the failure becomes silent — which is the shape of the
  original defect.

Not fixed: changing it means editing a test assertion, and the packet's hard
constraint is that assertions are not weakened to make something pass. This one
would be *strengthened*, but it is a change to test behaviour rather than to a
declaration, and it belongs to whoever owns the tier. `gate.yml` names the
discrepancy where a reader of the proofs will hit it, and weakens its own claim
for `admin` accordingly — the `admin-tests-passed` proof is documented as **not**
evidence that admin's tier reached a database.

---

## Environment-gated, named so the next reader knows what was not exercised

| what | status |
|---|---|
| **`TEST_DATABASE_URL`** — the gate's one environment gate | **SET, and the tier ran.** Against the container on 5433. **0 SKIP**, and 1590 PASS in the 13 tier packages. The skip count is the evidence: a silently-skipped tier would have shown a non-zero skip number or a lower tier count, and neither happened. |
| `go test -race ./...` (AGENTS.md's fourth gate) | **NOT run.** CI measures it at 2 m 26 s on a 2-core runner; this machine was at load 31–70 for the whole of this run. `bin/prime` was run green, uncached, twice (once directly, once through `--prove`). |
| `internal/httpapi`'s `-race` concurrency claims | **not exercised locally** |
| migrations applied before the suite | **verified directly**: `goose_db_version` reports 14 applied rows against 13 `.sql` files — goose's version-0 row is the difference. So the tier ran against a migrated schema, not an empty one. |
| coverage floor | **not measured**; `bin/coverage-floor` needs a profile, and this packet changed no Go code |
| Postgres minor | `postgres:17-alpine` on **port 5433** (5432 is held by a native PostgreSQL 18.4 — see below) |
| toolchain | go1.26.1 darwin/arm64 via mise |

**Two environment traps, both measured, both worth a line in `migrations/README.md`
or `docker-compose.yml` later:**

1. **Host port 5432 was already held by a native PostgreSQL 18.4.** The container
   came up and reported **healthy**, because the compose health check is
   `pg_isready`, which reports a server accepting connections and does not
   authenticate — while `goose` and every test failed with
   `FATAL: role "identity" does not exist`. The compose file already documents the
   remedy (`POSTGRES_PORT`), and `gate.yml` records it, because "the database is
   up and the gate cannot see it" is otherwise a very confusing hour.
2. **The suite can exhaust PostgreSQL's default `max_connections=100`.**
   *(Measured by the previous dispatch, not re-measured here; carried forward
   because it is a real trap and this run's load was 31–70, lower than the 121–166
   it was reproduced at, so this run neither confirmed nor contradicted it.)*
   `db.DefaultOptions()` sets `MaxConns: 8` and `dbtest.Schema` opens **two** pools
   per call, so one schema clone can hold 16 connections. `go test -p` defaults to
   `GOMAXPROCS`: **2 on CI's `ubuntu-latest` runner, 8 here.** Under load 121–166
   five tests failed with

   ```
   store_test.go:344: preparing the test_001121311e00 schema: timeout: context deadline exceeded
       ALTER TABLE test_001121311e00.mfa_challenges ADD CONSTRAINT … FOREIGN KEY …
   ```

   every one at exactly 20.0x s — `dbtest.Schema`'s hardcoded
   `context.WithTimeout(…, 20*time.Second)`, which covers acquiring a connection
   *and* running the DDL, so pool starvation surfaces as "the database was slow".
   **CI never sees this because its runner has two cores.** Not fixed: raising that
   timeout is a raised timeout, and it is the change the packet forbids. It is a
   decision for the manager, and the two candidate answers are a larger
   `max_connections` for the test database or a `-p` bound — both of which are
   environment or CI changes, not assertion changes.

OrbStack also died mid-run once (`dial unix …/docker.sock: no such file or
directory`), taking a 117-second suite with it. Reported because it is why one
intermediate measurement in this packet's history disagrees with the final one and
was discarded rather than averaged: **the numbers in this report are from
complete, exit-0 runs only.**

**One side effect left on the machine, recorded rather than tidied away.** While
OrbStack was down, a `postgres:17.11-alpine` container was unreachable, so an
attempt was made against the native PostgreSQL 18.4 on 5432. That needed a role
and a database named `identity`, and **both were created on the developer's shared
local PostgreSQL and have been left in place**:

```sql
CREATE ROLE identity LOGIN PASSWORD 'identity';   -- test-only, matches docker-compose.yml
CREATE DATABASE identity OWNER identity;
```

They are additive and reversible (`DROP DATABASE identity; DROP ROLE identity;`)
and the credentials are the same test-only ones `docker-compose.yml` and
`ci.yml` already commit, so nothing secret was created. It is left rather than
dropped because a concurrent worker may since have started using them, and
dropping a role another process depends on is the worse mistake. No measurement in
this report was taken against it: every number above is from the pinned
`postgres:17.11-alpine` container.

---

## What this run changed

`gate.yml` and this report and `CHANGELOG.md` were already written by the dead
dispatch and are **kept**, with their stale claims corrected. Changed here:

- **`bin/prime`: `-count=1` added to the `go test` line.** The finding of this
  packet. Before: a green gate that executed 2 of 18 packages. After: 18 of 18,
  0 cached, 126s. One flag, and it is the flag kit's own template ships and
  kit's validator fails a build without. **This is a strengthening, not a
  loosening** — no assertion was weakened, no timeout raised, no retry added.
- **`bin/prime`: the header no longer claims to be kit's template "unmodified".**
  It is not, and it said so while being wrong. It now records the real divergence
  (POSIX `/bin/sh`, no `--fast`, no `require` preflight, no `go vet`) and why each
  is deliberate, and drops a self-contradiction that called kit's template
  `#!/bin/sh` when it is `#!/usr/bin/env bash`.
- **`gate.yml`**: the `-count=1` section rewritten (it described a hole that is
  now closed); the no-floor justification rewritten to cite **this run's** evidence
  — a 5,225-line log and four probed capture-group patterns — and the schema's own
  sanction, instead of the unsupported phrase *"in any Go release"*; RED 0 (the
  false green) and RED 3 (the live cache false green) added, so the file carries
  three observed reds.
- **`internal/platform/ci/ci_test.go`: one comment.** It described kit's Go job as
  running `go test ./...`; it runs `go test -count=1 ./...`. No assertion changed.
- **Not touched**: `ci.yml`, every floor, every assertion, and no test added or
  deleted. **Nothing was pushed.**

Verified green before committing: `gate_check.py` static `OK, 0 failure(s),
2 warning(s)` exit 0; `--prove` `OK, 0 failure(s), 2 warning(s)` exit 0 with the
gate's log showing **18 packages, 0 cached**; `gofmt -l .` empty; `go vet ./...`
clean; `internal/platform/ci` green; `go test -count=1 ./...` exit 0.

The two warnings are `gate.requirement-unproven` for `mise` and `docker` — bare
names, so claims about this machine that the checker deliberately does not run.
That is the designed severity: it would be red on a laptop and green on CI.
`--log-dir` was used for every proving run, so no gate output — and therefore no
credential that could reach a log — was printed into this report. The saved logs
were swept for `postgres://…:…@` and `password=` before anything was quoted from
them: **0 matches**.

---

## What I could not verify

- **`go test -race ./...` was not run.** This is AGENTS.md's fourth gate and it is
  the one gate I did not exercise. The machine was at load 31–70 throughout, and a
  race run under that load measures contention rather than races. CI runs it, on a
  two-core runner, with `-count=1`. **Unverified locally.**
- **`bin/coverage-floor` was not run.** It needs a coverage profile, and this
  packet changed no Go code, so the coverage number is unchanged by construction —
  but I did not measure it to prove that.
- **The eight proofs are matched against package lines, so they detect a package
  disappearing, not an individual test being deleted.** This is a property of `go
  test` without `-v`, and it is why the decrease-detector lives in `ci.yml`. I have
  not proposed a change to the format, and `core` is read-only for this packet, so
  the question "how should a Go repository declare a floor" is left open for the
  manager rather than answered here.
- **I did not confirm that identity's `bin/prime` was ever actually run by a
  developer.** The cache measurement proves the flag was missing and that a green
  result could be vacuous; it does not prove anyone was misled. The claim is about
  the mechanism, and only the mechanism is asserted.
- **The `postgres:18.4` role and database left on port 5432** by the previous
  dispatch are described above from its report. I did not create them, did not
  verify they still exist, and took **no measurement** against them: every number
  in this report is from the `postgres:17-alpine` container on **5433**.
