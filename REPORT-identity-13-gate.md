# REPORT — identity-13-gate

## The finding

**`bin/prime` could not be executed at all.** The file has the executable bit and
no interpreter line. `execve(2)` on it fails with `ENOEXEC`, so the gate this
packet had to declare was impossible to start:

```
FAIL gate.command-missing: gate.command could not be started:
     [Errno 8] Exec format error: 'bin/prime'
```

A developer and CI never saw it, because `bash` and `zsh` both fall back to
interpreting a shebang-less file themselves. `core`'s `harness/gate_check.py` runs
the declared gate through `subprocess` with **no shell**, so it hit the real
behaviour on the first attempt. Every other adopter in the fleet ships a shebang
(`courier` `#!/bin/sh`, and `muse`/`darkroom`/`cafaye-rb`/`cafaye-ts`/`core`
`#!/usr/bin/env bash`); kit's own Go template ships `#!/bin/sh`. Identity's
scaffold lost it in identity-01 and nothing noticed for twelve packets.

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

## The two commands, measured, and they are not the same

| | command | measured |
|---|---|---|
| Developer | `bin/prime` — `go mod download && go build ./... && go test ./...` | exit 0, **335 s**, 18 `ok` packages, 0 FAIL |
| CI `gate` job | `./bin/prime` **and** `go test -v -count=1 -race -coverprofile=… ./...`, plus `goose up` above both, `go vet`, `gofmt`, a lockfile guard, `bin/coverage-floor`, and a five-process boot test | — |

**The difference that matters is one flag, and it is `-count=1`.** CI's counted
run has it; `bin/prime` does not, and `go test` without it is served from Go's
test cache.

- The green `bin/prime` run: **13 of its 18 `ok` package lines read `(cached)`** —
  five packages actually executed.
- The green `gate-check --prove` run: **16 of 18 cached**, 18 `ok` lines, all
  eight proofs satisfied, **`OK … 0 failure(s), 2 warning(s)`, in 10 seconds.**

So a developer who runs `bin/prime` twice with nothing changed gets a second
green gate that executed nothing, and this packet's own prover reported `OK` on a
run that executed two packages. Every proof in the declaration is matched against
a package line for exactly this reason: a `(cached)` line satisfies one, and
nothing written against this gate's output can do better. It is stated in
`gate.yml` rather than left for the next reader.

---

## The numbers, and CI's floors are far below them

Measured on this tree — `worker/identity-13-gate` at `98b9a8f` — with
`postgres:17.11-alpine` (the minor `ci.yml` pins), 13 migrations applied by
`goose`, 8-core arm64 darwin, load average between 6 and 60.

```
$ go test -v -count=1 ./...
PASS=1789  SKIP=0  FAIL=0        21 packages (18 ok, 3 [no test files]), 221 s, exit 0
```

Pass and skip counted **separately**, and the skip count is the load-bearing half:
**0**. `internal/mfa`, `internal/apikeys` and `internal/admin` each carry a
`TestTheDatabaseTierActuallyRan`, so the number of skips is a fact about this run
rather than an absence nobody looked for. Cross-checked two ways — `grep` on
`--- PASS: ` and `ci.yml`'s own awk — which report the same 1789.

Counted with **CI's own derivation** (the grep for `dbtest.Pool|Schema|EnvVar`
with comments stripped, then per-package sums):

| | measured | `ci.yml` floor | slack |
|---|---|---|---|
| whole suite | **1789** PASS, 0 SKIP | `SUITE_FLOOR: 1254` | **535** |
| database tier | **1590** PASS, 0 SKIP, **13 packages** | `DATABASE_TIER_FLOOR: 1166` | **424** |

**535 tests — 30% of this suite — could be deleted and CI would still be green.**
The floor is a decrease-detector, and a detector with 30% of headroom detects
almost nothing. This is the concrete form of the packet's premise: `bin/prime`
was worth an unknown number, and the number was never written down anywhere.

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

## The gate can fail — twice, observed, both quoted

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

Two independent signals. Repair the exit code alone and the tier proofs still go
red.

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
| `go test -race ./...` (AGENTS.md's fourth gate) | **NOT run.** Measured by CI at 2 m 26 s on a 2-core runner; this machine was at load 121–166 for most of the packet. `bin/prime` itself was run green five times. |
| `internal/httpapi`'s `-race` concurrency claims | not exercised locally |
| `goose status` before first test | 13 applied, printed by the run — the CI ordering held |
| coverage floor | not measured; `bin/coverage-floor` needs a profile, unchanged by this packet |
| Postgres minor | `17.11-alpine`, the pinned minor. A local `postgres:18.4` was tried first and abandoned. |
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

## What this packet changed

- **`gate.yml`, new.** Entry point, arguments, eight proofs, three external
  requirements, the CI binding. Static phase: `OK … 0 failure(s), 2 warning(s)`,
  exit 0. Proving phase: `OK … 0 failure(s), 2 warning(s)`, exit 0.
- **`bin/prime`, one line.** `#!/bin/sh`, plus the comment explaining why it is
  load-bearing. Behaviour unchanged.
- Nothing else. `ci.yml` is untouched, no floor was moved, no assertion was
  touched, no test was added or deleted, and nothing was pushed.

The two warnings are `gate.requirement-unproven` for `mise` and `docker` — bare
names, so claims about this machine that the checker deliberately does not run.
That is the designed severity: it would be red on a laptop and green on CI.
`--log-dir` was used for every proving run, so no gate output — and therefore no
credential that could reach a log — was printed into this report.
