# REPORT — identity-12-coverage

## The finding

**The coverage floor was measuring a generated file, and the fix that was available
in one line was to lower the floor.** `client/generated/api.gen.go` is 12,284 lines
of committed oapi-codegen output carrying 3,001 statements that no test in this
repository exercises. Go's `go tool cover -func` computes `total:` over every block in
the profile and has no flag to leave a path out, so module coverage reads **44.6%**
against a floor of 70. Lowering the floor to 45, or writing tests against a file the
next `go generate` deletes, would both have been green by Friday.

Neither was taken. The generated client is now excluded by a **declared path** in
[`coverage-exclusions`](coverage-exclusions), and the floor is still 70, measured at
**73.6%** over everything the declaration does not exclude.

The second finding is the one I would keep if I could only keep one: **the floor's
own number was already wrong, twice, and nothing could have told you.** `.github/workflows/ci.yml`
carried `"73.2% measured"` in two places. That number was measured before `client/`
existed, and it went stale again the moment the generated client was regenerated
against a document that had gained three operations. A percentage written into a
config file is a *copy* of a measurement, and a stale copy is indistinguishable from
a fresh one. This packet **deleted both copies** rather than updating them, and
`bin/coverage-floor` now measures and prints on every run. There is no hand-written
coverage number anywhere in the repository.

---

## The numbers, both measured

Measured on this tree — `master` (identity-11) + `worker/identity-10`, with the
generated client regenerated against the merged document — with the database tier
applied, by the exact command `ci.yml` runs:

```sh
go test -count=1 -race -coverprofile=coverage.out ./...
```

**Before** — `ci.yml`'s coverage step as it stood, verbatim:

```
$ go tool cover -func=coverage.out | tail -1
total:						(statements)			44.6%
```

**After** — `ci.yml`'s coverage step as it now stands, verbatim:

```
$ bin/coverage-floor coverage.out coverage-exclusions 70
coverage 73.6% of 4628 statements, over the profile minus 2257 block(s) this file excludes
excluded — 1 declared entry/entries in coverage-exclusions:
  client/generated  files=1 lines=12284  owner=identity since=2026-09-30 until=2027-03-31
      reason: oapi-codegen v2.8.0 output for openapi/v1.yaml, committed on purpose and regenerated on every document change; 3001 statements, none of them exercised by any test in this repository, and a test added to them would be deleted by the next `go generate`. This is not hand-written code and holding it to a hand-written coverage floor measures the generator rather than this repository
floor 70%  (coverage-fail-under, restated here so the measured number, the excluded set and the floor are read together rather than one at a time)
coverage 73.6% at or above the 70% floor
```

The arithmetic, so the two numbers can be checked against each other:

| | statements | covered | percentage |
|---|---:|---:|---:|
| whole module | 7,629 | 3,406 | **44.6%** |
| excluding `client/generated` | 4,628 | 3,406 | **73.6%** |

`client/generated` alone is 2,257 profile blocks and 3,001 statements, all at zero.

**MD16 says 45.9%; this tree reads 44.6%.** The difference is real and measured, not
a disagreement about the method: MD16's number was taken at `identity-10`'s tip,
where the generated file was 10,333 lines. Merging `identity-11` into that tree
adds three hand-written, well-tested operations *and* three generated ones, so the
file is now 12,284 lines and the module is larger on both sides of the ratio.

### The floor did not move, and no test was added to generated code

`COVERAGE_FAIL_UNDER` is `70` in three places and has not changed value in any of
them. There is no test in this repository that imports or exercises
`client/generated` — `go test ./client/generated` reports `no test files`, and a
test written against `api.gen.go` would be deleted by the next `go generate`, so the
coverage would not survive a week. That is the same argument the lint exclusion in
`.golangci.yml` makes, for the same file, in the same shape.

---

## What shipped

1. **[`coverage-exclusions`](coverage-exclusions)** — the declaration. One entry, in
   kit's allowlist dialect (`templates/tier/skip-allowlist`): reason, owner, `since`,
   `until`, the `files=`/`lines=` it covers, and the floor.

2. **[`bin/coverage-floor`](bin/coverage-floor)** — the mechanism. Reads the
   declaration, validates every field, filters the profile, prints the measured
   number / excluded set / floor in one block, then compares.

3. **[`internal/platform/ci/coverage_exclusions_test.go`](internal/platform/ci/coverage_exclusions_test.go)**
   — `TestTheCoverageExclusionIsOnlyGeneratedCode` and four siblings, plus
   `TestTheCoverageFilterCanFail`, which drives the real script through 22
   deliberately broken declarations and profiles.

4. **`.github/workflows/ci.yml`** — the `coverage` step calls the script; the stale
   `73.2% measured` is gone from three places; the five new tests are in the named
   security-test list.

5. **Docs** — `AGENTS.md`, `README.md`, `CHANGELOG.md`, and `DECISIONS.md` D6
   (which had left this open as "a manager's call").

### One repository, two exclusions, one discipline

The addendum was right that this should not become a second dialect, and the shape
is the one `identity-10` used:

| | lint | coverage |
|---|---|---|
| declaration | `.golangci.yml`, one anchored regex | `coverage-exclusions`, one path prefix |
| granularity | a **file**, because golangci-lint takes a regex | a **directory**, because Go takes a package |
| test | `TestTheLintExclusionIsOneFileAndNotAPrefix` | `TestTheCoverageExclusionIsOnlyGeneratedCode` |
| compensating obligation | walk every `.go` file; fail if the pattern matches one that is not the generated file | walk every `.go` file under the prefix; fail if one is not itself generated; and fail if the recorded `files=`/`lines=` no longer match |
| what it would cost to be wrong | a hand-written file stops being linted | hand-written code is held to no floor |

The grammar, the four hygiene rules and the "an entry matching nothing is a failure"
semantics are **kit's**, quoted from `templates/tier/skip-allowlist` and not
re-invented. `TestEveryExcludedDirectoryIsNamedInTheDeclaration` is one test this
packet adds that the lint side does not have, and it closes the other half of the
same hole: a generated directory that arrives and is *never* declared fails too, so
the denominator cannot grow by accident in either direction.

**Why the coverage case cannot simply copy the lint case**, which is the addendum's
one real difference and which the test above is the price of: `go tool cover` takes a
package pattern, not a file. `client/` would be a perfectly legal declaration, and it
would exempt `baseurl.go`, `credentials.go`, `errors.go`, `redact.go`, `client.go`,
`transport.go` and every test in the package. Nothing about the format stops it;
only the test does.

---

## The red proofs, all run against the real repository

Every proof below mutated the working tree, ran the **shipped** artefacts, and
restored. Nothing is simulated. Full transcript:
`/private/var/.../opencode/id12red/all.txt`.

### The control first — the unmodified tree

```
$ bin/coverage-floor <the real profile>
coverage 73.6% of 4628 statements, over the profile minus 2257 block(s) this file excludes
...
coverage 73.6% at or above the 70% floor
exit=0

$ go test ./internal/platform/ci/ -run Coverage
ok  	github.com/cafaye/identity/internal/platform/ci	1.913s
exit=0
```

### Proof 1 — the excluded path is deleted

```
$ rm client/generated/api.gen.go
$ go test -run 'TestTheCoverageExclusionIsOnlyGeneratedCode' ./internal/platform/ci/
--- FAIL: TestTheCoverageExclusionIsOnlyGeneratedCode (0.05s)
    coverage_exclusions_test.go:176: line 129: client/generated is excluded and client/generated/api.gen.go is in git but not in the worktree.
        The declaration is now exempting nothing. `git ls-files` still lists it, which is why this reads as a missing file rather than an unused entry — the generator moved, or the file was deleted, and either way somebody has to decide what the exclusion covers now.
    coverage_exclusions_test.go:207: line 129: client/generated records files=1 and the tree holds 0.
        The excluded set changed and the declaration was not restated, so the floor is now a percentage of a set nobody has read. Rewrite this entry in the same commit as whatever changed it.
    coverage_exclusions_test.go:214: line 129: client/generated records lines=12284 and the tree holds 0.
go test exit=1
```

**A finding worth reporting rather than hiding:** run against the *saved* profile,
`bin/coverage-floor` passed (exit 0). That is correct and it is a real limit of the
split — the script sees blocks, the test sees files. `bin/coverage-floor` catches an
entry that matches nothing **in a fresh profile**, which is what CI has;
`TestTheCoverageExclusionIsOnlyGeneratedCode` catches the source file disappearing.
Neither alone is the check; both are rule 4 against a different artefact. This was
also a bug I wrote: the first version of this test called `t.Fatalf("reading %s")`
and reported `no such file or directory`, which is true and useless. It now names
the declaration and says what to do.

### Proof 2 — an entry that matches nothing

```
$ sed -i '' 's|^excluded coverage client/generated |excluded coverage client/nowhere |' coverage-exclusions
$ bin/coverage-floor <profile> coverage-exclusions 70
::error::client/nowhere is excluded and matches NOTHING in …/before.out.
::error::The generator moved, the directory has no Go file in it, or it was
::error::deleted. Either way this entry is dead weight, and dead entries
::error::are how an allowlist becomes a list of everything (kit's rule 4,
::error::reportUnusedDisableDirectives).
bin/coverage-floor exit=1

$ go test -run Coverage ./internal/platform/ci/
--- FAIL: TestTheCoverageExclusionIsOnlyGeneratedCode (0.02s)
    coverage_exclusions_test.go:152: line 129: client/nowhere is excluded and contains no .go file in this repository.
go test exit=1
```

### Proof 3 — an entry with no reason, and an entry with no owner

```
$ remove reason=, then bin/coverage-floor
  - coverage-exclusions:129: entry names no reason — without one, "generated" becomes the reason for everything, including the hand-written file somebody put in a generated directory
bin/coverage-floor exit=1

$ remove owner=, then bin/coverage-floor
  - coverage-exclusions:129: entry names no owner — an exclusion nobody owns is an exclusion nobody will ever remove
bin/coverage-floor exit=1
```

### Proof 4 — the excluded set changes and the floor is not restated

The headline case: a **hand-written** `.go` file appears under `client/generated`.

```
--- FAIL: TestTheCoverageExclusionIsOnlyGeneratedCode (0.05s)
    coverage_exclusions_test.go:192: line 129: client/generated excludes 1 hand-written .go file(s):

          client/generated/handwritten_extra.go

        Go's coverage step takes a package pattern and not a file, so this exclusion is necessarily a directory — which is why this assertion has to exist. A hand-written file under an excluded directory is code nobody is measuring, held to no floor, and it would be absorbed silently by a rule about the directory rather than the file.

        Either that code moves out of client/generated, or the declaration is wrong and the floor has to cover it.
    coverage_exclusions_test.go:207: line 129: client/generated records files=1 and the tree holds 2.
    coverage_exclusions_test.go:214: line 129: client/generated records lines=12284 and the tree holds 12289.
go test exit=1
```

And a **second generated** file, which is legal and must still be restated:

```
--- FAIL: TestTheCoverageExclusionIsOnlyGeneratedCode (0.04s)
    coverage_exclusions_test.go:207: line 129: client/generated records files=1 and the tree holds 2.
    coverage_exclusions_test.go:214: line 129: client/generated records lines=12284 and the tree holds 12287.
go test exit=1
```

### Proof 5 — the floor moved in one file and not the others

```
$ sed -i '' "s|COVERAGE_FAIL_UNDER: '70'|COVERAGE_FAIL_UNDER: '45'|" .github/workflows/ci.yml
--- FAIL: TestTheCoverageFloorInTheDeclarationIsTheFloorsFloor (0.00s)
    coverage_exclusions_test.go:341: coverage-exclusions line 129 says the floor is 70 and .github/workflows/ci.yml says 45.
        The excluded set, the gate's env: block and the input passed to kit are three statements of one number. Keep them in step, or delete two of them.
go test exit=1
```

`bin/coverage-floor` catches the same thing at run time, from the third argument
`ci.yml` passes it:

```
$ bin/coverage-floor <profile> coverage-exclusions 45
::error::the caller asserts a floor of 45 and coverage-exclusions says 70.
```

### Proof 6 — the floor still bites

With the repository's own declaration in place, unchanged, doing the excluding:

```
--- 699/1000 = 69.9%
::error::coverage 69.9% (699/1000 statements) is below the 70% floor, measured over every statement NOT excluded above.
exit=1

--- 701/1000 = 70.1%
coverage 70.1% at or above the 70% floor
exit=0

--- 699/999 = 69.97%, which PRINTS as 70.0
::error::coverage 70.0% (699/999 statements) is below the 70% floor, measured over every statement NOT excluded above.
exit=1
```

**The third one is a bug this packet's own proof found, and it is the one I would
lead with.** My first implementation compared the *printed* percentage, which is
rounded to one decimal, so 69.97% printed as "70.0" and passed a floor of 70. The
whole floor, given away in the last character of a display format. The comparison is
now `covered * 100 < floor * total` in integers. Go's own tool rounds the same way
and kit's step compares the rounded value, so this is **stricter than the tool it
replaces** — which is the right way round: that tool's job is to report, this one's
is to refuse.

Without that, the exclusion would have made coverage unrestrictable, which is the one
outcome that turns this fix back into a hole.

### Also proved, in the same table

| | |
|---|---|
| entry with no `since` / no `until` | red |
| an **expired** `until` | red, on the day it passes |
| a malformed date (`since=last tuesday`) | red |
| an unknown/misspelled field (`owners=`) | red, not silently dropped |
| a line that is not an entry | red, not a skip |
| a declaration with **no** entry at all | red |
| a duplicate entry | red |
| two entries naming two floors | red |
| a floor of `0` | red — a gate that cannot fail is not a gate |
| a profile that is not a coverage profile | red |
| **every** package excluded (0/0) | red — not 100%, not 0% |
| nothing covered at all | red |
| the good declaration | green, and prints the number, the set, the reason and the floor |

---

## The kit question, answered

**It lives in `identity`. `kit` is untouched.** That is a judgement, not a fact, so
here is the reasoning and the thing that would change it.

The brief's principle is right: the shared workflow should carry the *mechanism* and
each repository its own *declaration*. But identity's **enforcing** coverage step is
its own `coverage` step in the `gate` job, and **kit's cannot enforce anything in
this repository at all**: its `test` step runs with no database, so
`internal/mfa`'s `TestTheDatabaseTierActuallyRan` fails first and the run never
reaches a coverage step. `.github/workflows/ci.yml` says so in its own header, and
that header was written before this packet.

So a mechanism in kit would not be the mechanism this repository uses. identity
would still need its own copy — it cannot read kit's at run time, which is the cost
`templates/tier/skip-allowlist` already records about the fleet-wide file — and a
copy in a consuming repository is a drifting copy with extra steps.

Three further reasons, each of which I weighed and none of which is decisive on its
own:

- **kit-04 is live in that repository.** Not colliding was a constraint, and I would
  not have used it to justify a decision I did not otherwise believe.
- **The one thing that makes this exclusion safe is the generated-file walk**, and it
  is a *test*, not a mechanism. A mechanism in kit would need a test in every
  consuming repository anyway; the part that is reusable is the filter, which is 200
  lines of shell.
- **This is the first repository to need it.** MD16's own trigger is "a second
  repository asking for a generated client". Generalising from one instance is how a
  standard acquires options nobody uses.

**What kit should grow, and when.** A `coverage-exclusions` input on the reusable
workflow plus the filter, so the second repository gets it for free — together with
the "every `.go` file under the excluded directory is generated" walk, because that
is the load-bearing part and the part a consumer is most likely to skip. **As a kit
packet, not by copying this file across**: a copy is a second dialect of the same
rule, which is the thing the addendum told me not to create.

**The disagreement this leaves behind, stated rather than papered over.**
`coverage-fail-under: '70'` is still passed to kit. kit's step computes `total:` over
the whole profile and cannot be told about this declaration, so **it would read
44.6%** if it ever reached its coverage step. That input is left alone on purpose:

- lowering it to 45 is the rejected option, and MD16 exists to forbid it;
- setting it to `0` would be weakening a gate to make a build green;
- removing the call to kit would be forking a shared workflow, which kit's own rules
  forbid.

The threshold is stated in all three files and
`TestTheCoverageFloorInTheDeclarationIsTheFloorsFloor` fails if they stop being the
same number. The **number** is deliberately stated in only one, because a hand-written
number is a copy and a copy goes stale silently.

---

## Something I had to fix that was not in the packet

`identity-10` and `identity-11` branched from the same commit and both changed
inputs the generated client is derived from. Merging them left `client` **red**:

```
--- FAIL: TestTheCommittedGeneratedFileIsWhatThePinnedGeneratorProduces (2.87s)
    regeneration_test.go:170: generated/api.gen.go is not what the pinned generator produces.
        first difference at line 45:
          committed: // Defines values for ConfirmedEnrollmentEnabled.
          generator: // Defines values for AuditLogEntryAction.
--- FAIL: TestTheTransportCoversEveryOperationInTheDocument (0.00s)
    transport_test.go:228: openapi/v1.yaml declares 3 operationId(s) the Transport interface has no method for:
          listaccountauditlog  revokeaccountinvitation  revokeaccountinvitations
FAIL	github.com/cafaye/identity/client	3.970s
GATE_EXIT=1
```

Neither packet was wrong. A committed generated file is a function of its input, so
two branches that each change the input cannot both have a correct output — **this
is the cost of committing generated code, and the next merge will hit it again.**

I repaired it because I could not measure coverage otherwise, and I want to be
explicit that this was not my ruling to make. The repair is exactly what both tests
asked for and nothing more: `go generate ./client/` against the merged document
(10,333 → 12,284 lines), and three methods on `Transport` with three wrappers on
`Client` (`ListAccountAuditLog`, `RevokeAccountInvitation`,
`RevokeAccountInvitations`). **No test, gate or threshold was touched to get green** —
the two failing tests are the drift gates from `identity-09` and `identity-10` doing
their job, and they are recorded in `CHANGELOG.md` as a `Fixed` entry rather than
buried here.

---

## The gate

`bin/prime`, unmodified, against a Postgres I started for this packet
(`POSTGRES_PORT=15502 docker compose -p cafid12cov`), migrated with goose:

```
ok  	github.com/cafaye/identity/client	4.516s
?   	github.com/cafaye/identity/client/generated	[no test files]
ok  	github.com/cafaye/identity/cmd/identity
ok  	github.com/cafaye/identity/internal/accounts
ok  	github.com/cafaye/identity/internal/admin
ok  	github.com/cafaye/identity/internal/apikeys
ok  	github.com/cafaye/identity/internal/auth
ok  	github.com/cafaye/identity/internal/config
ok  	github.com/cafaye/identity/internal/httpapi
ok  	github.com/cafaye/identity/internal/mfa
ok  	github.com/cafaye/identity/internal/oauth
ok  	github.com/cafaye/identity/internal/oidc
ok  	github.com/cafaye/identity/internal/outbox
ok  	github.com/cafaye/identity/internal/platform/ci
ok  	github.com/cafaye/identity/internal/platform/clock
ok  	github.com/cafaye/identity/internal/platform/db
?   	github.com/cafaye/identity/internal/platform/dbtest	[no test files]
ok  	github.com/cafaye/identity/internal/platform/id
?   	github.com/cafaye/identity/internal/platform/oauthtest	[no test files]
ok  	github.com/cafaye/identity/internal/sessions
ok  	github.com/cafaye/identity/internal/users
GATE_EXIT=0
```

**Pass and skip counts, separately** — a skipped check is not a passing check:

- `internal/platform/ci`: **24 tests PASS, 0 SKIP** (22 of the PASSes are the
  sub-cases of `TestTheCoverageFilterCanFail`; the package has 5 top-level tests
  from this packet and 19 pre-existing).
- Whole suite via `bin/prime`: every package `ok`, **zero `--- SKIP:` lines**.
- Three packages report `[no test files]` — `client/generated`,
  `internal/platform/dbtest`, `internal/platform/oauthtest` — which are **not**
  skips and are not counted as passes anywhere.

`go vet ./...` clean, `gofmt -l .` empty. The database I created
(`cafid12cov-postgres-1`, port 15502) is torn down by name at the end of this
session; the containers other workers are running were not touched.

---

## What I could not verify

**This section is the part I am least sure of, and I want it to be longer than is
comfortable rather than empty.**

1. **I never saw the GitHub Actions run.** Every number here is from a laptop
   against a locally started Postgres 17. The `gate` job's `coverage` step is a bash
   invocation of a checked-in script and I executed that script directly, but the
   job wrapper — `$RUNNER_TEMP`, `$GITHUB_STEP_SUMMARY`, the `::error::` annotations,
   the ordering against the earlier steps — was never executed. **`bin/coverage-floor`
   has never run inside Actions.** I tried to simulate it with a throwaway runner and
   did not, so I cannot claim the step works there.

2. **The kit job's behaviour is reasoned, not observed.** I state that kit's coverage
   step "would read 44.6%" — that is arithmetic over the tool's awk, plus reading its
   file. kit's `test` step cannot complete in this repository, so I could not let it
   run and see. **If kit ever grows a `services`/`env` seam, that step will go red
   against 70 and nobody will have seen it coming but me.**

3. **`go tool cover -func`'s `total:` is not what the floor uses any more.** I
   replaced it with explicit arithmetic. The agreement was measured, once, on this
   repository's 5,581-block profile:

   ```
   $ go tool cover -func=coverage.out | tail -1
   total:                                          (statements)   44.6%
   $ go tool cover -func=<the same profile, filtered> | tail -1
   total:                                          (statements)   73.6%
   $ bin/coverage-floor coverage.out coverage-exclusions 70 | head -1
   coverage 73.6% of 4628 statements, over the profile minus 2257 block(s) this file excludes
   ```

   That is **one comparison, on one profile**. If a future Go release changes what
   `total:` means, nothing in this repository would notice, and the comment in
   `bin/coverage-floor` asserting agreement would become false with nothing red.

4. **The `until=2027-03-31` ratchet is a date I chose.** MD16 says the separate-module
   shape should be ruled on before a second repository needs it, and gives no date. I
   picked six months. I cannot show that is the right interval, and the honest
   failure mode is that it rolls forward once without anybody deciding anything —
   which is the one thing kit's rule 3 exists to prevent.

5. **I did not run `go test -race` on the whole suite as a final gate**, only
   `bin/prime` (no `-race`) and the coverage run (which *is* `-race`, and exited 0).
   AGENTS.md names `go test -race ./...` as one of four gates; the `-race` run I did
   was `go test -count=1 -race -coverprofile=… ./...`, which is that command with a
   flag added, and it passed. I am recording the substitution rather than claiming
   the gate as listed.

6. **`golangci-lint` was not run** against this tree after my changes. I did not
   change `.golangci.yml`, but I added a shell script and a Go test file, and
   `TestTheLintExclusionNamesEveryEnabledLinter` runs golangci-lint as part of
   `bin/prime` — so it *was* run, by `client`'s suite, and passed. What I did not do
   is lint the whole tree with kit's stricter config, which this repository
   deliberately does not adopt.

7. **The generated client I committed has not been reviewed by a human against
   `openapi/v1.yaml`.** `TestTheCommittedGeneratedFileIsWhatThePinnedGeneratorProduces`
   proves it is what oapi-codegen v2.8.0 produces from the current document, which is
   the strongest available claim and is *not* the same as a person having read it.
   The three wrapper methods I wrote are covered by the drift gate's existence check
   and by nothing else — **no test exercises `ListAccountAuditLog`,
   `RevokeAccountInvitation` or `RevokeAccountInvitations` over the wire.** I added
   them to satisfy a red gate, which is a weaker justification than writing them
   first, and I would rather say so than let the green gate imply otherwise.

8. **I did not verify the race behaviour of the new script.** `bin/coverage-floor`
   writes to `mktemp -d` and reads `$RUNNER_TEMP/coverage.out`; two concurrent runs
   on one machine would not collide, because each gets its own directory, but I did
   not test two runs at once.

9. **`TestEveryExcludedDirectoryIsNamedInTheDeclaration` may be too strict.** It
   requires every directory containing a generated `.go` file to be declared, which
   would fail if somebody legitimately added a *tested* generated fixture. I chose
   that deliberately — a denominator should not grow without a decision — but I have
   not found out whether it will be annoying.

10. **The fleet-wide version is untested because it does not exist.** Everything in
    this report is about one repository. MD16's trigger is a second repository; if
    the second one copies this declaration format by hand, this packet has created
    exactly the second dialect it was told to avoid, and the only defence is a kit
    packet that I have recommended and not written.

11. **I could not test the failure mode that matters most.** The dangerous version of
    this is somebody widening the exclusion to `client/` under time pressure. I
    proved that a *hand-written file under* the excluded directory fails, which is
    the state it would land in. I did not prove anything about the review that
    should have stopped the edit.

---

## Files

| | |
|---|---|
| `coverage-exclusions` | new — the declaration |
| `bin/coverage-floor` | new — the mechanism |
| `internal/platform/ci/coverage_exclusions_test.go` | new — five tests, 22 sub-cases |
| `.github/workflows/ci.yml` | the coverage step; the stale `73.2%` removed from three places; five tests named |
| `client/generated/api.gen.go` | regenerated against the merged document (10,333 → 12,284 lines) |
| `client/transport.go`, `client/client.go` | three operations from `identity-11`'s document, wrapped |
| `AGENTS.md`, `README.md`, `CHANGELOG.md`, `DECISIONS.md` | the rule, the number, the ruling |

Ruling implemented: **MD16**. DECISIONS.md D6, which `identity-10` left open as "a
manager's call", is answered here with option 1 and the two options it is not.
