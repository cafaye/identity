# HANDOFF — identity-substrate-01

**Status:** the packet's four jobs are done and measured. Three commits on
`worker/identity-substrate-01`, base `fddb9f4`.

1. `1cc1e97` — the proof, and the measurement harness (`bin/credential-audit-drift`)
2. `c9b6ce6` — the fix (`migrations/00017_credential_audit_dependencies.sql`)
3. `386c678` — the drift gate (`internal/platform/ci/substrate_copy_test.go`)

Full write-up: `moon/logs/REPORT-identity-substrate-01.md`.

**Worktree is NOT green**, for one reason that is not mine:
`TestTheCoverageExclusionIsOnlyGeneratedCode` fails with
`client/generated records lines=22435 and the tree holds 22411`. Confirmed red at
`fddb9f4` by stashing. Untouched — it belongs to whoever changed `client/generated`.

---

## The one thing to know before you change anything here

The defect is **role-dependent**, and this is the trap.

Running the old audit as a role with no schema of its own returns the **correct**
answer. It returns **zero rows** as `cafaye` — kit's cluster admin role
(`KIT_POSTGRES_USER: ${KIT_POSTGRES_USER:-cafaye}`), i.e. the role an operator audits
credentials as. `pg_get_expr` omits the schema of a name the *session* could resolve,
and `"$user"` is a `search_path` entry.

**So: do not reproduce this by checking whether a regexp matches.** It matches. Reproduce
it by running `credential_tables()` as **two different roles**. `bin/credential-audit-drift`
does exactly that and takes about a minute.

---

## The successor's first move

Not a refinement of mine. The highest-value thing left, and I did not have time:

> **Check whether the other eight account-scoped services carry the same copy of
> identity's bug.** If `caf lock`'s third reason is right — that copying a template is
> invisible by construction — then each of them is another occurrence, and none of them
> has a gate.

Cheapest first pass, per service:

1. create a role named after `KIT_POSTGRES_USER` (default `cafaye`) in that service's database;
2. apply its migrations;
3. `select * from cafaye.credential_tables()` **as that role** and as the service role;
4. empty for one and not the other is the same defect.

Two things that will save you time, both measured:

- **`internal/platform/ci/substrate_copy_test.go` needs a kit checkout within three
  levels above the repo**, or it emits a named SKIP. It is not a silent pass — the SKIP
  text says exactly what was not checked.
- **Compare function bodies, not whole files.** identity's 00016 has its own header and
  five trailing `protect_*` calls, so a whole-file `diff` against kit is ~344 lines of
  noise. Six of the seven functions are byte-identical; only `credential_tables` drifted.

---

## What I could not finish, precisely

| Not done | Consequence |
|---|---|
| `bin/prime` (full suite), `go test -race ./...` | I verified the package my change touches, `gofmt -l .`, and `go vet ./...`. I did not run the whole suite. |
| `goose up` / `goose down` | I fed migrations through `bin/migration-up-section` into `psql` — the same Up-section extraction `bin/migrate` uses — but not goose's own parser. 00017's `Down` was applied by hand and applies cleanly. |
| `core/harness/tenancy_check.py` | Read only, not run. It checks `protect_credential_table` *call sites* and the DDL and RLS, and **never reads `credential_tables()`'s body** — so nothing in the fleet's scanner would have caught this. |
| Booting identity's real stack | I read kit's role-name default out of `templates/compose/docker-compose.yml`; I did not confirm identity's deployed cluster admin role is literally `cafaye`. |

---

## Two things I got wrong first, because both are the kind that survive review

1. **The check as I first wrote it was green on the defect.** It compared only 00017's
   body; putting the whole defect *back into 00016* left it green, because 00017 still
   installs the right function afterwards. In a migration sequence the last definition
   wins, so the sound question is whether **any** migration installs a spelling-reading
   audit. Rewritten, and a new `00018` re-copying kit's old substrate is now caught by
   name. If you add migrations here, keep that property.
2. **The fix did not match kit on its own first commit.** I put a provenance comment
   *inside* the function body; the byte comparison failed its own commit on six comment
   lines. Provenance comments for a verbatim copy belong **above** the function.

## Traps in the tree you will hit

- **00016 must not be edited.** It is applied in deployed environments. `00016` is a
  *named exception* in `migrationsThatPredateTheFix` in `substrate_copy_test.go`, and
  **a dead entry is a failure** — if you ever fix 00016 in place, delete the entry in the
  same commit or the gate goes red.
- **`repoRoot` already exists** in `internal/platform/ci/ci_test.go`. It resolves the root
  from the file's own path, not the working directory. I nearly wrote a second copy; use
  theirs.
- **The worktree is nested one level deeper** than the packet says:
  `cafaye/identity/cafaye/wt-m39-identity-substrate-01`, not `cafaye/wt-m39-...`. That is
  why the kit lookup walks up to three levels rather than one.