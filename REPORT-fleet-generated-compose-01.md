# REPORT — fleet-generated-compose-01

**Branches (one commit each, nothing pushed, nothing merged):**

| repo | branch | commit |
|---|---|---|
| `courier` | `worker/courier-fleet-generated-compose-01` | `aa9eda2` |
| `darkroom` | `worker/darkroom-fleet-generated-compose-01` | `3f30e19` |
| `identity` | `worker/identity-fleet-generated-compose-01` | `af94094` |
| `pantry` | `worker/pantry-fleet-generated-compose-01` | `63f8e21` |
| `core` | `worker/core-fleet-generated-compose-01` | `728b711` |
| `kit` | `worker/kit-fleet-generated-compose-01` | `7327304` |

Worktrees are `wt-m39-<repo>-fleet-generated-compose-01`. No repository's HEAD was
moved; all six main checkouts are still on `master`.

---

## 1. The headline: the packet's table was wrong, and it was wrong in the direction that hides the defect

The brief said to re-derive the scope and to treat a disagreement as the finding.
There is a disagreement, and it is large.

The brief names **five** repositories with the defect: `courier`, `darkroom`,
`identity`, `pantry` (untracked, not ignored) and `core` (tracked).

**Five more repositories have the same defect and the table does not mention
them:**

```
cafaye-rb   cafaye-ts   docs   guard   muse
```

All five have a `cafaye.yml`. None ignores `caf.dev.compose.yaml`. None currently
*has* one — because nobody has run `caf dev` in them on this machine.

That is the whole shape of the failure, stated as a finding: **the table is a
survey of files that happened to be on one laptop.** A repository becomes visible
in it only when somebody runs the local stack command there, which leaves a file
behind. Six repositories are one `caf dev` run from being in exactly the state the
table calls a defect, and a list cannot tell you about a repository nobody has
visited. My derivation finds 10 defective repositories; the table found 5.

Verified against the real fleet, and the check's own output names all ten:

```
14 of 16 repository(ies) have a cafaye.yml and were checked for caf.dev.compose.yaml;
2 have none, cannot produce the file, and were counted rather than dropped
  - cafaye-rb: ... not ignored ...
  - cafaye-ts: ... not ignored ...
  - core: ... is TRACKED ...
  - core: ... not ignored ...
  - courier: ... not ignored ...
  - darkroom: ... not ignored ...
  - docs: ... not ignored ...
  - guard: ... not ignored ...
  - identity: ... not ignored ...
  - muse: ... not ignored ...
  - pantry: ... not ignored ...
FAIL generated-stack: 11 problem(s) across the fleet.   (exit 1)
```

### The `cafaye.yml` cross-check the brief asked for

- **Every repo with a generated file also has the manifest that generates it.**
  No repo has the file without the manifest. Clean.
- **But the reverse is false and that is the finding:** 6 repos with a manifest
  have no generated file, and 5 of those 6 have no ignore entry either. Absence
  of the file is *not* evidence of safety — it is evidence nobody ran the command.
- `cafaye-py` and `kit` have no `cafaye.yml` and cannot produce the file. Correctly
  untouched, and the check counts them rather than dropping them.

---

## 2. How I proved `caf dev` really does produce the file everywhere

The brief forbade running `caf dev`, so I did not. Instead the claim rests on two
measurements that do not require it:

1. **The write is unconditional.** `caf/internal/cli/dev.go:186` calls
   `writeCompose`; the `len(stack.Services) == 0` early return is at **`:194`**,
   eight lines later. So a manifest that declares no services still gets a file.
   This is why `caf`, `docs` and the libraries are in scope and not just the six
   repos with a stack.
2. **Every manifest in the fleet loads.** `go run ./cmd/caf contract lint` on each
   one: `exit=0` for `cafaye-rb`, `cafaye-ts`, `docs`, `guard`, `muse`, `caf`,
   `parlor`, `site`, `courier`, `darkroom`, `identity`, `pantry`, `billing`. (`core`
   exits 1, but on a *fixture* manifest under `harness/tests/fixtures/` — its own
   `cafaye.yml` reports `OK`.)

So "has a valid `cafaye.yml`" is not a guess about which files might appear. It is
the same predicate `caf dev` itself uses: `dev.Load` returns `ErrNoManifest` when
there is no `cafaye.yml` at the root
(`caf/internal/dev/project.go:26`).

---

## 3. `core`: the tracked file, and what referenced it

The brief asked me to read the file and check for references before untracking.
Both answers, stated:

**What it was.** Five lines: the generated header, `name: core-dev`, and nothing
else — `core` declares no services, so the stack is empty. Its own first three
lines say it is build output.

**Did anything reference it?** **No.**

```
$ git -C core grep -n 'caf\.dev\.compose'      → exit 1, no matches
$ grep -rn 'caf\.dev' core/.github/            → no matches
$ grep -rn 'caf\.dev' core/tests core/harness core/bin → no matches
$ grep -rIn 'caf\.dev\.compose' --exclude-dir=.git core/ → only the file's own bytes
```

No script, no test, no workflow, no document has ever named that path in `core`.
So untracking it breaks no reference and leaves no stale pointer behind. The
brief asked for that finding either way; "nothing referenced it" is the finding,
and it is the reason this change is one commit rather than two.

**How it got in.** `git show --stat 8007d07` lists `caf.dev.compose.yaml | 5 +++++`
beside a real 13-line change to `tests/test_specs.py`, in a commit titled "core:
record kit-32's second non-database image reference in the fleet scan". Nobody
decided to track it. That is precisely what `billing/.gitignore` predicts in prose.

---

## 4. Before / after, per repository

The two questions the guard asks, measured directly in each worktree. "Tracked?" is
`git ls-files --error-unmatch`, and the rule column is the actual line `git
check-ignore -v` reports — so this is the rule that fires, not an intention.

| repo | `check-ignore` fires on | tracked? | before | after |
|---|---|---|---|---|
| `courier` | `.gitignore:64:/caf.dev.compose.yaml` | no | not ignored | **ignored** |
| `darkroom` | `.gitignore:19:/caf.dev.compose.yaml` | no | not ignored | **ignored** |
| `identity` | `.gitignore:30:/caf.dev.compose.yaml` | no | not ignored | **ignored** |
| `pantry` | `.gitignore:18:/caf.dev.compose.yaml` | no | not ignored | **ignored** |
| `core` | `.gitignore:30:/caf.dev.compose.yaml` | no | **TRACKED** + not ignored | **ignored, untracked** |

`core` keeps its file on disk (`git rm --cached`, not `git rm`), and `git status`
is clean with it present — which is the point.

Already compliant, verified and untouched: `billing`, `caf`, `parlor`, `site`.
`docker-compose.yml` is tracked and still tracked in `courier`, `darkroom` and
`identity`; I asserted this per worktree rather than trusting the diff.

---

## 5. The guard: a considered yes, and where it lives

**A guard belongs.** The brief asked me to say so or say why not. It belongs
because the derived population proved the list is not a fix: I found the same
defect in five repositories the list did not contain, and I found them by asking
the filesystem rather than by looking harder at a list.

**It is `kit/tests/generated_stack_check.py`, wired into `tests/validate.sh`,
and it is `kit` rather than `core` or `caf` for a reason worth stating:** `core`
documents in `fleet.yml` that it "cannot read a sibling repository", and `caf` is
a single-repo CLI whose tests run in its own tree. `kit` already owns the
cross-repo gate (`fleet_check.py`, D4: "a defect in the standard is invisible to a
gate that reads only the standard"), already owns the `FLEET-ABSENT:` skip marker,
and already has a stated carve-out for programs in `tests/`.

**Why not folded into `fleet_check.py`**, which is the first question a reviewer
will ask. Two reasons, both enforced where they live:

- **Scope.** `fleet_check.py` checks repos that *declare local infrastructure* —
  a root compose file or collector config. `core`, `docs`, `guard`, `muse` and
  `cafaye-ts` have manifests and no stack. Folding this in would have scoped the
  check that matters most to the predicate that **excludes it**.
- **Severity.** Every finding there goes through the adoption ceiling: a WARN
  until a repo commits `kit.ref`, a FAIL after. That ceiling is about *who owns a
  debt*. This defect has no adopter — a repo that has never heard of kit's stack
  still must not commit its generated one, and no adoption wave makes that
  acceptable.

**Scope is derived, not listed:** a root `cafaye.yml`, read off the filesystem —
the same predicate `caf dev` uses. `is_worktree` excludes worktrees, matching
`fleet_check.py` and `staleness.py`, so three callers enumerate the fleet one way.

### Proofs, each a planted divergence

| what | result |
|---|---|
| green control: 3 conforming fixture repos | **exit 0** |
| not-ignored: delete the ignore line from a conforming fixture | **exit 1**, naming that repo |
| tracked: `git add -f` over an existing ignore entry, then commit | **exit 1**, `TRACKED` finding alone |
| then `git rm --cached` | **green** |
| reverse: generated file with no manifest | **exit 1** |
| real fleet, fixes not merged | **exit 1, 11 findings / 10 repos** |
| gate section in `validate.sh --static-only` | `FAIL generated stack` — correct, fixes unmerged |
| `carve-out boundary` check with the new program listed | **PASS**, 3 programs, 10 stdlib imports |

### Two bugs I found in my own check, by running it

Both are recorded in the code beside the fix, because both are the failure modes
this repository already has names for.

1. **My `is_worktree` used `git rev-parse --is-inside-work-tree`, which is `true`
   for every checkout** — a clone is inside a work tree too. So all 15 repos were
   classified as worktrees, `discover()` returned `[]`, and the gate printed
   `FLEET-ABSENT:` and exited 0. Not a crash, not a red: a gate that examined
   nothing and said so, on the one machine where all five defective repos still
   had the defect. It would have shipped behind a test that only asserted a green
   run. Fixed to read the shape of `.git`, which is what the other two fleet
   checks do.
2. **The TRACKED branch also emitted a false "add it to `.gitignore`" finding.**
   Measured, not remembered: in a repo whose `.gitignore` carries the entry *and*
   whose index carries the file, `git check-ignore -q` exits **1** — git does not
   apply ignore rules to a path it already tracks. So the two independent
   questions produced two findings, the second asking for something the repository
   already did. On the finding that names `core`'s actual state, that is how a gate
   teaches people to skim it. TRACKED is now reported alone and carries the
   suppressed fact: the entry is necessary and *not* sufficient.

   Building that fixture also taught me something the packet's `core` case hides:
   you cannot reproduce `core`'s state with `git add -A`, because the ignore entry
   does its job. It takes `git add -f`. So `core`'s file was not swept in by a
   plain `add` of an unprotected tree — it was added deliberately, or by a path
   that bypasses the rules. That is why `8007d07` shows it arriving beside a real
   change: nobody was thinking about it either way.

---

## 6. What I did not do, and why

- **I did not fix the five repositories the table missed** (`cafaye-rb`,
  `cafaye-ts`, `docs`, `guard`, `muse`). The brief's item 1 names four repos, and
  the brief also says not to silently expand scope. Five more `.gitignore` commits
  is a manager's call, not a worker's. **The finding is in §1, the guard is live and
  will name all five by name, and the five one-line commits are mechanical** —
  `git check-ignore` on each already tells you the entry is absent.
- **No `self_test.sh` breakage recipe for the new check.** kit's convention is that
  a check is proved red through the harness. I proved it by direct measurement in
  both directions instead (§5) and named that in the commit message. This is the
  real gap in the kit commit and the first thing I would do next.
- **I did not run kit's full gate.** `--static-only` was run and scoped; the
  `self_test` phase alone is *n* whole gates in sequence and this repository's own
  AGENTS.md records it hitting a 90-minute bound. Reporting a bound as a pass is
  the silent skip that file forbids, so I ran what I could bound and named it.
- **No `caf dev`, no docker, no generated file.** Every command was `timeout`-bounded.

## 7. Two process notes for the manager

- **I wrote into another live worktree and put it back.** My first attempt at the
  guard landed in `wt-m39-kit-guard-wrapper-scope-01`, which belongs to
  `worker/kit-guard-wrapper-tier-scope-01` — a different packet, a different
  session. The only thing I added was one untracked file. I removed it, verified
  `git status --porcelain` in that worktree is **empty** and its branch unchanged,
  and moved to my own `wt-m39-kit-fleet-generated-compose-01`. Nothing of theirs
  was modified, staged or committed, and I did not touch it again. Flagging it
  because the directory name was in the listing I read at the start and it reads
  like one of mine.
- **`core`'s own `gate.yml` floor is not affected** by untracking one YAML file —
  `git rm --cached` changes no test count and `bin/prime`'s proof is a test-count
  floor. I did not run `bin/prime` (it needs a migrated Postgres, which is outside
  this packet's budget), so I am not claiming it green; I am claiming nothing in
  `core` reads the file, which is measured above.