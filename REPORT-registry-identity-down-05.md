# REPORT — registry-identity-down-05

**Repository:** identity · **Branch:** `worker/registry-identity-down-05` ·
**Base:** `caf6254` · **Worktree:** `wt-reg-identity-down-05`

## The short version

The packet asked for a gate tier that applies every `-- +goose Down` section in
identity. Delivering it turned up something bigger and something smaller:

1. **`goose up` cannot succeed on this repository's own CI.** Migration `00016`
   needs a LOGIN role named `identity_app`; `docker compose up` creates it and
   the workflow never did. The job has been unbuildable since `e323247`.
2. **All seventeen Down sections are correct.** The brief's lead — that `00016`
   and `00017` create standalone functions their Downs forget — was wrong, and
   the brief said it was a lead rather than a conclusion. Running it was the
   only way to find out; `00016`'s Down names all eight functions, and `00017`'s
   restores the definition `00016` installed, which is what a reversal to a
   green boot is supposed to be.
3. **Three of the harness's own checks were vacuous**, and finding that took
   more mutations than the real defects did.

## Finding 1 — CI cannot apply the migrations

`migrations/00016_account_isolation.sql` ends its Up with

```sql
select cafaye.protect_table('account_users');
```

`protect_table`'s second argument defaults to `current_user || '_app'` and its
first act is to refuse if that role is not a LOGIN role:

```
if not exists (select 1 from pg_roles where rolname = login_role and rolcanlogin) then
  raise exception 'cafaye.protect_table(%, %): % is not a LOGIN role on this cluster.'
```

`docker compose up` provides it. kit's cluster init reads
`KIT_POSTGRES_DATABASES: identity` and provisions `<service>_app` beside each
`<service>`, and `docker-compose.yml` inherits that. `.github/workflows/ci.yml`
runs a bare `postgres:17-alpine` **service container** — no init script, no
`KIT_POSTGRES_DATABASES` — so the only role on that cluster is `POSTGRES_USER`.

**Measured, not predicted.** I built a cluster the way this job builds one
(superuser `identity`, no `_app` role, plain database) and applied the
migrations:

```
ERROR:  cafaye.protect_table(account_users, identity_app):
        identity_app is not a LOGIN role on this cluster. (SQLSTATE 42704)
```

That is `goose up` failing at migration 16 of 17, in the step named *apply the
migrations*, on every run since `e323247` landed.

**Why nobody noticed.** On a laptop the migration takes the production path. The
one job nobody runs by hand is the job that could not build.

**The fix, and what it is not.** A step before `goose up` that provisions
`identity_app`. It is deliberately **not** a migration: a migration that created
roles would need `CREATEROLE`, would recreate a role an operator dropped on
purpose, and would leave a role no `goose down` could remove. That decision is
now a test (`TestNoMigrationCreatesAClusterRole`) rather than a comment, because
the alternative is available and looks harmless.

## Finding 2 — the Down sections

`bin/rollback` builds a throwaway database, then for each migration: applies Up,
censors the schema, applies Down, censors it, asserts the second census equals
the one before that Up, and applies Up again. Functions are compared by
`oid::regprocedure` so overloads stay distinct; the census covers tables, views,
materialized views, sequences, types, functions, triggers, policies, indexes and
columns, in every schema except the system's.

```
$ IDENTITY_ROLLBACK_URL=… ./bin/rollback
rollback: 17 migrations, one Down at a time, against postgres://…
rollback: 17 migrations, each rolled back and re-applied with zero leftovers
```

The brief's suspected defect was not present. What *was* present is below.

## Finding 3 — three harness defects that reported a clean tree

This is the part worth a reviewer's attention, because all three are ways a
rollback check can be green and wrong.

**The census was scoped to schema `cafaye`.** `00016` is the only migration that
says `create schema`, and it says it for its eight substrate functions. The
eighteen tables, their indexes and their twenty policies are created by
unqualified `CREATE TABLE account_users`, which lands in `public`. So the first
draft counted 8 functions and **nothing else** — against a fully migrated
database holding 18 tables, 52 indexes and 20 policies. Widened to every schema
but `pg_catalog`/`information_schema`/`pg_toast`/`pg_temp_*`.

**`00016`'s Down ended in `drop schema cafaye cascade`, and the cascade was
hiding the first defect.** A policy is a *dependent* object, not a member: each
of the twenty policies names `cafaye.current_account_id()` in its expression, so
`pg_depend` records the dependency and `cascade` takes the policy with the
function. Deleting one of the twenty explicit `drop policy` statements left the
database correct and the harness green. The cascade is removed, the eight
functions are named and dropped in dependency order (callers first, the two
`current_*` readers last), and the schema goes last and bare:

```
ERROR:  cannot drop schema cafaye because other objects depend on it
DETAIL:  policy account_audit_log_cafaye_delete on table account_audit_log depends on schema cafaye
```

which is the outcome a rollback wants — a forgotten statement now stops the
rollback and names itself.

**The census tracked no columns.** `alter table sessions drop column user_agent;`
appended to `00017`'s Down, where `sessions` and `user_agent` belong to `00003`:
before and after censuses byte-identical, all seventeen reported clean. A column
is not a `pg_class` row. Columns are in the census now, with `attnum > 0 and not
attisdropped` so an emptied column and a removed one stay different histories.

## Mutations

Sixteen, each reverted from a file backup rather than `git checkout` — see the
mechanism note below. Ten against the Go checks, six against the harness.

| # | mutation | caught by | verdict |
|---|---|---|---|
| M1 | delete the provisioning step | `TestTheLoginRole…IsProvisionedBeforeTheyAreApplied` | red, names the role |
| M2 | move provisioning *after* `goose up` | same | red, names both line numbers |
| M3 | build the role name from `${POSTGRES_USER}` | `TestTheProvisionedRoleIsCreatedFromTheJob…` | red |
| M4 | drop `IDENTITY_ROLLBACK_REQUIRED=1` | `TestTheRollbackRunsInCIAndCannotExitZero…` | red, prints the block |
| M5 | delete the rollback step | same | red |
| M6 | delete a migration's Down marker | `TestEveryMigrationCarriesADownMarker` | red |
| M7 | hardcode `APP_ROLE="identity_app"` in the script | `TestTheRollbackScriptNamesTheRole…` | red |
| M8 | drop the `rolcanlogin` half of the role probe | same | red |
| M9 | put `create role` in a migration | `TestNoMigrationCreatesAClusterRole` | red, quotes the line |
| H1 | 00016's Down forgets one policy (cascade removed) | `bin/rollback` | red — `cannot drop schema cafaye` |
| H2 | …the same, with `cascade` restored | `bin/rollback` | **SURVIVED** → Finding 3 |
| H3b | 00002 loses its Down marker entirely | `bin/rollback` | red, names the file |
| H4b | 00002's Down errors after dropping its table | `bin/rollback` | red |
| H5 | 00016's Down forgets one index | `bin/rollback` | red, diff prints `> index api_keys_cafaye_token_digest_idx` |
| H6 | census narrowed to `cafaye`, then forget an index | `bin/rollback` | **SURVIVED** → Finding 3 |
| H7 | columns removed from the census, then drop a column | `bin/rollback` | **SURVIVED** → Finding 3 |

**Two attempts to make the re-apply step go red, both of which survived, and
one of which I mis-constructed first.** The re-apply (apply Up N again after Down
N) is the "rollback, then redeploy the same version" property. H4c dropped a
column in `00002`'s Down *before* the table, so the Down succeeded, the census
matched (columns were not tracked then), and the re-apply succeeded too —
because `00002`'s Up recreates the table whole. On this tree I could not
construct a defect the re-apply catches and the census does not: everything the
census sees, the census reports first. **The step is retained as cheap
insurance and is recorded here as not independently shown red**, rather than
claimed as proven.

**M2 is the one I would point a reviewer at.** "The role exists" and "the role
exists *before the migrations run*" are different properties, and a check that
asks only the first passes on the ordering being wrong.

## Gate

```
TEST_DATABASE_URL=… ./bin/prime          exit 0
go test ./internal/platform/ci/ -count=1  ok
IDENTITY_ROLLBACK_URL=… ./bin/rollback    17 migrations, zero leftovers
```

**The floor moved in this commit**, 2020 → 2299, measured from a complete run of
`go test -v -count=1 ./...` with the database tier applied: **2292 on this
branch's base, 2301 with the packet applied, and only +7 of that is this
packet's** — the other two lines come from
`TestCouriersTypesAgreeWithCouriersDocument`, which reads
`../../courier/openapi.yaml` beside the checkout and *reports rather than skips*
when it is absent, so the base had to be measured from a worktree with a
sibling `courier/` present or the number is not comparable. The floor is the
base plus seven, not 2301, because a floor set from a measurement the runner
cannot reproduce installs a red on a green tree — the one outcome
`.github/workflows/ci.yml`'s own header says to avoid. `DATABASE_TIER_FLOOR`
stays 1732: `internal/platform/ci` opens no pool, so it is not in the tier, which
I confirmed by running the derivation's own comment-stripping `awk` over the
package.

## Notes for whoever picks up the next packet

- **A pre-existing red, fixed here.** `TestTheOtherSixSubstrateFunctionsAreKitsBytes`
  was failing on `caf6254` — `protect_table`'s body had drifted from kit's copy
  (the interleaved kit packets' doing). Kit's bytes are re-synced into
  `00016` in place, with a RE-SYNCED comment after the Up marker. This was not
  this packet's assignment; it blocked a green gate, so it went in the same
  commit rather than being reported and left.

- **MUSE AND DARKROOM STILL HAVE NO DOWN SECTIONS.** The brief's table: muse has
  2 migrations, darkroom 3, and none of the five carries a `-- +goose Down`
  marker. `TestEveryMigrationCarriesADownMarker` covers *identity* only. The
  honest next step is a written decision — either they get Down sections or they
  declare themselves forward-only — rather than porting a harness that will fail
  on their first run for a reason nobody chose.

- **Two mistakes worth naming**, because the second is a trap:
  - The first draft of `bin/rollback` created a fresh superuser `identity` as
    its fixture. On a cluster where `identity` already exists and *owns the
    service database*, the pre-clean's `drop role` fails (a role cannot be
    dropped while it owns anything), the create then fails, and the harness
    refuses to run — on the very cluster it was written for. It now connects as
    the caller and creates only `<caller>_app`.
  - My mutation driver reverted with `git checkout --`, which silently discarded
    my own **uncommitted** `ci.yml` edits and made three later "mutations" prove
    nothing (they were all measuring an already-broken file). Reverted from file
    backups afterwards. Same class of error as the cwd-reset incident recorded in
    the site packet: a revert tool used carelessly on a dirty tree is a
    destructive operation wearing a cleanup tool's clothes.

- **Environment.** A scratch PostgreSQL on port 55470 was used for every
  measurement here and is torn down at the end of the packet. It is not kit's
  cluster and nothing in the fleet depends on it.