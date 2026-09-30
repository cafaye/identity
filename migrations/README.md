# Migrations

Schema for `identity`, as goose SQL files. One migration per file, named
`NNNNN_snake_case_description.sql`, applied in filename order.

`goose` is **not** a module dependency of this repository — it is a command line
tool, installed separately, so nothing in `go.sum` moves when it changes. No
migration has been written yet: `00001_init.sql` is the convention marker.

## The convention

Every migration file carries goose's annotations. `-- +goose Up` and
`-- +goose Down` delimit the two directions, and statements that goose's parser
would misread are wrapped in `StatementBegin`/`StatementEnd`:

```sql
-- +goose Up
CREATE TABLE accounts (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE accounts;

-- +goose StatementBegin
CREATE INDEX CONCURRENTLY accounts_name_idx ON accounts (name);
-- +goose StatementEnd
```

`CREATE INDEX CONCURRENTLY`, `DO $$ ... $$` and any statement containing a
semicolon inside a string or dollar-quoted body **must** be wrapped in
`StatementBegin`/`StatementEnd`, or goose will split it into fragments and
execute half of it.

Rules that matter for review:

- **`Down` is required.** If a migration cannot be reversed, say why in a
  comment next to an empty `Down` rather than omitting the section. A file with
  no `Down` cannot be rolled back and will block an incident.
- **No edits to an applied migration.** The table records version, timestamp
  and a checksum. Changing a file that has already run somewhere makes goose
  refuse to apply anything after it. Write a new migration instead.
- **One logical change per file.** Never bundle "add users" with "add
  accounts", even in a packet where they are obviously related. They roll back
  separately or not at all.
- **No data backfill in a migration that also changes schema.** A backfill that
  touches every row locks the table. Schema first, backfill as a separate
  migration with a batched `UPDATE`.

## Running migrations

`DATABASE_URL` must be exported. In dev that is the compose service; in prod it
comes from the same secret the service reads.

```sh
goose -dir migrations postgres "$DATABASE_URL" status    # what has been applied
goose -dir migrations postgres "$DATABASE_URL" up        # apply everything pending
goose -dir migrations postgres "$DATABASE_URL" up-by-one  # one at a time, for prod
goose -dir migrations postgres "$DATABASE_URL" down      # roll back the last one
goose -dir migrations postgres "$DATABASE_URL" create add_accounts
```

The `create` subcommand scaffolds a correctly named and annotated file; edit the
statements into the body. It numbers itself from the highest existing file.

Install it with `mise` (see the root `mise.toml`) or
`go install github.com/pressly/goose/v3/cmd/goose@latest`.

## Dev

The compose stack in `docker-compose.yml` starts `postgres:17-alpine` and
waits for it to report healthy, so the database is accepting connections before
the service comes up:

```sh
docker compose up -d postgres
docker compose exec postgres pg_isready -U identity
goose -dir migrations postgres "$DATABASE_URL" up
TEST_DATABASE_URL="$DATABASE_URL" go test ./...   # runs the integration tests
```

`docker-compose.yml` publishes Postgres on host port 5432. If something already
listens there — a local Postgres install is the common case — the compose port
bind fails, or a host-side DSN silently reaches the *other* server and fails with
`role "identity" does not exist`. Either way the fix is the same: point
`DATABASE_URL` and `TEST_DATABASE_URL` at the port the compose stack actually
got, not at the one you assumed.

`TEST_DATABASE_URL` is what gates the two tests that need a real server
(`TestOpenAndPingIntegration`, `TestOpenAppliesConfiguredPoolSize`). Without it
those tests skip and the suite stays green on a bare runner.

## Prod

Migrations are a **deploy step, not a service step**. The service never migrates
itself on boot: a rolling deploy with two versions live would race, and a failed
migration would take the process down with it.

1. Run `goose ... up-by-one` as a single ordered job before the new image rolls
   out. Add each migration to a later release than the code that first needs it,
   so the currently-deployed version still works against the old and the new
   schema. Expand the contract, backfill, then contract in a subsequent release.
2. Fail the deploy on a non-zero exit. A migration that half-applied is worse
   than one that did not run, and goose stops at the first failure.
3. Take a backup first. A `Down` that is exercised in an incident is a first
   resort, not a plan.
4. Watch lock waits. An `ACCESS EXCLUSIVE` lock taken by a long-running `ALTER`
   blocks every query behind it, and the service's readiness probe will not save
   you: it only knows whether it can connect.

## Where the schema is going

Not written yet, and not in this packet. `identity` in Phase 1 grows accounts
and memberships, then OIDC, MFA and API tokens. Each of those arrives as its
own numbered migration with the tests that prove it (PLAN.md §3).
