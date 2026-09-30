# identity

`identity` is the cafaye service that knows who someone is: auth, sessions,
MFA, OAuth, accounts and tenancy, and OIDC. Every other cafaye service — billing,
courier, guard, parlor — asks this one who is calling and what they may do. It
is the platform's security boundary, and the reason `PLAN.md` §3 singles it out
for a user-run security review before the phase closes.

**v0 is a skeleton.** There is no auth logic here yet, on purpose: the
scaffolding *is* this packet's deliverable. What exists is the shape every later
packet builds on — configuration, liveness and readiness, a Postgres pool, the
migration convention, and an image. What it does today:

```
$ curl -s localhost:8080/healthz
{"status":"ok"}

$ curl -s localhost:8080/readyz
{"status":"ok","deps":"none"}
```

## Why chi

Chi over echo: same five routing features, a fraction of the dependencies, and
`net/http` is the type it serves, so a handler is a plain
`func(http.ResponseWriter, *http.Request)` with no framework types in the
signature. It is a router, not a framework — nothing in `internal/` needs to
know chi exists to be tested.

## Running it

Nothing but Go is needed, and no database is required — v0 supports an unset
`DATABASE_URL`:

```sh
mise install          # or use any Go >= 1.25
go run ./cmd/identity # http://localhost:8080
```

Or the gate, which is what CI runs:

```sh
bin/prime   # go mod download && go build ./... && go test ./...
```

With the database:

```sh
docker compose up -d
curl -s localhost:8080/readyz    # {"status":"ok","deps":"postgres"}
```

## Configuration

Read from the environment at startup, validated, and never mutated afterwards.
A value that is present but invalid fails startup rather than falling back to a
default, so a typo in a deployment is a crash with a message instead of a
service quietly listening on the wrong port.

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8080` | TCP port to bind. Must be 1-65535. |
| `DATABASE_URL` | *(unset)* | Postgres DSN. Optional in v0; unset means no pool and no readiness dependency. |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. Drives `log/slog`. |

## Endpoints

| Route | Response | Meaning |
|---|---|---|
| `GET /healthz` | `200 {"status":"ok"}` | Liveness. Always 200 while the process serves — it never touches a dependency, so a database outage cannot get the process restarted out from under in-flight work. |
| `GET /readyz` | `200 {"status":"ok","deps":"postgres"}` | Readiness. 200 when every dependency answers, `503 {"status":"unavailable",...}` otherwise, with each probe bounded at 2s. |
| anything else | `404 {"status":"not_found"}` | JSON, not chi's default plain text. |

With no `DATABASE_URL`, readiness is `200 {"status":"ok","deps":"none"}` — there
is nothing to check, and saying so is more useful to an operator than an empty
list or a 200 that looks identical to a healthy probe.

Probe failures are logged with the underlying error and **never** returned to the
caller: an unauthenticated request to `/readyz` must not be a way to learn that
a database host is `10.0.0.5` or that a password was rejected.

## Layout

```
cmd/identity/main.go   thin entrypoint: load config, build the app, serve, drain on SIGTERM
internal/config/       environment in, validated Config out
internal/httpapi/      the router and the two probe handlers
internal/platform/db/  the pgx pool, and the readiness ping
migrations/            goose SQL files (convention established, no schema yet)
```

`cmd/` + `internal/` is the layout from `refs/goreleaser`. `main` owns nothing
but process lifetime: everything testable lives in `internal/`, and the pieces
`main` does own — the socket, the drain, the signal handling — are in an `app`
type that the tests drive directly.

## Testing

`go test ./...` passes on a machine with no database and no Docker. The two
tests that need a real server skip themselves unless `TEST_DATABASE_URL` is set:

```sh
docker compose up -d postgres
TEST_DATABASE_URL="postgres://identity:identity@localhost:5432/identity?sslmode=disable" go test ./...
```

SIGTERM handling is not asserted through a mock: `TestMainHandlesSIGTERM` runs
the real `main()` in a child process, waits for it to report that it is serving,
sends the signal, and requires a clean exit. There are no `time.Sleep` calls in
this repository — every wait is on a channel the code under test signals, or on
a failure deadline (PLAN.md §3).

## Migrations

goose SQL files in `migrations/`, numbered and annotated. `goose` is a CLI
tool, not a module dependency. `00001_init.sql` establishes the convention and
creates nothing. Migrations are a deploy step, not a boot step — see
[migrations/README.md](migrations/README.md).

## Image

Multi-stage, `CGO_ENABLED=0`, `gcr.io/distroless/static-debian12:nonroot`. No
compiler and no shell in the shipped image:

```sh
docker build -t identity .
docker run --rm -p 8080:8080 identity
```

## Not built yet

Everything below is a later packet, and none of it is stubbed to look finished:
sessions and password auth, email verification, OAuth, accounts/roles/invites,
OIDC, MFA, API tokens, the admin API, and the generated authz matrix suite. No
users table, no JWT code, no OIDC provider.

## Roadmap

- [x] Skeleton: config, `/healthz`, `/readyz`, pgx pool, graceful shutdown
- [x] Migration convention, image, compose stack
- [ ] Password auth, sessions, lockout
- [ ] Email verification, password reset
- [ ] OAuth via goth
- [ ] Accounts, memberships, roles, invitations
- [ ] OIDC provider
- [ ] MFA: TOTP + recovery codes
- [ ] Scoped API tokens
- [ ] Admin API
- [ ] Authorization matrix suite (route table × role × anonymous)

See [AGENTS.md](AGENTS.md) for the conventions this repository follows and
[CHANGELOG.md](CHANGELOG.md) for what has landed.
