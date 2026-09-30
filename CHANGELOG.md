# Changelog

All notable changes to identity are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

## [0.1.0] - 2026-09-30

The v0 scaffold (packet identity-01). Structure before features: the shape every
later identity packet builds on, with no auth logic in it.

### Added

- `internal/config` — environment-driven configuration read once at startup and
  never mutated: `PORT` (default 8080, 1-65535), `DATABASE_URL` (optional in v0),
  `LOG_LEVEL` (default info, mapped to `log/slog`). A variable that is present but
  invalid fails startup with a wrapped sentinel rather than falling back to a
  default. Covered by table-driven tests for the defaults and the overrides.
- `internal/httpapi` — the chi router with `GET /healthz` → `200
  {"status":"ok"}` always, and `GET /readyz` → `200` when every dependency
  answers, `503 {"status":"unavailable",...}` otherwise, with each probe bounded
  at 2s. With no `DATABASE_URL` readiness reports `{"status":"ok","deps":"none"}`.
  Unknown routes and wrong methods answer JSON 404/405 rather than chi's plain
  text. Probe failures are logged by dependency name and never returned to the
  caller; a panicking dependency is a failed probe, not a dead process.
- `internal/platform/db` — a lazy pgx pool constructor that parses and sizes the
  pool without dialling, so a database that is down at startup surfaces as a
  failing readiness probe instead of a crash loop. `Ping` is wired to readiness
  only when `DATABASE_URL` is set.
- `cmd/identity` — a thin entrypoint: load config, build the app, serve, drain
  in-flight requests for up to 15s on SIGTERM, then close the pool. The socket,
  the drain and the signal handling live in an `app` type the tests drive
  directly, including a child-process test that sends a real SIGTERM and requires
  a clean exit.
- `migrations/` — the goose convention: `NNNNN_snake_case.sql`, annotations
  required, a `Down` (or a comment saying why not), one logical change per file,
  and a README covering dev and prod. `00001_init.sql` creates nothing.
- `Dockerfile` — two stages, `CGO_ENABLED=0`, `gcr.io/distroless/static-debian12:nonroot`.
  No compiler and no shell in the shipped image.
- `docker-compose.yml` — `postgres:17-alpine` plus the service, with the service
  gated on a `pg_isready` healthcheck so pgx never races Postgres in its init phase.
- `bin/prime` (the kit Go gate: `go mod download && go build ./... && go test
  ./...`), `mise.toml` pinning Go 1.26, and `.gitignore`.
- `cafaye.yml` as a clearly marked manifest draft, with guessed fields flagged
  `# GUESS` for reconciliation once core freezes the schema.
- `AGENTS.md` — the conventions this repository follows.

### Notes

- No auth logic, no JWT or OIDC code, no user tables. Those are later packets and
  none of it is stubbed to look finished.
- The only dependencies are `chi` (routing) and `pgx` (Postgres); reasoning in
  the README.
- `go test ./...` is green with no database and no Docker. The two Postgres
  integration tests skip unless `TEST_DATABASE_URL` is set.
