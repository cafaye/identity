// Package dbtest gives integration tests a real Postgres.
//
// It is a normal package rather than a _test.go file so that every package's
// tests can share it. Nothing imports it outside tests, so it contributes
// nothing to the service binary — `go list -deps ./cmd/identity` does not reach
// it.
//
// # Isolation
//
// `go test ./...` runs packages in parallel, and every package in this service
// shares one TEST_DATABASE_URL. So the tests here must not assume they have the
// database to themselves, and there is deliberately no TRUNCATE helper called
// from ordinary tests: a global truncate from internal/users would delete
// internal/sessions' fixtures mid-run, and the failure looks like a
// non-deterministic bug in the code under test rather than in the harness.
//
// Each test instead claims a unique email address, which makes it independent of
// every other test in every other package. Reset is available for a deliberate
// wipe and is not called automatically.
package dbtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cafaye/identity/internal/platform/db"
)

// EnvVar names the environment variable that points at a throwaway database.
const EnvVar = "TEST_DATABASE_URL"

// Pool returns a pool against TEST_DATABASE_URL, skipping the test when the
// variable is unset. The schema must already be applied — migrations are a deploy
// step, not a test step — so run `goose -dir migrations postgres "$DATABASE_URL"
// up` first, as migrations/README.md describes.
func Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	dsn := os.Getenv(EnvVar)
	if dsn == "" {
		t.Skipf("%s is not set; skipping the integration test", EnvVar)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := db.Open(ctx, dsn, db.DefaultOptions())
	if err != nil {
		t.Fatalf("opening a pool against %s: %v", EnvVar, err)
	}
	t.Cleanup(pool.Close)

	// A pool is lazy, so Open succeeding says nothing about the server being
	// there. Ping here, where the failure can name the variable that is wrong,
	// rather than inside an assertion about a users row.
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("%s is set but not reachable (%v). Is the server up, and are the "+
			"migrations applied? `goose -dir migrations postgres \"$DATABASE_URL\" up`", EnvVar, err)
	}

	return pool
}

// UniqueEmail returns an address no other test, in any package, in any run, will
// use.
//
// It is built from the test's name so a failing test is greppable in the table,
// plus random bytes so a second run against the same database does not collide
// with the first. The result satisfies users.ValidateEmail — including the RFC
// 5321 limit of 64 characters on the local part, which a long test name will
// otherwise blow through.
func UniqueEmail(t *testing.T) string {
	t.Helper()

	var noise [6]byte
	if _, err := rand.Read(noise[:]); err != nil {
		t.Fatalf("generating a unique test email: %v", err)
	}

	// The local part has to survive the users.email rules, so anything that is not
	// a lowercase letter or digit becomes a dash.
	label := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return '-'
		}
	}, t.Name())
	label = strings.Trim(label, "-")

	// 64 is the local-part ceiling; 12 is the hex noise; one is the separator.
	if len(label) > 64-12-1 {
		label = label[:64-12-1]
		label = strings.TrimRight(label, "-")
	}

	return fmt.Sprintf("%s-%s@example.com", label, hex.EncodeToString(noise[:]))
}

// Reset truncates every table this service owns.
//
// It is deliberately not used by ordinary tests — see the package comment. Call
// it from a single test, or run it by hand, when you want to inspect the
// database or reproduce a failure from an empty state. Calling it from two tests
// at once, or from a test running beside another package's tests, will delete
// their rows.
func Reset(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := pool.Exec(ctx, `TRUNCATE TABLE outbox_events, sessions, account_invitations, account_users, accounts, users CASCADE`); err != nil {
		t.Fatalf("truncating: %v", err)
	}
}

// Schema returns a pool whose search_path is a private schema containing a fresh
// copy of the three tables. Nothing any other test does can be seen by, or
// interfere with, a test using this pool.
//
// It exists for the tests that need an *empty* database rather than a private
// corner of a shared one — the outbox claim tests, which assert on which rows a
// SELECT returns, cannot do that while a backlog from another package is in the
// table. A unique email gives isolation for row *identity*; it cannot give
// isolation for a query's result set.
//
// The tables are cloned with LIKE ... INCLUDING ALL, which copies columns,
// defaults, CHECK constraints and indexes from whatever the migrations currently
// define — so a schema change is picked up with no edit here. Two things LIKE does
// not copy, both declared explicitly below: foreign keys (they would point at the
// original tables) and enum types (Postgres has no LIKE for a type). Re-read the
// migrations when adding a table, a constraint or an enum value; this list has to
// stay in step with them.
func Schema(t *testing.T) *pgxpool.Pool {
	t.Helper()

	base := dsn(t)

	var noise [6]byte
	if _, err := rand.Read(noise[:]); err != nil {
		t.Fatalf("generating a schema name: %v", err)
	}
	schema := "test_" + hex.EncodeToString(noise[:])

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	admin, err := db.Open(ctx, base, db.DefaultOptions())
	if err != nil {
		t.Fatalf("opening an admin pool against %s: %v", EnvVar, err)
	}
	// Registered first so that it runs *last*: cleanups are LIFO, and the DROP
	// SCHEMA below still needs this pool to be open.
	t.Cleanup(admin.Close)
	if err := admin.Ping(ctx); err != nil {
		t.Fatalf("%s is set but not reachable (%v). Is the server up, and are the migrations applied?", EnvVar, err)
	}

	stmts := []string{
		`CREATE SCHEMA ` + schema,
		`CREATE TABLE ` + schema + `.users (LIKE public.users INCLUDING ALL)`,
		`CREATE TABLE ` + schema + `.sessions (LIKE public.sessions INCLUDING ALL)`,
		`CREATE TABLE ` + schema + `.outbox_events (LIKE public.outbox_events INCLUDING ALL)`,
		`CREATE TABLE ` + schema + `.accounts (LIKE public.accounts INCLUDING ALL)`,
		`CREATE TABLE ` + schema + `.account_users (LIKE public.account_users INCLUDING ALL)`,
		`CREATE TABLE ` + schema + `.account_invitations (LIKE public.account_invitations INCLUDING ALL)`,
		// Postgres has no LIKE for a type, so the two enums are declared here
		// rather than cloned. That is a second copy of the migrations' enum
		// labels: re-read 00005 and 00007 when either changes, and note that
		// adding a role to public does NOT add it here — a test would then fail
		// on an enum value the database accepts and the private schema does not.
		`CREATE TYPE ` + schema + `.account_role AS ENUM ('owner', 'admin', 'member')`,
		`CREATE TYPE ` + schema + `.account_invitation_role AS ENUM ('admin', 'member')`,
		`ALTER TABLE ` + schema + `.sessions ADD CONSTRAINT sessions_user_id_fkey
			FOREIGN KEY (user_id) REFERENCES ` + schema + `.users (id) ON DELETE CASCADE`,
		`ALTER TABLE ` + schema + `.account_users ADD CONSTRAINT account_users_account_id_fkey
			FOREIGN KEY (account_id) REFERENCES ` + schema + `.accounts (id) ON DELETE CASCADE`,
		`ALTER TABLE ` + schema + `.account_users ADD CONSTRAINT account_users_user_id_fkey
			FOREIGN KEY (user_id) REFERENCES ` + schema + `.users (id) ON DELETE CASCADE`,
		`ALTER TABLE ` + schema + `.account_invitations ADD CONSTRAINT account_invitations_account_id_fkey
			FOREIGN KEY (account_id) REFERENCES ` + schema + `.accounts (id) ON DELETE CASCADE`,
		`ALTER TABLE ` + schema + `.account_invitations ADD CONSTRAINT account_invitations_invited_by_fkey
			FOREIGN KEY (invited_by) REFERENCES ` + schema + `.users (id) ON DELETE RESTRICT`,
		// The enums are schema-local, so the clones below would otherwise resolve
		// their role columns against public.account_role and account_invitation_role.
		// Two casts, and the private schema is genuinely private.
		`ALTER TABLE ` + schema + `.account_users ALTER COLUMN role TYPE ` + schema + `.account_role
			USING role::text::` + schema + `.account_role`,
		`ALTER TABLE ` + schema + `.account_invitations ALTER COLUMN role TYPE ` + schema + `.account_invitation_role
			USING role::text::` + schema + `.account_invitation_role`,
	}
	for _, stmt := range stmts {
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Fatalf("preparing the %s schema: %v\n%s", schema, err, stmt)
		}
	}
	t.Cleanup(func() {
		dropCtx, dropCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer dropCancel()
		if _, err := admin.Exec(dropCtx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE`); err != nil {
			t.Logf("dropping the %s schema: %v", schema, err)
		}
	})

	// search_path is a plain GUC, so pgx passes it as a connection runtime
	// parameter. Every unqualified name in the test's SQL then resolves inside the
	// private schema.
	pool, err := db.Open(ctx, withSearchPath(base, schema), db.DefaultOptions())
	if err != nil {
		t.Fatalf("opening a pool scoped to %s: %v", schema, err)
	}
	t.Cleanup(pool.Close)

	return pool
}

// dsn returns the configured DSN, skipping the test when it is unset.
func dsn(t *testing.T) string {
	t.Helper()

	value := os.Getenv(EnvVar)
	if value == "" {
		t.Skipf("%s is not set; skipping the integration test", EnvVar)
	}
	return value
}

// withSearchPath appends search_path to the DSN, preserving whatever query
// parameters it already carries.
func withSearchPath(dsnValue, schema string) string {
	parsed, err := url.Parse(dsnValue)
	if err != nil {
		// Pool already validated this DSN, so a parse failure here would be a
		// bug in this helper rather than bad configuration.
		panic("dbtest: parsing " + EnvVar + ": " + err.Error())
	}

	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()

	return parsed.String()
}
