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
// with the first. The result satisfies users.ValidateEmail.
func UniqueEmail(t *testing.T) string {
	t.Helper()

	var noise [6]byte
	if _, err := rand.Read(noise[:]); err != nil {
		t.Fatalf("generating a unique test email: %v", err)
	}

	// The local part has to survive the users.email_format rules, so anything
	// that is not a lowercase letter or digit becomes a dash.
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

	return fmt.Sprintf("%s-%s@example.com", strings.Trim(label, "-"), hex.EncodeToString(noise[:]))
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

	if _, err := pool.Exec(ctx, `TRUNCATE TABLE outbox_events, sessions, users CASCADE`); err != nil {
		t.Fatalf("truncating: %v", err)
	}
}
