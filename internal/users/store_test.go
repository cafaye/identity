package users

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
)

// These are integration tests: they need a real Postgres with the migrations
// applied. See dbtest.Pool for the gate and migrations/README.md for the setup.

func TestStoreCreateAndReadBack(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	ctx := context.Background()
	want := CreateParams{Email: dbtest.UniqueEmail(t), PasswordDigest: "$argon2id$fake"}

	created, err := store.Create(ctx, pool, want)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if created.ID.IsZero() {
		t.Error("Create returned a zero id")
	}
	// The address is stored normalized, not as it was typed. This is what makes
	// "Kaka@Example.com" and "kaka@example.com" one account rather than two.
	if created.Email != strings.ToLower(want.Email) {
		t.Errorf("Email = %q, want the normalized %q", created.Email, strings.ToLower(want.Email))
	}
	if created.PasswordDigest != want.PasswordDigest {
		t.Errorf("PasswordDigest = %q, want it stored verbatim", created.PasswordDigest)
	}
	if created.FailedLoginAttempts != 0 {
		t.Errorf("FailedLoginAttempts = %d, want 0", created.FailedLoginAttempts)
	}
	if created.LockedUntil != nil {
		t.Errorf("LockedUntil = %v, want nil", created.LockedUntil)
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Errorf("timestamps not set: created_at=%v updated_at=%v", created.CreatedAt, created.UpdatedAt)
	}

	byEmail, err := store.ByEmail(ctx, pool, NormalizeEmail(strings.ToUpper(want.Email)))
	if err != nil {
		t.Fatalf("ByEmail: %v", err)
	}
	if byEmail.ID != created.ID {
		t.Errorf("ByEmail returned id %s, want %s", byEmail.ID, created.ID)
	}

	byID, err := store.ByID(ctx, pool, created.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if byID.Email != created.Email {
		t.Errorf("ByID email = %q, want %q", byID.Email, created.Email)
	}
	if byID.PasswordDigest != created.PasswordDigest {
		t.Error("ByID lost the password digest")
	}
}

// A second registration of the same address must be refused by the database and
// surfaced as ErrEmailTaken, not as a raw pgx error. Registration is the one
// endpoint allowed to reveal this, and it does so as a 409.
func TestStoreCreateRejectsADuplicateEmail(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	ctx := context.Background()
	params := CreateParams{Email: dbtest.UniqueEmail(t), PasswordDigest: "$argon2id$first"}

	if _, err := store.Create(ctx, pool, params); err != nil {
		t.Fatalf("first Create: %v", err)
	}

	// The same normalized address again. This is the collision that matters: the
	// unique index is what makes one account per address true.
	//
	// Note what is *not* tested here: re-inserting the same address in a
	// different case. That cannot reach the unique index at all — the
	// users_email_is_normalized CHECK rejects it first, which is
	// TestStoreCreateRefusesAnUnnormalizedEmail's job. Case collapsing is proven
	// by TestStoreCreateAndReadBack, which stores a normalized address and finds
	// it again through an upper-cased lookup.
	params.PasswordDigest = "$argon2id$second"
	_, err := store.Create(ctx, pool, params)

	if !errors.Is(err, ErrEmailTaken) {
		t.Fatalf("second Create error = %v, want errors.Is(_, ErrEmailTaken)", err)
	}
}

func TestStoreLookupsMissCleanly(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	ctx := context.Background()

	if _, err := store.ByEmail(ctx, pool, "nobody@example.com"); !errors.Is(err, ErrNotFound) {
		t.Errorf("ByEmail on a missing row = %v, want errors.Is(_, ErrNotFound)", err)
	}

	if _, err := store.ByID(ctx, pool, id.MustNew()); !errors.Is(err, ErrNotFound) {
		t.Errorf("ByID on a missing row = %v, want errors.Is(_, ErrNotFound)", err)
	}
}

// A zero id must not match a row. A query that forgot its WHERE clause would
// otherwise return the first user in the table to anyone who passed the nil UUID.
func TestStoreByIDRejectsTheZeroID(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	if _, err := store.ByID(context.Background(), pool, id.UUID{}); !errors.Is(err, ErrNotFound) {
		t.Errorf("ByID with the zero id = %v, want errors.Is(_, ErrNotFound)", err)
	}
}

func TestStoreCreateRefusesAnUnnormalizedEmail(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	// The CHECK constraint is the last line of defence. CreateParams carrying an
	// unnormalized address is a caller bug, and the failure should be the
	// database's constraint violation, not a silently corrected row.
	_, err := store.Create(context.Background(), pool, CreateParams{
		Email:          "Kaka@Example.com",
		PasswordDigest: "$argon2id$fake",
	})
	if err == nil {
		t.Fatal("Create accepted an unnormalized email, want the users_email_is_normalized CHECK to reject it")
	}
}

func TestStoreRecordFailedLogin(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	ctx := context.Background()
	user, err := store.Create(ctx, pool, CreateParams{Email: dbtest.UniqueEmail(t), PasswordDigest: "$argon2id$fake"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	lockUntil := time.Date(2026, 9, 30, 12, 15, 0, 0, time.UTC)
	if err := store.RecordFailedLogin(ctx, pool, user.ID, 3, &lockUntil); err != nil {
		t.Fatalf("RecordFailedLogin: %v", err)
	}

	got, err := store.ByID(ctx, pool, user.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if got.FailedLoginAttempts != 3 {
		t.Errorf("FailedLoginAttempts = %d, want 3", got.FailedLoginAttempts)
	}
	if got.LockedUntil == nil || !got.LockedUntil.Equal(lockUntil) {
		t.Errorf("LockedUntil = %v, want %s", got.LockedUntil, lockUntil)
	}
}

// Clearing a null lock must store SQL NULL, not a zero timestamp. A zero
// timestamp is "locked until 1970", which reads as unlocked today and as locked
// for any clock set before it.
func TestStoreRecordFailedLoginStoresNullForAnUnlockedAccount(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	ctx := context.Background()
	user, err := store.Create(ctx, pool, CreateParams{Email: dbtest.UniqueEmail(t), PasswordDigest: "$argon2id$fake"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := store.RecordFailedLogin(ctx, pool, user.ID, 1, nil); err != nil {
		t.Fatalf("RecordFailedLogin: %v", err)
	}

	got, err := store.ByID(ctx, pool, user.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if got.LockedUntil != nil {
		t.Errorf("LockedUntil = %v, want nil", *got.LockedUntil)
	}
}

func TestStoreRecordFailedLoginRejectsANegativeCount(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	ctx := context.Background()
	user, err := store.Create(ctx, pool, CreateParams{Email: dbtest.UniqueEmail(t), PasswordDigest: "$argon2id$fake"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// The users_failed_login_attempts_non_negative CHECK is the backstop for a
	// bug that decrements the counter, which would otherwise quietly raise the
	// number of attempts needed to trigger a lockout.
	if err := store.RecordFailedLogin(ctx, pool, user.ID, -1, nil); err == nil {
		t.Error("RecordFailedLogin accepted a negative count, want the CHECK constraint to reject it")
	}
}

func TestStoreClearFailures(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	ctx := context.Background()
	user, err := store.Create(ctx, pool, CreateParams{Email: dbtest.UniqueEmail(t), PasswordDigest: "$argon2id$fake"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	lockUntil := time.Now().UTC().Add(time.Hour)
	if err := store.RecordFailedLogin(ctx, pool, user.ID, 5, &lockUntil); err != nil {
		t.Fatalf("RecordFailedLogin: %v", err)
	}

	if err := store.ClearFailures(ctx, pool, user.ID); err != nil {
		t.Fatalf("ClearFailures: %v", err)
	}

	got, err := store.ByID(ctx, pool, user.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	// A successful login has to reset the run, not just the lock: otherwise the
	// fifth failure is one attempt sooner every time the user signs in.
	if got.FailedLoginAttempts != 0 {
		t.Errorf("FailedLoginAttempts = %d, want 0 after a successful login", got.FailedLoginAttempts)
	}
	if got.LockedUntil != nil {
		t.Errorf("LockedUntil = %v, want nil after a successful login", *got.LockedUntil)
	}
	if !got.UpdatedAt.After(user.UpdatedAt) && !got.UpdatedAt.Equal(user.UpdatedAt) {
		t.Errorf("UpdatedAt = %s, want it moved to or past %s", got.UpdatedAt, user.UpdatedAt)
	}
}

func TestStoreCreateInsideATransactionRollsBackWithIt(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	email := dbtest.UniqueEmail(t)
	if _, err := store.Create(ctx, tx, CreateParams{Email: email, PasswordDigest: "$argon2id$fake"}); err != nil {
		t.Fatalf("Create inside the transaction: %v", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	// This is the property the Querier seam exists for: registering a user writes
	// two rows, and if the second one fails neither survives.
	if _, err := store.ByEmail(ctx, pool, email); !errors.Is(err, ErrNotFound) {
		t.Errorf("after Rollback the user is still readable: %v", err)
	}
}
