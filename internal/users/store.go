package users

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
)

// Postgres SQLSTATE 23505, unique_violation. The store maps exactly this, and
// only for the email index, onto ErrEmailTaken. Any other unique violation is
// left as-is: a 23505 on some future index is a different problem and deserves
// to be visible as one.
const uniqueViolation = "23505"

// CreateParams is everything a new user needs. It carries an already-normalized
// email and an already-hashed digest: this package does not decide what a valid
// address is or how to hash a password, and the store does not try to help.
type CreateParams struct {
	Email          string
	PasswordDigest string
}

// Store is the users table.
type Store struct {
	pool db.Pool
}

// NewStore returns a Store backed by pool.
func NewStore(pool db.Pool) *Store { return &Store{pool: pool} }

// userColumns is the select list, in the order scan expects. One constant, so a
// column added here cannot be forgotten in one query and present in another.
const userColumns = `id, email, password_digest, failed_login_attempts, locked_until, created_at, updated_at`

// Create inserts a user and returns the stored row.
//
// q is a db.Querier, not the pool, so the caller decides the transaction
// boundary: registering a user also writes an outbox event, and those two writes
// are one transaction or neither. See internal/outbox.
func (s *Store) Create(ctx context.Context, q db.Querier, p CreateParams) (User, error) {
	const query = `
		INSERT INTO users (email, password_digest)
		VALUES ($1, $2)
		RETURNING ` + userColumns

	var u User
	err := q.QueryRow(ctx, query, p.Email, p.PasswordDigest).Scan(
		&u.ID, &u.Email, &u.PasswordDigest, &u.FailedLoginAttempts, &u.LockedUntil, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if isEmailTaken(err) {
			return User{}, ErrEmailTaken
		}
		return User{}, fmt.Errorf("inserting a user: %w", err)
	}

	return u, nil
}

// ByEmail looks a user up by address. The email must already be normalized; the
// store does not normalize on read, because a lookup that silently repairs its
// argument hides the bug in whatever wrote the row.
func (s *Store) ByEmail(ctx context.Context, q db.Querier, email string) (User, error) {
	const query = `SELECT ` + userColumns + ` FROM users WHERE email = $1`

	return scanOne(q.QueryRow(ctx, query, email))
}

// ByID looks a user up by primary key. The zero id is rejected before the query
// runs: it is not a value any row can have, and a lookup that treated it as a
// wildcard would hand out an arbitrary account.
func (s *Store) ByID(ctx context.Context, q db.Querier, want id.UUID) (User, error) {
	if want.IsZero() {
		return User{}, ErrNotFound
	}

	const query = `SELECT ` + userColumns + ` FROM users WHERE id = $1`

	return scanOne(q.QueryRow(ctx, query, want))
}

// RecordFailedLogin persists the state a wrong password produced: the current
// consecutive-failure count, and the lock expiry when the policy decided on one.
//
// lockedUntil is a pointer so "the fifth failure, not yet locked" writes SQL NULL
// rather than a zero timestamp. The two are not the same value.
func (s *Store) RecordFailedLogin(ctx context.Context, q db.Querier, userID id.UUID, attempts int, lockedUntil *time.Time) error {
	const query = `
		UPDATE users
		SET failed_login_attempts = $2, locked_until = $3, updated_at = now()
		WHERE id = $1`

	tag, err := q.Exec(ctx, query, userID, attempts, lockedUntil)
	if err != nil {
		return fmt.Errorf("recording a failed login: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ClearFailures resets the consecutive-failure run and lifts any lock. A
// successful login is the only thing that calls it: the run has to restart from
// zero, or each sign-in makes the next lockout one attempt sooner.
func (s *Store) ClearFailures(ctx context.Context, q db.Querier, userID id.UUID) error {
	const query = `
		UPDATE users
		SET failed_login_attempts = 0, locked_until = NULL, updated_at = now()
		WHERE id = $1`

	tag, err := q.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("clearing login failures: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// scanOne turns "no rows" into ErrNotFound. pgx reports it as pgx.ErrNoRows, and
// a caller that has to know that is a caller that will get it wrong.
func scanOne(row interface{ Scan(...any) error }) (User, error) {
	var u User

	err := row.Scan(&u.ID, &u.Email, &u.PasswordDigest, &u.FailedLoginAttempts, &u.LockedUntil, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("scanning a user: %w", err)
	}

	return u, nil
}

// isEmailTaken reports whether err is the unique violation on users_email_key.
//
// The constraint name is checked as well as the code so that a unique violation
// raised by some other index is not misreported as a duplicate address.
func isEmailTaken(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == uniqueViolation && pgErr.ConstraintName == "users_email_key"
}
