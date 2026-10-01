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
const userColumns = `id, email, password_digest, failed_login_attempts, locked_until, ` +
	`email_verified_at, created_at, updated_at`

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
		&u.ID, &u.Email, &u.PasswordDigest, &u.FailedLoginAttempts, &u.LockedUntil,
		&u.EmailVerifiedAt, &u.CreatedAt, &u.UpdatedAt,
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

// SetPassword replaces the credential and clears the lockout, in one statement.
//
// THE LOCKOUT GOES WITH IT, and that is the decision rather than an oversight. A
// password reset is proved by a link delivered to the account's mailbox, which is
// strictly stronger evidence than the password that a run of failures was guessing
// at — so leaving a user who has just recovered their account locked out for the
// remainder of the window would punish them for somebody else's attempts, and the
// account would be unreachable for up to LockoutDuration after the very request
// that was supposed to get them back in.
//
// It takes the digest and never the password, for the reason NewSession does: the
// store has no way to hash and therefore no way to be handed the plaintext.
func (s *Store) SetPassword(ctx context.Context, q db.Querier, userID id.UUID, digest string) error {
	const query = `
		UPDATE users
		SET password_digest = $2, failed_login_attempts = 0, locked_until = NULL, updated_at = now()
		WHERE id = $1`

	tag, err := q.Exec(ctx, query, userID, digest)
	if err != nil {
		return fmt.Errorf("setting a new password: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetEmail moves the address and CLEARS THE VERIFICATION, in one statement.
//
// The clearing is the half that matters and it is why this is a method rather than
// a raw UPDATE the caller writes. `email_verified_at` is a claim about the address
// on THIS row; a row whose address has just changed while still carrying a
// verification timestamp would be asserting that somebody proved they can read an
// address they have never been sent anything at — which is precisely the claim the
// column exists to make impossible, and precisely how an account takeover becomes a
// matter of pointing your email at somebody else's inbox.
//
// A unique violation is ErrEmailTaken, for the same reason and the same index
// Create's is: 23505 on this table can only mean the address is registered.
func (s *Store) SetEmail(ctx context.Context, q db.Querier, userID id.UUID, email string) error {
	const query = `
		UPDATE users
		SET email = $2, email_verified_at = NULL, updated_at = now()
		WHERE id = $1`

	tag, err := q.Exec(ctx, query, userID, email)
	if err != nil {
		if isEmailTaken(err) {
			return ErrEmailTaken
		}
		return fmt.Errorf("setting a new email: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkEmailVerified records that somebody proved they can read the address on
// this row.
//
// IT IS CONDITIONAL ON THE COLUMN STILL BEING NULL, so it is idempotent by
// construction rather than by a caller remembering to check: redeeming two live
// verification links for the same address updates one row and leaves the other
// token to expire unused, and the instant recorded is the FIRST proof rather than
// the most recent one. Overwriting it would make "when did this address get
// verified" answer a question that moves every time somebody clicks a second
// link. Zero rows updated is therefore a SUCCESS, not an error.
//
// The user id is deliberately NOT the only thing in the WHERE clause, and the
// caller is deliberately not in it at all: proving you can read an inbox is not a
// thing a session authorizes. The verification token names the row, and a WHERE
// that also had to match a presented user would turn a correct token presented by
// the wrong party into a silent no-op rather than a refusal.
func (s *Store) MarkEmailVerified(ctx context.Context, q db.Querier, userID id.UUID, at time.Time) (bool, error) {
	const query = `
		UPDATE users
		SET email_verified_at = $2, updated_at = now()
		WHERE id = $1 AND email_verified_at IS NULL`

	tag, err := q.Exec(ctx, query, userID, at)
	if err != nil {
		return false, fmt.Errorf("marking an email verified: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// scanOne turns "no rows" into ErrNotFound. pgx reports it as pgx.ErrNoRows, and
// a caller that has to know that is a caller that will get it wrong.
func scanOne(row interface{ Scan(...any) error }) (User, error) {
	var u User

	err := row.Scan(&u.ID, &u.Email, &u.PasswordDigest, &u.FailedLoginAttempts, &u.LockedUntil,
		&u.EmailVerifiedAt, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("scanning a user: %w", err)
	}

	return u, nil
}

// isEmailTaken reports whether err is a unique violation raised by the email
// index.
//
// It matches on the SQLSTATE alone, and that is load-bearing rather than lazy: the
// users table has exactly one unique index, on email, so 23505 can only mean the
// address is taken. Matching the constraint *name* instead would be more precise
// in principle and is in practice brittle — Postgres renames an index when a table
// is cloned with LIKE ... INCLUDING INDEXES, which is exactly what the integration
// tests do, and a future migration could rename it legitimately. A silently
// mis-detected duplicate turns a 409 into a 500.
//
// TestUsersHasExactlyOneUniqueIndex fails if a second unique index is ever added,
// which is the point at which this has to become precise.
func isEmailTaken(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == uniqueViolation
}
