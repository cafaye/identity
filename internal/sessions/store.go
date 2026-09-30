package sessions

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
)

// errNoRows is pgx's "the query matched nothing", aliased so the intent reads
// at the call site. A caller that has to distinguish this from other errors is a
// caller that will get it wrong eventually.
var errNoRows = pgx.ErrNoRows

// ErrNotFound means no live session matches. It covers four situations that must
// be indistinguishable to the caller: no such token, a revoked token, an expired
// token, and a token belonging to a deleted user. One error, one status code, one
// response time.
var ErrNotFound = errors.New("session not found")

// Session is a row in the sessions table.
type Session struct {
	ID        id.UUID
	UserID    id.UUID
	ExpiresAt time.Time
	// UserAgent and IP record what presented the token. They are evidence for an
	// incident, not identity: nothing in this service trusts either of them, and
	// both are absent for a plain API client.
	UserAgent string
	IP        *netip.Addr
	CreatedAt time.Time
}

// NewSession is the input to Store.Create.
//
// TokenDigest, not Token. The store is given the hash and has no way to produce
// the token, so the raw credential cannot be written by accident from here.
type NewSession struct {
	UserID      id.UUID
	TokenDigest string
	ExpiresAt   time.Time
	UserAgent   string
	IP          *netip.Addr
}

// Store is the sessions table.
type Store struct {
	pool db.Pool
}

// NewStore returns a Store backed by pool.
func NewStore(pool db.Pool) *Store { return &Store{pool: pool} }

const sessionColumns = `id, user_id, expires_at, user_agent, ip, created_at`

// Create inserts a session and returns the stored row.
func (s *Store) Create(ctx context.Context, q db.Querier, n NewSession) (Session, error) {
	const query = `
		INSERT INTO sessions (user_id, token_digest, expires_at, user_agent, ip)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING ` + sessionColumns

	var out Session
	if err := scanSession(q.QueryRow(ctx, query, n.UserID, n.TokenDigest, n.ExpiresAt, nullString(n.UserAgent), n.IP), &out); err != nil {
		return Session{}, fmt.Errorf("inserting a session: %w", err)
	}

	return out, nil
}

// ByToken resolves a presented token to a live session.
//
// now comes from the caller rather than from the database's clock() on purpose:
// the service reads time through an injected Clock, and a row that expires
// mid-request has to be judged against the same instant the response is
// timestamped with. See internal/platform/clock.
//
// The expiry comparison happens in the WHERE clause, not after the row is read,
// so an expired session is never returned even to be discarded by the caller.
func (s *Store) ByToken(ctx context.Context, q db.Querier, token string, now time.Time) (Session, error) {
	const query = `
		SELECT ` + sessionColumns + `
		FROM sessions
		WHERE token_digest = $1 AND expires_at > $2`

	var out Session
	err := scanSession(q.QueryRow(ctx, query, Digest(token), now), &out)
	if errors.Is(err, errNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, fmt.Errorf("looking up a session: %w", err)
	}

	return out, nil
}

// Revoke deletes a session. Revoking a session that is already gone succeeds: a
// client retrying a logout should not get an error for having retried it.
func (s *Store) Revoke(ctx context.Context, q db.Querier, sessionID id.UUID) error {
	const query = `DELETE FROM sessions WHERE id = $1`

	if _, err := q.Exec(ctx, query, sessionID); err != nil {
		return fmt.Errorf("deleting a session: %w", err)
	}
	return nil
}

// nullString turns an empty user agent into SQL NULL. An empty string and "not
// recorded" are the same answer here, and NULL is the one that says so.
func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// scanSession reads one session row.
//
// user_agent is nullable and is scanned through a pointer: pgx refuses to put a
// NULL into a string, and the alternative — making the column NOT NULL and
// storing ” — would assert that "the client sent no user agent" and "we never
// learned one" are the same fact. A request through a proxy that strips the
// header is genuinely the second, and the domain's zero value already renders
// both as "nothing to show".
func scanSession(row pgx.Row, out *Session) error {
	var userAgent *string

	if err := row.Scan(&out.ID, &out.UserID, &out.ExpiresAt, &userAgent, &out.IP, &out.CreatedAt); err != nil {
		return err
	}
	if userAgent != nil {
		out.UserAgent = *userAgent
	}

	return nil
}
