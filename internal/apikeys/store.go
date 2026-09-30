package apikeys

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/cafaye/identity/internal/accounts"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
)

// Postgres SQLSTATE 23505, unique_violation.
const uniqueViolation = "23505"

// errNoRows is pgx's "the query matched nothing", aliased so the intent reads at
// the call site.
var errNoRows = pgx.ErrNoRows

// Errors this store returns beyond the package-level ErrNotFound. They are
// distinct values so the code says what happened, and the HTTP layer renders two
// of them differently for a reason that is written where it is rendered.
var (
	// ErrNameTaken means this account already has a LIVE token with that name.
	//
	// It is a 409 and not a 422, and the difference is the point: the request is
	// perfectly well formed and the state it asks for collides with one that
	// exists. The index that raises it is partial on revoked_at IS NULL, so a
	// REVOKED token of the same name does not collide — which is what makes
	// "revoke the old one, mint the new one" two requests rather than a
	// transaction that has to find a name free first.
	//
	// The case it exists for is operational rather than adversarial: an operator
	// revoking "ci-deploy" when two live tokens answer to that name is picking one
	// at random, and picking the wrong one leaves a credential live that somebody
	// believes they have just destroyed.
	ErrNameTaken = errors.New("an active api key with that name already exists in this account")

	// ErrAlreadyRevoked means the token exists and has already been withdrawn.
	//
	// Distinct from ErrNotFound so an operator who clicks twice is told so. A
	// 204 either way would leave them believing a second credential had just been
	// destroyed, which is the belief that ends up written in an incident timeline
	// as "we turned the old one off" when only one of two was.
	ErrAlreadyRevoked = errors.New("api key is already revoked")
)

// Key is a row in the api_keys table.
//
// TokenDigest is here because the row holds it, and it is the ONLY part of a
// credential on this struct. There is no Token field, and adding one would be the
// bug this package exists to prevent: the plaintext lives once, in a 201 body,
// and there is no column and no field that could hold it later.
//
// Role is NOT one of the row's columns. It is the caller's LIVE membership role,
// read by the resolution query's join, and it is a field here so the route can
// compare it against the route's minimum without a second query. A token does
// not hold a role; a user holds a role and the token names the user.
type Key struct {
	ID          id.UUID
	UserID      id.UUID
	AccountID   id.UUID
	Name        string
	TokenDigest string
	Scopes      []string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	// LastUsedAt is nil until the token has been used. A pointer because "never
	// used" and "used at the epoch" are different answers, and the first is the
	// one an operator wants to notice.
	LastUsedAt *time.Time
	// RevokedAt, RevokedBy and RevokeReason are set together or not at all, and
	// the table's CHECK says so. RevokeReason is a pointer because the empty
	// string is a legitimate reason ("rotated") and NULL means "none given".
	RevokedAt    *time.Time
	RevokedBy    *id.UUID
	RevokeReason *string

	// Role is the owner of this token's CURRENT role in its account, or "" when
	// the row was read by something that does not join account_users — the
	// settings page, which shows a credential whether or not its owner is still
	// a member.
	//
	// It is a field rather than a separate return value because it belongs to the
	// ANSWER to "who is calling", and a caller that resolved a token has both
	// halves in one struct with no way to forget one.
	Role accounts.Role
}

// IsRevoked reports whether the token has been withdrawn.
func (k Key) IsRevoked() bool { return k.RevokedAt != nil }

// IsExpired reports whether the token is past its deadline at now.
//
// The boundary is `now >= expires_at`: a token whose expiry is exactly now is
// spent, and the resolution query agrees. Two implementations of one boundary is
// how a token stays usable for a second longer than the response that used it
// said it would.
func (k Key) IsExpired(now time.Time) bool { return !k.ExpiresAt.After(now) }

// Allows reports whether the token carries scope.
func (k Key) Allows(scope string) bool { return HasScope(k.Scopes, scope) }

// NewKey is the input to Store.Create.
//
// It carries the DIGEST and never the token, for the reason sessions.NewSession
// does: the store has no way to produce the token, so the raw credential cannot
// be written by accident from here. There is no field for it.
type NewKey struct {
	UserID    id.UUID
	AccountID id.UUID
	Name      string
	Digest    string
	Scopes    []string
	// CreatedAt and ExpiresAt are passed rather than read from the clock, so the
	// row and the event announcing it agree and only one of the two is under
	// test control.
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Store is the api_keys table.
//
// Every method takes a db.Querier rather than the pool, so the caller chooses the
// transaction boundary: minting a token writes a row and an event, and those two
// are one fact or neither — which is what internal/outbox exists for.
type Store struct {
	pool db.Pool
}

// NewStore returns a Store backed by pool.
func NewStore(pool db.Pool) *Store { return &Store{pool: pool} }

// keyColumns is the select list, in the order scanKey expects. One constant, so
// a column added here cannot be forgotten in one query and present in another.
const keyColumns = `id, user_id, account_id, name, token_digest, scopes, created_at, expires_at, ` +
	`last_used_at, revoked_at, revoked_by, revoke_reason`

// Create inserts a token and returns the stored row.
//
// It does not check that the owner is a member of the account, and the omission
// is deliberate with the direction it fails in. The use case above it resolves
// the caller's role before it gets here, so a caller who is not a member never
// reaches this; and a row that somehow names an account its owner is not in — a
// direct write, a future migration — does not WORK, because the resolution query
// joins account_users and returns nothing. TestANonMemberTokenIsNotAnAccountToken
// writes exactly that row and asserts it is dead.
func (s *Store) Create(ctx context.Context, q db.Querier, n NewKey) (Key, error) {
	const query = `
		INSERT INTO api_keys (user_id, account_id, name, token_digest, scopes, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING ` + keyColumns

	out, err := scanKey(q.QueryRow(ctx, query,
		n.UserID, n.AccountID, n.Name, n.Digest, n.Scopes, n.CreatedAt, n.ExpiresAt))
	if err != nil {
		if isUniqueViolation(err) {
			// The only unique constraint a CALLER can collide with is the partial
			// index on (account_id, lower(name)) WHERE revoked_at IS NULL. The
			// digest's index is a 256-bit collision on a value this package
			// generated, which is a bug and not a request — the same reasoning
			// internal/oidc's CreateClient uses for its own secret column.
			return Key{}, ErrNameTaken
		}
		return Key{}, fmt.Errorf("apikeys: creating a token: %w", err)
	}
	return out, nil
}

// ByDigest resolves a presented value to a LIVE token, together with the role its
// owner holds in the token's account RIGHT NOW.
//
// THE JOIN IS THE WHOLE PACKET. account_users is inner-joined, so a token whose
// owner has been removed from the account does not come back — and because the
// same query reads the role, a demotion is visible to the token on the very next
// request, with no cache, no sweep and nothing to invalidate.
//
// That is the answer to "a token outlives the permission that made it". A token
// is a CREDENTIAL that names a user; it is not a permission. The authority it
// carries is whatever that user's live membership says it is, re-read every time.
// The alternative — snapshotting the role onto the token at creation — would make
// removing a contractor require an inventory of the credentials they minted, and
// an inventory nobody keeps is not a control.
//
// FOUR FILTERS IN ONE STATEMENT, and they are four rather than one because a
// caller must not be able to tell them apart:
//
//	revoked_at IS NULL   withdrawn
//	expires_at > now     spent
//	the join             no longer a member
//	(and the digest miss) never existed
//
// All four produce ErrNotFound: one status code, one response body, one database
// round trip. Splitting them — fetching the row and checking the revocation
// afterwards — would answer with one query plan for a revoked token and another
// for an unknown one, which is an oracle for exactly the question an attacker
// asks after "does this work".
//
// now is the caller's instant rather than the database's clock(), for the reason
// sessions.Store.ByToken takes one: the service reads time through an injected
// Clock, and a token that expires mid-request has to be judged against the same
// instant the response is timestamped with.
func (s *Store) ByDigest(ctx context.Context, q db.Querier, digest string, now time.Time) (Key, error) {
	// An empty digest never reaches the database. It is not a security boundary —
	// an empty string hashes to a well-formed digest like any other value, which
	// is the timing story — it is that the query has one shape and no caller
	// should be able to change it.
	if digest == "" {
		return Key{}, ErrNotFound
	}

	// A var rather than a const, and the reason is prefixed(): it is a function,
	// and the point of calling it is that a column added to keyColumns cannot be
	// forgotten in the aliased query. A constant cannot call a function.
	var query = `
		SELECT ` + prefixed("k", keyColumns) + `, au.role
		FROM api_keys k
		JOIN account_users au ON au.account_id = k.account_id AND au.user_id = k.user_id
		WHERE k.token_digest = $1
		  AND k.revoked_at IS NULL
		  AND k.expires_at > $2`

	var (
		out  Key
		role string
	)
	err := q.QueryRow(ctx, query, digest, now).Scan(
		&out.ID, &out.UserID, &out.AccountID, &out.Name, &out.TokenDigest, &out.Scopes,
		&out.CreatedAt, &out.ExpiresAt, &out.LastUsedAt, &out.RevokedAt, &out.RevokedBy, &out.RevokeReason,
		&role,
	)
	if errors.Is(err, errNoRows) {
		return Key{}, ErrNotFound
	}
	if err != nil {
		return Key{}, fmt.Errorf("apikeys: resolving a token: %w", err)
	}

	out.Role = accounts.Role(role)
	return out, nil
}

// ByID loads a token by its row id, revoked or not.
//
// The opposite filter from ByDigest on purpose: this is the settings page's
// query, and "was this token revoked, or was it always broken?" is a support
// question a deleted row answers for nobody. It does NOT join account_users,
// because the point of this lookup is to show somebody a credential whose owner
// may no longer be a member.
func (s *Store) ByID(ctx context.Context, q db.Querier, rowID id.UUID) (Key, error) {
	if rowID.IsZero() {
		return Key{}, ErrNotFound
	}

	const query = `SELECT ` + keyColumns + ` FROM api_keys WHERE id = $1`

	out, err := scanKey(q.QueryRow(ctx, query, rowID))
	if errors.Is(err, errNoRows) {
		return Key{}, ErrNotFound
	}
	if err != nil {
		return Key{}, fmt.Errorf("apikeys: loading a token: %w", err)
	}
	return out, nil
}

// ListForAccount returns every token an account holds, newest first, revoked
// ones included.
//
// Revoked rows are INCLUDED on purpose — see ByID. The order is
// created_at DESC, id DESC so two tokens minted in the same transaction have a
// defined order rather than whatever the planner returns, and a list whose order
// wobbles between two identical requests is a list a client cannot paginate.
func (s *Store) ListForAccount(ctx context.Context, q db.Querier, accountID id.UUID) ([]Key, error) {
	out := make([]Key, 0, 4)
	if accountID.IsZero() {
		return out, nil
	}

	const query = `
		SELECT ` + keyColumns + `
		FROM api_keys
		WHERE account_id = $1
		ORDER BY created_at DESC, id DESC`

	rows, err := q.Query(ctx, query, accountID)
	if err != nil {
		return nil, fmt.Errorf("apikeys: listing an account's tokens: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		key, err := scanKey(rows)
		if err != nil {
			return nil, fmt.Errorf("apikeys: reading an account's tokens: %w", err)
		}
		out = append(out, key)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("apikeys: reading an account's tokens: %w", err)
	}
	return out, nil
}

// Revoke withdraws a token and returns the stored row.
//
// SCOPED BY account_id as well as id. The route has already established that the
// caller owns the account; the query says so again because a use case reached any
// other way would not have, and a cross-tenant revocation is exactly the bug a
// redundant WHERE clause costs nothing to prevent.
//
// CONDITIONAL ON revoked_at IS NULL, so a second attempt updates zero rows and
// comes back ErrAlreadyRevoked rather than moving the timestamp and overwriting
// who did it. When a credential was actually withdrawn is an incident question,
// and two operators clicking the same button at the same moment must produce one
// answer rather than a later one overwriting an earlier one.
func (s *Store) Revoke(ctx context.Context, q db.Querier, rowID, accountID, by id.UUID, at time.Time, reason string) (Key, error) {
	if rowID.IsZero() {
		return Key{}, ErrNotFound
	}

	const query = `
		UPDATE api_keys
		SET revoked_at = $3, revoked_by = $4, revoke_reason = NULLIF($5, '')
		WHERE id = $1 AND account_id = $2 AND revoked_at IS NULL
		RETURNING ` + keyColumns

	out, err := scanKey(q.QueryRow(ctx, query, rowID, accountID, at, by, reason))
	if errors.Is(err, errNoRows) {
		// Either the row is gone, it belongs to another account, or it was already
		// revoked — and the three are told apart by a second read rather than
		// guessed, for the reason internal/oidc's RevokeClient gives: an operator
		// with a stale id deserves "not found" and an operator who clicked twice
		// deserves "already revoked".
		existing, lookupErr := s.ByID(ctx, q, rowID)
		if errors.Is(lookupErr, ErrNotFound) {
			return Key{}, ErrNotFound
		}
		if lookupErr != nil {
			return Key{}, lookupErr
		}
		if existing.AccountID != accountID {
			return Key{}, ErrNotFound
		}
		return Key{}, ErrAlreadyRevoked
	}
	if err != nil {
		return Key{}, fmt.Errorf("apikeys: revoking a token: %w", err)
	}
	return out, nil
}

// RevokeAllForUser withdraws every token a user holds, in one statement.
//
// IT EXISTS FOR THE SAME EVENT THAT SESSIONS HAVE ONE FOR, and the argument is
// the one internal/sessions' RevokeAllForUser already makes. Enabling MFA revokes
// every session, because a session minted under a one-factor policy was minted
// on a password alone, and leaving it alive means the attacker holding it does
// not have to solve the new problem.
//
// AN API KEY IS THAT ARGUMENT'S STRONGER CASE, not its weaker one. A session
// lives a fortnight and lives in a cookie nobody inspects; a token lives a
// quarter, has a NAME on a settings page, and is exactly the credential an
// attacker with a stolen password would mint for themselves before the user
// noticed anything. A user who turns on a second factor to lock somebody out has,
// without this sweep, handed that somebody a credential they cannot see.
//
// A REVOCATION AND NOT A DELETE, unlike the session sweep, and the difference is
// the audit trail: the row is what this service's own support reads afterwards to
// answer "what did that account hold", and a delete answers it for nobody.
//
// Revoking zero tokens is a success. A user who has never minted one is already in
// the state this is called for.
func (s *Store) RevokeAllForUser(ctx context.Context, q db.Querier, userID id.UUID, at time.Time) error {
	if userID.IsZero() {
		return nil
	}

	const query = `
		UPDATE api_keys
		SET revoked_at = $2, revoked_by = $1, revoke_reason = 'security posture changed'
		WHERE user_id = $1 AND revoked_at IS NULL`

	if _, err := q.Exec(ctx, query, userID, at); err != nil {
		return fmt.Errorf("apikeys: revoking a user's tokens: %w", err)
	}
	return nil
}

// Touch records that a token was used, at most once per resolution window.
//
// THIS IS THE ONLY WRITE ON THE READ PATH, and the rate limit is why it exists
// rather than a nicety. A CI token at a thousand requests a second would
// otherwise put a thousand UPDATE round trips a second on ONE row, and a single
// row's lock is a queue — the credential's own owner would be the one queued out.
//
// The condition is in the WHERE rather than read first, so there is no
// read-modify-write and two concurrent requests both deciding to write is a
// non-event. Zero rows updated is a SUCCESS: the column says "some time in the
// last five minutes" and it already does.
//
// A REVOKED TOKEN IS NOT TOUCHED, and the condition says so, because
// `last_used_at` on a dead credential is a column asserting that it was working.
func (s *Store) Touch(ctx context.Context, q db.Querier, rowID id.UUID, at time.Time) error {
	if rowID.IsZero() {
		return nil
	}

	const query = `
		UPDATE api_keys
		SET last_used_at = $2
		WHERE id = $1
		  AND revoked_at IS NULL
		  AND (last_used_at IS NULL OR last_used_at < $3)`

	// No RowsAffected check, and the comment is the reason: zero rows is the rate
	// limit working, and reporting it would turn a busy token into a failing one.
	if _, err := q.Exec(ctx, query, rowID, at, at.Add(-LastUsedResolution)); err != nil {
		return fmt.Errorf("apikeys: recording a token's last use: %w", err)
	}
	return nil
}

// rowScanner is the narrow interface both pgx.Row and pgx.Rows satisfy, so one
// read serves the single-row and the list query.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanKey(row rowScanner) (Key, error) {
	var k Key
	err := row.Scan(&k.ID, &k.UserID, &k.AccountID, &k.Name, &k.TokenDigest, &k.Scopes,
		&k.CreatedAt, &k.ExpiresAt, &k.LastUsedAt, &k.RevokedAt, &k.RevokedBy, &k.RevokeReason)
	if err != nil {
		if errors.Is(err, errNoRows) {
			return Key{}, errNoRows
		}
		return Key{}, fmt.Errorf("apikeys: scanning a token: %w", err)
	}
	return k, nil
}

// prefixed qualifies a bare column list with a table alias, so the joined
// resolution query and the plain reads can share one column constant. It is the
// same helper internal/accounts/store.go has, restated because neither package
// imports the other and a shared one would be an edge between two tables that
// have nothing to say to each other.
func prefixed(alias, columns string) string {
	out := make([]byte, 0, len(columns)+len(alias)+8)
	start := 0
	for i := 0; i <= len(columns); i++ {
		if i == len(columns) || columns[i] == ',' {
			out = append(out, alias...)
			out = append(out, '.')
			out = append(out, columns[start:i]...)
			if i < len(columns) {
				out = append(out, ',')
			}
			start = i + 1
		}
	}
	return string(out)
}

// isUniqueViolation reports whether err is a unique_violation.
//
// It matches on the SQLSTATE alone, which is load-bearing rather than lazy: the
// only unique constraint on this table a caller can collide with is the partial
// index on (account_id, lower(name)) WHERE revoked_at IS NULL. Matching that
// index's NAME would be more precise in principle and is in practice brittle —
// Postgres renames an index when a table is cloned with LIKE ... INCLUDING
// INDEXES, which is exactly what the integration tests do — and a silently
// mis-detected duplicate turns a 409 into a 500.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == uniqueViolation
}
