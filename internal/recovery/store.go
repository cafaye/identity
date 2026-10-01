package recovery

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
)

// errNoRows is pgx's "the query matched nothing", aliased so the intent reads at
// the call site — the same alias internal/sessions and internal/apikeys keep for
// the same reason.
var errNoRows = pgx.ErrNoRows

// Token is a row in the recovery_tokens table.
//
// TOKEN_DIGEST IS HERE BECAUSE THE ROW HOLDS IT, and it is the only part of a
// credential on this struct. There is no `Token` field, and adding one would be
// the bug this package exists to prevent: the plaintext exists once, inside the
// message that was mailed, and there is no column and no field that could hold it
// later.
//
// It is not argon2id, for the reason sessions.Digest gives and the reason is
// identical: 256 bits of crypto/rand has no structure to guess, so a memory-hard
// hash would cost tens of milliseconds on every redemption and make a search that
// cannot succeed any slower. The rule that matters on this column is the same one
// as on every other credential column here — the presented value is never stored,
// so a database dump is not a set of passwords waiting to be redeemed.
type Token struct {
	ID      id.UUID
	UserID  id.UUID
	Purpose Purpose
	Email   string
	// TargetEmail is the address an email change is moving to, and it is empty for
	// every other purpose. The schema says so with a CHECK.
	TargetEmail string
	// TargetMinted says whether the second token of an email change exists yet.
	// It is NOT the digest: the target token's digest is written and read inside
	// this package's own transaction and never travels, so there is no field that
	// could hold it after the fact.
	TargetMinted bool
	// TokenConsumedAt and TargetConsumedAt are the two halves of the single-use
	// property. Pointers, because "never confirmed" and "confirmed at the epoch"
	// are different answers and only the first is ever true.
	TokenConsumedAt  *time.Time
	TargetConsumedAt *time.Time
	CreatedAt        time.Time
	ExpiresAt        time.Time
}

// NewToken is the input to Store.Create.
//
// IT CARRIES THE DIGEST AND NEVER THE TOKEN, for the reason sessions.NewSession
// does: the store has no way to mint one, so the raw credential cannot be written
// by accident from here. There is no field for it.
type NewToken struct {
	UserID      id.UUID
	Purpose     Purpose
	Digest      string
	TargetEmail string
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// Store is the recovery_tokens table.
//
// Every method takes a db.Querier rather than the pool, so the caller chooses the
// transaction boundary: spending a token and writing the state it changes are one
// fact — a password that changed without the token being spent is a token that
// can be spent again.
type Store struct {
	pool db.Pool
}

// NewStore returns a Store backed by pool.
func NewStore(pool db.Pool) *Store { return &Store{pool: pool} }

// tokenColumns is the select list, in the order scanToken expects. One constant,
// so a column added here cannot be forgotten in one query and present in another.
const tokenColumns = `id, user_id, purpose, target_email, created_at, expires_at, ` +
	`token_consumed_at, target_consumed_at, (target_token_digest IS NOT NULL)`

// Create inserts a token and returns the stored row.
func (s *Store) Create(ctx context.Context, q db.Querier, n NewToken) (Token, error) {
	const query = `
		INSERT INTO recovery_tokens (user_id, purpose, token_digest, target_email, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING ` + tokenColumns

	out, err := scanToken(q.QueryRow(ctx, query,
		n.UserID, n.Purpose, n.Digest, nullString(n.TargetEmail), n.CreatedAt, n.ExpiresAt))
	if err != nil {
		return Token{}, fmt.Errorf("recovery: creating a %s token: %w", n.Purpose, err)
	}
	return out, nil
}

// Live resolves a presented value to a token that may still be spent.
//
// FOUR FILTERS IN ONE STATEMENT, and they are four rather than one because a
// caller must not be able to tell them apart:
//
//	purpose = $2            minted for a different flow
//	expires_at > $3         its window has closed
//	token_consumed_at NULL  it has been spent
//	(and the digest miss)   it never existed
//
// All four are ErrTokenNotFound: one status code, one body, one round trip.
// Splitting them — reading the row and checking the expiry afterwards — would give
// a caller one query plan for a spent token and another for an unknown one, which
// is an oracle for exactly the question an attacker asks after "does this work".
//
// now is the caller's instant rather than the database's clock(), for the reason
// sessions.Store.ByToken takes one: the service reads time through an injected
// Clock, and a token that expires mid-request has to be judged against the same
// instant the response is timestamped with.
func (s *Store) Live(ctx context.Context, q db.Querier, digest string, purpose Purpose, now time.Time) (Token, error) {
	// An empty digest never reaches the database. It is not a security boundary —
	// an empty string hashes to a well-formed digest like any other value, which is
	// the timing story — it is that the query has one shape and no caller can change
	// it.
	if digest == "" {
		return Token{}, ErrTokenNotFound
	}

	const query = `
		SELECT ` + tokenColumns + `
		FROM recovery_tokens
		WHERE token_digest = $1 AND purpose = $2 AND expires_at > $3 AND token_consumed_at IS NULL`

	out, err := scanToken(q.QueryRow(ctx, query, digest, purpose, now))
	if errors.Is(err, errNoRows) {
		return Token{}, ErrTokenNotFound
	}
	if err != nil {
		return Token{}, fmt.Errorf("recovery: resolving a %s token: %w", purpose, err)
	}
	return out, nil
}

// LiveTarget resolves a presented value against the SECOND digest of an email
// change: the confirmation the NEW address gave.
//
// IT IS A SEPARATE READ RATHER THAN A FLAG ON Live, and the reason is that the two
// lookups answer different questions with different keys. A reset token is found
// by `token_digest` and an email change's second token by `target_token_digest`,
// and a Live that took a "which digest" parameter would have let a caller ask
// about the first half while holding the second — which is the one thing the
// schema's `target_needs_a_confirmed_first_side` CHECK exists to make impossible.
//
// THE SAME FOUR FILTERS, for the same reason Live lists them: a caller must not be
// able to tell a spent token from an unknown one, and must not be able to confirm
// the new address before the old one has been confirmed by asking here. The
// `target_consumed_at IS NULL` filter is what makes the redemption single-use; the
// rest are ErrTokenNotFound along with it.
func (s *Store) LiveTarget(
	ctx context.Context, q db.Querier, digest string, purpose Purpose, now time.Time,
) (Token, error) {
	if digest == "" {
		return Token{}, ErrTokenNotFound
	}

	const query = `
		SELECT ` + tokenColumns + `
		FROM recovery_tokens
		WHERE target_token_digest = $1 AND purpose = $2 AND expires_at > $3
		  AND target_token_digest IS NOT NULL AND target_consumed_at IS NULL`

	out, err := scanToken(q.QueryRow(ctx, query, digest, purpose, now))
	if errors.Is(err, errNoRows) {
		return Token{}, ErrTokenNotFound
	}
	if err != nil {
		return Token{}, fmt.Errorf("recovery: resolving the new-address half of an email change: %w", err)
	}
	return out, nil
}

// NewestLive is the cooldown read: the most recent token of this purpose that is
// still redeemable, or ErrTokenNotFound.
//
// IT EXISTS TO BE COMPARED AGAINST A CLOCK rather than to be returned to anybody,
// which is why it filters on `expires_at > now` like Live does: a token outside
// its window must not suppress a fresh request, or the endpoint would refuse
// forever after a user did nothing wrong.
func (s *Store) NewestLive(ctx context.Context, q db.Querier, userID id.UUID, purpose Purpose, now time.Time) (Token, error) {
	const query = `
		SELECT ` + tokenColumns + `
		FROM recovery_tokens
		WHERE user_id = $1 AND purpose = $2 AND expires_at > $3 AND token_consumed_at IS NULL
		ORDER BY created_at DESC
		LIMIT 1`

	out, err := scanToken(q.QueryRow(ctx, query, userID, purpose, now))
	if errors.Is(err, errNoRows) {
		return Token{}, ErrTokenNotFound
	}
	if err != nil {
		return Token{}, fmt.Errorf("recovery: reading the newest %s token: %w", purpose, err)
	}
	return out, nil
}

// Consume spends the first half of a token.
//
// IT IS A CONDITIONAL UPDATE THAT REPORTS WHETHER IT WON, and the WHERE clause is
// the entire single-use guarantee: two requests carrying the same token resolve to
// one caller getting `true` and every other getting `false`, with no lock, no
// read-then-write, and nothing to roll back on the losing path.
//
// False is not an error here and the caller must not treat it as one being
// impossible — it is the answer to a double-clicked link.
func (s *Store) Consume(ctx context.Context, q db.Querier, tokenID id.UUID, at time.Time) (bool, error) {
	if tokenID.IsZero() {
		return false, ErrTokenNotFound
	}

	const query = `
		UPDATE recovery_tokens
		SET token_consumed_at = $2
		WHERE id = $1 AND token_consumed_at IS NULL AND expires_at > $2`

	tag, err := q.Exec(ctx, query, tokenID, at)
	if err != nil {
		return false, fmt.Errorf("recovery: spending a token: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// ConsumeTarget spends the second half of an email change: the confirmation the
// NEW address gave.
//
// THE WHERE CLAUSE CARRIES THE OTHER HALF TOO — `token_consumed_at IS NOT NULL` —
// and that is not redundancy. It is the statement of the flow's central rule: a
// change applies only after BOTH addresses have been confirmed, and expressing
// that as a predicate means the case where it does not hold cannot be reached by a
// caller who got the ordering wrong. A use case that checked the first half in Go
// and then called this would have a window between the check and the write.
//
// Zero rows is therefore ErrTokenNotFound rather than false: a token that reached
// this point without its first half confirmed is not redeemable, and the caller
// answers exactly as it would for one that never existed.
func (s *Store) ConsumeTarget(ctx context.Context, q db.Querier, tokenID id.UUID, at time.Time) (Token, error) {
	if tokenID.IsZero() {
		return Token{}, ErrTokenNotFound
	}

	const query = `
		UPDATE recovery_tokens
		SET target_consumed_at = $2
		WHERE id = $1 AND target_consumed_at IS NULL AND token_consumed_at IS NOT NULL
		  AND expires_at > $2
		RETURNING ` + tokenColumns

	out, err := scanToken(q.QueryRow(ctx, query, tokenID, at))
	if errors.Is(err, errNoRows) {
		return Token{}, ErrTokenNotFound
	}
	if err != nil {
		return Token{}, fmt.Errorf("recovery: confirming the new address of an email change: %w", err)
	}
	return out, nil
}

// MintTarget confirms the first half of an email change AND writes the second
// token, in one statement.
//
// IT IS ONE STATEMENT because the two facts are one fact. A change whose current
// address has been confirmed but whose new-address token does not exist is a
// request that can never finish — the user has done exactly what the mail asked
// and the account does not move, which is the worst possible outcome for the one
// step they were sure about. Writing the digest in the same conditional UPDATE
// that spends the first token means a rollback undoes both, and a second caller
// cannot mint a second new-address token for a half that is already spent.
//
// IT DOES NOT TOUCH expires_at, and that is the second half of EmailChangeTTL's
// reason for being one number rather than two: both confirmations share the
// window the request started with, so a change cannot be kept alive for ever by
// confirming the current address over and over. The target token therefore inherits
// whatever is left, which the schema's `expires_at > now` filter already enforces.
//
// The digest is the TARGET token's, and it is the only place in this package
// where it is written other than Create. It is never read back out into a struct,
// which is why `Token` has no field for it.
func (s *Store) MintTarget(ctx context.Context, q db.Querier, tokenID id.UUID, digest string, at time.Time) (Token, error) {
	if tokenID.IsZero() {
		return Token{}, ErrTokenNotFound
	}

	// THE ARGUMENT ORDER IS (id, at, digest) AND IT IS WORTH READING TWICE, because
	// the two values are both opaque 64-character hex strings and a swap here is a
	// runtime error rather than a compile-time one. The instant is $2 because it
	// appears twice in the statement — once as the value written and once in the
	// expiry filter — and Postgres numbers by first appearance.
	const query = `
		UPDATE recovery_tokens
		SET token_consumed_at = $2, target_token_digest = $3
		WHERE id = $1 AND token_consumed_at IS NULL AND target_token_digest IS NULL AND expires_at > $2
		RETURNING ` + tokenColumns

	out, err := scanToken(q.QueryRow(ctx, query, tokenID, at, digest))
	if errors.Is(err, errNoRows) {
		return Token{}, ErrTokenNotFound
	}
	if err != nil {
		return Token{}, fmt.Errorf("recovery: confirming the current address of an email change: %w", err)
	}
	return out, nil
}

// nullString turns an empty target address into SQL NULL. The CHECK on the column
// makes an empty string a constraint violation rather than a row with no target,
// and this is where that is turned into the right thing at the boundary.
func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// scanToken reads one token row.
//
// target_email is nullable — it is NULL for every purpose but an email change — and
// it is scanned through a pointer for the reason internal/sessions does the same
// for user_agent: pgx refuses to put a NULL into a string, and the alternative
// (making the column NOT NULL and storing "") would assert that "an address is
// being moved to" and "this flow does not move addresses" are the same fact. The
// domain's zero value already renders both as "no target", and one of them really
// is a target that happens to be empty.
func scanToken(row pgx.Row) (Token, error) {
	var (
		t           Token
		targetEmail *string
	)
	err := row.Scan(&t.ID, &t.UserID, &t.Purpose, &targetEmail, &t.CreatedAt, &t.ExpiresAt,
		&t.TokenConsumedAt, &t.TargetConsumedAt, &t.TargetMinted)
	if err != nil {
		if errors.Is(err, errNoRows) {
			return Token{}, errNoRows
		}
		return Token{}, fmt.Errorf("recovery: scanning a token: %w", err)
	}
	if targetEmail != nil {
		t.TargetEmail = *targetEmail
	}
	return t, nil
}
