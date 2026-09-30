package oidc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
)

// The authorization request: one row per /oidc/authorize, from the moment the
// request is validated to the moment its code is spent.
//
// It is a domain type AND the library's op.AuthRequest, because the two are the
// same object seen from two ends. Splitting them would mean a translation layer
// whose only content is field assignment, and every field would then be a place
// where the two could disagree.

// AuthRequest is a validated authorization request, waiting for a user.
type AuthRequest struct {
	// ID is the row's uuid and the value the login UI carries in its URL. It is
	// not a credential: it names a request, and a request is only worth anything
	// to a user who then authenticates against it.
	ID          id.UUID
	ClientRowID id.UUID
	// ClientID is the public handle, carried so the login page can say which
	// product is asking without a second query.
	ClientID string
	// ClientName is the product's registration name. Purely for display, and
	// load-bearing for that: a login page that cannot name the thing asking is a
	// login page a user types their password into on faith, which is the setup
	// for a phishing page on this service's own domain.
	ClientName string

	RedirectURI         string
	State               string
	Nonce               string
	ResponseType        string
	ResponseMode        string
	Scopes              []string
	CodeChallenge       string
	CodeChallengeMethod string
	LoginHint           string

	// Subject is the user who will own the resulting tokens, and AuthTime is when
	// they authenticated. They are set together and Done() reads the second, so
	// a request that knows who is expected without anyone having logged in yet is
	// representable — which is what an `id_token_hint` pre-fill is.
	Subject  *id.UUID
	AuthTime *time.Time

	CreatedAt  time.Time
	ExpiresAt  time.Time
	CodeDigest *string
	// CodeConsumedAt is set by the single UPDATE that redeems the code, which is
	// what makes a code single-use under concurrency rather than merely in
	// sequence.
	CodeConsumedAt *time.Time
}

// ErrAuthRequestNotFound means no live request with that id.
var ErrAuthRequestNotFound = errors.New("authorization request not found")

// ErrAuthRequestExpired is deliberately the same value as
// ErrAuthRequestNotFound. An expired request is one this service will not
// complete, and telling a caller which of the two it was would let a probe
// distinguish a request id that once existed from one that never did.
var ErrAuthRequestExpired = ErrAuthRequestNotFound

// NewAuthRequest is a request to record a validated authorization request.
type NewAuthRequest struct {
	ClientRowID         id.UUID
	RedirectURI         string
	State               string
	Nonce               string
	ResponseType        string
	ResponseMode        string
	Scopes              []string
	CodeChallenge       string
	CodeChallengeMethod string
	LoginHint           string
	CreatedAt           time.Time
	ExpiresAt           time.Time
}

const authRequestColumns = `r.id, r.client_row_id, c.client_id, c.name AS client_name, ` +
	`r.redirect_uri, r.state, r.nonce, r.response_type, r.response_mode, r.scopes, ` +
	`r.code_challenge, r.code_challenge_method, r.login_hint, ` +
	`r.subject, r.auth_time, r.created_at, r.expires_at, r.code_digest, r.code_consumed_at`

// CreateAuthRequest records a validated authorization request.
//
// CodeChallengeMethod is written as given and the table's CHECK constraint
// accepts nothing but 'S256'. That is deliberate: the authorize handler has
// already refused anything else, and putting the rule in the column as well means
// a code path added later cannot mint a request the token endpoint would then
// have to reason about.
func (s *Store) CreateAuthRequest(ctx context.Context, q db.Querier, n NewAuthRequest) (AuthRequest, error) {
	const query = `
		INSERT INTO oidc_auth_requests
			(client_row_id, redirect_uri, state, nonce, response_type, response_mode, scopes,
			 code_challenge, code_challenge_method, login_hint, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id`

	var rowID id.UUID
	if err := q.QueryRow(ctx, query,
		n.ClientRowID, n.RedirectURI, n.State, n.Nonce, n.ResponseType, n.ResponseMode, n.Scopes,
		n.CodeChallenge, n.CodeChallengeMethod, n.LoginHint, n.CreatedAt, n.ExpiresAt,
	).Scan(&rowID); err != nil {
		return AuthRequest{}, fmt.Errorf("oidc: creating an auth request: %w", err)
	}
	// n.CreatedAt is the reference instant rather than a separately supplied
	// "now": the row was written at that time, so a request is live at its own
	// creation by construction and anything else would be the caller's clock and
	// this package's disagreeing.
	return s.AuthRequestByID(ctx, q, rowID, n.CreatedAt)
}

// AuthRequestByID loads a live request, joining the client's public handle.
//
// A request whose ExpiresAt has passed is ErrAuthRequestNotFound, not a row with
// a flag: the login callback asks this question for an id that arrived in a URL,
// and the answer has to be the same for "too old" and "never existed" or the id
// becomes a probe for which authorizations are still in flight.
//
// now is a parameter and not Postgres's now() because every other window in this
// service is read through the injected clock, and a row written against a fake
// clock and checked against the server's is a test that passes or fails
// depending on what time of day it is.
func (s *Store) AuthRequestByID(ctx context.Context, q db.Querier, rowID id.UUID, now time.Time) (AuthRequest, error) {
	const query = `SELECT ` + authRequestColumns + `
		FROM oidc_auth_requests r
		JOIN oidc_clients c ON c.id = r.client_row_id
		WHERE r.id = $1 AND r.expires_at > $2`

	request, err := scanAuthRequest(q.QueryRow(ctx, query, rowID, now))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return AuthRequest{}, fmt.Errorf("%w: no live auth request with that id", ErrAuthRequestNotFound)
		}
		return AuthRequest{}, fmt.Errorf("oidc: loading an auth request: %w", err)
	}
	return request, nil
}

// CompleteAuthRequest records that a user authenticated against a request.
//
// Conditional on subject IS NULL, so two login submissions for the same request
// cannot both write a subject, and the second caller gets ErrAlreadyComplete
// rather than silently re-pointing a request at somebody else.
func (s *Store) CompleteAuthRequest(ctx context.Context, q db.Querier, rowID, subject id.UUID, at time.Time) error {
	const query = `
		UPDATE oidc_auth_requests
		SET subject = $2, auth_time = $3
		WHERE id = $1 AND subject IS NULL AND expires_at > $4`

	tag, err := q.Exec(ctx, query, rowID, subject, at, at)
	if err != nil {
		return fmt.Errorf("oidc: completing an auth request: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrAuthRequestNotFound
	}
	return nil
}

// SaveAuthCode stores the digest of a freshly minted authorization code.
//
// The digest, never the code. The code is in the browser's hands from the moment
// it is minted, and a row holding the value would be a row holding a credential
// for as long as the request lives.
func (s *Store) SaveAuthCode(ctx context.Context, q db.Querier, rowID id.UUID, digest string, expiresAt time.Time) error {
	const query = `
		UPDATE oidc_auth_requests
		SET code_digest = $2, code_expires_at = $3
		WHERE id = $1 AND code_digest IS NULL`

	tag, err := q.Exec(ctx, query, rowID, digest, expiresAt)
	if err != nil {
		return fmt.Errorf("oidc: saving an authorization code: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Either the request is gone or a code is already on it. The second is
		// the interesting one: two callbacks for one request would otherwise
		// leave the second code's holder holding a code that is not the one the
		// row knows about.
		return ErrNoAuthCode
	}
	return nil
}

// ConsumeAuthCode redeems an authorization code and returns its request.
//
// THIS IS THE SINGLE-USE GATE, and it is one conditional UPDATE for a reason.
// A read-then-delete would let two requests carrying the same code both pass the
// read; a conditional UPDATE cannot, because the second one matches zero rows.
// The returned request is the row as it was BEFORE the update, so the caller
// still has the scopes, the redirect URI and the code challenge it needs to mint
// tokens, and the code is already spent by the time it gets them.
//
// The three refusals — no such code, already spent, expired — are all
// ErrNoAuthCode. See that error for why.
func (s *Store) ConsumeAuthCode(ctx context.Context, q db.Querier, digest string, now time.Time) (AuthRequest, error) {
	const query = `
		WITH spent AS (
			UPDATE oidc_auth_requests
			SET code_consumed_at = $2
			WHERE code_digest = $1
			  AND code_consumed_at IS NULL
			  AND code_expires_at > $2
			RETURNING client_row_id
		)
		SELECT ` + authRequestColumns + `
		FROM oidc_auth_requests r
		JOIN oidc_clients c ON c.id = r.client_row_id
		WHERE r.client_row_id IN (SELECT client_row_id FROM spent)
		  AND r.code_digest = $1`

	request, err := scanAuthRequest(q.QueryRow(ctx, query, digest, now))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return AuthRequest{}, ErrNoAuthCode
		}
		return AuthRequest{}, fmt.Errorf("oidc: redeeming an authorization code: %w", err)
	}
	return request, nil
}

// DeleteAuthRequest removes a request and its code.
//
// Idempotent, and it has to be: ConsumeAuthCode has already taken the row's code
// out of circulation and the library calls this straight afterwards to tidy up.
// A DELETE that reported "no rows" as an error would turn every successful token
// exchange into a 500.
func (s *Store) DeleteAuthRequest(ctx context.Context, q db.Querier, rowID id.UUID) error {
	if _, err := q.Exec(ctx, `DELETE FROM oidc_auth_requests WHERE id = $1`, rowID); err != nil {
		return fmt.Errorf("oidc: deleting an auth request: %w", err)
	}
	return nil
}

func scanAuthRequest(row rowScanner) (AuthRequest, error) {
	var r AuthRequest
	var clientName *string
	if err := row.Scan(&r.ID, &r.ClientRowID, &r.ClientID, &clientName, &r.RedirectURI, &r.State, &r.Nonce,
		&r.ResponseType, &r.ResponseMode, &r.Scopes, &r.CodeChallenge, &r.CodeChallengeMethod, &r.LoginHint,
		&r.Subject, &r.AuthTime, &r.CreatedAt, &r.ExpiresAt, &r.CodeDigest, &r.CodeConsumedAt); err != nil {
		return AuthRequest{}, err
	}
	if clientName != nil {
		// The registration's name, for the login page to render. It is nullable
		// here only because the column is NOT NULL and a pointer is how pgx
		// reports "present"; there is no state in which it is nil.
		r.ClientName = *clientName
	}
	return r, nil
}
