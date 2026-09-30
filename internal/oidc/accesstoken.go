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

// The access token row.
//
// There is a row because the access token is a JWT, and a JWT is verifiable by
// anybody holding the published JWKS — which is the point, and is also why a
// stateless token needs a way to stop working before it expires. The row is that
// way: userinfo reads it, and so does anything that has to honour a revocation
// faster than the signature's `exp` would allow.
//
// The id IS the `jti`. There is no surrogate key, because the library hands this
// value to the signer as the claim and reads the claim back to find the row, and
// a second identifier would mean a join on the hot path of every userinfo call.

// AccessToken is one issued access token.
type AccessToken struct {
	// ID is the JWT's `jti`.
	ID          id.UUID
	ClientRowID id.UUID
	Subject     id.UUID
	Scopes      []string
	IssuedAt    time.Time
	ExpiresAt   time.Time
	RevokedAt   *time.Time
}

// ErrNoAccessToken means the token id is not one this service issued, or the
// row behind it is gone.
//
// One error for both, and the same reasoning as ErrNoAuthCode: the userinfo
// endpoint answers 401 either way, so a caller learns nothing about which token
// ids are real.
var ErrNoAccessToken = errors.New("access token is not valid")

// NewAccessToken is a token to record.
type NewAccessToken struct {
	ID          id.UUID
	ClientRowID id.UUID
	Subject     id.UUID
	Scopes      []string
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

// CreateAccessToken records an issued access token.
//
// The id is supplied rather than generated, because it has to be the same value
// that goes into the token's `jti`: the library mints the JWT from the value this
// method returns, so a generated id here and a generated one there would be two
// different tokens.
func (s *Store) CreateAccessToken(ctx context.Context, q db.Querier, n NewAccessToken) error {
	const query = `
		INSERT INTO oidc_access_tokens (id, client_row_id, subject, scopes, issued_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`

	if _, err := q.Exec(ctx, query, n.ID, n.ClientRowID, n.Subject, n.Scopes, n.IssuedAt, n.ExpiresAt); err != nil {
		return fmt.Errorf("oidc: recording an access token: %w", err)
	}
	return nil
}

const accessTokenColumns = `id, client_row_id, subject, scopes, issued_at, expires_at, revoked_at`

// AccessToken loads a token by its id, refusing one that is revoked.
//
// The revocation check is here rather than in the caller so that every reader of
// a token — userinfo today, introspection when it is mounted — gets the same
// answer, and so that adding a second reader cannot forget it. Expiry is NOT
// checked here: the library's verifier has already checked `exp` against the
// signature by the time it hands over the id, and checking it twice would mean two
// clocks disagreeing at the boundary.
func (s *Store) AccessToken(ctx context.Context, q db.Querier, tokenID id.UUID) (AccessToken, error) {
	const query = `SELECT ` + accessTokenColumns + `
		FROM oidc_access_tokens
		WHERE id = $1 AND revoked_at IS NULL`

	var t AccessToken
	err := q.QueryRow(ctx, query, tokenID).Scan(
		&t.ID, &t.ClientRowID, &t.Subject, &t.Scopes, &t.IssuedAt, &t.ExpiresAt, &t.RevokedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return AccessToken{}, ErrNoAccessToken
	}
	if err != nil {
		return AccessToken{}, fmt.Errorf("oidc: loading an access token: %w", err)
	}
	return t, nil
}

// RevokeAccessToken marks a token revoked, ignoring one that already is.
//
// Idempotent, and that is the correct semantic rather than a convenience: RFC
// 7009 says a revocation endpoint must answer 200 whether or not the token
// existed, and a second revocation of the same token is not an error worth
// distinguishing to a caller that is cleaning up after itself.
func (s *Store) RevokeAccessToken(ctx context.Context, q db.Querier, tokenID id.UUID, at time.Time) error {
	const query = `
		UPDATE oidc_access_tokens
		SET revoked_at = $2
		WHERE id = $1 AND revoked_at IS NULL`

	if _, err := q.Exec(ctx, query, tokenID, at); err != nil {
		return fmt.Errorf("oidc: revoking an access token: %w", err)
	}
	return nil
}
