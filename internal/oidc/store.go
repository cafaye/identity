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

// Postgres SQLSTATE 23505 is deliberately NOT mapped anywhere in this file, and
// the reason is in CreateClient: the only value in oidc_clients with a unique
// index that a caller does not choose is the client id, and a collision there is
// a bug rather than a request.

// OIDC flow windows.
//
// The numbers are the two the brief fixes and one the library needs:
//
//   - AuthRequestTTL bounds how long an /oidc/authorize stays redeemable before
//     anybody has logged in. It is the window in which an id from a URL the user
//     never followed is still worth presenting.
//   - AuthorizationCodeTTL is the interval between handing the code to the
//     browser and the client trading it for a token. RFC 6749 §4.1.2 says "MUST
//     expire shortly after it is issued" and recommends a maximum of ten
//     minutes; sixty seconds is the working value almost every provider settled
//     on, because the legitimate gap is one redirect and a PKCE exchange.
//   - AccessTokenTTL is core's cap: "Access tokens live ≤ 15 minutes". The
//     migration's CHECK constraint enforces the same bound in the database, so
//     this constant and that CHECK cannot drift into a token that outlives its
//     own policy.
const (
	AuthRequestTTL       = 10 * time.Minute
	AuthorizationCodeTTL = 60 * time.Second
	AccessTokenTTL       = 15 * time.Minute

	// IDTokenTTL is how long an id_token is valid. It is the same as
	// AccessTokenTTL and for the same reason: the id_token is a credential too,
	// and a product that keeps one for a week is holding a week-old assertion
	// about who somebody is.
	IDTokenTTL = AccessTokenTTL
)

// Store is the four OIDC tables: registrations, authorization requests,
// authorization codes and access tokens.
//
// Every method takes a db.Querier rather than the pool, so the caller chooses
// the transaction boundary. That is not a stylistic choice: registering a client
// writes a row and an event, and those two are one fact or neither, which is
// what internal/outbox exists for.
type Store struct {
	pool db.Pool
}

// NewStore returns a Store backed by pool.
func NewStore(pool db.Pool) *Store { return &Store{pool: pool} }

// ErrNoAuthCode means the presented code is not redeemable: it never existed, it
// has already been spent, or it has expired.
//
// One error for all three, deliberately. A caller who can tell "this code was
// real and you used it twice" from "this code was never real" learns whether a
// guess hit, and a code is 32 bytes of base64url that nobody is going to guess —
// but the rule that a refusal says nothing more than "not redeemable" costs
// nothing to keep and is the same one the invitation token and the session token
// already follow.
var ErrNoAuthCode = errors.New("authorization code is not redeemable")

// CreateClientParams is a new registration.
//
// ClientID and SecretDigest arrive already generated: the store does not mint
// credentials, it records them, and a store that minted its own would have no way
// to hand the raw value back to the only caller entitled to see it.
type CreateClientParams struct {
	AccountID    id.UUID
	ClientID     string
	Name         string
	SecretDigest string
	RedirectURIs []string
	GrantTypes   []string
	Scopes       []string
	CreatedBy    id.UUID
	CreatedAt    time.Time
}

// clientColumns is the select list, in the order scan expects. One constant, so
// a column added here cannot be forgotten in one query and present in another.
const clientColumns = `id, account_id, client_id, name, secret_digest, redirect_uris, grant_types, scopes, ` +
	`revoked_at, revoke_reason, revoked_by, created_at, created_by`

// CreateClient inserts a registration and returns the stored row.
func (s *Store) CreateClient(ctx context.Context, q db.Querier, p CreateClientParams) (Client, error) {
	const query = `
		INSERT INTO oidc_clients
			(account_id, client_id, name, secret_digest, redirect_uris, grant_types, scopes,
			 created_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING ` + clientColumns

	var c Client
	err := q.QueryRow(ctx, query,
		p.AccountID, p.ClientID, p.Name, p.SecretDigest, p.RedirectURIs, p.GrantTypes, p.Scopes, p.CreatedAt, p.CreatedBy,
	).Scan(&c.ID, &c.AccountID, &c.ClientID, &c.Name, &c.SecretDigest, &c.RedirectURIs, &c.GrantTypes, &c.Scopes,
		&c.RevokedAt, &c.RevokeReason, &c.RevokedBy, &c.CreatedAt, &c.CreatedBy)
	if err != nil {
		// A 23505 here is NOT mapped to a conflict, and the omission is the
		// decision. The colliding value is 32 bytes this method's caller
		// generated, so a collision is a bug with a probability around 2^-256,
		// not something the requester did. Reporting it as a 409 would invite a
		// retry that collides again and tell the caller to fix a field they never
		// chose. users/store.go maps its 23505 to ErrEmailTaken for the opposite
		// reason: an email is something the requester typed.
		return Client{}, fmt.Errorf("oidc: creating a client: %w", err)
	}
	return c, nil
}

// ClientByClientID loads a registration by the public handle.
//
// A revoked registration is returned, not hidden. The caller decides what to do
// with it — the token endpoint collapses revocation into the same 400 as every
// other refusal, and the admin list shows it — because "is it active" and "does
// it exist" are two different questions and only one caller is entitled to ask
// the second.
func (s *Store) ClientByClientID(ctx context.Context, q db.Querier, clientID string) (Client, error) {
	const query = `SELECT ` + clientColumns + ` FROM oidc_clients WHERE client_id = $1`

	c, err := scanClient(q.QueryRow(ctx, query, clientID))
	if err != nil {
		return Client{}, clientLookupError(err, "client_id")
	}
	return c, nil
}

// ClientByRowID loads a registration by its row id, which is what the event
// subject and the admin routes use.
func (s *Store) ClientByRowID(ctx context.Context, q db.Querier, rowID id.UUID) (Client, error) {
	const query = `SELECT ` + clientColumns + ` FROM oidc_clients WHERE id = $1`

	c, err := scanClient(q.QueryRow(ctx, query, rowID))
	if err != nil {
		return Client{}, clientLookupError(err, "id")
	}
	return c, nil
}

// ClientsForAccount lists an account's registrations, newest first.
//
// Cursor order is created_at DESC with the row id as the tie-break, so two
// registrations created in the same transaction have a defined order rather
// than whatever the planner returns.
func (s *Store) ClientsForAccount(ctx context.Context, q db.Querier, accountID id.UUID) ([]Client, error) {
	const query = `SELECT ` + clientColumns + `
		FROM oidc_clients
		WHERE account_id = $1
		ORDER BY created_at DESC, id DESC`

	rows, err := q.Query(ctx, query, accountID)
	if err != nil {
		return nil, fmt.Errorf("oidc: listing an account's clients: %w", err)
	}
	defer rows.Close()

	// An empty list rather than nil, so the JSON is [] and not null. The same
	// rule the account list follows.
	out := make([]Client, 0, 4)
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("oidc: reading an account's clients: %w", err)
	}
	return out, nil
}

// RevokeClient marks a registration revoked and returns the stored row.
//
// Scoped by account_id as well as id. The HTTP layer has already established that
// the caller owns the account; the query says so again because a use case
// reached any other way would not have, and a cross-tenant revocation is exactly
// the bug a redundant WHERE clause costs nothing to prevent.
//
// Conditional on revoked_at IS NULL, so a second revocation updates zero rows and
// comes back ErrAlreadyRevoked rather than moving revoked_at and overwriting who
// did it. Two operators clicking the same button at the same moment produce one
// revocation event, not two.
func (s *Store) RevokeClient(ctx context.Context, q db.Querier, rowID, accountID, by id.UUID, at time.Time, reason string) (Client, error) {
	const query = `
		UPDATE oidc_clients
		SET revoked_at = $3, revoked_by = $4, revoke_reason = NULLIF($5, '')
		WHERE id = $1 AND account_id = $2 AND revoked_at IS NULL
		RETURNING ` + clientColumns

	var c Client
	err := q.QueryRow(ctx, query, rowID, accountID, at, by, reason).Scan(
		&c.ID, &c.AccountID, &c.ClientID, &c.Name, &c.SecretDigest, &c.RedirectURIs, &c.GrantTypes, &c.Scopes,
		&c.RevokedAt, &c.RevokeReason, &c.RevokedBy, &c.CreatedAt, &c.CreatedBy,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		// Either the row is gone or it was already revoked, and the two are told
		// apart by a second read. It is a read rather than a guess because an
		// operator who clicked twice should be told "already revoked" and an
		// operator with a stale id should be told "not found" — the second is a
		// support question with a different answer.
		existing, lookupErr := s.ClientByRowID(ctx, q, rowID)
		if errors.Is(lookupErr, ErrNotFound) || existing.AccountID != accountID {
			return Client{}, ErrNotFound
		}
		return Client{}, ErrAlreadyRevoked
	}
	if err != nil {
		return Client{}, fmt.Errorf("oidc: revoking a client: %w", err)
	}
	return c, nil
}

// clientLookupError turns a miss into ErrNotFound and leaves everything else
// wrapped, so a database failure is never mistaken for an absent client.
func clientLookupError(err error, by string) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: no oidc client with that %s", ErrNotFound, by)
	}
	return fmt.Errorf("oidc: looking a client up by %s: %w", by, err)
}

// scanClient reads one row. It takes the narrow interface both pgx.Row and
// pgx.Rows satisfy, so the same six lines serve the single-row and the list
// query.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanClient(row rowScanner) (Client, error) {
	var c Client
	if err := row.Scan(&c.ID, &c.AccountID, &c.ClientID, &c.Name, &c.SecretDigest, &c.RedirectURIs,
		&c.GrantTypes, &c.Scopes, &c.RevokedAt, &c.RevokeReason, &c.RevokedBy, &c.CreatedAt, &c.CreatedBy); err != nil {
		return Client{}, err
	}
	return c, nil
}
