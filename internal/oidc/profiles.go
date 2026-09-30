package oidc

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
)

// What identity knows about a user, in the shape a token carries it.
//
// It is a projection assembled from rows this service already owns — users,
// accounts and account_users — and nothing is fetched from anywhere else. The
// rule the brief states is the rule this type exists to hold: no claim reaches a
// token that is not already in the database, and no internal id reaches a token
// unless it is the id a consumer needs to make its next authorized call.

// Profile is one user's claims, before scopes have been applied.
type Profile struct {
	UserID id.UUID
	Email  string
	// Name is the personal account's name.
	//
	// THIS IS NOT A USER-CHOSEN NAME, and it is a stand-in rather than a
	// feature. identity has no first_name / last_name pair, and the one
	// human-legible name it holds about a person is the personal account it
	// created for them, which is derived from their email local part. It is
	// rendered on the `profile` scope so a product has something to put on its
	// account screen, and a product that needs a real name needs the profile
	// packet this service does not have yet.
	Name string
	// EmailVerified is ALWAYS false, and that is a fact rather than an omission.
	//
	// identity has no email-verification column: the verification link, the
	// signed token and the resend endpoint are a later packet. There is therefore
	// nothing here that could prove an address, and `false` is the only claim that
	// is safe to make — a relying party that reads `true` from this would skip
	// sending a verification email to an address nobody has proved they own, and
	// an account takeover becomes a matter of registering somebody else's address.
	//
	// When the verification packet lands this becomes a read of
	// users.email_verified_at and nothing else changes. The claim is emitted
	// explicitly even though it is false, because oidc.UserInfo.EmailVerified
	// carries `omitempty` and a false bool would otherwise vanish from the token
	// and leave a relying party guessing whether the provider supports it.
	EmailVerified bool
	// Accounts is every membership the user holds, each with the role they hold
	// it under.
	Accounts []Membership
}

// Membership is one account a user belongs to, and what they may do in it.
type Membership struct {
	AccountID id.UUID
	Name      string
	Slug      string
	Role      string
	Personal  bool
}

// ProfileReader assembles a Profile from this service's own tables.
//
// It is an interface so the storage adapter has no dependency on the users or
// accounts packages: the adapter's job is to answer the library's questions, and
// how this service stores a user's claims is not the adapter's business. The
// implementation is NewProfileReader below.
type ProfileReader interface {
	// Profile returns the user's claims, or an error if there is no such user.
	//
	// q is a db.Querier because the token endpoint reads a profile inside the
	// transaction that records the access token, and a profile that came from a
	// different transaction is a profile that could be revoked between the two.
	Profile(ctx context.Context, q db.Querier, userID id.UUID) (Profile, error)
}

// ErrNoProfile means the subject on a token is not a user this service has.
var ErrNoProfile = errors.New("no such user")

// pgProfileReader reads a Profile out of users, account_users and accounts.
type pgProfileReader struct{}

// NewProfileReader returns the ProfileReader over this service's tables.
func NewProfileReader() ProfileReader { return pgProfileReader{} }

// Profile assembles the claims for one user.
//
// Two statements rather than one, and the order is not arbitrary: the user row
// first, because a subject with no user is a bug the caller has to hear about
// rather than a profile of empty strings, and the memberships second because they
// are the part that can legitimately be empty.
func (pgProfileReader) Profile(ctx context.Context, q db.Querier, userID id.UUID) (Profile, error) {
	p := Profile{UserID: userID, Accounts: []Membership{}}

	const userQuery = `SELECT email FROM users WHERE id = $1`
	if err := q.QueryRow(ctx, userQuery, userID).Scan(&p.Email); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Profile{}, fmt.Errorf("%w: %s", ErrNoProfile, userID)
		}
		return Profile{}, fmt.Errorf("oidc: reading a user for a token: %w", err)
	}

	// The personal account is the name. There is at most one, and the ORDER BY is
	// there so a data accident that produced two does not make the claim flap
	// between two values depending on the planner.
	const nameQuery = `
		SELECT a.name
		FROM accounts a
		JOIN account_users au ON au.account_id = a.id
		WHERE au.user_id = $1 AND a.personal
		ORDER BY a.created_at, a.id
		LIMIT 1`
	if err := q.QueryRow(ctx, nameQuery, userID).Scan(&p.Name); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Profile{}, fmt.Errorf("oidc: reading the personal account name for a token: %w", err)
	}

	const accountsQuery = `
		SELECT a.id, a.name, a.slug, au.role::text, a.personal
		FROM account_users au
		JOIN accounts a ON a.id = au.account_id
		WHERE au.user_id = $1
		ORDER BY a.created_at, a.id`
	rows, err := q.Query(ctx, accountsQuery, userID)
	if err != nil {
		return Profile{}, fmt.Errorf("oidc: reading an account's memberships for a token: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var m Membership
		if err := rows.Scan(&m.AccountID, &m.Name, &m.Slug, &m.Role, &m.Personal); err != nil {
			return Profile{}, fmt.Errorf("oidc: scanning a membership for a token: %w", err)
		}
		p.Accounts = append(p.Accounts, m)
	}
	if err := rows.Err(); err != nil {
		return Profile{}, fmt.Errorf("oidc: reading an account's memberships for a token: %w", err)
	}

	return p, nil
}

// claimAccount is the wire shape of one membership.
//
// It carries the account id, the slug, the name, the role and whether the
// account is the user's personal one — and nothing else. There is no invitation
// id, no created_at and no internal row id, because a product's next request is
// "act in this account" and a claim it cannot use is a claim that has made the
// token bigger for nothing.
type claimAccount struct {
	AccountID string `json:"account_id"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	Role      string `json:"role"`
	Personal  bool   `json:"personal"`
}

// claimAccounts projects memberships onto the wire, as an array and never null.
//
// An array is a different answer from a single id, and it is the right one: a
// user of a cafaye product is a member of a personal account and usually of
// several team accounts, so there is no single `account_id` to put in a token.
// core's conventions ask for `account_id` on authenticated service traffic; this
// is the multi-account form of that fact, and the disagreement is recorded in
// README.md rather than papered over with a field that would be wrong whenever
// the answer was not one account.
func accountsClaim(memberships []Membership) []claimAccount {
	out := make([]claimAccount, 0, len(memberships))
	for _, m := range memberships {
		out = append(out, claimAccount{
			AccountID: m.AccountID.String(),
			Name:      m.Name,
			Slug:      m.Slug,
			Role:      m.Role,
			Personal:  m.Personal,
		})
	}
	return out
}
