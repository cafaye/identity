package apikeys

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cafaye/identity/internal/accounts"
	"github.com/cafaye/identity/internal/outbox"
	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/users"
)

// The use cases: mint a credential, list an account's credentials, withdraw one,
// and turn a presented value into a caller.
//
// THE FOUR OPERATIONS, AND THE THREE THAT ARE NOT HERE, are the shape of the
// feature. There is no Rotate, no Reveal, no MintForAnotherUser, no SetScopes.
//
//	no Reveal          there is nothing to reveal. The plaintext exists once, in
//	                   the 201, and a "show me the token again" endpoint would be
//	                   an endpoint whose only purpose is to be called by somebody
//	                   who has already lost the credential.
//	no SetScopes       a token's authority is fixed at issue. Changing it means
//	                   minting a new one, which means a new secret, which means
//	                   the old one is revoked — so "change the scopes" is exactly
//	                   "rotate", expressed in two words, and having a second
//	                   spelling of it would be a second way to get the security
//	                   property wrong.
//	no MintForAnotherUser  a credential is minted BY the caller FOR the caller's
//	                   own account. There is no subject field, and MintInput has
//	                   no UserID: a machine credential is a user's own authority,
//	                                     narrowed, and one that can be minted for
//	                   somebody else is a way for an owner to plant a credential
//	                   somebody did not choose to hold.
//
// Errors beyond the package's own. They are declared here rather than in the
// store because each of them is a decision about what a CALLER is told, and the
// HTTP layer renders three of them differently on purpose.
var (
	// ErrNotAuthorized means the caller may not do this in this account: a member
	// where an owner is required, or a stranger.
	//
	// The use case returns it rather than the route, and the route turns it into
	// 403 for a member and 404 for a stranger — because a 403 for somebody who is
	// not in the account at all confirms that the account exists, which is the
	// tenant-enumeration oracle RequireAccountRole exists to avoid. The route has
	// the membership; this layer does not, and asking it to distinguish the two
	// would mean a second membership read.
	ErrNotAuthorized = errors.New("caller may not manage api keys in this account")
)

// ErrNameTaken and ErrAlreadyRevoked are the STORE's, and they are returned from
// these use cases unchanged rather than re-declared. A caller matches them with
// errors.Is against this package's exported names, and there is exactly one
// declaration of each: two would be two values that a `errors.Is` on one would not
// match against the other, and the 409 would silently become a 500.

// Caller is who a presented credential turned out to be.
//
// THE ROLE IS NOT ON THE KEY. It is read from the membership at the instant of
// resolution, which is the whole of this packet's answer to "a token outlives the
// permission that made it": the token names a user, the user has a role, and the
// role is re-read every time rather than snapshotted at issue.
type Caller struct {
	User users.User
	Key  Key
	Role accounts.Role
}

// UnitOfWork runs a function inside a transaction. db.TxRunner implements it; the
// interface is what lets these rules be tested without Postgres.
type UnitOfWork interface {
	Do(ctx context.Context, fn func(ctx context.Context, q db.Querier) error) error
}

// KeyStore is the slice of Store these use cases need.
//
// Declared here rather than taking *Store so a test can program a failure at the
// exact write that matters without standing up a database.
type KeyStore interface {
	Create(ctx context.Context, q db.Querier, n NewKey) (Key, error)
	ByDigest(ctx context.Context, q db.Querier, digest string, now time.Time) (Key, error)
	ByID(ctx context.Context, q db.Querier, rowID id.UUID) (Key, error)
	ListForAccount(ctx context.Context, q db.Querier, accountID id.UUID) ([]Key, error)
	Revoke(ctx context.Context, q db.Querier, rowID, accountID, by id.UUID, at time.Time, reason string) (Key, error)
	Touch(ctx context.Context, q db.Querier, rowID id.UUID, at time.Time) error
}

// EventAppender is the slice of outbox.Store these use cases need.
type EventAppender interface {
	Append(ctx context.Context, q db.Querier, e outbox.Envelope) error
}

// RoleReader answers "what is this user's role in this account", from
// accounts.Service.
//
// IT IS A DEPENDENCY RATHER THAN AN IMPORT because the tenancy rules are not
// restated here. This use case needs exactly one fact from tenancy — the caller's
// role — and every rule about who may mint what lives in accounts.Role.AtLeast,
// which this package calls rather than reimplements. A second implementation of
// "is a member an owner" is a second thing to be wrong about.
type RoleReader interface {
	Get(ctx context.Context, accountID, userID id.UUID) (accounts.Account, accounts.Role, error)
}

// Service is the api key use cases.
type Service struct {
	uow     UnitOfWork
	resolve CredentialResolver
	read    db.QuerierSource
	store   KeyStore
	events  EventAppender
	roles   RoleReader
	users   UserReader
	clk     clock.Clock
}

// NewService wires the use cases.
//
// roles may be nil, and then Mint and Revoke refuse with ErrNotAuthorized for
// every caller. That is the fail-closed direction and it is a supported
// configuration rather than a misconfiguration: a deployment that has not wired
// tenancy has no way to know who owns what, and a credential-management surface
// that mints without asking is worse than one that is absent.
//
// users may be nil for the same reason and with the same effect: Authenticate
// refuses everything, because a token that resolves to nobody is not a caller.
//
// `resolve` is the credential seam and it is NOT `uow`, which is the whole point
// of it taking its own parameter: `uow` is tenancy.TxRunner, which sets the
// request's ACCOUNT on every transaction it opens, and a resolution transaction
// that also began the account would have its read set be the union of "the row
// whose digest you presented" and "every row of the account you act as". Today
// the two cannot overlap because requireAccountRole resolves the credential
// before it calls tenancy.WithAccount, and that is call ORDER in another
// package — which is not a thing a security property should rest on. Passing one
// rather than two makes the narrowing structural: there is no spelling of this
// constructor that hands the resolution an account.
func NewService(
	uow UnitOfWork,
	resolve CredentialResolver,
	read db.QuerierSource,
	store KeyStore,
	events EventAppender,
	roles RoleReader,
	users UserReader,
	clk clock.Clock,
) *Service {
	return &Service{
		uow: uow, resolve: resolve, read: read, store: store,
		events: events, roles: roles, users: users, clk: clk,
	}
}

// CredentialResolver is the slice of tenancy.CredentialResolver these use cases
// need: it opens a transaction carrying the digest the caller presented, and a
// test can substitute a double for it without standing up Postgres.
//
// It is an interface rather than the concrete type because the alternative is a
// test that reaches the database to check that a statement was issued, and a test
// that needs a database to check a statement is a test that stops running.
type CredentialResolver interface {
	Do(ctx context.Context, digest string, fn func(ctx context.Context, q db.Querier) error) error
}

// resolveByDigest is the one lookup that has no account to predicate on, and it
// is HERE rather than inlined at each of its two call sites because the seam is
// the security-relevant part: the digest is hashed off the request by the
// caller, handed to Postgres as the statement that scopes the read, and expired
// with the transaction — before any query runs.
//
// THE QUERY IS UNCHANGED, and that is the point of adopting kit's mechanism
// rather than a local workaround. `where k.token_digest = $1` was always there;
// what changed is that the boundary now knows how to read it, because the
// policy carries the same predicate the query does.
//
// An error from inside the transaction is returned unchanged, so a refused
// resolution is still ErrNotFound and still 401. A failure to SET the digest is
// a different thing — a database problem, not an unknown credential — and it
// keeps its own sentinel (tenancy.ErrNoCredential) rather than being folded into
// ErrNotFound, because the two mean opposite things to whoever is reading the
// log at three in the morning.
func (s *Service) resolveByDigest(ctx context.Context, digest string, now time.Time) (Key, error) {
	var key Key
	err := s.resolve.Do(ctx, digest, func(ctx context.Context, q db.Querier) error {
		resolved, err := s.store.ByDigest(ctx, q, digest, now)
		if err != nil {
			return err
		}
		key = resolved
		return nil
	})
	if err != nil {
		return Key{}, err
	}
	return key, nil
}

// MintInput is a request for a credential.
//
// MintedBy is the caller and the OWNER of the credential, and there is no field
// for anybody else: the account comes from the path and the user from the session,
// and no version of this struct crosses that line.
//
// ExpiresIn is a duration rather than an absolute instant because the client
// asking for "a quarter" should not have to know what today is, and because a
// caller sending a timestamp invites the clock-skew problem that a duration does
// not have. A nil pointer means the default; a zero or negative one is REFUSED,
// and that is where "never expires" would have gone.
type MintInput struct {
	AccountID id.UUID
	Name      string
	Scopes    []string
	// ExpiresIn is optional. nil is the default lifetime; 0 or negative is
	// refused rather than defaulted, so a client that meant "forever" and typed
	// the wrong thing is told so.
	ExpiresIn *time.Duration
	MintedBy  id.UUID
}

// IssuedKey is a new credential and its one-time secret.
//
// Token is here and nowhere else. It is returned in the 201, never stored, and
// there is no endpoint that re-reads it — a caller that loses it mints another.
// The same shape as oidc.RegisteredClient and accounts' invitation token, for the
// same reason: a secret this service could produce again is a secret this service
// is storing.
type IssuedKey struct {
	Key   Key
	Token string
}

// Mint issues a credential and announces it.
//
// FOUR RULES, IN THIS ORDER, and the order is what makes the refusals cheap:
//
//  1. the ids are real          a zero uuid is a bug in the route, and handing it
//     to a query would be a wasted round trip
//  2. the name                  what an operator revokes by
//  3. the scopes                refused, never curated
//  4. the lifetime             and then the caller is asked whether they may
//     4b. the role                 mint AT ALL, which is after the validation because
//     a member who sent an unknown scope deserves the
//     scope error — it is the bug in their request, and
//     answering 403 would send them looking for a
//     permissions problem that is not the one they have
//
// The row and the event are one transaction. A token whose row committed and whose
// announcement did not is a credential this platform minted and no consumer was
// ever told about, and the outbox is the only place that can be made true.
func (s *Service) Mint(ctx context.Context, in MintInput) (IssuedKey, error) {
	if in.MintedBy.IsZero() || in.AccountID.IsZero() {
		return IssuedKey{}, ErrNotAuthorized
	}

	name, err := ValidateName(in.Name)
	if err != nil {
		return IssuedKey{}, err
	}
	scopes, err := ValidateScopes(in.Scopes)
	if err != nil {
		return IssuedKey{}, err
	}

	now := s.clk.Now()
	expiresAt, err := ResolveExpiry(now, in.ExpiresIn)
	if err != nil {
		return IssuedKey{}, err
	}

	// Minted AFTER validation and AFTER the role check, so a rejected request does
	// not consume entropy and a caller who may not have a credential is not told
	// anything about the randomness.
	token, digest, err := NewToken()
	if err != nil {
		return IssuedKey{}, err
	}

	var created Key
	err = s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		if err := s.requireOwner(ctx, in.AccountID, in.MintedBy); err != nil {
			return err
		}

		row, err := s.store.Create(ctx, q, NewKey{
			UserID:    in.MintedBy,
			AccountID: in.AccountID,
			Name:      name,
			Digest:    digest,
			Scopes:    scopes,
			CreatedAt: now,
			ExpiresAt: expiresAt,
		})
		if err != nil {
			return err
		}

		event, err := outbox.NewAPIKeyCreated(now, row.ID, row.AccountID, row.UserID, row.Name, row.Scopes, row.ExpiresAt)
		if err != nil {
			return err
		}
		if err := s.events.Append(ctx, q, event); err != nil {
			return err
		}

		created = row
		return nil
	})
	if err != nil {
		return IssuedKey{}, err
	}

	return IssuedKey{Key: created, Token: token}, nil
}

// List returns an account's credentials, newest first, revoked ones included.
//
// NO SECRET, no digest, and no filter on revoked_at — the settings page is where
// somebody finds out that the credential they are about to revoke was revoked last
// Tuesday, and a list that hid it would make them guess.
//
// s.read.Queryer() rather than the pool directly, and the reason is in
// db.QuerierSource: this is a single statement with no atomicity requirement, so
// it must not pay for a BEGIN and a COMMIT.
func (s *Service) List(ctx context.Context, accountID id.UUID) ([]Key, error) {
	if accountID.IsZero() {
		return nil, nil
	}
	return s.store.ListForAccount(ctx, s.read.Queryer(), accountID)
}

// RevokeInput is a request to withdraw a credential.
//
// RevokedBy is the actor, which is not necessarily Key's owner: an owner of an
// account may withdraw a credential another owner minted, because a live
// credential in an account is the account's problem and not one member's.
type RevokeInput struct {
	AccountID id.UUID
	KeyID     id.UUID
	RevokedBy id.UUID
	// Reason is stored on the row and NOT in the event. See outbox's note.
	Reason string
}

// Revoke withdraws a credential and announces it.
//
// The store's UPDATE is conditional and scoped, so this does not re-read to find
// out what happened; the store tells it. Two errors come back and the HTTP layer
// renders them as 404 and 409 for reasons that are written there.
func (s *Service) Revoke(ctx context.Context, in RevokeInput) (Key, error) {
	if in.AccountID.IsZero() || in.KeyID.IsZero() || in.RevokedBy.IsZero() {
		return Key{}, ErrNotFound
	}

	now := s.clk.Now()
	var revoked Key

	err := s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		if err := s.requireOwner(ctx, in.AccountID, in.RevokedBy); err != nil {
			return err
		}

		row, err := s.store.Revoke(ctx, q, in.KeyID, in.AccountID, in.RevokedBy, now, in.Reason)
		if err != nil {
			return err
		}

		event, err := outbox.NewAPIKeyRevoked(now, row.ID, row.AccountID, in.RevokedBy)
		if err != nil {
			return err
		}
		if err := s.events.Append(ctx, q, event); err != nil {
			return err
		}

		revoked = row
		return nil
	})
	if err != nil {
		return Key{}, err
	}

	return revoked, nil
}

// UserReader loads the user a key names.
//
// It is the slice of users.Store this package needs, and a dependency rather than
// an import of the whole service: the api key use cases have no business creating
// accounts, hashing passwords or counting sign-in failures, and declaring the one
// method they need is what keeps that true.
type UserReader interface {
	ByID(ctx context.Context, q db.Querier, id id.UUID) (users.User, error)
}

// Authenticate turns a presented value into a caller, or refuses it.
//
// THREE THINGS COME BACK AND ALL THREE ARE NEEDED: the user (whose identity this
// is), the key (so a handler can ask what it may do and name it in an audit
// trail), and the role read from the membership AT THIS INSTANT. The role is the
// interesting one — it is not stored on the token, so a demotion is visible here
// with no cache and nothing to invalidate.
//
// THE LOOKUP IS HASH-THEN-FIND, and there is no comparison of secrets anywhere on
// this path. The store never sees the presented value: `Digest` turns anything —
// an empty string, a session token, a truncated paste — into a well-formed
// 64-character hex digest, and the query is an ordinary indexed equality on that.
// So there is no length check to branch on, no early return to skip, and no
// function whose runtime reveals how much of a guess was right. That is a
// structural answer rather than a promise about subtle.ConstantTimeCompare, and
// the difference matters: a constant-time compare is what you reach for when a
// stored secret is compared byte by byte, and nothing here does that.
//
// ONE ERROR FOR EVERY REFUSAL. No such token, a revoked one, an expired one, one
// whose owner has been removed from the account, a session token presented here,
// the digest presented as a token, and an empty string are all ErrNotFound. The
// store's single query is what makes that cheap; the reason it matters is that a
// caller who can tell "revoked" from "never existed" learns whether a leaked value
// was live, which is the second question an attacker asks after "does this work".
//
// The last_used_at write is AFTER the resolution and cannot fail the request: a
// busy token must not be a failing one, and the accuracy of a column is worth less
// than the availability of the credential it describes. It is best-effort for that
// reason and the failure goes nowhere — see the note at the write.
//
// now is a parameter rather than read from the clock so a caller resolving a token
// judges it against the same instant the response is timestamped with. The
// Service's own clock is the default in the HTTP layer, which is the only caller
// that has one.
// Introspect resolves a presented token to a claim document, and it is NOT
// Authenticate with a different return type.
//
// The difference is one column and it matters: Introspect does not touch
// `last_used_at`. Asking "is this token still good" is not using it, and a
// resource server that introspects on every request — which is the normal shape
// for an opaque credential — would otherwise turn the column into a heartbeat
// that says the token is in use when nothing has been done with it. An operator
// reading "last used 4pm" and finding a CI job that only ever introspected would
// have no way to tell the difference.
//
// ONE ERROR, and it is the same one: a token that cannot be used is not an error
// here either. The caller renders ErrNotFound as `{"active": false}`, which is
// RFC 7662's answer and the one that keeps "revoked" and "never existed"
// indistinguishable.
//
// IT RESOLVES ON THE SAME SEAM Authenticate DOES, and that is not an
// implementation detail. This is the second reader of `api_keys` by digest, and
// leaving it on the bare pool would be a lookup that reads zero rows under the
// enforced boundary — so `/v1/introspections` would answer `{"active": false}` for
// every live token in the fleet, which is a silently wrong answer rather than a
// failure anyone would be paged for. See `resolveByDigest`.
func (s *Service) Introspect(ctx context.Context, token string, now time.Time) (Claims, error) {
	if token == "" {
		return Claims{}, ErrNotFound
	}
	key, err := s.resolveByDigest(ctx, Digest(token), now)
	if err != nil {
		return Claims{}, err
	}
	return ClaimsFor(key, now)
}

// Authenticate turns a presented value into a caller, or refuses it.
//
// THREE THINGS COME BACK AND ALL THREE ARE NEEDED: the user (whose identity this
// is), the key (so a handler can ask what it may do and name it in an audit
// trail), and the role read from the membership AT THIS INSTANT. The role is the
// interesting one — it is not stored on the token, so a demotion is visible here
// with no cache and nothing to invalidate.
//
// THE LOOKUP IS HASH-THEN-FIND, and there is no comparison of secrets anywhere on
// this path. The store never sees the presented value: `Digest` turns anything —
// an empty string, a session token, a truncated paste — into a well-formed
// 64-character hex digest, and the query is an ordinary indexed equality on that.
// So there is no length check to branch on, no early return to skip, and no
// function whose runtime reveals how much of a guess was right. That is a
// structural answer rather than a promise about subtle.ConstantTimeCompare, and
// the difference matters: a constant-time compare is what you reach for when a
// stored secret is compared byte by byte, and nothing here does that.
//
// ONE ERROR FOR EVERY REFUSAL. No such token, a revoked one, an expired one, one
// whose owner has been removed from the account, a session token presented here,
// the digest presented as a token, and an empty string are all ErrNotFound. The
// store's single query is what makes that cheap; the reason it matters is that a
// caller who can tell "revoked" from "never existed" learns whether a leaked value
// was live, which is the second question an attacker asks after "does this work".
//
// The last_used_at write is AFTER the resolution and cannot fail the request: a
// busy token must not be a failing one, and the accuracy of a column is worth less
// than the availability of the credential it describes. Introspect is the
// exception and does not write it at all — see there.
//
// now is a parameter rather than read from the clock so a caller resolving a token
// judges it against the same instant the response is timestamped with. The
// Service's own clock is the default in the HTTP layer, which is the only caller
// that has one.
//
// WHERE THE RESOLUTION RUNS, and it is the second thing this method needs saying.
// The lookup runs inside a transaction that already carries
// `cafaye.begin_credential(digest)`, because `api_keys` is a credential table
// (migrations/00016 calls `cafaye.protect_credential_table('api_keys',
// 'token_digest')`) and the query that turns a presented secret into a caller has
// no account to predicate on — the account is what it is FOR. Protected the ordinary
// way, that query read zero rows for a request with no identity set, which is the
// state every scoped-token request is in before it has resolved anything, and
// ErrNotFound became 401 for every valid machine credential in the fleet. Measured,
// not recalled: see the characterisation that used to pin it,
// TestTenancyACredentialLookupReadZeroRowsBeforeMD24AndThisIsItsReplacement.
//
// The transaction is transaction-local, so after it commits the digest is gone and
// the connection is an ordinary no-identity session until `requireAccountRole` sets
// the account — which is what keeps this from being a standing grant on a pooled
// connection. And the resolver cannot set an account at all; see `resolveByDigest`.
func (s *Service) Authenticate(ctx context.Context, token string, now time.Time) (Caller, error) {
	key, err := s.resolveByDigest(ctx, Digest(token), now)
	if err != nil {
		// Already ErrNotFound for every case, and the store's error is not wrapped
		// again here: a caller matching on it is the HTTP layer, and a wrapped
		// sentinel would still match, but a second error string on a refusal is
		// one more thing that could differ between two refusals.
		return Caller{}, err
	}

	if s.users == nil {
		return Caller{}, ErrNotFound
	}

	user, err := s.users.ByID(ctx, s.read.Queryer(), key.UserID)
	if err != nil {
		// A key whose user has been deleted cannot happen — the table cascades —
		// and a row that somehow names a user who is not there must not resolve. It
		// is refused as "not found" rather than as a 500 because from the caller's
		// side it is the same answer as a token that never existed, and a 500 here
		// would be the one way to tell them apart.
		return Caller{}, ErrNotFound
	}

	// Best effort, and deliberately not surfaced. The store's Touch is already
	// bounded to one write per LastUsedResolution, so this is at most one UPDATE
	// every five minutes on a row nobody is waiting on, and a failure of it — a
	// deadlock, a read-only replica, a dropped connection — is a missing audit
	// timestamp rather than a broken credential. Returning it would let a busy
	// token's own bookkeeping deny it service.
	//
	// The resolved row is updated IN HAND after the write rather than re-read, and
	// that is so the caller sees the timestamp of the use it just made. A caller
	// that rendered "last used: never" for a token it is currently using would be
	// reporting the state before its own request, which is the one reading that is
	// never true at the moment it is read.
	if err := s.store.Touch(ctx, s.read.Queryer(), key.ID, now); err == nil {
		key.LastUsedAt = &now
	}

	return Caller{User: user, Key: key, Role: key.Role}, nil
}

// requireOwner is the one authorization rule in this package: minting and revoking
// are owner-only, and "owner" is read through accounts.Role rather than compared
// here.
//
// IT IS IN THE TRANSACTION on purpose. Reading the role outside and then writing
// inside would leave a window in which the caller is demoted between the check and
// the write, and the credential they were about to mint would be minted anyway —
// the same read-then-write race mfa's partial unique index exists to remove.
func (s *Service) requireOwner(ctx context.Context, accountID, userID id.UUID) error {
	if s.roles == nil {
		// Said out loud rather than panicking: a deployment without tenancy wired
		// cannot answer "who owns this", and a nil-pointer panic in a
		// credential-management path is a 500 that says nothing.
		return ErrNotAuthorized
	}

	_, role, err := s.roles.Get(ctx, accountID, userID)
	if err != nil {
		// accounts.ErrNotAMember and accounts.ErrNotFound both mean the same thing
		// here — this caller has no standing in this account — and the route has
		// already answered the two differently before it got here. Anything else is
		// a real failure and stays one.
		if errors.Is(err, accounts.ErrNotAMember) || errors.Is(err, accounts.ErrNotFound) {
			return ErrNotAuthorized
		}
		return fmt.Errorf("apikeys: reading the caller's role: %w", err)
	}

	if !role.AtLeast(accounts.RoleOwner) {
		return ErrNotAuthorized
	}
	return nil
}
