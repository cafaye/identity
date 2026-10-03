package auth

// THE SOCIAL-LOGIN USE CASE: WHICH USER A PROVIDER IDENTITY RESOLVES TO.
//
// Everything hard about social sign-in was already written and tested in
// internal/oauth — the providers, the CSRF state, the code-for-token exchange, the
// cipher over the stored tokens and the `connected_accounts` table. What that
// package deliberately does not contain is this decision, and this file is it. It is
// a separate file and a separate type rather than four more methods on Service
// because Service's dependencies are fixed by its constructor and every one of them
// is about passwords; social login needs none of the password machinery except the
// session minting and the tenancy provisioning it borrows.
//
// # THREE PATHS, AND THE ORDER THEY ARE ASKED IN IS THE SECURITY PROPERTY
//
// Jumpstart Pro's callback dispatch (refs/jumpstart-pro,
// lib/jumpstart/lib/jumpstart/omniauth/callbacks.rb) asks four questions in a fixed
// order, and every one of the orders is a decision:
//
//  1. Has this provider identity been seen before?      → sign in as its owner
//  2. Is the caller authenticated as somebody else?    → refuse, 409
//  3. Is the caller authenticated at all?              → link to them
//  4. Does this address already belong to an account?  → REFUSE, 409
//  5. Otherwise                                        → create the account
//
// # WHY QUESTION 4 REFUSES RATHER THAN LINKS
//
// Email from an OAuth provider is not proof of control of that mailbox, and this
// service's `users.email` is unique. So a provider address that already belongs to an
// account is either (a) an attacker holding a provider account they set that address
// on, in which case linking it signs them in as the victim, or (b) the same person
// arriving two ways, in which case the honest answer is "sign in with the one you
// already have". There is no third option that is not one of those two.
//
// The refusal is a support call. Auto-linking is an incident. That is the whole
// trade, and it is recorded as DECISIONS.md D11 rather than left as a comment here.
//
// # AND WHY THE REFUSAL IS ONLY QUESTION 4
//
// Because questions 1 to 3 are decided by the PROVIDER'S OWN IDENTIFIER, which is a
// fact about the provider's account and not about a mailbox. A person who signed in
// as themselves is signing in as themselves, and their provider address colliding
// with another account's is not evidence of anything — which is why
// `attach_account` in the reference does not ask question 4 either. Adding the check
// to the link path would refuse a legitimate operation for a reason that does not
// apply to it.
//
// # QUESTION 4 IS NOT AN ENUMERATION ORACLE, AND THAT IS NOT AN ACCIDENT
//
// A 409 here does say "an account already exists for this address", to an anonymous
// caller. What makes that safe is question 4 being reachable only with a code a
// provider issued for an address the provider has itself verified: the client
// refuses an unverified address on both providers (internal/oauth/client.go), so by
// the time this package sees an address, the person at the browser has proved
// control of that exact mailbox. They could learn that fact by asking Google. So the
// bit disclosed is one the caller already holds, and closing it would cost a
// recovery flow to protect nothing.
//
// It is the other way round that matters, and is why the unverified refusal is a
// separate decision rather than a detail of this one: without it an attacker who
// can set an arbitrary address on a provider account walks straight into this 409
// with a guess, and the guess becomes a takeover. `email_verified` is not read for
// tidiness; it is what makes question 4 safe to ask out loud.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/cafaye/identity/internal/oauth"
	"github.com/cafaye/identity/internal/outbox"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/users"
)

// Social errors the HTTP layer maps onto status codes.
//
// ErrSocialEmailInUse is the refusal of question 4 and it is a value of its own
// rather than users.ErrEmailTaken, which means "you tried to register". They read
// differently to the person at the browser and they mean different things: one says
// "this address is spoken for, sign in the way you did before", the other says
// "pick another address". Collapsing them into one code would leave a client
// rendering the registration message on a social callback, which is the confusion
// the split exists to prevent.
var (
	// ErrSocialEmailInUse means the provider's address already belongs to an
	// account of this service, so this callback will not sign anybody in. See the
	// file comment for why refusing is the answer and why it is safe to say out
	// loud.
	ErrSocialEmailInUse = errors.New("that provider account's address already belongs to another account")

	// ErrSocialNoProviders means the deployment configured no provider, so the
	// social-login routes are not mounted at all. It exists so a caller that
	// reaches this type anyway gets a refusal rather than a nil dereference: the
	// route should not be mounted, and this is the shape of the mistake rather
	// than a crash.
	ErrSocialNoProviders = errors.New("social login is not configured")
)

// SocialRegistry is the part of oauth.Registry this use case needs: the provider
// named in the URL, and the configured base URL the callback is checked against.
//
// It is an interface declared here, at the consumer, for the reason UserStore and
// SessionStore are: the use case is testable without a registry and without a
// network, and oauth is not this package's dependency on the way it is not the
// handlers' either.
type SocialRegistry interface {
	Lookup(name string) (oauth.Provider, error)
	RedirectBase() string
}

// SocialExchanger is the part of oauth.Client: the code-for-token exchange and the
// "who is this" call. Both are on one interface because a flow that can do one and
// not the other is a flow that either mints a session for nobody or never learns
// who it is minting one for.
type SocialExchanger interface {
	Exchange(ctx context.Context, p oauth.Provider, code string) (oauth.Tokens, error)
	Identity(ctx context.Context, p oauth.Provider, tokens oauth.Tokens) (oauth.Identity, error)
}

// SocialAccounts is the connected_accounts table, and it is keyed on (provider,
// provider_uid) and never on an address. See internal/oauth.Store for why, and
// oauth.ErrAlreadyLinked for the refusal a unique-index violation becomes.
type SocialAccounts interface {
	ByProviderUID(ctx context.Context, q db.Querier, provider, providerUID string) (oauth.Account, error)
	Create(ctx context.Context, q db.Querier, n oauth.NewAccount) (oauth.Account, error)
	RefreshTokens(ctx context.Context, q db.Querier, accountID id.UUID, t oauth.StoredTokens) error
}

// SocialSealer seals a provider token for storage. The cipher is an interface here
// for one reason beyond testability: this package must never hold the key, and an
// interface it can only Seal through is a promise that it does not.
type SocialSealer interface {
	Seal(plaintext string) (string, error)
}

// SocialService is the use case behind the two social-login routes.
//
// It borrows Service rather than duplicating it: the session minting, the
// second-factor decision and the personal-account provisioning are all questions
// about a LOCAL account, and they are the same questions Register and Login ask. A
// second implementation of "mint a session and clear the failure run in one
// transaction" is a second thing to get right.
type SocialService struct {
	auth     *Service
	registry SocialRegistry
	client   SocialExchanger
	store    SocialAccounts
	sealer   SocialSealer
}

// NewSocialService wires the social-login use case.
//
// auth is the ordinary auth service, not a copy of it: every write below goes
// through its transaction runner, its session store and its tenancy provisioner, so
// a user minted here is a user the rest of the service cannot tell apart from one
// registered with a password.
func NewSocialService(
	a *Service,
	registry SocialRegistry,
	client SocialExchanger,
	store SocialAccounts,
	sealer SocialSealer,
) *SocialService {
	return &SocialService{auth: a, registry: registry, client: client, store: store, sealer: sealer}
}

// SocialCallbackInput is one completed provider round trip.
type SocialCallbackInput struct {
	// Provider is the name from the URL. It is attacker-chosen and is looked up in
	// the registry, so an unconfigured provider is a miss rather than a request.
	Provider string
	// Code is the authorization code the provider sent back.
	Code string

	// LinkTo is the user this callback should attach the provider identity to.
	//
	// IT IS EMPTY FOR A SIGN-IN, and that is the whole of how the link path is
	// chosen: the handler resolves the caller's session before calling here and
	// passes the user, and a caller who started the flow signed-out arrives with
	// the zero value even if they happen to hold a cookie by the time it returns.
	// The handler decides that from the intent recorded when the flow STARTED, not
	// from what is in hand now — see internal/httpapi/oauth.go for why, because a
	// cross-site GET can make a signed-in browser arrive here.
	LinkTo users.User

	UserAgent string
	IP        *netip.Addr
}

// Callback finishes a provider round trip and answers with whatever the caller
// needs next.
//
// IT RETURNS A LoginResult, not a social type of its own, and that is the second
// factor. The shape a caller gets here is decided by LoginResult.MFARequired and by
// nothing else, exactly as for a password login, which means an account with a
// confirmed second factor gets a CHALLENGE from a social callback and not a
// session. A social sign-in that minted a session for a two-factor account would be
// the single largest hole this file could have, and reusing the type is what makes
// it a hole somebody cannot add by accident: there is no field of this result from
// which a session can be had without the second factor having been presented.
func (s *SocialService) Callback(ctx context.Context, in SocialCallbackInput) (LoginResult, error) {
	if s.registry == nil {
		return LoginResult{}, ErrSocialNoProviders
	}

	provider, err := s.registry.Lookup(in.Provider)
	if err != nil {
		// Already a refusal the handler renders as 404. An endpoint that does not
		// exist and an endpoint whose resource does not exist are the same answer,
		// and neither of them says which providers this deployment configured.
		return LoginResult{}, err
	}

	tokens, err := s.client.Exchange(ctx, provider, in.Code)
	if err != nil {
		return LoginResult{}, err
	}
	// The address is only trusted once BOTH provider calls have succeeded, and the
	// order is not interchangeable: Exchange is what makes the token real, and
	// Identity is what turns it into a person. Asking first would spend a provider
	// call on a code that turns out to be worthless.
	identity, err := s.client.Identity(ctx, provider, tokens)
	if err != nil {
		return LoginResult{}, err
	}

	sealed, err := s.seal(tokens)
	if err != nil {
		return LoginResult{}, err
	}

	if !in.LinkTo.ID.IsZero() {
		return s.link(ctx, provider, identity, sealed, in)
	}
	return s.signIn(ctx, provider, identity, sealed, in)
}

// seal encrypts the access and refresh tokens for storage.
//
// BOTH ARE SEALED BEFORE ANY BRANCH RUNS, and that is the token-handling property
// this service holds to: the plaintext exists for the length of one function and
// goes nowhere else. It is not written into the user row, not written into the
// session, not put in an outbox event, and not logged. The reference's
// `connected_account_params` deletes the credentials out of the stored auth hash for
// the same reason — identity's schema has no auth-hash column, so the equivalent
// property is that the only place a provider token is ever written is the two
// `_ciphertext` columns.
//
// The refresh token is optional because GitHub issues none, and an empty one means
// SQL NULL rather than an empty string (see oauth.Store.Create).
func (s *SocialService) seal(tokens oauth.Tokens) (oauth.StoredTokens, error) {
	access, err := s.sealer.Seal(tokens.AccessToken)
	if err != nil {
		return oauth.StoredTokens{}, fmt.Errorf("sealing a provider access token: %w", err)
	}

	out := oauth.StoredTokens{AccessTokenCiphertext: access, ExpiresAt: tokens.ExpiresAt}
	if tokens.RefreshToken == "" {
		return out, nil
	}
	refresh, err := s.sealer.Seal(tokens.RefreshToken)
	if err != nil {
		return oauth.StoredTokens{}, fmt.Errorf("sealing a provider refresh token: %w", err)
	}
	out.RefreshTokenCiphertext = refresh
	return out, nil
}

// signIn is questions 1, 4 and 5: an account this provider identity already belongs
// to, a refusal, or a new account.
//
// # WHY A NEW USER GETS A PASSWORD NOBODY KNOWS
//
// `users.password_digest` is NOT NULL, and this schema has no "no password" state.
// The reference solves the same problem the same way (`user.password =
// SecureRandom.base58(24)`): hash 24 bytes of crypto/rand and throw the plaintext
// away. The consequence worth stating is that password login for this account is
// then IMPOSSIBLE rather than merely unlikely — there is no string that hashes to
// it — so a social account is a one-factor account unless the person also sets a
// password through the recovery flow, which is the correct shape and not a
// downgrade. Inventing a guessable placeholder here ("password") would put a login
// on the internet.
func (s *SocialService) signIn(
	ctx context.Context,
	provider oauth.Provider,
	identity oauth.Identity,
	sealed oauth.StoredTokens,
	in SocialCallbackInput,
) (LoginResult, error) {
	now := s.auth.clock.Now()

	account, err := s.store.ByProviderUID(ctx, s.auth.read.Queryer(), provider.Name, identity.ProviderUID)
	switch {
	case err == nil:
		return s.signInAs(ctx, account, sealed, in, now)

	case errors.Is(err, oauth.ErrNotFound):
		// Not seen before. Question 4 is asked here and ONLY here, and asking it
		// before the write rather than letting the unique index decide is the point:
		// `users.email` carries a unique index, so the write WOULD fail, and a
		// service that let the database raise it would answer 500 for a condition
		// it is required to recognise.
		existing, err := s.auth.users.ByEmail(ctx, s.auth.read.Queryer(), identity.Email)
		switch {
		case err == nil:
			// The refusal. `existing` is deliberately unused: naming the account
			// would turn one necessary bit into an inventory, and the handler's
			// detail sentence is a constant for the same reason.
			_ = existing
			return LoginResult{}, ErrSocialEmailInUse
		case errors.Is(err, users.ErrNotFound):
			return s.createAndSignIn(ctx, provider, identity, sealed, in, now)
		default:
			return LoginResult{}, fmt.Errorf("looking up a user by a provider's address: %w", err)
		}

	default:
		return LoginResult{}, fmt.Errorf("looking up a connected account: %w", err)
	}
}

// signInAs is question 1: this provider identity already belongs to somebody, so
// sign in as them.
//
// The freshly issued credential is written onto the existing row, which is what a
// re-consent produces and what keeps the stored copy from ageing into something
// unusable. It is written on the way IN and not on a later provider call, so the
// only copy of a token this service ever holds is the most recent one.
func (s *SocialService) signInAs(
	ctx context.Context,
	account oauth.Account,
	sealed oauth.StoredTokens,
	in SocialCallbackInput,
	now time.Time,
) (LoginResult, error) {
	user, err := s.auth.users.ByID(ctx, s.auth.read.Queryer(), account.UserID)
	if err != nil {
		// A connected account whose user is gone. `connected_accounts.user_id` is a
		// foreign key with ON DELETE CASCADE, so this cannot be a reachable state
		// and it is reported rather than handled: fabricating an identity to "recover"
		// from it would need an address the row does not have, and the honest
		// answer for a row that contradicts its own foreign key is that somebody
		// wrote to the database behind this service's back.
		return LoginResult{}, fmt.Errorf("connected account %s names a user that does not exist: %w",
			account.ID, err)
	}

	if err := s.store.RefreshTokens(ctx, s.auth.read.Queryer(), account.ID, sealed); err != nil {
		return LoginResult{}, fmt.Errorf("writing a refreshed provider credential: %w", err)
	}

	return s.auth.startLogin(ctx, user, LoginInput{UserAgent: in.UserAgent, IP: in.IP}, now)
}

// createAndSignIn is question 5: the user, their personal account, the ownership,
// the event and the connected account are ONE transaction, and the session follows.
//
// It is the same transaction Register uses, for the same reason and with the same
// ordering — the account before the membership, because `begin_account` happens
// between them and is transaction-local. What is added is the connected account,
// which is in the same transaction precisely because a user with no way to sign in
// again and a connected account with no user are the two halves of the same
// failure, and neither is repairable without reaching into the database.
func (s *SocialService) createAndSignIn(
	ctx context.Context,
	provider oauth.Provider,
	identity oauth.Identity,
	sealed oauth.StoredTokens,
	in SocialCallbackInput,
	now time.Time,
) (LoginResult, error) {
	digest, err := s.unusablePassword()
	if err != nil {
		return LoginResult{}, err
	}

	var created users.User
	err = s.auth.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		u, err := s.auth.users.Create(ctx, q, users.CreateParams{Email: identity.Email, PasswordDigest: digest})
		if err != nil {
			return err
		}
		if err := s.auth.provisionTenancy(ctx, q, u); err != nil {
			return err
		}
		event, err := outbox.NewUserCreated(now, u.ID, u.Email)
		if err != nil {
			return err
		}
		if err := s.auth.events.Append(ctx, q, event); err != nil {
			return err
		}
		// Last, and inside the same transaction. A unique-violation on
		// (provider, provider_uid) here means a concurrent callback for the same
		// provider identity won the race, and oauth.Store turns it into
		// ErrAlreadyLinked so the handler can answer 409 rather than 500.
		if _, err := s.store.Create(ctx, q, oauth.NewAccount{
			UserID:                 u.ID,
			Provider:               provider.Name,
			ProviderUID:            identity.ProviderUID,
			AccessTokenCiphertext:  sealed.AccessTokenCiphertext,
			RefreshTokenCiphertext: sealed.RefreshTokenCiphertext,
			ExpiresAt:              sealed.ExpiresAt,
		}); err != nil {
			return err
		}
		created = u
		return nil
	})
	if err != nil {
		return LoginResult{}, err
	}

	return s.auth.startLogin(ctx, created, LoginInput{UserAgent: in.UserAgent, IP: in.IP}, now)
}

// link is questions 2 and 3: the caller is signed in and is adding a second identity.
//
// # AND IT MINTS NO SESSION
//
// Linking is not signing in, and the result carries no token: the caller already
// has one. A 200 that handed back a fresh session would be a session minted by a
// third-party round trip, which is a credential whose lifetime this service chose
// for reasons the caller did not ask for.
//
// # AND IT DOES NOT ASK QUESTION 4
//
// See the file comment. The identity being attached is a fact about the provider's
// account, and its address colliding with another account's says nothing about who
// the caller is — the reference's `attach_account` does not ask it either, and a
// refusal here would block a legitimate operation for a reason that does not apply.
func (s *SocialService) link(
	ctx context.Context,
	provider oauth.Provider,
	identity oauth.Identity,
	sealed oauth.StoredTokens,
	in SocialCallbackInput,
) (LoginResult, error) {
	owner := in.LinkTo

	existing, err := s.store.ByProviderUID(ctx, s.auth.read.Queryer(), provider.Name, identity.ProviderUID)
	switch {
	case err == nil:
		if existing.UserID != owner.ID {
			// Question 2. Somebody else owns this provider identity and the caller
			// is signed in as somebody who does not. 409 and nothing else: a
			// redirect or a silent success would tell the caller their account is
			// linked to theirs when it is attached to another person's, which is
			// the exact state an attacker is trying to create.
			return LoginResult{}, oauth.ErrAlreadyLinked
		}
		// Already theirs, and they are asking again: a re-consent. Write the fresh
		// credential and answer 200 with no session.
		if err := s.store.RefreshTokens(ctx, s.auth.read.Queryer(), existing.ID, sealed); err != nil {
			return LoginResult{}, fmt.Errorf("writing a re-consented provider credential: %w", err)
		}
		return LoginResult{User: RegisteredUser{ID: owner.ID, Email: owner.Email}}, nil

	case errors.Is(err, oauth.ErrNotFound):
		_, err := s.store.Create(ctx, s.auth.read.Queryer(), oauth.NewAccount{
			UserID:                 owner.ID,
			Provider:               provider.Name,
			ProviderUID:            identity.ProviderUID,
			AccessTokenCiphertext:  sealed.AccessTokenCiphertext,
			RefreshTokenCiphertext: sealed.RefreshTokenCiphertext,
			ExpiresAt:              sealed.ExpiresAt,
		})
		if err != nil {
			// A concurrent callback for the same provider identity lost the race.
			return LoginResult{}, err
		}
		return LoginResult{User: RegisteredUser{ID: owner.ID, Email: owner.Email}}, nil

	default:
		return LoginResult{}, fmt.Errorf("looking up a connected account: %w", err)
	}
}

// unusablePassword hashes 24 bytes of crypto/rand and discards them, which is what
// gives a social account a `password_digest` that no password verifies against.
//
// Hashed through the same Hasher as a real password rather than written as a
// literal, so the column holds a real argon2id digest and nothing anywhere in this
// service can tell such an account apart by the shape of its digest.
func (s *SocialService) unusablePassword() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		// A degraded entropy source is a condition to stop on, for the reason
		// internal/oauth/cipher.go and internal/platform/id give: the alternative is
		// a digest of something predictable, and a predictable password is worse
		// than no account at all.
		return "", fmt.Errorf("reading random bytes for a social account's password: %w", err)
	}
	digest, err := s.auth.hasher.Hash(base64.RawURLEncoding.EncodeToString(raw))
	if err != nil {
		return "", fmt.Errorf("hashing a social account's placeholder password: %w", err)
	}
	return digest, nil
}

// identityFrom is gone, and the reason it was never written is the reason the
// dead-user branch above reports instead of recovering.
//
// `connected_accounts` stores the provider's identifier and NOT the address — the
// address is re-read from the provider on every callback, so it is never stale and
// never a lookup key. A row whose user has vanished therefore carries nothing that
// could stand in for a provider identity, and any function claiming to rebuild one
// would be inventing the field the whole schema declines to keep.
