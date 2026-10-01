package recovery

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cafaye/identity/internal/outbox"
	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/sessions"
	"github.com/cafaye/identity/internal/users"
)

// The use cases: the three flows, and the rules that govern them.
//
// Nothing here knows about HTTP. The handlers translate the errors in recovery.go
// into the cafaye error envelope; they do not define what a token is.

// UnitOfWork runs a function inside a transaction. db.TxRunner implements it; the
// interface is the seam that lets the ordering below be tested without Postgres.
type UnitOfWork interface {
	Do(ctx context.Context, fn func(ctx context.Context, q db.Querier) error) error
}

// TokenStore is the slice of the recovery_tokens table these use cases need.
//
// Declared here rather than taking *Store, for the reason every other store
// interface in this repository is: a test can program a failure at the exact write
// that matters — a token that loses its race, a send that fails — without standing
// up a database.
type TokenStore interface {
	Create(ctx context.Context, q db.Querier, n NewToken) (Token, error)
	Live(ctx context.Context, q db.Querier, digest string, purpose Purpose, now time.Time) (Token, error)
	LiveTarget(ctx context.Context, q db.Querier, digest string, purpose Purpose, now time.Time) (Token, error)
	NewestLive(ctx context.Context, q db.Querier, userID id.UUID, purpose Purpose, now time.Time) (Token, error)
	Consume(ctx context.Context, q db.Querier, tokenID id.UUID, at time.Time) (bool, error)
	MintTarget(ctx context.Context, q db.Querier, tokenID id.UUID, digest string, at time.Time) (Token, error)
	ConsumeTarget(ctx context.Context, q db.Querier, tokenID id.UUID, at time.Time) (Token, error)
}

// UserStore is the slice of users.Store the three flows need.
//
// IT IS DECLARED HERE RATHER THAN REUSING ONE, because these flows need the three
// WRITES that change a credential — the password, the address, the verification —
// and putting them on a shared surface would be a statement about `users` made by a
// different package.
type UserStore interface {
	ByEmail(ctx context.Context, q db.Querier, email string) (users.User, error)
	ByID(ctx context.Context, q db.Querier, userID id.UUID) (users.User, error)
	SetPassword(ctx context.Context, q db.Querier, userID id.UUID, digest string) error
	SetEmail(ctx context.Context, q db.Querier, userID id.UUID, email string) error
	MarkEmailVerified(ctx context.Context, q db.Querier, userID id.UUID, at time.Time) (bool, error)
}

// SessionRevoker ends every browser session a user holds.
//
// IT IS THE sessions STORE'S OWN METHOD rather than a bespoke one, and it is a
// dependency rather than an import for the reason internal/mfa takes the same one:
// "a session that was minted before this change is no longer a credential" has to
// be assertable in a test without a database.
type SessionRevoker interface {
	RevokeAllForUser(ctx context.Context, q db.Querier, userID id.UUID) error
}

// AccessTokenRevoker ends every OpenID Connect access token a user holds.
//
// THIS IS THE SAME RULE ONE SURFACE OVER, and it is here because "a reset that
// leaves the old session alive is not a reset" is a claim about every credential
// this service issued, not about the one it happens to resolve itself. A JWT is
// opaque to everybody else, so "it expires in fifteen minutes" is not an answer
// this service can give on the user's behalf.
//
// It is an interface for the reason SessionRevoker is: the table is internal/oidc's
// and the RULE is this package's, and an import in both directions would be an edge
// between two tables with nothing to say to each other.
type AccessTokenRevoker interface {
	RevokeAccessTokensForUser(ctx context.Context, q db.Querier, userID id.UUID, at time.Time) error
}

// EventAppender is the slice of outbox.Store these flows need.
type EventAppender interface {
	Append(ctx context.Context, q db.Querier, e outbox.Envelope) error
}

// Service is the recovery use cases.
type Service struct {
	uow      UnitOfWork
	read     db.QuerierSource
	tokens   TokenStore
	users    UserStore
	sessions SessionRevoker
	access   AccessTokenRevoker
	events   EventAppender
	mailer   Mailer
	hasher   *users.Hasher
	clk      clock.Clock
}

// NewService wires the use cases.
//
// mailer may be Unavailable{}, and then every path that needs to send a message
// fails with ErrNoMailer rather than pretending. See the package comment for why
// the alternative — a logger, or a nil — is not on the table.
func NewService(
	uow UnitOfWork,
	read db.QuerierSource,
	tokens TokenStore,
	userStore UserStore,
	revoker SessionRevoker,
	access AccessTokenRevoker,
	events EventAppender,
	mailer Mailer,
	hasher *users.Hasher,
	clk clock.Clock,
) *Service {
	return &Service{
		uow:      uow,
		read:     read,
		tokens:   tokens,
		users:    userStore,
		sessions: revoker,
		access:   access,
		events:   events,
		mailer:   mailer,
		hasher:   hasher,
		clk:      clk,
	}
}

// Verification is what GET /v1/email-verification answers.
//
// It is a type rather than a bare `users.User` because the HTTP layer must not be
// able to render a password digest by being handed the domain row — which is the
// reason `internal/httpapi` projects every other user it returns into a two-field
// type. Three fields, one of which is a fact rather than a claim.
type Verification struct {
	Email      string
	Verified   bool
	VerifiedAt *time.Time
}

// VerificationStatus reports whether the caller's own address has been proved.
//
// IT IS A READ AND NOT A DERIVATION from something else, and the distinction
// matters to a client: an unverified address is not an error and not an absent
// account, it is the state every account is in until somebody follows a link. So
// the answer is a 200 with a boolean rather than a 404 — the same shape decision
// GET /v1/mfa made for "do I have a second factor".
func (s *Service) VerificationStatus(ctx context.Context, userID id.UUID) (Verification, error) {
	user, err := s.users.ByID(ctx, s.read.Queryer(), userID)
	if err != nil {
		return Verification{}, err
	}
	return Verification{
		Email:      user.Email,
		Verified:   user.IsVerified(),
		VerifiedAt: user.EmailVerifiedAt,
	}, nil
}

// ---------------------------------------------------------------------------
// password reset
// ---------------------------------------------------------------------------

// RequestPasswordReset asks for a reset link, and reveals nothing about whether
// the address has an account.
//
// IT RETURNS AN ERROR FOR EXACTLY TWO REASONS, and neither of them is "no such
// account". A malformed address is a 422 about the caller's own input, and
// ErrNoMailer is a 503 about this deployment. A registered address and an
// unregistered one both return nil, and both produce the same status and the same
// body — `internal/httpapi`'s acceptedResponse is a constant for exactly that
// reason.
//
// THE ORDER IS THE SECURITY PROPERTY:
//
//  1. Check the mailer. Before the lookup, not after: with no delivery path every
//     request stops here, so a deployment that cannot send mail cannot be turned
//     into an existence oracle by the fact that one address gets further than the
//     other.
//  2. Normalise and validate the address, through the same users.NormalizeEmail
//     every other entry point uses, so "Kaka@Example.com" finds the row stored as
//     "kaka@example.com".
//  3. Look the user up. A miss returns nil.
//  4. Refuse inside RequestWindow, which mints nothing and sends nothing.
//  5. Mint, store the digest, mail the token.
//
// STEP 3 IS WHERE THE TIMING CHANNEL IS, and it is worth naming rather than
// claiming otherwise. Everything this service controls is symmetric: the same
// normalisation, the same validation, the same indexed equality lookup, the same
// token mint, the same digest. What is NOT symmetric is the delivery call itself,
// and closing that would mean mailing a reset link to every address an attacker
// typed — which is the mail cannon this endpoint would then be. So the residual is
// documented rather than closed: with a real Mailer, a request for a registered
// address costs one message and a request for an unregistered one costs none.
//
// THE COOLDOWN IS NOT A LOCKOUT. Nothing here counts failures, nothing here is
// countable by an attacker, and a user inside the window gets exactly the answer
// one outside it gets. See RequestWindow.
func (s *Service) RequestPasswordReset(ctx context.Context, email string) error {
	// (1) Before the lookup. See the order above.
	if err := s.deliverable(ctx); err != nil {
		return err
	}

	// (2)
	normalized := users.NormalizeEmail(email)
	if err := users.ValidateEmail(normalized); err != nil {
		return err
	}

	now := s.clk.Now()
	q := s.read.Queryer()

	// (3) A miss is the same answer as a hit.
	user, err := s.users.ByEmail(ctx, q, normalized)
	if err != nil {
		if errors.Is(err, users.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("recovery: looking up the account for a reset: %w", err)
	}

	// (4)
	if s.insideWindow(ctx, q, user.ID, PurposePasswordReset, now) {
		return nil
	}

	// (5)
	return s.mintAndSend(ctx, mintParams{
		UserID:  user.ID,
		Purpose: PurposePasswordReset,
		Kind:    messageReset,
		Email:   normalized,
		Now:     now,
	})
}

// RedeemPasswordResetInput is a token and the password to move to.
type RedeemPasswordResetInput struct {
	Token    string
	Password string
}

// RedeemPasswordResult is what a completed reset returns.
//
// It carries the ADDRESS rather than a user id, and that is the point: the caller
// of this route is anonymous and holds a token, so the one thing the service may
// tell them is which address the token was for. It is an address they already typed
// into the request that produced the link, and a user id would be a second
// identifier handed to an unauthenticated caller for no benefit.
type RedeemPasswordResult struct {
	Email string
}

// RedeemPasswordReset changes a password, spends the token, and ends every
// credential the account held.
//
// FOUR WRITES IN ONE TRANSACTION, and the order is the argument:
//
//  1. hash the new password   (outside the transaction — argon2id is ~100ms of
//     memory-hard work and holding a connection open for it
//     is the mistake auth.Register documents)
//  2. write the new digest and clear the lockout
//  3. revoke every session, and every OIDC access token
//  4. append identity.session.revoked
//
// STEP 3 IS THE PACKET'S REQUIREMENT AND IT IS NOT OPTIONAL. "A reset that leaves
// the old session alive is not a reset" is the whole of it: a user resetting
// because they think somebody else has their password would still be sharing the
// account with whoever has the cookie, and the mailbox they just proved they can
// read is the one piece of evidence that this reset was really theirs. Every
// session goes, including one on the device making this request, which is the
// price and is documented rather than surprising.
//
// WHAT IT DOES NOT REVOKE IS A SCOPED API KEY, and that is a decision rather than
// an omission. README.md already records it for MFA: revoking somebody's machine
// credentials because they changed a password breaks an unrelated CI job with
// nothing in the response saying why, and the owner of that credential named it
// deliberately and can revoke it themselves. A session is a cookie a person cannot
// see; an api key is a string in a CI secret. The reset ends the first and not the
// second.
//
// THE TOKEN IS SPENT INSIDE THE TRANSACTION, and conditionally. A reset that
// committed the new password and then failed to spend the token would leave a
// working link for an account whose password has already moved, which is a second
// way into the account for whoever holds it.
func (s *Service) RedeemPasswordReset(ctx context.Context, in RedeemPasswordResetInput) (RedeemPasswordResult, error) {
	// (1) Validation before the hash, exactly as auth.Login does it: a malformed
	// request should not cost a memory-hard operation.
	if err := users.ValidatePassword(in.Password); err != nil {
		return RedeemPasswordResult{}, err
	}
	digest, err := s.hasher.Hash(in.Password)
	if err != nil {
		return RedeemPasswordResult{}, fmt.Errorf("recovery: hashing the new password: %w", err)
	}

	now := s.clk.Now()

	// The token is resolved OUTSIDE the transaction, for the reason auth.Login reads
	// the user first: it costs no write, and the spend below is the authority rather
	// than this read.
	live, err := s.tokens.Live(ctx, s.read.Queryer(), sessions.Digest(in.Token), PurposePasswordReset, now)
	if err != nil {
		return RedeemPasswordResult{}, err
	}

	var out RedeemPasswordResult
	err = s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		spent, err := s.tokens.Consume(ctx, q, live.ID, now)
		if err != nil {
			return err
		}
		if !spent {
			// Somebody redeemed it between the read above and here. The honest answer
			// is the one a spent token gets, and the transaction rolls back rather
			// than writing a password nobody may change.
			return ErrTokenNotFound
		}

		if err := s.users.SetPassword(ctx, q, live.UserID, digest); err != nil {
			return err
		}
		if err := s.revokeEveryCredential(ctx, q, live.UserID, now); err != nil {
			return err
		}

		event, err := outbox.NewSessionsRevoked(now, live.UserID, "password reset")
		if err != nil {
			return err
		}
		if err := s.events.Append(ctx, q, event); err != nil {
			return err
		}

		user, err := s.users.ByID(ctx, q, live.UserID)
		if err != nil {
			return err
		}
		out = RedeemPasswordResult{Email: user.Email}
		return nil
	})
	if err != nil {
		return RedeemPasswordResult{}, err
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// address verification
// ---------------------------------------------------------------------------

// RequestVerification asks for a link that proves the caller reads this account's
// address.
//
// IT HAS THE SAME SHAPE AND THE SAME ANSWER AS A RESET REQUEST — one status, one
// body, whatever the row says — because the two endpoints have the same question
// behind them ("does an account exist for this address?") and only one of them
// being careful would leave the other as the oracle.
//
// A verified address is refused with ErrAlreadyVerified rather than quietly
// ignored. The caller is a product, and a product told "we emailed you" on the
// strength of a request that was refused renders a confirmation screen the user
// then cannot leave.
func (s *Service) RequestVerification(ctx context.Context, email string) error {
	if err := s.deliverable(ctx); err != nil {
		return err
	}

	normalized := users.NormalizeEmail(email)
	if err := users.ValidateEmail(normalized); err != nil {
		return err
	}

	now := s.clk.Now()
	q := s.read.Queryer()

	user, err := s.users.ByEmail(ctx, q, normalized)
	if err != nil {
		if errors.Is(err, users.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("recovery: looking up the account to verify: %w", err)
	}
	if user.IsVerified() {
		return ErrAlreadyVerified
	}
	if s.insideWindow(ctx, q, user.ID, PurposeVerifyEmail, now) {
		return nil
	}

	return s.mintAndSend(ctx, mintParams{
		UserID:  user.ID,
		Purpose: PurposeVerifyEmail,
		Kind:    messageVerify,
		Email:   normalized,
		Now:     now,
	})
}

// RedeemVerificationInput is the token from a verification link.
type RedeemVerificationInput struct {
	Token string
}

// RedeemVerification changes nothing about the credential and records one fact: a
// person proved they can read the address on this row.
//
// IT REVOKES NOTHING, and that is the difference from a password reset worth
// stating rather than assuming. A verification changes no secret and grants no
// access: the account could already sign in with exactly the same password and the
// same second factor. What it changes is what this service is willing to SAY about
// the address, which is a fact about the address and not about the account's
// authority — so ending the account's sessions would punish somebody for clicking
// a link, which is the opposite of the intent.
//
// NO SESSION IS MINTED EITHER. The caller reached the screen that says "your
// address is confirmed" through its own login; a token is not a session, and this
// route has no business turning possession of an inbox into a browser credential
// that nothing else in this service issues.
func (s *Service) RedeemVerification(ctx context.Context, in RedeemVerificationInput) error {
	now := s.clk.Now()

	live, err := s.tokens.Live(ctx, s.read.Queryer(), sessions.Digest(in.Token), PurposeVerifyEmail, now)
	if err != nil {
		return err
	}

	return s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		spent, err := s.tokens.Consume(ctx, q, live.ID, now)
		if err != nil {
			return err
		}
		if !spent {
			return ErrTokenNotFound
		}
		if _, err := s.users.MarkEmailVerified(ctx, q, live.UserID, now); err != nil {
			return err
		}
		event, err := outbox.NewUserEmailVerified(now, live.UserID)
		if err != nil {
			return err
		}
		return s.events.Append(ctx, q, event)
	})
}

// ---------------------------------------------------------------------------
// email change
// ---------------------------------------------------------------------------

// RequestEmailChangeInput is a signed-in user and the address they want.
type RequestEmailChangeInput struct {
	UserID id.UUID
	Email  string
}

// EmailChange is an in-flight change: where the account is, and where it is going.
type EmailChange struct {
	CurrentEmail string
	NewEmail     string
	ExpiresAt    time.Time
}

// RequestEmailChange starts a move to a new address.
//
// IT REQUIRES A CALLER, and the HTTP layer is what enforces it. Unlike a reset or a
// verification this route is session-gated, because what it starts is destructive
// and the mailbox it writes to first is the account's own: a credential that could
// start an email change is a credential that can move an account's recovery path,
// and there is no scope in the machine vocabulary for that.
//
// THE TWO VALIDATIONS ARE DELIBERATE AND BOTH ARE ANSWERED:
//
//	ErrSameAddress   the request describes a move to where the account already is.
//	                 Refused, because a 202 here would leave a caller believing a
//	                 change had been requested.
//	ErrEmailTaken    somebody else already has this address. Answered HERE, at the
//	                 first step, rather than at the last one: the alternative is two
//	                 emails and two clicks before a change that could never have
//	                 applied. It is not an existence oracle — the caller is
//	                 authenticated and typed the address themselves, which is the
//	                 same disclosure POST /v1/users already makes and the one place
//	                 in this service where it is safe.
//
// What comes back is a row whose FIRST token is the only token that exists. The
// new-address token is minted when the first is confirmed, and
// `recovery_tokens_target_needs_a_confirmed_first_side` is the schema's own
// version of that sentence.
//
// A request inside RequestWindow is refused rather than quietly ignored, and the
// error it gets is ErrSameAddress. That reads oddly and it is the honest answer
// available: the caller asked to move the account to a new address, and inside the
// window the answer is "there is already a change in flight for this account, wait
// for it" — which is what a second change in one minute means, whether or not the
// two were typed by the same person.
func (s *Service) RequestEmailChange(ctx context.Context, in RequestEmailChangeInput) (EmailChange, error) {
	if err := s.deliverable(ctx); err != nil {
		return EmailChange{}, err
	}

	normalized := users.NormalizeEmail(in.Email)
	if err := users.ValidateEmail(normalized); err != nil {
		return EmailChange{}, err
	}

	now := s.clk.Now()
	q := s.read.Queryer()

	user, err := s.users.ByID(ctx, q, in.UserID)
	if err != nil {
		return EmailChange{}, err
	}
	if user.Email == normalized {
		return EmailChange{}, ErrSameAddress
	}
	if _, err := s.users.ByEmail(ctx, q, normalized); err == nil {
		return EmailChange{}, ErrEmailTaken
	} else if !errors.Is(err, users.ErrNotFound) {
		return EmailChange{}, fmt.Errorf("recovery: checking whether the new address is taken: %w", err)
	}
	if s.insideWindow(ctx, q, user.ID, PurposeEmailChange, now) {
		return EmailChange{}, ErrSameAddress
	}

	if err := s.mintAndSend(ctx, mintParams{
		UserID:  user.ID,
		Purpose: PurposeEmailChange,
		Kind:    messageChangeFirst,
		Email:   user.Email,
		Target:  normalized,
		Now:     now,
	}); err != nil {
		return EmailChange{}, err
	}

	return EmailChange{
		CurrentEmail: user.Email,
		NewEmail:     normalized,
		ExpiresAt:    now.Add(TTLFor(PurposeEmailChange)),
	}, nil
}

// ConfirmEmailChangeCurrentInput is the token from the message sent to the account's
// CURRENT address.
type ConfirmEmailChangeCurrentInput struct {
	Token string
}

// ConfirmEmailChangeCurrent proves control of the address the account has now, and
// mints the token for the address it is moving to.
//
// THE SECOND TOKEN IS MINTED HERE AND NOWHERE ELSE, and that is the whole of the
// hijack property. Whoever starts a change — including somebody holding a stolen
// session — gets a link in the OWNER's inbox and no other mail at all. They cannot
// advance the request, and the owner receives a message naming the account, which
// is the only warning they would otherwise get.
//
// THE WRITE IS ONE STATEMENT (`MintTarget`) for the reason that store method gives:
// confirming the current address and creating the new-address token are one fact,
// and a rollback that undid only half of it would leave a user who did exactly what
// the mail asked with a change that can never complete.
func (s *Service) ConfirmEmailChangeCurrent(ctx context.Context, in ConfirmEmailChangeCurrentInput) (EmailChange, error) {
	now := s.clk.Now()
	q := s.read.Queryer()

	live, err := s.tokens.Live(ctx, q, sessions.Digest(in.Token), PurposeEmailChange, now)
	if err != nil {
		return EmailChange{}, err
	}
	if live.TargetEmail == "" {
		// Unreachable while the schema's CHECK holds — an email_change row always
		// carries a target. Checked anyway because the consequence of trusting it is
		// a message sent with an empty address in it.
		return EmailChange{}, ErrTokenNotFound
	}

	user, err := s.users.ByID(ctx, q, live.UserID)
	if err != nil {
		return EmailChange{}, err
	}

	targetToken, targetDigest, err := sessions.NewToken()
	if err != nil {
		return EmailChange{}, fmt.Errorf("recovery: minting an email change token for the new address: %w", err)
	}

	if err := s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		_, err := s.tokens.MintTarget(ctx, q, live.ID, targetDigest, now)
		return err
	}); err != nil {
		return EmailChange{}, err
	}

	// The message is rendered and delivered AFTER the transaction, for the same
	// reason the reset's is: a delivery that failed with the row still written
	// leaves a token nobody holds, which expires harmlessly, whereas a delivery
	// inside a transaction that then rolled back would be a message whose link does
	// not work — and the user has just been told it does.
	if err := s.send(ctx, messageChangeNew, messageData{
		Email:  user.Email,
		Target: live.TargetEmail,
		Token:  targetToken,
		Expiry: live.ExpiresAt,
		To:     live.TargetEmail,
	}); err != nil {
		return EmailChange{}, err
	}

	return EmailChange{CurrentEmail: user.Email, NewEmail: live.TargetEmail, ExpiresAt: live.ExpiresAt}, nil
}

// ConfirmEmailChangeNewInput is the token from the message sent to the NEW address.
type ConfirmEmailChangeNewInput struct {
	Token string
}

// ConfirmEmailChangeNew moves the account, spends both tokens, and ends every
// credential it held. It returns the row as it now stands.
//
// THIS IS THE ONLY PLACE AN EMAIL CHANGES, and it takes the same shape as a reset:
// spend the token, write the row, revoke everything the account had, announce it,
// all in one transaction. A change that moved the address and left the sessions
// alive would leave an attacker holding a cookie to an account whose recovery mail
// now goes somewhere else — which is worse than the reset case, because the
// password was never what was compromised.
//
// `users.Store.SetEmail` CLEARS THE VERIFICATION in the same statement, so the row
// lands UNVERIFIED and the new address has to be confirmed on its own. Clicking a
// link proves you can read an inbox; it does not prove the new address is this
// account's, and a service that conflated the two would let anybody point their
// email at a stranger's inbox and keep a verified claim on it.
//
// ErrEmailTaken is still possible here even though RequestEmailChange checked:
// that check was minutes or hours ago, on a different request, and somebody else
// may have registered the address since. It is answered as a 409 rather than
// swallowed, because "your address did not change and here is why" is a sentence a
// person who just clicked a link needs.
func (s *Service) ConfirmEmailChangeNew(ctx context.Context, in ConfirmEmailChangeNewInput) (users.User, error) {
	now := s.clk.Now()

	live, err := s.tokens.LiveTarget(ctx, s.read.Queryer(), sessions.Digest(in.Token), PurposeEmailChange, now)
	if err != nil {
		return users.User{}, err
	}

	var out users.User
	err = s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		spent, err := s.tokens.ConsumeTarget(ctx, q, live.ID, now)
		if err != nil {
			return err
		}
		if spent.ID.IsZero() {
			// Unreachable: ConsumeTarget answers ErrTokenNotFound rather than a zero
			// row. Guarded anyway, because a store that returned a zero value for
			// success would move an account on a token nobody redeemed.
			return ErrTokenNotFound
		}

		if err := s.users.SetEmail(ctx, q, live.UserID, spent.TargetEmail); err != nil {
			return err
		}
		if err := s.revokeEveryCredential(ctx, q, live.UserID, now); err != nil {
			return err
		}

		event, err := outbox.NewSessionsRevoked(now, live.UserID, "email address changed")
		if err != nil {
			return err
		}
		if err := s.events.Append(ctx, q, event); err != nil {
			return err
		}

		updated, err := s.users.ByID(ctx, q, live.UserID)
		if err != nil {
			return err
		}
		out = updated
		return nil
	})
	if err != nil {
		return users.User{}, err
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// deliverable reports whether this deployment can send a message at all.
//
// IT IS CHECKED BEFORE EVERY LOOKUP, in every flow, and that is the whole of it.
// ErrNoMailer is a property of the seam rather than a `mailer != Unavailable{}`
// type assertion in three places, so a Mailer that is present-but-cannot-deliver
// reports the same thing one that is absent does, and neither can be bypassed by a
// new flow forgetting to ask.
func (s *Service) deliverable(ctx context.Context) error {
	if s.mailer == nil {
		return ErrNoMailer
	}
	return s.mailer.Ready(ctx)
}

// insideWindow reports whether this user already asked for this purpose inside
// RequestWindow.
//
// A LOOKUP FAILURE IS NOT TREATED AS "INSIDE THE WINDOW", and that is the direction
// that matters: the consequence of getting it wrong is a message the user did not
// need, and the consequence of the other direction is a cooldown that silently
// stops existing because a database blip turned it off. A broken throttle should be
// a throttle that is not applying.
func (s *Service) insideWindow(ctx context.Context, q db.Querier, userID id.UUID, purpose Purpose, now time.Time) bool {
	newest, err := s.tokens.NewestLive(ctx, q, userID, purpose, now)
	if err != nil {
		return false
	}
	return now.Sub(newest.CreatedAt) < RequestWindow
}

// revokeEveryCredential ends every session and every OIDC access token a user
// holds.
//
// IT IS ONE FUNCTION CALLED FROM TWO FLOWS, because "a credential minted before this
// moment is not a credential after it" is one rule with two tables under it, and a
// second implementation would be a second place for the two to disagree about what
// a reset revokes.
func (s *Service) revokeEveryCredential(ctx context.Context, q db.Querier, userID id.UUID, at time.Time) error {
	if err := s.sessions.RevokeAllForUser(ctx, q, userID); err != nil {
		return err
	}
	return s.access.RevokeAccessTokensForUser(ctx, q, userID, at)
}

// send renders and delivers one message, and nothing else.
func (s *Service) send(ctx context.Context, kind messageKind, data messageData) error {
	message, err := messageFor(kind, data)
	if err != nil {
		return err
	}
	message.To = data.To
	if message.To == "" {
		// A message with no recipient is a bug in the caller above, and delivering
		// it would be worse than refusing it: the seam would have to invent one.
		return fmt.Errorf("recovery: refusing to send the %s message to no address", kind)
	}
	return s.mailer.Send(ctx, message)
}

// mintAndSend is the shape every request flow has: mint, store the digest, mail the
// value. Writing it once is what keeps "the digest the row was written with" and
// "the token in the message" the same value BY CONSTRUCTION rather than by care —
// the two come out of one sessions.NewToken call and there is no third path.
func (s *Service) mintAndSend(ctx context.Context, p mintParams) error {
	token, digest, err := sessions.NewToken()
	if err != nil {
		return fmt.Errorf("recovery: minting a %s token: %w", p.Purpose, err)
	}

	expiresAt := p.Now.Add(TTLFor(p.Purpose))
	if err := s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		_, err := s.tokens.Create(ctx, q, NewToken{
			UserID:      p.UserID,
			Purpose:     p.Purpose,
			Digest:      digest,
			TargetEmail: p.Target,
			CreatedAt:   p.Now,
			ExpiresAt:   expiresAt,
		})
		return err
	}); err != nil {
		return err
	}

	return s.send(ctx, p.Kind, messageData{
		Email:  p.Email,
		Target: p.Target,
		Token:  token,
		Expiry: expiresAt,
		To:     p.Recipient(),
	})
}

// mintParams is the input to mintAndSend.
//
// Recipient is a method rather than a field because WHICH address a flow mails is a
// decision inside the flow and not a thing a caller gets to state: the reset and
// the verification mail the address on the row, and the first half of an email
// change mails the CURRENT one rather than the one being moved to. Writing it as
// one method is what makes that the only answer a caller can reach.
type mintParams struct {
	UserID  id.UUID
	Purpose Purpose
	Kind    messageKind
	// Email is the address on the row, which is what every body names.
	Email string
	// Target is the address being moved to. It is empty for a reset or a
	// verification, and it is also the RECIPIENT for the first half of an email
	// change and never for the second.
	Target string
	Now    time.Time
}

// Recipient is where this flow's message goes.
//
// IT IS `Email` AND NEVER `Target`, and that is the flow rather than a
// simplification: an email change's FIRST message goes to the address the account
// has now, and the address it is moving to is written to only after that one has
// been confirmed. A stolen session therefore cannot make this service send a
// message to a stranger's inbox at all — the stranger's address is not a recipient
// anywhere in this package except the one place a legitimate user has already
// proved they read it.
func (p mintParams) Recipient() string { return p.Email }
