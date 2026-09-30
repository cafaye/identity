package mfa

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/cafaye/identity/internal/outbox"
	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/sessions"
)

// The use cases, and the rule that runs through all of them.
//
// ADDING A FACTOR IS AUTHORIZED BY A SESSION. REMOVING OR REPLACING ONE IS NOT.
//
// An enrollment makes the account safer and there is nothing to prove about it
// beyond "you are signed in", because a user with a stolen session adding a
// second factor locks the thief out of the account they are in. Every route that
// makes the account LESS safe — disabling, replacing the secret, regenerating the
// recovery codes — requires a second factor first, because every one of them is
// something an attacker who has a session and wants to hide behind would like to
// do. That is the whole of re-authentication for a destructive security action,
// and it is why VerifyFactor exists as a separate call from the destructive write:
// the factor is checked, and only then does the write happen.

// UnitOfWork runs a function inside a transaction. db.TxRunner implements it; the
// interface is what lets the ordering rules be tested without Postgres.
type UnitOfWork interface {
	Do(ctx context.Context, fn func(ctx context.Context, q db.Querier) error) error
}

// CredentialStore is the slice of Store these use cases need.
//
// Declared here rather than taking *Store so a test can program a failure at the
// exact write that matters — a confirmation that loses its race, a claim that
// comes back false — without standing up a database.
type CredentialStore interface {
	CreateCredential(ctx context.Context, q db.Querier, p CreateCredentialParams) (Credential, error)
	CredentialByID(ctx context.Context, q db.Querier, rowID id.UUID) (Credential, error)
	ConfirmedCredential(ctx context.Context, q db.Querier, userID id.UUID) (Credential, error)
	PendingCredential(ctx context.Context, q db.Querier, userID, rowID id.UUID) (Credential, error)
	DeleteUnconfirmedFor(ctx context.Context, q db.Querier, userID id.UUID) error
	ConfirmCredential(ctx context.Context, q db.Querier, rowID id.UUID, at time.Time) (Credential, bool, error)
	DeleteCredential(ctx context.Context, q db.Querier, rowID id.UUID) error
	RecordFactorFailure(ctx context.Context, q db.Querier, rowID id.UUID, attempts int, lockedUntil *time.Time) error
	ClearFactorFailures(ctx context.Context, q db.Querier, rowID id.UUID) error
	InsertRecoveryCodes(ctx context.Context, q db.Querier, credentialID id.UUID, digests []string, at time.Time) error
	DeleteRecoveryCodesFor(ctx context.Context, q db.Querier, credentialID id.UUID) error
	UnusedRecoveryCode(ctx context.Context, q db.Querier, credentialID id.UUID, digest string) (id.UUID, error)
	ConsumeRecoveryCode(ctx context.Context, q db.Querier, codeID id.UUID, at time.Time) (bool, error)
	CountUnusedRecoveryCodes(ctx context.Context, q db.Querier, credentialID id.UUID) (int, error)
	ClaimStep(ctx context.Context, q db.Querier, credentialID id.UUID, step int64, at time.Time) (bool, error)
	PruneSteps(ctx context.Context, q db.Querier, credentialID id.UUID, below int64) error
	CreateChallenge(ctx context.Context, q db.Querier, p NewChallengeParams) (Challenge, error)
	DeleteSupersededChallenges(ctx context.Context, q db.Querier, userID id.UUID, keep id.UUID) error
	LiveChallenge(ctx context.Context, q db.Querier, token string, now time.Time) (Challenge, error)
	ConsumeChallenge(ctx context.Context, q db.Querier, challengeID id.UUID, at time.Time) (bool, error)
}

// EventAppender is the slice of outbox.Store these use cases need.
type EventAppender interface {
	Append(ctx context.Context, q db.Querier, e outbox.Envelope) error
}

// SessionRevoker ends every session a user holds.
//
// It is the sessions store's own method rather than a bespoke one, and it is a
// dependency rather than an import so the "a session minted before this change
// is not a credential after it" rule can be asserted in a test without a
// database.
type SessionRevoker interface {
	RevokeAllForUser(ctx context.Context, q db.Querier, userID id.UUID) error
}

// Service is the second-factor use cases.
type Service struct {
	uow      UnitOfWork
	read     db.QuerierSource
	store    CredentialStore
	events   EventAppender
	sessions SessionRevoker
	vault    Vault
	clk      clock.Clock
	issuer   string
	// pendingRotations says whether replacing a live secret is allowed at all.
	//
	// It is a field rather than a behaviour so the decision has one place: the
	// route that starts an enrollment reads it to decide whether to require a
	// factor, and the confirmation reads it to decide whether the old credential
	// is still there. Two places asking "is this a first enrollment or a
	// rotation" is two places for the answer to be different.
	pendingRotations bool
}

// NewService wires the use cases.
//
// vault may be mfa.Unavailable{}, and then every path that needs to read or write
// a secret fails with ErrNoVault. That is a supported value rather than a
// misconfiguration to be caught: a process with no MFA_ENCRYPTION_KEY still has
// to know which of its users have a second factor, and refusing to let those
// users in is the fail-closed answer.
func NewService(
	uow UnitOfWork,
	read db.QuerierSource,
	store CredentialStore,
	events EventAppender,
	revoker SessionRevoker,
	vault Vault,
	clk clock.Clock,
	issuer string,
) *Service {
	return &Service{
		uow:              uow,
		read:             read,
		store:            store,
		events:           events,
		sessions:         revoker,
		vault:            vault,
		clk:              clk,
		issuer:           issuer,
		pendingRotations: true,
	}
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

// Status is what GET /v1/mfa returns.
//
// RecoveryCodesRemaining is on it, and that is the packet's "the honest thing is
// to tell them before they get there": a user with zero recovery codes and a lost
// phone is a support ticket, and a client that can render "2 codes left — print
// a new set" while there are still two is the difference between a warning and a
// lockout. Nothing secret is here — a count is not a credential.
type Status struct {
	Enabled                bool
	Method                 string
	EnrolledAt             *time.Time
	RecoveryCodesRemaining int
}

// ---------------------------------------------------------------------------
// enrollment
// ---------------------------------------------------------------------------

// StartEnrollmentInput is a request to begin enrolling a second factor.
type StartEnrollmentInput struct {
	UserID id.UUID
	// Factor is the code presented to authorise a ROTATION. It is required when
	// the user already has a credential and ignored when they do not, and the
	// caller does not have to know which case it is: the use case resolves that
	// from the rows and says so.
	Factor string
}

// StartedEnrollment is the pending credential and the ONE-TIME values that go
// with it.
//
// Secret and ProvisioningURI are here and nowhere else. They are returned in the
// 201, never stored in the clear, and there is no endpoint that re-reads them: a
// user who loses the response starts a new enrollment, which mints a new secret.
// The reasoning is the one internal/oidc/service.go states for a client secret
// and it applies exactly — a secret this service can produce again is a secret
// this service is storing, and a stored TOTP secret is a second factor for
// whoever reads the database.
type StartedEnrollment struct {
	Credential      Credential
	Secret          string
	ProvisioningURI string
	// Replaced says whether a live credential is still in force behind this
	// pending one. It is what lets a client say "your old authenticator keeps
	// working until you confirm" rather than leaving the user to find out.
	Replaced bool
}

// StartEnrollment generates a secret and stores it, unconfirmed.
//
// The secret comes from pquerna/otp, which reads crypto/rand. Nothing in this
// package reads a random byte for a credential, and the base32 the user sees is
// the encoder's.
//
// A pending enrollment is NOT MFA. The row has confirmed_at NULL, the login path
// only ever reads confirmed rows, and the challenge is not created for a user
// whose credential is pending. That is what makes "stored but never confirmed"
// mean "authenticates nothing" rather than "authenticates, eventually" — the
// failure mode being a user locked out of their own account by a mistyped entry
// they cannot see the correct answer to.
//
// ReplacesPendingFor a user who already has a pending row: the old one is
// deleted first, so a user who opens the setup page five times holds one
// unconfirmed secret and not five.
func (s *Service) StartEnrollment(ctx context.Context, in StartEnrollmentInput) (StartedEnrollment, error) {
	now := s.clk.Now()
	q := s.read.Queryer()

	_, err := s.store.ConfirmedCredential(ctx, q, in.UserID)
	replacing := err == nil
	switch {
	case replacing:
		// A rotation reduces nothing and weakens a lot, so it is gated on a factor
		// exactly like disabling is. The factor is verified through the same
		// VerifyFactor the login uses, so there is one implementation of what a
		// valid second factor is.
		if _, err := s.VerifyFactor(ctx, in.UserID, in.Factor, now); err != nil {
			return StartedEnrollment{}, err
		}
	case errors.Is(err, ErrNotEnabled):
		// The first enrollment. A session is the whole of the authorization: the
		// caller is making the account harder to get into.
	default:
		return StartedEnrollment{}, fmt.Errorf("looking up the user's mfa credential: %w", err)
	}

	// pquerna/otp owns the generation, the base32 and the provisioning URI. The
	// issuer and account name it is handed are the two strings an authenticator
	// app displays, and the account name is the email because that is what a user
	// recognises when they are looking at a list of accounts inside the app.
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.issuer,
		AccountName: s.issuer,
		Period:      uint(Period / time.Second),
		SecretSize:  SecretSize,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return StartedEnrollment{}, fmt.Errorf("generating a TOTP secret: %w", err)
	}

	sealed, err := s.vault.Seal(in.UserID, key.Secret())
	if err != nil {
		return StartedEnrollment{}, err
	}

	expiresAt := now.Add(EnrollmentTTL)
	var started Credential
	err = s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		if err := s.store.DeleteUnconfirmedFor(ctx, q, in.UserID); err != nil {
			return err
		}
		created, err := s.store.CreateCredential(ctx, q, CreateCredentialParams{
			UserID:           in.UserID,
			Method:           MethodTOTP,
			SecretCiphertext: sealed,
			Digits:           Digits,
			PeriodSeconds:    int(Period / time.Second),
			Algorithm:        AlgorithmSHA1,
			Label:            s.label(in.UserID),
			ExpiresAt:        &expiresAt,
			CreatedAt:        now,
		})
		if err != nil {
			return err
		}
		started = created
		return nil
	})
	if err != nil {
		return StartedEnrollment{}, err
	}

	return StartedEnrollment{
		Credential:      started,
		Secret:          key.Secret(),
		ProvisioningURI: key.URL(),
		Replaced:        replacing,
	}, nil
}

// ConfirmInput confirms a pending enrollment.
type ConfirmInput struct {
	UserID       id.UUID
	EnrollmentID id.UUID
	// Factor is the code produced from the pending secret. Required always: an
	// unconfirmed enrollment is not a second factor yet, so this is the only
	// thing that makes it one.
	Factor string
}

// ConfirmedEnrollment is a live credential and its one-time recovery codes.
//
// RecoveryCodes are here and nowhere else. There is no endpoint that re-reads
// them and no column that stores them, only a SHA-256 digest per code — the
// reasoning is the one internal/oidc/service.go states for a client secret, and
// it is the reasoning the whole of this package is built on.
type ConfirmedEnrollment struct {
	Credential    Credential
	RecoveryCodes []string
	// ReplacedCredentialID is the live credential this confirmation superseded,
	// zero when there was none. It is not rendered; it is here so a caller that
	// wants to log what happened has the fact without a second query.
	ReplacedCredentialID id.UUID
}

// Confirm proves the user can produce a code from the pending secret, and makes it
// live.
//
// The confirmation is a CONDITIONAL UPDATE, and the winner of that race is the
// only caller that gets a row back. A confirm that arrives twice — a double tap,
// a retried request — does not confirm twice and does not mint a second set of
// recovery codes.
//
// FOUR WRITES IN ONE TRANSACTION, and the order is the argument:
//
//  1. confirm the pending row          (conditional: one winner)
//  2. delete the credential it replaced, if any
//  3. delete the old recovery codes and write the new set
//  4. revoke every session the user holds
//  5. append identity.mfa.enabled
//
// STEP FOUR IS THE ONE THAT IS EASY TO GET WRONG, and it is there because of a
// question the packet asks: what happens to a session that was issued before MFA
// was enabled? The answer is that it stops working, and it is the only defensible
// one. A session minted under a one-factor policy was minted on a password alone;
// leaving it alive after the user opts into a second factor means the attacker
// who has it does not have to solve the new problem at all. It costs the user
// every other device they were signed in on, which is a real price, and it is
// the price of the change actually meaning something.
//
// The same revocation is why a rotation replaces the old row in step 2 rather
// than keeping it: after a secret rotation the old secret's codes must be refused,
// and the way to refuse them is not to have the secret any more.
func (s *Service) Confirm(ctx context.Context, in ConfirmInput) (ConfirmedEnrollment, error) {
	now := s.clk.Now()
	q := s.read.Queryer()

	pending, err := s.store.PendingCredential(ctx, q, in.UserID, in.EnrollmentID)
	if err != nil {
		return ConfirmedEnrollment{}, err
	}
	if pending.ExpiresAt != nil && !pending.ExpiresAt.After(now) {
		return ConfirmedEnrollment{}, ErrEnrollmentNotFound
	}

	// The code is checked against the PENDING secret, before anything is
	// confirmed. A wrong code changes nothing, and the pending row stays so the
	// user can try again with the same authenticator they just set up.
	if _, err := s.matchPendingFactor(ctx, pending, in.Factor, now); err != nil {
		return ConfirmedEnrollment{}, err
	}

	// The live credential this replaces, read before the transaction so that step
	// 2 knows what to delete and so a user with no live credential is not treated
	// as a rotation.
	previous, previousErr := s.store.ConfirmedCredential(ctx, q, in.UserID)
	isRotation := previousErr == nil
	if previousErr != nil && !errors.Is(previousErr, ErrNotEnabled) {
		return ConfirmedEnrollment{}, fmt.Errorf("looking up the credential being replaced: %w", previousErr)
	}

	// The recovery codes are minted OUTSIDE the transaction. They are 80 bits of
	// crypto/rand per code and there are ten of them; holding a connection and a
	// transaction open for that is the same mistake auth.Register avoids by
	// hashing the password before it opens one.
	codes, err := NewRecoveryCodes()
	if err != nil {
		return ConfirmedEnrollment{}, err
	}

	var out ConfirmedEnrollment
	err = s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		confirmed, won, err := s.store.ConfirmCredential(ctx, q, pending.ID, now)
		if err != nil {
			return err
		}
		if !won {
			// Somebody confirmed it between the read and here. Refusing is the
			// honest answer: this caller cannot produce a second set of recovery
			// codes for a credential that is already live, because it does not
			// know the first set.
			return ErrEnrollmentNotFound
		}

		if isRotation {
			// The old secret stops being stored, which is how its codes stop
			// being accepted. The unique index mfa_credentials_one_live_per_user
			// is what proves the two could never have been live at the same time.
			if err := s.store.DeleteCredential(ctx, q, previous.ID); err != nil {
				return err
			}
			out.ReplacedCredentialID = previous.ID
		}

		if err := s.replaceRecoveryCodes(ctx, q, confirmed.ID, codes, now); err != nil {
			return err
		}

		// Every session minted before this moment was minted on a password alone.
		if err := s.sessions.RevokeAllForUser(ctx, q, in.UserID); err != nil {
			return err
		}

		event, err := outbox.NewMFAEnabled(now, in.UserID, confirmed.ID, confirmed.Method)
		if err != nil {
			return err
		}
		if err := s.events.Append(ctx, q, event); err != nil {
			return err
		}

		out.Credential = confirmed
		out.RecoveryCodes = codes
		return nil
	})
	if err != nil {
		return ConfirmedEnrollment{}, err
	}
	return out, nil
}

// matchPendingFactor checks a code against a pending credential's secret.
//
// It is the same match the login does — same library, same window, same
// comparison — against a different row. A pending credential has no spent-step
// table to consult, and does not need one: it is not a credential, and the code
// it is checked against is about to be thrown away with the secret if the check
// fails.
func (s *Service) matchPendingFactor(ctx context.Context, pending Credential, code string, now time.Time) (int64, error) {
	secret, err := s.vault.Open(pending.UserID, pending.SecretCiphertext)
	if err != nil {
		return 0, err
	}
	matched, ok := MatchStep(secret, code, now,
		itoa(pending.Digits), pending.Algorithm,
		time.Duration(pending.PeriodSeconds)*time.Second, SkewSteps)
	if !ok {
		return 0, ErrInvalidFactor
	}
	return matched, nil
}

// ---------------------------------------------------------------------------
// the challenge
// ---------------------------------------------------------------------------

// CreateChallengeInput is a request to record a login waiting on a factor.
type CreateChallengeInput struct {
	UserID    id.UUID
	UserAgent string
	IP        *netip.Addr
}

// NewChallenge is a fresh challenge and the ONE-TIME token that addresses it.
//
// Token is here and nowhere else: it goes into a cookie and into a response body
// exactly once, and the row holds sessions.Digest of it rather than the value.
// The reason is the reason every credential in this service is a digest — it
// travels in a header and in an operator's log aggregator, and a log aggregator
// is a place secrets go to be read by people who should not read them.
type NewChallenge struct {
	Challenge Challenge
	Token     string
	ExpiresAt time.Time
}

// CreateChallenge records a correct password with no session behind it.
//
// It is called by internal/auth and by nothing else, and the fact that it is
// exported is the shape of the packet's central rule rather than a convenience:
// the one place a login becomes a session is the transaction that follows this
// row, and this row exists to make sure that transaction has a second factor in
// it.
func (s *Service) CreateChallenge(ctx context.Context, in CreateChallengeInput) (NewChallenge, error) {
	now := s.clk.Now()
	expiresAt := now.Add(ChallengeTTL)

	// sessions.NewToken rather than a new minting routine: the same 256 bits from
	// the same CSPRNG, the same base64url, and the same digest the store will
	// look up. A second token format in this service is a second thing to
	// recognise in a log and a second thing to get wrong.
	token, digest, err := sessions.NewToken()
	if err != nil {
		return NewChallenge{}, fmt.Errorf("minting an mfa challenge token: %w", err)
	}

	var created Challenge
	err = s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		row, err := s.store.CreateChallenge(ctx, q, NewChallengeParams{
			UserID:      in.UserID,
			TokenDigest: digest,
			UserAgent:   in.UserAgent,
			IP:          in.IP,
			CreatedAt:   now,
			ExpiresAt:   expiresAt,
		})
		if err != nil {
			return err
		}
		// One live challenge per user. A second sign-in supersedes the first,
		// which bounds the table at a row per user with no sweeper.
		if err := s.store.DeleteSupersededChallenges(ctx, q, in.UserID, row.ID); err != nil {
			return err
		}
		created = row
		return nil
	})
	if err != nil {
		return NewChallenge{}, err
	}

	return NewChallenge{Challenge: created, Token: token, ExpiresAt: expiresAt}, nil
}

// Claim is a verified second factor, and the writes that record its acceptance.
//
// It is returned by VerifyFactor and spent by Commit, and the split is the
// atomicity requirement stated in one place rather than spread across two
// functions: Commit is called INSIDE the transaction that mints the session, so
// "the code was accepted" and "the session exists" are one fact. If the session
// write fails, the claim rolls back with it and the user's code still works
// because the service never told them it had been used.
//
// The fields are unexported because there is exactly one way to make a Claim —
// VerifyFactor — and a caller that could construct one itself would be able to
// skip the verification that produced it.
type Claim struct {
	userID       id.UUID
	credentialID id.UUID
	method       string
	// step is the TOTP counter this claim spends. Zero for a recovery code.
	step int64
	// recoveryCodeID is the row this claim spends. Zero for a TOTP code.
	recoveryCodeID id.UUID
	// challengeID is the challenge this claim closes, or zero when the factor was
	// presented directly — disabling, rotating and regenerating all do that.
	challengeID id.UUID
	// recoveryCodesRemaining is read BEFORE the consumption, so a caller that
	// spends the last one can say so.
	recoveryCodesRemaining int
}

// UserID is the user whose factor was accepted.
func (c Claim) UserID() id.UUID { return c.userID }

// Method is which kind of factor was accepted: MethodTOTP or
// MethodRecoveryCode. It is rendered in the response because the two have
// different consequences, and a user who has just spent a recovery code needs to
// be told that is what happened.
func (c Claim) Method() string { return c.method }

// RecoveryCodesRemaining is how many were left when the factor was accepted. For
// a TOTP code it is the current count; for a recovery code it is the count AFTER
// this one, so the number a user reads is the number they have.
func (c Claim) RecoveryCodesRemaining() int { return c.recoveryCodesRemaining }

// VerifyFactor checks a presented code against a user's live credential and
// returns the claim for it.
//
// It is the only implementation of "is this second factor acceptable", and every
// path in this service goes through it: the login challenge, disabling, replacing
// the secret, and regenerating the recovery codes. A second implementation would
// be a second answer to "does this user have a second factor" and the two would
// disagree about a locked credential, a replayed code and an expired enrollment.
//
// THE ORDER IS THE SECURITY PROPERTY, and it is the order auth.Login documents
// for the password:
//
//  1. Load the CONFIRMED credential. No credential, no factor, and a pending
//     enrollment is not one.
//  2. If the second factor's own counter has locked, refuse before verifying
//     anything — there is no reason to spend work on a credential nobody may use,
//     and it means a locked factor cannot be probed.
//  3. Decrypt the secret. A deployment with no key refuses here, closed.
//  4. Check the shape of the code, and match it: TOTP first, recovery second.
//  5. Claim the step, or find the unused recovery code. Either may come back
//     false, which is a replay and a loss of a race respectively, and both are
//     ErrInvalidFactor.
//  6. On any failure, count it and persist the count, on its OWN querier. A
//     lockout that is not written down is not a lockout.
//
// Step 5 is deliberately a CLAIM and not a check. It runs outside the
// transaction that will mint the session, so a claim that succeeds is one the
// service will honour; Commit then re-does it conditionally inside the
// transaction, and if another request got there first Commit's conditional
// statement returns false and the whole thing rolls back. Two claims, one winner,
// no lock held across the session write.
func (s *Service) VerifyFactor(ctx context.Context, userID id.UUID, code string, now time.Time) (Claim, error) {
	q := s.read.Queryer()

	credential, err := s.store.ConfirmedCredential(ctx, q, userID)
	if err != nil {
		return Claim{}, err
	}

	lock := sessions.Lockout{FailedAttempts: credential.FailedAttempts, LockedUntil: credential.LockedUntil}
	if lock.Locked(now) {
		return Claim{}, &sessions.LockedError{RetryAfter: lock.RetryAfter(now)}
	}

	claim, err := s.matchFactor(ctx, credential, code, now)
	if err != nil {
		// The failure is counted even though the factor is refused, and the count
		// is written outside any transaction the caller might roll back.
		next := lock.Failed(now)
		if recordErr := s.store.RecordFactorFailure(ctx, q, credential.ID, next.FailedAttempts, next.LockedUntil); recordErr != nil {
			// Surfaced, not reported as an invalid factor. A store failure that
			// looks like a wrong code stops the counter climbing, and the
			// brute-force protection silently stops existing.
			return Claim{}, fmt.Errorf("recording a failed second factor: %w", recordErr)
		}
		return Claim{}, err
	}
	return claim, nil
}

// VerifyChallenge checks a code against the credential the challenge names, and
// closes the challenge.
//
// The credential is read AT VERIFICATION TIME rather than named when the challenge
// was created, which is how the packet's "a login halfway through when the user
// enables MFA on another device" is answered without a second answer:
//
//   - MFA was DISABLED on the other device: there is no confirmed credential, so
//     VerifyFactor returns ErrNotEnabled and no session is minted. The user logs
//     in again and gets straight in, which is correct — they turned MFA off.
//   - MFA was ENABLED or ROTATED on the other device: the challenge verifies
//     against whatever is confirmed NOW. A code from the old secret does not match
//     the new one and is refused. A code from the new secret works, which is
//     right.
//
// Both fall out of reading the row late. Caching the credential id on the
// challenge would have made the first case a session minted for an account with
// no second factor.
func (s *Service) VerifyChallenge(ctx context.Context, token, code string, now time.Time) (Claim, error) {
	q := s.read.Queryer()

	challenge, err := s.store.LiveChallenge(ctx, q, token, now)
	if err != nil {
		return Claim{}, err
	}

	claim, err := s.VerifyFactor(ctx, challenge.UserID, code, now)
	if err != nil {
		return Claim{}, err
	}
	claim.challengeID = challenge.ID
	return claim, nil
}

// matchFactor is the body of a verification: the shape test, the TOTP match, the
// recovery lookup, and the claim for whichever one it was.
func (s *Service) matchFactor(ctx context.Context, credential Credential, code string, now time.Time) (Claim, error) {
	trimmed := trimCode(code)
	if trimmed == "" {
		return Claim{}, ErrInvalidFactor
	}

	q := s.read.Queryer()

	switch {
	case isTOTPCode(trimmed):
		secret, err := s.vault.Open(credential.UserID, credential.SecretCiphertext)
		if err != nil {
			return Claim{}, err
		}
		step, ok := MatchStep(secret, trimmed, now,
			itoa(credential.Digits), credential.Algorithm,
			time.Duration(credential.PeriodSeconds)*time.Second, SkewSteps)
		if !ok {
			return Claim{}, ErrInvalidFactor
		}
		spent, err := s.store.ClaimStep(ctx, q, credential.ID, step, now)
		if err != nil {
			return Claim{}, err
		}
		if !spent {
			// The replay. A code that is still inside its window and has already
			// been accepted. ErrInvalidFactor and not something of its own, because
			// the one legitimate cause — a user who pasted the same code twice — is
			// not something to confirm and an attacker who could tell a replay from
			// a wrong guess knows to stop guessing.
			return Claim{}, ErrInvalidFactor
		}
		remaining, err := s.store.CountUnusedRecoveryCodes(ctx, q, credential.ID)
		if err != nil {
			return Claim{}, err
		}
		return Claim{
			userID:                 credential.UserID,
			credentialID:           credential.ID,
			method:                 MethodTOTP,
			step:                   step,
			recoveryCodesRemaining: remaining,
		}, nil

	case IsRecoveryCode(trimmed):
		codeID, err := s.store.UnusedRecoveryCode(ctx, q, credential.ID, RecoveryDigest(trimmed))
		if err != nil {
			return Claim{}, err
		}
		spent, err := s.store.ConsumeRecoveryCode(ctx, q, codeID, now)
		if err != nil {
			return Claim{}, err
		}
		if !spent {
			return Claim{}, ErrInvalidFactor
		}
		remaining, err := s.store.CountUnusedRecoveryCodes(ctx, q, credential.ID)
		if err != nil {
			return Claim{}, err
		}
		return Claim{
			userID:                 credential.UserID,
			credentialID:           credential.ID,
			method:                 MethodRecoveryCode,
			recoveryCodeID:         codeID,
			recoveryCodesRemaining: remaining,
		}, nil

	default:
		// Neither shape. One query, no round trip, and the same answer as a wrong
		// code of a recognised shape.
		return Claim{}, ErrInvalidFactor
	}
}

// Commit spends a claim, inside the caller's transaction.
//
// Every statement here is conditional, and each one returning false is a lost
// race that rolls the whole transaction back — including the session write the
// caller has already done. That is the point: two requests carrying the same
// code resolve to one session, not two.
//
// Commit also clears the second factor's failure run, because "this factor was
// accepted" and "the run against this factor is over" are one fact and the
// mirror of what auth does for the password on the same transaction.
func (s *Service) Commit(ctx context.Context, q db.Querier, claim Claim, now time.Time) error {
	if claim.step > 0 {
		spent, err := s.store.ClaimStep(ctx, q, claim.credentialID, claim.step, now)
		if err != nil {
			return err
		}
		if !spent {
			return ErrInvalidFactor
		}
		// Bounded by construction: everything below the oldest step still inside
		// the window can no longer be presented, so it goes now. This is the whole
		// of the table's housekeeping, and it needs no sweeper.
		oldest := StepAt(now, Period) - int64(SkewSteps+1)
		if err := s.store.PruneSteps(ctx, q, claim.credentialID, oldest); err != nil {
			return err
		}
	}

	if !claim.recoveryCodeID.IsZero() {
		spent, err := s.store.ConsumeRecoveryCode(ctx, q, claim.recoveryCodeID, now)
		if err != nil {
			return err
		}
		if !spent {
			return ErrInvalidFactor
		}
	}

	if !claim.challengeID.IsZero() {
		consumed, err := s.store.ConsumeChallenge(ctx, q, claim.challengeID, now)
		if err != nil {
			return err
		}
		if !consumed {
			return ErrChallengeNotFound
		}
	}

	return s.store.ClearFactorFailures(ctx, q, claim.credentialID)
}

// ---------------------------------------------------------------------------
// the destructive routes
// ---------------------------------------------------------------------------

// RegenerateRecoveryCodesInput is a request for a new set of recovery codes.
type RegenerateRecoveryCodesInput struct {
	UserID id.UUID
	// Factor authorises the regeneration. It is not optional and there is no
	// route that reaches this use case without one: handing out ten fresh codes is
	// equivalent to handing out ten fresh ways into the account, so it takes the
	// same proof that disabling does.
	Factor string
}

// RegeneratedRecoveryCodes is the new set and the count that replaced it.
type RegeneratedRecoveryCodes struct {
	RecoveryCodes []string
	IssuedAt      time.Time
}

// RegenerateRecoveryCodes issues a new set and destroys the old one.
//
// DELETE THEN INSERT, ONE TRANSACTION, and the atomicity is the whole requirement:
// a partial write leaves a user with two live sets, which is a second recovery path
// through codes nobody audited and nobody will ever see in a log. So the two
// statements share a transaction with the factor's acceptance, and a rollback
// leaves the original set intact rather than a half-empty one.
//
// The set is returned once. There is no endpoint that re-reads it and no column
// that stores it, only digests.
func (s *Service) RegenerateRecoveryCodes(ctx context.Context, in RegenerateRecoveryCodesInput) (RegeneratedRecoveryCodes, error) {
	now := s.clockNow()

	claim, err := s.VerifyFactor(ctx, in.UserID, in.Factor, now)
	if err != nil {
		return RegeneratedRecoveryCodes{}, err
	}

	codes, err := NewRecoveryCodes()
	if err != nil {
		return RegeneratedRecoveryCodes{}, err
	}

	err = s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		if err := s.Commit(ctx, q, claim, now); err != nil {
			return err
		}
		return s.replaceRecoveryCodes(ctx, q, claim.credentialID, codes, now)
	})
	if err != nil {
		return RegeneratedRecoveryCodes{}, err
	}
	return RegeneratedRecoveryCodes{RecoveryCodes: codes, IssuedAt: now}, nil
}

// DisableInput is a request to turn the second factor off.
type DisableInput struct {
	UserID id.UUID
	// Factor authorises the change. A password is NOT accepted here and there is no
	// path through this service that would let one be: re-authentication for a
	// destructive security action is the entire reason it exists, and a user who
	// has MFA enabled but whose phone is at home cannot disable it with the
	// password they already proved at login.
	Factor string
}

// Disable turns the second factor off, announces it, and ends every session.
//
// THREE WRITES, ONE TRANSACTION, and the order is chosen so the two facts that
// matter cannot come apart: the credential is gone, every session is revoked, and
// identity.mfa.disabled is announced.
//
// Revoking every session is the part the packet names, and the reason it is here
// rather than in a session middleware is that a user who turns MFA off has very
// often had it turned off FOR them — by somebody who got in with the password
// while the phone was elsewhere. Every session in existence was minted under a
// two-factor policy, and none of them should still be a credential afterwards.
//
// No event, no request, no change to the password. This service does not send
// mail, and an event without one is the only honest thing available to it.
func (s *Service) Disable(ctx context.Context, in DisableInput) error {
	now := s.clockNow()

	claim, err := s.VerifyFactor(ctx, in.UserID, in.Factor, now)
	if err != nil {
		return err
	}

	return s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		credential, err := s.store.CredentialByID(ctx, q, claim.credentialID)
		if err != nil {
			return err
		}
		if err := s.store.DeleteCredential(ctx, q, credential.ID); err != nil {
			return err
		}
		if err := s.sessions.RevokeAllForUser(ctx, q, in.UserID); err != nil {
			return err
		}
		event, err := outbox.NewMFADisabled(now, in.UserID, credential.Method)
		if err != nil {
			return err
		}
		return s.events.Append(ctx, q, event)
	})
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// StatusFor is what GET /v1/mfa reads.
//
// A user with no credential is `{"enabled": false}` and not a 404: the question
// "do I have a second factor" has an answer for every signed-in user, and a
// client asking it before rendering a settings page should not have to
// distinguish "you have none" from "this is not your account".
func (s *Service) StatusFor(ctx context.Context, userID id.UUID) (Status, error) {
	q := s.read.Queryer()

	credential, err := s.store.ConfirmedCredential(ctx, q, userID)
	if errors.Is(err, ErrNotEnabled) {
		return Status{Enabled: false}, nil
	}
	if err != nil {
		return Status{}, fmt.Errorf("looking up the user's mfa credential: %w", err)
	}

	remaining, err := s.store.CountUnusedRecoveryCodes(ctx, q, credential.ID)
	if err != nil {
		return Status{}, err
	}
	return Status{
		Enabled:                true,
		Method:                 credential.Method,
		EnrolledAt:             credential.ConfirmedAt,
		RecoveryCodesRemaining: remaining,
	}, nil
}

// Enabled reports whether the user has a live second factor. It is the question
// internal/auth asks after a correct password, and it is the question whose wrong
// answer is a login with one factor where there should be two.
func (s *Service) Enabled(ctx context.Context, q db.Querier, userID id.UUID) (bool, error) {
	_, err := s.store.ConfirmedCredential(ctx, q, userID)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, ErrNotEnabled):
		return false, nil
	default:
		return false, fmt.Errorf("looking up the user's mfa credential: %w", err)
	}
}

// replaceRecoveryCodes empties a credential's set and writes a new one.
func (s *Service) replaceRecoveryCodes(ctx context.Context, q db.Querier, credentialID id.UUID, codes []string, now time.Time) error {
	if err := s.store.DeleteRecoveryCodesFor(ctx, q, credentialID); err != nil {
		return err
	}
	digests := make([]string, 0, len(codes))
	for _, code := range codes {
		digests = append(digests, RecoveryDigest(code))
	}
	return s.store.InsertRecoveryCodes(ctx, q, credentialID, digests, now)
}

// clockNow is the one place a use case reads time, so the whole package is
// testable with a parked clock.
func (s *Service) clockNow() time.Time { return s.clk.Now() }

// label is what an authenticator app displays next to the entry. The account name
// is the issuer rather than the email because the provisioning URI is built before
// the use case knows anything else about the user, and an app that shows a
// service name plus an account name is legible when a user has two accounts in
// two authenticators.
func (s *Service) label(id.UUID) string { return s.issuer }
