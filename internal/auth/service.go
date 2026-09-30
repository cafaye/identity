// Package auth is the identity use cases: register, log in, log out, and resolve
// a token to the user it belongs to.
//
// It sits between the HTTP layer and the three aggregates that own the data
// (users, sessions, outbox) because the interesting part of authentication is
// not any one of them — it is the ordering, and the transactions. Checking the
// lock before the password, counting a failure even though the login is refused,
// and writing a session and its clearing of the failure counter together are all
// properties of the use case, not of a handler and not of a table.
//
// Nothing here knows about HTTP. The handlers translate the errors below into the
// cafaye error envelope (core: docs/openapi-conventions.md).
package auth

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/cafaye/identity/internal/accounts"
	"github.com/cafaye/identity/internal/mfa"
	"github.com/cafaye/identity/internal/outbox"
	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/sessions"
	"github.com/cafaye/identity/internal/users"
)

// Errors the HTTP layer maps onto status codes.
//
// The two credential errors are the important ones. They are distinct values so
// that the code says what happened, but ErrInvalidCredentials is deliberately the
// *same* value for "no such account" and "wrong password", and its message is
// deliberately identical in both cases. Anything that distinguishes them — a
// different status, a different detail string, a different response time — is an
// account-enumeration oracle.
var (
	// ErrInvalidCredentials is a refused login. The caller cannot tell why.
	ErrInvalidCredentials = errors.New("invalid email or password")

	// ErrUnauthenticated is a request with no usable credential: no token, an
	// unknown one, an expired one, or a revoked one. One value for all four.
	ErrUnauthenticated = errors.New("authentication required")
)

// LockedError is a login refused because the account is locked.
//
// It is an ALIAS, not a type of its own. The type lives in internal/sessions
// because the second factor's lockout is the same shape — same policy, same
// response, one 423 — and the HTTP layer matches the type rather than the source
// so that a caller who exhausts five TOTP guesses and a caller who exhausts five
// passwords are told the same thing. Declaring it here as well would give the
// layer two types to match and a bug the day it matched the wrong one.
type LockedError = sessions.LockedError

// DefaultSessionTTL is how long a session lasts when nothing overrides it.
const DefaultSessionTTL = 30 * 24 * time.Hour

// UnitOfWork runs a function inside a transaction. db.TxRunner implements it; the
// interface is what lets the lockout matrix be tested without Postgres.
type UnitOfWork interface {
	Do(ctx context.Context, fn func(ctx context.Context, q db.Querier) error) error
}

// UserStore is the part of users.Store that login and registration need.
type UserStore interface {
	Create(ctx context.Context, q db.Querier, p users.CreateParams) (users.User, error)
	ByEmail(ctx context.Context, q db.Querier, email string) (users.User, error)
	ByID(ctx context.Context, q db.Querier, id id.UUID) (users.User, error)
	RecordFailedLogin(ctx context.Context, q db.Querier, userID id.UUID, attempts int, lockedUntil *time.Time) error
	ClearFailures(ctx context.Context, q db.Querier, userID id.UUID) error
}

// SessionStore is the part of sessions.Store that login, logout and resolution
// need.
type SessionStore interface {
	Create(ctx context.Context, q db.Querier, n sessions.NewSession) (sessions.Session, error)
	ByToken(ctx context.Context, q db.Querier, token string, now time.Time) (sessions.Session, error)
	Revoke(ctx context.Context, q db.Querier, sessionID id.UUID) error
}

// SecondFactor is the part of internal/mfa that login needs, and it is REQUIRED.
//
// It is an interface declared here, at the consumer, for the same reason
// UserStore and SessionStore are, and it is the fourth thing Login cannot work
// without. The alternative — a nil check, or a default that answers "no" — is how
// a service ends up issuing single-factor sessions for users whose accounts have
// a second factor, and that failure is silent by construction: every login works,
// every login is one factor short, and nothing in the logs says so. NewService
// refuses a nil one, and Login refuses to mint a session without it.
//
// Three methods, and each one is a decision rather than a lookup:
//
//	Enabled          is this user's account two-factor right now
//	CreateChallenge  record a correct password with no session behind it
//	VerifyChallenge  check a code and claim what it spent
//	Commit           finish the acceptance, inside the session's transaction
type SecondFactor interface {
	Enabled(ctx context.Context, q db.Querier, userID id.UUID) (bool, error)
	CreateChallenge(ctx context.Context, in mfa.CreateChallengeInput) (mfa.NewChallenge, error)
	VerifyChallenge(ctx context.Context, token, code string, now time.Time) (mfa.Claim, error)
	Commit(ctx context.Context, q db.Querier, claim mfa.Claim, now time.Time) error
}

// EventAppender is the part of outbox.Store that registration needs.
type EventAppender interface {
	Append(ctx context.Context, q db.Querier, e outbox.Envelope) error
}

// PersonalAccountProvisioner is the part of the accounts service that
// registration needs: the personal account a new user gets, and the ownership
// that makes it theirs.
//
// It is an interface declared here, at the consumer, for the same reason
// UserStore and SessionStore are. It is also the reason its two methods take a
// db.Querier rather than opening their own transaction: they run inside the
// registration's, and a user who exists with no account is a state nothing
// downstream can repair.
//
// It is a required dependency rather than an optional one. A nil provisioner
// would mean a service that registers users into a void, and the failure would
// show up as a user with an empty account list rather than as a startup error —
// which is the worse of the two by a long way.
type PersonalAccountProvisioner interface {
	// Provision creates the personal account for a user.
	Provision(ctx context.Context, q db.Querier, userID id.UUID, email string) (accounts.Account, error)
	// AddOwner makes that user the account's owner, and announces the account.
	AddOwner(ctx context.Context, q db.Querier, accountID, userID id.UUID) (accounts.Membership, error)
}

// Service is the identity use cases.
type Service struct {
	uow        UnitOfWork
	read       db.QuerierSource
	users      UserStore
	sessions   SessionStore
	events     EventAppender
	tenancy    PersonalAccountProvisioner
	mfa        SecondFactor
	hasher     *users.Hasher
	clock      clock.Clock
	sessionTTL time.Duration
}

// ErrNoSecondFactor means this auth service has no second-factor dependency
// wired, so it cannot answer the question "does this user's account have a second
// factor" and therefore cannot know whether a correct password may mint a
// session.
//
// It is an error and not a degraded single-factor mode, and the direction of the
// refusal is the whole point: a login that proceeds without being able to check is
// exactly the bypass MFA exists to prevent. main wires the real dependency
// whenever it has a database, so reaching this is a wiring bug at a call site
// rather than a supported configuration.
var ErrNoSecondFactor = errors.New("logging in: no second-factor service is configured")

// NewService wires the use cases. A non-positive sessionTTL means
// DefaultSessionTTL.
//
// uow is used for the writes that must be atomic with each other — the user, its
// personal account, the ownership and the two events; and the session, the
// challenge it answers and the two failure counters it clears. read is used for
// everything else, so those lookups do not pay for a transaction.
//
// secondFactor is required. See ErrNoSecondFactor.
func NewService(
	uow UnitOfWork,
	read db.QuerierSource,
	userStore UserStore,
	sessionStore SessionStore,
	events EventAppender,
	tenancy PersonalAccountProvisioner,
	secondFactor SecondFactor,
	hasher *users.Hasher,
	clk clock.Clock,
	sessionTTL time.Duration,
) *Service {
	if sessionTTL <= 0 {
		sessionTTL = DefaultSessionTTL
	}
	return &Service{
		uow:        uow,
		read:       read,
		users:      userStore,
		sessions:   sessionStore,
		events:     events,
		tenancy:    tenancy,
		mfa:        secondFactor,
		hasher:     hasher,
		clock:      clk,
		sessionTTL: sessionTTL,
	}
}

// RegisterInput is a registration request.
type RegisterInput struct {
	Email    string
	Password string
}

// RegisteredUser is what a successful registration returns: the public projection
// of the user and nothing else.
//
// It is its own type rather than users.User so that the digest cannot reach a
// response body by accident. Adding a field to users.User does not add it here.
type RegisteredUser struct {
	ID    id.UUID
	Email string
}

// Register creates a user, their personal account, and announces both.
//
// The five writes — user, account, owner membership, `identity.user.created` and
// `identity.account.created` — are one transaction. That is the whole reason the
// outbox exists and the whole reason the provisioner takes a Querier: a user
// without its event would never be announced, an event without its user would
// announce a registration that did not happen, and a user without an account is
// somebody who has signed up and can do nothing at all.
//
// Does not create a session. Sign in separately.
func (s *Service) Register(ctx context.Context, in RegisterInput) (RegisteredUser, error) {
	email := users.NormalizeEmail(in.Email)
	if err := validateRegistration(email, in.Password); err != nil {
		return RegisteredUser{}, err
	}

	// Hashed before the transaction opens. Validation has already passed, so this
	// cannot fail for a request-shaped reason, and doing it outside keeps a ~100ms
	// memory-hard operation from holding a database connection and a transaction
	// open.
	digest, err := s.hasher.Hash(in.Password)
	if err != nil {
		return RegisteredUser{}, fmt.Errorf("hashing the password: %w", err)
	}

	now := s.clock.Now()

	var created users.User
	err = s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		u, err := s.users.Create(ctx, q, users.CreateParams{Email: email, PasswordDigest: digest})
		if err != nil {
			return err
		}

		// The tenancy comes before the events, because an event about an account
		// that does not exist is exactly the drift the outbox is supposed to
		// prevent. The user id is needed for both the slug and the ownership, so
		// this is the first point at which it can happen at all.
		if err := s.provisionTenancy(ctx, q, u); err != nil {
			return err
		}

		// The event is about this user, so it is built after the insert: the
		// subject is an id that now exists.
		event, err := outbox.NewUserCreated(now, u.ID, u.Email)
		if err != nil {
			return err
		}
		if err := s.events.Append(ctx, q, event); err != nil {
			return err
		}

		created = u
		return nil
	})
	if err != nil {
		return RegisteredUser{}, err
	}

	return RegisteredUser{ID: created.ID, Email: created.Email}, nil
}

// provisionTenancy creates the personal account and makes the user its owner,
// inside the registration's transaction.
//
// The two steps are separate rather than one call because the packet's ordering
// is the point: the account's slug is derived from the user id, and the ownership
// is what makes the account administrable. A service that created the membership
// first would have no account to attach it to.
func (s *Service) provisionTenancy(ctx context.Context, q db.Querier, u users.User) error {
	if s.tenancy == nil {
		// NewService requires a provisioner, so this is a wiring bug rather than a
		// supported configuration. It is said out loud rather than defaulted,
		// because the alternative — registering a user into an account-less void —
		// is a failure that would not surface until somebody complained that the
		// product was empty.
		return errors.New("registering: no personal account provisioner is configured")
	}

	account, err := s.tenancy.Provision(ctx, q, u.ID, u.Email)
	if err != nil {
		return fmt.Errorf("creating the personal account: %w", err)
	}
	if _, err := s.tenancy.AddOwner(ctx, q, account.ID, u.ID); err != nil {
		return fmt.Errorf("granting ownership of the personal account: %w", err)
	}
	return nil
}

// LoginInput is a login request.
type LoginInput struct {
	Email    string
	Password string
	// UserAgent and IP are recorded against the session for the incident trail.
	// Neither is trusted for any decision.
	UserAgent string
	IP        *netip.Addr
}

// LoginResult is what a successful login returns.
//
// It is one type with three shapes rather than three types, and the shape is
// decided by MFARequired and by nothing else:
//
//	MFARequired false  Token is a session token, Challenge is nil
//	MFARequired true   Token is EMPTY, Challenge is not nil
//
// THE EMPTY TOKEN IS THE POINT, and it is the shape of the mistake this whole
// package exists to prevent. A caller that ignores MFARequired and reads Token
// gets the empty string, which authenticates nothing, rather than a working
// credential. There is no field of this struct from which a session can be
// obtained without the second factor having been presented, and
// TestAResultThatRequiresASecondFactorCarriesNoSessionToken is the assertion.
type LoginResult struct {
	User RegisteredUser
	// Token and ExpiresAt are the SESSION's, and both are zero unless
	// MFARequired is false.
	Token     string
	ExpiresAt time.Time

	// MFARequired says the password was correct and this account has a second
	// factor. No session exists yet, and ExpiresAt is the CHALLENGE's expiry
	// rather than a session's, which is why it is repeated here rather than left
	// confusing: a client that reads ExpiresAt without reading MFARequired is
	// holding a challenge's deadline, and the only honest thing it can do with it
	// is nothing until it has the second factor.
	MFARequired bool
	// Challenge is the login that is halfway through. nil whenever a session was
	// minted.
	Challenge *Challenge
}

// Challenge is a login waiting on its second factor.
type Challenge struct {
	// Token is presented once, at the end of the challenge, and is stored only as
	// a digest. The same reasoning as an OIDC client secret: a secret this service
	// can produce again is a secret this service is storing.
	Token     string
	ExpiresAt time.Time
}

// Login authenticates an email and password.
//
// The order of the checks is the security property, so it is spelled out:
//
//  1. Validate the shape of the request. A malformed address never reaches argon2id.
//  2. Look the account up. A miss costs a dummy hash and returns
//     ErrInvalidCredentials — the same error, from the same path, in the same time
//     as a wrong password.
//  3. If the account is locked, return LockedError *before* verifying anything.
//     There is no reason to spend a memory-hard hash on an account nobody may log
//     into, and it means a locked account cannot be probed.
//  4. Verify the password.
//  5. On a mismatch, count the failure, persist it, and return
//     ErrInvalidCredentials.
//  6. On a match: ask whether this account has a CONFIRMED second factor.
//     If it does, mint a CHALLENGE and return MFARequired — no session, no token,
//     nothing that authenticates anything.
//  7. Otherwise mint the session and clear the password's failure run in one
//     transaction.
//
// STEP 6 IS THE LINE THIS PACKET IS ABOUT, and it sits where it does on purpose:
// after the password has been verified and before the session is created. A
// challenge is not a session, and a session created here for an account with a
// second factor is a login with one factor where there should be two — which is
// not a weaker version of MFA, it is the absence of it.
//
// Note what step 6 does NOT do: it does not clear the password's failure run. The
// password was right, but the login is not finished, and the run is cleared in
// CompleteSecondFactor, in the transaction that mints the session. Clearing it
// here would let five wrong passwords cost an attacker nothing while they work on
// the second factor.
func (s *Service) Login(ctx context.Context, in LoginInput) (LoginResult, error) {
	email := users.NormalizeEmail(in.Email)
	if err := validateLogin(email, in.Password); err != nil {
		return LoginResult{}, err
	}

	now := s.clock.Now()

	user, err := s.users.ByEmail(ctx, s.read.Queryer(), email)
	if err != nil {
		if !errors.Is(err, users.ErrNotFound) {
			return LoginResult{}, fmt.Errorf("looking up a user: %w", err)
		}
		// No such account. Do the same memory-hard work a real account would cost
		// and return the same error, so neither the response nor its timing says
		// whether this address is registered. Nothing is written: there is no row
		// to count against, and creating one would let anyone lock any address out
		// simply by guessing at it.
		s.hasher.VerifyDummy(in.Password)
		return LoginResult{}, ErrInvalidCredentials
	}

	lock := sessions.Lockout{FailedAttempts: user.FailedLoginAttempts, LockedUntil: user.LockedUntil}
	if lock.Locked(now) {
		return LoginResult{}, &LockedError{RetryAfter: lock.RetryAfter(now)}
	}

	if !s.hasher.Verify(user.PasswordDigest, in.Password) {
		// The failure is counted even though the login is refused, and the count
		// is persisted. A lockout that is not written down is not a lockout.
		next := lock.Failed(now)
		if err := s.recordFailure(ctx, user.ID, next); err != nil {
			// Surfaced, not reported as invalid credentials: a store failure that
			// looks like a wrong password stops the counter climbing, and the
			// brute-force protection silently stops existing.
			return LoginResult{}, fmt.Errorf("recording a failed login: %w", err)
		}
		return LoginResult{}, ErrInvalidCredentials
	}

	required, err := s.requiresSecondFactor(ctx, user.ID)
	if err != nil {
		return LoginResult{}, err
	}
	if required {
		return s.startChallenge(ctx, user, in, now)
	}

	return s.startSession(ctx, user, in, now)
}

// requiresSecondFactor asks internal/mfa whether this account has a live second
// factor, and refuses to guess.
func (s *Service) requiresSecondFactor(ctx context.Context, userID id.UUID) (bool, error) {
	if s.mfa == nil {
		return false, ErrNoSecondFactor
	}
	required, err := s.mfa.Enabled(ctx, s.read.Queryer(), userID)
	if err != nil {
		return false, fmt.Errorf("checking whether this account has a second factor: %w", err)
	}
	return required, nil
}

// startChallenge records a correct password with no session behind it.
//
// It is a separate function from startSession rather than a branch inside one,
// because the two write different things and a merge would make "which of these
// ran" a question about a boolean.
func (s *Service) startChallenge(ctx context.Context, user users.User, in LoginInput, now time.Time) (LoginResult, error) {
	challenge, err := s.mfa.CreateChallenge(ctx, mfa.CreateChallengeInput{
		UserID:    user.ID,
		UserAgent: in.UserAgent,
		IP:        in.IP,
	})
	if err != nil {
		return LoginResult{}, fmt.Errorf("creating a second-factor challenge: %w", err)
	}

	// No session. No token. Nothing that authenticates anything.
	//
	// ExpiresAt IS SET, to the CHALLENGE's expiry. It is the same field a session
	// uses, so leaving it zero would be a second, subtler version of the same bug —
	// a client reading `expires_at` would see the epoch and have to special-case it.
	// Repeating the challenge's deadline here means a client that reads only
	// ExpiresAt is holding a value it can use, and the value it can use is the
	// honest one: when this login has to be finished.
	return LoginResult{
		User:        RegisteredUser{ID: user.ID, Email: user.Email},
		ExpiresAt:   challenge.ExpiresAt,
		MFARequired: true,
		Challenge:   &Challenge{Token: challenge.Token, ExpiresAt: challenge.ExpiresAt},
	}, nil
}

// CompleteSecondFactorInput is a challenge token and the code that answers it.
type CompleteSecondFactorInput struct {
	// ChallengeToken is the token from the Login that returned MFARequired.
	ChallengeToken string
	// Code is a TOTP code or a recovery code. One field for both, because the
	// consequence of being wrong is identical and two fields would invite a client
	// to put a recovery code in the TOTP field and be told it was malformed rather
	// than not accepted.
	Code string
}

// CompleteSecondFactor answers a challenge and, only then, mints the session.
//
// THE ORDER IS THE WHOLE THING:
//
//  1. VerifyFactor (through mfa) matches the code and CLAIMS what it spent,
//     counting a failure and writing the counter itself if it does not match.
//  2. One transaction: consume the challenge, create the session, clear BOTH
//     failure counters.
//
// There is no branch, and there is no path through this method that returns a
// session without step 1 having succeeded. That is what makes the service's
// second factor a second factor.
//
// The two counters clear together and in this transaction for the reason the
// password's clears with the session in startSession: a counter that clears
// without the login it was counting towards completing hands an attacker a free
// reset every time they get it wrong. The second factor's counter lives on a
// different row from the password's, and both are cleared here — a successful
// two-factor login restarts both runs and neither one survives on its own.
func (s *Service) CompleteSecondFactor(ctx context.Context, in CompleteSecondFactorInput) (LoginResult, error) {
	if s.mfa == nil {
		return LoginResult{}, ErrNoSecondFactor
	}
	if in.ChallengeToken == "" {
		return LoginResult{}, ErrUnauthenticated
	}

	now := s.clock.Now()

	// Outside the transaction, and deliberately: this writes the second factor's
	// failure counter when the code is wrong, and a counter rolled back along with
	// the refusal it provoked is not a counter.
	claim, err := s.mfa.VerifyChallenge(ctx, in.ChallengeToken, in.Code, now)
	if err != nil {
		return LoginResult{}, err
	}

	token, digest, err := sessions.NewToken()
	if err != nil {
		return LoginResult{}, fmt.Errorf("minting a session token: %w", err)
	}
	expiresAt := now.Add(s.sessionTTL)

	err = s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		// The session is created first, for the reason startSession gives: if it
		// fails the transaction rolls back and the challenge is still live, so the
		// user can press "try again" rather than being told their login has
		// expired. The order of the other two is not load-bearing — they are both
		// accounting and the transaction covers all three.
		if _, err := s.sessions.Create(ctx, q, sessions.NewSession{
			UserID:      claim.UserID(),
			TokenDigest: digest,
			ExpiresAt:   expiresAt,
		}); err != nil {
			return err
		}
		// Consumes the challenge and clears the second factor's failure run.
		if err := s.mfa.Commit(ctx, q, claim, now); err != nil {
			return err
		}
		return s.users.ClearFailures(ctx, q, claim.UserID())
	})
	if err != nil {
		return LoginResult{}, err
	}

	user, err := s.users.ByID(ctx, s.read.Queryer(), claim.UserID())
	if err != nil {
		return LoginResult{}, fmt.Errorf("loading the user behind a second-factor login: %w", err)
	}

	return LoginResult{
		User:      RegisteredUser{ID: user.ID, Email: user.Email},
		Token:     token,
		ExpiresAt: expiresAt,
	}, nil
}

// startSession mints the session and clears the failure run together.
func (s *Service) startSession(ctx context.Context, user users.User, in LoginInput, now time.Time) (LoginResult, error) {
	token, digest, err := sessions.NewToken()
	if err != nil {
		return LoginResult{}, fmt.Errorf("minting a session token: %w", err)
	}
	expiresAt := now.Add(s.sessionTTL)

	err = s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		// The session is created first. If it fails, the transaction rolls back
		// and the counter is untouched — which is the safe direction, because a
		// reset with no session would hand an attacker five free attempts per
		// attempt.
		if _, err := s.sessions.Create(ctx, q, sessions.NewSession{
			UserID:      user.ID,
			TokenDigest: digest,
			ExpiresAt:   expiresAt,
			UserAgent:   in.UserAgent,
			IP:          in.IP,
		}); err != nil {
			return err
		}
		return s.users.ClearFailures(ctx, q, user.ID)
	})
	if err != nil {
		return LoginResult{}, err
	}

	return LoginResult{
		User:      RegisteredUser{ID: user.ID, Email: user.Email},
		Token:     token,
		ExpiresAt: expiresAt,
	}, nil
}

// recordFailure persists the new lockout state for an account.
func (s *Service) recordFailure(ctx context.Context, userID id.UUID, next sessions.Lockout) error {
	return s.users.RecordFailedLogin(ctx, s.read.Queryer(), userID, next.FailedAttempts, next.LockedUntil)
}

// Authenticate resolves a presented token to its user.
//
// A missing, unknown, expired or revoked token are one error. So is a token whose
// user has since been deleted: the session rows go with the user, so the lookup
// misses for a reason the caller has no way to distinguish.
func (s *Service) Authenticate(ctx context.Context, token string) (users.User, error) {
	if token == "" {
		return users.User{}, ErrUnauthenticated
	}

	session, err := s.sessions.ByToken(ctx, s.read.Queryer(), token, s.clock.Now())
	if err != nil {
		if errors.Is(err, sessions.ErrNotFound) {
			return users.User{}, ErrUnauthenticated
		}
		return users.User{}, fmt.Errorf("resolving a session: %w", err)
	}

	user, err := s.users.ByID(ctx, s.read.Queryer(), session.UserID)
	if err != nil {
		if errors.Is(err, users.ErrNotFound) {
			return users.User{}, ErrUnauthenticated
		}
		return users.User{}, fmt.Errorf("loading the session's user: %w", err)
	}

	return user, nil
}

// Logout revokes the session a token belongs to.
//
// A token that resolves to nothing is a success, not an error. A client retrying
// a logout, or a browser presenting a cookie that has already expired, should get
// an answer; answering 500 would make a retry look like a failure and would make
// the natural client behaviour (retry) pathological.
func (s *Service) Logout(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}

	session, err := s.sessions.ByToken(ctx, s.read.Queryer(), token, s.clock.Now())
	if err != nil {
		if errors.Is(err, sessions.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("resolving a session to revoke: %w", err)
	}

	if err := s.sessions.Revoke(ctx, s.read.Queryer(), session.ID); err != nil {
		return fmt.Errorf("revoking a session: %w", err)
	}
	return nil
}

// validateRegistration checks the request before anything is hashed or written.
func validateRegistration(email, password string) error {
	if err := users.ValidateEmail(email); err != nil {
		return err
	}
	return users.ValidatePassword(password)
}

// validateLogin checks the shape of a login without requiring a strong password:
// an existing account may predate any rule, and a login that failed validation
// because the password is short would be a way to probe which passwords are in
// use. The length bounds still apply, because they bound the work argon2id is
// asked to do.
func validateLogin(email, password string) error {
	if err := users.ValidateEmail(email); err != nil {
		return err
	}
	if password == "" {
		return &users.FieldError{Field: "password", Code: users.CodeRequired}
	}
	if len(password) > users.MaxPasswordLength {
		return &users.FieldError{Field: "password", Code: users.CodeTooLong}
	}
	return nil
}
