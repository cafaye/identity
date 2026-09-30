// Package mfa is the second factor: TOTP enrollment, the challenge a login waits
// on, the recovery codes that stand in for a lost phone, and the lockout that
// stops somebody who has stolen a password from finishing the job with six digits
// of guessing.
//
// # What this package owns, and what it does not
//
// It owns the credential, the challenge, the recovery codes and the decision
// "is this second factor acceptable". It does NOT own the session. The challenge
// is minted and verified here; the session is minted by internal/auth, in the
// same transaction that consumes the challenge, through the same
// sessions.NewToken that every other session in this service is minted with.
// There is deliberately no second way for a session to come into being, because
// the single most important line in this packet is that a correct password must
// not produce one.
//
// # The order of operations at login
//
//  1. POST /v1/session verifies the password, exactly as it did before this
//     package existed.
//  2. If the user has a CONFIRMED credential, Login mints a CHALLENGE and
//     returns it. No session. The response is 202, not 200.
//  3. POST /v1/session/mfa presents a code against the challenge. Only when that
//     succeeds does internal/auth create a session, in one transaction with the
//     challenge's consumption.
//
// # What the library owns and what this package owns
//
// github.com/pquerna/otp owns RFC 6238: the base32 of the shared secret, the
// HMAC, the dynamic truncation, the six-digit zero-padding, and the constant-time
// comparison. None of that is reimplemented here, and this package never computes
// an HMAC or encodes a secret by hand. A private implementation of a
// specification is a vulnerability with tests.
//
// This package owns the three decisions the specification does not make:
//
//   - WHICH steps are candidates. The library's totp.ValidateCustom tries a
//     window and returns a bool; it does not say which step matched, and the
//     replay guard needs to know. So this package walks the window itself and
//     calls hotp.ValidateCustom once per step.
//   - HOW LONG a code is accepted. SkewSteps, and why it is one.
//   - WHETHER a step has been spent. mfa_used_totp_steps, and why it is a set
//     rather than a high-water mark. See Store.ClaimStep.
package mfa

import (
	"errors"
	"net/netip"
	"time"

	"github.com/cafaye/identity/internal/platform/id"
)

// The methods this service knows how to store. A method is a property of the
// row rather than of the Go type because the row outlives this release: the day
// SMS or WebAuthn lands, it is a new row and not a rewrite of a table holding
// live credentials.
const (
	// MethodTOTP is a time-based one-time password, RFC 6238.
	MethodTOTP = "totp"

	// MethodRecoveryCode is one of the single-use codes issued alongside a
	// credential. It is a method because it is accepted where a TOTP code is
	// accepted and refused where one is refused, and the response says which one
	// was used — a user on their last recovery code needs to be told to generate
	// more.
	MethodRecoveryCode = "recovery_code"
)

// The TOTP parameters, and the argument for each.
//
// They are constants and not configuration because every one of them is baked
// into the secret a user's authenticator app already holds. Changing the period,
// the digit count or the algorithm after enrollment does not upgrade anybody's
// second factor — it invalidates it, silently, for every user at once. So they
// are written down here, in the code that reads them, and the row carries them
// as well so a verifier honours what the provisioning URI promised rather than
// what this version of the code happens to assume.
const (
	// Digits is the length of a TOTP code. Six, because that is what every
	// authenticator app on every phone produces and what every one scans. Eight
	// digits halves an already-hopeless search space; it is a convenience for a
	// user typing in a hurry, not a security improvement.
	Digits = 6

	// Period is how long one code is valid for. Thirty seconds, the value
	// RFC 6238's own appendix and every otpauth:// implementation default to.
	Period = 30 * time.Second

	// SkewSteps is how many steps either side of the current one are accepted.
	//
	// ONE, AND THE ARGUMENT IS THE WHOLE POINT.
	//
	// Zero would be tighter and is wrong in practice. It refuses any code typed
	// in the seconds either side of a step boundary, which is exactly when a user
	// is most likely to be reading digits off a screen, and the users it refuses
	// are the ones with the worst phone autocorrect, the slowest thumbs and the
	// worst network — the same users whose authenticator clock is least likely to
	// agree with the server's. A second factor with a visible 5% failure rate does
	// not get retried, it gets turned off, and a user with MFA off is worse off
	// than a user with MFA and a support ticket.
	//
	// Two or more is the other error, and it is the error the specification invites.
	// Every step of skew is thirty more seconds during which a phished or
	// shoulder-surfed code still works, and one more six-digit value an attacker
	// gets to guess. The window is the ONLY thing that grows with skew, so it is
	// held at the smallest value that tolerates real clock drift. At one step a
	// code is live for ninety seconds instead of thirty; at three it would be a
	// hundred and fifty.
	//
	// WHAT ONE STEP DOES NOT BUY, stated because the honest edge of this argument
	// belongs in it: it tolerates up to thirty seconds of clock drift in either
	// direction and no more. A phone forty-five seconds fast spends half of every
	// period showing a code two steps ahead, and that code is refused — a
	// fifteen-second wait, every thirty seconds, for that phone. No skew value
	// fixes it without a window wide enough to be a security decision rather than a
	// tolerance, and the replay guard is what makes the ninety seconds survivable:
	// a captured code is good for exactly one use however long it stays inside the
	// window.
	SkewSteps = 1

	// SecretSize is how many random bytes the shared secret has.
	//
	// Twenty, which is the RFC 4226 recommendation and pquerna/otp's default.
	// The secret is not the weak link in this system by any margin — it is 160
	// bits against a search space of ten to the sixth, which is the code and not
	// the secret — so there is no reason to make the provisioning URI longer than
	// every app can read.
	SecretSize = 20
)

// RecoveryCodeCount is how many recovery codes a credential is issued with.
//
// Ten, and the argument is arithmetic: ten single-use codes is a code the user
// can keep in a drawer, a code they can print, and a code they can be trusted to
// have not already used. Five is the number most products ship, and it is a
// number a user reuses — the same code written on two pieces of paper in two
// places, both of which are then in an attacker's hands.
const RecoveryCodeCount = 10

// RecoveryCodeBytes is the entropy in one recovery code.
//
// TEN BYTES, EIGHTY BITS, and this is a floor rather than a round number.
//
// The codes are compared by SHA-256, not by argon2id, and that is only safe
// because of this constant. A six-digit recovery code would be 10^6 candidates,
// and a SHA-256 of one is walked in microseconds — a database dump would then
// contain ten working second factors. At eighty bits the same search is
// 2^80 ≈ 1.2 × 10^24 candidates, which is not a computation rather than an
// intractable one. See the column comment on mfa_recovery_codes.code_digest.
const RecoveryCodeBytes = 10

// ChallengeTTL is how long a login's challenge is worth completing.
//
// Ten minutes, the same window as the OIDC login form's sealed state and the
// same reasoning: a challenge is something somebody is typing six digits into
// right now, and one that outlives the interruption it was created by is a
// credential sitting in a log waiting to be found.
const ChallengeTTL = 10 * time.Minute

// EnrollmentTTL is how long an unconfirmed secret is worth keeping.
//
// Ten minutes, and it is a bound rather than a courtesy because an unconfirmed
// credential authenticates nothing — it is a secret at rest for as long as the
// row survives, and a row with no deadline is a table that grows by one per
// abandoned setup. It is also about right for the task: reading a QR code,
// opening an authenticator app, and typing six digits.
const EnrollmentTTL = 10 * time.Minute

// CodeTTL is the de facto lifetime of a TOTP code, and the window an attacker's
// copy of it is good for. It is Period times the two-sided skew plus the step
// itself, and it exists so the value is stated once instead of being
// re-derived in prose and in a pruning query.
var CodeTTL = time.Duration(SkewSteps*2+1) * Period

// The errors the use cases return. Callers match them with errors.Is; nothing
// here is compared by string.
var (
	// ErrNotFound means no such credential row. It is the store's sentinel and the
	// use cases translate it into one of the four above, because a caller has no
	// useful answer for it that is not one of those.
	ErrNotFound = errors.New("mfa credential not found")

	// ErrNotEnabled means the user has no confirmed second factor. It is a 409
	// rather than a 404 on the management routes: the caller is asking to change
	// something that does not exist, and a 404 would be indistinguishable from
	// "this is not yours", which is a different and much more serious answer.
	ErrNotEnabled = errors.New("multi-factor authentication is not enabled for this user")

	// ErrAlreadyEnabled means the user already has a live credential and the
	// route does not allow replacing it. Every route that replaces one requires a
	// second factor first, so reaching this means the check that should have run
	// first did not.
	ErrAlreadyEnabled = errors.New("multi-factor authentication is already enabled for this user")

	// ErrEnrollmentNotFound means no unconfirmed credential with that id belongs
	// to the caller. A wrong id, somebody else's id, an id whose window closed
	// and an id that was already confirmed are one error, because a caller who
	// could tell them apart could probe which enrollments exist.
	ErrEnrollmentNotFound = errors.New("no pending enrollment with that id")

	// ErrChallengeNotFound means no live challenge matches the presented token.
	// Four situations, one answer: no such token, an expired one, a consumed one
	// and one belonging to a user who no longer exists.
	ErrChallengeNotFound = errors.New("no live sign-in challenge matches that token")

	// ErrInvalidFactor means the presented second factor was not accepted.
	//
	// ONE ERROR FOR EVERY WAY A FACTOR CAN FAIL, and the sameness is the security
	// property rather than a simplification. A wrong TOTP code, a wrong recovery
	// code, a TOTP code that has already been spent, a code that is neither shape
	// and a challenge whose credential has been rotated away are five different
	// facts, and an attacker who can tell them apart learns which of them to keep
	// trying. A legitimate user's most common cause is a code they already used,
	// and the honest response to that is the same sentence as for everything else.
	ErrInvalidFactor = errors.New("that code was not accepted")

	// ErrNoVault means this process cannot encrypt or decrypt a TOTP secret,
	// because MFA_ENCRYPTION_KEY is not configured.
	//
	// It is an error and not a degraded mode, and the direction of the failure is
	// the whole point: with no key a user who HAS enrolled cannot be let in, and
	// the only alternatives are refusing them or waving them through with one
	// factor. So the challenge is still created at login — the service knows they
	// have MFA — and the factor submission fails closed. See README.md, "MFA".
	ErrNoVault = errors.New("this deployment has no MFA_ENCRYPTION_KEY, so it cannot verify a second factor")

	// ErrNoIssuer is returned by a Vault that has no key, for symmetry with
	// ErrNoVault. It exists so the failure has a name at the point it happens.
	ErrNoIssuer = errors.New("the MFA issuer label is required")
)

// Field validation codes, which land verbatim in the `errors[]` array of the
// cafaye error envelope (core: docs/openapi-conventions.md) and which clients may
// switch on.
const (
	// CodeRequired is an absent value.
	CodeRequired = "required"

	// CodeInvalidFormat is a value of the wrong shape.
	CodeInvalidFormat = "invalid_format"
)

// FieldError is a per-field validation failure on an enrollment request.
type FieldError struct {
	Field string
	Code  string
}

func (e *FieldError) Error() string {
	return e.Field + ": " + e.Code
}

func fieldErr(field, code string) error {
	return &FieldError{Field: field, Code: code}
}

// Credential is a row in mfa_credentials.
//
// SecretCiphertext is carried because every read of this row needs it, and
// because the shape of the row is the shape of the decision. It is never
// rendered, never logged, and never leaves this package except as a base32
// string handed to the user exactly once at enrollment.
type Credential struct {
	ID     id.UUID
	UserID id.UUID
	Method string
	// SecretCiphertext is the sealed shared secret. Open it with the Vault; the
	// raw secret is not a field here on purpose, so nothing in this package can
	// log it by reaching for a struct member.
	SecretCiphertext string
	Digits           int
	PeriodSeconds    int
	Algorithm        string
	Label            string
	// ConfirmedAt is nil for a pending enrollment. A pending row authenticates
	// nothing and is never read by the login path.
	ConfirmedAt *time.Time
	// ExpiresAt is set only on a pending row.
	ExpiresAt *time.Time
	// FailedAttempts and LockedUntil are the SECOND FACTOR's brute-force state.
	// They are not the password's, which is on the users row, and that separation
	// is what stops five guesses here from costing five guesses there.
	FailedAttempts int
	LockedUntil    *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// IsConfirmed reports whether the credential is live. The login path reads only
// rows where this is true, which is what makes "stored but never confirmed"
// mean "authenticates nothing" rather than "authenticates, eventually".
func (c Credential) IsConfirmed() bool { return c.ConfirmedAt != nil }

// IsLocked reports whether the credential's own counter has locked the second
// factor as of now. Expiry is decided on read, so no sweeper has to clear it.
func (c Credential) IsLocked(now time.Time) bool {
	return c.LockedUntil != nil && c.LockedUntil.After(now)
}

// RetryAfter is how much longer the caller must wait on the second factor. It is
// zero once the window has closed and never negative.
func (c Credential) RetryAfter(now time.Time) time.Duration {
	if !c.IsLocked(now) {
		return 0
	}
	return c.LockedUntil.Sub(now)
}

// Challenge is a row in mfa_challenges: a correct password, and no session yet.
type Challenge struct {
	ID         id.UUID
	UserID     id.UUID
	UserAgent  string
	IP         *netip.Addr
	CreatedAt  time.Time
	ExpiresAt  time.Time
	ConsumedAt *time.Time
}

// Live reports whether the challenge may still be answered as of now.
func (c Challenge) Live(now time.Time) bool {
	if c.ConsumedAt != nil {
		return false
	}
	return c.ExpiresAt.After(now)
}
