// Package sessions owns the session row, the token that addresses it, and the
// brute-force policy that decides when an account stops accepting passwords.
package sessions

import (
	"fmt"
	"time"
)

const (
	// MaxFailedAttempts is the number of consecutive wrong passwords that locks
	// an account.
	MaxFailedAttempts = 5

	// LockoutDuration is how long a lock lasts.
	//
	// The trade-off, stated because it is a real one: this policy is per account
	// and not per source address, so an attacker who knows a victim's address
	// can lock them out on a schedule. Per-address throttling is what stops
	// that, and it belongs to the edge (guard), not to a service that cannot see
	// the address history. Fifteen minutes is long enough that guessing 256-bit
	// tokens or a dictionary attack is hopeless, and short enough that a locked
	// out user waits out one coffee.
	LockoutDuration = 15 * time.Minute
)

// LockedError is a credential refused because its counter says so.
//
// It lives here, next to the Lockout that produces it, and NOT in internal/auth,
// because by the time this packet lands there are two of them: the password's
// and the second factor's. The HTTP layer matches the type, not the source — a
// 423 with a Retry-After is the same answer whichever factor ran out of attempts
// — so a type declared twice would be a type the layer has to know the origin
// of, and the day a third counter appears the 423 silently stops matching.
//
// It is a distinct type rather than a sentinel error because the response has to
// say how long to wait, and because revealing a lock does confirm the account
// exists — which is why the 423 is the one place login is allowed to leak that
// much.
type LockedError struct {
	// RetryAfter is how much longer the caller must wait. Never negative.
	RetryAfter time.Duration
}

func (e *LockedError) Error() string {
	return fmt.Sprintf("too many failed attempts; retry after %s", e.RetryAfter)
}

// Lockout is the login-failure state of one account, or of one of that account's
// factors.
//
// It is a plain value with no clock and no database behind it: every method is a
// function of the state and the `now` it is handed. That is what makes the
// fifteen-minute window testable without a single sleep, and it is why the
// clock is a parameter here and not a field.
//
// ONE IMPLEMENTATION, TWO COUNTERS. The password's run lives on the users row and
// the second factor's on the credential row, and the security property this
// packet needs — an attacker cannot use a fast factor to accelerate a slow
// password, or the reverse — comes from the counters being separate, not from the
// arithmetic differing. So the arithmetic is written once, here, and both
// counters run it. A second implementation in internal/mfa would be a second
// place for the thresholds and the expiry reset to drift apart, and the drift
// would be invisible until a user was locked out of their own account for the
// wrong number of minutes. TestTheFactorLockoutIsThisLockout runs one table
// through both.
type Lockout struct {
	// FailedAttempts counts wrong passwords since the last success or the last
	// lock. It is not a lifetime total.
	FailedAttempts int `json:"failed_attempts"`
	// LockedUntil is nil when the account is not locked.
	LockedUntil *time.Time `json:"locked_until,omitempty"`
}

// Locked reports whether the account is locked as of now. A lock whose instant
// has arrived is not a lock: expiry is decided on read, so there is no window in
// which the row says "locked" and the answer is "yes, sorry" for a period that
// already closed, and no sweeper is needed to clear it.
func (l Lockout) Locked(now time.Time) bool {
	return l.LockedUntil != nil && l.LockedUntil.After(now)
}

// RetryAfter is how much longer the caller must wait. Zero once the window has
// closed, never negative: a 423 whose body says "retry in -3s" is a client bug
// waiting to happen.
func (l Lockout) RetryAfter(now time.Time) time.Duration {
	if !l.Locked(now) {
		return 0
	}
	return l.LockedUntil.Sub(now)
}

// Failed records one wrong password and returns the new state.
//
// While the account is locked it returns the state unchanged. Letting a rejected
// attempt push the expiry further out would mean an attacker can keep an account
// locked forever by continuing to try, and a legitimate user racing the clock
// would extend their own lockout by mistyping again.
//
// On reaching the threshold the counter returns to zero, so the next window is
// five fresh failures rather than one. The alternative — leaving the count at
// the threshold — turns the second lockout into a single attempt every fifteen
// minutes, indefinitely, which is a different policy from the one described and
// is a one-line change if it is ever wanted.
func (l Lockout) Failed(now time.Time) Lockout {
	if l.Locked(now) {
		return l
	}

	// An expired lock means the previous window is over. Without this reset the
	// count would still be at the threshold and the next mistake would re-lock.
	if l.LockedUntil != nil {
		l.FailedAttempts = 0
		l.LockedUntil = nil
	}

	l.FailedAttempts++
	if l.FailedAttempts >= MaxFailedAttempts {
		until := now.Add(LockoutDuration)
		return Lockout{FailedAttempts: 0, LockedUntil: &until}
	}

	return l
}

// Succeeded clears the run and lifts any lock. It is the only thing that calls
// it: without the reset, the fifth failure would be one attempt sooner every time
// the user signs in successfully.
func (l Lockout) Succeeded() Lockout {
	return Lockout{}
}
