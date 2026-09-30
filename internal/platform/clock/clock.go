// Package clock is the service's only source of time.
//
// Nothing in identity calls time.Now directly. Lockout windows, session expiry
// and outbox timestamps are all read through a Clock so a test can move time
// exactly where it needs it, instead of sleeping and hoping (PLAN.md §3: no
// sleeps, no raised retries).
package clock

import (
	"sync"
	"time"
)

// Clock reports the current time. The interface is deliberately one method wide:
// a narrower seam is not possible, and a wider one invites code that depends on
// timers the service does not have.
type Clock interface {
	Now() time.Time
}

// System is the production Clock. It is a value, not a pointer, so it is safe
// to copy and holds no state.
type System struct{}

// Now returns the current UTC time. UTC throughout: the service stores
// timestamptz and formats RFC3339, and a local-zone time.Time leaking into a
// JSON timestamp is how "expires_at" ends up ambiguous.
func (System) Now() time.Time {
	return time.Now().UTC()
}

// Fake is a Clock whose time is set by the test that owns it.
type Fake struct {
	mu  sync.RWMutex
	now time.Time
}

// NewFake returns a Fake parked at start. The start value is used verbatim, so
// a test can name a fixed instant and have every derived timestamp be exact.
func NewFake(start time.Time) *Fake {
	return &Fake{now: start.UTC()}
}

// Now returns the parked instant.
func (f *Fake) Now() time.Time {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.now
}

// Advance moves the clock forward by d. A non-positive d is ignored: rewinding
// time is never what a test means, and honouring it would let a bug hide.
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if d > 0 {
		f.now = f.now.Add(d)
	}
}

// Set parks the clock at an arbitrary instant, for the tests that need a
// specific expiry rather than a relative one.
func (f *Fake) Set(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = t.UTC()
}
