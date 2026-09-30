package clock

import (
	"sync"
	"testing"
	"time"
)

// epoch is an arbitrary fixed instant. Nothing in this package may depend on
// the wall clock, so every test names its own starting point.
var epoch = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

func TestSystemClockIsMonotonicEnoughToBeAClock(t *testing.T) {
	t.Parallel()

	before := System{}.Now()
	after := System{}.Now()

	if after.Before(before) {
		t.Errorf("System.Now went backwards: %s then %s", before, after)
	}
	if after.Sub(before) > time.Minute {
		t.Errorf("System.Now jumped %s between two calls; is something mocking it?", after.Sub(before))
	}
}

func TestFakeClockStartsWhereItIsTold(t *testing.T) {
	t.Parallel()

	c := NewFake(epoch)

	if got := c.Now(); !got.Equal(epoch) {
		t.Errorf("Now() = %s, want %s", got, epoch)
	}
}

func TestFakeClockAdvanceMovesForwardOnly(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give time.Duration
		want time.Time
	}{
		{name: "advance forward", give: 15 * time.Minute, want: epoch.Add(15 * time.Minute)},
		{name: "zero is a no-op", give: 0, want: epoch},
		{name: "negative is a no-op rather than rewinding", give: -time.Hour, want: epoch},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := NewFake(epoch)
			c.Advance(tt.give)

			if got := c.Now(); !got.Equal(tt.want) {
				t.Errorf("after Advance(%s) Now() = %s, want %s", tt.give, got, tt.want)
			}
		})
	}
}

func TestFakeClockSetMovesToAnArbitraryInstant(t *testing.T) {
	t.Parallel()

	c := NewFake(epoch)
	later := epoch.Add(48 * time.Hour)
	c.Set(later)

	if got := c.Now(); !got.Equal(later) {
		t.Errorf("Now() = %s, want %s", got, later)
	}
}

// The fake is shared between the HTTP handlers and the test goroutine, so a data
// race here is a real race in production code, not a test artefact.
func TestFakeClockIsSafeForConcurrentUse(t *testing.T) {
	t.Parallel()

	c := NewFake(epoch)

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Advance(time.Duration(i+1) * time.Second)
			_ = c.Now()
		}()
	}
	wg.Wait()

	if got := c.Now(); !got.After(epoch) {
		t.Errorf("Now() = %s, want it to have advanced past %s", got, epoch)
	}
}

// A Clock is satisfied by both implementations, which is the whole point of the
// interface: callers cannot tell which one they hold.
func TestBothImplementationsSatisfyClock(t *testing.T) {
	t.Parallel()

	var clocks = []Clock{System{}, NewFake(epoch)}

	for _, c := range clocks {
		if c.Now().IsZero() {
			t.Errorf("%T returned the zero time", c)
		}
	}
}
