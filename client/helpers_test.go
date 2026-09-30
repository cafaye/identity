package client

// Small helpers shared by this package's tests.
//
// They are here rather than inline because three of the tests need the same two
// of them, and a copy of `itoa` in three files is three places for a bug in it to
// hide. Nothing here is clever: each is three lines and each has a caller that
// says why it exists.

import (
	"context"
	"strconv"
	"time"
)

// contextWithTimeout bounds a subprocess. Used by the regeneration gate, which
// shells out to `go run` and compiles the generator on a cold cache.
func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

func itoa(n int) string { return strconv.Itoa(n) }

// truncate keeps a diff line readable. A generated line can be a 400-character
// struct tag, and four of them in a failure message is a wall rather than a
// diagnosis.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
