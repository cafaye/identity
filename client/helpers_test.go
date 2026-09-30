package client

// Small helpers shared by this package's tests.
//
// They are here rather than inline because three of the tests need the same two
// of them, and a copy of `itoa` in three files is three places for a bug in it to
// hide. Nothing here is clever: each is three lines and each has a caller that
// says why it exists.

import (
	"context"
	"errors"

	uuidlib "github.com/google/uuid"

	openapiTypes "github.com/oapi-codegen/runtime/types"
	"time"
)

// contextWithTimeout bounds a subprocess. Used by the regeneration gate, which
// shells out to `go run` and compiles the generator on a cold cache.
func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// errorsAs is `errors.As`, named once so the credential-leak test reads as a list
// of surfaces to sweep rather than a list of import statements.
func errorsAs(err error, target any) bool { return errors.As(err, target) }

// uuidOf builds a `types.UUID` from its canonical text form, and fails the test if
// the string is not one — which keeps a typo in a fixture from becoming a UUID that
// silently differs from the one the test means.
func uuidOf(s string) openapiTypes.UUID {
	parsed, err := uuidlib.Parse(s)
	if err != nil {
		panic("fixture uuid " + s + ": " + err.Error())
	}
	return openapiTypes.UUID(parsed)
}

// ptr is a fixture convenience: the generated structs distinguish an absent field
// from an empty one, and a fixture that has to write `&fakeToken` for every optional
// field is a fixture nobody keeps up to date.
func ptr[T any](value T) *T { return &value }
