package httpapi

import (
	"io"
	"log/slog"
	"os"
	"testing"
)

// The library behind the OIDC surface logs through slog's DEFAULT logger, not
// through the one this service injects — op.WithLogger is a documented no-op and
// op.NewProvider does not touch slog.SetDefault. Without this, a test that walks
// eleven refused redirect URIs prints eleven lines of the library's own
// structured logging into the middle of the suite's output.
//
// Routing the default to io.Discard costs this package nothing: every assertion
// in it about what the service logged passes an explicit logger through
// WithLogger, and the only other reader of slog.Default is writeProblem's
// "could not encode the body" warning, which no test depends on.
//
// It is a process global and it is set once, here, rather than per test — which
// is also why the tests in this package do not run with t.Parallel() at the top
// level while this is being considered a change. They do not need to be: nothing
// in this package reads the default logger's output.
func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}
