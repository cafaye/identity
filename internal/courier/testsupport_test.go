package courier

import (
	"net/http"
	"time"
)

// testingT is the slice of *testing.T these helpers need, named so a helper's
// signature does not import `testing` into every file in the package.
type testingT interface {
	Helper()
	Fatalf(format string, args ...any)
}

// newTestHTTP returns a transport with a short bound, so a test that points this
// package at an unroutable address fails on the bound rather than on the suite's
// own timeout.
func newTestHTTP() *http.Client {
	return &http.Client{Timeout: 2 * time.Second}
}
