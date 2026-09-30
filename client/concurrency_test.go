package client

// CONCURRENCY, AND THE CLAIM THAT IS EASY TO MAKE AND HARDER TO KEEP.
//
// `Client` is documented as safe for concurrent use because it is immutable after
// `New`: every method takes a context and returns, nothing mutates the struct, and the
// embedded `*http.Client` and the request editor are safe for concurrent use
// themselves.
//
// That is a claim about a struct with no synchronisation in it, which is exactly the
// kind of claim that stays true until somebody adds a cache, a counter or a memo and
// does not think about it. The failure would then appear in a *caller's* test suite,
// as a data race report pointing at this package, and the reader would have no way to
// know the invariant used to hold.
//
// So it is a test, and it runs under `-race` because that is the only thing that can
// see the failure this is about.
//
// # WHY THE READS ARE REAL WORK
//
// The test reads the token out of the client on every call — through the redaction and
// the request editor — rather than spinning on `HasCredential()`. A test that read one
// immutable bool would pass no matter what the token path did, which is the opposite
// of what it is for. Every goroutine also drives a full request, so the shared
// transport, the shared `http.Client` and the shared redactor are all genuinely
// concurrent rather than incidentally so.
//
// No sleeps, no retries, no raised timeouts: `WaitGroup` is the barrier and the
// server is already up before the goroutines start.

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// TestTheClientIsSafeForConcurrentUse holds the immutability claim.
//
// Run with `-race`, which is the whole point: without it this test only proves the
// calls return the right values, and the race it exists to catch is invisible to it.
func TestTheClientIsSafeForConcurrentUse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"ab000000-0000-0000-0000-000000000000",` +
			`"email":"someone@example.com"}`))
	}))
	defer server.Close()

	client, err := New(Options{BaseURL: server.URL, Token: apiCredential})
	if err != nil {
		t.Fatalf("building a client: %v", err)
	}

	// Enough goroutines to overlap, and each doing enough work that an unsynchronised
	// shared write would be caught. Thirty-two is chosen for overlap rather than for
	// a specific number: the race detector samples, and a small number of
	// interleavings can miss a race that a larger one would not.
	const goroutines = 32
	const iterations = 8

	var wg sync.WaitGroup
	wg.Add(goroutines)

	failures := make(chan string, goroutines*iterations)

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()

			for i := 0; i < iterations; i++ {
				// Every one of these TOUCHES the shared state this package claims is
				// immutable: the transport builds a request and runs the editor, which
				// closes over the credential; the redactor is consulted on the result;
				// the accessors read the same fields.
				user, err := client.GetCurrentUser(t.Context())
				switch {
				case err != nil:
					failures <- "GetCurrentUser: " + err.Error()
					return
				case user.Email != "someone@example.com":
					failures <- "GetCurrentUser returned " + string(user.Email)
					return
				}

				// And the printing paths, which is where the credential is most likely
				// to be read concurrently if a future change made the redactor carry
				// mutable state.
				_ = client.String()
				_ = client.SafeToLog(user)
				_ = client.BaseURL()
				_ = client.HasCredential()
			}
		}()
	}

	wg.Wait()
	close(failures)

	var reported []string
	for failure := range failures {
		reported = append(reported, failure)
	}

	if len(reported) > 0 {
		sortStrings(reported)
		if len(reported) > 4 {
			reported = reported[:4]
		}
		t.Fatalf("%d goroutine(s) failed; the first few:\n  %s\n\n"+
			"Concurrent use of one Client is documented as supported, so a failure here "+
			"is a defect in the client rather than a misuse. If this is a data race "+
			"rather than a wrong value, the usual cause is state added to Redactor or to "+
			"Client without a lock — both were deliberately immutable for this reason.",
			len(reported), joinLines(reported))
	}
}

// joinLines is a two-line helper so the failure above reads as a list.
func joinLines(values []string) string {
	out := ""
	for i, value := range values {
		if i > 0 {
			out += "\n  "
		}
		out += value
	}
	return out
}
