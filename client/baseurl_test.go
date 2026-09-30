package client

// BASE-URL PRECEDENCE, ONE TEST PER BRANCH.
//
// The brief requires each branch to have "a test proving the others did not win", and
// that clause is the whole difficulty. A table that sets one variable and asserts the
// answer passes whether the resolution is correct or accidentally correct — with a
// hard-coded winner, or with a chain that happens to reach the same string by two
// routes.
//
// So every case here sets EVERY source, differing only in which one is blank. If the
// winner were hard-coded, every row would fail; if precedence were reversed, the rows
// whose expected winner is not the first source would fail. That is what makes these
// tests a precedence test rather than a lookup test.
//
// # `-count=1`, PER MD12
//
// Every case supplies its own `LookupEnv` and never touches the process environment,
// so the Go test cache cannot produce a stale result from a previous run with
// different variables set. `-count=1` is still put on the command that runs this
// file's tests, because it costs nothing and it removes the question: MD12 records
// that Go keys its cache on `os.Getenv` reads, and a package that DOES read the real
// environment anywhere — `New` does, through `osGetenv`, when `LookupEnv` is nil —
// has two cache keys for one set of tests.

import (
	"errors"
	"strings"
	"testing"
)

// env builds a `LookupEnv` over a map, so no test in this file can affect another.
//
// A map rather than a closure over a variable list because a test that reads
// `os.Setenv` races every other test in the package and leaks past its end — which
// is the reason `internal/config` takes a `Lookup` and the reason this package does
// too.
func env(pairs map[string]string) LookupEnv {
	return func(name string) string { return pairs[name] }
}

// TestResolveBaseURLPrefersTheExplicitOptionOverEverything is the first branch.
func TestResolveBaseURLPrefersTheExplicitOptionOverEverything(t *testing.T) {
	got, err := ResolveBaseURL(BaseURLOptions{
		BaseURL:   "https://explicit.example.com",
		LookupEnv: env(map[string]string{ServiceBaseURLEnvVar: "https://service.example.com", BaseURLEnvVar: "https://fleet.example.com"}),
	})
	if err != nil {
		t.Fatalf("resolution failed: %v", err)
	}
	if got != "https://explicit.example.com" {
		t.Errorf("the explicit option lost to the environment: got %q.\n"+
			"Explicit beats ambient: somebody wrote this URL in code, which is the "+
			"strongest statement of intent available.", got)
	}
}

// TestResolveBaseURLPrefersTheServiceVariableOverTheFleetVariable is the second
// branch, and the one a fleet-wide variable silently gets wrong.
func TestResolveBaseURLPrefersTheServiceVariableOverTheFleetVariable(t *testing.T) {
	got, err := ResolveBaseURL(BaseURLOptions{
		LookupEnv: env(map[string]string{
			ServiceBaseURLEnvVar: "https://identity.example.com",
			BaseURLEnvVar:        "https://fleet.example.com",
		}),
	})
	if err != nil {
		t.Fatalf("resolution failed: %v", err)
	}
	if got != "https://identity.example.com" {
		t.Errorf("got %q, want the per-service variable to win.\n"+
			"Within one source the more specific beats the less. A self-hoster running "+
			"two deployments sets $CAFAYE_BASE_URL for the fleet and "+
			"$CAFAYE_IDENTITY_BASE_URL for this one; if the fleet-wide value won, the "+
			"per-service variable would be a setting that does nothing.",
			got)
	}
}

// TestResolveBaseURLUsesTheFleetVariableWhenNoServiceVariableIsSet is the third
// branch, and it is the one that proves the second is not just "first non-empty".
func TestResolveBaseURLUsesTheFleetVariableWhenNoServiceVariableIsSet(t *testing.T) {
	got, err := ResolveBaseURL(BaseURLOptions{
		LookupEnv: env(map[string]string{BaseURLEnvVar: "https://fleet.example.com"}),
	})
	if err != nil {
		t.Fatalf("resolution failed: %v", err)
	}
	if got != "https://fleet.example.com" {
		t.Errorf("got %q, want the fleet-wide variable.\n"+
			"A self-hoster with one deployment of everything should not have to spell "+
			"out six variable names.", got)
	}
}

// TestResolveBaseURLRefusesToGuess covers the fourth branch: there is no default.
//
// The document's `servers:` block lists `https://identity.cafaye.com`, and this
// branch is the decision NOT to use it. A self-hoster running their own identity
// would have their traffic — and their credentials — sent to somebody else's
// deployment, and it would SUCCEED, so nothing would be visibly wrong until somebody
// read a log.
//
// The error is asserted for content as well as for happening: a caller who gets this
// needs to know which variable to set, and an error that says only "no base URL" is
// a support ticket.
func TestResolveBaseURLRefusesToGuess(t *testing.T) {
	_, err := ResolveBaseURL(BaseURLOptions{LookupEnv: env(nil)})
	if err == nil {
		t.Fatal("resolution succeeded with nothing configured.\n" +
			"A default would be a guess about which deployment to send a customer's " +
			"credentials to, and that is the one guess this package refuses to make. If " +
			"you want identity.cafaye.com, set it.")
	}

	if !errors.Is(err, ErrNoBaseURL) {
		t.Errorf("the error does not match ErrNoBaseURL, so a caller cannot branch on "+
			"it: %v", err)
	}

	message := err.Error()
	for _, want := range []string{ServiceBaseURLEnvVar, BaseURLEnvVar} {
		if !strings.Contains(message, want) {
			t.Errorf("the error does not name $%s, so a caller reading it does not know "+
				"what to set:\n%s", want, message)
		}
	}
}

// TestResolveBaseURLRefusesABareHost covers the branch that is not precedence but is
// the same class of mistake: a value that is not a URL.
//
// The generated client CONCATENATES the base URL with an operation's path rather than
// resolving one against the other, so `identity.example.com` would produce
// `identity.example.com/v1/me`, which is not a URL, and the resulting failure names
// neither the typo nor the cause.
func TestResolveBaseURLRefusesABareHost(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"a bare host", "identity.example.com"},
		{"a scheme with no host", "https://"},
		{"a non-http scheme", "ftp://identity.example.com"},
		{"a javascript scheme", "javascript:alert(1)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ResolveBaseURL(BaseURLOptions{BaseURL: tc.value}); err == nil {
				t.Errorf("%q was accepted as a base URL.\n"+
					"cafaye's generated clients concatenate rather than resolve, so a bare "+
					"host produces something that is not a URL and an error naming neither "+
					"the value nor the cause.", tc.value)
			}
		})
	}
}

// TestResolveBaseURLStripsTrailingSlashesAndKeepsAPathPrefix is a small property with
// a real consequence behind it.
//
// The generated client concatenates, so a trailing slash becomes a doubled separator
// in the path. And a path PREFIX is kept: a self-hoster serving the fleet under
// `/cafaye` needs it, which `parsed.Scheme + "://" + parsed.Host` would helpfully but
// wrongly delete — so the reduction is a `TrimRight` on the whole string and not a
// rebuild from the parsed parts.
func TestResolveBaseURLStripsTrailingSlashesAndKeepsAPathPrefix(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"a trailing slash", "https://identity.example.com/", "https://identity.example.com"},
		{"several trailing slashes", "https://identity.example.com///", "https://identity.example.com"},
		{"surrounding whitespace", "  https://identity.example.com  ", "https://identity.example.com"},
		{"a path prefix", "https://example.com/cafaye/", "https://example.com/cafaye"},
		{"a path prefix without a trailing slash", "https://example.com/cafaye", "https://example.com/cafaye"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveBaseURL(BaseURLOptions{BaseURL: tc.in})
			if err != nil {
				t.Fatalf("resolution failed: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q.\n"+
					"The generated client concatenates the base URL with the operation's "+
					"path, so a trailing slash becomes a doubled separator.", got, tc.want)
			}
		})
	}
}

// TestResolveBaseURLPrefersTheExplicitOptionEvenWhenItIsBlank is the awkward corner,
// and it is here because a blank explicit value is ambiguous.
//
// `BaseURL: "  "` is treated as absent rather than as an override, so the environment
// wins. The alternative — an empty string meaning "explicitly nowhere" — would make
// `Options{BaseURL: someStringVariable}` silently fall through to the environment
// with no error, which is the opposite of what a caller who set it means.
//
// Asserted because it is a decision, and an unasserted decision is one the next
// reader has to guess at.
func TestResolveBaseURLPrefersTheExplicitOptionEvenWhenItIsBlank(t *testing.T) {
	got, err := ResolveBaseURL(BaseURLOptions{
		BaseURL:   "   ",
		LookupEnv: env(map[string]string{BaseURLEnvVar: "https://fleet.example.com"}),
	})
	if err != nil {
		t.Fatalf("resolution failed: %v", err)
	}
	if got != "https://fleet.example.com" {
		t.Errorf("a blank explicit value resolved to %q.\n"+
			"Blank is treated as absent so `Options{BaseURL: someVariable}` does not "+
			"silently override an operator's environment with nothing. A value that is "+
			"present and empty is a mistake worth reporting, not a silent redirect.",
			got)
	}
}

// TestBaseURLEnvVarForDerivesRatherThanLists is the reason there is one derivation
// and not six literals.
//
// Six string literals would be a second list of the six services next to the
// documents, and this repository is organised entirely around not having those.
func TestBaseURLEnvVarForDerivesRatherThanLists(t *testing.T) {
	for _, tc := range []struct{ service, want string }{
		{"identity", "CAFAYE_IDENTITY_BASE_URL"},
		{"billing", "CAFAYE_BILLING_BASE_URL"},
		{"courier", "CAFAYE_COURIER_BASE_URL"},
	} {
		t.Run(tc.service, func(t *testing.T) {
			if got := BaseURLEnvVarFor(tc.service); got != tc.want {
				t.Errorf("BaseURLEnvVarFor(%q) = %q, want %q", tc.service, got, tc.want)
			}
		})
	}

	// And a name that cannot become a cafaye service name refuses rather than
	// producing something that looks like one.
	for _, bad := range []string{"Identity", "identity-api", "identity2", "", "id entity"} {
		if got := BaseURLEnvVarFor(bad); got != "" {
			t.Errorf("BaseURLEnvVarFor(%q) = %q, want the empty string.\n"+
				"A name that cannot identify a cafaye service should not have an "+
				"environment variable derived from it: a typo would resolve to a "+
				"variable nobody sets, and the mistake would surface as a connection "+
				"refused rather than as a name.", bad, got)
		}
	}
}

// TestNewResolvesTheBaseURLEagerly is the reason New can fail at construction.
//
// A client that resolves per request reports a missing base URL as a connection
// refused on the fifth call, from a function that has nothing to do with
// configuration. Resolving in `New` makes it a construction-time error naming the
// variable.
func TestNewResolvesTheBaseURLEagerly(t *testing.T) {
	_, err := New(Options{LookupEnv: env(nil)})
	if err == nil {
		t.Fatal("New succeeded with no base URL configured.\n" +
			"Resolution belongs in the constructor: a per-request resolution reports a " +
			"configuration mistake as a transport failure, in a call site that has " +
			"nothing to do with configuration.")
	}
	if !errors.Is(err, ErrNoBaseURL) {
		t.Errorf("New returned %v, which does not match ErrNoBaseURL", err)
	}
}
