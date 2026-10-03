package httpapi

// FAULTS INJECTED INTO THE ROUTER THE CLAIMS ARE HELD TO.
//
// claims_test.go and oauth_absent_test.go both compare claims to `servedRoutes`,
// which walks the chi tree that `newMux` assembles. If that walk cannot see a
// route, every comparison in this package reports agreement about a service that is
// smaller than the one that runs — and it reports it confidently, because a walk
// that finds nothing is indistinguishable from a walk that is correct.
//
// ## This is not hypothetical, and it happened twice, to this file's own check
//
// AGENTS.md records it and the code records it, so the repetition here is
// deliberate. Adding the admin surface with the `admin` field left out of the
// `servedRoutes` options literal made `TestEveryServedRouteIsDocumentedOrNamed`
// PASS while three undocumented operations were mounted, because
// `registerAdminRoutes` returns early when the service is absent — exactly like
// every other conditional surface. Eight recovery routes were the second instance.
//
// A check that goes green by not checking is the one outcome this repository names
// as the failure mode these files exist to prevent, and it happened to the check
// written to catch precisely that. So the walk itself gets tested, and the tests
// below prove it can SEE a route rather than proving a field was set.
//
// ## What is asserted, and why a field being non-nil is not enough
//
// router_walk_test.go already compares the options struct's field list against the
// literals that configure a walk. That catches a field nobody set. It cannot catch
// a field set to a double whose routes the walk then fails to enumerate, and it
// cannot catch the walk being handed a tree that was never assembled.
//
// So each test below asserts on ROUTES FOUND, not on fields read. A test that
// asserted `options{}.admin != nil` would pass against a registrar that mounts
// nothing; a test that asserts `GET /v1/accounts/{}/admin/audit-log` is in the walk
// fails against one that does.

import (
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/cafaye/identity/internal/oauth"
)

// walkOptions is the full set of conditional surfaces, in one place, so the tests
// below and `servedRoutes` cannot drift into configuring different trees.
//
// This is the literal `servedRoutes` builds, and the reason it is a function rather
// than a var is that a package-level `options` value would be init-time state —
// which AGENTS.md forbids outright, and rightly: a mutable global that every walk
// reads is a way for one test to change what another test sees.
func walkOptions() options {
	return options{
		auth:         newFakeAuth(),
		tenancy:      newFakeTenancy(),
		oidcClients:  newFakeOIDCClients(),
		oidc:         newFakeOIDC(),
		apiKeys:      newFakeAPIKeys(),
		mfa:          newFakeMFAManage(),
		introspector: newFakeIntrospector(),
		admin:        newFakeAdmin(),
		recovery:     newFakeRecovery(),
		// social is set for the reason every other field here is, and it was the one
		// that was missing when the social-login routes landed: with this field out,
		// the walk these tests configure could not see the two routes and
		// TestTheClaimWalkSeesEveryConditionalSurface had no row asserting it could.
		social: newFakeSocial(),
	}
}

// routesIn walks the tree `o` assembles and returns the (method, path) pairs.
//
// It is the body of `servedRoutes` with the collision check and the empty check
// left off, because these tests want to COUNT what is visible and a count of zero
// is the thing several of them assert against. The two callers keep those checks:
// a checker that cannot fail is not a checker, and these helpers are not the
// checker.
func routesIn(t *testing.T, o options) map[operationKey]string {
	t.Helper()

	found := map[operationKey]string{}
	err := chi.Walk(newMux(nil, o), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		found[operationKey{Method: method, Path: normalisePath(route)}] = route
		return nil
	})
	if err != nil {
		t.Fatalf("walking the router: %v", err)
	}
	return found
}

// TestTheClaimWalkSeesEveryConditionalSurface asserts that a walk with all the
// doubles sees a route from EACH registrar, by route and not by field.
//
// Every entry is a route that exists only because one conditional surface is
// present, so a field left out of the literal drops exactly one of them and the
// check below reports one missing route rather than silently reporting a smaller
// service.
func TestTheClaimWalkSeesEveryConditionalSurface(t *testing.T) {
	found := routesIn(t, walkOptions())

	// One representative per conditional surface, chosen as the route that surface
	// exists to serve. The registrar is named in the message so a failure says which
	// field to add rather than just which route vanished.
	for _, want := range []struct {
		surface string
		key     operationKey
	}{
		{"auth", operationKey{Method: "POST", Path: "/v1/session"}},
		{"tenancy", operationKey{Method: "GET", Path: "/v1/accounts"}},
		{"oidcClients", operationKey{Method: "GET", Path: "/v1/accounts/{}/oidc-clients"}},
		{"oidc", operationKey{Method: "GET", Path: "/oidc/authorize"}},
		{"apiKeys", operationKey{Method: "GET", Path: "/v1/accounts/{}/api-keys"}},
		{"mfa", operationKey{Method: "GET", Path: "/v1/mfa"}},
		{"introspector", operationKey{Method: "POST", Path: "/v1/introspections"}},
		{"admin", operationKey{Method: "GET", Path: "/v1/accounts/{}/admin/audit-log"}},
		{"recovery", operationKey{Method: "POST", Path: "/v1/password-resets"}},
		// The social-login route is the one that was invisible to BOTH walks when it
		// landed, which is why this row is worth naming in this file as well as in
		// router_walk_test.go: this test is the one that would have caught it, had
		// anybody thought to add the row before mounting the surface.
		{"social", operationKey{Method: "GET", Path: "/v1/auth/oauth/{}"}},
	} {
		if _, ok := found[want.key]; !ok {
			t.Errorf("the claim walk does not see %s, so it does not see %s. The `options` "+
				"literal that configures the walk has no `%s` double, and `registerXRoutes` "+
				"returns early when the service is absent — so every claim check in this package "+
				"is currently reporting agreement about a service smaller than the one that runs.\n\n"+
				"Add the double to walkOptions AND to servedRoutes. They are the same tree and "+
				"they must not be configured separately.", want.key, want.surface, want.surface)
		}
	}
}

// TestTheClaimWalkSeesNothingWhenTheServicesAreAbsent is the negative, and it is
// what makes the test above mean something.
//
// A registrar that returns early when its service is nil is the mechanism the
// whole failure depends on. Asserting that a fully-populated walk finds routes and
// nothing about the empty case would still pass if every registrar ignored its
// options and mounted unconditionally — which is a different bug, and a real one
// worth knowing about on a service whose entire design is that an unconfigured
// deployment serves a clean 404 rather than a 500.
func TestTheClaimWalkSeesNothingWhenTheServicesAreAbsent(t *testing.T) {
	found := routesIn(t, options{})

	var conditional []string
	for key := range found {
		// The two probes are unconditional by design — `/healthz` is a constant
		// handler and readiness is registered whatever the checks are. Everything
		// else in this service is behind a surface.
		if key.Path == "/healthz" || key.Path == "/readyz" {
			continue
		}
		if strings.HasPrefix(key.Path, "/.well-known") {
			// The discovery documents are registered before the conditional
			// surfaces, so a process with no DATABASE_URL and no signing key can
			// still answer a probe for its own metadata. That is deliberate and
			// httpapi.go says why.
			continue
		}
		conditional = append(conditional, key.String())
	}
	sort.Strings(conditional)

	if len(conditional) > 0 {
		t.Errorf("a router built with no services at all still serves %d conditional "+
			"route(s):\n\n  %s\n\n"+
			"Every one of these is behind a surface that should have been absent. A registrar "+
			"that ignores its options and mounts anyway is a service whose \"absent without "+
			"configuration\" guarantee — the property the whole options struct exists for — is "+
			"not real, and the claim checks above would be holding claims against a router that "+
			"does not match any deployment.", len(conditional), strings.Join(conditional, "\n  "))
	}
}

// TestServedRoutesAndTheClaimWalkAgree is the consistency check between the two
// trees, and it exists because they are assembled by two literals in two files.
//
// `servedRoutes` is what the claim comparisons use. `walkOptions` is what the tests
// above use. They are written out separately — one in claims_test.go's neighbour
// openapi_drift_test.go, one here — and nothing forces them to stay the same. If
// they diverge, the tests in this file describe one router and the checks describe
// another, and both pass.
func TestServedRoutesAndTheClaimWalkAgree(t *testing.T) {
	declared := servedRoutes(t)
	actual := routesIn(t, walkOptions())

	for key := range declared {
		if _, ok := actual[key]; !ok {
			t.Errorf("servedRoutes reports %s but the walk this file configures does not. The "+
				"two options literals have diverged: openapi_drift_test.go's and this file's. "+
				"They describe the same deployed router, and a test suite that walks two "+
				"different routers reports agreement about a service neither one is.", key)
		}
	}
	for key := range actual {
		if _, ok := declared[key]; !ok {
			t.Errorf("the walk this file configures serves %s but servedRoutes does not report "+
				"it. Same divergence, other direction.", key)
		}
	}
}

// TestTheSocialLoginPrefixIsTheOneTheProviderBuilds ties this file's central
// constant to the code that would serve it.
//
// `socialLoginPrefix` is what the absence check looks for, and
// `Provider.RedirectURI` is what would build the real callback path. Nothing
// connects them except that both were written by reading the same idea, and a
// rename on one side would leave the absence test watching a path nothing will ever
// be mounted on — which passes, forever, while the feature ships at a new one.
//
// So the constant is checked against the function. It is a cheap test and it is the
// difference between a tripwire and a coincidence.
func TestTheSocialLoginPrefixIsTheOneTheProviderBuilds(t *testing.T) {
	const base = "https://identity.cafaye.com"

	// The REAL function, called with the real provider. This test could have
	// reimplemented the string concatenation and asserted against its own copy, and
	// that version would pass forever while the actual callback path moved — which is
	// the exact failure this file exists to prevent, committed in the test meant to
	// catch it.
	full := oauth.Google().RedirectURI(base)

	// RedirectURI returns an ABSOLUTE url, and the router serves paths. The
	// comparison has to be on the path component or it would be between a URL and a
	// path and would always disagree — and a test that always fails is a test that
	// gets deleted.
	parsed, err := url.Parse(full)
	if err != nil {
		t.Fatalf("parsing %q: %v", full, err)
	}
	if parsed.Host != strings.TrimPrefix(base, "https://") {
		t.Errorf("RedirectURI built %q, whose host is %q rather than the configured base's. "+
			"The function's whole argument is that the callback is derived from configuration "+
			"and never from a request, so a host that is not the configured one is a defect "+
			"wherever it came from.", full, parsed.Host)
	}

	path := parsed.Path
	if !strings.HasPrefix(path, socialLoginPrefix+"/") {
		t.Errorf("oauth.Provider.RedirectURI builds the path %q, which does not begin with "+
			"socialLoginPrefix %q. The absence check in oauth_absent_test.go watches a path the "+
			"surface would never be mounted on, so it would pass while the feature shipped "+
			"somewhere else.", path, socialLoginPrefix)
	}
	if !strings.HasSuffix(path, "/callback") {
		t.Errorf("oauth.Provider.RedirectURI builds the path %q, which does not end in "+
			"/callback. The README records that path, and so does the state's own test.", path)
	}

	// The README quotes the path with a {provider} placeholder rather than a concrete
	// name, so the two cannot be compared as strings. What can be checked is that the
	// README's quoted prefix is a prefix of the real path once the provider is
	// substituted — which is what makes the README's sentence true rather than
	// merely similar.
	readme, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("reading %s: %v", readmePath, err)
	}
	quoted := socialLoginPrefix + "/{provider}/callback"
	if !strings.Contains(string(readme), quoted) {
		t.Errorf("README.md does not quote the callback path %q, and RedirectURI really builds "+
			"%q. The section tells a reader to check for themselves that nothing serves the "+
			"social callback, and a path that is not the real one does not let them.",
			quoted, path)
	}
}
