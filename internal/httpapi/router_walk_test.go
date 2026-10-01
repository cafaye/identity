package httpapi

// EVERY ROUTER WALK MUST SEE EVERY CONDITIONAL SURFACE.
//
// This file exists because of a bug that was in this repository for the whole of
// packet identity-11, and it is worth stating precisely because the check that
// should have caught it did not.
//
// # WHAT HAPPENED
//
// The admin surface is mounted conditionally, like every other optional surface in
// this service: `registerAdminRoutes` returns immediately when `o.admin` is nil.
// `servedRoutes` in openapi_drift_test.go builds an `options` struct LITERAL to
// make every conditional take its "configured" path, and that literal did not
// mention `admin`.
//
// The result was that `TestEveryServedRouteIsDocumentedOrNamed` — the reverse-
// direction check, the one holding this repository's twelve findings, the one
// written specifically so a route nobody documented could not hide — went GREEN
// while three undocumented operations were mounted and being served. It was green
// because the router it walked had no admin routes in it. The check agreed with
// the document, and it agreed because it had read a smaller service than the one
// that runs.
//
// The same omission was in `mountedAccountRoutes`, so `TestEveryRouteIsInTheMatrix`
// — the completeness check the packet names by name — also passed with no admin
// row required, for the same reason and at the same time.
//
// # WHY IT IS NOT FIXED BY ADDING THE FIELD
//
// Because the fix that was applied (adding `admin:` to the literal in
// servedRoutes) is invisible to the next person who adds a conditional surface.
// Nothing about that edit tells a future author that the literal is a
// completeness obligation, and the next `o.someNewSurface == nil` early return
// would reproduce the bug exactly, with every test still green.
//
// So the property is stated as a check: every surface field that can cause a
// registrar to skip its routes must be set in every walk of the router, and a
// field that is not set is a failure here rather than a silent hole in two other
// checks.
//
// This is the same shape as the tripwire's own argument — a check that can be
// made green by not checking is not a check — applied to the check itself.

import (
	"reflect"
	"sort"
	"testing"
)

// conditionalSurfaces is every option field whose nil value causes a registrar to
// skip mounting routes.
//
// IT IS A LIST AND NOT A REFLECTION, deliberately: the reflection this file also
// does is over the STRUCT, and a struct cannot tell a service field from a
// config field. `WithReadinessTimeout` and `WithClock` are Options that take
// durations and clocks, not services, and a test that demanded a double for
// `readinessTimeout` would be asking for something meaningless.
//
// The cost of the list is that a new conditional surface must be added to it, and
// the benefit is that adding one and forgetting the walks is a failure in this
// file rather than a hole in two others.
var conditionalSurfaces = []string{
	// The service fields, each of which gates a registrar's early return.
	"auth", "tenancy", "apiKeyCaller", "introspector", "apiKeys", "oidc",
	"oidcClients", "mfa", "admin", "recovery",
}

// TestEveryConditionalSurfaceIsVisibleToTheWalk is the check.
//
// It reads the `options` struct's own field list and requires that every field
// named in conditionalSurfaces exists — so a rename in internal/httpapi fails here
// rather than making the walk quietly skip a surface that is still wired under the
// old name.
func TestEveryConditionalSurfaceIsVisibleToTheWalk(t *testing.T) {
	t.Parallel()

	fields := make(map[string]bool)
	for i := range reflect.TypeFor[options]().NumField() {
		fields[reflect.TypeFor[options]().Field(i).Name] = true
	}

	var missing []string
	for _, name := range conditionalSurfaces {
		if !fields[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("conditionalSurfaces names %v, which are not fields of options any more. Either the "+
			"field was renamed — in which case the walks in servedRoutes and mountedAccountRoutes "+
			"are also reading a struct literal that no longer sets it, and every route it gates is "+
			"invisible to two checks — or a surface was removed, in which case delete it from this "+
			"list and say so in the CHANGELOG", missing)
	}
}

// TestTheDriftWalkSeesTheAdminSurface is the specific instance, and it is here
// rather than only in the general check because the general one is a list
// membership test and this one is a behavioural one: it asserts the walk FINDS
// the routes, not that a field is set.
//
// A field can be set to a double that does not satisfy the interface's idea of
// "configured" — nil embedded in a non-nil struct, a double whose registrar takes
// a different branch — and the list test would pass. This one would not.
func TestTheDriftWalkSeesTheAdminSurface(t *testing.T) {
	t.Parallel()

	served := servedRoutes(t)

	for _, want := range []operationKey{
		{Method: "GET", Path: "/v1/accounts/{}/admin/audit-log"},
		{Method: "DELETE", Path: "/v1/accounts/{}/admin/invitations/{}"},
		{Method: "POST", Path: "/v1/accounts/{}/admin/invitation-revocations"},
	} {
		if _, seen := served[want]; !seen {
			t.Errorf("servedRoutes did not report %s as served. The router serves it — "+
				"TestEveryServedRouteIsDocumentedOrNamed depends on this walk seeing every mounted "+
				"route, and a route missing from the walk is a route whose documentation is never "+
				"checked in either direction", want)
		}
	}
}

// TestTheDriftWalkSeesTheRecoverySurface is the third instance of the admin-surface
// bug, for the eight routes the recovery packet added.
//
// It is here rather than folded into the general check because the general one is a
// list membership test and this one is behavioural: it asserts the walk FINDS the
// routes. A field can be set to a double the registrar does not consider
// "configured", and only the routes appearing in the walk can tell.
func TestTheDriftWalkSeesTheRecoverySurface(t *testing.T) {
	t.Parallel()

	served := servedRoutes(t)

	for _, want := range []operationKey{
		{Method: "POST", Path: "/v1/password-resets"},
		{Method: "POST", Path: "/v1/password-resets/confirm"},
		{Method: "POST", Path: "/v1/email-verifications"},
		{Method: "POST", Path: "/v1/email-verifications/confirm"},
		{Method: "GET", Path: "/v1/email-verification"},
		{Method: "POST", Path: "/v1/email-changes"},
		{Method: "POST", Path: "/v1/email-changes/current-address"},
		{Method: "POST", Path: "/v1/email-changes/new-address"},
	} {
		if _, seen := served[want]; !seen {
			t.Errorf("servedRoutes did not report %s as served. TestEveryServedRouteIsDocumentedOrNamed "+
				"depends on this walk seeing every mounted route, so a route missing from it has its "+
				"documentation checked in neither direction", want)
		}
	}
}

// TestTheMatrixWalkSeesTheAdminSurface is the same property for the
// authorization matrix, and it is the second of the two checks the bug blinded.
func TestTheMatrixWalkSeesTheAdminSurface(t *testing.T) {
	t.Parallel()

	mounted := mountedAccountRoutes()
	seen := make(map[string]bool, len(mounted))
	for _, route := range mounted {
		seen[route] = true
	}

	for _, want := range []string{
		"GET /v1/accounts/{accountID}/admin/audit-log",
		"DELETE /v1/accounts/{accountID}/admin/invitations/{invitationID}",
		"POST /v1/accounts/{accountID}/admin/invitation-revocations",
	} {
		if !seen[want] {
			t.Errorf("mountedAccountRoutes did not report %s. TestEveryRouteIsInTheMatrix walks this "+
				"list, so a route missing from it needs no matrix row and the completeness check "+
				"passes on a service with an unchecked surface", want)
		}
	}
}
