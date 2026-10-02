package httpapi

// THE PROOF THAT THE TRIPWIRE STILL BITES AFTER THE LIST EMPTIED.
//
// ## WHY THIS FILE EXISTS AT ALL
//
// `knownDrift` went from twelve entries to zero in packet identity-28, and the
// check it was holding in place is now the only thing standing between a
// forgotten route and a contract that does not describe it. A check that has
// never gone red has not been shown to work, and this one had exactly one run in
// its life that reported a finding — before the fix.
//
// So it gets run again here, pointed at the same twelve, in the state they were
// in when the check found them. Nothing about the twelve is reconstructed by
// hand: the routes come out of the REAL router walk, the operationIds come out
// of the REAL documents, and the only thing this file changes is the document —
// it removes the entries packet identity-28 added. Everything else is the code
// the suite runs every day.
//
// ## IT IS A RECONSTRUCTION, AND HERE IS THE ONE THING IT DOES NOT PROVE
//
// It proves that `diff(readTheContract(t), servedRoutes(t), knownDrift)` reports
// all twelve as unexplained with the map as it stands today — which is the
// expression `TestEveryServedRouteIsDocumentedOrNamed` evaluates, so that test
// would fail on exactly this input.
//
// It does not prove the service ever routed these twice, and it does not need to.
// The claim under test is about the COMPARISON, not about the router: given a
// served operation no document describes and an admission list that does not
// contain it, the check must say so. A hand-written pair of one-off maps would
// have proven the same thing with a fraction of the machinery, and would have
// kept proving it if the real reader quietly stopped reading — which is the way
// every other check in this package has already been fooled once.

import (
	"strings"
	"testing"
)

// documentedTwelve is the (method, path) list packet identity-28 removed from the
// two documents, in the spelling each document uses for itself.
//
// The path parameter names DIFFER between the documents and the router
// (`{account_id}` in YAML, `{accountID}` in chi) and `normalisePath` is what
// makes those one route, so this list is written with each side's own spelling
// rather than with one of them, and the keys are normalised on the way in. That
// is also the reason a renamed parameter is not drift, and the reason this list
// is hand-written at all: `TestARenamedPathParameterIsNotDrift` already covers
// the normaliser on its own.
var documentedTwelve = []operationKey{
	{Method: "POST", Path: "/v1/accounts"},
	{Method: "GET", Path: "/v1/accounts"},
	{Method: "GET", Path: "/v1/accounts/{account_id}"},
	{Method: "PATCH", Path: "/v1/accounts/{account_id}"},
	{Method: "DELETE", Path: "/v1/accounts/{account_id}"},
	{Method: "GET", Path: "/v1/accounts/{account_id}/members"},
	{Method: "POST", Path: "/v1/accounts/{account_id}/invitations"},
	{Method: "PATCH", Path: "/v1/accounts/{account_id}/members/{user_id}"},
	{Method: "DELETE", Path: "/v1/accounts/{account_id}/members/{user_id}"},
	{Method: "POST", Path: "/v1/invitations/accept"},
	{Method: "POST", Path: "/oidc/authorize"},
	{Method: "POST", Path: "/oidc/userinfo"},
}

// TestTheTwelveThisPacketClosedAreCaughtAgainIfAnyOfThemReturns is the check
// biting, on the real reader and the real router, with the real (empty) list.
//
// The direction is what matters: this removes DOCUMENT ENTRIES and keeps every
// route, which is exactly the state the repository was in on 2026-09-30 when
// identity-09's first run reported twelve undocumented operations.
func TestTheTwelveThisPacketClosedAreCaughtAgainIfAnyOfThemReturns(t *testing.T) {
	// The list first, because the whole claim is about the comparison refusing to
	// fall back on an admission. If a future packet puts one of these twelve back,
	// this test says so on its own terms rather than failing somewhere vaguer.
	if len(knownDrift) != 0 {
		t.Fatalf("knownDrift has %d entries, so this test is comparing against admissions "+
			"and the twelve below are not being measured on their own. That is a finding "+
			"about knownDrift, not about the comparison — read "+
			"TestKnownDriftIsEmptyBecauseEveryServedOperationIsDocumented first.",
			len(knownDrift))
	}

	full := readTheContract(t)
	before := map[operationKey]documentedOperation{}
	for key, op := range full {
		before[key] = op
	}
	for _, gone := range documentedTwelve {
		delete(before, operationKey{Method: gone.Method, Path: normalisePath(gone.Path)})
	}

	// The removal has to be REAL for the rest of this test to mean anything: if
	// this packet's document entries were never written, there is nothing to take
	// back and the twelve below would be unexplained for the wrong reason.
	for _, gone := range documentedTwelve {
		key := operationKey{Method: gone.Method, Path: normalisePath(gone.Path)}
		if _, present := full[key]; !present {
			t.Fatalf("the two documents do not describe %s, so this packet closed nothing "+
				"and the assertion below would pass against a service that was never "+
				"documented. Fix the document or fix this test — do not let it rot.", key)
		}
		if _, still := before[key]; still {
			t.Fatalf("removing %s from the contract did not take, so the twelve below would "+
				"be unexplained for the wrong reason.", key)
		}
	}

	unexplained := diff(before, servedRoutes(t), knownDrift).Unexplained
	got := map[string]bool{}
	for _, name := range unexplained {
		got[name] = true
	}

	var missed []string
	for _, gone := range documentedTwelve {
		key := operationKey{Method: gone.Method, Path: normalisePath(gone.Path)}
		if !got[key.String()] {
			missed = append(missed, key.String())
		}
	}
	if len(missed) > 0 {
		sortStrings(missed)
		t.Errorf("with their document entries removed, %d of the twelve are NOT reported as "+
			"undocumented:\n\n  %s\n\n"+
			"The check that holds this repository's contract to its router does not see them. "+
			"Either diff stopped admitting what it cannot account for, or the empty knownDrift "+
			"is being consulted in some way this test cannot see — and both of those are the "+
			"failure a green suite would have hidden.",
			len(missed), strings.Join(missed, "\n  "))
	}

	// And the OTHER direction, because a check that only ever reports one thing is
	// half a check: removing a document entry must not make anything look served
	// but undocumented that is not one of the twelve. The router has not changed,
	// so this is the full served set minus exactly what was taken away.
	if len(unexplained) != len(documentedTwelve) {
		names := append([]string(nil), unexplained...)
		sortStrings(names)
		t.Errorf("the pre-packet comparison reported %d unexplained operation(s), want exactly "+
			"the twelve:\n\n  %s\n\nA number other than twelve means the contract this test "+
			"reconstructed is not the pre-packet contract, and a check over the wrong set "+
			"proves nothing.", len(unexplained), strings.Join(names, "\n  "))
	}
}

// TestAnOperationTheDocumentDoesNotDescribeIsReported is the same claim about one
// route, with the subtraction taken from ONE side.
//
// The route is chosen out of the router's own walk rather than named, so this test
// does not itself become a second hand-maintained route list — the mistake this
// whole file exists because of. And only the DOCUMENT loses it: taking it out of
// both sides would test that a route nobody serves and nobody documents is
// reported, which is trivially true and is not the property.
func TestAnOperationTheDocumentDoesNotDescribeIsReported(t *testing.T) {
	served := servedRoutes(t)
	if len(served) == 0 {
		t.Fatal("the router was read as serving nothing, so there is no route to un-document.")
	}

	var victim operationKey
	for key := range served {
		victim = key
		break
	}

	contract := map[operationKey]documentedOperation{}
	for key, op := range readTheContract(t) {
		if key != victim {
			contract[key] = op
		}
	}

	got := diff(contract, served, knownDrift)
	if len(got.Unexplained) != 1 || got.Unexplained[0] != victim.String() {
		t.Errorf("with %s removed from the documents and left served, the check reported %v, "+
			"want exactly [%s].\n\n"+
			"This is the smallest possible statement of the property the check exists for: a "+
			"route that is served and documented nowhere, against an empty admission list, "+
			"has to be reported — otherwise the check is decoration and the next route nobody "+
			"wrote down goes straight through it.",
			victim, got.Unexplained, victim)
	}
	if len(got.DocumentedNotServed) != 0 {
		t.Errorf("taking one entry out of the documents reported %v as documented-but-unserved; "+
			"it is still served, so it belongs in Unexplained and nowhere else.",
			got.DocumentedNotServed)
	}
}
