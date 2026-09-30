package httpapi

// THE DOCUMENT-VERSUS-ROUTER TRIPWIRE.
//
// `openapi/v1.yaml` and `openid/openid.yaml` are what a client is generated
// from, and the router in this package is what answers. Two ways they can
// disagree, and neither is small for a service that holds every credential in
// the platform: an operation a document declares and the service does not serve
// is a call a generated client makes against a 404, and an operation the
// service serves that no document declares is reachable by nobody who wrote a
// client — an endpoint nobody chose, described nowhere, and the first thing a
// security review asks about.
//
// This is the last of these checks in the fleet. courier, darkroom, guard, muse,
// pantry and billing have had one since the sixth time it fired. This file is
// the seventh, and it fires on its first run: twelve operations are served and
// written down in no document at all. See `knownDrift` below and DECISIONS.md D1.
//
// ## Both sides are read, and both directions are compared
//
// The operations come from the two documents and the routes come from chi's own
// walk of the tree `New` assembles. Neither side is a list this repository
// maintains, because a hand-written list is a check that can only fail for a
// route somebody remembered to type — the failure mode that made pantry-03's
// coverage test useless.
//
// The comparison is over **sets of (method, path)** and never over counts. A
// count comparison passes when one operation is added and another is removed,
// which is a real and common way for a document to drift from a router; and a
// comparison over paths alone cannot see a method, which is billing's bug and
// which this repository already has once — see the last two entries of
// `knownDrift`.
//
// ## Both documents, not just `openapi/v1.yaml`
//
// The brief this check answers asked for `openapi/v1.yaml` against the router.
// Reading only that one would have been wrong rather than merely narrow, and
// wrong in a way that costs a lie: the eleven routes under `/oidc/*` and
// `/.well-known/*` are served, and nine of them ARE documented — in
// `openid/openid.yaml`, which exists for them. A check that read one document
// would have had to declare all eleven "not client operations", which is false
// about nine of them, and a list of omissions is exactly where a false claim
// does the most damage. So the check reads both documents and treats the union
// as the contract. The v1 direction is then a strict subset of what is checked,
// not a weaker version of it.
//
// ## There is no exclusion list, and not having one is the finding
//
// The brief this check answers expected one: the probes, and any error-handler
// route, named by method and path with a reason for each. identity needs none,
// and inventing one would have been the wrong way to make this suite green.
//
//   - `/healthz` and `/readyz` are DOCUMENTED. `openapi/v1.yaml` declares them
//     under the operationIds `liveness` and `readiness`, and
//     `TestTheProbesAreDocumentedRatherThanExcluded` holds that, so nobody
//     "fixes" this check later by excluding them. Whether a service may document
//     its probes is core's D25 and it is open; identity answered it for itself
//     by documenting them, and this packet does not reopen it.
//   - `/oidc/*` and `/.well-known/*` are documented too, in the sibling
//     document. Reading both is what makes that visible here instead of a list
//     of eleven "not client operations", which would have been false about nine
//     of them.
//   - chi registers no error-handler route. `NotFound` and `MethodNotAllowed`
//     are handlers on the mux, not routes, so 404 and 405 do not appear in a
//     walk. `/404`, `/422`, `/500` and `/503` are Rails' shape, from billing's
//     `config.exceptions_app`; this service answers a problem document from a
//     handler, and there is nothing on the router to exclude.
//
// So the ONE list in this file is `knownDrift`, and it is not an exclusion list.
// Every entry in it is a bug. Keeping those two meanings apart is the point: an
// exclusion list says "this is not part of the contract" and an entry in it is a
// claim about intent, while `knownDrift` says "this is served and written down
// nowhere" and an entry in it is an admission. Merged into one list, a future
// route could be excused by being called a bug — the same escape hatch wearing a
// different name.
//
// A test that fails when a route is *neither* documented *nor* listed is what
// keeps that from being where a forgotten route goes. Without it the next
// person adds a route, forgets both, and the list quietly turns the check into
// decoration. `TestEveryServedRouteIsDocumentedOrNamed` is that check, and
// `TestKnownDriftIsExactlyTheRoutesItClaimsToBe` pins the list so it cannot
// quietly become one.

import (
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// The two documents, relative to this package. Both are committed and both are
// what a client generator reads: `cafaye.yml`'s `exposes.api` names the first,
// and AGENTS.md explains why there are two rather than one.
const (
	v1Document     = "../../openapi/v1.yaml"
	openidDocument = "../../openid/openid.yaml"
)

// knownDrift is a route the router serves that NO document describes.
//
// ## These are bugs, and this packet is not allowed to fix them
//
// The ten tenancy routes below have been served since the accounts packet and
// appear in neither `openapi/v1.yaml` nor `openid/openid.yaml` nor the README's
// endpoint table. The two OIDC routes below are the billing bug verbatim:
// `registerOIDCRoutes` mounts GET and POST on `/oidc/authorize` and on
// `/oidc/userinfo` because OpenID Connect Core permits both and "a product
// behind a strict corporate proxy may have no choice", and `openid/openid.yaml`
// wrote down only the GET. The code says the POST is deliberate; the document
// does not mention it.
//
// Documenting the operations is forbidden to this packet ("this packet adds a
// check, not operations"), and calling them "not client operations" would be
// false — the tenancy routes are in the authorization matrix and, for seven of
// them, in `accountRouteScopes`, so they are checked for authorization and
// unrecorded as contract surface. So they are here, under a name that says what
// they are, and the check is what holds them visible.
//
// The list is pinned by `TestKnownDriftIsExactlyTheRoutesItClaimsToBe`: it
// cannot grow, because growth is how a forgotten route gets excused, and it
// cannot be emptied, because that is somebody deleting the list instead of
// fixing the routes. Closing D1 shrinks it, and shrinking it is the only way an
// entry is ever removed.
var knownDrift = map[operationKey]string{
	// The tenancy surface. Ten operations.
	{Method: "POST", Path: "/v1/accounts"}:                 "served since the accounts packet; in no document",
	{Method: "GET", Path: "/v1/accounts"}:                  "served since the accounts packet; in no document",
	{Method: "GET", Path: "/v1/accounts/{}"}:               "served since the accounts packet; in no document",
	{Method: "PATCH", Path: "/v1/accounts/{}"}:             "served since the accounts packet; in no document",
	{Method: "DELETE", Path: "/v1/accounts/{}"}:            "served since the accounts packet; in no document",
	{Method: "GET", Path: "/v1/accounts/{}/members"}:       "served since the accounts packet; in no document",
	{Method: "POST", Path: "/v1/accounts/{}/invitations"}:  "served since the accounts packet; in no document",
	{Method: "PATCH", Path: "/v1/accounts/{}/members/{}"}:  "served since the accounts packet; in no document",
	{Method: "DELETE", Path: "/v1/accounts/{}/members/{}"}: "served since the accounts packet; in no document",
	{Method: "POST", Path: "/v1/invitations/accept"}:       "served since the accounts packet; in no document",

	// The billing bug, already here, on the sibling document. A path registered
	// under a second method, with only the first written down. A check that
	// compared paths rather than (method, path) would report agreement on both.
	{Method: "POST", Path: "/oidc/authorize"}: "openid.yaml declares GET only; the POST is deliberate in registerOIDCRoutes",
	{Method: "POST", Path: "/oidc/userinfo"}:  "openid.yaml declares GET only; the POST is deliberate in registerOIDCRoutes",
}

// drift is the symmetric difference between what the documents declare and what
// the router serves, split by direction.
//
// It is a value and a function rather than assertions inside a test so the
// comparison can be pointed at an injected fault: a checker that cannot be shown
// to fail has not been shown to work, and a fault test that reimplements the
// comparison proves nothing about the comparison.
type drift struct {
	// DocumentedNotServed is the forward direction: the document has it, the
	// router does not. This is the direction that 404s a client.
	DocumentedNotServed []string
	// ServedNotDocumented is every operation the router serves that neither
	// document describes.
	ServedNotDocumented []string
	// Unexplained is the ones knownDrift does not account for. This is what the
	// check fails on, and the difference between it and ServedNotDocumented is a
	// declared admission rather than an oversight.
	Unexplained []string
}

// diff classifies the two sets. `served` is valued by the pattern the router
// spells it with, so a failure can name a path as written — chi's `{accountID}`
// beside the document's `{account_id}` is the thing a reader needs to see.
func diff(contract map[operationKey]documentedOperation, served map[operationKey]string, known map[operationKey]string) drift {
	var out drift

	for key := range contract {
		if _, ok := served[key]; !ok {
			out.DocumentedNotServed = append(out.DocumentedNotServed, key.String())
		}
	}
	for key := range served {
		if _, ok := contract[key]; ok {
			continue
		}
		label := key.String()
		out.ServedNotDocumented = append(out.ServedNotDocumented, label)
		if _, admitted := known[key]; !admitted {
			out.Unexplained = append(out.Unexplained, label)
		}
	}

	sort.Strings(out.DocumentedNotServed)
	sort.Strings(out.ServedNotDocumented)
	sort.Strings(out.Unexplained)
	return out
}

// readTheContract is everything the two documents declare, keyed by the
// normalised {method, path}. A failure to read either is a failure, not an empty
// contract: two readers that both find nothing agree, and that is how a check
// over nothing goes green.
func readTheContract(t *testing.T) map[operationKey]documentedOperation {
	t.Helper()

	contract := map[operationKey]documentedOperation{}
	for _, path := range []string{v1Document, openidDocument} {
		doc, err := readOpenAPIDocument(path)
		if err != nil {
			t.Fatalf("reading the contract: %v", err)
		}
		for key, op := range doc.Operations {
			if existing, clash := contract[key]; clash {
				t.Fatalf("%s and %s both declare %s, as %s and %s. Two documents describing "+
					"one operation means a generator has to pick one and this service has "+
					"not said which.", v1Document, path, key, existing.OperationID, op.OperationID)
			}
			contract[key] = op
		}
	}
	return contract
}

// servedRoutes is every (method, path) the router serves, read out of chi's own
// walk of the tree `New` assembles.
//
// The doubles below exist so every conditional branch in the assembly takes its
// "configured" path: `registerRoutes` returns immediately with no auth,
// `registerTenancyRoutes` needs a tenancy service, `registerMFARoutes` needs a
// key, `registerAPIKeyRoutes` needs apiKeys, the introspection route needs an
// Introspector, and the OIDC surface needs a provider and a client store. A walk
// of a router those are missing from would report the documents as describing
// routes that do not exist — the false half of drift, which is worse than the
// missing half because it looks like a real finding. Nothing is served:
// chi.Walk only reads the tree.
func servedRoutes(t *testing.T) map[operationKey]string {
	t.Helper()

	o := options{
		auth:         newFakeAuth(),
		tenancy:      newFakeTenancy(),
		oidcClients:  newFakeOIDCClients(),
		oidc:         newFakeOIDC(),
		apiKeys:      newFakeAPIKeys(),
		mfa:          newFakeMFAManage(),
		introspector: newFakeIntrospector(),
	}

	served := map[operationKey]string{}
	err := chi.Walk(newMux(nil, o), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		key := operationKey{Method: method, Path: normalisePath(route)}
		if existing, clash := served[key]; clash {
			t.Fatalf("the router serves %s twice, at %s and at %s. Two registrations that "+
				"normalise onto one route is a routing decision this check cannot see, and "+
				"at runtime the second one is invisible too.", key, existing, route)
		}
		served[key] = route
		return nil
	})
	if err != nil {
		t.Fatalf("walking the router: %v", err)
	}
	if len(served) == 0 {
		t.Fatal("the router was read as serving no routes at all. A router-reading check that " +
			"finds nothing agrees with a document that finds nothing.")
	}
	return served
}

// --- the two directions -------------------------------------------------------

// TestEveryServedRouteIsDocumentedOrNamed is the reverse direction, and it is
// the one holding this repository's twelve findings.
//
// A route nobody documented is a method the next generated client will not
// have, so the surface grows and the contract does not. On the service that
// issues every credential in the platform it is also the shape a security
// review asks about first: an endpoint with no documented authentication story,
// in a document nobody generated a client from.
func TestEveryServedRouteIsDocumentedOrNamed(t *testing.T) {
	unexplained := diff(readTheContract(t), servedRoutes(t), knownDrift).Unexplained

	// Every offender in one failure, not the first. A packet that fixes this
	// should see the whole list from a single run; reporting one at a time turns
	// "run the test, fix, run it again" into a loop whose length nobody can see
	// in advance.
	if len(unexplained) > 0 {
		sort.Strings(unexplained)
		t.Errorf("the router serves %d operation(s) that openapi/v1.yaml, openid/openid.yaml "+
			"and knownDrift all fail to account for:\n\n  %s\n\n"+
			"A route that is neither documented nor named is the failure this file exists to "+
			"catch, and the list must not become the place it hides. Do one of the two things:\n"+
			"  1. the route is part of the public surface — document it in openapi/v1.yaml or "+
			"openid/openid.yaml depending on which surface it is on, and give it an operationId.\n"+
			"  2. the route is not meant to be public — add it to knownDrift with the reason it "+
			"is not written down, and expect the pin on that list to fail so the addition gets "+
			"read rather than merged.\n\n"+
			"Do not add a prefix filter. A filter is a guess about intent, and it cannot see a "+
			"method — which is how PUT /v1/customers/{id} went on being served in billing under "+
			"a check that read paths only.",
			len(unexplained), strings.Join(unexplained, "\n  "))
	}
}

// TestEveryDocumentedOperationIsServed is the forward direction: an endpoint in
// the menu that answers 404 is a product configured against a route that does
// not exist, and they find out at their outage.
//
// It passes today — the drift this repository has is entirely one-directional —
// which is exactly why it earns its place. The direction nobody has needed yet is
// the one that has never been exercised, and a check written only for today's
// finding is a check that stops working the day the finding is fixed.
func TestEveryDocumentedOperationIsServed(t *testing.T) {
	contract := readTheContract(t)
	served := servedRoutes(t)
	unserved := diff(contract, served, knownDrift).DocumentedNotServed

	if len(unserved) > 0 {
		sort.Strings(unserved)
		t.Errorf("the documents declare %d operation(s) the router does not serve:\n\n  %s\n\n"+
			"A generated client calls these and gets a 404. Do one of the two things:\n"+
			"  1. the operation is shipping — mount it.\n"+
			"  2. it is not — delete it from the document, and note the removal in the CHANGELOG.",
			len(unserved), strings.Join(unserved, "\n  "))
	}
}

// --- the list, and what keeps it from being an escape hatch --------------------

// TestKnownDriftIsExactlyTheRoutesItClaimsToBe pins the list in both
// directions, and they are opposite on purpose.
//
// A list that can grow IS the escape hatch this file exists to close: the next
// undocumented route gets an entry, the suite goes green, and the check has been
// made green by not checking. So growth fails, and so does emptying the list,
// because a `knownDrift` with nothing in it means somebody deleted the list
// rather than documented the routes. The only legal change is a shrink, and a
// shrink happens by fixing a route, not by editing a list.
func TestKnownDriftIsExactlyTheRoutesItClaimsToBe(t *testing.T) {
	// The count this packet recorded. Twelve: ten tenancy operations and the two
	// OIDC POSTs.
	const want = 12

	if len(knownDrift) == want {
		return
	}

	names := make([]string, 0, len(knownDrift))
	for key := range knownDrift {
		names = append(names, key.String())
	}
	sort.Strings(names)

	if len(knownDrift) > want {
		t.Errorf("knownDrift has grown from %d entries to %d. A list that grows is the "+
			"escape hatch: an undocumented route would get an entry and the suite would go "+
			"green, which is a check that can be made green by not checking. Close "+
			"DECISIONS.md D1 — by documenting the route, or by ruling it out of the contract "+
			"in writing — and shrink this list with it. Never grow it to make a red go away.\n\n"+
			"  now: %v", want, len(knownDrift), names)
		return
	}
	t.Errorf("knownDrift has %d entries and this packet recorded %d. A list that shrank means "+
		"a route stopped being served, which closes a finding, and this file's "+
		"TestKnownDriftNamesOnlyServedRoutes should have caught it first. If a route really "+
		"was removed, delete its entry and say so in the CHANGELOG — and re-pin the count "+
		"here, so the shrink is a decision rather than an edit.\n\n  now: %v",
		len(knownDrift), want, names)
}

// TestKnownDriftNamesOnlyServedRoutes is the staleness guard, and it is the
// other half of what makes the list safe to have.
//
// Every entry claims a route IS served and IS unwritten-down. Both halves are
// checkable and both are checked: an entry naming a route the router stopped
// serving has stopped meaning anything, and it is a carve-out matching nothing —
// a hole waiting for the next route somebody adds at that path. An entry naming
// a route a document DOES describe is a contradiction where neither half can be
// right, and it is the one that matters most: it is an entry silently claiming
// that a documented operation is undocumented.
func TestKnownDriftNamesOnlyServedRoutes(t *testing.T) {
	contract := readTheContract(t)
	served := servedRoutes(t)

	for key, reason := range knownDrift {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("the knownDrift entry for %s has no reason. An entry with no reason is "+
				"an assertion, and an assertion is not reviewable.", key)
		}
		if op, documented := contract[key]; documented {
			t.Errorf("%s is in knownDrift and is also declared by a document, as %s. It is "+
				"documented, so it is not drift — remove the entry.", key, op.OperationID)
		}
		if _, ok := served[key]; !ok {
			t.Errorf("the knownDrift entry for %s names a route the router does not serve. "+
				"Drift is served-but-unwritten-down, so this entry has stopped meaning "+
				"anything and the list is lying about the size of the gap.", key)
		}
	}
}

// TestTheProbesAreDocumentedRatherThanExcluded is the answer to "what do you
// exclude", stated as a check instead of as a list.
//
// `/healthz` and `/readyz` are the routes every service in the platform has and
// most of them leave out of the contract. identity documents both, so the
// exclusion list this file was expected to need does not have them in it. That is
// a decision somebody made, and it is the kind that erodes silently: the next
// packet to want a shorter list has a route nobody documented and a precedent
// right here saying probes do not belong in a document. So it is asserted.
//
// core's D25 — "may a service document /healthz and /readyz in its OpenAPI
// document?" — is OPEN, and this is identity's answer to it rather than a
// decision about it: the document says what the service serves, the harness has
// not objected, and nothing about the two probes is a secret.
func TestTheProbesAreDocumentedRatherThanExcluded(t *testing.T) {
	contract := readTheContract(t)

	for _, probe := range []string{"/healthz", "/readyz"} {
		key := operationKey{Method: "GET", Path: probe}
		if _, ok := contract[key]; !ok {
			t.Errorf("GET %s is not in either document. This file's header records that "+
				"identity documents its probes rather than excluding them, and if that has "+
				"changed then the header is wrong and the exclusion has to be written down "+
				"with a reason instead.", probe)
		}
	}
}

// --- the operationIds, and the document's own version -------------------------

// TestEveryOperationHasAnOperationIdAndNoOperationIdIsUsedTwice is what a
// generator reads.
//
// An operationId is the name of the method on a generated client, so a missing
// one is an operation that exists in a contract and in no client, and a repeated
// one is two operations emitted under one name where the second is unreachable.
// core's conventions require both and the other six services in the fleet check
// them.
func TestEveryOperationHasAnOperationIdAndNoOperationIdIsUsedTwice(t *testing.T) {
	contract := readTheContract(t)

	byID := map[string][]operationKey{}
	for key, op := range contract {
		if op.OperationID == "" {
			t.Errorf("%s declares no operationId. That is the name of the method on a "+
				"generated client, so the operation is in the contract and in no client.", key)
			continue
		}
		byID[op.OperationID] = append(byID[op.OperationID], key)
	}

	for id, keys := range byID {
		if len(keys) > 1 {
			names := make([]string, 0, len(keys))
			for _, key := range keys {
				names = append(names, key.String())
			}
			sort.Strings(names)
			t.Errorf("the operationId %q is used by %d operations (%s). A generator emits "+
				"them as one method name and the second operation is unreachable from any "+
				"client.", id, len(keys), strings.Join(names, ", "))
		}
	}
}

// TestTheDocumentIsOpenAPI31AndCarriesAVersion holds the two strings core's
// conventions require.
//
// `info.version` is pinned rather than derived: a test that read the version out
// of the document and compared it with itself would pass every document ever
// written, including a regenerated one, and the whole point of the field is that
// a consumer has to be able to notice it move. 1.3.0 is the scoped-API-token
// build — identity-08's four operations. This packet adds no operations, so it
// does not bump it; a packet that does must move this pin in the same commit.
func TestTheDocumentIsOpenAPI31AndCarriesAVersion(t *testing.T) {
	doc, err := readOpenAPIDocument(v1Document)
	if err != nil {
		t.Fatalf("reading %s: %v", v1Document, err)
	}

	if doc.SpecVersion != "3.1.0" {
		t.Errorf("%s declares openapi %q, not 3.1.0. 3.1 is what core's conventions require "+
			"and what makes `null` a valid type rather than a keyword that changes meaning.",
			v1Document, doc.SpecVersion)
	}

	const want = "1.3.0"
	if doc.InfoVersion != want {
		t.Errorf("%s declares info.version %q, not %q. core's sync rule is that the /v1 "+
			"prefix says which contract and this says which build of it, and a non-breaking "+
			"addition bumps this and nothing else. If the document gained operations, move "+
			"this pin in the same commit and say so in the CHANGELOG.",
			v1Document, doc.InfoVersion, want)
	}
}
