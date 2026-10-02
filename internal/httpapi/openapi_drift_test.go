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
// the seventh, and it fired on its first run: twelve operations were served and
// written down in no document at all.
//
// It no longer does, and that is the whole of what packets identity-11 and
// identity-28 changed about it. All twelve are documented, `knownDrift` below is
// empty and pinned at empty, and the twelve are named in full in [DECISIONS.md
// D1]. What they bought is the thing a check like this is actually for: a service
// whose contract is held to its router by a test rather than by whoever remembered
// to write the entry down.
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
// which this repository already had once — on `POST /oidc/authorize` and
// `POST /oidc/userinfo`, both of which identity-28 documented.
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
// `TestKnownDriftIsEmptyBecauseEveryServedOperationIsDocumented` pins the list at
// the state it is actually in — which, since identity-28, is empty. The map is
// kept rather than deleted for the reason its own comment gives: an empty map is
// an assertion and a deleted map is an invitation.

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
// ## IT IS EMPTY, AND THE EMPTY IS THE FINDING
//
// It held TWELVE entries when packet `identity-09` wrote this file, and it fired
// on its first run because of them:
//
//   - the ten tenancy operations — `POST`/`GET /v1/accounts`,
//     `GET`/`PATCH`/`DELETE /v1/accounts/{account_id}`,
//     `GET /v1/accounts/{account_id}/members`,
//     `POST /v1/accounts/{account_id}/invitations`,
//     `PATCH`/`DELETE /v1/accounts/{account_id}/members/{user_id}` and
//     `POST /v1/invitations/accept` — served since the accounts packet, gated,
//     scope-checked and in the authorization matrix, and written down in no
//     document at all;
//   - `POST /oidc/authorize` and `POST /oidc/userinfo`, which
//     `registerOIDCRoutes` mounts deliberately and `openid/openid.yaml` declared
//     only the `GET` of. billing's bug, on this service's own protocol surface.
//
// Packet `identity-28` closed all twelve by documenting them, and it emptied the
// list the only way this file permits: **an entry is removed by fixing the route,
// never by editing the list.** The count went from twelve to zero and the
// pin below moved in the same commit as the document entries, which is what makes
// a shrink reviewable.
//
// The customer-language reason, because "a list got shorter" is not a change to
// anybody: before it, a client generated from these documents could read an
// account's API keys and register its OIDC clients and had **no method at all** for
// creating the account, inviting anybody into it, or accepting an invitation. A
// product cannot onboard a tenant through the client it ships. See
// [DECISIONS.md D1].
//
// ## WHY IT IS STILL HERE, EMPTY
//
// Because an empty map and a deleted map are different things, and the difference
// is the whole safety property. A deleted list cannot be re-added to by a packet
// that has an entry to put in it, and it turns `TestEveryServedRouteIsDocumentedOrNamed`
// into a check over an unmuffled route set that a future edit could quietly
// re-broaden. The map stays; its emptiness is asserted, its contents are checked
// for staleness in both directions, and any addition has to name a real blocker
// and move the pin — which is three review-visible edits rather than one.
var knownDrift = map[operationKey]string{}

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
		// admin is here because a route that is not in this struct literal is a
		// route this walk does not see, and a check that cannot see a route cannot
		// report it as undocumented.
		//
		// IT IS NOT A HYPOTHETICAL. Adding the admin surface with the field left
		// out of this literal made TestEveryServedRouteIsDocumentedOrNamed, this
		// file's own finding, PASS while three undocumented operations were
		// mounted — because registerAdminRoutes returns early when the service is
		// absent, exactly like every other conditional surface here. The check went
		// green by not checking, which is the one outcome AGENTS.md names as the
		// failure mode this file exists to prevent, and it happened to the check
		// that was written to catch precisely that.
		//
		// The list above is therefore a completeness obligation, not a
		// convenience. TestEveryConditionalSurfaceIsVisibleToTheWalk in
		// router_walk_test.go holds it: it compares this literal against the option
		// struct's own field list, so the next conditional surface added to
		// internal/httpapi fails there until somebody adds its double to this walk.
		admin: newFakeAdmin(),
		// recovery is here for the same reason, and it is a NEW instance of the bug
		// the block above describes rather than a hypothetical one: eight routes are
		// mounted off this field's absence being handled, and a walk that did not
		// set it would report the documents as agreeing about a service that is
		// smaller than the one that runs.
		recovery: newFakeRecovery(),
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

// TestKnownDriftIsEmptyBecauseEveryServedOperationIsDocumented is the pin, and
// it is a pin on ZERO.
//
// ## WHAT MOVED, AND WHY ZERO IS STILL A PIN
//
// It was twelve. `identity-11` left it at twelve while documenting three admin
// operations, and `identity-28` took it to zero by documenting the other twelve.
// The two halves of the old rule — "it cannot grow" and "it cannot be emptied" —
// are now ONE rule, and it is stronger than either:
//
//	**the only legal change to this map is a shrink, and a shrink happens by
//	documenting a route.**
//
// The old "cannot be emptied" clause was written against a list of *known bugs*,
// where deleting an entry could have meant deleting the memory of a gap rather
// than closing it. That is no longer the shape: the list's own header now records
// all twelve and the commit that closed them, so the memory survives the removal
// and an empty map means the service is fully documented rather than that somebody
// forgot.
//
// Growth is still the escape hatch this file exists to close, and it is now
// simpler to refuse: ANY entry is a failure, whatever the count.
//
// ## WHY THE MESSAGE IS THE ARGUMENT
//
// A packet that adds a route and lands here is one second away from writing a
// line of prose and watching the suite go green. So the failure message is the
// whole content of the rule, and it is the same argument in the same order every
// time: this is not an exclusion list, an entry is an admission, and an admission
// is a claim somebody has to defend. If the route genuinely is not contract
// surface, that is a decision to record in the document's own header and in the
// README — which is what courier's `openapi_document_test.exs` requires of its own
// exclusions — and it is still an entry here, with that reasoning as its reason.
func TestKnownDriftIsEmptyBecauseEveryServedOperationIsDocumented(t *testing.T) {
	// The count this file records. Zero, since packet identity-28.
	const want = 0

	if len(knownDrift) == want {
		return
	}

	names := make([]string, 0, len(knownDrift))
	for key, reason := range knownDrift {
		names = append(names, key.String()+" — "+reason)
	}
	sort.Strings(names)

	t.Errorf("knownDrift has %d entr(ies) and this file records %d: every route the router "+
		"serves is in openapi/v1.yaml or openid/openid.yaml.\n\n  %s\n\n"+
		"This map is NOT an exclusion list. An exclusion list says \"this is not part of "+
		"the contract\" and an entry in it is a claim about intent; an entry in THIS map "+
		"says \"this is served and written down nowhere\", and an entry is an admission "+
		"that the contract is missing an operation. Merging the two meanings is how a "+
		"future route gets excused by being called a bug.\n\n"+
		"Do one of the two things, and then DELETE the entry — which is the only way one "+
		"is ever removed:\n"+
		"  1. it is part of the public surface. Document it in openapi/v1.yaml or "+
		"openid/openid.yaml, whichever surface it is on, with an operationId. Ten tenancy "+
		"operations and two OIDC POSTs were closed exactly this way by packets identity-28 "+
		"and identity-11, and the list went to zero rather than growing.\n"+
		"  2. it is genuinely not contract surface. Record that in the document's header "+
		"AND in the README's endpoint table, in prose a consumer reads, and put the "+
		"reason here. Expect this test to fail either way — that is the point. A decision "+
		"to leave a route undocumented is three review-visible edits, not one line.\n\n"+
		"NEVER grow this list to make a red go away, and never add a prefix filter to the "+
		"check. A filter is a guess about intent and it cannot see a method — which is how "+
		"PUT /v1/customers/{id} went on being served in billing under a check that read "+
		"paths only.",
		len(knownDrift), want, strings.Join(names, "\n  "))
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
// a consumer has to be able to notice it move.
//
// 1.4.0 is the admin surface — identity-11's three operations under the `admin`
// tag. It is a non-breaking addition, which is what core's sync rule asks for, and
// therefore the only thing that moved.
//
// 1.6.0 is the FIRST bump here that is not purely additive, and the pin is what
// makes a consumer's generated code notice: identity-27 removed the 409 from
// `POST /v1/email-verifications`, so a client with a branch on that status has to
// be rebuilt. The alternative — leaving the version at 1.5.0 and describing the
// removal in prose — is how a client finds out from a support ticket.
//
// 1.7.0 is the tenancy surface: ten operations added, all of them served for
// months and written down nowhere. It is additive in the way that matters, and it
// is the bump that took `knownDrift` to zero — a client generated from 1.7.0 has
// `createAccount`, `inviteMember` and `acceptInvitation`, and one generated from
// 1.6.0 does not. The one response shape that changed (`members` entries, which
// used to carry an empty `user_id`) is on operations that 1.6.0 did not describe,
// so no client can be reading the old shape.
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

	const want = "1.7.0"
	if doc.InfoVersion != want {
		t.Errorf("%s declares info.version %q, not %q. core's sync rule is that the /v1 "+
			"prefix says which contract and this says which build of it, and a non-breaking "+
			"addition bumps this and nothing else. If the document gained operations, move "+
			"this pin in the same commit and say so in the CHANGELOG.",
			v1Document, doc.InfoVersion, want)
	}
}
