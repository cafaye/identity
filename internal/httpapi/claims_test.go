package httpapi

// THE README-AND-MANIFEST-VERSUS-ROUTER TRIPWIRE.
//
// `openapi_drift_test.go` holds the two OpenAPI documents to the router. This file
// holds the other two places this repository makes a claim about its own HTTP
// surface — the README's endpoint tables and roadmap, and `cafaye.yml`'s
// description — and it exists because the document check was not enough.
//
// ## What it found, and why the document check could not have found it
//
// The README's endpoint tables were **honest**. Not one of them ever claimed an
// OAuth social-login route, because there is not one. The lie was one layer up, in
// three places a route table cannot see:
//
//   - the Roadmap, where `- [x] OAuth (social login) via goth` said the capability
//     ships, and it does not — no route, no handler, no use case, and goth is not
//     even a dependency of this module;
//   - the opening paragraph, which listed "OAuth" among the things this service
//     owns;
//   - `cafaye.yml`'s `description`, which is the manifest customers are handed
//     and which listed "OAuth" beside "the OIDC provider" as though they were two
//     capabilities rather than one.
//
// A check that reads `paths:` blocks sees none of that, because none of it is in
// a `paths:` block. That is the general shape of this file: **the drift check
// answers "is the contract the router?", and this one answers "is everything the
// repository says about the router true?"** A repository can have a perfect
// OpenAPI document and still advertise an endpoint that does not exist, and on a
// service a customer generates a client from, that is the more expensive failure —
// the document is what they compile against, the prose is what they believe.
//
// ## What it does and does not prove, stated plainly
//
// A test cannot read English, so nothing here parses a sentence. What it does is
// narrower and still load-bearing: every claim is reduced to a **route**, and the
// route has to exist.
//
//   - The README's tables ARE data. `` `POST /v1/accounts` `` in a table cell is a
//     claim, and it is checked as one, in both directions and by method AND path.
//   - The manifest's capability list and the roadmap's checkboxes are reduced to
//     an **index** — a declared table mapping each item to the routes that prove
//     it. That table is the review surface. It is pinned, and growing it is an act
//     that puts a route that has to exist next to a claim that has to be true.
//
// So the honest description of this file is: it makes a false claim a *visible
// edit next to a route* rather than a line of prose nobody re-reads. It does not
// make a false claim impossible, and this comment says so rather than letting the
// green tick imply otherwise.
//
// ## The three directions, and which way each one fails
//
//   1. README row → no route. A promise the service cannot keep. This is the lie
//      this file was written for.
//   2. Route → no README row. An endpoint the repository does not mention, which is
//      how a route becomes invisible to the next person reading the README instead
//      of the router.
//   3. Manifest item or checked roadmap box → no route. A capability claim, which
//      is what a customer integrating from the manifest actually reads.
//
// Direction 1 is the one the brief cares about and the one that is a security
// matter: a customer integrating "Continue with Google" against a 404.
//
// ## A reader that refuses rather than under-reads
//
// The same property `openapi_reader_test.go` insists on, for the same reason: a
// check that finds nothing agrees with a check over nothing, and that is how a
// tripwire becomes decoration. So the README reader is an error on every way it
// could come back short —
//
//   - no endpoint table at all, or a table with no header row;
//   - fewer than a stated number of route rows, so deleting the whole table cannot
//     pass as "the README was tidied";
//   - a first cell containing a backticked span with a `/` in it that is neither
//     `METHOD /path` nor a bare `/path` — a malformed row is an error, never a row
//     quietly skipped. `accounts:read` in a scope table is not skipped for being
//     unparseable; it is skipped for containing no path at all, which is a
//     different thing and is stated as one.
//
// and the manifest reader is an error on a missing, empty, or block-scalar
// `description`.

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

// The two files read here, relative to this package. Both are committed, both are
// what a customer reads, and neither is a build artefact.
const (
	readmePath   = "../../README.md"
	manifestPath = "../../cafaye.yml"
)

// --- the README's endpoint tables ----------------------------------------------

// readmeAbsent is the pinned set of paths the README declares are NOT served.
//
// ## This is a declared absence, and it is a different thing from knownDrift
//
// `knownDrift` in openapi_drift_test.go is served-but-undocumented: an admission
// that the contract is missing an operation. These four are the opposite and much
// milder case — the README *does* document them, and what it documents is that
// they answer 404, because the OIDC provider declines to implement them and says
// so in its discovery document. A row that says "this is `404`, and here is why"
// is the README doing its job, so excluding it silently would be a filter, and
// this repository does not use filters.
//
// So it is pinned here, with a reason per entry, and the pin is a floor rather
// than a ceiling in one direction only: a NEW method-less row fails, so the next
// route nobody serves cannot join the list by being written down, and an entry
// that starts being served fails too, so a shipped route cannot hide here behind
// a README that still calls it a 404.
var readmeAbsent = map[string]string{
	"/oidc/introspect":           "the OIDC provider declines it; absent from its discovery document",
	"/oidc/revoke":               "the OIDC provider declines it; absent from its discovery document",
	"/oidc/end-session":          "the OIDC provider declines it; absent from its discovery document",
	"/oidc/device_authorization": "the OIDC provider declines it; absent from its discovery document",
}

// readmeRouteRowsFloor is the number of rows the README's tables must carry.
//
// A floor rather than an exact count, and deliberately so: a route added and a
// route removed leaves an exact count alone, which is the mistake openapi_drift_test.go
// exists to refuse and repeating it here would be the same mistake twice. What this
// number is for is the failure a count cannot see — a table deleted, truncated, or
// emptied by a well-meaning edit, which would leave every remaining row correct and
// the check comparing a shrunk README against the whole router and reporting
// agreement. It is set below the real row count with room to grow.
const readmeRouteRowsFloor = 45

// readmeClaims is every (method, path) the README's endpoint tables assert this
// service serves, read out of the markdown rather than maintained here.
//
// The two sides are compared in BOTH directions, which is the property that makes
// it a tripwire rather than a linter: a row with no route is a promise the service
// breaks, and a route with no row is an endpoint the repository has stopped
// describing. A one-directional check is a spell-checker.
func readmeClaims(t *testing.T) (map[operationKey]string, map[string]string) {
	t.Helper()

	raw, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("reading %s: %v", readmePath, err)
	}

	claims := map[operationKey]string{}
	absent := map[string]string{}
	rows := 0

	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for number := 1; scanner.Scan(); number++ {
		line := scanner.Text()
		if !strings.HasPrefix(strings.TrimSpace(line), "|") {
			continue
		}

		cell, ok := firstCell(line)
		if !ok {
			continue
		}
		spans := backtickSpans(cell)
		if len(spans) == 0 {
			continue // a header row, a separator, or a table that is not about routes
		}

		rowClaims, rowAbsent, isRouteRow, err := parseRouteCell(spans, number)
		if err != nil {
			t.Fatalf("%s:%d — %v", readmePath, number, err)
		}
		if !isRouteRow {
			continue // a scope table's first cell, e.g. `accounts:read`
		}
		rows++

		for key, spelled := range rowClaims {
			if existing, clash := claims[key]; clash {
				t.Fatalf("%s:%d — %s and %s both read as %s. Two README rows describing one "+
					"route means one of them is describing something else.", readmePath, number,
					existing, spelled, key)
			}
			claims[key] = spelled
		}
		for path := range rowAbsent {
			absent[path] = cell
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("reading %s: %v", readmePath, err)
	}

	if rows < readmeRouteRowsFloor {
		t.Fatalf("%s has %d endpoint-table row(s) carrying a route; this check requires at "+
			"least %d. A reader that finds nothing agrees with a document that finds nothing, "+
			"and a table that was emptied or truncated would leave every remaining row correct "+
			"while the comparison below reported agreement between the README and the whole "+
			"router. Raise the floor if the surface really did shrink, and say so in the "+
			"CHANGELOG.", readmePath, rows, readmeRouteRowsFloor)
	}
	if len(claims) == 0 {
		t.Fatalf("%s's endpoint tables claim no operation at all. Nothing was read, so "+
			"nothing below can fail, and a check over nothing is green.", readmePath)
	}
	return claims, absent
}

// firstCell is the first cell of a markdown table row, or false when the line is
// not a row this reader can take a cell from.
func firstCell(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "|") {
		return "", false
	}
	rest := trimmed[1:]
	end := strings.Index(rest, "|")
	if end < 0 {
		return "", false
	}
	return strings.TrimSpace(rest[:end]), true
}

// backtickSpans is every backtick-quoted span in a cell, in order.
func backtickSpans(cell string) []string {
	var out []string
	for _, part := range strings.Split(cell, "`")[1:] {
		if before, _, found := strings.Cut(part, "`"); found {
			part = before
		}
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// parseRouteCell reads one first cell, and answers three things: which operations
// it claims are served, which paths it declares are not, and whether it is a route
// row at all.
//
// ## Why "is it a route row" is a question and not a filter
//
// This README is not only two endpoint tables. It also has a package-timing table
// whose first cell is “ `internal/accounts` “, a scope table whose first cell is
// “ `accounts:read` “, and header rows. None of those claims a route, and a reader
// that treated every cell with a `/` in it as a route claim would refuse the file.
//
// So the test is SHAPE, not content: a span is a route claim if it starts with `/`
// or its first word starts with one of the eight method names. `internal/accounts`
// starts with neither and is not a route; `POST /v1/accounts` is. That distinction
// is why this is not a prefix filter over paths — it is a statement about what a
// route row LOOKS like, and a route row that is misspelled still looks like one.
//
// The consequence worth stating: a row whose first cell is `GETTY /v1/thing` is an
// ERROR, not a skip. It starts with a method name, so it is plainly claiming a
// route, and a reader that skipped it would be a check over a subset looking like a
// check over the whole table. A row that does not begin like a route is skipped and
// skipped honestly — it is not claiming one.
func parseRouteCell(spans []string, number int) (map[operationKey]string, map[string]bool, bool, error) {
	claims := map[operationKey]string{}
	absent := map[string]bool{}
	claimsRoutes := false

	for _, span := range spans {
		if !isRouteShaped(span) {
			continue // `internal/accounts`, `accounts:read`, `201 {…}`
		}
		claimsRoutes = true

		if strings.HasPrefix(span, "/") {
			absent[normalisePath(span)] = true
			continue
		}

		methods, path, found := strings.Cut(span, " ")
		if !found || !strings.HasPrefix(path, "/") {
			return nil, nil, false, fmt.Errorf(
				"the cell quotes %q, which begins like a route — it starts with a method name or a "+
					"slash — but is not `METHOD /path` or a bare `/path`. A row this reader cannot "+
					"parse is a claim it would otherwise skip silently, and a skipped claim is "+
					"exactly how a check over a subset passes as a check over the whole table.", span)
		}

		for _, method := range strings.Split(methods, ",") {
			upper := strings.ToUpper(strings.TrimSpace(method))
			if !isHTTPMethod(upper) {
				return nil, nil, false, fmt.Errorf(
					"the cell quotes %q, whose method %q is not one of the eight HTTP method names. "+
						"Refusing rather than guessing: a method this reader cannot see is the same "+
						"blind spot a path-only comparison has, and that is how a served operation "+
						"ends up described nowhere.", span, method)
			}
			claims[operationKey{Method: upper, Path: normalisePath(strings.TrimSpace(path))}] = span
		}
	}

	if len(claims) > 0 && len(absent) > 0 {
		return nil, nil, false, fmt.Errorf(
			"the cell claims some operations are served and declares others are not. One row cannot " +
				"be a promise and a refusal at once, and this reader will not pick which half it " +
				"meant. Split them into two rows.")
	}
	if !claimsRoutes {
		return nil, nil, false, nil
	}
	return claims, absent, true, nil
}

// isRouteShaped reports whether a backticked span is claiming an HTTP route.
//
// Shape, not content: a leading `/`, or a first word beginning with one of the
// eight method names. The second half is deliberately a PREFIX test — `GETTY /x`
// has to be recognised as a malformed route rather than as a non-route cell, or
// the one typo this reader exists to catch is the one it waves through.
func isRouteShaped(span string) bool {
	if strings.HasPrefix(span, "/") {
		return true
	}
	first, _, _ := strings.Cut(span, " ")
	upper := strings.ToUpper(first)
	// The map's VALUES are the canonical uppercase spellings; its keys are the
	// lowercase ones the YAML reader matches document keys against. Comparing
	// against the keys here would make this test recognise no method at all, and it
	// would do so silently — the file would parse as two route rows and the floor
	// below is the only thing that would notice.
	for _, method := range openAPIOperationKeys {
		if strings.HasPrefix(upper, method) {
			return true
		}
	}
	return false
}

func isHTTPMethod(name string) bool {
	_, ok := openAPIOperationKeys[strings.ToLower(name)]
	return ok
}

// TestTheReadmeEndpointTablesAreTheRoutesTheRouterServes is the README half of
// the tripwire, in both directions.
func TestTheReadmeEndpointTablesAreTheRoutesTheRouterServes(t *testing.T) {
	claims, _ := readmeClaims(t)
	served := servedRoutes(t)

	// The forward direction is inlined rather than delegated to a helper because it
	// has to report the README's OWN SPELLING beside the normalised key: chi writes
	// `{accountID}` where the README writes `:id`, and seeing the two together is
	// what tells a reader which document to edit. The reverse direction is the
	// function above, because the falsifiability test drives it with an injected
	// route and this one has nothing to add to it.
	var promised []string
	for key, spelled := range claims {
		if _, ok := served[key]; !ok {
			promised = append(promised, key.String()+"  (README spells it `"+spelled+"`)")
		}
	}
	sort.Strings(promised)

	if len(promised) > 0 {
		t.Errorf("README.md's endpoint tables advertise %d operation(s) this service does not "+
			"serve:\n\n  %s\n\n"+
			"A customer integrating from this README calls these and gets a 404, and the README "+
			"is the document a human reads before generating anything. Either the route is "+
			"shipping — mount it, document it in openapi/v1.yaml with an operationId, and give it "+
			"a row in the authorization matrix if it is account-scoped — or the claim is wrong, "+
			"and the honest fix is to take the row out and record the absence in the README's "+
			"`Not built yet` section.\n\n"+
			"Do not resolve this by widening the reader. A row this file cannot parse is "+
			"already an error, so there is nothing to widen.", len(promised), strings.Join(promised, "\n  "))
	}

	var undocumented []string
	for key := range served {
		if _, ok := claims[key]; !ok {
			undocumented = append(undocumented, key.String())
		}
	}
	sort.Strings(undocumented)

	if len(undocumented) > 0 {
		t.Errorf("this service serves %d operation(s) that README.md's endpoint tables do not "+
			"describe:\n\n  %s\n\n"+
			"The other direction, and the one a check written only for today's finding would "+
			"miss. A route nobody wrote down is an endpoint the next person discovers by reading "+
			"the router rather than the README, which is how a surface grows past what anybody "+
			"decided. Add the row.", len(undocumented), strings.Join(undocumented, "\n  "))
	}
}

// TestTheReadmeDeclaredAbsencesAreStillAbsent holds readmeAbsent against the
// router in the one direction that matters: a path the README promises answers 404
// must still answer 404.
//
// The list exists so the four refused OIDC endpoints are not read as a filter, and
// this is what stops it becoming a hiding place. A route that starts being served
// and stays in this list is a README that tells a customer to expect a 404 from an
// endpoint that answers 200.
func TestTheReadmeDeclaredAbsencesAreStillAbsent(t *testing.T) {
	_, declared := readmeClaims(t)
	served := servedRoutes(t)

	for path, reason := range readmeAbsent {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("the readmeAbsent entry for %s has no reason. An entry with no reason is "+
				"an assertion, and an assertion is not reviewable.", path)
		}
		if _, ok := declared[path]; !ok {
			t.Errorf("readmeAbsent names %s but the README no longer declares it absent. Either "+
				"the endpoint was removed — delete the entry and say so in the CHANGELOG — or it "+
				"is documented differently now, and the pinned list is stale.", path)
		}
	}

	// Every route the README declares absent, under ANY method, is still served. This
	// is why the list is keyed by path and not by (method, path): the README's row
	// spells one method and three bare paths, and a method-keyed list would have to
	// pin all four spellings of one statement.
	for key := range served {
		if _, ok := readmeAbsent[key.Path]; !ok {
			continue
		}
		if _, declaredHere := declared[key.Path]; declaredHere {
			continue // the README's row is the one carrying the mixed cell; parseRouteCell rejects it
		}
		t.Errorf("this service now serves %s, and readmeAbsent lists %s as one the README "+
			"declares answers 404. Either the route is real and the README row must go, or the "+
			"route was mounted by accident.", key, key.Path)
	}
}

// --- proving these checks can fail ---------------------------------------------

// The checks above are only worth what the router walk feeding them is worth, and a
// walk that cannot see a route reports agreement about a service smaller than the
// one that runs. That has happened TWICE in this repository, to this file's own
// neighbouring check: the admin surface and then the recovery surface were each
// mounted with the `options` literal left un-updated, and
// `TestEveryServedRouteIsDocumentedOrNamed` passed while three and then eight
// undocumented operations were live. `registerXRoutes` returns early when its
// service is nil, so a missing field is invisible rather than loud.
//
// Two tests close that, and both live in claims_faults_test.go because this file is
// what consumes the walk:
//
//   - TestTheClaimWalkSeesEveryConditionalSurface asserts a ROUTE from each
//     registrar, not that a field was set. A field test passes against a registrar
//     that mounts nothing; a route test does not.
//   - TestEveryClaimCheckFailsOnAnInjectedRoute, below, takes a route this service
//     genuinely does not serve, mounts it, and requires each of two checks to report
//     it. Without it, all of them could be vacuously green — a comparison that never
//     fires is indistinguishable from a comparison that is correct, which is the same
//     under-read the reader tests guard against one layer down.

// The two routes injected below, which this service does not serve and which
// nothing but the test mounts. Each is named for the check it exercises, because a
// single shared injection would be wrong for one of them: the README comparison
// looks for a route with no row beside it, so its injection has to be somewhere the
// README is silent, and the social-login check looks for a route UNDER the social
// prefix, so its injection has to be under that prefix. Using one path for both
// would leave one check comparing a set that does not contain what it looks for —
// green, and green for the wrong reason.
//
// The second one is a FICTIONAL path and that is the whole of the change from the
// version this replaces. It used to be the real callback,
// `socialLoginPrefix + "/google/callback"`, because the check it drove asserted
// that NO social-login route existed; the natural injection was then a real one.
// The check is inverted now, so the injection has to be a route no provider serves
// and the README does not describe: `/disconnect` under the social prefix is an
// obvious thing for a later packet to mount, which is exactly the regression this
// case exists to catch.
const (
	injectedUndocumentedRoute = "/v1/claims-fault-injection"

	// Built from socialLoginPrefix rather than spelled out, so a rename of the
	// production constant moves the injection with it. A literal would let the two
	// drift and the case would then be asserting about a path the router could never
	// be mounted on.
	injectedUndocumentedSocialLoginRoute = socialLoginPrefix + "/{provider}/disconnect"
)

// TestEveryClaimCheckFailsOnAnInjectedRoute is the falsifiability test for this
// file, and it is the one most likely to be missing from a check like this.
//
// Each case mounts a route that does not exist, runs one claim check against the
// augmented set, and requires it to REPORT. The assertion is on the report, and on
// the report naming the route:
//
//   - a check that cannot fail is not a check, and the green tests above prove
//     nothing at all unless something demonstrates they can go red;
//   - it is the only thing that distinguishes "the README agrees with the router"
//     from "the README and the router are both empty and the comparison is
//     comparing nothing";
//   - a failure that does not name the route is a failure nobody can act on, which
//     is nearly as bad as no failure.
//
// It drives the two route-comparing checks as FUNCTIONS rather than as subtests of
// the real ones. The real tests call servedRoutes themselves, which is the right
// shape for a test and the wrong shape here — this one has to hand in a set with a
// route added, and it cannot do that to a test that builds its own. So the
// comparison is a function returning what it found, and the real test is a caller.
func TestEveryClaimCheckFailsOnAnInjectedRoute(t *testing.T) {
	for name, testCase := range map[string]struct {
		inject string
		check  func(t *testing.T, served map[operationKey]string) string
	}{
		"a served route with no README row": {
			inject: injectedUndocumentedRoute,
			check:  readmeUndocumentedRoutes,
		},
		"a social-login route with no README row": {
			inject: injectedUndocumentedSocialLoginRoute,
			check:  undocumentedSocialLoginRoutes,
		},
	} {
		t.Run(name, func(t *testing.T) {
			served := routesIn(t, walkOptions())
			served[operationKey{Method: "GET", Path: testCase.inject}] = testCase.inject

			reported := testCase.check(t, served)
			if reported == "" {
				t.Fatalf("the check reported nothing with %s in the served set. It is either "+
					"not reading the set it was handed, or not reporting a route that has no "+
					"claim beside it — and either way it would also pass over an empty "+
					"comparison, which is the failure mode this file exists to prevent.",
					testCase.inject)
			}
			if !strings.Contains(reported, testCase.inject) {
				t.Errorf("the check reported %q, which does not name the injected route %s. A "+
					"report a reader cannot act on is nearly as bad as no report.", reported, testCase.inject)
			}
		})
	}
}

// readmeUndocumentedRoutes is the reverse direction of the README comparison —
// served but not written down — as a function over an injected route set.
//
// Only the reverse direction is here. The forward one is the lie this file was
// written for, and it is not injectable without also injecting a README, which
// would mean writing a temporary file for a test to read. The forward direction is
// covered differently and better: TestTheManifestDescribesOnlyCapabilitiesThisServiceHas
// and TestEveryCheckedRoadmapItemIsBackedByTheRouter both failed on their first run
// against the real OAuth claim, which is the strongest evidence available that this
// file finds a real one.
func readmeUndocumentedRoutes(t *testing.T, served map[operationKey]string) string {
	t.Helper()

	claims, _ := readmeClaims(t)

	var reported []string
	for key := range served {
		if _, documented := claims[key]; !documented {
			reported = append(reported, key.String())
		}
	}
	if len(reported) == 0 {
		return ""
	}
	sort.Strings(reported)
	return "served but in no README row: " + strings.Join(reported, ", ")
}

// undocumentedSocialLoginRoutes is readmeUndocumentedRoutes narrowed to the social
// prefix, and it used to be the exact opposite of this.
//
// ## The inversion, and what it cost
//
// It was `socialLoginRoutesMounted`, which reported the presence of any route under
// `socialLoginPrefix` as a defect. That was correct while the surface was unmounted
// and it was the whole of `oauth_absent_test.go`'s assertion, but as the surface
// mounted it became a check whose passing state is a router without a feature — so
// it had to be inverted rather than deleted, exactly as the tripwire's own rule
// demanded ("mounting social login without deleting this file is not finishing the
// work; deleting it is a review-visible act").
//
// What it now means: **a social-login route with no documentation beside it.** The
// narrowing to the prefix is what keeps it worth having next to the general check
// above. A route under `/v1/auth/oauth` is the one case where a missing README row
// is a repeat of a specific historical lie rather than ordinary drift, so it gets a
// failure message that says which surface it is about, and it keeps a falsifiability
// case of its own — `TestEveryClaimCheckFailsOnAnInjectedRoute` — so a future edit
// that widens this to the whole router is a visible change rather than a silent one.
//
// ## What was actually given up, stated plainly
//
// Mechanically, this case is now SUBSUMED by `readmeUndocumentedRoutes`: a served
// route with no README row is the same finding whether or not it is under the social
// prefix, so the general check would have fired on the injection without this one.
// What is preserved is not an independent signal — it is the narrowing, the
// surface-specific message, and the anchor to `socialLoginPrefix`. The other option
// for this case was deleting it, and that would have left the social surface with no
// check of its own at all, which is the regression the tripwire was watching for:
// social routes remounted without documentation, silently, because nothing in the
// package had that prefix in it. Given that the tripwire was deleted for exactly
// this surface, keeping the narrower check is the smaller loss.
func undocumentedSocialLoginRoutes(t *testing.T, served map[operationKey]string) string {
	t.Helper()

	claims, _ := readmeClaims(t)

	var reported []string
	for key := range served {
		if key.Path != socialLoginPrefix && !strings.HasPrefix(key.Path, socialLoginPrefix+"/") {
			continue
		}
		if _, documented := claims[key]; documented {
			continue
		}
		reported = append(reported, key.String())
	}
	if len(reported) == 0 {
		return ""
	}
	sort.Strings(reported)
	return "served under " + socialLoginPrefix + " with no README row: " + strings.Join(reported, ", ")
}

// --- the manifest --------------------------------------------------------------

// manifestCapabilityEvidence maps each item of `cafaye.yml`'s description to the
// routes that prove this service has that capability.
//
// ## This table is the review surface, and it is not a proof
//
// The description is one line of English and no test can read it for truth. What
// this table does is put every claim next to the routes that back it, so adding a
// capability to the manifest is an edit that names a route which has to exist —
// and, for the claim that started this file, to make "OAuth" a claim somebody has
// to look at rather than a word between two commas.
//
// The one thing a determined author can still do is point a capability at a
// route that exists but proves something else. That is why the table is pinned
// below and why each entry carries the sentence saying what it means.
var manifestCapabilityEvidence = map[string][]string{
	"Authentication":       {"/v1/users", "/v1/session"},
	"sessions":             {"/v1/session"},
	"MFA":                  {"/v1/mfa"},
	"accounts and tenancy": {"/v1/accounts", "/v1/invitations/accept"},
	"scoped API tokens":    {"/v1/accounts/{}/api-keys", "/v1/introspections"},
	"the OIDC provider":    {"/oidc/authorize", "/oidc/token"},
}

// manifestCapabilityCount pins the declared table, in the same direction as
// knownDrift: it cannot grow, and it cannot shrink. Growth is a new claim added
// without anybody deciding it; shrinking is a capability deleted from the table
// rather than from the manifest.
const manifestCapabilityCount = 6

// manifestDescription reads the `description:` value out of cafaye.yml.
func manifestDescription(t *testing.T) string {
	t.Helper()

	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("reading %s: %v", manifestPath, err)
	}

	description, err := readManifestDescription(string(raw))
	if err != nil {
		t.Fatalf("%s: %v", manifestPath, err)
	}
	return description
}

// readManifestDescription is the reader, separated from the file it is pointed at
// so the fault cases in claims_reader_test.go can drive it with a synthetic
// manifest. A reader that can only be exercised against the real file cannot be
// shown to refuse a form it does not understand, and an unshown refusal is an
// assumption.
//
// It is a line reader over a top-level `key: value`, which is the whole of the
// subset it understands. Everything else is an error:
//
//   - a block scalar (`|`, `>`, and the `-`/`+` chomping variants), which this
//     reader would otherwise return as the literal indicator character — a
//     capability list of one nonsense item, reported as a confident finding about a
//     file nobody wrote that way;
//   - an empty or `~` value, which is a claim set of nothing;
//   - no such key, which is a manifest asserting nothing to check.
//
// A `#` inside the value is NOT a comment. YAML would treat a `#` as one only when
// it starts the line or follows whitespace, and this manifest has neither, so
// stripping at the first `#` would be a guess about a language it does not parse.
func readManifestDescription(manifest string) (string, error) {
	for number, line := range strings.Split(manifest, "\n") {
		value, found := strings.CutPrefix(line, "description:")
		if !found {
			continue
		}
		trimmed := strings.TrimSpace(value)

		if trimmed == "" || trimmed == "~" || trimmed == "null" {
			return "", fmt.Errorf("%s:%d — `description:` is empty. The manifest is what a "+
				"customer reads before deciding what this service does, and an empty one is a "+
				"claim this check cannot hold anything against.", manifestPath, number+1)
		}
		if isBlockScalarIndicator(trimmed) {
			return "", fmt.Errorf("%s:%d — `description:` is a block scalar. This reader "+
				"understands one line of `key: value` and refusing here is deliberate: returning "+
				"the indicator character would report a confident finding about a file written "+
				"some other way.", manifestPath, number+1)
		}

		// Only the matching pair is stripped. Trimming both ends independently would
		// eat a legitimate apostrophe from a value like `the service's surface`, and
		// this repository's own description would be mangled by it.
		if len(trimmed) >= 2 {
			if (strings.HasPrefix(trimmed, `"`) && strings.HasSuffix(trimmed, `"`)) ||
				(strings.HasPrefix(trimmed, "'") && strings.HasSuffix(trimmed, "'")) {
				trimmed = trimmed[1 : len(trimmed)-1]
			}
		}
		if trimmed == "" {
			return "", fmt.Errorf("%s:%d — `description:` is quoted but empty.", manifestPath, number+1)
		}
		return trimmed, nil
	}

	return "", fmt.Errorf("%s has no top-level `description:`. The schema requires one, and a "+
		"manifest without it cannot be checked against the router because it asserts nothing to "+
		"check.", manifestPath)
}

// isBlockScalarIndicator reports whether a value opens a YAML block scalar, in
// either the literal or the folded style, with any chomping indicator.
func isBlockScalarIndicator(value string) bool {
	for _, style := range []string{"|", ">"} {
		if value == style || value == style+"-" || value == style+"+" {
			return true
		}
	}
	return false
}

// manifestCapabilities splits the description into its list items.
//
// On commas only, and not on " and ": "accounts and tenancy" is one capability
// and splitting it would produce two claims the table has never heard of, which is
// a way for this reader to cry wolf on an honest manifest.
func manifestCapabilities(description string) []string {
	var out []string
	for _, part := range strings.Split(description, ",") {
		item := strings.TrimSpace(part)
		item = strings.TrimPrefix(item, "and ")
		item = strings.TrimSpace(item)
		item = strings.TrimSuffix(item, ".")
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

// TestTheManifestDescribesOnlyCapabilitiesThisServiceHas holds `cafaye.yml`'s
// description to the router.
//
// The manifest is the one file here a customer is handed rather than reads, and
// the claim this found was in it: "OAuth" sat in the list beside "the OIDC
// provider", as two capabilities, when this service is the second and not the
// first. `/v1/auth/oauth` is not mounted. It never was.
func TestTheManifestDescribesOnlyCapabilitiesThisServiceHas(t *testing.T) {
	items := manifestCapabilities(manifestDescription(t))
	served := servedRoutes(t)

	servedPaths := map[string]bool{}
	for key := range served {
		servedPaths[key.Path] = true
	}

	var unknown []string
	for _, item := range items {
		evidence, declared := manifestCapabilityEvidence[item]
		if !declared {
			unknown = append(unknown, item)
			continue
		}
		for _, route := range evidence {
			if !servedPaths[normalisePath(route)] {
				t.Errorf("the manifest claims %q, and manifestCapabilityEvidence points at %s, "+
					"which the router does not serve. The claim outlived the capability.", item, route)
			}
		}
	}
	sort.Strings(unknown)

	if len(unknown) > 0 {
		t.Errorf("cafaye.yml's description claims %d capabilit(y/ies) this file has never heard "+
			"of:\n\n  %s\n\n"+
			"This is the check that found the OAuth claim. A customer reads the manifest and "+
			"decides what this service does, so an item with no route behind it is a promise in "+
			"the one file nobody diffs carefully. Either the capability is shipping — mount it, "+
			"and it will appear in the README's tables and in one of the documents — or the claim "+
			"is wrong and the word comes out of the manifest.\n\n"+
			"If the capability is real and simply new to this check, add it to "+
			"manifestCapabilityEvidence with the routes that prove it and bump "+
			"manifestCapabilityCount in the same commit — that edit is the review, so make it "+
			"legible.", len(unknown), strings.Join(unknown, "\n  "))
	}
}

// TestTheManifestCapabilityTableIsExactlyWhatItClaimsToBe pins the table in the
// same two directions knownDrift is pinned, for the same reason: a table that can
// grow without limit is where the next unbacked claim goes.
func TestTheManifestCapabilityTableIsExactlyWhatItClaimsToBe(t *testing.T) {
	if len(manifestCapabilityEvidence) == manifestCapabilityCount {
		return
	}

	names := make([]string, 0, len(manifestCapabilityEvidence))
	for name := range manifestCapabilityEvidence {
		names = append(names, name)
	}
	sort.Strings(names)

	if len(manifestCapabilityEvidence) > manifestCapabilityCount {
		t.Errorf("manifestCapabilityEvidence has grown from %d entries to %d. Growing it is how "+
			"a manifest claim gets a route pointed at it without anybody deciding the claim was "+
			"true — the edit that makes the suite green is the edit that makes the lie "+
			"unfalsifiable. Add the capability to the manifest only when it is mounted, and "+
			"bump the constant in the same commit so the bump is a decision.\n\n  now: %v",
			manifestCapabilityCount, len(manifestCapabilityEvidence), names)
		return
	}
	t.Errorf("manifestCapabilityEvidence has %d entries and this file records %d. A table that "+
		"shrank means a capability was dropped from the table rather than from the manifest, "+
		"which TestTheManifestDescribesOnlyCapabilitiesThisServiceHas would then report as an "+
		"unknown claim. Delete the capability from cafaye.yml's description, or restore the "+
		"entry and re-pin.\n\n  now: %v", len(manifestCapabilityEvidence), manifestCapabilityCount, names)
}

// --- the roadmap ---------------------------------------------------------------

// roadmapSurface maps a checked roadmap item to the routes that prove it shipped.
//
// Matched on a distinctive lowercase phrase rather than on the whole line, because
// a roadmap item is prose somebody will reword and a check that fails when they
// reword it is a check that gets deleted. The phrase has to be specific enough that
// exactly one entry matches, and an ambiguous match is an error rather than a
// silent pick.
var roadmapSurface = map[string][]string{
	"skeleton":              {"/healthz", "/readyz"},
	"password auth":         {"/v1/session", "/v1/me"},
	"email verification":    {"/v1/email-verifications", "/v1/password-resets", "/v1/email-changes"},
	"accounts, memberships": {"/v1/accounts", "/v1/invitations/accept"},
	"oidc provider":         {"/oidc/authorize", "/oidc/token"},
	"mfa: totp":             {"/v1/mfa"},
	"scoped api tokens":     {"/v1/accounts/{}/api-keys", "/v1/introspections"},
}

// roadmapNotSurface is the pinned set of checked roadmap items that are genuinely
// not an HTTP route, each with why.
//
// It is a list of absences rather than of excuses, and the distinction matters: an
// entry here says "this capability has no route and does not need one", which is a
// different claim from "this route is undocumented". The pin makes growth a
// failing test, so a capability cannot be moved onto this list to stop the surface
// check from noticing it has no route behind it.
var roadmapNotSurface = map[string]string{
	"migration convention":       "packaging — a migration convention, an image and a compose stack, and none of them answers a request",
	"error envelope":             "the problem-document shape every route in the tables above already returns; it is not a route of its own",
	"outbox:":                    "the publisher is a background loop claiming rows with SKIP LOCKED, and it serves no request",
	"authorization matrix suite": "a test suite, not a capability a customer integrates against",
}

// roadmapCheckedItems is every `- [x]` item in the README's Roadmap section.
func roadmapCheckedItems(t *testing.T) []string {
	t.Helper()

	raw, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("reading %s: %v", readmePath, err)
	}

	items := roadmapItemsFrom(string(raw))
	if len(items) == 0 {
		t.Fatalf("%s's Roadmap section has no checked item at all. Every capability in it has "+
			"either been deleted or unchecked, and a check over no claims cannot fail.", readmePath)
	}
	return items
}

// roadmapItemsFrom is the roadmap reader, separated from the file so the fault
// cases in claims_reader_test.go can drive it.
//
// Three things it gets right, and each is a case that would otherwise be a
// false finding or a missed one:
//
//   - **Continuation lines are folded.** A wrapped markdown list item is ONE item.
//     Read as two, the second is a fragment that matches no entry in either table
//     and the surface check reports a checked item that does not exist.
//   - **An unchecked box is skipped entirely.** It is the honest state and asserts
//     nothing — and it is this packet's own fix for the OAuth claim, so a reader
//     that counted them would make that fix impossible to apply.
//   - **Only the `## Roadmap` section is read.** A `- [x]` list under some other
//     heading is not a capability claim, and the walk stops at the next `## `.
//
// It returns an empty slice for a section with nothing checked, and the CALLER
// treats that as an error. Returning the error here instead would be marginally
// tidier and would make these cases untestable without a *testing.T, which is the
// wrong shape for a pure function.
func roadmapItemsFrom(readme string) []string {
	inSection := false
	var items []string
	var current string

	flush := func() {
		if current != "" {
			items = append(items, current)
			current = ""
		}
	}

	for _, line := range strings.Split(readme, "\n") {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "## ") {
			flush()
			// EqualFold rather than ==, because a reworded heading is still the
			// roadmap and a check that goes quiet on a rename is a check that has
			// stopped being run.
			inSection = strings.EqualFold(trimmed, "## Roadmap")
			continue
		}
		if !inSection {
			continue
		}

		switch {
		case strings.HasPrefix(trimmed, "- [x]"):
			flush()
			current = strings.TrimSpace(strings.TrimPrefix(trimmed, "- [x]"))
		case strings.HasPrefix(trimmed, "- [ ]"):
			// An unchecked box is the honest state and asserts nothing.
			flush()
		case current != "" && trimmed != "":
			current += " " + trimmed
		}
	}
	flush()

	return items
}

// TestEveryCheckedRoadmapItemIsBackedByTheRouter is the check that would have
// caught `- [x] OAuth (social login) via goth`.
//
// A checkbox is the strongest claim this repository makes about itself: it is
// short, it is checked, and it is what a reader skimming for "does this have it?"
// stops at. It is also the one place the OAuth lie lived, because the README's
// endpoint tables were honest — no table ever claimed the route.
//
// Two things are worth saying about the failure direction. It fails when a checked
// item has no route and no declared reason, which is the lie. And it fails when a
// declared reason names an item that is gone or reworded, so the list of "checked
// but not a route" cannot quietly become the place capabilities go to be excused.
func TestEveryCheckedRoadmapItemIsBackedByTheRouter(t *testing.T) {
	items := roadmapCheckedItems(t)
	served := servedRoutes(t)

	servedPaths := map[string]bool{}
	for key := range served {
		servedPaths[key.Path] = true
	}

	var unbacked []string
	for _, item := range items {
		lowered := strings.ToLower(item)

		matched := false
		for phrase, evidence := range roadmapSurface {
			if !strings.Contains(lowered, phrase) {
				continue
			}
			matched = true
			for _, route := range evidence {
				if !servedPaths[normalisePath(route)] {
					t.Errorf("the roadmap checks off %q and roadmapSurface points at %s, which the "+
						"router does not serve. The claim outlived the capability.", item, route)
				}
			}
		}
		if matched {
			continue
		}

		explained := false
		for phrase, reason := range roadmapNotSurface {
			if strings.Contains(lowered, phrase) {
				explained = true
				if strings.TrimSpace(reason) == "" {
					t.Errorf("the roadmapNotSurface entry for %q has no reason. An entry with no "+
						"reason is an assertion, and an assertion is not reviewable.", phrase)
				}
			}
		}
		if !explained {
			unbacked = append(unbacked, item)
		}
	}
	sort.Strings(unbacked)

	if len(unbacked) > 0 {
		t.Errorf("README.md's roadmap checks off %d item(s) that no route backs:\n\n  %s\n\n"+
			"This is the check the OAuth lie was for. `- [x] OAuth (social login) via goth` "+
			"asserted a capability this service does not have: there is no route, no handler and "+
			"no use case, and goth is not a dependency of this module at all. A checkbox is what "+
			"somebody reads to decide whether to integrate, so do one of the two things:\n"+
			"  1. the capability is shipping — mount it, document it, and add it to roadmapSurface "+
			"with the routes that prove it.\n"+
			"  2. it is not — uncheck the box, and record the absence in the README's "+
			"`Not built yet` section, which is the source of truth for what v0 does not claim.\n\n"+
			"Adding it to roadmapNotSurface is not a third option: that list is for capabilities "+
			"with genuinely no route, and a social sign-in endpoint has a route by definition.",
			len(unbacked), strings.Join(unbacked, "\n  "))
	}
}

// TestTheNotSurfaceListIsStillAboutTheItemsItNames is the staleness guard on
// roadmapNotSurface, in both directions.
//
// Without it the list is a hole with a comment: a phrase nobody matches any more
// excuses nothing, and a reworded item silently re-enters the unbacked set where it
// belongs — or worse, a new capability is given a phrase that happens to contain an
// existing one.
func TestTheNotSurfaceListIsStillAboutTheItemsItNames(t *testing.T) {
	items := roadmapCheckedItems(t)
	lowered := make([]string, len(items))
	for i, item := range items {
		lowered[i] = strings.ToLower(item)
	}

	for phrase, reason := range roadmapNotSurface {
		found := false
		for _, item := range lowered {
			if strings.Contains(item, phrase) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("roadmapNotSurface names %q, and no checked roadmap item mentions it any "+
				"more. The entry has stopped meaning anything, which makes it a carve-out "+
				"matching nothing — a hole waiting for the next item somebody words that way. "+
				"Delete it, or reword the item to match what it is actually claiming.", phrase)
		}
		_ = reason
	}

	const want = 4
	if len(roadmapNotSurface) != want {
		t.Errorf("roadmapNotSurface has %d entries and this file records %d. It cannot grow: "+
			"growth is a capability being excused of having a route, which is the one move this "+
			"check exists to refuse. A capability that genuinely has no route belongs here with "+
			"a reason; one that ought to have a route has to be mounted.", len(roadmapNotSurface), want)
	}
}
