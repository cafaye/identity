package httpapi

// The reader's own tests, and the tests for every normalisation it applies.
//
// This file exists because the check in openapi_drift_test.go is only worth
// having if the thing producing the two sets is itself trustworthy. A reader is
// a place a check can be made to pass by a document it quietly failed to read,
// and a normaliser is a place a check can be made to pass by a rewrite that
// should have failed it — so every rule gets a test naming the case it covers.
//
// The fault tests drive the real reader and the real comparison rather than
// hand-built maps, because a test of a tidier imitation of the code proves
// something about the imitation.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// writeDocument writes lines to a temporary file and returns its path. A
// document is data on disk, so the reader is given a real file and the tests do
// not get a seam that production does not have.
func writeDocument(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "v1.yaml")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("writing the test document: %v", err)
	}
	return path
}

// keysOf is the reader's output as sorted "METHOD /path" strings, which is how
// every assertion below reads.
func keysOf(doc openAPIDocument) []string {
	out := make([]string, 0, len(doc.Operations))
	for key := range doc.Operations {
		out = append(out, key.String())
	}
	sort.Strings(out)
	return out
}

// mustRead reads a document or fails the test, for the cases whose point is what
// the reader FOUND rather than what it refused.
func mustRead(t *testing.T, lines ...string) openAPIDocument {
	t.Helper()
	doc, err := readOpenAPIDocument(writeDocument(t, lines...))
	if err != nil {
		t.Fatalf("the reader refused a document it should have read: %v", err)
	}
	return doc
}

func TestTheReaderTakesThePathsAndTheMethodsAndNothingElse(t *testing.T) {
	doc := mustRead(t,
		"openapi: 3.1.0",
		"info:",
		"  title: identity",
		"  version: 9.9.9",
		"paths:",
		"  /v1/widgets:",
		"    get:",
		"      operationId: listWidgets",
		"    post:",
		"    patch:",
		"    delete:",
		"  /v1/widgets/{id}:",
		"    parameters:",
		"      - $ref: '#/components/parameters/WidgetId'",
		"    get:",
		"    put:",
		"components:",
		"  schemas:",
		"    Widget:",
		"      type: object",
	)

	want := []string{
		"DELETE /v1/widgets", "GET /v1/widgets", "GET /v1/widgets/{}",
		"PATCH /v1/widgets", "POST /v1/widgets", "PUT /v1/widgets/{}",
	}
	if got := keysOf(doc); !equalStrings(got, want) {
		t.Errorf("the reader found\n  %v\nand not\n  %v", got, want)
	}

	if doc.SpecVersion != "3.1.0" {
		t.Errorf("spec version is %q, not 3.1.0", doc.SpecVersion)
	}
	if doc.InfoVersion != "9.9.9" {
		t.Errorf("info.version is %q, not 9.9.9", doc.InfoVersion)
	}
}

// The spellings are kept so a failure can name a path as the source wrote it.
func TestTheReaderKeepsTheSpellingsTheSourceUsed(t *testing.T) {
	doc := mustRead(t, "openapi: 3.1.0", "info:", "  version: 1.0.0",
		"paths:", "  /v1/widgets/{widget_id}:", "    get:")

	key := operationKey{Method: "GET", Path: "/v1/widgets/{}"}
	if got := doc.Operations[key].Path; got != "/v1/widgets/{widget_id}" {
		t.Errorf("the operation is named %q; a failure has to show the path as the "+
			"document wrote it, which is %q", got, "/v1/widgets/{widget_id}")
	}
}

func TestTheReaderReadsTheOperationIdAndOnlyTheOperationsOwn(t *testing.T) {
	// The second `operationId` is three levels down inside a response example. A
	// reader that took the first one it found anywhere below the method key would
	// report this operation as named after an example payload, which is a name no
	// client would ever have.
	doc := mustRead(t,
		"openapi: 3.1.0", "info:", "  version: 1.0.0",
		"paths:",
		"  /v1/widgets:",
		"    get:",
		"      operationId: listWidgets",
		"      responses:",
		"        '200':",
		"          content:",
		"            application/json:",
		"              examples:",
		"                one:",
		"                  value:",
		"                    operationId: notThisOne",
	)

	op := doc.Operations[operationKey{Method: "GET", Path: "/v1/widgets"}]
	if op.OperationID != "listWidgets" {
		t.Errorf("the operationId is %q, not %q. The field inside the example is the "+
			"payload's, not the operation's.", op.OperationID, "listWidgets")
	}
}

func TestAKeyThatMerelyStartsWithAMethodNameIsNotAnOperation(t *testing.T) {
	// `get:` is an operation. `getaway:` is not, and a reader matching on the
	// prefix would count a schema property as a route.
	doc := mustRead(t, "openapi: 3.1.0", "info:", "  version: 1.0.0",
		"paths:", "  /v1/widgets:", "    get:", "    getaway:", "    posting:")

	if got := len(doc.Operations); got != 1 {
		t.Errorf("the reader found %d operations, and only `get:` is one", got)
	}
}

func TestCommentsAndBlankLinesInsideTheBlockAreSkipped(t *testing.T) {
	doc := mustRead(t,
		"openapi: 3.1.0", "info:", "  version: 1.0.0",
		"paths:",
		"  # the only surface this document ships",
		"  /v1/widgets:",
		"",
		"    # listing",
		"    get:",
		"")

	if got := len(doc.Operations); got != 1 {
		t.Errorf("the reader found %d operations, want 1", got)
	}
}

// A reader that hardcoded two and four spaces would read four-space YAML as
// having no operations at all — and a check that finds nothing passes.
func TestTheTwoIndentationLevelsAreDerivedFromTheDocumentNotAssumed(t *testing.T) {
	doc := mustRead(t, "openapi: 3.1.0", "info:", "    version: 1.0.0",
		"paths:", "    /v1/widgets:", "        get:", "        post:")

	if got := len(doc.Operations); got != 2 {
		t.Errorf("the reader found %d operations in a four-space document, want 2", got)
	}
}

func TestAnythingDeeperThanTheOperationLevelIsAnOperationsBody(t *testing.T) {
	// A real document nests: `parameters` holds a list of `$ref:` entries and an
	// operation holds a `responses:` mapping. A reader that treated every deeper
	// level as structure would count response status codes as routes.
	doc := mustRead(t,
		"openapi: 3.1.0", "info:", "  version: 1.0.0",
		"paths:",
		"  /v1/widgets/{id}:",
		"    parameters:",
		"      - $ref: '#/components/parameters/WidgetId'",
		"        description:",
		"          deeper still, inside the list entry",
		"    get:",
		"      responses:",
		"        '200':",
		"          description: ok",
		"          content:",
		"            application/json:",
		"              schema:",
		"                type: object")

	want := []string{"GET /v1/widgets/{}"}
	if got := keysOf(doc); !equalStrings(got, want) {
		t.Errorf("the reader found\n  %v\nand not\n  %v", got, want)
	}
}

// The failure this guards against is specific: a schema property named `delete`
// three levels down inside a response body, read as a DELETE route. It would be
// a phantom operation in the document, and the check would demand a route that
// should not exist.
func TestAKeyInsideABodySpelledLikeAMethodIsNotAnOperation(t *testing.T) {
	doc := mustRead(t,
		"openapi: 3.1.0", "info:", "  version: 1.0.0",
		"paths:",
		"  /v1/widgets:",
		"    get:",
		"      responses:",
		"        '200':",
		"          content:",
		"            application/json:",
		"              schema:",
		"                properties:",
		"                  delete:",
		"                    type: boolean",
		"                  patch:",
		"                    type: boolean",
		"    post:",
		"      requestBody:",
		"        content:",
		"          application/json:",
		"            schema:",
		"              properties:",
		"                get:",
		"                  type: string")

	want := []string{"GET /v1/widgets", "POST /v1/widgets"}
	if got := keysOf(doc); !equalStrings(got, want) {
		t.Errorf("the reader found\n  %v\nand not\n  %v — a body key spelled like a method "+
			"is not an operation", got, want)
	}
}

// `parameters` is the Path Item Object field that bites: every account path in
// this repository's document carries one, and a reader that did not know the
// difference would report it as an operation with no operationId.
func TestAPathItemsOwnFieldsAreNotOperations(t *testing.T) {
	doc := mustRead(t, "openapi: 3.1.0", "info:", "  version: 1.0.0",
		"paths:", "  /v1/widgets:", "    summary: widgets", "    get:")

	if got := len(doc.Operations); got != 1 {
		t.Errorf("the reader found %d operations; `summary` is a Path Item Object field, "+
			"not an operation", got)
	}
}

// --- the reader refuses rather than under-reads --------------------------------

// Every case here is a document that would make the check pass for the wrong
// reason. "Finds no paths and passes" is the failure mode this whole file is
// about, so the reader raises rather than returning an empty set.
func TestTheReaderRefusesRatherThanUnderReading(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lines []string
		want  string
	}{
		{
			name:  "a document with no top-level paths:",
			lines: []string{"openapi: 3.1.0", "info:", "  title: identity", "  version: 1.0.0"},
			want:  "no top-level `paths:`",
		},
		{
			name:  "a paths: block with nothing under it",
			lines: []string{"openapi: 3.1.0", "info:", "  version: 1.0.0", "paths:"},
			want:  "documents no operations",
		},
		{
			name: "a paths: block with one indentation level and no operations",
			lines: []string{"openapi: 3.1.0", "info:", "  version: 1.0.0",
				"paths:", "  /v1/widgets:"},
			want: "documents no operations",
		},
		{
			name: "a path item with no operation under it",
			lines: []string{"openapi: 3.1.0", "info:", "  version: 1.0.0",
				"paths:", "  /v1/widgets:", "    parameters:", "      - $ref: x"},
			want: "no operation under it",
		},
		{
			// Prepending a slash would quietly accept an invalid document and hide
			// the invalidity, so the reader refuses it.
			name: "a path key that does not start with a slash",
			lines: []string{"openapi: 3.1.0", "info:", "  version: 1.0.0",
				"paths:", "  v1/widgets:", "    get:"},
			want: "not a valid OpenAPI path",
		},
		{
			name: "a direct child of paths: that is neither a path nor a path-item field",
			lines: []string{"openapi: 3.1.0", "info:", "  version: 1.0.0",
				"paths:", "  widget:", "    get:"},
			want: "not a valid OpenAPI path",
		},
		{
			name:  "a document with no openapi: key",
			lines: []string{"info:", "  version: 1.0.0", "paths:", "  /v1/widgets:", "    get:"},
			want:  "no top-level `openapi:`",
		},
		{
			name:  "a document with no info.version",
			lines: []string{"openapi: 3.1.0", "info:", "  title: identity", "paths:", "  /v1/widgets:", "    get:"},
			want:  "no `info.version`",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readOpenAPIDocument(writeDocument(t, tc.lines...))
			if err == nil {
				t.Fatalf("the reader accepted a document it must refuse, so the check " +
					"would compare nothing and agree with nothing")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal does not say %q:\n  %v", tc.want, err)
			}
		})
	}
}

func TestAMissingDocumentIsAnError(t *testing.T) {
	_, err := readOpenAPIDocument(filepath.Join(t.TempDir(), "absent.yaml"))
	if err == nil || !strings.Contains(err.Error(), "could not read") {
		t.Fatalf("reading a missing document returned %v; a reader that finds no file "+
			"finds no paths, and a check over none passes", err)
	}
}

// A rewrite is only safe while it cannot map two different operations onto one.
// If it can, the check is blind to the collision, so the reader says so rather
// than keeping one of them.
func TestTwoOperationsThatNormaliseOntoOneAreAnError(t *testing.T) {
	_, err := readOpenAPIDocument(writeDocument(t,
		"openapi: 3.1.0", "info:", "  version: 1.0.0",
		"paths:", "  /v1/widgets/{id}:", "    get:", "  /v1/widgets/{name}:", "    get:"))

	if err == nil || !strings.Contains(err.Error(), "both read as GET /v1/widgets/{}") {
		t.Fatalf("the reader accepted two paths that are one route to a client: %v", err)
	}
}

// --- normalising ---------------------------------------------------------------

func TestARenamedPathParameterIsNotDrift(t *testing.T) {
	// A generated client substitutes a path parameter positionally, so `{id}`
	// becoming `{widget_id}` is a rename inside one route, not two routes. Failing
	// on it would make the check cry wolf, and a check people turn off is worse
	// than none. This is not hypothetical here: chi registers `{accountID}` and
	// the document writes `{account_id}`.
	if got := normalisePath("/v1/accounts/{accountID}"); got != normalisePath("/v1/accounts/{account_id}") {
		t.Errorf("chi's `{accountID}` and the document's `{account_id}` normalise to %q "+
			"and %q; they are one route", got, normalisePath("/v1/accounts/{account_id}"))
	}
}

func TestTheParameterNameIsTheOnlyThingErasedAndOnlyInsideASegment(t *testing.T) {
	// A mechanical rewrite: the whole segment becomes `{}` whether it is written
	// `{id}`, `:id` or `{some_long_name}`. What is NOT erased is WHICH segment it
	// was, so a path that gains or loses a parameter is still a difference.
	for _, tc := range []struct{ in, want string }{
		{"/v1/widgets/{id}", "/v1/widgets/{}"},
		{"/v1/widgets/:id", "/v1/widgets/{}"},
		{"/v1/widgets/extra", "/v1/widgets/extra"},
		{"/v1/widgets", "/v1/widgets"},
		{"/v1/widgets/{id}/parts/{part_id}", "/v1/widgets/{}/parts/{}"},
		{"/v1/widgets/{id}/parts", "/v1/widgets/{}/parts"},
		// A file suffix on the same parameter: erasing only `{id}` would leave
		// `.json` behind and produce a path the router could never serve.
		{"/v1/widgets/{id}.json", "/v1/widgets/{}"},
		{"/v1/widgets/:id.json", "/v1/widgets/{}"},
	} {
		if got := normalisePath(tc.in); got != tc.want {
			t.Errorf("normalisePath(%q) is %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestATrailingSlashIsNotADifference(t *testing.T) {
	// Grounded in the router's own behaviour rather than in taste: chi routes
	// `/healthz/` to the `/healthz` handler, so the two are one route.
	if got := normalisePath("/healthz/"); got != "/healthz" {
		t.Errorf("normalisePath(\"/healthz/\") is %q, want /healthz", got)
	}
	if got := normalisePath("/healthz//"); got != "/healthz" {
		t.Errorf("normalisePath(\"/healthz//\") is %q, want /healthz", got)
	}
}

func TestTheRootPathKeepsItsSlash(t *testing.T) {
	if got := normalisePath("/"); got != "/" {
		t.Errorf("normalisePath(\"/\") is %q; stripping it would produce an empty path "+
			"that compares equal to nothing", got)
	}
}

// --- the comparison, pointed at an injected fault ------------------------------

// Each of these injects one fault and asserts the comparison names it. This is
// the test that a comparison pointed the wrong way cannot pass: if it reported
// drift in the wrong direction, or none at all, the assertions below would fail.

func contractOf(pairs ...string) map[operationKey]documentedOperation {
	out := map[operationKey]documentedOperation{}
	for _, pair := range pairs {
		fields := strings.SplitN(pair, " ", 2)
		key := operationKey{Method: fields[0], Path: normalisePath(fields[1])}
		out[key] = documentedOperation{Method: fields[0], Path: fields[1], OperationID: "x"}
	}
	return out
}

func servedOf(pairs ...string) map[operationKey]string {
	out := map[operationKey]string{}
	for _, pair := range pairs {
		fields := strings.SplitN(pair, " ", 2)
		out[operationKey{Method: fields[0], Path: normalisePath(fields[1])}] = fields[1]
	}
	return out
}

func TestTheComparisonNamesADocumentedOperationTheRouterDoesNotServe(t *testing.T) {
	got := diff(
		contractOf("GET /v1/widgets", "GET /v1/gadgets"),
		servedOf("GET /v1/widgets"),
		nil)

	if !equalStrings(got.DocumentedNotServed, []string{"GET /v1/gadgets"}) {
		t.Errorf("the forward direction reported %v, want [GET /v1/gadgets]",
			got.DocumentedNotServed)
	}
	if len(got.ServedNotDocumented) != 0 {
		t.Errorf("the reverse direction reported %v and should have reported nothing",
			got.ServedNotDocumented)
	}
}

func TestTheComparisonNamesAServedOperationNoDocumentDescribes(t *testing.T) {
	got := diff(
		contractOf("GET /v1/widgets"),
		servedOf("GET /v1/widgets", "GET /v1/gadgets"),
		nil)

	if !equalStrings(got.Unexplained, []string{"GET /v1/gadgets"}) {
		t.Errorf("the reverse direction reported %v, want [GET /v1/gadgets]", got.Unexplained)
	}
	if len(got.DocumentedNotServed) != 0 {
		t.Errorf("the forward direction reported %v and should have reported nothing",
			got.DocumentedNotServed)
	}
}

// A count comparison passes here: two operations become two operations.
// Comparing the paths does not, and the offender appears on both sides — once
// for the document's spelling and once for the router's.
func TestTheComparisonReportsARenamedPathOnBothSides(t *testing.T) {
	got := diff(
		contractOf("GET /v1/widgets", "GET /v1/wodgets/{id}"),
		servedOf("GET /v1/widgets", "GET /v1/widgets/{id}"),
		nil)

	if !equalStrings(got.DocumentedNotServed, []string{"GET /v1/wodgets/{}"}) {
		t.Errorf("the forward direction reported %v, want [GET /v1/wodgets/{}]",
			got.DocumentedNotServed)
	}
	if !equalStrings(got.Unexplained, []string{"GET /v1/widgets/{}"}) {
		t.Errorf("the reverse direction reported %v, want [GET /v1/widgets/{}]",
			got.Unexplained)
	}
}

// THE billing bug. The path is in both sets, so a comparison over paths — or
// over counts — reports agreement, and one method goes on being served with
// nothing written down about it. In billing that was `PUT /v1/customers/{id}` in
// a money-handling service; here `POST /oidc/authorize` and `POST
// /oidc/userinfo` already are the same shape.
func TestAMethodAddedOnOneSideOnlyIsDriftEvenThoughThePathMatches(t *testing.T) {
	document := contractOf("GET /v1/widgets")
	agreed := servedOf("GET /v1/widgets")

	if got := diff(document, agreed, nil); len(got.Unexplained) != 0 {
		t.Fatalf("the agreed pair already reports %v", got.Unexplained)
	}

	// A second method on the same path. The path set is unchanged on both sides.
	withDelete := servedOf("GET /v1/widgets", "DELETE /v1/widgets")
	got := diff(document, withDelete, nil)

	if !equalStrings(got.Unexplained, []string{"DELETE /v1/widgets"}) {
		t.Errorf("adding a second method to an already-documented path reported %v, want "+
			"[DELETE /v1/widgets]. A path-only or count comparison passes here.", got.Unexplained)
	}
	if len(got.DocumentedNotServed) != 0 {
		t.Errorf("the forward direction reported %v; the path set did not change, so it "+
			"should not have moved", got.DocumentedNotServed)
	}
}

// A carve-out is how a real omission stays a real omission, and it has to be
// narrow: the same omission under a different method is drift again.
func TestAnAdmissionCoversTheOperationItNamesAndNotAnotherMethodOnTheSamePath(t *testing.T) {
	document := contractOf("GET /v1/widgets")
	router := servedOf("GET /v1/widgets", "GET /healthz", "DELETE /healthz")

	admitted := map[operationKey]string{
		{Method: "GET", Path: "/healthz"}: "an infrastructure probe",
	}

	got := diff(document, router, admitted)

	if !equalStrings(got.ServedNotDocumented, []string{"DELETE /healthz", "GET /healthz"}) {
		t.Errorf("the served-but-undocumented set is %v, want both methods on /healthz",
			got.ServedNotDocumented)
	}
	// The one the admission names is out of the unexplained set, and the one it
	// does not name is in it. Keying an admission by method rather than by path
	// is the whole of what makes that true.
	if !equalStrings(got.Unexplained, []string{"DELETE /healthz"}) {
		t.Errorf("the unexplained set is %v, want [DELETE /healthz]. An admission keyed by "+
			"path would have covered both methods, which is how an undocumented method "+
			"survives a check that looks like it is holding the line.", got.Unexplained)
	}
}

func TestTheComparisonReportsEveryOffenderAndNotTheFirst(t *testing.T) {
	got := diff(
		contractOf("GET /v1/a", "GET /v1/b"),
		servedOf("GET /v1/c", "GET /v1/d", "GET /v1/e"),
		nil)

	want := []string{"GET /v1/c", "GET /v1/d", "GET /v1/e"}
	if !equalStrings(got.Unexplained, want) {
		t.Errorf("the comparison reported %v, want all of %v. Reporting one at a time turns "+
			"\"run the test, fix, run it again\" into a loop whose length nobody can see.",
			got.Unexplained, want)
	}
	if !equalStrings(got.DocumentedNotServed, []string{"GET /v1/a", "GET /v1/b"}) {
		t.Errorf("the forward direction reported %v, want both", got.DocumentedNotServed)
	}
}

func TestTwoEmptySetsAgreeAndThatIsNotAReasonToTrustTheComparison(t *testing.T) {
	// The property that makes the emptiness guards in the reader worth having:
	// diff over nothing is empty and reports no drift. So a reader that found
	// nothing would make this check pass, which is why every under-read in
	// readOpenAPIDocument is an error and why servedRoutes fails on zero routes.
	got := diff(map[operationKey]documentedOperation{}, map[operationKey]string{}, nil)
	if len(got.Unexplained)+len(got.DocumentedNotServed) != 0 {
		t.Errorf("diff over two empty sets reported %v; it is supposed to report nothing, "+
			"and that is precisely why the readers must refuse rather than return empty",
			got)
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
