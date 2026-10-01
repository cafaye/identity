package httpapi

// FAULTS INJECTED INTO THE README-AND-MANIFEST READERS.
//
// claims_test.go compares claims to the router. That comparison is worth exactly
// as much as the reader feeding it, and a reader that under-reads does not fail —
// it reports agreement over a subset. So this file takes each way
// readmeClaims, manifestDescription, manifestCapabilities and roadmapCheckedItems
// could come back with less than they should, and asserts it is an ERROR rather
// than a smaller set.
//
// The rule being tested throughout is the one in openapi_reader_test.go: **two
// readers that both find nothing agree, and that is how a check over nothing goes
// green.** A test of a document is a test of the RULE the reader applies, never of
// the particular document — so every case here is a synthetic input, and the real
// README is only ever read by claims_test.go itself.

import (
	"strings"
	"testing"
)

// TestTheReadmeReaderRefusesAMalformedRouteRow is the case that matters most,
// because it is the one a substring-based reader waves through.
//
// A row whose first cell starts like a route but is not one is a claim this
// repository cannot check. The reader must say so. If it skipped the row instead,
// then a README row written as `GETTY /v1/thing` — a typo, a copy-paste, a method
// invented by whoever was writing — would be invisible, and the comparison below it
// would report that the README and the router agree.
func TestTheReadmeReaderRefusesAMalformedRouteRow(t *testing.T) {
	for name, span := range map[string]string{
		"a misspelled method":      "GETTY /v1/thing",
		"a method with no space":   "POST/v1/thing",
		"a method and no path":     "GET",
		"a method and prose":       "POST see below",
		"a method and a bare word": "GET healthz",
	} {
		t.Run(name, func(t *testing.T) {
			_, _, isRoute, err := parseRouteCell([]string{span}, 1)
			if err == nil {
				t.Fatalf("parseRouteCell accepted %q. A cell that begins like a route is "+
					"claiming one, and accepting it without understanding it means the claim is "+
					"never checked — which is the subset-agreement failure this reader exists to "+
					"prevent. (isRoute=%v)", span, isRoute)
			}
			if !strings.Contains(err.Error(), span) {
				t.Errorf("the error does not quote the span it refused (%q), so a reader of the "+
					"failure has to go and find it.", span)
			}
		})
	}
}

// TestTheReadmeReaderSkipsCellsThatAreNotRouteRows is the other direction, and it
// is here because the fix for the case above is a shape test, and a shape test that
// is too eager refuses the whole file.
//
// The README has a package-timing table whose cells are `internal/accounts`, a
// scope table whose cells are `accounts:read`, and header rows. None of those claim
// a route. A reader that treated "contains a `/`" as "claims a route" would refuse
// the README over a table of Go package paths, and a check that cries wolf gets
// turned off.
func TestTheReadmeReaderSkipsCellsThatAreNotRouteRows(t *testing.T) {
	for name, span := range map[string]string{
		"a package path":  "internal/accounts",
		"a scope name":    "accounts:read",
		"a status code":   "201 {…}",
		"a document name": "openapi/v1.yaml",
		"a migration":     "migrations/00008_connected_accounts.sql",
		"a file":          "internal/httpapi/oauth.go",
	} {
		t.Run(name, func(t *testing.T) {
			claims, absent, isRoute, err := parseRouteCell([]string{span}, 1)
			if err != nil {
				t.Fatalf("parseRouteCell refused %q: %v. This cell does not claim a route, and "+
					"refusing it makes the check fail on a table of Go package paths.", span, err)
			}
			if isRoute || len(claims) != 0 || len(absent) != 0 {
				t.Errorf("parseRouteCell read %q as a route claim (isRoute=%v, %d claims, %d "+
					"absences). It is not one, and counting it as one is the under-read this "+
					"reader must not do.", span, isRoute, len(claims), len(absent))
			}
		})
	}
}

// TestTheReadmeReaderRefusesARowThatIsBothAPromiseAndARefusal pins the mixed-cell
// rule.
//
// `GET /oidc/introspect`, `/oidc/revoke` was the real shape of this row before this
// packet: one methoded path and three bare ones in a single cell. A reader that took
// the first branch would have claimed the first is served and skipped the rest; one
// that took the second would have declared all four absent. Both are guesses, and
// the honest answer is to refuse the cell and let somebody fix the row.
func TestTheReadmeReaderRefusesARowThatIsBothAPromiseAndARefusal(t *testing.T) {
	_, _, _, err := parseRouteCell([]string{"GET /oidc/introspect", "/oidc/revoke"}, 820)
	if err == nil {
		t.Fatal("parseRouteCell accepted a cell that claims one operation is served and " +
			"declares another is not. The reader cannot know which half the author meant, and " +
			"picking one is how a document and a router end up reported as agreeing when they " +
			"were never compared.")
	}
	if !strings.Contains(err.Error(), "cannot be a promise and a refusal") {
		t.Errorf("the error does not say what is wrong with the cell: %v", err)
	}
}

// TestTheManifestReaderRefusesAFormItCannotRead covers the three shapes of
// `description:` that would each come back as a confident wrong answer.
//
//   - a block scalar, which this reader would return as the literal characters `|`;
//   - an empty value, which is a claim set of nothing;
//   - no key at all, which is a manifest that asserts nothing to check.
//
// All three are errors. None of them is an empty capability list, because an empty
// list compares equal to an empty router and that is agreement between nothing.
func TestTheManifestReaderRefusesAFormItCannotRead(t *testing.T) {
	for name, contents := range map[string]string{
		"a block scalar":  "name: identity\ndescription: |\n  A long description\n",
		"a folded scalar": "name: identity\ndescription: >\n  A long description\n",
		"an empty value":  "name: identity\ndescription:\n",
		"an absent key":   "name: identity\nlanguage: go\n",
		"a nil value":     "name: identity\ndescription: ~\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := readManifestDescription(contents)
			if err == nil {
				t.Fatal("the manifest reader accepted a description it cannot read. Returning " +
					"something — even an empty string — would make TestTheManifestDescribesOnly" +
					"CapabilitiesThisServiceHas compare a nonsense claim list against the router " +
					"and report the result as a finding.")
			}
		})
	}
}

// TestTheManifestReaderAcceptsTheFormsItUnderstands is the other half, because a
// reader that refuses everything is not strict, it is broken and it would be
// deleted.
func TestTheManifestReaderAcceptsTheFormsItUnderstands(t *testing.T) {
	for name, testCase := range map[string]struct{ contents, want string }{
		"a plain scalar": {
			contents: "name: identity\ndescription: One line of prose.\nlanguage: go\n",
			want:     "One line of prose.",
		},
		"a quoted scalar": {
			contents: "description: \"Quoted, with a comma.\"\n",
			want:     "Quoted, with a comma.",
		},
		"an apostrophe, which must survive": {
			contents: "description: The service's own surface.\n",
			want:     "The service's own surface.",
		},
		"a hash inside the value": {
			contents: "description: Issues tokens, then # not a comment here.\n",
			want:     "Issues tokens, then # not a comment here.",
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := readManifestDescription(testCase.contents)
			if err != nil {
				t.Fatalf("the manifest reader refused a form it should understand: %v", err)
			}
			if got != testCase.want {
				t.Errorf("got %q, want %q", got, testCase.want)
			}
		})
	}
}

// TestManifestCapabilitiesSplitsOnCommasOnly pins the one parsing decision in the
// manifest path, and the reason for it.
//
// Splitting on " and " as well would turn "accounts and tenancy" into two claims
// the evidence table has never heard of. That is not a hypothetical: this
// repository's description contains exactly that phrase, and a reader that split on
// both would fail on a manifest nobody had changed.
func TestManifestCapabilitiesSplitsOnCommasOnly(t *testing.T) {
	for name, testCase := range map[string]struct {
		description string
		want        []string
	}{
		"the real description, unsplit on and": {
			description: "Authentication, sessions, MFA, accounts and tenancy, scoped API tokens, and the OIDC provider.",
			want:        []string{"Authentication", "sessions", "MFA", "accounts and tenancy", "scoped API tokens", "the OIDC provider"},
		},
		"a trailing and is dropped": {
			description: "Sessions, and MFA.",
			want:        []string{"Sessions", "MFA"},
		},
		"a single item": {
			description: "Only one thing.",
			want:        []string{"Only one thing"},
		},
		"an empty segment is dropped rather than becoming a blank claim": {
			description: "Sessions,, MFA.",
			want:        []string{"Sessions", "MFA"},
		},
		"a description of nothing yields nothing, which the caller must notice": {
			// Dots, not an empty string: the empty string is already an error three
			// layers up in the reader, and a case here for it would assert on a path
			// that cannot be reached. What is being pinned is that a value with no
			// comma and no letters comes back as NO claim rather than as one item
			// reading "..", which would then be reported as an unknown capability.
			description: ", ,",
			want:        nil,
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := manifestCapabilities(testCase.description)
			if len(got) != len(testCase.want) {
				t.Fatalf("got %q, want %q", got, testCase.want)
			}
			for i := range got {
				if got[i] != testCase.want[i] {
					t.Errorf("item %d: got %q, want %q", i, got[i], testCase.want[i])
				}
			}
		})
	}
}

// TestRoadmapParsingFoldsContinuationsAndIgnoresUnchecked is the roadmap reader's
// whole contract, and both halves of it are load-bearing.
//
// A wrapped markdown list item is ONE item. Reading the continuation as its own
// would produce a fragment that matches no entry in either table, so the surface
// check would report a checked item that does not exist.
//
// An unchecked box asserts nothing and must be skipped entirely — it is the honest
// state, and this packet's whole subject. A reader that counted `- [ ]` items as
// claims would make the fix for the OAuth lie impossible to apply.
func TestRoadmapParsingFoldsContinuationsAndIgnoresUnchecked(t *testing.T) {
	const readme = "## Not built yet\n" +
		"\n" +
		"An unchecked box lives here and must be ignored by the roadmap reader.\n" +
		"\n" +
		"## Roadmap\n" +
		"\n" +
		"- [x] A checked item that is one line\n" +
		"- [x] A checked item that wraps, and whose second\n" +
		"      line continues it\n" +
		"- [ ] An unchecked item, which is the honest state\n" +
		"- [x] A third checked item\n" +
		"\n" +
		"## Something after\n" +
		"\n" +
		"- [x] Not in the roadmap section at all\n"

	items := roadmapItemsFrom(readme)
	want := []string{
		"A checked item that is one line",
		"A checked item that wraps, and whose second line continues it",
		"A third checked item",
	}

	if len(items) != len(want) {
		t.Fatalf("got %d item(s) %q, want %d %q", len(items), items, len(want), want)
	}
	for i := range want {
		if items[i] != want[i] {
			t.Errorf("item %d: got %q, want %q", i, items[i], want[i])
		}
	}
}

// TestRoadmapParsingRefusesAnEmptySection is the under-read case for the roadmap.
//
// A Roadmap with no checked items is a roadmap that has been emptied, or a section
// heading that was renamed, and either way the surface check would then have no
// claims to hold against the router. That is agreement between nothing.
func TestRoadmapParsingRefusesAnEmptySection(t *testing.T) {
	for name, readme := range map[string]string{
		"an empty roadmap":           "## Roadmap\n\nNothing here yet.\n",
		"only unchecked items":       "## Roadmap\n\n- [ ] Nothing ships\n",
		"a renamed section":          "## Milestones\n\n- [x] Something\n",
		"no section at all":          "The file has no roadmap.\n",
		"a checked box with no text": "## Roadmap\n\n- [x]\n",
	} {
		t.Run(name, func(t *testing.T) {
			if got := roadmapItemsFrom(readme); len(got) != 0 {
				t.Errorf("the roadmap reader found %q in a section with no checked item. Every "+
					"capability in it has been unchecked or the heading renamed, and a reader that "+
					"returns a claim list of nothing is a check that cannot fail.", got)
			}
		})
	}
}
