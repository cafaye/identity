package ci

// A reader for the one block of cafaye.yml this package needs.
//
// go.mod has no YAML dependency and adding one would put a parser and its CVEs in
// this module's dependency list for the sake of one list of strings, so this
// reads the block by shape — the same trade internal/httpapi/openapi_reader_test.go
// makes for the OpenAPI documents, and for the same reason.
//
// THE RULE THAT MATTERS HERE IS REFUSAL, NOT PARSING. A reader that finds nothing
// agrees with another reader that finds nothing, and a reader that silently skips
// a list item it did not understand turns "this service declares no events" into
// a claim about a document it never read. So every way this can come back with
// less than it should — no `exposes:`, no `events:` under it, a block that yields
// nothing, a line inside the block that is not a comment, a blank, or a `- type`
// entry, an entry with no value — is an error naming the line, and the caller
// turns that error into a failed test rather than into an empty list.
//
// It is a pure function of the document rather than a helper that fails the test
// itself, because a reader that reports through *testing.T cannot be tested for
// refusal at all: the proof that it refused is a failed test, and a test that
// fails cannot also assert. The tests below are the reason the signature is what
// it is.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// manifestEventTypes returns the entries of `exposes.events` in cafaye.yml, and
// fails the test if the block cannot be read whole.
func manifestEventTypes(t *testing.T) []string {
	t.Helper()
	path := filepath.Join(repoRoot(t), "cafaye.yml")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading cafaye.yml: %v", err)
	}
	got, err := eventTypesFromManifest(string(source))
	if err != nil {
		t.Fatalf("reading cafaye.yml: %v", err)
	}
	return got
}

// eventTypesFromManifest reads `exposes.events` out of a manifest document.
func eventTypesFromManifest(source string) ([]string, error) {
	lines := strings.Split(source, "\n")

	exposesAt := -1
	for i, line := range lines {
		if line == "exposes:" {
			if exposesAt >= 0 {
				return nil, fmt.Errorf("a second top-level `exposes:` at line %d, so which block is the contract is ambiguous", i+1)
			}
			exposesAt = i
		}
	}
	if exposesAt < 0 {
		return nil, fmt.Errorf("no top-level `exposes:`, so the event list could not be located")
	}

	eventsAt := -1
	for i := exposesAt + 1; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		// Blank lines and comments sit between sibling keys in this
		// repository's own manifest, so they are stepped over rather than
		// treated as the end of the block. Treating a blank line as the end
		// would make the reader refuse the real cafaye.yml, and a reader that
		// refuses everything is indistinguishable from a correct one.
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// `events:` is a key at two-space indentation, a sibling of `api:`.
		// A line indented less than that has left the block, and so has any
		// line at zero indentation.
		if line == "  events:" {
			eventsAt = i
			break
		}
		if !strings.HasPrefix(line, "  ") {
			break
		}
	}
	if eventsAt < 0 {
		return nil, fmt.Errorf("no `events:` list under `exposes:`, so the declaration could not be located")
	}

	var got []string
	for i := eventsAt + 1; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(line, "    - ") {
			if !strings.HasPrefix(line, "    ") {
				// Shallower than an entry: the list ended.
				break
			}
			return nil, fmt.Errorf("line %d is inside `exposes.events` and is not a list entry, a comment, or blank: %q", i+1, line)
		}
		value := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
		if value == "" {
			return nil, fmt.Errorf("line %d is an `exposes.events` entry with no value", i+1)
		}
		got = append(got, value)
	}

	if len(got) == 0 {
		return nil, fmt.Errorf("`exposes.events` yielded no entries, so a comparison against it would report every published event as undeclared")
	}
	return got, nil
}

// The tests below are of the READER, not of a document. Each is a shape the
// reader must refuse, because a reader exercised only against the real
// cafaye.yml has proven that it reads cafaye.yml and nothing else.

func TestTheManifestReaderReadsTheRealShape(t *testing.T) {
	const document = `name: identity
exposes:
  api: openapi/v1.yaml

  events:
    # A comment at the entry indentation.
    - identity.user.created

    - identity.api_key.created
repository:
  url: git@github.com:cafaye/identity.git
`

	got, err := eventTypesFromManifest(document)
	if err != nil {
		t.Fatalf("reading a well-formed document: %v\nIf the reader refuses this, the refusals below prove nothing about the real manifest.", err)
	}
	want := []string{"identity.user.created", "identity.api_key.created"}
	if len(got) != len(want) {
		t.Fatalf("read %v, want %v", got, want)
	}
	for i, typ := range want {
		if got[i] != typ {
			t.Errorf("entry %d = %q, want %q", i, got[i], typ)
		}
	}
}

func TestTheManifestReaderRefusesWhatItDidNotRead(t *testing.T) {
	const wellFormed = `exposes:
  events:
    - identity.user.created
`

	for name, document := range map[string]string{
		"no exposes block":                         "name: identity\nconsumes: []\n",
		"no events list under exposes":             "exposes:\n  api: openapi/v1.yaml\nrepository:\n  url: git@github.com:cafaye/identity.git\n",
		"an events list that yields nothing":       "exposes:\n  events:\n    # every line here is a comment\nrepository:\n  url: git@github.com:cafaye/identity.git\n",
		"an entry with no value":                   "exposes:\n  events:\n    - \n    - identity.user.created\n",
		"a line in the block that is not an entry": "exposes:\n  events:\n    - identity.user.created\n    identity.member.invited\n",
		"a second top-level exposes":               wellFormed + "exposes:\n  events:\n    - identity.user.created\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := eventTypesFromManifest(document); err == nil {
				t.Errorf("the reader returned a list for this document instead of refusing it.\nA reader that under-reads a document it did not understand is worse than no reader: the checks built on it go green, and they are green about a list nobody read.")
			}
		})
	}
}

// The control for the table above: the same reader, on a document it must accept.
// Without it, a reader that refused EVERYTHING would pass every case in the table.
func TestTheManifestReaderAcceptsWhatItUnderstands(t *testing.T) {
	const document = `exposes:
  events:
    - identity.user.created
`
	if _, err := eventTypesFromManifest(document); err != nil {
		t.Fatalf("the reader refused a document it is supposed to read: %v", err)
	}
}
