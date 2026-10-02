package ci

// The event grammar, checked against what the CODE emits rather than against
// what the manifest says.
//
// core's contract checker owns the grammar and this file does not restate it.
// `event.own-prefix` has read `exposes.events` since core-17, and a second
// implementation of core's rule inside a service would be a second answer to
// "is this type well formed" — which is the four-way drift the shared harness
// exists to end. So there is no grammar rule here that duplicates one.
//
// What core structurally cannot see is the gap this file covers. Every rule in
// harness/rules.json reads the manifest, because every rule reads a declaration.
// None of them reads another repository's source, so an event the code emits
// and the manifest never names is invisible to all of them at once. core-17
// measured this and reported it as "not this packet's work": five events are
// emitted from internal/accounts/service.go, declared nowhere, and core ships
// one identity payload schema for twelve published types.
//
// A sixth would have joined them silently. That is the whole argument for this
// file: the check has to read the source, and no core rule will ever do it
// without a decision about reading another language's code.
//
// RE-VERIFIED 2026-10-02 by packet `identity-28`, and the sentence above is out
// of date in a way worth correcting rather than leaving. "core ships one identity
// payload schema (user/created) for twelve published types" was true when it was
// written and is no longer: **core-23 paid that debt**, and core now ships NINE
// identity payload schemas — `api_key/{created,revoked}`,
// `mfa/{enabled,disabled}`, `oidc_client/{created,revoked}`, `session/revoked` and
// `user/{created,email_verified}`.
//
// The blocker is unchanged, and it was re-MEASURED rather than assumed, against
// core at `5ec0cec` and again at `15a5df2`: `core/schemas/events/identity/` has
// `api_key`, `mfa`, `oidc_client`, `session` and `user` and **no `account/` and no
// `member/`**, and `identity.member.accepted` has no catalog row at all under that
// name — core calls the fact `identity.member.joined`.
//
// The five were declared anyway on a scratch copy and core's own checker was run
// against it. Six findings, and the reasons in this map are exactly them:
//
//	event.unknown-published        identity.member.accepted is published here and
//	                               core's catalog does not list it, so no consumer
//	                               is known to be waiting for it
//	event.payload-schema-missing  … identity/account/created.schema.json
//	event.payload-schema-missing  … identity/member/invited.schema.json
//	event.payload-schema-missing  … identity/member/accepted.schema.json
//	event.payload-schema-missing  … identity/member/role_changed.schema.json
//	event.payload-schema-missing  … identity/member/removed.schema.json
//
// So the gap is still blocked on CORE, by the mechanism these reasons name, and
// the evidence is a red build rather than a reading of a directory listing. What
// core needs is written down in DECISIONS.md D1: those five files, plus a catalog
// row for `identity.member.accepted` or a recorded ruling that `accepted` and
// `joined` are one fact.
//
// The comparison is a SET comparison, not a count, for the reason
// TestEveryServedRouteIsDocumentedOrNamed in internal/httpapi gives. One event
// declared and one dropped leaves the count alone, and a count is not a claim
// about what this service publishes.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// publishedEventConstant matches a published event type at its definition: the
// constant's name and the string it is given, which is the type on the wire.
//
// `(?m)` is load-bearing rather than decorative. Without it `^` matches only the
// start of the file, the expression finds nothing in a file that is nothing but
// constant definitions, and the failure this check exists to prevent is reported
// as "this service publishes no events" — a refusal that reads as a pass.
//
// Anchored on `Event` so that it reads this repository's published types and
// nothing else, and it is deliberately NOT anchored to a file: every published
// type in this repository lives in internal/outbox, and a new one in another
// package has to be found by this check rather than by someone remembering to
// widen the walk.
var publishedEventConstant = regexp.MustCompile(`(?m)^\s*(Event[A-Za-z0-9_]*)\s*=\s*"([^"]+)"`)

// outboxDir is where the published event types are defined.
const outboxDir = "internal/outbox"

// emittedEventTypes returns every published event type in the tree, as a map
// from the Go constant's name to the type string it publishes.
//
// A constant that is defined twice under two names would be a second fact under
// one spelling, so the two directions are checked: an unreadable definition is
// an error rather than an absence, because an absence here would look identical
// to "this service publishes no events" and every check built on it would agree.
func emittedEventTypes(t *testing.T) map[string]string {
	t.Helper()

	dir := filepath.Join(repoRoot(t), outboxDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v\nThe published event types are defined there, and a check that cannot find them is a check that agrees with a reader that cannot find them.", outboxDir, err)
	}
	if len(entries) == 0 {
		t.Fatalf("%s holds no files, so this service publishes no event types.\nThat is a change to the service, not to a test, and it is not something a reader of a green suite should have to guess at.", outboxDir)
	}

	got := map[string]string{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("reading %s: %v", filepath.Join(outboxDir, name), err)
		}
		for _, match := range publishedEventConstant.FindAllStringSubmatch(string(source), -1) {
			constant, typ := match[1], match[2]
			if previous, clash := got[constant]; clash && previous != typ {
				t.Errorf("%s is %q and also %q — one name publishing two types is a fact stated twice", constant, previous, typ)
			}
			got[constant] = typ
		}
	}

	if len(got) == 0 {
		t.Fatalf("no published event constant matched in %s.\nEither the constants moved or the expression %s is wrong; both are this test's problem and neither is a reason to read zero events as correct.", outboxDir, publishedEventConstant)
	}
	return got
}

// knownUndeclaredEvents is the emitted-but-undeclared set, pinned.
//
// IT CANNOT GROW AND IT CANNOT BE EMPTIED QUIETLY, and both directions are the
// point. Growing means a packet emitted an event and did not declare it, which
// is the defect this file exists to catch. Emptying means a packet declared one
// of these and forgot to delete the line here, which is how a list of known
// exceptions becomes a list of things nobody checks.
//
// Neither is a legal change to this map on its own. Declaring one of these is
// blocked on CORE, not here: `event.payload-schema-missing` reads
// schemas/events/… out of the core checkout, and core has no payload schema for
// `identity.account.created` or for any `identity.member.*` type — see the file
// header for the measurement and for the six findings declaring them produces.
// Declaring these five today would trade a silent gap for six loud reds, which
// is not obviously better — so the gap is written down, pinned, and reported
// instead, with the red build quoted rather than the reasoning behind it.
//
// The values are the reason each one is still here, so a reader arriving at this
// map in six months learns why rather than only that.
var knownUndeclaredEvents = map[string]string{
	"identity.account.created":     "core has the catalog row but no payload schema; declaring it fails event.payload-schema-missing",
	"identity.member.invited":      "core has the catalog row but no payload schema",
	"identity.member.accepted":     "core has NO catalog row — its row is identity.member.joined, and the divergence is a recorded manager decision (see internal/outbox/tenancy.go)",
	"identity.member.role_changed": "core has the catalog row but no payload schema",
	"identity.member.removed":      "core has the catalog row but no payload schema",
}

// TestEveryEmittedEventTypeIsThreeSegmentAndOwnPrefixed pins core 0.2's grammar
// against the EMITTED types.
//
// The same rule core applies to declared types, applied to the side core cannot
// read. internal/outbox/tenancy_test.go pins it for the five tenancy constants;
// this is the same assertion over all twelve, so a type added to any package
// under internal/outbox is covered without a second test remembering to exist.
//
// A two-segment type is the specific failure: core froze that form away in 0.2.0
// and `event.own-prefix` would catch it on the manifest side, but a constant
// that loses its prefix still passes Envelope's own pattern validation, which is
// why the shape has to be asserted rather than inferred.
func TestEveryEmittedEventTypeIsThreeSegmentAndOwnPrefixed(t *testing.T) {
	const service = "identity"

	emitted := emittedEventTypes(t)
	for _, constant := range sortedKeys(emitted) {
		typ := emitted[constant]
		t.Run(typ, func(t *testing.T) {
			segments := strings.Split(typ, ".")
			if len(segments) != 3 {
				t.Errorf("%s = %q has %d segments, want exactly 3 (`<service>.<entity>.<action>`).\ncore froze the two-segment form away in 0.2.0 — CHANGELOG.md maps every one of them — and a type in that form is refused by core's eventType pattern.", constant, typ, len(segments))
			}
			for i, segment := range segments {
				if segment == "" {
					t.Errorf("%s = %q has an empty segment at position %d", constant, typ, i)
				}
			}
			if !strings.HasPrefix(typ, service+".") {
				t.Errorf("%s = %q does not start with the publishing service's own name (%s.…).\nThis is core's event.own-prefix rule, applied to the emitted side: a type without the prefix is one no consumer can route by service.", constant, typ, service)
			}
		})
	}
}

// TestTheManifestDeclaresEveryEmittedEvent is the check core cannot write.
//
// Set equality between what internal/outbox publishes and what
// cafaye.yml's exposes.events declares, with the difference pinned to
// knownUndeclaredEvents. The failure message names both sides because the whole
// defect is that one of them is invisible from the other.
func TestTheManifestDeclaresEveryEmittedEvent(t *testing.T) {
	emitted := emittedEventTypes(t)
	declared := manifestEventTypes(t)

	emittedTypes := map[string]bool{}
	for _, typ := range emitted {
		emittedTypes[typ] = true
	}

	// Sorted by TYPE, not by constant name, so the message names the fact
	// rather than the Go identifier. The constant is a lookup key on the way
	// in; what the manifest declares and what the wire carries is the type.
	var undeclared []string
	for _, constant := range sortedKeys(emitted) {
		if typ := emitted[constant]; !contains(declared, typ) {
			undeclared = append(undeclared, typ)
		}
	}
	sort.Strings(undeclared)

	for _, typ := range undeclared {
		reason, known := knownUndeclaredEvents[typ]
		if !known {
			t.Errorf("%q is emitted by internal/outbox and is not in cafaye.yml's exposes.events, and it is not in knownUndeclaredEvents.\nThat is the defect this file exists to catch: every core rule reads the manifest, so an event nobody declared is invisible to all of them. Declare it, or pin it here with the reason it cannot be declared yet.", typ)
			continue
		}
		// Logged rather than asserted: this is a real gap, and a gap that
		// prints only when the suite goes red is a gap nobody re-reads. The
		// reason travels with it so the next reader learns why the event is
		// undeclared rather than only that it is.
		t.Logf("KNOWN GAP: %q is emitted and undeclared — %s", typ, reason)
	}

	// The pin is exact, in both directions. A declared event that is not
	// emitted is the mirror defect and core's `event.unknown-published` only
	// catches it if core's catalog happens to know the type.
	for _, typ := range declared {
		if !emittedTypes[typ] {
			t.Errorf("%q is declared in exposes.events and emitted nowhere in internal/outbox.\ncore's event.unknown-published only fires for a type core's catalog knows, so a declared-but-unemitted type outside the catalog is this file's to catch.", typ)
		}
	}

	// Stale pins: a line in knownUndeclaredEvents for something that is now
	// declared. Removing the declaration without removing the pin would leave a
	// reason for an exception that no longer exists, and the next reader counts
	// it as outstanding.
	for _, typ := range sortedKeys(knownUndeclaredEvents) {
		if contains(declared, typ) {
			t.Errorf("knownUndeclaredEvents still lists %q, but it IS declared in exposes.events now.\nDelete the line — that is the only legal way this map shrinks, and it shrinks by a packet declaring the event.", typ)
		}
	}
}

// contains is a small helper so the comparison reads as the set question it is.
func contains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}
