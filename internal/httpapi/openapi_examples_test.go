package httpapi

// EVERY IDENTIFIER THIS DOCUMENT SHOWS A READER MUST BE ONE.
//
// ## The finding
//
// `openapi/v1.yaml` carried `sub: ab000000-0000-0000-0000-0000000000u1` in the
// introspection example. `u` is not a hex digit, so the value is not a uuid — and
// `sub` on `IntrospectionResponse` is declared `format: uuid`. The document's own
// example of a uuid was not a uuid, which is the most expensive kind of wrong in a
// contract: nothing rejects it, nothing fails, and every reader who tries it finds
// out. A worker on another service wasted time on it before it was reported here.
//
// It was in FOUR places, not one. The same mnemonic suffix had been written into
// `user_id` twice and `actor_user_id` once, so fixing the line the finding named
// would have left three of the same defect in the tree — which is why this is a
// test over both documents rather than an edit to one line.
//
// ## What "a uuid" means HERE, and why the check is narrower than it sounds
//
// **Hex digits and the canonical 8-4-4-4-12 grouping.** That is all.
//
// The RFC 4122 version and variant nibbles are deliberately NOT required, because
// these examples are mnemonic on purpose: `a1` is the api key, `b1` the user, `c1`
// the account, `d1` the invitation, so a reader comparing two ids in a diff can see
// at a glance that they are meant to be the same row or different rows. Demanding a
// v4-shaped value would throw that away and would still not catch the defect this
// test exists for, which is a character that is not a digit of the radix at all.
//
// `encoding/hex` rather than a uuid library, and no dependency: `go.mod` carries
// none for this and `go mod tidy` must leave `go.mod` and `go.sum` alone. A uuid
// parser would also accept forms this document does not use (`urn:uuid:…`, braces,
// no hyphens), which is a way to pass a check while the document drifts away from
// the canonical form its own `format: uuid` promises.

import (
	"encoding/hex"
	"os"
	"regexp"
	"strings"
	"testing"
)

// uuidShaped finds anything written in the canonical grouping, with HEX OR NOT in
// each group — which is the whole trick. A stricter pattern would only ever find
// the values that are already correct.
//
// The character class is alphanumerics rather than hex digits on purpose: this is
// the pattern that matches the defect, and the hex decode below is what judges it.
var uuidShaped = regexp.MustCompile(`[0-9A-Za-z]{8}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{12}`)

// TestEveryIdentifierInAnExampleIsAUuid walks both committed documents.
//
// BOTH, because the finding was in `v1.yaml` and the OpenID Connect document is
// read by the same generated clients and the same drift check — a check that
// covered one of two documents would be a check over half the contract.
//
// IT FAILS ON A DOCUMENT IT CANNOT READ, and it fails when it found nothing AT ALL
// across both of them — the two ways this check could go green without having
// looked at anything. A check that finds no candidates has proved nothing, so the
// count is asserted rather than assumed: a pair of documents that lose their
// examples does not get to pass by becoming empty.
//
// The count is over the PAIR rather than over each file, because
// `openid/openid.yaml` carries no uuid example today — it is a protocol document
// about endpoints and key sets — and demanding one of it would be a rule about
// documentation style dressed up as a security check.
func TestEveryIdentifierInAnExampleIsAUuid(t *testing.T) {
	checked := 0
	for _, path := range []string{v1Document, openidDocument} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}

		found := 0
		for i, line := range strings.Split(string(raw), "\n") {
			for _, candidate := range uuidShaped.FindAllString(line, -1) {
				found++
				digits := strings.ReplaceAll(candidate, "-", "")
				if _, err := hex.DecodeString(digits); err != nil {
					t.Errorf("%s:%d: %q is not a uuid: %v\n"+
						"Every id in this document is declared `format: uuid`, and an example that "+
						"cannot be one is a false claim a reader discovers by trying it. Use hex "+
						"digits — the mnemonic suffixes in use are a1 (api key), b1 (user), c1 "+
						"(account), d1 (invitation).",
						path, i+1, candidate, err)
				}
			}
		}
		checked += found
		t.Logf("%s: %d identifiers, all of them hex", path, found)
	}

	if checked == 0 {
		t.Errorf("neither document carries an identifier in the canonical 8-4-4-4-12 grouping, " +
			"so this test proved nothing about either. Either the examples were removed or they " +
			"were spelled some other way, and a check that cannot see them cannot hold them.")
	}
}
