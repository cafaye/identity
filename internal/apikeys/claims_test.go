package apikeys

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/platform/id"
)

// The claim document: what identity tells a resource server about an opaque token,
// and the two things the addendum in this packet's brief is explicit about.
//
//   - BOTH claim names, byte for byte equal, until MD7 is ruled.
//   - `account_id` required, and no `sub` fallback anywhere.

// claimKey is a live token with everything set, so a test can change one thing at
// a time.
func claimKey() Key {
	return Key{
		ID:        id.MustNew(),
		UserID:    id.MustNew(),
		AccountID: id.MustNew(),
		Name:      "ci-deploy",
		Scopes:    []string{ScopeAccountsWrite, ScopeAccountsRead},
		Role:      "owner",
		CreatedAt: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 12, 30, 12, 0, 0, 0, time.UTC),
	}
}

// TestTheTwoScopeClaimNamesAreEqual is the addendum's requirement, as a test.
//
// IT IS THE ASSERTION THAT MAKES THE INTERIM SAFE. A document carrying a scope in
// one name and not the other is worse than either choice: guard would see an
// empty set and refuse every request, and the debugging session would be spent
// asking why a token that "has" the scope does not work. So the two are compared
// as the strings a consumer will actually parse, over every shape of grant — and
// the comparison is on the rendered JSON, not on the struct, because the struct is
// not what crosses the wire.
func TestTheTwoScopeClaimNamesAreEqual(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		scopes []string
	}{
		{name: "one scope", scopes: []string{ScopeAccountsRead}},
		{name: "every scope", scopes: AllScopes()},
		// Out of order on purpose: the two names must be equal whatever order the
		// row stored, and the document sorts both identically.
		{name: "reversed", scopes: []string{ScopeAccountsDelete, ScopeAccountsRead, ScopeAccountsWrite}},
		{name: "a single scope that sorts last", scopes: []string{ScopeOIDCClientsWrite}},
		{name: "a single scope that sorts first", scopes: []string{ScopeAccountsDelete}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			key := claimKey()
			key.Scopes = tt.scopes

			claims, err := ClaimsFor(key, key.CreatedAt)
			if err != nil {
				t.Fatalf("ClaimsFor: %v", err)
			}

			doc := claims.Document()
			primary, primaryOK := doc[ClaimScopes].(string)
			mirror, mirrorOK := doc[ClaimScope].(string)
			if !primaryOK || !mirrorOK {
				t.Fatalf("the document does not carry both names as strings: %#v", doc)
			}
			if primary != mirror {
				t.Errorf("%s = %q and %s = %q; they must be byte for byte equal or a consumer "+
					"reads a scope set that depends on which name it happens to use",
					ClaimScopes, primary, ClaimScope, mirror)
			}

			// And over the wire, not just in the map: the rendered JSON is what a
			// resource server parses.
			raw, err := json.Marshal(claims)
			if err != nil {
				t.Fatalf("rendering: %v", err)
			}
			var decoded map[string]any
			if err := json.Unmarshal(raw, &decoded); err != nil {
				t.Fatalf("decoding: %v", err)
			}
			if decoded[ClaimScopes] != decoded[ClaimScope] {
				t.Errorf("the rendered document disagrees: %s = %v, %s = %v",
					ClaimScopes, decoded[ClaimScopes], ClaimScope, decoded[ClaimScope])
			}
		})
	}
}

// TestTheScopeClaimIsASpaceSeparatedString is the shape, and it is a decision
// rather than a default: guard splits the claim on whitespace and REFUSES a
// non-string one, so an array is a token the gateway will not parse at all. The
// alternative spelling is asserted too — no array anywhere in the document.
func TestTheScopeClaimIsASpaceSeparatedString(t *testing.T) {
	t.Parallel()

	key := claimKey()
	claims, err := ClaimsFor(key, key.CreatedAt)
	if err != nil {
		t.Fatalf("ClaimsFor: %v", err)
	}

	raw, err := json.Marshal(claims.Document())
	if err != nil {
		t.Fatalf("rendering: %v", err)
	}
	if strings.Contains(string(raw), `"scopes":[`) || strings.Contains(string(raw), `"scope":[`) {
		t.Errorf("a scope claim is an array: %s. guard splits on whitespace and rejects a "+
			"non-string claim, so an array is a token it cannot read", raw)
	}

	// The exact form guard's own split produces.
	want := "accounts:read accounts:write"
	if claims.Scopes != want {
		t.Errorf("scopes = %q, want %q", claims.Scopes, want)
	}
	for _, scope := range strings.Fields(claims.Scopes) {
		if !IsSupportedScope(scope) {
			t.Errorf("the claim carries %q, which is not in the vocabulary", scope)
		}
	}
}

// TestAccountIDIsRequiredAndNeverDerivedFromSub is the second half of the
// addendum, and the part that is a security property rather than a naming
// question.
//
// There is no `sub` fallback anywhere: a token with no account produces an
// inactive document and ErrNoAccountID from the resolver, and the assertions below
// check that the account id in the document is the ROW's account and not
// something reconstructed from the subject.
func TestAccountIDIsRequiredAndNeverDerivedFromSub(t *testing.T) {
	t.Parallel()

	key := claimKey()
	claims, err := ClaimsFor(key, key.CreatedAt)
	if err != nil {
		t.Fatalf("ClaimsFor: %v", err)
	}

	if claims.AccountID != key.AccountID.String() {
		t.Errorf("account_id = %q, want the row's %q", claims.AccountID, key.AccountID)
	}
	if claims.Subject != key.UserID.String() {
		t.Errorf("sub = %q, want the row's user %q", claims.Subject, key.UserID)
	}
	if claims.AccountID == claims.Subject {
		t.Error("account_id and sub are the same value, so the tenancy key is the subject")
	}

	resolved, err := ResolveAccountID(claims)
	if err != nil {
		t.Fatalf("ResolveAccountID: %v", err)
	}
	if resolved != key.AccountID {
		t.Errorf("ResolveAccountID = %s, want %s", resolved, key.AccountID)
	}

	// A claim document with no account is refused, not defaulted.
	if _, err := ResolveAccountID(Claims{Active: true, Subject: key.UserID.String()}); !errors.Is(err, ErrNoAccountID) {
		t.Errorf("a claim with no account = %v, want ErrNoAccountID", err)
	}
	// And a malformed one is refused too, rather than being parsed leniently into
	// the nil uuid — which is a value no row can have and which a query that
	// treated it as a wildcard would return everything for.
	if _, err := ResolveAccountID(Claims{Active: true, AccountID: "not-a-uuid"}); !errors.Is(err, ErrNoAccountID) {
		t.Errorf("a claim with a malformed account = %v, want ErrNoAccountID", err)
	}
	// A token whose row has no account cannot produce a document at all.
	if _, err := ClaimsFor(Key{ID: key.ID, UserID: key.UserID}, key.CreatedAt); !errors.Is(err, ErrNoAccountID) {
		t.Errorf("a key with no account = %v, want ErrNoAccountID", err)
	}
}

// TestAnUnusableTokenIsInactiveAndCarriesNothingElse: the one-error rule, in claim
// form. RFC 7662 says an introspection response for a token that cannot be used
// is `{"active": false}` and nothing else, and every field here exists to be
// absent — a `sub` on an inactive document is a user id handed to whoever asked.
func TestAnUnusableTokenIsInactiveAndCarriesNothingElse(t *testing.T) {
	t.Parallel()

	revokedAt := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		give func(k *Key)
		at   time.Time
	}{
		{
			name: "revoked",
			give: func(k *Key) { k.RevokedAt = &revokedAt },
			at:   time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC),
		},
		{
			name: "expired",
			give: func(k *Key) {},
			at:   time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC),
		},
		{
			// The boundary: `now >= expires_at` is spent. One nanosecond earlier it
			// is not, and both are asserted so one implementation of the boundary
			// does not drift from the other.
			name: "exactly at its expiry",
			give: func(k *Key) {},
			at:   time.Date(2026, 12, 30, 12, 0, 0, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			key := claimKey()
			tt.give(&key)

			claims, err := ClaimsFor(key, tt.at)
			if err != nil {
				t.Fatalf("ClaimsFor: %v", err)
			}
			if claims.Active {
				t.Fatal("an unusable token produced an active claim document")
			}

			raw, err := json.Marshal(claims.Document())
			if err != nil {
				t.Fatalf("rendering: %v", err)
			}
			if got, want := strings.TrimSpace(string(raw)), `{"active":false}`; got != want {
				t.Errorf("the document is %s, want exactly %s. A refusal that carries a subject "+
					"is a user id handed to whoever asked", got, want)
			}
		})
	}

	// One nanosecond before the boundary it is still live, which is the direction
	// that matters: a claim that goes inactive early kills a credential between
	// the request that used it and the response that said it was fine.
	key := claimKey()
	claims, err := ClaimsFor(key, key.ExpiresAt.Add(-time.Nanosecond))
	if err != nil {
		t.Fatalf("ClaimsFor: %v", err)
	}
	if !claims.Active {
		t.Error("a token one nanosecond before its expiry is already inactive")
	}
}

// TestTheClaimCarriesTheGrantAndNotTheCredential. The claim document names what
// the token may do and who it is; it never carries a value that authenticates
// anything. A `digest` in here would be a second copy of the row's sensitive
// column in a document whose whole job is to be readable.
func TestTheClaimCarriesTheGrantAndNotTheCredential(t *testing.T) {
	t.Parallel()

	key := claimKey()
	key.TokenDigest = Digest(Prefix + strings.Repeat("x", 43))
	claims, err := ClaimsFor(key, key.CreatedAt)
	if err != nil {
		t.Fatalf("ClaimsFor: %v", err)
	}

	raw, err := json.Marshal(claims.Document())
	if err != nil {
		t.Fatalf("rendering: %v", err)
	}
	for _, forbidden := range []string{"digest", "token", "secret", Prefix, key.TokenDigest} {
		if strings.Contains(string(raw), forbidden) {
			t.Errorf("the claim document mentions %q: %s", forbidden, raw)
		}
	}

	// And the fields that ARE there, because a document that answered "who is this"
	// without saying "for which account" would be the missing-tenancy bug.
	for _, want := range []string{ClaimAccountID, ClaimScopes, ClaimScope, "sub", "jti", "iat", "exp"} {
		if _, present := claims.Document()[want]; !present {
			t.Errorf("the document has no %q", want)
		}
	}
}

// TestTheClaimIsStableForTheSameRow: a resource server may cache on these bytes,
// so two renderings of one row must be identical. A map's iteration order would
// not make them differ in JSON (encoding/json sorts keys) but it WOULD make the
// scope string differ, which is why the scopes are sorted rather than joined in
// whatever order the row held.
func TestTheClaimIsStableForTheSameRow(t *testing.T) {
	t.Parallel()

	key := claimKey()
	key.Scopes = []string{ScopeAccountsWrite, ScopeAccountsRead, ScopeAccountsDelete}

	first, err := ClaimsFor(key, key.CreatedAt)
	if err != nil {
		t.Fatalf("ClaimsFor: %v", err)
	}
	// The same scopes in a different order, as a row read twice could return them
	// if the array order were ever not guaranteed.
	key.Scopes = []string{ScopeAccountsDelete, ScopeAccountsRead, ScopeAccountsWrite}
	second, err := ClaimsFor(key, key.CreatedAt)
	if err != nil {
		t.Fatalf("ClaimsFor: %v", err)
	}

	a, _ := json.Marshal(first.Document())
	b, _ := json.Marshal(second.Document())
	if string(a) != string(b) {
		t.Errorf("two renderings of one row differ:\n%s\n%s", a, b)
	}
}

// TestTheClaimStringDoesNotLeak: Claims has a String method precisely so a %v in a
// log line does not print every field, and this asserts what it prints.
func TestTheClaimStringDoesNotLeak(t *testing.T) {
	t.Parallel()

	key := claimKey()
	claims, err := ClaimsFor(key, key.CreatedAt)
	if err != nil {
		t.Fatalf("ClaimsFor: %v", err)
	}

	rendered := claims.String()
	if !strings.Contains(rendered, key.AccountID.String()) {
		t.Errorf("the string form does not name the account, so a log line cannot be traced: %s", rendered)
	}
	// The subject is the one field deliberately left out: a log line about a
	// token needs the account and the credential's id to be useful, and a user id
	// is the thing a log aggregator is worst place to accumulate.
	if strings.Contains(rendered, key.UserID.String()) {
		t.Errorf("the string form carries the subject: %s", rendered)
	}
	if !strings.Contains(rendered, "active=true") {
		t.Errorf("the string form does not say the token is live: %s", rendered)
	}

	// And the inactive one says exactly that.
	if got, want := InactiveClaims().String(), "apikeys.claims{active=false}"; got != want {
		t.Errorf("InactiveClaims().String() = %q, want %q", got, want)
	}
}
