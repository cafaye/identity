package apikeys

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// The wire format, the scopes and the validators.
//
// These are the facts a client compiles against and a reviewer reads before
// trusting anything else in this packet, so they are tested on their own terms
// and not only through a route.

// TestTheWireFormatIsAFixedShape is the assertion a client is written against:
// a token is the brand prefix and exactly 43 base64url characters, every time.
func TestTheWireFormatIsAFixedShape(t *testing.T) {
	for i := range 32 {
		token, digest, err := NewToken()
		if err != nil {
			t.Fatalf("NewToken: %v", err)
		}

		if !strings.HasPrefix(token, Prefix) {
			t.Fatalf("token %d does not start with %q: %q", i, Prefix, token)
		}

		secret, ok := strings.CutPrefix(token, Prefix)
		if !ok {
			t.Fatalf("token %d does not carry the prefix", i)
		}
		// 32 bytes in base64url without padding is 43 characters: 32*4/3 is 42
		// and two thirds, and the encoder spends the last character on the two
		// bits that are left over. Asserted as a literal rather than computed
		// from SecretBytes so that raising the entropy is a FAILING test here and
		// not a silently longer token.
		if len(secret) != 43 {
			t.Errorf("token %d's secret is %d characters, want 43", i, len(secret))
		}
		if len(token) != len(Prefix)+43 {
			t.Errorf("token %d is %d characters, want %d", i, len(token), len(Prefix)+43)
		}
		if strings.ContainsAny(secret, "+/=") {
			t.Errorf("token %d's secret is not base64url without padding: %q", i, secret)
		}

		// And the digest is the hex SHA-256 of the WHOLE presented value, prefix
		// included, because the value a client pastes is the value that gets
		// hashed. A digest of the secret alone would still verify — this service
		// strips the prefix and re-adds it — but it would mean two formats of the
		// same credential hashing differently, and the whole point of hashing the
		// presented string is that there is exactly one of it.
		sum := sha256.Sum256([]byte(token))
		if want := hex.EncodeToString(sum[:]); digest != want {
			t.Errorf("token %d's digest is %q, want the SHA-256 of the whole value %q", i, digest, want)
		}
	}
}

// TestTokensAreDistinct is the property that makes a digest column unique: two
// mints never collide. Thirty-two is not a statistical argument — it is a check
// that the generator is actually being called and not returning a constant.
func TestTokensAreDistinct(t *testing.T) {
	seen := make(map[string]string, 64)
	for range 64 {
		token, digest, err := NewToken()
		if err != nil {
			t.Fatalf("NewToken: %v", err)
		}
		if previous, clash := seen[digest]; clash {
			t.Fatalf("two mints produced the same digest: %q and %q", previous, token)
		}
		seen[digest] = token
	}
}

// TestThePrefixIsRecognisable says what the prefix buys, as an assertion rather
// than as the comment on the constant: a string that begins with it is
// unmistakably this platform's credential and not a Stripe key, a GitHub token
// or a password somebody pasted in the wrong field.
func TestThePrefixIsRecognisable(t *testing.T) {
	token, _, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}

	if !strings.HasPrefix(token, "cafaye_") {
		t.Errorf("the prefix is %q, want something that names the platform", Prefix)
	}
	// Short enough to leave the whole credential inside a CI variable's value
	// field and a log line's column budget, long enough that grepping for it does
	// not match every English word beginning with it.
	if len(Prefix) < 6 {
		t.Errorf("the prefix is %d characters, too short to be a useful grep term", len(Prefix))
	}
	// And it is a PREFIX, not an infix: it cannot be missed by a scanner that
	// looks at the first few bytes, which is where a leaked credential's first
	// few bytes are most likely to be noticed.
	if !strings.Contains(Prefix, "_") {
		t.Error("the prefix does not end in a separator, so a truncated log line could read as a valid token")
	}
}

// TestDigestOfAnythingIsWellFormed is the timing answer, as a test.
//
// The concern is a comparison that returns early on a length mismatch. There is
// no such comparison here, and the reason is that the hashed value is a FIXED
// WIDTH: an empty string, a one-character string, a truncated credential and a
// well-formed one all produce the same 64-character hex digest, so the lookup
// they reach is an ordinary indexed equality in exactly one shape. A malformed
// credential cannot short-circuit past the store because the store never sees
// the malformed value at all.
func TestDigestOfAnythingIsWellFormed(t *testing.T) {
	token, _, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}

	cases := []struct {
		name      string
		presented string
	}{
		{"empty", ""},
		{"one character", "x"},
		{"the prefix alone", Prefix},
		{"the prefix and nothing else", Prefix},
		{"a bare session token", strings.Repeat("A", 43)},
		{"a session token with a prefix glued on", Prefix + strings.Repeat("A", 43)},
		{"a real token", token},
		{"a real token with one character changed", token[:len(token)-1] + "z"},
		{"a real token with one character removed", token[:len(token)-1]},
		{"a real token doubled", token + token},
		{"a non-base64url body", Prefix + "!!!!"},
		{"very long", Prefix + strings.Repeat("A", 4096)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			digest := Digest(tc.presented)
			if len(digest) != 64 {
				t.Errorf("Digest returned %d characters, want 64", len(digest))
			}
			if digest != strings.ToLower(digest) {
				t.Error("the digest is not lower case, so an index built on it would miss")
			}
			if _, err := hex.DecodeString(digest); err != nil {
				t.Errorf("the digest is not hex: %v", err)
			}
		})
	}
}

// TestDigestDistinguishesEveryCharacter is the part of the above that says a
// difference in the presented value is a difference in the stored one. A digest
// that ignored its last character would make every credential sharing a 42-byte
// prefix interchangeable.
func TestDigestDistinguishesEveryCharacter(t *testing.T) {
	token, digest, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}

	for at := range len(token) {
		altered := make([]byte, len(token))
		copy(altered, token)
		if altered[at] == 'A' {
			altered[at] = 'B'
		} else {
			altered[at] = 'A'
		}
		if Digest(string(altered)) == digest {
			t.Fatalf("changing byte %d of the token did not change the digest", at)
		}
	}
}

// ---------------------------------------------------------------------------
// the scope vocabulary
// ---------------------------------------------------------------------------

// TestEveryScopeIsWiredToARoute is the answer to "a scope nobody ever checks at
// the point of use is a scope that is a comment".
//
// The route each scope names is spelled out here, and internal/httpapi's
// TestEveryScopeIsEnforcedOnItsRoutes walks the router and fails if one of these
// strings stops appearing on the route table. Two lists that have to agree, and
// a disagreement is a failure rather than a comment.
func TestEveryScopeIsWiredToARoute(t *testing.T) {
	want := map[string][]string{
		ScopeAccountsRead: {
			"GET /v1/accounts",
			"GET /v1/accounts/{accountID}",
			"GET /v1/accounts/{accountID}/members",
		},
		ScopeAccountsWrite: {
			"POST /v1/accounts",
			"PATCH /v1/accounts/{accountID}",
			"POST /v1/accounts/{accountID}/invitations",
			"PATCH /v1/accounts/{accountID}/members/{userID}",
			"DELETE /v1/accounts/{accountID}/members/{userID}",
			"POST /v1/invitations/accept",
		},
		ScopeAccountsDelete: {
			"DELETE /v1/accounts/{accountID}",
		},
		ScopeOIDCClientsWrite: {
			"POST /v1/accounts/{accountID}/oidc-clients",
			"GET /v1/accounts/{accountID}/oidc-clients",
			"GET /v1/accounts/{accountID}/oidc-clients/{clientID}",
			"DELETE /v1/accounts/{accountID}/oidc-clients/{clientID}",
		},
		// The admin surface's two scopes. Listed here because the test's claim is
		// that a scope in the vocabulary is enforced somewhere, and these were
		// added to the vocabulary with their routes in the same commit — which is
		// the only order in which the claim stays true.
		ScopeAuditLogRead: {
			"GET /v1/accounts/{accountID}/admin/audit-log",
		},
		ScopeAccountInvitationsWrite: {
			"DELETE /v1/accounts/{accountID}/admin/invitations/{invitationID}",
			"POST /v1/accounts/{accountID}/admin/invitation-revocations",
		},
	}

	if len(want) != len(AllScopes()) {
		t.Fatalf("this test knows %d scopes and AllScopes lists %d: %v",
			len(want), len(AllScopes()), AllScopes())
	}
	for _, scope := range AllScopes() {
		routes, known := want[scope]
		if !known {
			t.Errorf("scope %q is in the vocabulary and has no route listed here, so nothing tests where it is enforced", scope)
			continue
		}
		if len(routes) == 0 {
			t.Errorf("scope %q is enforced on no route at all, which is what a comment with a type looks like", scope)
		}
	}
}

// TestAllScopesAreInCoreShape checks the naming against core's own convention,
// which is "scopes for capability (`invoices:write`)". A scope that does not
// look like the ones every other cafaye service writes is one a developer will
// not guess at an integration.
func TestAllScopesAreInCoreShape(t *testing.T) {
	for _, scope := range AllScopes() {
		resource, action, found := strings.Cut(scope, ":")
		if !found {
			t.Errorf("scope %q has no resource:action separator", scope)
			continue
		}
		if resource == "" || action == "" {
			t.Errorf("scope %q has an empty half", scope)
		}
		if resource != strings.ToLower(resource) || action != strings.ToLower(action) {
			t.Errorf("scope %q is not lower case", scope)
		}
	}
}

// TestNoScopeGrantsEverything is the property the whole vocabulary exists for.
//
// There is no wildcard, no `*`, and no scope that means "the union of the
// others". A token is granted the scopes it names, so "read this account" and
// "delete this account" are two separate decisions a person makes twice.
func TestNoScopeGrantsEverything(t *testing.T) {
	for _, scope := range AllScopes() {
		if scope == "*" || strings.Contains(scope, "*") {
			t.Errorf("scope %q is a wildcard; a scope set is a list of capabilities, not a pattern", scope)
		}
	}
	if HasScope(nil, "*") {
		t.Error("an empty scope set satisfies the wildcard, which is the same bug")
	}
}

// TestValidateScopes is the creation-time gate: a closed vocabulary, at least
// one entry, deduped, sorted, and never repaired.
func TestValidateScopes(t *testing.T) {
	cases := []struct {
		name    string
		give    []string
		want    []string
		wantErr *FieldError
	}{
		{
			name: "one supported scope",
			give: []string{ScopeAccountsRead},
			want: []string{ScopeAccountsRead},
		},
		{
			name: "sorted and deduplicated",
			give: []string{ScopeOIDCClientsWrite, ScopeAccountsRead, ScopeAccountsRead},
			want: []string{ScopeAccountsRead, ScopeOIDCClientsWrite},
		},
		{
			name: "surrounding whitespace is trimmed, and only that",
			give: []string{" " + ScopeAccountsRead + " "},
			want: []string{ScopeAccountsRead},
		},
		{
			name: "empty is refused rather than defaulted",
			// The failure this whole packet is about: a token with no scopes is a
			// session that never expires, and it arrives as "the client did not
			// send the field".
			give:    nil,
			wantErr: &FieldError{Field: "scopes", Code: CodeRequired},
		},
		{
			name:    "an empty list is the same as none",
			give:    []string{},
			wantErr: &FieldError{Field: "scopes", Code: CodeRequired},
		},
		{
			name:    "a list of empty strings is still no scopes",
			give:    []string{"", "  "},
			wantErr: &FieldError{Field: "scopes", Code: CodeRequired},
		},
		{
			name: "an unknown scope is refused, not dropped",
			// internal/oidc's registration path CURATES: it drops what it does not
			// implement, because a product registering itself asks for what it
			// would like and an operator curates what it gets. This path does not.
			// A CI job asking for `accounts:admin` and silently receiving
			// `accounts:read` is a script that runs and fails for a week.
			give:    []string{ScopeAccountsRead, "accounts:admin"},
			wantErr: &FieldError{Field: "scopes", Code: CodeUnsupported},
		},
		{
			name: "a prefix of a real scope is not a real scope",
			// `accounts` is not `accounts:read`, and accepting it because it
			// starts with one of the four would hand out a capability set nobody
			// wrote down.
			give:    []string{"accounts"},
			wantErr: &FieldError{Field: "scopes", Code: CodeUnsupported},
		},
		{
			name:    "a superstring of a real scope is not a real scope",
			give:    []string{ScopeAccountsRead + "s"},
			wantErr: &FieldError{Field: "scopes", Code: CodeUnsupported},
		},
		{
			name:    "case does not fold",
			give:    []string{"Accounts:Read"},
			wantErr: &FieldError{Field: "scopes", Code: CodeUnsupported},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateScopes(tc.give)
			if tc.wantErr != nil {
				var fieldErr *FieldError
				assertFieldError(t, err, &fieldErr)
				if *fieldErr != *tc.wantErr {
					t.Fatalf("error = %+v, want %+v", *fieldErr, *tc.wantErr)
				}
				if got != nil {
					t.Errorf("a refused scope list still returned %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateScopes(%v): %v", tc.give, err)
			}
			assertScopes(t, got, tc.want)
		})
	}
}

// TestHasScope is the point of use. It is tested here as well as on the routes,
// because a function that is wrong AND unwired fails exactly the same way as
// one that is right and unwired — with the second being much harder to notice.
func TestHasScope(t *testing.T) {
	given := []string{ScopeAccountsRead, ScopeOIDCClientsWrite}

	cases := []struct {
		name  string
		held  []string
		scope string
		want  bool
	}{
		{"held", given, ScopeAccountsRead, true},
		{"held, the second", given, ScopeOIDCClientsWrite, true},
		{"not held", given, ScopeAccountsDelete, false},
		{"not held, not in the vocabulary", given, "admin", false},
		{"an empty set holds nothing", nil, ScopeAccountsRead, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasScope(tc.held, tc.scope); got != tc.want {
				t.Errorf("HasScope(%v, %q) = %t, want %t", tc.held, tc.scope, got, tc.want)
			}
		})
	}
}

// TestHasScopeIsNotAPrefixMatch is the specific comparison that would hand out a
// capability nobody wrote down.
func TestHasScopeIsNotAPrefixMatch(t *testing.T) {
	given := []string{ScopeAccountsRead}
	for _, almost := range []string{"accounts", ScopeAccountsRead + "s", "accounts:Read", "accounts:read:all"} {
		if HasScope(given, almost) {
			t.Errorf("HasScope(%v, %q) is true; the comparison is a prefix match", given, almost)
		}
	}
}

// ---------------------------------------------------------------------------
// the name and the lifetime
// ---------------------------------------------------------------------------

func TestValidateName(t *testing.T) {
	cases := []struct {
		name    string
		give    string
		want    string
		wantErr *FieldError
	}{
		{name: "the shape a settings page shows", give: "ci-deploy", want: "ci-deploy"},
		{name: "spaces inside are kept", give: "GitHub Actions (main)", want: "GitHub Actions (main)"},
		{name: "surrounding whitespace is trimmed", give: "  staging  ", want: "staging"},
		{name: "empty", give: "", wantErr: &FieldError{Field: "name", Code: CodeRequired}},
		{name: "whitespace only", give: "   ", wantErr: &FieldError{Field: "name", Code: CodeRequired}},
		{
			name: "at the limit",
			give: strings.Repeat("n", MaxNameLength),
			want: strings.Repeat("n", MaxNameLength),
		},
		{
			name:    "over the limit",
			give:    strings.Repeat("n", MaxNameLength+1),
			wantErr: &FieldError{Field: "name", Code: CodeTooLong},
		},
		{
			// The limit is in CHARACTERS and not bytes, because the column is
			// bounded in characters too and a name that passes in a Go test and
			// fails at the CHECK constraint is a 500 for a user with an emoji in
			// their CI variable's description.
			name: "a multi-byte name is counted in characters",
			give: strings.Repeat("é", MaxNameLength),
			want: strings.Repeat("é", MaxNameLength),
		},
		{
			name:    "an interior control character is not a name",
			give:    "deploy\nelsewhere",
			wantErr: &FieldError{Field: "name", Code: CodeInvalidFormat},
		},
		{
			name:    "a tab is a control character",
			give:    "deploy\telsewhere",
			wantErr: &FieldError{Field: "name", Code: CodeInvalidFormat},
		},
		{
			// And the trailing case is asserted positively, because a reader of the
			// rule above should not have to work out that trimming makes it fine.
			name: "a trailing newline is trimmed rather than refused",
			give: "deploy\n",
			want: "deploy",
		},
		{
			name:    "a DEL is a control character",
			give:    "deploy\x7felsewhere",
			wantErr: &FieldError{Field: "name", Code: CodeInvalidFormat},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateName(tc.give)
			if tc.wantErr != nil {
				var fieldErr *FieldError
				assertFieldError(t, err, &fieldErr)
				if *fieldErr != *tc.wantErr {
					t.Fatalf("error = %+v, want %+v", *fieldErr, *tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateName(%q): %v", tc.give, err)
			}
			if got != tc.want {
				t.Errorf("ValidateName(%q) = %q, want %q", tc.give, got, tc.want)
			}
		})
	}
}

// TestResolveExpiry is the expiry decision, as a table.
//
// THE DECISION: expires_at is REQUIRED, with a default of ninety days and a hard
// ceiling of a year. There is no "never" — not as a sentinel, not as an empty
// body, not as a flag.
//
// WHAT IT COSTS, stated here because the table is where a reader looks: a token
// that must be replaced every ninety days is friction on exactly the CI job that
// motivates the feature. The counter is that rotation is two requests — mint the
// replacement, revoke the old one — and that ninety days is short enough that a
// credential nobody has rotated in three quarters has almost certainly stopped
// being used, which is what `last_used_at` is for. A permanent credential has no
// such moment, and the moment is the entire point.
func TestResolveExpiry(t *testing.T) {
	created := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name    string
		give    *time.Duration
		want    time.Time
		wantErr *FieldError
	}{
		{
			name: "no request takes the default",
			give: nil,
			want: created.Add(DefaultTTL),
		},
		{
			name: "a requested lifetime is honoured",
			give: durationPtr(24 * time.Hour),
			want: created.Add(24 * time.Hour),
		},
		{
			name: "exactly the ceiling",
			give: durationPtr(MaxTTL),
			want: created.Add(MaxTTL),
		},
		{
			name:    "past the ceiling is refused, not clamped",
			give:    durationPtr(MaxTTL + time.Hour),
			wantErr: &FieldError{Field: "expires_in", Code: CodeTooLong},
		},
		{
			name:    "an explicit zero is not 'never'",
			give:    durationPtr(0),
			wantErr: &FieldError{Field: "expires_in", Code: CodeOutOfRange},
		},
		{
			name:    "a negative lifetime is refused",
			give:    durationPtr(-time.Hour),
			wantErr: &FieldError{Field: "expires_in", Code: CodeOutOfRange},
		},
		{
			// The floor exists because a token that expires in a second is a way to
			// create a row and get a 401 on the next request, and a caller who
			// meant "as long as possible" has made a mistake worth answering.
			name:    "under the floor is refused",
			give:    durationPtr(time.Second),
			wantErr: &FieldError{Field: "expires_in", Code: CodeOutOfRange},
		},
		{
			name: "exactly the floor",
			give: durationPtr(MinTTL),
			want: created.Add(MinTTL),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveExpiry(created, tc.give)
			if tc.wantErr != nil {
				var fieldErr *FieldError
				assertFieldError(t, err, &fieldErr)
				if *fieldErr != *tc.wantErr {
					t.Fatalf("error = %+v, want %+v", *fieldErr, *tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveExpiry: %v", err)
			}
			if !got.Equal(tc.want) {
				t.Errorf("expiry = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestEveryExpiryIsWithinTheCeiling is the constant and the schema's CHECK
// agreeing. The migration enforces the same year in `api_keys_maximum_lifetime`,
// and a drift between them is a credential that outlives its own policy on one
// side of the boundary only.
func TestEveryExpiryIsWithinTheCeiling(t *testing.T) {
	created := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	for _, give := range []*time.Duration{nil, durationPtr(MinTTL), durationPtr(MaxTTL), durationPtr(DefaultTTL)} {
		got, err := ResolveExpiry(created, give)
		if err != nil {
			t.Fatalf("ResolveExpiry(%v): %v", give, err)
		}
		if got.After(created.Add(MaxTTL)) {
			t.Errorf("expiry %s is past the %s ceiling", got, MaxTTL)
		}
		if !got.After(created) {
			t.Errorf("expiry %s is not after creation", got)
		}
	}
}

// TestTheCeilingIsAYear pins the number, because "a year" is a policy and a
// policy that drifts silently is one nobody chose.
func TestTheCeilingIsAYear(t *testing.T) {
	if want := 365 * 24 * time.Hour; MaxTTL != want {
		t.Errorf("MaxTTL is %s, want %s", MaxTTL, want)
	}
	// And the default is inside it, so the default cannot drift past the ceiling
	// without this failing.
	if DefaultTTL > MaxTTL {
		t.Errorf("DefaultTTL is %s, past the %s ceiling", DefaultTTL, MaxTTL)
	}
}

// TestDigestIsNotReversible is the "the hash is not reversible" claim, tested as
// a property rather than asserted in a comment.
//
// What can actually be checked: the digest is a function of the presented value
// and of nothing else, it does not contain the value, and no prefix or suffix of
// the value appears in it. What cannot be checked without a preimage search is
// that SHA-256 resists inversion — that is the specification's job, and the
// honest claim here is narrower: this service stores no part of the credential,
// and a dump of the column is not a set of working tokens.
func TestDigestIsNotReversible(t *testing.T) {
	token, digest, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}

	secret := strings.TrimPrefix(token, Prefix)
	sum := sha256.Sum256([]byte(token))
	if digest != hex.EncodeToString(sum[:]) {
		t.Fatalf("the digest is not the SHA-256 of the presented value")
	}

	if digest == token {
		t.Error("the digest is the token")
	}
	if digest == secret {
		t.Error("the digest is the token's secret")
	}
	if strings.Contains(digest, token) || strings.Contains(digest, secret) {
		t.Error("the digest contains the credential it was made from")
	}
	// No run of the credential's own characters survives in the digest. Eight is
	// the shortest run worth checking: a 43-character secret has 36 windows of
	// eight, and any of them appearing in 64 hex characters is not chance.
	encoded := hex.EncodeToString([]byte(token))
	for at := 0; at+8 <= len(encoded); at++ {
		window := encoded[at : at+8]
		if strings.Contains(digest, window) {
			t.Errorf("the digest contains %q, which is eight characters of the credential", window)
		}
	}
}

// TestDigestIsAFunctionOfTheWholeValue is the other half: same input, same
// output, every time. A digest that salted itself per call would make every
// credential unusable.
func TestDigestIsAFunctionOfTheWholeValue(t *testing.T) {
	token, digest, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	for range 4 {
		if Digest(token) != digest {
			t.Fatal("Digest is not stable for the same input")
		}
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func durationPtr(d time.Duration) *time.Duration { return &d }

func assertScopes(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("scopes = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("scopes = %v, want %v", got, want)
		}
	}
}

// assertFieldError says a package validation error came back, without importing
// errors into every case above.
func assertFieldError(t *testing.T, err error, target **FieldError) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a validation error and got nil")
	}
	fe, ok := err.(*FieldError)
	if !ok {
		t.Fatalf("error is %T, want *FieldError", err)
	}
	*target = fe
}
