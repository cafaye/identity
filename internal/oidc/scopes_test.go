package oidc

import (
	"slices"
	"testing"
)

// The scope set is a closed list of four names, and the test is the list. An
// unknown scope is a 400 rather than a silently dropped parameter, which means
// the set has to be exhaustive in one place: a scope the authorize endpoint
// would accept but the claims builder does not know is a token that comes back
// with nothing in it.

func TestSupportedScopesAreExactlyTheFour(t *testing.T) {
	t.Parallel()

	want := []string{"openid", "email", "profile", "accounts"}

	if !slices.Equal(SupportedScopes, want) {
		t.Fatalf("SupportedScopes = %v, want %v", SupportedScopes, want)
	}
}

func TestIsSupportedScope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
		want bool
	}{
		{name: "openid", give: ScopeOpenID, want: true},
		{name: "email", give: ScopeEmail, want: true},
		{name: "profile", give: ScopeProfile, want: true},
		{name: "accounts", give: ScopeAccounts, want: true},

		// The standard scopes the library knows but this service does not hand
		// out. A product asking for `phone` has asked for something identity
		// cannot answer, and answering with a token that quietly omits it is how
		// a product ships a sign-in screen with a missing phone field.
		{name: "phone is not a cafaye scope", give: "phone"},
		{name: "address is not a cafaye scope", give: "address"},
		{name: "offline_access is not offered", give: "offline_access"},

		// A near miss on one of ours. `profile` and `profiles` are different
		// strings and a prefix comparison would accept the second.
		{name: "a plural is not the singular", give: "profiles"},
		{name: "an underscore is not a hyphen", give: "open-id"},
		{name: "empty", give: ""},
		{name: "nonsense", give: "admin:all"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := IsSupportedScope(tt.give); got != tt.want {
				t.Errorf("IsSupportedScope(%q) = %t, want %t", tt.give, got, tt.want)
			}
		})
	}
}

// NormalizeScopes deduplicates and orders a requested scope list.
//
// Order matters because the list ends up in the discovery document's
// scopes_supported and in the event payload, and a map iteration order would
// make both differ between two runs of the same registration.
func TestNormalizeScopesIsStableAndDeduplicated(t *testing.T) {
	t.Parallel()

	got := NormalizeScopes([]string{"email", "openid", "email", "profile"})
	want := []string{"email", "openid", "profile"}

	if !slices.Equal(got, want) {
		t.Errorf("NormalizeScopes = %v, want %v", got, want)
	}
}

func TestNormalizeScopesDropsTheUnsupported(t *testing.T) {
	t.Parallel()

	got := NormalizeScopes([]string{"openid", "phone", "email"})

	if !slices.Equal(got, []string{"email", "openid"}) {
		t.Errorf("NormalizeScopes = %v, want the supported two in order", got)
	}
}

// FirstUnsupported returns the first requested scope this service does not
// implement, or "" when every one of them is supported.
//
// The authorize endpoint reports the offending name rather than a generic
// message, because the caller is a developer configuring a product and "unknown
// scope: phone" is the difference between a five-minute fix and an afternoon.
// Nothing else about the caller is disclosed: the answer is a function of what
// they asked for and not of who they are.
func TestFirstUnsupportedNamesTheScope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give []string
		want string
	}{
		{name: "all supported", give: []string{"openid", "email"}, want: ""},
		{name: "none requested", give: nil, want: ""},
		{name: "one unsupported", give: []string{"openid", "phone"}, want: "phone"},
		{name: "the first of several", give: []string{"nope", "also-nope"}, want: "nope"},
		// The requested order is the caller's order, not the sorted one, so the
		// name reported is the first one they actually wrote.
		{name: "reported in the order requested", give: []string{"phone", "address"}, want: "phone"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := FirstUnsupported(tt.give); got != tt.want {
				t.Errorf("FirstUnsupported(%v) = %q, want %q", tt.give, got, tt.want)
			}
		})
	}
}

// openid is not optional in OpenID Connect. A request without it is a plain
// OAuth 2.0 request and gets a plain OAuth 2.0 answer, which means no id_token
// and a userinfo endpoint that has nothing to authenticate with.
func TestValidateRequestedScopesRequiresOpenID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		give    []string
		wantErr string
	}{
		{name: "openid with others", give: []string{"openid", "email"}},
		{name: "openid alone", give: []string{"openid"}},
		{name: "email alone", give: []string{"email"}, wantErr: "openid"},
		{name: "nothing at all", give: nil, wantErr: "openid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateRequestedScopes(tt.give)
			switch {
			case err == nil && tt.wantErr != "":
				t.Fatalf("ValidateRequestedScopes(%v) = nil, want an error naming %q", tt.give, tt.wantErr)
			case err != nil && tt.wantErr == "":
				t.Fatalf("ValidateRequestedScopes(%v) = %v, want nil", tt.give, err)
			case err != nil && !containsAll(err.Error(), tt.wantErr):
				t.Errorf("error = %q, want it to name %q", err, tt.wantErr)
			}
		})
	}
}

func containsAll(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
