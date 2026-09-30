package oauth

import (
	"net/url"
	"strings"
	"testing"
)

// The state parameter is the entire CSRF defence for the OAuth round trip.
//
// The callback arrives as a top-level cross-site GET from the provider, so it
// cannot carry a header and cannot read one; the session cookie rides along
// (SameSite=Lax) and that is the whole problem. A `state` this service minted and
// put in a cookie it can read back is what distinguishes "the user is finishing
// the flow we started" from "an attacker pasted a code into the callback URL".

func TestNewStateBindsTheProvider(t *testing.T) {
	t.Parallel()

	raw, err := NewState("github")
	if err != nil {
		t.Fatalf("NewState: %v", err)
	}

	name, token, ok := strings.Cut(raw, ".")
	if !ok {
		t.Fatalf("NewState = %q, want it to carry a provider prefix", raw)
	}
	if name != "github" {
		t.Errorf("the state names %q, want the provider it was minted for", name)
	}
	if len(token) != 43 {
		t.Errorf("the state token is %d characters, want 43 (32 bytes of base64url)", len(token))
	}
	for _, r := range token {
		if !(r >= 'A' && r <= 'Z') && !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' && r != '_' {
			t.Errorf("the state token %q is not base64url", token)
			break
		}
	}
}

func TestNewStateIsNotRepeated(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool, 64)
	for range 64 {
		raw, err := NewState("google")
		if err != nil {
			t.Fatalf("NewState: %v", err)
		}
		if seen[raw] {
			t.Fatalf("NewState produced %q twice; the token is not random per call", raw)
		}
		seen[raw] = true
	}
}

// A state is single-use in practice because the handler clears the cookie when it
// verifies one, but the token still has to be unguessable: an attacker who
// completes a flow against their own provider account and then replays the state
// against a victim's browser would otherwise be indistinguishable from a real
// round trip.
func TestVerifyStateAcceptsOnlyTheExactPair(t *testing.T) {
	t.Parallel()

	sealed, err := NewState("google")
	if err != nil {
		t.Fatalf("NewState: %v", err)
	}

	if !VerifyState("google", sealed, sealed) {
		t.Error("VerifyState rejected the pair it should accept")
	}

	other, err := NewState("google")
	if err != nil {
		t.Fatalf("NewState: %v", err)
	}

	tests := []struct {
		name      string
		provider  string
		sealed    string
		presented string
	}{
		{name: "a different token from the same provider", provider: "google", sealed: sealed, presented: other},
		{name: "nothing presented", provider: "google", sealed: sealed, presented: ""},
		{name: "nothing in the cookie", provider: "google", sealed: "", presented: sealed},
		{name: "the token without its provider", provider: "google", sealed: sealed, presented: strings.TrimPrefix(sealed, "google.")},
		{name: "a truncated token", provider: "google", sealed: sealed, presented: sealed[:len(sealed)-1]},
		{name: "no separator at all", provider: "google", sealed: "no-separator-here", presented: "no-separator-here"},
		{name: "the provider prefix only", provider: "google", sealed: "google.", presented: "google."},
		{name: "an empty token on both sides", provider: "google", sealed: "google.", presented: "google."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if VerifyState(tt.provider, tt.sealed, tt.presented) {
				t.Errorf("VerifyState(%q, %q, %q) = true, want false", tt.provider, tt.sealed, tt.presented)
			}
		})
	}
}

// The state is bound to the provider that minted it, so a flow started for GitHub
// cannot be finished at Google's callback. Without the binding, one captured state
// is a valid CSRF bypass for every provider this service offers.
func TestVerifyStateRejectsAStateMintedForAnotherProvider(t *testing.T) {
	t.Parallel()

	sealed, err := NewState("github")
	if err != nil {
		t.Fatalf("NewState: %v", err)
	}

	if VerifyState("google", sealed, sealed) {
		t.Error("a github state verified at the google callback")
	}
}

// The provider comes from the URL, so it is caller-controlled. Case matters here:
// these are the exact strings in the registry and the database enum, and
// case-folding a provider name is how "Google" and "google" become two accounts.
func TestVerifyStateMatchesTheProviderExactly(t *testing.T) {
	t.Parallel()

	sealed, err := NewState("google")
	if err != nil {
		t.Fatalf("NewState: %v", err)
	}

	for _, provider := range []string{"Google", "GOOGLE", "goo gle", "", "google "} {
		if VerifyState(provider, sealed, sealed) {
			t.Errorf("VerifyState accepted the provider %q", provider)
		}
	}
}

// The separator must be the FIRST one, and everything after it is the token. A
// provider name containing a dot is not a thing here, but a lenient split would
// turn "google.a.b" into provider "google" and token "a.b" without anyone noticing.
func TestVerifyStateSplitsOnTheFirstSeparatorOnly(t *testing.T) {
	t.Parallel()

	if VerifyState("google", "google.x.y", "google.x.y") {
		t.Error("a state with two separators verified")
	}
}

// NewState must not depend on a clock: the TTL is the cookie's Max-Age, set by the
// handler from a constant. This pins that the function is a pure entropy source.
func TestNewStateTakesNoArgumentsBeyondTheProvider(t *testing.T) {
	t.Parallel()

	// The compile-time assertion is the test. If NewState ever grows a clock or a
	// store argument, this call site stops compiling and the failure is at the
	// build rather than in a test that has to be written to catch it.
	var newState func(string) (string, error) = NewState
	if _, err := newState("google"); err != nil {
		t.Fatalf("NewState: %v", err)
	}
}

// The authorize URL is what a browser is handed, and every one of its parameters
// is load-bearing: without `state` the flow has no CSRF defence, and without a
// `redirect_uri` that matches the callback exactly the provider refuses.
func TestProviderAuthCodeURLCarriesTheRequiredParameters(t *testing.T) {
	t.Parallel()

	p := Google()
	p.ClientID = "client-id"
	redirect := "https://identity.cafaye.com/v1/auth/oauth/google/callback"

	parsed, err := url.Parse(p.AuthCodeURL("the-state", redirect))
	if err != nil {
		t.Fatalf("parsing the authorize URL: %v", err)
	}

	if parsed.Scheme != "https" || parsed.Host != "accounts.google.com" {
		t.Errorf("the authorize URL points at %s://%s, want Google's", parsed.Scheme, parsed.Host)
	}

	query := parsed.Query()
	for name, want := range map[string]string{
		"client_id":     "client-id",
		"redirect_uri":  redirect,
		"response_type": "code",
		"scope":         strings.Join(p.Scopes, " "),
		"state":         "the-state",
	} {
		if got := query.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

// Google only issues a refresh token on the first consent unless the request asks
// for offline access. Without this parameter the refresh_token column is written
// as NULL forever and the stored credential cannot be renewed — which looks like
// working software right up until the access token expires an hour later.
func TestGoogleAsksForOfflineAccess(t *testing.T) {
	t.Parallel()

	query, err := url.Parse(Google().AuthCodeURL("s", "https://example.test/cb"))
	if err != nil {
		t.Fatalf("parsing the authorize URL: %v", err)
	}
	if got := query.Query().Get("access_type"); got != "offline" {
		t.Errorf("access_type = %q, want offline", got)
	}
}

// GitHub has no such switch, and sending one is harmless but inventing per-provider
// behaviour that no provider documents is how a config ends up wrong. What matters
// is that the scopes are the ones the identity endpoints actually need.
func TestProviderScopesAreTheOnesTheIdentityEndpointsNeed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		provider Provider
		want     []string
	}{
		{provider: Google(), want: []string{"openid", "email", "profile"}},
		// read:user for /user, user:email for /user/emails — without the second,
		// a GitHub account with a private email address cannot be identified at all
		// and this service would have no address to create a user with.
		{provider: GitHub(), want: []string{"read:user", "user:email"}},
	}

	for _, tt := range tests {
		t.Run(tt.provider.Name, func(t *testing.T) {
			t.Parallel()

			if strings.Join(tt.provider.Scopes, " ") != strings.Join(tt.want, " ") {
				t.Errorf("scopes = %v, want %v", tt.provider.Scopes, tt.want)
			}
		})
	}
}
