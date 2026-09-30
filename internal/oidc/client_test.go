package oidc

import (
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// The client aggregate: the credential a product presents, and the three lists
// that decide what it is allowed to do with one.
//
// Everything asserted here is a security property, not a formatting choice. A
// client that can be talked into a redirect URI outside its registration turns
// this service into an open redirector for every product on it; a client id that
// can be guessed turns the token endpoint into an oracle; a plaintext secret in
// the row turns one database dump into a credential for every product.

func TestNewClientCredentialsAreRandomAndUnguessable(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool, 32)
	for i := 0; i < 32; i++ {
		clientID, secret, err := NewClientCredentials()
		if err != nil {
			t.Fatalf("NewClientCredentials: %v", err)
		}
		if seen[clientID] {
			t.Fatalf("client id %q came up twice in 32 draws", clientID)
		}
		seen[clientID] = true

		// The id travels in a form body and an Authorization header, so it has to
		// be URL-safe with no escaping, and it has to be long enough that guessing
		// is not a plan. 32 bytes is the same budget as a session token, for the
		// same reason.
		if clientID != base64.RawURLEncoding.EncodeToString(mustDecode(t, clientID)) {
			t.Errorf("client id %q is not base64url", clientID)
		}
		if len(mustDecode(t, clientID)) != clientIDBytes {
			t.Errorf("client id carries %d bytes, want %d", len(mustDecode(t, clientID)), clientIDBytes)
		}
		if secret == clientID {
			t.Error("the client secret equals the client id; one leaked value would then be both")
		}
	}
}

// The secret is stored as a digest and never as itself.
//
// SHA-256 rather than argon2id, and the reason is the one internal/sessions
// already wrote down for its token column: argon2id exists to make GUESSING
// expensive, and a 256-bit random value has no guessable structure to slow down.
// A slow hash here would cost tens of milliseconds on every token request and
// buy nothing. The invariant that matters on both columns is the same one — the
// presented value is never stored, so a dump of this table yields no credential.
func TestSecretDigestIsNotTheSecret(t *testing.T) {
	t.Parallel()

	_, secret, err := NewClientCredentials()
	if err != nil {
		t.Fatalf("NewClientCredentials: %v", err)
	}

	digest := SecretDigest(secret)
	if digest == secret {
		t.Fatal("SecretDigest returned the secret itself")
	}
	if len(digest) != 64 {
		t.Errorf("the digest is %d characters, want 64 (lower-case hex SHA-256)", len(digest))
	}
	if strings.ToLower(digest) != digest {
		t.Errorf("the digest %q is not lower case; the column is compared with equality", digest)
	}
	// Stable, because the token endpoint looks a client up by digest equality.
	if SecretDigest(secret) != digest {
		t.Error("SecretDigest is not stable for one secret")
	}
	if SecretDigest(secret+"x") == digest {
		t.Error("two different secrets produced one digest")
	}
}

func TestValidateRedirectURIs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give []string
		want []string
		// wantCode is the FieldError code the caller will put in errors[].
		wantCode string
	}{
		{
			name: "one https origin",
			give: []string{"https://app.example.com/cb"},
			want: []string{"https://app.example.com/cb"},
		},
		{
			name: "several, deduplicated and sorted",
			give: []string{"https://b.example.com/cb", "https://a.example.com/cb", "https://b.example.com/cb"},
			want: []string{"https://a.example.com/cb", "https://b.example.com/cb"},
		},
		{
			// The loopback carve-out is what lets a product develop against a
			// local parlor without the registration accepting any http origin at
			// all. The library would allow any registered http URI for a
			// confidential client; refusing at registration is the earlier and
			// cheaper place to say no.
			name: "loopback http is allowed",
			give: []string{"http://localhost:3000/cb", "http://127.0.0.1:8080/cb"},
			want: []string{"http://127.0.0.1:8080/cb", "http://localhost:3000/cb"},
		},
		{name: "none at all", give: nil, wantCode: CodeRequired},
		{name: "plain http is not", give: []string{"http://app.example.com/cb"}, wantCode: CodeInvalidFormat},
		{name: "a bare host is not a redirect target", give: []string{"app.example.com/cb"}, wantCode: CodeInvalidFormat},
		{name: "a custom scheme is not", give: []string{"myapp://cb"}, wantCode: CodeInvalidFormat},
		{
			// A fragment cannot survive the round trip: the authorization response
			// is appended to the query string, so a registered fragment would end
			// up somewhere the client never reads it.
			name: "a fragment is not", give: []string{"https://app.example.com/cb#done"}, wantCode: CodeInvalidFormat,
		},
		{
			// A wildcard would make the exact-match check in ValidateAuthReqRedirectURI
			// meaningless, which is the whole of the open-redirect defence.
			name: "a wildcard is not", give: []string{"https://*.example.com/cb"}, wantCode: CodeInvalidFormat,
		},
		{name: "empty", give: []string{""}, wantCode: CodeInvalidFormat},
		{name: "more than the maximum", give: manyRedirectURIs(MaxRedirectURIs + 1), wantCode: CodeTooMany},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ValidateRedirectURIs(tt.give)
			if tt.wantCode != "" {
				assertFieldError(t, err, "redirect_uris", tt.wantCode)
				return
			}
			if err != nil {
				t.Fatalf("ValidateRedirectURIs(%v) = %v, want it accepted", tt.give, err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("ValidateRedirectURIs(%v) = %v, want %v", tt.give, got, tt.want)
			}
		})
	}
}

// The grant types this provider honours, and the refusal of everything else.
//
// `authorization_code` is the only entry because it is the only flow this
// service implements. `refresh_token` is absent because there is no refresh
// token store, and `client_credentials` and the JWT profile because there is no
// service identity to authenticate as — a package that advertised them would
// have products configure a grant that fails at the token endpoint.
func TestValidateGrantTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		give     []string
		want     []string
		wantCode string
	}{
		{name: "authorization_code alone", give: []string{GrantAuthorizationCode}, want: []string{GrantAuthorizationCode}},
		{name: "deduplicated", give: []string{GrantAuthorizationCode, GrantAuthorizationCode}, want: []string{GrantAuthorizationCode}},
		{name: "a refresh token grant", give: []string{GrantAuthorizationCode, GrantRefreshToken}, wantCode: CodeUnsupported},
		{name: "client credentials", give: []string{GrantClientCredentials}, wantCode: CodeUnsupported},
		{name: "nothing at all", give: nil, wantCode: CodeRequired},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ValidateGrantTypes(tt.give)
			if tt.wantCode != "" {
				assertFieldError(t, err, "grant_types", tt.wantCode)
				return
			}
			if err != nil {
				t.Fatalf("ValidateGrantTypes(%v) = %v, want it accepted", tt.give, err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("ValidateGrantTypes(%v) = %v, want %v", tt.give, got, tt.want)
			}
		})
	}
}

// A registration that cannot ask for openid is a registration whose tokens carry
// no identity at all, so it is refused at the door rather than producing a
// credential that authenticates nobody.
func TestValidateRegistrationScopesRequiresOpenID(t *testing.T) {
	t.Parallel()

	_, err := ValidateRegistrationScopes([]string{"email"})
	assertFieldError(t, err, "scopes", CodeOpenIDRequired)

	got, err := ValidateRegistrationScopes([]string{"accounts", "openid", "phone"})
	if err != nil {
		t.Fatalf("ValidateRegistrationScopes = %v, want the supported two accepted", err)
	}
	if !slices.Equal(got, []string{"accounts", "openid"}) {
		t.Errorf("scopes = %v, want the supported two, sorted", got)
	}
}

// IsActive is the one question every lookup asks, and the answer for a revoked
// client is false rather than "the row is gone": the row stays so an audit can
// see the credential existed, and revoked_at is what makes the difference
// readable.
func TestRevokedClientIsNotActive(t *testing.T) {
	t.Parallel()

	live := Client{}
	if !live.IsActive() {
		t.Error("a client with no revoked_at is not active; that is backwards")
	}

	at := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	revoked := Client{RevokedAt: &at}
	if revoked.IsActive() {
		t.Error("a revoked client reports itself active")
	}
}

func manyRedirectURIs(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, "https://app"+string(rune('a'+i%26))+itoa(i)+".example.com/cb")
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decoding %q: %v", s, err)
	}
	return raw
}

func assertFieldError(t *testing.T, err error, field, code string) {
	t.Helper()

	if err == nil {
		t.Fatalf("got a nil error, want a field error on %q with code %q", field, code)
	}
	var fieldErr *FieldError
	if !errors.As(err, &fieldErr) {
		t.Fatalf("error %v is not a *FieldError", err)
	}
	if fieldErr.Field != field || fieldErr.Code != code {
		t.Errorf("field error = %q/%q, want %q/%q", fieldErr.Field, fieldErr.Code, field, code)
	}
}
