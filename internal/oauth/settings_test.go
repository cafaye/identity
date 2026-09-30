package oauth

import (
	"encoding/base64"
	"errors"
	"testing"
)

// Configuration is validated at startup or the process refuses to run. That is
// AGENTS.md's rule and it is load-bearing here for a specific reason: a missing
// client secret does not fail a sign-in, it makes "Continue with Google" redirect
// to Google, get refused, and return an error a user sees as the platform being
// broken. Failing the deploy turns that into a log line.

func TestSettingsValidateAcceptsAbsentOAuth(t *testing.T) {
	t.Parallel()

	// Nothing set at all. This is the shipped default and it must not be an error:
	// the OAuth routes are simply not mounted, and /v1 keeps working.
	var s Settings
	if err := s.Validate(); err != nil {
		t.Errorf("Validate on the zero Settings = %v, want nil", err)
	}
	if s.Enabled() {
		t.Error("Enabled on the zero Settings, want false")
	}
}

// The dangerous case is a provider with half its credentials. Falling back to
// "provider disabled" would hide a missing secret behind a 404 that looks exactly
// like a typo in the URL.
func TestSettingsValidateRejectsAHalfConfiguredProvider(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		s    Settings
	}{
		{
			name: "google without a secret",
			s: Settings{
				RedirectBaseURL: "https://identity.cafaye.com",
				EncryptionKey:   testKeyBase64(1),
				Google:          ProviderSettings{ClientID: "id"},
			},
		},
		{
			name: "github without an id",
			s: Settings{
				RedirectBaseURL: "https://identity.cafaye.com",
				EncryptionKey:   testKeyBase64(2),
				GitHub:          ProviderSettings{ClientSecret: "secret"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := tt.s.Validate(); !errors.Is(err, ErrIncompleteProvider) {
				t.Errorf("Validate = %v, want ErrIncompleteProvider", err)
			}
		})
	}
}

// A configured provider without a base URL cannot build a callback, and one
// without a key cannot store a token. Both are startup errors rather than a
// runtime surprise on the first successful login.
func TestSettingsValidateRejectsAProviderMissingItsSharedSettings(t *testing.T) {
	t.Parallel()

	google := ProviderSettings{ClientID: "id", ClientSecret: "secret"}

	tests := []struct {
		name string
		s    Settings
	}{
		{name: "no redirect base url", s: Settings{EncryptionKey: testKeyBase64(1), Google: google}},
		{name: "no encryption key", s: Settings{RedirectBaseURL: "https://identity.cafaye.com", Google: google}},
		{name: "neither", s: Settings{Google: google}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := tt.s.Validate(); !errors.Is(err, ErrIncompleteSettings) {
				t.Errorf("Validate = %v, want ErrIncompleteSettings", err)
			}
		})
	}
}

// A key that is present but unusable is the same class of mistake: the operator
// believes tokens are encrypted and they are not.
func TestSettingsValidateRejectsABadEncryptionKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		key  string
	}{
		{name: "not base64", key: "not base64 at all"},
		{name: "base64 of the wrong length", key: testKeyBase64(3)[:40]},
		{name: "a passphrase rather than a key", key: "correct horse battery staple"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := Settings{RedirectBaseURL: "https://identity.cafaye.com", EncryptionKey: tt.key}
			if err := s.Validate(); !errors.Is(err, ErrInvalidEncKey) {
				t.Errorf("Validate = %v, want ErrInvalidEncKey", err)
			}
		})
	}
}

// The key is validated even when no provider is configured, because "set but
// wrong" is a mistake worth failing on regardless of whether anything reads it
// today. It is the deployer who is told, while they still care.
func TestSettingsValidateChecksTheKeyWithoutAnyProvider(t *testing.T) {
	t.Parallel()

	s := Settings{EncryptionKey: "not a key"}
	if err := s.Validate(); !errors.Is(err, ErrInvalidEncKey) {
		t.Errorf("Validate = %v, want ErrInvalidEncKey", err)
	}
}

func TestSettingsValidateRejectsABadRedirectBase(t *testing.T) {
	t.Parallel()

	for _, base := range []string{
		"identity.cafaye.com",
		"ftp://identity.cafaye.com",
		"https://",
		"https://identity.cafaye.com?next=/v1",
		"https://identity.cafaye.com#frag",
	} {
		t.Run(base, func(t *testing.T) {
			t.Parallel()

			s := Settings{RedirectBaseURL: base}
			if err := s.Validate(); !errors.Is(err, ErrInvalidRedirectBaseURL) {
				t.Errorf("Validate(%q) = %v, want ErrInvalidRedirectBaseURL", base, err)
			}
		})
	}
}

func TestSettingsValidateAcceptsAWorkingConfiguration(t *testing.T) {
	t.Parallel()

	s := Settings{
		RedirectBaseURL: "https://identity.cafaye.com",
		EncryptionKey:   testKeyBase64(1),
		Google:          ProviderSettings{ClientID: "id", ClientSecret: "secret"},
		GitHub:          ProviderSettings{ClientID: "id2", ClientSecret: "secret2"},
	}

	if err := s.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !s.Enabled() {
		t.Error("Enabled = false with two configured providers")
	}

	providers := s.Providers()
	if len(providers) != 2 {
		t.Fatalf("Providers() returned %d, want 2", len(providers))
	}
	// Every configured provider carries its credentials and this service's
	// endpoints, and nothing else is included.
	for _, p := range providers {
		if p.ClientID == "" || p.ClientSecret == "" {
			t.Errorf("provider %q has no credentials", p.Name)
		}
		if p.AuthorizeURL == "" || p.TokenURL == "" || p.UserInfoURL == "" {
			t.Errorf("provider %q has an incomplete endpoint set: %+v", p.Name, p)
		}
	}
	if providers[0].Name != ProviderGoogle || providers[1].Name != ProviderGitHub {
		t.Errorf("Providers() = %q, %q; want a stable order", providers[0].Name, providers[1].Name)
	}
}

// A base URL with a trailing slash must produce one callback URL, not two with a
// double slash in the middle — the registered redirect_uri has to byte-match.
func TestProviderRedirectURIIsStable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		base string
		want string
	}{
		{base: "https://identity.cafaye.com", want: "https://identity.cafaye.com/v1/auth/oauth/google/callback"},
		{base: "https://identity.cafaye.com/", want: "https://identity.cafaye.com/v1/auth/oauth/google/callback"},
		// A base behind a path prefix is a legitimate deployment shape.
		{base: "https://example.test/identity", want: "https://example.test/identity/v1/auth/oauth/google/callback"},
	}

	for _, tt := range tests {
		t.Run(tt.base, func(t *testing.T) {
			t.Parallel()

			if got := Google().RedirectURI(tt.base); got != tt.want {
				t.Errorf("RedirectURI(%q) = %q, want %q", tt.base, got, tt.want)
			}
		})
	}
}

// Every configured name has to be one the enum accepts, or the insert fails at
// runtime rather than at startup.
func TestConfiguredProvidersAreAllKnown(t *testing.T) {
	t.Parallel()

	s := Settings{
		RedirectBaseURL: "https://identity.cafaye.com",
		EncryptionKey:   testKeyBase64(1),
		Google:          ProviderSettings{ClientID: "id", ClientSecret: "secret"},
		GitHub:          ProviderSettings{ClientID: "id2", ClientSecret: "secret2"},
	}

	for _, p := range s.Providers() {
		found := false
		for _, known := range knownProviders {
			if p.Name == known {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("provider %q is not in knownProviders %v", p.Name, knownProviders)
		}
	}
}

// An unconfigured provider must be indistinguishable from one that does not
// exist: same error, so an unauthenticated caller cannot enumerate what this
// deployment has credentials for.
func TestRegistryLookupDoesNotDistinguishUnconfiguredFromUnknown(t *testing.T) {
	t.Parallel()

	configured := Google()
	configured.ClientID = "id"
	configured.ClientSecret = "secret"

	registry, err := NewRegistry("https://identity.cafaye.com", configured)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	_, googleErr := registry.Lookup(ProviderGoogle)
	if googleErr != nil {
		t.Fatalf("Lookup(%q) = %v, want the configured provider", ProviderGoogle, googleErr)
	}

	for _, name := range []string{ProviderGitHub, "apple", "", "GOOGLE", "../google"} {
		_, err := registry.Lookup(name)
		if !errors.Is(err, ErrUnknownProvider) {
			t.Errorf("Lookup(%q) = %v, want ErrUnknownProvider", name, err)
		}
	}
}

func TestNewRegistryRejectsABadBase(t *testing.T) {
	t.Parallel()

	if _, err := NewRegistry("nope", Google()); !errors.Is(err, ErrInvalidRedirectBaseURL) {
		t.Errorf("NewRegistry = %v, want ErrInvalidRedirectBaseURL", err)
	}
}

// A provider with no credentials is dropped rather than stored, which is what
// makes Empty the right thing for the caller to branch on.
func TestNewRegistryDropsUnconfiguredProviders(t *testing.T) {
	t.Parallel()

	google := Google()
	google.ClientID = "id"
	google.ClientSecret = "secret"

	registry, err := NewRegistry("https://identity.cafaye.com", google, GitHub())
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	if got := registry.Names(); len(got) != 1 || got[0] != ProviderGoogle {
		t.Errorf("Names() = %v, want [google]", got)
	}
	if registry.Empty() {
		t.Error("Empty() = true with one configured provider")
	}
}

func TestEmptyRegistryIsEmpty(t *testing.T) {
	t.Parallel()

	registry, err := NewRegistry("https://identity.cafaye.com")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if !registry.Empty() {
		t.Error("Empty() = false with no providers")
	}
	if got := registry.Names(); len(got) != 0 {
		t.Errorf("Names() = %v, want empty", got)
	}
}

// testKeyBase64 encodes n as a distinct 32-byte key in the form the settings take,
// which is standard base64 — what `head -c 32 /dev/urandom | base64` prints.
func testKeyBase64(n byte) string {
	return base64.StdEncoding.EncodeToString(testKey(n))
}
