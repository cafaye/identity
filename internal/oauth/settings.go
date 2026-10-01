package oauth

import (
	"encoding/base64"
	"errors"
	"fmt"
)

// ErrIncompleteSettings means at least one provider is configured but the
// settings every provider shares — the public base URL and the encryption key —
// are not.
//
// It is deliberately distinct from ErrIncompleteProvider: that one says "you gave
// me half of this provider's credentials", this one says "this provider needs two
// things you did not set". An operator reading the first will go looking for a
// secret variable; an operator reading the second will go looking for a base URL,
// and sending them to the same message sends them to the wrong place.
var ErrIncompleteSettings = errors.New("oauth settings are incomplete")

// ProviderSettings is one provider's client credentials from the environment.
type ProviderSettings struct {
	ClientID     string
	ClientSecret string
}

// configured reports whether both halves are present. A caller must have run
// Validate before trusting a false here to mean "leave it out".
func (p ProviderSettings) configured() bool {
	return p.ClientID != "" && p.ClientSecret != ""
}

// halfConfigured reports whether exactly one half is present, which is always a
// mistake and never an intention.
func (p ProviderSettings) halfConfigured() bool {
	return (p.ClientID == "") != (p.ClientSecret == "")
}

// Settings is the OAuth configuration as the environment states it, before
// anything has been built from it.
//
// It lives in this package rather than in internal/config so that the rules about
// which combinations of these values make sense stay with the code that consumes
// them. When the surface mounts, internal/config reads the environment into one of
// these and calls Validate; it does not know what a client secret is.
//
// THAT IS THE INTENDED SHAPE AND NOT THE CURRENT ONE. Nothing constructs a
// Settings today: there is no `OAUTH_REDIRECT_BASE_URL`, no `OAUTH_ENCRYPTION_KEY`
// and no per-provider client id or secret in internal/config, so Validate is
// exercised only by its own tests. A deployment cannot turn social login on,
// because there is nothing to turn it on with. This comment used to say
// internal/config reads the environment into a Settings, and it did not — a
// reader checking would have found no `OAUTH_` string in that package at all,
// which is the same class of defect as a README describing an endpoint that
// answers 404. See README.md's "Social login is not built".
type Settings struct {
	// RedirectBaseURL is this service's public base URL. Callback URLs are built
	// from it and from nothing else — never from a Host header.
	RedirectBaseURL string
	// EncryptionKey is standard base64 of 32 bytes, which is what
	// `head -c 32 /dev/urandom | base64` prints.
	EncryptionKey string
	Google        ProviderSettings
	GitHub        ProviderSettings
}

// Validate reports whether these settings can be used to serve sign-in.
//
// The rule throughout is AGENTS.md's: a variable that is absent is a supported
// state, and a variable that is present but wrong is an error. So an empty
// Settings is fine, and so is a set base URL with no providers; a key that does
// not decode is never fine.
func (s Settings) Validate() error {
	for _, p := range []ProviderSettings{s.Google, s.GitHub} {
		if p.halfConfigured() {
			return fmt.Errorf("%w: set both the client id and the client secret, or neither", ErrIncompleteProvider)
		}
	}

	// Checked whenever present, independently of whether anything reads it: a key
	// that is wrong today is wrong the day a provider is added, and the deployer
	// is the only person who can fix it.
	if _, err := s.Key(); err != nil {
		return err
	}

	if s.RedirectBaseURL != "" {
		if err := validateRedirectBase(s.RedirectBaseURL); err != nil {
			return err
		}
	}

	if s.Enabled() && s.RedirectBaseURL == "" {
		return fmt.Errorf("%w: a provider is configured, so the redirect base url must be set too", ErrIncompleteSettings)
	}
	if s.Enabled() && s.EncryptionKey == "" {
		return fmt.Errorf("%w: a provider is configured, so the token encryption key must be set too", ErrIncompleteSettings)
	}

	return nil
}

// Key decodes the configured encryption key.
//
// The length is checked here rather than being handed to NewCipher so that the
// operator gets an error naming the environment variable, not an error from deep
// inside AES.
func (s Settings) Key() ([]byte, error) {
	if s.EncryptionKey == "" {
		return nil, nil
	}

	raw, err := base64.StdEncoding.DecodeString(s.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("%w: it is not standard base64: %v", ErrInvalidEncKey, err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("%w: it decodes to %d bytes, want 32", ErrInvalidEncKey, len(raw))
	}
	return raw, nil
}

// Enabled reports whether at least one provider is fully configured. The process
// mounts the OAuth routes only when this is true.
func (s Settings) Enabled() bool {
	return s.Google.configured() || s.GitHub.configured()
}

// Providers returns the fully-configured providers, each carrying this service's
// endpoints and the operator's credentials.
//
// The order is fixed — google, then github — so a startup log line naming them is
// stable between restarts of the same configuration.
func (s Settings) Providers() []Provider {
	definitions := []Provider{Google(), GitHub()}
	credentials := map[string]ProviderSettings{
		ProviderGoogle: s.Google,
		ProviderGitHub: s.GitHub,
	}

	out := make([]Provider, 0, len(definitions))
	for _, definition := range definitions {
		c := credentials[definition.Name]
		if !c.configured() {
			continue
		}
		definition.ClientID = c.ClientID
		definition.ClientSecret = c.ClientSecret
		out = append(out, definition)
	}
	return out
}
