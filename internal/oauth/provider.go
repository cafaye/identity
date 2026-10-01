package oauth

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"golang.org/x/oauth2"
)

// Provider names. These are the two values of the `oauth_provider` enum in
// migrations/00008_connected_accounts.sql, and the two keys the URL would accept
// once the surface is mounted. There is one list of them and it is here.
//
// The OpenAPI mention this comment used to make was false: no document in this
// repository declares a social-login operation, because there is no route for one.
// The migration number was stale for the same kind of reason — the table was
// renumbered from 00005 to 00008 when the accounts packet moved it.
const (
	ProviderGoogle = "google"
	ProviderGitHub = "github"
)

// knownProviders is the closed set, in the order they are logged. An unlisted name
// is a 404 rather than a lookup, so a typo in a URL cannot become a query against
// a provider this service has no client credentials for.
var knownProviders = []string{ProviderGoogle, ProviderGitHub}

// Errors from the registry and from Settings.Validate.
var (
	// ErrUnknownProvider means the name is not one this service offers. It is a
	// 404: an endpoint that does not exist and an endpoint whose resource does not
	// exist are the same answer, and neither reveals which providers are
	// configured on this deployment.
	ErrUnknownProvider = errors.New("unknown oauth provider")

	// ErrIncompleteProvider means a provider has one half of its credentials and
	// not the other. Startup fails on this rather than disabling the provider: a
	// sign-in button that 404s because a secret went missing is a support call
	// that should have been a failed deploy.
	ErrIncompleteProvider = errors.New("oauth provider is half-configured")

	// ErrInvalidRedirectBaseURL means the public base URL this service builds
	// callback URLs from is unusable.
	ErrInvalidRedirectBaseURL = errors.New("invalid oauth redirect base url")
)

// Provider is one configured OAuth 2.0 authorization-code provider.
//
// The endpoints are fields rather than constants because that is what lets a test
// point the whole flow at an httptest server. In production they come from
// Google() and GitHub() and nothing mutates them after startup.
type Provider struct {
	// Name is the enum value: "google" or "github".
	Name string
	// ClientID and ClientSecret are the redirect pair registered with the provider.
	ClientID     string
	ClientSecret string
	// Scopes are space-separated on the wire.
	Scopes []string
	// AuthorizeURL is where the browser is sent to obtain a code.
	AuthorizeURL string
	// TokenURL exchanges that code for a token.
	TokenURL string
	// UserInfoURL is called with the access token to learn who the user is.
	UserInfoURL string
	// EmailsURL is GitHub-only: /user returns a null email for an account whose
	// address is private, and /user/emails is the documented way to get it.
	// Empty for providers that always return the address on the identity call.
	EmailsURL string
	// ExtraAuthorizeOptions are provider-specific parameters appended to every
	// authorize URL. There is exactly one, and why it exists is in Google().
	ExtraAuthorizeOptions []oauth2.AuthCodeOption
}

// Google returns the provider definition with this service's endpoint choices.
//
// The endpoints are pinned rather than discovered from
// https://accounts.google.com/.well-known/openid-configuration: identity is an
// OIDC *provider*, and a service that hard-codes its own RPs to what it resolves
// at boot is a service whose behaviour depends on what a third party served it
// that morning. Apple's and Microsoft's endpoints arrive the same way when those
// packets land.
func Google() Provider {
	return Provider{
		Name:         ProviderGoogle,
		Scopes:       []string{"openid", "email", "profile"},
		AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:     "https://oauth2.googleapis.com/token",
		UserInfoURL:  "https://openidconnect.googleapis.com/v1/userinfo",
		// Google issues a refresh token only on the FIRST consent unless the
		// request asks for offline access. Without this, refresh_token is NULL on
		// every account forever, and the stored credential dies an hour later with
		// nothing to renew it.
		ExtraAuthorizeOptions: []oauth2.AuthCodeOption{oauth2.AccessTypeOffline},
	}
}

// GitHub returns the provider definition with this service's endpoint choices.
func GitHub() Provider {
	return Provider{
		Name:         ProviderGitHub,
		Scopes:       []string{"read:user", "user:email"},
		AuthorizeURL: "https://github.com/login/oauth/authorize",
		TokenURL:     "https://github.com/login/oauth/access_token",
		UserInfoURL:  "https://api.github.com/user",
		EmailsURL:    "https://api.github.com/user/emails?per_page=100",
	}
}

// AuthCodeURL builds the URL the browser is redirected to.
//
// Every parameter here is required by the flow, and two of them are the CSRF
// defence: `state` goes into a cookie this service reads back, and
// `redirect_uri` must byte-match the callback URL registered with the provider or
// the exchange is refused. prompt/response_type/scope are the provider's own
// requirements.
func (p Provider) AuthCodeURL(state, redirectURI string) string {
	conf := p.oauth2Config()
	conf.RedirectURL = redirectURI

	// The URL is built by golang.org/x/oauth2 rather than assembled here, so the
	// authorize step and the exchange step are guaranteed to agree about the
	// client, the scopes and the endpoint. Two implementations of "what the
	// provider expects" in one service is a bug waiting for the one provider
	// whose authorize parameters differ from its token parameters.
	return conf.AuthCodeURL(state, p.ExtraAuthorizeOptions...)
}

// oauth2Config is the provider expressed as an x/oauth2 configuration. It is
// unexported because callers outside this package have no business constructing
// one: they should call AuthCodeURL or Client.Exchange, both of which set the
// fields that matter.
func (p Provider) oauth2Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Scopes:       p.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  p.AuthorizeURL,
			TokenURL: p.TokenURL,
		},
	}
}

// RedirectURI is the callback URL this provider must send the browser back to.
//
// It is derived from the configured base rather than taken from the request: a
// Host header an attacker chose must not become part of an OAuth redirect_uri, or
// the code is delivered to wherever they asked.
//
// The path it appends is not served by anything today, and the value is the same
// one the exchange sends: Client.Exchange calls this with the same base, so the
// authorize step and the token step cannot disagree about it. When the surface
// mounts, the route it names has to be this one — a callback at any other path is
// a second redirect_uri, and one that is not the configured one is refused by the
// provider without saying which of the two was wrong.
func (p Provider) RedirectURI(baseURL string) string {
	return strings.TrimSuffix(baseURL, "/") + "/v1/auth/oauth/" + p.Name + "/callback"
}

// Registry is the set of providers this deployment will accept, keyed by name.
//
// It holds only providers that are fully configured. A name that is absent is a
// 404 whether it is nonsense ("apple") or a real provider this deployment has no
// credentials for, and that is on purpose: an unauthenticated endpoint that
// distinguishes those two is a way to enumerate a deployment's configuration.
type Registry struct {
	byName map[string]Provider
	// redirectBase is the public base URL every callback is built from.
	redirectBase string
}

// NewRegistry returns a Registry over providers, built from baseURL.
//
// Providers with no credentials are dropped rather than stored as broken entries.
// The returned error is only about baseURL, which every caller needs.
//
// Unwired: no route constructs a Registry today, and Empty is the flag the
// not-yet-written mount would consult to decide whether to serve social login at
// all. It is the honest shape for the decision — absent rather than 404-per-provider
// — and it is untested against a real process until something mounts it.
func NewRegistry(baseURL string, providers ...Provider) (*Registry, error) {
	if err := validateRedirectBase(baseURL); err != nil {
		return nil, err
	}

	byName := make(map[string]Provider, len(providers))
	for _, p := range providers {
		if p.ClientID == "" || p.ClientSecret == "" {
			continue
		}
		byName[p.Name] = p
	}

	return &Registry{byName: byName, redirectBase: baseURL}, nil
}

// Lookup returns the provider with this name.
//
// A name that is well-formed but not configured is the same miss as a name that
// does not exist: ErrUnknownProvider either way.
func (r *Registry) Lookup(name string) (Provider, error) {
	p, ok := r.byName[name]
	if !ok {
		return Provider{}, fmt.Errorf("%w: %q", ErrUnknownProvider, name)
	}
	return p, nil
}

// RedirectBase is the configured public base URL.
func (r *Registry) RedirectBase() string { return r.redirectBase }

// Names returns the configured provider names, sorted. It exists for a startup log
// line: an operator who cannot see which providers came up has no way to tell a
// missing secret from a broken route.
func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.byName))
	for name := range r.byName {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Empty reports whether no provider is configured. The process mounts the OAuth
// routes only when this is false, so a deployment with no credentials serves a
// clean 404 rather than a redirect to a provider it cannot authenticate with.
func (r *Registry) Empty() bool { return len(r.byName) == 0 }

// validateRedirectBase rejects a base URL this service cannot build a callback
// from.
//
// The scheme has to be http or https because a callback on any other scheme does
// not come back to a browser. Query and fragment are refused because the callback
// is appended as a path: a base with "?x=1" would produce a URL whose query
// absorbs the path, and the provider would refuse the registration match.
func validateRedirectBase(baseURL string) error {
	if baseURL == "" {
		return fmt.Errorf("%w: it is empty", ErrInvalidRedirectBaseURL)
	}

	parsed, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRedirectBaseURL, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%w: scheme %q is not http or https", ErrInvalidRedirectBaseURL, parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%w: it has no host", ErrInvalidRedirectBaseURL)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%w: it carries a query or fragment", ErrInvalidRedirectBaseURL)
	}
	return nil
}
