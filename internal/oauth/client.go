package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/cafaye/identity/internal/users"
)

// DefaultProviderTimeout bounds every call this service makes to a provider.
//
// It is a property of the client rather than of the request, because the caller's
// deadline is the browser's: a user who has walked away is still holding a
// connection, and an unbounded call to a third party is how one slow provider
// turns into a saturated identity service.
const DefaultProviderTimeout = 10 * time.Second

// maxIdentityBytes caps an identity response.
//
// Google's userinfo is about 200 bytes and GitHub's /user about 150, so this is a
// thousand times more than any real answer. It is a statement about what the
// response is rather than a race against a slow link, and a body past it truncates
// mid-document and fails to parse rather than being read into memory.
const maxIdentityBytes = 256 << 10

// Client errors, in the three groups a caller has to tell apart: the provider said
// no, the provider could not be reached, and the provider said yes to something this
// service cannot use.
//
// NOT MAPPED TO A STATUS ANYWHERE, because the social-login surface is not mounted.
// A comment here used to point at internal/httpapi/oauth.go, which does not exist
// and never has — a dangling pointer to the handler that would render these. When
// the surface mounts, the mapping is ErrCodeRefused and ErrNoEmail to a refusal the
// person at the browser sees, and ErrProviderUnavailable to a 5xx whose cause goes
// to the log. See README.md's "Social login is not built" for why that is a packet
// of its own rather than a line each.
var (
	// ErrCodeRefused means the provider rejected the authorization code: it was
	// never issued, it has already been used, or the person declined consent. It is
	// the caller's problem, not an outage, and it is deliberately a different value
	// from ErrProviderUnavailable so the two get different status codes.
	ErrCodeRefused = errors.New("the oauth provider refused the authorization code")

	// ErrProviderUnavailable means the provider could not be reached, answered 5xx,
	// or answered something this service cannot read. It is never rendered to a
	// caller beyond "the provider is unavailable" — the cause goes to the log.
	ErrProviderUnavailable = errors.New("the oauth provider is unavailable")

	// ErrNoEmail means the provider returned no address this service could create
	// an account from. Creating a user without one is not an option on this schema,
	// and substituting a placeholder would put an address the person does not own
	// into `users.email`.
	ErrNoEmail = errors.New("the oauth provider returned no usable email address")
)

// Tokens is what a provider issued for one authorization code.
type Tokens struct {
	AccessToken string
	// RefreshToken is empty when the provider issued none. That is GitHub's normal
	// case, so an empty value here is not an error.
	RefreshToken string
	// ExpiresAt is nil when the token does not expire. It is the provider token's
	// expiry and has nothing to do with a session's.
	ExpiresAt *time.Time
}

// Identity is what a provider says about the person behind a token.
type Identity struct {
	// ProviderUID is the provider's own stable identifier for the account — not an
	// email, which can be changed at the provider and is not unique across accounts
	// there. This is the value a connected account is keyed on.
	ProviderUID string
	Email       string
	Name        string
}

// Client performs the two calls this service makes to a provider.
//
// It holds no state between calls and caches nothing, so a test drives it with an
// httptest server and production drives it with the provider's real endpoints.
type Client struct {
	http *http.Client
	// redirectBase is the configured public base URL. The Client needs it because
	// the redirect_uri sent with the exchange has to be the one the authorize step
	// offered, and the Provider a caller hands it carries no base.
	redirectBase string
}

// ClientOptions configures a Client.
type ClientOptions struct {
	// HTTPClient overrides the client and its timeout. Nil gets a fresh
	// *http.Client with DefaultProviderTimeout — not a package-level default,
	// because a shared one would be global state that tests race on.
	HTTPClient *http.Client
	// RedirectBaseURL is this service's public base URL, used to rebuild the
	// redirect_uri for the token exchange. It must match the one the authorize
	// step used or the provider refuses the exchange.
	RedirectBaseURL string
}

// NewClient returns a Client for the given options.
func NewClient(opts ClientOptions) *Client {
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: DefaultProviderTimeout}
	}
	return &Client{http: httpClient, redirectBase: opts.RedirectBaseURL}
}

// Exchange trades an authorization code for a token.
//
// The redirect URI is the same one the authorize step offered, and it has to be:
// both providers compare it against the registered value and refuse a mismatch
// without saying which of the two URLs was wrong.
func (c *Client) Exchange(ctx context.Context, p Provider, code string) (Tokens, error) {
	if strings.TrimSpace(code) == "" {
		// Refused before the request rather than after. A callback with no code is
		// cheap for anyone to produce and should cost nothing.
		return Tokens{}, fmt.Errorf("%w: no code was presented", ErrCodeRefused)
	}

	conf := p.oauth2Config()
	conf.RedirectURL = p.RedirectURI(c.redirectBase)

	// The client travels on the context, which is how it reaches the request x/oauth2
	// builds for us.
	ctx = context.WithValue(ctx, oauth2.HTTPClient, c.http)

	token, err := conf.Exchange(ctx, code)
	if err != nil {
		return Tokens{}, providerError("exchanging the authorization code", err)
	}
	if token.AccessToken == "" {
		// A 200 with no token is not a token. Storing the empty string would produce
		// a connected account whose every later provider call is anonymous.
		return Tokens{}, fmt.Errorf("%w: the exchange succeeded with no access token", ErrProviderUnavailable)
	}

	out := Tokens{AccessToken: token.AccessToken, RefreshToken: token.RefreshToken}
	if !token.Expiry.IsZero() {
		expiry := token.Expiry.UTC()
		out.ExpiresAt = &expiry
	}
	return out, nil
}

// Identity asks the provider who the token belongs to.
//
// The address is validated against the same rules a registration is held to, and a
// provider that returns something unusable is refused rather than repaired. The
// alternative — accepting whatever came back and letting `users.email`'s CHECK
// reject it later — moves the failure to a place with no provider context.
func (c *Client) Identity(ctx context.Context, p Provider, tokens Tokens) (Identity, error) {
	if tokens.AccessToken == "" {
		// Not a refusal: there is nothing to present. It is reported as unavailable
		// because from here it is indistinguishable from a credential the provider
		// will not honour, and the caller treats both the same way.
		return Identity{}, fmt.Errorf("%w: there is no access token to present", ErrProviderUnavailable)
	}

	switch p.Name {
	case ProviderGoogle:
		return c.googleIdentity(ctx, p, tokens)
	case ProviderGitHub:
		return c.githubIdentity(ctx, p, tokens)
	default:
		// Unreachable through a Registry, which only holds these two. Returned rather
		// than panicked on: a third provider added to the constructors and not to
		// this switch should be a failure with a status, not a crash.
		return Identity{}, fmt.Errorf("%w: %q has no identity endpoint", ErrUnknownProvider, p.Name)
	}
}

// googleResponse is Google's OpenID Connect userinfo document. Only `sub` and
// `email` matter here; the remaining claims are for an OIDC client, which is a
// later packet.
//
// ## `email_verified` is deliberately absent, and that is a known gap
//
// Google's document carries `email_verified`, and it is not read. For an OIDC
// *client* that is defensible, because the client is verifying a token it was
// issued and the `email` claim inside it was already the subject of an
// authorization the user performed. For a *relying party deciding whether to sign
// somebody in* it is not: `email` alone is a string the account holder can set, and
// this service's `users.email` is unique, so an unverified provider address that
// matched an existing row would be a takeover.
//
// GitHub's path here is already stricter — githubEmail refuses an address that is
// not `verified` — so the two providers are not held to the same bar and the weaker
// one is Google's.
//
// It is left unfixed rather than fixed because nothing calls Identity: the surface
// is unmounted, so the gap is unreachable, and "unreachable" is a weaker state than
// "closed" and this comment is what makes the difference legible. Whoever mounts
// social login must add `EmailVerified bool \`json:"email_verified"\“ here and
// refuse an unverified address the way githubEmail does, BEFORE the value can reach
// a `users.email` lookup. That is the first thing the mounting packet has to do and
// it is recorded here so it cannot be discovered by a customer instead.
type googleResponse struct {
	Subject string `json:"sub"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	// `email_verified` is in the document and is NOT decoded into a field here, on
	// purpose for now: adding the field without the check that uses it would read
	// as though the check existed. See the comment above — it is the first thing the
	// mounting packet does, and it brings the field and the refusal together.
}

func (c *Client) googleIdentity(ctx context.Context, p Provider, tokens Tokens) (Identity, error) {
	var body googleResponse
	if err := c.getJSON(ctx, p.UserInfoURL, tokens.AccessToken, &body); err != nil {
		return Identity{}, err
	}

	// Google's `sub` is the account's stable, non-reassignable identifier. The
	// email can be changed; the sub cannot.
	return identity(body.Subject, body.Email, body.Name)
}

// githubResponse is GitHub's /user. `id` is a number and `email` may be null.
type githubResponse struct {
	ID    int64  `json:"id"`
	Email string `json:"email"`
	Login string `json:"login"`
	Name  string `json:"name"`
}

// githubEmail is one entry of /user/emails.
type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func (c *Client) githubIdentity(ctx context.Context, p Provider, tokens Tokens) (Identity, error) {
	var body githubResponse
	if err := c.getJSON(ctx, p.UserInfoURL, tokens.AccessToken, &body); err != nil {
		return Identity{}, err
	}

	name := body.Name
	if name == "" {
		// The profile name is optional and frequently absent; the login is always
		// there. It is a display name, not an identifier, so this is a convenience
		// and not a decision.
		name = body.Login
	}

	// The identifier is the number rendered as text. The column is text, and "0"
	// and 0 must not become two different keys for the same person.
	uid := ""
	if body.ID > 0 {
		uid = strconv.FormatInt(body.ID, 10)
	}

	email := body.Email
	if email == "" && p.EmailsURL != "" {
		resolved, err := c.githubEmail(ctx, p, tokens)
		if err != nil {
			return Identity{}, err
		}
		email = resolved
	}

	return identity(uid, email, name)
}

// githubEmail resolves the address GitHub left off /user.
//
// It takes the primary verified address when there is one, then any verified
// address, and otherwise refuses. An unverified address is not evidence of
// anything: on GitHub it is set by the account holder, so accepting one would let
// any account claim any address and then sign in as that address's owner.
func (c *Client) githubEmail(ctx context.Context, p Provider, tokens Tokens) (string, error) {
	var emails []githubEmail
	if err := c.getJSON(ctx, p.EmailsURL, tokens.AccessToken, &emails); err != nil {
		return "", err
	}

	fallback := ""
	for _, e := range emails {
		if !e.Verified {
			continue
		}
		if e.Primary {
			return e.Email, nil
		}
		if fallback == "" {
			fallback = e.Email
		}
	}
	if fallback != "" {
		return fallback, nil
	}

	return "", fmt.Errorf("%w: github has no verified address for this account", ErrNoEmail)
}

// identity is the single place a provider's answer becomes an Identity, so the
// validation cannot differ between the two providers.
//
// Both checks live here rather than with the callers because both are what makes
// the resulting row safe: an empty provider_uid collides with every other empty
// one, and an unvalidated address fails later at a `users.email` CHECK with no
// provider context to explain it.
func identity(uid, email, name string) (Identity, error) {
	uid = strings.TrimSpace(uid)
	if uid == "" {
		return Identity{}, fmt.Errorf("%w: the provider returned no account identifier", ErrNoEmail)
	}

	// Normalized through the one function internal/users defines, so "Kaka@Example.com"
	// and "kaka@example.com" are one account here as they are everywhere else.
	normalized := users.NormalizeEmail(email)
	if err := users.ValidateEmail(normalized); err != nil {
		// The address is not echoed: it came from a third party and this error is
		// rendered to whoever is holding the browser.
		return Identity{}, fmt.Errorf("%w: the provider returned an address this service will not store", ErrNoEmail)
	}

	return Identity{ProviderUID: uid, Email: normalized, Name: strings.TrimSpace(name)}, nil
}

// getJSON performs one authorized GET and decodes the body into dst.
//
// Every failure is ErrProviderUnavailable, including a 401. A 401 here means the
// token the token endpoint just issued is not honoured by the identity endpoint,
// which is a provider inconsistency and not anything the person at the browser did
// — so it is an outage, not a refusal.
func (c *Client) getJSON(ctx context.Context, endpoint, accessToken string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("%w: building the request: %v", ErrProviderUnavailable, err)
	}
	// `token` is GitHub's older documented scheme and `Bearer` is what Google
	// documents. Both providers accept Bearer, and only GitHub accepts token, so
	// Bearer is the one that works for both.
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: the provider answered %d", ErrProviderUnavailable, resp.StatusCode)
	}

	if err := json.NewDecoder(io.LimitReader(resp.Body, maxIdentityBytes)).Decode(dst); err != nil {
		return fmt.Errorf("%w: reading the identity response: %v", ErrProviderUnavailable, err)
	}
	return nil
}

// providerError classifies an x/oauth2 failure into one of the two sentinels the
// HTTP layer knows how to answer.
//
// The split is on the status the provider returned: a 4xx from the token endpoint
// is about the code the caller presented and becomes ErrCodeRefused; everything
// else — 5xx, a transport failure, an unparseable body — is the provider's problem
// and becomes ErrProviderUnavailable.
func providerError(what string, err error) error {
	var retrieve *oauth2.RetrieveError
	if errors.As(err, &retrieve) && retrieve.Response != nil {
		status := retrieve.Response.StatusCode
		if status >= 400 && status < 500 {
			return fmt.Errorf("%w: %s was rejected with %d (%s)", ErrCodeRefused, what, status, retrieve.ErrorCode)
		}
		return fmt.Errorf("%w: %s failed with %d", ErrProviderUnavailable, what, status)
	}
	return fmt.Errorf("%w: %s: %v", ErrProviderUnavailable, what, err)
}
