package oauth_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/oauth"
	"github.com/cafaye/identity/internal/platform/oauthtest"
)

// These are the two calls this service makes to a provider, driven end to end
// against an httptest server. The alternatives — a hand-written RoundTripper, or a
// mock of the client's own interface — would both assert that the code does what
// the test assumed; an httptest server asserts it does what the wire says.

const fakeRedirectURI = "https://identity.cafaye.com/v1/auth/oauth/google/callback"

func newTestClient(t *testing.T) *oauth.Client {
	t.Helper()
	return oauth.NewClient(oauth.ClientOptions{RedirectBaseURL: "https://identity.cafaye.com"})
}

// The exchange must present the code together with the same redirect_uri the
// authorize step offered. Google answers redirect_uri_mismatch otherwise, and the
// message names neither URL.
func TestClientExchangeSendsTheCodeAndTheRedirectURI(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t)
	provider := server.Provider(t, oauth.Google())

	tokens, err := newTestClient(t).Exchange(context.Background(), provider, server.Code)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	form := server.LastTokenForm()
	if got := form.Get("code"); got != server.Code {
		t.Errorf("code = %q, want %q", got, server.Code)
	}
	if got := form.Get("redirect_uri"); got != fakeRedirectURI {
		t.Errorf("redirect_uri = %q, want %q", got, fakeRedirectURI)
	}
	if got := form.Get("grant_type"); got != "authorization_code" {
		t.Errorf("grant_type = %q, want authorization_code", got)
	}

	if tokens.AccessToken != server.AccessToken {
		t.Errorf("AccessToken = %q, want %q", tokens.AccessToken, server.AccessToken)
	}
	if tokens.RefreshToken != server.RefreshToken {
		t.Errorf("RefreshToken = %q, want %q", tokens.RefreshToken, server.RefreshToken)
	}
	if tokens.ExpiresAt == nil {
		t.Fatal("ExpiresAt is nil, want the token's one-hour expiry")
	}
	if want := time.Now().Add(time.Hour); !tokens.ExpiresAt.After(want.Add(-time.Minute)) || !tokens.ExpiresAt.Before(want.Add(time.Minute)) {
		t.Errorf("ExpiresAt = %s, want about %s", tokens.ExpiresAt, want)
	}
}

// GitHub issues no expiry by default, and "no expiry" has to be nil rather than
// the zero time: a zero time is a token that expired in the year 1, and the code
// that later refreshes it would treat it as long dead.
func TestClientExchangeWithNoExpiryLeavesExpiresAtNil(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t).WithoutExpiry()

	tokens, err := newTestClient(t).Exchange(context.Background(), server.Provider(t, oauth.GitHub()), server.Code)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tokens.ExpiresAt != nil {
		t.Errorf("ExpiresAt = %v, want nil when the provider issues no expiry", *tokens.ExpiresAt)
	}
}

// A 200 with no access token is not a successful exchange. Accepting it would
// store an empty credential and every later provider call would be unauthenticated,
// with nothing in the logs to say why.
func TestClientExchangeRefusesA200WithNoAccessToken(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t)
	server.AccessToken = "" // the fake answers 200 with an empty access_token

	if _, err := newTestClient(t).Exchange(context.Background(), server.Provider(t, oauth.Google()), server.Code); err == nil {
		t.Error("Exchange accepted a 200 with no access token")
	}
}

// An empty code never reaches the network. The callback can arrive with no `code`
// at all — the user hit back, or the provider sent only an error — and spending a
// request on it is a free amplification of unauthenticated traffic.
func TestClientExchangeRefusesAnEmptyCodeWithoutCallingTheProvider(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t)

	for _, code := range []string{"", "   "} {
		_, err := newTestClient(t).Exchange(context.Background(), server.Provider(t, oauth.Google()), code)
		if !errors.Is(err, oauth.ErrCodeRefused) {
			t.Errorf("Exchange(%q) = %v, want ErrCodeRefused", code, err)
		}
	}
	if calls := server.Calls(); len(calls) != 0 {
		t.Errorf("the provider was called %v for an empty code, want no call at all", calls)
	}
}

// A refused code is the caller's problem and a 502 would be a lie: nothing is
// broken, the code simply was not good. It has to be distinguishable from a
// provider outage, because the two get different status codes and the second is
// worth retrying while the first is not.
func TestClientExchangeMapsAProviderRefusal(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t).FailToken(http.StatusBadRequest)

	_, err := newTestClient(t).Exchange(context.Background(), server.Provider(t, oauth.Google()), "a-code-the-provider-never-issued")
	if !errors.Is(err, oauth.ErrCodeRefused) {
		t.Errorf("Exchange = %v, want ErrCodeRefused", err)
	}
	if errors.Is(err, oauth.ErrProviderUnavailable) {
		t.Error("a refused code was also reported as an unavailable provider")
	}
}

// A 5xx from the token endpoint is the provider's problem, not the caller's, and
// it is the case that becomes a 502. The cause goes to the log; the response says
// only that the provider could not be reached.
func TestClientExchangeMapsAProviderOutage(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()

			server := oauthtest.NewServer(t).FailToken(status)
			_, err := newTestClient(t).Exchange(context.Background(), server.Provider(t, oauth.Google()), server.Code)
			if !errors.Is(err, oauth.ErrProviderUnavailable) {
				t.Errorf("Exchange with a %d = %v, want ErrProviderUnavailable", status, err)
			}
		})
	}
}

// A provider that cannot be reached at all is the same 502 as one that answers 500.
// The two are indistinguishable from here and should be indistinguishable to the
// caller.
func TestClientExchangeMapsAnUnreachableProvider(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t)
	provider := server.Provider(t, oauth.Google())
	server.Close() // nothing is listening any more

	_, err := newTestClient(t).Exchange(context.Background(), provider, server.Code)
	if !errors.Is(err, oauth.ErrProviderUnavailable) {
		t.Errorf("Exchange against a dead server = %v, want ErrProviderUnavailable", err)
	}
}

// The provider's error is in the message and the message is in the log. It must
// not be in a response body, which is why these are the two distinct sentinels
// rather than one error with a reason string the HTTP layer would have to parse.
func TestClientErrorsCarryTheProviderDetail(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t).FailToken(http.StatusInternalServerError)

	_, err := newTestClient(t).Exchange(context.Background(), server.Provider(t, oauth.Google()), server.Code)
	if err == nil {
		t.Fatal("Exchange succeeded against a 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error %q does not mention the status the provider returned", err)
	}
}

func TestClientIdentityReadsGoogle(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t).Person("107346492749283471920", "kaka@example.com", "Kaka")

	identity, err := newTestClient(t).Identity(context.Background(), server.Provider(t, oauth.Google()), oauth.Tokens{
		AccessToken: server.AccessToken,
	})
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}

	if identity.ProviderUID != "107346492749283471920" {
		t.Errorf("ProviderUID = %q, want the google sub", identity.ProviderUID)
	}
	if identity.Email != "kaka@example.com" {
		t.Errorf("Email = %q, want kaka@example.com", identity.Email)
	}
	if identity.Name != "Kaka" {
		t.Errorf("Name = %q, want Kaka", identity.Name)
	}
	// The access token, not a remembered value, is what authorized the call.
	if got := server.LastAuthorization(); !strings.Contains(got, server.AccessToken) {
		t.Errorf("the identity call carried %q, want it to present the access token", got)
	}
}

func TestClientIdentityReadsGitHub(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t).Person("583231", "kaka@example.com", "Kaka")

	identity, err := newTestClient(t).Identity(context.Background(), server.Provider(t, oauth.GitHub()), oauth.Tokens{
		AccessToken: server.AccessToken,
	})
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}

	// GitHub's id is a number; the value stored must be the string, because the
	// column is text and because "583231" and 583231 must never be two accounts.
	if identity.ProviderUID != "583231" {
		t.Errorf("ProviderUID = %q, want 583231 as a string", identity.ProviderUID)
	}
	if identity.Email != "kaka@example.com" {
		t.Errorf("Email = %q, want kaka@example.com", identity.Email)
	}
}

// GitHub returns a null email for an account whose address is private, and
// /user/emails is the documented way to get it. Without this the service cannot
// identify a large fraction of real GitHub accounts at all.
func TestClientIdentityFallsBackToTheGitHubEmailsEndpoint(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t).
		Person("583231", "", "Kaka").
		WithoutEmail().
		WithEmails(
			oauthtest.Email{Address: "old@example.com", Verified: true},
			oauthtest.Email{Address: "kaka@example.com", Primary: true, Verified: true},
			oauthtest.Email{Address: "other@example.com"},
		)

	identity, err := newTestClient(t).Identity(context.Background(), server.Provider(t, oauth.GitHub()), oauth.Tokens{
		AccessToken: server.AccessToken,
	})
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}

	if identity.Email != "kaka@example.com" {
		t.Errorf("Email = %q, want the primary verified address", identity.Email)
	}
	oauthtest.RequireCalls(t, server, oauthtest.UserInfoEndpointPath, oauthtest.EmailsEndpointPath)
}

// Unverified addresses are not identities. Refusing rather than accepting one is
// the whole reason the fallback filters: an unverified address on somebody else's
// GitHub account is the cheapest account takeover there is.
func TestClientIdentityRefusesAnUnverifiedOnlyGitHubAccount(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t).
		Person("583231", "", "Kaka").
		WithoutEmail().
		WithEmails(oauthtest.Email{Address: "attacker@example.com", Primary: true, Verified: false})

	_, err := newTestClient(t).Identity(context.Background(), server.Provider(t, oauth.GitHub()), oauth.Tokens{
		AccessToken: server.AccessToken,
	})
	if !errors.Is(err, oauth.ErrNoEmail) {
		t.Errorf("Identity = %v, want ErrNoEmail", err)
	}
}

// An address this service cannot create a user with is refused. The rules in
// internal/users are the same ones a registration is held to, and an OAuth login
// that bypassed them would be a way around them.
func TestClientIdentityRefusesAnEmailThisServiceCannotUse(t *testing.T) {
	t.Parallel()

	for _, email := range []string{
		"",                // nothing at all
		"   ",             // whitespace
		"not an address",  // no @, no domain
		"a@",              // no domain
		"@example.com",    // no local part
		"a b@example.com", // inner space
	} {
		t.Run(email, func(t *testing.T) {
			t.Parallel()

			server := oauthtest.NewServer(t).Person("583231", email, "Kaka")

			_, err := newTestClient(t).Identity(context.Background(), server.Provider(t, oauth.Google()), oauth.Tokens{
				AccessToken: server.AccessToken,
			})
			if !errors.Is(err, oauth.ErrNoEmail) {
				t.Errorf("Identity with the email %q = %v, want ErrNoEmail", email, err)
			}
		})
	}
}

// A response with no identity in it is not a person. A provider that answered 200
// with a body this service cannot read must not become a user whose provider_uid
// is empty, because the empty uid would then collide with every other empty uid.
func TestClientIdentityRefusesAResponseWithNoIdentifier(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t).Person("", "kaka@example.com", "Kaka")

	for _, name := range []string{oauth.ProviderGoogle, oauth.ProviderGitHub} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			base := oauth.Google()
			if name == oauth.ProviderGitHub {
				base = oauth.GitHub()
			}

			_, err := newTestClient(t).Identity(context.Background(), server.Provider(t, base), oauth.Tokens{
				AccessToken: server.AccessToken,
			})
			if err == nil {
				t.Error("Identity accepted a response with no provider identifier")
			}
		})
	}
}

func TestClientIdentityMapsAProviderOutage(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t).FailUserInfo(http.StatusInternalServerError)

	_, err := newTestClient(t).Identity(context.Background(), server.Provider(t, oauth.Google()), oauth.Tokens{
		AccessToken: server.AccessToken,
	})
	if !errors.Is(err, oauth.ErrProviderUnavailable) {
		t.Errorf("Identity = %v, want ErrProviderUnavailable", err)
	}
}

// An identity endpoint that answers 401 for a token it just issued is broken
// provider-side, and saying so as 502 is honest. Treating it as a refused login
// would be a 400 blaming the user for the provider's inconsistency.
func TestClientIdentityMapsAnUnauthorizedIdentityCall(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t)

	// A token the fake never issued, so its identity endpoint answers 401.
	_, err := newTestClient(t).Identity(context.Background(), server.Provider(t, oauth.Google()), oauth.Tokens{
		AccessToken: "a-token-the-provider-never-issued",
	})
	if !errors.Is(err, oauth.ErrProviderUnavailable) {
		t.Errorf("Identity = %v, want ErrProviderUnavailable", err)
	}
}

// An empty access token must not become an unauthenticated request. The provider
// answers 401, and this service must surface that rather than treating an
// anonymous profile as an identity.
func TestClientIdentityRefusesAnEmptyAccessToken(t *testing.T) {
	t.Parallel()

	server := oauthtest.NewServer(t)

	_, err := newTestClient(t).Identity(context.Background(), server.Provider(t, oauth.Google()), oauth.Tokens{})
	if !errors.Is(err, oauth.ErrProviderUnavailable) {
		t.Errorf("Identity with no access token = %v, want ErrProviderUnavailable", err)
	}
	oauthtest.RequireCalls(t, server)
}

// A provider that answers with something enormous must not be read into memory
// whole. The identity payload is a few hundred bytes; anything past the cap is a
// misconfiguration or an attack, and either way the parse fails rather than the
// process growing to meet it.
func TestClientIdentityCapsTheResponseBody(t *testing.T) {
	t.Parallel()

	// Four megabytes of padding, then the real document. The cap is well under
	// this, so the parse fails on a truncated body.
	padding := strings.Repeat("x", 4<<20)
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"sub":"1","email":"`)
		_, _ = io.WriteString(w, padding)
		_, _ = io.WriteString(w, `","name":"Kaka"}`)
	}))
	defer big.Close()

	provider := oauth.Google()
	provider.UserInfoURL = big.URL + "/userinfo"

	client := oauth.NewClient(oauth.ClientOptions{
		HTTPClient:      &http.Client{Timeout: 5 * time.Second},
		RedirectBaseURL: "https://identity.cafaye.com",
	})
	if _, err := client.Identity(context.Background(), provider, oauth.Tokens{AccessToken: "t"}); err == nil {
		t.Error("Identity accepted a response past the size cap")
	}
}
