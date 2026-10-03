// Package oauthtest is a fake OAuth 2.0 provider for tests.
//
// It exists for the same reason internal/platform/dbtest does: the flow under test
// spans three packages — the HTTP client in internal/oauth, the use case in
// internal/auth and the handlers in internal/httpapi — and all three have to be
// able to point the whole round trip at a real server without reaching Google or
// GitHub. A test that reaches a real provider is a test with a rate limit, a
// network dependency and a credential in its environment.
//
// It is a normal package rather than a _test.go file so that every package's tests
// can share it. Nothing imports it outside tests, so it contributes nothing to the
// service binary.
package oauthtest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"

	"github.com/cafaye/identity/internal/oauth"
)

// Email is one entry of GitHub's /user/emails response.
type Email struct {
	Address  string
	Primary  bool
	Verified bool
}

// Server is a fake provider serving a token endpoint, an identity endpoint and —
// because GitHub's identity endpoint does not always carry one — an emails
// endpoint.
//
// Every method is safe to call before the first request; the knobs are read under
// a mutex when a handler runs, and go test runs tests within a package in
// sequence unless they call t.Parallel.
type Server struct {
	// URL is the base to point a Provider's endpoints at.
	URL string

	// closer shuts the server down early. A test that wants the provider to be
	// unreachable calls it; otherwise the server stops when the test ends.
	closer func()

	// Code is the only authorization code the token endpoint accepts. Anything
	// else is answered as RFC 6749 invalid_grant.
	Code string
	// AccessToken and RefreshToken are what a successful exchange returns.
	AccessToken  string
	RefreshToken string
	// ExpiresIn is the access token's lifetime in seconds. Zero means the token
	// does not expire, which is GitHub's default.
	ExpiresIn int

	// ProviderUID, Email and Name are what the identity endpoint reports.
	ProviderUID string
	Email       string
	Name        string

	// Emails is the /user/emails payload, consulted only when Email is empty.
	Emails []Email

	// OmitEmail makes the identity endpoint report no address at all, which is
	// what a GitHub account with a private address looks like.
	OmitEmail bool

	// UnverifiedEmail makes Google's userinfo carry `"email_verified": false`,
	// and makes GitHub's /user/emails carry the address with `verified: false`.
	//
	// It exists because the client REFUSES an unverified address, on both
	// providers, and a fake that could only ever report a verified one would make
	// that refusal untestable in either direction: a test asserting the refusal
	// would have nothing to assert against, and a client that had stopped checking
	// would keep passing every happy path.
	UnverifiedEmail bool

	// tokenStatus, userInfoStatus and emailsStatus are the status codes those
	// endpoints return. Zero means 200.
	tokenStatus    int
	userInfoStatus int
	emailsStatus   int

	mu        sync.Mutex
	calls     []string
	tokenForm url.Values
	authz     string
}

// NewServer starts a fake provider and stops it when the test ends.
func NewServer(t *testing.T) *Server {
	t.Helper()

	s := &Server{
		Code:         "the-authorization-code",
		AccessToken:  "an-access-token",
		RefreshToken: "a-refresh-token",
		ExpiresIn:    3600,
		ProviderUID:  "107346492749283471920",
		Email:        "kaka@example.com",
		Name:         "Kaka",
	}

	server := httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(server.Close)
	s.URL = server.URL
	s.closer = server.Close

	return s
}

// Close stops the server, so a test can prove what a caller sees when the provider
// cannot be reached at all.
func (s *Server) Close() { s.closer() }

// Person sets what the identity endpoint reports.
func (s *Server) Person(uid, email, name string) *Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ProviderUID, s.Email, s.Name = uid, email, name
	return s
}

// WithoutEmail makes the identity endpoint report no address. Combined with
// Emails, it is the GitHub case where the address has to come from a second call.
func (s *Server) WithoutEmail() *Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.OmitEmail = true
	return s
}

// WithEmails sets the /user/emails payload.
func (s *Server) WithEmails(emails ...Email) *Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Emails = emails
	return s
}

// WithoutVerifiedEmail makes the provider report the address as NOT verified. It is
// the case the client must refuse, and it is a distinct knob from WithoutEmail: one
// is "the provider said nothing usable", the other is "the provider said something
// and it is not good enough".
func (s *Server) WithoutVerifiedEmail() *Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.UnverifiedEmail = true
	return s
}

// WithoutExpiry makes the token endpoint return a token that does not expire.
func (s *Server) WithoutExpiry() *Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ExpiresIn = 0
	return s
}

// FailToken makes the token endpoint answer with this status and an RFC 6749 error
// body. 500 is "the provider is broken"; 400 is "your code was no good", and the
// two mean different things to the caller.
func (s *Server) FailToken(status int) *Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokenStatus = status
	return s
}

// FailUserInfo makes the identity endpoint answer with this status.
func (s *Server) FailUserInfo(status int) *Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.userInfoStatus = status
	return s
}

// FailEmails makes the emails endpoint answer with this status.
func (s *Server) FailEmails(status int) *Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.emailsStatus = status
	return s
}

// Calls returns the endpoints that were hit, in order, so a test can assert that
// the flow stopped where it should.
func (s *Server) Calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

// LastTokenForm returns the form the last token request carried. The code and the
// redirect_uri are the two fields a test needs to check that the right code was
// exchanged for the right callback.
func (s *Server) LastTokenForm() url.Values {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokenForm
}

// LastAuthorization returns the Authorization header the last identity request
// carried. A test asserting the access token is presented — rather than a
// remembered session id, or nothing at all — is what catches an implementation
// that fetched the profile before exchanging the code.
func (s *Server) LastAuthorization() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authz
}

// Provider returns base with every endpoint pointed at this server.
//
// It is how a test gets a real Provider value — a real one, with real scopes and a
// real client id — into a flow whose network calls land in this process.
func (s *Server) Provider(t *testing.T, base oauth.Provider) oauth.Provider {
	t.Helper()

	base.AuthorizeURL = s.URL + "/authorize"
	base.TokenURL = s.URL + "/token"
	base.UserInfoURL = s.URL + "/userinfo"
	base.EmailsURL = s.URL + "/emails"
	base.ClientID = "test-client-id"
	base.ClientSecret = "test-client-secret"
	return base
}

// Providers returns a Registry holding every provider pointed at this server, so a
// test can exercise the 404 path for a provider it has deliberately not
// configured.
func (s *Server) Providers(t *testing.T) []oauth.Provider {
	t.Helper()

	return []oauth.Provider{
		s.Provider(t, oauth.Google()),
		s.Provider(t, oauth.GitHub()),
	}
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// The authorize endpoint is never actually served: the browser is redirected
	// there, and in a test the redirect is followed by nothing. Recording the hit
	// is enough for a test that wants to assert the redirect was built.
	s.record(r.URL.Path)

	if status := s.tokenStatus; status != 0 && r.URL.Path == "/token" {
		s.serveTokenError(w, status)
		return
	}
	if status := s.userInfoStatus; status != 0 && r.URL.Path == "/userinfo" {
		http.Error(w, `{"error":"server_error"}`, status)
		return
	}
	if status := s.emailsStatus; status != 0 && r.URL.Path == "/emails" {
		http.Error(w, `{"message":"server error"}`, status)
		return
	}

	switch r.URL.Path {
	case "/token":
		s.serveToken(w, r)
	case "/userinfo":
		s.serveUserInfo(w, r)
	case "/emails":
		s.serveEmails(w, r)
	case "/authorize":
		// Answered rather than 404 so a test that accidentally follows the
		// redirect gets a body it can recognise instead of chi's plain text.
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>authorize</body></html>"))
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) record(path string) {
	s.calls = append(s.calls, path)
}

// authorizes reports whether the request carries the access token this server
// issued. It is the fake's whole fidelity: everything downstream of a successful
// exchange is conditional on the credential being right.
func (s *Server) authorizes(r *http.Request) bool {
	return r.Header.Get("Authorization") == "Bearer "+s.AccessToken
}

// serveToken answers a code exchange.
//
// The redirect_uri is echoed into the body so a test can assert that the flow
// offered the provider exactly the redirect URI it is about to be checked against
// — a mismatch here is the single most common way a deployment gets a
// redirect_uri_mismatch from Google and no idea why.
func (s *Server) serveToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	s.tokenForm = r.PostForm

	if r.PostForm.Get("code") != s.Code {
		s.serveTokenError(w, http.StatusBadRequest)
		return
	}

	body := map[string]any{
		"access_token": s.AccessToken,
		"token_type":   "Bearer",
	}
	if s.RefreshToken != "" {
		body["refresh_token"] = s.RefreshToken
	}
	if s.ExpiresIn > 0 {
		body["expires_in"] = s.ExpiresIn
	}
	body["redirect_uri"] = r.PostForm.Get("redirect_uri")

	writeJSON(w, http.StatusOK, body)
}

func (s *Server) serveTokenError(w http.ResponseWriter, status int) {
	code := "server_error"
	if status < 500 {
		code = "invalid_grant"
	}
	writeJSON(w, status, map[string]string{"error": code})
}

// serveUserInfo answers in the shape both providers use: an `id`/`sub` and an
// address. Google sends `sub` as a string, GitHub sends `id` as a number, and
// which one is present is what tells the decoder which provider it is talking to.
func (s *Server) serveUserInfo(w http.ResponseWriter, r *http.Request) {
	if !s.authorizes(r) {
		// A real provider answers 401 for a token it did not issue — including none
		// at all. So does this one, and that is what makes it useful: an
		// implementation that fetched the profile with no credential, or with a
		// remembered session id instead of the access token, passes against a fake
		// that always says yes and fails here.
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	s.authz = r.Header.Get("Authorization")

	body := map[string]any{
		"name":  s.Name,
		"login": s.ProviderUID,
	}
	if s.OmitEmail {
		// null, not "": GitHub sends a JSON null, and a decoder that only handles
		// the empty string gets a provider that "works" against this fake and
		// fails in production.
		body["email"] = nil
	} else {
		body["email"] = s.Email
	}

	// Both spellings at once. The decoder picks the one its provider uses, and the
	// other is inert.
	body["sub"] = s.ProviderUID
	if _, err := strconv.ParseInt(s.ProviderUID, 10, 64); err == nil {
		body["id"] = json.Number(s.ProviderUID)
	}
	// Google's document carries `email_verified` and the client reads it, so the
	// fake has to serve it — a fake that omitted the claim would make an
	// implementation that checks it fail against the fake and one that ignores it
	// pass, which is the opposite of what a fake is for.
	body["email_verified"] = !s.UnverifiedEmail

	writeJSON(w, http.StatusOK, body)
}

func (s *Server) serveEmails(w http.ResponseWriter, r *http.Request) {
	if !s.authorizes(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	s.authz = r.Header.Get("Authorization")

	out := make([]map[string]any, 0, len(s.Emails))
	for _, e := range s.Emails {
		out = append(out, map[string]any{
			"email": e.Address,
			// The entry's own flag AND the server-wide knob, so a caller can test
			// either "this particular address is unverified" or "nothing this
			// account has is verified" without two different mechanisms.
			"primary":  e.Primary,
			"verified": e.Verified && !s.UnverifiedEmail,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// TokenEndpointPath and the others are exported so a test in another package can
// assert on Server.Calls() without hard-coding strings that might drift.
const (
	TokenEndpointPath    = "/token"
	UserInfoEndpointPath = "/userinfo"
	EmailsEndpointPath   = "/emails"
)

// RequireCalls fails the test unless the endpoints were hit in this order. A flow
// that calls the identity endpoint before the token endpoint is a flow that
// authenticates nobody, and this is how that is caught.
func RequireCalls(t *testing.T, s *Server, want ...string) {
	t.Helper()

	got := s.Calls()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("the provider was called %v, want %v", got, want)
	}
}
