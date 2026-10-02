package httpapi

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cafaye/identity/internal/accounts"
	"github.com/cafaye/identity/internal/oidc"
	"github.com/cafaye/identity/internal/outbox"
	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
)

// THE OIDC SUITE.
//
// The real router, the real use cases, the real SQL, over a private schema, with
// a real RSA key. Every test here is a thing a product would do and a thing an
// attacker would try, driven through the same handler the process serves.
//
// The clock is the SYSTEM clock, not the fake one the auth and tenancy suites
// use, and the reason is the library rather than taste: an id_token's expiry is
// `time.Now() + validity` and the validity is computed against the library's own
// `time.Now()`. A fixed 2026 instant on one side of that and the real clock on
// the other produces a token whose `exp` is in the past before it is signed. The
// flow's own windows — a sixty-second code, a fifteen-minute token — are far
// longer than the milliseconds a test takes, so nothing here has to sleep.

const (
	oidcTestIssuer   = "https://identity.test"
	oidcTestKeyID    = "cafaye-test-key"
	oidcTestRedirect = "https://app.example.com/cb"
	oidcTestPassword = "correct horse battery staple"
	// oidcTestUserAgent is the client identity internal/auth records an attempt
	// under, so a lockout test can tell which attempt it is looking at.
	oidcTestUserAgent = "identity-oidc-test/1"
	// oidcTestLoginUI is the configured login UI: a DIFFERENT ORIGIN from
	// oidcTestIssuer, because that is the deployment this packet is about. A
	// same-origin login UI would hide every question the interaction cookies and
	// the escaping of client_name exist to answer, and a suite that only ever ran
	// against a same-origin one would be green for a configuration nobody deploys.
	oidcTestLoginUI = "https://login.example.com/sign-in/oidc"
)

// oidcFixture is the world the OIDC suite runs in.
type oidcFixture struct {
	handler  http.Handler
	pool     *pgxpool.Pool
	provider *oidc.Provider
	storage  *oidc.Storage
	clients  *oidc.Service
	account  id.UUID
	owner    id.UUID
	email    string
	// tenancy is the account service, kept so a test can build a second account
	// without reaching for the whole wiring again.
	tenancy *accounts.Service
	// jar is the cookie store. The login page is a browser flow and the test has
	// to behave like the browser: a state cookie set on the GET and presented on
	// the POST, and a session cookie set on the POST.
	jar *cookieJar
}

// signOut drops the owner's session from the jar.
//
// The fixture signs the owner in because the ADMIN routes need a caller, and the
// login page then has to be reached signed out or it skips the form entirely and
// the state check and the password check are never exercised. This is the same
// line a browser is on when a user opens a second product in a new tab, so the
// case is real rather than a contrivance of the harness.
func (f *oidcFixture) signOut() {
	delete(f.jar.cookies, SessionCookieName)
}

func newOIDCFixture(t *testing.T) *oidcFixture {
	t.Helper()

	pool := dbtest.Schema(t)
	// A throwaway key per test. It is generated rather than read from a fixture
	// file so no PEM in this repository is a private key, even a dead one.
	key := generateTestKey(t)

	// The real clock; see the comment at the top of this file.
	clk := clock.System{}

	store := oidc.NewStore(pool)
	storage := oidc.NewStorage(store, oidc.NewProfileReader(), key, clk, db.Direct{Pool: pool}, oidc.PathLogin)

	provider, err := oidc.NewProvider(oidc.Config{
		Issuer:     oidcTestIssuer,
		SigningKey: key,
		LoginUIURL: oidcTestLoginUI,
	}, storage)
	if err != nil {
		t.Fatalf("building the provider: %v", err)
	}

	tenancy := realTenancy(pool, clk)
	f := &oidcFixture{tenancy: tenancy}
	authSvc := authServiceFor(pool, clk)
	clients := oidc.NewService(db.TxRunner{Pool: pool}, store, outbox.NewStore(pool), storage, clk, db.Direct{Pool: pool})

	handler := New(nil,
		WithAuth(authSvc),
		WithTenancy(tenancy),
		WithOIDC(provider),
		WithOIDCClients(clients),
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
	)

	f.handler = handler
	f.pool = pool
	f.provider = provider
	f.storage = storage
	f.clients = clients
	f.jar = &cookieJar{}

	// A user, with the personal account a registration creates, is the owner of
	// the account the client will be registered under.
	email := dbtest.UniqueEmail(t)
	rec := f.do(t, http.MethodPost, "/v1/users", `{"email":"`+email+`","password":"`+oidcTestPassword+`"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering a user: %d; body: %s", rec.Code, rec.Body)
	}
	var created userResponse
	mustJSON(t, rec.Body.Bytes(), &created)

	// A session, so the admin routes have a caller. This is the ONLY reason the
	// owner is signed in before the flow: the login page below is driven with the
	// credentials directly, so that the state check and the password check are
	// both exercised rather than short-circuited by an existing session.
	login := f.do(t, http.MethodPost, "/v1/session", `{"email":"`+email+`","password":"`+oidcTestPassword+`"}`, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("signing in: %d; body: %s", login.Code, login.Body)
	}
	var session sessionResponse
	mustJSON(t, login.Body.Bytes(), &session)
	f.jar.set(session.Token)

	parsed, err := id.Parse(created.ID)
	if err != nil {
		t.Fatalf("the service returned an id that does not parse: %v", err)
	}
	f.owner = parsed
	f.email = email

	mine, err := tenancy.ListMine(t.Context(), f.owner)
	if err != nil {
		t.Fatalf("listing the personal account: %v", err)
	}
	if len(mine) != 1 {
		t.Fatalf("a fresh registration has %d accounts, want 1", len(mine))
	}
	f.account = mine[0].Account.ID

	return f
}

// tenantAccount creates an extra account owned by owner, for the cross-account
// cases. It goes through the tenancy service rather than a direct insert so the
// account is one the service would have made.
func (f *oidcFixture) tenantAccount(t *testing.T, owner id.UUID) (id.UUID, error) {
	t.Helper()

	created, err := f.tenancy.Create(t.Context(), accounts.CreateInput{
		Name:  "OIDC test " + owner.String()[:8],
		Owner: owner,
	})
	if err != nil {
		return id.UUID{}, err
	}
	return created.Account.ID, nil
}

func generateTestKey(t *testing.T) *oidc.SigningKey {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating a signing key: %v", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(t, priv)})

	key, err := oidc.LoadSigningKey(string(encoded), oidcTestKeyID)
	if err != nil {
		t.Fatalf("loading the signing key: %v", err)
	}
	return key
}

func mustPKCS8(t *testing.T, priv *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := marshalPKCS8Key(priv)
	if err != nil {
		t.Fatalf("marshalling the signing key: %v", err)
	}
	return der
}

// registered is a client this fixture registered, with the one-time secret.
type registered struct {
	ID           string
	ClientID     string
	ClientSecret string
	Email        string
	Password     string
}

// registerClient registers a relying party for the account, through the real
// route, as the owner.
func (f *oidcFixture) registerClient(t *testing.T) registered {
	t.Helper()

	body := fmt.Sprintf(`{"name":"Anytalk","redirect_uris":[%q],"grant_types":["authorization_code"],`+
		`"scopes":["openid","email","profile","accounts"]}`, oidcTestRedirect)

	rec := f.do(t, http.MethodPost, "/v1/accounts/"+f.account.String()+"/oidc-clients", body, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering a client: %d; body: %s", rec.Code, rec.Body)
	}

	var created oidcClientCreatedResponse
	mustJSON(t, rec.Body.Bytes(), &created)
	if created.ClientSecret == "" {
		t.Fatal("the 201 carried no client_secret; it exists exactly once, here")
	}
	if created.ClientID == "" || created.ID == "" {
		t.Fatalf("the 201 is missing the identifiers: %s", rec.Body)
	}

	return registered{
		ID:           created.ID,
		ClientID:     created.ClientID,
		ClientSecret: created.ClientSecret,
		Email:        f.email,
		Password:     oidcTestPassword,
	}
}

// codeVerifier is a fresh PKCE verifier and its S256 challenge.
func codeVerifier(t *testing.T) (verifier, challenge string) {
	t.Helper()

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("generating a code verifier: %v", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// authorize drives GET /oidc/authorize and returns the login URL the browser was
// sent to.
func (f *oidcFixture) authorize(t *testing.T, client registered, challenge, state, nonce string, extra url.Values) string {
	t.Helper()

	query := url.Values{
		"client_id":             []string{client.ClientID},
		"redirect_uri":          []string{oidcTestRedirect},
		"response_type":         []string{"code"},
		"scope":                 []string{"openid email profile accounts"},
		"state":                 []string{state},
		"nonce":                 []string{nonce},
		"code_challenge":        []string{challenge},
		"code_challenge_method": []string{"S256"},
	}
	for key, values := range extra {
		query[key] = values
	}

	rec := f.do(t, http.MethodGet, oidc.PathAuthorize+"?"+query.Encode(), "", nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("GET /oidc/authorize = %d, want 302; body: %s", rec.Code, rec.Body)
	}
	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, oidc.PathLogin+"/") {
		t.Fatalf("the browser was sent to %q, want the login page", location)
	}
	return location
}

// login drives the login interaction the way a browser with a form on another
// origin would: GET the endpoint, follow the redirect to the login UI, take the
// state out of the query it carries, and POST it back with the credentials.
//
// The GET is still a GET against this service and the POST is still a POST
// against this service, because that is the whole design — the login UI is a
// renderer, not a participant. What changed is where the state is read from, and
// `interactionState` says why.
func (f *oidcFixture) login(t *testing.T, loginURL, email, password string) *oidcResponse {
	t.Helper()

	f.signOut()

	form := f.do(t, http.MethodGet, loginURL, "", nil)
	redirect := mustRedirectToLoginUI(t, form)
	if got := redirect.Query().Get(oidc.LoginParamClientName); got != "Anytalk" {
		t.Errorf("%s = %q, want the product asking; a sign-in form that cannot name the "+
			"application is a credential-phishing page", oidc.LoginParamClientName, got)
	}
	if got := redirect.Query().Get(oidc.LoginParamStep); got != oidc.LoginStepPassword {
		t.Errorf("%s = %q, want %q", oidc.LoginParamStep, got, oidc.LoginStepPassword)
	}

	post := url.Values{
		"state":    []string{interactionState(t, form)},
		"email":    []string{email},
		"password": []string{password},
	}
	rec := f.do(t, http.MethodPost, loginURL, "", post)
	f.jar.absorb(rec.Result().Cookies())
	return rec
}

// exchange trades a code for tokens.
func (f *oidcFixture) exchange(t *testing.T, client registered, code, verifier, redirectURI string) *oidcResponse {
	t.Helper()

	form := url.Values{
		"grant_type":    []string{"authorization_code"},
		"code":          []string{code},
		"redirect_uri":  []string{redirectURI},
		"code_verifier": []string{verifier},
	}
	req := httptest.NewRequest(http.MethodPost, oidc.PathToken, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+basicAuth(client.ClientID, client.ClientSecret))

	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return newResponse(rec)
}

// roundTrip runs authorize -> login -> token and returns the token response.
func (f *oidcFixture) roundTrip(t *testing.T, client registered) map[string]any {
	t.Helper()

	verifier, challenge := codeVerifier(t)
	const state, nonce = "state-round-trip", "nonce-round-trip"

	loginURL := f.authorize(t, client, challenge, state, nonce, nil)

	rec := f.login(t, loginURL, client.Email, client.Password)
	if rec.Code != http.StatusFound {
		t.Fatalf("POST the login form = %d, want 302; body: %s", rec.Code, rec.Body)
	}

	redirect, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("the login redirect is not a URL: %v", err)
	}
	if got := redirect.Scheme + "://" + redirect.Host + redirect.Path; got != oidcTestRedirect {
		t.Fatalf("the browser was returned to %q, want the registered %q", got, oidcTestRedirect)
	}
	if got := redirect.Query().Get("state"); got != state {
		t.Errorf("the redirect carried state %q, want %q; the client's CSRF value must come back untouched", got, state)
	}
	code := redirect.Query().Get("code")
	if code == "" {
		t.Fatalf("the redirect carried no code: %s", redirect)
	}

	tokens := f.exchange(t, client, code, verifier, oidcTestRedirect)
	if tokens.Code != http.StatusOK {
		t.Fatalf("the token exchange = %d, want 200; body: %s", tokens.Code, tokens.Body)
	}

	var body map[string]any
	mustJSON(t, tokens.Body.Bytes(), &body)
	return body
}

// verify checks a token's signature against the PUBLISHED key set, which is the
// same thing guard does and the only check worth making about an RS256 token.
func (f *oidcFixture) verify(t *testing.T, token string) map[string]any {
	t.Helper()

	rec := f.do(t, http.MethodGet, oidc.PathJWKS, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET the jwks = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	var set jose.JSONWebKeySet
	mustJSON(t, rec.Body.Bytes(), &set)

	parsed, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("the token is not an RS256 JWS: %v", err)
	}
	payload, err := parsed.Verify(set.Keys[0].Key)
	if err != nil {
		t.Fatalf("the token does not verify against the published key set: %v", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("the token payload is not JSON: %v", err)
	}
	return claims
}

// do issues a request through the fixture's handler, with the cookie jar.
func (f *oidcFixture) do(t *testing.T, method, target, body string, form url.Values) *oidcResponse {
	t.Helper()

	return f.doWithSession(t, "", method, target, body, form)
}

// doWithSession is do with the credential stated rather than taken from the jar,
// for the cases where using the owner's session would be the whole answer.
func (f *oidcFixture) doWithSession(t *testing.T, session, method, target, body string, form url.Values) *oidcResponse {
	t.Helper()

	var reader io.Reader
	switch {
	case form != nil:
		reader = strings.NewReader(form.Encode())
	case body != "":
		reader = strings.NewReader(body)
	default:
		reader = strings.NewReader("")
	}

	req := httptest.NewRequest(method, target, reader)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", oidcTestUserAgent)
	if session != "" {
		req.Header.Set("Authorization", "Bearer "+session)
	} else if cookie := f.jar.header(); cookie != "" {
		req.Header.Set("Cookie", cookie)
	}

	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	f.jar.absorb(rec.Result().Cookies())
	return newResponse(rec)
}

// cookieJar is the browser's cookie store, minus the parts of it this flow does
// not use. It is here because the login page's state check reads a cookie the GET
// set, and a test that passed one cookie and not the other would be testing a
// flow no browser can complete.
type cookieJar struct {
	cookies map[string]*http.Cookie
}

func (j *cookieJar) absorb(cookies []*http.Cookie) {
	if j.cookies == nil {
		j.cookies = map[string]*http.Cookie{}
	}
	for _, c := range cookies {
		if c.MaxAge < 0 || c.Value == "" {
			delete(j.cookies, c.Name)
			continue
		}
		j.cookies[c.Name] = c
	}
}

func (j *cookieJar) set(token string) {
	if j.cookies == nil {
		j.cookies = map[string]*http.Cookie{}
	}
	j.cookies[SessionCookieName] = &http.Cookie{Name: SessionCookieName, Value: token}
}

func (j *cookieJar) header() string {
	names := make([]string, 0, len(j.cookies))
	for name := range j.cookies {
		names = append(names, name)
	}
	// Sorted, so the header is the same on every request and a failure is not a
	// function of map order.
	sortStrings(names)

	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, name+"="+j.cookies[name].Value)
	}
	return strings.Join(parts, "; ")
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for k := i; k > 0 && values[k] < values[k-1]; k-- {
			values[k], values[k-1] = values[k-1], values[k]
		}
	}
}

func basicAuth(user, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(user) + ":" + url.QueryEscape(password)))
}

// interactionState pulls the CSRF state out of a redirect to the login UI.
//
// IT READS THE `Location` AND NOT A BODY, and that is the whole of what this
// packet changed about the test harness: the state this service mints now travels
// in a query string to a page on another origin, and a test that parsed a
// `<input name="state">` out of a rendered form would be testing markup that no
// longer exists. The value is the same value — the test asserts on the CONTRAT'T,
// and the contract moved from a hidden field to a query parameter.
//
// A redirect that is not a redirect, or a redirect to somewhere that carries no
// state, is a test failure rather than an empty string, because "the page did not
// carry a state" used to be a failure too and it should stay one.
func interactionState(t *testing.T, rec *oidcResponse) string {
	t.Helper()

	location := rec.Header().Get("Location")
	if location == "" {
		t.Fatalf("the response carried no Location; it was %d with body:\n%s", rec.Code, rec.Body)
	}
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("the redirect %q is not a URL: %v", location, err)
	}
	state := parsed.Query().Get(oidc.LoginParamState)
	if state == "" {
		t.Fatalf("the redirect %q carried no %q", location, oidc.LoginParamState)
	}
	return state
}

// interactionParams is the parsed query of a redirect to the login UI, for the
// assertions that are about what travels rather than about one field.
func interactionParams(t *testing.T, rec *oidcResponse) url.Values {
	t.Helper()

	location := rec.Header().Get("Location")
	if location == "" {
		t.Fatalf("the response carried no Location; it was %d with body:\n%s", rec.Code, rec.Body)
	}
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("the redirect %q is not a URL: %v", location, err)
	}
	return parsed.Query()
}

// mustRedirect asserts that a response is a redirect to the login UI and returns
// where. Every assertion about the interaction goes through it, so "is this
// actually a redirect to the login UI" is one question answered in one place
// rather than restated in a dozen tests.
func mustRedirectToLoginUI(t *testing.T, rec *oidcResponse) *url.URL {
	t.Helper()

	if rec.Code != http.StatusFound {
		t.Fatalf("= %d, want 302 to the login UI; body:\n%s", rec.Code, rec.Body)
	}
	parsed, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("the redirect is not a URL: %v", err)
	}
	if got := parsed.Scheme + "://" + parsed.Host + parsed.Path; got != oidcTestLoginUI {
		t.Fatalf("the browser was sent to %q, want the configured login UI %q", got, oidcTestLoginUI)
	}
	return parsed
}

func mustJSON(t *testing.T, data []byte, into any) {
	t.Helper()

	if err := json.Unmarshal(data, into); err != nil {
		t.Fatalf("the body is not JSON: %v\n%s", err, data)
	}
}

// marshalPKCS8Key is x509.MarshalPKCS8PrivateKey, named so the test file does
// not import crypto/x509 for one call.
func marshalPKCS8Key(priv *rsa.PrivateKey) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(priv)
}
