package httpapi

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cafaye/identity/internal/mfa"
	"github.com/cafaye/identity/internal/oidc"
	"github.com/cafaye/identity/internal/outbox"
	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
)

// THE OIDC LOGIN INTERACTION AND THE SECOND FACTOR.
//
// This is a LOGIN, so the packet's central rule applies to it exactly as it
// applies to POST /v1/session: a correct password must not complete an
// authorization request for an account with a second factor. A handler that
// quietly completed the flow would be the worst bug this service could have —
// invisible, affecting every MFA user of every product, and MFA off in practice
// while on in the database.
//
// So most of what follows asserts what does NOT happen on the password step: no
// code minted, no session cookie, and the step the browser is sent to.
//
// THE CLOCK IS THE FAKE ONE HERE AND THE SYSTEM ONE in oidc_integration_test.go,
// deliberately and for the reason that file's header states: an id_token's expiry
// is computed against the library's own time.Now(), so the provider needs the real
// clock. The auth and MFA services need the fake one, because the whole packet's
// timing is about a code that is valid for thirty seconds and a lock that lasts
// fifteen minutes — neither of which a test can wait for and both of which a fake
// clock states exactly.
//
// THE LOGIN UI IS A DIFFERENT ORIGIN here, as it is in every other fixture in this
// package, and that is the point of the whole packet.

// oidcMFAFixture is a registered relying party, a user, and a login page, with the
// whole MFA surface mounted.
type oidcMFAFixture struct {
	handler  http.Handler
	pool     *pgxpool.Pool
	clock    *clock.Fake
	second   *mfa.Service
	email    string
	userID   id.UUID
	secret   string
	recovery string
	// requestID is the auth request the login page is reached for.
	requestID string
	jar       *cookieJar
}

func newOIDCMFAFixture(t *testing.T, withMFA bool) *oidcMFAFixture {
	t.Helper()

	pool := dbtest.Schema(t)
	clk := clock.NewFake(time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))

	// A throwaway key per test, generated rather than read from a file, so no PEM in
	// this repository is a private key even a dead one.
	key := generateTestKey(t)
	store := oidc.NewStore(pool)
	storage := oidc.NewStorage(store, oidc.NewProfileReader(), key, clock.System{},
		db.Direct{Pool: pool}, oidc.PathLogin)
	provider, err := oidc.NewProvider(oidc.Config{
		Issuer:     oidcTestIssuer,
		SigningKey: key,
		LoginUIURL: oidcTestLoginUI,
	}, storage)
	if err != nil {
		t.Fatalf("building the provider: %v", err)
	}

	second := testMFAService(pool, clk)
	authSvc := authServiceFor(pool, clk)
	clients := oidc.NewService(db.TxRunner{Pool: pool}, store, outbox.NewStore(pool), storage,
		clock.System{}, db.Direct{Pool: pool})

	f := &oidcMFAFixture{
		pool: pool, clock: clk, second: second, jar: &cookieJar{},
		handler: New(nil,
			WithAuth(authSvc),
			WithMFA(second),
			WithOIDC(provider),
			WithOIDCClients(clients),
			WithLogger(slogLogger(&recordingHandler{})),
		),
	}

	// A user and a personal account, which is the account the client registers under.
	email := dbtest.UniqueEmail(t)
	rec := f.send(t, http.MethodPost, "/v1/users",
		`{"email":"`+email+`","password":"`+oidcTestPassword+`"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering a user: %d; body: %s", rec.Code, rec.Body)
	}
	var created userResponse
	mustJSON(t, rec.Body.Bytes(), &created)
	parsed, err := id.Parse(created.ID)
	if err != nil {
		t.Fatalf("parsing the registered id: %v", err)
	}
	f.userID, f.email = parsed, email

	mine, err := realTenancy(pool, clk).ListMine(t.Context(), f.userID)
	if err != nil || len(mine) != 1 {
		t.Fatalf("listing the personal account: %v (%d accounts)", err, len(mine))
	}

	if withMFA {
		started, err := second.StartEnrollment(t.Context(), mfa.StartEnrollmentInput{UserID: f.userID})
		if err != nil {
			t.Fatalf("StartEnrollment: %v", err)
		}
		f.secret = started.Secret
		confirmed, err := second.Confirm(t.Context(), mfa.ConfirmInput{
			UserID:       f.userID,
			EnrollmentID: started.Credential.ID,
			Factor:       mustTOTPCode(t, started.Secret, clk.Now()),
		})
		if err != nil {
			t.Fatalf("Confirm: %v", err)
		}
		f.recovery = confirmed.RecoveryCodes[0]
	}

	registered, err := clients.Register(t.Context(), oidc.RegisterInput{
		AccountID:    mine[0].Account.ID,
		Name:         "Anytalk",
		RedirectURIs: []string{oidcTestRedirect},
		GrantTypes:   []string{oidc.GrantAuthorizationCode},
		Scopes:       []string{oidc.ScopeOpenID, oidc.ScopeEmail},
		RegisteredBy: f.userID,
	})
	if err != nil {
		t.Fatalf("registering a relying party: %v", err)
	}

	// An authorization request for that client, stored the way /oidc/authorize
	// stores it, so the login page has something to render and to complete.
	f.requestID = seedAuthRequest(t, pool, store, registered.Client)
	return f
}

// send issues one request through the fixture, absorbing cookies into the jar the
// way a browser would.
func (f *oidcMFAFixture) send(t *testing.T, method, target, body string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()

	var reader = strings.NewReader("")
	contentType := ""
	switch {
	case form != nil:
		reader = strings.NewReader(form.Encode())
		contentType = "application/x-www-form-urlencoded"
	case body != "":
		reader = strings.NewReader(body)
		contentType = "application/json"
	}

	req := httptest.NewRequest(method, target, reader)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("User-Agent", oidcTestUserAgent)
	if cookie := f.jar.header(); cookie != "" {
		req.Header.Set("Cookie", cookie)
	}

	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	f.jar.absorb(rec.Result().Cookies())
	return rec
}

// loginPage opens the login interaction and drops the session cookie, so the
// browser is sent to the login UI rather than through the silent path. A browser
// on this step is signed out, or they would not be here.
func (f *oidcMFAFixture) loginPage(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	delete(f.jar.cookies, SessionCookieName)
	return f.send(t, http.MethodGet, oidc.PathLogin+"/"+f.requestID, "", nil)
}

// submit posts a form to the login endpoint with the cookies the GET set.
func (f *oidcMFAFixture) submit(t *testing.T, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	return f.send(t, http.MethodPost, oidc.PathLogin+"/"+f.requestID, "", form)
}

// signIn is the password step: a real GET for the sealed state and a real POST with
// it, so the state check is exercised rather than bypassed.
func (f *oidcMFAFixture) signIn(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()

	page := f.loginPage(t)
	form := url.Values{
		"state":    {stateFromRedirect(t, page)},
		"email":    {f.email},
		"password": {oidcTestPassword},
	}
	return f.submit(t, form)
}

// presentCode is the challenge step, with the state the challenge redirect
// re-minted.
func (f *oidcMFAFixture) presentCode(t *testing.T, fromChallengeStep *httptest.ResponseRecorder, code string) *httptest.ResponseRecorder {
	t.Helper()
	return f.submit(t, url.Values{"state": {stateFromRedirect(t, fromChallengeStep)}, "code": {code}})
}

func (f *oidcMFAFixture) advance(d time.Duration) { f.clock.Advance(d) }

// stateFromRedirect pulls the sealed state out of a redirect to the login UI,
// which is the only place it appears now.
func stateFromRedirect(t *testing.T, rec *httptest.ResponseRecorder) string {
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

// redirectQuery is the parsed query of a redirect, for the step assertions.
func redirectQuery(t *testing.T, rec *httptest.ResponseRecorder) url.Values {
	t.Helper()

	location := rec.Header().Get("Location")
	if location == "" {
		t.Fatalf("the response carried no Location; it was %d with body:\n%s", rec.Code, rec.Body)
	}
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("the redirect %q is not a URL: %v", location, err)
	}
	if got := parsed.Scheme + "://" + parsed.Host + parsed.Path; got != oidcTestLoginUI {
		t.Fatalf("the browser was sent to %q, want the configured login UI %q", got, oidcTestLoginUI)
	}
	return parsed.Query()
}

// seedAuthRequest stores one authorization request, the way /oidc/authorize does, so
// the login page has a request to render and to complete.
//
// It is written straight into the store rather than through the protocol endpoint
// because the endpoint needs a signed-in caller, and this suite's whole point is
// that the page runs for a caller who is NOT signed in.
func seedAuthRequest(t *testing.T, pool *pgxpool.Pool, store *oidc.Store, client oidc.Client) string {
	t.Helper()

	now := time.Now().UTC()
	created, err := store.CreateAuthRequest(t.Context(), pool, oidc.NewAuthRequest{
		ClientRowID:         client.ID,
		RedirectURI:         client.RedirectURIs[0],
		State:               "state-value-for-the-login-page-test",
		Nonce:               "nonce-value-for-the-login-page-test",
		ResponseType:        "code",
		ResponseMode:        "query",
		Scopes:              client.Scopes,
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", // RFC 7636 §B.1
		CodeChallengeMethod: "S256",
		LoginHint:           "",
		CreatedAt:           now,
		ExpiresAt:           now.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("seeding an authorization request: %v", err)
	}
	return created.ID.String()
}

// ---------------------------------------------------------------------------
// the password step
// ---------------------------------------------------------------------------

// TestTheOIDCLoginInteractionChallengesAnMFAUser is the composition: the password
// step sends the browser to the CODE step, mints no code, and sets no session.
//
// THE `step` PARAMETER IS THE ASSERTION HERE, and it is worth saying why it is
// load-bearing rather than a detail. Before this packet the page rendered a code
// box and the test looked for `name="code"` in the body. Now there is no body, and
// the only thing that tells the login UI to render the code box instead of the
// password box is that parameter — so a handler that got the password right and
// then said `step=password` would pass every other test in this file and produce a
// sign-in that asks for the password forever.
func TestTheOIDCLoginInteractionChallengesAnMFAUser(t *testing.T) {
	f := newOIDCMFAFixture(t, true)

	rec := f.signIn(t)

	if rec.Code != http.StatusFound {
		t.Fatalf("the password step = %d, want 302 to the login UI; body:\n%s", rec.Code, rec.Body)
	}
	query := redirectQuery(t, rec)
	if got := query.Get(oidc.LoginParamStep); got != oidc.LoginStepChallenge {
		t.Errorf("%s = %q, want %q; a login UI rendering the password box again is a "+
			"sign-in that can never be finished", oidc.LoginParamStep, got, oidc.LoginStepChallenge)
	}
	if got := query.Get(oidc.LoginParamError); got != "" {
		t.Errorf("the password step reported %s = %q; a correct password is not a failure",
			oidc.LoginParamError, got)
	}
	if cookie := cookieNamed(rec, SessionCookieName); cookie != nil && cookie.Value != "" {
		t.Error("the password step set a session cookie for an account with a second factor")
	}
	// Not a redirect to the PRODUCT either. A code on the Location would mean the
	// flow completed, and this is the assertion that a correct password does not
	// complete it.
	if strings.Contains(rec.Header().Get("Location"), oidcTestRedirect) {
		t.Errorf("the password step redirected to the product (%q), which means an "+
			"authorization code was minted for an account with a second factor",
			rec.Header().Get("Location"))
	}
	// The challenge has to survive to the next request, or the interaction cannot
	// be finished at all. It is a cookie rather than something in the query, and
	// oidcInteractionSameSite is why that is still true across a cross-site POST.
	challenge := cookieNamed(rec, OIDCChallengeCookiePrefix+f.requestID)
	if challenge == nil || challenge.Value == "" {
		t.Errorf("the password step kept no challenge cookie; cookies: %v", cookieNames(rec.Result().Cookies()))
	} else if challenge.SameSite != http.SameSiteNoneMode {
		t.Errorf("the challenge cookie is SameSite=%v; the code form is a cross-site POST "+
			"and a Lax cookie is not sent on one", challenge.SameSite)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

// TestTheOIDCLoginInteractionSignsInAnAccountWithNoSecondFactor is the
// compatibility half: a user with no MFA gets exactly the behaviour the page had
// before this packet, and the redirect goes to the PRODUCT rather than to the
// login UI.
func TestTheOIDCLoginInteractionSignsInAnAccountWithNoSecondFactor(t *testing.T) {
	f := newOIDCMFAFixture(t, false)

	rec := f.signIn(t)
	if rec.Code < 300 || rec.Code >= 400 {
		t.Fatalf("the password step = %d, want a redirect to the product; body:\n%s", rec.Code, rec.Body)
	}
	// The library's callback has run and redirected on to the PRODUCT, with an
	// authorization code minted. Asserting on the product's redirect_uri rather than
	// on this service's own path, because that redirect IS the proof the flow
	// completed.
	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, oidcTestRedirect) {
		t.Errorf("Location = %q, want the product's redirect_uri", location)
	}
	if !strings.Contains(location, "code=") {
		t.Errorf("Location = %q carries no authorization code", location)
	}
	if cookie := cookieNamed(rec, SessionCookieName); cookie == nil || cookie.Value == "" {
		t.Error("the password step set no session cookie for a user with no second factor")
	}
}

// ---------------------------------------------------------------------------
// the challenge step
// ---------------------------------------------------------------------------

// TestTheOIDCChallengeStepFinishesTheFlow: the code form's POST goes through
// auth.CompleteSecondFactor, so the only route that mints an authorization code for
// an MFA user is the one that presented a code.
func TestTheOIDCChallengeStepFinishesTheFlow(t *testing.T) {
	f := newOIDCMFAFixture(t, true)

	challengeForm := f.signIn(t)
	f.advance(mfa.Period + time.Second)
	rec := f.presentCode(t, challengeForm, mustTOTPCode(t, f.secret, f.clock.Now()))

	if rec.Code < 300 || rec.Code >= 400 {
		t.Fatalf("the challenge step = %d, want a redirect to the product; body:\n%s", rec.Code, rec.Body)
	}
	// The redirect to the PRODUCT is the proof: an authorization code was minted,
	// and it was only reachable through a second factor.
	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, oidcTestRedirect) || !strings.Contains(location, "code=") {
		t.Errorf("Location = %q, want the product's redirect_uri carrying a code", location)
	}
	if cookie := cookieNamed(rec, SessionCookieName); cookie == nil || cookie.Value == "" {
		t.Error("the challenge step set no session cookie")
	}
	if cookie := cookieNamed(rec, "__Host-oidc-mfa-"+f.requestID); cookie == nil || cookie.Value != "" {
		t.Error("the challenge cookie was not cleared")
	}
}

// TestTheOIDCChallengeStepAcceptsARecoveryCode: a user whose phone is at home.
func TestTheOIDCChallengeStepAcceptsARecoveryCode(t *testing.T) {
	f := newOIDCMFAFixture(t, true)

	challengeForm := f.signIn(t)
	rec := f.presentCode(t, challengeForm, f.recovery)

	if rec.Code < 300 || rec.Code >= 400 {
		t.Fatalf("a recovery code = %d, want a redirect to the product; body:\n%s", rec.Code, rec.Body)
	}
	if cookie := cookieNamed(rec, SessionCookieName); cookie == nil || cookie.Value == "" {
		t.Error("a recovery code did not produce a session")
	}
}

// TestTheOIDCChallengeStepRefusesAWrongCode says the same thing whatever went
// wrong, so the interaction is not an oracle for which part was right.
//
// THE ASSERTION IS THE STEP, and it is the same assertion the page's own markup
// used to give: a refused code sends the browser back to the CODE step, so the
// user can type the next one. A handler that answered `step=password` here would
// be refused in a way the user cannot retry.
func TestTheOIDCChallengeStepRefusesAWrongCode(t *testing.T) {
	f := newOIDCMFAFixture(t, true)
	challengeStep := f.signIn(t)

	rec := f.presentCode(t, challengeStep, "000000")

	if rec.Code != http.StatusFound {
		t.Fatalf("a wrong code = %d, want 302 back to the login UI; body:\n%s", rec.Code, rec.Body)
	}
	query := redirectQuery(t, rec)
	if got := query.Get(oidc.LoginParamStep); got != oidc.LoginStepChallenge {
		t.Errorf("%s = %q, want %q: a refused code has to send the user back to the code "+
			"box, not the password box", oidc.LoginParamStep, got, oidc.LoginStepChallenge)
	}
	if got := query.Get(oidc.LoginParamError); got != oidc.LoginErrorChallengeRejected {
		t.Errorf("%s = %q, want %q", oidc.LoginParamError, got, oidc.LoginErrorChallengeRejected)
	}
	if query.Get(oidc.LoginParamErrorDetail) == "" {
		t.Error("the refusal carried no sentence; the user is told a code failed and not why")
	}
	if cookie := cookieNamed(rec, SessionCookieName); cookie != nil && cookie.Value != "" {
		t.Error("a wrong code set a session cookie")
	}
	// THE CHALLENGE SURVIVES, and the assertion is the SECOND attempt rather than
	// the presence of a cookie on this response, because that is the direction that
	// matters: a challenge spent per attempt would reset internal/mfa's per-factor
	// counter on every try, the lockout would never trip, and a six-digit code
	// would be guessable at the rate of the HTTP round trip.
	//
	// It is a wrong code again rather than a right one, so the assertion is not
	// circular: were the challenge gone, the second POST would be answered
	// `interaction_expired` on the PASSWORD step and this would be a redirect with
	// no code on it.
	second := f.presentCode(t, rec, "000000")
	if second.Code != http.StatusFound {
		t.Fatalf("a second wrong code = %d, want 302 back to the login UI; body:\n%s",
			second.Code, second.Body)
	}
	again := redirectQuery(t, second)
	if got := again.Get(oidc.LoginParamError); got != oidc.LoginErrorChallengeRejected {
		t.Errorf("the second wrong code answered %s = %q, want %q; the first one spent the "+
			"challenge, which resets the per-factor lockout on every attempt",
			oidc.LoginParamError, got, oidc.LoginErrorChallengeRejected)
	}
	if got := again.Get(oidc.LoginParamStep); got != oidc.LoginStepChallenge {
		t.Errorf("the second wrong code landed on %s = %q, want %q", oidc.LoginParamStep,
			got, oidc.LoginStepChallenge)
	}
	if strings.Contains(rec.Header().Get("Location"), oidcTestRedirect) {
		t.Errorf("a wrong code redirected to the product, which means an authorization code "+
			"was minted: %s", rec.Header().Get("Location"))
	}
}

// TestTheOIDCChallengeStepRefusesAReplay: the same protection the JSON surface has,
// through the interaction.
func TestTheOIDCChallengeStepRefusesAReplay(t *testing.T) {
	f := newOIDCMFAFixture(t, true)

	challengeStep := f.signIn(t)
	f.advance(mfa.Period + time.Second)
	captured := mustTOTPCode(t, f.secret, f.clock.Now())

	if rec := f.presentCode(t, challengeStep, captured); rec.Code < 300 || rec.Code >= 400 {
		t.Fatalf("the first use = %d, want a redirect; body:\n%s", rec.Code, rec.Body)
	}

	// A fresh login, then the same code.
	second := f.signIn(t)
	rec := f.presentCode(t, second, captured)
	if rec.Code != http.StatusFound {
		t.Errorf("a replayed code = %d, want 302 back to the login UI; body:\n%s", rec.Code, rec.Body)
	}
	query := redirectQuery(t, rec)
	if got := query.Get(oidc.LoginParamError); got != oidc.LoginErrorChallengeRejected {
		t.Errorf("%s = %q, want %q", oidc.LoginParamError, got, oidc.LoginErrorChallengeRejected)
	}
	if strings.Contains(rec.Header().Get("Location"), oidcTestRedirect) {
		t.Error("a replayed code redirected to the product, which means an authorization " +
			"code was minted")
	}
}

// TestTheOIDCChallengeStepWithoutAChallengeGoesBackToThePasswordStep: a POST with a
// code and no cookie is not a login, it is a guess — and the answer is the
// password step, because there is no challenge left to answer.
func TestTheOIDCChallengeStepWithoutAChallengeGoesBackToThePasswordStep(t *testing.T) {
	f := newOIDCMFAFixture(t, true)
	// A FRESH GET for a valid sealed state, and then the challenge cookie is thrown
	// away — which is a browser that opened the form and lost the challenge, and is
	// the case worth testing. Using a stale state instead would be answered by the
	// CSRF check first, which is a different test with a different answer.
	page := f.loginPage(t)
	delete(f.jar.cookies, OIDCChallengeCookiePrefix+f.requestID)

	rec := f.submit(t, url.Values{"state": {stateFromRedirect(t, page)}, "code": {"123456"}})
	if rec.Code != http.StatusFound {
		t.Fatalf("a code with no challenge = %d, want 302 back to the login UI; body:\n%s", rec.Code, rec.Body)
	}
	query := redirectQuery(t, rec)
	if got := query.Get(oidc.LoginParamError); got != oidc.LoginErrorInteractionExpired {
		t.Errorf("%s = %q, want %q", oidc.LoginParamError, got, oidc.LoginErrorInteractionExpired)
	}
	// The PASSWORD step, and this is the assertion worth having: a challenge that
	// is gone cannot be answered, so sending the user back to a code box would be a
	// sign-in that can never complete.
	if got := query.Get(oidc.LoginParamStep); got != oidc.LoginStepPassword {
		t.Errorf("%s = %q, want %q", oidc.LoginParamStep, got, oidc.LoginStepPassword)
	}
}

// TestTheOIDCChallengeStepLockoutCarriesItsWaitToTheLoginUI is the per-factor
// lockout seen from the sign-in form, which is where a user actually meets it — and
// the `retry_after` is the whole point of the assertion.
//
// THE 423 BECAME A 302 CARRYING A NUMBER, and the reason is that a browser
// following a redirect does not read a `Retry-After` header. Before this packet the
// wait was rendered into the page as "Too many attempts. Try again in 15m."; now it
// has to cross an origin boundary as data, and a lockout whose wait the UI cannot
// see is a lockout the user experiences as a frozen page that will keep failing.
func TestTheOIDCChallengeStepLockoutCarriesItsWaitToTheLoginUI(t *testing.T) {
	f := newOIDCMFAFixture(t, true)

	for range 5 {
		step := f.signIn(t)
		if rec := f.presentCode(t, step, "000000"); rec.Code != http.StatusFound {
			t.Fatalf("a wrong code = %d, want 302 back to the login UI", rec.Code)
		}
	}

	step := f.signIn(t)
	rec := f.presentCode(t, step, "000000")
	if rec.Code != http.StatusFound {
		t.Fatalf("the attempt past the threshold = %d, want 302 back to the login UI; body:\n%s",
			rec.Code, rec.Body)
	}
	query := redirectQuery(t, rec)
	if got := query.Get(oidc.LoginParamError); got != oidc.LoginErrorAccountLocked {
		t.Errorf("%s = %q, want %q", oidc.LoginParamError, got, oidc.LoginErrorAccountLocked)
	}
	if got := query.Get(oidc.LoginParamStep); got != oidc.LoginStepChallenge {
		t.Errorf("%s = %q, want %q; the lockout is on the second factor, so the user is "+
			"still on the code step", oidc.LoginParamStep, got, oidc.LoginStepChallenge)
	}
	if query.Get(oidc.LoginParamErrorDetail) == "" {
		t.Error("the lockout carried no sentence")
	}
	// THE WAIT. Absent, this is a lockout the user experiences as a page that will
	// keep failing, and it is the one piece of the old 423 that could not simply
	// disappear.
	wait := query.Get(oidc.LoginParamRetryAfter)
	if wait == "" {
		t.Errorf("the lockout carried no %s; the user is not told how long to wait",
			oidc.LoginParamRetryAfter)
	} else if seconds, err := strconv.Atoi(wait); err != nil || seconds <= 0 {
		t.Errorf("%s = %q, want a positive whole number of seconds", oidc.LoginParamRetryAfter, wait)
	}
	if cookie := cookieNamed(rec, SessionCookieName); cookie != nil && cookie.Value != "" {
		t.Error("a locked second factor produced a session")
	}
}

// TestTheChallengeStepIsReachableOnlyThroughTheOIDCPath asserts the routing
// decision: POST /v1/session/mfa is on /v1 and NOT on /oidc, because /oidc answers
// RFC 6749's error shape and a cafaye problem document there would be a shape a
// client library cannot parse.
func TestTheChallengeStepIsReachableOnlyThroughTheOIDCPath(t *testing.T) {
	f := newOIDCMFAFixture(t, true)
	_ = f.signIn(t)

	// /oidc/session/mfa does not exist, and the miss is the service's own problem
	// document rather than net/http's plain text — which is what the two-shape rule
	// in AGENTS.md is about.
	rec := f.send(t, http.MethodPost, "/oidc/session/mfa", "", url.Values{"code": {"123456"}})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("/oidc/session/mfa = %d, want 404; body: %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", got)
	}
}

// compile-time proof the fixture's dependencies are the ones it claims.
var (
	_ = dbtest.Pool
	_ = outbox.NewStore
)
