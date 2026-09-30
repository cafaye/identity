package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cafaye/identity/internal/mfa"
	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
)

// Every test in this file runs the real router, the real use cases and the real SQL
// over a private schema, because the properties being asserted are properties of
// the WIRE and of the sessions table: what a caller receives, and whether a
// credential exists behind it.

// mfaServer is a test server with the MFA surface mounted.
type mfaServer struct {
	handler http.Handler
	pool    *pgxpool.Pool
	clock   *clock.Fake
	second  *mfa.Service
	// token is the current session token for the fixture's user. It is REFRESHED
	// after an enrollment, because confirming one revokes every session the user
	// holds — including the one the enrollment was made with. That is the packet's
	// requirement stated as a fact about the fixture, and a test that forgot to
	// re-login would see 401s on every subsequent request.
	token string
	// userID is the fixture's user, remembered from signUp rather than looked up
	// afterwards: an enrollment and a disable both empty the sessions table, and a
	// helper that found the user by "whichever session exists" would break exactly
	// when a test is asserting that a session was revoked.
	userID id.UUID
	// user is the enrolled factor the fixture's own sign-in used, kept so the
	// authorization matrix can produce a fresh code without threading it through
	// every row of its table.
	user enrolledUser
	// pendingID and pendingCode are a PENDING enrollment the fixture owns, for the
	// confirm row of that matrix.
	pendingID   string
	pendingCode string
	// logs is the handler every request's log record goes to, so the canary test can
	// render them. Every other test in this package uses one too and ignores it.
	logs *recordingHandler
	// email is the fixture's address, kept for the tests that make several requests
	// to the same user without holding signUp's return value.
	email string
}

func newMFAServer(t *testing.T) *mfaServer {
	t.Helper()

	pool := dbtest.Schema(t)
	clk := clock.NewFake(time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))
	second := testMFAService(pool, clk)
	svc := authServiceFor(pool, clk)

	logs := &recordingHandler{}
	return &mfaServer{
		handler: New(nil,
			WithAuth(svc),
			WithMFA(second),
			WithLogger(slogLogger(logs)),
		),
		pool:   pool,
		clock:  clk,
		second: second,
		logs:   logs,
	}
}

// newCanaryServer is newMFAServer for the logging canary: the same real wiring, with
// the log handler reachable so its records can be rendered.
func newCanaryServer(t *testing.T) *mfaServer {
	t.Helper()

	s := newMFAServer(t)
	s.email, s.token = s.signUp(t)
	return s
}

// rendered is every captured log record as ONE string: message plus every attribute,
// key and value, in order. Asserting on this is what makes the canary assertion
// about every attribute rather than about the ones somebody thought of.
func (h *recordingHandler) rendered() string {
	var b strings.Builder
	for _, entry := range h.entries {
		b.WriteString(entry)
		b.WriteString("\n")
	}
	return b.String()
}

// signUp registers a user and returns their session token.
func (s *mfaServer) signUp(t *testing.T) (email, token string) {
	t.Helper()

	email = dbtest.UniqueEmail(t)
	s.email = email
	s.token = ""
	s.userID = id.UUID{}
	rec := post(t, s.handler, "/v1/users",
		`{"email":"`+email+`","password":"`+matrixPassword+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /v1/users = %d, want 201; body: %s", rec.Code, rec.Body)
	}
	var created userResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("the registration body is not JSON: %v", err)
	}

	login := post(t, s.handler, "/v1/session", `{"email":"`+email+`","password":"`+matrixPassword+`"}`)
	if login.Code != http.StatusOK {
		t.Fatalf("POST /v1/session = %d, want 200; body: %s", login.Code, login.Body)
	}
	var session sessionResponse
	if err := json.Unmarshal(login.Body.Bytes(), &session); err != nil {
		t.Fatalf("the login body is not JSON: %v", err)
	}
	s.token = session.Token
	parsed, err := id.Parse(created.ID)
	if err != nil {
		t.Fatalf("parsing the registered id: %v", err)
	}
	s.userID = parsed
	return email, session.Token
}

// signInWithFactor is the whole login for an account with MFA: POST /v1/session
// answers 202, and POST /v1/session/mfa turns the challenge into a session.
//
// It is what a client does, and the fixture does it rather than reaching into the
// sessions table — a helper that wrote a session row directly would make every
// "no session was issued" assertion in this package meaningless, because the only
// thing it could then prove is that the helper had not been called.
func (s *mfaServer) signInWithFactor(t *testing.T, email string, user enrolledUser) string {
	t.Helper()

	rec := post(t, s.handler, "/v1/session", `{"email":"`+email+`","password":"`+matrixPassword+`"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /v1/session = %d, want 202; body: %s", rec.Code, rec.Body)
	}
	var challengeBody challengeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &challengeBody); err != nil {
		t.Fatalf("the 202 body is not JSON: %v", err)
	}

	// A fresh period, so the code this fixture presents has not been spent by
	// whatever the test did before calling here.
	s.clock.Advance(mfa.Period + time.Second)
	finished := s.post(t, "/v1/session/mfa", "",
		`{"challenge":"`+challengeBody.Challenge+`","code":"`+user.code(t, s.clock.Now())+`"}`)
	if finished.Code != http.StatusOK {
		t.Fatalf("POST /v1/session/mfa = %d, want 200; body: %s", finished.Code, finished.Body)
	}
	var session sessionResponse
	if err := json.Unmarshal(finished.Body.Bytes(), &session); err != nil {
		t.Fatalf("the login body is not JSON: %v", err)
	}
	s.token = session.Token
	return session.Token
}

// ---------------------------------------------------------------------------
// POST /v1/session — the 202 branch
// ---------------------------------------------------------------------------

// TestACorrectPasswordAnswers202WithAChallengeAndNoSession is the packet's central
// property at the HTTP layer: the status says the login is unfinished, the body has
// no `token` key at all, and no session row exists.
//
// The `token` key is checked for ABSENCE rather than for emptiness. A client that
// reads `body.token` finds nothing, which is unambiguous; a client that finds an
// empty string has to know what that means.
func TestACorrectPasswordAnswers202WithAChallengeAndNoSession(t *testing.T) {
	s := newMFAServer(t)
	email, token := s.signUp(t)

	created := s.post(t, "/v1/mfa/enrollments", token, `{}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("POST /v1/mfa/enrollments = %d, want 201; body: %s", created.Code, created.Body)
	}
	var started struct {
		EnrollmentID    string `json:"enrollment_id"`
		Secret          string `json:"secret"`
		ProvisioningURI string `json:"provisioning_uri"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &started); err != nil {
		t.Fatalf("the enrollment body is not JSON: %v\n%s", err, created.Body)
	}
	if started.EnrollmentID == "" || started.Secret == "" || started.ProvisioningURI == "" {
		t.Fatalf("the enrollment response is missing a field: %s", created.Body)
	}
	code, err := mfa.Code(started.Secret, s.clock.Now())
	if err != nil {
		t.Fatalf("mfa.Code: %v", err)
	}
	confirmed := s.post(t, "/v1/mfa/enrollments/"+started.EnrollmentID+"/confirm", token,
		`{"code":"`+code+`"}`)
	if confirmed.Code != http.StatusOK {
		t.Fatalf("confirm = %d, want 200; body: %s", confirmed.Code, confirmed.Body)
	}

	// And now the login.
	rec := post(t, s.handler, "/v1/session", `{"email":"`+email+`","password":"`+matrixPassword+`"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /v1/session = %d, want 202; body: %s", rec.Code, rec.Body)
	}

	// The body has no `token` key.
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("the 202 body is not JSON: %v\n%s", err, rec.Body)
	}
	if _, present := raw["token"]; present {
		t.Errorf("the 202 body carries a `token` key: %s", rec.Body)
	}
	if raw["mfa_required"] != true {
		t.Errorf("mfa_required = %v, want true", raw["mfa_required"])
	}
	challenge, _ := raw["challenge"].(string)
	if challenge == "" {
		t.Fatalf("the 202 body carries no challenge: %s", rec.Body)
	}

	// NO SESSION COOKIE. This is the assertion that a return-value test cannot make.
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == SessionCookieName {
			t.Fatal("the 202 set a session cookie; a challenge is not a session")
		}
		if cookie.Value == "" {
			t.Errorf("cookie %q is empty, which clears it rather than setting it", cookie.Name)
		}
	}
	if !hasCookie(rec, MFAChallengeCookieName, challenge) {
		t.Errorf("the 202 did not set the %s cookie to the challenge token", MFAChallengeCookieName)
	}

	// And no session row.
	if got := s.totalSessions(t); got != 0 {
		t.Errorf("%d session rows exist after a login waiting on a second factor", got)
	}
}

// TestTheChallengeIsACookieAndNotASessionOnDisk says the same thing from the other
// side: presenting the challenge token as a bearer credential resolves to nothing.
func TestTheChallengeIsACookieAndNotASessionOnDisk(t *testing.T) {
	s := newMFAServer(t)
	email, token := s.signUp(t)
	user := s.enrollAndConfirmFor(t, email, token)

	rec := post(t, s.handler, "/v1/session", `{"email":"`+email+`","password":"`+matrixPassword+`"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /v1/session = %d, want 202", rec.Code)
	}
	var body challengeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the 202 body is not JSON: %v", err)
	}

	// The challenge token is not a session token.
	me := sendWith(t, s.handler, http.MethodGet, "/v1/me", body.Challenge, "", "")
	if me.Code != http.StatusUnauthorized {
		t.Errorf("GET /v1/me with the challenge token = %d, want 401", me.Code)
	}
	// And it is not a usable challenge on its own either: it needs a code. The
	// count is RELATIVE, because the fixture has already signed this user in to
	// establish the enrollment — an absolute zero here would be asserting about the
	// fixture rather than about the code.
	before := s.sessionsForID(t, s.userIDFor(t))
	finished := s.post(t, "/v1/session/mfa", "", `{"challenge":"`+body.Challenge+`","code":"000000"}`)
	if finished.Code == http.StatusOK {
		t.Error("a wrong code produced a session")
	}
	if got := s.sessionsForID(t, s.userIDFor(t)); got != before {
		t.Errorf("%d sessions after a wrong code, want the fixture's %d", got, before)
	}

	// The right code on the same challenge finishes the login, and there is then
	// exactly ONE MORE session — which is the other half of "one code, one session".
	//
	// The challenge goes in the BODY here, as an API client would send it. The
	// cookie route is covered by TestTheBrowserCookieFinishesTheLoginToo, because
	// a client that can only use a cookie and a client that can only use a body are
	// different claims and each needs its own test.
	s.clock.Advance(mfa.Period + time.Second)
	ok := s.post(t, "/v1/session/mfa", "",
		`{"challenge":"`+body.Challenge+`","code":"`+user.code(t, s.clock.Now())+`"}`)
	if ok.Code != http.StatusOK {
		t.Fatalf("POST /v1/session/mfa = %d, want 200; body: %s", ok.Code, ok.Body)
	}
	if cookie := cookieNamed(ok, SessionCookieName); cookie == nil || cookie.Value == "" {
		t.Error("the 200 did not set a session cookie")
	}
	if cookie := cookieNamed(ok, MFAChallengeCookieName); cookie == nil || cookie.Value != "" {
		t.Error("the 200 did not clear the challenge cookie")
	}
	if got := s.sessionsForID(t, s.userIDFor(t)); got != before+1 {
		t.Errorf("%d sessions after a completed login, want %d", got, before+1)
	}
	var session sessionResponse
	if err := json.Unmarshal(ok.Body.Bytes(), &session); err != nil {
		t.Fatalf("the 200 body is not a session: %v\n%s", err, ok.Body)
	}
	if session.Token == "" {
		t.Fatal("the 200 body carries no token")
	}
}

func (s *mfaServer) totalSessions(t *testing.T) int {
	t.Helper()
	var n int
	if err := s.pool.QueryRow(t.Context(), `SELECT count(*) FROM sessions`).Scan(&n); err != nil {
		t.Fatalf("counting sessions: %v", err)
	}
	return n
}

// hasCookie reports whether a response set name to value.
func hasCookie(rec *httptest.ResponseRecorder, name, value string) bool {
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == name && cookie.Value == value {
			return true
		}
	}
	return false
}

// cookieNamed returns the cookie a response set under name, or nil. A cookie with
// an empty value is a deletion, which is why the value is left to the caller.
func cookieNamed(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func (s *mfaServer) post(t *testing.T, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	return sendWith(t, s.handler, http.MethodPost, path, token, "", body)
}

func (s *mfaServer) del(t *testing.T, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	return sendWith(t, s.handler, http.MethodDelete, path, token, "", body)
}

func (s *mfaServer) get(t *testing.T, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	return sendWith(t, s.handler, http.MethodGet, path, token, "", "")
}

// enrollAndConfirm runs the whole flow over HTTP and returns the enrolled user.
func (s *mfaServer) enrollAndConfirm(t *testing.T, email string) enrolledUser {
	t.Helper()
	return s.enrollAndConfirmFor(t, email, "")
}

func (s *mfaServer) enrollAndConfirmFor(t *testing.T, email, token string) enrolledUser {
	t.Helper()

	if token == "" {
		_, token = s.signUp(t)
	}
	_ = email

	created := s.post(t, "/v1/mfa/enrollments", token, `{}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("POST /v1/mfa/enrollments = %d; body: %s", created.Code, created.Body)
	}
	var started struct {
		EnrollmentID string `json:"enrollment_id"`
		Secret       string `json:"secret"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &started); err != nil {
		t.Fatalf("the enrollment body is not JSON: %v\n%s", err, created.Body)
	}

	code, err := mfa.Code(started.Secret, s.clock.Now())
	if err != nil {
		t.Fatalf("mfa.Code: %v", err)
	}
	confirmed := s.post(t, "/v1/mfa/enrollments/"+started.EnrollmentID+"/confirm", token,
		`{"code":"`+code+`"}`)
	if confirmed.Code != http.StatusOK {
		t.Fatalf("confirm = %d, want 200; body: %s", confirmed.Code, confirmed.Body)
	}
	var body struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if err := json.Unmarshal(confirmed.Body.Bytes(), &body); err != nil {
		t.Fatalf("the confirmation body is not JSON: %v", err)
	}
	if len(body.RecoveryCodes) != mfa.RecoveryCodeCount {
		t.Fatalf("%d recovery codes, want %d", len(body.RecoveryCodes), mfa.RecoveryCodeCount)
	}

	holds := enrolledUser{User: s.userID, Secret: started.Secret, RecoveryCode: body.RecoveryCodes[0]}
	s.user = holds

	// The confirmation revoked every session this user had, the one the enrollment
	// was made with included — so the fixture has to log in again, which for an
	// enrolled user means a second factor. That is a real client's sequence and it
	// is why s.token exists.
	s.signInWithFactor(t, email, holds)
	return holds
}
