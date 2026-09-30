package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/auth"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/users"
)

// slogLogger wraps the existing recordingHandler from httpapi_test.go so a test
// can assert on what the service logged rather than on stderr.
func slogLogger(h slog.Handler) *slog.Logger { return slog.New(h) }

// decodeJSON is a small alias so the tests do not each import encoding/json
// error handling.
func decodeJSON(data []byte, v any) error { return json.Unmarshal(data, v) }

// parseUUIDish is deliberately loose: the trace tests care that a generated trace
// id looks like an identifier, not that it is a valid UUID version.
func parseUUIDish(s string) (string, error) {
	if len(s) != 36 {
		return "", errors.New("not 36 characters")
	}
	for i, r := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if r != '-' {
				return "", errors.New("dash in the wrong place")
			}
			continue
		}
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return "", errors.New("not lower-case hex")
		}
	}
	return s, nil
}

// fakeAuth is a programmable stand-in for auth.Service, so the handlers can be
// exercised for status codes, headers and cookie attributes without a database.
// The end-to-end suite (auth_routes_integration_test.go) runs the same requests
// through the real service and a real Postgres.

type fakeAuth struct {
	mu sync.Mutex

	user  users.User
	token string
	login auth.LoginResult

	registerErr error
	loginErr    error
	authErr     error
	logoutErr   error
	// secondFactorErr is returned by CompleteSecondFactor.
	secondFactorErr error
	// secondFactor is the result CompleteSecondFactor returns.
	secondFactor auth.LoginResult

	// recorded inputs
	registered []auth.RegisterInput
	loggedIn   []auth.LoginInput
	loggedOut  []string
	// completed records the challenges CompleteSecondFactor was handed, so a test
	// can prove which token the handler read and from where.
	completed []auth.CompleteSecondFactorInput
	// lastAuthToken is the credential Authenticate was handed, so a test can
	// prove which surface the handler read it from.
	lastAuthToken string
}

func newFakeAuth() *fakeAuth {
	var uid id.UUID
	uid[0] = 0xab
	return &fakeAuth{
		user:  users.User{ID: uid, Email: "kaka@example.com"},
		token: "a-session-token",
		login: auth.LoginResult{
			User:      auth.RegisteredUser{ID: uid, Email: "kaka@example.com"},
			Token:     "a-session-token",
			ExpiresAt: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
		},
		secondFactor: auth.LoginResult{
			User:      auth.RegisteredUser{ID: uid, Email: "kaka@example.com"},
			Token:     "a-second-factor-token",
			ExpiresAt: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
		},
	}
}

func (f *fakeAuth) CompleteSecondFactor(_ context.Context, in auth.CompleteSecondFactorInput) (auth.LoginResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.completed = append(f.completed, in)
	if f.secondFactorErr != nil {
		return auth.LoginResult{}, f.secondFactorErr
	}
	return f.secondFactor, nil
}

func (f *fakeAuth) Register(_ context.Context, in auth.RegisterInput) (auth.RegisteredUser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.registered = append(f.registered, in)
	if f.registerErr != nil {
		return auth.RegisteredUser{}, f.registerErr
	}
	return auth.RegisteredUser{ID: f.user.ID, Email: f.user.Email}, nil
}

func (f *fakeAuth) Login(_ context.Context, in auth.LoginInput) (auth.LoginResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loggedIn = append(f.loggedIn, in)
	if f.loginErr != nil {
		return auth.LoginResult{}, f.loginErr
	}
	return f.login, nil
}

func (f *fakeAuth) Authenticate(_ context.Context, token string) (users.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastAuthToken = token
	if f.authErr != nil {
		return users.User{}, f.authErr
	}
	return f.user, nil
}

func (f *fakeAuth) Logout(_ context.Context, token string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loggedOut = append(f.loggedOut, token)
	return f.logoutErr
}

// post sends a JSON body and returns the recorder.
func post(t *testing.T, h http.Handler, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	return send(t, h, http.MethodPost, target, body)
}

func send(t *testing.T, h http.Handler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()

	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeProblem(t *testing.T, rec *httptest.ResponseRecorder) Problem {
	t.Helper()

	if got, want := rec.Header().Get("Content-Type"), "application/problem+json"; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}
	var p Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("the body is not a problem document: %v\n%s", err, rec.Body)
	}
	return p
}

// ---------------------------------------------------------------------------
// POST /v1/users
// ---------------------------------------------------------------------------

func TestRegisterHappyPath(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	rec := post(t, New(nil, WithAuth(f)), "/v1/users", `{"email":"kaka@example.com","password":"correct horse battery"}`)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", rec.Code, rec.Body)
	}
	if got, want := rec.Header().Get("Content-Type"), "application/json; charset=utf-8"; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}

	var body struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not JSON: %v\n%s", err, rec.Body)
	}
	if body.Email != "kaka@example.com" {
		t.Errorf("email = %q, want kaka@example.com", body.Email)
	}
	if body.ID != f.user.ID.String() {
		t.Errorf("id = %q, want %q", body.ID, f.user.ID)
	}

	// The response is a projection, and the projection has exactly two fields. A
	// digest reaching a registration response would be the worst leak in this
	// service; a row count here is what makes that a test failure rather than a
	// code review's memory.
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("the body is not a JSON object: %v", err)
	}
	if len(raw) != 2 {
		t.Errorf("the response has %d fields (%v), want exactly id and email", len(raw), raw)
	}
	for _, forbidden := range []string{"password", "digest", "password_digest", "locked_until", "failed_login_attempts"} {
		if _, present := raw[forbidden]; present {
			t.Errorf("the response carries %q", forbidden)
		}
	}
}

// Registration is the one endpoint that may reveal that an address is taken: the
// caller supplied it, and the alternative is letting them pick a password against
// an account they cannot have.
func TestRegisterDuplicateEmailIs409(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	f.registerErr = users.ErrEmailTaken

	rec := post(t, New(nil, WithAuth(f)), "/v1/users", `{"email":"kaka@example.com","password":"correct horse battery"}`)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body: %s", rec.Code, rec.Body)
	}
	p := decodeProblem(t, rec)
	if p.Code != CodeConflict {
		t.Errorf("code = %q, want %q", p.Code, CodeConflict)
	}
	if p.Type != errorTypeBase+CodeConflict {
		t.Errorf("type = %q, want %q", p.Type, errorTypeBase+CodeConflict)
	}
	if p.Status != http.StatusConflict {
		t.Errorf("body status = %d, want 409", p.Status)
	}
	if p.TraceID == "" {
		t.Error("trace_id is empty")
	}
}

// The 422 mapping is the *handler's* job: turning a domain FieldError into core's
// errors[] array. Deciding that a password is too short belongs to the service,
// and TestRegisterValidationEndToEnd in the integration suite proves that with the
// real one. What is asserted here is that a FieldError crosses the boundary
// faithfully, because that is what this layer can get wrong.
func TestRegisterFieldErrorBecomes422WithErrorsArray(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		err       error
		wantField string
		wantCode  string
	}{
		{
			name:      "a short password",
			err:       &users.FieldError{Field: "password", Code: "too_short"},
			wantField: "password",
			wantCode:  "too_short",
		},
		{
			name:      "a malformed address",
			err:       &users.FieldError{Field: "email", Code: "invalid_format"},
			wantField: "email",
			wantCode:  "invalid_format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFakeAuth()
			f.registerErr = tt.err

			rec := post(t, New(nil, WithAuth(f)), "/v1/users",
				`{"email":"kaka@example.com","password":"correct horse battery"}`)

			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422; body: %s", rec.Code, rec.Body)
			}
			p := decodeProblem(t, rec)
			if p.Code != CodeValidationFailed {
				t.Errorf("code = %q, want %q", p.Code, CodeValidationFailed)
			}
			if p.Type != errorTypeBase+CodeValidationFailed {
				t.Errorf("type = %q, want %q", p.Type, errorTypeBase+CodeValidationFailed)
			}
			if len(p.Errors) != 1 {
				t.Fatalf("errors has %d entries, want 1: %+v", len(p.Errors), p.Errors)
			}
			if p.Errors[0].Field != tt.wantField || p.Errors[0].Code != tt.wantCode {
				t.Errorf("errors[0] = %+v, want %s/%s", p.Errors[0], tt.wantField, tt.wantCode)
			}

			// The submitted password must not be echoed back in the detail.
			if strings.Contains(rec.Body.String(), "correct horse") {
				t.Errorf("the 422 echoes the submitted password: %s", rec.Body)
			}
		})
	}
}

// A body that is not JSON at all is 400, not 422. core: "400 only for malformed
// syntax the client could not have known; anything semantically wrong is 422."
func TestRegisterMalformedJSONIs400(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{name: "truncated", body: `{"email":"kaka@example.com"`},
		{name: "not an object", body: `["kaka@example.com"]`},
		{name: "not JSON at all", body: `this is not json`},
		{name: "an empty body", body: ``},
		{name: "a JSON null", body: `null`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFakeAuth()
			rec := post(t, New(nil, WithAuth(f)), "/v1/users", tt.body)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body)
			}
			p := decodeProblem(t, rec)
			if p.Code != CodeInvalidJSON {
				t.Errorf("code = %q, want %q", p.Code, CodeInvalidJSON)
			}
			if p.Errors != nil {
				t.Errorf("errors = %v on a 400, want none; core scopes errors[] to 422", p.Errors)
			}
		})
	}
}

// An unauthenticated caller must not be able to make the service hash a
// gigabyte.
func TestRegisterRejectsAnOversizedBody(t *testing.T) {
	t.Parallel()

	huge := `{"email":"kaka@example.com","password":"` + strings.Repeat("a", maxRequestBody) + `"}`

	f := newFakeAuth()
	rec := post(t, New(nil, WithAuth(f)), "/v1/users", huge)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body: %s", rec.Code, rec.Body)
	}
	p := decodeProblem(t, rec)
	if p.Code != CodePayloadTooLarge {
		t.Errorf("code = %q, want %q", p.Code, CodePayloadTooLarge)
	}
	if f.hasRegistered() {
		t.Error("an oversized body reached the service")
	}
}

func TestRegisterUnknownFieldsAreRejected(t *testing.T) {
	t.Parallel()

	// A typo in a client ("emial") that is silently ignored produces an account
	// with an address the caller did not choose, and an error message that points
	// at nothing.
	f := newFakeAuth()
	rec := post(t, New(nil, WithAuth(f)), "/v1/users", `{"emial":"kaka@example.com","password":"correct horse battery"}`)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body: %s", rec.Code, rec.Body)
	}
	p := decodeProblem(t, rec)
	if p.Code != CodeValidationFailed {
		t.Errorf("code = %q, want %q", p.Code, CodeValidationFailed)
	}
}

// ---------------------------------------------------------------------------
// POST /v1/session
// ---------------------------------------------------------------------------

func TestLoginHappyPathSetsTheHostCookieAndReturnsTheToken(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	rec := post(t, New(nil, WithAuth(f)), "/v1/session", `{"email":"kaka@example.com","password":"correct horse battery"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	// The API surface: the token in the body.
	var body struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not JSON: %v\n%s", err, rec.Body)
	}
	if body.Token != f.login.Token {
		t.Errorf("token = %q, want %q", body.Token, f.login.Token)
	}
	if !body.ExpiresAt.Equal(f.login.ExpiresAt) {
		t.Errorf("expires_at = %s, want %s", body.ExpiresAt, f.login.ExpiresAt)
	}

	// The browser surface: the same value in a hardened cookie.
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want exactly 1: %+v", len(cookies), cookies)
	}
	c := cookies[0]

	// The __Host- prefix is a browser-enforced contract: a cookie carrying it is
	// accepted only when Secure is set, Path is /, and there is no Domain. Getting
	// any of those wrong means the browser silently drops the cookie, and the
	// symptom is a user who logs in and is not logged in.
	if c.Name != SessionCookieName {
		t.Errorf("cookie name = %q, want %q", c.Name, SessionCookieName)
	}
	if !strings.HasPrefix(c.Name, "__Host-") {
		t.Errorf("cookie name %q does not carry the __Host- prefix, so it is not origin-bound", c.Name)
	}
	if !c.Secure {
		t.Error("cookie is not Secure; a __Host- cookie without Secure is rejected by the browser")
	}
	if c.Path != "/" {
		t.Errorf("cookie Path = %q, want /", c.Path)
	}
	if c.Domain != "" {
		t.Errorf("cookie Domain = %q, want empty; a __Host- cookie with a Domain is rejected", c.Domain)
	}
	if !c.HttpOnly {
		t.Error("cookie is not HttpOnly, so a script can read the session token")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie SameSite = %v, want Lax", c.SameSite)
	}
	if c.Value != f.login.Token {
		t.Errorf("cookie value = %q, want the token %q", c.Value, f.login.Token)
	}
	if c.Expires.IsZero() {
		t.Error("cookie has no expiry, so it dies when the browser closes")
	}
}

// A wrong password and an unknown address are one answer. The body, the status
// and the wording are all identical, and neither mentions which.
func TestLoginRefusalIsGeneric(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
	}{
		{name: "wrong credentials", err: auth.ErrInvalidCredentials},
		{name: "an unknown account", err: auth.ErrInvalidCredentials},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFakeAuth()
			f.loginErr = tt.err

			rec := post(t, New(nil, WithAuth(f)), "/v1/session", `{"email":"kaka@example.com","password":"wrong"}`)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401; body: %s", rec.Code, rec.Body)
			}
			p := decodeProblem(t, rec)
			if p.Code != CodeUnauthorized {
				t.Errorf("code = %q, want %q", p.Code, CodeUnauthorized)
			}
			// The detail must not distinguish the two cases.
			if strings.Contains(strings.ToLower(p.Detail), "no such") ||
				strings.Contains(strings.ToLower(p.Detail), "unknown") ||
				strings.Contains(strings.ToLower(p.Detail), "not found") {
				t.Errorf("detail %q reveals whether the account exists", p.Detail)
			}
			// And no cookie is set on a refusal.
			if cookies := rec.Result().Cookies(); len(cookies) != 0 {
				t.Errorf("a refused login set %d cookies", len(cookies))
			}
		})
	}
}

// A locked account gets 423 and the remaining window, in the body and in a header
// a client can read without parsing JSON.
func TestLoginLockedIs423WithRetryAfter(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	f.loginErr = &auth.LockedError{RetryAfter: 7 * time.Minute}

	rec := post(t, New(nil, WithAuth(f)), "/v1/session", `{"email":"kaka@example.com","password":"correct horse battery"}`)

	if rec.Code != http.StatusLocked {
		t.Fatalf("status = %d, want 423; body: %s", rec.Code, rec.Body)
	}
	p := decodeProblem(t, rec)
	if p.Code != CodeAccountLocked {
		t.Errorf("code = %q, want %q", p.Code, CodeAccountLocked)
	}
	if p.Status != http.StatusLocked {
		t.Errorf("body status = %d, want 423", p.Status)
	}

	// The window is in the header, in the unit RFC 9110 defines Retry-After in.
	if got, want := rec.Header().Get(RetryAfterHeader), "420"; got != want {
		t.Errorf("%s = %q, want %q seconds", RetryAfterHeader, got, want)
	}
	// And in the detail, so a human reading the response can act on it.
	if !strings.Contains(p.Detail, "420") {
		t.Errorf("detail %q does not say how long to wait", p.Detail)
	}
	// It must NOT be an errors[] entry: core scopes that array to 422 and to
	// per-field request failures, and "retry_after" is not a field anyone typed.
	if p.Errors != nil {
		t.Errorf("errors = %v on a 423, want none; core scopes errors[] to 422", p.Errors)
	}
	// A locked account gets no session.
	if cookies := rec.Result().Cookies(); len(cookies) != 0 {
		t.Errorf("a locked login set %d cookies", len(cookies))
	}
}

// Retry-After is rounded up: telling a client to wait 419.7 seconds when 420
// remain is a rounding error in the client's disfavour for no reason.
func TestRetryAfterSecondsRoundsUp(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give time.Duration
		want string
	}{
		{name: "exactly a minute", give: time.Minute, want: "60"},
		{name: "with a remainder rounds up", give: 90 * time.Second, want: "90"},
		{name: "a millisecond over a second", give: time.Second + time.Millisecond, want: "2"},
		{name: "a single second", give: time.Second, want: "1"},
		{name: "zero", give: 0, want: "0"},
		{name: "negative clamps to zero", give: -time.Minute, want: "0"},
		{name: "fifteen minutes", give: 15 * time.Minute, want: "900"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := retryAfterSeconds(tt.give); got != tt.want {
				t.Errorf("retryAfterSeconds(%s) = %q, want %q", tt.give, got, tt.want)
			}
		})
	}
}

func TestLoginRecordsRequestMetadata(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	req := httptest.NewRequest(http.MethodPost, "/v1/session",
		strings.NewReader(`{"email":"kaka@example.com","password":"correct horse battery"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "integration-test/1.0")
	req.RemoteAddr = "203.0.113.7:54321"

	rec := httptest.NewRecorder()
	New(nil, WithAuth(f)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	inputs := f.loginInputs()
	if len(inputs) != 1 {
		t.Fatalf("Login was called %d times, want 1", len(inputs))
	}
	if inputs[0].UserAgent != "integration-test/1.0" {
		t.Errorf("UserAgent = %q, want the request's", inputs[0].UserAgent)
	}
	if inputs[0].IP == nil || inputs[0].IP.String() != "203.0.113.7" {
		t.Errorf("IP = %v, want 203.0.113.7 parsed from RemoteAddr", inputs[0].IP)
	}
}

// A RemoteAddr that is not an IP (some proxies set arbitrary values) must not
// fail the login.
func TestLoginToleratesAnUnparseableRemoteAddr(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	req := httptest.NewRequest(http.MethodPost, "/v1/session",
		strings.NewReader(`{"email":"kaka@example.com","password":"correct horse battery"}`))
	req.RemoteAddr = "not-an-address"

	rec := httptest.NewRecorder()
	New(nil, WithAuth(f)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if inputs := f.loginInputs(); len(inputs) != 1 || inputs[0].IP != nil {
		t.Errorf("IP = %v, want nil for an unparseable RemoteAddr", inputs[0].IP)
	}
}

// ---------------------------------------------------------------------------
// GET /v1/me
// ---------------------------------------------------------------------------

func TestMeAcceptsTheCookie(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "a-session-token"})

	rec := httptest.NewRecorder()
	New(nil, WithAuth(f)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	if len(body) != 2 {
		t.Errorf("the response has %d fields (%v), want exactly id and email", len(body), body)
	}
	if body["email"] != "kaka@example.com" {
		t.Errorf("email = %v, want kaka@example.com", body["email"])
	}
}

func TestMeAcceptsABearerToken(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	req.Header.Set("Authorization", "Bearer a-session-token")

	rec := httptest.NewRecorder()
	New(nil, WithAuth(f)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}
}

func TestMeRejectsEveryMissingOrBrokenCredential(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prepare func(*http.Request)
	}{
		{name: "nothing at all", prepare: func(*http.Request) {}},
		{
			name: "an empty cookie",
			prepare: func(r *http.Request) {
				r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: ""})
			},
		},
		{
			name: "a cookie under the wrong name",
			prepare: func(r *http.Request) {
				r.AddCookie(&http.Cookie{Name: "session", Value: "a-session-token"})
			},
		},
		{
			name: "a bare Authorization header",
			prepare: func(r *http.Request) {
				r.Header.Set("Authorization", "a-session-token")
			},
		},
		{
			name: "the wrong scheme",
			prepare: func(r *http.Request) {
				r.Header.Set("Authorization", "Basic a-session-token")
			},
		},
		{
			name: "an empty bearer",
			prepare: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer ")
			},
		},
		{
			name: "a token the service rejects",
			prepare: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer never-issued")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFakeAuth()
			if strings.Contains(tt.name, "rejects") {
				f.authErr = auth.ErrUnauthenticated
			}

			req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
			tt.prepare(req)

			rec := httptest.NewRecorder()
			New(nil, WithAuth(f)).ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401; body: %s", rec.Code, rec.Body)
			}
			p := decodeProblem(t, rec)
			if p.Code != CodeUnauthorized {
				t.Errorf("code = %q, want %q", p.Code, CodeUnauthorized)
			}
		})
	}
}

// An explicit Authorization header wins over a cookie. A client holding both —
// a browser session plus an API token it pasted in — has said which one it means,
// and guessing would make the answer depend on invisible state.
func TestMePrefersTheAuthorizationHeaderOverTheCookie(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "cookie-token"})
	req.Header.Set("Authorization", "Bearer header-token")

	rec := httptest.NewRecorder()
	New(nil, WithAuth(f)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if got := f.lastAuthenticatedToken(); got != "header-token" {
		t.Errorf("the service was given %q, want the header's header-token", got)
	}
}

// ---------------------------------------------------------------------------
// DELETE /v1/session
// ---------------------------------------------------------------------------

func TestLogoutClearsTheCookieAndRevokes(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	req := httptest.NewRequest(http.MethodDelete, "/v1/session", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "a-session-token"})

	rec := httptest.NewRecorder()
	New(nil, WithAuth(f)).ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", rec.Code, rec.Body)
	}
	if body := rec.Body.String(); body != "" {
		t.Errorf("a 204 has a body: %q", body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "" {
		t.Errorf("a 204 declares Content-Type %q, want none", ct)
	}

	// The cookie is expired with the same attributes that set it, or the browser
	// keeps the old one.
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1 clearing the session", len(cookies))
	}
	c := cookies[0]
	if c.Name != SessionCookieName {
		t.Errorf("cookie name = %q, want %q", c.Name, SessionCookieName)
	}
	if c.Value != "" {
		t.Errorf("cookie value = %q, want empty", c.Value)
	}
	if c.MaxAge >= 0 {
		t.Errorf("cookie MaxAge = %d, want negative so the browser deletes it", c.MaxAge)
	}
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		t.Errorf("the clearing cookie's attributes differ from the setting cookie's: %+v", c)
	}
}

func TestLogoutWorksForABearerClient(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	req := httptest.NewRequest(http.MethodDelete, "/v1/session", nil)
	req.Header.Set("Authorization", "Bearer a-session-token")

	rec := httptest.NewRecorder()
	New(nil, WithAuth(f)).ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", rec.Code, rec.Body)
	}
	if got := f.lastLoggedOutToken(); got != "a-session-token" {
		t.Errorf("the service revoked %q, want a-session-token", got)
	}
}

// Logging out with nothing is a 401, not a 204. There is no session to revoke,
// and answering 204 would tell a client its request succeeded when nothing
// happened — which is how a client ends up believing it is still signed in.
func TestLogoutWithoutACredentialIs401(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	rec := send(t, New(nil, WithAuth(f)), http.MethodDelete, "/v1/session", "")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body: %s", rec.Code, rec.Body)
	}
	p := decodeProblem(t, rec)
	if p.Code != CodeUnauthorized {
		t.Errorf("code = %q, want %q", p.Code, CodeUnauthorized)
	}
}

// A logout whose token the service cannot resolve still clears the client's
// cookie. A stale cookie is the common case — the session expired hours ago and
// the browser kept it — and leaving it in place means the user clicks sign out
// again and nothing appears to happen.
func TestLogoutWithAStaleTokenStillClearsTheCookie(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	f.logoutErr = auth.ErrUnauthenticated

	req := httptest.NewRequest(http.MethodDelete, "/v1/session", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "expired"})

	rec := httptest.NewRecorder()
	New(nil, WithAuth(f)).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body: %s", rec.Code, rec.Body)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge >= 0 {
		t.Errorf("the stale cookie was not cleared: %+v", cookies)
	}
}

// ---------------------------------------------------------------------------
// error handling
// ---------------------------------------------------------------------------

// An infrastructure failure is a 500 with a trace id, and the internal cause goes
// to the log rather than the body.
func TestUnexpectedErrorsAre500WithTheCauseInTheLog(t *testing.T) {
	t.Parallel()

	logs := &recordingHandler{}
	logger := slogLogger(logs)

	f := newFakeAuth()
	f.loginErr = errors.New("dial tcp 10.0.0.5:5432: connection refused (password authentication failed for user identity)")

	rec := post(t, New(nil, WithAuth(f), WithLogger(logger)), "/v1/session", `{"email":"kaka@example.com","password":"correct horse battery"}`)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body)
	}
	p := decodeProblem(t, rec)
	if p.Code != CodeInternal {
		t.Errorf("code = %q, want %q", p.Code, CodeInternal)
	}
	if p.TraceID == "" {
		t.Error("trace_id is empty; support could not correlate this")
	}

	// Nothing internal leaks.
	for _, secret := range []string{"10.0.0.5", "password", "refused", "dial tcp", "identity"} {
		if strings.Contains(strings.ToLower(rec.Body.String()), secret) {
			t.Errorf("the body leaks %q: %s", secret, rec.Body)
		}
	}

	// But the operator gets it.
	entry := logs.find("request failed")
	if entry == "" {
		t.Fatalf("nothing was logged; got %d entries", logs.count())
	}
	if !strings.Contains(entry, "10.0.0.5") {
		t.Errorf("the log entry does not carry the cause: %s", entry)
	}
	if !strings.Contains(entry, p.TraceID) {
		t.Errorf("the log entry does not carry the trace id %q: %s", p.TraceID, entry)
	}
}

// A panic in a handler must not take the process down or leak a stack trace.
func TestPanicInAHandlerIs500(t *testing.T) {
	t.Parallel()

	logs := &recordingHandler{}
	h := New(nil, WithAuth(panickingAuth{}), WithLogger(slogLogger(logs)))

	rec := post(t, h, "/v1/users", `{"email":"kaka@example.com","password":"correct horse battery"}`)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "goroutine") || strings.Contains(rec.Body.String(), "panic") {
		t.Errorf("the body carries a stack trace: %s", rec.Body)
	}
	if logs.find("request failed") == "" {
		t.Error("the panic was not logged")
	}
}

// A store failure during registration is a 500, not a 409. Only a real duplicate
// is a conflict, and conflating them would tell a caller their address is taken
// when the database is simply down.
func TestRegistrationStoreFailureIs500Not409(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	f.registerErr = errors.New("connection reset by peer")

	rec := post(t, New(nil, WithAuth(f)), "/v1/users", `{"email":"kaka@example.com","password":"correct horse battery"}`)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body)
	}
	p := decodeProblem(t, rec)
	if p.Code == CodeConflict {
		t.Error("a store failure was reported as a conflict; that tells a caller their address is taken")
	}
}

// The v1 routes are not mounted when no auth service is configured, so a
// misconfigured process fails at startup rather than serving 500s.
func TestAuthRoutesAreAbsentWithoutAnAuthService(t *testing.T) {
	t.Parallel()

	tests := []struct {
		method string
		target string
	}{
		{method: http.MethodPost, target: "/v1/users"},
		{method: http.MethodPost, target: "/v1/session"},
		{method: http.MethodDelete, target: "/v1/session"},
		{method: http.MethodGet, target: "/v1/me"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.target, func(t *testing.T) {
			t.Parallel()

			rec := send(t, New(nil), tt.method, tt.target, `{}`)

			if rec.Code != http.StatusNotFound {
				t.Errorf("status = %d, want 404 when no auth service is configured; body: %s", rec.Code, rec.Body)
			}
		})
	}
}

// Every route rejects the methods it does not implement, as a problem document.
func TestWrongMethodsAreProblemJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		target string
	}{
		{name: "GET on register", method: http.MethodGet, target: "/v1/users"},
		{name: "PUT on login", method: http.MethodPut, target: "/v1/session"},
		{name: "POST on me", method: http.MethodPost, target: "/v1/me"},
		{name: "GET on logout", method: http.MethodGet, target: "/v1/session"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := send(t, New(nil, WithAuth(newFakeAuth())), tt.method, tt.target, `{}`)

			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d, want 405; body: %s", rec.Code, rec.Body)
			}
			p := decodeProblem(t, rec)
			if p.Code != CodeMethodNotAllowed {
				t.Errorf("code = %q, want %q", p.Code, CodeMethodNotAllowed)
			}
		})
	}
}

// An unknown route is a problem document too. core's rule is about *every*
// non-2xx response, and a bespoke 404 body is how two error shapes start.
func TestUnknownRouteIsProblemJSON(t *testing.T) {
	t.Parallel()

	rec := send(t, New(nil), http.MethodGet, "/v1/nope", "")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", rec.Code, rec.Body)
	}
	p := decodeProblem(t, rec)
	if p.Code != CodeNotFound {
		t.Errorf("code = %q, want %q", p.Code, CodeNotFound)
	}
	if p.Instance != "/v1/nope" {
		t.Errorf("instance = %q, want /v1/nope", p.Instance)
	}
}

// Health endpoints must stay reachable and keep their 2xx shape. They are not
// part of the v1 contract and a client for them is a load balancer.
func TestProbesAreUnaffectedByTheV1Surface(t *testing.T) {
	t.Parallel()

	h := New(nil, WithAuth(newFakeAuth()))

	for _, target := range []string{"/healthz", "/readyz"} {
		rec := send(t, h, http.MethodGet, target, "")
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200; body: %s", target, rec.Code, rec.Body)
		}
		if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
			t.Errorf("GET %s Content-Type = %q, want application/json", target, got)
		}
	}
}

// ---------------------------------------------------------------------------
// helpers on the fake
// ---------------------------------------------------------------------------

func (f *fakeAuth) hasRegistered() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.registered) > 0
}

func (f *fakeAuth) loginInputs() []auth.LoginInput {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]auth.LoginInput(nil), f.loggedIn...)
}

func (f *fakeAuth) lastLoggedOutToken() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.loggedOut) == 0 {
		return ""
	}
	return f.loggedOut[len(f.loggedOut)-1]
}

func (f *fakeAuth) lastAuthenticatedToken() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastAuthToken
}

// panickingAuth blows up in every method, to prove the handlers recover.
type panickingAuth struct{}

func (panickingAuth) Register(context.Context, auth.RegisterInput) (auth.RegisteredUser, error) {
	panic("handler exploded")
}
func (panickingAuth) CompleteSecondFactor(context.Context, auth.CompleteSecondFactorInput) (auth.LoginResult, error) {
	panic("handler exploded")
}
func (panickingAuth) Login(context.Context, auth.LoginInput) (auth.LoginResult, error) {
	panic("handler exploded")
}
func (panickingAuth) Authenticate(context.Context, string) (users.User, error) {
	panic("handler exploded")
}
func (panickingAuth) Logout(context.Context, string) error {
	panic("handler exploded")
}
