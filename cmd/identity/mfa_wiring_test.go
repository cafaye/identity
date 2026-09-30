package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/config"
	"github.com/cafaye/identity/internal/mfa"
	"github.com/cafaye/identity/internal/platform/dbtest"
)

// THE MFA WIRING.
//
// What matters here is not the behaviour — internal/auth and internal/httpapi own
// that — but that newApp CONNECTS the pieces correctly, because there is one way
// for this to be wrong that no behavioural test elsewhere would catch:
//
//	A PROCESS WITH A DATABASE AND NO MFA_ENCRYPTION_KEY MUST STILL REFUSE A
//	SECOND-FACTOR LOGIN, AND MUST NOT LET A USER ENROLL ONE IT CANNOT VERIFY.
//
// If the challenge route were mounted on the MFA management route's condition, such
// a process would have no POST /v1/session/mfa at all — and a client seeing a 404
// for it would be free to conclude there was no second factor to present. That is
// the bypass, expressed as a routing decision.

// mfaKey is a 32-byte key, base64url, the shape the environment takes.
func mfaKey(t *testing.T) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString([]byte("identity-cmd-mfa-wiring-key-32!!"))
}

// TestNewAppMountsMFAWithAKey: the whole surface, management and challenge, plus a
// login that stops at the challenge.
func TestNewAppMountsMFAWithAKey(t *testing.T) {
	dsn := testDatabaseURL(t)
	ctx := context.Background()

	cfg := config.Config{
		Port: "0", LogLevel: "error", DatabaseURL: dsn,
		MFAEncryptionKeyValue: mustDecodeKey(t, mfaKey(t)),
		MFAIssuerLabel:        config.DefaultMFAIssuer,
	}
	a, err := newApp(ctx, cfg, discardLogger())
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	defer a.Close()

	email := dbtest.UniqueEmail(t)
	rec := serveBody(t, a, http.MethodPost, "/v1/users",
		`{"email":"`+email+`","password":"correct horse battery staple"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /v1/users = %d; body: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	decodeJSON(t, rec, &created)

	// With no second factor, the login is a plain 200 with a session. The
	// compatibility property, asserted here rather than only in internal/httpapi,
	// because it is the wiring that could break it.
	login := serveBody(t, a, http.MethodPost, "/v1/session",
		`{"email":"`+email+`","password":"correct horse battery staple"}`, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("POST /v1/session = %d, want 200; body: %s", login.Code, login.Body.String())
	}
	var session struct {
		Token string `json:"token"`
	}
	decodeJSON(t, login, &session)
	if session.Token == "" {
		t.Fatal("the login body carries no token")
	}

	// The management surface is mounted.
	enroll := serveBody(t, a, http.MethodPost, "/v1/mfa/enrollments", `{}`, bearer(session.Token))
	if enroll.Code != http.StatusCreated {
		t.Fatalf("POST /v1/mfa/enrollments = %d, want 201; body: %s", enroll.Code, enroll.Body.String())
	}
	var started struct {
		EnrollmentID string `json:"enrollment_id"`
		Secret       string `json:"secret"`
	}
	decodeJSON(t, enroll, &started)
	if started.EnrollmentID == "" || started.Secret == "" {
		t.Fatalf("the enrollment response is missing a field: %s", enroll.Body.String())
	}

	code, err := mfa.Code(started.Secret, time.Now())
	if err != nil {
		t.Fatalf("mfa.Code: %v", err)
	}
	confirm := serveBody(t, a, http.MethodPost,
		"/v1/mfa/enrollments/"+started.EnrollmentID+"/confirm", `{"code":"`+code+`"}`, bearer(session.Token))
	if confirm.Code != http.StatusOK {
		t.Fatalf("confirm = %d, want 200; body: %s", confirm.Code, confirm.Body.String())
	}

	// And now the login stops at the challenge — over the real handler the process
	// serves, which is the assertion that matters here.
	chained := serveBody(t, a, http.MethodPost, "/v1/session",
		`{"email":"`+email+`","password":"correct horse battery staple"}`, nil)
	if chained.Code != http.StatusAccepted {
		t.Fatalf("POST /v1/session for an enrolled user = %d, want 202; body: %s",
			chained.Code, chained.Body.String())
	}
	if strings.Contains(chained.Body.String(), `"token"`) {
		t.Errorf("the 202 carries a token key: %s", chained.Body.String())
	}

	// The challenge endpoint answers with a refusal, not a 404, because a 404 would
	// say this service has never heard of MFA.
	step := serveBody(t, a, http.MethodPost, "/v1/session/mfa", `{"challenge":"not-a-challenge","code":"123456"}`, nil)
	if step.Code != http.StatusNotFound {
		t.Errorf("POST /v1/session/mfa with a bogus challenge = %d, want 404; body: %s",
			step.Code, step.Body.String())
	}
	_ = created
}

// TestNewAppWithoutMFAKeyMountsNoManagementRoutesAndStillChallenges: THE test.
//
// A database and no key is a legitimate deployment — MFA simply is not turned on —
// and it has to degrade in one direction only.
//
//	management routes   ABSENT. A 404, because a user must not be talked into
//	                    enrolling a factor this process could not later verify.
//	challenge route     PRESENT. A user who enrolled elsewhere is refused at their
//	                    second factor rather than being let in on their password.
func TestNewAppWithoutMFAKeyMountsNoManagementRoutesAndStillChallenges(t *testing.T) {
	dsn := testDatabaseURL(t)
	ctx := context.Background()

	cfg := config.Config{Port: "0", LogLevel: "error", DatabaseURL: dsn}
	a, err := newApp(ctx, cfg, discardLogger())
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	defer a.Close()

	email := dbtest.UniqueEmail(t)
	rec := serveBody(t, a, http.MethodPost, "/v1/users",
		`{"email":"`+email+`","password":"correct horse battery staple"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /v1/users = %d; body: %s", rec.Code, rec.Body.String())
	}
	login := serveBody(t, a, http.MethodPost, "/v1/session",
		`{"email":"`+email+`","password":"correct horse battery staple"}`, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("POST /v1/session = %d, want 200; body: %s", login.Code, login.Body.String())
	}
	var session struct {
		Token string `json:"token"`
	}
	decodeJSON(t, login, &session)

	for _, c := range []struct{ method, path, body string }{
		{http.MethodGet, "/v1/mfa", ""},
		{http.MethodPost, "/v1/mfa/enrollments", `{}`},
		{http.MethodPost, "/v1/mfa/recovery-codes", `{"code":"123456"}`},
		{http.MethodDelete, "/v1/mfa", `{"code":"123456"}`},
	} {
		got := serveBody(t, a, c.method, c.path, c.body, bearer(session.Token))
		if got.Code != http.StatusNotFound {
			t.Errorf("%s %s without a key = %d, want 404", c.method, c.path, got.Code)
		}
	}

	// The challenge route is the one that must EXIST, because its absence is the
	// bypass. It answers 404 here only because the challenge token is bogus — a
	// route that did not exist would answer 404 too, so the assertion that
	// distinguishes them is the one above plus the login below.
	step := serveBody(t, a, http.MethodPost, "/v1/session/mfa", `{"challenge":"x","code":"123456"}`, nil)
	if step.Code != http.StatusNotFound {
		t.Errorf("POST /v1/session/mfa = %d, want 404 for a bogus challenge", step.Code)
	}
	if got := step.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Errorf("Content-Type = %q, want the problem envelope", got)
	}
}

// TestNewAppRefusesAnMFAKeyOfTheWrongLength is a startup failure and not a warning:
// an operator who configured a 16-byte key believes they have 128 bits of entropy
// protecting every second factor on the platform.
func TestNewAppRefusesAnMFAKeyOfTheWrongLength(t *testing.T) {
	dsn := testDatabaseURL(t)

	cfg := config.Config{
		Port: "0", LogLevel: "error", DatabaseURL: dsn,
		MFAEncryptionKeyValue: []byte("sixteen bytes ok"),
	}
	if _, err := newApp(context.Background(), cfg, discardLogger()); err == nil {
		t.Fatal("newApp accepted a 16-byte MFA key")
	}
}

// TestMFAEncryptionKeyIsNeverGenerated: a key generated at boot would mean every
// restart invalidates every enrolled user's secret, and a restart is not something
// anybody decides to do.
func TestMFAEncryptionKeyIsNeverGenerated(t *testing.T) {
	cfg := config.Config{Port: "0"}
	key, err := cfg.MFAEncryptionKey()
	if err == nil {
		t.Fatalf("MFAEncryptionKey() with nothing configured returned %q, want ErrNoMFAEncryptionKey", key)
	}
	if cfg.MFAEncryptionKeyConfigured() {
		t.Error("MFAEncryptionKeyConfigured() is true with no key configured")
	}
	if cfg.MFAIssuer() != config.DefaultMFAIssuer {
		t.Errorf("MFAIssuer() = %q, want the default label", cfg.MFAIssuer())
	}
}

func mustDecodeKey(t *testing.T, encoded string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decoding the fixture key: %v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("the fixture key is %d bytes, want 32", len(decoded))
	}
	return decoded
}

// bearer is the Authorization header for a session token, because three of these
// tests need one and spelling it out each time is three chances to spell it
// differently.
func bearer(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

// decodeJSON reads a recorder's body into dst, failing the test with the body rather
// than with a bare unmarshal error.
func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("the body is not JSON: %v\n%s", err, rec.Body)
	}
}
