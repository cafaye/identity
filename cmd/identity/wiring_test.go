package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/cafaye/identity/internal/config"
	"github.com/cafaye/identity/internal/platform/dbtest"
)

// discardLogger matches the helper the app tests use: assertions on log output
// live in internal/httpapi, where the handler that writes them is.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// The wiring tests: newApp has to produce a process that serves the v1 surface
// when a database is configured, and that still serves its probes when one is
// not. The auth behaviour itself is covered in internal/httpapi and
// internal/auth; what matters here is that the two are actually connected.

func testDatabaseURL(t *testing.T) string {
	t.Helper()

	dsn := os.Getenv(dbtest.EnvVar)
	if dsn == "" {
		t.Skipf("%s is not set; skipping the wiring test", dbtest.EnvVar)
	}
	return dsn
}

// With a database, the v1 routes are mounted and the whole flow works over the
// real handler the process serves.
func TestNewAppServesTheAuthSurfaceWithADatabase(t *testing.T) {
	dsn := testDatabaseURL(t)
	ctx := context.Background()

	cfg := config.Config{Port: "0", LogLevel: "error", DatabaseURL: dsn}
	a, err := newApp(ctx, cfg, discardLogger())
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	defer a.Close()

	email := dbtest.UniqueEmail(t)
	const password = "correct horse battery staple"

	// Register.
	rec := serveBody(t, a, http.MethodPost, "/v1/users", `{"email":"`+email+`","password":"`+password+`"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /v1/users = %d, want 201; body: %s", rec.Code, rec.Body)
	}

	// Log in.
	loginRec := serveBody(t, a, http.MethodPost, "/v1/session", `{"email":"`+email+`","password":"`+password+`"}`, nil)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("POST /v1/session = %d, want 200; body: %s", loginRec.Code, loginRec.Body)
	}

	var login struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(loginRec.Body.Bytes(), &login); err != nil {
		t.Fatalf("the login body is not JSON: %v", err)
	}
	if login.Token == "" {
		t.Fatal("the login returned no token")
	}

	cookies := loginRec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "__Host-session" {
		t.Errorf("the login set cookies %+v, want one __Host-session", cookies)
	}

	// The identity of the session.
	meRec := serveBody(t, a, http.MethodGet, "/v1/me", "", map[string]string{
		"Authorization": "Bearer " + login.Token,
	})
	if meRec.Code != http.StatusOK {
		t.Fatalf("GET /v1/me = %d, want 200; body: %s", meRec.Code, meRec.Body)
	}

	// Log out, and the token dies.
	logoutRec := serveBody(t, a, http.MethodDelete, "/v1/session", "", map[string]string{
		"Authorization": "Bearer " + login.Token,
	})
	if logoutRec.Code != http.StatusNoContent {
		t.Fatalf("DELETE /v1/session = %d, want 204; body: %s", logoutRec.Code, logoutRec.Body)
	}

	afterLogout := serveBody(t, a, http.MethodGet, "/v1/me", "", map[string]string{
		"Authorization": "Bearer " + login.Token,
	})
	if afterLogout.Code != http.StatusUnauthorized {
		t.Errorf("GET /v1/me after logout = %d, want 401; body: %s", afterLogout.Code, afterLogout.Body)
	}
}

// Without a database the process must still start and still answer its probes.
// The v1 routes are absent rather than present-and-broken, so the failure mode of
// a missing DATABASE_URL is a clear 404 instead of a pile of 500s.
func TestNewAppWithoutADatabaseStillServesTheProbes(t *testing.T) {
	cfg := config.Config{Port: "0", LogLevel: "error"}

	a, err := newApp(context.Background(), cfg, discardLogger())
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	defer a.Close()

	for _, target := range []string{"/healthz", "/readyz"} {
		rec := serveBody(t, a, http.MethodGet, target, "", nil)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200; body: %s", target, rec.Code, rec.Body)
		}
	}

	// Readiness reports that there is nothing to probe, which is the v0 shape.
	readyRec := serveBody(t, a, http.MethodGet, "/readyz", "", nil)
	if !strings.Contains(readyRec.Body.String(), `"deps":"none"`) {
		t.Errorf("/readyz = %s, want deps none with no database", readyRec.Body)
	}

	// The auth surface is simply not there.
	for _, route := range []struct{ method, target string }{
		{http.MethodPost, "/v1/users"},
		{http.MethodPost, "/v1/session"},
		{http.MethodDelete, "/v1/session"},
		{http.MethodGet, "/v1/me"},
	} {
		rec := serveBody(t, a, route.method, route.target, `{}`, nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404 without a database", route.method, route.target, rec.Code)
		}
	}
}

// A syntactically valid DATABASE_URL pointing at nothing is a different case from
// a malformed one: db.Open parses without dialling, so the app builds and the
// readiness probe is what reports the database as unreachable. main_test.go covers
// the malformed case. This one proves the lazy-pool rule still holds now that the
// pool is also carrying the auth stores.
func TestNewAppWithAnUnreachableDatabaseStillBuilds(t *testing.T) {
	cfg := config.Config{
		Port:        "0",
		LogLevel:    "error",
		DatabaseURL: "postgres://identity:identity@127.0.0.1:1/identity?sslmode=disable&connect_timeout=1",
	}

	a, err := newApp(context.Background(), cfg, discardLogger())
	if err != nil {
		t.Fatalf("newApp: %v; the pool is lazy, so an unreachable database is a probe failure, not a startup failure", err)
	}
	defer a.Close()

	// Liveness is unconditional even with the database gone.
	rec := serveBody(t, a, http.MethodGet, "/healthz", "", nil)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /healthz = %d, want 200 with an unreachable database; body: %s", rec.Code, rec.Body)
	}
}

// serveBody drives the app's handler with a body and optional headers.
func serveBody(t *testing.T, a *app, method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
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
	for name, value := range headers {
		req.Header.Set(name, value)
	}

	rec := httptest.NewRecorder()
	a.srv.Handler.ServeHTTP(rec, req)
	return rec
}
