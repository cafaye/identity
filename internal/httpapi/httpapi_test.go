package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var errUnreachable = errors.New("dependency unreachable")

// okCheck reports a healthy dependency without touching the network.
func okCheck(name string) Check {
	return Check{Name: name, Ping: func(context.Context) error { return nil }}
}

// failingCheck reports an unreachable dependency.
func failingCheck(name string) Check {
	return Check{Name: name, Ping: func(context.Context) error { return errUnreachable }}
}

// blockingCheck blocks until the caller's context expires, so readiness
// deadline handling can be exercised without sleeping in the test.
func blockingCheck(name string) Check {
	return Check{Name: name, Ping: func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}}
}

type response struct {
	Code        int
	Body        string
	ContentType string
	JSON        map[string]any
}

// do performs a request and decodes the body as JSON.
//
// Both application/json and application/problem+json are accepted. The split is
// core's: 2xx responses are plain JSON, every non-2xx is an RFC 9457 problem
// document. A helper that only accepted the first would have hidden the change
// that made the 404 and the 405 conform.
func do(t *testing.T, handler http.Handler, method, target string) response {
	t.Helper()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(method, target, nil))

	res := response{Code: rec.Code, Body: rec.Body.String(), ContentType: rec.Header().Get("Content-Type")}
	switch {
	case strings.HasPrefix(res.ContentType, "application/json"),
		strings.HasPrefix(res.ContentType, "application/problem+json"):
	default:
		t.Errorf("%s %s Content-Type = %q, want application/json or application/problem+json", method, target, res.ContentType)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res.JSON); err != nil {
		t.Fatalf("%s %s body %q is not JSON: %v", method, target, res.Body, err)
	}
	return res
}

func TestHealthz(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		checks  []Check
		method  string
		want    int
		wantDep string
	}{
		{name: "no dependencies", checks: nil, method: http.MethodGet, want: http.StatusOK},
		{name: "healthy dependency", checks: []Check{okCheck("postgres")}, method: http.MethodGet, want: http.StatusOK},
		{name: "unhealthy dependency", checks: []Check{failingCheck("postgres")}, method: http.MethodGet, want: http.StatusOK},
		// A 405 is a problem document now, so the JSON-shape assertion below is
		// skipped for it like every other non-2xx.
		{name: "empty method is a 405", checks: nil, method: http.MethodPost, want: http.StatusMethodNotAllowed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := do(t, New(tt.checks), tt.method, "/healthz")

			if got.Code != tt.want {
				t.Errorf("status = %d, want %d", got.Code, tt.want)
			}
			if tt.want != http.StatusOK {
				return
			}
			if strings.TrimSpace(got.Body) != `{"status":"ok"}` {
				t.Errorf("body = %s, want {\"status\":\"ok\"}", got.Body)
			}
			if got.JSON["status"] != "ok" {
				t.Errorf("status field = %v, want ok", got.JSON["status"])
			}
		})
	}
}

func TestReadyz(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		checks     []Check
		want       int
		wantDeps   any
		wantStatus any
	}{
		{
			// v0 ships without a database: readiness must still succeed.
			name:       "no DATABASE_URL means nothing to check",
			checks:     nil,
			want:       http.StatusOK,
			wantDeps:   "none",
			wantStatus: "ok",
		},
		{
			name:       "empty check list behaves like no database",
			checks:     []Check{},
			want:       http.StatusOK,
			wantDeps:   "none",
			wantStatus: "ok",
		},
		{
			name:       "reachable dependency",
			checks:     []Check{okCheck("postgres")},
			want:       http.StatusOK,
			wantDeps:   "postgres",
			wantStatus: "ok",
		},
		{
			name:       "all reachable dependencies are listed",
			checks:     []Check{okCheck("postgres"), okCheck("redis")},
			want:       http.StatusOK,
			wantDeps:   "postgres,redis",
			wantStatus: "ok",
		},
		{
			name:       "unreachable dependency",
			checks:     []Check{failingCheck("postgres")},
			want:       http.StatusServiceUnavailable,
			wantDeps:   "postgres",
			wantStatus: "unavailable",
		},
		{
			name:       "one bad dependency fails the whole probe",
			checks:     []Check{okCheck("redis"), failingCheck("postgres")},
			want:       http.StatusServiceUnavailable,
			wantDeps:   "redis,postgres",
			wantStatus: "unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := do(t, New(tt.checks), http.MethodGet, "/readyz")

			if got.Code != tt.want {
				t.Errorf("status = %d, want %d", got.Code, tt.want)
			}
			if got.JSON["deps"] != tt.wantDeps {
				t.Errorf("deps = %v, want %v", got.JSON["deps"], tt.wantDeps)
			}
			if got.JSON["status"] != tt.wantStatus {
				t.Errorf("status field = %v, want %v", got.JSON["status"], tt.wantStatus)
			}
			if _, ok := got.JSON["deps"]; !ok {
				t.Error(`body is missing the "deps" field`)
			}
		})
	}
}

func TestReadyzDeadlineIsServiceUnavailable(t *testing.T) {
	t.Parallel()

	// A dependency that never answers must not hold the probe open: the
	// deadline is what turns a hang into a 503.
	handler := New([]Check{blockingCheck("postgres")}, WithReadinessTimeout(20*time.Millisecond))

	got := do(t, handler, http.MethodGet, "/readyz")

	if got.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", got.Code, http.StatusServiceUnavailable)
	}
	if got.JSON["deps"] != "postgres" {
		t.Errorf("deps = %v, want postgres", got.JSON["deps"])
	}
}

func TestReadyzReceivesADeadline(t *testing.T) {
	t.Parallel()

	deadlineSeen := make(chan bool, 1)
	checks := []Check{{Name: "postgres", Ping: func(ctx context.Context) error {
		_, ok := ctx.Deadline()
		deadlineSeen <- ok
		return nil
	}}}

	do(t, New(checks), http.MethodGet, "/readyz")

	if !<-deadlineSeen {
		t.Error("ping context has no deadline, want one bounded by the readiness timeout")
	}
}

// A 404 is a problem document, like every other non-2xx response. core's error
// envelope has no exception for "not found", and a bespoke body here is how a
// client ends up parsing two error shapes.
func TestUnknownRouteIsProblem404(t *testing.T) {
	t.Parallel()

	got := do(t, New(nil), http.MethodGet, "/does-not-exist")

	if got.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", got.Code, http.StatusNotFound)
	}
	if want := "application/problem+json"; got.ContentType != want {
		t.Errorf("Content-Type = %q, want %q", got.ContentType, want)
	}
	if got.JSON["code"] != CodeNotFound {
		t.Errorf("code = %v, want %q", got.JSON["code"], CodeNotFound)
	}
	if got.JSON["status"] != float64(http.StatusNotFound) {
		t.Errorf("status field = %v, want %d", got.JSON["status"], http.StatusNotFound)
	}
}

func TestReadyzWrongMethodIsProblem405(t *testing.T) {
	t.Parallel()

	got := do(t, New(nil), http.MethodPost, "/readyz")

	if got.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", got.Code, http.StatusMethodNotAllowed)
	}
	if want := "application/problem+json"; got.ContentType != want {
		t.Errorf("Content-Type = %q, want %q", got.ContentType, want)
	}
	if got.JSON["code"] != CodeMethodNotAllowed {
		t.Errorf("code = %v, want %q", got.JSON["code"], CodeMethodNotAllowed)
	}
}

func TestWithLoggerSendsProbeFailuresToTheLog(t *testing.T) {
	t.Parallel()

	logs := &recordingHandler{}
	logger := slog.New(logs)

	do(t, New([]Check{failingCheck("postgres")}, WithLogger(logger)), http.MethodGet, "/readyz")

	entry := logs.find("readiness probe failed")
	if entry == "" {
		t.Fatalf("no log entry for a failed readiness probe, got %d entries", logs.count())
	}
	if !strings.Contains(entry, "postgres") {
		t.Errorf("log entry %q does not name the failing dependency", entry)
	}
}

// TestProbeFailureIsNotLeakedToClients guards against leaking internal
// dependency error strings to unauthenticated callers.
func TestProbeFailureIsNotLeakedToClients(t *testing.T) {
	t.Parallel()

	checks := []Check{{Name: "postgres", Ping: func(context.Context) error {
		return errors.New("dial tcp 10.0.0.5:5432: connection refused (password authentication failed for user identity)")
	}}}

	got := do(t, New(checks), http.MethodGet, "/readyz")

	if got.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", got.Code, http.StatusServiceUnavailable)
	}
	for _, secret := range []string{"password", "refused", "10.0.0.5", "identity"} {
		if strings.Contains(got.Body, secret) {
			t.Errorf("body %q leaks %q from the dependency error", got.Body, secret)
		}
	}
}

func TestHealthzDoesNotTouchDependencies(t *testing.T) {
	t.Parallel()

	called := false
	checks := []Check{{Name: "postgres", Ping: func(context.Context) error {
		called = true
		return errUnreachable
	}}}

	if got := do(t, New(checks), http.MethodGet, "/healthz"); got.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", got.Code)
	}
	if called {
		t.Error("healthz called the dependency ping; liveness must never depend on readiness")
	}
}

func TestPanicInProbeIsRecoveredAsUnavailable(t *testing.T) {
	t.Parallel()

	checks := []Check{{Name: "postgres", Ping: func(context.Context) error {
		panic("probe exploded")
	}}}

	got := do(t, New(checks), http.MethodGet, "/readyz")

	if got.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", got.Code, http.StatusServiceUnavailable)
	}
}

func TestResponseBodyIsASingleJSONObject(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	New([]Check{failingCheck("postgres")}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("body %q is not a single JSON object: %v", body, err)
	}
	if len(decoded) != 2 {
		t.Errorf("body has %d fields (%v), want exactly status and deps", len(decoded), decoded)
	}
}

// recordingHandler captures slog output so tests can assert on what the
// service logs rather than on what it prints to a real stderr.
type recordingHandler struct {
	entries []string
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.entries = append(h.entries, r.Message+" "+recordAttrs(r))
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

func (h *recordingHandler) count() int { return len(h.entries) }

func (h *recordingHandler) find(message string) string {
	for _, entry := range h.entries {
		if strings.Contains(entry, message) {
			return entry
		}
	}
	return ""
}

func recordAttrs(r slog.Record) string {
	var b strings.Builder
	r.Attrs(func(a slog.Attr) bool {
		b.WriteString(" " + a.Key + "=" + a.Value.String())
		return true
	})
	return b.String()
}
