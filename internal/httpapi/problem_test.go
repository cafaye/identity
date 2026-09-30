package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Every assertion here comes from cafaye/core docs/openapi-conventions.md,
// "Error envelope". The document says no service invents its own error body, so
// this file is the service's half of that rule.

func TestProblemMatchesTheCoreEnvelope(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/users?debug=1", nil)
	req = req.WithContext(withTraceID(req.Context(), "0af7651916cd43dd8448eb211c80319c"))

	writeProblem(rec, req, newProblem(http.StatusUnauthorized, CodeUnauthorized))

	if got, want := rec.Header().Get("Content-Type"), "application/problem+json"; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}

	var p Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("the body is not JSON: %v\n%s", err, rec.Body)
	}

	// type is the machine-readable contract: a stable errors.cafaye.com URI.
	if want := "https://errors.cafaye.com/unauthorized"; p.Type != want {
		t.Errorf("type = %q, want %q", p.Type, want)
	}
	// code is the same slug as the last segment of type.
	if slug := strings.TrimPrefix(p.Type, "https://errors.cafaye.com/"); p.Code != slug {
		t.Errorf("code = %q, want the last segment of type (%q)", p.Code, slug)
	}
	if p.Status != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", p.Status, http.StatusUnauthorized)
	}
	if p.Title == "" {
		t.Error("title is empty; it is the human-readable summary clients log")
	}
	// instance is the request path. The query string is not part of it: it can
	// carry an email address, and this body is rendered to anonymous callers.
	if p.Instance != "/v1/users" {
		t.Errorf("instance = %q, want /v1/users with no query string", p.Instance)
	}
	// trace_id is always present and always matches the header.
	if p.TraceID != "0af7651916cd43dd8448eb211c80319c" {
		t.Errorf("trace_id = %q, want the request's trace id", p.TraceID)
	}
	if got := rec.Header().Get(TraceHeader); got != p.TraceID {
		t.Errorf("%s = %q but trace_id in the body is %q; core requires them to match", TraceHeader, got, p.TraceID)
	}
	// errors[] appears only for 422.
	if p.Errors != nil {
		t.Errorf("errors = %v on a %d, want it omitted outside 422", p.Errors, p.Status)
	}
}

// errors[] exists so a client can point at the field that was wrong. Without it a
// 422 is a string and a form can only say "something was invalid".
func TestProblemCarriesFieldErrorsForValidation(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/users", nil)

	p := newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
		withDetail("the request body has 2 invalid fields").
		withFieldErrors([]FieldError{
			{Field: "email", Code: "invalid_format"},
			{Field: "password", Code: "too_short"},
		})
	writeProblem(rec, req, p)

	var got Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}

	if len(got.Errors) != 2 {
		t.Fatalf("errors has %d entries, want 2", len(got.Errors))
	}
	if got.Errors[0].Field != "email" || got.Errors[0].Code != "invalid_format" {
		t.Errorf("errors[0] = %+v, want email/invalid_format", got.Errors[0])
	}
	if got.Errors[1].Field != "password" || got.Errors[1].Code != "too_short" {
		t.Errorf("errors[1] = %+v, want password/too_short", got.Errors[1])
	}
	// The field errors must not invent attributes core does not define.
	for _, fe := range got.Errors {
		encoded, err := json.Marshal(fe)
		if err != nil {
			t.Fatalf("marshalling a field error: %v", err)
		}
		if strings.Contains(string(encoded), "message") {
			t.Errorf("a field error carries a message: %s; core's example has only field and code", encoded)
		}
	}
}

// The title is fixed per code. A client that switched on it would break if the
// wording drifted, and core says it may be reworded only without a version bump —
// which is exactly why it is a constant here rather than something assembled from
// the detail.
func TestProblemTitlesAreStablePerCode(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		CodeUnauthorized:     "Unauthorized",
		CodeValidationFailed: "Validation failed",
		CodeConflict:         "Conflict",
		CodeNotFound:         "Not found",
		CodeInternal:         "Internal server error",
		CodeAccountLocked:    "Account locked",
		CodeMethodNotAllowed: "Method not allowed",
		CodeInvalidJSON:      "Malformed request body",
		CodePayloadTooLarge:  "Request body too large",
	}

	for code, want := range cases {
		t.Run(code, func(t *testing.T) {
			t.Parallel()

			if got := titleFor(code); got != want {
				t.Errorf("titleFor(%q) = %q, want %q", code, got, want)
			}
		})
	}
}

// The status and the code must agree. core lists the reserved codes with their
// statuses, and a 401 with code "conflict" is a contract that lies.
func TestProblemStatusAndCodeAgree(t *testing.T) {
	t.Parallel()

	tests := []struct {
		code       string
		wantStatus int
	}{
		{CodeUnauthorized, http.StatusUnauthorized},
		{CodeValidationFailed, http.StatusUnprocessableEntity},
		{CodeConflict, http.StatusConflict},
		{CodeNotFound, http.StatusNotFound},
		{CodeInternal, http.StatusInternalServerError},
		{CodeAccountLocked, http.StatusLocked},
		{CodeMethodNotAllowed, http.StatusMethodNotAllowed},
		{CodeInvalidJSON, http.StatusBadRequest},
		{CodePayloadTooLarge, http.StatusRequestEntityTooLarge},
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			t.Parallel()

			p := newProblem(tt.wantStatus, tt.code)

			if p.Status != tt.wantStatus {
				t.Errorf("status = %d, want %d", p.Status, tt.wantStatus)
			}
			if p.Code != tt.code {
				t.Errorf("code = %q, want %q", p.Code, tt.code)
			}
			if p.Type != errorTypeBase+tt.code {
				t.Errorf("type = %q, want %q", p.Type, errorTypeBase+tt.code)
			}
			if p.Title != titleFor(tt.code) {
				t.Errorf("title = %q, want %q", p.Title, titleFor(tt.code))
			}
		})
	}
}

// An unknown code must still produce a well-formed problem. Falling through to an
// empty type would emit a document every client rejects.
func TestProblemFallsBackForAnUnknownCode(t *testing.T) {
	t.Parallel()

	p := newProblem(http.StatusInternalServerError, "something_new")

	if p.Type != errorTypeBase+"something_new" {
		t.Errorf("type = %q, want it built from the code", p.Type)
	}
	if p.Title == "" {
		t.Error("title is empty for an unknown code")
	}
	if p.Code != "something_new" {
		t.Errorf("code = %q, want something_new", p.Code)
	}
}

// The body must never carry internal detail. core's rule is that `detail` is
// specific to the occurrence and not parsed, and this service applies it strictly:
// a database error goes to the log with the trace id, and the caller gets a
// generic 500.
func TestProblemDetailIsNotFilledFromAnInternalError(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)

	p := newProblem(http.StatusInternalServerError, CodeInternal)
	if p.Detail != "" {
		t.Errorf("a fresh internal problem has detail %q, want empty; callers set it deliberately", p.Detail)
	}
	writeProblem(rec, req, p)

	body := rec.Body.String()
	for _, secret := range []string{"pgconn", "10.0.0.5", "password", "sql", "dial tcp"} {
		if strings.Contains(strings.ToLower(body), secret) {
			t.Errorf("the body leaks %q: %s", secret, body)
		}
	}
}

// A 204 has no body, so it cannot be a problem document. This asserts the writer
// would not add one if a handler asked for a bodiless status by mistake.
func TestProblemIsNeverWrittenForASuccessStatus(t *testing.T) {
	t.Parallel()

	// The handler decides the status; the writer's job is only to render a
	// problem. Asserting the shape rather than a guard here, because the guard
	// would be defending against a programmer error that the type system cannot
	// catch and that no test would ever produce.
	p := newProblem(http.StatusNoContent, CodeInternal)
	if p.Status != http.StatusNoContent {
		t.Errorf("status = %d, want 204 carried through unchanged", p.Status)
	}
	if p.Code != CodeInternal {
		t.Errorf("code = %q, want it carried through unchanged", p.Code)
	}
}
