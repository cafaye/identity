package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A trace id has to exist on every response, or support cannot correlate a
// customer's report with a log line. That includes the responses nobody thought
// about: the 404, the 405, the panic-free 200.
func TestTraceHeaderIsAlwaysPresent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		target string
	}{
		{name: "a known route", method: http.MethodGet, target: "/healthz"},
		{name: "an unknown route", method: http.MethodGet, target: "/nope"},
		{name: "a wrong method", method: http.MethodPost, target: "/healthz"},
		{name: "the root", method: http.MethodGet, target: "/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			New(nil).ServeHTTP(rec, httptest.NewRequest(tt.method, tt.target, nil))

			got := rec.Header().Get(TraceHeader)
			if got == "" {
				t.Fatalf("%s %s has no %s", tt.method, tt.target, TraceHeader)
			}
			if _, err := parseUUIDish(got); err != nil {
				t.Errorf("%s = %q, want a generated UUID", TraceHeader, got)
			}
		})
	}
}

// An inbound id is reused so a trace crosses a proxy hop intact.
func TestInboundTraceIDIsReused(t *testing.T) {
	t.Parallel()

	const inbound = "0af7651916cd43dd8448eb211c80319c"

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set(TraceHeader, inbound)

	rec := httptest.NewRecorder()
	New(nil).ServeHTTP(rec, req)

	if got := rec.Header().Get(TraceHeader); got != inbound {
		t.Errorf("%s = %q, want the inbound %q", TraceHeader, got, inbound)
	}
}

// A hostile or untidy inbound value is replaced rather than reflected. The value
// lands in a response header and a log line, so anything that is not a
// conservative identifier is refused.
func TestUnusableInboundTraceIDIsReplaced(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		give   string
		reason string
	}{
		{name: "a header injection attempt", give: "abc\r\nX-Admin: true", reason: "CRLF would forge a second header"},
		{name: "a space", give: "abc def", reason: "not an identifier"},
		{name: "a very long value", give: strings.Repeat("a", maxInboundTraceID+1), reason: "unbounded into a log line"},
		{name: "a unicode value", give: "trace-é中", reason: "not an identifier"},
		{name: "a quote", give: `abc"def`, reason: "would break a log format"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			req.Header.Set(TraceHeader, tt.give)

			rec := httptest.NewRecorder()
			New(nil).ServeHTTP(rec, req)

			got := rec.Header().Get(TraceHeader)
			if got == tt.give {
				t.Errorf("the unusable inbound value %q was reflected; %s", tt.give, tt.reason)
			}
			if got == "" {
				t.Error("no trace id was set at all")
			}
			// The forged header must not have materialised.
			if rec.Header().Get("X-Admin") != "" {
				t.Error("the injected header reached the response")
			}
		})
	}
}

// The body's trace_id and the header's are the same value, which is the property
// core states explicitly. A handler that minted its own would break support's
// ability to find the log line.
func TestProblemTraceIDMatchesTheResponseHeader(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	req.Header.Set(TraceHeader, "0af7651916cd43dd8448eb211c80319c")

	rec := httptest.NewRecorder()
	New(nil, WithAuth(newFakeAuth())).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}

	var p Problem
	if err := decodeJSON(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	if p.TraceID != rec.Header().Get(TraceHeader) {
		t.Errorf("body trace_id = %q, header = %q; core requires them to match",
			p.TraceID, rec.Header().Get(TraceHeader))
	}
}

func TestInboundTraceIDRejectsWhatItShould(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
		want string
	}{
		{name: "a UUID", give: "0af7651916cd43dd8448eb211c80319c", want: "0af7651916cd43dd8448eb211c80319c"},
		{name: "an opaque word", give: "edge-7f3a.9:12", want: "edge-7f3a.9:12"},
		{name: "empty", give: "", want: ""},
		{name: "with a newline", give: "abc\ndef", want: ""},
		{name: "with a tab", give: "abc\tdef", want: ""},
		{name: "with a slash", give: "abc/def", want: ""},
		{name: "over the cap", give: strings.Repeat("a", maxInboundTraceID+1), want: ""},
		{name: "exactly at the cap", give: strings.Repeat("a", maxInboundTraceID), want: strings.Repeat("a", maxInboundTraceID)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			req.Header.Set(TraceHeader, tt.give)

			if got := inboundTraceID(req); got != tt.want {
				t.Errorf("inboundTraceID(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}
