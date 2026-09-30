package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/cafaye/identity/internal/oauth"
	"github.com/cafaye/identity/internal/platform/id"
)

// jsonUnmarshal is a one-line alias so newResponse reads as one statement. The
// error is returned rather than fatal on purpose: a non-JSON body is a fact the
// calling assertion may be checking for.
func jsonUnmarshal(data []byte, into any) error { return json.Unmarshal(data, into) }

// The small helpers the OIDC suite shares. They are here rather than inline in
// each case because a test that spends three lines on its own scaffolding reads
// as a test about that scaffolding.

// oidcResponse is a recorder plus the decoded body.
//
// Two accessors rather than one function per use: `rec.Code` and `rec.Body` read
// the same as they do everywhere else in this package, and `rec.JSON` is the
// decoded document for the cases that assert on a field. A body that is not JSON
// leaves JSON nil, and the cases that expect JSON say so in their own assertion
// rather than panicking in a helper.
type oidcResponse struct {
	*httptest.ResponseRecorder
	JSON map[string]any
}

// newResponse wraps a recorder, decoding the body when it is a JSON object.
func newResponse(rec *httptest.ResponseRecorder) *oidcResponse {
	out := &oidcResponse{ResponseRecorder: rec}
	fields := map[string]any{}
	if err := jsonUnmarshal(rec.Body.Bytes(), &fields); err == nil {
		out.JSON = fields
	}
	return out
}

// mustCode pulls the authorization code out of a redirect, and fails the test
// with the whole URL when there is not one.
func mustCode(t *testing.T, location string) string {
	t.Helper()

	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("the redirect %q is not a URL: %v", location, err)
	}
	code := parsed.Query().Get("code")
	if code == "" {
		t.Fatalf("the redirect %q carries no code", location)
	}
	return code
}

// mustParseID parses an id the service returned, failing with the value when it
// does not parse.
func mustParseID(t *testing.T, raw string) id.UUID {
	t.Helper()

	parsed, err := id.Parse(raw)
	if err != nil {
		t.Fatalf("the service returned an id that does not parse (%q): %v", raw, err)
	}
	return parsed
}

// newRequestWithBearer builds a request carrying a bearer token and no cookie,
// for the calls where a session would change the answer.
func newRequestWithBearer(method, target, token string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

// newRequestNoCookie builds a request with no credential at all.
func newRequestNoCookie(method, target string) *http.Request {
	return httptest.NewRequest(method, target, nil)
}

// newRequestForm builds a urlencoded POST, which is what the login page and the
// token endpoint both take.
func newRequestForm(method, target string, form url.Values) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// serveRecorder drives a handler and returns the raw recorder, for the cases
// that go through decodeProblem or assert on headers alone.
func serveRecorder(handler http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// sortedKeys is the field names of a decoded body, in order, so a failure
// message about "the body has these fields" is stable between runs.
func sortedKeys(fields map[string]any) []string {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// oauthStateSeparator is the character internal/oauth joins a provider name to a
// state token with, restated here so this file can assert that the value the
// login page seals really is one oauth.NewState minted.
//
// It is a restatement rather than a use of oauth.StateSeparator because the
// assertion is ABOUT the two agreeing; a test that imported the constant it is
// checking against would pass whatever the implementation did.
const oauthStateSeparator = "."

// oauthVerifyState is internal/oauth's VerifyState, aliased so the test names the
// package it is asserting a contract with. There is no wrapper to write: the point
// is that the service uses that function unchanged.
func oauthVerifyState(provider, sealed, presented string) bool {
	return oauth.VerifyState(provider, sealed, presented)
}

// audienceContains says whether an `aud` claim names the given audience.
//
// RFC 7519 allows `aud` to be a single string or an array of them, and which one
// a provider emits is its own choice — a consumer has to handle both. This is
// the one place in the suite that has to, and it is written once here so the
// difference is stated in one comment rather than in every assertion.
func audienceContains(claim any, want string) bool {
	switch value := claim.(type) {
	case string:
		return value == want
	case []any:
		for _, entry := range value {
			if entry == want {
				return true
			}
		}
	}
	return false
}
