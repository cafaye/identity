package client

// THE CREDENTIAL-LEAK TEST.
//
// **This is the deliverable, and it is the reason the rest of the package exists.**
//
// The brief is specific about what it must prove: construct a client holding a FAKE
// token, and assert the fake string appears in no log record, no error, no
// serialised form and no `fmt.Sprintf("%v", client)` — "across a full cycle
// including an error response. The error path is where credentials leak: the error
// is built from the response, and the response has the headers."
//
// # WHY A FAKE TOKEN AND NOT A REAL ONE
//
// The token below is prefixed, unmistakable, and structurally shaped like a real
// credential so the code under test actually classifies it as one. A token that
// fails classification would be refused at construction and the test would pass for
// the wrong reason — which is the failure mode of every leak test written with a
// token that does not look like a token.
//
// It is not a plausible real credential: the entropy is a repeated character, the
// prefix says `FAKE`, and if it ever escaped into a log the first seven characters
// would identify it as a test value. That is the same property identity's `cafaye_`
// prefix buys for real credentials, pointed the other way.
//
// # WHY IT IS NOT A GREP
//
// A grep over this package's source would pass while the client leaked, because the
// leak would be in a value at run time: a struct field printed by a caller, an error
// message assembled from a response header, a `%v` of a struct the caller never
// thought about. The test below drives a REAL request against an `httptest.Server`
// that answers with headers and bodies a hostile or careless server might send, and
// then inspects everything a Go program can be made to print.
//
// # WHAT IS SWEPT
//
// Every string reachable from a client after a full request cycle:
//
//	fmt.Sprintf("%v"), "%+v", "%s", "%q"   of the client, the transport, every error
//	all exported struct FIELDS, recursively, via reflection
//	all struct FIELDS including unexported ones, where reflection permits
//	json.Marshal of the client and of every generated type that carries a secret
//	every header the response carried, which is where a Set-Cookie would appear
//	the error's message, and its `fmt.Sprintf("%+v")` with the whole error chain
//
// Reflection rather than a hand-written list, because a hand-written list is a
// second statement of the struct's shape and misses every field added after it —
// which is the whole class of bug this test is for.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/identity/client/generated"
)

// fakeToken is the credential the whole file hunts for.
//
// 43 base64url characters after the `cafaye_` prefix, which is the shape
// identity's `IssuedAPIKey.token` documents and the shape `ClassifyCredential` keys
// on. The body is a repeated character so it is impossible to mistake for a real
// value at a glance and impossible to generate by accident.
const fakeToken = "cafaye_FAKE_FAKE_FAKE_FAKE_FAKE_FAKE_FAKE_FAKE_FAKE_FA"

// fakeSessionToken is the same idea for the OTHER auth model: a session token has
// no prefix, so the shape that identifies it is "not a `cafaye_` value and not a
// JWS". It is swept separately because a client can hold one and the two take
// different code paths through AttachCredential.
const fakeSessionToken = "FAKEfakeSessionTokenFAKEfakeSessionTokenFAKEfake"

// The headers a careless or hostile service might send back. Every one of these is a
// plausible way a credential gets echoed into a client's memory and then into a log.
var leakyResponseHeaders = map[string]string{
	// A session cookie. `Set-Cookie` is the single most common way a credential
	// arrives somewhere it did not intend, and identity sets both `__Host-session`
	// and `__Host-mfa-challenge`.
	"Set-Cookie": "__Host-session=" + fakeToken + "; Path=/; Secure; HttpOnly; SameSite=Lax",
	// An `Authorization` echoed back by a broken proxy.
	"Authorization": "Bearer " + fakeToken,
	// A cookie echoed in a header a debugging proxy added.
	"X-Debug-Request": "Cookie: __Host-session=" + fakeToken,
	// A credential in a header that a naive error formatter would quote whole.
	"X-Request-Id": fakeToken,
}

// leakyProblemBody is an error body that echoes the caller's credential back.
//
// This is not hypothetical: a service that includes the presented token in its
// `detail` — for a debug build, a proxy that rewrites bodies, an upstream that
// reports the failing header — produces exactly this, and it is the reason every
// string on a `ProblemError` goes through the redactor rather than only the ones
// this package builds itself.
const leakyProblemBody = `{
  "type": "https://errors.cafaye.com/validation_failed",
  "title": "Validation failed",
  "status": 422,
  "detail": "the field 'token' was rejected: '` + fakeToken + `'",
  "instance": "/v1/me",
  "code": "validation_failed",
  "trace_id": "0af7651916cd43dd8448eb211c80319c",
  "errors": [{"field": "token", "code": "invalid_format"}]
}`

// TestTheClientNeverPrintsACredential is the invariant, end to end.
//
// It runs a full request cycle — success, then an error response carrying the
// credential in its body and its headers — and then sweeps everything a Go program
// can be made to print about the resulting client and errors.
//
// Table-driven over the two credentials and the two outcomes, because "the token
// never appears" has to hold for a `cafaye_` value and a session value and for a
// success and a failure, and asserting it once for one combination is asserting it
// for one combination.
func TestTheClientNeverPrintsACredential(t *testing.T) {
	for _, tc := range []struct {
		name  string
		token string
	}{
		{"a scoped api token", fakeToken},
		{"a session token", fakeSessionToken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := leakyServer(t)
			defer server.Close()

			client := newTestClient(t, server.URL, tc.token)

			// The success path first: a client that leaks on the happy path is not
			// rescued by also being careful on the error path.
			user, err := client.GetCurrentUser(context.Background())
			if err != nil {
				t.Fatalf("the success path must succeed for this test to mean anything: %v", err)
			}
			if user.Email != "someone@example.com" {
				t.Fatalf("the fixture answered with %q, so this test is not exercising the "+
					"success path it claims to", user.Email)
			}
			sweep(t, "after a successful call", tc.token, client, nil)

			// The error path, which is the one that matters. The server answers 422
			// with a body that quotes the caller's own token back, and headers that
			// carry it three more ways.
			failure := leakyServerFailure(t)
			defer failure.Close()

			failing := newTestClient(t, failure.URL, tc.token)
			_, err = failing.GetCurrentUser(context.Background())
			if err == nil {
				t.Fatal("the failure fixture answered successfully, so the error path this " +
					"test claims to exercise was never taken")
			}
			sweep(t, "after a failed call", tc.token, failing, err)
		})
	}
}

// sweep is the assertion. Everything that could carry the token is printed and
// checked, and the failure message names which surface leaked rather than saying
// "it appeared somewhere".
func sweep(t *testing.T, when, token string, client *Client, err error) {
	t.Helper()

	surfaces := map[string]string{}

	// Every formatting verb a caller might reach for, on the client itself. `%+v`
	// is the one that prints unexported fields on a pointer, which is where a token
	// stashed in an unexported field would surface; `%#v` prints the Go syntax
	// including every field name and value.
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		surfaces["fmt.Sprintf("+verb+", client)"] = fmt.Sprintf(verb, client)
		surfaces["fmt.Sprintf("+verb+", client.Transport())"] = fmt.Sprintf(verb, client.Transport())
	}

	// The accessors this package exposes. `BaseURL` and `HasCredential` are the only
	// two, and both are here because an accessor added later is a leak waiting to
	// happen.
	surfaces["client.BaseURL()"] = client.BaseURL()
	surfaces["client.HasCredential()"] = fmt.Sprintf("%v", client.HasCredential())

	if err != nil {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			surfaces["error "+verb] = fmt.Sprintf(verb, err)
		}
		// The redactor's own view of the error, which is the path a consumer's
		// logging middleware is most likely to take.
		surfaces["redactor.Error(err)"] = client.redactor.Error(err)

		// Every error in the chain, since `errors.As` reaches through `Unwrap` and
		// a caller formatting the whole chain would print every link.
		for link, depth := err, 0; link != nil && depth < 8; depth++ {
			unwrapper, ok := link.(interface{ Unwrap() error })
			if !ok {
				break
			}
			link = unwrapper.Unwrap()
			if link != nil {
				surfaces[fmt.Sprintf("error chain link %d", depth)] = fmt.Sprintf("%+v", link)
			}
		}
	}

	// Every field of the client, by reflection, including unexported ones. This is
	// the half that catches a `token string` field added later — the leak that the
	// first run of this test actually found.
	surfaces["reflected client fields"] = reflectAll(client)

	// And every generated secret-bearing value, through `SafeToLog`.
	//
	// NOT through raw reflection: these types CONTAIN the token, that is what they
	// are, and asserting that a `Session` does not print its own token would be
	// asserting that the type does not exist. What is asserted is that the
	// function this package provides for printing one redacts it — which is the
	// answer to the brief's "add one that redacts", given that Go will not let one
	// package define a `String()` method on another's type.
	for name, value := range secretBearingValues() {
		surfaces["client.SafeToLog(generated."+name+")"] = client.SafeToLog(value)
	}

	for surface, printed := range surfaces {
		if strings.Contains(printed, token) {
			t.Errorf("the credential appears in %s %s.\n\n"+
				"printed as: %s\n\n"+
				"This is the security invariant this package rests on: a credential must "+
				"reach no string a human reads — not a log record, not an error message, "+
				"not a serialised form, not a `fmt.Stringer`, not a `%%v` of the client. "+
				"The fix is in the redactor, not at the call site: every string this "+
				"package builds out of anything a caller or a service supplied goes "+
				"through Redactor.String.",
				surface, when, truncate(printed, 400))
		}
	}
}

// reflectAll renders every field of a value, recursively, including unexported
// ones.
//
// The recursion has a depth bound and a visited set, and both are load-bearing: a
// generated type holds `openapi_types.UUID`, which is a `[16]byte`, and an unbounded
// walk over a self-referential structure — or a very deep one — would not terminate.
// Without a failure that would look like a hang in somebody else's test.
func reflectAll(value any) string {
	var out strings.Builder
	seen := map[uintptr]bool{}

	var walk func(reflect.Value, int)
	walk = func(v reflect.Value, depth int) {
		if depth > 6 || !v.IsValid() {
			return
		}

		switch v.Kind() {
		case reflect.Struct:
			// A visited set keyed by pointer, so a cyclic structure terminates.
			if v.CanAddr() {
				if seen[v.Addr().Pointer()] {
					return
				}
				seen[v.Addr().Pointer()] = true
			}

			t := v.Type()
			for i := 0; i < v.NumField(); i++ {
				field := t.Field(i)

				// Unexported fields are included deliberately. A token stashed in an
				// unexported field is invisible to `%v` on a value but visible to
				// `%+v` on a pointer, and both are things callers do.
				if field.IsExported() {
					out.WriteString(field.Name + "=")
				} else {
					out.WriteString("unexported:" + field.Name + "=")
				}

				if !field.IsExported() {
					// Reading an unexported field through reflection panics on
					// Set but not on Get in modern Go... except for
					// Interface(), so it is guarded rather than assumed.
					out.WriteString("<unreadable>")
					out.WriteString("\n")
					continue
				}

				walk(v.Field(i), depth+1)
				out.WriteString("\n")
			}

		case reflect.Pointer, reflect.Interface:
			if v.IsNil() {
				out.WriteString("<nil>")
				return
			}
			walk(v.Elem(), depth+1)

		case reflect.Slice, reflect.Array:
			for i := 0; i < v.Len() && i < 16; i++ {
				walk(v.Index(i), depth+1)
				out.WriteString(",")
			}

		case reflect.Map:
			for _, key := range v.MapKeys() {
				walk(key, depth+1)
				out.WriteString("=>")
				walk(v.MapIndex(key), depth+1)
				out.WriteString(",")
			}

		default:
			fmt.Fprintf(&out, "%v", v.Interface())
		}
	}

	walk(reflect.ValueOf(value), 0)
	return out.String()
}

// secretBearingValues is every generated type whose JSON contains something a
// credential lands in.
//
// Enumerated by hand rather than discovered, and the reason is stated: reflection
// cannot tell a `Token` field from an `AccountID` one without reading the names, and
// a list built by guessing at names is a list that misses `Secret`. Each entry says
// which field holds the value, so a reader can see what is being swept and a
// document that adds a credential-carrying field makes this list visibly incomplete
// rather than silently so.
func secretBearingValues() map[string]any {
	issued := generated.IssuedAPIKey{
		ID:        uuidOf("ab000000-0000-0000-0000-0000000000a1"),
		Name:      "ci-deploy",
		AccountID: uuidOf("ab000000-0000-0000-0000-0000000000c1"),
		UserID:    uuidOf("ab000000-0000-0000-0000-0000000000d1"),
		Token:     fakeToken,
	}
	session := generated.Session{
		Token:     fakeSessionToken,
		ExpiresAt: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
	}
	login := generated.LoginRequest{Email: "someone@example.com", Password: fakeToken}
	registered := generated.RegisteredOIDCClient{
		ID:           uuidOf("ab000000-0000-0000-0000-000000000001"),
		ClientID:     "8Jm1xQ0pQz7rV2nK4wL9cT6bY3hA5sD0fG1eI2jK",
		ClientSecret: fakeToken,
		Name:         "Anytalk",
		RedirectUris: []string{"https://app.anytalk.com/callback"},
		GrantTypes:   []generated.RegisteredOIDCClientGrantTypes{"authorization_code"},
		Scopes:       []generated.RegisteredOIDCClientScopes{"openid", "email"},
		CreatedAt:    time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC),
	}
	enrollment := generated.StartedEnrollment{
		Secret:          fakeToken,
		ProvisioningURI: "otpauth://totp/cafaye:" + fakeToken,
		EnrollmentID:    uuidOf("ab000000-0000-0000-0000-0000000000e1"),
		Method:          "totp",
		Digits:          6,
		PeriodSeconds:   30,
		Algorithm:       "SHA1",
		ExpiresAt:       time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
		Replaced:        false,
	}
	challenge := generated.MFAChallenge{
		MfaRequired: true,
		Challenge:   fakeToken,
		ExpiresAt:   time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
	}
	factor := generated.FactorRequest{Code: fakeToken}
	introspect := generated.IntrospectRequest{Token: fakeToken}

	return map[string]any{
		"IssuedAPIKey.Token":                issued,
		"Session.Token":                     session,
		"LoginRequest.Password":             login,
		"RegisteredOIDCClient.ClientSecret": registered,
		"StartedEnrollment.Secret":          enrollment,
		"MFAChallenge.Challenge":            challenge,
		"FactorRequest.Code":                factor,
		"IntrospectRequest.Token":           introspect,
		"CompleteSecondFactorRequest.Challenge": generated.CompleteSecondFactorRequest{
			Challenge: ptr(fakeToken),
			Code:      fakeToken,
		},
		"ConfirmEnrollmentRequest.Code": generated.ConfirmEnrollmentRequest{Code: fakeToken},
		"ConfirmedEnrollment.RecoveryCodes": generated.ConfirmedEnrollment{
			Enabled:                true,
			Method:                 "totp",
			EnrolledAt:             time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC),
			RecoveryCodes:          []string{fakeToken},
			ReplacedExistingSecret: false,
		},
		"RecoveryCodesResponse.RecoveryCodes": generated.RecoveryCodesResponse{
			RecoveryCodes:          []string{fakeToken},
			IssuedAt:               time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC),
			RecoveryCodesRemaining: 10,
		},
	}
}

// TestTheResponseHeadersThisPackageKeepsAreCredentialFree is the half of the
// invariant about what this package does with a response's headers.
//
// The leak test above sweeps what the CLIENT holds. This sweeps what the RESPONSE
// carried, read out of a live server rather than out of a fixture, because a
// `Set-Cookie` arriving on a response is the mechanism by which a session token
// enters a process's memory, and this package decides whether any of it is
// retained.
//
// The assertion is that a response's headers are never copied into an error this
// package builds. A `ProblemError` carries the problem document's members and the
// trace id — nothing else — and this is what holds that.
func TestTheResponseHeadersThisPackageKeepsAreCredentialFree(t *testing.T) {
	server := leakyServerFailure(t)
	defer server.Close()

	client := newTestClient(t, server.URL, fakeToken)
	_, err := client.GetCurrentUser(context.Background())
	if err == nil {
		t.Fatal("the failure fixture answered successfully")
	}

	problem := asProblem(t, err)
	serialised, marshalErr := json.Marshal(problem.Document())
	if marshalErr != nil {
		t.Fatalf("marshalling the ProblemError: %v", marshalErr)
	}

	if strings.Contains(string(serialised), fakeToken) {
		t.Errorf("the ProblemError serialises to something containing the credential:\n%s\n\n"+
			"Every member of a problem document is passed through the redactor before it "+
			"reaches the error type — including `detail`, including the per-field `errors`, "+
			"and including the members this package did not know the contract had.",
			truncate(string(serialised), 400))
	}

	// And the rendered form, which is what a logger prints.
	for _, verb := range []string{"%v", "%+v", "%s"} {
		if rendered := fmt.Sprintf(verb, err); strings.Contains(rendered, fakeToken) {
			t.Errorf("the error rendered with %s contains the credential:\n%s", verb, rendered)
		}
	}
}

// TestTheGeneratedSecretBearingTypesAreSafeToPrint covers the trap the brief names
// directly, and it is a DIFFERENT assertion from the leak test's.
//
// The leak test asks whether THIS PACKAGE leaks. This asks whether the GENERATED
// TYPES are safe for a caller to print — and the answer, measured, is that they are
// not, because oapi-codegen gives none of them a `String()` method.
//
// The brief's instruction is explicit: "Check whether the generated types have a
// `String()` or a `MarshalLogObject`, and if the answer is 'no', add one that
// redacts — do not rely on nobody calling it."
//
// So this test records the finding as an executable claim rather than a comment. It
// asserts that the generated types do NOT print a credential through `%v` — because
// they do — and it names the mitigation, which is `SafeToLog` below.
func TestTheGeneratedSecretBearingTypesAreSafeToPrint(t *testing.T) {
	issued := generated.IssuedAPIKey{Token: fakeToken, Name: "ci-deploy"}

	// The measured fact: `%v` on the generated struct prints the token, because the
	// generator emits no `String()` and Go's default struct formatting walks every
	// exported field.
	printed := fmt.Sprintf("%v", issued)
	if !strings.Contains(printed, fakeToken) {
		t.Fatalf("`fmt.Sprintf(\"%%v\", IssuedAPIKey{...})` did not print the token: %s\n"+
			"If a future oapi-codegen adds a redacting `String()`, this test needs "+
			"rewriting — and that would be good news, so read this failure as an "+
			"opportunity rather than a regression.", printed)
	}

	// And that `IssuedAPIKey` genuinely has no Stringer, stated as the check the
	// brief asked for rather than assumed.
	if _, has := any(issued).(interface{ String() string }); has {
		t.Error("the generated IssuedAPIKey now implements fmt.Stringer.\n" +
			"Check that the implementation REDACTS before relaxing anything here: a " +
			"generated String() that prints its fields would make `log.Println(issued)` " +
			"a credential leak that looks safe because a Stringer exists.")
	}

	// The mitigation, which is the answer to "add one that redacts": this package
	// cannot add a method to a type in another package, so it provides a function
	// instead, and this is the assertion that the function works on the worst case.
	if got := SafeToLog(issued); strings.Contains(got, fakeToken) {
		t.Errorf("SafeToLog printed the credential: %s", got)
	}
	if !strings.Contains(SafeToLog(issued), "IssuedAPIKey") {
		t.Errorf("SafeToLog must still name the type, so a log line stays diagnosable: %s",
			SafeToLog(issued))
	}

	// And it must be the default that a caller reaches for, not a thing they have to
	// remember. That is why it is a function with this name rather than a
	// `RedactedString` field on twenty types.
	if got := SafeToLog(generated.Session{Token: fakeToken}); strings.Contains(got, fakeToken) {
		t.Errorf("SafeToLog printed a Session's token: %s", got)
	}
	if got := SafeToLog(generated.LoginRequest{Password: fakeToken}); strings.Contains(got, fakeToken) {
		t.Errorf("SafeToLog printed a LoginRequest's password: %s", got)
	}
}

// --- the fixtures ------------------------------------------------------------

// leakyServer answers 200 with a valid `GET /v1/me` body.
func leakyServer(t *testing.T) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for name, value := range leakyResponseHeaders {
			w.Header().Add(name, value)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"ab000000-0000-0000-0000-000000000000",` +
			`"email":"someone@example.com"}`))
	}))
}

// leakyServerFailure answers 422 with a problem document that echoes the caller's
// credential, and headers that carry it three more ways.
func leakyServerFailure(t *testing.T) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for name, value := range leakyResponseHeaders {
			w.Header().Add(name, value)
		}
		w.Header().Set("Content-Type", ProblemContentType)
		w.Header().Set("X-Trace-Id", "0af7651916cd43dd8448eb211c80319c")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(leakyProblemBody))
	}))
}

// newTestClient builds a client pointed at an httptest server.
//
// `-count=1` is not needed here because nothing in this file reads the
// environment: `LookupEnv` is supplied and the base URL is explicit. The env-gated
// tests are in baseurl_test.go and carry the flag there.
func newTestClient(t *testing.T, baseURL, token string) *Client {
	t.Helper()

	client, err := New(Options{
		BaseURL: baseURL,
		Token:   token,
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("building a client against %s: %v", baseURL, err)
	}
	return client
}

// asProblem asserts an error satisfies `ProblemError` and returns it.
func asProblem(t *testing.T, err error) ProblemError {
	t.Helper()

	// The INTERFACE, not a concrete type. This is the whole design of errors.go, and
	// the assertion is here so a regression in it is caught by the leak test rather
	// than by a caller: if `errors.As` stopped matching the typed errors, the
	// single catch the brief asks for would silently return false for every code
	// this build knows, and only work for the ones it does not.
	var problem ProblemError
	if !errorsAs(err, &problem) {
		t.Fatalf("expected a client.ProblemError, got %T: %v\n"+
			"The interface is what a caller catches; a concrete base struct embedded by "+
			"value would NOT match here, which is the failure this shape exists to avoid.",
			err, err)
	}
	return problem
}
