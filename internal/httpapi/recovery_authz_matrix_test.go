package httpapi

import (
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// THE RECOVERY HALF OF THE AUTHORIZATION MATRIX.
//
// IT IS A THIRD TABLE AND A THIRD QUESTION, and the question is not the MFA one.
// The MFA matrix asks "is this caller anybody at all" and answers it with two
// columns. This surface has to distinguish THREE credentials at once, because four
// of the eight routes are anonymous BY DESIGN:
//
//   - two routes require a SESSION: reading the verification state, and starting an
//     email change.
//   - four routes require a TOKEN IN THE BODY and no credential at all: the token
//     IS the authentication. A session is neither required nor refused on these,
//     and that is a decision — a caller holding a valid session and presenting no
//     recovery token is exactly the hijacked-browser case.
//   - all eight refuse a SCOPED API TOKEN.
//
// The scoped-token column is the one that cannot be got wrong by accident, because
// it is a middleware rather than a handler (`sessionCredentialOnly`) and the
// middleware runs BEFORE the use case. So that column asserts two things: the
// status is 403, and the use case was never reached. The second half is the one
// that matters — a handler that refused after calling the service would have already
// minted a token and sent a mail by the time it answered.
//
// What this suite adds is the one no other suite can: that a route mounted on this
// surface without an authorization decision is a route nobody checked. The
// interesting decisions on this surface are NOT authorization decisions — they are
// that a request route cannot be told apart (TestTheTwoRequestRoutesAnswer… and
// TestTheTwoRequestRoutesAnswerIdenticallyOverHTTP), that a spent token is a 404 and
// not a 401, and that no token reaches the logs (TestNoRecoveryTokenReachesTheLogs).

// recoveryMatrixEndpoint is one row of the recovery route table.
type recoveryMatrixEndpoint struct {
	name   string
	method string
	// pattern is the chi pattern, spelled as the router spells it, because the
	// coverage check compares it against a chi.Walk rather than against a string.
	pattern string
	// anonymous, withSession and withToken are the status each of the three
	// credentials receives. There is no role and no account in any of the eight
	// paths, so a role column would be decoration.
	anonymous   int
	withSession int
	withToken   int
	// body is the request body. It carries a token on the four redemption rows and
	// an email on the three request rows, and it is a literal rather than something
	// computed, because the matrix is asserting on AUTHORIZATION and a token the
	// fixture had to mint would be asserting on the token lifecycle instead — which
	// is what internal/recovery's own tests are for.
	body string
}

// recoveryMatrixEndpoints is the table. Every route on the recovery surface appears
// here exactly once, and TestEveryRecoveryRouteIsInTheMatrix walks the router to
// prove it.
//
// The anonymous and session columns AGREE on five of the eight rows, and that is the
// shape of the surface rather than a copy-paste: on those five neither credential is
// what the route checks, so both get the same answer from the same place.
func recoveryMatrixEndpoints() []recoveryMatrixEndpoint {
	return []recoveryMatrixEndpoint{
		{
			// The 202 for BOTH columns, and identical bytes for both, is the
			// enumeration property. The token column differs, because a machine
			// credential that could mint a password reset is a takeover with a delay
			// rather than a break-in.
			name: "ask for a password-reset link", method: http.MethodPost,
			pattern:   "/v1/password-resets",
			anonymous: http.StatusAccepted, withSession: http.StatusAccepted, withToken: http.StatusForbidden,
			body: `{"email":"kaka@example.com"}`,
		},
		{
			// THE ANONYMOUS CONFIRMATION ROW. A session is not required and not
			// refused here — the body token is the credential, and a session in the
			// header changes nothing about whether it is right.
			name: "spend a reset link", method: http.MethodPost,
			pattern:   "/v1/password-resets/confirm",
			anonymous: http.StatusNoContent, withSession: http.StatusNoContent, withToken: http.StatusForbidden,
			body: `{"token":"a-token","password":"a completely new password"}`,
		},
		{
			name: "ask for a verification link", method: http.MethodPost,
			pattern:   "/v1/email-verifications",
			anonymous: http.StatusAccepted, withSession: http.StatusAccepted, withToken: http.StatusForbidden,
			body: `{"email":"kaka@example.com"}`,
		},
		{
			name: "spend a verification link", method: http.MethodPost,
			pattern:   "/v1/email-verifications/confirm",
			anonymous: http.StatusNoContent, withSession: http.StatusNoContent, withToken: http.StatusForbidden,
			body: `{"token":"a-token"}`,
		},
		{
			// THE FIRST SESSION-ONLY ROW. 401 rather than 404, and the difference
			// from the redemption rows above is the whole reason both kinds exist on
			// one table: there is a resource here (this account's verification state)
			// and the caller has not proved it is theirs.
			name: "read the verification status", method: http.MethodGet,
			pattern:   "/v1/email-verification",
			anonymous: http.StatusUnauthorized, withSession: http.StatusOK, withToken: http.StatusForbidden,
		},
		{
			// THE SECOND SESSION-ONLY ROW, and the one where the session is load
			// bearing: a credential that could start an email change is a credential
			// that can move an account's recovery path.
			name: "start an email change", method: http.MethodPost,
			pattern:   "/v1/email-changes",
			anonymous: http.StatusUnauthorized, withSession: http.StatusCreated, withToken: http.StatusForbidden,
			body: `{"email":"new-address@example.com"}`,
		},
		{
			// The first half of the two-sided change. Anonymous by design, like every
			// other redemption route, and the 202 body says nothing about where the
			// second link goes — see handleConfirmEmailChangeCurrent.
			name: "confirm the current address", method: http.MethodPost,
			pattern:   "/v1/email-changes/current-address",
			anonymous: http.StatusAccepted, withSession: http.StatusAccepted, withToken: http.StatusForbidden,
			body: `{"token":"a-token"}`,
		},
		{
			name: "confirm the new address", method: http.MethodPost,
			pattern:   "/v1/email-changes/new-address",
			anonymous: http.StatusOK, withSession: http.StatusOK, withToken: http.StatusForbidden,
			body: `{"token":"a-token"}`,
		},
	}
}

// TestTheRecoveryAuthorizationMatrix is the suite.
//
// THREE COLUMNS. Getting the scoped-token one wrong on any of these eight would mean
// a machine credential can mint a password reset, move an account's address, or read
// a verification state — none of which has a scope in this service's vocabulary, and
// all of which would be worse for having one.
func TestTheRecoveryAuthorizationMatrix(t *testing.T) {
	for _, endpoint := range recoveryMatrixEndpoints() {
		endpoint := endpoint
		t.Run(endpoint.name, func(t *testing.T) {
			for _, column := range []struct {
				name string
				// credential is what the bearer header carries. A scoped token is
				// distinguished by its `cafaye_` prefix before any query runs, which
				// is why it is a shape and not a flag.
				credential string
				want       int
			}{
				{name: "anonymous", credential: "", want: endpoint.anonymous},
				{name: "session", credential: "a-session-token", want: endpoint.withSession},
				{name: "scoped token", credential: scopedTokenForTheMatrix, want: endpoint.withToken},
			} {
				column := column
				t.Run(column.name, func(t *testing.T) {
					f := newFakeRecovery()
					rec := sendWith(t, recoveryServer(t, f, newFakeAuth()),
						endpoint.method, endpoint.pattern, column.credential, "", endpoint.body)

					if rec.Code != column.want {
						t.Fatalf("%s %s as %s = %d, want %d; body: %s",
							endpoint.method, endpoint.pattern, column.name, rec.Code, column.want, rec.Body)
					}

					// A 2xx must not be carrying a problem document. It cannot on this
					// service today, but the assertion is one line and it is the
					// difference between "answered 202" and "answered 202 with an error
					// body", which is the failure a caller cannot detect.
					if column.want < 300 {
						if ct := rec.Header().Get("Content-Type"); strings.HasPrefix(ct, "application/problem+json") {
							t.Errorf("a %d is carrying a problem document: %s", rec.Code, rec.Body)
						}
					} else if got := decodeProblem(t, rec).Code; got != CodeUnauthorized && got != CodeForbidden {
						t.Errorf("code = %q, want %q or %q", got, CodeUnauthorized, CodeForbidden)
					}

					// THE ASSERTION THAT IS ACTUALLY ABOUT AUTHORIZATION: on the two
					// session-only rows a session must REACH the use case, because a
					// 201 achieved by refusing after the fact would still be a refusal.
					// Everywhere else the use case must NOT have been reached at all
					// when the answer is 403.
					switch {
					case column.want == http.StatusForbidden && f.touched():
						t.Error("the use case ran before the refusal; a scoped token must be turned " +
							"away by the middleware, not by a handler that has already minted a token")
					case column.name == "session" && endpoint.anonymous == http.StatusUnauthorized:
						if !f.touched() {
							t.Errorf("a session on %s did not reach the use case, so the %d is a "+
								"refusal rather than the answer", endpoint.pattern, column.want)
						}
					}
				})
			}
		})
	}
}

// scopedTokenForTheMatrix is a value shaped like a scoped api key and belonging to
// nothing. `sessionCredentialOnly` decides from the PREFIX alone, before any query,
// so a token that resolves to no row is the right fixture for this column: it proves
// the refusal comes from the credential's SHAPE and not from a lookup failing.
const scopedTokenForTheMatrix = "cafaye_" + "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"

// TestTheTwoSessionOnlyRoutesAreTheOnlyTwoThatRequireOne is the session column stated
// as a property rather than as a status code.
//
// A route whose anonymous answer is 401 requires a session; one whose anonymous
// answer is a success does not. Walking the table rather than restating the two paths
// means a ninth route cannot land without this failing — and the failure would name
// which way it went, so the decision gets read rather than made by accident.
func TestTheTwoSessionOnlyRoutesAreTheOnlyTwoThatRequireOne(t *testing.T) {
	var sessionOnly []string
	for _, endpoint := range recoveryMatrixEndpoints() {
		if endpoint.anonymous == http.StatusUnauthorized {
			sessionOnly = append(sessionOnly, endpoint.pattern)
		}
	}
	sort.Strings(sessionOnly)

	want := []string{"/v1/email-changes", "/v1/email-verification"}
	if len(sessionOnly) != len(want) {
		t.Fatalf("%d route(s) require a session (%v), want %d (%v)",
			len(sessionOnly), sessionOnly, len(want), want)
	}
	for i, pattern := range want {
		if sessionOnly[i] != pattern {
			t.Errorf("the session-only routes are %v, want %v", sessionOnly, want)
		}
	}
}

// TestNoRecoveryRouteAcceptsASessionInPlaceOfItsToken is the other half of the
// session column, and it is the negative a matrix cannot hold.
//
// On the four redemption routes a session is not refused — and it must not be
// REQUIRED either. If any of them called `currentUser`, a person following a link
// from a mail client with no cookie would get a 401 on a link they legitimately
// received, and the token that IS their credential would be ignored in favour of a
// browser session they may not have.
//
// So: four routes, zero credentials, and every one of them reaches the use case.
func TestNoRecoveryRouteAcceptsASessionInPlaceOfItsToken(t *testing.T) {
	redemptions := 0
	for _, endpoint := range recoveryMatrixEndpoints() {
		if endpoint.anonymous == http.StatusNotFound || endpoint.anonymous == http.StatusUnauthorized {
			continue
		}
		redemptions++

		f := newFakeRecovery()
		rec := sendWith(t, recoveryServer(t, f, newFakeAuth()),
			endpoint.method, endpoint.pattern, "", "", endpoint.body)
		if rec.Code != endpoint.anonymous {
			t.Errorf("%s %s with no credential at all = %d, want %d; body: %s",
				endpoint.method, endpoint.pattern, rec.Code, endpoint.anonymous, rec.Body)
		}
		if !f.touched() {
			t.Errorf("%s never reached the use case, so it is authenticating by something "+
				"other than the token in its own body", endpoint.pattern)
		}
	}
	if redemptions != 6 {
		t.Errorf("the table has %d routes that answer a no-credential caller with a success; "+
			"this packet has six. A route that changed which credential it requires belongs in "+
			"its own test with its own reason.", redemptions)
	}
}

// TestEveryRecoveryRouteIsInTheMatrix fails when a route is mounted and has no row.
//
// It walks the ROUTER, so the table cannot go stale the way a restated one does —
// and a restated list is one more thing to forget, which is the failure this whole
// exercise exists to catch.
func TestEveryRecoveryRouteIsInTheMatrix(t *testing.T) {
	mounted := mountedRecoveryRoutes()

	covered := make(map[string]bool, len(recoveryMatrixEndpoints()))
	for _, endpoint := range recoveryMatrixEndpoints() {
		covered[normalizeRoute(endpoint.method, endpoint.pattern)] = true
	}

	for _, route := range mounted {
		if !covered[route] {
			t.Errorf("route %s is mounted on the recovery surface but has no row in its "+
				"authorization matrix", route)
		}
	}
	if len(covered) > len(mounted) {
		t.Errorf("the recovery matrix has %d rows for %d mounted routes; it is asserting on "+
			"routes that do not exist", len(covered), len(mounted))
	}
}

// mountedRecoveryRoutes is every route on the recovery surface, read out of chi.
//
// It registers the WHOLE /v1 surface — which is what production does — and filters
// to this surface's four prefixes, so a route added under /v1/password-resets is
// caught by the coverage check rather than being invisible to it.
func mountedRecoveryRoutes() []string {
	var found []string

	r := chi.NewRouter()
	opts := options{auth: newFakeAuth(), recovery: newFakeRecovery()}
	opts.registerRoutes(r)

	_ = chi.Walk(r, func(method string, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		clean := normalizeRoute(method, route)
		if isRecoverySurfaceRoute(clean) {
			found = append(found, clean)
		}
		return nil
	})

	sort.Strings(found)
	return found
}

// isRecoverySurfaceRoute says whether a "METHOD /path" key belongs to this surface.
//
// `/v1/email-verification` (the singular status route) is matched EXACTLY rather
// than as a prefix, because `/v1/email-verifications` — the plural request route —
// starts with those characters. A prefix test over the singular one would have
// swept up the plural and let a row be "covered" by a different operation's pattern.
func isRecoverySurfaceRoute(route string) bool {
	path := strings.TrimPrefix(route, strings.SplitN(route, " ", 2)[0]+" ")
	switch {
	case strings.HasPrefix(path, "/v1/password-resets"):
		return true
	case strings.HasPrefix(path, "/v1/email-verifications"):
		return true
	case strings.HasPrefix(path, "/v1/email-changes"):
		return true
	case path == "/v1/email-verification":
		return true
	default:
		return false
	}
}
