package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cafaye/identity/internal/mfa"
	"github.com/cafaye/identity/internal/platform/id"
)

// THE MFA HALF OF THE AUTHORIZATION MATRIX.
//
// It is a separate table and a separate suite from the tenancy one, and the reason
// is that the QUESTION is different. Every route on the tenancy surface asks "may
// this caller act on this account", which needs a role and an account in the path.
// Every route here asks "is this caller anybody at all" — there is no account in the
// path and no role to compare — so the whole matrix is two columns: an anonymous
// caller and an authenticated one.
//
// WHICH MEANS THE TABLE IS SMALL AND THAT IS CORRECT. The interesting decisions on
// this surface are not authorization decisions, they are:
//
//   - does a correct password mint a session (no — TestACorrectPasswordAnswers202…)
//   - is a replayed code accepted (no — TestAWrongCodeIs401AndIsNot…)
//   - is a destructive route gated on a factor (yes — TestTheDestructiveRoutes…)
//   - is the lockout per-factor (yes — TestTheSecondFactorLockoutIs423…)
//
// and each of those has its own test with the property named. What this suite adds
// is the one NO other suite can: that a route mounted without an authorization
// decision is a route nobody checked.
//
// TestEveryMFARouteIsInTheMatrix reads the routes out of chi rather than restating
// them, so the list cannot go stale the way a restated one does — and a restated
// list is one more thing to forget. This is the same argument the tenancy matrix
// makes, for the same reason: the forgotten row is the one that was going to be the
// vulnerability.

// mfaMatrixEndpoint is one row of the MFA route table.
type mfaMatrixEndpoint struct {
	name   string
	method string
	// pattern is the chi pattern, spelled exactly as the router spells it, because
	// the coverage check compares it against a chi.Walk.
	pattern string
	// anonymous is the status a caller with no credential receives. 401 for every
	// row here, and it is the assertion this suite exists for.
	anonymous int
	// authenticated is the status an authenticated caller receives.
	//
	// It is 2xx for the five management routes — and 401 for the login's second
	// step, which is the one honest asymmetry on this surface and is spelled out on
	// that row.
	authenticated int
	// body renders the request body from the case's fixture, and path renders the
	// concrete path for the one row with a parameter. Both take the test explicitly
	// rather than reaching for it out of the fixture, because a helper that can fail
	// a test from somewhere that has no test fails in a confusing place.
	body func(t *testing.T, s *mfaServer) string
	path func(t *testing.T, s *mfaServer) string
}

// mfaMatrixEndpoints is the table. Every route on the MFA surface appears here
// exactly once.
func mfaMatrixEndpoints() []mfaMatrixEndpoint {
	return []mfaMatrixEndpoint{
		{
			name: "read the second-factor status", method: http.MethodGet,
			pattern: "/v1/mfa", anonymous: http.StatusUnauthorized, authenticated: http.StatusOK,
		},
		{
			name: "start an enrollment", method: http.MethodPost,
			pattern: "/v1/mfa/enrollments", anonymous: http.StatusUnauthorized, authenticated: http.StatusCreated,
			// A code, because the fixture's actor ALREADY has a second factor and so
			// this route is a ROTATION, which requires one. Without it the row would
			// be asserting a 401 where the table says 201 — and it would be right
			// about the endpoint and wrong about the fixture, which is the two
			// failures this table exists to prevent.
			body: func(t *testing.T, s *mfaServer) string {
				return `{"code":"` + s.codeFor(t) + `"}`
			},
		},
		{
			name: "confirm an enrollment", method: http.MethodPost,
			pattern:   "/v1/mfa/enrollments/{enrollmentID}/confirm",
			anonymous: http.StatusUnauthorized, authenticated: http.StatusOK,
			// The actor's OWN pending enrollment, created for this case, and a code
			// produced from the secret that came back with it. Anything less would be
			// asserting on a 404 rather than on the authorization.
			path: func(t *testing.T, s *mfaServer) string {
				return "/v1/mfa/enrollments/" + s.pendingEnrollmentID(t) + "/confirm"
			},
			body: func(t *testing.T, s *mfaServer) string {
				return `{"code":"` + s.pendingEnrollmentCode(t) + `"}`
			},
		},
		{
			name: "regenerate the recovery codes", method: http.MethodPost,
			pattern: "/v1/mfa/recovery-codes", anonymous: http.StatusUnauthorized, authenticated: http.StatusOK,
			body: func(t *testing.T, s *mfaServer) string {
				return `{"code":"` + s.codeFor(t) + `"}`
			},
		},
		{
			name: "disable the second factor", method: http.MethodDelete,
			pattern: "/v1/mfa", anonymous: http.StatusUnauthorized, authenticated: http.StatusNoContent,
			body: func(t *testing.T, s *mfaServer) string {
				return `{"code":"` + s.codeFor(t) + `"}`
			},
		},
		{
			// THE ONE ROW WHERE AN AUTHENTICATED CALLER IS NOT 2xx, and it is here
			// rather than excluded so that a route added here cannot be forgotten.
			//
			// A session is not a challenge. A caller holding a perfectly good session
			// has still presented no second factor, and this route's credential is the
			// challenge — so the honest answer for both columns is 401, and the test
			// below says why the two are not the same test.
			name: "complete a second factor", method: http.MethodPost,
			pattern: "/v1/session/mfa", anonymous: http.StatusUnauthorized, authenticated: http.StatusUnauthorized,
			body: func(*testing.T, *mfaServer) string { return `{"code":"123456"}` },
		},
	}
}

// TestTheMFAAuthorizationMatrix is the suite.
//
// TWO COLUMNS, and the anonymous one is the assertion. There is no role to compare
// and no account in the path, so "not signed in" is the only denial available — and
// getting it wrong on any one of these routes would mean a second factor is
// something an anonymous caller can turn off, replace, reissue codes for, or read.
func TestTheMFAAuthorizationMatrix(t *testing.T) {
	for _, endpoint := range mfaMatrixEndpoints() {
		endpoint := endpoint
		t.Run(endpoint.name, func(t *testing.T) {
			t.Run("anonymous", func(t *testing.T) {
				s := newMFAServer(t)
				email, _ := s.signUp(t)
				s.enrollAndConfirmFor(t, email, s.token)

				rec := s.send(t, endpoint, "", enrolledUser{})
				if rec.Code != endpoint.anonymous {
					t.Fatalf("%s %s as anonymous = %d, want %d; body: %s",
						endpoint.method, endpoint.pattern, rec.Code, endpoint.anonymous, rec.Body)
				}
				if got := decodeProblem(t, rec).Code; got != CodeUnauthorized {
					t.Errorf("code = %q, want %q", got, CodeUnauthorized)
				}
			})

			t.Run("authenticated", func(t *testing.T) {
				s := newMFAServer(t)
				email, _ := s.signUp(t)
				user := s.enrollAndConfirmFor(t, email, s.token)

				// A fresh period, so the code every body carries has not been spent
				// by the fixture's own sign-in.
				s.clock.Advance(mfa.Period + time.Second)

				rec := s.send(t, endpoint, s.token, user)
				if rec.Code != endpoint.authenticated {
					t.Fatalf("%s %s as an authenticated caller = %d, want %d; body: %s",
						endpoint.method, endpoint.pattern, rec.Code, endpoint.authenticated, rec.Body)
				}
			})
		})
	}
}

// TestEveryMFARouteIsInTheMatrix fails when a route is mounted and has no row.
//
// It walks the ROUTER, so the list cannot drift the way a restated one does. This
// is the same argument the tenancy matrix makes, for the same reason.
func TestEveryMFARouteIsInTheMatrix(t *testing.T) {
	mounted := mountedMFARoutes()

	covered := make(map[string]bool, len(mfaMatrixEndpoints()))
	for _, e := range mfaMatrixEndpoints() {
		covered[normalizeRoute(e.method, e.pattern)] = true
	}

	for _, route := range mounted {
		if !covered[route] {
			t.Errorf("route %s is mounted but has no row in the MFA authorization matrix", route)
		}
	}
	if len(covered) > len(mounted) {
		t.Errorf("the MFA matrix has %d rows for %d mounted routes; it is asserting on routes that do not exist",
			len(covered), len(mounted))
	}
}

// mountedMFARoutes is every route on the MFA surface, read out of chi itself.
//
// It registers the WHOLE /v1 surface — that is what production does — and then
// filters to this surface's paths. The filter is the two prefixes and the one extra
// path spelled out, rather than a hardcoded list of routes, so a route added under
// /v1/mfa is caught by the coverage check and one added elsewhere on the surface is
// caught by the tenancy matrix.
func mountedMFARoutes() []string {
	var found []string

	r := chi.NewRouter()
	opts := options{auth: newFakeAuth(), mfa: newFakeMFAManage()}
	opts.registerRoutes(r)

	_ = chi.Walk(r, func(method string, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		clean := normalizeRoute(method, route)
		if isMFASurfaceRoute(clean) {
			found = append(found, clean)
		}
		return nil
	})

	sort.Strings(found)
	return found
}

// isMFASurfaceRoute says whether a "METHOD /path" key belongs to this surface.
func isMFASurfaceRoute(route string) bool {
	path := strings.TrimPrefix(route, strings.SplitN(route, " ", 2)[0]+" ")
	return strings.HasPrefix(path, "/v1/mfa") || path == "/v1/session/mfa"
}

// ---------------------------------------------------------------------------
// fixture helpers the table needs
// ---------------------------------------------------------------------------

// send issues one matrix request.
func (s *mfaServer) send(t *testing.T, endpoint mfaMatrixEndpoint, token string, _ enrolledUser) *httptest.ResponseRecorder {
	t.Helper()

	path := endpoint.pattern
	if endpoint.path != nil {
		path = endpoint.path(t, s)
	}
	body := ""
	if endpoint.body != nil {
		body = endpoint.body(t, s)
	}
	return sendWith(t, s.handler, endpoint.method, path, token, "", body)
}

// codeFor is a code from the fixture user's authenticator at the fixture's current
// instant. It reads the secret off the FIXTURE rather than off a parameter,
// because every row in the table needs the same user's code and threading it
// through the table would let one row quietly assert on another row's factor.
func (s *mfaServer) codeFor(t *testing.T) string {
	t.Helper()
	return s.user.code(t, s.clock.Now())
}

// pendingEnrollmentID and pendingEnrollmentCode are a PENDING enrollment the fixture
// owns, so the confirm row can name an id that is real and unconfirmed.
//
// Created lazily and CACHED, because the two halves of the row are asked for in
// sequence and creating one per question would leave the first unreferenced — and
// the confirm would then be answering a 404 rather than a 200 for a reason that has
// nothing to do with authorization.
func (s *mfaServer) pendingEnrollmentID(t *testing.T) string {
	t.Helper()
	s.ensurePendingEnrollment(t)
	return s.pendingID
}

func (s *mfaServer) pendingEnrollmentCode(t *testing.T) string {
	t.Helper()
	s.ensurePendingEnrollment(t)
	return s.pendingCode
}

func (s *mfaServer) ensurePendingEnrollment(t *testing.T) {
	t.Helper()
	if s.pendingID != "" {
		return
	}

	// A fresh period first: the fixture's own sign-in already spent the current step
	// against the same secret, and a code for it would be refused as a replay — which
	// would make this row a test of the replay guard rather than of the matrix.
	s.clock.Advance(mfa.Period + time.Second)

	rec := s.post(t, "/v1/mfa/enrollments", s.token, `{"code":"`+s.codeFor(t)+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("creating the fixture's pending enrollment = %d; body: %s", rec.Code, rec.Body)
	}

	var body struct {
		EnrollmentID string `json:"enrollment_id"`
		Secret       string `json:"secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the enrollment body is not JSON: %v", err)
	}
	code, err := mfa.Code(body.Secret, s.clock.Now())
	if err != nil {
		t.Fatalf("mfa.Code: %v", err)
	}
	s.pendingID, s.pendingCode = body.EnrollmentID, code
}

// fakeMFAManage satisfies MFAManage for the router walk, which consults the options
// for presence and nothing else.
type fakeMFAManage struct{}

func (fakeMFAManage) StatusFor(context.Context, id.UUID) (mfa.Status, error) {
	return mfa.Status{}, nil
}

func (fakeMFAManage) StartEnrollment(context.Context, mfa.StartEnrollmentInput) (mfa.StartedEnrollment, error) {
	return mfa.StartedEnrollment{}, nil
}

func (fakeMFAManage) Confirm(context.Context, mfa.ConfirmInput) (mfa.ConfirmedEnrollment, error) {
	return mfa.ConfirmedEnrollment{}, nil
}

func (fakeMFAManage) RegenerateRecoveryCodes(context.Context, mfa.RegenerateRecoveryCodesInput) (mfa.RegeneratedRecoveryCodes, error) {
	return mfa.RegeneratedRecoveryCodes{}, nil
}

func (fakeMFAManage) Disable(context.Context, mfa.DisableInput) error { return nil }

// newFakeMFAManage is the constructor the walk uses.
func newFakeMFAManage() MFAManage { return fakeMFAManage{} }
