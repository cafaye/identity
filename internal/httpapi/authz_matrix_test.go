package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cafaye/identity/internal/accounts"
	"github.com/cafaye/identity/internal/oidc"
	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
)

// THE AUTHORIZATION MATRIX.
//
// Every account-scoped endpoint, times every kind of caller, with the expected
// status code asserted explicitly. It runs the real router, the real use cases
// and the real SQL over a private schema, so what it proves is what a client
// would experience and not what a double was told to say.
//
// The table is generated from a route table rather than written out longhand. A
// matrix copied by hand is a matrix that goes stale the first time somebody adds
// an endpoint and forgets a row, and the forgotten row is the one that was
// going to be the vulnerability. Adding a route here without adding a case fails
// the test below (TestEveryRouteIsInTheMatrix).
//
// THE COLUMN THAT MATTERS
//
// The non-member column is 404 on every account-scoped route and never 403.
// That is the whole of TestRequireAccountRole's decision, asserted here across
// the entire surface, and it is the column a reviewer should read first.

const matrixPassword = "correct horse battery staple"

// actor is one kind of caller in the matrix.
type actor struct {
	name string
	// token is empty for the anonymous row: no credential is presented at all.
	token string
	user  id.UUID
	// role is the caller's role in the target account, for the rows that are
	// members of it. Empty means "not a member".
	role accounts.Role
}

// matrixCase is one (endpoint, actor) pair with the status the matrix requires.
type matrixCase struct {
	endpoint   matrixEndpoint
	actor      actor
	wantStatus int
	// wantProblemCode is checked when the status is not 2xx, so the matrix pins
	// the code as well as the line. A row that asserted only "403" would pass if
	// the body said `not_found`.
	wantProblemCode string
}

// matrixEndpoint is one row of the route table.
type matrixEndpoint struct {
	name   string
	method string
	// pattern is the chi pattern, spelled exactly as the router spells it. It is
	// what the coverage check compares against a chi.Walk, so it is a literal
	// rather than something rendered from ids.
	pattern string
	// unscoped says that the account in the path is NOT the target account — the
	// collection routes, where the only authorization question is "are you
	// authenticated". It is negatively named on purpose: a row added without it
	// defaults to scoped, which is the direction that gets its minimum checked.
	// A default of "unscoped" would silently exempt a new account-scoped route
	// from every 404 and 403 cell in the matrix.
	unscoped bool
	// success is the 2xx this endpoint returns to a caller who is allowed. It is
	// declared per row rather than derived from the method because POST is not
	// uniform: creating an account is 201 and accepting an invitation is 200.
	success int
	// expect overrides the default authorization rule for one endpoint, for the
	// one case where a second and independent rule changes the answer.
	//
	// It exists because the matrix's job is the AUTHORIZATION decision, and
	// pretending otherwise would make it lie. Accepting an invitation into an
	// account you are already in is a 409 — that is a rule about the caller's
	// state, not their permissions, and the member, admin and owner columns are
	// all members of the account their token names. Writing that down in the row
	// is more honest than weakening the endpoint to make the table uniform.
	expect func(column actor) (status int, problemCode string)
	// body renders the request body from the case's fixture, so a row can use a
	// unique name, a unique address or a freshly minted token without any of them
	// being shared between cases.
	body func(f *matrixFixture) string
	// min is the route's minimum role, restated here so the expectations are
	// derived from the route rather than guessed. TestRouteMinimumsMatchTheRouter
	// is what keeps this honest.
	min accounts.Role
}

// path renders the concrete request path for a case.
func (e matrixEndpoint) path(accountID, memberID, clientID id.UUID) string {
	out := e.pattern
	out = strings.ReplaceAll(out, "{accountID}", accountID.String())
	out = strings.ReplaceAll(out, "{userID}", memberID.String())
	out = strings.ReplaceAll(out, "{clientID}", clientID.String())
	return out
}

// The route table. Every route registerTenancyRoutes mounts appears here exactly
// once, and TestEveryRouteIsInTheMatrix fails if that ever stops being true.
func matrixEndpoints() []matrixEndpoint {
	return []matrixEndpoint{
		// The collection routes. There is no account in the path, so the target
		// account is irrelevant to whether the caller may make the request: the
		// only question is whether they are authenticated at all.
		{
			name: "list my accounts", method: http.MethodGet,
			pattern: "/v1/accounts", unscoped: true, success: http.StatusOK,
		},
		{
			name: "create an account", method: http.MethodPost,
			pattern: "/v1/accounts", unscoped: true, success: http.StatusCreated, body: func(f *matrixFixture) string {
				// The slug is derived from the name and is unique, so a fixed name
				// would make every row after the first a 409 for a reason that has
				// nothing to do with authorization.
				return `{"name":"` + f.caseName + `"}`
			},
		},
		{
			// The token names the account, so there is none in the path. A fresh
			// pending invitation is minted per case, which is what lets every
			// authenticated column expect the same 200: without it the first column
			// to run would spend the token and every other would see a 410.
			name: "accept an invitation", method: http.MethodPost,
			pattern: "/v1/invitations/accept", unscoped: true, success: http.StatusOK,
			body: func(f *matrixFixture) string { return `{"token":"` + f.pendingToken + `"}` },
			expect: func(column actor) (int, string) {
				// The token names the target account, and the member, admin and
				// owner columns are already in it. A second invitation for an
				// account you are already in is a 409, and it is one no amount of
				// privilege should change.
				if column.role != "" {
					return http.StatusConflict, CodeConflict
				}
				return http.StatusOK, ""
			},
		},

		// The account-scoped routes.
		{
			name: "read the account", method: http.MethodGet,
			pattern: "/v1/accounts/{accountID}", min: accounts.RoleMember, success: http.StatusOK,
		},
		{
			name: "list the members", method: http.MethodGet,
			pattern: "/v1/accounts/{accountID}/members", min: accounts.RoleMember, success: http.StatusOK,
		},
		{
			name: "rename the account", method: http.MethodPatch,
			pattern: "/v1/accounts/{accountID}", min: accounts.RoleAdmin, success: http.StatusOK,
			body: func(*matrixFixture) string { return `{"name":"Renamed"}` },
		},
		{
			name: "invite a member", method: http.MethodPost,
			pattern: "/v1/accounts/{accountID}/invitations", min: accounts.RoleAdmin, success: http.StatusCreated,
			body: func(f *matrixFixture) string {
				return `{"email":"` + f.inviteeEmail + `","role":"member"}`
			},
		},
		{
			name: "remove a member", method: http.MethodDelete,
			pattern: "/v1/accounts/{accountID}/members/{userID}", min: accounts.RoleAdmin, success: http.StatusNoContent,
		},
		{
			name: "change a role", method: http.MethodPatch,
			pattern: "/v1/accounts/{accountID}/members/{userID}", min: accounts.RoleOwner, success: http.StatusOK,
			body: func(*matrixFixture) string { return `{"role":"admin"}` },
		},
		{
			name: "delete the account", method: http.MethodDelete,
			pattern: "/v1/accounts/{accountID}", min: accounts.RoleOwner, success: http.StatusNoContent,
		},

		// The OIDC registrations. All four are owner-only, and the reason is a
		// security property rather than a convention: adding a client is adding a
		// new way for code to arrive in this product and get a token back out, and
		// "can read the member list" is not authority to widen the perimeter.
		//
		// A member of the account is 403 rather than 404 because they can already
		// see the account — the resource is theirs to know about — and an owner of
		// a DIFFERENT account is 404 because they are a non-member here. The
		// general rules in expectedStatus produce both, and that is the point of
		// deriving them rather than tabulating them.
		{
			name: "register an OIDC client", method: http.MethodPost,
			pattern: "/v1/accounts/{accountID}/oidc-clients", min: accounts.RoleOwner, success: http.StatusCreated,
			body: func(f *matrixFixture) string {
				return `{"name":"` + f.caseName + `","redirect_uris":["https://matrix.example.com/cb"],` +
					`"grant_types":["authorization_code"],"scopes":["openid","email"]}`
			},
		},
		{
			name: "list the OIDC clients", method: http.MethodGet,
			pattern: "/v1/accounts/{accountID}/oidc-clients", min: accounts.RoleOwner, success: http.StatusOK,
		},
		{
			name: "read an OIDC client", method: http.MethodGet,
			pattern: "/v1/accounts/{accountID}/oidc-clients/{clientID}", min: accounts.RoleOwner, success: http.StatusOK,
		},
		{
			name: "revoke an OIDC client", method: http.MethodDelete,
			pattern: "/v1/accounts/{accountID}/oidc-clients/{clientID}", min: accounts.RoleOwner, success: http.StatusNoContent,
		},
	}
}

// matrixFixture is the world the matrix runs in: one target account, and one
// caller per row of the role columns, each with a real session.
type matrixFixture struct {
	handler     http.Handler
	pool        *pgxpool.Pool
	clock       *clock.Fake
	oidcClients *oidc.Service

	// The account every row is about, and the plain member inside it, which is
	// what the member-scoped routes act on.
	accountID id.UUID
	memberID  id.UUID
	// pendingToken is a fresh, unaccepted invitation into the target account,
	// minted per case. It belongs to the fixture rather than to the endpoint table
	// because the table is a value and this is per-subtest state.
	pendingToken string
	// caseName is the subtest's name, used to keep created account names unique.
	caseName string
	// seq counts the targets built so far. It is what the fixture's account NAMES
	// are built from, and it replaced the test name for that job: a slug is capped
	// at 63 characters, and "Elsewhere TestAuthorizationMatrix/register_an_OIDC_client-owner"
	// and "Elsewhere TestAuthorizationMatrix/register_an_OIDC_client-owner of another
	// account" both truncate to the same 63 characters. A harness whose fixtures
	// collide is a harness whose failures are about the harness.
	seq int
	// clientID is a fresh OIDC registration in the target account, minted per case
	// for the same reason pendingToken is: the revoke row destroys what it is
	// given, so one shared row would be gone by the second column.
	clientID id.UUID
	// inviteeEmail is a fresh address for the invite row, so the partial unique
	// index on pending invitations does not fire for a reason unrelated to
	// authorization.
	inviteeEmail string

	// One actor per column. A fresh target account is built per case, because
	// one of the cases is "delete the account" and it would take the fixture with
	// it.
	owner    actor
	admin    actor
	member   actor
	stranger actor
	// elsewhere is authenticated and owns a DIFFERENT account. On the target
	// account they are a non-member, which is the point: the column proves that
	// owning an account confers nothing on another one.
	elsewhere actor
}

func newMatrixFixture(t *testing.T) *matrixFixture {
	t.Helper()

	pool := dbtest.Schema(t)
	clk := clock.NewFake(time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))

	tenancy := realTenancy(pool, clk)
	authSvc := authServiceFor(pool, clk)
	clients := matrixOIDCClients(t, pool, clk)

	handler := New(nil,
		WithAuth(authSvc),
		WithTenancy(tenancy),
		WithOIDCClients(clients),
		WithOIDC(newFakeOIDC()),
		WithLogger(slogLogger(&recordingHandler{})),
	)

	// actor.role is the caller's role IN THE TARGET ACCOUNT, which is not always
	// what the column is named after. `elsewhere` owns an account — a real one,
	// created per case — and on the target account they hold nothing at all. That
	// difference is the entire content of that column: owning an account confers
	// nothing on any other.
	return &matrixFixture{
		handler:     handler,
		pool:        pool,
		clock:       clk,
		oidcClients: clients,
		owner:       actor{name: "owner", role: accounts.RoleOwner},
		admin:       actor{name: "admin", role: accounts.RoleAdmin},
		member:      actor{name: "member", role: accounts.RoleMember},
		stranger:    actor{name: "non-member"},
		elsewhere:   actor{name: "owner of another account"},
	}
}

// register creates a user and a live session for them, through the real use
// cases, so the token in the matrix is one the service minted.
func (f *matrixFixture) register(t *testing.T, a *actor) {
	t.Helper()

	email := dbtest.UniqueEmail(t)
	rec := post(t, f.handler, "/v1/users", `{"email":"`+email+`","password":"`+matrixPassword+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering the %s actor: %d; body: %s", a.name, rec.Code, rec.Body)
	}
	var created userResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("the registration body is not JSON: %v", err)
	}
	parsed, err := id.Parse(created.ID)
	if err != nil {
		t.Fatalf("the service returned an id that does not parse: %v", err)
	}
	a.user = parsed

	login := post(t, f.handler, "/v1/session", `{"email":"`+email+`","password":"`+matrixPassword+`"}`)
	if login.Code != http.StatusOK {
		t.Fatalf("signing the %s actor in: %d; body: %s", a.name, login.Code, login.Body)
	}
	var session sessionResponse
	if err := json.Unmarshal(login.Body.Bytes(), &session); err != nil {
		t.Fatalf("the login body is not JSON: %v", err)
	}
	a.token = session.Token
}

// anonymous is the column with no credential at all.
var anonymous = actor{name: "anonymous"}

// buildTarget creates a fresh account owned by the owner actor, and puts the
// admin and member actors in it at their roles. It also gives the "elsewhere"
// actor an account of their own.
//
// A fresh account per case is what lets "delete the account" sit in the same
// table as everything else without taking the fixture down with it.
func (f *matrixFixture) buildTarget(t *testing.T) {
	t.Helper()

	// Recorded so the create-account row can use a name no other case has used.
	f.caseName = strings.ReplaceAll(t.Name(), "/", " ")
	f.inviteeEmail = dbtest.UniqueEmail(t)
	f.seq++

	created, err := realTenancy(f.pool, f.clock).Create(t.Context(), accounts.CreateInput{
		Name:  f.label("Matrix"),
		Owner: f.owner.user,
	})
	if err != nil {
		t.Fatalf("creating the target account: %v", err)
	}
	f.accountID = created.Account.ID

	store := accounts.NewStore(f.pool)
	add := func(userID id.UUID, role accounts.Role) {
		t.Helper()
		if _, err := store.AddMember(t.Context(), f.pool, accounts.Membership{
			AccountID: f.accountID, UserID: userID, Role: role,
		}); err != nil {
			t.Fatalf("adding the %s actor at %s: %v", userID, role, err)
		}
	}
	add(f.admin.user, accounts.RoleAdmin)
	add(f.member.user, accounts.RoleMember)
	f.memberID = f.member.user

	// The "elsewhere" actor gets an account of their own, so the column is a
	// genuine owner who simply owns the wrong account.
	if _, err := realTenancy(f.pool, f.clock).Create(t.Context(), accounts.CreateInput{
		Name:  f.label("Elsewhere"),
		Owner: f.elsewhere.user,
	}); err != nil {
		t.Fatalf("creating the elsewhere account: %v", err)
	}

	// A fresh OIDC registration, registered through the real use case so the row
	// in the matrix is one the service would have written.
	registered, err := f.oidcClients.Register(t.Context(), oidc.RegisterInput{
		AccountID:    f.accountID,
		Name:         f.label("Matrix"),
		RedirectURIs: []string{"https://matrix.example.com/cb"},
		GrantTypes:   []string{oidc.GrantAuthorizationCode},
		Scopes:       []string{oidc.ScopeOpenID, oidc.ScopeEmail},
		RegisteredBy: f.owner.user,
	})
	if err != nil {
		t.Fatalf("registering the matrix's OIDC client: %v", err)
	}
	f.clientID = registered.Client.ID

	// A fresh, unaccepted invitation for the accept route. Per case rather than
	// per suite, so no column spends the token another column needs.
	invited, err := realTenancy(f.pool, f.clock).Invite(t.Context(), accounts.InviteInput{
		AccountID: f.accountID,
		Email:     dbtest.UniqueEmail(t),
		Role:      accounts.RoleMember,
		InvitedBy: f.owner.user,
	})
	if err != nil {
		t.Fatalf("creating the pending invitation: %v", err)
	}
	f.pendingToken = invited.Token
}

// label is a short unique name for a fixture row.
//
// Short AND unique, because accounts.Slugify truncates at 63 characters and two
// long names that share a prefix truncate to one slug — which is a 409 on the
// second and a failure in the harness rather than in the code under test. The
// counter is enough on its own and reads better in a database than a test path
// does.
func (f *matrixFixture) label(prefix string) string {
	return fmt.Sprintf("%s %d", prefix, f.seq)
}

// columns is the actor set the matrix runs every endpoint against.
func (f *matrixFixture) columns() []actor {
	return []actor{
		anonymous,
		f.stranger,
		f.elsewhere,
		f.member,
		f.admin,
		f.owner,
	}
}

// TestAuthorizationMatrix is the suite. The name is the first line of the
// failure output, so it is the one worth having.
func TestAuthorizationMatrix(t *testing.T) {
	f := newMatrixFixture(t)

	// Every actor registers once. The sessions live for the whole matrix, which
	// is what makes the columns comparable: the only thing that varies between
	// two rows of the same endpoint is the caller's role.
	f.register(t, &f.owner)
	f.register(t, &f.admin)
	f.register(t, &f.member)
	f.register(t, &f.stranger)
	f.register(t, &f.elsewhere)

	for _, endpoint := range matrixEndpoints() {
		endpoint := endpoint
		t.Run(endpoint.name, func(t *testing.T) {
			for _, column := range f.columns() {
				column := column
				t.Run(column.name, func(t *testing.T) {
					// A fresh account per (endpoint, column), because one of the
					// cases destroys it.
					f.buildTarget(t)

					tt := matrixCase{endpoint: endpoint, actor: column}
					tt.wantStatus, tt.wantProblemCode = expectedStatus(t, endpoint, column)

					rec := f.send(t, endpoint, column)
					if rec.Code != tt.wantStatus {
						t.Fatalf("%s %s as %s = %d, want %d\nbody: %s",
							endpoint.method, endpoint.path(f.accountID, f.memberID, f.clientID),
							column.name, rec.Code, tt.wantStatus, rec.Body)
					}
					if tt.wantProblemCode == "" {
						return
					}
					p := decodeProblem(t, rec)
					if p.Code != tt.wantProblemCode {
						t.Errorf("code = %q, want %q; body: %s", p.Code, tt.wantProblemCode, rec.Body)
					}
				})
			}
		})
	}
}

// expectedStatus is the matrix, written as rules rather than as 42 cells.
//
// Deriving the expectations instead of tabulating them is the point: a rule that
// says "non-members get 404, members below the route minimum get 403, everyone
// else gets what the route does" cannot drift from the route's own minimum,
// because it reads it. A hand-written cell can, and would.
func expectedStatus(_ *testing.T, endpoint matrixEndpoint, column actor) (status int, problemCode string) {
	// Authentication is the one decision no endpoint overrides: a route with no
	// usable credential is a 401 whatever the body says, and the override below
	// never sees an unauthenticated column.
	if column.token == "" {
		return http.StatusUnauthorized, CodeUnauthorized
	}
	if endpoint.expect != nil {
		return endpoint.expect(column)
	}

	switch {
	case column.token == "":
		// No credential. 401 on everything, before the account is even looked at.
		return http.StatusUnauthorized, CodeUnauthorized

	case endpoint.unscoped:
		// There is no account in the path, so no membership question arises. The
		// only decision is "are you authenticated", and the answer above already
		// established that they are.
		//
		// Every column gets the same success here, which is the honest answer: an
		// owner of another account is not less entitled to create an account or
		// redeem an invitation than anybody else.
		return endpoint.success, ""

	case column.role == "":
		// Authenticated, but holds no membership in this account. 404 and never
		// 403: a 403 would confirm the account exists to somebody who has no
		// business knowing.
		return http.StatusNotFound, CodeNotFound

	case !column.role.AtLeast(endpoint.min):
		// A member of the account who is below this route's minimum. They can
		// already see the account, so 403 reveals nothing new.
		return http.StatusForbidden, CodeForbidden

	default:
		// The route's own answer, which for every endpoint in the table is a
		// success. The default arm exists so that a new row added without a
		// `success` shows up as a failure rather than as a silent pass.
		if endpoint.success == 0 {
			panic("matrix: " + endpoint.name + " declares no success status")
		}
		return endpoint.success, ""
	}
}

// send issues one matrix request as the given actor.
func (f *matrixFixture) send(t *testing.T, endpoint matrixEndpoint, column actor) *httptest.ResponseRecorder {
	t.Helper()

	body := ""
	if endpoint.body != nil {
		body = endpoint.body(f)
	}

	req := httptest.NewRequest(endpoint.method, endpoint.path(f.accountID, f.memberID, f.clientID), strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if column.token != "" {
		req.Header.Set("Authorization", "Bearer "+column.token)
	}

	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

// A route that is mounted and has no row in the matrix is a route nobody
// checked. This is what keeps the table honest as the surface grows, and it
// reads the routes out of chi rather than restating them — a restated list is
// one more thing to forget to update.
func TestEveryRouteIsInTheMatrix(t *testing.T) {
	mounted := mountedAccountRoutes()

	covered := make(map[string]bool, len(matrixEndpoints()))
	for _, e := range matrixEndpoints() {
		covered[normalizeRoute(e.method, e.pattern)] = true
	}

	for _, route := range mounted {
		if !covered[route] {
			t.Errorf("route %s is mounted but has no row in the authorization matrix", route)
		}
	}
	if len(covered) > len(mounted) {
		t.Errorf("the matrix has %d rows for %d mounted routes; it is asserting on routes that do not exist",
			len(covered), len(mounted))
	}
}

// mountedAccountRoutes is every route registerTenancyRoutes puts on the router,
// read out of chi itself. The /v1/accounts and /v1/invitations/accept collection
// routes are included: they are in the matrix's own table below.
func mountedAccountRoutes() []string {
	var found []string

	r := chi.NewRouter()
	opts := options{tenancy: newFakeTenancy(), auth: newFakeAuth(), oidcClients: newFakeOIDCClients()}
	opts.registerTenancyRoutes(r)

	// chi.Walk needs a real method handler; the routes are registered on a mux
	// built for the purpose, so walking it enumerates exactly what production
	// mounts.
	_ = chi.Walk(r, func(method string, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		found = append(found, normalizeRoute(method, route))
		return nil
	})

	sort.Strings(found)
	return found
}

// normalizeRoute puts a method and a path into the matrix's key form: chi
// patterns use {param} and the matrix uses the same names, but the collection
// routes come back as a prefix and the parameterised ones as a leaf. Uppercase
// methods, no trailing slash.
func normalizeRoute(method, route string) string {
	return method + " " + strings.TrimRight(route, "/")
}

func TestEveryMountedRouteIsAnAccountRoute(t *testing.T) {
	for _, route := range mountedAccountRoutes() {
		path := strings.TrimPrefix(route, strings.SplitN(route, " ", 2)[0]+" ")
		if !strings.HasPrefix(path, "/v1/accounts") && path != "/v1/invitations/accept" {
			t.Errorf("registerTenancyRoutes mounted %s, which is not a tenancy route — it belongs on the auth routes", route)
		}
	}
}
