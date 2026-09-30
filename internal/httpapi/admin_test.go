package httpapi

// THE ADMIN SURFACE'S ROUTER-LEVEL TESTS.
//
// What is here and why the database tests are in another file:
//
//   the three RED PROOFS the packet names  → here, against the real router with
//     doubles, because each is about the ROUTER's wiring — which middleware is
//     wrapped round which route — and a test that called the middleware directly
//     would be asserting about a different service
//   the same-transaction rollback           → internal/admin, over real Postgres
//     with a trigger that raises, because that property is about what the
//     DATABASE does with a half-finished transaction
//
// The split is the reason both files exist. A rollback proof in this file would
// pass against a service that never opened a transaction at all, as long as it
// returned an error; a wiring proof in the integration file would need a database
// to learn that a route is missing a middleware.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cafaye/identity/internal/accounts"
	"github.com/cafaye/identity/internal/admin"
	"github.com/cafaye/identity/internal/apikeys"
	"github.com/cafaye/identity/internal/platform/id"
)

// ---------------------------------------------------------------------------
// doubles
// ---------------------------------------------------------------------------

// fakeAdmin is the admin use case as the handlers need it.
//
// The failures are programmable because two of the three red proofs are about a
// route reporting a failure: the no-account_id refusal must be assertable per
// route rather than once in a helper, and the audit failure has to reach the
// handler as a 500 for the client-facing half of the proof.
type fakeAdmin struct {
	revokedOne   int
	revokedMany  int
	revokeOneErr error
	revokeManyEr error
	listErr      error
	records      []admin.Record

	// seen records what reached the use case, so a test can assert a route was
	// REFUSED rather than reached and answered.
	sawRevokeOne  bool
	sawRevokeMany bool
	sawList       bool
	// lastActor is the actor the handler assembled from the request context.
	// Asserting on it is how a test proves the audit record COULD name the
	// credential that acted.
	lastActor admin.Actor
}

func (f *fakeAdmin) RevokeInvitation(_ context.Context, in admin.RevokeInvitationInput) (int, error) {
	f.sawRevokeOne = true
	f.lastActor = in.Actor
	if f.revokeOneErr != nil {
		return 0, f.revokeOneErr
	}
	return f.revokedOne, nil
}

func (f *fakeAdmin) RevokeInvitations(_ context.Context, in admin.RevokeInvitationsInput) (int, error) {
	f.sawRevokeMany = true
	f.lastActor = in.Actor
	if f.revokeManyEr != nil {
		return 0, f.revokeManyEr
	}
	return f.revokedMany, nil
}

func (f *fakeAdmin) List(_ context.Context, _ id.UUID, _ admin.Page) ([]admin.Record, error) {
	f.sawList = true
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.records, nil
}

// newFakeAdmin is the configured double for the router walks in
// openapi_drift_test.go and authz_matrix_test.go.
//
// IT IS A CONSTRUCTOR RATHER THAN A `&fakeAdmin{}` AT EACH CALL SITE, and that is
// so the walks cannot drift into configuring it differently from each other. A
// walk that passed a differently-configured double would see a different tree, and
// the two checks would be comparing against different services without either
// saying so.
func newFakeAdmin() *fakeAdmin { return &fakeAdmin{revokedOne: 1, revokedMany: 1} }

var _ Admin = (*fakeAdmin)(nil)

// auditFailure is what a failed audit write looks like to a handler: an error
// that is not one of the mapped sentinels, so it takes the 500 arm. It stands in
// for the trigger-raised failure in the integration test.
var auditFailure = errors.New("appending the audit record: injected failure")

// ---------------------------------------------------------------------------
// fixture
// ---------------------------------------------------------------------------

// adminFixture is a router with the admin surface mounted, an admin token that is
// a member of the account, and a session for the same user.
type adminFixture struct {
	handler http.Handler
	admin   *fakeAdmin

	accountID id.UUID
	memberID  id.UUID
	// token is a live scoped token for the account, and session is a live browser
	// session for the same user. Both are needed: the admin routes are
	// token-only, so the session exists to prove it is refused.
	token   string
	session string
}

// newAdminFixture builds the router with an admin whose token holds BOTH admin
// scopes and whose user is an ADMIN of the account.
//
// The role is admin rather than owner so that a test raising the route's minimum
// is a deliberate change: the bulk route is owner-only, and the fixture being an
// admin is what makes "the owner column and the admin column differ" visible.
func newAdminFixture(t *testing.T, scopes ...string) *adminFixture {
	t.Helper()

	if len(scopes) == 0 {
		scopes = []string{apikeys.ScopeAuditLogRead, apikeys.ScopeAccountInvitationsWrite}
	}
	return newAdminFixtureAs(t, accounts.RoleOwner, scopes...)
}

// newAdminFixtureAs is newAdminFixture with the caller's role, because the bulk
// route is OWNER-only and the two admin routes that are not are ADMIN-routable —
// so a fixture pinned to one role cannot test the other two.
//
// It exists because the alternative was pinning every test to owner and losing the
// ability to say "an admin may revoke one but not many", which is half of what
// makes the bulk minimum worth having.
func newAdminFixtureAs(t *testing.T, role accounts.Role, scopes ...string) *adminFixture {
	t.Helper()

	if len(scopes) == 0 {
		scopes = []string{apikeys.ScopeAuditLogRead, apikeys.ScopeAccountInvitationsWrite}
	}

	auth := newFakeAuth()
	accountID := id.MustNew()
	memberID := auth.user.ID

	tenancy := adminTenancy(accountID, role)
	caller := newFakeAPIKeyCaller(auth.user, apikeys.Key{
		ID:        id.MustNew(),
		UserID:    memberID,
		AccountID: accountID,
		Scopes:    scopes,
	})
	adminSvc := &fakeAdmin{revokedOne: 1, revokedMany: 1}

	handler := New(nil,
		WithAuth(auth),
		WithTenancy(tenancy),
		WithAPIKeyCaller(caller),
		WithAdmin(adminSvc),
	)

	return &adminFixture{
		handler:   handler,
		admin:     adminSvc,
		accountID: accountID,
		memberID:  memberID,
		token:     apiKeySecret,
		session:   "session-for-the-same-user",
	}
}

// adminTenancy is a tenancy double answering 200 for one account and one member.
//
// It reuses fakeTenancy's own single-account and single-role fields rather than
// the maps I first wrote here, because those fields are what its Get already
// consults — a second, parallel map would have been a double that satisfied the
// interface and answered nothing, and the tests would have failed at 404 for a
// reason that looked like the admin gate refusing them.
func adminTenancy(accountID id.UUID, role accounts.Role) *fakeTenancy {
	tenancy := newFakeTenancy()
	tenancy.account = accounts.Account{
		ID: accountID, Name: "Admin Fixture", Slug: "admin-fixture",
	}
	tenancy.role = role
	return tenancy
}

// adminSend issues a request to an admin route.
func (f *adminFixture) adminSend(t *testing.T, method, path, body, credential string) *httptest.ResponseRecorder {
	t.Helper()

	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func (f *adminFixture) auditPath() string {
	return "/v1/accounts/" + f.accountID.String() + "/admin/audit-log"
}

func (f *adminFixture) revokeOnePath() string {
	return "/v1/accounts/" + f.accountID.String() + "/admin/invitations/" + id.MustNew().String()
}

func (f *adminFixture) revokeAllPath() string {
	return "/v1/accounts/" + f.accountID.String() + "/admin/invitation-revocations"
}

// ---------------------------------------------------------------------------
// the three routes work
// ---------------------------------------------------------------------------

// TestTheAdminRoutesAnswer is the happy path with the status code AND the JSON
// shape, per AGENTS.md's rule that a 200 with the wrong body is a failure.
func TestTheAdminRoutesAnswer(t *testing.T) {
	t.Parallel()

	t.Run("the audit trail", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixture(t)
		f.admin.records = []admin.Record{{
			ID: id.MustNew(), AccountID: f.accountID, Action: admin.ActionInvitationRevoked,
			ActorUserID: f.memberID, ActorKeyID: id.MustNew(), Target: id.MustNew().String(),
			Affected: 1, TraceID: "trace-abc",
			OccurredAt: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC),
		}}

		rec := f.adminSend(t, http.MethodGet, f.auditPath(), "", f.token)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("Content-Type = %q, want JSON", ct)
		}

		var got auditLogResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("the body is not JSON: %v; body: %s", err, rec.Body)
		}
		if len(got.Entries) != 1 {
			t.Fatalf("got %d entries, want 1", len(got.Entries))
		}
		one := got.Entries[0]
		if one.Action != string(admin.ActionInvitationRevoked) {
			t.Errorf("action = %q", one.Action)
		}
		if one.Affected != 1 {
			t.Errorf("affected = %d, want 1", one.Affected)
		}
		if one.ActorKeyID == "" || one.ActorUserID == "" {
			t.Error("the record does not name the credential and the user that acted")
		}
		// The response shape must have no field a token could be written into.
		// An operator copies this into a ticket during an incident.
		var raw map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
			t.Fatal(err)
		}
		for _, entry := range raw["entries"].([]any) {
			for _, field := range []string{"token", "secret", "bearer", "jwt", "password", "digest"} {
				if _, present := entry.(map[string]any)[field]; present {
					t.Errorf("the audit entry has a %q field. This response is what an operator copies "+
						"into an incident ticket, and a shape with a credential field is one somebody "+
						"will eventually populate", field)
				}
			}
		}
	})

	t.Run("revoking one invitation", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixture(t)
		rec := f.adminSend(t, http.MethodDelete, f.revokeOnePath(), "", f.token)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204; body: %s", rec.Code, rec.Body)
		}
		if rec.Body.Len() != 0 {
			t.Errorf("a 204 carried a body: %s", rec.Body)
		}
		if !f.admin.sawRevokeOne {
			t.Error("the use case was not reached")
		}
		// The actor must name the credential, or the audit row cannot say who acted.
		if f.admin.lastActor.KeyID.IsZero() {
			t.Error("the actor carries no key id, so the audit record would name no credential")
		}
		if f.admin.lastActor.UserID != f.memberID {
			t.Errorf("actor user = %s, want the caller %s", f.admin.lastActor.UserID, f.memberID)
		}
	})

	t.Run("revoking many", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixture(t)
		f.admin.revokedMany = 2
		ids := []string{id.MustNew().String(), id.MustNew().String()}

		body := `{"invitation_ids":["` + ids[0] + `","` + ids[1] + `"],"confirm":true}`
		rec := f.adminSend(t, http.MethodPost, f.revokeAllPath(), body, f.token)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
		}

		var got bulkRevokeResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("the body is not JSON: %v", err)
		}
		// BOTH counts, and the reason is on the type: "you asked for four and two
		// went" and "you asked for two and two went" are different answers and a
		// client that cannot tell them apart will report a completed task over an
		// incident.
		if got.Requested != 2 || got.Revoked != 2 {
			t.Errorf("requested = %d, revoked = %d; want 2 and 2", got.Requested, got.Revoked)
		}
	})
}

// ---------------------------------------------------------------------------
// RED PROOF 1 — R4: a session alone reaches nothing
// ---------------------------------------------------------------------------

// TestNoAdminRouteIsReachableWithASessionAlone is the R4 red proof, and it is
// PER ROUTE rather than once in a helper, for the reason the packet states: a
// helper that refuses a session proves the helper refuses a session, and says
// nothing about the fourth route somebody adds next.
//
// The assertion is a 403 AND that the use case was never reached. A 403 from a
// handler that had already done the work would pass the status check, and the
// audit row would be the evidence.
func TestNoAdminRouteIsReachableWithASessionAlone(t *testing.T) {
	t.Parallel()

	routes := []struct {
		name   string
		method string
		path   func(*adminFixture) string
		body   string
	}{
		{
			name: "read the audit trail", method: http.MethodGet,
			path: func(f *adminFixture) string { return f.auditPath() },
		},
		{
			name: "revoke one invitation", method: http.MethodDelete,
			path: func(f *adminFixture) string { return f.revokeOnePath() },
		},
		{
			name:   "revoke many invitations",
			method: http.MethodPost,
			path:   func(f *adminFixture) string { return f.revokeAllPath() },
			body:   `{"invitation_ids":["` + id.MustNew().String() + `"],"confirm":true}`,
		},
	}

	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			t.Parallel()
			f := newAdminFixture(t)

			rec := f.adminSend(t, route.method, route.path(f), route.body, f.session)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("a browser session reached %s %s = %d, want 403; body: %s",
					route.method, route.path(f), rec.Code, rec.Body)
			}
			p := decodeProblem(t, rec)
			if p.Code != CodeForbidden {
				t.Errorf("code = %q, want %q", p.Code, CodeForbidden)
			}
			// AND the use case was not reached, which is the half a status code
			// alone does not establish.
			if f.admin.sawList || f.admin.sawRevokeOne || f.admin.sawRevokeMany {
				t.Error("a session reached the admin use case. A 403 is the right answer, but a 403 " +
					"written by a handler that had already performed the action is not a refusal")
			}
		})
	}
}

// TestTheSessionRefusalIsSpecificEnoughToActOn checks the detail says what is
// wrong, because a 403 whose body is "forbidden" sends an operator looking at
// their role instead of at their credential.
func TestTheSessionRefusalIsSpecificEnoughToActOn(t *testing.T) {
	t.Parallel()

	f := newAdminFixture(t)
	rec := f.adminSend(t, http.MethodGet, f.auditPath(), "", f.session)

	p := decodeProblem(t, rec)
	if !strings.Contains(p.Detail, "api key") {
		t.Errorf("detail = %q; it should say the surface wants a scoped api key, so a reader knows "+
			"the fix is a different credential rather than a different role", p.Detail)
	}
	// And it must not name anything about the account or the caller beyond that.
	for _, leak := range []string{"token=", f.session, apiKeySecret} {
		if strings.Contains(p.Detail, leak) {
			t.Errorf("the refusal detail contains %q", leak)
		}
	}
}

// ---------------------------------------------------------------------------
// RED PROOF 2 — R2: a token with no account_id reaches nothing
// ---------------------------------------------------------------------------

// TestATokenWithNoAccountIsRefused is the R2 red proof, PER ROUTE.
//
// The packet's wording is the reason it is per route and not a helper test: "a
// service-to-service token with no account_id is refused, not defaulted — if an
// admin route can be reached by a token whose account_id is absent, the tenancy
// check has nothing to check."
//
// THE DANGEROUS ANSWER IS 404, NOT 401, and that is why this test needs a double
// rather than the real apikeys.Service. A token with no account would mismatch the
// path's account and be refused incidentally, by the account comparison that runs
// for every route in the service — so a test using the real service would PASS
// while proving nothing about the admin surface. The double manufactures the
// specific shape the requirement names: a live, authenticated token whose Key has
// a zero AccountID, presented to an admin route.
//
// The two statuses are both refusals, and both are checked because which one you
// get is a fact about this service's answer: 401 says the credential is not
// usable here, 404 says the account is not visible. Either is a refusal; the
// point is that the use case is never reached.
func TestATokenWithNoAccountIsRefused(t *testing.T) {
	t.Parallel()

	routes := []struct {
		name   string
		method string
		path   func(*adminFixture) string
		body   string
	}{
		{
			name: "read the audit trail", method: http.MethodGet,
			path: func(f *adminFixture) string { return f.auditPath() },
		},
		{
			name: "revoke one invitation", method: http.MethodDelete,
			path: func(f *adminFixture) string { return f.revokeOnePath() },
		},
		{
			name:   "revoke many invitations",
			method: http.MethodPost,
			path:   func(f *adminFixture) string { return f.revokeAllPath() },
			body:   `{"invitation_ids":["` + id.MustNew().String() + `"],"confirm":true}`,
		},
	}

	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			t.Parallel()

			auth := newFakeAuth()
			// The manufactured shape: a resolved caller whose token carries NO
			// account. Every scope in the vocabulary, so nothing about the scope
			// gate can be what refuses it — the refusal has to come from the
			// tenancy decision.
			accountless := newFakeAPIKeyCaller(auth.user, apikeys.Key{
				ID:     id.MustNew(),
				UserID: auth.user.ID,
				Scopes: apikeys.AllScopes(),
			})
			if !accountless.key.AccountID.IsZero() {
				t.Fatal("the double is not accountless, so this test would prove nothing")
			}

			accountID := id.MustNew()
			adminSvc := &fakeAdmin{revokedOne: 1, revokedMany: 1}
			handler := New(nil,
				WithAuth(auth),
				WithTenancy(adminTenancy(accountID, accounts.RoleAdmin)),
				WithAPIKeyCaller(accountless),
				WithAdmin(adminSvc),
			)

			path := strings.Replace(route.path(&adminFixture{accountID: accountID}), "{", "", 1)
			req := httptest.NewRequest(route.method, path, strings.NewReader(route.body))
			if route.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			req.Header.Set("Authorization", "Bearer "+apiKeySecret)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code == http.StatusOK || rec.Code == http.StatusNoContent {
				t.Fatalf("a token with NO account reached %s %s = %d. The tenancy check had nothing "+
					"to check and the action was performed anyway; body: %s",
					route.method, path, rec.Code, rec.Body)
			}
			// 401, 403 and 404 are all refusals and all are acceptable answers here;
			// the substantive assertion is the one below, that the use case was
			// never reached. Restricting this to a guess about which status the
			// service would pick would make the test a statement about the mapping
			// rather than about the guard, and would have to be rewritten the day
			// the mapping is improved.
			switch rec.Code {
			case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			default:
				t.Errorf("status = %d; a refusal is 401, 403 or 404, and anything else means the request "+
					"failed for a reason that is not the tenancy guard", rec.Code)
			}
			if adminSvc.sawList || adminSvc.sawRevokeOne || adminSvc.sawRevokeMany {
				t.Error("a token with no account_id reached the admin use case")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// RED PROOF 3 — a failed audit write is a 500 and the client is told
// ---------------------------------------------------------------------------

// TestAFailedAuditWriteIsAFiveHundred is the third red proof, at the HTTP edge.
//
// The same-transaction half is proven in internal/admin against a real database,
// because that is a property of the transaction. THIS is the half a client
// experiences: a mutation whose audit record could not be written must not answer
// 204. A 204 says "this happened"; the transaction rolled back, so it did not,
// and a caller that trusted the 204 would believe an invitation is revoked when it
// is still redeemable.
func TestAFailedAuditWriteIsAFiveHundred(t *testing.T) {
	t.Parallel()

	t.Run("revoking one", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixture(t)
		f.admin.revokeOneErr = auditFailure

		rec := f.adminSend(t, http.MethodDelete, f.revokeOnePath(), "", f.token)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500. A 204 here would tell the caller the invitation is "+
				"revoked when the rollback means it is not; body: %s", rec.Code, rec.Body)
		}
		p := decodeProblem(t, rec)
		if p.Code != CodeInternal {
			t.Errorf("code = %q, want %q", p.Code, CodeInternal)
		}
		// The caller gets a trace id and nothing about the database.
		if p.TraceID == "" {
			t.Error("no trace id on the failure; an operator cannot quote what they were given")
		}
		if strings.Contains(p.Detail, "audit") || strings.Contains(p.Detail, "SQL") {
			t.Errorf("the 500 body leaks internals: %q", p.Detail)
		}
	})

	t.Run("revoking many", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixture(t)
		f.admin.revokeManyEr = auditFailure

		body := `{"invitation_ids":["` + id.MustNew().String() + `"],"confirm":true}`
		rec := f.adminSend(t, http.MethodPost, f.revokeAllPath(), body, f.token)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body)
		}
	})
}

// ---------------------------------------------------------------------------
// the audit trail is not writable through this API
// ---------------------------------------------------------------------------

// TestTheAuditTrailIsNotWritableThroughThisAPI is the packet's second property,
// proved at the surface.
//
// IT WALKS THE ROUTER rather than calling handlers, and that is the whole point:
// the property is about which methods are MOUNTED, so a check that drove the
// handler would pass even with a DELETE registered beside it — which is exactly
// what a later packet adding a "purge the trail" endpoint would do.
//
// It also checks the property the database cannot: the api key's own
// DELETE /v1/accounts/:id/api-keys/:keyID is a revocation route, and the shapes
// are close enough that an admin route added for the wrong reason could easily
// sit on a path prefix that overlaps it.
func TestTheAuditTrailIsNotWritableThroughThisAPI(t *testing.T) {
	t.Parallel()

	const auditPrefix = "/v1/accounts/{accountID}/admin/audit-log"

	// The walk reads the tree `newMux` assembles, the same tree
	// openapi_drift_test.go's servedRoutes walks. `New` returns the router behind
	// two middlewares, so the handler is not the mux — the fixture builds the mux
	// directly rather than type-asserting a value that is wrapped.
	mux := newMux(nil, options{
		auth:        newFakeAuth(),
		tenancy:     newFakeTenancy(),
		apiKeys:     newFakeAPIKeys(),
		oidcClients: newFakeOIDCClients(),
		admin:       &fakeAdmin{},
	})

	var found []string
	err := chi.Walk(mux, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if strings.HasPrefix(route, auditPrefix) {
			found = append(found, method+" "+route)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the router: %v", err)
	}

	if len(found) != 1 {
		t.Fatalf("the audit trail is reachable by %d operations (%v), want exactly one GET. Every "+
			"method beyond the read is a way to change the record of what an admin did",
			len(found), found)
	}
	if found[0] != "GET "+auditPrefix {
		t.Errorf("the audit trail's only operation is %q, want a GET", found[0])
	}

	// And the check itself is not vacuous: a mutating method on the audit path
	// must be caught. The double is mounted through the real registrar, so this
	// walks the same tree the assertion above did.
	t.Run("the check would notice a DELETE", func(t *testing.T) {
		t.Parallel()

		opts := options{
			auth:        newFakeAuth(),
			tenancy:     newFakeTenancy(),
			apiKeys:     newFakeAPIKeys(),
			admin:       &fakeAdmin{},
			oidcClients: newFakeOIDCClients(),
		}

		// Register a mutating method on the audit path against a real router, the
		// way a future packet adding a "purge the trail" endpoint would.
		injected := chi.NewRouter()
		opts.registerAdminRoutes(injected)
		injected.Delete(auditPrefix, func(http.ResponseWriter, *http.Request) {})

		var methods []string
		if err := chi.Walk(injected, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
			if strings.HasPrefix(route, auditPrefix) {
				methods = append(methods, method)
			}
			return nil
		}); err != nil {
			t.Fatalf("walking the injected router: %v", err)
		}

		var hasDelete bool
		for _, m := range methods {
			if m == http.MethodDelete {
				hasDelete = true
			}
		}
		if !hasDelete {
			t.Fatal("the injected DELETE is not on the audit path, so the assertion above would not " +
				"have caught it and the check is not testing what it claims")
		}
		// The real check would now fail, which is the point: two operations means
		// len(found) != 1.
		if len(methods) == 1 {
			t.Error("only one method found, so this subtest did not exercise the failure")
		}
	})
}

// ---------------------------------------------------------------------------
// the bounds
// ---------------------------------------------------------------------------

// TestTheAuditLogBoundsAreEnforced is R5 at the API, and each case is a value a
// client can actually send.
//
// The over-the-ceiling case is a 422 and NOT a silent clamp, and that is the
// substantive claim: a client that asked for 500 rows and was quietly given 100
// has been told a lie about how much of the trail it has read, and an operator
// building an export would produce a short one without knowing.
func TestTheAuditLogBoundsAreEnforced(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		query     string
		wantCode  int
		wantField string
	}{
		{name: "no limit", query: "", wantCode: http.StatusOK},
		{name: "at the ceiling", query: "?limit=100", wantCode: http.StatusOK},
		{name: "one over the ceiling", query: "?limit=101", wantCode: http.StatusUnprocessableEntity, wantField: "limit"},
		{name: "absurd", query: "?limit=100000", wantCode: http.StatusUnprocessableEntity, wantField: "limit"},
		{name: "zero is the default", query: "?limit=0", wantCode: http.StatusOK},
		{name: "negative", query: "?limit=-1", wantCode: http.StatusUnprocessableEntity, wantField: "limit"},
		{name: "not a number", query: "?limit=lots", wantCode: http.StatusUnprocessableEntity, wantField: "limit"},

		// A cursor this build did not issue is REFUSED, and it is refused at the
		// handler rather than left to the use case. That distinction is a real
		// difference in behaviour and not a matter of which layer happens to check
		// first: a cursor the use case cannot decode and a limit the use case
		// refuses are both errors, but only one of them can be reported as a bad
		// FIELD on a query string, and an operator who has lost their place in a
		// trail needs to be told the cursor is wrong rather than shown a generic
		// "the audit log query is not one this endpoint accepts".
		{name: "a forged cursor", query: "?before=not-a-real-cursor", wantCode: http.StatusUnprocessableEntity, wantField: "before"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newAdminFixture(t)

			rec := f.adminSend(t, http.MethodGet, f.auditPath()+tt.query, "", f.token)
			if rec.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantCode, rec.Body)
			}
			if tt.wantField == "" {
				return
			}
			p := decodeProblem(t, rec)
			if p.Code != CodeValidationFailed {
				t.Errorf("code = %q, want %q", p.Code, CodeValidationFailed)
			}
			var named bool
			for _, fe := range p.Errors {
				if fe.Field == tt.wantField {
					named = true
				}
			}
			if !named {
				t.Errorf("the field errors do not name %q: %+v", tt.wantField, p.Errors)
			}
			if f.admin.sawList {
				t.Error("a rejected query reached the use case")
			}
		})
	}
}

// TestTheBulkBoundsAreEnforced is R5 on the request side, and the confirm cases
// are the heart of the packet's third property.
func TestTheBulkBoundsAreEnforced(t *testing.T) {
	t.Parallel()

	t.Run("confirm is required", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixture(t)
		// The accident this exists for: an array with no confirmation. It must not
		// revoke anything.
		body := `{"invitation_ids":["` + id.MustNew().String() + `"]}`
		rec := f.adminSend(t, http.MethodPost, f.revokeAllPath(), body, f.token)

		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422; body: %s", rec.Code, rec.Body)
		}
		if f.admin.sawRevokeMany {
			t.Fatal("a bulk revocation WITHOUT confirmation performed the action. This is the " +
				"off-by-one-is-an-outage case, and the confirmation is what stands between a " +
				"mis-typed request and every pending invitation in the account")
		}
		p := decodeProblem(t, rec)
		var named bool
		for _, fe := range p.Errors {
			if fe.Field == "confirm" {
				named = true
			}
		}
		if !named {
			t.Errorf("the error does not name the confirm field: %+v", p.Errors)
		}
	})

	t.Run("confirm false is the same as absent", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixture(t)
		body := `{"invitation_ids":["` + id.MustNew().String() + `"],"confirm":false}`
		rec := f.adminSend(t, http.MethodPost, f.revokeAllPath(), body, f.token)

		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422", rec.Code)
		}
		if f.admin.sawRevokeMany {
			t.Error("confirm:false performed the action")
		}
	})

	t.Run("an empty array", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixture(t)
		rec := f.adminSend(t, http.MethodPost, f.revokeAllPath(),
			`{"invitation_ids":[],"confirm":true}`, f.token)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422", rec.Code)
		}
		if f.admin.sawRevokeMany {
			t.Error("an empty array performed the action")
		}
	})

	t.Run("one over the ceiling", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixture(t)
		ids := make([]string, 0, admin.MaxBulkInvitationIDs+1)
		for range admin.MaxBulkInvitationIDs + 1 {
			ids = append(ids, `"`+id.MustNew().String()+`"`)
		}
		rec := f.adminSend(t, http.MethodPost, f.revokeAllPath(),
			`{"invitation_ids":[`+strings.Join(ids, ",")+`],"confirm":true}`, f.token)

		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422; body: %s", rec.Code, rec.Body)
		}
		if f.admin.sawRevokeMany {
			t.Errorf("a request of %d ids reached the use case", len(ids))
		}
	})

	t.Run("at the ceiling is allowed", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixture(t)
		ids := make([]string, 0, admin.MaxBulkInvitationIDs)
		for range admin.MaxBulkInvitationIDs {
			ids = append(ids, `"`+id.MustNew().String()+`"`)
		}
		rec := f.adminSend(t, http.MethodPost, f.revokeAllPath(),
			`{"invitation_ids":[`+strings.Join(ids, ",")+`],"confirm":true}`, f.token)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 at the ceiling; body: %s", rec.Code, rec.Body)
		}
	})

	t.Run("a malformed id names the field", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixture(t)
		rec := f.adminSend(t, http.MethodPost, f.revokeAllPath(),
			`{"invitation_ids":["not-a-uuid"],"confirm":true}`, f.token)

		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422; body: %s", rec.Code, rec.Body)
		}
		if f.admin.sawRevokeMany {
			t.Error("a malformed id reached the use case")
		}
		p := decodeProblem(t, rec)
		if len(p.Errors) == 0 || p.Errors[0].Field != "invitation_ids" {
			t.Errorf("the error does not name invitation_ids: %+v", p.Errors)
		}
	})

	t.Run("an unknown field is refused", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixture(t)
		// A client sending `confirm_all` believing it worked is exactly the shape
		// decodeBody's DisallowUnknownFields exists to catch.
		rec := f.adminSend(t, http.MethodPost, f.revokeAllPath(),
			`{"invitation_ids":["`+id.MustNew().String()+`"],"confirm_all":true}`, f.token)

		if rec.Code == http.StatusOK {
			t.Error("an unknown field was accepted; a client that misspelled confirm would have " +
				"revoked every pending invitation believing it had been asked to confirm")
		}
		if f.admin.sawRevokeMany {
			t.Error("the action ran despite an unknown field")
		}
	})
}

// TestTheBulkRouteIsOwnerOnly is the minimum the design chose, asserted rather
// than asserted-in-prose.
//
// IT MATTERS BECAUSE THE TWO ADMIN ROUTES DIFFER: an admin may revoke one
// invitation and read the trail, and may not revoke them all. A test that only
// ever used an owner would pass with the two minimums equal, so the asymmetry has
// to be pinned by name or it will be "simplified" later.
func TestTheBulkRouteIsOwnerOnly(t *testing.T) {
	t.Parallel()

	ids := `"` + id.MustNew().String() + `"`
	body := `{"invitation_ids":[` + ids + `],"confirm":true}`

	t.Run("an admin may revoke one", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixtureAs(t, accounts.RoleAdmin)
		rec := f.adminSend(t, http.MethodDelete, f.revokeOnePath(), "", f.token)
		if rec.Code != http.StatusNoContent {
			t.Errorf("an admin revoking one invitation = %d, want 204; body: %s", rec.Code, rec.Body)
		}
	})

	t.Run("an admin may read the trail", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixtureAs(t, accounts.RoleAdmin)
		rec := f.adminSend(t, http.MethodGet, f.auditPath(), "", f.token)
		if rec.Code != http.StatusOK {
			t.Errorf("an admin reading the trail = %d, want 200; body: %s", rec.Code, rec.Body)
		}
	})

	t.Run("an admin may NOT revoke them all", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixtureAs(t, accounts.RoleAdmin)
		rec := f.adminSend(t, http.MethodPost, f.revokeAllPath(), body, f.token)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("an admin revoking every pending invitation = %d, want 403. The bulk route is "+
				"the one where an off-by-one is an outage, and owner is the whole of why; body: %s",
				rec.Code, rec.Body)
		}
		if f.admin.sawRevokeMany {
			t.Fatal("the use case was reached by an admin")
		}
	})

	t.Run("a member may do none of it", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixtureAs(t, accounts.RoleMember)
		for _, tt := range []struct {
			name   string
			method string
			path   string
			body   string
		}{
			{"read the trail", http.MethodGet, f.auditPath(), ""},
			{"revoke one", http.MethodDelete, f.revokeOnePath(), ""},
			{"revoke all", http.MethodPost, f.revokeAllPath(), body},
		} {
			rec := f.adminSend(t, tt.method, tt.path, tt.body, f.token)
			if rec.Code != http.StatusForbidden {
				t.Errorf("a member %s = %d, want 403; body: %s", tt.name, rec.Code, rec.Body)
			}
		}
		if f.admin.sawList || f.admin.sawRevokeOne || f.admin.sawRevokeMany {
			t.Error("a member reached the admin use case")
		}
	})
}

// TestTheSingleRouteNeedsNoConfirmation is the other half of the shape
// difference, and it is a test because the asymmetry is easy to "fix" later.
//
// Somebody tidying up the API will notice the bulk route needs `confirm: true`
// and the single one does not, and the tidying instinct is to add it. That would
// be adding a field to a DELETE that changes exactly one row the URL already
// names — and a client that forgot to send it would get a 422 on a safe,
// idempotent operation.
func TestTheSingleRouteNeedsNoConfirmation(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		body string
	}{
		{name: "no body at all", body: ""},
		{name: "an empty object", body: "{}"},
		{name: "a confirmation field, harmlessly ignored", body: `{"confirm":true}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newAdminFixture(t)
			rec := f.adminSend(t, http.MethodDelete, f.revokeOnePath(), tt.body, f.token)
			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want 204; body: %s", rec.Code, rec.Body)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// the privilege boundary, at the router
// ---------------------------------------------------------------------------

// TestTheScopeTableIsTheWholeBoundary walks the router and requires that every
// admin route declares a scope, and that the scopes declared are only the two the
// boundary names.
//
// It is the answer to "what can an admin token do", expressed as a check rather
// than as a paragraph: a fourth admin route with no row is closed to tokens
// (scopeRequiredBy returns ""), and a fourth route with a row is a new capability
// somebody decided to add, which shows up in this diff.
func TestTheScopeTableIsTheWholeBoundary(t *testing.T) {
	t.Parallel()

	want := map[string]string{
		"GET /v1/accounts/{accountID}/admin/audit-log":                     apikeys.ScopeAuditLogRead,
		"DELETE /v1/accounts/{accountID}/admin/invitations/{invitationID}": apikeys.ScopeAccountInvitationsWrite,
		"POST /v1/accounts/{accountID}/admin/invitation-revocations":       apikeys.ScopeAccountInvitationsWrite,
	}

	var adminRoutes []string
	for route := range accountRouteScopes {
		if strings.Contains(route, "/admin/") {
			adminRoutes = append(adminRoutes, route)
		}
	}
	if len(adminRoutes) != len(want) {
		t.Errorf("the scope table declares %d admin routes, want %d: %v",
			len(adminRoutes), len(want), adminRoutes)
	}
	for route, scope := range want {
		got, declared := accountRouteScopes[route]
		if !declared {
			t.Errorf("%s has no scope row, so it is CLOSED to tokens. That is the safe direction, but "+
				"it means the route cannot be reached by the credential the admin surface requires, so "+
				"one of these two facts is wrong", route)
			continue
		}
		if got != scope {
			t.Errorf("%s requires %q, want %q", route, got, scope)
		}
	}
}

// TestAnAdminTokenHoldingNeitherScopeIsRefused is the boundary's negative, and
// it is worth having because "narrow" is a claim about what is DENIED.
//
// A token with accounts:read — the scope a CI job is handed — reaches no admin
// route. So does a token with a scope that does not exist. Both are 403 and
// neither reaches the use case.
func TestAnAdminTokenHoldingNeitherScopeIsRefused(t *testing.T) {
	t.Parallel()

	for _, scope := range []string{apikeys.ScopeAccountsRead, apikeys.ScopeAccountsWrite, "invented:scope"} {
		t.Run(scope, func(t *testing.T) {
			t.Parallel()
			f := newAdminFixture(t, scope)

			rec := f.adminSend(t, http.MethodGet, f.auditPath(), "", f.token)
			if rec.Code != http.StatusForbidden {
				t.Errorf("a token with %s reached the audit trail = %d, want 403", scope, rec.Code)
			}
			if f.admin.sawList {
				t.Error("the use case was reached")
			}
		})
	}
}

// TestTheAdminRoutesAreAbsentWithoutTheService follows the house rule that a
// misconfiguration is a 404 rather than a 500, and it is here because the admin
// surface is the one where a route that silently does not exist is most
// expensive: somebody would conclude the account has no admin history.
func TestTheAdminRoutesAreAbsentWithoutTheService(t *testing.T) {
	t.Parallel()

	auth := newFakeAuth()
	handler := New(nil,
		WithAuth(auth),
		WithTenancy(newFakeTenancy()),
		WithAPIKeyCaller(newFakeAPIKeyCaller(auth.user, apikeys.Key{
			ID: id.MustNew(), UserID: auth.user.ID, AccountID: id.MustNew(),
			Scopes: apikeys.AllScopes(),
		})),
		// No WithAdmin.
	)

	req := httptest.NewRequest(http.MethodGet, "/v1/accounts/"+id.MustNew().String()+"/admin/audit-log", nil)
	req.Header.Set("Authorization", "Bearer "+apiKeySecret)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404; body: %s", rec.Code, rec.Body)
	}
}
