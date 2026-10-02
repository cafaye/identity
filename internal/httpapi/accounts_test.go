package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"log/slog"

	"github.com/cafaye/identity/internal/accounts"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/users"
)

// These are the handler tests, against a programmable double for the tenancy use
// cases. They pin the mapping from a domain error to a status code, which is the
// half of the surface the integration suite cannot check: once a handler has
// called the service successfully, what it wrote is real, and the interesting
// failures are the ones a real database would refuse to produce twice.

func TestTenancyStatusCodes(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "a not-found is a 404",
			err:        accounts.ErrNotFound,
			wantStatus: http.StatusNotFound,
			wantCode:   CodeNotFound,
		},
		{
			// A caller with no membership in an account is told the account does
			// not exist. core: "403 is not allowed to leak existence". A 403 here
			// would confirm to any authenticated user that the id they guessed is
			// a real account, which is a free tenant-enumeration oracle.
			name:       "not being a member is a 404, not a 403",
			err:        accounts.ErrNotAMember,
			wantStatus: http.StatusNotFound,
			wantCode:   CodeNotFound,
		},
		{
			name:       "a taken slug is a 409",
			err:        accounts.ErrSlugTaken,
			wantStatus: http.StatusConflict,
			wantCode:   CodeConflict,
		},
		{
			name:       "an existing membership is a 409",
			err:        accounts.ErrAlreadyAMember,
			wantStatus: http.StatusConflict,
			wantCode:   CodeConflict,
		},
		{
			name:       "a pending invitation already exists is a 409",
			err:        accounts.ErrInvitationEmailTaken,
			wantStatus: http.StatusConflict,
			wantCode:   CodeConflict,
		},
		{
			// core's deprecation section puts 410 on the surface that is gone with a
			// link to its replacement, and an expired invitation is exactly that:
			// it is not redeemable and the fix is to ask for a new one.
			name:       "an expired invitation is a 410",
			err:        accounts.ErrInvitationExpired,
			wantStatus: http.StatusGone,
			wantCode:   CodeGone,
		},
		{
			name:       "a spent invitation is a 410",
			err:        accounts.ErrInvitationUsed,
			wantStatus: http.StatusGone,
			wantCode:   CodeGone,
		},
		{
			// A wrong token is a 404, not a 403 and not a 410. 403 would say "this
			// invitation exists, you may not have it"; 410 would say it too. Only
			// 404 is indistinguishable from an invitation that was never created.
			name:       "a wrong token is a 404",
			err:        accounts.ErrInvitationNotFound,
			wantStatus: http.StatusNotFound,
			wantCode:   CodeNotFound,
		},
		{
			name:       "demoting the only owner is a 422",
			err:        accounts.ErrSelfRoleChange,
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   CodeValidationFailed,
		},
		{
			name:       "removing the only owner is a 422",
			err:        accounts.ErrLastOwner,
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   CodeValidationFailed,
		},
		{
			name:       "an admin removing an owner is a 403",
			err:        accounts.ErrOwnerProtected,
			wantStatus: http.StatusForbidden,
			wantCode:   CodeForbidden,
		},
		{
			// Inviting the owner role is a well-formed request for something that
			// does not exist, which is 422 rather than 403: nothing about the
			// caller is wrong.
			name:       "inviting an owner is a 422",
			err:        accounts.ErrRoleNotInvitable,
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   CodeValidationFailed,
		},
		{
			name:       "a field error is a 422 with errors[]",
			err:        &accounts.FieldError{Field: "name", Code: accounts.CodeRequired},
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   CodeValidationFailed,
		},
		{
			name:       "a users field error is a 422 too",
			err:        &users.FieldError{Field: "email", Code: users.CodeInvalidFormat},
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   CodeValidationFailed,
		},
		{
			name:       "anything else is a 500",
			err:        errors.New("the connection pool is exhausted"),
			wantStatus: http.StatusInternalServerError,
			wantCode:   CodeInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeTenancy()
			fake.createErr = tt.err
			auth := newFakeAuth()
			rec := requestAs(t, New(nil, WithAuth(auth), WithTenancy(fake)), auth.token,
				http.MethodPost, "/v1/accounts", `{"name":"Acme"}`)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body)
			}
			p := decodeProblem(t, rec)
			if p.Code != tt.wantCode {
				t.Errorf("code = %q, want %q", p.Code, tt.wantCode)
			}
			if p.Status != tt.wantStatus {
				t.Errorf("the body's status = %d, want %d — they must agree with the response line", p.Status, tt.wantStatus)
			}
			if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
				t.Errorf("Content-Type = %q, want application/problem+json", got)
			}
			// core: errors[] appears only on a 422.
			if tt.wantStatus == http.StatusUnprocessableEntity {
				if len(p.Errors) == 0 {
					t.Error("a 422 with no errors[]; core scopes that array to 422 and it is empty")
				}
			} else if p.Errors != nil {
				t.Errorf("errors = %v on a %d; core scopes errors[] to 422", p.Errors, tt.wantStatus)
			}
		})
	}
}

// A 500 must not carry the internal error to the caller. A driver message names
// a host, a pool and sometimes a role.
func TestTenancyInternalErrorsAreLoggedNotReturned(t *testing.T) {
	fake := newFakeTenancy()
	fake.createErr = errors.New("dial tcp 10.0.0.5:5432: connection refused")

	auth := newFakeAuth()
	rec := requestAs(t, New(nil, WithAuth(auth), WithTenancy(fake)), auth.token,
		http.MethodPost, "/v1/accounts", `{"name":"Acme"}`)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "10.0.0.5") {
		t.Errorf("the 500 body leaks an internal address: %s", rec.Body)
	}
	p := decodeProblem(t, rec)
	if p.TraceID == "" {
		t.Error("the 500 carries no trace id, so support has nothing to quote")
	}
	if p.TraceID != rec.Header().Get(TraceHeader) {
		t.Errorf("the body's trace_id %q does not match the header %q", p.TraceID, rec.Header().Get(TraceHeader))
	}
}

// RequireAccountRole is the authorization decision, and it is the one place that
// decides between 404 and 403. Those two answers are not interchangeable: a 403
// on an account the caller cannot see confirms the account exists.
//
// The middleware is exercised directly, on a probe route, rather than through a
// real endpoint. That is what lets a case choose the minimum it is testing
// against: through PATCH the minimum is fixed at admin, so "a member is refused
// the owner minimum" would be untestable — the route would refuse them for a
// different reason and the test would prove nothing.
func TestRequireAccountRoleDistinguishesInvisibleFromForbidden(t *testing.T) {
	accountID := id.MustNew()
	auth := newFakeAuth()

	tests := []struct {
		name       string
		role       accounts.Role
		min        accounts.Role
		lookupErr  error
		wantStatus int
	}{
		{name: "a member meets the member minimum", role: accounts.RoleMember, min: accounts.RoleMember, wantStatus: http.StatusOK},
		{name: "an admin meets the member minimum", role: accounts.RoleAdmin, min: accounts.RoleMember, wantStatus: http.StatusOK},
		{name: "an owner meets the owner minimum", role: accounts.RoleOwner, min: accounts.RoleOwner, wantStatus: http.StatusOK},
		{name: "a member does not meet the admin minimum", role: accounts.RoleMember, min: accounts.RoleAdmin, wantStatus: http.StatusForbidden},
		{name: "an admin does not meet the owner minimum", role: accounts.RoleAdmin, min: accounts.RoleOwner, wantStatus: http.StatusForbidden},
		{
			// The one the whole function exists for. A 403 here would confirm to
			// any authenticated caller that the account id they guessed is real.
			name:       "no membership is a 404, whatever the minimum",
			role:       accounts.RoleMember,
			min:        accounts.RoleMember,
			lookupErr:  accounts.ErrNotAMember,
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "no membership is a 404 even for the owner minimum",
			role:       accounts.RoleMember,
			min:        accounts.RoleOwner,
			lookupErr:  accounts.ErrNotAMember,
			wantStatus: http.StatusNotFound,
		},
		{
			// A 500 rather than a 403: the membership could not be read, which is
			// not evidence that the caller is under-privileged. Answering 403 would
			// turn a database blip into a wrong authorization answer.
			name:       "a lookup failure is a 500",
			role:       accounts.RoleMember,
			min:        accounts.RoleMember,
			lookupErr:  errors.New("the connection pool is exhausted"),
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeTenancy()
			fake.getErr = tt.lookupErr
			fake.account = accounts.Account{ID: accountID, Name: "Acme", Slug: "acme"}
			fake.role = tt.role

			rec := requestAs(t, probeRouter(auth, fake, tt.min),
				auth.token, http.MethodGet, "/probe/"+accountID.String(), "")

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body)
			}
			switch tt.wantStatus {
			case http.StatusNotFound:
				if code := decodeProblem(t, rec).Code; code != CodeNotFound {
					t.Errorf("code = %q, want %q", code, CodeNotFound)
				}
			case http.StatusForbidden:
				if code := decodeProblem(t, rec).Code; code != CodeForbidden {
					t.Errorf("code = %q, want %q", code, CodeForbidden)
				}
			}
		})
	}
}

// probeRouter mounts the middleware on its own route, with a minimum the test
// chooses, and a handler that only reports that it was reached.
//
// It builds an options value directly rather than going through New, because New
// returns an http.Handler and the middleware under test is a method on options.
// The trace middleware is still wrapped around it so a decoded problem carries
// the header the body claims.
func probeRouter(a Auth, ten Tenancy, min accounts.Role) http.Handler {
	opts := options{
		auth:    a,
		tenancy: ten,
		logger:  slog.New(slog.DiscardHandler),
	}
	r := chi.NewRouter()
	r.Get("/probe/{accountID}", opts.requireAccountRole(min, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"reached": "the handler"})
	}))
	return traceMiddleware(r)
}

// The two denials must be indistinguishable in what they reveal, or the
// difference between them becomes the oracle. Neither may name the account.
func TestTheTwoDenialsDoNotLeakExistence(t *testing.T) {
	accountID := id.MustNew()
	auth := newFakeAuth()

	denial := func(role accounts.Role, min accounts.Role, lookupErr error) string {
		fake := newFakeTenancy()
		fake.getErr = lookupErr
		fake.account = accounts.Account{ID: accountID, Name: "Secret Project", Slug: "secret-project"}
		fake.role = role

		rec := requestAs(t, probeRouter(auth, fake, min),
			auth.token, http.MethodGet, "/probe/"+accountID.String(), "")
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 or 404", rec.Code)
		}
		return rec.Body.String()
	}

	bodies := map[string]string{
		"not a member":     denial(accounts.RoleMember, accounts.RoleMember, accounts.ErrNotAMember),
		"under-privileged": denial(accounts.RoleMember, accounts.RoleAdmin, nil),
	}

	// The slug is what must not appear: it is the one fact about the account the
	// caller does not already have. The id is in `instance`, which is the request
	// path core specifies, and the caller sent that path.
	for label, body := range bodies {
		if strings.Contains(body, "secret-project") {
			t.Errorf("a %s denial names the account's slug: %s", label, body)
		}
		if strings.Contains(body, "Secret Project") {
			t.Errorf("a %s denial names the account: %s", label, body)
		}
	}
}

// Every /v1 route requires a credential. This is the anonymous row of the matrix,
// asserted for the whole surface rather than per endpoint, because the one
// endpoint that must *not* require one is POST /v1/users and it is registered
// before the account routes.
func TestTenancyRoutesAreAbsentWithoutTenancy(t *testing.T) {
	// With no tenancy service there are no account routes at all, so a
	// misconfigured process answers 404 rather than a stack of 500s. Same rule as
	// the auth routes.
	h := New(nil, WithAuth(newFakeAuth()))

	for _, path := range []string{
		"/v1/accounts",
		"/v1/accounts/" + id.MustNew().String(),
		"/v1/accounts/" + id.MustNew().String() + "/invitations",
		"/v1/accounts/" + id.MustNew().String() + "/members/" + id.MustNew().String(),
		"/v1/invitations/accept",
	} {
		rec := request(t, h, http.MethodGet, path, "")
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s with no tenancy service = %d, want 404 — the route should not be mounted", path, rec.Code)
		}
	}
}

// The account detail response carries the caller's own role, so a client can
// render "you are an admin" without a second request. The shape is the contract.
func TestAccountResponseShape(t *testing.T) {
	accountID := id.MustNew()
	created := testInstant

	fake := newFakeTenancy()
	fake.account = accounts.Account{
		ID: accountID, Name: "Acme Corp", Slug: "acme-corp", Personal: false,
		CreatedAt: created, UpdatedAt: created,
	}
	fake.role = accounts.RoleAdmin
	fake.members = []accounts.MemberSummary{
		{Account: fake.account, Role: accounts.RoleOwner},
		{Account: fake.account, Role: accounts.RoleAdmin},
	}

	auth := newFakeAuth()
	rec := requestAs(t, New(nil, WithAuth(auth), WithTenancy(fake)), auth.token,
		http.MethodGet, "/v1/accounts/"+accountID.String(), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	var body accountResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not JSON: %v\n%s", err, rec.Body)
	}
	if body.ID != accountID.String() || body.Name != "Acme Corp" || body.Slug != "acme-corp" {
		t.Errorf("body = %+v, want the account that was created", body)
	}
	if body.Role != accounts.RoleAdmin {
		t.Errorf("role = %q, want the caller's own role %q", body.Role, accounts.RoleAdmin)
	}
	if len(body.Members) != 2 {
		t.Errorf("members = %+v, want 2 entries", body.Members)
	}
	if !body.CreatedAt.Equal(created) {
		t.Errorf("created_at = %s, want %s", body.CreatedAt, created)
	}
}

// The account list is a plain JSON array, not the {data, page} envelope. That is
// a deliberate, recorded deviation from core's pagination convention; see
// openapi/v1.yaml's Known gaps. What matters here is that it is an array and
// never null, because `null` and `[]` mean different things to a generated SDK.
func TestAccountListIsAnArrayNotNull(t *testing.T) {
	fake := newFakeTenancy()
	fake.list = []accounts.MemberSummary{}

	auth := newFakeAuth()
	rec := requestAs(t, New(nil, WithAuth(auth), WithTenancy(fake)), auth.token, http.MethodGet, "/v1/accounts", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	var body []accountListItem
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not a JSON array: %v\n%s", err, rec.Body)
	}
	if len(body) != 0 {
		t.Errorf("body = %+v, want an empty array", body)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != "[]" {
		t.Errorf("an empty list rendered as %q, want []", got)
	}
}

// EVERY ENTRY OF A MEMBER LIST HAS TO IDENTIFY THE MEMBER, and it did not.
//
// `membershipResponses` projected only `Role`, because `accounts.MemberSummary`
// carries the ACCOUNT and the role and never the user — the struct is shaped for
// `ListMine`, which answers "which accounts does this user belong to", and
// `Members` reuses it for "who is in this account". The consequence on the wire
// was three entries that differed only by role:
//
//	[{"account_id":"","user_id":"","role":"admin","created_at":"0001-01-01T00:00:00Z"}, …]
//
// A member list nobody can tell apart is not a member list, and it is worse than
// a missing one: a client rendering it draws three rows with no way to send
// `PATCH` or `DELETE` against any of them, because the path needs a user id the
// response does not carry.
//
// It went unnoticed because the operation is in no document — so there is no
// generated client and no consumer whose complaint would have surfaced it. That
// is the same gap packet identity-28 closes, and this is what closing it found.
// The fix is on the projection and on the summary; the assertion is here because
// a member list is exactly the kind of response a refactor silently empties.
func TestEveryMemberInAMemberListIdentifiesItself(t *testing.T) {
	accountID, ownerID, memberID, adminID := id.MustNew(), id.MustNew(), id.MustNew(), id.MustNew()
	joined := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
	account := accounts.Account{ID: accountID, Name: "Acme Corp", Slug: "acme-corp", CreatedAt: joined, UpdatedAt: joined}

	fake := newFakeTenancy()
	fake.account = account
	fake.role = accounts.RoleOwner
	fake.members = []accounts.MemberSummary{
		{Account: account, UserID: adminID, JoinedAt: joined, Role: accounts.RoleAdmin},
		{Account: account, UserID: ownerID, JoinedAt: joined, Role: accounts.RoleOwner},
		{Account: account, UserID: memberID, JoinedAt: joined, Role: accounts.RoleMember},
	}

	auth := newFakeAuth()
	handler := New(nil, WithAuth(auth), WithTenancy(fake))

	for _, target := range []string{
		"/v1/accounts/" + accountID.String(),
		"/v1/accounts/" + accountID.String() + "/members",
	} {
		rec := requestAs(t, handler, auth.token, http.MethodGet, target, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200; body: %s", target, rec.Code, rec.Body)
		}

		// Read the raw body rather than one projection: `GET /v1/accounts/{id}`
		// nests the array under `members` and `/members` under `memberships`, and a
		// test that only knows one of them would pass while the other stayed empty.
		var envelope struct {
			Members     []membershipResponse `json:"members"`
			Memberships []membershipResponse `json:"memberships"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
			t.Fatalf("GET %s is not JSON: %v\n%s", target, err, rec.Body)
		}
		got := envelope.Members
		if got == nil {
			got = envelope.Memberships
		}

		if len(got) != 3 {
			t.Fatalf("GET %s returned %d membership(s), want 3; body: %s", target, len(got), rec.Body)
		}
		seen := map[string]accounts.Role{}
		for _, m := range got {
			if m.UserID == "" {
				t.Errorf("GET %s — a membership carries no user_id: %+v\n"+
					"The two other routes that act on a member are "+
					"PATCH and DELETE /v1/accounts/{account_id}/members/{user_id}, so an entry "+
					"without one cannot be acted on by anything.", target, m)
				continue
			}
			if m.AccountID != accountID.String() {
				t.Errorf("GET %s — membership.account_id = %q, want %q", target, m.AccountID, accountID)
			}
			if m.CreatedAt.IsZero() {
				t.Errorf("GET %s — membership for %s has a zero created_at; it is when this user "+
					"joined, and a client rendering a member list shows it", target, m.UserID)
			}
			seen[m.UserID] = m.Role
		}
		for user, role := range map[id.UUID]accounts.Role{
			ownerID: accounts.RoleOwner, memberID: accounts.RoleMember, adminID: accounts.RoleAdmin,
		} {
			if seen[user.String()] != role {
				t.Errorf("GET %s — no entry for %s with role %q; the list read %v",
					target, user, role, seen)
			}
		}
	}
}

// The invitation token is returned exactly once, in the 201, and never again.
// A 200 on the same token has to be impossible, which is the store's conditional
// UPDATE; here the point is narrower: the create response is the only place it
// appears.
func TestInvitationResponseCarriesTheTokenOnce(t *testing.T) {
	accountID := id.MustNew()
	fake := newFakeTenancy()
	fake.invite = accounts.Invited{
		Invitation: accounts.Invitation{
			ID:          id.MustNew(),
			AccountID:   accountID,
			Email:       "invitee@example.com",
			Role:        accounts.RoleMember,
			ExpiresAt:   time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC),
			TokenDigest: "0f7c" + strings.Repeat("a", 60),
		},
		Token: "the-one-time-token",
	}

	auth := newFakeAuth()
	fake.role = accounts.RoleAdmin
	rec := requestAs(t, New(nil, WithAuth(auth), WithTenancy(fake)), auth.token,
		http.MethodPost, "/v1/accounts/"+accountID.String()+"/invitations",
		`{"email":"invitee@example.com","role":"member"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", rec.Code, rec.Body)
	}

	var body invitationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	if body.Token != "the-one-time-token" {
		t.Errorf("token = %q, want the one-time token", body.Token)
	}
	// The digest is what the row holds; it must not be in the response.
	if strings.Contains(rec.Body.String(), fake.invite.Invitation.TokenDigest) {
		t.Errorf("the response carries the stored digest: %s", rec.Body)
	}
}

// Accepting an invitation returns the membership that now exists. It is the
// moment the caller needs to know their role, and the token is gone from the
// response by then.
func TestAcceptInvitationReturnsTheMembership(t *testing.T) {
	accountID := id.MustNew()
	userID := id.MustNew()
	acceptedAt := testInstant

	fake := newFakeAuth()
	tenancy := newFakeTenancy()
	tenancy.accepted = accounts.Membership{
		AccountID: accountID, UserID: userID, Role: accounts.RoleAdmin, CreatedAt: acceptedAt,
	}

	rec := requestAs(t, New(nil, WithAuth(fake), WithTenancy(tenancy)), fake.token,
		http.MethodPost, "/v1/invitations/accept", `{"token":"a-token"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	var body membershipResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	if body.AccountID != accountID.String() || body.UserID != userID.String() || body.Role != accounts.RoleAdmin {
		t.Errorf("body = %+v, want the membership that was created", body)
	}
}

// A malformed id in the path is a 404, not a 422. The path is part of a
// resource's identity: "this id is not an id this service issued" and "this id
// is an id this service issued but you cannot see it" must be the same answer,
// or the second one becomes probeable.
func TestMalformedAccountIDIsNotFound(t *testing.T) {
	for _, path := range []string{
		"/v1/accounts/not-a-uuid",
		"/v1/accounts/12345",
		"/v1/accounts/00000000-0000-0000-0000-000000000000",
		"/v1/accounts/../../../etc/passwd",
		"/v1/accounts/%2e%2e%2f%2e%2e",
	} {
		t.Run(path, func(t *testing.T) {
			// Authenticated, because 401 is checked first and 401 is the right
			// answer for an anonymous caller whatever the path says.
			auth := newFakeAuth()
			rec := requestAs(t, New(nil, WithAuth(auth), WithTenancy(newFakeTenancy())),
				auth.token, http.MethodGet, path, "")
			if rec.Code != http.StatusNotFound {
				t.Errorf("GET %s = %d, want 404; body: %s", path, rec.Code, rec.Body)
			}
		})
	}
}

// The role path parameter is parsed the same way whether it arrives as
// accounts.Role or as a string, and an unknown one is a 422 that names the field
// rather than a 400 or a 500.
//
// Note what is NOT in this table: `{"role": 7}`. A JSON value of the wrong type
// is a 400 in this service, grouped with a syntax error by decodeBody, and that
// grouping was decided and reviewed in identity-02 — see its comment. A tenancy
// endpoint does not get a third opinion, so the behaviour is asserted here
// rather than left to be rediscovered.
func TestRoleBodyErrorsAreFieldErrors(t *testing.T) {
	accountID := id.MustNew()
	userID := id.MustNew()
	fakeAuth := newFakeAuth()

	tests := []struct {
		name     string
		body     string
		wantCode string
	}{
		{name: "an unknown role", body: `{"role":"superuser"}`, wantCode: accounts.CodeUnknownRole},
		{name: "an empty role", body: `{"role":""}`, wantCode: accounts.CodeUnknownRole},
		{name: "a role with the wrong case", body: `{"role":"Admin"}`, wantCode: accounts.CodeUnknownRole},
		{name: "no role at all", body: `{}`, wantCode: accounts.CodeUnknownRole},
		{name: "a role with trailing space", body: `{"role":"member "}`, wantCode: accounts.CodeUnknownRole},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The caller has to be an owner to reach the route at all, so that the
			// 422 under test is about the body and not about the minimum.
			tenancy := newFakeTenancy()
			tenancy.role = accounts.RoleOwner

			path := fmt.Sprintf("/v1/accounts/%s/members/%s", accountID, userID)
			rec := requestAs(t, New(nil, WithAuth(fakeAuth), WithTenancy(tenancy)),
				fakeAuth.token, http.MethodPatch, path, tt.body)

			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422; body: %s", rec.Code, rec.Body)
			}
			p := decodeProblem(t, rec)
			found := false
			for _, fe := range p.Errors {
				if fe.Field == "role" && fe.Code == tt.wantCode {
					found = true
				}
			}
			if !found {
				t.Errorf("errors = %+v, want an entry for role/%s", p.Errors, tt.wantCode)
			}
		})
	}
}

// A JSON value of the wrong type is a 400, not a 422, and it stays that way on
// the tenancy routes. decodeBody groups json.UnmarshalTypeError with syntax
// errors and core reserves 400 for "malformed syntax the client could not have
// known"; whether a number where a string belongs counts is that group's call,
// and it was made in identity-02 for every endpoint in the service.
func TestRoleOfTheWrongJSONTypeIs400(t *testing.T) {
	auth := newFakeAuth()
	tenancy := newFakeTenancy()
	tenancy.role = accounts.RoleOwner

	path := fmt.Sprintf("/v1/accounts/%s/members/%s", id.MustNew(), id.MustNew())
	rec := requestAs(t, New(nil, WithAuth(auth), WithTenancy(tenancy)),
		auth.token, http.MethodPatch, path, `{"role":7}`)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body: %s", rec.Code, rec.Body)
	}
	if code := decodeProblem(t, rec).Code; code != CodeInvalidJSON {
		t.Errorf("code = %q, want %q", code, CodeInvalidJSON)
	}
}

// contextWithAccount is a helper for handler tests that need the request context
// RequireAccountRole populates.
func contextWithAccount(ctx context.Context, a accounts.Account, role accounts.Role) context.Context {
	return context.WithValue(ctx, accountContextKey{}, accountScope{Account: a, Role: role})
}
