package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/accounts"
	"github.com/cafaye/identity/internal/platform/id"
)

// fakeTenancy is a programmable stand-in for accounts.Service, so the handlers
// can be exercised for status codes, response shapes and which use case was
// called without a database. The end-to-end suite drives the real service over
// real SQL.
//
// Every use case has an error field, because the interesting handler behaviour
// is the mapping from a domain error to a status code and that cannot be produced
// by a real database on demand.
type fakeTenancy struct {
	// What the lookups return when no error is set.
	account  accounts.Account
	role     accounts.Role
	members  []accounts.MemberSummary
	list     []accounts.MemberSummary
	invite   accounts.Invited
	accepted accounts.Membership

	// What each use case should fail with.
	createErr     error
	getErr        error
	listErr       error
	membersErr    error
	renameErr     error
	deleteErr     error
	inviteErr     error
	acceptErr     error
	changeRoleErr error
	removeErr     error

	// Recorded inputs, so a test can prove the handler passed the caller's own id
	// rather than one from the request body.
	listedFor  id.UUID
	createdFor id.UUID
	invitedBy  id.UUID
	invitedFor id.UUID
	acceptedBy id.UUID
	changedFor ChangeRoleCall
	removedFor RemoveMemberCall
}

// ChangeRoleCall is what the handler asked for.
type ChangeRoleCall struct {
	AccountID id.UUID
	UserID    id.UUID
	Role      string
	Actor     id.UUID
}

// RemoveMemberCall is what the handler asked for.
type RemoveMemberCall struct {
	AccountID id.UUID
	UserID    id.UUID
	Actor     id.UUID
}

func newFakeTenancy() *fakeTenancy {
	return &fakeTenancy{
		list:     []accounts.MemberSummary{},
		members:  []accounts.MemberSummary{},
		accepted: accounts.Membership{},
	}
}

func (f *fakeTenancy) Create(_ context.Context, in accounts.CreateInput) (accounts.Created, error) {
	f.createdFor = in.Owner
	if f.createErr != nil {
		return accounts.Created{}, f.createErr
	}
	account := f.account
	if account.ID.IsZero() {
		account = accounts.Account{
			ID:        id.MustNew(),
			Name:      in.Name,
			Slug:      accounts.Slugify(in.Name),
			CreatedAt: testInstant,
			UpdatedAt: testInstant,
		}
	}
	return accounts.Created{Account: account, Membership: accounts.Membership{Role: accounts.RoleOwner}}, nil
}

func (f *fakeTenancy) ListMine(_ context.Context, userID id.UUID) ([]accounts.MemberSummary, error) {
	f.listedFor = userID
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.list, nil
}

func (f *fakeTenancy) Get(_ context.Context, accountID, userID id.UUID) (accounts.Account, accounts.Role, error) {
	if f.getErr != nil {
		return accounts.Account{}, "", f.getErr
	}
	return f.account, f.role, nil
}

func (f *fakeTenancy) Members(_ context.Context, _ id.UUID) ([]accounts.MemberSummary, error) {
	if f.membersErr != nil {
		return nil, f.membersErr
	}
	return f.members, nil
}

func (f *fakeTenancy) Rename(_ context.Context, accountID id.UUID, name string) (accounts.Account, error) {
	if f.renameErr != nil {
		return accounts.Account{}, f.renameErr
	}
	renamed := f.account
	renamed.Name = name
	return renamed, nil
}

func (f *fakeTenancy) Delete(_ context.Context, _ id.UUID) error { return f.deleteErr }

func (f *fakeTenancy) InviteRole(_ context.Context, accountID id.UUID, email, role string, invitedBy id.UUID) (accounts.Invited, error) {
	f.invitedFor, f.invitedBy = accountID, invitedBy
	if f.inviteErr != nil {
		return accounts.Invited{}, f.inviteErr
	}
	return f.invite, nil
}

func (f *fakeTenancy) Accept(_ context.Context, in accounts.AcceptInput) (accounts.Membership, error) {
	f.acceptedBy = in.User
	if f.acceptErr != nil {
		return accounts.Membership{}, f.acceptErr
	}
	return f.accepted, nil
}

func (f *fakeTenancy) ChangeRole(_ context.Context, in accounts.ChangeRoleInput) (accounts.Membership, error) {
	f.changedFor = ChangeRoleCall{
		AccountID: in.AccountID,
		UserID:    in.UserID,
		Role:      string(in.Role),
		Actor:     in.Actor,
	}
	if f.changeRoleErr != nil {
		return accounts.Membership{}, f.changeRoleErr
	}
	return accounts.Membership{AccountID: in.AccountID, UserID: in.UserID, Role: in.Role, CreatedAt: testInstant}, nil
}

func (f *fakeTenancy) RemoveMember(_ context.Context, in accounts.RemoveMemberInput) error {
	f.removedFor = RemoveMemberCall{AccountID: in.AccountID, UserID: in.UserID, Actor: in.Actor}
	return f.removeErr
}

// testInstant is the fixed instant the doubles stamp, so a response body's
// timestamps are exact rather than approximate.
var testInstant = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

// ---------------------------------------------------------------------------
// request helpers
// ---------------------------------------------------------------------------

// request sends a request with NO credential and fails the test if the route
// answers with a success.
//
// It is a separate function rather than a flag on requestAs so that "forgot to
// authenticate" is not a thing a test can express by accident: the anonymous row
// of the matrix is a different call site from every other row.
func request(t *testing.T, h http.Handler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()

	rec := send(t, h, method, target, body)
	if rec.Code == http.StatusOK || rec.Code == http.StatusCreated || rec.Code == http.StatusNoContent {
		t.Fatalf("%s %s = %d with no credential presented; the route is reachable anonymously", method, target, rec.Code)
	}
	return rec
}

// get is an unauthenticated read. It does NOT assert the failure, because some
// of its call sites are checking a 2xx from a handler reached through a
// middleware that has already authenticated — see accounts_test.go.
func get(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	return send(t, h, methodGet, target, "")
}

const methodGet = "GET"

// requestAs sends a request carrying a bearer token.
func requestAs(t *testing.T, h http.Handler, token, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+token)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
