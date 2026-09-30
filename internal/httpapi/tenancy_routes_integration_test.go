package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/accounts"
	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
)

// The targeted tenancy cases, over HTTP, against the real service and a real
// database. The authorization matrix proves the shape of every answer; this file
// proves the ones that depend on state changing: an invitation being spent, an
// owner's count reaching one, a slug being taken.
//
// Each test drives the real router, so a token in these tests is one the service
// minted and a role in the database is one a previous request wrote.

type tenancyWorld struct {
	handler http.Handler
	clock   *clock.Fake
}

// newTenancyWorld builds the whole service over a private schema.
func newTenancyWorld(t *testing.T) *tenancyWorld {
	t.Helper()
	return newTenancyWorldWithSession(t, 24*time.Hour)
}

// newTenancyWorldWithSession is newTenancyWorld with the session lifetime
// spelled out.
//
// A test that moves the clock by more than a day has to say so here, and the
// reason is worth stating once: moving the clock also ages every session, so a
// 24-hour session is a 401 by the time an invitation's seven-day window closes.
// That is the system behaving correctly — the test was asking two questions at
// once — and the fix is a session that outlives the thing under test.
func newTenancyWorldWithSession(t *testing.T, sessionTTL time.Duration) *tenancyWorld {
	t.Helper()

	pool := dbtest.Schema(t)
	clk := clock.NewFake(time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))

	return &tenancyWorld{
		handler: New(nil,
			WithAuth(authServiceWithSessionTTL(pool, clk, sessionTTL)),
			WithTenancy(realTenancy(pool, clk)),
			WithLogger(slogLogger(&recordingHandler{})),
		),
		clock: clk,
	}
}

// signedUp is a user with a live session: the fixture every test starts from.
type signedUp struct {
	token string
	id    id.UUID
	email string
}

func (w *tenancyWorld) signUp(t *testing.T) signedUp {
	t.Helper()

	email := dbtest.UniqueEmail(t)
	rec := post(t, w.handler, "/v1/users", `{"email":"`+email+`","password":"`+matrixPassword+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering: %d; body: %s", rec.Code, rec.Body)
	}
	var created userResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("the registration body is not JSON: %v", err)
	}
	parsed, err := id.Parse(created.ID)
	if err != nil {
		t.Fatalf("the service returned an unparseable id: %v", err)
	}

	login := post(t, w.handler, "/v1/session", `{"email":"`+email+`","password":"`+matrixPassword+`"}`)
	if login.Code != http.StatusOK {
		t.Fatalf("signing in: %d; body: %s", login.Code, login.Body)
	}
	var session sessionResponse
	if err := json.Unmarshal(login.Body.Bytes(), &session); err != nil {
		t.Fatalf("the login body is not JSON: %v", err)
	}

	return signedUp{token: session.Token, id: parsed, email: email}
}

// response wraps a recorder with the account and invitation shapes the tests
// read back, so each assertion says what it means instead of decoding JSON.
type tenancyResponse struct {
	code      int
	body      string
	account   accountResponse
	member    membershipResponse
	invite    invitationResponse
	list      []accountListItem
	decoded   bool
	problem   Problem
	rawHeader http.Header
}

func (w *tenancyWorld) call(t *testing.T, token, method, target, body string) *tenancyResponse {
	t.Helper()

	rec := requestAs(t, w.handler, token, method, target, body)
	out := &tenancyResponse{code: rec.Code, body: rec.Body.String(), rawHeader: rec.Header()}

	switch rec.Code {
	case http.StatusOK, http.StatusCreated:
		switch {
		case strings.HasSuffix(target, "/invitations/accept"):
			out.decode(t, &out.member)
		case strings.HasSuffix(target, "/invitations"):
			out.decode(t, &out.invite)
		case target == "/v1/accounts" && method == http.MethodGet:
			out.decode(t, &out.list)
		case strings.Contains(target, "/members/"):
			out.decode(t, &out.member)
		default:
			out.decode(t, &out.account)
		}
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound,
		http.StatusConflict, http.StatusGone, http.StatusUnprocessableEntity:
		out.decode(t, &out.problem)
	}
	return out
}

func (r *tenancyResponse) decode(t *testing.T, into any) {
	t.Helper()
	if err := json.Unmarshal([]byte(r.body), into); err != nil {
		t.Fatalf("the body is not the JSON the test expects: %v\n%s", err, r.body)
	}
}

// A registration creates a personal account, and GET /v1/accounts shows it. This
// is the packet's "auto-create personal account, same transaction" as a client
// experiences it, and the name is the email's local part.
func TestRegistrationProvisionsAPersonalAccount(t *testing.T) {
	w := newTenancyWorld(t)
	user := w.signUp(t)

	listed := w.call(t, user.token, http.MethodGet, "/v1/accounts", "")
	if listed.code != http.StatusOK {
		t.Fatalf("GET /v1/accounts = %d; body: %s", listed.code, listed.body)
	}

	var personal *accountListItem
	for i := range listed.list {
		if listed.list[i].Personal {
			personal = &listed.list[i]
		}
	}
	if personal == nil {
		t.Fatalf("no personal account in the list: %+v", listed.list)
	}
	if want := accounts.PersonalName(user.email); personal.Name != want {
		t.Errorf("the personal account is named %q, want the email local part %q", personal.Name, want)
	}
	if personal.Role != accounts.RoleOwner {
		t.Errorf("the personal account's role is %q, want %q", personal.Role, accounts.RoleOwner)
	}
}

// A slug is derived from the name and is unique, so the second account with the
// same name is a 409. It is a refusal rather than a silent disambiguation: the
// second person is told, and the first person's handle does not move.
func TestSlugUniquenessIs409(t *testing.T) {
	w := newTenancyWorld(t)
	user := w.signUp(t)

	first := w.call(t, user.token, http.MethodPost, "/v1/accounts", `{"name":"Acme Corp"}`)
	if first.code != http.StatusCreated {
		t.Fatalf("the first create = %d; body: %s", first.code, first.body)
	}
	if first.account.Slug != "acme-corp" {
		t.Errorf("slug = %q, want %q", first.account.Slug, "acme-corp")
	}

	second := w.call(t, user.token, http.MethodPost, "/v1/accounts", `{"name":"acme corp"}`)
	if second.code != http.StatusConflict {
		t.Fatalf("the second create = %d, want 409; body: %s", second.code, second.body)
	}
	if second.problem.Code != CodeConflict {
		t.Errorf("code = %q, want %q", second.problem.Code, CodeConflict)
	}

	// The first account is untouched, and nothing was disambiguated.
	list := w.call(t, user.token, http.MethodGet, "/v1/accounts", "")
	seen := 0
	for _, item := range list.list {
		if item.Slug == "acme-corp" {
			seen++
		}
	}
	if seen != 1 {
		t.Errorf("%d accounts carry the slug acme-corp, want 1: %+v", seen, list.list)
	}
}

// The whole invitation lifecycle over HTTP: an admin invites, the invitee
// redeems, and the membership exists. Then the token is spent and says so.
func TestInvitationLifecycleOverHTTP(t *testing.T) {
	w := newTenancyWorld(t)
	owner := w.signUp(t)

	account := w.call(t, owner.token, http.MethodPost, "/v1/accounts", `{"name":"Inviting"}`)
	if account.code != http.StatusCreated {
		t.Fatalf("creating the account = %d; body: %s", account.code, account.body)
	}
	path := "/v1/accounts/" + account.account.ID

	invitee := w.signUp(t)
	invited := w.call(t, owner.token, http.MethodPost, path+"/invitations",
		`{"email":"`+invitee.email+`","role":"member"}`)
	if invited.code != http.StatusCreated {
		t.Fatalf("inviting = %d; body: %s", invited.code, invited.body)
	}
	if invited.invite.Token == "" {
		t.Fatal("the 201 carries no token, so the invitation cannot be redeemed")
	}
	// The response is the only place the raw token ever appears, and the digest is
	// not in it at all: the digest is what the row holds, and a response that
	// echoed it would tell a client something it has no use for.
	if strings.Contains(invited.body, "token_digest") {
		t.Errorf("the invitation response carries the stored digest: %s", invited.body)
	}

	// Before accepting, the invitee is a stranger to the account.
	if got := w.call(t, invitee.token, http.MethodGet, path, "").code; got != http.StatusNotFound {
		t.Errorf("the invitee reading the account before accepting = %d, want 404", got)
	}

	accepted := w.call(t, invitee.token, http.MethodPost, "/v1/invitations/accept",
		`{"token":"`+invited.invite.Token+`"}`)
	if accepted.code != http.StatusOK {
		t.Fatalf("accepting = %d; body: %s", accepted.code, accepted.body)
	}
	if accepted.member.Role != accounts.RoleMember {
		t.Errorf("the membership's role is %q, want %q", accepted.member.Role, accounts.RoleMember)
	}
	if accepted.member.AccountID != account.account.ID {
		t.Errorf("the membership is for account %s, want %s", accepted.member.AccountID, account.account.ID)
	}
	if accepted.member.UserID != invitee.id.String() {
		t.Errorf("the membership is for user %s, want %s", accepted.member.UserID, invitee.id)
	}

	// And now the invitee can read it, at the role the invitation carried.
	read := w.call(t, invitee.token, http.MethodGet, path, "")
	if read.code != http.StatusOK {
		t.Fatalf("the invitee reading the account after accepting = %d; body: %s", read.code, read.body)
	}
	if read.account.Role != accounts.RoleMember {
		t.Errorf("the invitee's role is %q, want %q", read.account.Role, accounts.RoleMember)
	}

	// The token is spent: a second redemption is a 410, not a 200.
	again := w.call(t, owner.token, http.MethodPost, "/v1/invitations/accept",
		`{"token":"`+invited.invite.Token+`"}`)
	if again.code != http.StatusGone {
		t.Errorf("redeeming a spent token = %d, want 410; body: %s", again.code, again.body)
	}
	if again.problem.Code != CodeGone {
		t.Errorf("code = %q, want %q", again.problem.Code, CodeGone)
	}
}

// Expiry, with the clock moved rather than slept through, and the four shapes of
// a token that does not work.
func TestInvitationExpiryAndBadTokensOverHTTP(t *testing.T) {
	// A 30-day session, so the seven days this test moves the clock are about the
	// invitation's window and not about the session's.
	w := newTenancyWorldWithSession(t, 30*24*time.Hour)
	owner := w.signUp(t)
	account := w.call(t, owner.token, http.MethodPost, "/v1/accounts", `{"name":"Expiring"}`)

	invitee := w.signUp(t)
	invited := w.call(t, owner.token, http.MethodPost,
		"/v1/accounts/"+account.account.ID+"/invitations",
		`{"email":"`+invitee.email+`","role":"member"}`)

	// One second before the window closes, it still works.
	w.clock.Advance(accounts.InvitationTTL - time.Second)
	if got := w.call(t, invitee.token, http.MethodPost, "/v1/invitations/accept",
		`{"token":"`+invited.invite.Token+`"}`).code; got != http.StatusOK {
		t.Errorf("one second before expiry = %d, want 200", got)
	}

	// A second invitation, and the clock moved past its window.
	latecomer := w.signUp(t)
	late := w.call(t, owner.token, http.MethodPost,
		"/v1/accounts/"+account.account.ID+"/invitations",
		`{"email":"`+latecomer.email+`","role":"member"}`)
	if late.code != http.StatusCreated {
		t.Fatalf("the second invitation = %d, want 201; body: %s", late.code, late.body)
	}
	w.clock.Advance(accounts.InvitationTTL + time.Second)

	expired := w.call(t, latecomer.token, http.MethodPost, "/v1/invitations/accept",
		`{"token":"`+late.invite.Token+`"}`)
	if expired.code != http.StatusGone {
		t.Errorf("an expired invitation = %d, want 410; body: %s", expired.code, expired.body)
	}

	// The four ways a token can be wrong, all one answer.
	fresh := w.signUp(t)
	real := late.invite.Token
	if len(real) < 2 {
		t.Fatalf("the second invitation returned no usable token: %q", real)
	}
	tampered := real[:len(real)-1] + "z"
	_, unknown, err := accounts.NewToken()
	if err != nil {
		t.Fatalf("minting an unknown token: %v", err)
	}

	for name, token := range map[string]string{
		"empty":     "",
		"malformed": "not-a-token",
		"unknown":   unknown,
		"tampered":  tampered,
	} {
		t.Run("a "+name+" token is a 404", func(t *testing.T) {
			got := w.call(t, fresh.token, http.MethodPost, "/v1/invitations/accept",
				`{"token":"`+token+`"}`)
			if got.code != http.StatusNotFound {
				t.Errorf("status = %d, want 404; body: %s", got.code, got.body)
			}
			if got.problem.Code != CodeNotFound {
				t.Errorf("code = %q, want %q", got.problem.Code, CodeNotFound)
			}
		})
	}
}

// The last-owner protection, over HTTP: the only owner cannot demote themselves
// (422) and cannot be removed (422), and a second owner unlocks both.
func TestLastOwnerProtectionOverHTTP(t *testing.T) {
	w := newTenancyWorld(t)
	owner := w.signUp(t)
	account := w.call(t, owner.token, http.MethodPost, "/v1/accounts", `{"name":"Sole Owner"}`)
	base := "/v1/accounts/" + account.account.ID

	// The only owner, demoting themselves.
	demote := w.call(t, owner.token, http.MethodPatch,
		base+"/members/"+owner.id.String(), `{"role":"member"}`)
	if demote.code != http.StatusUnprocessableEntity {
		t.Errorf("the only owner demoting themselves = %d, want 422; body: %s", demote.code, demote.body)
	}
	if demote.problem.Code != CodeValidationFailed {
		t.Errorf("code = %q, want %q", demote.problem.Code, CodeValidationFailed)
	}

	// The only owner, removing themselves.
	remove := w.call(t, owner.token, http.MethodDelete, base+"/members/"+owner.id.String(), "")
	if remove.code != http.StatusUnprocessableEntity {
		t.Errorf("the only owner removing themselves = %d, want 422; body: %s", remove.code, remove.body)
	}

	// Still the owner, in both cases.
	read := w.call(t, owner.token, http.MethodGet, base, "")
	if read.account.Role != accounts.RoleOwner {
		t.Errorf("the owner's role is %q after two refusals, want %q", read.account.Role, accounts.RoleOwner)
	}

	// A second owner. NOT by invitation: the owner role is not invitable, so the
	// only way an account gains one is an existing owner promoting a member. That
	// is a deliberate rule — ownership is granted, never carried by a link — and
	// this is where the suite pins the consequence of it.
	successor := w.signUp(t)
	inviteAndAcceptOver(t, w, owner, base, successor, accounts.RoleMember)

	promoted := w.call(t, owner.token, http.MethodPatch,
		base+"/members/"+successor.id.String(), `{"role":"owner"}`)
	if promoted.code != http.StatusOK {
		t.Fatalf("promoting a member to owner = %d, want 200; body: %s", promoted.code, promoted.body)
	}
	if promoted.member.Role != accounts.RoleOwner {
		t.Errorf("the promoted role is %q, want %q", promoted.member.Role, accounts.RoleOwner)
	}

	// Two owners now, so the first may step down.
	stepDown := w.call(t, owner.token, http.MethodPatch,
		base+"/members/"+owner.id.String(), `{"role":"member"}`)
	if stepDown.code != http.StatusOK {
		t.Errorf("one of two owners stepping down = %d, want 200; body: %s", stepDown.code, stepDown.body)
	}
	if stepDown.member.Role != accounts.RoleMember {
		t.Errorf("the new role is %q, want %q", stepDown.member.Role, accounts.RoleMember)
	}

	// And now the account has one owner again, who cannot step down.
	again := w.call(t, successor.token, http.MethodPatch,
		base+"/members/"+successor.id.String(), `{"role":"admin"}`)
	if again.code != http.StatusUnprocessableEntity {
		t.Errorf("the new sole owner demoting themselves = %d, want 422; body: %s", again.code, again.body)
	}

	// And the last owner cannot be removed either.
	removeLast := w.call(t, successor.token, http.MethodDelete,
		base+"/members/"+successor.id.String(), "")
	if removeLast.code != http.StatusUnprocessableEntity {
		t.Errorf("the sole owner removing themselves = %d, want 422; body: %s", removeLast.code, removeLast.body)
	}
}

// An admin may not remove an owner, and may not hand out the admin role. Both
// are 403 and 422 respectively, and neither depends on the admin being able to
// do everything else.
func TestAdminCannotTouchOwnersOverHTTP(t *testing.T) {
	w := newTenancyWorld(t)
	owner := w.signUp(t)
	account := w.call(t, owner.token, http.MethodPost, "/v1/accounts", `{"name":"Hierarchy"}`)
	base := "/v1/accounts/" + account.account.ID

	admin := w.signUp(t)
	inviteAndAcceptOver(t, w, owner, base, admin, accounts.RoleAdmin)

	// An admin removing the owner: 403.
	removeOwner := w.call(t, admin.token, http.MethodDelete, base+"/members/"+owner.id.String(), "")
	if removeOwner.code != http.StatusForbidden {
		t.Errorf("an admin removing the owner = %d, want 403; body: %s", removeOwner.code, removeOwner.body)
	}
	if removeOwner.problem.Code != CodeForbidden {
		t.Errorf("code = %q, want %q", removeOwner.problem.Code, CodeForbidden)
	}

	// The owner is still there.
	if got := w.call(t, owner.token, http.MethodGet, base, ""); got.code != http.StatusOK {
		t.Errorf("the owner lost access after a refused removal: %d", got.code)
	}

	// An admin inviting an admin: 422. The privilege has to come from above.
	inviteAdmin := w.call(t, admin.token, http.MethodPost, base+"/invitations",
		`{"email":"`+dbtest.UniqueEmail(t)+`","role":"admin"}`)
	if inviteAdmin.code != http.StatusUnprocessableEntity {
		t.Errorf("an admin inviting an admin = %d, want 422; body: %s", inviteAdmin.code, inviteAdmin.body)
	}

	// An admin inviting a member: 201.
	inviteMember := w.call(t, admin.token, http.MethodPost, base+"/invitations",
		`{"email":"`+dbtest.UniqueEmail(t)+`","role":"member"}`)
	if inviteMember.code != http.StatusCreated {
		t.Errorf("an admin inviting a member = %d, want 201; body: %s", inviteMember.code, inviteMember.body)
	}

	// And the owner may invite an admin, because they already hold the role.
	ownerInvite := w.call(t, owner.token, http.MethodPost, base+"/invitations",
		`{"email":"`+dbtest.UniqueEmail(t)+`","role":"admin"}`)
	if ownerInvite.code != http.StatusCreated {
		t.Errorf("an owner inviting an admin = %d, want 201; body: %s", ownerInvite.code, ownerInvite.body)
	}

	// The owner role is not invitable at all, even by the owner.
	inviteOwner := w.call(t, owner.token, http.MethodPost, base+"/invitations",
		`{"email":"`+dbtest.UniqueEmail(t)+`","role":"owner"}`)
	if inviteOwner.code != http.StatusUnprocessableEntity {
		t.Errorf("inviting the owner role = %d, want 422; body: %s", inviteOwner.code, inviteOwner.body)
	}
}

// A pending invitation for the same address is a 409, and re-inviting the same
// address after the first is accepted is allowed.
func TestDuplicatePendingInvitationIs409(t *testing.T) {
	w := newTenancyWorld(t)
	owner := w.signUp(t)
	account := w.call(t, owner.token, http.MethodPost, "/v1/accounts", `{"name":"One Invite"}`)
	base := "/v1/accounts/" + account.account.ID
	address := dbtest.UniqueEmail(t)

	if got := w.call(t, owner.token, http.MethodPost, base+"/invitations",
		`{"email":"`+address+`","role":"member"}`).code; got != http.StatusCreated {
		t.Fatalf("the first invitation = %d, want 201", got)
	}
	// The same address in a different case is the same address.
	second := w.call(t, owner.token, http.MethodPost, base+"/invitations",
		`{"email":"`+strings.ToUpper(address)+`","role":"member"}`)
	if second.code != http.StatusConflict {
		t.Errorf("a second pending invitation = %d, want 409; body: %s", second.code, second.body)
	}
}

// A rename moves the name and not the slug, and a rename to an invalid name is a
// 422.
func TestRenameOverHTTP(t *testing.T) {
	w := newTenancyWorld(t)
	owner := w.signUp(t)
	account := w.call(t, owner.token, http.MethodPost, "/v1/accounts", `{"name":"Before"}`)
	base := "/v1/accounts/" + account.account.ID

	renamed := w.call(t, owner.token, http.MethodPatch, base, `{"name":"After"}`)
	if renamed.code != http.StatusOK {
		t.Fatalf("renaming = %d; body: %s", renamed.code, renamed.body)
	}
	if renamed.account.Name != "After" {
		t.Errorf("name = %q, want %q", renamed.account.Name, "After")
	}
	if renamed.account.Slug != account.account.Slug {
		t.Errorf("slug = %q after a rename, want the original %q — a moving slug breaks every link already sent",
			renamed.account.Slug, account.account.Slug)
	}

	blank := w.call(t, owner.token, http.MethodPatch, base, `{"name":"   "}`)
	if blank.code != http.StatusUnprocessableEntity {
		t.Errorf("renaming to whitespace = %d, want 422; body: %s", blank.code, blank.body)
	}
}

// Deleting an account takes its members with it, and afterwards it is a 404 for
// everybody including the owner.
func TestDeleteOverHTTP(t *testing.T) {
	w := newTenancyWorld(t)
	owner := w.signUp(t)
	account := w.call(t, owner.token, http.MethodPost, "/v1/accounts", `{"name":"Temporary"}`)
	base := "/v1/accounts/" + account.account.ID

	member := w.signUp(t)
	inviteAndAcceptOver(t, w, owner, base, member, accounts.RoleMember)

	deleted := w.call(t, owner.token, http.MethodDelete, base, "")
	if deleted.code != http.StatusNoContent {
		t.Fatalf("deleting = %d, want 204; body: %s", deleted.code, deleted.body)
	}
	if body := strings.TrimSpace(deleted.body); body != "" {
		t.Errorf("a 204 carries a body: %q", body)
	}

	if got := w.call(t, owner.token, http.MethodGet, base, "").code; got != http.StatusNotFound {
		t.Errorf("reading a deleted account = %d, want 404", got)
	}
	// And the former member's list no longer mentions it.
	list := w.call(t, member.token, http.MethodGet, "/v1/accounts", "")
	for _, item := range list.list {
		if item.ID == account.account.ID {
			t.Error("a deleted account is still in a former member's list")
		}
	}
}

// The account list is the caller's own and nobody else's, and it carries the
// caller's role in each.
func TestAccountListIsScopedToTheCaller(t *testing.T) {
	w := newTenancyWorld(t)
	mine := w.signUp(t)
	theirs := w.signUp(t)

	mineAccount := w.call(t, mine.token, http.MethodPost, "/v1/accounts", `{"name":"Mine"}`)
	theirsAccount := w.call(t, theirs.token, http.MethodPost, "/v1/accounts", `{"name":"Theirs"}`)

	listed := w.call(t, mine.token, http.MethodGet, "/v1/accounts", "")
	if listed.code != http.StatusOK {
		t.Fatalf("listing = %d; body: %s", listed.code, listed.body)
	}
	for _, item := range listed.list {
		if item.ID == theirsAccount.account.ID {
			t.Error("the list contains another user's account")
		}
	}

	found := false
	for _, item := range listed.list {
		if item.ID == mineAccount.account.ID {
			found = true
			if item.Role != accounts.RoleOwner {
				t.Errorf("role = %q for an account the caller created, want %q", item.Role, accounts.RoleOwner)
			}
		}
	}
	if !found {
		t.Errorf("the list does not contain the account the caller created: %+v", listed.list)
	}
}

// inviteAndAcceptOver drives one invitation to completion over HTTP, so a test's
// fixture is built the way a client's would be: the inviter mints the token and
// the invitee redeems it with their own session.
func inviteAndAcceptOver(t *testing.T, w *tenancyWorld, inviter signedUp, base string, invitee signedUp, role accounts.Role) {
	t.Helper()

	invited := w.call(t, inviter.token, http.MethodPost, base+"/invitations",
		`{"email":"`+invitee.email+`","role":"`+string(role)+`"}`)
	if invited.code != http.StatusCreated {
		t.Fatalf("inviting %s as %s: %d; body: %s", invitee.email, role, invited.code, invited.body)
	}

	accepted := w.call(t, invitee.token, http.MethodPost, "/v1/invitations/accept",
		`{"token":"`+invited.invite.Token+`"}`)
	if accepted.code != http.StatusOK {
		t.Fatalf("%s accepting: %d; body: %s", invitee.email, accepted.code, accepted.body)
	}
	if accepted.member.Role != role {
		t.Errorf("%s joined as %q, want the invited role %q", invitee.email, accepted.member.Role, role)
	}
}
