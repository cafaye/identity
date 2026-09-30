package accounts

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/outbox"
	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/users"
)

// These drive the real Service over the real Store against a private schema.
//
// The rules worth testing here are the ones a hand-written fake would let you
// get wrong: the ones that depend on what is in the database at the moment of
// the decision — how many owners there are, whether an address already has a
// pending invitation, whether the user is already a member — and the ones about
// which writes land in the same transaction as which.

type harness struct {
	svc     *Service
	store   *Store
	events  *recordedEvents
	revokes *recordedRevocations
	clock   *clock.Fake
	q       db.Querier
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	pool := dbtest.Schema(t)
	clk := clock.NewFake(time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))
	events := &recordedEvents{}
	revokes := &recordedRevocations{}
	store := NewStore(pool)

	return &harness{
		store:   store,
		events:  events,
		revokes: revokes,
		clock:   clk,
		q:       pool,
		svc: NewService(
			db.TxRunner{Pool: pool},
			store,
			events,
			revokes,
			clk,
			db.Direct{Pool: pool},
		),
	}
}

// recordedRevocations is the CredentialRevoker double.
//
// It exists rather than the real api key store because this package CANNOT import
// that one: internal/apikeys imports this package for accounts.Role, so a real one
// here would be an import cycle that exists only because a role is a type on both
// sides. The double records what the use case asked for, which is the whole of
// this package's half of the contract — the table it reaches is apikeys' problem
// and is tested there.
type recordedRevocations struct {
	mu       sync.Mutex
	calls    []revocation
	failWith error
}

type revocation struct {
	accountID id.UUID
	userID    id.UUID
	at        time.Time
}

func (r *recordedRevocations) RevokeAllForMember(_ context.Context, _ db.Querier, accountID, userID id.UUID, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failWith != nil {
		return r.failWith
	}
	r.calls = append(r.calls, revocation{accountID: accountID, userID: userID, at: at})
	return nil
}

func (r *recordedRevocations) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

// recordedEvents keeps the envelopes, so a test can assert that an event was
// written rather than only that a method was called.
type recordedEvents struct {
	appended []outbox.Envelope
}

func (r *recordedEvents) Append(_ context.Context, _ db.Querier, e outbox.Envelope) error {
	r.appended = append(r.appended, e)
	return nil
}

// types is the list of event types appended so far, for failure messages.
func (r *recordedEvents) types() []string {
	out := make([]string, 0, len(r.appended))
	for _, e := range r.appended {
		out = append(out, e.Type)
	}
	return out
}

// only asserts that the appended events are exactly wantTypes, in any order.
func (r *recordedEvents) only(t *testing.T, wantTypes ...string) {
	t.Helper()

	got := r.types()
	if len(got) != len(wantTypes) {
		t.Errorf("appended %v, want exactly %v", got, wantTypes)
		return
	}
	seen := make(map[string]int, len(got))
	for _, typ := range got {
		seen[typ]++
	}
	for _, want := range wantTypes {
		if seen[want] == 0 {
			t.Errorf("no %s event was appended; appended %v", want, got)
			continue
		}
		seen[want]--
	}
}

// payloadFor returns the raw data of the first appended event of the given type.
func (r *recordedEvents) payloadFor(t *testing.T, eventType string) outbox.Envelope {
	t.Helper()

	for _, e := range r.appended {
		if e.Type == eventType {
			return e
		}
	}
	t.Fatalf("no %s event was appended; appended %v", eventType, r.types())
	return outbox.Envelope{}
}

// addUser writes a user row and returns its id. A fixture helper, not a use
// case: most of these tests care about memberships, not about how a user comes
// to exist.
func addUser(t *testing.T, q db.Querier) id.UUID {
	t.Helper()
	return addUserWithEmail(t, q, dbtest.UniqueEmail(t))
}

func addUserWithEmail(t *testing.T, q db.Querier, email string) id.UUID {
	t.Helper()

	uid := id.MustNew()
	if _, err := q.Exec(t.Context(),
		`INSERT INTO users (id, email, password_digest) VALUES ($1, $2, $3)`,
		uid, email, "argon2id$stub"); err != nil {
		t.Fatalf("inserting a user: %v", err)
	}
	return uid
}

// member makes a user with the given role in an account, without going through
// the invitation path. Fixtures need the end state, not the journey.
func (h *harness) member(t *testing.T, accountID id.UUID, role Role) id.UUID {
	t.Helper()

	uid := addUser(t, h.q)
	if _, err := h.store.AddMember(t.Context(), h.q, Membership{AccountID: accountID, UserID: uid, Role: role}); err != nil {
		t.Fatalf("adding a %s: %v", role, err)
	}
	return uid
}

// owned makes an account with owner as its sole owner, through the real use
// case so the fixture is the shape a client's would produce.
func (h *harness) owned(t *testing.T, name string, owner id.UUID) Account {
	t.Helper()

	created, err := h.svc.Create(t.Context(), CreateInput{Name: name, Owner: owner})
	if err != nil {
		t.Fatalf("Create(%q): %v", name, err)
	}
	return created.Account
}

func assertRole(t *testing.T, h *harness, accountID, userID id.UUID, want Role) {
	t.Helper()

	m, err := h.svc.Member(t.Context(), accountID, userID)
	if err != nil {
		t.Fatalf("Member(%s): %v", userID, err)
	}
	if m.Role != want {
		t.Errorf("role of %s is %q, want %q", userID, m.Role, want)
	}
}

func TestCreateMakesTheCallerTheOwner(t *testing.T) {
	h := newHarness(t)
	owner := addUser(t, h.q)

	account := h.owned(t, "Acme Corp", owner)

	if account.Personal {
		t.Error("Create made a personal account; only a registration does that")
	}
	if account.Slug != "acme-corp" {
		t.Errorf("slug = %q, want %q — it is derived from the name", account.Slug, "acme-corp")
	}

	// The creator is the owner, and that is the only membership. If this were
	// wrong the account would exist with nobody able to administer it.
	assertRole(t, h, account.ID, owner, RoleOwner)

	h.events.only(t, outbox.EventAccountCreated)
}

func TestCreateRejectsAnInvalidName(t *testing.T) {
	h := newHarness(t)
	owner := addUser(t, h.q)

	tests := []struct {
		name  string
		input string
		field string
		code  string
	}{
		{name: "empty", input: "", field: "name", code: CodeRequired},
		{name: "blank", input: "   ", field: "name", code: CodeRequired},
		{name: "nothing sluggable", input: "東京", field: "name", code: CodeInvalidFormat},
		{name: "over the limit", input: strings.Repeat("a", MaxNameLength+1), field: "name", code: CodeTooLong},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := h.svc.Create(t.Context(), CreateInput{Name: tt.input, Owner: owner})
			var fe *FieldError
			if !errors.As(err, &fe) {
				t.Fatalf("Create(%q) error is %T (%v), want *FieldError so the handler can answer 422", tt.input, err, err)
			}
			if fe.Field != tt.field || fe.Code != tt.code {
				t.Errorf("Create(%q) = %s/%s, want %s/%s", tt.input, fe.Field, fe.Code, tt.field, tt.code)
			}
		})
	}

	// A refused Create writes nothing at all: not an account, not an event.
	if got := h.events.types(); len(got) != 0 {
		t.Errorf("refused creates emitted %v, want none", got)
	}
}

// The slug is derived from the name and is unique, so the second account called
// "Acme Corp" is a 409 and the first is untouched. The refusal is the point: a
// silent "-2" suffix would hand the second person a handle nobody chose and move
// nothing for the first, but it would also mean the caller never learns their
// account is not the one they asked for.
func TestCreateRejectsATakenSlugThroughTheService(t *testing.T) {
	h := newHarness(t)
	owner := addUser(t, h.q)
	first := h.owned(t, "Acme Corp", owner)

	if _, err := h.svc.Create(t.Context(), CreateInput{Name: "acme corp", Owner: owner}); !errors.Is(err, ErrSlugTaken) {
		t.Fatalf("the second Create = %v, want ErrSlugTaken so the handler can answer 409", err)
	}

	read, err := h.svc.Account(t.Context(), first.ID)
	if err != nil {
		t.Fatalf("Account: %v", err)
	}
	if read.Name != "Acme Corp" || read.Slug != "acme-corp" {
		t.Errorf("the first account became %+v, want it untouched", read)
	}

	var count int
	if err := h.q.QueryRow(t.Context(), `SELECT count(*) FROM accounts`).Scan(&count); err != nil {
		t.Fatalf("counting accounts: %v", err)
	}
	if count != 1 {
		t.Errorf("%d accounts exist after a refused create, want 1", count)
	}
}

func TestGetIsInvisibleToANonMember(t *testing.T) {
	h := newHarness(t)
	owner := addUser(t, h.q)
	stranger := addUser(t, h.q)
	account := h.owned(t, "Private", owner)

	if _, _, err := h.svc.Get(t.Context(), account.ID, owner); err != nil {
		t.Fatalf("the owner cannot read their own account: %v", err)
	}

	// ErrNotAMember, not ErrNotFound: this package tells the two apart so the
	// HTTP layer can decide, and what the HTTP layer must then do is render them
	// identically.
	if _, _, err := h.svc.Get(t.Context(), account.ID, stranger); !errors.Is(err, ErrNotAMember) {
		t.Errorf("a stranger reading the account = %v, want ErrNotAMember", err)
	}
	if _, _, err := h.svc.Get(t.Context(), id.MustNew(), owner); !errors.Is(err, ErrNotAMember) {
		t.Errorf("reading a missing account = %v, want ErrNotAMember — it must be indistinguishable from not being a member", err)
	}
}

func TestListMineIsScopedToTheCaller(t *testing.T) {
	h := newHarness(t)
	mine := addUser(t, h.q)
	theirs := addUser(t, h.q)

	h.owned(t, "Mine One", mine)
	h.owned(t, "Mine Two", mine)
	h.owned(t, "Theirs", theirs)

	got, err := h.svc.ListMine(t.Context(), mine)
	if err != nil {
		t.Fatalf("ListMine: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("ListMine returned %d accounts, want 2: %+v", len(got), got)
	}
	for _, m := range got {
		if m.Account.Name == "Theirs" {
			t.Error("ListMine returned somebody else's account")
		}
		if m.Role != RoleOwner {
			t.Errorf("%q has role %q, want %q", m.Account.Name, m.Role, RoleOwner)
		}
	}
}

func TestInviteLifecycle(t *testing.T) {
	h := newHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, "Inviting", owner)
	email := dbtest.UniqueEmail(t)
	invitee := addUserWithEmail(t, h.q, email)

	invited, err := h.svc.Invite(t.Context(), InviteInput{
		AccountID: account.ID, Email: email, Role: RoleMember, InvitedBy: owner,
	})
	if err != nil {
		t.Fatalf("Invite: %v", err)
	}
	invitation, token := invited.Invitation, invited.Token

	// The token is returned exactly once and the row holds only its digest.
	if token == "" {
		t.Fatal("Invite returned no token, so nobody could ever accept it")
	}
	if invitation.TokenDigest == token {
		t.Error("the returned token is the stored digest, so the row holds the credential itself")
	}
	if invitation.TokenDigest != Digest(token) {
		t.Error("the stored digest is not the digest of the returned token")
	}
	if invitation.AcceptedAt != nil {
		t.Errorf("a pending invitation has accepted_at = %v, want nil", invitation.AcceptedAt)
	}
	if want := h.clock.Now().Add(InvitationTTL); !invitation.ExpiresAt.Equal(want) {
		t.Errorf("expires_at = %s, want %s (the injected now plus %s)", invitation.ExpiresAt, want, InvitationTTL)
	}

	// The invitee is not a member until they accept.
	if _, err := h.svc.Member(t.Context(), account.ID, invitee); !errors.Is(err, ErrNotAMember) {
		t.Errorf("the invitee is a member before accepting: %v", err)
	}

	m, err := h.svc.Accept(t.Context(), AcceptInput{Token: token, User: invitee})
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if m.Role != RoleMember || m.AccountID != account.ID {
		t.Errorf("Accept returned %+v, want a member of %s with role %q", m, account.ID, RoleMember)
	}

	// Both events, both in the redemption's transaction.
	h.events.only(t,
		outbox.EventAccountCreated,
		outbox.EventMemberInvited,
		outbox.EventMemberAccepted,
	)
}

// Expiry is checked against the injected clock, never by sleeping.
func TestAcceptIsRefusedAfterExpiry(t *testing.T) {
	h := newHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, "Expiring", owner)

	// One second before the window closes, the invitation still works.
	justInTime, err := h.svc.Invite(t.Context(), InviteInput{
		AccountID: account.ID, Email: dbtest.UniqueEmail(t), Role: RoleMember, InvitedBy: owner,
	})
	if err != nil {
		t.Fatalf("Invite: %v", err)
	}
	h.clock.Advance(InvitationTTL - time.Second)
	if _, err := h.svc.Accept(t.Context(), AcceptInput{Token: justInTime.Token, User: addUser(t, h.q)}); err != nil {
		t.Fatalf("one second before expiry: %v", err)
	}

	// A second invitation, and the clock moved past its window.
	late, err := h.svc.Invite(t.Context(), InviteInput{
		AccountID: account.ID, Email: dbtest.UniqueEmail(t), Role: RoleMember, InvitedBy: owner,
	})
	if err != nil {
		t.Fatalf("Invite: %v", err)
	}
	h.clock.Advance(InvitationTTL + time.Second)

	_, err = h.svc.Accept(t.Context(), AcceptInput{Token: late.Token, User: addUser(t, h.q)})
	if !errors.Is(err, ErrInvitationExpired) {
		t.Errorf("Accepting an expired invitation = %v, want ErrInvitationExpired so the handler can answer 410", err)
	}
}

// A wrong token, an unknown token, a tampered token and a malformed one are all
// the same error. Distinguishing them is how an invitation endpoint becomes an
// oracle for "was somebody invited to this account".
func TestAcceptIsSilentForAWrongToken(t *testing.T) {
	h := newHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, "Silent", owner)

	// A pending invitation to this same account, whose token we then decline to
	// present: the miss is silent even when a valid one exists, so the endpoint
	// cannot be turned into "does this person have an invitation here".
	if _, err := h.svc.Invite(t.Context(), InviteInput{
		AccountID: account.ID, Email: dbtest.UniqueEmail(t), Role: RoleMember, InvitedBy: owner,
	}); err != nil {
		t.Fatalf("Invite: %v", err)
	}
	invited, err := h.svc.Invite(t.Context(), InviteInput{
		AccountID: account.ID, Email: dbtest.UniqueEmail(t), Role: RoleMember, InvitedBy: owner,
	})
	if err != nil {
		t.Fatalf("Invite: %v", err)
	}
	_, unknown, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	user := addUser(t, h.q)

	cases := map[string]string{
		"an empty token":    "",
		"a malformed token": "not-a-token",
		"an unknown token":  unknown,
		"a tampered token":  tamper(invited.Token),
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := h.svc.Accept(t.Context(), AcceptInput{Token: token, User: user}); !errors.Is(err, ErrInvitationNotFound) {
				t.Errorf("Accept = %v, want ErrInvitationNotFound", err)
			}
		})
	}
}

func TestAcceptIsRefusedTwice(t *testing.T) {
	h := newHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, "Once", owner)
	email := dbtest.UniqueEmail(t)
	user := addUserWithEmail(t, h.q, email)

	invited, err := h.svc.Invite(t.Context(), InviteInput{
		AccountID: account.ID, Email: email, Role: RoleMember, InvitedBy: owner,
	})
	if err != nil {
		t.Fatalf("Invite: %v", err)
	}
	token := invited.Token
	if _, err := h.svc.Accept(t.Context(), AcceptInput{Token: token, User: user}); err != nil {
		t.Fatalf("the first Accept: %v", err)
	}

	if _, err := h.svc.Accept(t.Context(), AcceptInput{Token: token, User: user}); !errors.Is(err, ErrInvitationUsed) {
		t.Errorf("the second Accept = %v, want ErrInvitationUsed", err)
	}
}

// Accepting an invitation for an account you are already in is a 409, not a
// silent success: the caller's intent was to add a membership, and the state
// they asked for already holds.
func TestAcceptRefusesASecondMembership(t *testing.T) {
	h := newHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, "Twice", owner)
	user := addUser(t, h.q)

	first, err := h.svc.Invite(t.Context(), InviteInput{
		AccountID: account.ID, Email: "one-" + user.String()[:8] + "@example.com", Role: RoleMember, InvitedBy: owner,
	})
	if err != nil {
		t.Fatalf("Invite: %v", err)
	}
	if _, err := h.svc.Accept(t.Context(), AcceptInput{Token: first.Token, User: user}); err != nil {
		t.Fatalf("the first Accept: %v", err)
	}

	second, err := h.svc.Invite(t.Context(), InviteInput{
		AccountID: account.ID, Email: "two-" + user.String()[:8] + "@example.com", Role: RoleMember, InvitedBy: owner,
	})
	if err != nil {
		t.Fatalf("the second Invite: %v", err)
	}
	if _, err := h.svc.Accept(t.Context(), AcceptInput{Token: second.Token, User: user}); !errors.Is(err, ErrAlreadyAMember) {
		t.Errorf("Accepting into an account you are already in = %v, want ErrAlreadyAMember", err)
	}
}

// The email is normalized exactly as a registration's is, so "kaka@example.com"
// and "Kaka@Example.com" cannot both hold a pending invitation to one account.
func TestInviteNormalizesTheEmail(t *testing.T) {
	h := newHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, "Normalizing", owner)
	local := dbtest.UniqueEmail(t)

	invited, err := h.svc.Invite(t.Context(), InviteInput{
		AccountID: account.ID, Email: local, Role: RoleMember, InvitedBy: owner,
	})
	if err != nil {
		t.Fatalf("Invite: %v", err)
	}
	if invited.Invitation.Email != users.NormalizeEmail(local) {
		t.Errorf("stored email = %q, want the normalized %q", invited.Invitation.Email, users.NormalizeEmail(local))
	}

	_, err = h.svc.Invite(t.Context(), InviteInput{
		AccountID: account.ID, Email: strings.ToUpper(local), Role: RoleMember, InvitedBy: owner,
	})
	if !errors.Is(err, ErrInvitationEmailTaken) {
		t.Errorf("a second invitation to the same address in a different case = %v, want ErrInvitationEmailTaken", err)
	}
}

// An admin may invite a member; only an owner may invite an admin. It is the one
// asymmetry in the invite path, and it is why Invite resolves the inviter's own
// membership rather than trusting the middleware to have checked it.
func TestOnlyAnOwnerMayInviteAnAdmin(t *testing.T) {
	h := newHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, "Hierarchy", owner)
	admin := h.member(t, account.ID, RoleAdmin)
	member := h.member(t, account.ID, RoleMember)

	if _, err := h.svc.Invite(t.Context(), InviteInput{
		AccountID: account.ID, Email: dbtest.UniqueEmail(t), Role: RoleMember, InvitedBy: admin,
	}); err != nil {
		t.Errorf("an admin inviting a member = %v, want success", err)
	}
	if _, err := h.svc.Invite(t.Context(), InviteInput{
		AccountID: account.ID, Email: dbtest.UniqueEmail(t), Role: RoleMember, InvitedBy: member,
	}); !errors.Is(err, ErrOwnerProtected) {
		t.Errorf("a member inviting anybody = %v, want ErrOwnerProtected", err)
	}

	// An admin inviting an admin: refused. The privilege has to be granted by
	// somebody who already holds it, or an admin can clone themselves.
	_, err := h.svc.Invite(t.Context(), InviteInput{
		AccountID: account.ID, Email: dbtest.UniqueEmail(t), Role: RoleAdmin, InvitedBy: admin,
	})
	if !errors.Is(err, ErrRoleNotInvitable) {
		t.Errorf("an admin inviting an admin = %v, want ErrRoleNotInvitable", err)
	}

	if _, err := h.svc.Invite(t.Context(), InviteInput{
		AccountID: account.ID, Email: dbtest.UniqueEmail(t), Role: RoleAdmin, InvitedBy: owner,
	}); err != nil {
		t.Errorf("an owner inviting an admin = %v, want success", err)
	}
}

// Even the owner cannot invite an owner. Ownership is granted, not carried by a
// link: an account whose owner arrives by accepting a forwarded email has an
// owner nobody chose.
func TestInviteRefusesTheOwnerRole(t *testing.T) {
	h := newHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, "No Owner Invites", owner)

	if _, err := h.svc.Invite(t.Context(), InviteInput{
		AccountID: account.ID, Email: dbtest.UniqueEmail(t), Role: RoleOwner, InvitedBy: owner,
	}); !errors.Is(err, ErrRoleNotInvitable) {
		t.Errorf("inviting the owner role = %v, want ErrRoleNotInvitable", err)
	}
}

func TestInviteRoleParsesTheRequestString(t *testing.T) {
	h := newHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, "Strings", owner)

	// The string form, which is what a request body carries, has to go through
	// the same rules as the typed one.
	_, err := h.svc.InviteRole(t.Context(), account.ID, dbtest.UniqueEmail(t), "owner", owner)
	if !errors.Is(err, ErrRoleNotInvitable) {
		t.Errorf("InviteRole(\"owner\") = %v, want ErrRoleNotInvitable", err)
	}
	_, err = h.svc.InviteRole(t.Context(), account.ID, dbtest.UniqueEmail(t), "superuser", owner)
	var fe *FieldError
	if !errors.As(err, &fe) || fe.Field != "role" || fe.Code != CodeUnknownRole {
		t.Errorf("InviteRole(\"superuser\") = %v, want a role/unknown_role field error", err)
	}
	if _, err := h.svc.InviteRole(t.Context(), account.ID, dbtest.UniqueEmail(t), "admin", owner); err != nil {
		t.Errorf("InviteRole(\"admin\") = %v, want success", err)
	}
}

func TestInviteRejectsABadEmail(t *testing.T) {
	h := newHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, "Addresses", owner)

	tests := []struct{ name, email, code string }{
		{name: "empty", email: "", code: CodeRequired},
		{name: "not an address", email: "not an address", code: CodeInvalidFormat},
		{name: "no domain", email: "kaka@", code: CodeInvalidFormat},
		{name: "over the limit", email: strings.Repeat("a", users.MaxEmailLength) + "@example.com", code: CodeTooLong},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := h.svc.Invite(t.Context(), InviteInput{
				AccountID: account.ID, Email: tt.email, Role: RoleMember, InvitedBy: owner,
			})
			var fe *FieldError
			if !errors.As(err, &fe) {
				t.Fatalf("Invite(%q) error is %T, want *FieldError", tt.email, err)
			}
			if fe.Field != "email" || fe.Code != tt.code {
				t.Errorf("Invite(%q) = %s/%s, want email/%s", tt.email, fe.Field, fe.Code, tt.code)
			}
		})
	}
}

// The last-owner protection, in every shape. An account with no owner has nobody
// who can administer it and every later request to it fails forever, so this is
// the invariant most worth pinning.
func TestLastOwnerProtection(t *testing.T) {
	t.Run("the only owner cannot demote themselves", func(t *testing.T) {
		h := newHarness(t)
		owner := addUser(t, h.q)
		account := h.owned(t, "Sole Owner", owner)
		h.member(t, account.ID, RoleMember)

		_, err := h.svc.ChangeRole(t.Context(), ChangeRoleInput{
			AccountID: account.ID, UserID: owner, Role: RoleMember, Actor: owner,
		})
		if !errors.Is(err, ErrSelfRoleChange) {
			t.Errorf("demoting the only owner = %v, want ErrSelfRoleChange", err)
		}
		assertRole(t, h, account.ID, owner, RoleOwner)
	})

	t.Run("the only owner cannot be removed", func(t *testing.T) {
		h := newHarness(t)
		owner := addUser(t, h.q)
		account := h.owned(t, "Undeletable Owner", owner)

		err := h.svc.RemoveMember(t.Context(), RemoveMemberInput{
			AccountID: account.ID, UserID: owner, Actor: owner,
		})
		if !errors.Is(err, ErrLastOwner) {
			t.Errorf("removing the only owner = %v, want ErrLastOwner", err)
		}
		assertRole(t, h, account.ID, owner, RoleOwner)
	})

	t.Run("one of two owners may step down", func(t *testing.T) {
		h := newHarness(t)
		first := addUser(t, h.q)
		account := h.owned(t, "Two Owners", first)
		second := h.member(t, account.ID, RoleOwner)

		updated, err := h.svc.ChangeRole(t.Context(), ChangeRoleInput{
			AccountID: account.ID, UserID: first, Role: RoleAdmin, Actor: first,
		})
		if err != nil {
			t.Fatalf("one of two owners stepping down: %v", err)
		}
		if updated.Role != RoleAdmin {
			t.Errorf("role = %q, want %q", updated.Role, RoleAdmin)
		}
		assertRole(t, h, account.ID, second, RoleOwner)
	})

	t.Run("a member can be promoted to owner, which adds one", func(t *testing.T) {
		h := newHarness(t)
		owner := addUser(t, h.q)
		account := h.owned(t, "Promotion", owner)
		successor := h.member(t, account.ID, RoleAdmin)

		if _, err := h.svc.ChangeRole(t.Context(), ChangeRoleInput{
			AccountID: account.ID, UserID: successor, Role: RoleOwner, Actor: owner,
		}); err != nil {
			t.Fatalf("promoting to owner: %v", err)
		}
		// Now the original owner may step down: the account has two.
		if _, err := h.svc.ChangeRole(t.Context(), ChangeRoleInput{
			AccountID: account.ID, UserID: owner, Role: RoleMember, Actor: successor,
		}); err != nil {
			t.Fatalf("the first owner stepping down: %v", err)
		}
		assertRole(t, h, account.ID, successor, RoleOwner)
	})
}

// An admin may remove members and other admins. The owner's membership is a
// different object: only an owner touches it, and only while another remains.
func TestRemoveMemberThroughTheService(t *testing.T) {
	h := newHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, "Departures", owner)
	admin := h.member(t, account.ID, RoleAdmin)
	target := h.member(t, account.ID, RoleMember)

	// An admin removing a member: allowed.
	if err := h.svc.RemoveMember(t.Context(), RemoveMemberInput{
		AccountID: account.ID, UserID: target, Actor: admin,
	}); err != nil {
		t.Errorf("an admin removing a member = %v, want success", err)
	}
	if _, err := h.svc.Member(t.Context(), account.ID, target); !errors.Is(err, ErrNotAMember) {
		t.Errorf("the member survived removal: %v", err)
	}

	// An admin removing the owner: refused, and the owner stays.
	err := h.svc.RemoveMember(t.Context(), RemoveMemberInput{
		AccountID: account.ID, UserID: owner, Actor: admin,
	})
	if !errors.Is(err, ErrOwnerProtected) {
		t.Errorf("an admin removing the owner = %v, want ErrOwnerProtected", err)
	}
	assertRole(t, h, account.ID, owner, RoleOwner)

	// An owner removing a non-owner: allowed, even when that owner is the last.
	if err := h.svc.RemoveMember(t.Context(), RemoveMemberInput{
		AccountID: account.ID, UserID: admin, Actor: owner,
	}); err != nil {
		t.Errorf("an owner removing an admin = %v, want success", err)
	}
}

// TestRemoveMemberRevokesTheCredentialsTheyHeld is the rule this package exists to
// enforce on behalf of another one, and it is worth its own test here rather than
// only in internal/apikeys because THE USE CASE IS WHERE THE DECISION LIVES.
//
// THE STORY IT TELLS IS AN OFFBOARDING. A user is removed from an account, which
// stops every machine credential they hold in it — and the second half is the one
// that is easy to miss: the credential must not come BACK when the same person is
// re-invited. A token whose authority is only re-evaluated would satisfy the
// membership join again the moment a new row existed, and a contractor's CI
// credential that was supposed to have died at offboarding would quietly start
// working the day somebody re-adds them. So the removal revokes, explicitly, in the
// same transaction.
//
// It is the same transaction on purpose. A membership deleted and a credential
// left live is a state neither is defensible on its own: the operator believes both
// happened or neither did.
func TestRemoveMemberRevokesTheCredentialsTheyHeld(t *testing.T) {
	h := newHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, "Departures", owner)
	target := h.member(t, account.ID, RoleMember)

	if err := h.svc.RemoveMember(t.Context(), RemoveMemberInput{
		AccountID: account.ID, UserID: target, Actor: owner,
	}); err != nil {
		t.Fatalf("removing: %v", err)
	}

	if h.revokes.count() != 1 {
		t.Fatalf("the removal swept credentials %d times, want 1", h.revokes.count())
	}
	got := h.revokes.calls[0]
	if got.accountID != account.ID {
		t.Errorf("the sweep was scoped to account %s, want %s", got.accountID, account.ID)
	}
	if got.userID != target {
		t.Errorf("the sweep was scoped to user %s, want the member who was removed %s", got.userID, target)
	}
	// The same instant the removal and the event carry, so "when was this
	// credential withdrawn" and "when was this person removed" have one answer.
	if !got.at.Equal(h.clock.Now()) {
		t.Errorf("the sweep ran at %s, want the service clock's %s", got.at, h.clock.Now())
	}

	// A REFUSED removal sweeps nothing. An admin who cannot remove the owner must
	// not leave that owner's credentials revoked on the way to being told no — a
	// sweep outside the transaction's success path is a partial write.
	before := h.revokes.count()
	if err := h.svc.RemoveMember(t.Context(), RemoveMemberInput{
		AccountID: account.ID, UserID: owner, Actor: h.member(t, account.ID, RoleAdmin),
	}); !errors.Is(err, ErrOwnerProtected) {
		t.Fatalf("an admin removing the owner = %v, want ErrOwnerProtected", err)
	}
	if h.revokes.count() != before {
		t.Error("a refused removal swept credentials anyway")
	}
}

// TestARemovalThatCannotSweepRollsBack is the other direction of the same
// transaction, and it is the one that would be a real incident: the membership is
// gone and the credentials are live, or the reverse. A revoker that fails must take
// the whole removal with it.
func TestARemovalThatCannotSweepRollsBack(t *testing.T) {
	h := newHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, "Departures", owner)
	target := h.member(t, account.ID, RoleMember)

	h.revokes.failWith = errors.New("the api_keys table is not reachable")
	if err := h.svc.RemoveMember(t.Context(), RemoveMemberInput{
		AccountID: account.ID, UserID: target, Actor: owner,
	}); err == nil {
		t.Fatal("a removal succeeded with a revoker that failed")
	}

	// The membership is back, and the event was not written: both writes were inside
	// the transaction the sweep's failure rolled back.
	if _, err := h.svc.Member(t.Context(), account.ID, target); err != nil {
		t.Errorf("the membership was removed even though the sweep failed: %v", err)
	}
	for _, e := range h.events.appended {
		if e.Type == outbox.EventMemberRemoved {
			t.Error("identity.member.removed was announced for a removal that rolled back")
		}
	}
}

// TestARemovalWithNoRevokerStillRemovesTheMembership: the sweep may be nil — a
// deployment with no api key table has no credentials to revoke — and the
// membership change must still happen. Refusing to offboard anybody because a
// table that does not exist is not available would be a availability bug dressed up
// as a safety one.
func TestARemovalWithNoRevokerStillRemovesTheMembership(t *testing.T) {
	h := newHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, "Departures", owner)
	target := h.member(t, account.ID, RoleMember)

	// A service with no revoker, built the production way with a nil.
	withoutSweep := NewService(
		db.TxRunner{Pool: h.q.(db.Pool)},
		h.store,
		h.events,
		nil,
		h.clock,
		db.Direct{Pool: h.q.(db.Pool)},
	)
	if err := withoutSweep.RemoveMember(t.Context(), RemoveMemberInput{
		AccountID: account.ID, UserID: target, Actor: owner,
	}); err != nil {
		t.Fatalf("removing with no revoker wired: %v", err)
	}
	if _, err := withoutSweep.Member(t.Context(), account.ID, target); !errors.Is(err, ErrNotAMember) {
		t.Errorf("the membership survived a removal with no revoker: %v", err)
	}
}

func TestRemoveMemberMisses(t *testing.T) {
	h := newHarness(t)
	owner := addUser(t, h.q)
	stranger := addUser(t, h.q)
	account := h.owned(t, "Misses", owner)

	if err := h.svc.RemoveMember(t.Context(), RemoveMemberInput{
		AccountID: account.ID, UserID: stranger, Actor: owner,
	}); !errors.Is(err, ErrNotAMember) {
		t.Errorf("removing a non-member = %v, want ErrNotAMember", err)
	}
}

// core's catalog: "data carries old and new role". A consumer that only learns
// the new role cannot revoke what it previously granted, and one that only
// learns the old one cannot rebuild the current state.
func TestChangeRoleEmitsBothRoles(t *testing.T) {
	h := newHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, "Promotions", owner)
	target := h.member(t, account.ID, RoleMember)

	if _, err := h.svc.ChangeRole(t.Context(), ChangeRoleInput{
		AccountID: account.ID, UserID: target, Role: RoleAdmin, Actor: owner,
	}); err != nil {
		t.Fatalf("ChangeRole: %v", err)
	}

	e := h.events.payloadFor(t, outbox.EventMemberRoleChanged)
	if want := account.ID.String(); e.Subject != want {
		t.Errorf("subject = %q, want the account id %q", e.Subject, want)
	}
	for _, want := range []string{`"previous_role":"member"`, `"role":"admin"`} {
		if !strings.Contains(string(e.Data), want) {
			t.Errorf("the payload %s does not contain %s", e.Data, want)
		}
	}
}

func TestRemoveMemberEmitsTheRoleTheyHeld(t *testing.T) {
	h := newHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, "Emitting", owner)
	target := h.member(t, account.ID, RoleAdmin)

	if err := h.svc.RemoveMember(t.Context(), RemoveMemberInput{
		AccountID: account.ID, UserID: target, Actor: owner,
	}); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}

	e := h.events.payloadFor(t, outbox.EventMemberRemoved)
	if !strings.Contains(string(e.Data), `"role":"admin"`) {
		t.Errorf("the payload %s does not carry the role they held", e.Data)
	}
	if want := account.ID.String(); e.Subject != want {
		t.Errorf("subject = %q, want the account id %q", e.Subject, want)
	}
}

func TestRenameGoesThroughTheService(t *testing.T) {
	h := newHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, "Before", owner)

	renamed, err := h.svc.Rename(t.Context(), account.ID, "After")
	if err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if renamed.Name != "After" {
		t.Errorf("name = %q, want %q", renamed.Name, "After")
	}
	// The slug does not move: it is a handle that goes into logs, emails and a
	// future hostname, and one that moved would break every link already sent.
	if renamed.Slug != account.Slug {
		t.Errorf("slug = %q, want the original %q", renamed.Slug, account.Slug)
	}

	if _, err := h.svc.Rename(t.Context(), account.ID, "   "); err == nil {
		t.Error("renaming to whitespace succeeded; it should be a 422")
	}
}

func TestDelete(t *testing.T) {
	h := newHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, "Temporary", owner)
	h.member(t, account.ID, RoleMember)

	if err := h.svc.Delete(t.Context(), account.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := h.svc.Account(t.Context(), account.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("the account survived deletion: %v", err)
	}
	if err := h.svc.Delete(t.Context(), account.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting twice = %v, want ErrNotFound", err)
	}
}

// Provision and AddOwner do not open their own transactions: they run
// inside the registration's, which is the whole point of the packet's "same
// transaction" requirement.
func TestProvision(t *testing.T) {
	h := newHarness(t)
	email := dbtest.UniqueEmail(t)
	userID := addUserWithEmail(t, h.q, email)

	var account Account
	var membership Membership
	runner := db.TxRunner{Pool: h.q.(db.Pool)}

	err := runner.Do(t.Context(), func(ctx context.Context, tx db.Querier) error {
		created, err := h.svc.Provision(ctx, tx, userID, email)
		if err != nil {
			return err
		}
		account = created

		m, err := h.svc.AddOwner(ctx, tx, created.ID, userID)
		if err != nil {
			return err
		}
		membership = m
		return nil
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	if !account.Personal {
		t.Error("Provision made a team account")
	}
	if want := PersonalName(email); account.Name != want {
		t.Errorf("name = %q, want the email local part %q", account.Name, want)
	}
	if want := PersonalSlug(email, userID); account.Slug != want {
		t.Errorf("slug = %q, want %q", account.Slug, want)
	}
	if membership.Role != RoleOwner {
		t.Errorf("the membership's role is %q, want %q", membership.Role, RoleOwner)
	}
	h.events.only(t, outbox.EventAccountCreated)
}

// Two people whose email local parts are the same must both be able to
// register. This is the failure a plain Slugify would have produced: the second
// is a 409 on a table they never knew they were competing for.
func TestTwoPeopleWithTheSameLocalPartBothRegister(t *testing.T) {
	h := newHarness(t)
	runner := db.TxRunner{Pool: h.q.(db.Pool)}

	for i := 0; i < 2; i++ {
		email := "kaka-" + dbtest.UniqueEmail(t)[len("kaka-"):]
		uid := addUserWithEmail(t, h.q, email)
		if err := runner.Do(t.Context(), func(ctx context.Context, tx db.Querier) error {
			created, err := h.svc.Provision(ctx, tx, uid, email)
			if err != nil {
				return err
			}
			_, err = h.svc.AddOwner(ctx, tx, created.ID, uid)
			return err
		}); err != nil {
			t.Fatalf("provisioning a personal account for %s: %v", email, err)
		}
	}

	var personal int
	if err := h.q.QueryRow(t.Context(), `SELECT count(*) FROM accounts WHERE personal`).Scan(&personal); err != nil {
		t.Fatalf("counting: %v", err)
	}
	if personal != 2 {
		t.Errorf("%d personal accounts exist, want 2 — the second registration collided on the slug", personal)
	}
}

// tamper returns token with its last character changed: a well-formed token that
// matches no invitation, which is the closest thing to "a caller who guesses".
func tamper(token string) string {
	if token == "" {
		return "x"
	}
	replacement := byte('a')
	if token[len(token)-1] == 'a' {
		replacement = 'b'
	}
	return token[:len(token)-1] + string(replacement)
}
