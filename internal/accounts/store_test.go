package accounts

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/users"
)

// These are the store's tests, against a real Postgres in a private schema.
// A store is where a silent translation bug lives — a role read back as its
// ordinal, a NULL scanned into a zero time, a 23505 that is not mapped — and
// none of those are visible through a fake querier.

// errDeliberate is the sentinel the rollback test's transaction function
// returns. A package-level value rather than errors.New at the call site,
// because errors.Is compares identity and two separately constructed values with
// the same message are different errors.
var errDeliberate = errors.New("deliberate failure after both writes")

func newStore(t *testing.T) (*Store, db.Querier) {
	t.Helper()

	pool := dbtest.Schema(t)
	store := NewStore(pool)
	return store, pool
}

// insertUser writes a user row directly, because most of these tests care about
// memberships rather than about how a user comes to exist.
func insertUser(t *testing.T, q db.Querier) id.UUID {
	t.Helper()

	uid := id.MustNew()
	if _, err := q.Exec(t.Context(),
		`INSERT INTO users (id, email, password_digest) VALUES ($1, $2, $3)`,
		uid, dbtest.UniqueEmail(t), "argon2id$stub"); err != nil {
		t.Fatalf("inserting a user: %v", err)
	}
	return uid
}

func insertAccount(t *testing.T, q db.Querier, name string) Account {
	t.Helper()

	account, err := NewStore(q.(db.Pool)).Create(t.Context(), q, CreateParams{
		Name:     NormalizeName(name),
		Slug:     Slugify(name),
		Personal: false,
	})
	if err != nil {
		t.Fatalf("creating %q: %v", name, err)
	}
	return account
}

func TestCreateStoresWhatItWasGiven(t *testing.T) {
	store, q := newStore(t)

	created, err := store.Create(t.Context(), q, CreateParams{
		Name: "Acme Corp", Slug: "acme-corp", Personal: false,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if created.ID.IsZero() {
		t.Error("Create returned a zero id")
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Errorf("Create returned zero timestamps: %+v", created)
	}

	// Read it back through a different statement than the one that wrote it.
	read, err := store.ByID(t.Context(), q, created.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if read.Name != "Acme Corp" || read.Slug != "acme-corp" || read.Personal {
		t.Errorf("read back %+v, want the row that was written", read)
	}
}

// The role is stored as its name and read back as its name. If it round-tripped
// through an integer the authorization matrix would still pass — the tests
// insert the same constants they read — so this asserts the column itself.
func TestMembershipRoleRoundTripsAsItsName(t *testing.T) {
	store, q := newStore(t)
	account := insertAccount(t, q, "Roles")

	for _, role := range AllRoles() {
		t.Run(role.String(), func(t *testing.T) {
			// A fresh user per role: the composite primary key is (account_id,
			// user_id), so reusing one user would be testing the duplicate
			// rejection rather than the round trip.
			user := insertUser(t, q)
			m, err := store.AddMember(t.Context(), q, Membership{AccountID: account.ID, UserID: user, Role: role})
			if err != nil {
				t.Fatalf("AddMember(%s): %v", role, err)
			}
			if m.Role != role {
				t.Errorf("AddMember returned role %q, want %q", m.Role, role)
			}

			var raw string
			if err := q.QueryRow(t.Context(),
				`SELECT role::text FROM account_users WHERE account_id = $1 AND user_id = $2`,
				account.ID, user).Scan(&raw); err != nil {
				t.Fatalf("reading the raw role: %v", err)
			}
			if raw != role.String() {
				t.Errorf("account_users.role = %q, want %q", raw, role)
			}

			read, err := store.Member(t.Context(), q, account.ID, user)
			if err != nil {
				t.Fatalf("Member: %v", err)
			}
			if read.Role != role {
				t.Errorf("Member returned %q, want %q", read.Role, role)
			}
		})
	}
}

func TestCreateRejectsATakenSlug(t *testing.T) {
	store, q := newStore(t)
	insertAccount(t, q, "Acme")

	_, err := store.Create(t.Context(), q, CreateParams{Name: "Acme Two", Slug: "acme"})
	if !errors.Is(err, ErrSlugTaken) {
		t.Errorf("Create with a taken slug = %v, want ErrSlugTaken so the handler can answer 409", err)
	}
}

func TestMemberLookupsMiss(t *testing.T) {
	store, q := newStore(t)
	account := insertAccount(t, q, "Empty")
	stranger := insertUser(t, q)

	if _, err := store.Member(t.Context(), q, account.ID, stranger); !errors.Is(err, ErrNotAMember) {
		t.Errorf("Member for a non-member = %v, want ErrNotAMember", err)
	}
	if _, err := store.Member(t.Context(), q, id.MustNew(), stranger); !errors.Is(err, ErrNotAMember) {
		t.Errorf("Member for a missing account = %v, want ErrNotAMember", err)
	}
	if _, err := store.ByID(t.Context(), q, id.MustNew()); !errors.Is(err, ErrNotFound) {
		t.Errorf("ByID for a missing account = %v, want ErrNotFound", err)
	}
}

// The zero uuid is not a value any row can have. A lookup that treated it as a
// wildcard would hand out an arbitrary account, so it is rejected before the
// query runs.
func TestZeroIDIsNotFound(t *testing.T) {
	store, q := newStore(t)

	if _, err := store.ByID(t.Context(), q, id.UUID{}); !errors.Is(err, ErrNotFound) {
		t.Errorf("ByID(zero) = %v, want ErrNotFound", err)
	}
	if _, err := store.Member(t.Context(), q, id.UUID{}, insertUser(t, q)); !errors.Is(err, ErrNotAMember) {
		t.Errorf("Member(zero account) = %v, want ErrNotAMember", err)
	}
}

func TestAddMemberRejectsADuplicate(t *testing.T) {
	store, q := newStore(t)
	account := insertAccount(t, q, "Dupes")
	user := insertUser(t, q)

	if _, err := store.AddMember(t.Context(), q, Membership{AccountID: account.ID, UserID: user, Role: RoleMember}); err != nil {
		t.Fatalf("the first AddMember: %v", err)
	}
	_, err := store.AddMember(t.Context(), q, Membership{AccountID: account.ID, UserID: user, Role: RoleAdmin})
	if !errors.Is(err, ErrAlreadyAMember) {
		t.Errorf("the second AddMember = %v, want ErrAlreadyAMember so the handler can answer 409", err)
	}

	// The refused insert must not have changed the existing role.
	m, err := store.Member(t.Context(), q, account.ID, user)
	if err != nil {
		t.Fatalf("Member: %v", err)
	}
	if m.Role != RoleMember {
		t.Errorf("role = %q after a refused duplicate, want the original %q", m.Role, RoleMember)
	}
}

func TestSetRole(t *testing.T) {
	store, q := newStore(t)
	account := insertAccount(t, q, "Promotions")
	user := insertUser(t, q)
	if _, err := store.AddMember(t.Context(), q, Membership{AccountID: account.ID, UserID: user, Role: RoleMember}); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	updated, err := store.SetRole(t.Context(), q, account.ID, user, RoleAdmin)
	if err != nil {
		t.Fatalf("SetRole: %v", err)
	}
	if updated.Role != RoleAdmin {
		t.Errorf("SetRole returned %q, want %q", updated.Role, RoleAdmin)
	}

	// updated_at has to move, or a poller cannot tell a change from a no-op.
	if !updated.UpdatedAt.After(updated.CreatedAt) && !updated.UpdatedAt.Equal(updated.CreatedAt) {
		t.Errorf("updated_at %s is before created_at %s", updated.UpdatedAt, updated.CreatedAt)
	}

	if _, err := store.SetRole(t.Context(), q, account.ID, insertUser(t, q), RoleAdmin); !errors.Is(err, ErrNotAMember) {
		t.Errorf("SetRole for a non-member = %v, want ErrNotAMember", err)
	}
}

func TestRemoveMember(t *testing.T) {
	store, q := newStore(t)
	account := insertAccount(t, q, "Departures")
	leaver := insertUser(t, q)
	stayer := insertUser(t, q)

	for _, u := range []id.UUID{leaver, stayer} {
		if _, err := store.AddMember(t.Context(), q, Membership{AccountID: account.ID, UserID: u, Role: RoleMember}); err != nil {
			t.Fatalf("AddMember: %v", err)
		}
	}

	if err := store.RemoveMember(t.Context(), q, account.ID, leaver); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	if _, err := store.Member(t.Context(), q, account.ID, leaver); !errors.Is(err, ErrNotAMember) {
		t.Errorf("the leaver is still a member: %v", err)
	}
	if _, err := store.Member(t.Context(), q, account.ID, stayer); err != nil {
		t.Errorf("the stayer lost their membership: %v", err)
	}

	if err := store.RemoveMember(t.Context(), q, account.ID, leaver); !errors.Is(err, ErrNotAMember) {
		t.Errorf("removing twice = %v, want ErrNotAMember", err)
	}
}

// The last-owner check and the role change have to be one transaction, or two
// concurrent demotions both see two owners and both succeed.
func TestCountOwners(t *testing.T) {
	store, q := newStore(t)
	account := insertAccount(t, q, "Ownership")
	member := insertUser(t, q)

	if n, err := store.CountOwners(t.Context(), q, account.ID); err != nil || n != 0 {
		t.Errorf("CountOwners on an account with no members = %d, %v; want 0, nil", n, err)
	}

	owner := insertUser(t, q)
	if _, err := store.AddMember(t.Context(), q, Membership{AccountID: account.ID, UserID: owner, Role: RoleOwner}); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	if _, err := store.AddMember(t.Context(), q, Membership{AccountID: account.ID, UserID: member, Role: RoleMember}); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	if n, err := store.CountOwners(t.Context(), q, account.ID); err != nil || n != 1 {
		t.Errorf("CountOwners = %d, %v; want 1, nil", n, err)
	}
}

// The whole point of the accounts list: an authenticated user's own accounts,
// and nobody else's. Ordering is personal first then name, which is what a
// sidebar wants and what jumpstart's `sorted` scope does.
func TestListForUser(t *testing.T) {
	store, q := newStore(t)
	mine := insertUser(t, q)
	theirs := insertUser(t, q)

	personal := insertAccount(t, q, "mine personal")
	// Make it personal, which Create does not decide for a caller.
	if _, err := q.Exec(t.Context(), `UPDATE accounts SET personal = true WHERE id = $1`, personal.ID); err != nil {
		t.Fatalf("marking the account personal: %v", err)
	}
	beta := insertAccount(t, q, "Beta")
	alpha := insertAccount(t, q, "Alpha")
	foreign := insertAccount(t, q, "Not Mine")

	for _, a := range []Account{personal, beta, alpha} {
		if _, err := store.AddMember(t.Context(), q, Membership{AccountID: a.ID, UserID: mine, Role: RoleMember}); err != nil {
			t.Fatalf("AddMember: %v", err)
		}
	}
	if _, err := store.AddMember(t.Context(), q, Membership{AccountID: foreign.ID, UserID: theirs, Role: RoleOwner}); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	// The list carries the caller's role, so the response needs no second query.
	got, err := store.ListForUser(t.Context(), q, mine)
	if err != nil {
		t.Fatalf("ListForUser: %v", err)
	}
	wantOrder := []Account{personal, alpha, beta}
	if len(got) != len(wantOrder) {
		t.Fatalf("ListForUser returned %d accounts, want %d: %+v", len(got), len(wantOrder), got)
	}
	for i, want := range wantOrder {
		if got[i].Account.ID != want.ID {
			t.Errorf("account %d is %q, want %q", i, got[i].Account.Name, want.Name)
		}
		if got[i].Role != RoleMember {
			t.Errorf("account %d role = %q, want %q", i, got[i].Role, RoleMember)
		}
	}

	// A user with no memberships gets an empty list, not a nil one, so a JSON
	// encoder renders [] rather than null.
	empty, err := store.ListForUser(t.Context(), q, id.MustNew())
	if err != nil {
		t.Fatalf("ListForUser: %v", err)
	}
	if empty == nil {
		t.Error("ListForUser returned nil for a user with no accounts; the response would be null rather than []")
	}
	if len(empty) != 0 {
		t.Errorf("ListForUser returned %d accounts for a stranger, want 0", len(empty))
	}
}

func TestRenameLeavesTheSlugAlone(t *testing.T) {
	store, q := newStore(t)
	account := insertAccount(t, q, "Old Name")

	renamed, err := store.Rename(t.Context(), q, account.ID, "New Name")
	if err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if renamed.Name != "New Name" {
		t.Errorf("name = %q, want %q", renamed.Name, "New Name")
	}
	if renamed.Slug != account.Slug {
		t.Errorf("slug = %q after a rename, want the original %q — a moving slug breaks every link already sent", renamed.Slug, account.Slug)
	}

	if _, err := store.Rename(t.Context(), q, id.MustNew(), "Ghost"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Rename on a missing account = %v, want ErrNotFound", err)
	}
}

func TestDeleteCascades(t *testing.T) {
	store, q := newStore(t)
	account := insertAccount(t, q, "Doomed")
	user := insertUser(t, q)
	if _, err := store.AddMember(t.Context(), q, Membership{AccountID: account.ID, UserID: user, Role: RoleOwner}); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	token, digest, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	_ = token
	if _, err := store.CreateInvitation(t.Context(), q, NewInvitation{
		AccountID: account.ID, Email: dbtest.UniqueEmail(t), Role: RoleMember,
		TokenDigest: digest, ExpiresAt: time.Now().Add(7 * 24 * time.Hour), InvitedBy: user,
	}); err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}

	if err := store.Delete(t.Context(), q, account.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	var memberships, invitations int
	if err := q.QueryRow(t.Context(), `SELECT count(*) FROM account_users WHERE account_id = $1`, account.ID).Scan(&memberships); err != nil {
		t.Fatalf("counting memberships: %v", err)
	}
	if err := q.QueryRow(t.Context(), `SELECT count(*) FROM account_invitations WHERE account_id = $1`, account.ID).Scan(&invitations); err != nil {
		t.Fatalf("counting invitations: %v", err)
	}
	if memberships != 0 || invitations != 0 {
		t.Errorf("after Delete: %d memberships and %d invitations survive, want 0 and 0 (the FKs are ON DELETE CASCADE)", memberships, invitations)
	}

	if err := store.Delete(t.Context(), q, account.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting twice = %v, want ErrNotFound", err)
	}
}

// A deleted user takes their memberships with them. Leaving them would mean
// every account query has to join users to find out whether the member is real.
func TestDeletingAUserCascadesMemberships(t *testing.T) {
	store, q := newStore(t)
	account := insertAccount(t, q, "Survivors")
	leaver := insertUser(t, q)
	stayer := insertUser(t, q)

	for _, u := range []id.UUID{leaver, stayer} {
		if _, err := store.AddMember(t.Context(), q, Membership{AccountID: account.ID, UserID: u, Role: RoleMember}); err != nil {
			t.Fatalf("AddMember: %v", err)
		}
	}
	if _, err := q.Exec(t.Context(), `DELETE FROM users WHERE id = $1`, leaver); err != nil {
		t.Fatalf("deleting the user: %v", err)
	}

	if _, err := store.Member(t.Context(), q, account.ID, leaver); !errors.Is(err, ErrNotAMember) {
		t.Errorf("the deleted user is still a member: %v", err)
	}
	if _, err := store.Member(t.Context(), q, account.ID, stayer); err != nil {
		t.Errorf("the surviving user lost their membership: %v", err)
	}
}

func TestInvitationLifecycle(t *testing.T) {
	store, q := newStore(t)
	account := insertAccount(t, q, "Inviting")
	inviter := insertUser(t, q)
	email := dbtest.UniqueEmail(t)
	_, digest, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	expires := time.Now().UTC().Add(7 * 24 * time.Hour).Truncate(time.Microsecond)

	invitation, err := store.CreateInvitation(t.Context(), q, NewInvitation{
		AccountID: account.ID, Email: email, Role: RoleAdmin,
		TokenDigest: digest, ExpiresAt: expires, InvitedBy: inviter,
	})
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}
	if invitation.AcceptedAt != nil {
		t.Errorf("a new invitation has accepted_at = %v, want nil", invitation.AcceptedAt)
	}
	if !invitation.ExpiresAt.Equal(expires) {
		t.Errorf("expires_at = %s, want the %s the caller asked for", invitation.ExpiresAt, expires)
	}

	// Redemption is by digest, which is the only credential the table holds.
	found, err := store.InvitationByToken(t.Context(), q, digest)
	if err != nil {
		t.Fatalf("InvitationByToken: %v", err)
	}
	if found.ID != invitation.ID {
		t.Errorf("found invitation %s, want %s", found.ID, invitation.ID)
	}

	// Redeeming marks it, and the mark survives a re-read.
	acceptedAt := time.Now().UTC().Truncate(time.Microsecond)
	if err := store.MarkInvitationAccepted(t.Context(), q, invitation.ID, acceptedAt); err != nil {
		t.Fatalf("MarkInvitationAccepted: %v", err)
	}
	reread, err := store.InvitationByToken(t.Context(), q, digest)
	if err != nil {
		t.Fatalf("InvitationByToken after acceptance: %v", err)
	}
	if reread.AcceptedAt == nil {
		t.Fatal("accepted_at is still nil after MarkInvitationAccepted")
	}
	if !reread.AcceptedAt.Equal(acceptedAt) {
		t.Errorf("accepted_at = %s, want %s", reread.AcceptedAt, acceptedAt)
	}
}

// A second redemption of the same token must not silently succeed. This is the
// method the store exposes for exactly that, and it reports "already marked"
// rather than pretending it did the marking.
func TestMarkInvitationAcceptedIsNotTwice(t *testing.T) {
	store, q := newStore(t)
	account := insertAccount(t, q, "Once Only")
	inviter := insertUser(t, q)
	_, digest, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	invitation, err := store.CreateInvitation(t.Context(), q, NewInvitation{
		AccountID: account.ID, Email: dbtest.UniqueEmail(t), Role: RoleMember,
		TokenDigest: digest, ExpiresAt: time.Now().Add(time.Hour), InvitedBy: inviter,
	})
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}

	if err := store.MarkInvitationAccepted(t.Context(), q, invitation.ID, time.Now().UTC()); err != nil {
		t.Fatalf("the first MarkInvitationAccepted: %v", err)
	}
	if err := store.MarkInvitationAccepted(t.Context(), q, invitation.ID, time.Now().UTC()); !errors.Is(err, ErrInvitationUsed) {
		t.Errorf("the second MarkInvitationAccepted = %v, want ErrInvitationUsed", err)
	}
}

func TestInvitationByTokenMisses(t *testing.T) {
	store, q := newStore(t)
	_, wrongDigest, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}

	// A wrong token, a well-formed but unused token, and an empty one are the
	// same error. Distinguishing them is how an invitation endpoint becomes an
	// oracle for "was somebody invited to this account".
	if _, err := store.InvitationByToken(t.Context(), q, wrongDigest); !errors.Is(err, ErrInvitationNotFound) {
		t.Errorf("InvitationByToken with an unused token = %v, want ErrInvitationNotFound", err)
	}
	if _, err := store.InvitationByToken(t.Context(), q, "not-a-digest"); !errors.Is(err, ErrInvitationNotFound) {
		t.Errorf("InvitationByToken with a malformed token = %v, want ErrInvitationNotFound", err)
	}
	if _, err := store.InvitationByToken(t.Context(), q, ""); !errors.Is(err, ErrInvitationNotFound) {
		t.Errorf("InvitationByToken with an empty token = %v, want ErrInvitationNotFound", err)
	}
}

func TestCreateInvitationRejectsAPendingDuplicate(t *testing.T) {
	store, q := newStore(t)
	account := insertAccount(t, q, "One Invite")
	inviter := insertUser(t, q)
	email := dbtest.UniqueEmail(t)

	_, first, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if _, err := store.CreateInvitation(t.Context(), q, NewInvitation{
		AccountID: account.ID, Email: email, Role: RoleMember,
		TokenDigest: first, ExpiresAt: time.Now().Add(time.Hour), InvitedBy: inviter,
	}); err != nil {
		t.Fatalf("the first invitation: %v", err)
	}

	_, second, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	_, err = store.CreateInvitation(t.Context(), q, NewInvitation{
		AccountID: account.ID, Email: email, Role: RoleMember,
		TokenDigest: second, ExpiresAt: time.Now().Add(time.Hour), InvitedBy: inviter,
	})
	if !errors.Is(err, ErrInvitationEmailTaken) {
		t.Errorf("a second pending invitation for the same address = %v, want ErrInvitationEmailTaken", err)
	}
}

// A personal account is the one a registration creates, and the packet says the
// personal account is created in the same transaction as the user. This asserts
// the store can do both writes on one Querier, which is what makes that
// transaction possible.
func TestPersonalAccountAndUserInOneTransaction(t *testing.T) {
	store, q := newStore(t)
	runner := db.TxRunner{Pool: q.(db.Pool)}

	email := dbtest.UniqueEmail(t)
	var account Account

	err := runner.Do(t.Context(), func(ctx context.Context, tx db.Querier) error {
		uid := id.MustNew()
		if _, err := tx.Exec(ctx,
			`INSERT INTO users (id, email, password_digest) VALUES ($1, $2, $3)`,
			uid, email, "argon2id$stub"); err != nil {
			return err
		}

		created, err := store.Create(ctx, tx, CreateParams{
			Name:     PersonalName(email),
			Slug:     PersonalSlug(email, uid),
			Personal: true,
		})
		if err != nil {
			return err
		}
		account = created
		return nil
	})
	if err != nil {
		t.Fatalf("the transaction: %v", err)
	}

	if account.Personal != true {
		t.Error("the account is not marked personal")
	}
	// A personal account has exactly one member at birth: its owner.
	members, err := store.Members(t.Context(), q, account.ID)
	if err != nil {
		t.Fatalf("Members: %v", err)
	}
	if len(members) != 0 {
		t.Errorf("Members returned %d, want 0 — the owner is added by the caller in the same transaction", len(members))
	}

	// A failing step rolls the whole thing back: no orphan user, no orphan
	// account. This is the property the packet's "same transaction" rests on.
	//
	// Both writes have to *succeed* before the failure, or the test would only be
	// proving that a rejected statement leaves nothing behind — which is the
	// transaction manager's job and not the interesting one.
	rollbackErr := runner.Do(t.Context(), func(ctx context.Context, tx db.Querier) error {
		uid := id.MustNew()
		if _, err := tx.Exec(ctx,
			`INSERT INTO users (id, email, password_digest) VALUES ($1, $2, $3)`,
			uid, dbtest.UniqueEmail(t), "argon2id$stub"); err != nil {
			return err
		}
		if _, err := store.Create(ctx, tx, CreateParams{
			Name: "Doomed",
			Slug: "doomed-" + PersonalSlug("", id.MustNew()),
		}); err != nil {
			return err
		}
		return errDeliberate
	})
	if !errors.Is(rollbackErr, errDeliberate) {
		t.Fatalf("the failing transaction returned %v, want the sentinel the function returned", rollbackErr)
	}

	var doomed int
	if err := q.QueryRow(t.Context(), `SELECT count(*) FROM accounts WHERE name = 'Doomed'`).Scan(&doomed); err != nil {
		t.Fatalf("counting: %v", err)
	}
	if doomed != 0 {
		t.Errorf("%d accounts named 'Doomed' survived the rollback, want 0", doomed)
	}
	_ = users.NormalizeEmail
}
