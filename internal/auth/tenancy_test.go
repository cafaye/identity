package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cafaye/identity/internal/accounts"
	"github.com/cafaye/identity/internal/outbox"
	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/sessions"
	"github.com/cafaye/identity/internal/users"
)

// A registration creates a personal account for its user, and the three writes —
// user, account, membership — plus the two events are one transaction.
//
// These are the tests for that. The unit test proves the provisioner is reached
// through the registration's transaction rather than beside it; the integration
// tests prove the writes really are atomic.

// fakeTenancy is an in-memory PersonalAccountProvisioner. It records the querier
// it was handed for the same reason the other doubles do: a test asserting the
// account was written inside the transaction must fail if the code reaches for
// the pool instead.
type fakeTenancy struct {
	provisioned []tenancyCall
	// err is returned by Provision, to exercise a failure in the middle of the
	// registration.
	err error
	// queriersUsed records the querier each call was handed.
	queriersUsed []db.Querier
	// addOwnerErr is returned by AddOwner.
	addOwnerErr error
}

type tenancyCall struct {
	UserID id.UUID
	Email  string
}

func (f *fakeTenancy) Provision(_ context.Context, q db.Querier, userID id.UUID, email string) (accounts.Account, error) {
	f.queriersUsed = append(f.queriersUsed, q)
	f.provisioned = append(f.provisioned, tenancyCall{UserID: userID, Email: email})
	if f.err != nil {
		return accounts.Account{}, f.err
	}
	return accounts.Account{ID: id.MustNew(), Name: accounts.PersonalName(email), Personal: true}, nil
}

func (f *fakeTenancy) AddOwner(_ context.Context, _ db.Querier, _ id.UUID, _ id.UUID) (accounts.Membership, error) {
	if f.addOwnerErr != nil {
		return accounts.Membership{}, f.addOwnerErr
	}
	return accounts.Membership{Role: accounts.RoleOwner}, nil
}

// A new registration provisions exactly one personal account, for the user it
// just created, with that user's normalized address.
func TestRegisterProvisionsAPersonalAccount(t *testing.T) {
	f := newFixture()

	registered, err := f.svc.Register(context.Background(), RegisterInput{
		Email: "  Kaka@Example.com  ", Password: "correct horse battery",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if len(f.tenancy.provisioned) != 1 {
		t.Fatalf("Provision was called %d times, want exactly 1", len(f.tenancy.provisioned))
	}
	call := f.tenancy.provisioned[0]
	if call.UserID != registered.ID {
		t.Errorf("Provision was given user %s, want the user just created, %s", call.UserID, registered.ID)
	}
	if call.Email != "kaka@example.com" {
		t.Errorf("Provision was given %q, want the normalized %q", call.Email, "kaka@example.com")
	}
}

// Inside the transaction, not beside it. A personal account written outside
// would commit or roll back independently of the user, and "a user with no
// account" is a state nothing downstream can repair.
func TestRegisterProvisionsThroughTheTransaction(t *testing.T) {
	f := newFixture()

	if _, err := f.svc.Register(context.Background(), RegisterInput{
		Email: "kaka@example.com", Password: "correct horse battery",
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if len(f.tenancy.queriersUsed) == 0 {
		t.Fatal("Provision was never called")
	}
	for i, q := range f.tenancy.queriersUsed {
		if q != f.uow.querier {
			t.Errorf("call %d used querier %v, want the registration's transaction %v — the personal account is not in the same transaction as the user", i, q, f.uow.querier)
		}
	}
	// And the same transaction wrote the events.
	if len(f.events.queriersUsed) == 0 {
		t.Fatal("no events were appended")
	}
	for i, q := range f.events.queriersUsed {
		if q != f.uow.querier {
			t.Errorf("event %d was appended through %v, want the transaction %v", i, q, f.uow.querier)
		}
	}
}

// A registration that is refused writes no account. The account is created after
// the user, so a failure earlier in the transaction has to stop it being reached
// at all rather than being cleaned up afterwards.
func TestRegisterProvisionsNothingWhenTheRequestIsInvalid(t *testing.T) {
	f := newFixture()

	if _, err := f.svc.Register(context.Background(), RegisterInput{
		Email: "not an address", Password: "correct horse battery",
	}); err == nil {
		t.Fatal("Register accepted a malformed address")
	}
	if len(f.tenancy.provisioned) != 0 {
		t.Errorf("a refused registration provisioned %d accounts, want 0", len(f.tenancy.provisioned))
	}
}

// A failure to provision fails the registration. The alternative — a user who
// exists with no account — is the state the packet's "same transaction" exists
// to prevent, and a service that returns 201 for it has told the client
// something false.
func TestRegisterFailsWhenTheAccountCannotBeProvisioned(t *testing.T) {
	f := newFixture()
	f.tenancy.err = errors.New("the accounts table is unavailable")

	_, err := f.svc.Register(context.Background(), RegisterInput{
		Email: "kaka@example.com", Password: "correct horse battery",
	})
	if err == nil {
		t.Fatal("Register succeeded even though the account could not be provisioned")
	}
	if !errors.Is(err, f.tenancy.err) {
		t.Errorf("Register = %v, want the provisioning failure to be surfaced", err)
	}
}

// A failure to grant ownership fails the registration too, for the same reason:
// an account with no owner cannot be administered by anybody, ever.
func TestRegisterFailsWhenOwnershipCannotBeGranted(t *testing.T) {
	f := newFixture()
	f.tenancy.addOwnerErr = errors.New("the membership write was rejected")

	_, err := f.svc.Register(context.Background(), RegisterInput{
		Email: "kaka@example.com", Password: "correct horse battery",
	})
	if !errors.Is(err, f.tenancy.addOwnerErr) {
		t.Errorf("Register = %v, want the membership failure to be surfaced", err)
	}
}

// failingTenancy provisions for real and then refuses to grant ownership, so a
// test can watch the registration roll back an account it really did write.
type failingTenancy struct {
	inner *accounts.Service
}

func (f *failingTenancy) Provision(ctx context.Context, q db.Querier, userID id.UUID, email string) (accounts.Account, error) {
	return f.inner.Provision(ctx, q, userID, email)
}

func (f *failingTenancy) AddOwner(context.Context, db.Querier, id.UUID, id.UUID) (accounts.Membership, error) {
	return accounts.Membership{}, errors.New("the membership write was rejected")
}

func clockForTest() clock.Clock { return clock.NewFake(start) }

// realTenancy is the production provisioner: the real accounts.Service over the
// real store. It exists in a _test.go file so the wiring in cmd/identity and the
// wiring in a test cannot drift — both are the same three lines.
func realTenancy(pool db.Pool, clk clock.Clock) PersonalAccountProvisioner {
	return accounts.NewService(
		db.TxRunner{Pool: pool},
		accounts.NewStore(pool),
		outbox.NewStore(pool),
		clk,
		db.Direct{Pool: pool},
	)
}

// newServiceWithTenancy builds the service the same way newIntegrationService
// does, with an arbitrary provisioner, so a test can break one link.
func newServiceWithTenancy(t *testing.T, pool *pgxpool.Pool, tenancy PersonalAccountProvisioner) *Service {
	t.Helper()

	return NewService(
		db.TxRunner{Pool: pool},
		db.Direct{Pool: pool},
		users.NewStore(pool),
		sessions.NewStore(pool),
		outbox.NewStore(pool),
		tenancy,
		users.NewHasherWithParams(&argon2id.Params{
			Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
		}),
		clockForTest(),
		24*time.Hour,
	)
}

// ---------------------------------------------------------------------------
// the same thing, over a real database
// ---------------------------------------------------------------------------

// The end-to-end version: a registration over real SQL leaves a user, a personal
// account named after the email's local part, an owner membership, and two
// events — all committed together.
func TestIntegrationRegisterProvisionsTenancyInTheSameTransaction(t *testing.T) {
	svc, pool, _ := newIntegrationService(t)
	ctx := context.Background()
	email := dbtest.UniqueEmail(t)

	registered, err := svc.Register(ctx, RegisterInput{Email: email, Password: "correct horse battery"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	var (
		accountID   id.UUID
		name        string
		personal    bool
		memberRole  string
		accountUser id.UUID
	)
	err = pool.QueryRow(ctx, `
		SELECT a.id, a.name, a.personal, au.role::text, au.user_id
		FROM accounts a
		JOIN account_users au ON au.account_id = a.id
		WHERE au.user_id = $1`, registered.ID).
		Scan(&accountID, &name, &personal, &memberRole, &accountUser)
	if err != nil {
		t.Fatalf("the personal account was not committed: %v", err)
	}

	if !personal {
		t.Error("the account is not marked personal")
	}
	if want := accounts.PersonalName(email); name != want {
		t.Errorf("the account's name is %q, want the email local part %q", name, want)
	}
	if memberRole != string(accounts.RoleOwner) {
		t.Errorf("the membership's role is %q, want %q", memberRole, accounts.RoleOwner)
	}
	if accountUser != registered.ID {
		t.Errorf("the membership belongs to %s, want %s", accountUser, registered.ID)
	}

	// Two events, both committed: the user and the account.
	var types []string
	rows, err := pool.Query(ctx, `SELECT type FROM outbox_events WHERE subject = $1 OR subject = $2 ORDER BY created_at`, registered.ID, accountID)
	if err != nil {
		t.Fatalf("reading the outbox: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var typ string
		if err := rows.Scan(&typ); err != nil {
			t.Fatalf("scanning a type: %v", err)
		}
		types = append(types, typ)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("reading the outbox: %v", err)
	}

	want := map[string]bool{outbox.EventUserCreated: true, outbox.EventAccountCreated: true}
	if len(types) != len(want) {
		t.Fatalf("the registration wrote %v, want exactly %v", types, want)
	}
	for _, typ := range types {
		if !want[typ] {
			t.Errorf("unexpected event %q; want only %v", typ, want)
		}
	}
}

// The atomicity claim, proved by breaking it. A registration whose account write
// fails must leave no user, no account and no event — the half-written state the
// transaction exists to prevent.
func TestIntegrationRegisterRollsBackTenancy(t *testing.T) {
	pool := dbtest.Schema(t)
	ctx := context.Background()
	email := dbtest.UniqueEmail(t)

	// A provisioner that takes no shortcut: it writes the account for real, and
	// then the ownership grant fails. That is the only ordering in which the
	// rollback has something to undo.
	failing := &failingTenancy{inner: accounts.NewService(
		db.TxRunner{Pool: pool},
		accounts.NewStore(pool),
		outbox.NewStore(pool),
		clockForTest(),
		db.Direct{Pool: pool},
	)}
	broken := newServiceWithTenancy(t, pool, failing)

	if _, err := broken.Register(ctx, RegisterInput{Email: email, Password: "correct horse battery"}); err == nil {
		t.Fatal("Register succeeded even though ownership could not be granted")
	}

	if _, err := users.NewStore(pool).ByEmail(ctx, pool, email); !errors.Is(err, users.ErrNotFound) {
		t.Errorf("the user survived: %v — registration is not atomic", err)
	}

	var accountsLeft, events int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM accounts`).Scan(&accountsLeft); err != nil {
		t.Fatalf("counting accounts: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM outbox_events`).Scan(&events); err != nil {
		t.Fatalf("counting events: %v", err)
	}
	if accountsLeft != 0 || events != 0 {
		t.Errorf("a failed registration left %d accounts and %d events, want 0 and 0", accountsLeft, events)
	}
}
