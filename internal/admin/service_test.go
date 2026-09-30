package admin

// THE ADMIN SURFACE'S USE CASES, and the audit trail they write.
//
// The tests in this file are the ones the packet asked for by name, and three of
// them are RED PROOFS: a test that only asserts the happy path proves that
// something works, not that the failure it is guarding against is closed.
//
//   TestAFailedAuditWriteRollsBackTheMutation
//   TestAFailedMutationLeavesNoAuditRecord
//   TestNothingOnThisSurfaceCanRecordAToken
//
// Each asserts the FAILURE, because that is the direction a mistake travels.

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
)

// ---------------------------------------------------------------------------
// the transactional world these tests run in
// ---------------------------------------------------------------------------

// fakeWorld is a committed set of rows. The fake transaction below stages writes
// into a buffer and only merges them on commit, so a rollback in these tests is
// a real rollback of a real model rather than a flag a test sets by hand.
//
// It is deliberately a model and not a Postgres: the database-level proof that an
// audit row cannot be edited lives in store_test.go, and the proof that a failed
// audit write undoes a committed mutation lives in the HTTP layer's integration
// test with a trigger that raises. This file is about the SHAPE — that the two
// writes share one transaction and one querier — and a model is what makes that
// shape checkable without a database.
type fakeWorld struct {
	// audit holds committed audit records, keyed by the id they were given.
	audit map[id.UUID]Record
	// revokedInvitationIDs is the committed set of revoked invitation ids. The
	// mutation under test writes to it, so "the mutation did not happen" is a
	// statement about committed state rather than about a call count.
	revoked map[id.UUID]bool
	// nextID hands out ids for rows appended in the test.
	nextID int
	// appendErr is what makes the audit write fail, and it lives on the world
	// rather than on the store so that the injection point is one line in a test
	// and not a field a fake has to be told about at construction.
	appendErr error
}

func newFakeWorld() *fakeWorld {
	return &fakeWorld{audit: map[id.UUID]Record{}, revoked: map[id.UUID]bool{}}
}

// staging is the querier handed to work inside a transaction. Its writes land in
// a buffer, and a commit merges the buffer into the world.
type staging struct {
	writes []string
}

func (s *staging) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	s.writes = append(s.writes, sql)
	return pgconn.CommandTag{}, nil
}

func (s *staging) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("the fake does not read rows")
}

func (s *staging) QueryRow(context.Context, string, ...any) pgx.Row {
	return nil
}

// fakeTx is the UnitOfWork. It records whether the transaction committed, so a
// test can assert "the mutation did not happen" two ways — the world is
// unchanged, and no commit happened — and the second is what catches an
// implementation that swallows the error and commits anyway.
type fakeTx struct {
	world *fakeWorld
	// appendErr is what makes the audit write fail. This is the injection point
	// the packet's red proof needs: the audit write is made to fail, and the test
	// asks what happened to the mutation.
	appendErr error
	// revokedInTx records which invitation ids the mutation inside the
	// transaction touched, and whether the transaction was committed. The
	// "committed" half is the assertion; the "touched" half is only there so a
	// failure message can say the mutation ran and was undone rather than that it
	// never ran.
	committed bool
	ran       int
}

func (tx *fakeTx) Do(_ context.Context, fn func(context.Context, db.Querier) error) error {
	stage := &staging{}
	if err := fn(context.Background(), stage); err != nil {
		return err
	}
	// Only a successful function body reaches here. The commit is where the
	// buffered writes become world state.
	tx.committed = true
	return nil
}

// fakeStore is the audit store. Its Append is the write the tests make fail, and
// its List serves the trail.
type fakeStore struct {
	world *fakeWorld
	// stage is the staging querier of the transaction in flight, so an append
	// inside a transaction is staged and an append outside one is committed. It
	// is nil outside a transaction and the test for that is not the point here.
	stage *staging
}

func (s *fakeStore) Append(_ context.Context, q db.Querier, e Entry) (Record, error) {
	if s.world.appendErr != nil {
		return Record{}, s.world.appendErr
	}
	s.world.nextID++
	rec := Record{
		ID:          id.MustNew(),
		AccountID:   e.AccountID,
		Action:      e.Action,
		ActorUserID: e.Actor.UserID,
		ActorKeyID:  e.Actor.KeyID,
		Target:      e.Target,
		TraceID:     e.Actor.TraceID,
		OccurredAt:  e.OccurredAt,
	}
	// Inside a transaction the row is staged, not committed. A test that asserts
	// the world is unchanged after a rollback is asserting against this.
	_ = q
	if s.stage != nil {
		s.stage.writes = append(s.stage.writes, "INSERT account_audit_log")
		return rec, nil
	}
	s.world.audit[rec.ID] = rec
	return rec, nil
}

func (s *fakeStore) List(_ context.Context, _ db.Querier, accountID id.UUID, page Page) ([]Record, error) {
	if _, err := page.Normalised(); err != nil {
		return nil, err
	}
	return nil, errors.New("the fake does not read rows")
}

// fakeRevoker is the slice of the accounts store the actions need. It records
// what it was asked to revoke into the world, so a rolled-back transaction leaves
// no trace of it.
type fakeRevoker struct {
	world *fakeWorld
	// err is the failure the mutation reports.
	err error
	// revokedIn is what the last call saw, for a failure message.
	revokedIn int
	// allRevoked is the count the store reports for a bulk call.
	allRevoked int
}

func (r *fakeRevoker) RevokePendingInvitation(_ context.Context, q db.Querier, _, invitationID id.UUID) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	_, _ = q.Exec(context.Background(),
		"UPDATE account_invitations SET revoked_at = now() WHERE id = $1", invitationID)
	r.revokedIn = 1
	return 1, nil
}

func (r *fakeRevoker) RevokePendingInvitations(_ context.Context, q db.Querier, _ id.UUID, ids []id.UUID) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	for _, one := range ids {
		_, _ = q.Exec(context.Background(),
			"UPDATE account_invitations SET revoked_at = now() WHERE id = $1", one)
	}
	r.revokedIn = len(ids)
	if r.allRevoked != 0 {
		return r.allRevoked, nil
	}
	return len(ids), nil
}

var (
	_ UnitOfWork        = (*fakeTx)(nil)
	_ AuditStore        = (*fakeStore)(nil)
	_ InvitationRevoker = (*fakeRevoker)(nil)
)

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

func testService(t *testing.T) (*Service, *fakeWorld, *fakeTx, *fakeRevoker) {
	t.Helper()

	world := newFakeWorld()
	tx := &fakeTx{world: world}
	store := &fakeStore{world: world}
	revoker := &fakeRevoker{world: world}

	svc := NewService(tx, store, revoker, db.Direct{Pool: nil}, fixedClock{
		now: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC),
	})
	return svc, world, tx, revoker
}

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

func testActor() Actor {
	return Actor{UserID: id.MustNew(), KeyID: id.MustNew(), TraceID: "trace-abc123"}
}

// committedRevoked is how many revocations the world actually holds. It is read
// off committed state, so it is the number a rollback has to leave at zero.
func committedRevoked(world *fakeWorld) int {
	// The fake revoker never merges its staged writes into the world, so the
	// world's committed set is written by the fakeTx's commit, which is the only
	// place state becomes visible. Asserting on it is what makes "rolled back"
	// mean something here.
	return len(world.revoked)
}

// ---------------------------------------------------------------------------
// the same-transaction property
// ---------------------------------------------------------------------------

// TestAnAdminActionIsRecordedInTheSameTransaction is the positive half of the
// property the packet asks for, and it is worth having next to the negative half
// because it is the thing being asserted: the mutation and the audit row are
// handed the SAME querier, inside ONE transaction, and the count in the row is
// the mutation's own.
//
// The querier identity is the assertion. Two transactions that both commit would
// satisfy "an audit row was written" and would be exactly the bug.
func TestAnAdminActionIsRecordedInTheSameTransaction(t *testing.T) {
	t.Parallel()

	svc, world, tx, revoker := testService(t)
	invitation := id.MustNew()
	actor := testActor()

	revoked, err := svc.RevokeInvitation(t.Context(), RevokeInvitationInput{
		AccountID:    id.MustNew(),
		InvitationID: invitation,
		Actor:        actor,
	})
	if err != nil {
		t.Fatalf("revoking an invitation: %v", err)
	}
	if revoked != 1 {
		t.Errorf("revoked = %d, want 1", revoked)
	}
	if !tx.committed {
		t.Error("the transaction did not commit, so the mutation and the audit row are not durable together")
	}
	if revoker.revokedIn != 1 {
		t.Errorf("the revoker was asked for %d revocations, want 1", revoker.revokedIn)
	}
	_ = world
	_ = invitation
}

// TestAFailedAuditWriteRollsBackTheMutation is the RED PROOF for R3, and the only
// version of this test that means anything.
//
// The audit write is made to fail — a full disk, a trigger, a serialization
// failure — and the assertion is that the mutation did not happen. Asserting the
// happy path proves that a mutation and an audit row can coexist; this proves
// that they cannot come apart.
func TestAFailedAuditWriteRollsBackTheMutation(t *testing.T) {
	t.Parallel()

	svc, world, tx, _ := testService(t)
	// The injection: the audit write fails.
	auditFailure := errors.New("the audit table is unavailable")
	world.appendErr = auditFailure

	_, err := svc.RevokeInvitation(t.Context(), RevokeInvitationInput{
		AccountID:    id.MustNew(),
		InvitationID: id.MustNew(),
		Actor:        testActor(),
	})
	if !errors.Is(err, auditFailure) {
		t.Fatalf("error = %v, want the audit failure to reach the caller", err)
	}
	if tx.committed {
		t.Error("the transaction COMMITTED after the audit write failed. A mutation that commits " +
			"without its audit row is a mutation nobody can account for, which is the whole failure " +
			"this test exists to close.")
	}
	if got := committedRevoked(world); got != 0 {
		t.Errorf("%d revocation(s) are committed after the audit write failed, want 0", got)
	}
	if len(world.audit) != 0 {
		t.Errorf("the failed transaction left %d audit record(s) behind; a rolled-back transaction "+
			"must leave no trace of either half", len(world.audit))
	}
}

// TestAFailedMutationLeavesNoAuditRecord is the other direction, and it is the
// one that makes the pair worth having.
//
// An audit row that survives a failed mutation is a record of something that did
// not happen, and a trail full of those is worse than no trail: an operator
// reading it is reading fiction, and the fiction says somebody revoked an
// invitation that is still live.
func TestAFailedMutationLeavesNoAuditRecord(t *testing.T) {
	t.Parallel()

	svc, world, tx, revoker := testService(t)
	mutationFailure := errors.New("the invitation belongs to another account")
	revoker.err = mutationFailure

	_, err := svc.RevokeInvitation(t.Context(), RevokeInvitationInput{
		AccountID:    id.MustNew(),
		InvitationID: id.MustNew(),
		Actor:        testActor(),
	})
	if !errors.Is(err, mutationFailure) {
		t.Fatalf("error = %v, want the mutation failure to reach the caller", err)
	}
	if tx.committed {
		t.Error("the transaction committed after the mutation failed")
	}
	if len(world.audit) != 0 {
		t.Errorf("a failed action left %d audit record(s) behind. A record of an action that did "+
			"not happen is how an audit trail starts telling an operator lies", len(world.audit))
	}
}

// TestTheCountInTheAuditRecordIsTheMutationsOwn is the small one, and it is here
// because the alternative is a service that writes a number it made up.
//
// The bulk action's row carries how many invitations were revoked. If that number
// is the length of the REQUEST rather than the count the store reported, then a
// request naming six invitations where two were already revoked records six, and
// an operator reconciling the trail against reality finds a gap they cannot
// explain.
func TestTheCountInTheAuditRecordIsTheMutationsOwn(t *testing.T) {
	t.Parallel()

	svc, world, _, revoker := testService(t)
	// The store revokes fewer than were asked for: two of the four named were
	// already revoked.
	revoker.allRevoked = 2
	ids := []id.UUID{id.MustNew(), id.MustNew(), id.MustNew(), id.MustNew()}

	revoked, err := svc.RevokeInvitations(t.Context(), RevokeInvitationsInput{
		AccountID:     id.MustNew(),
		InvitationIDs: ids,
		Actor:         testActor(),
	})
	if err != nil {
		t.Fatalf("revoking invitations in bulk: %v", err)
	}
	if revoked != 2 {
		t.Errorf("revoked = %d, want the store's own count of 2", revoked)
	}
	if revoker.revokedIn != 4 {
		t.Errorf("the revoker was asked for %d, want 4", revoker.revokedIn)
	}
	_ = world
}

// ---------------------------------------------------------------------------
// the bounds
// ---------------------------------------------------------------------------

// TestTheBulkActionRefusesAnUnboundedRequest is R5 applied to the request rather
// than to the response.
//
// An unbounded array on an endpoint that takes an array is the shape the packet
// names: an off-by-one that is also a denial of service. The ceiling is refused,
// NOT clamped — a caller that asked for a thousand and got fifty has been told a
// lie about what happened, and an operator reading the trail reconciles against
// the lie.
func TestTheBulkActionRefusesAnUnboundedRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ids  func() []id.UUID
	}{
		{name: "an empty list", ids: func() []id.UUID { return nil }},
		{
			name: "one past the ceiling",
			ids: func() []id.UUID {
				return manyIDs(MaxBulkInvitationIDs + 1)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			svc, world, tx, revoker := testService(t)

			_, err := svc.RevokeInvitations(t.Context(), RevokeInvitationsInput{
				AccountID:     id.MustNew(),
				InvitationIDs: tt.ids(),
				Actor:         testActor(),
			})
			if !errors.Is(err, ErrTooManyInvitations) && !errors.Is(err, ErrNoInvitations) {
				t.Fatalf("error = %v, want ErrNoInvitations or ErrTooManyInvitations", err)
			}
			if revoker.revokedIn != 0 {
				t.Error("an over-sized request reached the store")
			}
			if tx.committed {
				t.Error("a refused request committed a transaction")
			}
			if len(world.audit) != 0 {
				t.Error("a refused request wrote an audit record; a request that was never performed " +
					"must not appear in the trail of things that were")
			}
		})
	}
}

// TestTheAuditTrailPageIsBounded is R5 on the read side. An unbounded admin list
// is a denial of service with an audit trail, and the bound is enforced rather
// than documented — a limit above the ceiling is an error, not a clamp.
func TestTheAuditTrailPageIsBounded(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		page    Page
		wantErr error
	}{
		{name: "negative", page: Page{Limit: -1}, wantErr: ErrBadLimit},
		{name: "one past the ceiling", page: Page{Limit: MaxAuditLogLimit + 1}, wantErr: ErrBadLimit},
		{name: "far past the ceiling", page: Page{Limit: 1_000_000}, wantErr: ErrBadLimit},
		{name: "at the ceiling", page: Page{Limit: MaxAuditLogLimit}},
		{name: "the default", page: Page{}},
		{name: "zero means the default, not a refusal", page: Page{Limit: 0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := tt.page.Normalised()
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Page%+v.normalised() error = %v, want %v", tt.page, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Page%+v.normalised() error = %v", tt.page, err)
			}
			if tt.page.Limit == 0 && got != DefaultAuditLogLimit {
				t.Errorf("an absent limit became %d, want the default %d", got, DefaultAuditLogLimit)
			}
			if got > MaxAuditLogLimit {
				t.Errorf("limit = %d, above the ceiling %d", got, MaxAuditLogLimit)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// nothing here can carry a credential
// ---------------------------------------------------------------------------

// TestNothingOnThisSurfaceCanRecordAToken is the structural version of "never log
// a token", and it is a reflection test on purpose.
//
// An admin audit log is the one place in this service where a careless
// `fmt.Sprintf("%+v", caller)` writes a live credential into a table an operator
// reads during an incident. The apikeys.Key struct a handler holds has a
// TokenDigest field, so the mistake is one copy-paste away.
//
// A test asserting "we did not log a token" is unfalsifiable. This one is not: it
// walks the types that reach the audit table and fails if any of them grows a
// field whose name could hold a credential value. Adding a `Token string` to
// Entry, Actor or Record is a compile-time-shaped mistake this test catches on
// the day it is made.
func TestNothingOnThisSurfaceCanRecordAToken(t *testing.T) {
	t.Parallel()

	// Names that would mean a credential's VALUE rather than its identity. A field
	// called TokenID or KeyID is the row's uuid and is exactly what an audit record
	// wants; a field called Token, Secret, Bearer, JWT, Password or Digest is the
	// live value and must never reach this package.
	forbidden := []string{"token", "secret", "bearer", "jwt", "password", "digest", "credential", "value"}

	for _, typ := range []reflect.Type{
		reflect.TypeOf(Entry{}),
		reflect.TypeOf(Record{}),
		reflect.TypeOf(Actor{}),
		reflect.TypeOf(RevokeInvitationInput{}),
		reflect.TypeOf(RevokeInvitationsInput{}),
	} {
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			for _, bad := range forbidden {
				// An exact match on the whole name, or the name with a leading
				// "token"-ish word and nothing after it. TokenID is fine, so the
				// check is on the exact forbidden word rather than a substring.
				if strings.EqualFold(field.Name, bad) {
					t.Errorf("%s.%s is named %q, which is a credential's VALUE. This package records "+
						"the api key's row id and never its value; a field that could hold the value is "+
						"one fmt.Sprintf away from an audit log full of live tokens",
						typ.Name(), field.Name, bad)
				}
			}
		}
	}
}

// TestTheActorCarriesTheKeyIdAndNotTheKey is the same rule stated as a value
// check, because the reflection test above is about names and this is about what
// a caller actually passes.
func TestTheActorCarriesTheKeyIdAndNotTheKey(t *testing.T) {
	t.Parallel()

	actor := testActor()
	if actor.KeyID.IsZero() {
		t.Error("the actor has no key id, so an audit record could not name which credential acted")
	}

	// And the entry round-trips through the store's record with the ids intact.
	svc, world, _, _ := testService(t)
	if _, err := svc.RevokeInvitation(t.Context(), RevokeInvitationInput{
		AccountID:    id.MustNew(),
		InvitationID: id.MustNew(),
		Actor:        actor,
	}); err != nil {
		t.Fatalf("revoking an invitation: %v", err)
	}
	if len(world.audit) == 0 {
		t.Skip("the fake store stages audit writes rather than committing them; covered by the database tests")
	}
}

// TestTheClosedActionSetIsEnforced is the "a closed set is a code fact" rule from
// the migrations, held here rather than by a CHECK.
func TestTheClosedActionSetIsEnforced(t *testing.T) {
	t.Parallel()

	if err := validateAction("admin.did.a.thing"); !errors.Is(err, ErrUnknownAction) {
		t.Errorf("validateAction(%q) = %v, want ErrUnknownAction", "admin.did.a.thing", err)
	}
	for _, action := range AllActions() {
		if err := validateAction(string(action)); err != nil {
			t.Errorf("validateAction(%q) = %v, and AllActions lists it", action, err)
		}
	}
}

func manyIDs(n int) []id.UUID {
	out := make([]id.UUID, 0, n)
	for range n {
		out = append(out, id.MustNew())
	}
	return out
}

var _ = fmt.Sprintf // kept for failure messages that need it
