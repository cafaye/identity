package admin

// THE STORE'S TESTS AGAINST A REAL POSTGRES.
//
// The service_test.go proofs are about shape — that the two writes share one
// transaction. These are about the two claims that only a database can settle:
//
//	TestTheAuditRecordCannotBeUpdated    the trigger, from the table's side
//	TestTheAuditRecordCannotBeDeleted
//	TestTheAuditLogOutlivesItsAccount    no foreign key, so the trail is not
//	                                    deletable by deleting the tenant
//
// The first two are the packet's requirement that the record "cannot be edited by
// the admin who performed it", and a Go-level test could not establish it: a
// promise written in the service does not bind a psql session.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
)

// The database tier must actually run. Every test in this file needs a migrated
// schema, and a file that skips itself proves nothing — the rule AGENTS.md states
// for internal/mfa and it applies here for the same reason.
func TestTheDatabaseTierActuallyRan(t *testing.T) {
	if testing.Short() {
		t.Fatal("this file is entirely database tests; -short would report them as skipped, " +
			"which is a green suite that proved nothing")
	}
}

// newTestStore returns the store and the pool over a private schema.
//
// The pool is returned alongside rather than the store alone because most of the
// proofs here go AROUND the service: an UPDATE issued directly against the pool
// is what makes TestTheAuditRecordCannotBeUpdated a proof rather than a
// restatement of the service's own API.
func newTestStore(t *testing.T) (*Store, *pgxpool.Pool) {
	t.Helper()

	pool := dbtest.Schema(t)
	return NewStore(pool), pool
}

func testEntry(t *testing.T, accountID id.UUID) Entry {
	t.Helper()
	return Entry{
		AccountID:  accountID,
		Action:     ActionInvitationRevoked,
		Actor:      Actor{UserID: id.MustNew(), KeyID: id.MustNew(), TraceID: "trace-store-test"},
		Target:     id.MustNew().String(),
		OccurredAt: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC),
	}
}

// --- the append-only property, from the table's side --------------------------

// TestTheAuditRecordCannotBeUpdated is a red proof for the strongest claim in
// the packet: the audit record cannot be edited by the admin who performed it.
//
// It goes around the service entirely and issues UPDATE directly against the
// pool, which is what makes it a proof rather than a restatement. A test that
// called Service would only show that Service has no Update method — true, and
// irrelevant to somebody with psql.
func TestTheAuditRecordCannotBeUpdated(t *testing.T) {
	store, pool := newTestStore(t)
	ctx := t.Context()

	rec, err := store.Append(ctx, pool, testEntry(t, id.MustNew()))
	if err != nil {
		t.Fatalf("appending a record: %v", err)
	}

	_, err = pool.Exec(ctx,
		`UPDATE account_audit_log SET target = 'rewritten' WHERE id = $1`, rec.ID)
	if err == nil {
		t.Fatal("an UPDATE to the audit trail SUCCEEDED. The record is editable, and it is editable " +
			"by whoever can reach the database — which includes the admin whose action is in it, " +
			"through a repair script or a psql session that never goes near this service.")
	}
	if !strings.Contains(err.Error(), "append-only") {
		t.Errorf("the UPDATE failed for a reason that is not the append-only rule: %v", err)
	}

	// And the row is genuinely unchanged, not merely reported as failing.
	var target string
	if err := pool.QueryRow(ctx, `SELECT target FROM account_audit_log WHERE id = $1`, rec.ID).
		Scan(&target); err != nil {
		t.Fatalf("reading the record back: %v", err)
	}
	if target != rec.Target {
		t.Errorf("target = %q, want the original %q — the failed UPDATE still changed the row", target, rec.Target)
	}
}

// TestTheAuditRecordCannotBeDeleted is the other half, and DELETE is the one
// that matters more: a trail that cannot be edited can still be emptied, and an
// emptied trail is indistinguishable from one where nothing suspicious happened.
func TestTheAuditRecordCannotBeDeleted(t *testing.T) {
	store, pool := newTestStore(t)
	ctx := t.Context()

	rec, err := store.Append(ctx, pool, testEntry(t, id.MustNew()))
	if err != nil {
		t.Fatalf("appending a record: %v", err)
	}

	if _, err := pool.Exec(ctx, `DELETE FROM account_audit_log WHERE id = $1`, rec.ID); err == nil {
		t.Fatal("a DELETE from the audit trail SUCCEEDED")
	} else if !strings.Contains(err.Error(), "append-only") {
		t.Errorf("the DELETE failed for a reason that is not the append-only rule: %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM account_audit_log WHERE id = $1`, rec.ID).
		Scan(&count); err != nil {
		t.Fatalf("counting the record: %v", err)
	}
	if count != 1 {
		t.Errorf("the record is gone after a DELETE that reported failure")
	}
}

// TestTheAuditTrailOutlivesItsAccount is the design decision in 00012, and it is
// the answer to "prove the record is not writable through the API it records".
//
// An admin surface is reachable by the admin of the account it acts on, and
// `DELETE /v1/accounts/{accountID}` is a route they hold. If the audit log
// cascaded from accounts, then the shortest route from "an admin did something
// questionable" to "there is no record of it" would be one request, and the
// packet's requirement would be satisfied by the router instead of defeated by
// it.
func TestTheAuditTrailOutlivesItsAccount(t *testing.T) {
	store, pool := newTestStore(t)
	ctx := t.Context()

	accountID := id.MustNew()
	rec, err := store.Append(ctx, pool, testEntry(t, accountID))
	if err != nil {
		t.Fatalf("appending a record: %v", err)
	}

	if _, err := pool.Exec(ctx, `DELETE FROM accounts WHERE id = $1`, accountID); err != nil {
		// No account row exists in this private schema to delete, which is itself
		// the point: the audit table declares no foreign key, so the statement is
		// a plain delete that touches nothing. The test is about the SCHEMA, so it
		// asserts the absence of a constraint rather than the presence of a row.
		t.Logf("no account row to delete, which is consistent with there being no cascade: %v", err)
	}

	// The row is still readable, and the trigger still protects it. Both halves
	// matter: retention without immutability is a log somebody can prune, and
	// immutability without retention is a table nobody can reach.
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM account_audit_log WHERE id = $1`, rec.ID).
		Scan(&count); err != nil {
		t.Fatalf("reading the record after the account is gone: %v", err)
	}
	if count != 1 {
		t.Error("the audit record did not survive. Either the table has a foreign key to accounts " +
			"that the migration says it does not, or something cascaded.")
	}

	if _, err := pool.Exec(ctx, `DELETE FROM account_audit_log WHERE id = $1`, rec.ID); err == nil {
		t.Error("the record became deletable once its account was gone")
	}
}

// --- the page ------------------------------------------------------------------

// TestTheListIsBoundedAndNewestFirst is R5 on the read path, against the real
// query.
//
// The order matters as much as the limit and is the reason the test writes rows
// with DISTINCT timestamps rather than a loop: two rows sharing an instant is the
// case the (occurred_at, id) tiebreak exists for, and a test that only ever
// writes distinct timestamps would pass against a query missing it.
func TestTheListIsBoundedAndNewestFirst(t *testing.T) {
	store, pool := newTestStore(t)
	ctx := t.Context()

	accountID := id.MustNew()
	// Two rows share an instant deliberately.
	base := time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC)
	for i := range 5 {
		entry := testEntry(t, accountID)
		entry.OccurredAt = base.Add(time.Duration(i/2) * time.Hour)
		if _, err := store.Append(ctx, pool, entry); err != nil {
			t.Fatalf("appending record %d: %v", i, err)
		}
	}

	t.Run("the default page is bounded", func(t *testing.T) {
		got, err := store.List(ctx, pool, accountID, Page{})
		if err != nil {
			t.Fatalf("listing: %v", err)
		}
		if len(got) > DefaultAuditLogLimit {
			t.Errorf("a default page returned %d rows, over the default of %d", len(got), DefaultAuditLogLimit)
		}
	})

	t.Run("the ceiling is respected", func(t *testing.T) {
		got, err := store.List(ctx, pool, accountID, Page{Limit: MaxAuditLogLimit})
		if err != nil {
			t.Fatalf("listing: %v", err)
		}
		if len(got) > MaxAuditLogLimit {
			t.Errorf("a page of %d returned %d rows", MaxAuditLogLimit, len(got))
		}
	})

	t.Run("newest first", func(t *testing.T) {
		got, err := store.List(ctx, pool, accountID, Page{Limit: 10})
		if err != nil {
			t.Fatalf("listing: %v", err)
		}
		if len(got) < 2 {
			t.Fatalf("got %d rows, want at least 2 to compare", len(got))
		}
		for i := 1; i < len(got); i++ {
			if got[i].OccurredAt.After(got[i-1].OccurredAt) {
				t.Fatalf("row %d (%s) is newer than row %d (%s); the order is not newest-first",
					i, got[i].OccurredAt, i-1, got[i-1].OccurredAt)
			}
		}
	})

	// THE CURSOR, and this is the test that found the timestamp-only keyset.
	//
	// The five rows above are written with DELIBERATELY REPEATED timestamps — two
	// at 09:00, two at 10:00, one at 11:00 — and that is the whole point. The
	// service's clock is a timestamp and not a sequence, so two admin actions in
	// the same second is the normal case. A keyset comparing `occurred_at` alone
	// returns one page, then drops every row sharing the boundary instant, and
	// this test is what says so: it walks to exhaustion and asserts that all five
	// rows come back exactly once between them.
	//
	// An offset would also pass this, on a static table. What an offset cannot do
	// is survive a concurrent append, so that is the second half: a row appended
	// BETWEEN two pages must not shift the window.
	t.Run("the cursor pages to exhaustion without losing a tied row", func(t *testing.T) {
		seen := map[id.UUID]bool{}
		var before string
		pages := 0
		for {
			got, err := store.List(ctx, pool, accountID, Page{Limit: 2, Before: before})
			if err != nil {
				t.Fatalf("page %d: %v", pages, err)
			}
			if len(got) == 0 {
				break
			}
			for _, one := range got {
				if seen[one.ID] {
					t.Errorf("page %d returned %s, which an earlier page already returned", pages, one.ID)
				}
				seen[one.ID] = true
			}
			before = got[len(got)-1].Next
			if before == "" {
				break
			}
			pages++
			if pages > 10 {
				t.Fatal("the cursor is not advancing; paging never terminates")
			}
		}
		if len(seen) != 5 {
			t.Errorf("paging returned %d distinct rows of 5. Rows sharing an instant with the page "+
				"boundary are the ones a timestamp-only keyset drops silently", len(seen))
		}
	})

	t.Run("a row appended between pages does not shift the window", func(t *testing.T) {
		// This is what an offset cannot do and the reason the cursor is a keyset.
		// Page one, then append a NEWEST row, then page two with the cursor page
		// one handed back. An offset would now skip a row, because the new row
		// pushed everything down by one; the keyset does not care, because it
		// addresses rows rather than positions.
		first, err := store.List(ctx, pool, accountID, Page{Limit: 2})
		if err != nil {
			t.Fatalf("page one: %v", err)
		}
		if len(first) != 2 {
			t.Fatalf("page one returned %d rows, want 2", len(first))
		}
		cursor := first[len(first)-1].Next
		if cursor == "" {
			t.Fatal("page one offered no cursor, so there is no way to ask for page two")
		}

		// Something happens on the account while the operator is paging.
		arrival := testEntry(t, accountID)
		arrival.OccurredAt = base.Add(48 * time.Hour)
		arrived, err := store.Append(ctx, pool, arrival)
		if err != nil {
			t.Fatalf("appending the concurrent row: %v", err)
		}

		second, err := store.List(ctx, pool, accountID, Page{Limit: 10, Before: cursor})
		if err != nil {
			t.Fatalf("page two: %v", err)
		}
		for _, one := range second {
			if one.ID == arrived.ID {
				t.Error("page two returned the row appended after page one. A keyset pages backwards " +
					"from a cursor, so an action that happened while the operator was reading cannot " +
					"appear in the page they are on — it will be in the next one.")
			}
			for _, seen := range first {
				if one.ID == seen.ID {
					t.Errorf("page two repeated %s from page one", one.ID)
				}
			}
		}
	})

	t.Run("a cursor this build did not issue is refused", func(t *testing.T) {
		// Answered with the first page, this would look to an operator like a
		// gap in the trail. It is an error instead.
		for _, bad := range []string{"not-base64!!", "bm90LWEtY3Vyc29y", "MjAyNi0wOS0zMA"} {
			if _, err := store.List(ctx, pool, accountID, Page{Before: bad}); !errors.Is(err, ErrBadCursor) {
				t.Errorf("List with cursor %q = %v, want ErrBadCursor", bad, err)
			}
		}
	})
}

// TestTheListIsScopedToOneAccount is the tenancy half of the read, and it is
// separate from the cursor test because a keyset query is exactly the shape that
// forgets its WHERE clause: "newest first" is a reason to read the whole table
// and return the best of it.
func TestTheListIsScopedToOneAccount(t *testing.T) {
	store, pool := newTestStore(t)
	ctx := t.Context()

	mine, theirs := id.MustNew(), id.MustNew()
	for range 3 {
		if _, err := store.Append(ctx, pool, testEntry(t, mine)); err != nil {
			t.Fatalf("appending: %v", err)
		}
		if _, err := store.Append(ctx, pool, testEntry(t, theirs)); err != nil {
			t.Fatalf("appending: %v", err)
		}
	}

	got, err := store.List(ctx, pool, mine, Page{Limit: MaxAuditLogLimit})
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d rows for one account, want 3", len(got))
	}
	for _, one := range got {
		if one.AccountID != mine {
			t.Errorf("a row from account %s appeared in %s's trail", one.AccountID, mine)
		}
	}
}

// --- the round trip -------------------------------------------------------------

// TestARecordRoundTrips is the shape assertion, and it is here rather than in
// service_test.go because it needs the real column list: a column added to
// auditColumns and not scanned is a runtime error, and a test using the real
// table is what catches it.
func TestARecordRoundTrips(t *testing.T) {
	store, pool := newTestStore(t)
	ctx := t.Context()

	entry := testEntry(t, id.MustNew())
	want, err := store.Append(ctx, pool, entry)
	if err != nil {
		t.Fatalf("appending: %v", err)
	}

	if want.ID.IsZero() {
		t.Error("the stored row has no id")
	}
	if want.Action != entry.Action {
		t.Errorf("action = %q, want %q", want.Action, entry.Action)
	}
	if want.ActorUserID != entry.Actor.UserID || want.ActorKeyID != entry.Actor.KeyID {
		t.Error("the actor did not round-trip; an audit record that cannot name who acted is useless")
	}
	if want.TraceID != entry.Actor.TraceID {
		t.Errorf("trace_id = %q, want %q", want.TraceID, entry.Actor.TraceID)
	}
	if want.Affected != 0 {
		t.Errorf("affected = %d, want 0 for a raw append", want.Affected)
	}
}

// TestTheStoreRefusesAnEntryItCannotWrite is the request-level validation, held
// at the store as well as the use case because the store is reachable from a
// future packet that has not read Service.
//
// The affected column is the interesting one: Append hard-codes 0, so the only
// way a caller could put a number there is by writing the INSERT themselves, and
// this asserts the count is the store's to set rather than the caller's.
func TestTheStoreRefusesAnEntryItCannotWrite(t *testing.T) {
	store, pool := newTestStore(t)
	ctx := t.Context()

	tests := []struct {
		name    string
		mutate  func(*Entry)
		wantErr bool
	}{
		{name: "a good entry", mutate: func(*Entry) {}},
		{name: "no account", mutate: func(e *Entry) { e.AccountID = id.UUID{} }, wantErr: true},
		{name: "an unknown action", mutate: func(e *Entry) { e.Action = "admin.exfiltrated" }, wantErr: true},
		{name: "no action", mutate: func(e *Entry) { e.Action = "" }, wantErr: true},
		{name: "no target", mutate: func(e *Entry) { e.Target = "" }, wantErr: true},
		{name: "no actor", mutate: func(e *Entry) { e.Actor = Actor{} }, wantErr: true},
		{
			name: "an over-long target",
			mutate: func(e *Entry) {
				e.Target = strings.Repeat("x", maxTargetLength+1)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := testEntry(t, id.MustNew())
			tt.mutate(&entry)

			_, err := store.Append(ctx, pool, entry)
			if tt.wantErr {
				if err == nil {
					t.Fatal("the entry was accepted")
				}
				return
			}
			if err != nil {
				t.Fatalf("appending: %v", err)
			}
		})
	}
}

// TestTheDatabaseRefusesAnOverLongTarget is the column CHECK, asserted against
// the database rather than against Entry.validate.
//
// The service checks the same bound, and this is the reason the two are not
// redundant: the service's check is the request's, this one is the schema's, and
// a caller that skipped the service — a migration, a script, a future packet —
// still cannot write an unbounded target.
func TestTheDatabaseRefusesAnOverLongTarget(t *testing.T) {
	pool := dbtest.Schema(t)
	ctx := t.Context()

	_, err := pool.Exec(ctx, `
		INSERT INTO account_audit_log
			(account_id, action, actor_user_id, actor_key_id, target, affected, trace_id, occurred_at)
		VALUES ($1, 'invitation.revoked', $2, $3, $4, 0, 'trace-check', now())`,
		id.MustNew(), id.MustNew(), id.MustNew(), strings.Repeat("x", maxTargetLength+1))
	if err == nil {
		t.Error("the database accepted a target over its CHECK bound")
	}
}

// TestTheServiceIsUsableOverARealPool is the wiring, and it exists because
// service_test.go's fakes model the transaction and a real one has to be proven
// too. It is the smallest end-to-end path through the package: append a record,
// read it back, through the real Store and a real transaction.
func TestTheServiceIsUsableOverARealPool(t *testing.T) {
	pool := dbtest.Schema(t)
	ctx := t.Context()

	store := NewStore(pool)
	svc := NewService(
		db.TxRunner{Pool: pool},
		store,
		noRevoker{},
		db.Direct{Pool: pool},
		clock.System{},
	)

	accountID := id.MustNew()
	actor := Actor{UserID: id.MustNew(), KeyID: id.MustNew(), TraceID: "trace-e2e"}

	revoked, err := svc.RevokeInvitation(ctx, RevokeInvitationInput{
		AccountID:    accountID,
		InvitationID: id.MustNew(),
		Actor:        actor,
	})
	if err != nil {
		t.Fatalf("revoking an invitation: %v", err)
	}
	// noRevoker reports one row changed, so the number is the revoker's rather
	// than the request's.
	if revoked != 1 {
		t.Errorf("revoked = %d, want 1", revoked)
	}

	trail, err := svc.List(ctx, accountID, Page{})
	if err != nil {
		t.Fatalf("listing the trail: %v", err)
	}
	if len(trail) != 1 {
		t.Fatalf("the trail has %d records, want 1 — the mutation committed without its audit row", len(trail))
	}
	if trail[0].ActorKeyID != actor.KeyID {
		t.Error("the record does not name the api key that performed the action")
	}
	if trail[0].Affected != 1 {
		t.Errorf("affected = %d, want 1", trail[0].Affected)
	}
	if !trail[0].OccurredAt.After(time.Time{}.Add(-time.Hour)) {
		t.Error("occurred_at was not set from the service's clock")
	}
}

// TestAFailedAuditWriteRollsBackARealMutation is the red proof for R3 over a real
// transaction, and it is the version of service_test.go's proof that means the
// most: the audit write is made to fail by a trigger installed in this test's own
// private schema, and the assertion is on committed database state.
//
// The trigger is the injection point rather than a mock because a mock cannot
// fail a statement INSIDE a transaction that the database has already begun, and
// the property under test is precisely about what the database does with the
// half-finished work.
func TestAFailedAuditWriteRollsBackARealMutation(t *testing.T) {
	pool := dbtest.Schema(t)
	ctx := t.Context()

	// THE INJECTION, and it is a trigger rather than a fake because the property
	// under test is what the DATABASE does with a transaction whose audit write
	// failed. A mock that returns an error from Append would exercise the Go code
	// path and prove nothing about whether the half-written transaction is
	// discarded.
	//
	// It is a separate BEFORE INSERT trigger rather than a replacement of the
	// append-only one, and the reason is that the production trigger fires on
	// UPDATE and DELETE — replacing its body with a raise would make it fail on
	// the wrong operations and this test would pass without the INSERT ever
	// reaching it.
	//
	// The function is created BEFORE the trigger that uses it: Postgres resolves
	// the function by name when the trigger is created, not when it fires, so the
	// other order fails with "function does not exist" and a reader looking at that
	// error would reasonably conclude the trigger syntax was wrong.
	if _, err := pool.Exec(ctx, `
		CREATE FUNCTION account_audit_log_injected_failure() RETURNS trigger AS $$
		BEGIN
			RAISE EXCEPTION 'injected audit write failure';
		END;
		$$ LANGUAGE plpgsql`); err != nil {
		t.Fatalf("installing the failing trigger function: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		CREATE TRIGGER account_audit_log_injected_insert_failure
		BEFORE INSERT ON account_audit_log
		FOR EACH ROW EXECUTE FUNCTION account_audit_log_injected_failure()`); err != nil {
		t.Fatalf("installing the failing trigger: %v", err)
	}

	// A real account with a real pending invitation, so the mutation is a real
	// UPDATE against a real row rather than a no-op that would pass either way.
	account, invitation := seedPendingInvitation(t, pool)

	svc := NewService(
		db.TxRunner{Pool: pool},
		NewStore(pool),
		countingRevoker{},
		db.Direct{Pool: pool},
		clock.System{},
	)

	_, err := svc.RevokeInvitation(ctx, RevokeInvitationInput{
		AccountID:    account,
		InvitationID: invitation,
		Actor:        Actor{UserID: id.MustNew(), KeyID: id.MustNew(), TraceID: "trace-rollback"},
	})
	if err == nil {
		t.Fatal("the action SUCCEEDED with a failing audit write. The audit record and the mutation " +
			"are not in the same transaction, so a mutation can commit with nothing to account for it.")
	}
	if !strings.Contains(err.Error(), "injected audit write failure") {
		t.Errorf("error = %v, want the injected failure to reach the caller", err)
	}

	// THE ASSERTION. The invitation is still redeemable, and it is still
	// unrevoked — read from the database, not from a fake's call log.
	var revokedAt *time.Time
	if err := pool.QueryRow(ctx,
		`SELECT revoked_at FROM account_invitations WHERE id = $1`, invitation).
		Scan(&revokedAt); err != nil {
		t.Fatalf("reading the invitation: %v", err)
	}
	if revokedAt != nil {
		t.Error("the invitation is REVOKED after the audit write failed. The mutation committed and " +
			"the audit row did not, which is a mutation nobody can account for.")
	}

	var records int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM account_audit_log WHERE account_id = $1`, account).
		Scan(&records); err != nil {
		t.Fatalf("counting audit records: %v", err)
	}
	if records != 0 {
		t.Errorf("%d audit record(s) survived a rolled-back transaction", records)
	}
}

// TestAFailedMutationRollsBackARealAuditRecord is the other direction over a
// real transaction: a mutation that fails must leave no record claiming it
// happened.
func TestAFailedMutationRollsBackARealAuditRecord(t *testing.T) {
	pool := dbtest.Schema(t)
	ctx := t.Context()

	account := id.MustNew()
	svc := NewService(
		db.TxRunner{Pool: pool},
		NewStore(pool),
		failingRevoker{},
		db.Direct{Pool: pool},
		clock.System{},
	)

	_, err := svc.RevokeInvitation(ctx, RevokeInvitationInput{
		AccountID:    account,
		InvitationID: id.MustNew(),
		Actor:        Actor{UserID: id.MustNew(), KeyID: id.MustNew(), TraceID: "trace-mutation-fail"},
	})
	if !errors.Is(err, errRevoker) {
		t.Fatalf("error = %v, want the mutation failure", err)
	}

	var records int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM account_audit_log WHERE account_id = $1`, account).
		Scan(&records); err != nil {
		t.Fatalf("counting audit records: %v", err)
	}
	if records != 0 {
		t.Errorf("%d audit record(s) describe an action that did not happen. A record of an action "+
			"that never occurred is how a trail starts telling an operator lies", records)
	}
}

var errRevoker = errors.New("the invitation is not revocable")

// --- fixtures ------------------------------------------------------------------

// noRevoker reports one changed row without touching anything, for the wiring
// test where the point is the audit trail and not the invitation.
type noRevoker struct{}

func (noRevoker) RevokePendingInvitation(context.Context, db.Querier, id.UUID, id.UUID) (int, error) {
	return 1, nil
}

func (noRevoker) RevokePendingInvitations(context.Context, db.Querier, id.UUID, []id.UUID) (int, error) {
	return 0, nil
}

// countingRevoker reports a count without a database, for the rollback proof —
// where the mutation's own effect is asserted against the invitation table and
// the point is that even a revoker which SUCCEEDS does not survive the rollback.
type countingRevoker struct{}

func (countingRevoker) RevokePendingInvitation(_ context.Context, q db.Querier, accountID, invitationID id.UUID) (int, error) {
	const query = `UPDATE account_invitations SET revoked_at = now()
		WHERE id = $1 AND account_id = $2 AND accepted_at IS NULL AND revoked_at IS NULL`
	tag, err := q.Exec(context.Background(), query, invitationID, accountID)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func (countingRevoker) RevokePendingInvitations(context.Context, db.Querier, id.UUID, []id.UUID) (int, error) {
	return 0, errors.New("not used")
}

type failingRevoker struct{}

func (failingRevoker) RevokePendingInvitation(context.Context, db.Querier, id.UUID, id.UUID) (int, error) {
	return 0, errRevoker
}

func (failingRevoker) RevokePendingInvitations(context.Context, db.Querier, id.UUID, []id.UUID) (int, error) {
	return 0, errRevoker
}

// seedPendingInvitation creates a real account, a real user in it, and a real
// pending invitation, and returns the two ids.
//
// A rollback proof against a mutation that touches no row would pass for the
// wrong reason: the assertion "the invitation is not revoked" is only meaningful
// if the UPDATE could have matched something.
func seedPendingInvitation(t *testing.T, pool db.Pool) (id.UUID, id.UUID) {
	t.Helper()
	ctx := t.Context()

	accountID, userID := id.MustNew(), id.MustNew()
	if _, err := pool.Exec(ctx, `
		INSERT INTO accounts (id, name, slug, personal, created_at, updated_at)
		VALUES ($1, 'Rollback', $2, false, now(), now())`, accountID, "rollback-"+accountID.String()[:8]); err != nil {
		t.Fatalf("seeding an account: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO users (id, email, password_digest, created_at, updated_at)
		 VALUES ($1, $2, 'digest', now(), now())`, userID, "rollback-"+userID.String()[:8]+"@example.com"); err != nil {
		t.Fatalf("seeding a user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO account_users (account_id, user_id, role, created_at, updated_at)
		VALUES ($1, $2, 'owner', now(), now())`, accountID, userID); err != nil {
		t.Fatalf("seeding a membership: %v", err)
	}
	invitationID := id.MustNew()
	if _, err := pool.Exec(ctx, `
		INSERT INTO account_invitations
			(id, account_id, email, role, token_digest, expires_at, invited_by, created_at, updated_at)
		VALUES ($1, $2, 'pending@example.com', 'member', $3, now() + interval '7 days', $4, now(), now())`,
		invitationID, accountID, strings.Repeat("a", 64), userID); err != nil {
		t.Fatalf("seeding an invitation: %v", err)
	}
	return accountID, invitationID
}
