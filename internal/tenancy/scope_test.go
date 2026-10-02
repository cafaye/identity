package tenancy

import (
	"context"
	"errors"
	"testing"

	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
)

// The runtime seam, tested without a database. Every assertion here is about
// WHICH STATEMENTS were issued and in what order — a database can prove the
// identity took effect, and only a fake can prove it was set on this transaction
// and this request rather than somewhere convenient.

func TestAnAccountTravelsOnTheContextAndComesBack(t *testing.T) {
	t.Parallel()

	account := mustNewAccount(t)
	ctx := WithAccount(context.Background(), account)

	got, ok := AccountFrom(ctx)
	if !ok {
		t.Fatal("AccountFrom reported no account on a context carrying one")
	}
	if got != account {
		t.Errorf("AccountFrom = %v, want the account that was put on the context (%v)", got, account)
	}
}

// A request with no account is a legitimate state — a login, and a
// registration's pre-account phase — so it has to be REPORTABLE rather than
// silently reading as a wiring bug or, worse, as an account.
func TestAContextWithNoAccountSaysSo(t *testing.T) {
	t.Parallel()

	for name, ctx := range map[string]context.Context{
		"nothing was put on it": context.Background(),
		"the nil uuid was":      WithAccount(context.Background(), id.UUID{}),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if account, ok := AccountFrom(ctx); ok {
				t.Errorf("AccountFrom = (%v, true), want (zero, false): a request with no account must not read as one", account)
			}
		})
	}
}

// The whole property, in one test: the identity is set on the caller's
// transaction, BEFORE the use case runs, and only when the request has one.
func TestTxRunnerSetsTheIdentityBeforeTheUseCaseRuns(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		account id.UUID
		wantSet bool
	}{
		{name: "a request with an account sets it", account: mustNewAccount(t), wantSet: true},
		{name: "a request with none does not", wantSet: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pool, tx := newRecording()
			runner := TxRunner{TxRunner: db.TxRunner{Pool: pool}}

			ctx := context.Background()
			if !tc.account.IsZero() {
				ctx = WithAccount(ctx, tc.account)
			}

			var sawSet bool
			var sawArgument any
			tx.onExec = func(sql string, args []any) {
				if sql != beginAccountSQL {
					return
				}
				sawSet = true
				if len(args) == 1 {
					sawArgument = args[0]
				}
			}

			ran := false
			err := runner.Do(ctx, func(ctx context.Context, q db.Querier) error {
				ran = true
				// The identity must already be on the transaction by the time the
				// use case can write anything. A seam that set it afterwards would
				// leave every account-scoped INSERT inside the use case's first
				// statements refused with 42501.
				if sawSet != tc.wantSet {
					t.Errorf("inside the use case, begin_account had been issued = %v, want %v", sawSet, tc.wantSet)
				}
				return nil
			})
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			if !ran {
				t.Fatal("Do committed without running the function")
			}

			if sawSet != tc.wantSet {
				t.Fatalf("begin_account was issued = %v, want %v", sawSet, tc.wantSet)
			}
			if tc.wantSet && sawArgument != tc.account {
				t.Errorf("begin_account was called with %v, want the request's account %v", sawArgument, tc.account)
			}
		})
	}
}

// The identity must be set on the TRANSACTION, not on the pool. This is the
// difference between a boundary and a leak: a pool-level set_config with
// is_local => false goes back to the pool carrying tenant A's identity, tenant B
// is handed the connection, and tenant B reads tenant A's rows.
func TestTheIdentityIsSetOnTheTransactionAndNotOnThePool(t *testing.T) {
	t.Parallel()

	pool, tx := newRecording()
	runner := TxRunner{TxRunner: db.TxRunner{Pool: pool}}

	if err := runner.Do(WithAccount(context.Background(), mustNewAccount(t)), func(context.Context, db.Querier) error {
		return nil
	}); err != nil {
		t.Fatalf("Do: %v", err)
	}

	if len(pool.execs) != 0 {
		t.Errorf("the pool received %d statements, want none: begin_account is transaction-local and must "+
			"never be issued on the pool, where it would outlive the request. Statements: %v",
			len(pool.execs), pool.execs)
	}
	if len(tx.execs) != 1 {
		t.Fatalf("the transaction received %d statements, want exactly one (the identity): %v", len(tx.execs), tx.execs)
	}
}

// A failed begin_account must fail the whole transaction. Continuing would mean
// running a use case whose every account-scoped write is about to be refused,
// which surfaces as a 500 with a cause three layers from the mistake.
func TestAFailedIdentityFailsTheTransactionWithoutRunningTheUseCase(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("the GUC would not set")
	pool, tx := newRecording()
	tx.failBeginAccountWith = sentinel
	runner := TxRunner{TxRunner: db.TxRunner{Pool: pool}}

	ran := false
	err := runner.Do(WithAccount(context.Background(), mustNewAccount(t)), func(context.Context, db.Querier) error {
		ran = true
		return nil
	})

	if !errors.Is(err, ErrNoIdentity) {
		t.Errorf("Do returned %v, want something matching ErrNoIdentity, so a caller can tell a refused identity from an absent account", err)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("Do returned %v, want it to wrap the underlying failure too", err)
	}
	if ran {
		t.Error("the use case ran after the identity was refused")
	}
	if !tx.rolledBack {
		t.Error("the transaction was not rolled back after the identity was refused")
	}
	if tx.committed {
		t.Error("the transaction committed after the identity was refused")
	}
}

// A request with no account must not pay for a statement that clears a GUC that
// is already unset. This is on the authentication hot path — every login and
// every session lookup — and a round trip to say nothing is a round trip that
// gets measured and then removed by somebody who does not know why it is there.
func TestARequestWithNoAccountPaysNoRoundTrip(t *testing.T) {
	t.Parallel()

	pool, tx := newRecording()
	runner := TxRunner{TxRunner: db.TxRunner{Pool: pool}}

	if err := runner.Do(context.Background(), func(context.Context, db.Querier) error {
		return nil
	}); err != nil {
		t.Fatalf("Do: %v", err)
	}

	if len(tx.execs) != 0 {
		t.Errorf("the transaction received %d statements, want none for a request with no account: %v",
			len(tx.execs), tx.execs)
	}
}

// An error from the use case is the caller's to keep. The seam wraps only the
// identity call, so a caller matching on its own store's sentinel still matches.
func TestTheSeamDoesNotSwallowTheUseCasesError(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("the store said no")
	pool, tx := newRecording()
	runner := TxRunner{TxRunner: db.TxRunner{Pool: pool}}

	err := runner.Do(WithAccount(context.Background(), mustNewAccount(t)), func(context.Context, db.Querier) error {
		return sentinel
	})

	if !errors.Is(err, sentinel) {
		t.Errorf("Do returned %v, want the use case's own error unwrapped", err)
	}
	if tx.committed {
		t.Error("a transaction whose use case failed was committed")
	}
}

// The nil account is a bug in the caller, not a request with no account. It has
// to be refused where it can be read, rather than left to be discovered as a
// 42501 from the substrate three layers down.
func TestBeginAccountRefusesTheNilAccount(t *testing.T) {
	t.Parallel()

	pool, tx := newRecording()
	err := BeginAccount(context.Background(), pool, id.UUID{})

	if !errors.Is(err, ErrNoIdentity) {
		t.Errorf("BeginAccount with the nil account returned %v, want something matching ErrNoIdentity", err)
	}
	if len(pool.execs)+len(tx.execs) != 0 {
		t.Errorf("BeginAccount issued %d statements for the nil account, want none: a caller about to write "+
			"a membership for nobody must be told, not sent to the database to be refused there",
			len(pool.execs)+len(tx.execs))
	}
}

// BeginAccount is the one exported writer of this GUC, so its call is the one a
// reader greps for when asking which transaction writes an account-scoped row
// as an account it just created.
func TestBeginAccountSetsTheGivenAccountOnTheCallersTransaction(t *testing.T) {
	t.Parallel()

	account := mustNewAccount(t)
	pool, _ := newRecording()

	if err := BeginAccount(context.Background(), pool, account); err != nil {
		t.Fatalf("BeginAccount: %v", err)
	}

	if len(pool.execs) != 1 || pool.execs[0] != beginAccountSQL {
		t.Errorf("the querier received %v, want exactly [%s]", pool.execs, beginAccountSQL)
	}
	if len(pool.args) != 1 || len(pool.args[0]) != 1 || pool.args[0][0] != account {
		t.Errorf("begin_account was called with %v, want the account it was handed (%v)", pool.args, account)
	}
}

// mustNewAccount is id.New without the error, which cannot happen.
//
// It is a helper rather than an inline pair because a UUID generator failing is
// not something these tests are about, and an ignored error would be a lie about
// that. t.Fatalf in a non-test goroutine is the reason it takes *testing.T
// rather than being a plain function.
func mustNewAccount(t *testing.T) id.UUID {
	t.Helper()
	account, err := id.New()
	if err != nil {
		t.Fatalf("generating a uuid: %v", err)
	}
	return account
}
