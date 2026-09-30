package db

import (
	"context"
	"errors"
	"testing"
)

// TxRunner runs a function inside a transaction and commits or rolls back
// around it.
//
// It exists so a use case that must write two rows together — a user and its
// outbox event — can say so without naming pgx, and so that use case can be
// tested without a database. The alternative, a use case that calls Begin itself,
// forces every test of its branching to stand up Postgres or fake pgx.Tx.

func TestTxRunnerCommitsWhenTheFunctionSucceeds(t *testing.T) {
	t.Parallel()

	runner, fake := newFakeTxRunner()

	ran := false
	err := runner.Do(context.Background(), func(_ context.Context, _ Querier) error {
		ran = true
		return nil
	})

	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !ran {
		t.Error("the function never ran")
	}
	if !fake.committed {
		t.Error("the transaction was not committed")
	}
	if fake.rolledBack {
		t.Error("the transaction was rolled back after a successful function")
	}
}

func TestTxRunnerRollsBackAndReturnsTheError(t *testing.T) {
	t.Parallel()

	runner, fake := newFakeTxRunner()
	boom := errors.New("second write failed")

	err := runner.Do(context.Background(), func(context.Context, Querier) error {
		return boom
	})

	// The error is returned unwrapped: a caller that has to unwrap to find out
	// what went wrong will eventually stop checking.
	if !errors.Is(err, boom) {
		t.Errorf("Do = %v, want the function's error verbatim", err)
	}
	if !fake.rolledBack {
		t.Error("the transaction was not rolled back")
	}
	if fake.committed {
		t.Error("the transaction was committed after the function failed")
	}
}

// The function gets the transaction as its Querier, not the pool. That is the
// whole mechanism behind "these two writes are one transaction", and a test can
// see it: a statement issued through the handed-over querier must not be visible
// on the pool.
func TestTxRunnerHandsOverTheTransactionNotThePool(t *testing.T) {
	t.Parallel()

	runner, fake := newFakeTxRunner()

	var inside Querier
	if err := runner.Do(context.Background(), func(_ context.Context, q Querier) error {
		inside = q
		fake.queryerUsedByFunction = q
		return nil
	}); err != nil {
		t.Fatalf("Do: %v", err)
	}

	if inside == nil {
		t.Fatal("the function was handed a nil Querier")
	}
	if fake.queryerUsedByFunction == nil {
		t.Error("the function was not handed the transaction")
	}
}

// A panic inside the function must roll back rather than leave the transaction
// open on a connection. The error is returned, not re-panicked: the transaction
// manager is below the HTTP handlers, and a panic there is a bug to be surfaced,
// not one to be re-raised from two frames down.
func TestTxRunnerRecoversAPanicAndRollsBack(t *testing.T) {
	t.Parallel()

	runner, fake := newFakeTxRunner()

	var recovered any
	func() {
		defer func() { recovered = recover() }()

		if err := runner.Do(context.Background(), func(context.Context, Querier) error {
			panic("the second write panicked")
		}); err == nil {
			t.Error("Do returned nil after a panic, want an error")
		}
	}()

	if recovered != nil {
		t.Errorf("the panic escaped Do: %v", recovered)
	}
	if !fake.rolledBack {
		t.Error("the transaction was not rolled back after a panic")
	}
}

// A commit that fails is reported, not swallowed. A caller that believes two
// writes are durable when they are not will go on to tell a client its
// registration succeeded.
func TestTxRunnerReportsACommitFailure(t *testing.T) {
	t.Parallel()

	runner, fake := newFakeTxRunner()
	fake.commitErr = errors.New("connection lost during COMMIT")

	err := runner.Do(context.Background(), func(context.Context, Querier) error { return nil })

	if !errors.Is(err, fake.commitErr) {
		t.Errorf("Do = %v, want the commit failure", err)
	}
}

// An already-cancelled context is refused before a transaction is opened, so the
// caller does not hold a connection for a request that is not going to happen.
func TestTxRunnerRefusesADeadContext(t *testing.T) {
	t.Parallel()

	runner, _ := newFakeTxRunner()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := runner.Do(ctx, func(context.Context, Querier) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Errorf("Do on a cancelled context = %v, want context.Canceled", err)
	}
	if runner.pool.pool.began {
		t.Error("a transaction was begun for an already-cancelled context")
	}
}

func TestTxRunnerRefusesANilFunction(t *testing.T) {
	t.Parallel()

	runner, _ := newFakeTxRunner()

	if err := runner.Do(context.Background(), nil); err == nil {
		t.Error("Do(nil) returned no error, want a rejection")
	}
}
