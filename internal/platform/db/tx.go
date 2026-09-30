package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// ErrNilTxFunc is returned by TxRunner.Do when it is handed no function. A nil
// function would otherwise panic inside the deferred rollback, and a panic from
// a transaction manager is a confusing way to learn that a caller passed nil.
var ErrNilTxFunc = errors.New("transaction function must not be nil")

// QuerierSource hands out a querier for statements that need no transaction:
// a lookup by primary key, a credential check, an expiry comparison.
//
// It is separate from UnitOfWork because those reads are single statements with
// no atomicity requirement, and routing them through a transaction would mean a
// BEGIN and a COMMIT for every authentication on the hot path. Naming the seam
// explicitly also lets a test substitute a marker without faking pgx.
type QuerierSource interface {
	Queryer() Querier
}

// Direct is a QuerierSource backed by a pool. Every statement it hands out runs
// in its own implicit transaction, which is the right scope for a single read.
type Direct struct {
	Pool Pool
}

// Queryer returns the pool itself: the pool satisfies Querier, and a statement
// issued through it is atomic on its own.
func (d Direct) Queryer() Querier { return d.Pool }

// TxRunner runs a function inside a transaction.
//
// It exists so a use case that must write two rows together — a user and the
// event announcing it — can say so without naming pgx, and so that use case can
// be tested without a database. A use case calling Begin itself forces every test
// of its branching to stand up Postgres or fake pgx.Tx.
//
// Commit is deliberately not retried on failure. A commit whose outcome is
// unknown (the connection dropped after the server accepted it) is genuinely
// ambiguous, and retrying it could double-apply work the function did inside
// pgx.Tx's idempotency guarantees. The caller's recovery is to fail the request;
// at-least-once delivery on the outbox makes a duplicate event harmless, whereas
// a silently retried commit is not.
type TxRunner struct {
	Pool Pool
}

// Do runs fn inside a transaction, committing when it returns nil and rolling
// back when it returns an error or panics.
func (r TxRunner) Do(ctx context.Context, fn func(ctx context.Context, q Querier) error) error {
	if fn == nil {
		return ErrNilTxFunc
	}
	// Checked before Begin: opening a transaction for a request that has already
	// been cancelled only ties up a connection until the pool reclaims it.
	if err := ctx.Err(); err != nil {
		return err
	}

	tx, err := r.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning a transaction: %w", err)
	}

	if err := runInTx(ctx, tx, fn); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing the transaction: %w", err)
	}
	return nil
}

// runInTx invokes fn and makes sure the transaction is rolled back on any exit
// other than success.
//
// The rollback runs on a context detached from the caller's. That is not
// incidental: the common case for reaching here is that the caller's context was
// cancelled — a client hung up mid-request — and a rollback issued on a dead
// context fails, which would leave the transaction open on its connection. The
// transaction is then discarded, which is the outcome being asked for either way.
func runInTx(ctx context.Context, tx pgx.Tx, fn func(context.Context, Querier) error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			// Rolled back below; the panic is converted to an error so the HTTP
			// layer reports a 500 with a trace id instead of a broken connection.
			err = fmt.Errorf("panic inside a transaction: %v", r)
		}
		if err != nil {
			_ = tx.Rollback(context.WithoutCancel(ctx))
		}
	}()

	return fn(ctx, tx)
}
