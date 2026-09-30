package db

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// fakeTx is a pgx.Tx that records what was done to it. Only the three methods
// TxRunner calls are implemented; the rest panic, so an unexpected call is a loud
// test failure rather than a silent no-op.
type fakeTx struct {
	committed  bool
	rolledBack bool
	commitErr  error
	// queryerUsedByFunction records the Querier TxRunner handed to the function,
	// so a test can prove it was the transaction rather than the pool.
	queryerUsedByFunction Querier
}

func (t *fakeTx) Commit(context.Context) error {
	t.committed = true
	return t.commitErr
}

func (t *fakeTx) Rollback(context.Context) error {
	t.rolledBack = true
	return nil
}

func (t *fakeTx) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func (t *fakeTx) QueryRow(context.Context, string, ...any) pgx.Row { return nil }

func (t *fakeTx) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("not implemented in this test double")
}

func (t *fakeTx) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, errors.New("not implemented in this test double")
}

func (t *fakeTx) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	return nil, errors.New("not implemented in this test double")
}

func (t *fakeTx) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults {
	return nil
}

func (t *fakeTx) LargeObjects() pgx.LargeObjects { return pgx.LargeObjects{} }

func (t *fakeTx) Begin(context.Context) (pgx.Tx, error) {
	return nil, errors.New("not implemented in this test double")
}

func (t *fakeTx) Conn() *pgx.Conn { return nil }

// fakePool hands out one fakeTx and nothing else.
type fakePool struct {
	tx *fakeTx
	// pool records the things a test asserts about the pool side: that Begin ran
	// or did not, and the querier the pool itself would have handed out.
	pool poolFacts
}

// poolFacts is kept separate from fakePool so the fake transaction does not have
// to carry the counters.
type poolFacts struct {
	// began counts Begin calls so a test can assert no transaction was opened.
	began bool
	// poolQuerier is what the pool itself would hand out, to prove the function
	// was given the transaction instead.
	poolQuerier Querier
}

func (p *fakePool) Begin(context.Context) (pgx.Tx, error) {
	p.pool.began = true
	return p.tx, nil
}

func (p *fakePool) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func (p *fakePool) QueryRow(context.Context, string, ...any) pgx.Row { return nil }

func (p *fakePool) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("not implemented in this test double")
}

// fakeRunner bundles what the tests need: the runner, the transaction it opened,
// and the pool's own view of events.
type fakeRunner struct {
	TxRunner
	tx   *fakeTx
	pool *fakePool
}

func newFakeTxRunner() (fakeRunner, *fakeTx) {
	tx := &fakeTx{}
	pool := &fakePool{tx: tx}
	pool.pool.poolQuerier = tx
	return fakeRunner{TxRunner: TxRunner{Pool: pool}, tx: tx, pool: pool}, tx
}
