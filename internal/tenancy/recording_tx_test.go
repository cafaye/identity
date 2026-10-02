package tenancy

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/cafaye/identity/internal/platform/db"
)

// A pool and a transaction that are SEPARATE OBJECTS and record separately.
//
// The separation is the whole point of this fake. "The identity was set on the
// transaction" and "the identity was set on the pool" are opposite properties —
// one is the boundary, the other is a cross-tenant leak waiting for a pooled
// connection to change hands — and a fake built as one object would report the
// same thing for both. So `Begin` hands back a DIFFERENT type, and the two keep
// their own statement lists.
type recordingPool struct {
	tx *recordingTx

	// began records that a transaction was opened at all, so a test can tell
	// "no statement reached the pool" from "the pool was never asked".
	began bool
	// execs is everything issued to the pool directly — which, for this seam, is
	// only ever a mistake: begin_account is transaction-local and a pool-level
	// set_config would outlive the request.
	execs []string
	args  [][]any
}

type recordingTx struct {
	// failBeginAccountWith makes the identity statement fail, which is how a
	// refused `cafaye.begin_account` reaches the code under test without a
	// database.
	failBeginAccountWith error

	// onExec fires for every statement issued to EITHER side. A test uses it to
	// observe ORDERING — specifically that the identity is set before the use case
	// runs, since a seam that set it afterwards would leave every account-scoped
	// INSERT among the use case's first statements refused with 42501.
	onExec func(sql string, args []any)

	execs []string
	args  [][]any

	committed  bool
	rolledBack bool
}

var (
	_ db.Pool = (*recordingPool)(nil)
	_ pgx.Tx  = (*recordingTx)(nil)
)

func newRecording() (*recordingPool, *recordingTx) {
	tx := &recordingTx{}
	return &recordingPool{tx: tx}, tx
}

func (p *recordingPool) Begin(context.Context) (pgx.Tx, error) {
	p.began = true
	return p.tx, nil
}

func (p *recordingPool) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if p.tx.onExec != nil {
		p.tx.onExec(sql, args)
	}
	p.execs = append(p.execs, sql)
	p.args = append(p.args, args)
	return pgconn.CommandTag{}, nil
}

func (p *recordingPool) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return nil, errors.New("recordingPool does not produce rows; this seam issues no reads")
}

func (p *recordingPool) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	panic("the account seam issues no reads; QueryRow reaching the fake is a defect in it")
}

func (t *recordingTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if t.onExec != nil {
		t.onExec(sql, args)
	}
	if sql == beginAccountSQL && t.failBeginAccountWith != nil {
		return pgconn.CommandTag{}, t.failBeginAccountWith
	}
	t.execs = append(t.execs, sql)
	t.args = append(t.args, args)
	return pgconn.CommandTag{}, nil
}

func (t *recordingTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return nil, errors.New("recordingTx does not produce rows; this seam issues no reads")
}

func (t *recordingTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	panic("the account seam issues no reads; QueryRow reaching the fake is a defect in it")
}

func (t *recordingTx) Commit(context.Context) error {
	t.committed = true
	return nil
}

func (t *recordingTx) Rollback(context.Context) error {
	t.rolledBack = true
	return nil
}

// The rest of pgx.Tx is not used by db.TxRunner and is here only to satisfy the
// interface. Each returns an error or panics rather than a silent zero value,
// because a no-op Commit or a zero Rows would let a defect in db.TxRunner pass as
// a green run.
func (t *recordingTx) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, errors.New("not used by the account seam")
}

func (t *recordingTx) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	return nil, errors.New("not used by the account seam")
}

func (t *recordingTx) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults {
	return nil
}

func (t *recordingTx) LargeObjects() pgx.LargeObjects { return pgx.LargeObjects{} }

func (t *recordingTx) Begin(context.Context) (pgx.Tx, error) {
	return nil, errors.New("the account seam does not open nested transactions")
}

func (t *recordingTx) Conn() *pgx.Conn { return nil }
