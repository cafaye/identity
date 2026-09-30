package db

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Querier is the slice of pgx that both *pgxpool.Pool and pgx.Tx satisfy.
//
// Stores take a Querier rather than a *pgxpool.Pool so the caller decides the
// transaction boundary. Registering a user has to write two rows — the user and
// the outbox event — atomically, and that is a property of the call site, not
// of the store.
//
// Query is here for the multi-row reads: a membership list and an account list
// are the two statements in this service that return more than one row, and
// forcing them through QueryRow would mean either a N+1 or a bespoke seam for
// one store.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Pool is what a store is constructed with: a Querier plus the ability to open
// a transaction.
type Pool interface {
	Querier
	Begin(ctx context.Context) (pgx.Tx, error)
}
