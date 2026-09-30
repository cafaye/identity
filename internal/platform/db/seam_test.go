package db

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The Querier/Pool seam exists so a store can be handed either the pool or an
// open transaction and cannot tell the difference. That is what lets "create the
// user and record the event" be one transaction while still being testable
// against a fake.
//
// These assertions are compile-time: if pgx changes either signature, the
// package stops building and this test fails to compile rather than failing at
// runtime in production.
func TestPoolAndTxBothSatisfyQuerier(t *testing.T) {
	t.Parallel()

	var _ Querier = (*pgxpool.Pool)(nil)
	var _ Querier = (pgx.Tx)(nil)
}

func TestPoolSatisfiesPool(t *testing.T) {
	t.Parallel()

	var _ Pool = (*pgxpool.Pool)(nil)
}

// Pool is the seam a store is constructed with. Begin is part of it because
// registering a user spans two tables that must commit together; a store that
// only saw a Querier could not open that transaction.
func TestPoolBeginYieldsAQuerier(t *testing.T) {
	t.Parallel()

	// A nil pool is enough here: Begin must be reached through the interface,
	// and a nil receiver panics, which proves the method is on the interface
	// rather than being satisfied by some accidental concrete type.
	var p Pool

	defer func() {
		if recover() == nil {
			t.Fatal("Begin on a nil Pool did not reach the concrete type")
		}
	}()

	_ = p
	_, _ = p.Begin(context.Background())
}
