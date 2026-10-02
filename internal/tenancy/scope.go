// Package tenancy is identity's account boundary.
//
// Two halves, and they are deliberately in one package because they are one
// decision:
//
//   - scope.go, here: the RUNTIME seam. Where the account a request acts as is
//     carried, and the one call that hands it to Postgres.
//   - credential.go: the SECOND runtime seam, for the one lookup that has no
//     account to predicate on — resolving a presented secret to its row. It is a
//     separate file rather than two more functions in this one because this file's
//     whole argument is that there is exactly ONE place that writes
//     `cafaye.account_id`, and a reader hunting that one place should not have to
//     decide whether the second statement is part of it.
//   - the proof beside them: isolation.sql, assertions.txt and tenancy_test.go,
//     which assert that the substrate in migrations/00016 actually holds.
//
// # WHY begin_account IS CALLED HERE AND NOWHERE ELSE
//
// kit's templates/database/tenancy/README.md §Adopting step 3 asks for
// `cafaye.begin_account/1` "once per request, inside your transaction, from
// whatever already authenticates the request". In this service the thing that
// already authenticates a request and resolves its account is
// `requireAccountRole` in internal/httpapi, which is middleware rather than a
// transaction — and the transaction that has to carry the identity is opened
// DEEPER, by the use case the handler calls. So the identity travels on the
// request CONTEXT from the middleware to the transaction, and this file is the
// seam that turns a context value into the GUC.
//
// It is a context value rather than a parameter for one reason: six services
// open transactions, each behind its own `UnitOfWork` interface declared at the
// consumer. Threading an account id through every one of those interfaces is a
// signature change in six packages and a new argument in every use case, and the
// argument would have to be threaded again by every future caller. The context is
// already how the HTTP layer hands a request's identity to a handler, so the
// account joins it there and the transaction picks it up on the way past.
//
// # IT IS TRANSACTION-LOCAL, AND THAT IS NOT AN OPTIMISATION
//
// `begin_account` is `set_config(..., is_local => true)`. Outside an explicit
// transaction that expires at the end of the statement that set it, so a caller
// reaching the database in autocommit reads zero rows. That is why TxRunner below
// sets it INSIDE the transaction it has already begun, and why a store handed a
// bare pool cannot be made to see an account at all. It is also why the
// transaction-local form is the safe one on a pooled connection: a session-level
// account variable goes back to the pool carrying tenant A's identity and tenant
// B is handed the connection.
//
// # THE ONE PLACE THAT WRITES THIS GUC
//
// Every statement that sets `cafaye.account_id` in this service is the one
// `beginAccount` below, which is why it is not a constant query string a caller
// can pass around. A second spelling of it is a second place to forget.
package tenancy

import (
	"context"
	"errors"
	"fmt"

	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
)

// ErrNoIdentity is returned when the GUC could not be set.
//
// It is a sentinel so a caller can match it with errors.Is rather than by
// substring, and it exists at all because a failure here is NOT an absent
// account. An absent account reads zero rows and looks like a service with no
// data; a REFUSED begin_account looks like a database problem, and the two
// demand different responses.
var ErrNoIdentity = errors.New("setting the account identity on the transaction")

// beginAccountSQL is kit's seam, called by name rather than written out.
//
// It is kit's function, not ours: migrations/00016 applies kit's substrate
// verbatim and this is the one entry point that substrate declares. A service
// that hand-rolled the GUC would have two sources of truth for the boundary, and
// the one that drifts is the one nothing checks.
const beginAccountSQL = `select cafaye.begin_account($1)`

// accountKey is the context key the account travels on.
//
// An unexported struct type rather than a string, because a context key that is
// a plain string can be forged by any package that guesses the name — and this
// one decides which tenant's rows a statement can see.
type accountKey struct{}

// WithAccount returns a context carrying the account a request acts as.
//
// It is called by the middleware that has already resolved the account, and by
// the registration use case for the account it has just created. Both are places
// where the account is a FACT rather than something read from a request body,
// which is the rule that keeps tenancy out of caller-supplied input.
//
// A zero account is refused rather than carried: it would read as an account no
// row can have, and a caller that meant "no account" wanted WithNoAccount, which
// this package does not offer because "none" and "the nil uuid" must not be two
// spellings of one thing.
func WithAccount(ctx context.Context, account id.UUID) context.Context {
	return context.WithValue(ctx, accountKey{}, account)
}

// AccountFrom returns the account a request is acting as, and whether it set one.
//
// The bool is not a convenience. "No account" is a legitimate and LOAD-BEARING
// state — a login and a registration's pre-account phase both have none — and it
// has to be distinguishable from a context that was never given one, because the
// first is expected and the second is a wiring bug.
func AccountFrom(ctx context.Context) (id.UUID, bool) {
	account, ok := ctx.Value(accountKey{}).(id.UUID)
	if !ok || account.IsZero() {
		return id.UUID{}, false
	}
	return account, true
}

// beginAccount sets the identity on a transaction that is already open.
//
// It is deliberately unexported: a store cannot call it, so the identity is set
// by the transaction boundary and by nothing else. The exported way to get an
// identity into a transaction is TxRunner, or BeginAccount for the one write that
// creates the account it acts as.
func beginAccount(ctx context.Context, q db.Querier, account id.UUID) error {
	if _, err := q.Exec(ctx, beginAccountSQL, account); err != nil {
		return fmt.Errorf("%w: %w", ErrNoIdentity, err)
	}
	return nil
}

// BeginAccount sets the identity on the caller's own transaction, for the write
// that CREATES the account it acts as.
//
// THIS EXISTS FOR EXACTLY ONE CALL SITE, and it is the exception that proves the
// rule. A request that authenticates resolves its account before it writes, so
// TxRunner can set the identity from the context. Registration does not have an
// account at all until the middle of its transaction: it creates a personal
// account and then writes the owner's membership into it, and the membership
// INSERT meets `with check (account_id = (select cafaye.current_account_id()))`
// with a NULL identity, which is not true and is refused with SQLSTATE 42501.
//
// So the account has to be named before the membership is written, and the value
// that names it is the one the provisioning step just returned. Calling it here,
// on the same transaction, is "begin_account as the NEW account" rather than as
// nobody.
//
// It is a function rather than a field on the request because the identity is a
// property of the TRANSACTION, and the transaction is what the substrate scopes
// it to. Anything else — a context value, a parameter threaded through the store
// — would put it somewhere the RLS policies cannot see.
func BeginAccount(ctx context.Context, q db.Querier, account id.UUID) error {
	if account.IsZero() {
		// Named rather than defaulted. A caller reaching here with no account is
		// about to write a membership for nobody, and the substrate's refusal of
		// that INSERT is correct — this makes the mistake legible at the call site
		// instead of leaving it to be read out of a 42501.
		return fmt.Errorf("%w: refusing to begin as the nil account", ErrNoIdentity)
	}
	return beginAccount(ctx, q, account)
}

// TxRunner is the UnitOfWork every service in this repository is constructed
// with, in place of db.TxRunner.
//
// It is a DROP-IN for db.TxRunner — same field, same Do — because six packages
// declare their own `UnitOfWork` interface with an identical method set, and a
// seam that had to be threaded through all six would be a seam somebody would
// route around. This type satisfies all of them with no signature change
// anywhere, so a service cannot be constructed with an unwired transaction
// runner by accident.
//
// WHAT IT DOES, AND WHY IT IS NOT OPTIONAL: after Begin it sets the account
// identity, when the request has one, before handing the transaction to the use
// case. Every account-scoped write in this service goes through a use case that
// goes through here, so "every account-scoped write runs under an identity" is a
// property of this one type rather than a rule repeated at each call site.
//
// A request with NO account — a login, a session lookup, a registration's first
// statements — is left alone. Setting `begin_account(NULL)` would be the same
// state, but it would be a statement on the hot authentication path whose only
// effect is to clear a GUC that is already unset on a fresh connection, and a
// service that pays a round trip to say nothing is a service that will be
// measured on it.
//
// Every query KEEPS its own `where account_id = ?`. That is unchanged by this
// type and is not optional: the predicate is what makes the query indexable, and
// RLS is defence in depth rather than a licence to delete it.
type TxRunner struct {
	db.TxRunner
}

// Do runs fn inside a transaction that already carries the request's account.
//
// On any failure the transaction is rolled back by db.TxRunner, which also covers
// the failure of beginAccount itself — the identity is set before the use case
// runs, so a transaction that never got one never gets to write anything.
func (r TxRunner) Do(ctx context.Context, fn func(ctx context.Context, q db.Querier) error) error {
	return r.TxRunner.Do(ctx, func(ctx context.Context, q db.Querier) error {
		if account, ok := AccountFrom(ctx); ok {
			if err := beginAccount(ctx, q, account); err != nil {
				return err
			}
		}
		return fn(ctx, q)
	})
}
