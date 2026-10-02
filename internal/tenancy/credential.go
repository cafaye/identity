package tenancy

import (
	"context"
	"errors"
	"fmt"

	"github.com/cafaye/identity/internal/platform/db"
)

// The CREDENTIAL seam: the transaction that resolves a presented secret to its row.
//
// # WHY THIS IS A SEPARATE FILE AND NOT A SECOND FUNCTION IN scope.go
//
// scope.go is the account seam and its whole argument is that there is exactly
// ONE place that writes `cafaye.account_id`, so a boundary stated in two places
// is a boundary asserted in zero times. The same argument applies here, and it is
// why this file exists rather than two more functions in that one: the digest is
// a second GUC, it is set by a second statement, and a reader looking for the one
// place that opens a request's identity should not have to decide whether the
// second statement is part of it.
//
// # IT IS NOT THE ACCOUNT SEAM, AND IT MUST NOT BECOME ONE
//
// `begin_account` answers "which tenant is this request acting as", and every
// query that runs under it carries its own `where account_id = ?`. This one
// answers "which row does this presented secret name", and it exists ONLY because
// the query that authenticates a caller has no account to predicate on: the
// account is what that query is FOR. Measured before this seam existed, as the
// owner, against the real protected table:
//
//	no identity at all (the state a token request is in)  ->  0 rows
//	identity = the credential's own account                ->  1 row
//	identity = A, reading another tenant's credential      ->  0 rows
//
// The first line is the finding: every scoped token was refused as though it had
// never existed, because `ErrNoRows` becomes `ErrNotFound` and the HTTP layer
// becomes 401.
//
// # CredentialResolver CANNOT SET AN ACCOUNT, AND THAT IS THE POINT
//
// It is deliberately NOT `TxRunner` and deliberately not built on top of it. A
// resolver that also began the request's account would make the resolution
// session's read set the UNION of two policies — `account_id = …` OR
// `token_digest = …` — and the union of "the row whose digest you presented"
// with "every row of the account you are acting as" is not the resolution
// session's semantics, it is a browsing session with a narrower name. Whether
// that could happen today depends on CALL ORDER — `requireAccountRole` resolves
// the credential before it calls `tenancy.WithAccount` — and a security property
// that holds because of the order of two statements in another package is a
// property that survives exactly until somebody reorders them.
//
// So the narrowing is STRUCTURAL: this type holds a `db.TxRunner` and cannot be
// given an account, so there is no spelling of it that sets one.

// ErrNoCredential is returned when the credential GUC could not be set.
//
// It is a sentinel, and for the same reason ErrNoIdentity is one: a failure here
// is NOT an unknown credential. An unknown credential reads zero rows and looks
// like a service with no data; a REFUSED begin_credential looks like a database
// problem, and the two demand different responses.
var ErrNoCredential = errors.New("setting the credential digest on the transaction")

// beginCredentialSQL is kit's second seam, called by name rather than written
// out, for the reason beginAccountSQL is.
//
// It is kit's function, not ours: migrations/00016 applies kit's substrate
// verbatim and this is the second entry point that substrate declares. MD24 is
// kit's decision — the mechanism and the four answers it rejected are argued in
// the substrate itself and in kit's DECISIONS.md — and this service adopts it
// rather than carrying a second opinion about how a credential resolves.
const beginCredentialSQL = `select cafaye.begin_credential($1)`

// beginCredential sets the presented digest on a transaction that is already
// open. It is unexported, so the digest is written by CredentialResolver and by
// nothing else, for the reason every seam in this package is unexported.
func beginCredential(ctx context.Context, q db.Querier, digest string) error {
	if digest == "" {
		// Unreachable from the only caller, and named rather than defaulted.
		// `apikeys.Digest` is a hex SHA-256 and is 64 characters for every input
		// including the empty string, so no presented value can produce this. It is
		// here because the alternative — passing "" — sets the GUC to empty, which
		// `current_credential_digest()` reads back as NULL, which reads no rows and
		// looks indistinguishable from an unknown credential. A bug at the call site
		// should be a loud one; "reads nothing" is the quietest possible answer and
		// it is the answer this whole packet exists to stop being the default.
		return fmt.Errorf("%w: refusing to begin with an empty digest", ErrNoCredential)
	}
	if _, err := q.Exec(ctx, beginCredentialSQL, digest); err != nil {
		return fmt.Errorf("%w: %w", ErrNoCredential, err)
	}
	return nil
}

// CredentialResolver runs one resolution inside a transaction that already
// carries the digest the caller presented.
//
// It is the structural mirror of TxRunner, and it is a drop-in for it in the
// same sense — same embedded `db.TxRunner`, same `Do` — with ONE difference that
// is the entire reason this is a second type: `Do` takes the digest, and there
// is no account parameter for a caller to pass.
type CredentialResolver struct {
	db.TxRunner
}

// Do runs fn inside a transaction that carries `digest`, before fn runs.
//
// The digest is what the caller PRESENTED, computed by the caller before any
// query — `apikeys.Digest` hashes the token off the request — and this type
// never derives one from a result. That direction is load-bearing: a digest
// computed FROM a row would be a digest the database chose, and a policy
// qualified by it would scope the read to whatever the substrate decided was
// interesting rather than to what the caller proved it held.
//
// # IT IS TRANSACTION-LOCAL, FOR THE SAME REASON begin_account IS
//
// `set_config(..., is_local => true)` outside an explicit transaction expires at
// the end of the statement that set it, which is why the digest is set INSIDE the
// transaction `db.TxRunner` has already begun rather than on a pooled connection.
// It is also why the safe form is the transaction-local one: a session-level
// digest would survive the pool and hand one resolution's credential to the next
// connection to be leased, which is a bearer token delivered to a stranger. After
// the transaction commits the digest is gone and the connection is an ordinary
// no-identity session, until `requireAccountRole` sets the account.
//
// # WHAT THE SESSION MAY DO WITH IT
//
// Exactly one thing: read the row whose digest it presented. `select *` from
// api_keys inside one of these transactions returns THAT row and not the table,
// because the predicate is in the POLICY as well as in the caller's query —
// RLS policies combine permissively, and a policy that merely said "a credential
// session may select this table" would hand the caller a table-wide browse.
//
// It cannot write. There is no insert/update/delete counterpart on a resolve
// policy, so a resolution session meets the ordinary account policies on the
// write side, where a NULL identity is 42501: a service cannot mint a credential
// while resolving one.
//
// And it does not open another table. One policy, on one named table, so
// `account_users` still reads zero rows from inside a resolution.
func (r CredentialResolver) Do(ctx context.Context, digest string, fn func(ctx context.Context, q db.Querier) error) error {
	return r.TxRunner.Do(ctx, func(ctx context.Context, q db.Querier) error {
		if err := beginCredential(ctx, q, digest); err != nil {
			return err
		}
		return fn(ctx, q)
	})
}
