package tenancy

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestTenancyACredentialResolvesByTheDigestTheCallerPresentedAndNothingElse is the
// property kit's MD24 buys, asserted against the real protected tables in this
// service's real database.
//
// # WHAT CHANGED, AND WHY THIS TEST HAS A NEW NAME
//
// It used to be `TestTenancyACredentialLookupHasNoIdentityToRunUnder`, and it
// was GREEN while asserting that a scoped token resolved to nothing:
//
//	no identity at all (the state a token request is in)  ->  0 rows
//
// That was a characterisation, not a requirement, and it was pinned deliberately
// so that whoever fixed the problem would get a red test naming exactly what
// moved. migrations/00016 now calls
// `cafaye.protect_credential_table('api_keys', 'token_digest')` and the
// application opens the resolution with `cafaye.begin_credential(digest)`, so the
// measurement it took is no longer what the service does — and a test whose name
// says "has no identity to run under" would now be a test asserting a defect.
//
// # THE PROPERTY, STATED BEFORE THE ASSERTIONS
//
//	> A resolution session may read exactly the credential row whose digest it
//	> presented, and nothing else in the database.
//
// Narrower than "reads nothing", which is what the old test measured, and not one
// bit wider than the caller could already have asked for: the digest is unguessable,
// it is hashed off the request before any query runs, and Postgres is handed a
// string to compare rather than a secret to learn. The predicate lives in the
// POLICY as well as in the caller's query, which is what makes `select *` return
// that row instead of the table — RLS policies combine permissively, so a policy
// saying merely "a credential session may select this table" would hand the
// caller a browse of every key in the database.
//
// # THE FOUR THINGS THAT ARE NOT ABOUT THE LOOKUP
//
// Three denials and one allowance is kit's rule for an isolation proof and it is
// the rule here too: a resolution that returns its row is satisfied by a policy
// that permits everything, and a resolution that returns nothing is satisfied by a
// table with no policy at all. So this test also proves the session CANNOT write,
// CANNOT browse, and CANNOT open another table — and, after the transaction, that
// it has no identity at all and is an ordinary no-identity session again. The
// three-way denial on every OTHER protected table is re-asserted unchanged,
// because "api_keys got a fifth policy" must not have moved anything else.
//
// # WHY NO OTHER TEST IN THIS REPOSITORY SEES ANY OF IT
//
// Every integration test that drives an account-scoped route builds its fixtures
// with `dbtest.Schema(t)`, which clones tables with `LIKE … INCLUDING ALL`. LIKE
// does not copy row-level security, so a private fixture schema has an
// `account_id` column and NO policies — the RLS half of the service is simply
// absent from those tests. They pass with this wiring, and they would pass with NO
// wiring at all. That is not a criticism of them: they were written to prove
// authorization answers, and they do. It is the reason this test has to exist, and
// the reason it runs against the real tables rather than a fixture.
func TestTenancyACredentialResolvesByTheDigestTheCallerPresentedAndNothingElse(t *testing.T) {
	// The package's own skip, so REQUIRED_DB=1 makes this non-optional too. A second
	// skip path here would be a proof that CI cannot make mandatory, which is the
	// silent-skip this package was written to refuse.
	dsn := dsnOrSkip(t)

	ctx, cancel := context.WithTimeout(context.Background(), oneMinute)
	defer cancel()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	// Registered FIRST so it runs LAST: t.Cleanup is LIFO, and the seed registers
	// its row cleanup after this. With `defer conn.Close(ctx)` instead, the deferred
	// close ran when this function returned — BEFORE any t.Cleanup — so every
	// fixture row survived into the next run with the error discarded by `_, _ =`.
	//
	// That is not a cosmetic leak. It corrupts later measurements rather than just
	// tidying badly, and it did: two of the three negative controls run while
	// measuring this file reported "the fixture holds 8 api keys under tenant A,
	// want 1", because the rows under test were the PREVIOUS run's. A control that
	// fails for a reason the run before it created is worse than no control.
	t.Cleanup(func() { _ = conn.Close(context.Background()) })

	// The lookup under test is the shape of apikeys.ByDigest — a row addressed by a
	// value that is NOT the account — and that shape is the point, so it is
	// exercised on api_keys itself, with real foreign keys, because a fixture that
	// dodged them would not be the query.
	tenantA, tenantB := seedCredentialRows(t, ctx, conn)

	// 0. THE FIXTURE REALLY HOLDS TWO KEYS, and this is asserted rather than
	//    assumed. Every "a resolution session sees exactly one row" assertion below
	//    is only meaningful against a table with more than one row in it: with a
	//    single row, "the table" and "that row" are the same set and a table-wide
	//    SELECT would pass every one of them.
	//
	//    TWO COUNTS, and the second one is not redundancy. The first is the
	//    fixture's own account, read with the account_id predicate in the query, so
	//    it holds whatever the policies do — that is what makes it a precondition
	//    rather than a tripwire. The second is the same read with no predicate, and
	//    it is the earliest possible witness of a resolve policy that has been
	//    widened: a `using (true)` anywhere on this table shows up HERE, before any
	//    of the resolution cases run, because an account-scoped read can then see
	//    another tenant's key. Measured, with the widened policy installed.
	var fixtureOwn, fixtureVisible int
	if err := countOwnKeysAs(ctx, conn, tenantA, &fixtureOwn); err != nil {
		t.Fatalf("counting the fixture's own api keys under tenant A: %v", err)
	}
	if fixtureOwn != 1 {
		t.Fatalf("the fixture holds %d api keys OF ITS OWN under tenant A, want 1. The seed is wrong "+
			"and every assertion below would be measuring the wrong table.", fixtureOwn)
	}
	if err := countAsAccount(ctx, conn, tenantA, "", &fixtureVisible); err != nil {
		t.Fatalf("counting the fixture's api keys under tenant A: %v", err)
	}
	if fixtureVisible != 1 {
		t.Fatalf("tenant A can see %d api keys, want 1. Every assertion below reads 'a resolution sees "+
			"exactly one row', which is only a statement about browsing if the table holds more than one "+
			"row — and this is also where a resolve policy that has been widened past the presented digest "+
			"is caught first.", fixtureVisible)
	}

	// 1. NO DIGEST AND NO IDENTITY: still nothing. This is the measurement the old
	//    test took, kept rather than deleted, and it is load-bearing in its new
	//    place: it is the half that says a session which has been given nothing
	//    reads nothing. If the resolve policy had been written with `using (true)`
	//    instead of the digest predicate, THIS is the assertion that catches it.
	//
	//    AUTOCOMMIT IS CORRECT HERE AND ONLY HERE. `begin_credential` is
	//    `set_config(…, is_local => true)`, which outside an explicit transaction
	//    expires at the end of the statement that set it — so a digest cannot be
	//    carried into a later statement on the same connection at all. Cases 2
	//    through 5 therefore open a real transaction, and this one deliberately
	//    does not: "given nothing at all" is only expressible in autocommit.
	var seen int
	if err := conn.QueryRow(ctx,
		`select count(*) from api_keys where token_digest = $1`, digestFor(tenantA)).Scan(&seen); err != nil {
		t.Fatalf("counting api_keys with no identity and no digest: %v", err)
	}
	if seen != 0 {
		t.Errorf("a credential lookup with NO identity and NO digest saw %d rows, want 0.\n"+
			"  The resolve policy's qualifier is the digest the caller presented, and a session that has\n"+
			"  presented nothing must read nothing. A non-zero here means the policy was widened.", seen)
	}

	// 2. THE RESOLUTION ITSELF: the presented digest returns the row, with NO account
	//    identity set — which is the whole claim, because the account is what the
	//    query is FOR and cannot also be what it is scoped by.
	//
	//    `byDigest` is checked against BOTH tenants in both directions, so a policy
	//    that leaked the other tenant's key would be caught: a resolution for A must
	//    return A's row and not B's.
	for _, tc := range []struct {
		name      string
		accountID string
		digest    string
		want      int
	}{
		{"the credential it presented", tenantA, digestFor(tenantA), 1},
		{"the other tenant's credential", tenantB, digestFor(tenantB), 1},
		{"a digest no row has", tenantA, digestFor(tenantA)[:63] + "0", 0},
	} {
		t.Run("resolve "+tc.name, func(t *testing.T) {
			seen, err := countAsCredential(ctx, conn, tc.digest)
			if err != nil {
				t.Fatalf("resolving by digest: %v", err)
			}
			if seen != tc.want {
				t.Errorf("a resolution session presenting %s… saw %d rows, want %d.\n"+
					"  The resolve policy's qualifier IS the presented digest, so this is either a row that\n"+
					"  does not exist being returned, or the row it names not being returned.",
					tc.digest[:8], seen, tc.want)
			}
		})
	}

	// 3. IT CANNOT BROWSE. `select * from api_keys` with no WHERE, inside a
	//    resolution session, returns THAT row and not the table — and this asserts
	//    WHICH row, not merely how many, because "one row" is also what a session
	//    that can see nothing would return and the two must not be confused.
	names, err := namesInResolution(ctx, conn, digestFor(tenantA))
	if err != nil {
		t.Fatalf("selecting every api_keys row in a resolution session: %v", err)
	}
	if len(names) != 1 || names[0] != keyNameFor(tenantA) {
		t.Errorf("select * from api_keys in a resolution session returned %v, want exactly [%s].\n"+
			"  The fixture holds TWO keys, so this is the assertion that says a resolution session reads one\n"+
			"  row rather than the table: the predicate is in the POLICY, so it narrows an unqualified SELECT\n"+
			"  too. Returning two rows here is a credential table-wide browse; returning none is a broken\n"+
			"  boundary or a resolution that did not open.",
			names, keyNameFor(tenantA))
	}

	// 4. IT DOES NOT OPEN ANOTHER TABLE. One policy, on one named table.
	var members int
	if err := countInResolution(ctx, conn, digestFor(tenantA),
		`select count(*) from account_users`, &members); err != nil {
		t.Fatalf("reading account_users in a resolution session: %v", err)
	}
	if members != 0 {
		t.Errorf("a resolution session read %d rows of account_users, want 0: the resolve policy is on\n"+
			"  api_keys and names one table, and opening a second one would be the mechanism having become a\n"+
			"  general bypass rather than a resolution.", members)
	}

	// 5. IT CANNOT WRITE. `for select` and nothing else, so a resolution session
	//    meets the ordinary account policies on the write side, where a NULL
	//    identity is 42501: a service cannot mint a credential while resolving one.
	//
	//    The assertion is that the STATEMENT fails, not that a count is unchanged.
	//    "The row count did not move" is also true of an UPDATE that matched no
	//    row, which is precisely the silent-zero-write failure this repository has
	//    already found once on the other side of this seam.
	wrote, err := writeInResolution(ctx, conn, digestFor(tenantA), tenantA)
	if err != nil {
		t.Fatalf("attempting a write in a resolution session returned a transport error: %v", err)
	}
	if wrote {
		t.Error("an INSERT into api_keys SUCCEEDED inside a resolution session.\n" +
			"  The resolve policy is `for select`, so the ordinary insert policy still applies and a NULL\n" +
			"  account identity must be refused. A resolution session that can mint a credential is not a\n" +
			"  resolution.")
	}

	// 6. AFTER THE TRANSACTION THE SESSION HAS NO IDENTITY. The digest is
	//    transaction-local, which is the reason it is the safe form: a
	//    session-level digest would survive the pool and hand one resolution's
	//    bearer token to the next connection to be leased.
	seen = 0
	if err := conn.QueryRow(ctx,
		`select count(*) from api_keys where token_digest = $1`, digestFor(tenantA)).Scan(&seen); err != nil {
		t.Fatalf("counting api_keys after the resolution transaction: %v", err)
	}
	if seen != 0 {
		t.Errorf("after the resolution transaction committed, the same connection still saw %d rows, want 0.\n"+
			"  The digest expired with its transaction, so this connection is an ordinary no-identity session\n"+
			"  again until requireAccountRole sets the account. A digest that outlived its transaction would\n"+
			"  travel back to the pool with the connection.", seen)
	}

	// 7. AND THE THREE-DENIAL PROPERTY IS UNCHANGED ON EVERY OTHER TABLE. A fifth
	//    policy on one table must not have moved the four account policies beside
	//    it, and the only way to know is to run them again: no identity reads
	//    nothing, another tenant's valid identity reads nothing, and its own
	//    identity reads its own rows.
	seen = 0
	if err := countAsAccount(ctx, conn, tenantA, digestFor(tenantA), &seen); err != nil {
		t.Fatalf("counting api_keys with its own identity: %v", err)
	}
	if seen != 1 {
		t.Errorf("a credential lookup with the credential's OWN account saw %d rows, want 1: adding a resolve\n"+
			"  policy must not have broken the ordinary account-scoped read, or the three-way denial this\n"+
			"  package exists to prove no longer holds on api_keys.", seen)
	}
	seen = 0
	if err := countAsAccount(ctx, conn, tenantA, digestFor(tenantB), &seen); err != nil {
		t.Fatalf("counting another tenant's credential: %v", err)
	}
	if seen != 0 {
		t.Errorf("with account A's identity set, account B's credential was VISIBLE (%d rows). "+
			"That is a cross-tenant read and it is the one failure this whole package exists to prevent.", seen)
	}
}

// countAsAccount runs one credential lookup inside a transaction that begins as
// accountID, which is the only way an account-scoped lookup can carry an identity
// at all.
//
// It is a function rather than an inline block because the transaction is the
// subtlety: an identity set outside one silently evaporates, and a test written in
// autocommit would report a broken boundary where there is only a broken test.
// That is not hypothetical — this helper exists because the first version of this
// file made exactly that mistake and reported a false failure.
//
// An empty digest counts the table under the identity rather than looking one up,
// so the same transaction can establish what the identity can SEE — which is case
// 0's tripwire.
func countAsAccount(ctx context.Context, conn *pgx.Conn, accountID, digest string, out *int) error {
	return inTransaction(ctx, conn, `select cafaye.begin_account($1)`, accountID, func(ctx context.Context, tx pgx.Tx) error {
		if digest == "" {
			return tx.QueryRow(ctx, `select count(*) from api_keys`).Scan(out)
		}
		return tx.QueryRow(ctx,
			`select count(*) from api_keys where token_digest = $1`, digest).Scan(out)
	})
}

// countOwnKeysAs is the policy-INDEPENDENT half of case 0: the account's own rows,
// counted with the predicate in the QUERY rather than relying on the policy to
// supply it. It is what makes case 0's precondition a precondition — it holds
// whatever the policies do, so a failure names the seed rather than the boundary.
func countOwnKeysAs(ctx context.Context, conn *pgx.Conn, accountID string, out *int) error {
	return inTransaction(ctx, conn, `select cafaye.begin_account($1)`, accountID,
		func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `select count(*) from api_keys where account_id = $1`, accountID).Scan(out)
		})
}

// countAsCredential is the mirror: the transaction that begins as the credential,
// with no account identity at all. That absence is the point — the whole claim is
// that a resolution works before the account is known.
func countAsCredential(ctx context.Context, conn *pgx.Conn, digest string) (int, error) {
	var out int
	err := inTransaction(ctx, conn, `select cafaye.begin_credential($1)`, digest,
		func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx,
				`select count(*) from api_keys where token_digest = $1`, digest).Scan(&out)
		})
	return out, err
}

// namesInResolution is case 3's query — `select name from api_keys`, no WHERE —
// and it returns the NAMES rather than a count so the assertion can name the row
// it got back. A count would make "one row" and "the right one row" the same
// assertion.
func namesInResolution(ctx context.Context, conn *pgx.Conn, digest string) ([]string, error) {
	var names []string
	err := inTransaction(ctx, conn, `select cafaye.begin_credential($1)`, digest,
		func(ctx context.Context, tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `select name from api_keys`)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var name string
				if err := rows.Scan(&name); err != nil {
					return err
				}
				names = append(names, name)
			}
			return rows.Err()
		})
	return names, err
}

// countInResolution runs an arbitrary read inside a resolution session, so the
// "it does not open another table" case is measured on another table rather than
// asserted from the shape of the policy.
func countInResolution(ctx context.Context, conn *pgx.Conn, digest, query string, out *int) error {
	return inTransaction(ctx, conn, `select cafaye.begin_credential($1)`, digest,
		func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, query).Scan(out)
		})
}

// writeInResolution attempts an INSERT inside a resolution session and reports
// whether it was ACCEPTED.
//
// The insert is unwound to a savepoint rather than by aborting the transaction,
// so one refusal does not cost the rest of the case its connection and its
// transaction — an aborted transaction ignores every later command, and a test
// that stops measuring after its first refusal is not measuring the second thing
// it said it would.
//
// The user id comes from `users`, which is deliberately NOT a protected table
// (00016 names it as global by construction: login has to find a person before
// any account is known). Reading it needs no identity, which is the only reason
// it is read here at all — the row being written has to satisfy a foreign key, and
// reading it off api_keys would need the identity this case is refusing.
func writeInResolution(ctx context.Context, conn *pgx.Conn, digest, accountID string) (bool, error) {
	var userID string
	if err := conn.QueryRow(ctx,
		`select id::text from users where email like $1 || '-%'`, accountID).Scan(&userID); err != nil {
		return false, fmt.Errorf("reading tenant %s's fixture user: %w", accountID[:8], err)
	}

	accepted := false
	err := inTransaction(ctx, conn, `select cafaye.begin_credential($1)`, digest,
		func(ctx context.Context, tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `savepoint resolution_write`); err != nil {
				return err
			}
			_, err := tx.Exec(ctx,
				`insert into api_keys (user_id, account_id, name, token_digest, scopes, expires_at)
				 values ($1, $2, 'minted-in-a-resolution', $3, array['accounts:read'], $4)`,
				userID, accountID, "0"+digest[1:], time.Now().Add(24*time.Hour))
			if err != nil {
				// Expected. Unwinding to the savepoint puts the transaction back in a
				// usable state so the refusal costs nothing else.
				if _, rbErr := tx.Exec(ctx, `rollback to savepoint resolution_write`); rbErr != nil {
					return rbErr
				}
				return nil
			}
			accepted = true
			return nil
		})
	return accepted, err
}

// inTransaction opens a transaction, issues the one seam statement, runs fn, and
// commits. Every case in this test needs exactly that shape and each of them
// re-deriving it is four chances to forget that `set_config(…, is_local => true)`
// outside a transaction expires at the end of the statement that set it.
func inTransaction(ctx context.Context, conn *pgx.Conn, begin, arg string, fn func(context.Context, pgx.Tx) error) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning a transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, begin, arg); err != nil {
		return fmt.Errorf("issuing %s: %w", begin, err)
	}
	if err := fn(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing: %w", err)
	}
	return nil
}

// seedCredentialRows writes one account, user and api key for each of two tenants,
// each under its own identity, and returns their account ids.
//
// The identities have to be set per row because the owner's INSERT is itself
// subject to `with check` — FORCE removed the owner's exemption — which is the
// adoption cost kit's README states. It is the same thing seedAuditRows does, on
// the table that has foreign keys.
//
// Each key's NAME carries the first eight characters of its account, so a test can
// assert WHICH row a resolution returned rather than only how many it returned.
// Two keys named `fixture` would make "one row" and "the right one row" the same
// assertion, and case 3 needs them to be different.
func seedCredentialRows(t *testing.T, ctx context.Context, conn *pgx.Conn) (tenantA, tenantB string) {
	t.Helper()

	if err := conn.QueryRow(ctx, `select gen_random_uuid()::text, gen_random_uuid()::text`).
		Scan(&tenantA, &tenantB); err != nil {
		t.Fatalf("minting tenant ids: %v", err)
	}

	// The user ids are read back rather than minted twice, and they are KEPT because
	// the cleanup below needs them: `accounts` cascades to `api_keys`, and nothing
	// cascades to `users`, so a fixture that only deleted its accounts left two users
	// behind on every run. That is the same leak the closed connection used to cause
	// and it was found by a negative control failing for the previous run's reasons.
	userIDs := make([]string, 0, 2)

	// A transaction per tenant, because begin_account is transaction-local: an
	// identity set in one transaction does not survive into the next.
	for _, accountID := range []string{tenantA, tenantB} {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatalf("beginning a transaction: %v", err)
		}
		if _, err := tx.Exec(ctx, `insert into users (id, email, password_digest)
			values (gen_random_uuid(), $1 || '-' || gen_random_uuid()::text || '@example.test', $2)`,
			accountID, credentialTestDigest); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("inserting a fixture user: %v", err)
		}
		if _, err := tx.Exec(ctx, `select cafaye.begin_account($1)`, accountID); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("setting the identity: %v", err)
		}
		if _, err := tx.Exec(ctx, `insert into accounts (id, name, slug) values ($1, $2, $3)`,
			accountID, "Credential "+accountID[:8], "cred-"+accountID[:8]); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("inserting a fixture account: %v", err)
		}
		// The user id has to be the one just inserted, so it is read back rather
		// than minted twice.
		var userID string
		if err := tx.QueryRow(ctx, `select id::text from users where email like $1 || '-%'`, accountID).Scan(&userID); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("reading back the fixture user: %v", err)
		}
		userIDs = append(userIDs, userID)
		if _, err := tx.Exec(ctx, `insert into api_keys
			(user_id, account_id, name, token_digest, scopes, expires_at)
			values ($1, $2, $3, $4, array['accounts:read'], $5)`,
			userID, accountID, keyNameFor(accountID), digestFor(accountID), time.Now().Add(24*time.Hour)); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("inserting a fixture api key: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("committing tenant %s: %v", accountID[:8], err)
		}
	}

	t.Cleanup(func() {
		// On a context detached from the test's: this runs after the one-minute
		// budget's context is cancelled, and a cleanup that inherits a cancelled
		// context silently deletes nothing. `accounts` cascades to `api_keys`; the
		// users are deleted explicitly because nothing cascades to them.
		bg := context.Background()
		for _, accountID := range []string{tenantA, tenantB} {
			if _, err := conn.Exec(bg, `delete from accounts where id = $1`, accountID); err != nil {
				t.Errorf("cleaning up tenant %s's account: %v", accountID[:8], err)
			}
		}
		for _, userID := range userIDs {
			if _, err := conn.Exec(bg, `delete from users where id = $1`, userID); err != nil {
				t.Errorf("cleaning up a fixture user: %v", err)
			}
		}
	})

	return tenantA, tenantB
}

// keyNameFor is the name each fixture key carries, so an assertion can name the row
// a resolution returned.
func keyNameFor(accountID string) string { return "key-" + accountID[:8] }

// digestFor builds the 64-character token digest the api_keys CHECK constraint
// requires. It is derived from the account id so each tenant's fixture key has a
// stable, distinct value the test can look up.
func digestFor(accountID string) string {
	d := accountID + accountID
	if len(d) < 64 {
		d += d
	}
	return d[:64]
}

// credentialTestDigest satisfies users.password_digest's NOT NULL and its CHECK.
// Nothing signs in as a fixture user, so the value only has to be well-formed.
const credentialTestDigest = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$" +
	"bG9uZy1ub3QtaGEzaC1hLWZpeHR1cmUtZml4dHVyZQ"
