// Package tenancy proves that identity's account boundary is enforced by Postgres.
//
// Two tests, and they prove two different things, which is why both are here.
//
//	TestTenancyAccountIsolation          kit's assertion set, run whole. Its fixture is
//	                                    its OWN TEMPORARY tables, so it proves the
//	                                    SUBSTRATE 00016 installed and that the
//	                                    assertion set can still fail - including the
//	                                    FORCE-RLS control, which is the only half that
//	                                    proves the owner is subject to its own policies.
//
// TestTenancyIdentityOwnsItsFiveTables  the other half. The first test's tables are
//
//	kit's, not identity's, so on its own it proves a
//	service can call protect_table and nothing about
//	whether identity's FIVE tables are protected.
//	This one names them, reads pg_catalog, and runs
//	the three-way denial against real rows.
//
// THE DSN IS THE OWNER. TEST_DATABASE_URL must be a role that may `set role` to
// `identity_app`, because the proof has to run as BOTH roles and impersonating a
// strictly weaker one cannot widen anything. On the dev cluster the owner is
// `identity` and kit's initdb grants `identity_app` TO `identity` for exactly this.
// In CI the same DSN is `identity:identity@localhost:5432/identity`.
//
// NO BUILD TAG, and that is a decision rather than an omission. kit's template is
// tagged `tier_db`, and this repository has no tier_db convention: `go test ./...` in
// .github/workflows/ci.yml is the whole suite and it passes no tags, so a tagged test
// would never be COMPILED there and the account boundary would ship with a proof that
// cannot run. What replaces the tag is the repository's own pair: a loud skip when
// TEST_DATABASE_URL is unset (so `go test ./...` stays green with no database, which
// this suite is built to do), and REQUIRED_DB=1 to turn that skip into a FAILURE for
// anyone who needs the tier to be non-optional - which is the same contract kit's
// driver states, carried over so the driver is still recognisably kit's.
package tenancy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// result is one row of the proof's answer: what was asserted, what was expected,
// what happened, and why the assertion exists at all.
type result struct{ expected, actual, verdict, why string }

// oneMinute is the whole budget for the proof. Bounded rather than defaulted because
// a hang here is a hang in the service's gate.
const oneMinute = time.Minute

// identityTables is the set 00016 protects. Named here as well as in the migration
// because the migration is the decision and this is the check on the decision: a
// table added to one and not the other is exactly what the sweep below reports.
var identityTables = []string{
	"account_users",
	"account_invitations",
	"oidc_clients",
	"api_keys",
	"account_audit_log",
}

// dsnOrSkip is the loud one.
//
// The message names the variable, says what was NOT proven, and says what to do -
// a skip whose text is only "skipping" is indistinguishable at a glance from a test
// that passed, which is the whole failure mode a database tier has.
func dsnOrSkip(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("REQUIRED_DB") == "1" {
			t.Fatal("REQUIRED_DB=1 and TEST_DATABASE_URL is unset: the account-isolation " +
				"proof cannot run, and a skipped proof is a green run that proved nothing. " +
				"Start the database, or unset REQUIRED_DB to skip this tier on purpose.")
		}
		t.Skip("TEST_DATABASE_URL is unset, so NOTHING WAS CHECKED HERE. The account " +
			"boundary - that no request without an account reads another account's rows - " +
			"was not proven by this run. Apply the migrations and set the variable: " +
			"`goose -dir migrations postgres \"$DATABASE_URL\" up` then re-run. To make this " +
			"tier non-optional, set REQUIRED_DB=1 and it fails instead of skipping.")
	}
	return dsn
}

func connect(t *testing.T) (ctx context.Context, conn *pgx.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), oneMinute)
	t.Cleanup(cancel)

	conn, err := pgx.Connect(ctx, dsnOrSkip(t))
	if err != nil {
		t.Fatalf("connect to TEST_DATABASE_URL: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return ctx, conn
}

// TestTenancyAccountIsolation runs kit's assertion set and checks the names it got
// back against the manifest, in BOTH directions.
//
// Named with a `Tenancy` prefix rather than kit's `TestAccountIsolation` so that
// `-run Tenancy` selects it; the shape of the file is otherwise kit's, because the
// file's own argument is that a thin driver is safe precisely when it compares names
// rather than counts.
func TestTenancyAccountIsolation(t *testing.T) {
	ctx, conn := connect(t)

	// The proof, run whole and unexamined. It opens a transaction and leaves it open,
	// because two of the things it does refuse to do outside one; every object it
	// creates is TEMPORARY, so nothing survives the session either way.
	//
	// pgx sends a statement with no bind parameters over the simple protocol, which
	// is the one that accepts a multi-statement batch.
	script, err := os.ReadFile(here("isolation.sql"))
	if err != nil {
		t.Fatalf("read isolation.sql: %v", err)
	}
	if _, err := conn.Exec(ctx, string(script)); err != nil {
		t.Fatalf("isolation.sql did not complete: %v", err)
	}

	rows, err := conn.Query(ctx, `
		select assertion, expected, actual, verdict, why
		  from pg_temp.cafaye_probe_result
		 order by assertion`)
	if err != nil {
		t.Fatalf("read the assertion results: %v", err)
	}

	got := map[string]result{}
	for rows.Next() {
		var name string
		var r result
		if err := rows.Scan(&name, &r.expected, &r.actual, &r.verdict, &r.why); err != nil {
			t.Fatalf("scan an assertion result: %v", err)
		}
		got[name] = r
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate the assertion results: %v", err)
	}

	// Roll the proof's transaction back rather than leaving it open: everything it
	// created is temporary, but a test that leaves a transaction open makes every test
	// after it run inside it.
	if _, err := conn.Exec(ctx, "rollback"); err != nil {
		t.Fatalf("roll back the proof's transaction: %v", err)
	}

	t.Logf("kit's assertion set returned %d assertions", len(got))
	assertComplete(t, got)
	assertAllPass(t, got)
}

// TestTenancyIdentityOwnsItsFiveTables is the half kit's assertion set cannot be.
//
// isolation.sql protects its own temporary fixture table and proves the substrate
// works. It never names account_users, account_invitations, oidc_clients, api_keys or
// account_audit_log, so a migration that installed a perfect substrate and protected
// NO tables would pass it. This test is the one that closes that gap, in the two ways
// that are available from outside:
//
//  1. the CATALOG. For each of the five: row-level security enabled, and FORCED - the
//     bit without which the owner reads every account's rows while the policies look
//     like they are in place - plus the four named policies protect_table wrote.
//  2. THE THREE-WAY DENIAL, on real rows, as BOTH roles. no identity reads zero; the
//     other tenant's VALID identity reads zero of that tenant's rows; the account's
//     own identity reads its own rows. The third arm is the one with the information
//     in it: a suite that only asserts the first two is satisfied by a table nobody
//     can read.
//
// IT USES account_audit_log FOR THE DATA-BEARING HALF, and the reason is in 00012's
// header: this table has NO foreign keys, so the fixture needs no users and no
// accounts and cannot collide with any other package's rows. The four tables that do
// have foreign keys are covered by the catalog half above rather than by fixture
// rows, because seeding them correctly means seeding users and accounts in tables
// this repository's other packages also write to - and a shared database plus a
// global TRUNCATE is precisely the non-deterministic failure dbtest's package comment
// warns about.
func TestTenancyIdentityOwnsItsFiveTables(t *testing.T) {
	ctx, conn := connect(t)

	t.Run("every declared table is enabled and FORCED", func(t *testing.T) {
		for _, table := range identityTables {
			rows, err := conn.Query(ctx, `
				select c.relrowsecurity, c.relforcerowsecurity,
				       (select count(*) > 0 from pg_index i
				         where i.indrelid = c.oid
				           and i.indkey[0] = (select attnum from pg_attribute a
				                               where a.attrelid = c.oid and a.attname = 'account_id')) as acct_index,
				       (select count(*) > 0 from pg_policy p where p.polrelid = c.oid) as policies
				  from pg_class c
				 where c.relname = $1`, table)
			if err != nil {
				t.Fatalf("reading the catalog for %s: %v", table, err)
			}
			var enabled, forced, acctIndex, policies bool
			if !rows.Next() {
				rows.Close()
				t.Fatalf("%s is not in this database at all, so 00016 protected nothing. "+
					"Have the migrations been applied?", table)
			}
			if err := rows.Scan(&enabled, &forced, &acctIndex, &policies); err != nil {
				rows.Close()
				t.Fatalf("scan the catalog row for %s: %v", table, err)
			}
			rows.Close()

			if !enabled {
				t.Errorf("%s: row level security is NOT enabled, so no policy on it is ever evaluated", table)
			}
			if !forced {
				// The one finding no lint in this fleet checks for, and the one this
				// whole migration exists to get right.
				t.Errorf("%s: NOT set FORCE ROW LEVEL SECURITY. Postgres exempts a table's owner "+
					"from its own policies, and this service runs its migrations as the role that "+
					"owns every table here - so the role that matters reads every account's rows "+
					"while every policy on it sits in the catalog looking like a boundary", table)
			}
			if !acctIndex {
				t.Errorf("%s: no index leads with account_id. A policy is a filter on every row, so "+
					"an unindexed one is a sequential scan behind a primary-key lookup", table)
			}
			if !policies {
				t.Errorf("%s: row level security is enabled with no policy, which hides every row "+
					"from every role including this service", table)
			}
		}
	})

	t.Run("the sweep finds nothing unprotected", func(t *testing.T) {
		// The sweep is the question "is this service isolated?", and it answers for
		// every table rather than the first, because a caller that gets rows can
		// print them all.
		rows, err := conn.Query(ctx, `select table_schema, table_name, why from cafaye.unprotected_tables()`)
		if err != nil {
			t.Fatalf("running the sweep: %v", err)
		}
		defer rows.Close()
		var unprotected []string
		for rows.Next() {
			var schema, table, why string
			if err := rows.Scan(&schema, &table, &why); err != nil {
				t.Fatalf("scan a sweep row: %v", err)
			}
			unprotected = append(unprotected, fmt.Sprintf("%s.%s (%s)", schema, table, why))
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("iterate the sweep: %v", err)
		}
		if len(unprotected) > 0 {
			t.Errorf("cafaye.unprotected_tables() found %d account-scoped table(s) with no boundary:\n  %s",
				len(unprotected), strings.Join(unprotected, "\n  "))
		}
	})

	// THE THREE-WAY DENIAL, on real rows, as each role in turn.
	//
	// `role` is a parameter rather than an identifier, so it cannot be interpolated
	// into SQL - it is passed to `set role`, which takes a string, and both values
	// are literals in this file.
	for _, role := range []string{"identity_app", "identity"} {
		role := role
		t.Run("three-way denial as "+role, func(t *testing.T) {
			ctx, conn := connect(t)

			// The transaction is explicit because begin_account/1 is
			// transaction-local: outside one it expires at the end of the statement
			// that set it, and this would read zero rows everywhere and look like
			// perfect isolation.
			if _, err := conn.Exec(ctx, "begin"); err != nil {
				t.Fatalf("begin: %v", err)
			}
			t.Cleanup(func() {
				if _, err := conn.Exec(context.Background(), "rollback"); err != nil {
					t.Logf("rollback: %v", err)
				}
			})

			if _, err := conn.Exec(ctx, "set local role "+role); err != nil {
				t.Fatalf("set local role %s: %v", role, err)
			}

			// Two tenants, one row each, written by the OWNER before the identity is
			// set and before the role is dropped - because the insert policy is
			// `with check (account_id = (select cafaye.current_account_id()))`, so a
			// writer with no identity is refused, which is the write-side twin of the
			// read denial and is itself correct.
			tenantA, tenantB := seedAuditRows(t, ctx, conn, role)

			// ARM ONE. No identity. `begin_account(NULL)` clears, which is the state a
			// request that never authenticated is in.
			if _, err := conn.Exec(ctx, `select cafaye.begin_account(NULL)`); err != nil {
				t.Fatalf("clearing the account identity: %v", err)
			}
			if got := countAuditRows(t, ctx, conn); got != 0 {
				t.Errorf("as %s with NO identity: read %d rows, want 0. A request that never "+
					"authenticated is reading account data", role, got)
			}

			// ARM TWO. The other tenant's VALID identity. This is the arm that carries
			// the information: the credential is real, it belongs to another account,
			// and it must be indistinguishable from one that does not exist.
			if _, err := conn.Exec(ctx, `select cafaye.begin_account($1)`, tenantB); err != nil {
				t.Fatalf("setting the other tenant's identity: %v", err)
			}
			if got := countAuditRows(t, ctx, conn); got != 1 {
				t.Errorf("as %s carrying ANOTHER tenant's valid identity: read %d rows, want 1 "+
					"(its own). Anything more is a cross-account read", role, got)
			}
			if got := countAuditRowsIn(t, ctx, conn, tenantA); got != 0 {
				t.Errorf("as %s carrying ANOTHER tenant's valid identity: read %d of THAT "+
					"tenant's rows, want 0", role, got)
			}

			// ARM THREE. Its own identity. The positive control, and the only arm a
			// deny-everything table can pass.
			if _, err := conn.Exec(ctx, `select cafaye.begin_account($1)`, tenantA); err != nil {
				t.Fatalf("setting the account's own identity: %v", err)
			}
			if got := countAuditRowsIn(t, ctx, conn, tenantA); got != 1 {
				t.Errorf("as %s with its OWN identity: read %d of its own rows, want 1. A table "+
					"that denies everybody also passes the two arms above, which is why this one "+
					"exists", role, got)
			}
			if got := countAuditRows(t, ctx, conn); got != 1 {
				t.Errorf("as %s with its OWN identity: an unqualified read returned %d rows, want 1 "+
					"(its own only)", role, got)
			}

			// AND THE WRITE SIDE, because a read denial with no write assertion is
			// half a boundary: `using` denies an UPDATE by matching zero rows and
			// raising nothing, so "the other tenant's row came back unchanged" is the
			// only proof that the denial happened rather than the write being a no-op.
			if _, err := conn.Exec(ctx, `select cafaye.begin_account($1)`, tenantB); err != nil {
				t.Fatalf("setting the other tenant's identity: %v", err)
			}
			tag, err := conn.Exec(ctx,
				`update account_audit_log set target = 'rewritten' where account_id = $1`, tenantA)
			if err != nil {
				t.Fatalf("the cross-account UPDATE raised %v, which is a different failure from "+
					"the one being asserted: a `using` denial matches zero rows and raises "+
					"nothing, so this statement is expected to SUCCEED and change nothing", err)
			}
			if tag.RowsAffected() != 0 {
				t.Errorf("as %s: a cross-account UPDATE matched %d rows, want 0",
					role, tag.RowsAffected())
			}
		})
	}
}

// seedAuditRows writes one account_audit_log row per tenant and returns the two
// account ids.
//
// IT SETS AN IDENTITY FOR EACH ROW, AND THAT IS NOT A WORKAROUND — it is the write
// side of the same boundary, arriving in the fixture. `protect_table` names the OWNER
// in every policy (FORCE removed the owner's exemption, so an owner with no identity
// would read nothing at all), which means the owner's INSERT is subject to
// `with check (account_id = (select cafaye.current_account_id()))` too. Seeding
// without an identity fails with:
//
//	ERROR: new row violates row-level security policy for table "account_audit_log"
//	(SQLSTATE 42501)
//
// which is the correct behaviour and the first evidence in this repository that the
// boundary is live: before 00016 that INSERT succeeded. Each row therefore gets its
// own `begin_account` inside the same transaction — `is_local = true` means the value
// is transaction-scoped rather than connection-scoped, so overwriting it per row is
// exactly what it is for and a pooled connection cannot carry it to the next request.
//
// account_audit_log is the table used because 00012 gives it NO foreign keys, so the
// fixture needs no users and no accounts and cannot collide with another package's
// rows in the shared TEST_DATABASE_URL.
func seedAuditRows(t *testing.T, ctx context.Context, conn *pgx.Conn, role string) (tenantA, tenantB string) {
	t.Helper()

	// `gen_random_uuid()` is executable by PUBLIC and reads no table, so this works
	// under either role.
	var ids [2]string
	for i := range ids {
		if err := conn.QueryRow(ctx, `select gen_random_uuid()::text`).Scan(&ids[i]); err != nil {
			t.Fatalf("minting a tenant account id: %v", err)
		}
	}

	for _, id := range ids {
		if _, err := conn.Exec(ctx, `select cafaye.begin_account($1)`, id); err != nil {
			t.Fatalf("setting the identity for the seeded row: %v", err)
		}
		if _, err := conn.Exec(ctx, `
			insert into account_audit_log
				(account_id, action, actor_user_id, actor_key_id, target, affected, trace_id, occurred_at)
			values ($1, 'account.created', gen_random_uuid(), gen_random_uuid(),
			        'seed', 0, 'tenancy-test', now())`, id); err != nil {
			t.Fatalf("seeding account_audit_log for %s: %v", id, err)
		}
	}

	// `set local role` again, because seeding ran under whichever role the caller had
	// already selected and this makes the choice explicit rather than inherited.
	if _, err := conn.Exec(ctx, "set local role "+role); err != nil {
		t.Fatalf("restoring the role under test: %v", err)
	}
	return ids[0], ids[1]
}

func countAuditRows(t *testing.T, ctx context.Context, conn *pgx.Conn) int {
	t.Helper()
	return countAuditRowsIn(t, ctx, conn, "")
}

func countAuditRowsIn(t *testing.T, ctx context.Context, conn *pgx.Conn, accountID string) int {
	t.Helper()
	var n int
	var err error
	if accountID == "" {
		err = conn.QueryRow(ctx,
			`select count(*) from account_audit_log where target = 'seed'`).Scan(&n)
	} else {
		err = conn.QueryRow(ctx,
			`select count(*) from account_audit_log where target = 'seed' and account_id = $1`,
			accountID).Scan(&n)
	}
	if err != nil {
		t.Fatalf("counting account_audit_log rows: %v", err)
	}
	return n
}

// assertComplete — the assertion set is EXACTLY the one assertions.txt names.
//
// Both directions, and both are needed. A missing name means the proof stopped
// asserting something, which a "no failures" assertion would report as a pass. An
// extra name means the proof grew something the driver does not know about, which
// means the driver and the proof have separated and the next edit to either is made
// against a stale idea of the other. A count would not do: a count of 24 is
// compatible with 24 of the wrong 24.
func assertComplete(t *testing.T, got map[string]result) {
	t.Helper()
	want := readManifest(t)

	var missing, unexpected []string
	for _, name := range want {
		if _, ok := got[name]; !ok {
			missing = append(missing, name)
		}
	}
	for name := range got {
		if !contains(want, name) {
			unexpected = append(unexpected, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(unexpected)

	if len(missing) > 0 {
		t.Errorf("the proof did not return %d of the %d assertions it is supposed to make: %s",
			len(missing), len(want), strings.Join(missing, ", "))
		t.Error("  A missing assertion is a green suite proving less than it says. isolation.sql and")
		t.Error("  assertions.txt have drifted apart; isolation.sql is the one that moved.")
	}
	if len(unexpected) > 0 {
		t.Errorf("the proof returned %d assertion(s) assertions.txt does not name: %s",
			len(unexpected), strings.Join(unexpected, ", "))
		t.Error("  A new assertion has to be listed in assertions.txt before it counts, or it is")
		t.Error("  invisible to every service that adopted this.")
	}
}

// assertAllPass — every assertion that came back, and its reason when it did not.
func assertAllPass(t *testing.T, got map[string]result) {
	t.Helper()
	var failed []string
	for name, r := range got {
		if r.verdict != "pass" {
			failed = append(failed, fmt.Sprintf(
				"\n  %s\n    expected %q\n    actual   %q\n    because   %s",
				name, r.expected, r.actual, r.why))
		}
	}
	if len(failed) > 0 {
		sort.Strings(failed)
		t.Errorf("%d of %d account-isolation assertions failed:%s",
			len(failed), len(got), strings.Join(failed, ""))
	}
}

// readManifest — the names assertions.txt lists, comments and blanks dropped.
func readManifest(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(here("assertions.txt"))
	if err != nil {
		t.Fatalf("read assertions.txt: %v", err)
	}
	var names []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		names = append(names, line)
	}
	if len(names) == 0 {
		t.Fatal("assertions.txt lists no assertions, so completeness is satisfied by a proof that returns nothing")
	}
	return names
}

// here — the directory this source file is in.
//
// `runtime.Caller` rather than the working directory, because a test's working
// directory is the package directory only for `go test` in the module root: run from
// elsewhere, and a relative path silently finds nothing.
func here(name string) string {
	_, self, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(self), name)
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
