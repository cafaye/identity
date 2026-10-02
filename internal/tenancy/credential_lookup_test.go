package tenancy

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestTenancyACredentialLookupHasNoIdentityToRunUnder pins a MEASURED LIMITATION
// of the substrate, and it is here because the limitation is invisible to every
// other test in this repository.
//
// # WHAT IS PINNED
//
// `api_keys` is protected by 00016. A scoped token is resolved by digest:
//
//	SELECT … FROM api_keys k JOIN account_users au ON … WHERE k.token_digest = $1
//
// There is NO `account_id = $2` in that WHERE, and there cannot be one: the query
// has no account to predicate on, because the account is what the query is FOR. A
// token resolves to a key, and the key carries the account id that later
// authorizes the request.
//
// Under per-request row-level security that query is unanswerable before the
// account is known. Measured on this cluster, as the OWNER role, against the real
// protected table:
//
//	no identity at all                              ->  0 rows
//	identity = the credential's own account          ->  1 row
//	identity = A, reading another tenant's credential ->  0 rows
//
// The first line is the finding: with no identity set — which is the state a
// request presenting a scoped token is in, because it has not resolved the token
// yet — the lookup that authenticates the caller reads nothing. Every scoped token
// would be refused, and refused as NOT FOUND rather than as an error, because
// `apikeys.ByDigest` maps `pgx.ErrNoRows` to `ErrNotFound` and the HTTP layer maps
// that to 401.
//
// # WHY NO OTHER TEST SEES IT
//
// Every integration test that drives an account-scoped route builds its fixtures
// with `dbtest.Schema(t)`, which clones tables with `LIKE … INCLUDING ALL`. LIKE
// does not copy row-level security, so a private fixture schema has an
// `account_id` column and NO policies — the RLS half of the service is simply
// absent from those tests. They pass with the wiring, and they would pass with NO
// wiring at all. That is not a criticism of them: they were written to prove
// authorization answers, and they do. It is the reason this test has to exist and
// state the limitation in a place a reader will meet it while looking at the
// proofs.
//
// # THIS IS A CHARACTERISATION, NOT A REQUIREMENT
//
// It asserts what the substrate does today, and it is GREEN while asserting it.
// It is NOT claiming token authentication works. It is pinning a number so that:
//
//   - the number is checkable rather than remembered, and
//   - whoever fixes this — by exempting the credential lookup, by giving the
//     resolution a shape the boundary can express, or by deciding the owner
//     exemption is correct for a table whose access path is a secret digest —
//     gets a RED test naming exactly what changed.
//
// The decision is not a service's: it forks "FORCE ROW LEVEL SECURITY is not
// optional", which is kit's rule. See HANDOFF-identity-isolation.md.
func TestTenancyACredentialLookupHasNoIdentityToRunUnder(t *testing.T) {
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
	defer conn.Close(ctx)

	// The fixture uses account_audit_log for the cross-tenant half, because it has
	// no foreign keys and needs no users. But the lookup under test is the shape of
	// api_keys.ByDigest — a row addressed by a value that is NOT the account — and
	// that shape is the point, so it is exercised on api_keys itself, with real
	// foreign keys, because a fixture that dodged them would not be the query.

	// Seed two accounts, each with a user and a key, setting the identity per row
	// the way every write in this repository must now.
	tenantA, tenantB := seedCredentialRows(t, ctx, conn)

	// 1. No identity. This is the state a request presenting a scoped token is in:
	//    it has not looked the token up yet, so it cannot have an account.
	//
	//    AUTOCOMMIT IS CORRECT HERE AND ONLY HERE. `begin_account` is
	//    `set_config(…, is_local => true)`, which outside an explicit transaction
	//    expires at the end of the statement that set it — so an identity cannot be
	//    carried into a later statement on the same connection at all. Cases 2 and 3
	//    below therefore open a real transaction, and this one deliberately does
	//    not: "no identity at all" is only expressible in autocommit.
	var seen int
	if err := conn.QueryRow(ctx,
		`select count(*) from api_keys where token_digest = $1`, digestFor(tenantA)).Scan(&seen); err != nil {
		t.Fatalf("counting api_keys with no identity: %v", err)
	}
	if seen != 0 {
		t.Errorf("a credential lookup with NO identity saw %d rows, want 0.\n"+
			"  This is the limitation this test pins: the query that authenticates a scoped token has no\n"+
			"  account to predicate on, so row-level security has nothing to scope it to. If this is now 1,\n"+
			"  something changed — say so here and in HANDOFF-identity-isolation.md rather than leaving a\n"+
			"  stale claim that token auth is broken when it is not.", seen)
	}

	// 2. Its own account: the identity a request would have AFTER resolving the
	//    token. This must keep working — it is the half that is not broken, and a
	//    test that only asserted the first case would pass on a table whose policy
	//    permits nothing at all.
	seen = 0
	if err := countAsAccount(ctx, conn, tenantA, digestFor(tenantA), &seen); err != nil {
		t.Fatalf("counting api_keys with its own identity: %v", err)
	}
	if seen != 1 {
		t.Errorf("a credential lookup with the credential's OWN account saw %d rows, want 1: the working half "+
			"of this lookup has to keep working, or the limitation above is being described as the whole story", seen)
	}

	// 3. The other tenant's credential, under this identity. Absence, not refusal —
	//    the cross-tenant property the rest of this package proves.
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
// accountID, which is the only way a lookup can carry an identity at all.
//
// It is a function rather than three inline blocks because the transaction is the
// subtlety: an identity set outside one silently evaporates, and a test written in
// autocommit would report a broken boundary where there is only a broken test.
// That is not hypothetical — this helper exists because the first version of this
// file made exactly that mistake and reported a false failure.
func countAsAccount(ctx context.Context, conn *pgx.Conn, accountID, digest string, out *int) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning a transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `select cafaye.begin_account($1)`, accountID); err != nil {
		return fmt.Errorf("setting the identity: %w", err)
	}
	if err := tx.QueryRow(ctx,
		`select count(*) from api_keys where token_digest = $1`, digest).Scan(out); err != nil {
		return fmt.Errorf("counting api_keys: %w", err)
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
func seedCredentialRows(t *testing.T, ctx context.Context, conn *pgx.Conn) (tenantA, tenantB string) {
	t.Helper()

	ids := map[string]*string{"a": &tenantA, "b": &tenantB}
	for label, out := range ids {
		if err := conn.QueryRow(ctx, `select gen_random_uuid()::text`).Scan(out); err != nil {
			t.Fatalf("minting tenant %s ids: %v", label, err)
		}
	}

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
		if _, err := tx.Exec(ctx, `insert into api_keys
			(user_id, account_id, name, token_digest, scopes, expires_at)
			values ($1, $2, 'fixture', $3, array['accounts:read'], $4)`,
			userID, accountID, digestFor(accountID), time.Now().Add(24*time.Hour)); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("inserting a fixture api key: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("committing tenant %s: %v", accountID[:8], err)
		}
	}

	t.Cleanup(func() {
		// Cleaned up by account, so a fixture cannot outlive the run and collide
		// with the next one. accounts cascades to api_keys through the foreign key.
		for _, accountID := range []string{tenantA, tenantB} {
			_, _ = conn.Exec(context.Background(), `delete from accounts where id = $1`, accountID)
		}
	})

	return tenantA, tenantB
}

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
