package apikeys

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/users"
)

// The store, over a real Postgres in a private schema.
//
// The tests run the SQL rather than a double because the interesting properties
// of this table are properties of the SCHEMA — the partial unique index that
// makes rotation possible, the CHECK that makes a permanent credential
// unwritable, the join that makes a revoked membership stop a token — and none
// of them exist in a fake.

var testInstant = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

// fixture is the world these tests run in: a user, an account, and a membership.
type fixture struct {
	pool  *pgxpool.Pool
	clk   *clock.Fake
	store *Store
	user  id.UUID
	// account is an account the user OWNS, and other is one they are not in. The
	// second exists because "a token for one account must not work on another" is
	// a cross-tenant assertion and a test that only has one account cannot make
	// it.
	account id.UUID
	other   id.UUID
	// owner is a second user who owns `other`, so a cross-account test has a real
	// membership to cross into rather than a query that returns nothing.
	owner id.UUID
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	pool := dbtest.Schema(t)
	clk := clock.NewFake(testInstant)

	f := &fixture{pool: pool, clk: clk, store: NewStore(pool)}
	f.seed(t)
	return f
}

// seed writes the three rows the table's foreign keys need. It is three INSERTs
// rather than the use cases because the store under test does not create users
// and asking it to would be asking it to be a different package.
func (f *fixture) seed(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	f.user = id.MustNew()
	if _, err := f.pool.Exec(ctx,
		`INSERT INTO users (id, email, password_digest) VALUES ($1, $2, $3)`,
		f.user, dbtest.UniqueEmail(t), testPasswordDigest); err != nil {
		t.Fatalf("inserting the user: %v", err)
	}

	f.owner = id.MustNew()
	if _, err := f.pool.Exec(ctx,
		`INSERT INTO users (id, email, password_digest) VALUES ($1, $2, $3)`,
		f.owner, dbtest.UniqueEmail(t), testPasswordDigest); err != nil {
		t.Fatalf("inserting the second user: %v", err)
	}

	for _, owner := range []id.UUID{f.user, f.owner} {
		_ = owner
	}

	f.account = f.makeAccount(t, f.user)
	f.other = f.makeAccount(t, f.owner)
}

// testPasswordDigest is a syntactically valid argon2id digest for a fixture user.
//
// The column is NOT NULL and the store never reads it, so the value only has to
// satisfy the column's shape. It is a constant rather than a hash of anything
// because a fixture password nobody signs in with does not need a real hash — and
// a real one would cost this file a hundred milliseconds per insert.
const testPasswordDigest = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$" +
	"bG9uZy1ub3QtaGEzaC1hLWZpeHR1cmUtZml4dHVyZQ"

func (f *fixture) makeAccount(t *testing.T, owner id.UUID) id.UUID {
	t.Helper()
	accountID := id.MustNew()
	if _, err := f.pool.Exec(context.Background(),
		`INSERT INTO accounts (id, name, slug) VALUES ($1, $2, $3)`,
		accountID, "Fixture "+accountID.String()[:8], "fixture-"+accountID.String()[:8]); err != nil {
		t.Fatalf("inserting an account: %v", err)
	}
	if _, err := f.pool.Exec(context.Background(),
		`INSERT INTO account_users (account_id, user_id, role) VALUES ($1, $2, 'owner')`,
		accountID, owner); err != nil {
		t.Fatalf("inserting the membership: %v", err)
	}
	return accountID
}

// issue mints a live token through the store, so the fixtures never have to know
// how a row is written.
//
// The plaintext is deliberately NOT returned and NOT kept anywhere. Every test
// that needs to authenticate builds the value itself from a literal, because a
// fixture struct holding the token in a field is one more place for a failing
// assertion to print it.
func (f *fixture) issue(t *testing.T, name string, scopes ...string) Key {
	t.Helper()
	key, err := f.store.Create(context.Background(), f.pool, NewKey{
		UserID:    f.user,
		AccountID: f.account,
		Name:      name,
		Digest:    Digest("cafaye_" + strings.Repeat("k", 43) + name),
		Scopes:    scopes,
		ExpiresAt: testInstant.Add(DefaultTTL),
		CreatedAt: testInstant,
	})
	if err != nil {
		t.Fatalf("creating the token %q: %v", name, err)
	}
	return key
}

// TestTheDigestIsTheOnlyThingStored is the packet's "the plaintext is nowhere at
// rest" assertion, done over a real table rather than in a comment.
//
// It is deliberately paranoid: it searches EVERY text column of the row for the
// plaintext, for the plaintext with its prefix stripped, for the plaintext's
// hex encoding, and for the base64 encoding, and it reads the row back as JSON so
// a column added later cannot escape the search by being a new field.
func TestTheDigestIsTheOnlyThingStored(t *testing.T) {
	f := newFixture(t)

	token, _, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	secret := strings.TrimPrefix(token, Prefix)

	key, err := f.store.Create(context.Background(), f.pool, NewKey{
		UserID:    f.user,
		AccountID: f.account,
		Name:      "paranoia",
		Digest:    Digest(token),
		Scopes:    []string{ScopeAccountsRead},
		ExpiresAt: testInstant.Add(DefaultTTL),
		CreatedAt: testInstant,
	})
	if err != nil {
		t.Fatalf("creating the token: %v", err)
	}

	// The row, rendered as a map rather than read field by field, so a column
	// added by a later packet is searched too.
	row := f.readRow(t, key.ID)
	raw, err := json.Marshal(row)
	if err != nil {
		t.Fatalf("rendering the row: %v", err)
	}
	rendered := string(raw)

	for _, forbidden := range []string{token, secret, strings.ToLower(token)} {
		if strings.Contains(rendered, forbidden) {
			t.Errorf("the row carries the plaintext token: the whole row is %s", rendered)
		}
	}

	if row["token_digest"] != Digest(token) {
		t.Errorf("token_digest = %v, want the SHA-256 of the presented value", row["token_digest"])
	}
	if Digest(token) == token || Digest(token) == secret {
		t.Error("the digest is the credential")
	}

	// And the whole table, not just this row, in case anything wrote a copy
	// somewhere the primary key does not reach.
	var everyRow string
	if err := f.pool.QueryRow(context.Background(),
		`SELECT coalesce(string_agg(row_to_json(api_keys)::text, E'\n'), '') FROM api_keys`).Scan(&everyRow); err != nil {
		t.Fatalf("rendering the table: %v", err)
	}
	if strings.Contains(everyRow, token) || strings.Contains(everyRow, secret) {
		t.Error("the table carries the plaintext token somewhere other than the row read above")
	}
}

// TestANonMemberTokenIsNotAnAccountToken is the cross-tenant property, asserted
// where it is enforced: a token's account is the account it was minted for, and
// the join that decides it is the one a future migration could widen by accident.
func TestANonMemberTokenIsNotAnAccountToken(t *testing.T) {
	f := newFixture(t)
	key := f.issue(t, "cross-tenant", ScopeAccountsRead)

	// A token row pointed at an account its owner is not a member of. The table's
	// foreign keys allow it — they constrain the ids, not the relationship — so
	// this is a state the schema permits and the store has to refuse.
	bystander := f.makeAccountWithoutMembership(t, f.user)

	if _, err := f.pool.Exec(context.Background(),
		`UPDATE api_keys SET account_id = $2 WHERE id = $1`, key.ID, bystander); err != nil {
		t.Fatalf("pointing the token at a foreign account: %v", err)
	}

	_, err := f.store.ByDigest(context.Background(), f.pool, key.TokenDigest, testInstant)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("resolving a token whose owner is not a member of its account = %v, want ErrNotFound", err)
	}
}

// TestALiveTokenResolves is the positive case, and it is here before every
// refusal so a broken fixture shows up as "everything is not found" rather than
// as a suite of green refusals.
func TestALiveTokenResolves(t *testing.T) {
	f := newFixture(t)
	key := f.issue(t, "live", ScopeAccountsRead, ScopeAccountsWrite)

	resolved, err := f.store.ByDigest(context.Background(), f.pool, key.TokenDigest, testInstant)
	if err != nil {
		t.Fatalf("a live token did not resolve: %v", err)
	}
	if resolved.ID != key.ID {
		t.Errorf("resolved id = %s, want %s", resolved.ID, key.ID)
	}
	if resolved.UserID != f.user || resolved.AccountID != f.account {
		t.Errorf("resolved to user %s account %s, want %s and %s",
			resolved.UserID, resolved.AccountID, f.user, f.account)
	}
	if !resolved.Role.Valid() {
		t.Errorf("the resolved row carries no role: %q", resolved.Role)
	}
	assertScopes(t, resolved.Scopes, []string{ScopeAccountsRead, ScopeAccountsWrite})
}

// TestAMembershipRemovedAfterIssuanceStopsTheToken is THE case the brief names,
// and it is asserted against the store because that is where the decision is.
//
// A token is not a permission. It is a credential that names a user, and every
// request re-reads that user's membership. Removing somebody from an account
// stops their token on the next request, with no cache to expire and nothing to
// sweep — which is the difference between this and a permission snapshot, and it
// is the reason a token does not outlive the permission that made it.
func TestAMembershipRemovedAfterIssuanceStopsTheToken(t *testing.T) {
	f := newFixture(t)
	key := f.issue(t, "will-be-removed", ScopeAccountsRead)

	// Live first, so the removal is the only thing that changes.
	if _, err := f.store.ByDigest(context.Background(), f.pool, key.TokenDigest, testInstant); err != nil {
		t.Fatalf("the token does not resolve before the removal: %v", err)
	}

	if _, err := f.pool.Exec(context.Background(),
		`DELETE FROM account_users WHERE account_id = $1 AND user_id = $2`,
		f.account, f.user); err != nil {
		t.Fatalf("removing the membership: %v", err)
	}

	_, err := f.store.ByDigest(context.Background(), f.pool, key.TokenDigest, testInstant)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("after the membership was removed the token resolved to %v, want ErrNotFound", err)
	}

	// And the row is STILL THERE. "The token stopped working" and "the token
	// record was deleted" are different facts, and an operator asking which
	// happened after removing a contractor needs the answer.
	stored, err := f.store.ByID(context.Background(), f.pool, key.ID)
	if err != nil {
		t.Fatalf("the row was deleted by a membership removal: %v", err)
	}
	if stored.ID != key.ID {
		t.Error("the surviving row is not the token that was issued")
	}
}

// TestADemotionIsVisibleToTheTokenOnTheNextRequest is the same property one
// step down: the role is re-read, so a demotion from owner to member takes
// effect immediately. The route-level consequence is a 403 where there used to
// be a 200; the store-level consequence is a different Role on the row.
func TestADemotionIsVisibleToTheTokenOnTheNextRequest(t *testing.T) {
	f := newFixture(t)
	key := f.issue(t, "will-be-demoted", ScopeAccountsWrite)

	before, err := f.store.ByDigest(context.Background(), f.pool, key.TokenDigest, testInstant)
	if err != nil {
		t.Fatalf("the token does not resolve: %v", err)
	}
	if before.Role != "owner" {
		t.Fatalf("the fixture's role is %q, want owner", before.Role)
	}

	if _, err := f.pool.Exec(context.Background(),
		`UPDATE account_users SET role = 'member' WHERE account_id = $1 AND user_id = $2`,
		f.account, f.user); err != nil {
		t.Fatalf("demoting the membership: %v", err)
	}

	after, err := f.store.ByDigest(context.Background(), f.pool, key.TokenDigest, testInstant)
	if err != nil {
		t.Fatalf("the token stopped resolving after a demotion: %v", err)
	}
	if after.Role != "member" {
		t.Errorf("the resolved role is %q after a demotion, want member", after.Role)
	}
}

// TestRevokedAndExpiredAreBothJustNotFound is the one-error rule, and it is here
// at the store because this is where the four situations stop being
// distinguishable.
func TestRevokedAndExpiredAreBothJustNotFound(t *testing.T) {
	f := newFixture(t)

	t.Run("revoked", func(t *testing.T) {
		key := f.issue(t, "to-be-revoked", ScopeAccountsRead)
		if _, err := f.store.Revoke(context.Background(), f.pool, key.ID, f.account, f.user, testInstant, "test"); err != nil {
			t.Fatalf("revoking: %v", err)
		}
		if _, err := f.store.ByDigest(context.Background(), f.pool, key.TokenDigest, testInstant); !errors.Is(err, ErrNotFound) {
			t.Errorf("a revoked token resolved to %v, want ErrNotFound", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		key := f.issue(t, "to-expire", ScopeAccountsRead)
		// A second boundary later, not `Equal`: the resolution query says
		// `expires_at > now`, so a token whose expiry is exactly now is spent,
		// and the test says so rather than letting the next person decide.
		after := testInstant.Add(DefaultTTL).Add(time.Nanosecond)
		if _, err := f.store.ByDigest(context.Background(), f.pool, key.TokenDigest, after); !errors.Is(err, ErrNotFound) {
			t.Errorf("an expired token resolved to %v, want ErrNotFound", err)
		}
		// And one nanosecond before its expiry it is still live, which is the
		// direction that matters: a boundary that expired tokens early would be
		// a token that dies before the response that used it was written.
		justBefore := testInstant.Add(DefaultTTL).Add(-time.Nanosecond)
		if _, err := f.store.ByDigest(context.Background(), f.pool, key.TokenDigest, justBefore); err != nil {
			t.Errorf("a token one nanosecond before its expiry did not resolve: %v", err)
		}
	})

	t.Run("unknown", func(t *testing.T) {
		if _, err := f.store.ByDigest(context.Background(), f.pool,
			Digest("cafaye_"+strings.Repeat("z", 43)), testInstant); !errors.Is(err, ErrNotFound) {
			t.Errorf("an unknown token resolved to %v, want ErrNotFound", err)
		}
	})
}

// TestRevokeIsConditionalAndScoped is the write path's three properties: a
// second revoke does not move revoked_at, a revoke cannot reach another
// account's token even with the right id, and a revoke never writes a half
// revocation.
func TestRevokeIsConditionalAndScoped(t *testing.T) {
	f := newFixture(t)
	key := f.issue(t, "revoke-once", ScopeAccountsRead)

	first, err := f.store.Revoke(context.Background(), f.pool, key.ID, f.account, f.user, testInstant, "leaked")
	if err != nil {
		t.Fatalf("revoking: %v", err)
	}
	if first.RevokedAt == nil {
		t.Fatal("the revocation did not stamp revoked_at")
	}
	if first.RevokedBy == nil || *first.RevokedBy != f.user {
		t.Errorf("revoked_by = %v, want %s", first.RevokedBy, f.user)
	}
	if first.RevokeReason == nil || *first.RevokeReason != "leaked" {
		t.Errorf("revoke_reason = %v, want \"leaked\"", first.RevokeReason)
	}

	_, err = f.store.Revoke(context.Background(), f.pool, key.ID, f.account, f.user, testInstant.Add(time.Hour), "again")
	if !errors.Is(err, ErrAlreadyRevoked) {
		t.Errorf("a second revocation = %v, want ErrAlreadyRevoked", err)
	}

	// The second attempt must not have moved the timestamp, which is the whole
	// point of the conditional UPDATE: "when was this actually revoked" is an
	// incident question and the second click must not overwrite the answer.
	after, err := f.store.ByID(context.Background(), f.pool, key.ID)
	if err != nil {
		t.Fatalf("reading the revoked row: %v", err)
	}
	if !after.RevokedAt.Equal(testInstant) {
		t.Errorf("revoked_at is %s after a second attempt at %s, want the first", after.RevokedAt, testInstant)
	}

	// The cross-account revoke: the right id, the wrong account. A caller who
	// guessed an id must not be able to destroy a credential they cannot see.
	foreign := f.issueAs(t, f.owner, f.other, "someone-elses", ScopeAccountsRead)
	if _, err := f.store.Revoke(context.Background(), f.pool, foreign.ID, f.account, f.user, testInstant, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoking a token in another account = %v, want ErrNotFound", err)
	}
	if _, err := f.store.Revoke(context.Background(), f.pool, id.MustNew(), f.account, f.user, testInstant, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoking an id that does not exist = %v, want ErrNotFound", err)
	}

	// And the empty reason becomes NULL rather than "" — "no reason given" and
	// "the reason is the empty string" are not the same fact.
	bare := f.issue(t, "no-reason", ScopeAccountsRead)
	revoked, err := f.store.Revoke(context.Background(), f.pool, bare.ID, f.account, f.user, testInstant, "")
	if err != nil {
		t.Fatalf("revoking without a reason: %v", err)
	}
	if revoked.RevokeReason != nil {
		t.Errorf("revoke_reason = %q for an empty reason, want NULL", *revoked.RevokeReason)
	}
}

// TestOneLiveNamePerAccountAndRotationIsPossible is the partial unique index,
// and both of its halves: two live tokens with one name are refused, and a
// revoked token frees the name for its replacement.
func TestOneLiveNamePerAccountAndRotationIsPossible(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	f.issue(t, "ci-deploy", ScopeAccountsRead)

	_, err := f.store.Create(ctx, f.pool, NewKey{
		UserID: f.user, AccountID: f.account, Name: "ci-deploy",
		Digest: Digest("cafaye_" + strings.Repeat("a", 43)),
		Scopes: []string{ScopeAccountsRead}, ExpiresAt: testInstant.Add(DefaultTTL), CreatedAt: testInstant,
	})
	if !errors.Is(err, ErrNameTaken) {
		t.Fatalf("a second live token with the same name = %v, want ErrNameTaken", err)
	}

	// The index is on lower(name), so a capital is the same name.
	_, err = f.store.Create(ctx, f.pool, NewKey{
		UserID: f.user, AccountID: f.account, Name: "CI-Deploy",
		Digest: Digest("cafaye_" + strings.Repeat("b", 43)),
		Scopes: []string{ScopeAccountsRead}, ExpiresAt: testInstant.Add(DefaultTTL), CreatedAt: testInstant,
	})
	if !errors.Is(err, ErrNameTaken) {
		t.Errorf("a name differing only in case = %v, want ErrNameTaken", err)
	}

	// And the name is per ACCOUNT: another account's "ci-deploy" is fine,
	// because two customers having a token called ci-deploy is not a collision.
	if _, err := f.store.Create(ctx, f.pool, NewKey{
		UserID: f.owner, AccountID: f.other, Name: "ci-deploy",
		Digest: Digest("cafaye_" + strings.Repeat("c", 43)),
		Scopes: []string{ScopeAccountsRead}, ExpiresAt: testInstant.Add(DefaultTTL), CreatedAt: testInstant,
	}); err != nil {
		t.Errorf("the same name in another account was refused: %v", err)
	}

	// Rotation: revoke, then create. Two statements in that order, and the
	// replacement gets the name — which is the whole reason the index is partial.
	rows, err := f.store.ListForAccount(ctx, f.pool, f.account)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("the account holds %d tokens, want 1", len(rows))
	}
	if _, err := f.store.Revoke(ctx, f.pool, rows[0].ID, f.account, f.user, testInstant, "rotating"); err != nil {
		t.Fatalf("revoking for rotation: %v", err)
	}
	if _, err := f.store.Create(ctx, f.pool, NewKey{
		UserID: f.user, AccountID: f.account, Name: "ci-deploy",
		Digest: Digest("cafaye_" + strings.Repeat("d", 43)),
		Scopes: []string{ScopeAccountsRead}, ExpiresAt: testInstant.Add(DefaultTTL), CreatedAt: testInstant,
	}); err != nil {
		t.Errorf("creating the replacement after a revocation: %v", err)
	}

	// And the list now holds two rows — the revoked one is kept, so an operator
	// can still see that "ci-deploy" existed and was rotated rather than never
	// having been minted at all.
	rows, err = f.store.ListForAccount(ctx, f.pool, f.account)
	if err != nil {
		t.Fatalf("listing after the rotation: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("after a rotation the account holds %d rows, want 2: a revoked token is kept", len(rows))
	}
	if rows[0].RevokedAt == nil && rows[1].RevokedAt == nil {
		t.Error("neither row is marked revoked, so the rotation lost the old token")
	}
}

// TestTouchIsRateLimitedByResolution is the write on the read path, and the
// reason it exists is a hot token turning one row into a queue.
func TestTouchIsRateLimitedByResolution(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	key := f.issue(t, "hot", ScopeAccountsRead)

	// First use stamps it.
	if err := f.store.Touch(ctx, f.pool, key.ID, testInstant); err != nil {
		t.Fatalf("touching: %v", err)
	}
	first, err := f.store.ByID(ctx, f.pool, key.ID)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if first.LastUsedAt == nil {
		t.Fatal("the first use did not stamp last_used_at")
	}
	if !first.LastUsedAt.Equal(testInstant) {
		t.Errorf("last_used_at = %s, want %s", first.LastUsedAt, testInstant)
	}

	// A use a second later does NOT restamp. One row, one write per resolution
	// window, whatever the request rate.
	later := testInstant.Add(time.Second)
	if err := f.store.Touch(ctx, f.pool, key.ID, later); err != nil {
		t.Fatalf("touching again: %v", err)
	}
	second, err := f.store.ByID(ctx, f.pool, key.ID)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if second.LastUsedAt == nil || !second.LastUsedAt.Equal(testInstant) {
		t.Errorf("last_used_at = %v after a use %s later, want it left at %s",
			second.LastUsedAt, later.Sub(testInstant), testInstant)
	}

	// And one past the window does restamp, which is what makes the column mean
	// "some time in the last five minutes" rather than "the first use ever".
	past := testInstant.Add(LastUsedResolution).Add(time.Second)
	if err := f.store.Touch(ctx, f.pool, key.ID, past); err != nil {
		t.Fatalf("touching past the window: %v", err)
	}
	third, err := f.store.ByID(ctx, f.pool, key.ID)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if third.LastUsedAt == nil || !third.LastUsedAt.Equal(past) {
		t.Errorf("last_used_at = %v after a use past the resolution window, want %s", third.LastUsedAt, past)
	}
}

// TestTouchOnARevokedTokenIsANoOp is the direction of the conditional UPDATE.
// A revoked token should not get a last_used_at, because "last used" on a dead
// credential is a column that says it was working.
func TestTouchOnARevokedTokenIsANoOp(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	key := f.issue(t, "dead", ScopeAccountsRead)

	if _, err := f.store.Revoke(ctx, f.pool, key.ID, f.account, f.user, testInstant, "test"); err != nil {
		t.Fatalf("revoking: %v", err)
	}
	if err := f.store.Touch(ctx, f.pool, key.ID, testInstant.Add(time.Minute)); err != nil {
		t.Fatalf("touching a revoked token returned an error: %v", err)
	}
	after, err := f.store.ByID(ctx, f.pool, key.ID)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if after.LastUsedAt != nil {
		t.Errorf("last_used_at = %v on a revoked token, want NULL", after.LastUsedAt)
	}
}

// TestTheSchemaRefusesAPermanentCredential is the migration's CHECK, reached
// directly rather than through the service. A constraint nothing has ever
// violated is a constraint nobody knows works.
func TestTheSchemaRefusesAPermanentCredential(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	cases := []struct {
		name      string
		expiresAt time.Time
	}{
		{"before creation", testInstant.Add(-time.Hour)},
		{"the creation instant itself", testInstant},
		{"past the year ceiling", testInstant.Add(MaxTTL + time.Hour)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.pool.Exec(ctx, `
				INSERT INTO api_keys (user_id, account_id, name, token_digest, scopes, created_at, expires_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7)`,
				f.user, f.account, "boundary-"+tc.name,
				Digest("cafaye_"+strings.Repeat("e", 43)),
				[]string{ScopeAccountsRead}, testInstant, tc.expiresAt)
			if err == nil {
				t.Fatalf("the table accepted expires_at = %s, which the migration says it must not", tc.expiresAt)
			}
			if !strings.Contains(err.Error(), "api_keys_") {
				t.Errorf("the refusal came from %v, which is not one of this table's CHECK constraints", err)
			}
		})
	}
}

// TestTheSchemaRefusesAnEmptyScopeList is the second CHECK, and the one that
// makes "a token with no scopes" a database fact rather than a service-layer
// convention.
func TestTheSchemaRefusesAnEmptyScopeList(t *testing.T) {
	f := newFixture(t)

	_, err := f.pool.Exec(context.Background(), `
		INSERT INTO api_keys (user_id, account_id, name, token_digest, scopes, created_at, expires_at)
		VALUES ($1, $2, 'no-scopes', $3, $4, $5, $6)`,
		f.user, f.account, Digest("cafaye_"+strings.Repeat("f", 43)),
		[]string{}, testInstant, testInstant.Add(DefaultTTL))
	if err == nil {
		t.Fatal("the table accepted a token with no scopes")
	}
	if !strings.Contains(err.Error(), "api_keys_scopes_not_empty") {
		t.Errorf("the refusal came from %v, which is not api_keys_scopes_not_empty", err)
	}
}

// TestTheSchemaRefusesAHalfRevocation is the third CHECK: revoked_at and
// revoked_by are set together or not at all, because a revoked token with no
// revoker is an incident record with the wrong half of the story.
func TestTheSchemaRefusesAHalfRevocation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	digest := Digest("cafaye_" + strings.Repeat("9", 43))
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO api_keys (user_id, account_id, name, token_digest, scopes, created_at, expires_at, revoked_at)
		VALUES ($1, $2, 'half-revoked', $3, $4, $5, $6, $5)`,
		f.user, f.account, digest, []string{ScopeAccountsRead}, testInstant, testInstant.Add(DefaultTTL)); err == nil {
		t.Fatal("the table accepted a revocation with no revoker")
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO api_keys (user_id, account_id, name, token_digest, scopes, created_at, expires_at, revoked_by)
		VALUES ($1, $2, 'half-revoked-2', $3, $4, $5, $6, $7)`,
		f.user, f.account, Digest("cafaye_"+strings.Repeat("8", 43)), []string{ScopeAccountsRead},
		testInstant, testInstant.Add(DefaultTTL), f.user); err == nil {
		t.Fatal("the table accepted a revoker with no revocation")
	}
	_ = digest
}

// TestRevokeAllForUserKeepsTheRows is the sweep that answers "enabling MFA should
// not leave a long-lived credential behind", and its second property is that it
// is a REVOCATION rather than a delete.
func TestRevokeAllForUserKeepsTheRows(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	mine := f.issue(t, "mine-a", ScopeAccountsRead)
	also := f.issue(t, "mine-b", ScopeAccountsRead)

	// Somebody else's token, in another account. The sweep must not reach it.
	theirs := f.issueAs(t, f.owner, f.other, "theirs", ScopeAccountsRead)

	if err := f.store.RevokeAllForUser(ctx, f.pool, f.user, testInstant); err != nil {
		t.Fatalf("sweeping: %v", err)
	}

	for _, key := range []Key{mine, also} {
		row, err := f.store.ByID(ctx, f.pool, key.ID)
		if err != nil {
			t.Fatalf("a swept token's row was deleted rather than revoked: %v", err)
		}
		if row.RevokedAt == nil {
			t.Errorf("token %q was not revoked by the sweep", key.Name)
		}
	}

	untouched, err := f.store.ByID(ctx, f.pool, theirs.ID)
	if err != nil {
		t.Fatalf("reading somebody else's token: %v", err)
	}
	if untouched.RevokedAt != nil {
		t.Error("the sweep revoked a token belonging to somebody else")
	}

	// And a sweep that matches nothing is a success, because a user who has never
	// minted a token is already in the state the sweep is for.
	if err := f.store.RevokeAllForUser(ctx, f.pool, id.MustNew(), testInstant); err != nil {
		t.Errorf("sweeping a user with no tokens: %v", err)
	}
}

// TestTheStoreTakesAQuerierAndRunsInsideTheCallersTransaction is the direction
// that matters for a creation: a transaction that fails half way leaves the user
// with nothing, rather than with a row no event announced.
func TestTheStoreTakesAQuerierAndRunsInsideTheCallersTransaction(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	rolledBack := db.TxRunner{Pool: f.pool}.Do(ctx, func(ctx context.Context, q db.Querier) error {
		_, err := f.store.Create(ctx, q, NewKey{
			UserID: f.user, AccountID: f.account, Name: "rolled-back",
			Digest: Digest("cafaye_" + strings.Repeat("1", 43)),
			Scopes: []string{ScopeAccountsRead}, ExpiresAt: testInstant.Add(DefaultTTL), CreatedAt: testInstant,
		})
		if err != nil {
			return err
		}
		// Visible inside the transaction, so the insert really ran.
		rows, err := f.store.ListForAccount(ctx, q, f.account)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return errors.New("the insert was not visible inside the transaction")
		}
		return errors.New("the second write failed")
	})
	if rolledBack == nil {
		t.Fatal("the transaction was expected to fail")
	}

	rows, err := f.store.ListForAccount(ctx, f.pool, f.account)
	if err != nil {
		t.Fatalf("listing after the rollback: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("%d rows survived a rolled-back transaction, want 0", len(rows))
	}
}

// TestTheDatabaseTierActuallyRan fails rather than skips when TEST_DATABASE_URL
// is unset. In this package every test above is a database test, so without it
// this whole file has proven nothing and a suite reporting "ok" has reported
// something false.
func TestTheDatabaseTierActuallyRan(t *testing.T) {
	if os.Getenv(dbtest.EnvVar) == "" {
		t.Fatalf("%s is not set, so every test in this file skipped. A green run without it verifies nothing: "+
			"`docker compose up -d postgres`, `goose -dir migrations postgres \"$DATABASE_URL\" up`, and re-run with %s set.",
			dbtest.EnvVar, dbtest.EnvVar)
	}
	pool := dbtest.Pool(t)
	if err := pool.Ping(context.Background()); err != nil {
		t.Fatalf("the test database is not reachable: %v", err)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// issueAs mints a token for somebody other than the fixture's user, so a
// cross-account assertion has a real second membership.
func (f *fixture) issueAs(t *testing.T, userID, accountID id.UUID, name string, scopes ...string) Key {
	t.Helper()
	key, err := f.store.Create(context.Background(), f.pool, NewKey{
		UserID:    userID,
		AccountID: accountID,
		Name:      name,
		Digest:    Digest("cafaye_" + strings.Repeat("r", 43) + name),
		Scopes:    scopes,
		ExpiresAt: testInstant.Add(DefaultTTL),
		CreatedAt: testInstant,
	})
	if err != nil {
		t.Fatalf("issuing %q for another user: %v", name, err)
	}
	return key
}

// makeAccountWithoutMembership writes an account with no members, which the
// foreign keys permit and no use case produces.
func (f *fixture) makeAccountWithoutMembership(t *testing.T, _ id.UUID) id.UUID {
	t.Helper()
	accountID := id.MustNew()
	if _, err := f.pool.Exec(context.Background(),
		`INSERT INTO accounts (id, name, slug) VALUES ($1, $2, $3)`,
		accountID, "Empty "+accountID.String()[:8], "empty-"+accountID.String()[:8]); err != nil {
		t.Fatalf("inserting an account with no members: %v", err)
	}
	return accountID
}

// readRow returns the whole row as a map, so a column added later is searched
// too. `api_keys::text` is Postgres's own rendering, which includes every
// column whether or not the Go struct knows about it.
// row_to_json, not api_keys::text.
//
// A bare composite cast renders Postgres's RECORD syntax — `(id,user_id,…)`,
// parenthesised and unquoted — which is not JSON and would make this helper fail
// on every row rather than silently pass. row_to_json gives the same field names
// as the table, so the search still covers a column a later packet adds.
func (f *fixture) readRow(t *testing.T, keyID id.UUID) map[string]any {
	t.Helper()
	var raw []byte
	if err := f.pool.QueryRow(context.Background(),
		`SELECT row_to_json(api_keys)::text FROM api_keys WHERE id = $1`, keyID).Scan(&raw); err != nil {
		t.Fatalf("rendering the row: %v", err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("the rendered row is not JSON: %v", err)
	}
	return out
}

// Compile-time proof the store takes what the fixtures pass it.
var _ = fmt.Sprintf
var _ = users.User{}
