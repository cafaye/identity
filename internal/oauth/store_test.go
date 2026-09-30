package oauth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/users"
)

// Integration tests: they need a real Postgres with the migrations applied. See
// dbtest.Schema for the gate and migrations/README.md for the setup.
//
// They run in a private schema rather than against the shared one. A unique email
// is enough isolation for rows this service identifies by address; it is not
// enough for rows identified by (provider, provider_uid), because several of
// these tests deliberately reuse the same uid to prove the unique index fires.

func newAccountUser(t *testing.T, pool *pgxpool.Pool) id.UUID {
	t.Helper()

	u, err := users.NewStore(pool).Create(context.Background(), pool, users.CreateParams{
		Email:          dbtest.UniqueEmail(t),
		PasswordDigest: "$argon2id$fake",
	})
	if err != nil {
		t.Fatalf("creating the user to link to: %v", err)
	}
	return u.ID
}

func TestStoreCreateAndReadBack(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	ctx := context.Background()

	userID := newAccountUser(t, pool)
	expiresAt := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

	created, err := store.Create(ctx, pool, NewAccount{
		UserID:                 userID,
		Provider:               ProviderGoogle,
		ProviderUID:            "107346492749283471920",
		AccessTokenCiphertext:  "v1.abcdef",
		RefreshTokenCiphertext: "v1.abcdef",
		ExpiresAt:              &expiresAt,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if created.ID.IsZero() {
		t.Error("Create returned a zero id")
	}
	if created.UserID != userID {
		t.Errorf("UserID = %s, want %s", created.UserID, userID)
	}
	if created.Provider != ProviderGoogle {
		t.Errorf("Provider = %q, want %q", created.Provider, ProviderGoogle)
	}
	if created.ProviderUID != "107346492749283471920" {
		t.Errorf("ProviderUID = %q, want it stored verbatim", created.ProviderUID)
	}
	if created.ExpiresAt == nil || !created.ExpiresAt.Equal(expiresAt) {
		t.Errorf("ExpiresAt = %v, want %s", created.ExpiresAt, expiresAt)
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Errorf("timestamps not set: created_at=%v updated_at=%v", created.CreatedAt, created.UpdatedAt)
	}

	found, err := store.ByProviderUID(ctx, pool, ProviderGoogle, "107346492749283471920")
	if err != nil {
		t.Fatalf("ByProviderUID: %v", err)
	}
	if found.ID != created.ID {
		t.Errorf("ByProviderUID returned id %s, want %s", found.ID, created.ID)
	}
}

// GitHub issues no refresh token by default, and that has to be stored as NULL
// rather than as "". An empty string is not a value either caller can act on:
// it looks refreshable, and it is not.
func TestStoreCreateStoresNullForAMissingRefreshToken(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	ctx := context.Background()

	userID := newAccountUser(t, pool)

	created, err := store.Create(ctx, pool, NewAccount{
		UserID:                userID,
		Provider:              ProviderGitHub,
		ProviderUID:           "583231",
		AccessTokenCiphertext: "v1.abcdef",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.RefreshTokenCiphertext != "" {
		t.Errorf("RefreshTokenCiphertext = %q, want empty for SQL NULL", created.RefreshTokenCiphertext)
	}

	round, err := store.ByProviderUID(ctx, pool, ProviderGitHub, "583231")
	if err != nil {
		t.Fatalf("ByProviderUID: %v", err)
	}
	if round.RefreshTokenCiphertext != "" {
		t.Errorf("the read-back row has RefreshTokenCiphertext = %q, want empty", round.RefreshTokenCiphertext)
	}
	if round.ExpiresAt != nil {
		t.Errorf("ExpiresAt = %v, want nil when the provider issues no expiry", *round.ExpiresAt)
	}
}

// The uniqueness that matters is (provider, provider_uid). Without it two users
// could both "own" one social identity, and the second login through it would be a
// silent account takeover.
func TestStoreCreateRejectsTheSameProviderIdentityTwice(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	ctx := context.Background()

	first := newAccountUser(t, pool)
	second := newAccountUser(t, pool)

	params := NewAccount{
		UserID:                first,
		Provider:              ProviderGoogle,
		ProviderUID:           "the-same-person",
		AccessTokenCiphertext: "v1.abcdef",
	}
	if _, err := store.Create(ctx, pool, params); err != nil {
		t.Fatalf("first Create: %v", err)
	}

	params.UserID = second
	_, err := store.Create(ctx, pool, params)
	if !errors.Is(err, ErrAlreadyLinked) {
		t.Fatalf("second Create = %v, want errors.Is(_, ErrAlreadyLinked)", err)
	}

	// And the row still belongs to the first user: a rejected insert must not
	// leave a half-attached account behind.
	owner, err := store.ByProviderUID(ctx, pool, ProviderGoogle, "the-same-person")
	if err != nil {
		t.Fatalf("ByProviderUID: %v", err)
	}
	if owner.UserID != first {
		t.Errorf("the account is owned by %s, want %s", owner.UserID, first)
	}
}

// The same numeric id at two different providers is two different people. GitHub
// user 583231 and Google sub 583231 share nothing, and a uniqueness rule that
// ignored the provider would refuse one of two legitimate sign-ins.
func TestStoreTheSameUIDOnTwoProvidersIsTwoAccounts(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	ctx := context.Background()

	userID := newAccountUser(t, pool)

	for _, provider := range []string{ProviderGoogle, ProviderGitHub} {
		if _, err := store.Create(ctx, pool, NewAccount{
			UserID:                userID,
			Provider:              provider,
			ProviderUID:           "583231",
			AccessTokenCiphertext: "v1.abcdef",
		}); err != nil {
			t.Errorf("Create for %s: %v", provider, err)
		}
	}
}

// The enum is a real database guarantee: a provider this service does not offer
// cannot be written at all, which is stronger than any check the Go code makes.
func TestStoreCreateRefusesAProviderOutsideTheEnum(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	ctx := context.Background()

	_, err := store.Create(ctx, pool, NewAccount{
		UserID:                newAccountUser(t, pool),
		Provider:              "apple",
		ProviderUID:           "001234",
		AccessTokenCiphertext: "v1.abcdef",
	})
	if err == nil {
		t.Fatal("Create accepted a provider outside the oauth_provider enum")
	}
	// Not a conflict: the row was never a duplicate, it was never valid.
	if errors.Is(err, ErrAlreadyLinked) {
		t.Errorf("an out-of-enum provider reported as ErrAlreadyLinked: %v", err)
	}
}

func TestStoreLookupsMissCleanly(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	ctx := context.Background()

	if _, err := store.ByProviderUID(ctx, pool, ProviderGoogle, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Errorf("ByProviderUID on a missing row = %v, want errors.Is(_, ErrNotFound)", err)
	}
}

// Every OAuth login refreshes the stored token, so this is on the hot path and not
// an administrative edit. A refresh must not disturb the link itself.
func TestStoreRefreshTokens(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	ctx := context.Background()

	userID := newAccountUser(t, pool)
	created, err := store.Create(ctx, pool, NewAccount{
		UserID:                userID,
		Provider:              ProviderGoogle,
		ProviderUID:           "107346492749283471920",
		AccessTokenCiphertext: "v1.first-access",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	expiresAt := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	if err := store.RefreshTokens(ctx, pool, created.ID, StoredTokens{
		AccessTokenCiphertext:  "v1.second-access",
		RefreshTokenCiphertext: "v1.first-refresh",
		ExpiresAt:              &expiresAt,
	}); err != nil {
		t.Fatalf("RefreshTokens: %v", err)
	}

	got, err := store.ByProviderUID(ctx, pool, ProviderGoogle, "107346492749283471920")
	if err != nil {
		t.Fatalf("ByProviderUID: %v", err)
	}
	if got.AccessTokenCiphertext != "v1.second-access" {
		t.Errorf("AccessTokenCiphertext = %q, want the refreshed value", got.AccessTokenCiphertext)
	}
	if got.RefreshTokenCiphertext != "v1.first-refresh" {
		t.Errorf("RefreshTokenCiphertext = %q, want the newly issued one", got.RefreshTokenCiphertext)
	}
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(expiresAt) {
		t.Errorf("ExpiresAt = %v, want %s", got.ExpiresAt, expiresAt)
	}
	// The link is unchanged.
	if got.UserID != userID || got.ProviderUID != created.ProviderUID || got.ID != created.ID {
		t.Errorf("RefreshTokens moved the link: %+v", got)
	}
}

// Google does not reissue a refresh token on every exchange, so a provider that
// omits it must leave the stored one in place. Writing NULL would silently
// downgrade an account to a credential that dies in an hour with no way back.
func TestStoreRefreshTokensKeepsAnExistingRefreshTokenWhenNoneIsIssued(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	ctx := context.Background()

	created, err := store.Create(ctx, pool, NewAccount{
		UserID:                 newAccountUser(t, pool),
		Provider:               ProviderGoogle,
		ProviderUID:            "107346492749283471920",
		AccessTokenCiphertext:  "v1.first-access",
		RefreshTokenCiphertext: "v1.the-refresh",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := store.RefreshTokens(ctx, pool, created.ID, StoredTokens{AccessTokenCiphertext: "v1.second-access"}); err != nil {
		t.Fatalf("RefreshTokens: %v", err)
	}

	got, err := store.ByProviderUID(ctx, pool, ProviderGoogle, "107346492749283471920")
	if err != nil {
		t.Fatalf("ByProviderUID: %v", err)
	}
	if got.RefreshTokenCiphertext != "v1.the-refresh" {
		t.Errorf("RefreshTokenCiphertext = %q, want the stored one kept", got.RefreshTokenCiphertext)
	}
}

func TestStoreRefreshTokensMissesCleanly(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)

	err := store.RefreshTokens(context.Background(), pool, id.MustNew(), StoredTokens{
		AccessTokenCiphertext: "v1.abcdef",
	})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("RefreshTokens on a missing row = %v, want errors.Is(_, ErrNotFound)", err)
	}
}

// A deleted user has no connected accounts. The cascade is what frees the
// provider uid so that the same person can sign up again later.
func TestStoreDeleteUserCascades(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	ctx := context.Background()

	userID := newAccountUser(t, pool)
	if _, err := store.Create(ctx, pool, NewAccount{
		UserID:                userID,
		Provider:              ProviderGoogle,
		ProviderUID:           "107346492749283471920",
		AccessTokenCiphertext: "v1.abcdef",
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID); err != nil {
		t.Fatalf("deleting the user: %v", err)
	}

	if _, err := store.ByProviderUID(ctx, pool, ProviderGoogle, "107346492749283471920"); !errors.Is(err, ErrNotFound) {
		t.Errorf("the connected account survived the user: %v", err)
	}
}

// The store detects a duplicate on SQLSTATE 23505 alone, which is only sound while
// the table has exactly one application-level unique index. This is what makes
// that assumption self-enforcing — the same guard internal/users carries.
func TestConnectedAccountsHasExactlyOneApplicationUniqueIndex(t *testing.T) {
	pool := dbtest.Schema(t)

	rows, err := pool.Query(context.Background(), `
		SELECT a.attname
		FROM pg_index i
		JOIN pg_class c ON c.oid = i.indexrelid
		JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0]
		WHERE i.indrelid = 'connected_accounts'::regclass AND i.indisunique AND NOT i.indisprimary
		ORDER BY a.attname`)
	if err != nil {
		t.Fatalf("listing unique indexes on connected_accounts: %v", err)
	}
	defer rows.Close()

	var columns []string
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			t.Fatalf("scanning an index column: %v", err)
		}
		columns = append(columns, column)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("reading the index list: %v", err)
	}

	if len(columns) != 1 || columns[0] != "provider" {
		t.Errorf("connected_accounts has application-level unique indexes on %v, want exactly one on "+
			"provider. The duplicate detection matches on SQLSTATE 23505 alone and can no longer tell a "+
			"re-linked provider identity from a violation of a new constraint", columns)
	}
}

// A provider uid is whatever the provider says it is, so its length is the only
// bound available. The CHECK is the last line of defence for an index entry.
func TestStoreCreateEnforcesTheProviderUIDLength(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	ctx := context.Background()

	userID := newAccountUser(t, pool)

	for _, uid := range []string{"", strings.Repeat("x", 256)} {
		_, err := store.Create(ctx, pool, NewAccount{
			UserID:                userID,
			Provider:              ProviderGoogle,
			ProviderUID:           uid,
			AccessTokenCiphertext: "v1.abcdef",
		})
		if err == nil {
			t.Errorf("Create accepted a %d-character provider_uid", len(uid))
		}
	}
}
