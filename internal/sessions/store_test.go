package sessions

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/users"
)

var issuedAt = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

func newTestUser(t *testing.T, pool *pgxpool.Pool) users.User {
	t.Helper()

	u, err := users.NewStore(pool).Create(context.Background(), pool, users.CreateParams{
		Email:          dbtest.UniqueEmail(t),
		PasswordDigest: "$argon2id$fake",
	})
	if err != nil {
		t.Fatalf("creating a user: %v", err)
	}
	return u
}

func TestStoreCreateAndFindByToken(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)

	ctx := context.Background()
	token, digest, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	ip := netip.MustParseAddr("203.0.113.7")

	want := NewSession{
		UserID:      user.ID,
		TokenDigest: digest,
		ExpiresAt:   issuedAt.Add(24 * time.Hour),
		UserAgent:   "Mozilla/5.0 (Macintosh)",
		IP:          &ip,
	}

	created, err := store.Create(ctx, pool, want)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if created.ID.IsZero() {
		t.Error("Create returned a zero id")
	}
	if created.UserID != user.ID {
		t.Errorf("UserID = %s, want %s", created.UserID, user.ID)
	}
	if !created.ExpiresAt.Equal(want.ExpiresAt) {
		t.Errorf("ExpiresAt = %s, want %s", created.ExpiresAt, want.ExpiresAt)
	}
	if created.UserAgent != want.UserAgent {
		t.Errorf("UserAgent = %q, want %q", created.UserAgent, want.UserAgent)
	}
	if created.IP == nil || *created.IP != ip {
		t.Errorf("IP = %v, want %v", created.IP, ip)
	}

	// The lookup is by the token the client presents, not by the digest the
	// client never sees.
	found, err := store.ByToken(ctx, pool, token, issuedAt)
	if err != nil {
		t.Fatalf("ByToken: %v", err)
	}
	if found.ID != created.ID {
		t.Errorf("ByToken returned session %s, want %s", found.ID, created.ID)
	}
}

// The raw token must not be in the table. This is the assertion that catches the
// worst plausible bug in this file: storing token instead of token_digest.
func TestStoreNeverWritesTheRawToken(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)

	ctx := context.Background()
	token, digest, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}

	created, err := store.Create(ctx, pool, NewSession{
		UserID:      user.ID,
		TokenDigest: digest,
		ExpiresAt:   issuedAt.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Scoped to this session: every package in the service shares one test
	// database, so `LIMIT 1` would read whichever row another package's test
	// wrote last.
	var stored string
	if err := pool.QueryRow(ctx, `SELECT token_digest FROM sessions WHERE id = $1`, created.ID).Scan(&stored); err != nil {
		t.Fatalf("reading the stored digest: %v", err)
	}
	if stored == token {
		t.Error("the raw token is in sessions.token_digest")
	}
	if stored != digest {
		t.Errorf("token_digest = %q, want %q", stored, digest)
	}
}

// An expired session is not a session. This is the single most important read in
// the package: it is what makes expires_at mean something.
func TestStoreByTokenIgnoresAnExpiredSession(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)

	ctx := context.Background()
	token, digest, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}

	if _, err := store.Create(ctx, pool, NewSession{
		UserID:      user.ID,
		TokenDigest: digest,
		ExpiresAt:   issuedAt,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	tests := []struct {
		name    string
		now     time.Time
		wantErr bool
	}{
		// expires_at is exclusive: the session is live right up to the instant
		// and dead at it.
		{name: "well before expiry", now: issuedAt.Add(-time.Hour)},
		{name: "one nanosecond before expiry", now: issuedAt.Add(-time.Nanosecond)},
		{name: "at expiry", now: issuedAt, wantErr: true},
		{name: "one nanosecond after expiry", now: issuedAt.Add(time.Nanosecond), wantErr: true},
		{name: "long after expiry", now: issuedAt.Add(365 * 24 * time.Hour), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := store.ByToken(ctx, pool, token, tt.now)

			if tt.wantErr {
				if !errors.Is(err, ErrNotFound) {
					t.Errorf("ByToken at %s = %v, want errors.Is(_, ErrNotFound)", tt.now, err)
				}
				return
			}
			if err != nil {
				t.Errorf("ByToken at %s = %v, want the session to resolve", tt.now, err)
			}
		})
	}
}

func TestStoreByTokenMissesCleanly(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)
	newTestUser(t, pool)

	ctx := context.Background()
	other, _, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}

	tests := []struct {
		name  string
		token string
	}{
		{name: "empty", token: ""},
		{name: "well-formed but never issued", token: other},
		{name: "not a token at all", token: "nonsense"},
		// A digest is not a token. Handing back the stored value must not
		// authenticate, or the digest stops being a secret.
		{name: "a digest rather than a token", token: Digest(other)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := store.ByToken(ctx, pool, tt.token, issuedAt); !errors.Is(err, ErrNotFound) {
				t.Errorf("ByToken(%q) = %v, want errors.Is(_, ErrNotFound)", tt.name, err)
			}
		})
	}
}

func TestStoreRevoke(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)

	ctx := context.Background()
	token, digest, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	created, err := store.Create(ctx, pool, NewSession{
		UserID:      user.ID,
		TokenDigest: digest,
		ExpiresAt:   issuedAt.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := store.Revoke(ctx, pool, created.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Revocation has to invalidate the credential, not just the row id.
	if _, err := store.ByToken(ctx, pool, token, issuedAt); !errors.Is(err, ErrNotFound) {
		t.Errorf("ByToken after Revoke = %v, want errors.Is(_, ErrNotFound)", err)
	}
	// The row itself is gone too, not merely unusable. Scoped to this session's
	// id: another package's tests are using the same database.
	var remaining int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE id = $1`, created.ID).Scan(&remaining); err != nil {
		t.Fatalf("counting the revoked session: %v", err)
	}
	if remaining != 0 {
		t.Errorf("the revoked session row is still present")
	}
}

func TestStoreRevokeIsIdempotent(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	// Revoking something already gone is not an error. Logout is a request a
	// client retries, and a 500 on the second attempt is a worse answer than a
	// 204.
	if err := store.Revoke(context.Background(), pool, id.MustNew()); err != nil {
		t.Errorf("Revoke of a missing session = %v, want nil", err)
	}
}

// Two sessions for one user are independent: revoking one leaves the other
// working. "Sign out everywhere" is a different operation and a later packet.
func TestStoreSessionsAreIndependentPerToken(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)

	ctx := context.Background()
	firstToken, firstDigest, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	secondToken, secondDigest, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}

	first, err := store.Create(ctx, pool, NewSession{UserID: user.ID, TokenDigest: firstDigest, ExpiresAt: issuedAt.Add(time.Hour)})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := store.Create(ctx, pool, NewSession{UserID: user.ID, TokenDigest: secondDigest, ExpiresAt: issuedAt.Add(time.Hour)}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := store.Revoke(ctx, pool, first.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	if _, err := store.ByToken(ctx, pool, firstToken, issuedAt); !errors.Is(err, ErrNotFound) {
		t.Errorf("the revoked token still resolves: %v", err)
	}
	if _, err := store.ByToken(ctx, pool, secondToken, issuedAt); err != nil {
		t.Errorf("the untouched token stopped resolving: %v", err)
	}
}

// The user_agent and ip columns are optional: an API client has no user agent and
// may sit behind a proxy that gives no address.
func TestStoreCreateAcceptsAbsentRequestMetadata(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)

	// A real minted digest, not a fixed one: a hard-coded digest survives the
	// rollback of this test's transaction nowhere, so it collides with the row
	// the previous run left behind.
	_, digest, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	created, err := store.Create(context.Background(), pool, NewSession{
		UserID:      user.ID,
		TokenDigest: digest,
		ExpiresAt:   issuedAt.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if created.UserAgent != "" {
		t.Errorf("UserAgent = %q, want empty", created.UserAgent)
	}
	if created.IP != nil {
		t.Errorf("IP = %v, want nil", *created.IP)
	}
}

// Deleting a user takes their sessions with them, so a deleted account cannot
// keep serving authenticated requests off a token issued a moment earlier.
func TestSessionsAreRemovedWithTheirUser(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)

	ctx := context.Background()
	token, digest, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if _, err := store.Create(ctx, pool, NewSession{UserID: user.ID, TokenDigest: digest, ExpiresAt: issuedAt.Add(time.Hour)}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, user.ID); err != nil {
		t.Fatalf("deleting the user: %v", err)
	}

	if _, err := store.ByToken(ctx, pool, token, issuedAt); !errors.Is(err, ErrNotFound) {
		t.Errorf("a session outlived its user: %v", err)
	}
}

func TestStoreCreateRejectsAnUnknownUser(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)

	// The foreign key is what stops a session existing without an owner. The
	// error is the constraint, not a wrapped ErrNotFound: the caller asked for
	// something impossible, and saying "no such user" would be a guess.
	_, err := store.Create(context.Background(), pool, NewSession{
		UserID:      id.MustNew(),
		TokenDigest: Digest("orphan"),
		ExpiresAt:   issuedAt.Add(time.Hour),
	})
	if err == nil {
		t.Error("Create accepted a session for a user that does not exist, want the foreign key to reject it")
	}
}

func TestStoreCreateRejectsADuplicateToken(t *testing.T) {
	pool := dbtest.Pool(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)

	ctx := context.Background()
	_, digest, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	row := NewSession{UserID: user.ID, TokenDigest: digest, ExpiresAt: issuedAt.Add(time.Hour)}

	if _, err := store.Create(ctx, pool, row); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := store.Create(ctx, pool, row); err == nil {
		t.Error("Create accepted the same token twice, want sessions_token_digest_key to reject it")
	}
}
