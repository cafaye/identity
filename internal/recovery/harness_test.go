package recovery

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cafaye/identity/internal/outbox"
	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/sessions"
	"github.com/cafaye/identity/internal/users"
)

// The harness, and the reason it is the real thing rather than doubles.
//
// Every test in this package that exercises a flow runs the real store over a real
// Postgres, because the properties being asserted are properties of the WIRE and
// of the tables: a token spent once, an expiry honoured, a verification cleared by
// the statement that moved an address. A double would answer exactly what the test
// told it to, and the whole value of these tests is that they would fail if the SQL
// were wrong.

// harness is one recovery service over one pool, with a clock a test can move and a
// mailer that keeps what it was asked to send.
type harness struct {
	t      *testing.T
	svc    *Service
	pool   *pgxpool.Pool
	clk    *clock.Fake
	mailer *recordingMailer
	access *recordingAccessRevoker
	users  *users.Store
	// token is the session token register() last minted, kept on the harness rather
	// than returned because most tests want a live session without caring about its
	// value.
	token string
}

// recordingMailer is the seam's double: it keeps every message so a test can read
// the token out of it, which is the only place the plaintext exists.
type recordingMailer struct {
	mu       sync.Mutex
	sent     []Message
	readyErr error
	sendErr  error
}

func (m *recordingMailer) Ready(context.Context) error { return m.readyErr }

func (m *recordingMailer) Send(_ context.Context, msg Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sendErr != nil {
		return m.sendErr
	}
	m.sent = append(m.sent, msg)
	return nil
}

// messages is every message delivered so far.
func (m *recordingMailer) messages() []Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Message(nil), m.sent...)
}

// count is how many messages have been delivered, which is the assertion a mail
// cannon is made of.
func (m *recordingMailer) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

// last is the most recent message, failing the test when there is none.
func (m *recordingMailer) last(t *testing.T) Message {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sent) == 0 {
		t.Fatal("no message was delivered; the flow under test never reached the seam")
	}
	return m.sent[len(m.sent)-1]
}

// recordingAccessRevoker stands in for internal/oidc's store, which cannot be
// built over the same schema in a test that does not also configure a signing key
// and an issuer. The assertion is about WHICH users were swept and WHEN, both of
// which are answered by a record; the SQL it stands for is a single UPDATE and is
// exercised in internal/oidc's own store test.
type recordingAccessRevoker struct {
	mu      sync.Mutex
	revoked map[id.UUID]time.Time
}

func newRecordingAccessRevoker() *recordingAccessRevoker {
	return &recordingAccessRevoker{revoked: map[id.UUID]time.Time{}}
}

func (r *recordingAccessRevoker) RevokeAccessTokensForUser(_ context.Context, _ db.Querier, userID id.UUID, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked[userID] = at
	return nil
}

func (r *recordingAccessRevoker) swept(userID id.UUID) (time.Time, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	at, ok := r.revoked[userID]
	return at, ok
}

// newHarness builds the service over a shared pool.
//
// schema says whether to build a PRIVATE schema instead, which a test needs only
// when it asserts about the contents of a table rather than about one account's
// rows — a unique-email test cannot see anybody else's fixtures, but a sweep for
// "this token is not in the clear anywhere in this table" needs the table to hold
// nothing else.
func newHarness(t *testing.T, schema bool) *harness {
	t.Helper()

	pool := dbtest.Pool(t)
	if schema {
		pool = dbtest.Schema(t)
	}

	clk := clock.NewFake(issuedAt())
	mailer := &recordingMailer{}
	access := newRecordingAccessRevoker()
	userStore := users.NewStore(pool)

	return &harness{
		t:      t,
		pool:   pool,
		clk:    clk,
		mailer: mailer,
		access: access,
		users:  userStore,
		svc: NewService(
			db.TxRunner{Pool: pool},
			db.Direct{Pool: pool},
			NewStore(pool),
			userStore,
			sessions.NewStore(pool),
			access,
			outbox.NewStore(pool),
			mailer,
			testHasher(),
			clk,
		),
	}
}

// issuedAt is the instant every test in this package starts from. A fixed value, so
// every derived expiry is exact and none of these tests depends on when they run.
func issuedAt() time.Time {
	return time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
}

// testHasher is a real argon2id hasher with cheap parameters.
//
// IT IS NOT FASTER THAN THE PRODUCTION ONE BY MUCH and that is the point: the cost
// parameters exist to make guessing a password expensive, and a test that is about
// whether a password CHANGED does not need them. It is still argon2id, so a digest
// written here verifies through the production hasher and the production one would
// verify a digest written here — which is what lets these tests assert that a reset
// really moved the credential rather than only that a column was written.
func testHasher() *users.Hasher {
	params := users.DefaultParams()
	// 8 KiB x parallelism is argon2id's floor; the library refuses anything lower.
	params.Memory = 8 * 1024
	params.Iterations = 1
	params.Parallelism = 1
	return users.NewHasherWithParams(params)
}

// account is a registered user and a live session, so a test can assert that a flow
// ended the session and not merely that it said it did.
type account struct {
	id    id.UUID
	email string
	token string
}

// register creates a user and signs them in.
func (h *harness) register(email, password string) account {
	h.t.Helper()

	digest, err := testHasher().Hash(password)
	if err != nil {
		h.t.Fatalf("hashing: %v", err)
	}

	var user users.User
	err = db.TxRunner{Pool: h.pool}.Do(h.t.Context(), func(ctx context.Context, q db.Querier) error {
		created, err := h.users.Create(ctx, q, users.CreateParams{Email: email, PasswordDigest: digest})
		if err != nil {
			return err
		}
		user = created
		token, tokenDigest, err := sessions.NewToken()
		if err != nil {
			return err
		}
		_, err = sessions.NewStore(h.pool).Create(ctx, q, sessions.NewSession{
			UserID:      created.ID,
			TokenDigest: tokenDigest,
			ExpiresAt:   h.now().Add(24 * time.Hour),
		})
		if err != nil {
			return err
		}
		h.token = token
		return nil
	})
	if err != nil {
		h.t.Fatalf("registering %s: %v", email, err)
	}

	return account{id: user.ID, email: user.Email}
}

// registerSimple creates an account with a live session.
func (h *harness) registerSimple() account {
	h.t.Helper()
	return h.register(dbtest.UniqueEmail(h.t), "correct horse battery staple")
}

// now is the harness's instant.
func (h *harness) now() time.Time { return h.clk.Now() }

// sessionsFor is how many live sessions a user holds.
func (h *harness) sessionsFor(userID id.UUID) int {
	h.t.Helper()
	var n int
	err := h.pool.QueryRow(h.t.Context(),
		`SELECT count(*) FROM sessions WHERE user_id = $1`, userID).Scan(&n)
	if err != nil {
		h.t.Fatalf("counting sessions: %v", err)
	}
	return n
}

// tokenFrom reads the plaintext token out of a delivered message.
//
// IT PARSES THE BODY rather than reaching into the service, and that is the whole
// point: the plaintext exists in exactly one place in this package's whole path, and
// a test that obtained it any other way would be testing a token the service did
// not actually mail. A token is 43 characters of base64url on a line of its own;
// the bodies put it there so it can be copied by a person.
func tokenFrom(t *testing.T, m Message) string {
	t.Helper()
	for _, line := range strings.Split(m.Body, "\n") {
		candidate := strings.TrimSpace(line)
		if len(candidate) == 43 && !strings.ContainsAny(candidate, " \t") && isBase64URL(candidate) {
			return candidate
		}
	}
	t.Fatalf("no token in the delivered body:\n%s", m.Body)
	return ""
}

// isBase64URL reports whether s is 43 characters of the base64url alphabet, which
// is what sessions.NewToken produces for 32 bytes.
func isBase64URL(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// tokenRowCount is how many rows of recovery_tokens exist for a user and purpose.
func (h *harness) tokenRowCount(userID id.UUID, purpose Purpose) int {
	h.t.Helper()
	var n int
	err := h.pool.QueryRow(h.t.Context(),
		`SELECT count(*) FROM recovery_tokens WHERE user_id = $1 AND purpose = $2`,
		userID, purpose).Scan(&n)
	if err != nil {
		h.t.Fatalf("counting %s tokens: %v", purpose, err)
	}
	return n
}

// storedTokenRow is the raw row, for the assertions about what is and is not
// stored. It is read through a map rather than the Token type on purpose: a test
// asserting "the plaintext is not in the row" must be able to look at every column,
// including the ones the domain type deliberately has no field for.
func (h *harness) storedTokenRow(tokenID id.UUID) map[string]any {
	h.t.Helper()
	rows, err := h.pool.Query(h.t.Context(),
		`SELECT * FROM recovery_tokens WHERE id = $1`, tokenID)
	if err != nil {
		h.t.Fatalf("reading the token row: %v", err)
	}
	defer rows.Close()

	fields := rows.FieldDescriptions()
	out := map[string]any{}
	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			h.t.Fatalf("reading the token row: %v", err)
		}
		for i, f := range fields {
			out[string(f.Name)] = values[i]
		}
	}
	if len(out) == 0 {
		h.t.Fatalf("no recovery_tokens row with id %s", tokenID)
	}
	return out
}

// hasTargetDigest reports whether an email change's second token exists yet.
//
// IT ASKS THE COLUMN AND NOT THE DOMAIN TYPE, because `Token` deliberately has no
// field for the target digest: the plaintext target token never leaves the service,
// and its DIGEST is written once and read once inside a transaction. A test that
// could read it off a struct would be a test asserting a property the type is
// shaped to prevent anybody from depending on.
func (h *harness) hasTargetDigest(tokenID id.UUID) bool {
	h.t.Helper()
	var present bool
	if err := h.pool.QueryRow(h.t.Context(),
		`SELECT target_token_digest IS NOT NULL FROM recovery_tokens WHERE id = $1`,
		tokenID).Scan(&present); err != nil {
		h.t.Fatalf("reading the target digest state: %v", err)
	}
	return present
}

// dbCreate is a users.CreateParams for an address somebody else already holds, for
// the test that needs a second account to appear mid-flow.
//
// THE DIGEST IS NOT A REAL ARGON2ID VALUE and nothing in that test verifies a
// password: it registers a collision and asserts that a change refuses to take the
// address. A fixture that had to be a real digest would be paying a memory-hard
// hash to prove a UNIQUE index works.
func dbCreate(email string) users.CreateParams {
	return users.CreateParams{Email: email, PasswordDigest: "$argon2id$fixture-not-a-real-digest"}
}

// newestTokenID is the id of the most recent row for a user and purpose, for the
// assertions that reach into the table rather than through the store.
func (h *harness) newestTokenID(userID id.UUID, purpose Purpose) id.UUID {
	h.t.Helper()
	var rowID id.UUID
	err := h.pool.QueryRow(h.t.Context(),
		`SELECT id FROM recovery_tokens WHERE user_id = $1 AND purpose = $2
		 ORDER BY created_at DESC, id DESC LIMIT 1`, userID, purpose).Scan(&rowID)
	if err != nil {
		h.t.Fatalf("reading the newest %s token id: %v", purpose, err)
	}
	return rowID
}

// TestTheDatabaseTierActuallyRan enforces the tier for this package.
//
// IT FAILS RATHER THAN SKIPS when TEST_DATABASE_URL is unset, and every test in
// this package is a database test, so a skip here would read like coverage. A
// suite that reports `ok` having never touched Postgres has proved nothing about a
// package whose entire subject is what a database stores.
func TestTheDatabaseTierActuallyRan(t *testing.T) {
	if os.Getenv(dbtest.EnvVar) == "" {
		t.Fatalf("%s is not set. Every test in internal/recovery is a database test, and a skip "+
			"here reads like coverage. Run `goose -dir migrations postgres \"$DATABASE_URL\" up` and "+
			"then `TEST_DATABASE_URL=\"$DATABASE_URL\" go test ./...`; see README.md, Testing.",
			dbtest.EnvVar)
	}
}

// errIsFieldError reports whether err is a users.FieldError naming a field, which
// is how the validation refusals are asserted without pinning the whole type.
func errIsFieldError(err error, field string) bool {
	var fe *users.FieldError
	if !errors.As(err, &fe) {
		return false
	}
	return fe.Field == field
}
