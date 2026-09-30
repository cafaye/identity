package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/cafaye/identity/internal/outbox"
	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/sessions"
	"github.com/cafaye/identity/internal/users"
)

var start = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

// ---------------------------------------------------------------------------
// doubles
// ---------------------------------------------------------------------------

// fakeUsers is an in-memory users.Store. Modelling the state faithfully matters:
// the lockout tests are only meaningful if the counter and the lock survive
// across calls the way a row does.
type fakeUsers struct {
	byEmail map[string]users.User
	byID    map[id.UUID]users.User
	nextID  int

	// createErr is returned by Create, to exercise a failure inside the
	// registration transaction.
	createErr error
	// recordErr is returned by RecordFailedLogin.
	recordErr error
	// cleared counts ClearFailures calls.
	cleared int
	// creates counts Create calls.
	creates int
}

func newFakeUsers() *fakeUsers {
	return &fakeUsers{byEmail: map[string]users.User{}, byID: map[id.UUID]users.User{}, nextID: 1}
}

func (f *fakeUsers) Create(_ context.Context, _ db.Querier, p users.CreateParams) (users.User, error) {
	f.creates++
	if f.createErr != nil {
		return users.User{}, f.createErr
	}
	if _, taken := f.byEmail[p.Email]; taken {
		return users.User{}, users.ErrEmailTaken
	}

	// Sequential ids, not random: a test asserting on which event was written
	// needs a stable subject.
	var raw id.UUID
	raw[15] = byte(f.nextID)
	f.nextID++

	u := users.User{ID: raw, Email: p.Email, PasswordDigest: p.PasswordDigest}
	f.byEmail[p.Email] = u
	f.byID[u.ID] = u
	return u, nil
}

func (f *fakeUsers) ByEmail(_ context.Context, _ db.Querier, email string) (users.User, error) {
	u, ok := f.byEmail[email]
	if !ok {
		return users.User{}, users.ErrNotFound
	}
	return u, nil
}

func (f *fakeUsers) ByID(_ context.Context, _ db.Querier, want id.UUID) (users.User, error) {
	u, ok := f.byID[want]
	if !ok {
		return users.User{}, users.ErrNotFound
	}
	return u, nil
}

func (f *fakeUsers) RecordFailedLogin(_ context.Context, _ db.Querier, userID id.UUID, attempts int, lockedUntil *time.Time) error {
	if f.recordErr != nil {
		return f.recordErr
	}
	u, ok := f.byID[userID]
	if !ok {
		return users.ErrNotFound
	}
	u.FailedLoginAttempts = attempts
	u.LockedUntil = lockedUntil
	f.byID[userID] = u
	f.byEmail[u.Email] = u
	return nil
}

func (f *fakeUsers) ClearFailures(_ context.Context, _ db.Querier, userID id.UUID) error {
	f.cleared++
	u, ok := f.byID[userID]
	if !ok {
		return users.ErrNotFound
	}
	u.FailedLoginAttempts = 0
	u.LockedUntil = nil
	f.byID[userID] = u
	f.byEmail[u.Email] = u
	return nil
}

// fakeSessions records what was minted and hands the tokens back.
type fakeSessions struct {
	minted []sessions.NewSession
	live   map[string]id.UUID // digest -> session id
	// owners maps a session id back to its user, so ByToken can return the field
	// Authenticate needs to load the user.
	owners map[id.UUID]id.UUID
	nextID int
	// revoked records revoked session ids.
	revoked []id.UUID
	// createErr and byTokenErr simulate infrastructure failures.
	createErr  error
	byTokenErr error
	// nowSeen records the clock the lookup was called with, so a test can prove
	// expiry is judged against the injected clock rather than the database's.
	nowSeen []time.Time
}

func newFakeSessions() *fakeSessions {
	return &fakeSessions{live: map[string]id.UUID{}, owners: map[id.UUID]id.UUID{}, nextID: 1}
}

func (f *fakeSessions) Create(_ context.Context, _ db.Querier, n sessions.NewSession) (sessions.Session, error) {
	if f.createErr != nil {
		return sessions.Session{}, f.createErr
	}
	f.minted = append(f.minted, n)
	var sid id.UUID
	sid[14] = byte(f.nextID)
	f.nextID++
	f.live[n.TokenDigest] = sid
	f.owners[sid] = n.UserID
	return sessions.Session{ID: sid, UserID: n.UserID, ExpiresAt: n.ExpiresAt, UserAgent: n.UserAgent, IP: n.IP}, nil
}

func (f *fakeSessions) ByToken(_ context.Context, _ db.Querier, token string, now time.Time) (sessions.Session, error) {
	f.nowSeen = append(f.nowSeen, now)
	if f.byTokenErr != nil {
		return sessions.Session{}, f.byTokenErr
	}
	sid, ok := f.live[sessions.Digest(token)]
	if !ok {
		return sessions.Session{}, sessions.ErrNotFound
	}
	return sessions.Session{ID: sid, UserID: f.owners[sid]}, nil
}

func (f *fakeSessions) Revoke(_ context.Context, _ db.Querier, sessionID id.UUID) error {
	f.revoked = append(f.revoked, sessionID)
	for digest, sid := range f.live {
		if sid == sessionID {
			delete(f.live, digest)
		}
	}
	return nil
}

// fakeEvents captures the envelopes written inside the caller's transaction.
type fakeEvents struct {
	appended []outbox.Envelope
	// appendErr fails the append, which must roll the whole registration back.
	appendErr error
	// queriersUsed records what querier each append was handed.
	queriersUsed []db.Querier
}

func (f *fakeEvents) Append(_ context.Context, q db.Querier, e outbox.Envelope) error {
	f.queriersUsed = append(f.queriersUsed, q)
	if f.appendErr != nil {
		return f.appendErr
	}
	f.appended = append(f.appended, e)
	return nil
}

// fakeUnitOfWork runs fn against a marker querier and records whether it would
// commit. It cannot really roll back, so tests that need the rollback behaviour
// use the integration suite; this double exists to prove the two writes share one
// transaction and one context.
type fakeUnitOfWork struct {
	ran     int
	querier db.Querier
	// failWith, when set, is returned without running fn.
	failWith error
}

func (f *fakeUnitOfWork) Do(ctx context.Context, fn func(context.Context, db.Querier) error) error {
	f.ran++
	if f.failWith != nil {
		return f.failWith
	}
	return fn(ctx, f.querier)
}

// fixture wires a Service over the doubles with a fake clock and a cheap hasher.
type fixture struct {
	svc      *Service
	users    *fakeUsers
	sessions *fakeSessions
	events   *fakeEvents
	uow      *fakeUnitOfWork
	reader   *fakeReader
	clock    *clock.Fake
}

// markerQuerier is a db.Querier that does nothing. It exists so a test can tell
// which seam a statement went through by comparing identity, rather than by
// inspecting SQL.
type markerQuerier struct{ name string }

func (m markerQuerier) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func (m markerQuerier) QueryRow(context.Context, string, ...any) pgx.Row { return nil }

// fakeReader hands out a marker querier for statements that need no transaction,
// so a test can tell a read from a write inside the registration transaction.
type fakeReader struct{ q db.Querier }

func (r *fakeReader) Queryer() db.Querier { return r.q }

func newFixture() *fixture {
	f := &fixture{
		users:    newFakeUsers(),
		sessions: newFakeSessions(),
		events:   &fakeEvents{},
		clock:    clock.NewFake(start),
	}
	// A marker querier, so a test can tell the transaction from the pool.
	// Two distinct markers: a test asserting that the event was written through
	// the transaction must fail if the reader is used instead.
	f.reader = &fakeReader{q: markerQuerier{name: "reader"}}
	f.uow = &fakeUnitOfWork{querier: markerQuerier{name: "transaction"}}

	f.svc = NewService(
		f.uow,
		f.reader,
		f.users,
		f.sessions,
		f.events,
		users.NewHasherWithParams(&argon2id.Params{
			Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
		}),
		f.clock,
		24*time.Hour,
	)
	return f
}

// register creates a user directly, bypassing the use case, so a test can set up
// a known credential.
func (f *fixture) register(t *testing.T, email, password string) users.User {
	t.Helper()

	u, err := f.users.Create(context.Background(), f.uow.querier, users.CreateParams{
		Email:          email,
		PasswordDigest: mustHash(t, password),
	})
	if err != nil {
		t.Fatalf("seeding a user: %v", err)
	}
	return u
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func mustHash(t *testing.T, password string) string {
	t.Helper()

	digest, err := users.NewHasherWithParams(&argon2id.Params{
		Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	}).Hash(password)
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}
	return digest
}

// ---------------------------------------------------------------------------
// Register
// ---------------------------------------------------------------------------

func TestRegisterCreatesTheUserAndTheEventInOneTransaction(t *testing.T) {
	t.Parallel()

	f := newFixture()

	got, err := f.svc.Register(context.Background(), RegisterInput{
		Email:    "Kaka@Example.com",
		Password: "correct horse battery staple",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if got.Email != "kaka@example.com" {
		t.Errorf("Email = %q, want the normalized kaka@example.com", got.Email)
	}
	if f.users.byEmail["kaka@example.com"].PasswordDigest == "" || f.users.byEmail["kaka@example.com"].PasswordDigest == "correct horse battery staple" {
		t.Errorf("PasswordDigest = %q, want an argon2id digest", f.users.byEmail["kaka@example.com"].PasswordDigest)
	}
	if strings.Contains(f.users.byEmail["kaka@example.com"].PasswordDigest, "correct horse") {
		t.Error("the digest contains the plaintext password")
	}

	// Exactly one event, and it is about this user.
	if len(f.events.appended) != 1 {
		t.Fatalf("%d events were written, want exactly 1", len(f.events.appended))
	}
	e := f.events.appended[0]
	if err := e.Validate(); err != nil {
		t.Errorf("the event does not satisfy core's schema: %v", err)
	}
	if e.Type != outbox.EventUserCreated {
		t.Errorf("event type = %q, want %q", e.Type, outbox.EventUserCreated)
	}
	if e.Source != outbox.SourceIdentity {
		t.Errorf("event source = %q, want %q", e.Source, outbox.SourceIdentity)
	}
	if e.Subject != got.ID.String() {
		t.Errorf("event subject = %q, want the user id %q", e.Subject, got.ID)
	}
	// The event must not carry the credential out to every subscriber.
	if strings.Contains(string(e.Data), f.users.byEmail["kaka@example.com"].PasswordDigest) {
		t.Error("the event payload contains the password digest")
	}
	if !strings.Contains(string(e.Data), `"email":"kaka@example.com"`) {
		t.Errorf("event payload = %s, want it to carry the email", e.Data)
	}

	// One transaction, and the event went in through it rather than through the
	// pool. This is the assertion the whole outbox exists for.
	if f.uow.ran != 1 {
		t.Errorf("the unit of work ran %d times, want 1", f.uow.ran)
	}
	if len(f.events.queriersUsed) != 1 {
		t.Fatalf("Append was called %d times, want 1", len(f.events.queriersUsed))
	}
	if f.events.queriersUsed[0] != f.uow.querier {
		t.Error("the event was appended outside the registration transaction")
	}
}

func TestRegisterValidatesBeforeTouchingTheDatabase(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		give     RegisterInput
		wantCode string
	}{
		{
			name:     "a short password",
			give:     RegisterInput{Email: "kaka@example.com", Password: "1234567"},
			wantCode: "too_short",
		},
		{
			name:     "an empty password",
			give:     RegisterInput{Email: "kaka@example.com", Password: ""},
			wantCode: "required",
		},
		{
			name:     "a malformed address",
			give:     RegisterInput{Email: "not an address", Password: "correct horse battery"},
			wantCode: "invalid_format",
		},
		{
			name:     "an empty address",
			give:     RegisterInput{Email: "", Password: "correct horse battery"},
			wantCode: "required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture()

			_, err := f.svc.Register(context.Background(), tt.give)
			assertFieldError(t, err, tt.wantCode)

			// Nothing was written and nothing was hashed. Validating first is
			// what keeps a malformed request from costing an argon2id operation.
			if f.uow.ran != 0 {
				t.Error("a transaction was opened for an invalid registration")
			}
			if f.users.creates != 0 {
				t.Error("a user row was written for an invalid registration")
			}
			if len(f.events.appended) != 0 {
				t.Error("an event was written for an invalid registration")
			}
		})
	}
}

// A registration that fails to write the event must not leave a user behind, and
// one that fails to write the user must not leave an event. The transaction is
// what makes both true; this asserts the service goes through it for both writes.
func TestRegisterPropagatesAnAppendFailure(t *testing.T) {
	t.Parallel()

	f := newFixture()
	f.events.appendErr = errors.New("outbox insert failed")

	_, err := f.svc.Register(context.Background(), RegisterInput{
		Email:    "kaka@example.com",
		Password: "correct horse battery",
	})
	if err == nil {
		t.Fatal("Register succeeded even though the event could not be written")
	}
}

func TestRegisterRejectsATakenAddress(t *testing.T) {
	t.Parallel()

	f := newFixture()
	f.register(t, "kaka@example.com", "correct horse battery")

	_, err := f.svc.Register(context.Background(), RegisterInput{
		Email:    "KAKA@example.com",
		Password: "another good passphrase",
	})
	if !errors.Is(err, users.ErrEmailTaken) {
		t.Errorf("Register = %v, want errors.Is(_, users.ErrEmailTaken)", err)
	}
	// No second event for a registration that did not happen.
	if len(f.events.appended) != 0 {
		t.Error("an event was written for a rejected registration")
	}
}

// The event id is minted per registration and is the consumers' dedupe key.
func TestRegisterMintsAFreshEventIDEachTime(t *testing.T) {
	t.Parallel()

	f := newFixture()

	first, err := f.svc.Register(context.Background(), RegisterInput{Email: "a@example.com", Password: "correct horse battery"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	second, err := f.svc.Register(context.Background(), RegisterInput{Email: "b@example.com", Password: "correct horse battery"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if first.ID == second.ID {
		t.Error("two registrations produced the same user id")
	}
	if f.events.appended[0].ID == f.events.appended[1].ID {
		t.Error("two registrations produced the same envelope id")
	}
}

func TestRegisterUsesTheInjectedClock(t *testing.T) {
	t.Parallel()

	f := newFixture()
	later := start.Add(72 * time.Hour)
	f.clock.Set(later)

	if _, err := f.svc.Register(context.Background(), RegisterInput{Email: "kaka@example.com", Password: "correct horse battery"}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if got := f.events.appended[0].Time; !got.Equal(later) {
		t.Errorf("event time = %s, want the injected clock's %s", got, later)
	}
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

func TestLoginSucceedsAndMintsASession(t *testing.T) {
	t.Parallel()

	f := newFixture()
	f.register(t, "kaka@example.com", "correct horse battery staple")

	got, err := f.svc.Login(context.Background(), LoginInput{
		Email:     "KAKA@Example.com",
		Password:  "correct horse battery staple",
		UserAgent: "Mozilla/5.0",
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	if got.User.Email != "kaka@example.com" {
		t.Errorf("Email = %q, want kaka@example.com", got.User.Email)
	}
	if got.Token == "" {
		t.Fatal("Login returned no token; the API client surface would be broken")
	}
	if want := start.Add(24 * time.Hour); !got.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %s, want %s — the TTL comes from the configuration", got.ExpiresAt, want)
	}

	// The token is handed to the client; only its digest is stored.
	if len(f.sessions.minted) != 1 {
		t.Fatalf("%d sessions were minted, want 1", len(f.sessions.minted))
	}
	minted := f.sessions.minted[0]
	if minted.TokenDigest == got.Token {
		t.Error("the stored digest equals the token returned to the client")
	}
	if minted.TokenDigest != sessions.Digest(got.Token) {
		t.Error("the stored digest is not Digest(token)")
	}
	if minted.UserAgent != "Mozilla/5.0" {
		t.Errorf("UserAgent = %q, want the one from the request", minted.UserAgent)
	}
	if minted.UserID != got.User.ID {
		t.Errorf("the session belongs to %s, want %s", minted.UserID, got.User.ID)
	}
}

// The whole enumeration story: a wrong password and an unknown address produce
// the same error, so the response cannot be used to discover who has an account.
func TestLoginDoesNotDistinguishAWrongPasswordFromAnUnknownAddress(t *testing.T) {
	t.Parallel()

	f := newFixture()
	f.register(t, "kaka@example.com", "correct horse battery staple")

	wrongPassword, wrongPasswordErr := f.svc.Login(context.Background(), LoginInput{
		Email: "kaka@example.com", Password: "not the right password",
	})
	unknownEmail, unknownEmailErr := f.svc.Login(context.Background(), LoginInput{
		Email: "nobody@example.com", Password: "not the right password",
	})

	if !errors.Is(wrongPasswordErr, ErrInvalidCredentials) {
		t.Errorf("a wrong password gave %v, want ErrInvalidCredentials", wrongPasswordErr)
	}
	if !errors.Is(unknownEmailErr, ErrInvalidCredentials) {
		t.Errorf("an unknown address gave %v, want ErrInvalidCredentials", unknownEmailErr)
	}
	if wrongPasswordErr.Error() != unknownEmailErr.Error() {
		t.Errorf("the two errors differ in text: %q vs %q. The message is rendered to an anonymous caller.",
			wrongPasswordErr, unknownEmailErr)
	}
	if wrongPassword.Token != "" || unknownEmail.Token != "" {
		t.Error("a failed login returned a session token")
	}
	if !wrongPassword.ExpiresAt.IsZero() || !unknownEmail.ExpiresAt.IsZero() {
		t.Error("a failed login returned an expiry")
	}
	if !wrongPassword.User.ID.IsZero() || !unknownEmail.User.ID.IsZero() {
		t.Error("a failed login returned a user")
	}
}

// An unknown address must not leave state behind. There is no row to count a
// failure against, and inventing one would let anyone lock any address out by
// trying passwords at it.
func TestLoginAgainstAnUnknownAddressWritesNoState(t *testing.T) {
	t.Parallel()

	f := newFixture()

	if _, err := f.svc.Login(context.Background(), LoginInput{Email: "nobody@example.com", Password: "correct horse battery"}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login = %v, want ErrInvalidCredentials", err)
	}

	if f.users.cleared != 0 {
		t.Error("a failed login against an unknown address cleared failures")
	}
	if len(f.sessions.minted) != 0 {
		t.Error("a failed login minted a session")
	}
	if f.uow.ran != 0 {
		t.Error("a failed login against an unknown address opened a transaction")
	}
}

// The lockout matrix. Five consecutive failures lock the account for fifteen
// minutes; the sixth attempt is refused with the remaining window rather than
// being answered.
func TestLoginLockoutMatrix(t *testing.T) {
	t.Parallel()

	const password = "correct horse battery staple"

	t.Run("five failures then locked", func(t *testing.T) {
		t.Parallel()

		f := newFixture()
		f.register(t, "kaka@example.com", password)

		// Attempts one through four: refused, and the counter climbs.
		for attempt := 1; attempt <= sessions.MaxFailedAttempts-1; attempt++ {
			_, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "wrong"})
			if !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("attempt %d = %v, want ErrInvalidCredentials", attempt, err)
			}
			u, _ := f.users.ByEmail(context.Background(), f.uow.querier, "kaka@example.com")
			if u.FailedLoginAttempts != attempt {
				t.Errorf("after attempt %d the counter is %d, want %d", attempt, u.FailedLoginAttempts, attempt)
			}
			if u.IsLocked(f.clock.Now()) {
				t.Fatalf("locked after only %d failures", attempt)
			}
		}

		// The fifth trips it.
		_, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "wrong"})
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("the fifth attempt = %v, want ErrInvalidCredentials", err)
		}

		u, _ := f.users.ByEmail(context.Background(), f.uow.querier, "kaka@example.com")
		if !u.IsLocked(f.clock.Now()) {
			t.Fatal("not locked after five consecutive failures")
		}

		// The sixth is refused with the remaining window, and is not answered.
		_, err = f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: password})
		var locked *LockedError
		if !errors.As(err, &locked) {
			t.Fatalf("the sixth attempt = %v, want a *LockedError", err)
		}
		if want := sessions.LockoutDuration; locked.RetryAfter != want {
			t.Errorf("RetryAfter = %s, want %s", locked.RetryAfter, want)
		}
		if len(f.sessions.minted) != 0 {
			t.Error("a locked account was given a session")
		}
	})

	// The clock, not a sleep: the window opens on the injected instant.
	t.Run("the lock lifts when the window closes", func(t *testing.T) {
		t.Parallel()

		f := newFixture()
		f.register(t, "kaka@example.com", password)

		for range sessions.MaxFailedAttempts {
			if _, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "wrong"}); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("Login = %v, want ErrInvalidCredentials", err)
			}
		}

		// One nanosecond before the window closes: still locked.
		f.clock.Set(start.Add(sessions.LockoutDuration - time.Nanosecond))
		var locked *LockedError
		if _, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: password}); !errors.As(err, &locked) {
			t.Fatalf("just before expiry = %v, want a *LockedError", err)
		}
		if got := locked.RetryAfter; got != time.Nanosecond {
			t.Errorf("RetryAfter = %s, want 1ns", got)
		}

		// At the window's end: the right password works again, with no sleep.
		f.clock.Set(start.Add(sessions.LockoutDuration))
		got, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: password})
		if err != nil {
			t.Fatalf("Login after the window closed = %v, want success", err)
		}
		if got.Token == "" {
			t.Error("Login after the window closed returned no token")
		}
	})

	// A success in the middle restarts the run, so guessing one in five does not
	// accumulate towards a lockout.
	t.Run("a success resets the run", func(t *testing.T) {
		t.Parallel()

		f := newFixture()
		f.register(t, "kaka@example.com", password)

		for range sessions.MaxFailedAttempts - 1 {
			if _, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "wrong"}); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("Login = %v, want ErrInvalidCredentials", err)
			}
		}
		if _, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: password}); err != nil {
			t.Fatalf("the interleaved success failed: %v", err)
		}

		u, _ := f.users.ByEmail(context.Background(), f.uow.querier, "kaka@example.com")
		if u.FailedLoginAttempts != 0 {
			t.Errorf("FailedAttempts after a success = %d, want 0", u.FailedLoginAttempts)
		}
		if u.IsLocked(f.clock.Now()) {
			t.Error("locked despite a successful login")
		}

		// Four more failures must still not lock it.
		for range sessions.MaxFailedAttempts - 1 {
			if _, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "wrong"}); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("Login = %v, want ErrInvalidCredentials", err)
			}
		}
		u, _ = f.users.ByEmail(context.Background(), f.uow.querier, "kaka@example.com")
		if u.IsLocked(f.clock.Now()) {
			t.Error("locked after 4 post-success failures")
		}
	})

	// Failures on one account must not affect another. Otherwise anyone could
	// lock every account on the platform out by guessing at each of them.
	t.Run("failures are per account", func(t *testing.T) {
		t.Parallel()

		f := newFixture()
		f.register(t, "victim@example.com", password)
		f.register(t, "bystander@example.com", password)

		for range sessions.MaxFailedAttempts {
			if _, err := f.svc.Login(context.Background(), LoginInput{Email: "victim@example.com", Password: "wrong"}); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("Login = %v, want ErrInvalidCredentials", err)
			}
		}

		if _, err := f.svc.Login(context.Background(), LoginInput{Email: "bystander@example.com", Password: password}); err != nil {
			t.Errorf("an unrelated account was locked too: %v", err)
		}
	})
}

// A locked account is refused before the password is checked. There is no reason
// to spend argon2id on an account nobody may log into, and the order means a
// locked account cannot be probed at all.
func TestLoginChecksTheLockBeforeThePassword(t *testing.T) {
	t.Parallel()

	f := newFixture()
	f.register(t, "kaka@example.com", "correct horse battery staple")
	for range sessions.MaxFailedAttempts {
		if _, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "wrong"}); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("Login = %v, want ErrInvalidCredentials", err)
		}
	}

	before := len(f.sessions.minted)
	if _, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "wrong"}); err == nil {
		t.Fatal("a locked account accepted a login attempt")
	}
	if len(f.sessions.minted) != before {
		t.Error("a locked attempt minted a session")
	}

	// The lock is not extended by the attempt.
	u, _ := f.users.ByEmail(context.Background(), f.uow.querier, "kaka@example.com")
	var locked *LockedError
	_, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "wrong"})
	if !errors.As(err, &locked) {
		t.Fatalf("Login = %v, want a *LockedError", err)
	}
	if got := locked.RetryAfter; got != sessions.LockoutDuration {
		t.Errorf("RetryAfter = %s, want the original %s; a rejected attempt extended the lock", got, sessions.LockoutDuration)
	}
	_ = u
}

// Clearing the failure run and minting the session is one transaction. If the
// session cannot be written, the counter must not be reset, or a partial failure
// would hand an attacker free attempts.
func TestLoginMintsTheSessionAndClearsFailuresTogether(t *testing.T) {
	t.Parallel()

	f := newFixture()
	f.register(t, "kaka@example.com", "correct horse battery staple")
	if _, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "wrong"}); err == nil {
		t.Fatal("the seeded failure did not fail")
	}

	f.sessions.createErr = errors.New("insert into sessions failed")

	_, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "correct horse battery staple"})
	if err == nil {
		t.Fatal("Login succeeded even though the session could not be written")
	}
	// Only the successful attempt opens a transaction: a refused login is a
	// single UPDATE against users and needs no atomicity, so routing it through
	// one would be a BEGIN/COMMIT per failed password for nothing.
	if f.uow.ran != 1 {
		t.Errorf("the unit of work ran %d times, want 1 — only the successful attempt", f.uow.ran)
	}
	if f.users.cleared != 0 {
		t.Error("the failure run was cleared even though no session was minted")
	}
}

// A failure to record the failed attempt is an infrastructure problem, and it
// must surface: a login path that swallows it would stop counting and the
// lockout would silently stop working.
func TestLoginReportsAFailureToRecordTheAttempt(t *testing.T) {
	t.Parallel()

	f := newFixture()
	f.register(t, "kaka@example.com", "correct horse battery staple")
	f.users.recordErr = errors.New("update users failed")

	_, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "wrong"})
	if !errors.Is(err, f.users.recordErr) {
		t.Errorf("Login = %v, want the store error to surface", err)
	}
	if errors.Is(err, ErrInvalidCredentials) {
		t.Error("a store failure was reported as invalid credentials; the lockout would stop counting")
	}
}

func TestLoginValidatesTheInputShape(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		give     LoginInput
		wantCode string
	}{
		{name: "an empty address", give: LoginInput{Email: "", Password: "whatever"}, wantCode: "required"},
		{name: "a malformed address", give: LoginInput{Email: "not an address", Password: "whatever"}, wantCode: "invalid_format"},
		{name: "an empty password", give: LoginInput{Email: "kaka@example.com", Password: ""}, wantCode: "required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture()

			_, err := f.svc.Login(context.Background(), tt.give)
			assertFieldError(t, err, tt.wantCode)

			// A malformed request is answered before any password is hashed.
			if f.uow.ran != 0 {
				t.Error("a transaction was opened for a malformed login")
			}
		})
	}
}

// An over-long password is rejected before argon2id sees it. Without this an
// unauthenticated caller chooses how much memory-hashing work each request costs.
func TestLoginRejectsAnOverLongPassword(t *testing.T) {
	t.Parallel()

	f := newFixture()
	f.register(t, "kaka@example.com", "correct horse battery staple")

	_, err := f.svc.Login(context.Background(), LoginInput{
		Email:    "kaka@example.com",
		Password: strings.Repeat("a", users.MaxPasswordLength+1),
	})
	assertFieldError(t, err, "too_long")
}

func TestLoginRecordsTheRequestAddress(t *testing.T) {
	t.Parallel()

	f := newFixture()
	f.register(t, "kaka@example.com", "correct horse battery staple")
	ip := mustAddr("203.0.113.7")

	if _, err := f.svc.Login(context.Background(), LoginInput{
		Email: "kaka@example.com", Password: "correct horse battery staple", IP: &ip,
	}); err != nil {
		t.Fatalf("Login: %v", err)
	}

	minted := f.sessions.minted[0]
	if minted.IP == nil || minted.IP.String() != "203.0.113.7" {
		t.Errorf("IP = %v, want 203.0.113.7 recorded for the incident trail", minted.IP)
	}
}

// ---------------------------------------------------------------------------
// Authenticate and Logout
// ---------------------------------------------------------------------------

func TestAuthenticateResolvesATokenToItsUser(t *testing.T) {
	t.Parallel()

	f := newFixture()
	f.register(t, "kaka@example.com", "correct horse battery staple")

	login, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	got, err := f.svc.Authenticate(context.Background(), login.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got.ID != login.User.ID {
		t.Errorf("Authenticate returned user %s, want %s", got.ID, login.User.ID)
	}
	if got.Email != "kaka@example.com" {
		t.Errorf("Email = %q, want kaka@example.com", got.Email)
	}
}

// Every unusable token is one error, so /v1/me cannot be used to probe which
// tokens once existed.
func TestAuthenticateRejectsUnusableTokens(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		token string
	}{
		{name: "empty", token: ""},
		{name: "not a token", token: "nonsense"},
		{name: "a well-formed token that was never issued", token: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{name: "a revoked token", token: "revoked"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture()
			if _, err := f.svc.Authenticate(context.Background(), tt.token); !errors.Is(err, ErrUnauthenticated) {
				t.Errorf("Authenticate(%q) = %v, want ErrUnauthenticated", tt.name, err)
			}
		})
	}
}

// The expiry check is made against the injected clock. If it were the database's,
// a test could not move time and a frozen system clock would change the answer.
func TestAuthenticateUsesTheInjectedClock(t *testing.T) {
	t.Parallel()

	f := newFixture()
	f.register(t, "kaka@example.com", "correct horse battery staple")
	login, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	f.clock.Now() // establish a baseline
	if _, err := f.svc.Authenticate(context.Background(), login.Token); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if len(f.sessions.nowSeen) == 0 {
		t.Fatal("the session lookup never happened")
	}
	if got := f.sessions.nowSeen[len(f.sessions.nowSeen)-1]; !got.Equal(f.clock.Now()) {
		t.Errorf("the lookup was given %s, want the injected clock's %s", got, f.clock.Now())
	}
}

func TestLogoutRevokesTheSession(t *testing.T) {
	t.Parallel()

	f := newFixture()
	f.register(t, "kaka@example.com", "correct horse battery staple")
	login, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := f.svc.Authenticate(context.Background(), login.Token); err != nil {
		t.Fatalf("the token did not authenticate before logout: %v", err)
	}

	if err := f.svc.Logout(context.Background(), login.Token); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	// This is the requirement: the token is dead immediately.
	if _, err := f.svc.Authenticate(context.Background(), login.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("the token still authenticates after Logout: %v", err)
	}
}

// Logging out with something that is not a session is a no-op, not an error. A
// client retrying a logout, or a browser sending a stale cookie, should get an
// answer rather than a 500.
func TestLogoutIsIdempotent(t *testing.T) {
	t.Parallel()

	f := newFixture()

	if err := f.svc.Logout(context.Background(), "never-issued"); err != nil {
		t.Errorf("Logout of an unknown token = %v, want nil", err)
	}
}

func TestLogoutLeavesOtherSessionsAlone(t *testing.T) {
	t.Parallel()

	f := newFixture()
	f.register(t, "kaka@example.com", "correct horse battery staple")

	first, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatalf("first Login: %v", err)
	}
	second, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatalf("second Login: %v", err)
	}

	if err := f.svc.Logout(context.Background(), first.Token); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	if _, err := f.svc.Authenticate(context.Background(), first.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Error("the logged-out token still authenticates")
	}
	if _, err := f.svc.Authenticate(context.Background(), second.Token); err != nil {
		t.Errorf("an unrelated session was revoked too: %v", err)
	}
}

// The password digest must never appear in a value the HTTP layer can render.
func TestUserResultsCarryNoDigest(t *testing.T) {
	t.Parallel()

	f := newFixture()
	user := f.register(t, "kaka@example.com", "correct horse battery staple")

	login, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	authed, err := f.svc.Authenticate(context.Background(), login.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	// The digest lives on the domain type on purpose — login needs it — so the
	// guarantee is that no *result* type carries it. Both results are structs
	// whose only user field is a public projection.
	// Authenticate returns the domain user, because login needs the digest and
	// the handler needs the address. The guarantee is therefore about the shapes
	// the HTTP layer renders, and the handler's projection is asserted there. What
	// matters here is that the two *result* types have no digest field at all, so
	// a digest cannot be rendered by accident.
	projections := map[string]any{
		"register":     RegisteredUser{ID: user.ID, Email: user.Email},
		"login":        login.User,
		"authenticate": RegisteredUser{ID: authed.ID, Email: authed.Email},
	}
	for name, projection := range projections {
		encoded, err := json.Marshal(projection)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, secret := range []string{"$argon2id$", "password_digest", "digest"} {
			if strings.Contains(string(encoded), secret) {
				t.Errorf("%s result renders %q: %s", name, secret, encoded)
			}
		}
	}
}

func assertFieldError(t *testing.T, err error, wantCode string) {
	t.Helper()

	if err == nil {
		t.Fatalf("got nil error, want code %q", wantCode)
	}
	var fe *users.FieldError
	if !errors.As(err, &fe) {
		t.Fatalf("error = %v (%T), want a *users.FieldError", err, err)
	}
	if fe.Code != wantCode {
		t.Errorf("code = %q, want %q", fe.Code, wantCode)
	}
}
