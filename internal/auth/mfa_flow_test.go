package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cafaye/identity/internal/mfa"
	"github.com/cafaye/identity/internal/outbox"
	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/sessions"
	"github.com/cafaye/identity/internal/users"
)

// THE ASSERTION THE WHOLE PACKET EXISTS FOR, over a real Postgres.
//
// Everything here is integration: the real use cases, the real SQL, the real
// sessions table. A double could only report what Login returned, and the failure
// this packet is about is a login that returns no token AND WRITES A SESSION
// ANYWAY — which is invisible to any test that does not count rows. So every test
// below counts rows, and the fixture exists to make that cheap.

// mfaHarness is one registered user with the real auth service, the real
// second-factor service, and a parked clock over a private schema.
type mfaHarness struct {
	t      *testing.T
	svc    *Service
	second *mfa.Service
	pool   *pgxpool.Pool
	clk    *clock.Fake
	user   users.User
	email  string
	// holds is what the USER has: the secret in their authenticator and one
	// recovery code from the confirmation. The service never has both at once,
	// which is the property the whole package is built on.
	holds enrolledFactor
}

// enrolledFactor is a user's second factor, as they hold it.
type enrolledFactor struct {
	Secret       string
	RecoveryCode string
}

// code is what that user's authenticator app is showing at instant.
func (e enrolledFactor) code(t *testing.T, at time.Time) string {
	t.Helper()
	code, err := mfa.Code(e.Secret, at)
	if err != nil {
		t.Fatalf("mfa.Code: %v", err)
	}
	return code
}

func newMFAHarness(t *testing.T) *mfaHarness {
	t.Helper()

	svc, pool, clk, second := newIntegrationServiceWithMFA(t)
	email := dbtest.UniqueEmail(t)

	registered, err := svc.Register(context.Background(), RegisterInput{
		Email: email, Password: "correct horse battery",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	parsed, err := id.Parse(registered.ID.String())
	if err != nil {
		t.Fatalf("parsing the registered id: %v", err)
	}

	return &mfaHarness{
		t: t, svc: svc, second: second, pool: pool, clk: clk,
		user:  users.User{ID: parsed, Email: registered.Email},
		email: registered.Email,
	}
}

// enroll runs the whole first-time enrollment, keeping what a user would keep.
func (h *mfaHarness) enroll() enrolledFactor {
	h.t.Helper()
	ctx := context.Background()

	started, err := h.second.StartEnrollment(ctx, mfa.StartEnrollmentInput{UserID: h.user.ID})
	if err != nil {
		h.t.Fatalf("StartEnrollment: %v", err)
	}
	holds := enrolledFactor{Secret: started.Secret}

	confirmed, err := h.second.Confirm(ctx, mfa.ConfirmInput{
		UserID:       h.user.ID,
		EnrollmentID: started.Credential.ID,
		Factor:       holds.code(h.t, h.clk.Now()),
	})
	if err != nil {
		h.t.Fatalf("Confirm: %v", err)
	}
	holds.RecoveryCode = confirmed.RecoveryCodes[0]
	h.holds = holds
	return holds
}

// login is a correct password.
func (h *mfaHarness) login() LoginResult {
	h.t.Helper()
	result, err := h.svc.Login(context.Background(), LoginInput{
		Email: h.email, Password: "correct horse battery", UserAgent: "Test/1.0",
	})
	if err != nil {
		h.t.Fatalf("Login: %v", err)
	}
	return result
}

// sessions is how many session rows this user holds. It is a method rather than a
// bare query because every assertion in this file is about this number.
func (h *mfaHarness) sessions() int {
	h.t.Helper()
	var n int
	if err := h.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM sessions WHERE user_id = $1`, h.user.ID).Scan(&n); err != nil {
		h.t.Fatalf("counting sessions: %v", err)
	}
	return n
}

// ---------------------------------------------------------------------------
// the central property
// ---------------------------------------------------------------------------

// TestACorrectPasswordMintsNoSessionForAnAccountWithASecondFactor is the packet's
// "single most important line", stated as four assertions on two different things —
// the return value and the table — because a service that got it half right would
// return the right answer and still have written a credential.
func TestACorrectPasswordMintsNoSessionForAnAccountWithASecondFactor(t *testing.T) {
	h := newMFAHarness(t)
	h.enroll()

	result := h.login()

	if !result.MFARequired {
		t.Fatal("a correct password for an account with MFA returned a session")
	}
	if result.Token != "" {
		t.Errorf("LoginResult.Token = %q; it must be EMPTY, because a caller that ignores MFARequired reads this field", result.Token)
	}
	if result.Challenge == nil || result.Challenge.Token == "" {
		t.Fatal("LoginResult carries no challenge token, so the login cannot be finished")
	}
	if result.ExpiresAt != result.Challenge.ExpiresAt {
		t.Error("LoginResult.ExpiresAt is not the challenge's; a client reading it would be holding a session's deadline")
	}
	if got := h.sessions(); got != 0 {
		t.Errorf("%d sessions were written for a login that has not presented a second factor", got)
	}
}

// TestTheSessionExistsOnlyAfterTheSecondFactor is the other half: the challenge
// DOES finish, and the session it produces is the only one there has ever been.
func TestTheSessionExistsOnlyAfterTheSecondFactor(t *testing.T) {
	h := newMFAHarness(t)
	h.enroll()

	challenge := h.login().Challenge.Token

	h.clk.Advance(mfa.Period + time.Second)
	result, err := h.svc.CompleteSecondFactor(context.Background(), CompleteSecondFactorInput{
		ChallengeToken: challenge,
		Code:           h.holds.code(t, h.clk.Now()),
	})
	if err != nil {
		t.Fatalf("CompleteSecondFactor: %v", err)
	}

	if result.MFARequired {
		t.Error("a completed login still says a second factor is required")
	}
	if result.Token == "" {
		t.Fatal("a completed login returned no token")
	}
	if got := h.sessions(); got != 1 {
		t.Errorf("%d sessions after a completed second-factor login, want exactly 1", got)
	}

	// And the token really is a session: the login is over, not merely answered.
	user, err := h.svc.Authenticate(context.Background(), result.Token)
	if err != nil {
		t.Fatalf("the token from a second-factor login does not authenticate: %v", err)
	}
	if user.ID != h.user.ID {
		t.Errorf("the token belongs to %s, want %s", user.ID, h.user.ID)
	}
}

// TestARecoveryCodeFinishesTheLoginToo, because a user with a lost phone has
// nothing else and the code is the reason recovery codes exist.
func TestARecoveryCodeFinishesTheLoginToo(t *testing.T) {
	h := newMFAHarness(t)
	holds := h.enroll()

	challenge := h.login().Challenge.Token
	result, err := h.svc.CompleteSecondFactor(context.Background(), CompleteSecondFactorInput{
		ChallengeToken: challenge,
		Code:           holds.RecoveryCode,
	})
	if err != nil {
		t.Fatalf("a recovery code did not finish the login: %v", err)
	}
	if result.Token == "" {
		t.Fatal("a completed login returned no token")
	}
	if got := h.sessions(); got != 1 {
		t.Errorf("%d sessions, want 1", got)
	}

	// Single use, over the whole login rather than at one endpoint.
	h.clk.Advance(mfa.Period + time.Second)
	next := h.login().Challenge.Token
	if _, err := h.svc.CompleteSecondFactor(context.Background(), CompleteSecondFactorInput{
		ChallengeToken: next,
		Code:           holds.RecoveryCode,
	}); !errors.Is(err, mfa.ErrInvalidFactor) {
		t.Errorf("a spent recovery code = %v, want ErrInvalidFactor", err)
	}
	if got := h.sessions(); got != 1 {
		t.Errorf("%d sessions after a replayed recovery code, want 1", got)
	}
}

// TestAReplayedCodeIsRefusedAndNoSecondSessionAppears: the replay guard, seen from
// the login rather than from the second-factor package, which is where an attacker
// would meet it.
func TestAReplayedCodeIsRefusedAndNoSecondSessionAppears(t *testing.T) {
	h := newMFAHarness(t)
	h.enroll()

	captured := h.holds.code(t, h.clk.Now())

	if _, err := h.svc.CompleteSecondFactor(context.Background(),
		CompleteSecondFactorInput{ChallengeToken: h.login().Challenge.Token, Code: captured}); err != nil {
		t.Fatalf("the first use was refused: %v", err)
	}
	if got := h.sessions(); got != 1 {
		t.Fatalf("%d sessions after the first use, want 1", got)
	}

	h.clk.Advance(time.Second)
	if _, err := h.svc.CompleteSecondFactor(context.Background(),
		CompleteSecondFactorInput{ChallengeToken: h.login().Challenge.Token, Code: captured}); !errors.Is(err, mfa.ErrInvalidFactor) {
		t.Errorf("a replayed code = %v, want ErrInvalidFactor", err)
	}

	h.clk.Advance(mfa.Period + time.Second)
	if _, err := h.svc.CompleteSecondFactor(context.Background(),
		CompleteSecondFactorInput{ChallengeToken: h.login().Challenge.Token, Code: captured}); !errors.Is(err, mfa.ErrInvalidFactor) {
		t.Errorf("a replayed code a step later = %v, want ErrInvalidFactor", err)
	}
	if got := h.sessions(); got != 1 {
		t.Errorf("%d sessions after two replays, want 1: a code was accepted twice", got)
	}
}

// TestAWrongCodeProducesNoSession, and it counts the failure against the SECOND
// factor rather than the password — the packet's per-factor requirement, seen from
// the login.
func TestAWrongCodeProducesNoSession(t *testing.T) {
	h := newMFAHarness(t)
	h.enroll()

	// One short of the threshold: the fifth wrong code is what LOCKS, so four is
	// the last count at which a correct code is still accepted. Using five here
	// would test the lockout rather than the reset.
	for i := range sessions.MaxFailedAttempts - 1 {
		if _, err := h.svc.CompleteSecondFactor(context.Background(),
			CompleteSecondFactorInput{ChallengeToken: h.login().Challenge.Token, Code: "000000"}); !errors.Is(err, mfa.ErrInvalidFactor) {
			t.Fatalf("attempt %d = %v, want ErrInvalidFactor", i+1, err)
		}
		if got := h.sessions(); got != 0 {
			t.Fatalf("%d sessions after a wrong code", got)
		}
	}

	// The password's counter is untouched: five wrong CODES must not have cost five
	// password attempts, or an attacker could accelerate the slow factor from the
	// fast one's budget.
	user, err := users.NewStore(h.pool).ByID(context.Background(), h.pool, h.user.ID)
	if err != nil {
		t.Fatalf("reading the user: %v", err)
	}
	if user.FailedLoginAttempts != 0 || user.LockedUntil != nil {
		t.Errorf("the password's counter moved: %d attempts, locked until %v", user.FailedLoginAttempts, user.LockedUntil)
	}

	// And a correct code after four wrong ones still works, which is what makes the
	// counter a counter rather than a lockout on every fifth login.
	h.clk.Advance(mfa.Period + time.Second)
	if _, err := h.svc.CompleteSecondFactor(context.Background(),
		CompleteSecondFactorInput{ChallengeToken: h.login().Challenge.Token, Code: h.holds.code(t, h.clk.Now())}); err != nil {
		t.Errorf("a correct code after four wrong ones was refused: %v", err)
	}
	if got := h.sessions(); got != 1 {
		t.Errorf("%d sessions, want 1", got)
	}
}

// TestTheSecondFactorsLockoutIsSeparateFromThePasswords is the same property from
// the other direction: the two counters really are two rows, and exhausting one
// leaves the other alone.
func TestTheSecondFactorsLockoutIsSeparateFromThePasswords(t *testing.T) {
	h := newMFAHarness(t)
	h.enroll()
	ctx := context.Background()

	// Five wrong passwords: the password counter locks, the factor's does not.
	for range sessions.MaxFailedAttempts {
		if _, err := h.svc.Login(ctx, LoginInput{Email: h.email, Password: "wrong"}); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("a wrong password = %v, want ErrInvalidCredentials", err)
		}
	}

	// The factor still works, and so does a login with a good password — which is
	// what "the limits are per-factor" has to mean if the password lockout is not
	// also a second-factor lockout.
	status, err := h.second.StatusFor(ctx, h.user.ID)
	if err != nil {
		t.Fatalf("StatusFor: %v", err)
	}
	if !status.Enabled {
		t.Error("the password lockout turned the second factor off")
	}
	if status.RecoveryCodesRemaining != mfa.RecoveryCodeCount {
		t.Errorf("%d recovery codes, want %d", status.RecoveryCodesRemaining, mfa.RecoveryCodeCount)
	}

	// And the password's lock IS real, so the two are not merely both zero.
	var locked *LockedError
	if _, err := h.svc.Login(ctx, LoginInput{Email: h.email, Password: "correct horse battery"}); !errors.As(err, &locked) {
		t.Errorf("the password lockout did not take: %v", err)
	}
}

// TestNoSecondFactorConfiguredStillLogsYouIn is the compatibility property: an
// account with no second factor has the login it had before this packet.
func TestNoSecondFactorConfiguredStillLogsYouIn(t *testing.T) {
	h := newMFAHarness(t)

	result := h.login()
	if result.MFARequired {
		t.Error("an account with no second factor was asked for one")
	}
	if result.Token == "" {
		t.Fatal("Login returned no token for an account with no second factor")
	}
	if result.Challenge != nil {
		t.Error("Login returned a challenge for an account with no second factor")
	}
	if got := h.sessions(); got != 1 {
		t.Errorf("%d sessions, want 1", got)
	}
}

// TestAPendingEnrollmentDoesNotChangeTheLogin is the "stored but never confirmed"
// property at the layer that matters: a user with an open setup form is not an
// MFA user yet, so they are not challenged.
func TestAPendingEnrollmentDoesNotChangeTheLogin(t *testing.T) {
	h := newMFAHarness(t)
	ctx := context.Background()

	if _, err := h.second.StartEnrollment(ctx, mfa.StartEnrollmentInput{UserID: h.user.ID}); err != nil {
		t.Fatalf("StartEnrollment: %v", err)
	}

	result := h.login()
	if result.MFARequired {
		t.Error("an unconfirmed enrollment was treated as a second factor")
	}
	if result.Token == "" {
		t.Error("an unconfirmed enrollment blocked the login entirely")
	}
	if got := h.sessions(); got != 1 {
		t.Errorf("%d sessions, want 1", got)
	}
}

// TestAServiceWithNoSecondFactorDependencyRefusesToLogIn is the wiring guard. A
// login that cannot ask whether MFA is on must not proceed, because proceeding IS
// the bypass — and the refusal has to be a named error rather than a nil panic, so
// an operator is told what is wrong with the deployment instead of a stack trace.
func TestAServiceWithNoSecondFactorDependencyRefusesToLogIn(t *testing.T) {
	svc, pool, clk, _ := newIntegrationServiceWithMFA(t)
	ctx := context.Background()

	// A SECOND service over the same pool, built without the dependency. This is the
	// one wiring a future change could produce by accident, and it is why the guard
	// is a test rather than a comment.
	unwired := NewService(
		db.TxRunner{Pool: pool},
		db.Direct{Pool: pool},
		users.NewStore(pool),
		sessions.NewStore(pool),
		outbox.NewStore(pool),
		realTenancy(pool, clk),
		nil,
		users.NewHasherWithParams(&argon2id.Params{
			Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
		}),
		clk,
		24*time.Hour,
	)

	email := dbtest.UniqueEmail(t)
	if _, err := svc.Register(ctx, RegisterInput{Email: email, Password: "correct horse battery"}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if _, err := unwired.Login(ctx, LoginInput{Email: email, Password: "correct horse battery"}); !errors.Is(err, ErrNoSecondFactor) {
		t.Errorf("a login with no second-factor dependency = %v, want ErrNoSecondFactor", err)
	}
	// Not a panic, and not a session: the count is what proves it.
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM sessions`).Scan(&n); err != nil {
		t.Fatalf("counting sessions: %v", err)
	}
	if n != 0 {
		t.Errorf("%d sessions were written by a service that could not check for MFA", n)
	}

}

// TestACompletedLoginClearsBOTHCounters, because a two-factor login restarts both
// runs and neither one survives on its own.
func TestACompletedLoginClearsBOTHCounters(t *testing.T) {
	h := newMFAHarness(t)
	h.enroll()
	ctx := context.Background()

	// Three wrong passwords, then three wrong codes. Neither counter has reached
	// its threshold, so the login is still possible.
	for range 3 {
		if _, err := h.svc.Login(ctx, LoginInput{Email: h.email, Password: "wrong"}); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("a wrong password = %v, want ErrInvalidCredentials", err)
		}
	}
	for range 3 {
		if _, err := h.svc.CompleteSecondFactor(ctx, CompleteSecondFactorInput{
			ChallengeToken: h.login().Challenge.Token, Code: "000000",
		}); !errors.Is(err, mfa.ErrInvalidFactor) {
			t.Fatalf("a wrong code = %v, want ErrInvalidFactor", err)
		}
	}

	// A correct code finishes the login, and both runs restart.
	h.clk.Advance(2 * mfa.Period)
	if _, err := h.svc.CompleteSecondFactor(ctx, CompleteSecondFactorInput{
		ChallengeToken: h.login().Challenge.Token, Code: h.holds.code(t, h.clk.Now()),
	}); err != nil {
		t.Fatalf("the login was refused: %v", err)
	}

	user, err := users.NewStore(h.pool).ByID(ctx, h.pool, h.user.ID)
	if err != nil {
		t.Fatalf("reading the user: %v", err)
	}
	if user.FailedLoginAttempts != 0 || user.LockedUntil != nil {
		t.Errorf("the password's run survived a completed login: %d attempts, locked until %v",
			user.FailedLoginAttempts, user.LockedUntil)
	}
	status, err := h.second.StatusFor(ctx, h.user.ID)
	if err != nil {
		t.Fatalf("StatusFor: %v", err)
	}
	// Three wrong codes then one right: the run restarted, so four more wrong codes
	// would be needed to lock. The count is checked through the lockout below rather
	// than by reading the column, because StatusFor deliberately does not expose it.
	_ = status
	// Five, because the fifth is what sets the lock and the sixth is what observes
	// it. A counter that had NOT been cleared by the completed login would already
	// be at three, so this loop would lock on the third and the assertions below
	// would fail — which is exactly what the test is for.
	for range sessions.MaxFailedAttempts {
		if _, err := h.svc.CompleteSecondFactor(ctx, CompleteSecondFactorInput{
			ChallengeToken: h.login().Challenge.Token, Code: "000000",
		}); !errors.Is(err, mfa.ErrInvalidFactor) {
			t.Fatalf("a wrong code after the reset = %v, want ErrInvalidFactor", err)
		}
	}
	var locked *LockedError
	if _, err := h.svc.CompleteSecondFactor(ctx, CompleteSecondFactorInput{
		ChallengeToken: h.login().Challenge.Token, Code: "000000",
	}); !errors.As(err, &locked) {
		t.Errorf("the factor did not lock after %d failures post-reset: %v", sessions.MaxFailedAttempts, err)
	}
}
