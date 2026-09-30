package mfa

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/sessions"
	"github.com/cafaye/identity/internal/users"
)

// challengeAt is a fresh challenge for the harness's user.
func (h *harness) challengeAt() NewChallenge {
	h.t.Helper()
	challenge, err := h.svc.CreateChallenge(h.t.Context(), CreateChallengeInput{
		UserID:    h.user.ID,
		UserAgent: "Test/1.0",
	})
	if err != nil {
		h.t.Fatalf("CreateChallenge: %v", err)
	}
	return challenge
}

// complete is a WHOLE LOGIN, both halves, in one place: verify the factor, then
// consume the challenge and mint the session in the transaction that internal/auth
// writes. Leaving the second half out is not a simplification — VerifyChallenge on
// its own does not consume the challenge, so a test that stopped there would be
// asserting against a flow that could be replayed, and every "the challenge was
// spent" assertion in this package would be vacuous.
//
// The session write is a real one, so the session count in the table is evidence
// rather than bookkeeping.
func (h *harness) complete(challenge NewChallenge, code string) (Claim, error) {
	h.t.Helper()

	claim, err := h.svc.VerifyChallenge(h.t.Context(), challenge.Token, code, h.now())
	if err != nil {
		return Claim{}, err
	}

	token, digest, err := sessions.NewToken()
	if err != nil {
		h.t.Fatalf("NewToken: %v", err)
	}
	runner := h.svc.uow
	if err := runner.Do(h.t.Context(), func(ctx context.Context, q db.Querier) error {
		if err := h.svc.Commit(ctx, q, claim, h.now()); err != nil {
			return err
		}
		_, err := sessions.NewStore(h.pool).Create(ctx, q, sessions.NewSession{
			UserID:      claim.UserID(),
			TokenDigest: digest,
			ExpiresAt:   h.now().Add(24 * time.Hour),
		})
		return err
	}); err != nil {
		return Claim{}, err
	}
	_ = token
	return claim, nil
}

// TestACorrectPasswordIsFollowedByAChallengeAndNotASession is the whole packet in
// one assertion: a challenge exists, a session does not.
//
// The "not a session" half is checked against the sessions table rather than
// against a return value, because a service that returned an error *and* wrote a
// session would defeat every check that looks at the return value.
func TestACorrectPasswordIsFollowedByAChallengeAndNotASession(t *testing.T) {
	h := newHarness(t)
	h.enroll()

	if got := h.liveSessions(); got != 0 {
		t.Fatalf("%d sessions exist before the login, want 0", got)
	}

	challenge := h.challengeAt()

	if challenge.Token == "" {
		t.Fatal("the challenge carries no token")
	}
	if !challenge.ExpiresAt.After(h.now()) {
		t.Errorf("the challenge expires at %s, which is not after %s", challenge.ExpiresAt, h.now())
	}
	if got := challenge.ExpiresAt.Sub(h.now()); got != ChallengeTTL {
		t.Errorf("the challenge is good for %s, want %s", got, ChallengeTTL)
	}

	// A challenge is NOT a session. The row exists and the sessions table is
	// still empty.
	if got := h.liveSessions(); got != 0 {
		t.Errorf("%d sessions exist after a challenge was created; a challenge is not a session", got)
	}
	if !challenge.Challenge.Live(h.now()) {
		t.Error("a fresh challenge does not report itself as live")
	}

	// And the token is not a session token, which is worth its own assertion: the
	// challenge is stored as a digest, so a token lifted out of a log resolves to
	// nothing.
	if _, err := sessions.NewStore(h.pool).ByToken(t.Context(), h.pool, challenge.Token, h.now()); !errors.Is(err, sessions.ErrNotFound) {
		t.Errorf("a challenge token resolved as a session token: %v", err)
	}
}

// TestAReplayedCodeIsRefused is the assertion the packet asks for by name.
//
// A code observed by a phishing page, a camera over a shoulder, or a proxy is good
// until it is used ONCE. This is the test that says so over a real database rather
// than in a comment.
func TestAReplayedCodeIsRefused(t *testing.T) {
	h := newHarness(t)
	h.enroll()
	challenge := h.challengeAt()
	// Captured ONCE. The code an attacker photographs is one fixed string, and
	// recomputing it after moving the clock would be a different code — which is
	// how a replay test quietly becomes a "does a fresh code work" test.
	captured := h.code()

	first, err := h.complete(challenge, captured)
	if err != nil {
		t.Fatalf("the first use of a code was refused: %v", err)
	}
	if first.Method() != MethodTOTP {
		t.Errorf("Method = %q, want %q", first.Method(), MethodTOTP)
	}

	// A fresh challenge, because the first one is spent. The code is not.
	h.clk.Advance(time.Second)
	if _, err := h.complete(h.challengeAt(), captured); !errors.Is(err, ErrInvalidFactor) {
		t.Errorf("a replayed code = %v, want ErrInvalidFactor", err)
	}

	// And it is refused THROUGH THE WHOLE WINDOW, not just immediately: move a
	// whole step on and try the same string again, which is the shape of the
	// attack — a code captured at the start of its period and replayed at the end.
	h.clk.Advance(Period + time.Second)
	if _, err := h.complete(h.challengeAt(), captured); !errors.Is(err, ErrInvalidFactor) {
		t.Errorf("a code replayed a whole step later = %v, want ErrInvalidFactor", err)
	}

	// Once it is out of the window it is refused by the window — and by then the
	// step has been pruned, so the two rules agree rather than one quietly
	// covering for the other.
	h.clk.Advance(Period + time.Second)
	if _, err := h.complete(h.challengeAt(), captured); !errors.Is(err, ErrInvalidFactor) {
		t.Errorf("a code from two steps ago = %v, want ErrInvalidFactor", err)
	}
}

// TestAReplayCountsAgainstTheSecondFactorIsNotOnTheSameTable as
// TestACorrectPasswordIsFollowedByAChallengeAndNotASession: a replay is a wrong
// code, and a wrong code has to be counted, or an attacker may present a captured
// code as often as they like for the window's length.
func TestAReplayCountsAgainstTheSecondFactor(t *testing.T) {
	h := newHarness(t)
	h.enroll()

	challenge := h.challengeAt()
	code := h.code()
	if _, err := h.complete(challenge, code); err != nil {
		t.Fatalf("the first use was refused: %v", err)
	}

	for i := range 2 {
		if _, err := h.complete(h.challengeAt(), code); !errors.Is(err, ErrInvalidFactor) {
			t.Fatalf("replay %d = %v, want ErrInvalidFactor", i+1, err)
		}
	}

	credential, err := h.store.ConfirmedCredential(t.Context(), h.pool, h.user.ID)
	if err != nil {
		t.Fatalf("reading the credential: %v", err)
	}
	if credential.FailedAttempts != 2 {
		t.Errorf("the second factor's counter is %d after two replays, want 2", credential.FailedAttempts)
	}
	// And the PASSWORD's counter, which is a different row and knows nothing about
	// any of this.
	user, err := users.NewStore(h.pool).ByID(t.Context(), h.pool, h.user.ID)
	if err != nil {
		t.Fatalf("reading the user: %v", err)
	}
	if user.FailedLoginAttempts != 0 || user.LockedUntil != nil {
		t.Errorf("the password's counter moved: %d attempts, locked until %v", user.FailedLoginAttempts, user.LockedUntil)
	}
}

// TestTheSkewWindowIsTheSameAtTheChallenge as it is at VerifyFactor, because a
// user types the code into the challenge form and nothing about the window may
// depend on which of the two entry points they used.
func TestTheSkewWindowIsTheSameAtTheChallenge(t *testing.T) {
	h := newHarness(t)
	h.enroll()
	secret := h.secret

	for _, c := range []struct {
		name  string
		steps int64
		want  bool
	}{
		{"two steps back is refused", -2, false},
		{"one step back is accepted", -1, true},
		{"the current step is accepted", 0, true},
		{"one step forward is accepted", 1, true},
		{"two steps forward is refused", 2, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			// Each case gets a fresh period, so a step spent by the previous case
			// cannot turn this into a replay assertion by accident.
			h.clk.Advance(Period * 10)
			base := StepAt(h.now(), Period)
			code := codeFor(t, secret, base+c.steps)

			_, err := h.complete(h.challengeAt(), code)
			if c.want && err != nil {
				t.Errorf("a code %d steps from now was refused: %v", c.steps, err)
			}
			if !c.want && !errors.Is(err, ErrInvalidFactor) {
				t.Errorf("a code %d steps from now = %v, want ErrInvalidFactor", c.steps, err)
			}
		})
	}
}

// TestTheChallengeIsSpentByASecondFactorAndNotByAWrongCode: a challenge is good
// for several attempts, because the per-factor lockout is what bounds them.
// Consuming it on the first wrong code would turn five guesses into one and make
// the lockout unreachable.
func TestTheChallengeIsSpentByASecondFactorAndNotByAWrongCode(t *testing.T) {
	h := newHarness(t)
	h.enroll()
	challenge := h.challengeAt()

	for i := range sessions.MaxFailedAttempts {
		if _, err := h.complete(challenge, "000000"); !errors.Is(err, ErrInvalidFactor) {
			t.Fatalf("wrong code %d = %v, want ErrInvalidFactor", i+1, err)
		}
	}

	// Locked out now, and the challenge is still there — the COUNTER, not the
	// challenge, is what stopped the fifth attempt from being the sixth. That is
	// the whole design: five guesses, not one.
	var locked *sessions.LockedError
	if _, err := h.complete(challenge, h.code()); !errors.As(err, &locked) {
		t.Errorf("attempt past the threshold = %v, want a *sessions.LockedError", err)
	}
	if _, err := h.store.LiveChallenge(t.Context(), h.pool, challenge.Token, h.now()); err != nil {
		t.Errorf("a wrong code consumed the challenge: %v", err)
	}

	// Past the lockout the CHALLENGE HAS ALSO EXPIRED, and that is deliberate
	// rather than an oversight. ChallengeTTL is ten minutes and LockoutDuration is
	// fifteen, so a user who trips the lockout waits longer than their challenge
	// lives and has to start the login again. The alternative — a challenge TTL
	// longer than the lockout — would mean holding a permission to finish a
	// sign-in for a quarter of an hour, which is the worse of the two by a long
	// way. The cost is a second password entry, and the password counter is clear
	// because it was never touched.
	h.clk.Advance(sessions.LockoutDuration + time.Second)
	if _, err := h.complete(challenge, h.code()); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("a challenge that outlived its own TTL was accepted: %v", err)
	}

	// A fresh login after the lockout, which is what a user actually does.
	fresh := h.challengeAt()
	h.clk.Advance(2 * Period)
	if _, err := h.complete(fresh, h.code()); err != nil {
		t.Errorf("a login that started after the lockout was refused: %v", err)
	}
	// And the challenge that finished it is spent, which is the assertion the
	// single-use rule exists for.
	h.clk.Advance(2 * Period)
	if _, err := h.complete(fresh, h.code()); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("a spent challenge was accepted: %v", err)
	}
}

// TestFourChallengeAnswersAreOneAnswer: no such token, an expired one, a consumed
// one, and a challenge for somebody who no longer exists. One error, because the
// difference between them is what an attacker probes for.
func TestFourChallengeAnswersAreOneAnswer(t *testing.T) {
	h := newHarness(t)
	h.enroll()

	// No such token.
	if _, err := h.complete(NewChallenge{Token: "not-a-token"}, "123456"); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("an unknown token = %v, want ErrChallengeNotFound", err)
	}

	// A consumed one.
	spent := h.challengeAt()
	if _, err := h.complete(spent, h.code()); err != nil {
		t.Fatalf("completing a challenge: %v", err)
	}
	h.clk.Advance(2 * Period)
	if _, err := h.complete(spent, h.code()); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("a consumed token = %v, want ErrChallengeNotFound", err)
	}

	// An expired one.
	expiring := h.challengeAt()
	h.clk.Advance(ChallengeTTL + time.Second)
	if _, err := h.complete(expiring, h.code()); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("an expired token = %v, want ErrChallengeNotFound", err)
	}

	// And a challenge belonging to a user who has been deleted, which the cascade
	// takes with them.
	deleted := h.challengeAt()
	if _, err := h.pool.Exec(t.Context(), `DELETE FROM users WHERE id = $1`, h.user.ID); err != nil {
		t.Fatalf("deleting the user: %v", err)
	}
	if _, err := h.complete(deleted, "123456"); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("a challenge for a deleted user = %v, want ErrChallengeNotFound", err)
	}
}

// TestASecondSignInSupersedesTheFirst, so a user cannot hold several open
// permissions to finish a login, and so the table is bounded by one row per user
// with no sweeper.
func TestASecondSignInSupersedesTheFirst(t *testing.T) {
	h := newHarness(t)
	h.enroll()

	first := h.challengeAt()
	h.clk.Advance(time.Second)
	second := h.challengeAt()

	h.clk.Advance(2 * Period)
	if _, err := h.complete(first, h.code()); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("the superseded challenge was accepted: %v", err)
	}
	if _, err := h.complete(second, h.code()); err != nil {
		t.Errorf("the current challenge was refused: %v", err)
	}
}

// TestALoginHalfwayThroughWhenTheUserChangesMFA answers the packet's second
// question — a login that is halfway through while the user enables MFA on another
// device — by reading the credential at verification time rather than caching it.
//
// Four situations, and all four fall out of one design decision:
//
//	the user ENABLED MFA on another device  this challenge now verifies against
//	                                  the new secret; the pending row is not a
//	                                  factor, so the challenge waits for the
//	                                  confirmation rather than skipping it
//	the user ROTATED the secret            the code from the old secret does not
//	                                  match the new one and is refused
//	the user DISABLED MFA                 there is no credential to verify
//	                                  against, and NO SESSION is minted
func TestALoginHalfwayThroughWhenTheUserChangesMFA(t *testing.T) {
	t.Run("the user disabled MFA on another device", func(t *testing.T) {
		h := newHarness(t)
		h.enroll()
		challenge := h.challengeAt()

		if err := h.svc.Disable(t.Context(), DisableInput{UserID: h.user.ID, Factor: h.code()}); err != nil {
			t.Fatalf("Disable: %v", err)
		}

		// The right code for the credential that is no longer there.
		if _, err := h.complete(challenge, h.code()); !errors.Is(err, ErrNotEnabled) {
			t.Errorf("verifying against a credential that is gone = %v, want ErrNotEnabled", err)
		}
		if got := h.liveSessions(); got != 0 {
			t.Errorf("%d sessions exist after a challenge against a disabled credential", got)
		}
	})

	t.Run("the user rotated the secret on another device", func(t *testing.T) {
		h := newHarness(t)
		h.enroll()
		challenge := h.challengeAt()
		oldCode := h.code()

		// Rotate: authorise with the current code, then confirm the new secret.
		started, err := h.svc.StartEnrollment(t.Context(), StartEnrollmentInput{UserID: h.user.ID, Factor: oldCode})
		if err != nil {
			t.Fatalf("rotating: %v", err)
		}
		h.secret = started.Secret
		h.clk.Advance(Period)
		if _, err := h.svc.Confirm(t.Context(), ConfirmInput{
			UserID: h.user.ID, EnrollmentID: started.Credential.ID, Factor: h.code(),
		}); err != nil {
			t.Fatalf("Confirm: %v", err)
		}

		// The code captured before the rotation no longer works, and that is the
		// whole of the rotation's security claim.
		h.clk.Advance(2 * Period)
		if _, err := h.complete(challenge, oldCode); !errors.Is(err, ErrInvalidFactor) {
			t.Errorf("a code from the rotated-away secret = %v, want ErrInvalidFactor", err)
		}
		// And the new secret's code does, against the same challenge.
		if _, err := h.complete(h.challengeAt(), h.code()); err != nil {
			t.Errorf("the new secret does not work against a challenge made before the rotation: %v", err)
		}
	})

	t.Run("the user enabled MFA on another device", func(t *testing.T) {
		h := newHarness(t)
		// A login that began while there was no MFA at all. There is no challenge
		// for it — internal/auth only mints one once it knows MFA is on — so what
		// this asserts is that a user who has since enrolled cannot be let in by a
		// flow that has not re-read their state.
		if enabled, err := h.svc.Enabled(t.Context(), h.pool, h.user.ID); err != nil || enabled {
			t.Fatalf("Enabled before enrollment = (%v, %v), want (false, nil)", enabled, err)
		}
		started, err := h.svc.StartEnrollment(t.Context(), StartEnrollmentInput{UserID: h.user.ID})
		if err != nil {
			t.Fatalf("StartEnrollment: %v", err)
		}
		h.secret = started.Secret
		// Unconfirmed: still not a factor, and the answer is ErrNotEnabled rather
		// than ErrInvalidFactor because that is the truer one — there is nothing
		// to verify against yet.
		if enabled, _ := h.svc.Enabled(t.Context(), h.pool, h.user.ID); enabled {
			t.Error("an unconfirmed enrollment reports MFA as enabled")
		}
		if _, err := h.svc.VerifyFactor(t.Context(), h.user.ID, h.code(), h.now()); !errors.Is(err, ErrNotEnabled) {
			t.Errorf("verifying against an unconfirmed secret = %v, want ErrNotEnabled", err)
		}
		if _, err := h.svc.Confirm(t.Context(), ConfirmInput{
			UserID: h.user.ID, EnrollmentID: started.Credential.ID, Factor: h.code(),
		}); err != nil {
			t.Fatalf("Confirm: %v", err)
		}
		if enabled, _ := h.svc.Enabled(t.Context(), h.pool, h.user.ID); !enabled {
			t.Error("a confirmed credential does not report MFA as enabled")
		}
	})
}

// TestCommitConsumesTheChallengeInsideTheCallersTransaction: the challenge goes
// away in the same transaction as the session, so a session that fails to be
// written leaves the challenge usable rather than a user with a half-finished
// login and no way to finish it.
//
// This test drives VerifyChallenge DIRECTLY rather than through h.complete, and
// that is deliberate: h.complete runs the whole login including the Commit this
// test is about, so using it here would commit the challenge before the assertion
// had a chance to roll it back.
func TestCommitConsumesTheChallengeInsideTheCallersTransaction(t *testing.T) {
	h := newHarness(t)
	h.enroll()
	challenge := h.challengeAt()

	claim, err := h.svc.VerifyChallenge(t.Context(), challenge.Token, h.code(), h.now())
	if err != nil {
		t.Fatalf("verifying: %v", err)
	}
	// The challenge is still live: VerifyFactor alone does not consume it.
	if _, err := h.store.LiveChallenge(t.Context(), h.pool, challenge.Token, h.now()); err != nil {
		t.Fatalf("the challenge was consumed before Commit: %v", err)
	}

	// A transaction that fails AFTER Commit has run.
	runner := h.svc.uow
	if err := runner.Do(t.Context(), func(ctx context.Context, q db.Querier) error {
		if err := h.svc.Commit(ctx, q, claim, h.now()); err != nil {
			return err
		}
		return errors.New("the session write failed")
	}); err == nil {
		t.Fatal("the transaction was expected to fail")
	}

	// The consumption rolled back, so the challenge is still live and a user who
	// presses "try again" is not locked out of a login they had already proved
	// half of. (The TOTP STEP did not roll back — the claim commits outside the
	// transaction, which is the documented trade-off — so the user needs the next
	// code, not this one.)
	if _, err := h.store.LiveChallenge(t.Context(), h.pool, challenge.Token, h.now()); err != nil {
		t.Errorf("a rolled-back Commit consumed the challenge anyway: %v", err)
	}

	// The next login completes on the same challenge with a fresh code.
	h.clk.Advance(Period + time.Second)
	if _, err := h.complete(challenge, h.code()); err != nil {
		t.Errorf("the challenge did not survive the rolled-back Commit: %v", err)
	}
}

// TestCommitClearsTheSecondFactorsFailureRun: accepting a factor has to reset the
// counter against that factor, or every fifth login ends in a lockout.
func TestCommitClearsTheSecondFactorsFailureRun(t *testing.T) {
	h := newHarness(t)
	h.enroll()

	for range sessions.MaxFailedAttempts - 1 {
		if _, err := h.complete(h.challengeAt(), "000000"); !errors.Is(err, ErrInvalidFactor) {
			t.Fatalf("a wrong code = %v, want ErrInvalidFactor", err)
		}
	}
	if credential, _ := h.store.ConfirmedCredential(t.Context(), h.pool, h.user.ID); credential.FailedAttempts == 0 {
		t.Fatal("the failures were not counted")
	}

	// A correct code as the fifth attempt is accepted — the lock begins on the
	// NEXT one — and the acceptance has to clear the run.
	h.clk.Advance(2 * Period)
	if _, err := h.complete(h.challengeAt(), h.code()); err != nil {
		t.Fatalf("a correct code after four wrong ones was refused: %v", err)
	}

	cleared, _ := h.store.ConfirmedCredential(t.Context(), h.pool, h.user.ID)
	if cleared.FailedAttempts != 0 || cleared.LockedUntil != nil {
		t.Errorf("after acceptance: %d attempts, locked until %v; want 0 and no lock",
			cleared.FailedAttempts, cleared.LockedUntil)
	}

	// A FRESH run of failures after the acceptance must therefore behave like a
	// fresh run: five of them are refused and the sixth finds the lock. A counter
	// that had not been cleared would already be at five before the first of them
	// and would answer this loop in one attempt, which is the observable
	// consequence the assertion below depends on.
	for range sessions.MaxFailedAttempts {
		if _, err := h.complete(h.challengeAt(), "000000"); !errors.Is(err, ErrInvalidFactor) {
			t.Fatalf("a wrong code after the reset = %v, want ErrInvalidFactor", err)
		}
	}
	var locked *sessions.LockedError
	if _, err := h.complete(h.challengeAt(), "000000"); !errors.As(err, &locked) {
		t.Errorf("the attempt after %d wrong ones = %v, want a *sessions.LockedError",
			sessions.MaxFailedAttempts, err)
	}
}

// TestTheSpentStepTableStaysSmall is the housekeeping assertion: a credential that
// has been used for a long time holds a handful of rows, not one per login.
func TestTheSpentStepTableStaysSmall(t *testing.T) {
	h := newHarness(t)
	h.enroll()

	for i := range 25 {
		h.clk.Advance(Period + time.Second)
		if _, err := h.complete(h.challengeAt(), h.code()); err != nil {
			t.Fatalf("login %d: %v", i, err)
		}
	}

	credential, _ := h.store.ConfirmedCredential(t.Context(), h.pool, h.user.ID)
	var rows int
	if err := h.pool.QueryRow(t.Context(),
		`SELECT count(*) FROM mfa_used_totp_steps WHERE credential_id = $1`, credential.ID).Scan(&rows); err != nil {
		t.Fatalf("counting spent steps: %v", err)
	}
	// At most (2·skew + 1) plus the step accepted in the same transaction as the
	// prune; the bound is the property, not the exact number.
	if rows > 2*SkewSteps+2 {
		t.Errorf("%d spent-step rows after 25 logins, want at most %d: the prune is not keeping up",
			rows, 2*SkewSteps+2)
	}
	if rows == 0 {
		t.Error("no spent-step rows at all; the prune is discarding the window it must keep")
	}
}

// TestAValueThatIsNeitherShapeIsRefusedWithoutTouchingTheDatabase, so a client
// with the wrong kind of value in the wrong field gets one sentence and this
// service does no work for it.
func TestAValueThatIsNeitherShapeIsRefusedWithoutTouchingTheDatabase(t *testing.T) {
	h := newHarness(t)
	h.enroll()

	for _, value := range []string{"", "   ", "abcdef", "12345", "12345678901", "not a code", "🙂"} {
		// The counter is reset between values so the assertion is about the shape
		// rather than about the lockout, which would otherwise answer on the fifth.
		h.clearFactorFailures()
		h.clk.Advance(Period + time.Second)
		if _, err := h.complete(h.challengeAt(), value); !errors.Is(err, ErrInvalidFactor) {
			t.Errorf("a value of %q = %v, want ErrInvalidFactor", value, err)
		}
	}
	h.clearFactorFailures()
}

// TestTheTokenIsStoredAsADigestAndTheRowIsBoundedByOneUser: the first is the
// reason a challenge token may live in a cookie, the second is why there is no
// sweeper.
func TestTheTokenIsStoredAsADigestAndTheRowIsBoundedByOneUser(t *testing.T) {
	h := newHarness(t)
	h.enroll()

	challenge := h.challengeAt()
	var stored string
	if err := h.pool.QueryRow(t.Context(),
		`SELECT token_digest FROM mfa_challenges WHERE id = $1`, challenge.Challenge.ID).Scan(&stored); err != nil {
		t.Fatalf("reading the challenge: %v", err)
	}
	if stored == challenge.Token {
		t.Fatal("the row holds the challenge token in the clear")
	}
	if stored != sessions.Digest(challenge.Token) {
		t.Error("the stored digest is not the one the sessions package produces")
	}
	if strings.Contains(stored, challenge.Token) {
		t.Error("the stored digest contains the token")
	}

	for range 4 {
		if _, err := h.svc.CreateChallenge(t.Context(), CreateChallengeInput{UserID: h.user.ID}); err != nil {
			t.Fatalf("CreateChallenge: %v", err)
		}
	}
	var rows int
	if err := h.pool.QueryRow(t.Context(),
		`SELECT count(*) FROM mfa_challenges WHERE user_id = $1`, h.user.ID).Scan(&rows); err != nil {
		t.Fatalf("counting challenges: %v", err)
	}
	if rows != 1 {
		t.Errorf("%d challenges for one user, want 1", rows)
	}
}
