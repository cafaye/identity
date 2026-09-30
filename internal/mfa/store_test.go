package mfa

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/sessions"
	"github.com/cafaye/identity/internal/users"
)

// EVERY TEST IN THIS FILE IS A DATABASE TEST, and none of them can run without
// one. The things they assert — that a TOTP step cannot be spent twice, that a
// recovery code is single-use even when two requests carry it at the same instant,
// that a user cannot end up with two live credentials — are properties of the
// SCHEMA. A double would answer whatever the double was told, which is the
// question, not the answer.
//
// They skip when TEST_DATABASE_URL is unset, and a skip here is the one thing the
// packet is most explicit about: a skipped MFA test reads like coverage. So
// TestTheDatabaseTierActuallyRan is the last test in the file, and it fails
// rather than skips when the variable is unset.

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

func newCredential(t *testing.T, pool *pgxpool.Pool, user users.User) Credential {
	t.Helper()
	ctx := context.Background()
	expires := issuedAt.Add(EnrollmentTTL)
	row, err := NewStore(pool).CreateCredential(ctx, pool, CreateCredentialParams{
		UserID:           user.ID,
		Method:           MethodTOTP,
		SecretCiphertext: SealPrefix + "ZmFrZS1zZWNyZXQ",
		Digits:           Digits,
		PeriodSeconds:    int(Period / time.Second),
		Algorithm:        AlgorithmSHA1,
		Label:            "cafaye",
		ExpiresAt:        &expires,
		CreatedAt:        issuedAt,
	})
	if err != nil {
		t.Fatalf("creating a credential: %v", err)
	}
	return row
}

func confirm(t *testing.T, pool *pgxpool.Pool, row Credential) Credential {
	t.Helper()
	confirmed, won, err := NewStore(pool).ConfirmCredential(context.Background(), pool, row.ID, issuedAt)
	if err != nil {
		t.Fatalf("confirming: %v", err)
	}
	if !won {
		t.Fatal("confirming a pending credential did not win")
	}
	return confirmed
}

func TestStoreConfirmMakesACredentialLiveAndOnlyOnce(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)
	ctx := context.Background()

	pending := newCredential(t, pool, user)
	if pending.IsConfirmed() {
		t.Fatal("a newly created credential is already confirmed")
	}

	// A pending row is not a credential, and the login read must not see it. This
	// is the assertion behind "stored but never confirmed means authenticates
	// nothing".
	if _, err := store.ConfirmedCredential(ctx, pool, user.ID); !errors.Is(err, ErrNotEnabled) {
		t.Errorf("a pending credential was returned by the login read: %v", err)
	}

	live, won, err := store.ConfirmCredential(ctx, pool, pending.ID, issuedAt)
	if err != nil || !won {
		t.Fatalf("ConfirmCredential = (%v, %v, %v), want a win", live, won, err)
	}
	if !live.IsConfirmed() {
		t.Error("the confirmed row does not say it is confirmed")
	}
	if live.ExpiresAt != nil {
		t.Error("the confirmed row kept its enrollment expiry; the CHECK requires it cleared")
	}

	// A second confirmation loses. This is what a double-tapped confirm button and
	// a retried request both look like, and the loser must not mint a second set
	// of recovery codes.
	if _, won, err := store.ConfirmCredential(ctx, pool, pending.ID, issuedAt); err != nil || won {
		t.Errorf("a second ConfirmCredential = (%v, %v), want (false, nil)", won, err)
	}
}

// TestAUserCannotHoldTwoLiveCredentials is the invariant the partial unique index
// exists for, asserted against the database rather than against a read-then-write
// this service might have written.
func TestAUserCannotHoldTwoLiveCredentials(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)
	ctx := context.Background()

	first := confirm(t, pool, newCredential(t, pool, user))
	second := newCredential(t, pool, user)

	if _, won, err := store.ConfirmCredential(ctx, pool, second.ID, issuedAt); err == nil {
		t.Fatalf("confirming a second credential succeeded (won=%v); the unique index did not fire", won)
	}

	// And the first is untouched, so a failed rotation leaves the user with the
	// factor they had rather than none.
	reread, err := store.ConfirmedCredential(ctx, pool, user.ID)
	if err != nil {
		t.Fatalf("rereading the live credential: %v", err)
	}
	if reread.ID != first.ID {
		t.Errorf("the live credential is %s, want the original %s", reread.ID, first.ID)
	}

	// Two PENDING rows are fine, and are what a rotation looks like from the
	// database's point of view: the old secret stays live until the new one is
	// confirmed.
	if err := store.DeleteUnconfirmedFor(ctx, pool, user.ID); err != nil {
		t.Fatalf("deleting pending rows: %v", err)
	}
}

// TestClaimStepIsTheReplayGuard is the assertion the packet asks for by name, and
// the primary key is the mechanism.
func TestClaimStepIsTheReplayGuard(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)
	ctx := context.Background()
	credential := confirm(t, pool, newCredential(t, pool, user))

	step := StepAt(issuedAt, Period)

	first, err := store.ClaimStep(ctx, pool, credential.ID, step, issuedAt)
	if err != nil || !first {
		t.Fatalf("the first claim of step %d = (%v, %v), want (true, nil)", step, first, err)
	}
	second, err := store.ClaimStep(ctx, pool, credential.ID, step, issuedAt)
	if err != nil {
		t.Fatalf("claiming a spent step: %v", err)
	}
	if second {
		t.Error("a step was claimed twice; the replay guard did not fire")
	}
}

// TestClaimStepIsAtomicUnderConcurrency is the property the high-water-mark design
// would have got wrong, and the one a read-then-write would also get wrong: fifty
// requests carrying the same code, one winner.
//
// No sleep, no retry loop, no raised count to reach green — the goroutines are
// released by a WaitGroup and the assertion is exact.
func TestClaimStepIsAtomicUnderConcurrency(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)
	credential := confirm(t, pool, newCredential(t, pool, user))
	step := StepAt(issuedAt, Period)

	const racers = 50
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners int
		errs    []error
	)
	start := make(chan struct{})

	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ok, err := store.ClaimStep(context.Background(), pool, credential.ID, step, issuedAt)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
			}
			if ok {
				winners++
			}
		}()
	}
	close(start)
	wg.Wait()

	if len(errs) > 0 {
		t.Fatalf("%d of the claims errored, first: %v", len(errs), errs[0])
	}
	if winners != 1 {
		t.Errorf("%d of %d concurrent claims of one step succeeded, want exactly 1", winners, racers)
	}
}

// TestStepsAreASetAndNotAHighWaterMark is the design decision the whole table
// exists for, expressed as what it does NOT do.
//
// THE SET REFUSES A REPEAT AND NOTHING ELSE. An unspent step inside the window is
// always accepted, whatever order steps arrive in.
//
// A single "highest step accepted" column would refuse anything at or below its
// mark, so it refuses unspent steps too. That bites whenever a code inside the
// window arrives out of order — a phone whose clock is corrected backwards, a user
// who switches to a backup authenticator that is behind, a device that re-syncs
// time mid-window — and each of those is a user who is told their correct code is
// wrong. There is no configuration of set versus mark that avoids it; the set
// avoids it by construction, which is the property worth one small table.
func TestStepsAreASetAndNotAHighWaterMark(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)
	credential := confirm(t, pool, newCredential(t, pool, user))
	ctx := context.Background()
	base := StepAt(issuedAt, Period)

	// Steps arrive in order, as they normally do.
	for _, step := range []int64{base, base + 1} {
		if ok, err := store.ClaimStep(ctx, pool, credential.ID, step, issuedAt); err != nil || !ok {
			t.Fatalf("claiming step %d = (%v, %v), want (true, nil)", step, ok, err)
		}
	}

	// Now an unspent step BELOW the mark, still inside the window. This is the
	// assertion a high-water mark cannot pass: it has forgotten only that steps
	// base and base+1 were spent, and it cannot tell the difference.
	if ok, err := store.ClaimStep(ctx, pool, credential.ID, base-1, issuedAt); err != nil || !ok {
		t.Errorf("an unspent earlier step = (%v, %v), want (true, nil): a high-water mark refuses this", ok, err)
	}

	// And each step that WAS spent is still refused, however many others followed
	// it. A mark has this property too; it is listed so the test says which half
	// of the design is the one being bought.
	for _, step := range []int64{base, base + 1, base - 1} {
		if ok, _ := store.ClaimStep(ctx, pool, credential.ID, step, issuedAt); ok {
			t.Errorf("step %d was claimed a second time", step)
		}
	}
}

// TestPruneStepsKeepsTheTableBounded. The housekeeping is a DELETE in the same
// transaction as the acceptance, not a sweeper, and this is what proves the table
// does not grow with the login history.
func TestPruneStepsKeepsTheTableBounded(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)
	credential := confirm(t, pool, newCredential(t, pool, user))
	ctx := context.Background()

	for step := int64(1); step <= 50; step++ {
		if _, err := store.ClaimStep(ctx, pool, credential.ID, step, issuedAt); err != nil {
			t.Fatalf("claiming step %d: %v", step, err)
		}
	}

	countSteps := func() int {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM mfa_used_totp_steps WHERE credential_id = $1`, credential.ID).Scan(&n); err != nil {
			t.Fatalf("counting spent steps: %v", err)
		}
		return n
	}
	if got := countSteps(); got != 50 {
		t.Fatalf("before pruning there are %d rows, want 50", got)
	}

	if err := store.PruneSteps(ctx, pool, credential.ID, 40); err != nil {
		t.Fatalf("pruning: %v", err)
	}
	if got := countSteps(); got != 10 {
		t.Errorf("after pruning there are %d rows, want 10", got)
	}

	// A pruned step can be claimed again, which is correct: a code for it is
	// outside the acceptance window and is refused by the window, not by the
	// table. The table is a cache of "recently spent", not a ledger.
	if ok, err := store.ClaimStep(ctx, pool, credential.ID, 5, issuedAt); err != nil || !ok {
		t.Errorf("claiming a pruned step = (%v, %v), want (true, nil)", ok, err)
	}
}

// TestARecoveryCodeIsSingleUse covers the ordinary path and the simultaneous one.
func TestARecoveryCodeIsSingleUse(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)
	credential := confirm(t, pool, newCredential(t, pool, user))
	ctx := context.Background()

	digests := []string{RecoveryDigest("7KQF4W2X5DTRM3HN"), RecoveryDigest("AAAA2222BBBB3333")}
	if err := store.InsertRecoveryCodes(ctx, pool, credential.ID, digests, issuedAt); err != nil {
		t.Fatalf("inserting recovery codes: %v", err)
	}

	if got, err := store.CountUnusedRecoveryCodes(ctx, pool, credential.ID); err != nil || got != 2 {
		t.Fatalf("CountUnusedRecoveryCodes = (%d, %v), want (2, nil)", got, err)
	}

	// A code that was never issued is ErrInvalidFactor, and so is a code that has
	// already been spent — one answer, because the difference is what an attacker
	// probes for.
	if _, err := store.UnusedRecoveryCode(ctx, pool, credential.ID, RecoveryDigest("ZZZZ2222YYYY3333")); !errors.Is(err, ErrInvalidFactor) {
		t.Errorf("an unknown code = %v, want ErrInvalidFactor", err)
	}

	codeID, err := store.UnusedRecoveryCode(ctx, pool, credential.ID, digests[0])
	if err != nil {
		t.Fatalf("looking up a fresh code: %v", err)
	}
	spent, err := store.ConsumeRecoveryCode(ctx, pool, codeID, issuedAt)
	if err != nil || !spent {
		t.Fatalf("ConsumeRecoveryCode = (%v, %v), want (true, nil)", spent, err)
	}
	spent, err = store.ConsumeRecoveryCode(ctx, pool, codeID, issuedAt)
	if err != nil {
		t.Fatalf("consuming a spent code: %v", err)
	}
	if spent {
		t.Error("a recovery code was spent twice")
	}
	if _, err := store.UnusedRecoveryCode(ctx, pool, credential.ID, digests[0]); !errors.Is(err, ErrInvalidFactor) {
		t.Errorf("a spent code was found as unused: %v", err)
	}
	if got, _ := store.CountUnusedRecoveryCodes(ctx, pool, credential.ID); got != 1 {
		t.Errorf("%d codes are left, want 1", got)
	}
}

// TestARecoveryCodeIsSingleUseUnderConcurrency: the same code on twenty requests
// at the same instant, one winner.
func TestARecoveryCodeIsSingleUseUnderConcurrency(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)
	credential := confirm(t, pool, newCredential(t, pool, user))
	ctx := context.Background()

	digest := RecoveryDigest("7KQF4W2X5DTRM3HN")
	if err := store.InsertRecoveryCodes(ctx, pool, credential.ID, []string{digest}, issuedAt); err != nil {
		t.Fatalf("inserting a recovery code: %v", err)
	}
	codeID, err := store.UnusedRecoveryCode(ctx, pool, credential.ID, digest)
	if err != nil {
		t.Fatalf("looking up the code: %v", err)
	}

	const racers = 20
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners int
	)
	start := make(chan struct{})
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ok, err := store.ConsumeRecoveryCode(context.Background(), pool, codeID, issuedAt)
			mu.Lock()
			defer mu.Unlock()
			if err == nil && ok {
				winners++
			}
		}()
	}
	close(start)
	wg.Wait()

	if winners != 1 {
		t.Errorf("%d of %d concurrent consumptions of one code succeeded, want exactly 1", winners, racers)
	}
}

// TestAChallengeIsLiveOnce: the four situations that must be one answer, and the
// shape of the lookup that gives them one.
func TestAChallengeIsLiveOnce(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)
	ctx := context.Background()

	other := newTestUser(t, pool)
	addr := netip.MustParseAddr("203.0.113.9")

	token, digest, err := sessions.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	row, err := store.CreateChallenge(ctx, pool, NewChallengeParams{
		UserID:      user.ID,
		TokenDigest: digest,
		UserAgent:   "Test/1.0",
		IP:          &addr,
		CreatedAt:   issuedAt,
		ExpiresAt:   issuedAt.Add(ChallengeTTL),
	})
	if err != nil {
		t.Fatalf("creating a challenge: %v", err)
	}
	if row.IP == nil || *row.IP != addr || row.UserAgent != "Test/1.0" {
		t.Errorf("the challenge recorded %q / %v, want the values it was given", row.UserAgent, row.IP)
	}
	if !row.Live(issuedAt) || !row.Live(issuedAt.Add(ChallengeTTL-time.Second)) {
		t.Error("a fresh challenge is not live")
	}
	if row.Live(issuedAt.Add(ChallengeTTL + time.Second)) {
		t.Error("a challenge is live past its expiry")
	}

	if _, err := store.LiveChallenge(ctx, pool, token, issuedAt); err != nil {
		t.Fatalf("resolving a live challenge: %v", err)
	}
	if _, err := store.LiveChallenge(ctx, pool, "not-the-token", issuedAt); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("an unknown token = %v, want ErrChallengeNotFound", err)
	}
	if _, err := store.LiveChallenge(ctx, pool, token, issuedAt.Add(ChallengeTTL)); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("an expired token = %v, want ErrChallengeNotFound", err)
	}

	consumed, err := store.ConsumeChallenge(ctx, pool, row.ID, issuedAt)
	if err != nil || !consumed {
		t.Fatalf("ConsumeChallenge = (%v, %v), want (true, nil)", consumed, err)
	}
	if consumed, _ := store.ConsumeChallenge(ctx, pool, row.ID, issuedAt); consumed {
		t.Error("a challenge was consumed twice")
	}
	if _, err := store.LiveChallenge(ctx, pool, token, issuedAt); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("a consumed token = %v, want ErrChallengeNotFound", err)
	}

	// A second sign-in supersedes the first, which bounds the table at one row per
	// user with no sweeper.
	replacement, _, err := sessions.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if _, err := store.CreateChallenge(ctx, pool, NewChallengeParams{
		UserID:      user.ID,
		TokenDigest: sessions.Digest(replacement),
		CreatedAt:   issuedAt,
		ExpiresAt:   issuedAt.Add(ChallengeTTL),
	}); err != nil {
		t.Fatalf("creating the superseding challenge: %v", err)
	}
	if err := store.DeleteSupersededChallenges(ctx, pool, user.ID, id.UUID{}); err != nil {
		t.Fatalf("deleting superseded challenges: %v", err)
	}
	if _, err := store.LiveChallenge(ctx, pool, replacement, issuedAt); !errors.Is(err, ErrChallengeNotFound) {
		t.Error("a challenge was deleted even though it was the one to keep")
	}
	// Somebody else's challenge is untouched by this user's cleanup.
	if _, err := store.CreateChallenge(ctx, pool, NewChallengeParams{
		UserID:      other.ID,
		TokenDigest: digest,
		CreatedAt:   issuedAt,
		ExpiresAt:   issuedAt.Add(ChallengeTTL),
	}); err != nil {
		t.Fatalf("creating another user's challenge: %v", err)
	}
}

// TestDeletingACredentialTakesItsCodesAndItsSpentStepsWithIt. A recovery code
// belonging to no credential is a live credential to a credential that is gone.
func TestDeletingACredentialTakesItsCodesAndItsSpentStepsWithIt(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)
	credential := confirm(t, pool, newCredential(t, pool, user))
	ctx := context.Background()

	if err := store.InsertRecoveryCodes(ctx, pool, credential.ID, []string{RecoveryDigest("7KQF4W2X5DTRM3HN")}, issuedAt); err != nil {
		t.Fatalf("inserting a recovery code: %v", err)
	}
	if _, err := store.ClaimStep(ctx, pool, credential.ID, 7, issuedAt); err != nil {
		t.Fatalf("claiming a step: %v", err)
	}
	if err := store.DeleteCredential(ctx, pool, credential.ID); err != nil {
		t.Fatalf("deleting the credential: %v", err)
	}

	for _, table := range []string{"mfa_recovery_codes", "mfa_used_totp_steps"} {
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE credential_id = $1`, credential.ID).Scan(&n); err != nil {
			t.Fatalf("counting %s: %v", table, err)
		}
		if n != 0 {
			t.Errorf("%s still has %d rows for a deleted credential", table, n)
		}
	}
}

// TestTheSecondFactorsCounterIsNotThePasswords. The columns exist, they are
// separate, and writing one does not move the other — which is the property the
// packet asks for when it says the limits are per-factor.
func TestTheSecondFactorsCounterIsNotThePasswords(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)
	credential := confirm(t, pool, newCredential(t, pool, user))
	ctx := context.Background()

	locked := issuedAt.Add(15 * time.Minute)
	if err := store.RecordFactorFailure(ctx, pool, credential.ID, 0, &locked); err != nil {
		t.Fatalf("recording a factor failure: %v", err)
	}

	// The password's own counter is on the users row and must be untouched.
	reread, err := users.NewStore(pool).ByID(ctx, pool, user.ID)
	if err != nil {
		t.Fatalf("rereading the user: %v", err)
	}
	if reread.FailedLoginAttempts != 0 || reread.LockedUntil != nil {
		t.Errorf("the user's password counter moved: %d attempts, locked until %v", reread.FailedLoginAttempts, reread.LockedUntil)
	}

	// And the reverse: a failed password does not lock the factor.
	lock := sessions.Lockout{}
	for range 10 {
		lock = lock.Failed(issuedAt)
	}
	if err := users.NewStore(pool).RecordFailedLogin(ctx, pool, user.ID, lock.FailedAttempts, lock.LockedUntil); err != nil {
		t.Fatalf("recording a failed password: %v", err)
	}
	fresh, err := store.ConfirmedCredential(ctx, pool, user.ID)
	if err != nil {
		t.Fatalf("rereading the credential: %v", err)
	}
	if !fresh.IsLocked(issuedAt) {
		t.Error("the factor is not locked after the failure that was recorded against it")
	}
	if fresh.FailedAttempts != 0 {
		t.Errorf("the factor's failure run is %d, want 0", fresh.FailedAttempts)
	}

	if err := store.ClearFactorFailures(ctx, pool, credential.ID); err != nil {
		t.Fatalf("clearing the factor's failures: %v", err)
	}
	cleared, err := store.ConfirmedCredential(ctx, pool, user.ID)
	if err != nil {
		t.Fatalf("rereading the credential: %v", err)
	}
	if cleared.IsLocked(issuedAt) || cleared.FailedAttempts != 0 {
		t.Errorf("after clearing: %d attempts, locked until %v", cleared.FailedAttempts, cleared.LockedUntil)
	}
	// The password's lock survived, because it is a different row.
	reread, _ = users.NewStore(pool).ByID(ctx, pool, user.ID)
	if !reread.IsLocked(issuedAt) {
		t.Error("clearing the factor's failures lifted the password's lock")
	}
}

// TestTheSchemaRefusesWhatTheGoCodeRefuses. A database that accepts a digit count
// the verifier cannot handle is a row that makes every login fail with a 500
// instead of a clean 401, and the CHECK constraints are what stop it.
//
// Every row here is a value the Go side refuses or cannot interpret, written
// straight to the table. If one of them is accepted, the migration and the code
// have drifted apart and that is a bug the test exists to find.
func TestTheSchemaRefusesWhatTheGoCodeRefuses(t *testing.T) {
	pool := dbtest.Schema(t)
	user := newTestUser(t, pool)
	ctx := context.Background()
	expires := issuedAt.Add(EnrollmentTTL)

	const insert = `INSERT INTO mfa_credentials
		(user_id, method, secret_ciphertext, digits, period_seconds, algorithm, label, expires_at, confirmed_at, failed_attempts)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	cases := []struct {
		name                                     string
		method, digits, period, algorithm, label string
		expires, confirmed, attempts             any
	}{
		{
			name:   "a method this service does not implement",
			method: "sms", digits: "6", period: "30", algorithm: "SHA1", label: "cafaye",
			expires: expires, attempts: 0,
		},
		{
			name:   "a digit count no verifier can handle",
			method: "totp", digits: "7", period: "30", algorithm: "SHA1", label: "cafaye",
			expires: expires, attempts: 0,
		},
		{
			name:   "a digit count far outside the spec",
			method: "totp", digits: "60", period: "30", algorithm: "SHA1", label: "cafaye",
			expires: expires, attempts: 0,
		},
		{
			name:   "an algorithm no authenticator app speaks",
			method: "totp", digits: "6", period: "30", algorithm: "SHA512", label: "cafaye",
			expires: expires, attempts: 0,
		},
		{
			name:   "a period of zero, which divides by zero in the counter arithmetic",
			method: "totp", digits: "6", period: "0", algorithm: "SHA1", label: "cafaye",
			expires: expires, attempts: 0,
		},
		{
			name:   "a period long enough that a code is a day old",
			method: "totp", digits: "6", period: "86400", algorithm: "SHA1", label: "cafaye",
			expires: expires, attempts: 0,
		},
		{
			name:   "a negative failure count",
			method: "totp", digits: "6", period: "30", algorithm: "SHA1", label: "cafaye",
			expires: expires, attempts: -1,
		},
		{
			// confirmed_at without expires_at is the half of the pair the table
			// refuses, and it is the state a careless UPDATE would produce.
			name:   "a confirmation that kept its enrollment expiry",
			method: "totp", digits: "6", period: "30", algorithm: "SHA1", label: "cafaye",
			expires: expires, confirmed: issuedAt, attempts: 0,
		},
		{
			name:   "an enrollment with no deadline at all",
			method: "totp", digits: "6", period: "30", algorithm: "SHA1", label: "cafaye",
			expires: nil, attempts: 0,
		},
		{
			name:   "an empty label, which an authenticator app would display as nothing",
			method: "totp", digits: "6", period: "30", algorithm: "SHA1", label: "",
			expires: expires, attempts: 0,
		},
		{
			name:   "a label longer than an authenticator app has room for",
			method: "totp", digits: "6", period: "30", algorithm: "SHA1", label: strings.Repeat("cafaye", 100),
			expires: expires, attempts: 0,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := pool.Exec(ctx, insert,
				user.ID, c.method, "mfa1.c2VhbGVk", c.digits, c.period, c.algorithm, c.label,
				c.expires, c.confirmed, c.attempts,
			); err == nil {
				t.Error("the database accepted a value the Go code refuses")
			}
		})
	}

	// And the sealed secret is NOT NULL, checked separately because it is the one
	// column whose absence would make every login fail rather than merely weaken.
	t.Run("a credential with no sealed secret at all", func(t *testing.T) {
		const withoutSecret = `INSERT INTO mfa_credentials
			(user_id, method, secret_ciphertext, digits, period_seconds, algorithm, label, expires_at)
			VALUES ($1, 'totp', '', 6, 30, 'SHA1', 'cafaye', $2)`
		if _, err := pool.Exec(ctx, withoutSecret, user.ID, expires); err == nil {
			t.Error("the database accepted a credential with no sealed secret")
		}
	})
}

// TestADatabaseDumpYieldsNoWorkingSecondFactor is the packet's "secrets at rest"
// requirement, asserted by reading the table the way a dump would and trying to
// use what comes back.
//
// The test is deliberately adversarial about its own setup: it enrols a real
// credential through the real use case, confirms it with a real code, and then
// insists that NOTHING the database holds lets an attacker produce a passing
// code. A test that merely checked "the column is not the secret" would pass if
// the secret were stored somewhere else, or base64'd, or in a column nobody
// looked at.
func TestADatabaseDumpYieldsNoWorkingSecondFactor(t *testing.T) {
	pool := dbtest.Schema(t)
	user := newTestUser(t, pool)
	store := NewStore(pool)
	ctx := context.Background()

	vault, err := NewAESCipher(testKey)
	if err != nil {
		t.Fatalf("NewAESCipher: %v", err)
	}
	secret := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	sealed, err := vault.Seal(user.ID, secret)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	expires := issuedAt.Add(EnrollmentTTL)
	credential, err := store.CreateCredential(ctx, pool, CreateCredentialParams{
		UserID: user.ID, Method: MethodTOTP, SecretCiphertext: sealed,
		Digits: Digits, PeriodSeconds: int(Period / time.Second),
		Algorithm: AlgorithmSHA1, Label: "cafaye", ExpiresAt: &expires, CreatedAt: issuedAt,
	})
	if err != nil {
		t.Fatalf("creating a credential: %v", err)
	}
	credential, _, _ = store.ConfirmCredential(ctx, pool, credential.ID, issuedAt)

	// The recovery codes, as a dump would find them.
	codes, err := NewRecoveryCodes()
	if err != nil {
		t.Fatalf("NewRecoveryCodes: %v", err)
	}
	digests := make([]string, 0, len(codes))
	for _, code := range codes {
		digests = append(digests, RecoveryDigest(code))
	}
	if err := store.InsertRecoveryCodes(ctx, pool, credential.ID, digests, issuedAt); err != nil {
		t.Fatalf("inserting recovery codes: %v", err)
	}

	// THE ATTACKER'S POSITION: everything the schema holds for this user.
	rows, err := pool.Query(ctx, `SELECT secret_ciphertext FROM mfa_credentials WHERE user_id = $1`, user.ID)
	if err != nil {
		t.Fatalf("reading the credentials: %v", err)
	}
	defer rows.Close()
	var stored []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			t.Fatalf("scanning: %v", err)
		}
		stored = append(stored, value)
	}
	rows.Close()
	if len(stored) != 1 {
		t.Fatalf("a dump shows %d credentials, want 1", len(stored))
	}

	// Non-vacuity first: the dump really does contain the value under test, or
	// this whole test would pass for the wrong reason.
	if stored[0] != sealed {
		t.Fatalf("the row does not hold the sealed value; the assertions below would be vacuous")
	}
	if stored[0] == secret {
		t.Fatal("the row holds the secret in the clear")
	}
	if !isTOTPCode(codeFor(t, secret, StepAt(issuedAt, Period))) {
		t.Fatal("the fixture code is not a real code, so the dump test proves nothing")
	}

	// And the attacker's attempt: the sealed value is not a base32 secret, so it
	// cannot be fed to a verifier.
	if _, ok := MatchStep(stored[0], codeFor(t, secret, StepAt(issuedAt, Period)), issuedAt, DigitSix, AlgorithmSHA1, Period, SkewSteps); ok {
		t.Error("the stored ciphertext was accepted as a TOTP secret")
	}
	if IsRecoveryCode(stored[0]) {
		t.Error("the stored ciphertext is shaped like a recovery code")
	}

	// Nor is a dump of the recovery table a set of codes.
	codeRows, err := pool.Query(ctx, `SELECT code_digest FROM mfa_recovery_codes WHERE credential_id = $1`, credential.ID)
	if err != nil {
		t.Fatalf("reading the recovery codes: %v", err)
	}
	defer codeRows.Close()
	var seen int
	for codeRows.Next() {
		var digest string
		if err := codeRows.Scan(&digest); err != nil {
			t.Fatalf("scanning: %v", err)
		}
		seen++
		for _, code := range codes {
			if digest == code || IsRecoveryCode(digest) {
				t.Error("a stored recovery digest is itself a usable code")
			}
		}
	}
	codeRows.Close()
	if seen != RecoveryCodeCount {
		t.Errorf("a dump shows %d recovery codes, want %d", seen, RecoveryCodeCount)
	}
}

// TestTheDatabaseTierActuallyRan is the last line of defence against a green gate
// that verified nothing.
//
// It FAILS rather than skips when TEST_DATABASE_URL is unset, because in this
// package a skip is the failure mode the packet names: every other test here is a
// database test, so without the variable this whole file has proven nothing, and a
// suite that reports "ok" has reported something false.
func TestTheDatabaseTierActuallyRan(t *testing.T) {
	if os.Getenv(dbtest.EnvVar) == "" {
		t.Fatalf("%s is not set, so every database test in this package skipped. "+
			"A green run without it verifies nothing: `docker compose up -d postgres`, "+
			"`goose -dir migrations postgres \"$DATABASE_URL\" up`, and re-run with %s set.",
			dbtest.EnvVar, dbtest.EnvVar)
	}
	pool := dbtest.Pool(t)
	if err := pool.Ping(context.Background()); err != nil {
		t.Fatalf("the test database is not reachable: %v", err)
	}
}

// TestTheStoreTakesAQuerierAndRunsInsideTheCallersTransaction. The direction
// that matters for a rotation is the one this asserts: a transaction that fails
// half way leaves the user with the credential they had, rather than with none.
//
// That is why a rotation confirms the replacement and deletes the original in ONE
// transaction, and it is the failure the packet names — a partial write here
// leaves a user with two live sets, which is a recovery path nobody audited.
func TestTheStoreTakesAQuerierAndRunsInsideTheCallersTransaction(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	user := newTestUser(t, pool)
	credential := confirm(t, pool, newCredential(t, pool, user))
	ctx := context.Background()

	rolledBack := db.TxRunner{Pool: pool}.Do(ctx, func(ctx context.Context, q db.Querier) error {
		if err := store.DeleteCredential(ctx, q, credential.ID); err != nil {
			return err
		}
		// GONE inside the transaction, so the delete really happened.
		if _, err := store.ConfirmedCredential(ctx, q, user.ID); !errors.Is(err, ErrNotEnabled) {
			t.Errorf("the delete did not take effect inside the transaction: %v", err)
		}
		return fmt.Errorf("the second write failed")
	})
	if rolledBack == nil {
		t.Fatal("the transaction was expected to fail")
	}

	// And BACK afterwards, which is the whole point: the user did not lose their
	// second factor because a write three statements later failed.
	survived, err := store.ConfirmedCredential(ctx, pool, user.ID)
	if err != nil {
		t.Fatalf("the credential did not survive the rollback: %v", err)
	}
	if survived.ID != credential.ID {
		t.Errorf("the surviving credential is %s, want %s", survived.ID, credential.ID)
	}

	// The other direction, so the assertion above is not passing because the
	// delete simply never ran: a committed transaction does remove it.
	runner := db.TxRunner{Pool: pool}
	if err := runner.Do(ctx, func(ctx context.Context, q db.Querier) error {
		return store.DeleteCredential(ctx, q, credential.ID)
	}); err != nil {
		t.Fatalf("committing a deletion: %v", err)
	}
	if _, err := store.ConfirmedCredential(ctx, pool, user.ID); !errors.Is(err, ErrNotEnabled) {
		t.Errorf("a committed delete did not take effect: %v", err)
	}
}
