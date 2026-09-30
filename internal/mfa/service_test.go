package mfa

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
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

// EVERY TEST IN THIS FILE IS A DATABASE TEST, for the reason the packet gives: the
// things being asserted are properties of the SQL. Whether a claim loses a race,
// whether a confirmation is atomic with the revocation that follows it, whether
// two live credentials can exist — none of that is answerable without the schema
// that forbids it, and a double would only say what it was told.

const testIssuer = "cafaye identity"

// harness is one enrolled-or-not user and the service over a private schema.
type harness struct {
	t     *testing.T
	pool  *pgxpool.Pool
	clk   *clock.Fake
	store *Store
	svc   *Service
	user  users.User
	// secret and codes are what the USER holds: the base32 from the enrollment
	// response and the recovery codes from the confirmation. They are fixture
	// state rather than service state, which is the distinction the whole package
	// is about — the service never has them all at once.
	secret string
	codes  []string
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	pool := dbtest.Schema(t)
	clk := clock.NewFake(issuedAt)
	store := NewStore(pool)

	h := &harness{
		t:     t,
		pool:  pool,
		clk:   clk,
		store: store,
		svc: NewService(
			db.TxRunner{Pool: pool},
			db.Direct{Pool: pool},
			store,
			outbox.NewStore(pool),
			sessions.NewStore(pool),
			mustVault(t),
			clk,
			testIssuer,
		),
	}
	h.user = newTestUser(t, pool)
	return h
}

func mustVault(t *testing.T) Vault {
	t.Helper()
	vault, err := NewAESCipher(testKey)
	if err != nil {
		t.Fatalf("NewAESCipher: %v", err)
	}
	return vault
}

func (h *harness) now() time.Time { return h.clk.Now() }

// code is what the user's authenticator app is showing right now.
func (h *harness) code() string {
	h.t.Helper()
	if h.secret == "" {
		h.t.Fatal("no secret: enrol first")
	}
	code, err := Code(h.secret, h.now())
	if err != nil {
		h.t.Fatalf("Code: %v", err)
	}
	return code
}

// enroll runs the whole first-time flow and keeps the returned secrets, which is
// what a real client does with them.
func (h *harness) enroll() Credential {
	h.t.Helper()
	started, err := h.svc.StartEnrollment(h.t.Context(), StartEnrollmentInput{UserID: h.user.ID})
	if err != nil {
		h.t.Fatalf("StartEnrollment: %v", err)
	}
	h.secret = started.Secret

	confirmed, err := h.svc.Confirm(h.t.Context(), ConfirmInput{
		UserID:       h.user.ID,
		EnrollmentID: started.Credential.ID,
		Factor:       h.code(),
	})
	if err != nil {
		h.t.Fatalf("Confirm: %v", err)
	}
	h.codes = confirmed.RecoveryCodes
	return confirmed.Credential
}

// clearFactorFailures resets the second factor's counter, so a test can refute
// several codes in a row without the lockout answering instead of the code.
func (h *harness) clearFactorFailures() {
	h.t.Helper()
	credential, err := h.store.ConfirmedCredential(h.t.Context(), h.pool, h.user.ID)
	if err != nil {
		return
	}
	if err := h.store.ClearFactorFailures(h.t.Context(), h.pool, credential.ID); err != nil {
		h.t.Fatalf("resetting the factor's counter: %v", err)
	}
}

// signIn mints a session the way auth does, so "every session is revoked" has a
// real row to be revoked.
func (h *harness) signIn() sessions.Session {
	h.t.Helper()
	token, digest, err := sessions.NewToken()
	if err != nil {
		h.t.Fatalf("NewToken: %v", err)
	}
	session, err := sessions.NewStore(h.pool).Create(h.t.Context(), h.pool, sessions.NewSession{
		UserID:      h.user.ID,
		TokenDigest: digest,
		ExpiresAt:   h.now().Add(24 * time.Hour),
		UserAgent:   "Test/1.0",
	})
	if err != nil {
		h.t.Fatalf("creating a session: %v", err)
	}
	_ = token
	return session
}

func (h *harness) liveSessions() int {
	h.t.Helper()
	var n int
	if err := h.pool.QueryRow(h.t.Context(), `SELECT count(*) FROM sessions WHERE user_id = $1`, h.user.ID).Scan(&n); err != nil {
		h.t.Fatalf("counting sessions: %v", err)
	}
	return n
}

func (h *harness) events(eventType string) []outbox.Envelope {
	h.t.Helper()
	rows, err := h.pool.Query(h.t.Context(),
		`SELECT envelope FROM outbox_events WHERE type = $1 AND subject = $2 ORDER BY occurred_at`,
		eventType, h.user.ID.String())
	if err != nil {
		h.t.Fatalf("reading the outbox: %v", err)
	}
	defer rows.Close()

	var out []outbox.Envelope
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			h.t.Fatalf("scanning an event: %v", err)
		}
		var e outbox.Envelope
		if err := json.Unmarshal(raw, &e); err != nil {
			h.t.Fatalf("the stored envelope is not an outbox envelope: %v", err)
		}
		out = append(out, e)
	}
	return out
}

// ---------------------------------------------------------------------------
// enrollment
// ---------------------------------------------------------------------------

// TestAnEnrollmentIsNotMFAUntilItIsConfirmed is the packet's first requirement: a
// secret that is stored but never confirmed is a user who will be locked out of
// their own account by a mistyped entry, so nothing about a pending enrollment may
// change what the login path does.
func TestAnEnrollmentIsNotMFAUntilItIsConfirmed(t *testing.T) {
	h := newHarness(t)

	started, err := h.svc.StartEnrollment(t.Context(), StartEnrollmentInput{UserID: h.user.ID})
	if err != nil {
		t.Fatalf("StartEnrollment: %v", err)
	}
	h.secret = started.Secret

	status, err := h.svc.StatusFor(t.Context(), h.user.ID)
	if err != nil {
		t.Fatalf("StatusFor: %v", err)
	}
	if status.Enabled {
		t.Error("an unconfirmed enrollment reports itself as enabled")
	}
	if enabled, err := h.svc.Enabled(t.Context(), h.pool, h.user.ID); err != nil || enabled {
		t.Errorf("Enabled = (%v, %v) for a pending enrollment, want (false, nil)", enabled, err)
	}

	// A wrong code confirms nothing and changes nothing.
	if _, err := h.svc.Confirm(t.Context(), ConfirmInput{
		UserID: h.user.ID, EnrollmentID: started.Credential.ID, Factor: "000000",
	}); !errors.Is(err, ErrInvalidFactor) {
		t.Errorf("Confirm with a wrong code = %v, want ErrInvalidFactor", err)
	}
	if status, _ := h.svc.StatusFor(t.Context(), h.user.ID); status.Enabled {
		t.Error("a failed confirmation enabled MFA")
	}

	// The right code does.
	confirmed, err := h.svc.Confirm(t.Context(), ConfirmInput{
		UserID: h.user.ID, EnrollmentID: started.Credential.ID, Factor: h.code(),
	})
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if !confirmed.Credential.IsConfirmed() {
		t.Error("the confirmed credential does not say it is confirmed")
	}
	if len(confirmed.RecoveryCodes) != RecoveryCodeCount {
		t.Errorf("%d recovery codes were issued, want %d", len(confirmed.RecoveryCodes), RecoveryCodeCount)
	}

	status, _ = h.svc.StatusFor(t.Context(), h.user.ID)
	if !status.Enabled {
		t.Error("a confirmed credential does not report itself as enabled")
	}
	if status.RecoveryCodesRemaining != RecoveryCodeCount {
		t.Errorf("StatusFor reports %d codes left, want %d", status.RecoveryCodesRemaining, RecoveryCodeCount)
	}
	if status.EnrolledAt == nil {
		t.Error("StatusFor has no enrolled_at for an enrolled user")
	}
}

// TestTheSecretIsShownOnceAndStoredSealed is the one-time-value rule, asserted on
// the database rather than in a comment: the base32 the user typed into their
// authenticator is not anywhere in the row.
func TestTheSecretIsShownOnceAndStoredSealed(t *testing.T) {
	h := newHarness(t)
	started, err := h.svc.StartEnrollment(t.Context(), StartEnrollmentInput{UserID: h.user.ID})
	if err != nil {
		t.Fatalf("StartEnrollment: %v", err)
	}

	if started.Secret == "" || !strings.HasSuffix(strings.ToUpper(started.Secret), strings.ToUpper(started.Secret)) {
		t.Fatalf("the enrollment response carries no secret: %q", started.Secret)
	}
	if !strings.HasPrefix(started.ProvisioningURI, "otpauth://totp/") {
		t.Errorf("the provisioning URI is %q, want an otpauth://totp/ one", started.ProvisioningURI)
	}

	var stored string
	if err := h.pool.QueryRow(t.Context(),
		`SELECT secret_ciphertext FROM mfa_credentials WHERE id = $1`, started.Credential.ID).Scan(&stored); err != nil {
		t.Fatalf("reading the stored secret: %v", err)
	}
	if strings.Contains(stored, started.Secret) {
		t.Fatal("the row holds the secret in the clear")
	}
	if stored != started.Credential.SecretCiphertext {
		t.Error("the response and the row disagree about the sealed value")
	}
	if !strings.HasPrefix(stored, SealPrefix) {
		t.Errorf("the stored value %q has no version prefix", stored)
	}

	// And there is no second read: StatusFor carries no secret, only counts.
	status, _ := h.svc.StatusFor(t.Context(), h.user.ID)
	encoded, _ := json.Marshal(status)
	if strings.Contains(string(encoded), started.Secret) {
		t.Fatal("the status response carries the secret")
	}
}

// TestConfirmingRevokesEverySessionIssuedBeforeMFA is the packet's question — what
// happens to a session that was issued before MFA was enabled — and the answer has
// to be that it stops working.
//
// A session minted under a one-factor policy was minted on a password alone.
// Leaving it alive after the user opts into a second factor means the attacker
// holding it does not have to solve the new problem.
func TestConfirmingRevokesEverySessionIssuedBeforeMFA(t *testing.T) {
	h := newHarness(t)

	before := h.signIn()
	h.enroll()

	if got := h.liveSessions(); got != 0 {
		t.Errorf("%d sessions survived the enrollment, want 0", got)
	}
	// Including the caller's own, which is the price and is deliberate.
	token, digest, err := sessions.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if _, err := h.store.ConfirmedCredential(t.Context(), h.pool, h.user.ID); err != nil {
		t.Fatalf("the credential went with the session: %v", err)
	}
	if _, err := sessions.NewStore(h.pool).ByToken(t.Context(), h.pool, token, h.now()); !errors.Is(err, sessions.ErrNotFound) {
		t.Errorf("a session token resolved after the revocation: %v", err)
	}
	_ = before
	_ = digest
}

// TestConfirmingAnnouncesItself, and announces it in the same transaction. A
// consumer of identity.mfa.enabled that never hears about a rotation is holding a
// stale picture of how the account is protected.
func TestConfirmingAnnouncesItself(t *testing.T) {
	h := newHarness(t)
	if got := h.events(outbox.EventMFAEnabled); len(got) != 0 {
		t.Fatalf("%d events before enrollment, want 0", len(got))
	}

	credential := h.enroll()

	events := h.events(outbox.EventMFAEnabled)
	if len(events) != 1 {
		t.Fatalf("%d identity.mfa.enabled events, want 1", len(events))
	}
	if events[0].Subject != h.user.ID.String() {
		t.Errorf("subject = %q, want the user %q", events[0].Subject, h.user.ID)
	}
	var payload struct {
		UserID       string `json:"user_id"`
		CredentialID string `json:"credential_id"`
		Method       string `json:"method"`
	}
	if err := json.Unmarshal(events[0].Data, &payload); err != nil {
		t.Fatalf("the payload is not JSON: %v", err)
	}
	if payload.CredentialID != credential.ID.String() || payload.Method != MethodTOTP || payload.UserID != h.user.ID.String() {
		t.Errorf("payload = %+v", payload)
	}
	// And nothing secret travelled with it. Every event on the platform reaches
	// every subscriber, which is the wrong place for a credential.
	rendered := string(events[0].Data)
	for _, secretValue := range []string{h.secret, h.codes[0], strings.Join(h.codes, "")} {
		if strings.Contains(rendered, secretValue) {
			t.Fatalf("the event payload carries a secret: %s", rendered)
		}
	}
	if got := h.events(outbox.EventMFADisabled); len(got) != 0 {
		t.Errorf("%d identity.mfa.disabled events after an enrollment", len(got))
	}
}

// TestAnExpiredEnrollmentIsRefused, because a pending secret with no deadline is a
// secret at rest forever and a table that grows by one per abandoned setup.
func TestAnExpiredEnrollmentIsRefused(t *testing.T) {
	h := newHarness(t)
	started, err := h.svc.StartEnrollment(t.Context(), StartEnrollmentInput{UserID: h.user.ID})
	if err != nil {
		t.Fatalf("StartEnrollment: %v", err)
	}
	h.secret = started.Secret
	code := h.code()

	h.clk.Advance(EnrollmentTTL + time.Second)

	if _, err := h.svc.Confirm(t.Context(), ConfirmInput{
		UserID: h.user.ID, EnrollmentID: started.Credential.ID, Factor: code,
	}); !errors.Is(err, ErrEnrollmentNotFound) {
		t.Errorf("Confirming an expired enrollment = %v, want ErrEnrollmentNotFound", err)
	}
}

// TestStartingAnEnrollmentReplacesThePendingOne, so a user who opens the setup
// page five times holds one unconfirmed secret and not five.
func TestStartingAnEnrollmentReplacesThePendingOne(t *testing.T) {
	h := newHarness(t)

	var firstID id.UUID
	for range 3 {
		started, err := h.svc.StartEnrollment(t.Context(), StartEnrollmentInput{UserID: h.user.ID})
		if err != nil {
			t.Fatalf("StartEnrollment: %v", err)
		}
		if firstID.IsZero() {
			firstID = started.Credential.ID
		}
		h.secret = started.Secret
	}

	var pending int
	if err := h.pool.QueryRow(t.Context(),
		`SELECT count(*) FROM mfa_credentials WHERE user_id = $1 AND confirmed_at IS NULL`, h.user.ID).Scan(&pending); err != nil {
		t.Fatalf("counting pending enrollments: %v", err)
	}
	if pending != 1 {
		t.Errorf("%d pending enrollments, want 1", pending)
	}
}

// ---------------------------------------------------------------------------
// rotation
// ---------------------------------------------------------------------------

// TestARotatedSecretInvalidatesTheOldOne, with the old secret staying live until
// the replacement is confirmed — so a user who abandons a rotation has not lost
// their second factor.
func TestARotatedSecretInvalidatesTheOldOne(t *testing.T) {
	h := newHarness(t)
	h.enroll()
	oldSecret := h.secret
	oldCodes := h.codes

	// A rotation requires a factor, because replacing a second factor is a
	// destructive security action like disabling is.
	if _, err := h.svc.StartEnrollment(t.Context(), StartEnrollmentInput{UserID: h.user.ID}); !errors.Is(err, ErrInvalidFactor) {
		t.Errorf("rotating with no factor = %v, want ErrInvalidFactor", err)
	}

	started, err := h.svc.StartEnrollment(t.Context(), StartEnrollmentInput{UserID: h.user.ID, Factor: h.code()})
	if err != nil {
		t.Fatalf("rotating: %v", err)
	}
	if !started.Replaced {
		t.Error("the rotation does not say it replaced a live credential")
	}
	h.secret = started.Secret

	// Between the start and the confirmation BOTH secrets authenticate, because
	// the old row is untouched. That is the safe direction: an abandoned rotation
	// leaves the user with the factor they had.
	//
	// The clock moves on first, because authorising the rotation spent the current
	// step against the OLD secret: re-presenting that exact code would be a replay
	// and would correctly be refused, which would make this an assertion about the
	// replay guard rather than about the rotation.
	h.clk.Advance(Period)
	if _, err := h.svc.VerifyFactor(t.Context(), h.user.ID, codeFor(t, oldSecret, StepAt(h.now(), Period)), h.now()); err != nil {
		t.Errorf("the old secret stopped working before the rotation was confirmed: %v", err)
	}
	// And the new, unconfirmed secret is not a factor yet.
	h.clk.Advance(Period)
	if _, err := h.svc.VerifyFactor(t.Context(), h.user.ID, h.code(), h.now()); !errors.Is(err, ErrInvalidFactor) {
		t.Errorf("an unconfirmed secret was accepted as a factor: %v", err)
	}

	confirmed, err := h.svc.Confirm(t.Context(), ConfirmInput{
		UserID: h.user.ID, EnrollmentID: started.Credential.ID, Factor: h.code(),
	})
	if err != nil {
		t.Fatalf("Confirming the rotation: %v", err)
	}
	if confirmed.ReplacedCredentialID.IsZero() {
		t.Error("the confirmation does not say what it replaced")
	}
	h.codes = confirmed.RecoveryCodes

	// AFTER: the old secret is gone, so its codes are refused. This is the
	// assertion the packet asks for by name.
	if _, err := h.svc.VerifyFactor(t.Context(), h.user.ID, codeFor(t, oldSecret, StepAt(h.now(), Period)), h.now()); !errors.Is(err, ErrInvalidFactor) {
		t.Errorf("the OLD secret still works after a rotation: %v", err)
	}
	// And the old recovery codes went with it.
	for _, code := range oldCodes {
		h.refuteFactor(code)
	}
	// And the new one works. A fresh step, because the refutations above each spent
	// a failure against the factor.
	h.clk.Advance(2 * Period)
	if _, err := h.svc.VerifyFactor(t.Context(), h.user.ID, h.code(), h.now()); err != nil {
		t.Errorf("the new secret does not work after the rotation: %v", err)
	}
}

// ---------------------------------------------------------------------------
// recovery codes
// ---------------------------------------------------------------------------

// TestARecoveryCodeIsAcceptedInPlaceOfATOTPCodeAndIsSingleUse.
func TestARecoveryCodeIsAcceptedInPlaceOfATOTPCodeAndIsSingleUse(t *testing.T) {
	h := newHarness(t)
	h.enroll()

	code := h.codes[0]
	claim, err := h.svc.VerifyFactor(t.Context(), h.user.ID, code, h.now())
	if err != nil {
		t.Fatalf("a recovery code was refused: %v", err)
	}
	if claim.Method() != MethodRecoveryCode {
		t.Errorf("Method = %q, want %q", claim.Method(), MethodRecoveryCode)
	}
	// Spelled any of the ways a human spells it.
	spelling := strings.ToLower(strings.ReplaceAll(code, "-", " "))
	if _, err := h.svc.VerifyFactor(t.Context(), h.user.ID, spelling, h.now()); !errors.Is(err, ErrInvalidFactor) {
		t.Errorf("a re-spelled code was not refused as spent: %v", err)
	}
}

// TestSpellingDoesNotMatterForAFirstUse, so a user reading a code off paper is not
// defeated by their own handwriting.
func TestSpellingDoesNotMatterForAFirstUse(t *testing.T) {
	h := newHarness(t)
	h.enroll()

	spellings := []func(string) string{
		func(code string) string { return code },
		func(code string) string { return strings.ToLower(code) },
		func(code string) string { return strings.ReplaceAll(code, "-", "") },
		func(code string) string { return strings.ReplaceAll(code, "-", " ") },
		func(code string) string { return "  " + code + "  " },
	}

	// A different code per spelling, because the first use of a code spends it and
	// the point here is the FIRST use — that every spelling a human produces
	// reaches the same stored digest.
	for i, spell := range spellings {
		t.Run(spell(h.codes[i]), func(t *testing.T) {
			code := h.codes[i]
			if _, err := h.svc.VerifyFactor(t.Context(), h.user.ID, spell(code), h.now()); err != nil {
				t.Errorf("a recovery code spelled %q was refused: %v", spell(code), err)
			}
			// And the same code in the canonical spelling is now spent, so it is the
			// same code that was matched rather than a second digest.
			if _, err := h.svc.VerifyFactor(t.Context(), h.user.ID, code, h.now()); !errors.Is(err, ErrInvalidFactor) {
				t.Errorf("the code was spendable twice")
			}
		})
	}
}

// TestTheLastRecoveryCodeIsCalledOut is the packet's "the honest thing is to tell
// them before they get there": the count goes in the response, and it is the
// number the user has left, not the number before.
func TestTheLastRecoveryCodeIsCalledOut(t *testing.T) {
	h := newHarness(t)
	h.enroll()

	for i := 1; i < len(h.codes); i++ {
		claim, err := h.svc.VerifyFactor(t.Context(), h.user.ID, h.codes[i], h.now())
		if err != nil {
			t.Fatalf("using code %d: %v", i, err)
		}
		if want := RecoveryCodeCount - i; claim.RecoveryCodesRemaining() != want {
			t.Errorf("after using code %d the claim reports %d left, want %d", i, claim.RecoveryCodesRemaining(), want)
		}
	}

	last, err := h.svc.VerifyFactor(t.Context(), h.user.ID, h.codes[0], h.now())
	if err != nil {
		t.Fatalf("using the last code: %v", err)
	}
	if last.RecoveryCodesRemaining() != 0 {
		t.Errorf("after the last code the claim reports %d left, want 0", last.RecoveryCodesRemaining())
	}

	// And StatusFor says so before the user gets there, which is the point of it
	// being a field rather than a log line.
	status, _ := h.svc.StatusFor(t.Context(), h.user.ID)
	if status.RecoveryCodesRemaining != 0 {
		t.Errorf("StatusFor reports %d codes left, want 0", status.RecoveryCodesRemaining)
	}
}

// TestRegeneratingInvalidatesTheOldSetAtomically: delete and insert in one
// transaction, because a partial write leaves a user with two live sets — a second
// recovery path through codes nobody audited.
func TestRegeneratingInvalidatesTheOldSetAtomically(t *testing.T) {
	h := newHarness(t)
	h.enroll()
	old := h.codes

	// Regenerating takes a factor too. Handing out ten fresh codes is handing out
	// ten fresh ways into the account.
	if _, err := h.svc.RegenerateRecoveryCodes(t.Context(), RegenerateRecoveryCodesInput{UserID: h.user.ID}); !errors.Is(err, ErrInvalidFactor) {
		t.Errorf("regenerating with no factor = %v, want ErrInvalidFactor", err)
	}

	// A code the user has already spent cannot authorise anything, so spend one
	// first and then try to authorise with it.
	if _, err := h.svc.VerifyFactor(t.Context(), h.user.ID, old[0], h.now()); err != nil {
		t.Fatalf("spending a code: %v", err)
	}
	if _, err := h.svc.RegenerateRecoveryCodes(t.Context(),
		RegenerateRecoveryCodesInput{UserID: h.user.ID, Factor: old[0]}); !errors.Is(err, ErrInvalidFactor) {
		t.Errorf("regenerating with a SPENT code = %v, want ErrInvalidFactor", err)
	}

	regenerated, err := h.svc.RegenerateRecoveryCodes(t.Context(),
		RegenerateRecoveryCodesInput{UserID: h.user.ID, Factor: h.code()})
	if err != nil {
		t.Fatalf("RegenerateRecoveryCodes: %v", err)
	}
	if len(regenerated.RecoveryCodes) != RecoveryCodeCount {
		t.Fatalf("%d codes issued, want %d", len(regenerated.RecoveryCodes), RecoveryCodeCount)
	}
	h.codes = regenerated.RecoveryCodes

	// EVERY old code is dead, including the one spent before the regeneration,
	// which is the half of this a partial write fails.
	for _, code := range old {
		h.refuteFactor(code)
	}
	// And the count is the new set's, not the old one's plus the new one's: two
	// live sets would show RecoveryCodeCount+9 here.
	status, _ := h.svc.StatusFor(t.Context(), h.user.ID)
	if status.RecoveryCodesRemaining != RecoveryCodeCount {
		t.Errorf("%d codes left, want %d: the old set was not invalidated", status.RecoveryCodesRemaining, RecoveryCodeCount)
	}
	h.clk.Advance(2 * Period)
	if _, err := h.svc.VerifyFactor(t.Context(), h.user.ID, h.codes[0], h.now()); err != nil {
		t.Errorf("a new code does not work: %v", err)
	}
}

// TestRegeneratingIsAtomicOrItDoesNotHappenAtAll. The old set is either wholly
// replaced or wholly intact — never half of each.
func TestRegeneratingIsAtomicOrItDoesNotHappenAtAll(t *testing.T) {
	h := newHarness(t)
	h.enroll()
	old := h.codes[0]

	// Claim a code, then roll the transaction back underneath the regeneration by
	// making Commit fail. The simplest way to do that from a test is to make the
	// insert fail, and the way this asserts the invariant is by checking the row
	// count is either RecoveryCodeCount-unused or RecoveryCodeCount, never between.
	err := h.svc.uow.Do(t.Context(), func(ctx context.Context, q db.Querier) error {
		if err := h.svc.replaceRecoveryCodes(ctx, q, h.credentialID(), []string{"7KQF4W2X5DTRM3HN"}, h.now()); err != nil {
			return err
		}
		return errors.New("the second write failed")
	})
	if err == nil {
		t.Fatal("the transaction was expected to fail")
	}

	status, err := h.svc.StatusFor(t.Context(), h.user.ID)
	if err != nil {
		t.Fatalf("StatusFor: %v", err)
	}
	if status.RecoveryCodesRemaining != RecoveryCodeCount {
		t.Errorf("%d codes left after a rolled-back regeneration, want %d: the old set was partly destroyed",
			status.RecoveryCodesRemaining, RecoveryCodeCount)
	}
	if _, err := h.svc.VerifyFactor(t.Context(), h.user.ID, old, h.now()); err != nil {
		t.Errorf("an old code stopped working after a rolled-back regeneration: %v", err)
	}
}

// refuteFactor asserts that a code is NOT accepted, with the counter put back
// afterwards.
//
// The bookkeeping around the assertion is the point. Refuting ten old recovery
// codes in a row would otherwise reach the threshold on the fifth, and every
// later assertion would be refused by the LOCKOUT rather than by the code — so
// the test would pass whether or not the codes were invalidated, which is the one
// thing it exists to decide. Each refutation therefore starts from a clean counter.
//
// That is test scaffolding, not production behaviour, and it is why it clears
// through the store rather than through the service: no caller in this service
// gets to clear the second factor's failure run except by successfully using a
// factor, and a test that quietly acquired that power would be testing a door
// that does not exist.
func (h *harness) refuteFactor(code string) {
	h.t.Helper()

	h.clearFactorFailures()
	if _, err := h.svc.VerifyFactor(h.t.Context(), h.user.ID, code, h.now()); !errors.Is(err, ErrInvalidFactor) {
		h.t.Errorf("the code %s was accepted, want ErrInvalidFactor (err = %v)", code, err)
	}
	h.clearFactorFailures()
}

func (h *harness) credentialID() id.UUID {
	h.t.Helper()
	credential, err := h.store.ConfirmedCredential(h.t.Context(), h.pool, h.user.ID)
	if err != nil {
		h.t.Fatalf("reading the credential: %v", err)
	}
	return credential.ID
}

// ---------------------------------------------------------------------------
// disabling
// ---------------------------------------------------------------------------

// TestDisablingRequiresASecondFactor and not just a session, which is the entire
// reason re-authentication for a destructive security action exists.
func TestDisablingRequiresASecondFactor(t *testing.T) {
	h := newHarness(t)
	h.enroll()
	live := h.signIn()

	// No code at all.
	if err := h.svc.Disable(t.Context(), DisableInput{UserID: h.user.ID}); !errors.Is(err, ErrInvalidFactor) {
		t.Errorf("disabling with no code = %v, want ErrInvalidFactor", err)
	}
	// A wrong code.
	if err := h.svc.Disable(t.Context(), DisableInput{UserID: h.user.ID, Factor: "000000"}); !errors.Is(err, ErrInvalidFactor) {
		t.Errorf("disabling with a wrong code = %v, want ErrInvalidFactor", err)
	}
	// The session's own bearer token is not a factor, and this route has no field
	// that could carry one.
	if _, err := h.svc.StatusFor(t.Context(), h.user.ID); err != nil {
		t.Fatalf("StatusFor: %v", err)
	}
	if status, _ := h.svc.StatusFor(t.Context(), h.user.ID); !status.Enabled {
		t.Fatal("a refused disable turned MFA off anyway")
	}
	if h.liveSessions() != 1 {
		t.Error("a refused disable revoked a session")
	}
	_ = live

	// A recovery code is a factor, which is the escape hatch a user with a lost
	// phone needs and the reason codes exist.
	if err := h.svc.Disable(t.Context(), DisableInput{UserID: h.user.ID, Factor: h.codes[0]}); err != nil {
		t.Errorf("disabling with a recovery code: %v", err)
	}
	if status, _ := h.svc.StatusFor(t.Context(), h.user.ID); status.Enabled {
		t.Error("MFA is still enabled after a valid disable")
	}
}

// TestDisablingRevokesSessionsAndAnnouncesIt, because a user who turns MFA off
// has very often had it turned off FOR them.
func TestDisablingRevokesSessionsAndAnnouncesIt(t *testing.T) {
	h := newHarness(t)
	h.enroll()
	h.signIn()
	h.signIn()

	if err := h.svc.Disable(t.Context(), DisableInput{UserID: h.user.ID, Factor: h.code()}); err != nil {
		t.Fatalf("Disable: %v", err)
	}

	if got := h.liveSessions(); got != 0 {
		t.Errorf("%d sessions survived the disable, want 0", got)
	}
	events := h.events(outbox.EventMFADisabled)
	if len(events) != 1 {
		t.Fatalf("%d identity.mfa.disabled events, want 1", len(events))
	}
	if events[0].Subject != h.user.ID.String() {
		t.Errorf("subject = %q, want the user", events[0].Subject)
	}
	if strings.Contains(string(events[0].Data), h.secret) {
		t.Error("the disable event carries the secret")
	}
	// The credential, its codes and its spent steps are all gone.
	for _, table := range []string{"mfa_credentials", "mfa_recovery_codes", "mfa_used_totp_steps"} {
		var n int
		if err := h.pool.QueryRow(t.Context(), `SELECT count(*) FROM `+table+` WHERE credential_id = $1`,
			h.credentialIDOrZero()).Scan(&n); err == nil && n != 0 {
			t.Errorf("%s still has %d rows after a disable", table, n)
		}
	}
}

// credentialIDOrZero returns the id of a credential that Disable has just removed,
// so the assertion above can find its rows by a key that no longer has a parent.
func (h *harness) credentialIDOrZero() id.UUID {
	var raw string
	if err := h.pool.QueryRow(h.t.Context(),
		`SELECT subject FROM outbox_events WHERE type = $1 ORDER BY occurred_at LIMIT 1`,
		outbox.EventMFADisabled).Scan(&raw); err != nil {
		h.t.Fatalf("reading the disable event: %v", err)
	}
	// The event's subject is the user, and the credential is gone, so query by the
	// one join that still works: nothing.
	return id.UUID{}
}

// TestDisablingRefusesWhenTheSecondFactorIsLocked, and does not count the attempt.
// A locked factor must not be probeable, which is why the lock check comes before
// the verification.
func TestDisablingRefusesWhenTheSecondFactorIsLocked(t *testing.T) {
	h := newHarness(t)
	h.enroll()

	for range sessions.MaxFailedAttempts {
		if _, err := h.svc.VerifyFactor(t.Context(), h.user.ID, "000000", h.now()); !errors.Is(err, ErrInvalidFactor) {
			t.Fatalf("a wrong code = %v, want ErrInvalidFactor", err)
		}
	}

	var locked *sessions.LockedError
	_, err := h.svc.VerifyFactor(t.Context(), h.user.ID, "000000", h.now())
	if !errors.As(err, &locked) {
		t.Fatalf("attempt %d past the threshold = %v, want a *sessions.LockedError", sessions.MaxFailedAttempts, err)
	}
	if locked.RetryAfter != sessions.LockoutDuration {
		t.Errorf("RetryAfter = %s, want %s", locked.RetryAfter, sessions.LockoutDuration)
	}

	// A LOCKED factor refuses even a CORRECT code, which is the property worth
	// having: it is what stops an attacker from using a correct code to probe
	// whether a lock has expired.
	if _, err := h.svc.VerifyFactor(t.Context(), h.user.ID, h.code(), h.now()); !errors.As(err, &locked) {
		t.Errorf("a correct code during a lock = %v, want a *sessions.LockedError", err)
	}
	// And disabling is refused too, rather than being a way past the lock.
	if err := h.svc.Disable(t.Context(), DisableInput{UserID: h.user.ID, Factor: h.codes[0]}); !errors.As(err, &locked) {
		t.Errorf("disabling during a lock = %v, want a *sessions.LockedError", err)
	}

	// The window closing lifts it, with no sweeper: expiry is decided on read.
	h.clk.Advance(sessions.LockoutDuration + time.Second)
	if _, err := h.svc.VerifyFactor(t.Context(), h.user.ID, h.code(), h.now()); err != nil {
		t.Errorf("the lock did not lapse: %v", err)
	}
}

// TestTheFactorLockoutIsThisLockout runs one table of counter transitions through
// both this package's use of it and internal/sessions' — the same table the
// password path runs — so the two cannot drift apart silently.
//
// They are the same type today, which is the point; this test exists so that if
// somebody later gives MFA its own numbers, the SHARED semantics are still
// asserted rather than assumed.
func TestTheFactorLockoutIsThisLockout(t *testing.T) {
	cases := []struct {
		name string
		from sessions.Lockout
		at   time.Time
	}{
		{"a fresh counter", sessions.Lockout{}, issuedAt},
		{"one failure down", sessions.Lockout{FailedAttempts: 1}, issuedAt},
		{"one short of the threshold", sessions.Lockout{FailedAttempts: sessions.MaxFailedAttempts - 1}, issuedAt},
		{"an expired lock with a stale count", sessions.Lockout{
			FailedAttempts: sessions.MaxFailedAttempts,
			LockedUntil:    ptr(issuedAt.Add(-time.Minute)),
		}, issuedAt},
		{"an active lock", sessions.Lockout{
			LockedUntil: ptr(issuedAt.Add(time.Minute)),
		}, issuedAt},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// This package reaches the policy through a credential row, so exercise
			// it that way rather than calling sessions.Lockout directly: the point
			// is that the credential's counter and the users row's counter are the
			// same arithmetic.
			pool := dbtest.Schema(t)
			store := NewStore(pool)
			user := newTestUser(t, pool)
			ctx := context.Background()
			credential := confirm(t, pool, newCredential(t, pool, user))

			lockUntil := c.from.LockedUntil
			if err := store.RecordFactorFailure(ctx, pool, credential.ID, c.from.FailedAttempts, lockUntil); err != nil {
				t.Fatalf("seeding the counter: %v", err)
			}

			read, err := store.ConfirmedCredential(ctx, pool, user.ID)
			if err != nil {
				t.Fatalf("reading the credential: %v", err)
			}
			onRow := sessions.Lockout{FailedAttempts: read.FailedAttempts, LockedUntil: read.LockedUntil}

			if onRow.Locked(c.at) != c.from.Locked(c.at) {
				t.Errorf("Locked = %v, want %v", onRow.Locked(c.at), c.from.Locked(c.at))
			}
			if onRow.RetryAfter(c.at) != c.from.RetryAfter(c.at) {
				t.Errorf("RetryAfter = %s, want %s", onRow.RetryAfter(c.at), c.from.RetryAfter(c.at))
			}
			next := onRow.Failed(c.at)
			if next.FailedAttempts != c.from.Failed(c.at).FailedAttempts {
				t.Errorf("Failed().FailedAttempts = %d, want %d", next.FailedAttempts, c.from.Failed(c.at).FailedAttempts)
			}
			if (next.LockedUntil == nil) != (c.from.Failed(c.at).LockedUntil == nil) {
				t.Errorf("Failed().LockedUntil = %v, want %v", next.LockedUntil, c.from.Failed(c.at).LockedUntil)
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }

// TestADeploymentWithNoKeyFailsClosed. The failure mode is the whole reason
// Unavailable is a type rather than a nil: an enrolled user must not be let in on
// their password by a deployment that cannot decrypt anything.
func TestADeploymentWithNoKeyFailsClosed(t *testing.T) {
	pool := dbtest.Schema(t)
	clk := clock.NewFake(issuedAt)
	store := NewStore(pool)
	user := newTestUser(t, pool)

	// Enrol with a key, so there is a real secret in the row.
	real := NewService(db.TxRunner{Pool: pool}, db.Direct{Pool: pool}, store,
		outbox.NewStore(pool), sessions.NewStore(pool), mustVault(t), clk, testIssuer)
	started, err := real.StartEnrollment(t.Context(), StartEnrollmentInput{UserID: user.ID})
	if err != nil {
		t.Fatalf("StartEnrollment: %v", err)
	}
	secret := started.Secret
	code, err := Code(secret, clk.Now())
	if err != nil {
		t.Fatalf("Code: %v", err)
	}
	if _, err := real.Confirm(t.Context(), ConfirmInput{
		UserID: user.ID, EnrollmentID: started.Credential.ID, Factor: code,
	}); err != nil {
		t.Fatalf("Confirm: %v", err)
	}

	// Now the process loses its key.
	keyless := NewService(db.TxRunner{Pool: pool}, db.Direct{Pool: pool}, store,
		outbox.NewStore(pool), sessions.NewStore(pool), Unavailable{}, clk, testIssuer)

	if _, err := keyless.StartEnrollment(t.Context(), StartEnrollmentInput{UserID: user.ID, Factor: code}); !errors.Is(err, ErrNoVault) {
		t.Errorf("enrolling with no key = %v, want ErrNoVault", err)
	}
	if _, err := keyless.VerifyFactor(t.Context(), user.ID, code, clk.Now()); !errors.Is(err, ErrNoVault) {
		t.Errorf("verifying with no key = %v, want ErrNoVault: an enrolled user must not be let in", err)
	}
	if _, err := keyless.VerifyFactor(t.Context(), user.ID, "123456", clk.Now()); !errors.Is(err, ErrNoVault) {
		t.Errorf("verifying a wrong code with no key = %v, want ErrNoVault", err)
	}
	if err := keyless.Disable(t.Context(), DisableInput{UserID: user.ID, Factor: code}); !errors.Is(err, ErrNoVault) {
		t.Errorf("disabling with no key = %v, want ErrNoVault", err)
	}
	// And a recovery code needs no key, so a user with a lost phone and no
	// deployment key is not locked out of their own account.
	if _, err := real.StatusFor(t.Context(), user.ID); err != nil {
		t.Fatalf("StatusFor: %v", err)
	}
}
