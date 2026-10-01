package recovery

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/sessions"
)

// THE PASSWORD RESET FLOW, AND EVERY NEGATIVE IT HAS TO HAVE.
//
// The brief names four of them — an expired token is refused, a reused token is
// refused, a token minted for one account does not work on another, and a request
// for an unknown address leaks nothing — and they are the four tests below with
// those names, over a real database rather than a double.

// TestAResetForAnUnknownAddressSendsNothingAndWritesNothing is the enumeration
// property stated as a fact about the world rather than about a response body.
//
// IT ASSERTS THE NEGATIVE IN BOTH DIRECTIONS, which is what makes it a test rather
// than a comment: no message went out (so an unknown address costs a stranger
// nothing), and no row was written (so the table does not become a list of every
// address anybody has ever asked about).
func TestAResetForAnUnknownAddressSendsNothingAndWritesNothing(t *testing.T) {
	h := newHarness(t, false)

	if err := h.svc.RequestPasswordReset(t.Context(), dbtest.UniqueEmail(t)); err != nil {
		t.Fatalf("RequestPasswordReset for an unknown address = %v, want nil", err)
	}

	if got := h.mailer.count(); got != 0 {
		t.Errorf("%d messages delivered for an address with no account, want 0", got)
	}
	// And no row anywhere: the strongest form of the same assertion, and the one a
	// private schema makes possible.
	private := newHarness(t, true)
	if err := private.svc.RequestPasswordReset(t.Context(), dbtest.UniqueEmail(t)); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if got := countRows(t, private, `SELECT count(*) FROM recovery_tokens`); got != 0 {
		t.Errorf("%d recovery_tokens rows exist after a request for an address with no account", got)
	}
}

// TestAResetForAKnownAddressWritesExactlyOneRowAndOneMessage is the other half of
// the pair above. Without it, "an unknown address sends nothing" passes on a service
// whose request route sends nothing for anybody.
func TestAResetForAKnownAddressWritesExactlyOneRowAndOneMessage(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()

	if err := h.svc.RequestPasswordReset(t.Context(), who.email); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}

	if got := h.mailer.count(); got != 1 {
		t.Errorf("%d messages delivered, want exactly 1", got)
	}
	if got := h.tokenRowCount(who.id, PurposePasswordReset); got != 1 {
		t.Errorf("%d password_reset rows, want 1", got)
	}

	message := h.mailer.last(t)
	if message.To != who.email {
		t.Errorf("the message went to %q, want the account's own address %q", message.To, who.email)
	}
}

// TestAResetRequestInsideTheWindowSendsNothing is the mail-cannon test.
//
// THE ATTACK IS AN ANONYMOUS ENDPOINT, so what it needs to assert is that N
// requests produce one message. It is also why nothing here is a lockout: there is
// no counter, no 423 and nothing an attacker can trip on somebody else's account —
// the answer to every request inside the window is the answer to the first one.
func TestAResetRequestInsideTheWindowSendsNothing(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()

	if err := h.svc.RequestPasswordReset(t.Context(), who.email); err != nil {
		t.Fatalf("the first request: %v", err)
	}

	// Twenty more, spread across the window rather than all at one instant: a
	// cooldown measured against the NEWEST token is what the code does, and a test
	// that fired them all at t+0 would not notice the difference between measuring
	// against the newest and measuring against the oldest.
	for i := range 20 {
		h.clk.Advance(time.Second)
		if err := h.svc.RequestPasswordReset(t.Context(), who.email); err != nil {
			t.Fatalf("request %d inside the window = %v, want nil", i+2, err)
		}
	}

	if got := h.mailer.count(); got != 1 {
		t.Errorf("%d messages after 21 requests inside a %s window, want 1", got, RequestWindow)
	}
	if got := h.tokenRowCount(who.id, PurposePasswordReset); got != 1 {
		t.Errorf("%d rows after 21 requests, want 1", got)
	}

	// One second short of the window, measured from the newest token: still nothing.
	h.clk.Advance(RequestWindow - 21*time.Second - time.Second)
	if err := h.svc.RequestPasswordReset(t.Context(), who.email); err != nil {
		t.Fatalf("a request one second short of the window: %v", err)
	}
	if got := h.mailer.count(); got != 1 {
		t.Errorf("%d messages one second short of the window, want 1", got)
	}

	// And past it the endpoint mails again, because a user who lost the first email
	// must be able to ask again without a support ticket.
	h.clk.Advance(2 * time.Second)
	if err := h.svc.RequestPasswordReset(t.Context(), who.email); err != nil {
		t.Fatalf("the request after the window: %v", err)
	}
	if got := h.mailer.count(); got != 2 {
		t.Errorf("%d messages after a request outside the window, want 2", got)
	}
	if got := h.tokenRowCount(who.id, PurposePasswordReset); got != 2 {
		t.Errorf("%d rows after two requests outside the window, want 2 — a later request must "+
			"not invalidate the link already sitting in somebody's inbox", got)
	}
}

// TestAReusedResetTokenIsRefused is the packet's single-use negative.
//
// IT CHECKS THE PASSWORD TWICE, which is the half that matters: a service that
// returned ErrTokenNotFound on the second attempt while having written the second
// password would pass a status-only test and leave the token working.
func TestAReusedResetTokenIsRefused(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()

	token := h.requestReset(t, who)
	if _, err := h.svc.RedeemPasswordReset(t.Context(), RedeemPasswordResetInput{
		Token: token, Password: "a brand new password",
	}); err != nil {
		t.Fatalf("the first redemption: %v", err)
	}

	// The token that worked, presented again.
	if _, err := h.svc.RedeemPasswordReset(t.Context(), RedeemPasswordResetInput{
		Token: token, Password: "a third password entirely",
	}); err == nil {
		t.Fatal("a reset token was accepted twice")
	}

	// The password is the FIRST new one. A token redeemed twice would leave the
	// second one in place, and a service that returned an error while doing it would
	// have handed an attacker the account.
	assertPasswordIs(t, h, who, "a brand new password")
	assertPasswordIsNot(t, h, who, "a third password entirely")
}

// TestAnExpiredResetTokenIsRefused is the packet's expiry negative.
//
// IT MOVES THE CLOCK PAST THE WINDOW rather than waiting, and it checks the window
// is the one the token was given rather than a constant the test invented: the row's
// own expires_at is read back and compared, so a TTL that drifted from the
// documentation fails here instead of passing.
func TestAnExpiredResetTokenIsRefused(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()

	token := h.requestReset(t, who)

	row := h.storedTokenRow(h.newestTokenID(who.id, PurposePasswordReset))
	wantExpiry := h.now().Add(PasswordResetTTL)
	if !row["expires_at"].(time.Time).Equal(wantExpiry) {
		t.Errorf("the row expires at %v, want %v", row["expires_at"], wantExpiry)
	}

	// One second before, it still works.
	h.clk.Advance(PasswordResetTTL - time.Second)
	if _, err := h.svc.RedeemPasswordReset(t.Context(), RedeemPasswordResetInput{
		Token: token, Password: "still inside the window",
	}); err != nil {
		t.Fatalf("a token one second before its own expiry was refused: %v", err)
	}

	// A second later it is dead, and the password it set is still the one in force.
	h.clk.Advance(2 * time.Second)
	if _, err := h.svc.RedeemPasswordReset(t.Context(), RedeemPasswordResetInput{
		Token: token, Password: "past the window",
	}); err == nil {
		t.Fatal("an expired reset token was accepted")
	}
	assertPasswordIs(t, h, who, "still inside the window")
}

// TestATokenMintedForOneAccountDoesNotTouchAnother is the packet's cross-account
// negative, and it is asserted as the absence of an EFFECT rather than the presence
// of an error.
//
// TWO ACCOUNTS, and the one that is not involved has to be untouched in every way
// the flows can touch an account: its password, its sessions, and its tokens. The
// dangerous version of this bug is not that account B's token works on account A —
// it is that redeeming A's token quietly ends B's sessions, which is a denial of
// service an attacker can trigger with a token they were never given.
func TestATokenMintedForOneAccountDoesNotTouchAnother(t *testing.T) {
	h := newHarness(t, false)
	alice := h.registerSimple()
	bob := h.registerSimple()

	bobSessionsBefore := h.sessionsFor(bob.id)
	bobDigestBefore := digestOf(t, h, bob)

	token := h.requestReset(t, alice)
	if _, err := h.svc.RedeemPasswordReset(t.Context(), RedeemPasswordResetInput{
		Token: token, Password: "alice's new password",
	}); err != nil {
		t.Fatalf("the redemption: %v", err)
	}

	// Alice changed and Bob did not.
	assertPasswordIs(t, h, alice, "alice's new password")
	assertPasswordIsNot(t, h, alice, "correct horse battery staple")

	if got := digestOf(t, h, bob); got != bobDigestBefore {
		t.Error("redeeming one account's reset token changed another account's password")
	}
	if got := h.sessionsFor(bob.id); got != bobSessionsBefore {
		t.Errorf("redeeming one account's reset token ended %d of another account's sessions",
			bobSessionsBefore-got)
	}
	if _, swept := h.access.swept(bob.id); swept {
		t.Error("redeeming one account's reset token revoked another account's access tokens")
	}
	if got := h.tokenRowCount(bob.id, PurposePasswordReset); got != 0 {
		t.Errorf("%d reset tokens exist for the account that never asked for one", got)
	}
}

// TestAResetRevokesEverySessionAndEveryAccessToken is the requirement the brief
// calls out by name: a reset that leaves the old session alive is not a reset.
func TestAResetRevokesEverySessionAndEveryAccessToken(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()

	// A second session, because one is not the shape of the thing being asserted.
	// Minted rather than hand-written, because the sessions table has a UNIQUE index
	// on the digest and every test in this package shares one database.
	_, second, err := sessions.NewToken()
	if err != nil {
		t.Fatalf("minting a second session: %v", err)
	}
	if _, err := sessions.NewStore(h.pool).Create(t.Context(), h.pool, sessions.NewSession{
		UserID: who.id, TokenDigest: second,
		ExpiresAt: h.now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("creating a second session: %v", err)
	}
	if got := h.sessionsFor(who.id); got != 2 {
		t.Fatalf("%d sessions before the reset, want 2", got)
	}

	token := h.requestReset(t, who)
	if _, err := h.svc.RedeemPasswordReset(t.Context(), RedeemPasswordResetInput{
		Token: token, Password: "the recovered password",
	}); err != nil {
		t.Fatalf("the redemption: %v", err)
	}

	if got := h.sessionsFor(who.id); got != 0 {
		t.Errorf("%d sessions survived a password reset, want 0: a reset that leaves the old "+
			"session alive is not a reset", got)
	}
	at, swept := h.access.swept(who.id)
	if !swept {
		t.Error("no access tokens were revoked")
	} else if !at.Equal(h.now()) {
		t.Errorf("the access tokens were revoked at %s, want the service clock's %s", at, h.now())
	}
}

// TestAResetDoesNotRevokeAScopedAPIKey is the other half of the requirement above,
// and it is the decision README.md already records for MFA: a machine credential
// outlives every session, its owner named it on purpose, and silently revoking it
// breaks an unrelated CI job with nothing in the response saying why.
func TestAResetDoesNotRevokeAScopedAPIKey(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()

	// WRITTEN DIRECTLY, because this test is about what the reset does NOT do, and
	// minting a key through the tenancy use cases would drag half this service into a
	// question about one statement's absence. The account and the membership go in
	// with it: the row has to be a real one on the real table for the assertion to
	// mean anything, and a key needs an account to belong to.
	accountID, keyID := id.MustNew(), id.MustNew()
	if _, err := h.pool.Exec(t.Context(),
		`INSERT INTO accounts (id, name, slug, personal) VALUES ($1, 'Reset Fixture', $2, false)`,
		accountID, "reset-fixture-"+strings.ReplaceAll(accountID.String(), "-", "")[:8]); err != nil {
		t.Fatalf("creating the fixture account: %v", err)
	}
	if _, err := h.pool.Exec(t.Context(), `
		INSERT INTO account_users (account_id, user_id, role) VALUES ($1, $2, 'owner')`,
		accountID, who.id); err != nil {
		t.Fatalf("creating the fixture membership: %v", err)
	}
	_, keyDigest, err := sessions.NewToken()
	if err != nil {
		t.Fatalf("minting the fixture key's digest: %v", err)
	}
	if _, err := h.pool.Exec(t.Context(), `
		INSERT INTO api_keys (id, user_id, account_id, name, token_digest, scopes, created_at, expires_at)
		VALUES ($1, $2, $3, 'reset-fixture', $4, ARRAY['accounts:read'], $5, $6)`,
		keyID, who.id, accountID, keyDigest, h.now(), h.now().Add(90*24*time.Hour)); err != nil {
		t.Fatalf("creating the fixture api key: %v", err)
	}

	token := h.requestReset(t, who)
	if _, err := h.svc.RedeemPasswordReset(t.Context(), RedeemPasswordResetInput{
		Token: token, Password: "the recovered password",
	}); err != nil {
		t.Fatalf("the redemption: %v", err)
	}

	var revokedAt *time.Time
	if err := h.pool.QueryRow(t.Context(),
		`SELECT revoked_at FROM api_keys WHERE id = $1`, keyID).Scan(&revokedAt); err != nil {
		t.Fatalf("reading the api key: %v", err)
	}
	if revokedAt != nil {
		t.Errorf("the api key was revoked at %s by a password reset. README.md records the decision "+
			"not to sweep machine credentials here: a CI job stops working with nothing in the "+
			"response saying why", revokedAt)
	}
}

// TestAResetClearsALockout: a user who was locked out by somebody else's five wrong
// passwords must be able to sign in after recovering their own account. Leaving the
// lock in place would make the recovery route useless for exactly the users who
// needed it most, for up to LockoutDuration afterwards.
func TestAResetClearsALockout(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()

	if _, err := h.pool.Exec(t.Context(), `
		UPDATE users SET failed_login_attempts = 5, locked_until = $2 WHERE id = $1`,
		who.id, h.now().Add(15*time.Minute)); err != nil {
		t.Fatalf("locking the account: %v", err)
	}

	token := h.requestReset(t, who)
	if _, err := h.svc.RedeemPasswordReset(t.Context(), RedeemPasswordResetInput{
		Token: token, Password: "the recovered password",
	}); err != nil {
		t.Fatalf("the redemption: %v", err)
	}

	var attempts int
	var lockedUntil *time.Time
	if err := h.pool.QueryRow(t.Context(),
		`SELECT failed_login_attempts, locked_until FROM users WHERE id = $1`, who.id).
		Scan(&attempts, &lockedUntil); err != nil {
		t.Fatalf("reading the lockout state: %v", err)
	}
	if attempts != 0 || lockedUntil != nil {
		t.Errorf("after a reset: %d attempts, locked until %v; want 0 and no lock — somebody else's "+
			"five wrong guesses must not survive a proof of mailbox control", attempts, lockedUntil)
	}
}

// TestAResetTokenIsStoredAsADigestAndThePlaintextIsNowhere is the storage property,
// asserted over the whole table rather than one column.
//
// The plaintext has to be searched for three ways, because "it is not in
// token_digest" would pass on a table that stored it in a column nobody thought to
// check: the whole row serialised, the whole table, and the digest — which has to be
// FOUND, or the test would pass on a table that stored nothing at all.
func TestAResetTokenIsStoredAsADigestAndThePlaintextIsNowhere(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()

	token := h.requestReset(t, who)
	digest := sessions.Digest(token)

	row := h.storedTokenRow(h.newestTokenID(who.id, PurposePasswordReset))
	stored, _ := row["token_digest"].(string)
	if stored != digest {
		t.Errorf("token_digest = %q, want sessions.Digest of the mailed token", stored)
	}
	if strings.Contains(stored, token) {
		t.Error("token_digest contains the token")
	}

	// The whole table, rendered as text, for the token and for its bare digest.
	table := dumpTable(t, h, `SELECT * FROM recovery_tokens`)
	for _, forbidden := range []string{token, token[:20]} {
		if strings.Contains(table, forbidden) {
			t.Errorf("the recovery_tokens table contains the plaintext token (%q)", forbidden)
		}
	}
	if !strings.Contains(table, digest) {
		t.Error("the digest is not in the table either, so this test would pass on a table that " +
			"stored nothing at all")
	}

	// And the outbox: the event a reset announces must not carry the credential.
	events := dumpTable(t, h, `SELECT * FROM outbox_events`)
	if strings.Contains(events, token) {
		t.Error("the token reached the outbox")
	}
}

// TestAResetTokenIsNotAVerificationToken cross-checks the purposes, in both
// directions.
//
// The store filters on `purpose`, so the two token families live in the same table
// and the only thing keeping them apart is that filter. A version of this package
// that looked tokens up by digest alone would accept a reset token at the
// verification endpoint, and the consequence is not subtle: redeeming it would mark
// an address proved that nobody proved.
func TestAResetTokenIsNotAVerificationToken(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()

	reset := h.requestReset(t, who)
	h.clk.Advance(RequestWindow + time.Second)
	if err := h.svc.RequestVerification(t.Context(), who.email); err != nil {
		t.Fatalf("RequestVerification: %v", err)
	}
	verify := tokenFrom(t, h.mailer.last(t))

	if err := h.svc.RedeemVerification(t.Context(), RedeemVerificationInput{Token: reset}); err == nil {
		t.Error("a password reset token was accepted by the verification redemption")
	}
	if _, err := h.svc.RedeemPasswordReset(t.Context(), RedeemPasswordResetInput{
		Token: verify, Password: "a new password",
	}); err == nil {
		t.Error("a verification token was accepted by the password reset redemption")
	}

	// And the refusals changed nothing.
	assertPasswordIs(t, h, who, "correct horse battery staple")
	assertNotVerified(t, h, who)
}

// TestADeploymentWithNoMailerRefusesBeforeItLearnsAnything is the enumeration
// property for the configuration this service actually ships in.
//
// The order in RequestPasswordReset is that Ready is asked BEFORE the users table
// is read, so a deployment that cannot send mail cannot be probed: every address,
// registered or not, produces the same ErrNoMailer, and the rows prove that nothing
// was written and nothing was sent for any of them.
func TestADeploymentWithNoMailerRefusesBeforeItLearnsAnything(t *testing.T) {
	h := newHarness(t, true)
	known := h.registerSimple()
	h.mailer.mu.Lock()
	h.mailer.readyErr = ErrNoMailer
	h.mailer.mu.Unlock()

	unknown := dbtest.UniqueEmail(t)
	for _, address := range []string{known.email, unknown, "not-an-address", ""} {
		if err := h.svc.RequestPasswordReset(t.Context(), address); err != ErrNoMailer {
			t.Errorf("RequestPasswordReset(%q) = %v, want ErrNoMailer", address, err)
		}
		if err := h.svc.RequestVerification(t.Context(), address); err != ErrNoMailer {
			t.Errorf("RequestVerification(%q) = %v, want ErrNoMailer", address, err)
		}
	}
	if _, err := h.svc.RequestEmailChange(t.Context(), RequestEmailChangeInput{
		UserID: known.id, Email: dbtest.UniqueEmail(t),
	}); err != ErrNoMailer {
		t.Errorf("RequestEmailChange = %v, want ErrNoMailer", err)
	}

	if got := countRows(t, h, `SELECT count(*) FROM recovery_tokens`); got != 0 {
		t.Errorf("%d rows were written by requests this deployment cannot deliver", got)
	}
	if got := h.mailer.count(); got != 0 {
		t.Errorf("%d messages were sent by a deployment that reported it could not send any", got)
	}
}

// TestUnavailableRefusesEveryEntryPoint is the seam's own contract, and it is
// separate from the test above so that a Mailer which is merely PRESENT and broken
// cannot be confused with one that is absent.
func TestUnavailableRefusesEveryEntryPoint(t *testing.T) {
	var m Mailer = Unavailable{}

	if err := m.Ready(t.Context()); err != ErrNoMailer {
		t.Errorf("Ready = %v, want ErrNoMailer", err)
	}
	if err := m.Send(t.Context(), Message{To: "kaka@example.com", Body: "hello"}); err != ErrNoMailer {
		t.Errorf("Send = %v, want ErrNoMailer", err)
	}
}

// TestAMalformedAddressIsRefusedAndNoRowIsWritten: a 422 is about the caller's own
// input and not about an account, so it is safe to answer — and it must not leave a
// row behind on the way out.
func TestAMalformedAddressIsRefusedAndNoRowIsWritten(t *testing.T) {
	h := newHarness(t, true)

	for _, address := range []string{"", "   ", "not-an-address", "a@b", "no dot@here"} {
		err := h.svc.RequestPasswordReset(t.Context(), address)
		if !errIsFieldError(err, "email") {
			t.Errorf("RequestPasswordReset(%q) = %v, want a field error naming email", address, err)
		}
	}
	if got := countRows(t, h, `SELECT count(*) FROM recovery_tokens`); got != 0 {
		t.Errorf("%d rows exist after four malformed requests", got)
	}
}

// --- helpers -----------------------------------------------------------------

// requestReset runs the whole request step and returns the mailed token.
func (h *harness) requestReset(t *testing.T, who account) string {
	t.Helper()
	if err := h.svc.RequestPasswordReset(t.Context(), who.email); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	return tokenFrom(t, h.mailer.last(t))
}

// assertPasswordIs checks the stored digest verifies the given plaintext.
func assertPasswordIs(t *testing.T, h *harness, who account, plaintext string) {
	t.Helper()
	if !testHasher().Verify(digestOf(t, h, who), plaintext) {
		t.Errorf("the account's password is not %q any more", plaintext)
	}
}

// assertPasswordIsNot is the same check's negative, and it exists because a test
// that only ever asserts the positive passes on a service that never writes the
// password column at all.
func assertPasswordIsNot(t *testing.T, h *harness, who account, plaintext string) {
	t.Helper()
	if testHasher().Verify(digestOf(t, h, who), plaintext) {
		t.Errorf("the account's password is still %q", plaintext)
	}
}

// digestOf reads the stored digest for a user.
func digestOf(t *testing.T, h *harness, who account) string {
	t.Helper()
	var digest string
	if err := h.pool.QueryRow(t.Context(),
		`SELECT password_digest FROM users WHERE id = $1`, who.id).Scan(&digest); err != nil {
		t.Fatalf("reading the password digest: %v", err)
	}
	return digest
}

// assertNotVerified checks the account's address is still unproved.
func assertNotVerified(t *testing.T, h *harness, who account) {
	t.Helper()
	var at *time.Time
	if err := h.pool.QueryRow(t.Context(),
		`SELECT email_verified_at FROM users WHERE id = $1`, who.id).Scan(&at); err != nil {
		t.Fatalf("reading the verification state: %v", err)
	}
	if at != nil {
		t.Errorf("the address is verified as of %s; a refused token marked it proved", at)
	}
}

// assertVerified checks the account's address is proved, and when.
func assertVerified(t *testing.T, h *harness, who account) {
	t.Helper()
	var at *time.Time
	if err := h.pool.QueryRow(t.Context(),
		`SELECT email_verified_at FROM users WHERE id = $1`, who.id).Scan(&at); err != nil {
		t.Fatalf("reading the verification state: %v", err)
	}
	if at == nil {
		t.Fatal("the address is not verified")
	}
	if !at.Equal(h.now()) {
		t.Errorf("verified at %s, want the service clock's %s", at, h.now())
	}
}

// countRows runs a counting query.
func countRows(t *testing.T, h *harness, query string, args ...any) int {
	t.Helper()
	var n int
	if err := h.pool.QueryRow(t.Context(), query, args...).Scan(&n); err != nil {
		t.Fatalf("counting (%s): %v", query, err)
	}
	return n
}

// dumpTable renders every row of a one-column-or-more query as text, for the
// "the plaintext is nowhere" sweeps.
//
// IT RENDERS WITH %v AND NOT BY SELECTING INTO A STRUCT, because the point is to
// see every column including the ones no Go type has a field for.
func dumpTable(t *testing.T, h *harness, query string, args ...any) string {
	t.Helper()
	rows, err := h.pool.Query(t.Context(), query, args...)
	if err != nil {
		t.Fatalf("dumping (%s): %v", query, err)
	}
	defer rows.Close()

	var b strings.Builder
	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			t.Fatalf("reading a dumped row: %v", err)
		}
		for _, v := range values {
			b.WriteString(stringify(v))
			b.WriteByte('\n')
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("dumping rows: %v", err)
	}
	return b.String()
}

// stringify renders a database value for the sweeps.
func stringify(v any) string {
	switch typed := v.(type) {
	case nil:
		return "<nil>"
	case []byte:
		return string(typed)
	case time.Time:
		return typed.Format(time.RFC3339Nano)
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}
