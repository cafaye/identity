package recovery

import (
	"testing"
	"time"

	"github.com/cafaye/identity/internal/platform/dbtest"
)

// THE VERIFICATION FLOW.
//
// It is the smallest of the three and the one with the fewest moving parts, which is
// why the assertions here are about what it does NOT do almost as much as what it
// does: a verification that revoked a session or minted one would be a security
// change wearing a "confirm your address" label.

// TestAVerificationProvesTheAddressAndNothingElse is the whole flow in one
// assertion, and then the two negatives that make it a property rather than a
// feature.
func TestAVerificationProvesTheAddressAndNothingElse(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()
	assertNotVerified(t, h, who)

	token := h.requestVerification(t, who)
	if got := h.mailer.last(t).To; got != who.email {
		t.Errorf("the verification went to %q, want the account's own address %q", got, who.email)
	}

	sessionsBefore := h.sessionsFor(who.id)
	if err := h.svc.RedeemVerification(t.Context(), RedeemVerificationInput{Token: token}); err != nil {
		t.Fatalf("RedeemVerification: %v", err)
	}

	assertVerified(t, h, who)

	// THE TWO NEGATIVES.
	//
	// A verification changes no secret, so ending the account's sessions over it
	// would punish somebody for clicking a link — and minting a session would turn
	// possession of an inbox into a browser credential, which is the one thing this
	// service has never done and the reason a token is not a session everywhere
	// else in it.
	if got := h.sessionsFor(who.id); got != sessionsBefore {
		t.Errorf("%d sessions after a verification, want %d: verifying an address is not a "+
			"security change", got, sessionsBefore)
	}
	if _, swept := h.access.swept(who.id); swept {
		t.Error("a verification revoked the account's access tokens")
	}

	// And the event is on the outbox, so a consumer can find out.
	// Scoped to THIS account, because every test in this package shares one database
	// and an unscoped count would be measuring the run rather than the flow.
	var seen int
	if err := h.pool.QueryRow(t.Context(),
		`SELECT count(*) FROM outbox_events WHERE type = 'identity.user.email_verified' AND subject = $1`,
		who.id.String()).Scan(&seen); err != nil {
		t.Fatalf("counting the verification event: %v", err)
	}
	if seen != 1 {
		t.Errorf("%d identity.user.email_verified events after one verification, want 1", seen)
	}
}

// TestAReusedVerificationTokenIsRefused and TestAnExpiredVerificationTokenIsRefused
// are the same two negatives as the password reset's, on the third flow.
//
// They are written out rather than shared because the flows have different
// consequences on failure: a reused reset token would change a password, a reused
// verification token would mark an address proved. A table of them would be one
// test whose failure names neither.
func TestAReusedVerificationTokenIsRefused(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()

	token := h.requestVerification(t, who)
	if err := h.svc.RedeemVerification(t.Context(), RedeemVerificationInput{Token: token}); err != nil {
		t.Fatalf("the first redemption: %v", err)
	}
	if err := h.svc.RedeemVerification(t.Context(), RedeemVerificationInput{Token: token}); err == nil {
		t.Fatal("a verification token was accepted twice")
	}

	// The instant recorded is the FIRST proof, not the most recent click: a column
	// that moved every time somebody followed a second link would make "when was
	// this address verified" answer a question with no answer.
	var at *time.Time
	if err := h.pool.QueryRow(t.Context(),
		`SELECT email_verified_at FROM users WHERE id = $1`, who.id).Scan(&at); err != nil {
		t.Fatalf("reading the verification state: %v", err)
	}
	if !at.Equal(h.now()) {
		t.Errorf("verified at %s, want %s: a replay moved the instant", at, h.now())
	}
}

func TestAnExpiredVerificationTokenIsRefused(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()

	token := h.requestVerification(t, who)
	h.clk.Advance(VerifyEmailTTL + time.Second)

	if err := h.svc.RedeemVerification(t.Context(), RedeemVerificationInput{Token: token}); err == nil {
		t.Fatal("an expired verification token was accepted")
	}
	assertNotVerified(t, h, who)
}

// TestAVerificationRequestForAKnownAddressIsRefusedOnceVerified: the honest answer
// to "send me another verification link" on an account that is already proved.
//
// It matters because the alternative is a 202 a client renders as "we emailed you",
// and the user then sits in front of an inbox that is never going to receive
// anything.
func TestAVerificationRequestForAKnownAddressIsRefusedOnceVerified(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()

	token := h.requestVerification(t, who)
	if err := h.svc.RedeemVerification(t.Context(), RedeemVerificationInput{Token: token}); err != nil {
		t.Fatalf("RedeemVerification: %v", err)
	}

	err := h.svc.RequestVerification(t.Context(), who.email)
	if err != ErrAlreadyVerified {
		t.Errorf("RequestVerification on a verified account = %v, want ErrAlreadyVerified", err)
	}
	if got := h.mailer.count(); got != 1 {
		t.Errorf("%d messages after a second request on a verified account, want 1", got)
	}
}

// TestAVerificationRequestForAnUnknownAddressIsSilent: the same enumeration answer
// the reset request gives, because the question behind the two is the same one.
func TestAVerificationRequestForAnUnknownAddressIsSilent(t *testing.T) {
	h := newHarness(t, true)

	if err := h.svc.RequestVerification(t.Context(), dbtest.UniqueEmail(t)); err != nil {
		t.Fatalf("RequestVerification for an unknown address = %v, want nil", err)
	}
	if got := h.mailer.count(); got != 0 {
		t.Errorf("%d messages for an address with no account", got)
	}
	if got := countRows(t, h, `SELECT count(*) FROM recovery_tokens`); got != 0 {
		t.Errorf("%d rows for an address with no account", got)
	}
}

// TestAVerificationRequestInsideTheWindowSendsNothing: the same cooldown as the
// reset, on the second anonymous request route.
func TestAVerificationRequestInsideTheWindowSendsNothing(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()

	if err := h.svc.RequestVerification(t.Context(), who.email); err != nil {
		t.Fatalf("the first request: %v", err)
	}
	for range 10 {
		h.clk.Advance(time.Second)
		if err := h.svc.RequestVerification(t.Context(), who.email); err != nil {
			t.Fatalf("a request inside the window: %v", err)
		}
	}
	if got := h.mailer.count(); got != 1 {
		t.Errorf("%d verification messages after 11 requests inside the window, want 1", got)
	}
}

// TestVerificationStatusIsA200WithABooleanRatherThanAnError: the question every
// settings page asks, answered for an unverified account.
//
// It is 200 rather than a 404 because "not verified" is the state every account is
// in until somebody follows a link, and a client that has to distinguish it from
// "this is not your account" cannot render a banner.
func TestVerificationStatusIsA200WithABooleanRatherThanAnError(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()

	before, err := h.svc.VerificationStatus(t.Context(), who.id)
	if err != nil {
		t.Fatalf("VerificationStatus before verifying: %v", err)
	}
	if before.Verified || before.VerifiedAt != nil || before.Email != who.email {
		t.Errorf("before: %+v, want unverified at %q", before, who.email)
	}

	h.requestVerification(t, who)
	if err := h.svc.RedeemVerification(t.Context(), RedeemVerificationInput{
		Token: tokenFrom(t, h.mailer.last(t)),
	}); err != nil {
		t.Fatalf("RedeemVerification: %v", err)
	}

	after, err := h.svc.VerificationStatus(t.Context(), who.id)
	if err != nil {
		t.Fatalf("VerificationStatus after verifying: %v", err)
	}
	if !after.Verified || after.VerifiedAt == nil || !after.VerifiedAt.Equal(h.now()) {
		t.Errorf("after: %+v, want verified at %s", after, h.now())
	}
}

// --- helpers -----------------------------------------------------------------

// requestVerification runs the whole request step and returns the mailed token.
func (h *harness) requestVerification(t *testing.T, who account) string {
	t.Helper()
	if err := h.svc.RequestVerification(t.Context(), who.email); err != nil {
		t.Fatalf("RequestVerification: %v", err)
	}
	return tokenFrom(t, h.mailer.last(t))
}
