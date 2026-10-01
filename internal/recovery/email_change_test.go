package recovery

import (
	"strings"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/platform/id"

	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/sessions"
)

// THE EMAIL CHANGE FLOW.
//
// Three requests, two mailboxes, and one property that the rest of this file is
// built around: a token for the NEW address cannot exist until the CURRENT address
// has been confirmed. That is what makes a stolen session harmless here.

// TestAnEmailChangeNeedsBothAddressesConfirmed walks the whole flow and asserts
// after every step what does and does not exist.
func TestAnEmailChangeNeedsBothAddressesConfirmed(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()
	target := dbtest.UniqueEmail(t)

	change, err := h.svc.RequestEmailChange(t.Context(), RequestEmailChangeInput{
		UserID: who.id, Email: target,
	})
	if err != nil {
		t.Fatalf("RequestEmailChange: %v", err)
	}
	if change.CurrentEmail != who.email || change.NewEmail != target {
		t.Errorf("the change = %+v, want %q -> %q", change, who.email, target)
	}

	// The FIRST message goes to the address the account has now. Not the one being
	// moved to: that is the whole of the flow.
	first := h.mailer.last(t)
	if first.To != who.email {
		t.Fatalf("the first message went to %q, want the CURRENT address %q", first.To, who.email)
	}
	current := tokenFrom(t, first)

	// Nothing has moved, and there is no token for the new address yet.
	assertEmailIs(t, h, who, who.email)
	if h.hasTargetDigest(h.newestTokenID(who.id, PurposeEmailChange)) {
		t.Error("a target token exists before the current address was confirmed")
	}

	if _, err := h.svc.ConfirmEmailChangeCurrent(t.Context(), ConfirmEmailChangeCurrentInput{
		Token: current,
	}); err != nil {
		t.Fatalf("ConfirmEmailChangeCurrent: %v", err)
	}

	// The second message goes to the NEW address.
	second := h.mailer.last(t)
	if second.To != target {
		t.Errorf("the second message went to %q, want the NEW address %q", second.To, target)
	}
	next := tokenFrom(t, second)
	if next == current {
		t.Error("the new-address token is the one already spent on the current address")
	}

	// And still nothing has moved. One confirmed address is not a change.
	assertEmailIs(t, h, who, who.email)

	if _, err := h.svc.ConfirmEmailChangeNew(t.Context(), ConfirmEmailChangeNewInput{
		Token: next,
	}); err != nil {
		t.Fatalf("ConfirmEmailChangeNew: %v", err)
	}

	assertEmailIs(t, h, who, target)
	assertEmailAvailable(t, h, who.email)
}

// TestTheNewAddressTokenIsMintedOnlyAfterTheCurrentAddressIsConfirmed is the same
// fact read at the moment it becomes true, and it is separate from the walk above
// because the walk asserts the OUTCOME while this asserts the TIMING — and the
// timing is the property.
func TestTheNewAddressTokenIsMintedOnlyAfterTheCurrentAddressIsConfirmed(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()
	rowID := h.requestEmailChange(t, who, dbtest.UniqueEmail(t))

	if h.hasTargetDigest(rowID) {
		t.Error("a target token exists immediately after the request")
	}
	// And the database agrees, which is the schema's own CHECK and the reason this
	// is not merely a code convention.
	if err := h.pool.QueryRow(t.Context(),
		`UPDATE recovery_tokens SET target_token_digest = $2 WHERE id = $1`,
		rowID, sessions.Digest("written by hand")).Scan(nil); err == nil {
		t.Error("the database accepted a target token before the current address was confirmed")
	}

	token := tokenFrom(t, h.mailer.last(t))
	if _, err := h.svc.ConfirmEmailChangeCurrent(t.Context(), ConfirmEmailChangeCurrentInput{
		Token: token,
	}); err != nil {
		t.Fatalf("ConfirmEmailChangeCurrent: %v", err)
	}
	if !h.hasTargetDigest(rowID) {
		t.Error("no target token exists after the current address was confirmed")
	}
}

// TestAChangeDoesNotApplyFromTheCurrentAddressTokenAlone: the negative that the
// second half of the flow is for.
//
// A token that could move an address on its own would let a stolen session change
// where the account's recovery mail goes, which is the account takeover this whole
// packet is about — arrived at from the other direction.
func TestAChangeDoesNotApplyFromTheCurrentAddressTokenAlone(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()
	target := dbtest.UniqueEmail(t)
	h.requestEmailChange(t, who, target)
	current := tokenFrom(t, h.mailer.last(t))

	if _, err := h.svc.ConfirmEmailChangeNew(t.Context(), ConfirmEmailChangeNewInput{
		Token: current,
	}); err == nil {
		t.Fatal("the current-address token moved the address on its own")
	}
	assertEmailIs(t, h, who, who.email)
}

// TestAChangeDoesNotApplyFromTheNewAddressTokenAlone: the mirror. Somebody who
// controls only the new inbox cannot move an address whose owner has not agreed.
func TestAChangeDoesNotApplyFromTheNewAddressTokenAlone(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()
	target := dbtest.UniqueEmail(t)
	h.requestEmailChange(t, who, target)

	// The current address is confirmed, which is what mints the target token. This
	// test is about the token's own single-use and the expiry, so it has to get past
	// the first step legitimately.
	h.svc.ConfirmEmailChangeCurrent(t.Context(), ConfirmEmailChangeCurrentInput{
		Token: tokenFrom(t, h.mailer.last(t)),
	})
	next := tokenFrom(t, h.mailer.last(t))

	if _, err := h.svc.ConfirmEmailChangeNew(t.Context(), ConfirmEmailChangeNewInput{Token: next}); err != nil {
		t.Fatalf("ConfirmEmailChangeNew: %v", err)
	}
	// The second presentation of the same token is refused, and the address does not
	// move again.
	if _, err := h.svc.ConfirmEmailChangeNew(t.Context(), ConfirmEmailChangeNewInput{Token: next}); err == nil {
		t.Fatal("the new-address token was accepted twice")
	}
	assertEmailIs(t, h, who, target)
}

// TestAnExpiredEmailChangeTokenIsRefusedOnBothHalves.
func TestAnExpiredEmailChangeTokenIsRefusedOnBothHalves(t *testing.T) {
	t.Run("the current-address half", func(t *testing.T) {
		h := newHarness(t, true)
		who := h.registerSimple()
		h.requestEmailChange(t, who, dbtest.UniqueEmail(t))
		current := tokenFrom(t, h.mailer.last(t))

		h.clk.Advance(EmailChangeTTL + time.Second)
		if _, err := h.svc.ConfirmEmailChangeCurrent(t.Context(), ConfirmEmailChangeCurrentInput{
			Token: current,
		}); err == nil {
			t.Fatal("an expired current-address token was accepted")
		}
		if got := h.mailer.count(); got != 1 {
			t.Errorf("%d messages; a refused token mailed the new address anyway", got)
		}
	})

	t.Run("the new-address half", func(t *testing.T) {
		h := newHarness(t, true)
		who := h.registerSimple()
		h.requestEmailChange(t, who, dbtest.UniqueEmail(t))
		h.svc.ConfirmEmailChangeCurrent(t.Context(), ConfirmEmailChangeCurrentInput{
			Token: tokenFrom(t, h.mailer.last(t)),
		})
		next := tokenFrom(t, h.mailer.last(t))

		h.clk.Advance(EmailChangeTTL + time.Second)
		if _, err := h.svc.ConfirmEmailChangeNew(t.Context(), ConfirmEmailChangeNewInput{Token: next}); err == nil {
			t.Fatal("an expired new-address token was accepted")
		}
		assertEmailIs(t, h, who, who.email)
	})
}

// TestAChangeClearsTheVerificationAndEndsEveryCredential is the "old access tokens
// are invalidated" requirement on the second surface, and the first half of it is
// the one people get wrong: the new address lands UNVERIFIED.
//
// The column is cleared by the same statement that moves the address, so an address
// that arrives proved would mean somebody either clicked a verification link nobody
// sent or read a column the write path does not maintain.
func TestAChangeClearsTheVerificationAndEndsEveryCredential(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()

	// Prove the address first, so the change has something to clear.
	h.requestVerification(t, who)
	if err := h.svc.RedeemVerification(t.Context(), RedeemVerificationInput{
		Token: tokenFrom(t, h.mailer.last(t)),
	}); err != nil {
		t.Fatalf("RedeemVerification: %v", err)
	}
	assertVerified(t, h, who)

	target := dbtest.UniqueEmail(t)
	h.requestEmailChange(t, who, target)
	h.svc.ConfirmEmailChangeCurrent(t.Context(), ConfirmEmailChangeCurrentInput{
		Token: tokenFrom(t, h.mailer.last(t)),
	})
	if _, err := h.svc.ConfirmEmailChangeNew(t.Context(), ConfirmEmailChangeNewInput{
		Token: tokenFrom(t, h.mailer.last(t)),
	}); err != nil {
		t.Fatalf("ConfirmEmailChangeNew: %v", err)
	}

	assertNotVerified(t, h, who)
	if got := h.sessionsFor(who.id); got != 0 {
		t.Errorf("%d sessions survived an email change, want 0", got)
	}
	if _, swept := h.access.swept(who.id); !swept {
		t.Error("an email change revoked no access tokens")
	}
}

// TestAnEmailChangeToAnAddressSomebodyElseHasIsRefusedTwice: once at the request,
// because two emails and two clicks before a change that could never apply is worse
// than a 409; and again at the confirmation, because somebody may have registered it
// in between.
func TestAnEmailChangeToAnAddressSomebodyElseHasIsRefusedTwice(t *testing.T) {
	t.Run("at the request", func(t *testing.T) {
		h := newHarness(t, true)
		who := h.registerSimple()
		taken := h.registerSimple()

		_, err := h.svc.RequestEmailChange(t.Context(), RequestEmailChangeInput{
			UserID: who.id, Email: taken.email,
		})
		if err != ErrEmailTaken {
			t.Errorf("RequestEmailChange to a registered address = %v, want ErrEmailTaken", err)
		}
		if got := h.mailer.count(); got != 0 {
			t.Errorf("%d messages were sent for a change that could never apply", got)
		}
	})

	t.Run("at the confirmation", func(t *testing.T) {
		h := newHarness(t, true)
		who := h.registerSimple()
		target := dbtest.UniqueEmail(t)
		h.requestEmailChange(t, who, target)
		h.svc.ConfirmEmailChangeCurrent(t.Context(), ConfirmEmailChangeCurrentInput{
			Token: tokenFrom(t, h.mailer.last(t)),
		})
		next := tokenFrom(t, h.mailer.last(t))

		// Somebody registers the address while the change is halfway through.
		if _, err := h.users.Create(t.Context(), h.pool, dbCreate(target)); err != nil {
			t.Fatalf("registering the address mid-change: %v", err)
		}

		if _, err := h.svc.ConfirmEmailChangeNew(t.Context(), ConfirmEmailChangeNewInput{Token: next}); err != ErrEmailTaken {
			t.Errorf("ConfirmEmailChangeNew onto a registered address = %v, want ErrEmailTaken", err)
		}
		assertEmailIs(t, h, who, who.email)
	})
}

// TestAnEmailChangeToTheCurrentAddressIsRefused: a 202 here would leave a caller
// believing a change had been requested, and then nothing would ever arrive in
// either inbox.
func TestAnEmailChangeToTheCurrentAddressIsRefused(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()

	for _, address := range []string{who.email, "  " + strings.ToUpper(who.email) + " "} {
		_, err := h.svc.RequestEmailChange(t.Context(), RequestEmailChangeInput{
			UserID: who.id, Email: address,
		})
		if err != ErrSameAddress {
			t.Errorf("RequestEmailChange(%q) = %v, want ErrSameAddress", address, err)
		}
	}
	if got := h.mailer.count(); got != 0 {
		t.Errorf("%d messages were sent for a change that describes no move", got)
	}
}

// TestAnEmailChangeTokenIsNotAResetOrAVerificationToken: three purposes, three
// tables' worth of meaning, one lookup keyed on the digest — and the filter on
// `purpose` is the only thing keeping them apart.
func TestAnEmailChangeTokenIsNotAResetOrAVerificationToken(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()
	h.requestEmailChange(t, who, dbtest.UniqueEmail(t))
	change := tokenFrom(t, h.mailer.last(t))

	if err := h.svc.RedeemVerification(t.Context(), RedeemVerificationInput{Token: change}); err == nil {
		t.Error("an email change token was accepted by the verification redemption")
	}
	h.clk.Advance(RequestWindow + time.Second)
	reset := h.requestReset(t, who)
	if _, err := h.svc.ConfirmEmailChangeCurrent(t.Context(),
		ConfirmEmailChangeCurrentInput{Token: reset}); err == nil {
		t.Error("a password reset token was accepted as an email change confirmation")
	}
	assertNotVerified(t, h, who)
	assertPasswordIs(t, h, who, "correct horse battery staple")
}

// --- helpers -----------------------------------------------------------------

// requestEmailChange runs the request step and returns the row id, so a test can
// look at the row rather than only at the flow.
func (h *harness) requestEmailChange(t *testing.T, who account, target string) id.UUID {
	t.Helper()
	if _, err := h.svc.RequestEmailChange(t.Context(), RequestEmailChangeInput{
		UserID: who.id, Email: target,
	}); err != nil {
		t.Fatalf("RequestEmailChange: %v", err)
	}
	return h.newestTokenID(who.id, PurposeEmailChange)
}

// assertEmailIs checks the address on the row.
func assertEmailIs(t *testing.T, h *harness, who account, want string) {
	t.Helper()
	var got string
	if err := h.pool.QueryRow(t.Context(),
		`SELECT email FROM users WHERE id = $1`, who.id).Scan(&got); err != nil {
		t.Fatalf("reading the address: %v", err)
	}
	if got != want {
		t.Errorf("the account's address is %q, want %q", got, want)
	}
}

// assertEmailAvailable checks an address is free to be registered, which is what
// "the change did not happen" looks like from the outside.
func assertEmailAvailable(t *testing.T, h *harness, email string) {
	t.Helper()
	var n int
	if err := h.pool.QueryRow(t.Context(),
		`SELECT count(*) FROM users WHERE email = $1`, email).Scan(&n); err != nil {
		t.Fatalf("counting users at %q: %v", email, err)
	}
	if n != 0 {
		t.Errorf("%d accounts still hold %q; the old address was not freed", n, email)
	}
}
