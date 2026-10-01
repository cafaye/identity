package recovery

import (
	"strings"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/sessions"
)

// THE MESSAGES, AND THE STORE'S TWO CLAIMS.
//
// A token in a subject line is a token in a provider's index, a notification
// daemon's log and a phone's lock screen, so the subject assertions here are the
// ones worth writing by hand rather than deriving from the same map the renderer
// reads.

// TestNoSubjectCarriesAToken walks every message kind and asserts the property that
// has no equivalent elsewhere in this package.
//
// IT RENDERS FIRST AND THEN SEARCHES, so a test that cannot render cannot pass: the
// assertion is about a real rendered subject, not about the constant that produced
// it.
func TestNoSubjectCarriesAToken(t *testing.T) {
	const token = "Zz3vK7mXpR2tY8wB4cN6dF0gH1jK5lM9oP3qS7uV2wX4yZ8"

	for kind := range messageBodies {
		kind := kind
		t.Run(string(kind), func(t *testing.T) {
			t.Parallel()

			message, err := messageFor(kind, messageData{
				To: "kaka@example.com", Email: "kaka@example.com",
				Target: "new@example.com", Token: token, Expiry: issuedAt().Add(time.Hour),
			})
			if err != nil {
				t.Fatalf("messageFor(%s): %v", kind, err)
			}
			if strings.Contains(message.Subject, token) {
				t.Errorf("the %s subject carries the token: %q", kind, message.Subject)
			}
			if !strings.Contains(message.Body, token) {
				t.Errorf("the %s body does not carry its token; a user cannot enter a code "+
					"that was never in the message:\n%s", kind, message.Body)
			}
			if strings.Contains(message.Body, "{{") {
				t.Errorf("the %s body has an unsubstituted placeholder in it:\n%s", kind, message.Body)
			}
		})
	}
}

// TestEveryMessageNamesTheAddressAndTheDeadline: a code that arrives with nothing
// else in it is a code somebody cannot tell is theirs, and a deadline nobody can
// place is a deadline they ignore.
func TestEveryMessageNamesTheAddressAndTheDeadline(t *testing.T) {
	for kind := range messageBodies {
		kind := kind
		t.Run(string(kind), func(t *testing.T) {
			t.Parallel()

			expiry := issuedAt().Add(EmailChangeTTL)
			message, err := messageFor(kind, messageData{
				To: "kaka@example.com", Email: "kaka@example.com",
				Target: "new@example.com", Token: "a-token", Expiry: expiry,
			})
			if err != nil {
				t.Fatalf("messageFor(%s): %v", kind, err)
			}
			if !strings.Contains(message.Body, "kaka@example.com") {
				t.Errorf("the %s body does not name the account's address:\n%s", kind, message.Body)
			}
			if !strings.Contains(message.Body, expiry.UTC().Format(time.RFC1123)) {
				t.Errorf("the %s body does not carry a deadline a reader can place:\n%s", kind, message.Body)
			}
		})
	}
}

// TestAMessageWithNoTokenIsRefused: the one rendering bug that matters, caught where
// it can happen rather than in a delivered mail.
func TestAMessageWithNoTokenIsRefused(t *testing.T) {
	for kind := range messageBodies {
		if _, err := messageFor(kind, messageData{Email: "kaka@example.com"}); err == nil {
			t.Errorf("messageFor(%s) rendered a body with no token in it", kind)
		}
	}
}

// TestAMessageKindWithNoBodyIsRefusedRatherThanRenderedEmpty: a new kind that
// somebody forgets to write a body for must fail here, not arrive at an inbox.
func TestAMessageKindWithNoBodyIsRefusedRatherThanRenderedEmpty(t *testing.T) {
	if _, err := messageFor(messageKind("not_a_kind"), messageData{Token: "a-token"}); err == nil {
		t.Fatal("an unknown message kind rendered")
	}
}

// TestAnEmailChangeBodyNamesTheNewAddress is the one message with a third address
// in it, and it is the one a user needs: "somebody asked to move the account on
// kaka@example.com to THIS address" is only actionable if the reader can see which
// address they are being asked to confirm.
func TestAnEmailChangeBodyNamesTheNewAddress(t *testing.T) {
	message, err := messageFor(messageChangeNew, messageData{
		Email: "kaka@example.com", Target: "new@example.com",
		Token: "a-token", Expiry: issuedAt().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("messageFor: %v", err)
	}
	if !strings.Contains(message.Body, "new@example.com") {
		t.Errorf("the new-address body does not name the new address:\n%s", message.Body)
	}
}

// TestThePurposesAreAClosedSetThatTheSchemaAgreesWith is the Go half of a pair; the
// schema half is TestTheSchemaRefusesAnUnknownPurpose. Between them, a row naming a
// purpose this build does not implement cannot be written and cannot be read.
func TestThePurposesAreAClosedSetThatTheSchemaAgreesWith(t *testing.T) {
	want := map[Purpose]bool{
		PurposePasswordReset: true,
		PurposeVerifyEmail:   true,
		PurposeEmailChange:   true,
	}
	for _, p := range []Purpose{PurposePasswordReset, PurposeVerifyEmail, PurposeEmailChange} {
		if !want[p] {
			t.Errorf("%q is not in the set this test pins", p)
		}
		delete(want, p)
	}
	if len(want) != 0 {
		t.Errorf("the pinned set has %d purposes this file no longer declares: %v", len(want), want)
	}

	// And every one of them has a body, because a purpose with no message is a flow
	// that mails nobody.
	for _, p := range []Purpose{PurposePasswordReset, PurposeVerifyEmail, PurposeEmailChange} {
		if _, ok := messageBodies[purposeMessageKind(p)]; !ok {
			t.Errorf("%q has no message body", p)
		}
	}
}

// purposeMessageKind is the mapping a request flow uses: the FIRST message of a
// purpose. An email change's second message is not reachable from a purpose, which
// is why this returns one kind rather than a slice.
func purposeMessageKind(p Purpose) messageKind {
	if p == PurposeEmailChange {
		return messageChangeFirst
	}
	return messageKind(p)
}

// TestTheSchemaRefusesAnUnknownPurpose is the database half of the pair above.
func TestTheSchemaRefusesAnUnknownPurpose(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()

	_, digest, err := sessions.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}

	if err := h.pool.QueryRow(t.Context(), `
		INSERT INTO recovery_tokens (user_id, purpose, token_digest, created_at, expires_at)
		VALUES ($1, 'sign_their_will', $2, $3, $4)`,
		who.id, digest, h.now(), h.now().Add(time.Hour)).Scan(nil); err == nil {
		t.Error("the database accepted a purpose this build does not implement")
	}
}

// TestTheSchemaRefusesATokenWhoseExpiryIsItsOwnCreation is the second CHECK worth
// holding, and it is the one that makes an expired token indistinguishable from an
// absent one at the storage layer: a row that expires at the instant it was minted
// can never pass `expires_at > now`, so it can never be spent and cannot be told
// apart from a row that was never there.
func TestTheSchemaRefusesATokenWhoseExpiryIsItsOwnCreation(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()

	_, digest, err := sessions.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}

	if err := h.pool.QueryRow(t.Context(), `
		INSERT INTO recovery_tokens (user_id, purpose, token_digest, created_at, expires_at)
		VALUES ($1, 'password_reset', $2, $3, $3)`,
		who.id, digest, h.now()).Scan(nil); err == nil {
		t.Error("the database accepted a token that expires the instant it was created")
	}
}

// TestTheSchemaRefusesATargetOnAFlowThatDoesNotMoveAddresses: the
// `target_is_for_an_email_change` CHECK, which is what stops a reset token from
// carrying an address somebody could later claim it was for.
func TestTheSchemaRefusesATargetOnAFlowThatDoesNotMoveAddresses(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()

	_, digest, err := sessions.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}

	if err := h.pool.QueryRow(t.Context(), `
		INSERT INTO recovery_tokens (user_id, purpose, token_digest, target_email, created_at, expires_at)
		VALUES ($1, 'password_reset', $2, 'attacker@example.com', $3, $4)`,
		who.id, digest, h.now(), h.now().Add(time.Hour)).Scan(nil); err == nil {
		t.Error("the database accepted a password reset token carrying a target address")
	}

	if err := h.pool.QueryRow(t.Context(), `
		INSERT INTO recovery_tokens (user_id, purpose, token_digest, created_at, expires_at)
		VALUES ($1, 'email_change', $2, $3, $4)`,
		who.id, digest, h.now(), h.now().Add(time.Hour)).Scan(nil); err == nil {
		t.Error("the database accepted an email change token with no target address")
	}
}

// TestTokensAreGoneWithTheirUser: a token for a deleted account can only ever be
// refused, and leaving it behind would keep the table growing for accounts that
// are not there.
func TestTokensAreGoneWithTheirUser(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()
	h.requestReset(t, who)

	// Scoped to THIS row rather than counting the table, because every test in this
	// package shares one database and an unscoped count measures the run.
	rowID := h.newestTokenID(who.id, PurposePasswordReset)
	if got := countRows(t, h, `SELECT count(*) FROM recovery_tokens WHERE id = $1`, rowID); got != 1 {
		t.Fatalf("%d rows before the user is deleted, want 1", got)
	}
	if _, err := h.pool.Exec(t.Context(), `DELETE FROM users WHERE id = $1`, who.id); err != nil {
		t.Fatalf("deleting the user: %v", err)
	}
	if got := countRows(t, h, `SELECT count(*) FROM recovery_tokens WHERE id = $1`, rowID); got != 0 {
		t.Errorf("the token survived its user: %d rows remain", got)
	}
}

// TestOneTokenSpentOnceUnderConcurrency is the single-use property at the only
// place it can actually be wrong: two requests carrying the same token at the same
// instant, resolved by a conditional UPDATE with no lock.
//
// It asserts the SUM — exactly one redemption — rather than "at least one
// succeeded". A service that let every racer through would pass the second and fail
// this one, which is the whole direction the assertion has to point.
func TestOneTokenSpentOnceUnderConcurrency(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()
	token := h.requestReset(t, who)

	const racers = 8
	type outcome struct {
		ok  bool
		err error
	}
	results := make(chan outcome, racers)
	start := make(chan struct{})

	for range racers {
		go func() {
			<-start
			_, err := h.svc.RedeemPasswordReset(t.Context(), RedeemPasswordResetInput{
				Token: token, Password: "one of these will win",
			})
			results <- outcome{err: err}
		}()
	}
	close(start)

	won := 0
	for range racers {
		got := <-results
		if got.err == nil {
			won++
		}
	}
	if won != 1 {
		t.Errorf("%d of %d concurrent redemptions of one token succeeded, want exactly 1", won, racers)
	}
	assertPasswordIs(t, h, who, "one of these will win")
}

// TestTheStoredDigestIsTheOnlyCredential checks the digest construction itself, at
// the store, over a row created by the store rather than by a flow.
//
// The reason sessions.Digest is a *function* and not a field is that a lookup has
// to turn ANY presented value into a well-formed digest, so "no token", "wrong
// token" and "expired token" are one query and one response time. That is the
// timing story this whole service tells, and it is worth one test at the layer where
// it is decided.
func TestTheStoredDigestIsTheOnlyCredential(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()

	token, digest, err := sessions.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	created, err := NewStore(h.pool).Create(t.Context(), h.pool, NewToken{
		UserID: who.id, Purpose: PurposePasswordReset,
		Digest: digest, CreatedAt: h.now(), ExpiresAt: h.now().Add(PasswordResetTTL),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	row := h.storedTokenRow(created.ID)
	if got := row["token_digest"]; got != digest {
		t.Errorf("token_digest = %v, want the digest the store was handed", got)
	}

	// Garbage still produces a well-formed digest, so a lookup cannot be told from
	// its query shape whether the caller had anything.
	for _, garbage := range []string{"", " ", "not-a-token", token, token[:20], strings.Repeat("x", 4096)} {
		got := sessions.Digest(garbage)
		if len(got) != 64 {
			t.Errorf("Digest(%d bytes) is %d characters, want 64", len(garbage), len(got))
		}
	}
	if sessions.Digest(token) != digest {
		t.Error("Digest is not a function of its input; the lookup could not be an indexed equality")
	}

	// The purpose filter is the only thing keeping the three flows' tokens apart,
	// and it is asserted here at the store rather than only through a flow.
	if _, err := NewStore(h.pool).Live(t.Context(), h.pool, digest, PurposePasswordReset, h.now()); err != nil {
		t.Fatalf("Live on a fresh token: %v", err)
	}
	if _, err := NewStore(h.pool).Live(t.Context(), h.pool, digest, PurposeVerifyEmail, h.now()); err != ErrTokenNotFound {
		t.Errorf("Live for the wrong purpose = %v, want ErrTokenNotFound", err)
	}
}
