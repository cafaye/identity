package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cafaye/identity/internal/mfa"
	"github.com/cafaye/identity/internal/outbox"
	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/sessions"
)

// The second-factor helpers, for the httpapi tests.
//
// These are the REAL use cases over a private schema. A double would make every
// test in this package pass with a login that skips the challenge — which is the
// one bug identity-06 exists to prevent — and the whole value of the httpapi tests
// for MFA is that they run the SQL.
//
// The key is a constant because it is a test fixture, not a secret. It is 32 bytes
// of ASCII and it is the same in every test in this package, which is what lets a
// test seal a value here and open it there.

var testMFAKey = testKey32("identity-httpapi-mfa-key-32-byte")

// testMFAIssuer is what an authenticator app would display.
const testMFAIssuer = "cafaye identity"

// testMFAService builds the real mfa.Service over a pool.
func testMFAService(pool *pgxpool.Pool, clk clock.Clock) *mfa.Service {
	vault, err := mfa.NewAESCipher(testMFAKey)
	if err != nil {
		// Unreachable: the fixture key is 32 bytes, which the constructor checks.
		// Panicking here is honest — a test binary with a broken fixture cannot
		// prove anything about the code under test.
		panic("httpapi: the MFA test key is not 32 bytes: " + err.Error())
	}
	return mfa.NewService(
		db.TxRunner{Pool: pool},
		db.Direct{Pool: pool},
		mfa.NewStore(pool),
		outbox.NewStore(pool),
		sessions.NewStore(pool),
		vault,
		clk,
		testMFAIssuer,
	)
}

// enrolledUser is a user with a confirmed second factor, and the two values a test
// needs to act as their authenticator: the base32 secret and a recovery code.
type enrolledUser struct {
	User         id.UUID
	Secret       string
	RecoveryCode string
}

// code is what that user's authenticator app is showing at instant.
func (e enrolledUser) code(t *testing.T, at time.Time) string {
	t.Helper()
	code, err := mfa.Code(e.Secret, at)
	if err != nil {
		t.Fatalf("mfa.Code: %v", err)
	}
	return code
}

// enrollMFA runs the whole first-time enrollment through the real use cases and
// returns what a real client would have captured: the secret and the first recovery
// code.
func enrollMFA(t *testing.T, svc *mfa.Service, userID id.UUID, now time.Time) enrolledUser {
	t.Helper()
	ctx := context.Background()

	started, err := svc.StartEnrollment(ctx, mfa.StartEnrollmentInput{UserID: userID})
	if err != nil {
		t.Fatalf("StartEnrollment: %v", err)
	}
	code, err := mfa.Code(started.Secret, now)
	if err != nil {
		t.Fatalf("mfa.Code: %v", err)
	}
	confirmed, err := svc.Confirm(ctx, mfa.ConfirmInput{
		UserID:       userID,
		EnrollmentID: started.Credential.ID,
		Factor:       code,
	})
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if len(confirmed.RecoveryCodes) == 0 {
		t.Fatal("the confirmation issued no recovery codes")
	}

	return enrolledUser{User: userID, Secret: started.Secret, RecoveryCode: confirmed.RecoveryCodes[0]}
}

// sendWith is the one place these tests build an MFA request, so the bearer header
// and the challenge cookie are always set the same way and a test cannot
// accidentally assert on a request that was missing one.
//
// token is the session bearer and challenge is the challenge cookie; either may be
// empty for a test that is about the other one.
func sendWith(t *testing.T, h http.Handler, method, path, token, challenge, body string) *httptest.ResponseRecorder {
	t.Helper()

	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if challenge != "" {
		req.AddCookie(&http.Cookie{Name: MFAChallengeCookieName, Value: challenge})
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// testKey32 is a fixed 32-byte key, built as an ARRAY so the length is a
// compile-time fact rather than a thing to count by hand.
//
// It is a fixture, not a secret: the same value in every test in this package is
// what lets one test seal a value and another open it. Counting a string literal by
// eye is exactly the mistake this helper exists to remove — it happened twice while
// this packet was being written.
func testKey32(literal string) []byte {
	var key [32]byte
	copy(key[:], literal)
	return key[:]
}
