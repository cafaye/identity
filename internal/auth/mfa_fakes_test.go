package auth

import (
	"context"
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

// The second-factor dependency, twice over: a fake for the branching tests and the
// real use cases for the ones that have to be about SQL.
//
// It is a REQUIRED argument to NewService, so both exist. The fake models the two
// things a login can be told — "this account has a second factor" and "here is a
// challenge" — and the integration tests use the real mfa.Service so that "no
// session before the second factor" is proved against the sessions table rather
// than against a return value.

// fakeSecondFactor is an in-memory SecondFactor.
type fakeSecondFactor struct {
	// enabled is the set of users whose accounts have a second factor.
	enabled map[id.UUID]bool

	// verifyErr is what VerifyChallenge returns.
	verifyErr error
	// enabledErr is what Enabled returns.
	enabledErr error
	// createErr is what CreateChallenge returns.
	createErr error
	// commitErr is what Commit returns.
	commitErr error

	// challengeToken is what a minted challenge is addressed by.
	challengeToken string
	// claim is what a successful VerifyChallenge hands back.
	claim mfa.Claim
	// claimUser is the user that claim belongs to.
	claimUser id.UUID

	// recorded
	enabledCalls  int
	challenges    []mfa.CreateChallengeInput
	verifications []CompleteSecondFactorInput
	commits       int
	// committed is the user whose challenge Commit was told about, so a test can
	// prove the failure counter was cleared on the right account.
	committed id.UUID
}

func newFakeSecondFactor() *fakeSecondFactor {
	var user id.UUID
	user[1] = 1
	return &fakeSecondFactor{
		enabled:        map[id.UUID]bool{},
		challengeToken: "a-challenge-token",
		claimUser:      user,
	}
}

func (f *fakeSecondFactor) Enabled(_ context.Context, _ db.Querier, userID id.UUID) (bool, error) {
	f.enabledCalls++
	if f.enabledErr != nil {
		return false, f.enabledErr
	}
	return f.enabled[userID], nil
}

func (f *fakeSecondFactor) CreateChallenge(_ context.Context, in mfa.CreateChallengeInput) (mfa.NewChallenge, error) {
	f.challenges = append(f.challenges, in)
	if f.createErr != nil {
		return mfa.NewChallenge{}, f.createErr
	}
	expires := start.Add(10 * time.Minute)
	return mfa.NewChallenge{
		Challenge: mfa.Challenge{UserID: in.UserID, CreatedAt: start, ExpiresAt: expires},
		Token:     f.challengeToken,
		ExpiresAt: expires,
	}, nil
}

func (f *fakeSecondFactor) VerifyChallenge(_ context.Context, token, code string, _ time.Time) (mfa.Claim, error) {
	f.verifications = append(f.verifications, CompleteSecondFactorInput{ChallengeToken: token, Code: code})
	if f.verifyErr != nil {
		return mfa.Claim{}, f.verifyErr
	}
	return f.claim, nil
}

func (f *fakeSecondFactor) Commit(_ context.Context, _ db.Querier, claim mfa.Claim, _ time.Time) error {
	f.commits++
	f.committed = claim.UserID()
	return f.commitErr
}

// claim is what a successful VerifyChallenge hands back. It names a user and
// nothing else, which is all Commit can act on for a claim that did not come from a
// real verification.
func (f *fakeSecondFactor) claimFor(user id.UUID) mfa.Claim { return mfa.ClaimForTest(user) }

// realSecondFactor builds the actual mfa.Service over a pool.
//
// It is a separate function rather than a parameter so the tests that need it can
// say so, and it exists because the property this packet is about — no session
// before the second factor — is a claim about the SESSIONS TABLE and not about a
// return value. A fake can only answer "did Login return a token".
func realSecondFactor(t *testing.T, pool *pgxpool.Pool, clk clock.Clock) *mfa.Service {
	t.Helper()

	vault, err := mfa.NewAESCipher(testSecondFactorKey)
	if err != nil {
		t.Fatalf("building the MFA test vault: %v", err)
	}
	return mfa.NewService(
		db.TxRunner{Pool: pool},
		db.Direct{Pool: pool},
		mfa.NewStore(pool),
		outbox.NewStore(pool),
		sessions.NewStore(pool),
		vault,
		clk,
		"cafaye identity",
	)
}

// testSecondFactorKey is 32 bytes of ASCII. It is a fixture, not a secret: the same
// value in every test in this package is what lets one test seal a value and
// another open it.
var testSecondFactorKey = testKey32("identity-auth-mfa-key-32-bytes--")

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
