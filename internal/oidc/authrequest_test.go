package oidc

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/platform/id"
)

// The authorization request and its code: the two statements the token endpoint
// depends on, tested against the database because the properties being asserted
// are properties of the SQL.

// newAuthRequest records a request for a client, ready to be completed by the
// login UI.
func (f storeFixture) newAuthRequest(t *testing.T, client Client, expiresAt time.Time) AuthRequest {
	t.Helper()

	request, err := f.store.CreateAuthRequest(f.ctx, f.q(), NewAuthRequest{
		ClientRowID:         client.ID,
		RedirectURI:         "https://app.example.com/cb",
		State:               "state-abc",
		Nonce:               "nonce-abc",
		ResponseType:        "code",
		ResponseMode:        "",
		Scopes:              []string{"accounts", "email", "openid"},
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		LoginHint:           "someone@example.com",
		CreatedAt:           storeTestNow,
		ExpiresAt:           expiresAt,
	})
	if err != nil {
		t.Fatalf("CreateAuthRequest: %v", err)
	}
	return request
}

func TestStoreAuthRequestRoundTrip(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)
	client := f.mustCreateClient(t, f.account, f.owner)
	request := f.newAuthRequest(t, client, storeTestNow.Add(AuthRequestTTL))

	if request.Subject != nil || request.AuthTime != nil {
		t.Error("a fresh request already has a subject; the user has not logged in yet")
	}
	if request.ClientID != client.ClientID {
		t.Errorf("the request carries client_id %q, want %q", request.ClientID, client.ClientID)
	}
	if request.ClientName != "Anytalk" {
		t.Errorf("the login page would show %q, want the registration's name", request.ClientName)
	}

	loaded, err := f.store.AuthRequestByID(f.ctx, f.q(), request.ID, storeTestNow)
	if err != nil {
		t.Fatalf("AuthRequestByID: %v", err)
	}
	if loaded.RedirectURI != request.RedirectURI {
		t.Errorf("redirect_uri = %q, want %q", loaded.RedirectURI, request.RedirectURI)
	}
	if loaded.CodeChallenge != request.CodeChallenge {
		t.Error("the code challenge did not survive the round trip")
	}
}

func TestStoreAuthRequestRefusesAnExpiredOne(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)
	client := f.mustCreateClient(t, f.account, f.owner)

	// An hour old, so the row is written already expired. The read below is
	// against the injected instant rather than the server's, which is what makes
	// "expired" a fact about this test rather than about what time it is.
	created, err := f.store.CreateAuthRequest(f.ctx, f.q(), NewAuthRequest{
		ClientRowID:         client.ID,
		RedirectURI:         "https://app.example.com/cb",
		State:               "state-abc",
		Nonce:               "nonce-abc",
		ResponseType:        "code",
		Scopes:              []string{"openid"},
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		CreatedAt:           storeTestNow.Add(-time.Hour),
		ExpiresAt:           storeTestNow.Add(-time.Second),
	})
	if err != nil {
		t.Fatalf("CreateAuthRequest: %v", err)
	}

	// The same error as "never existed", and the reason is the message: an id
	// that arrived in a URL is not something a probe should be able to classify.
	if _, err := f.store.AuthRequestByID(f.ctx, f.q(), created.ID, storeTestNow); !errors.Is(err, ErrAuthRequestNotFound) {
		t.Errorf("AuthRequestByID on an expired request = %v, want ErrAuthRequestNotFound", err)
	}
	if _, err := f.store.AuthRequestByID(f.ctx, f.q(), id.MustNew(), storeTestNow); !errors.Is(err, ErrAuthRequestNotFound) {
		t.Errorf("AuthRequestByID on an unknown id = %v, want ErrAuthRequestNotFound", err)
	}
}

func TestStoreCompleteAuthRequestIsOnceOnly(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)
	client := f.mustCreateClient(t, f.account, f.owner)
	request := f.newAuthRequest(t, client, storeTestNow.Add(AuthRequestTTL))
	_, other := f.seedAccount(t, "completer")

	if err := f.store.CompleteAuthRequest(f.ctx, f.q(), request.ID, f.owner, storeTestNow); err != nil {
		t.Fatalf("CompleteAuthRequest: %v", err)
	}

	loaded, err := f.store.AuthRequestByID(f.ctx, f.q(), request.ID, storeTestNow)
	if err != nil {
		t.Fatalf("AuthRequestByID: %v", err)
	}
	if loaded.Subject == nil || *loaded.Subject != f.owner {
		t.Errorf("subject = %v, want %s", loaded.Subject, f.owner)
	}
	if loaded.AuthTime == nil || !loaded.AuthTime.Equal(storeTestNow) {
		t.Errorf("auth_time = %v, want the injected instant", loaded.AuthTime)
	}

	// A second login submission for the same request must not re-point it at
	// somebody else: the row the redirect is built from would then name a
	// different user than the one who authenticated.
	if err := f.store.CompleteAuthRequest(f.ctx, f.q(), request.ID, other, storeTestNow.Add(time.Minute)); !errors.Is(err, ErrAuthRequestNotFound) {
		t.Errorf("the second CompleteAuthRequest = %v, want a refusal", err)
	}
	after, err := f.store.AuthRequestByID(f.ctx, f.q(), request.ID, storeTestNow)
	if err != nil {
		t.Fatalf("AuthRequestByID: %v", err)
	}
	if *after.Subject != f.owner {
		t.Error("a second completion re-pointed the request at another user")
	}
}

func TestStoreAuthCodeIsRedeemableExactlyOnce(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)
	client := f.mustCreateClient(t, f.account, f.owner)
	request := f.newAuthRequest(t, client, storeTestNow.Add(AuthRequestTTL))

	if err := f.store.CompleteAuthRequest(f.ctx, f.q(), request.ID, f.owner, storeTestNow); err != nil {
		t.Fatalf("CompleteAuthRequest: %v", err)
	}
	if err := f.store.SaveAuthCode(f.ctx, f.q(), request.ID, SecretDigest("the-code"), storeTestNow.Add(time.Minute)); err != nil {
		t.Fatalf("SaveAuthCode: %v", err)
	}

	redeemed, err := f.store.ConsumeAuthCode(f.ctx, f.q(), SecretDigest("the-code"), storeTestNow.Add(30*time.Second))
	if err != nil {
		t.Fatalf("ConsumeAuthCode: %v", err)
	}
	if redeemed.ID != request.ID {
		t.Errorf("redeemed request %s, want %s", redeemed.ID, request.ID)
	}
	// The request has to come back whole: the token endpoint still needs the
	// scopes, the redirect URI and the code challenge after the code is spent.
	if redeemed.RedirectURI != request.RedirectURI || redeemed.CodeChallenge != request.CodeChallenge {
		t.Error("the redeemed request lost the fields the token exchange needs")
	}
	if len(redeemed.Scopes) != len(request.Scopes) {
		t.Errorf("scopes = %v, want %v", redeemed.Scopes, request.Scopes)
	}

	if _, err := f.store.ConsumeAuthCode(f.ctx, f.q(), SecretDigest("the-code"), storeTestNow.Add(31*time.Second)); !errors.Is(err, ErrNoAuthCode) {
		t.Errorf("the second ConsumeAuthCode = %v, want ErrNoAuthCode", err)
	}
	if _, err := f.store.ConsumeAuthCode(f.ctx, f.q(), SecretDigest("never-issued"), storeTestNow); !errors.Is(err, ErrNoAuthCode) {
		t.Errorf("ConsumeAuthCode for an unknown code = %v, want ErrNoAuthCode", err)
	}
}

// An expired code is not redeemable, and the answer is the same as for a code
// that was never issued. Both are ErrNoAuthCode on purpose: see that error.
func TestStoreExpiredAuthCodeIsNotRedeemable(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)
	client := f.mustCreateClient(t, f.account, f.owner)
	request := f.newAuthRequest(t, client, storeTestNow.Add(AuthRequestTTL))

	if err := f.store.SaveAuthCode(f.ctx, f.q(), request.ID, SecretDigest("the-code"), storeTestNow.Add(time.Minute)); err != nil {
		t.Fatalf("SaveAuthCode: %v", err)
	}

	if _, err := f.store.ConsumeAuthCode(f.ctx, f.q(), SecretDigest("the-code"), storeTestNow.Add(2*time.Minute)); !errors.Is(err, ErrNoAuthCode) {
		t.Errorf("ConsumeAuthCode after expiry = %v, want ErrNoAuthCode", err)
	}
}

// The gate is a single conditional UPDATE, and this is the assertion that says
// so: two redemptions racing on the same code produce exactly one winner, and it
// is the UPDATE that decides rather than a read that both of them passed.
//
// The assertion is on the COUNT of successes, not on which goroutine won, so it
// holds for every interleaving. There is no sleep and no retry: a barrier puts
// both goroutines in front of the statement at the same time, and the database
// serialises them.
func TestStoreAuthCodeCannotBeRedeemedTwiceConcurrently(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)
	client := f.mustCreateClient(t, f.account, f.owner)
	request := f.newAuthRequest(t, client, storeTestNow.Add(AuthRequestTTL))
	if err := f.store.SaveAuthCode(f.ctx, f.q(), request.ID, SecretDigest("the-code"), storeTestNow.Add(time.Minute)); err != nil {
		t.Fatalf("SaveAuthCode: %v", err)
	}

	const racers = 8
	var (
		start     sync.WaitGroup
		done      sync.WaitGroup
		mu        sync.Mutex
		succeeded int
	)
	start.Add(1)
	for i := 0; i < racers; i++ {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			_, err := f.store.ConsumeAuthCode(f.ctx, f.q(), SecretDigest("the-code"), storeTestNow.Add(30*time.Second))
			if err == nil {
				mu.Lock()
				succeeded++
				mu.Unlock()
			}
		}()
	}
	start.Done()
	done.Wait()

	if succeeded != 1 {
		t.Errorf("%d of %d concurrent redemptions succeeded, want exactly 1", succeeded, racers)
	}
}

// Two codes on one request is a state the token endpoint could not reason about,
// so the second SaveAuthCode is refused rather than overwriting the first.
func TestStoreSaveAuthCodeRefusesASecond(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)
	client := f.mustCreateClient(t, f.account, f.owner)
	request := f.newAuthRequest(t, client, storeTestNow.Add(AuthRequestTTL))

	if err := f.store.SaveAuthCode(f.ctx, f.q(), request.ID, SecretDigest("first"), storeTestNow.Add(time.Minute)); err != nil {
		t.Fatalf("the first SaveAuthCode: %v", err)
	}
	if err := f.store.SaveAuthCode(f.ctx, f.q(), request.ID, SecretDigest("second"), storeTestNow.Add(time.Minute)); !errors.Is(err, ErrNoAuthCode) {
		t.Errorf("the second SaveAuthCode = %v, want ErrNoAuthCode", err)
	}
	// The first code is the one that still works.
	if _, err := f.store.ConsumeAuthCode(f.ctx, f.q(), SecretDigest("first"), storeTestNow); err != nil {
		t.Errorf("the first code is not redeemable: %v", err)
	}
}

// The CHECK on the column is the reason a request with `plain` cannot exist, so
// this test is about the database rather than about the handler that refuses it.
func TestStoreRefusesAPlainCodeChallenge(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)
	client := f.mustCreateClient(t, f.account, f.owner)

	_, err := f.store.CreateAuthRequest(f.ctx, f.q(), NewAuthRequest{
		ClientRowID:         client.ID,
		RedirectURI:         "https://app.example.com/cb",
		State:               "state-abc",
		Nonce:               "nonce-abc",
		ResponseType:        "code",
		Scopes:              []string{"openid"},
		CodeChallenge:       "plain-verifier",
		CodeChallengeMethod: "plain",
		CreatedAt:           storeTestNow,
		ExpiresAt:           storeTestNow.Add(AuthRequestTTL),
	})
	if err == nil {
		t.Fatal("CreateAuthRequest accepted code_challenge_method plain")
	}
}

// Deleting a request is idempotent, because ConsumeAuthCode has already taken the
// code out of circulation and the library tidies up straight afterwards. A
// DELETE that reported "no rows" as an error would turn every token exchange
// into a 500.
func TestStoreDeleteAuthRequestIsIdempotent(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)
	client := f.mustCreateClient(t, f.account, f.owner)
	request := f.newAuthRequest(t, client, storeTestNow.Add(AuthRequestTTL))

	if err := f.store.DeleteAuthRequest(f.ctx, f.q(), request.ID); err != nil {
		t.Fatalf("the first DeleteAuthRequest: %v", err)
	}
	if err := f.store.DeleteAuthRequest(f.ctx, f.q(), request.ID); err != nil {
		t.Errorf("the second DeleteAuthRequest = %v, want nil", err)
	}
	if _, err := f.store.AuthRequestByID(f.ctx, f.q(), request.ID, storeTestNow); !errors.Is(err, ErrAuthRequestNotFound) {
		t.Errorf("AuthRequestByID after a delete = %v, want ErrAuthRequestNotFound", err)
	}
}
