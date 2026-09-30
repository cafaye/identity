package mfa

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
)

// The library's own values, named once so the tests read against the same
// constants the production code passes.
var (
	six  = otp.DigitsSix
	sha1 = otp.AlgorithmSHA1
)

// A key for the vault tests. It is a constant so two runs produce the same
// ciphertext, which is what lets a test assert a specific value is stable — and it
// is not a secret, it is a test fixture.
var testKey = []byte("0123456789abcdef0123456789abcdef")

func TestVaultRoundTripsASecret(t *testing.T) {
	vault, err := NewAESCipher(testKey)
	if err != nil {
		t.Fatalf("NewAESCipher: %v", err)
	}
	user := mustUUID(t, "6f1a3f2e-0000-4000-8000-000000000001")

	sealed, err := vault.Seal(user, rawKey)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if strings.Contains(sealed, rawKey) {
		t.Fatal("the sealed value contains the secret in the clear")
	}
	if !strings.HasPrefix(sealed, SealPrefix) {
		t.Errorf("the sealed value has no version prefix: %q", sealed)
	}

	opened, err := vault.Open(user, sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if opened != rawKey {
		t.Errorf("Open = %q, want %q", opened, rawKey)
	}
}

// TestTheSameSecretSealsDifferentlyEveryTime. A deterministic nonce would mean
// two rows for the same user hold byte-identical ciphertext, which tells a reader
// of the database that two users chose the same secret — and GCM under one nonce
// is a catastrophic failure rather than a curiosity.
func TestTheSameSecretSealsDifferentlyEveryTime(t *testing.T) {
	vault, err := NewAESCipher(testKey)
	if err != nil {
		t.Fatalf("NewAESCipher: %v", err)
	}
	user := mustUUID(t, "6f1a3f2e-0000-4000-8000-000000000001")

	first, err := vault.Seal(user, rawKey)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	second, err := vault.Seal(user, rawKey)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if first == second {
		t.Error("two seals of the same secret produced identical ciphertext")
	}
}

// TestASealedSecretCannotBeMovedBetweenUsers is what the AAD buys, and it is a
// real attack: an attacker with write access to the mfa_credentials table copies
// their own sealed secret onto a victim's row and then presents codes for a secret
// they already hold. Without per-user AAD the copy decrypts.
func TestASealedSecretCannotBeMovedBetweenUsers(t *testing.T) {
	vault, err := NewAESCipher(testKey)
	if err != nil {
		t.Fatalf("NewAESCipher: %v", err)
	}
	attacker := mustUUID(t, "6f1a3f2e-0000-4000-8000-0000000000aa")
	victim := mustUUID(t, "6f1a3f2e-0000-4000-8000-0000000000bb")

	sealed, err := vault.Seal(attacker, rawKey)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := vault.Open(victim, sealed); !errors.Is(err, ErrMalformedSeal) {
		t.Errorf("Open for the wrong user = %v, want ErrMalformedSeal", err)
	}
}

// TestASecretSealedUnderAnotherKeyDoesNotOpen. This is the key-rotation path: a
// deployment that pastes the wrong MFA_ENCRYPTION_KEY must fail every
// verification loudly rather than every verification silently passing.
func TestASecretSealedUnderAnotherKeyDoesNotOpen(t *testing.T) {
	first, err := NewAESCipher(testKey)
	if err != nil {
		t.Fatalf("NewAESCipher: %v", err)
	}
	other, err := NewAESCipher([]byte("fedcba9876543210fedcba9876543210"))
	if err != nil {
		t.Fatalf("NewAESCipher: %v", err)
	}
	user := mustUUID(t, "6f1a3f2e-0000-4000-8000-000000000001")

	sealed, err := first.Seal(user, rawKey)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := other.Open(user, sealed); !errors.Is(err, ErrMalformedSeal) {
		t.Errorf("Open under the wrong key = %v, want ErrMalformedSeal", err)
	}
}

// TestAVaultRefusesAnEditedCiphertext rather than decrypting it to something an
// attacker chose. GCM is authenticated, so a flipped bit must be a failure.
func TestAVaultRefusesAnEditedCiphertext(t *testing.T) {
	vault, err := NewAESCipher(testKey)
	if err != nil {
		t.Fatalf("NewAESCipher: %v", err)
	}
	user := mustUUID(t, "6f1a3f2e-0000-4000-8000-000000000001")

	sealed, err := vault.Seal(user, rawKey)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	edited := []byte(sealed)
	edited[len(edited)-2] ^= 'A' ^ 'B'

	if _, err := vault.Open(user, string(edited)); !errors.Is(err, ErrMalformedSeal) {
		t.Errorf("Open of an edited value = %v, want ErrMalformedSeal", err)
	}
}

// TestTheKeyLengthIsExact. A 16-byte key is accepted by AES and would halve the
// guarantee, so it has to be refused rather than stretched.
func TestTheKeyLengthIsExact(t *testing.T) {
	for _, size := range []int{0, 1, 16, 24, 31, 33, 64} {
		if _, err := NewAESCipher(make([]byte, size)); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("NewAESCipher(%d bytes) = %v, want ErrInvalidKey", size, err)
		}
	}
}

// TestUnavailableVaultFailsClosed is the deployment with no MFA_ENCRYPTION_KEY.
//
// Both directions must be ErrNoVault. The Seal direction stops a process with no
// key from storing something it could never read back; the Open direction is the
// one that matters, because it is the difference between refusing an enrolled
// user and waving them in on their password.
func TestUnavailableVaultFailsClosed(t *testing.T) {
	var vault Vault = Unavailable{}
	user := mustUUID(t, "6f1a3f2e-0000-4000-8000-000000000001")

	if _, err := vault.Seal(user, rawKey); !errors.Is(err, ErrNoVault) {
		t.Errorf("Seal = %v, want ErrNoVault", err)
	}
	if _, err := vault.Open(user, "whatever"); !errors.Is(err, ErrNoVault) {
		t.Errorf("Open = %v, want ErrNoVault", err)
	}
}

// TestTheVaultIsNotTheOAuthOne is a cheap guard against a future merge of the two
// ciphertext formats. internal/oauth seals provider tokens under a "v1." prefix
// and no AAD; if that prefix ever appeared here, a token could be pasted into a
// credential column.
func TestTheVaultIsNotTheOAuthOne(t *testing.T) {
	if strings.HasPrefix(SealPrefix, "v1.") {
		t.Error("the mfa seal prefix collides with internal/oauth's")
	}
}

// TestHotpOptionsRejectsWhatTheSchemaForbids. The CHECK constraints in the
// migration make these values unwritable, so reaching here means a row was written
// by something other than this service — and the answer has to be a refusal.
func TestHotpOptionsRejectsWhatTheSchemaForbids(t *testing.T) {
	if _, err := hotpOptions(DigitEight, AlgorithmSHA1); err != nil {
		t.Errorf("eight digits should be verifiable: %v", err)
	}
	for _, c := range []struct{ digits, algorithm string }{
		{"7", AlgorithmSHA1},
		{"0", AlgorithmSHA1},
		{"", AlgorithmSHA1},
		{DigitSix, "SHA256"},
		{DigitSix, ""},
	} {
		if _, err := hotpOptions(c.digits, c.algorithm); err == nil {
			t.Errorf("hotpOptions(%q, %q) accepted a value the schema forbids", c.digits, c.algorithm)
		}
	}
}

// TestTotpCodeGeneratesTheCodeForAnInstant, which is what every test fixture in
// this package and in internal/httpapi uses to act as an authenticator.
func TestTotpCodeGeneratesTheCodeForAnInstant(t *testing.T) {
	got, err := Code(rawKey, at)
	if err != nil {
		t.Fatalf("Code: %v", err)
	}
	if !isTOTPCode(got) {
		t.Errorf("Code produced %q, which is not a six-digit code", got)
	}
	if got != codeFor(t, rawKey, stepBase) {
		t.Errorf("Code = %q, want %q", got, codeFor(t, rawKey, stepBase))
	}
	if _, err := Code(rawKey, time.Unix(-60, 0)); err == nil {
		t.Error("Code accepted a pre-epoch instant")
	}
	if _, err := totpCode(rawKey, at, "7", AlgorithmSHA1, Period); err == nil {
		t.Error("totpCode accepted a digit count the schema forbids")
	}
}
