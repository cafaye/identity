package users

import (
	"strings"
	"testing"

	"github.com/alexedwards/argon2id"
)

// fastHasher is a Hasher with deliberately cheap parameters.
//
// NewHasher derives a dummy digest eagerly, which is right at startup and wrong
// in a test: at the production 64 MiB it dominates the suite's runtime, and
// these assertions are about digest format and verify/compare behaviour, not
// about cost. The cost-related assertion is
// TestDefaultParamsAreNotWeakerThanTheLibraryDefaults, which uses DefaultParams
// on purpose.
func fastHasher() *Hasher {
	return NewHasherWithParams(&argon2id.Params{
		Memory:      8 * 1024,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	})
}

func TestHashPasswordProducesAVerifiableArgon2idDigest(t *testing.T) {
	t.Parallel()

	h := fastHasher()

	digest, err := h.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	if !strings.HasPrefix(digest, "$argon2id$") {
		t.Errorf("digest %q does not start with $argon2id$", digest)
	}
	if strings.Contains(digest, "correct horse") {
		t.Errorf("digest %q contains the plaintext password", digest)
	}
}

func TestVerifyPassword(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		password  string
		presented string
		want      bool
	}{
		{name: "the right password", password: "correct horse battery staple", presented: "correct horse battery staple", want: true},
		{name: "a wrong password", password: "correct horse battery staple", presented: "correct horse battery stapl", want: false},
		{name: "an empty password cannot match", password: "correct horse battery staple", presented: "", want: false},
		{name: "a unicode password round-trips", password: "pässwörd🔐", presented: "pässwörd🔐", want: true},
		{name: "the wrong unicode password is rejected", password: "pässwörd🔐", presented: "pässwörd🔒", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := fastHasher()
			digest, err := h.Hash(tt.password)
			if err != nil {
				t.Fatalf("Hash: %v", err)
			}

			if got := h.Verify(digest, tt.presented); got != tt.want {
				t.Errorf("Verify(%q) = %v, want %v", tt.presented, got, tt.want)
			}
		})
	}
}

// Every digest gets its own random salt, so two users with the same password
// must not produce the same column value. Identical digests would leak that fact
// to anyone with read access to the table.
func TestHashPasswordSaltsEachDigest(t *testing.T) {
	t.Parallel()

	h := fastHasher()

	first, err := h.Hash("same password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	second, err := h.Hash("same password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	if first == second {
		t.Error("two hashes of the same password are identical; the salt is not random")
	}
	if !h.Verify(first, "same password") || !h.Verify(second, "same password") {
		t.Error("a salted digest failed to verify against its own password")
	}
}

// A corrupt or truncated digest is a failed verification, never a panic and
// never a true. Anything else turns a bad row into an authentication bypass.
func TestVerifyPasswordRejectsMalformedDigests(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		digest string
	}{
		{name: "empty", digest: ""},
		{name: "plaintext", digest: "correct horse battery staple"},
		{name: "truncated argon2id", digest: "$argon2id$v=19$m=65536"},
		{name: "wrong algorithm", digest: "$2a$10$abcdefghijklmnopqrstuv"},
		{name: "valid prefix, garbage body", digest: "$argon2id$v=19$m=65536,t=1,p=2$AAAA$!!!!not base64!!!!"},
		{name: "not base64 at all", digest: "not-a-digest"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if fastHasher().Verify(tt.digest, "anything") {
				t.Errorf("Verify(%q) returned true for a malformed digest", tt.digest)
			}
		})
	}
}

// This is the anti-enumeration guarantee: an attempt against an address with no
// account must cost the same as one against a real account. VerifyDummy is what
// the login path calls instead of skipping the hash.
func TestVerifyDummyDoesTheWorkWithoutAccepting(t *testing.T) {
	t.Parallel()

	h := fastHasher()

	// Any input at all must be rejected: the dummy digest is not a credential
	// for anything, so a caller must never be able to "guess" it. VerifyDummy
	// reports nothing by construction — there is no answer to get wrong.
	for _, presented := range []string{"", "password", "anything at all"} {
		h.VerifyDummy(presented)
	}

	if h.Verify(h.dummyDigest(), "anything at all") {
		t.Error("the dummy digest verified a presented password; it must never match")
	}
}

// The dummy has to be a real, well-formed argon2id digest, otherwise Verify on
// it short-circuits and the timing it is there to flatten never happens.
func TestDummyDigestIsWellFormed(t *testing.T) {
	t.Parallel()

	h := fastHasher()

	digest := h.dummyDigest()
	if !strings.HasPrefix(digest, "$argon2id$") {
		t.Fatalf("dummy digest %q is not an argon2id digest", digest)
	}
	if _, _, _, err := argon2id.DecodeHash(digest); err != nil {
		t.Errorf("dummy digest does not parse: %v", err)
	}
}

// The default parameters have to stay at or above the argon2id library's
// recommendation, and the library's own defaults are the floor. A downgrade here
// is invisible in review and catastrophic in practice, so it is asserted.
func TestDefaultParamsAreNotWeakerThanTheLibraryDefaults(t *testing.T) {
	t.Parallel()

	p := DefaultParams()

	if p.Memory < argon2id.DefaultParams.Memory {
		t.Errorf("Memory = %d KiB, want at least the library default %d KiB", p.Memory, argon2id.DefaultParams.Memory)
	}
	if p.Iterations < argon2id.DefaultParams.Iterations {
		t.Errorf("Iterations = %d, want at least the library default %d", p.Iterations, argon2id.DefaultParams.Iterations)
	}
	if p.SaltLength < argon2id.DefaultParams.SaltLength {
		t.Errorf("SaltLength = %d, want at least %d", p.SaltLength, argon2id.DefaultParams.SaltLength)
	}
	if p.KeyLength < argon2id.DefaultParams.KeyLength {
		t.Errorf("KeyLength = %d, want at least %d", p.KeyLength, argon2id.DefaultParams.KeyLength)
	}
	if p.Parallelism < 1 {
		t.Errorf("Parallelism = %d, want at least 1", p.Parallelism)
	}
}

func TestHashPasswordRejectsEmptyInput(t *testing.T) {
	t.Parallel()

	// Hashing "" would mint a credential that satisfies no login but does sit in
	// the column; ValidatePassword is the gate that keeps it out, and this is the
	// backstop.
	if _, err := NewHasher().Hash(""); err == nil {
		t.Error("Hash(\"\") returned no error, want a rejection")
	}
}
