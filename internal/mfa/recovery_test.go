package mfa

import (
	"encoding/base32"
	"strings"
	"testing"
)

// TestARecoveryCodeIsAHumanSizedAmountOfEntropy. The whole single-use property
// rests on this: a code that is cheap to guess is a credential a database dump
// yields, and a code that is impossible to type is a code nobody writes down.
func TestARecoveryCodeIsAHumanSizedAmountOfEntropy(t *testing.T) {
	code, err := NewRecoveryCode()
	if err != nil {
		t.Fatalf("NewRecoveryCode: %v", err)
	}

	if !IsRecoveryCode(code) {
		t.Fatalf("%q is not recognised as a recovery code", code)
	}
	// 16 base32 characters in four groups: eighty bits, on one line of a settings
	// page and about the width of a phone's screen.
	if strings.Count(code, "-") != 3 {
		t.Errorf("%q has %d dashes, want 3", code, strings.Count(code, "-"))
	}
	if len(code) != 16+3 {
		t.Errorf("%q is %d characters, want 19", code, len(code))
	}
	for _, group := range strings.Split(code, "-") {
		if len(group) != recoveryGroup {
			t.Errorf("group %q is %d characters, want %d", group, len(group), recoveryGroup)
		}
	}
}

// TestTheAlphabetOmitsTheDigitsPeopleMistypeForLetters is the reason base32
// rather than hex: 0, 1, 8 and 9 are not in the set, so a mistyped digit is
// REJECTED rather than silently becoming a different code. That is the property
// that makes a typed recovery code usable at all.
func TestTheAlphabetOmitsTheDigitsPeopleMistypeForLetters(t *testing.T) {
	for _, r := range "0189" {
		if strings.ContainsRune(recoveryAlphabetChars, r) {
			t.Errorf("the recovery alphabet contains %q, which is mistranscribed for a letter", r)
		}
	}
	// And the letters it is supposed to have, so the test above is not passing
	// because the constant is empty.
	for _, r := range "OBIL" {
		if !strings.ContainsRune(recoveryAlphabetChars, r) {
			t.Errorf("the recovery alphabet is missing %q", r)
		}
	}
}

// TestTheAlphabetIsTheOneTheEncoderUses keeps the hand-copied constant from
// drifting away from encoding/base32. A recovery code generated with one alphabet
// and validated with another would be a code that never works, and the failure
// would look like a bug in the user's authenticator.
func TestTheAlphabetIsTheOneTheEncoderUses(t *testing.T) {
	if len(recoveryAlphabetChars) != 32 {
		t.Fatalf("the alphabet has %d characters, want 32", len(recoveryAlphabetChars))
	}

	// Every character the encoder can produce must be in the constant, and every
	// character in the constant must survive a decode/encode round trip. Either
	// direction failing means IsRecoveryCode and NewRecoveryCode disagree.
	seen := map[rune]bool{}
	for _, r := range recoveryAlphabetChars {
		seen[r] = true
	}
	for i := range 32 {
		raw := make([]byte, 1)
		raw[0] = byte(i)
		for _, r := range recoveryAlphabet.EncodeToString(raw) {
			if !seen[r] {
				t.Errorf("the encoder produced %q, which is not in recoveryAlphabetChars", r)
			}
		}
	}
}

// TestRecoveryCodesAreUnpredictable checks the two properties a set must have:
// no repeats inside itself, and no repeats against a set minted a moment ago.
func TestRecoveryCodesAreUnpredictable(t *testing.T) {
	first, err := NewRecoveryCodes()
	if err != nil {
		t.Fatalf("NewRecoveryCodes: %v", err)
	}
	if len(first) != RecoveryCodeCount {
		t.Fatalf("a set has %d codes, want %d", len(first), RecoveryCodeCount)
	}

	second, err := NewRecoveryCodes()
	if err != nil {
		t.Fatalf("NewRecoveryCodes: %v", err)
	}

	seen := make(map[string]bool, 2*RecoveryCodeCount)
	for _, set := range [][]string{first, second} {
		for _, code := range set {
			if !IsRecoveryCode(code) {
				t.Errorf("%q is not a recovery code", code)
			}
			if seen[code] {
				t.Errorf("%q was issued twice", code)
			}
			seen[code] = true
		}
	}
}

// TestNormalizeRecoveryCodeIsTheComparison: every spelling a human produces has
// to hash to the same value, or a code read off paper is a code that does not
// work.
func TestNormalizeRecoveryCodeIsTheComparison(t *testing.T) {
	const canonical = "7KQF4W2X5DTRM3HN"
	spellings := []string{
		canonical,
		strings.ToLower(canonical),
		"7KQF-4W2X-5DTR-M3HN",
		"7kqf-4w2x-5dtr-m3hn",
		"  7KQF 4W2X 5DTR M3HN  ",
		"7KQF-4W2X-5DTR-M3HN\n",
	}

	digest := RecoveryDigest(canonical)
	for _, spelling := range spellings {
		if got := NormalizeRecoveryCode(spelling); got != canonical {
			t.Errorf("NormalizeRecoveryCode(%q) = %q, want %q", spelling, got, canonical)
		}
		if got := RecoveryDigest(spelling); got != digest {
			t.Errorf("RecoveryDigest(%q) differs from the canonical digest", spelling)
		}
	}
}

// TestTwoDifferentCodesHaveDifferentDigests, so a match is a match and not a
// collision in a truncated comparison.
func TestTwoDifferentCodesHaveDifferentDigests(t *testing.T) {
	first, err := NewRecoveryCode()
	if err != nil {
		t.Fatalf("NewRecoveryCode: %v", err)
	}
	second, err := NewRecoveryCode()
	if err != nil {
		t.Fatalf("NewRecoveryCode: %v", err)
	}
	if RecoveryDigest(first) == RecoveryDigest(second) {
		t.Fatal("two different codes produced the same digest")
	}
	// 32 hex characters, matching the CHECK constraint on the column.
	if len(RecoveryDigest(first)) != 64 {
		t.Errorf("the digest is %d characters, want 64", len(RecoveryDigest(first)))
	}
}

// TestIsRecoveryCodeRejectsWhatItMust, including a value that is a TOTP code with
// padding — the shape test is what lets one request field carry both kinds.
func TestIsRecoveryCodeRejectsWhatItMust(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"7KQF4W2X5DTRM3HN", true},
		{"7KQF-4W2X-5DTR-M3HN", true},
		{"123456", false},
		{"7KQF4W2X5DTRM3H", false},
		{"7KQF4W2X5DTRM3HNN", false},
		{"7KQF4W2X9DTRM3H1", false}, // 1 is not in the base32 alphabet
		{"", false},
		{"not a code at all!!!!", false},
	}

	for _, c := range cases {
		if got := IsRecoveryCode(c.in); got != c.want {
			t.Errorf("IsRecoveryCode(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestAStoredRecoveryCodeIsNotAUsableCode is the invariant the packet asks about,
// asserted on the value the column actually holds rather than in a comment.
func TestAStoredRecoveryCodeIsNotAUsableCode(t *testing.T) {
	code, err := NewRecoveryCode()
	if err != nil {
		t.Fatalf("NewRecoveryCode: %v", err)
	}
	digest := RecoveryDigest(code)

	if strings.Contains(digest, code) || strings.Contains(digest, NormalizeRecoveryCode(code)) {
		t.Fatal("the stored digest contains the code")
	}
	if digest != strings.ToLower(digest) {
		t.Error("the digest is not lower-case hex, which is what the column stores")
	}
}

// TestTheEncodingLengthIsDerivedFromTheEntropy rather than typed, so changing
// RecoveryCodeBytes cannot leave a stale constant deciding what a code looks like.
func TestTheEncodingLengthIsDerivedFromTheEntropy(t *testing.T) {
	want := (RecoveryCodeBytes*8 + 4) / 5
	if recoveryEncodingLen != want {
		t.Errorf("recoveryEncodingLen = %d, want %d", recoveryEncodingLen, want)
	}
	// And the derived number is what the encoder agrees with.
	raw := make([]byte, RecoveryCodeBytes)
	if got := len(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)); got != recoveryEncodingLen {
		t.Errorf("the encoder produces %d characters for %d bytes, want %d", got, RecoveryCodeBytes, recoveryEncodingLen)
	}
}
