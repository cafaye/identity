package mfa

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// The recovery codes, and why they are shaped the way they are.
//
// A recovery code is the worst credential in this system and it is still
// preferable to the alternative, which is a locked-out user. It has 80 bits of
// entropy, it is typed into a form, and it is very likely to end up written on
// paper. Every design choice below follows from those three facts.
//
// THE SHAPE: 16 base32 characters in four groups of four, separated by dashes.
//
//	7KQF-4W2X-9DTR-M3HN
//
// Base32 rather than hex, because base32 is 20% more compact at the same
// entropy: 80 bits is 20 hex characters or 16 base32 ones, and a code a user has
// to retype is a code they will mistype. It is encoding/base32 from the standard
// library and not a hand-rolled alphabet — the packet forbids reimplementing
// base32, and the reason is the same one that put pquerna/otp in go.mod: this is
// a specification, and a private implementation of a specification is a
// vulnerability with tests.
//
// Grouped, because a 16-character unbroken string is mistyped at a
// rate that shows up as "my code does not work" support tickets, and a human
// reading a code back over the phone needs somewhere to pause.
//
// The alphabet is the RFC 4648 base32 alphabet — A-Z and 2-7 — and the four
// digits it omits are the whole reason for using it rather than hex. 0, 1, 8 and
// 9 are not in the set, which means the four transcription confusions that
// actually happen with typed codes — 0 for O, 1 for I, 1 for l, 8 for B — cannot
// occur at all. A mistyped digit is REJECTED, loudly, instead of being silently
// accepted as a different code, and a user who is told their code is wrong can
// try again rather than wondering which character went missing.
//
// The case confusions that remain are resolved by the uppercase normalisation in
// NormalizeRecoveryCode rather than by choosing a different alphabet: a user with
// Caps Lock off types a lower-case L and gets an upper-case L, which is the
// character they meant.

// recoveryAlphabet is RFC 4648 base32 without padding, which is the same encoding
// an authenticator app uses for a TOTP secret. Reusing it means one decoder in
// this package and one thing to get right.
var recoveryAlphabet = base32.StdEncoding.WithPadding(base32.NoPadding)

// recoveryGroup is how many characters sit between dashes.
const recoveryGroup = 4

// NewRecoveryCodes mints a full set.
//
// The set is returned once and never again: there is no endpoint that re-reads
// it, and the table holds a digest per code. The reasoning is the one
// internal/oidc/service.go states for a client secret and it applies verbatim —
// a secret this service can produce again is a secret this service is storing,
// and the only safe way to show ten of them is to show them exactly once.
//
// A failure of crypto/rand is returned, not worked around. A recovery set with a
// predictable code in it is a way into an account, and it is discovered by the
// user rather than by the service.
func NewRecoveryCodes() ([]string, error) {
	codes := make([]string, 0, RecoveryCodeCount)
	for i := 0; i < RecoveryCodeCount; i++ {
		code, err := NewRecoveryCode()
		if err != nil {
			return nil, err
		}
		codes = append(codes, code)
	}
	return codes, nil
}

// NewRecoveryCode mints one recovery code in its display form.
func NewRecoveryCode() (string, error) {
	raw := make([]byte, RecoveryCodeBytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		// As in internal/platform/id and internal/sessions: a degraded entropy
		// source is a condition to stop on, not something to produce a credential
		// from.
		return "", fmt.Errorf("mfa: reading random bytes for a recovery code: %w", err)
	}
	return formatRecoveryCode(recoveryAlphabet.EncodeToString(raw)), nil
}

// formatRecoveryCode adds the dashes.
func formatRecoveryCode(joined string) string {
	var b strings.Builder
	for i, r := range joined {
		if i > 0 && i%recoveryGroup == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// NormalizeRecoveryCode is the form that gets hashed, and the form two spellings
// of the same code have to agree on.
//
// Upper case, no dashes, no spaces. A user reading a code off a piece of paper
// writes a space where the dash is, or types the whole thing in lower case
// because their keyboard was set that way, or transcribes "O" for "0" — and
// none of those is a different code. Everything a human types goes through here
// before it is compared, and the comparison is against a value that has been
// stored in this same normalised form, so the two sides cannot disagree about
// spelling.
func NormalizeRecoveryCode(code string) string {
	stripped := strings.Map(func(r rune) rune {
		switch r {
		case '-', ' ', '\t', '\n':
			return -1
		}
		return r
	}, strings.ToUpper(strings.TrimSpace(code)))
	return stripped
}

// IsRecoveryCode reports whether a presented value could be a recovery code.
//
// The length is the whole test, and it is enough: 16 base32 characters is 80
// bits, and no other value in this service is that shape. A code is checked for
// shape BEFORE any query runs, so a value that is neither six digits nor sixteen
// base32 characters costs one comparison and no database round trip.
func IsRecoveryCode(value string) bool {
	normalized := NormalizeRecoveryCode(value)
	if len(normalized) != recoveryEncodingLen {
		return false
	}
	for _, r := range normalized {
		if !strings.ContainsRune(recoveryAlphabetChars, r) {
			return false
		}
	}
	return true
}

// recoveryEncodingLen is the length of RecoveryCodeBytes in base32, computed
// rather than typed so RecoveryCodeBytes and this cannot drift.
var recoveryEncodingLen = (RecoveryCodeBytes*8 + 4) / 5

// recoveryAlphabetChars is the RFC 4648 §6 alphabet, upper case, which is the one
// recoveryAlphabet encodes with. It is spelled out so IsRecoveryCode has
// something to test membership against, and
// TestRecoveryAlphabetIsTheOneTheEncoderUses is what keeps the two from drifting:
// a hand-copied alphabet next to an encoder is a hand-copied alphabet.
const recoveryAlphabetChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

// RecoveryDigest is the value stored in mfa_recovery_codes.code_digest.
//
// SHA-256 and not argon2id, for the reason sessions.Digest gives and the reason
// is the same: a recovery code is 80 bits of crypto/rand output with no structure
// to guess, so a memory-hard hash would buy nothing that the entropy has not
// already bought, and would cost tens of milliseconds on every sign-in that
// reaches for it. Argon2id exists to make GUESSING expensive, and there is
// nothing here to guess.
//
// The invariant both columns share is the one that matters: the presented value
// is never stored, so a dump of this table is not a set of credentials.
func RecoveryDigest(code string) string {
	sum := sha256.Sum256([]byte(NormalizeRecoveryCode(code)))
	return hex.EncodeToString(sum[:])
}
