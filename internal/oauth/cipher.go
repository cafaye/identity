// Package oauth is social sign-in: the providers, the CSRF state that guards the
// round trip, the code-for-token exchange, and the `connected_accounts` table
// that ties a provider's identifier to a user of this service.
//
// It is a cafaye concept rather than platform infrastructure, so it lives at
// internal/oauth rather than under internal/platform. What it deliberately does
// not contain is the decision about *which user* a callback resolves to: that is
// a use case, it sits in internal/auth alongside register and login, and this
// package knows nothing about sessions.
//
// # THE SOCIAL-LOGIN SURFACE IS NOT MOUNTED
//
// Read that before concluding the feature ships. Of everything in this package,
// only NewState and VerifyState are live — the OIDC login's round trip uses them.
// The rest is written and tested against a real database, and **no route, handler
// or use case reaches any of it**: there is no `/v1/auth/oauth`, no
// `internal/httpapi/oauth.go`, no `OAUTH_*` configuration variable, and
// `connected_accounts` is an applied migration nothing writes to. A product
// integrating "Continue with Google" against this service gets a 404.
//
// The gap is deliberate and the reasoning is in README.md's "Social login is not
// built, and the code that looks like it is". In short: the parts that are hard are
// done, and what is missing is a product decision about which user a callback
// resolves to, plus a cross-site browser surface this service does not have. Both
// are a packet of their own on the platform's security boundary.
//
// Two consequences for anyone working in here:
//
//   - The code is kept rather than deleted because it is correct, and because the
//     migration that backs it is applied and an applied migration is not edited.
//     What it must not be is *invisible*, which is why the package doc, the
//     README, `cafaye.yml` and TestTheSocialLoginSurfaceIsNotMounted all say the
//     same thing.
//   - AGENTS.md's "stubs stay honest" rule cuts the other way from the usual
//     reading of it: a tested-but-unwired method is called a lie, and the honest
//     state is "a paragraph in the README and no code". This package is the
//     exception, and it earns that by being recorded in four places rather than
//     one. Deleting it is the alternative, and it is a bigger intervention than
//     leaving it — so the decision is written down instead of defaulted.
package oauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Errors the cipher returns. Both are matched with errors.Is by internal/config,
// which turns them into a startup failure, and by the store's readers.
var (
	// ErrInvalidEncKey means the configured key is not 32 bytes. It is never
	// padded or truncated: an operator who pastes a 16-byte key has configured
	// half the entropy they think they have, and quietly stretching it would
	// hide that until the day it matters.
	ErrInvalidEncKey = errors.New("oauth encryption key must be 32 bytes")

	// ErrMalformedCiphertext means a stored value is not something this Cipher
	// wrote: no prefix, an unknown version, not base64, truncated, or sealed
	// under a different key. All of those are one failure at the call site —
	// there is no recovery that distinguishes them — so they are one error.
	ErrMalformedCiphertext = errors.New("oauth token ciphertext is malformed")
)

// SealPrefix marks the format version of a stored token.
//
// It is in the stored value rather than in the schema because the schema is a
// migration and a migration is not free to run again: a key rotation has to be
// able to read what the previous key wrote, and the version is what tells it
// which format it is looking at. A column named only after the current version
// cannot be rolled back to.
const SealPrefix = "v1."

// Cipher seals and opens the provider tokens this service holds for a connected
// account.
//
// AES-256-GCM: authenticated, so a value edited in the database fails to open
// rather than decrypting to something an attacker chose. The key never leaves
// this struct and is never written anywhere.
type Cipher struct {
	aead cipher.AEAD
}

// NewCipher returns a Cipher for a 32-byte AES-256 key.
//
// The key length is exact rather than "at least 16": a shorter key would be
// accepted by AES and silently weaken the guarantee that a database dump plus
// this column does not yield usable credentials.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidEncKey, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		// Unreachable for a 32-byte key; aes.NewCipher only rejects lengths the
		// check above already rejected. Wrapped rather than ignored so a future
		// AES change surfaces here instead of vanishing.
		return nil, fmt.Errorf("building the AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("building the GCM cipher: %w", err)
	}

	return &Cipher{aead: aead}, nil
}

// Seal encrypts plaintext and returns the value to store.
//
// The nonce is 12 bytes from crypto/rand on every call, which is what makes GCM's
// catastrophic failure — two messages under one nonce — a probabilistic event
// rather than a structural one. The cost is 12 bytes per row and a reseed-free
// key: a deterministic nonce would need a counter in the database, and a
// database counter that can be rolled back is exactly the state a nonce must not
// depend on.
func (c *Cipher) Seal(plaintext string) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		// As in internal/platform/id: a degraded entropy source is a condition to
		// stop on, not to produce credentials from.
		return "", fmt.Errorf("reading random bytes for the GCM nonce: %w", err)
	}

	sealed := c.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return SealPrefix + base64.RawURLEncoding.EncodeToString(sealed), nil
}

// Open decrypts a value produced by Seal.
//
// A failure here is always ErrMalformedCiphertext, including a value that
// decrypted under the wrong key. The caller cannot do anything useful with the
// distinction, and a caller that could — an operator rotating keys — wants to see
// the failure, not to have it silently succeed.
func (c *Cipher) Open(value string) (string, error) {
	if !strings.HasPrefix(value, SealPrefix) {
		return "", fmt.Errorf("%w: missing the %q prefix", ErrMalformedCiphertext, SealPrefix)
	}

	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, SealPrefix))
	if err != nil {
		return "", fmt.Errorf("%w: not base64url: %v", ErrMalformedCiphertext, err)
	}

	nonceSize := c.aead.NonceSize()
	if len(raw) < nonceSize+c.aead.Overhead() {
		// A nonce alone, or a nonce and a partial tag. GCM would reject these too;
		// checking first keeps the error ours rather than a panic-shaped surprise
		// from slicing below.
		return "", fmt.Errorf("%w: %d bytes is shorter than a nonce and a tag", ErrMalformedCiphertext, len(raw))
	}

	nonce, ciphertext := raw[:nonceSize], raw[nonceSize:]
	opened, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("%w: authentication failed", ErrMalformedCiphertext)
	}

	return string(opened), nil
}
