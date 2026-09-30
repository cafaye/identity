// Package oidc is identity's OpenID Connect provider: the discovery document,
// the authorization-code flow, the JWKS, the userinfo endpoint, and the
// registrations that decide who may use all three.
//
// The protocol is not reimplemented here. github.com/zitadel/oidc owns the
// OAuth 2.0 and OIDC state machines — parsing, redirect-URI validation, PKCE
// verification, the token response, the id_token — and this package supplies the
// two things a library cannot have: a storage implementation over this service's
// own tables, and a login UI bound to this service's own sessions. The rule
// this package exists to hold is the one that decides where a line goes: an
// OIDC concept belongs here, an infrastructure concern belongs in
// internal/platform, and every protocol decision the library already makes is
// delegated rather than restated.
package oidc

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/zitadel/oidc/v3/pkg/op"
)

// The signing key.
//
// ONE key, and it is configured rather than generated. Two properties of this
// service depend on that and neither survives the alternative:
//
//   - guard verifies every token this service issues against the JWKS this key
//     produces, and caches by `kid` for minutes at a time. A key generated at
//     boot would publish a document no cached verifier has seen, and every
//     request would fail until the cache expired. A key generated per process
//     also means two processes behind a load balancer sign with two different
//     keys and neither one's `kid` is stable.
//   - The brief for this packet says not to introduce a second key. The JWKS is
//     the OIDC key set AND the platform's verification surface, so there is
//     exactly one private key in this service, one `kid`, and one published
//     document.
//
// What is NOT here is a rotation mechanism. A second key with an overlap window
// is the right design and it is not this packet: it needs a key table, an
// activation time, and a deactivation time, and half of that is worse than none
// of it. The rotation story is in README.md, "Not built yet".
const (
	// MinKeyBits is the floor on an RSA key. 2048 is the size every verifier in
	// the platform accepts, and a shorter key is refused here rather than
	// published: a 1024-bit key verifies fine locally and is the reason a
	// published JWKS is a durable commitment.
	MinKeyBits = 2048

	// keyUseSignature is the `use` value for a key that verifies signatures.
	// The library's own examples use "sig" and so does RFC 7517's registry;
	// anything else makes some verifiers reject the set outright.
	keyUseSignature = "sig"
)

// Errors LoadSigningKey returns. Callers match them with errors.Is.
var (
	// ErrNoSigningKey means the key material is absent. An OIDC provider cannot
	// issue a token it cannot sign and cannot publish a document it cannot
	// verify, so an absent key is a startup failure and not a degraded mode.
	ErrNoSigningKey = errors.New("no OIDC signing key configured")
	// ErrWeakSigningKey means the key parsed but is smaller than MinKeyBits.
	ErrWeakSigningKey = errors.New("OIDC signing key is too small")
	// ErrKeyID means the key identifier is absent or is not a safe token.
	ErrKeyID = errors.New("OIDC signing key id is missing or unsafe")
)

// keyIDPattern bounds the key identifier.
//
// The value travels into a JWT protected header, into the JWKS, and into every
// verifier's key cache on the platform, where it is a map key and appears in log
// lines. Base64url plus dot, dash and underscore keeps it unambiguous in all
// three and leaves no room for a separator that could make two ids read as one.
var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// SigningKey is this service's one RSA signing key.
//
// It is immutable after construction and shared by every caller: it is read on
// every token the service issues and on every JWKS request, and it holds no
// per-request state, so there is nothing to synchronize and nothing to copy.
type SigningKey struct {
	kid  string
	priv *rsa.PrivateKey
}

// LoadSigningKey parses a PEM-encoded RSA private key and binds it to a key id.
//
// Both PKCS#1 (`BEGIN RSA PRIVATE KEY`, what `openssl genrsa` has written for
// years) and PKCS#8 (`BEGIN PRIVATE KEY`) are accepted. An operator following
// the wrong line of a runbook should get a service that starts, not one that
// fails on a container difference.
//
// Every failure is a refusal. A key that is absent, unparseable or too small is
// a startup error rather than a default, because the alternative — generating
// one — produces a service whose tokens nobody else can verify and whose trust
// anchor moves on every restart.
func LoadSigningKey(keyPEM, keyID string) (*SigningKey, error) {
	if keyPEM == "" {
		return nil, fmt.Errorf("%w: set OIDC_SIGNING_KEY to a PEM RSA private key", ErrNoSigningKey)
	}
	if !keyIDPattern.MatchString(keyID) {
		// The id is not quoted back: it is operator configuration and may be a
		// secret-adjacent string in a malformed deployment. The pattern is the
		// whole of the explanation.
		return nil, fmt.Errorf("%w: it must be 1-64 characters of A-Z a-z 0-9 . _ -", ErrKeyID)
	}

	priv, err := parseRSAPrivateKey([]byte(keyPEM))
	if err != nil {
		return nil, err
	}
	if priv.N.BitLen() < MinKeyBits {
		return nil, fmt.Errorf("%w: %d bits, want at least %d", ErrWeakSigningKey, priv.N.BitLen(), MinKeyBits)
	}

	return &SigningKey{kid: keyID, priv: priv}, nil
}

// parseRSAPrivateKey reads either encoding, in the order `openssl` writes them.
func parseRSAPrivateKey(raw []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%w: the value is not a PEM block", ErrNoSigningKey)
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: neither a PKCS#1 nor a PKCS#8 RSA private key", ErrNoSigningKey)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		// Named rather than quoted: an ECDSA or Ed25519 key pasted into the
		// variable is a plausible mistake, and "this provider signs with RS256"
		// is the useful thing to say about it.
		return nil, fmt.Errorf("%w: the key is a %T, and this provider signs with RS256", ErrNoSigningKey, parsed)
	}
	return key, nil
}

// ID is the `kid` this key publishes and signs under. The name is the library's,
// not this package's: op.SigningKey declares it, and a method called KeyID that
// implemented it would be a rename waiting to be undone.
func (k *SigningKey) ID() string { return k.kid }

// Key returns the private key, for the library's signing path.
//
// It is the private half and it is exposed because op.SigningKey is defined in
// terms of it. The only caller is the library's token minting; the JWKS is
// served from PublicKeyOf and has no path to this method.
func (k *SigningKey) Key() any { return k.priv }

// SignatureAlgorithm is RS256.
//
// core's conventions allow RS256 and ES256 and forbid everything else, and
// guard pins RS256 before it fetches anything. One algorithm, stated once: a
// provider that advertised a second one and then used the first is a provider
// whose tokens stop verifying the day it rotates.
func (k *SigningKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.RS256 }

// PublicKeyOf returns the publishable half, as the library's op.Key.
//
// It is a function rather than a method on SigningKey so that a nil
// *SigningKey is representable: the storage layer hands out a key set on every
// JWKS request and on every signature check, and "there is no key" is a
// different answer from "a key with an empty id".
func PublicKeyOf(k *SigningKey) op.Key {
	return publicKey{signingKey: k}
}

type publicKey struct {
	signingKey *SigningKey
}

func (p publicKey) ID() string {
	if p.signingKey == nil {
		return ""
	}
	return p.signingKey.kid
}

func (p publicKey) Algorithm() jose.SignatureAlgorithm { return jose.RS256 }

func (p publicKey) Use() string { return keyUseSignature }

func (p publicKey) Key() any {
	if p.signingKey == nil {
		return nil
	}
	return &p.signingKey.priv.PublicKey
}

// JWKS renders the published key set: RFC 7517, one key, no private material.
//
// The document is byte-stable for a given key: the same key and kid produce the
// same JSON on every call, which is what lets a consumer cache it for minutes
// (guard's default is five) without re-fetching on every request. go-jose
// marshals a JSONWebKey struct, whose field order is fixed, so there is no map
// anywhere in the path.
func (k *SigningKey) JWKS() ([]byte, error) {
	if k == nil {
		return nil, ErrNoSigningKey
	}

	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		KeyID:     k.kid,
		Algorithm: string(jose.RS256),
		Use:       keyUseSignature,
		Key:       &k.priv.PublicKey,
	}}}

	document, err := json.Marshal(set)
	if err != nil {
		return nil, fmt.Errorf("oidc: marshalling the key set: %w", err)
	}
	return document, nil
}

// marshalPKCS8 re-encodes the private key, for the encryption-key derivation in
// provider.go.
//
// The bytes are the same key in a canonical encoding whatever PEM block it
// arrived in, which is what makes the derived value stable across a
// PKCS#1-to-PKCS#8 rewrite of the same file.
func marshalPKCS8(k *SigningKey) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(k.priv)
}
