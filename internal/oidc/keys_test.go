package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"regexp"
	"testing"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/zitadel/oidc/v3/pkg/op"
)

// The key is the one piece of configuration this service cannot invent at
// runtime and cannot have two of. Everything below is about the one key: that it
// loads from a PEM rather than being generated, that it is big enough, that its
// identifier is safe to put in a JWT header and a consumer's cache, and that the
// document served at the JWKS URL is shaped the way guard's verifier reads it.

func TestLoadSigningKey(t *testing.T) {
	t.Parallel()

	t.Run("a PKCS#1 PEM loads", func(t *testing.T) {
		t.Parallel()

		key, err := LoadSigningKey(pemFor(t, 2048, pkcs1), "cafaye-2026-09")
		if err != nil {
			t.Fatalf("LoadSigningKey: %v", err)
		}
		if key.ID() != "cafaye-2026-09" {
			t.Errorf("ID = %q, want cafaye-2026-09", key.ID())
		}
		if key.SignatureAlgorithm() != jose.RS256 {
			t.Errorf("algorithm = %q, want RS256; the JWKS and every token header say the same thing", key.SignatureAlgorithm())
		}
		priv, ok := key.Key().(*rsa.PrivateKey)
		if !ok {
			t.Fatalf("Key() is a %T, want the parsed *rsa.PrivateKey", key.Key())
		}
		if priv.N.BitLen() != 2048 {
			t.Errorf("modulus is %d bits, want 2048", priv.N.BitLen())
		}
	})

	t.Run("a PKCS#8 PEM loads to the same shape", func(t *testing.T) {
		t.Parallel()

		key, err := LoadSigningKey(pemFor(t, 2048, pkcs8), "cafaye-2026-09")
		if err != nil {
			t.Fatalf("LoadSigningKey: %v", err)
		}
		if _, ok := key.Key().(*rsa.PrivateKey); !ok {
			t.Fatalf("Key() is a %T, want the parsed *rsa.PrivateKey", key.Key())
		}
	})
}

// Every rejection is a startup failure, not a fallback. A key that silently
// degrades to a smaller one, or to a generated one, is a service that verifies
// tokens nobody else can and rotates its own trust anchor on every restart.
func TestLoadSigningKeyRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
		kid  string
	}{
		{name: "no PEM at all", give: "", kid: "kid-1"},
		{name: "whitespace", give: "   \n\t ", kid: "kid-1"},
		{name: "not a PEM block", give: "-----BEGIN NONSENSE-----", kid: "kid-1"},
		{name: "a PEM that is not a key", give: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("hello")})), kid: "kid-1"},
		{name: "a 1024-bit key", give: pemFor(t, 1024, pkcs8), kid: "kid-1"},
		{name: "no key id", give: pemFor(t, 2048, pkcs8), kid: ""},
		{name: "a key id with a slash", give: pemFor(t, 2048, pkcs8), kid: "cafaye/2026"},
		{name: "a key id with a space", give: pemFor(t, 2048, pkcs8), kid: "cafaye 2026"},
		{name: "an over-long key id", give: pemFor(t, 2048, pkcs8), kid: string(make([]byte, 0, 65)) + repeat("k", 65)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := LoadSigningKey(tt.give, tt.kid); err == nil {
				t.Fatal("LoadSigningKey = nil error, want a refusal")
			}
		})
	}
}

// The published document is guard's entire view of this service's trust, and
// guard reads it with three specific expectations: a `keys` array, non-empty,
// of objects; a `kid` on the key that matches the token header; and an RS256
// key. The shape is asserted field by field rather than "it is JSON" because
// every one of these has a different failure on the consumer side.
func TestJWKSIsTheDocumentGuardReads(t *testing.T) {
	t.Parallel()

	key, err := LoadSigningKey(pemFor(t, 2048, pkcs8), "cafaye-2026-09")
	if err != nil {
		t.Fatalf("LoadSigningKey: %v", err)
	}

	document, err := key.JWKS()
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}

	var decoded struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatalf("the JWKS is not JSON: %v", err)
	}

	// guard's isKeySet: an array, non-empty, every entry an object. An empty
	// array is a 401 on every request, so it is worth pinning.
	if len(decoded.Keys) != 1 {
		t.Fatalf("the key set has %d keys, want exactly 1; this service has one signing key", len(decoded.Keys))
	}
	got := decoded.Keys[0]
	if got.Kty != "RSA" {
		t.Errorf("kty = %q, want RSA", got.Kty)
	}
	if got.Kid != "cafaye-2026-09" {
		t.Errorf("kid = %q, want the configured key id", got.Kid)
	}
	if got.Alg != "RS256" {
		t.Errorf("alg = %q, want RS256; guard refuses any token whose header is not RS256", got.Alg)
	}
	if got.Use != "sig" {
		t.Errorf("use = %q, want sig; the key verifies signatures and encrypts nothing", got.Use)
	}
	// The modulus and exponent are what jose actually verifies with. A document
	// with a kid and no `n` parses and matches, and then fails every token.
	if !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(got.N) || got.N == "" {
		t.Errorf("n = %q, want base64url of the modulus", got.N)
	}
	if got.E == "" {
		t.Error("e is empty, want base64url of the public exponent")
	}
}

// The private half must never reach the document. This is the assertion that
// says so out loud, because the only thing separating the two is which of the
// two accessors the handler happens to call.
func TestJWKSNeverCarriesThePrivateKey(t *testing.T) {
	t.Parallel()

	key, err := LoadSigningKey(pemFor(t, 2048, pkcs8), "cafaye-2026-09")
	if err != nil {
		t.Fatalf("LoadSigningKey: %v", err)
	}
	document, err := key.JWKS()
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatalf("the JWKS is not JSON: %v", err)
	}
	for _, jwk := range decoded["keys"].([]any) {
		for _, private := range []string{"d", "p", "q", "dp", "dq", "qi", "oth"} {
			if _, present := jwk.(map[string]any)[private]; present {
				t.Errorf("the published key set carries the private component %q", private)
			}
		}
	}
}

// The key is the library's op.SigningKey and its published half is an op.Key.
// The assertions name the real interfaces rather than a copy of their method
// sets, so a signature change upstream fails here with a message that says which
// interface moved instead of failing in three call sites with no explanation.
func TestSigningKeySatisfiesTheLibraryInterfaces(t *testing.T) {
	t.Parallel()

	var _ op.SigningKey = (*SigningKey)(nil)
	var _ op.Key = PublicKeyOf(nil)
}

// PEM encodings. Both are accepted because `openssl genrsa` has emitted both for
// a decade and an operator following the wrong line of a runbook should not be
// left with a service that will not start.
type pemEncoding int

const (
	pkcs1 pemEncoding = iota
	pkcs8
)

// pemFor generates a throwaway key of the given size and encodes it.
//
// Generated rather than checked in so no test fixture in this repository holds a
// private key, even a dead one: a PEM in a test file is a PEM somebody eventually
// copies into a deployment.
func pemFor(t *testing.T, bits int, encoding pemEncoding) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generating a %d-bit key: %v", bits, err)
	}

	var block *pem.Block
	switch encoding {
	case pkcs1:
		block = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	case pkcs8:
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("marshalling PKCS#8: %v", err)
		}
		block = &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	default:
		t.Fatalf("unknown encoding %d", encoding)
	}

	return string(pem.EncodeToMemory(block))
}

func repeat(s string, n int) string {
	out := make([]byte, 0, n*len(s))
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
