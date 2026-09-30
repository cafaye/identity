package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"testing"

	"github.com/cafaye/identity/internal/config"
	"github.com/cafaye/identity/internal/oidc"
	"github.com/cafaye/identity/internal/platform/dbtest"
)

// The OIDC wiring. What matters here is that the two configurations are
// actually connected: a process with a key and a database IS a provider, and a
// process without one is not. Everything the provider does is covered in
// internal/oidc and internal/httpapi; what cannot be covered from there is
// whether newApp wires it at all.

// testKeyPEM returns a throwaway RSA key as a PEM, for the configuration.
//
// Generated per call rather than a fixture file: a PEM checked into a repository
// is a PEM somebody eventually copies into a deployment.
func testKeyPEM(t *testing.T) string {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating a signing key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshalling the signing key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// oidcConfig is a complete OIDC configuration for a test process.
func oidcConfig(t *testing.T, dsn string) config.Config {
	t.Helper()

	return config.Config{
		Port:           "0",
		LogLevel:       "error",
		DatabaseURL:    dsn,
		OIDCIssuer:     "https://identity.test",
		OIDCSigningKey: testKeyPEM(t),
		OIDCKeyID:      "cafaye-wiring-test",
	}
}

// With a database and a key, the process is an OpenID Connect provider: the
// discovery document, the key set and the registration routes are all served.
func TestNewAppServesTheOIDCProvider(t *testing.T) {
	dsn := testDatabaseURL(t)

	a, err := newApp(context.Background(), oidcConfig(t, dsn), discardLogger())
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	defer a.Close()

	rec := serveBody(t, a, http.MethodGet, oidc.PathDiscovery, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200; body: %s", oidc.PathDiscovery, rec.Code, rec.Body)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("the discovery document is not JSON: %v", err)
	}
	if doc["issuer"] != "https://identity.test" {
		t.Errorf("issuer = %v, want the configured one", doc["issuer"])
	}

	// The RFC 8414 alias, which the library does not register and identity does.
	alias := serveBody(t, a, http.MethodGet, oidc.PathOAuthAuthorizationServer, "", nil)
	if alias.Code != http.StatusOK {
		t.Errorf("GET %s = %d, want 200", oidc.PathOAuthAuthorizationServer, alias.Code)
	}

	keys := serveBody(t, a, http.MethodGet, oidc.PathJWKS, "", nil)
	if keys.Code != http.StatusOK {
		t.Errorf("GET %s = %d, want 200", oidc.PathJWKS, keys.Code)
	}

	// The registration routes, which need an account and a session. This asserts
	// they are MOUNTED and not that they succeed: a 401 here means the route
	// exists and the authorization gate ran, and a 404 means the wiring is
	// missing.
	registered := serveBody(t, a, http.MethodPost, "/v1/accounts/00000000-0000-4000-8000-000000000000/oidc-clients", `{}`, nil)
	if registered.Code != http.StatusUnauthorized {
		t.Errorf("POST an OIDC client route anonymously = %d, want 401; a 404 means the route is not mounted",
			registered.Code)
	}
}

// Without a key, the process serves its probes and its /v1 surface and is not an
// OpenID Connect provider. The routes are ABSENT rather than present-and-500, the
// same rule a missing DATABASE_URL follows.
func TestNewAppWithoutOIDCKeysIsNotAProvider(t *testing.T) {
	dsn := testDatabaseURL(t)

	cfg := config.Config{Port: "0", LogLevel: "error", DatabaseURL: dsn}
	a, err := newApp(context.Background(), cfg, discardLogger())
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	defer a.Close()

	for _, target := range []string{
		oidc.PathDiscovery,
		oidc.PathOAuthAuthorizationServer,
		oidc.PathJWKS,
		oidc.PathAuthorize,
		oidc.PathToken,
		oidc.PathUserinfo,
		oidc.PathLogin + "/00000000-0000-4000-8000-000000000000",
	} {
		rec := serveBody(t, a, http.MethodGet, target, "", nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404 with no OIDC configuration; body: %s", target, rec.Code, rec.Body)
		}
	}

	// The /v1 surface is untouched, which is the point: a process that is not a
	// provider is not a broken one.
	email := dbtest.UniqueEmail(t)
	rec := serveBody(t, a, http.MethodPost, "/v1/users", `{"email":"`+email+`","password":"correct horse battery staple"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Errorf("POST /v1/users = %d, want 201; the /v1 surface must not depend on the OIDC configuration", rec.Code)
	}
}

// Keys with no database is the configuration that cannot work, and it says so by
// mounting nothing rather than by serving a provider that can sign tokens for
// clients nobody can register or revoke.
func TestNewAppWithOIDCKeysButNoDatabaseIsNotAProvider(t *testing.T) {
	cfg := oidcConfig(t, "")
	cfg.DatabaseURL = ""

	a, err := newApp(context.Background(), cfg, discardLogger())
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	defer a.Close()

	// Liveness first: the process is up, it is just not a provider.
	rec := serveBody(t, a, http.MethodGet, "/healthz", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /healthz = %d, want 200", rec.Code)
	}

	for _, target := range []string{oidc.PathDiscovery, oidc.PathJWKS, oidc.PathAuthorize} {
		got := serveBody(t, a, http.MethodGet, target, "", nil)
		if got.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404 with no database; body: %s", target, got.Code, got.Body)
		}
	}
}

// A key that will not parse is a startup failure, not a warning. A provider that
// invents its own key signs tokens nobody can verify and rotates its own trust
// anchor on every restart.
func TestNewAppRefusesAnUnparseableSigningKey(t *testing.T) {
	dsn := testDatabaseURL(t)

	cfg := oidcConfig(t, dsn)
	cfg.OIDCSigningKey = "-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----\n"

	if _, err := newApp(context.Background(), cfg, discardLogger()); err == nil {
		t.Fatal("newApp accepted an unparseable signing key")
	}
}
