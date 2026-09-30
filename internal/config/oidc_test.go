package config

import (
	"errors"
	"strings"
	"testing"
)

// The OIDC configuration, and the rule that decides whether the OIDC surface
// exists at all.
//
// The rule is all-or-nothing: an issuer without a key, or a key without an
// issuer, is a startup failure. A provider with a key and no issuer has no `iss`
// to put in a token, and a provider with an issuer and no key can sign nothing
// and publish nothing — and in both cases the failure would otherwise be a 500 on
// the first sign-in, discovered by a user rather than by an operator.

func TestLoadOIDC(t *testing.T) {
	t.Parallel()

	// A syntactically valid stand-in; the key's contents are not parsed here,
	// that is internal/oidc's job and its own tests.
	const keyPEM = "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n"

	tests := []struct {
		name    string
		env     map[string]string
		wantErr error
		assert  func(t *testing.T, cfg Config)
	}{
		{
			name: "no OIDC configuration at all",
			env:  map[string]string{},
			assert: func(t *testing.T, cfg Config) {
				if cfg.OIDCEnabled() {
					t.Error("OIDCEnabled with no issuer and no key; the surface would be mounted and broken")
				}
			},
		},
		{
			name: "an issuer with no key",
			env:  map[string]string{"OIDC_ISSUER": "https://identity.cafaye.com"},
			// Not a fallback: a provider with an issuer and no key cannot sign.
			wantErr: ErrInvalidOIDC,
		},
		{
			name:    "a key with no issuer",
			env:     map[string]string{"OIDC_SIGNING_KEY": keyPEM, "OIDC_SIGNING_KEY_ID": "cafaye-2026-09"},
			wantErr: ErrInvalidOIDC,
		},
		{
			name: "an issuer, a key and a key id",
			env: map[string]string{
				"OIDC_ISSUER":         "https://identity.cafaye.com",
				"OIDC_SIGNING_KEY":    keyPEM,
				"OIDC_SIGNING_KEY_ID": "cafaye-2026-09",
			},
			assert: func(t *testing.T, cfg Config) {
				if !cfg.OIDCEnabled() {
					t.Error("OIDCEnabled is false with a complete configuration")
				}
				if cfg.OIDCIssuer != "https://identity.cafaye.com" {
					t.Errorf("OIDCIssuer = %q", cfg.OIDCIssuer)
				}
				if cfg.OIDCKeyID != "cafaye-2026-09" {
					t.Errorf("OIDCKeyID = %q", cfg.OIDCKeyID)
				}
				if cfg.OIDCAllowInsecure {
					t.Error("OIDCAllowInsecure defaults to true; an http issuer must be asked for")
				}
			},
		},
		{
			name: "values are trimmed",
			env: map[string]string{
				"OIDC_ISSUER":         "  https://identity.cafaye.com  ",
				"OIDC_SIGNING_KEY":    keyPEM,
				"OIDC_SIGNING_KEY_ID": "  cafaye-2026-09  ",
			},
			assert: func(t *testing.T, cfg Config) {
				if cfg.OIDCIssuer != "https://identity.cafaye.com" {
					t.Errorf("OIDCIssuer = %q, want it trimmed", cfg.OIDCIssuer)
				}
				if cfg.OIDCKeyID != "cafaye-2026-09" {
					t.Errorf("OIDCKeyID = %q, want it trimmed", cfg.OIDCKeyID)
				}
			},
		},
		{
			// A trailing newline in a PEM from a secret manager is normal, and
			// trimming it is the difference between a mounted surface and a startup
			// failure at 3am.
			name: "a key keeps its interior and loses its trailing whitespace",
			env: map[string]string{
				"OIDC_ISSUER":         "https://identity.cafaye.com",
				"OIDC_SIGNING_KEY":    keyPEM + "\n\n  ",
				"OIDC_SIGNING_KEY_ID": "cafaye-2026-09",
			},
			assert: func(t *testing.T, cfg Config) {
				if strings.HasSuffix(cfg.OIDCSigningKey, "\n") || strings.HasSuffix(cfg.OIDCSigningKey, " ") {
					t.Errorf("OIDCSigningKey = %q, want it trimmed", cfg.OIDCSigningKey)
				}
			},
		},
		{
			name: "an http issuer without the explicit opt-in",
			env: map[string]string{
				"OIDC_ISSUER":         "http://localhost:8080",
				"OIDC_SIGNING_KEY":    keyPEM,
				"OIDC_SIGNING_KEY_ID": "cafaye-2026-09",
			},
			wantErr: ErrInsecureOIDCIssuer,
		},
		{
			name: "an http issuer with the opt-in",
			env: map[string]string{
				"OIDC_ISSUER":         "http://localhost:8080",
				"OIDC_SIGNING_KEY":    keyPEM,
				"OIDC_SIGNING_KEY_ID": "cafaye-2026-09",
				"OIDC_ALLOW_INSECURE": "true",
			},
			assert: func(t *testing.T, cfg Config) {
				if !cfg.OIDCAllowInsecure {
					t.Error("OIDCAllowInsecure is false after being asked for")
				}
			},
		},
		{
			name: "a misspelt opt-in",
			env: map[string]string{
				"OIDC_ISSUER":         "https://identity.cafaye.com",
				"OIDC_SIGNING_KEY":    keyPEM,
				"OIDC_SIGNING_KEY_ID": "cafaye-2026-09",
				"OIDC_ALLOW_INSECURE": "yes-please",
			},
			wantErr: ErrInvalidOIDC,
		},
		{
			name: "an issuer that is not a URL",
			env: map[string]string{
				"OIDC_ISSUER":         "identity.cafaye.com",
				"OIDC_SIGNING_KEY":    keyPEM,
				"OIDC_SIGNING_KEY_ID": "cafaye-2026-09",
			},
			wantErr: ErrInvalidOIDC,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg, err := Load(mapOf(tt.env))
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Load = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			tt.assert(t, cfg)
		})
	}
}

// The untrimmed value is what the process actually reads, and a PEM with a stray
// leading space fails to parse with an error that names a parse failure rather
// than a configuration mistake.
func TestLoadTrimsTheSigningKey(t *testing.T) {
	t.Parallel()

	env := map[string]string{
		"OIDC_ISSUER":         "https://identity.cafaye.com",
		"OIDC_SIGNING_KEY":    "  -----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----  ",
		"OIDC_SIGNING_KEY_ID": "k1",
	}
	cfg, err := Load(mapOf(env))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !strings.HasPrefix(cfg.OIDCSigningKey, "-----BEGIN") {
		t.Errorf("OIDCSigningKey = %q, want it to start at the PEM header", cfg.OIDCSigningKey)
	}
}

func mapOf(env map[string]string) Lookup {
	return func(key string) (string, bool) {
		value, ok := env[key]
		return value, ok
	}
}
