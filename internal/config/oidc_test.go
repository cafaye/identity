package config

import (
	"errors"
	"strings"
	"testing"

	"github.com/cafaye/identity/internal/oidc"
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

			// The block is COMPLETE in every case that mentions the block at all,
			// unless the case sets the login UI itself, and that is the point of
			// doing it here rather than in nine maps: these cases are about the
			// issuer, the key, the key id and the insecure opt-in, and injecting the
			// fourth variable keeps them about those. The rule that the login UI is
			// REQUIRED lives in one test below, where it can be stated as a rule
			// instead of being implied by nine repetitions of a variable.
			//
			// "mentions the block at all" rather than "is non-empty", because the
			// one case with no block is the one that must stay that way: a login UI
			// with nothing to apply it to is its own refusal, and injecting one here
			// would have that case fail for a reason it is not about.
			env := map[string]string{}
			for key, value := range tt.env {
				env[key] = value
			}
			if _, set := env[oidc.LoginUIEnvVar]; !set && mentionsTheOIDCBlock(env) {
				env[oidc.LoginUIEnvVar] = "https://login.cafaye.com/sign-in/oidc"
			}

			cfg, err := Load(mapOf(env))
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

// The login UI is part of the block, and both halves of "part of" are refusals:
// a block with no login UI, and a login UI with no block.
//
// THE FIRST ONE IS THE ONE THAT MATTERS, and it is a startup failure rather than
// a degraded mode for the reason the whole block is one: `identity` renders no
// HTML, so a provider that cannot send a browser to a page that asks for a
// password is a provider that publishes a working discovery document and cannot
// complete a single authorization flow. The alternative — mount the surface and
// answer 503 — is a discovery document advertising a capability that does not
// work, which is the failure this repository treats as a sin everywhere else.
func TestTheLoginUIIsPartOfTheOIDCBlock(t *testing.T) {
	t.Parallel()

	// A syntactically valid stand-in; the key's contents are not parsed here.
	const keyPEM = "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n"

	block := map[string]string{
		"OIDC_ISSUER":         "https://identity.cafaye.com",
		"OIDC_SIGNING_KEY":    keyPEM,
		"OIDC_SIGNING_KEY_ID": "cafaye-2026-09",
	}

	tests := []struct {
		name    string
		env     map[string]string
		wantErr error
	}{
		{
			name:    "a complete block with no login UI",
			env:     block,
			wantErr: ErrInvalidOIDC,
		},
		{
			name: "a login UI with nothing to apply it to",
			env:  map[string]string{oidc.LoginUIEnvVar: "https://login.cafaye.com/sign-in/oidc"},
			// Same reasoning as OIDC_ALLOW_INSECURE with no issuer: a setting an
			// operator changed and nothing reads is a typo, and a typo found at boot
			// costs a log line.
			wantErr: ErrInvalidOIDC,
		},
		{
			name: "a login UI that is not an address a browser can be sent to",
			env: map[string]string{
				"OIDC_ISSUER":         "https://identity.cafaye.com",
				"OIDC_SIGNING_KEY":    keyPEM,
				"OIDC_SIGNING_KEY_ID": "cafaye-2026-09",
				oidc.LoginUIEnvVar:    "javascript:alert(1)",
			},
			wantErr: ErrInvalidOIDC,
		},
		{
			name: "a complete block",
			env: map[string]string{
				"OIDC_ISSUER":         "https://identity.cafaye.com",
				"OIDC_SIGNING_KEY":    keyPEM,
				"OIDC_SIGNING_KEY_ID": "cafaye-2026-09",
				oidc.LoginUIEnvVar:    "https://login.cafaye.com/sign-in/oidc",
			},
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
				// The refusal has to NAME the variable, because the reader is an
				// operator at boot with a log line and a variable list.
				if !strings.Contains(err.Error(), oidc.LoginUIEnvVar) {
					t.Errorf("the refusal does not name %s: %v", oidc.LoginUIEnvVar, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.OIDCLoginUIURL != "https://login.cafaye.com/sign-in/oidc" {
				t.Errorf("OIDCLoginUIURL = %q, want the configured one", cfg.OIDCLoginUIURL)
			}
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
		oidc.LoginUIEnvVar:    "https://login.cafaye.com/sign-in/oidc",
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

// mentionsTheOIDCBlock reports whether an environment names any of the three
// variables whose presence is what makes this process a provider at all.
//
// It is a helper rather than three inline lookups because the test using it is
// about the ISSUER and the KEY, and spelling out "does this case want a login UI"
// as a membership question is the difference between a reader learning the rule
// and a reader counting variables.
func mentionsTheOIDCBlock(env map[string]string) bool {
	for _, key := range []string{"OIDC_ISSUER", "OIDC_SIGNING_KEY", "OIDC_SIGNING_KEY_ID"} {
		if env[key] != "" {
			return true
		}
	}
	return false
}
