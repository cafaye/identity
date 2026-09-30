// Package config loads the service configuration from the environment.
//
// Configuration is read once at startup and never mutated afterwards: the
// Config value is the single source of truth threaded through the process.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
)

const (
	// DefaultPort is used when PORT is unset.
	DefaultPort = "8080"
	// DefaultLogLevel is used when LOG_LEVEL is unset.
	DefaultLogLevel = "info"

	minPort = 1
	maxPort = 65535
)

// Lookup mirrors os.LookupEnv: it returns the value for key and whether the
// key was present. Injecting it keeps Load testable without mutating the
// process environment.
type Lookup func(key string) (string, bool)

// Errors returned by Load. They are wrapped with context, so callers should
// match them with errors.Is.
var (
	ErrInvalidPort        = errors.New("invalid PORT")
	ErrInvalidLogLevel    = errors.New("invalid LOG_LEVEL")
	ErrInvalidDatabaseURL = errors.New("invalid DATABASE_URL")

	// ErrInvalidOIDC means the OIDC configuration is present and incomplete, or
	// present and unreadable. It is a startup failure rather than a degraded mode
	// for the reason the whole block is: a provider with an issuer and no key can
	// sign nothing, and one with a key and no issuer has no `iss` to put in a
	// token. Both would otherwise be discovered as a 500 by the first user to try
	// to sign in.
	ErrInvalidOIDC = errors.New("invalid OIDC configuration")

	// ErrInsecureOIDCIssuer means the issuer is http and OIDC_ALLOW_INSECURE was
	// not set. It is its own sentinel so an operator reading a startup log is told
	// the one thing they have to do, rather than being told their configuration is
	// invalid.
	ErrInsecureOIDCIssuer = errors.New("OIDC_ISSUER is http")
)

// Config is the fully validated service configuration.
type Config struct {
	// Port is the TCP port the HTTP server binds to.
	Port string
	// DatabaseURL is the Postgres connection string. Empty means "no database
	// configured", which is valid in v0 and makes readiness checks a no-op.
	DatabaseURL string
	// LogLevel is one of debug, info, warn, error.
	LogLevel string

	// The OIDC provider's configuration. All three are required together or not
	// at all; see OIDCEnabled.
	//
	// OIDCSigningKey is a PEM-encoded RSA private key, read from the
	// environment rather than from a file so that the secret is whatever the
	// deployment's secret store already is. It is never logged and never
	// rendered in a response.
	OIDCIssuer     string
	OIDCSigningKey string
	OIDCKeyID      string
	// OIDCAllowInsecure permits an http issuer. It exists for `localhost` and for
	// a compose stack, and it is a field rather than a behaviour because "this
	// deployment is local" is a fact about the deployment and guessing it from
	// the hostname would be a security decision made by a string match.
	OIDCAllowInsecure bool
}

// OIDCEnabled reports whether the OIDC surface is configured.
//
// One boolean rather than three checks at every use, because the decision is
// genuinely one thing: either this process is an OpenID Connect provider or it is
// not. A process with an unset OIDC_ISSUER serves its /v1 surface and its probes
// and nothing else, and the routes are absent rather than present-and-500 — the
// same rule WithAuth and WithTenancy already follow for a missing DATABASE_URL.
func (c Config) OIDCEnabled() bool {
	return c.OIDCIssuer != "" && c.OIDCSigningKey != "" && c.OIDCKeyID != ""
}

// Load reads the environment through lookup and returns a validated Config.
//
// A nil lookup means "no environment": the defaults apply. Values that are
// present but invalid are errors rather than silent fallbacks, so a typo in a
// deployment manifests as a startup failure and not as surprising behaviour.
func Load(lookup Lookup) (Config, error) {
	if lookup == nil {
		lookup = func(string) (string, bool) { return "", false }
	}

	cfg := Config{
		Port:        DefaultPort,
		LogLevel:    DefaultLogLevel,
		DatabaseURL: lookupValue(lookup, "DATABASE_URL"),
	}

	if port, ok := lookup("PORT"); ok {
		cfg.Port = port
	}
	if err := cfg.validatePort(); err != nil {
		return Config{}, err
	}

	if level, ok := lookup("LOG_LEVEL"); ok {
		cfg.LogLevel = strings.ToLower(strings.TrimSpace(level))
	}
	if err := cfg.validateLogLevel(); err != nil {
		return Config{}, err
	}

	if err := cfg.validateDatabaseURL(); err != nil {
		return Config{}, err
	}

	if err := cfg.loadOIDC(lookup); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// loadOIDC reads and validates the OIDC block.
//
// The rule is all-or-nothing, and it is a startup failure rather than a fallback
// in every direction:
//
//   - an issuer with no key, or a key with no issuer, or a key with no id. A
//     provider with an issuer and no key can sign nothing; one with a key and no
//     issuer has no `iss` to put in a token; one with no key id publishes a
//     document whose `kid` a verifier cannot match against a token header.
//   - an http issuer without OIDC_ALLOW_INSECURE. Every verifier on the platform
//     compares `iss` for equality and fetches the JWKS over the same scheme, so
//     an http issuer in production is a token nobody can verify and a key
//     document nobody will fetch over a channel that protects it.
//
// Absent is the supported state: no issuer and no key is a process that is not an
// OpenID Connect provider, and that is a legitimate deployment — a courier, or a
// local stack that has no key yet.
func (c *Config) loadOIDC(lookup Lookup) error {
	issuer := lookupValue(lookup, "OIDC_ISSUER")
	key := lookupValue(lookup, "OIDC_SIGNING_KEY")
	keyID := lookupValue(lookup, "OIDC_SIGNING_KEY_ID")

	present := 0
	for _, value := range []string{issuer, key, keyID} {
		if value != "" {
			present++
		}
	}
	switch {
	case present == 0:
		if _, ok := lookup("OIDC_ALLOW_INSECURE"); ok && lookupValue(lookup, "OIDC_ALLOW_INSECURE") != "" {
			// Asking for an insecure issuer with nothing to apply it to is a
			// configuration mistake, not a no-op: the variable was written for a
			// deployment that has an issuer and does not.
			return fmt.Errorf("%w: OIDC_ALLOW_INSECURE is set but there is no OIDC_ISSUER to apply it to", ErrInvalidOIDC)
		}
		return nil
	case present != 3:
		return fmt.Errorf("%w: OIDC_ISSUER, OIDC_SIGNING_KEY and OIDC_SIGNING_KEY_ID must all be set, or none of them", ErrInvalidOIDC)
	}

	parsed, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("%w: OIDC_ISSUER is not a URL: %v", ErrInvalidOIDC, err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("%w: OIDC_ISSUER scheme is %q, want https", ErrInvalidOIDC, parsed.Scheme)
	}

	allowInsecure := false
	if _, ok := lookup("OIDC_ALLOW_INSECURE"); ok {
		value := lookupValue(lookup, "OIDC_ALLOW_INSECURE")
		switch strings.ToLower(value) {
		case "true", "1", "yes":
			allowInsecure = true
		case "false", "0", "no", "":
		default:
			return fmt.Errorf("%w: OIDC_ALLOW_INSECURE is %q, want true or false", ErrInvalidOIDC, value)
		}
	}
	if parsed.Scheme == "http" && !allowInsecure {
		return fmt.Errorf("%w: set OIDC_ALLOW_INSECURE=true to use it; every verifier on the platform fetches the "+
			"JWKS over this scheme, so an http issuer is only safe on localhost", ErrInsecureOIDCIssuer)
	}

	c.OIDCIssuer = strings.TrimSuffix(issuer, "/")
	c.OIDCSigningKey = key
	c.OIDCKeyID = keyID
	c.OIDCAllowInsecure = allowInsecure
	return nil
}

// Addr is the address the HTTP server listens on.
func (c Config) Addr() string {
	return ":" + c.Port
}

// SlogLevel maps the configured LOG_LEVEL onto a slog level.
func (c Config) SlogLevel() slog.Level {
	var level slog.Level
	if err := level.UnmarshalText([]byte(c.LogLevel)); err != nil {
		return slog.LevelInfo
	}
	return level
}

func (c Config) validatePort() error {
	port, err := strconv.Atoi(c.Port)
	if err != nil {
		return fmt.Errorf("%w: %q is not a number", ErrInvalidPort, c.Port)
	}
	if port < minPort || port > maxPort {
		return fmt.Errorf("%w: %d is outside %d-%d", ErrInvalidPort, port, minPort, maxPort)
	}
	return nil
}

func (c Config) validateLogLevel() error {
	var level slog.Level
	if err := level.UnmarshalText([]byte(c.LogLevel)); err != nil {
		return fmt.Errorf("%w: %q is not one of debug, info, warn, error", ErrInvalidLogLevel, c.LogLevel)
	}
	return nil
}

func (c Config) validateDatabaseURL() error {
	if c.DatabaseURL == "" {
		return nil
	}
	parsed, err := url.Parse(c.DatabaseURL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidDatabaseURL, err)
	}
	if parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" {
		return fmt.Errorf("%w: scheme %q is not postgres", ErrInvalidDatabaseURL, parsed.Scheme)
	}
	return nil
}

func lookupValue(lookup Lookup, key string) string {
	value, _ := lookup(key)
	return strings.TrimSpace(value)
}
