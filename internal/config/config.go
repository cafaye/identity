// Package config loads the service configuration from the environment.
//
// Configuration is read once at startup and never mutated afterwards: the
// Config value is the single source of truth threaded through the process.
package config

import (
	"encoding/base64"
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

	// ErrInvalidMFA means MFA_ENCRYPTION_KEY is present and unreadable. A startup
	// failure rather than a degraded mode, for the reason the OIDC block is: a
	// deployment whose key does not decode cannot seal a TOTP secret, so every
	// enrolled user would be locked out at their second factor — and would find
	// out at login, in front of somebody who thought they had a second factor.
	ErrInvalidMFA = errors.New("invalid MFA_ENCRYPTION_KEY")

	// ErrNoMFAEncryptionKey means MFA_ENCRYPTION_KEY is not set at all, which is a
	// supported state: a deployment with no second factor. It is a distinct
	// sentinel from ErrInvalidMFA because the two lead to completely different
	// places — one starts up, the other mounts a reduced surface and logs why.
	ErrNoMFAEncryptionKey = errors.New("MFA_ENCRYPTION_KEY is not configured")

	// ErrInvalidCourier means the courier block is present and unreadable: a base
	// URL that is not one, or a recovery link template that cannot produce a
	// working link. A startup failure rather than a degraded mode, for the reason
	// the OIDC and MFA blocks are — a deployment whose mail configuration is wrong
	// cannot send a password reset, and it would find out from a user who never got
	// one, in front of somebody waiting on a link.
	ErrInvalidCourier = errors.New("invalid courier configuration")

	// ErrNoCourierToken means COURIER_TOKEN is not set at all, which is a
	// SUPPORTED state: a deployment with no mail path. It is a distinct sentinel
	// from ErrInvalidCourier for the same reason ErrNoMFAEncryptionKey is distinct
	// from ErrInvalidMFA — one starts up and mounts a reduced surface, the other
	// refuses to start, and conflating them would either refuse to boot a
	// legitimate deployment or silently boot a broken one.
	ErrNoCourierToken = errors.New("COURIER_TOKEN is not configured")
)

// DefaultMFAIssuer is what an authenticator app displays next to the entry when
// MFA_ISSUER is unset.
//
// "cafaye identity", with a space rather than a hyphen, because that is what a
// person reads in a phone's authenticator next to the six digits and the clock.
// It is also what the provisioning URI's issuer parameter carries, so changing it
// changes what every future enrollment shows and nothing about the credentials
// already confirmed.
const DefaultMFAIssuer = "cafaye identity"

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

	// MFAEncryptionKeyValue is the raw key a TOTP secret is sealed under, decoded
	// from MFA_ENCRYPTION_KEY. Empty means "this deployment has no second factor",
	// which is a supported state and reduces the surface rather than failing.
	MFAEncryptionKeyValue []byte

	// MFAIssuerLabel is what an authenticator app displays. It is NOT a secret, and
	// changing it is harmless to every credential already confirmed.
	MFAIssuerLabel string

	// The courier block: the platform's mail service, and the only thing that can
	// deliver a recovery message.
	//
	// ALL THREE ARE REQUIRED TOGETHER OR NOT AT ALL, for the same all-or-nothing
	// reason the OIDC block is. A base URL with no credential would send every
	// request as an anonymous caller, and courier's answer to that is a 401 on a
	// mail egress; a credential with no base URL is a secret with nowhere to go; and
	// a link template is what turns a reset token into a link a person can follow,
	// so without it a "sent" reset mail would arrive with nothing to click.
	//
	// The token is never logged and never rendered, and it is read from the
	// environment rather than a file so the secret is whatever the deployment's
	// secret store already is.
	CourierBaseURL       string
	CourierTokenValue    string
	RecoveryLinkTemplate string
}

// MFAEncryptionKey returns the configured key, or ErrNoMFAEncryptionKey.
//
// The decoding is base64url and then a length check, and BOTH failures are startup
// errors. The length check belongs here rather than at the cipher because an
// operator who pasted a 16-byte key has configured half the entropy they think they
// have, and quietly stretching it would hide that until the day it matters.
func (c Config) MFAEncryptionKey() ([]byte, error) {
	if len(c.MFAEncryptionKeyValue) == 0 {
		return nil, ErrNoMFAEncryptionKey
	}
	if len(c.MFAEncryptionKeyValue) != 32 {
		return nil, fmt.Errorf("%w: it decodes to %d bytes, want exactly 32",
			ErrInvalidMFA, len(c.MFAEncryptionKeyValue))
	}
	return c.MFAEncryptionKeyValue, nil
}

// MFAIssuer is the label an authenticator app displays next to the entry.
//
// The default is applied HERE as well as in Load, so a Config written as a literal —
// in a test, or in a one-off tool — still names something. An authenticator app
// showing a blank account is a support ticket, and Load is not the only way to
// build a Config.
func (c Config) MFAIssuer() string {
	if c.MFAIssuerLabel == "" {
		return DefaultMFAIssuer
	}
	return c.MFAIssuerLabel
}

// MFAEncryptionKeyConfigured reports whether this deployment has a usable key,
// without revealing anything about it. main uses it to decide whether to mount the
// MFA management routes.
func (c Config) MFAEncryptionKeyConfigured() bool {
	return len(c.MFAEncryptionKeyValue) == 32
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

// CourierToken returns the service credential, or ErrNoCourierToken.
//
// The split sentinel matters at the one place it is used: `main` treats "absent"
// as a deployment with no mail path and mounts `recovery.Unavailable{}`, and treats
// "present and unreadable" as a startup failure. Those are opposite behaviours and
// an operator who cannot tell them apart from the log has been told nothing.
func (c Config) CourierToken() (string, error) {
	if c.CourierTokenValue == "" {
		return "", ErrNoCourierToken
	}
	return c.CourierTokenValue, nil
}

// CourierEnabled reports whether this deployment can send a message.
//
// One boolean rather than three checks at the use site, because the decision is one
// thing — either this process has a mail path or it does not — and a caller that
// checked three fields could get a combination this service does not allow.
func (c Config) CourierEnabled() bool {
	return c.CourierBaseURL != "" && c.CourierTokenValue != "" && c.RecoveryLinkTemplate != ""
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

	if err := cfg.loadMFA(lookup); err != nil {
		return Config{}, err
	}

	if err := cfg.loadCourier(lookup); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// loadMFA reads the MFA block.
//
// The asymmetry with the OIDC block above is deliberate and is the whole of this
// function: OIDC's three variables are all-or-nothing because a provider with an
// issuer and no key is a broken provider, whereas MFA's single variable has a
// SUPPORTED absent state — a deployment that has not turned a second factor on.
//
// That is the only thing absent means here. Present-but-unreadable is still a
// startup failure, because a deployment that believes it has a key and has one
// that does not decode would lock every enrolled user out at their second factor
// and tell nobody why.
//
// MFA_ISSUER is the exception to "absent is supported": absent means the default
// label, because it is a display string and not a secret, and a default is what a
// display string wants.
func (c *Config) loadMFA(lookup Lookup) error {
	c.MFAIssuerLabel = DefaultMFAIssuer
	if issuer := lookupValue(lookup, "MFA_ISSUER"); issuer != "" {
		c.MFAIssuerLabel = issuer
	}

	encoded := lookupValue(lookup, "MFA_ENCRYPTION_KEY")
	if encoded == "" {
		return nil
	}

	// base64url, no padding — the same shape as every other secret this service
	// takes, so an operator pasting from the same secret store as
	// OIDC_SIGNING_KEY does not have to think about it.
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("%w: it is not base64url: %v", ErrInvalidMFA, err)
	}
	c.MFAEncryptionKeyValue = decoded
	return nil
}

// loadCourier reads and validates the courier block.
//
// IT MIRRORS `loadOIDC`'s all-or-nothing rule and for the same reason: three
// variables that only make sense together, and a partial block is a deployment that
// believes it can send mail.
//
// Absent is supported. All three unset is a process with no mail path, which is a
// legitimate deployment — a local stack, or one where courier is not deployed yet —
// and it mounts `recovery.Unavailable{}` so every route that needs a message answers
// 503 with a sentence saying why.
//
// The base URL is checked HERE rather than by the courier client. That is the whole
// point of loading it at boot: a URL that does not parse is a typo, and a typo found
// by the first user's password reset is a typo found in front of somebody who cannot
// sign in.
func (c *Config) loadCourier(lookup Lookup) error {
	baseURL := lookupValue(lookup, "COURIER_BASE_URL")
	token := lookupValue(lookup, "COURIER_TOKEN")
	linkTemplate := lookupValue(lookup, "RECOVERY_LINK_TEMPLATE")

	present := 0
	for _, value := range []string{baseURL, token, linkTemplate} {
		if value != "" {
			present++
		}
	}
	if present == 0 {
		return nil
	}
	if present != 3 {
		return fmt.Errorf("%w: COURIER_BASE_URL, COURIER_TOKEN and RECOVERY_LINK_TEMPLATE "+
			"must all be set, or none of them", ErrInvalidCourier)
	}

	if err := validateMailBaseURL(baseURL); err != nil {
		return err
	}
	if err := validateRecoveryLinkTemplate(linkTemplate); err != nil {
		return err
	}

	c.CourierBaseURL = baseURL
	c.CourierTokenValue = token
	c.RecoveryLinkTemplate = linkTemplate
	return nil
}

// validateMailBaseURL refuses a courier address that is not one.
//
// IT IS DUPLICATED RATHER THAN CALLED because the rule is identity's at boot and
// `internal/courier`'s at construction, and the two must be true independently: this
// service should refuse to start on a bad URL whether or not a courier client is
// built, and the client should refuse to exist on one whether or not something else
// validated it. `TestTheBootRulesAndTheClientRulesAgree` holds them in step.
func validateMailBaseURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("%w: COURIER_BASE_URL is not a URL: %v", ErrInvalidCourier, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%w: COURIER_BASE_URL scheme is %q, want https",
			ErrInvalidCourier, parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%w: COURIER_BASE_URL has no host", ErrInvalidCourier)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		// A base URL with a query is a base URL somebody is about to concatenate a
		// path onto, and the result is a request whose query this service did not
		// write.
		return fmt.Errorf("%w: COURIER_BASE_URL has a query or a fragment", ErrInvalidCourier)
	}
	return nil
}

// validateRecoveryLinkTemplate refuses a template that cannot produce a link a
// person can follow.
//
// THE PLACEHOLDER IS REQUIRED and the check runs against a SUBSTITUTED copy rather
// than the raw string, because `{token}` is not a legal URI character: validating
// the template as written would let through a shape courier's `format: uri` rejects
// once the real token is in it.
func validateRecoveryLinkTemplate(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if !strings.Contains(trimmed, recoveryTokenPlaceholder) {
		return fmt.Errorf("%w: RECOVERY_LINK_TEMPLATE has no %s in it, so a reset link "+
			"would carry no token", ErrInvalidCourier, recoveryTokenPlaceholder)
	}
	probe := strings.ReplaceAll(trimmed, recoveryTokenPlaceholder, "6f5d4c3b-2a19-4e8f-9c07-1b2d3e4f5061")
	parsed, err := url.Parse(probe)
	if err != nil {
		return fmt.Errorf("%w: RECOVERY_LINK_TEMPLATE is not a URL: %v", ErrInvalidCourier, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%w: RECOVERY_LINK_TEMPLATE scheme is %q, want https",
			ErrInvalidCourier, parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%w: RECOVERY_LINK_TEMPLATE has no host", ErrInvalidCourier)
	}
	if parsed.Fragment != "" {
		// A fragment is not sent to a server, so a token in one reaches a browser
		// and never the screen that redeems it.
		return fmt.Errorf("%w: RECOVERY_LINK_TEMPLATE has a fragment; a mail client "+
			"does not send one to a server", ErrInvalidCourier)
	}
	if parsed.User != nil {
		return fmt.Errorf("%w: RECOVERY_LINK_TEMPLATE has a userinfo section", ErrInvalidCourier)
	}
	return nil
}

// recoveryTokenPlaceholder is the marker a link template must contain.
//
// IT IS DECLARED HERE AND NOT IMPORTED FROM `internal/courier` because the
// dependency runs the other way: `internal/courier` implements
// `recovery.Mailer` and this package is the service's configuration. Duplicating one
// constant is cheaper than an import that inverts the layering, and
// `TestTheBootPlaceholderIsCouriersPlaceholder` holds the two in step.
const recoveryTokenPlaceholder = "{token}"

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
