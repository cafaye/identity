package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/cafaye/identity/internal/platform/id"
)

// The OIDC client: the credential a product presents at the token endpoint, and
// the three lists that decide what that credential may be used for.
//
// It is a domain type with no protocol methods. The op.Client implementation
// lives in storage.go, wrapped around this, so that a change to what identity
// stores and a change to what the library asks for are two edits in two files
// rather than one edit in a file that has to be read against a third-party
// interface to be understood.

// Errors the use cases and the store return. Callers match them with errors.Is.
var (
	// ErrNotFound means no registration with that client_id. It is deliberately
	// the same error for "never existed" and "was deleted", and the token
	// endpoint renders both the same way, so a caller cannot use it to discover
	// which client ids are real.
	ErrNotFound = errors.New("oidc client not found")
	// ErrRevoked means the registration exists and has been revoked. It is a
	// distinct error because an operator debugging a broken integration needs to
	// be able to tell it from a typo, and it never reaches an anonymous caller:
	// the token endpoint collapses it into the same 400 as every other refusal.
	ErrRevoked = errors.New("oidc client is revoked")
	// ErrInvalidSecret means the presented secret does not match the stored
	// digest. Same reasoning as ErrRevoked: distinct internally, one answer
	// outside.
	ErrInvalidSecret = errors.New("oidc client secret is invalid")
)

// Field validation codes. They land verbatim in the `errors[]` array of the
// cafaye error envelope, so they are part of the contract.
const (
	CodeRequired          = "required"
	CodeInvalidFormat     = "invalid_format"
	CodeTooMany           = "too_many"
	CodeUnsupported       = "unsupported"
	CodeOpenIDRequired    = "openid_required"
	CodeDuplicateClientID = "duplicate_client_id"
	CodeAlreadyRevoked    = "already_revoked"
)

// FieldError is a per-field validation failure, rendered as one entry of a
// 422's errors[].
type FieldError struct {
	Field string
	Code  string
}

func (e *FieldError) Error() string { return fmt.Sprintf("%s: %s", e.Field, e.Code) }

func fieldErr(field, code string) error { return &FieldError{Field: field, Code: code} }

const (
	// clientIDBytes is the entropy of a client id. 32 bytes is 256 bits — the
	// same budget as a session token, for the same reason: the client id is
	// half of a credential pair, and it appears in an Authorization header on
	// every token request, so it has to be unguessable rather than merely
	// unique. A sequential or derived id would be a free oracle for "which
	// products run on this platform".
	clientIDBytes = 32

	// MaxRedirectURIs bounds the registration. Ten origins is more than any
	// product needs — a web app, a mobile app and a couple of staging
	// environments — and the bound is what stops a registration from becoming an
	// unbounded allow-list that a later reviewer skims past.
	MaxRedirectURIs = 10
)

// The grant types this provider implements.
//
// A client may register `authorization_code` and nothing else. See
// ValidateGrantTypes for why each of the others is absent rather than merely
// unimplemented.
const (
	GrantAuthorizationCode = "authorization_code"
	GrantRefreshToken      = "refresh_token"
	GrantClientCredentials = "client_credentials"
	GrantImplicit          = "implicit"
)

// Client is one OIDC registration.
type Client struct {
	// ID is the row's uuid. It is the event subject and nothing else: the value
	// a relying party presents is ClientID, and conflating the two is how a
	// consumer ends up correlating on something it cannot look up.
	ID id.UUID
	// AccountID is the account that owns the registration, and the account whose
	// owner is the only caller allowed to create or revoke it.
	AccountID id.UUID
	// ClientID is the public, protocol-visible handle. Random, 32 bytes,
	// base64url.
	ClientID string
	// SecretDigest is the lower-case hex SHA-256 of the client secret. The secret
	// itself is never stored and is returned exactly once, by Register.
	SecretDigest string
	// RedirectURIs is the allow-list, matched EXACTLY. No glob, no prefix, no
	// pattern of any kind: the library offers a glob-matching client interface
	// and this service deliberately does not implement it.
	RedirectURIs []string
	// GrantTypes is what this client may ask for. Always a subset of
	// SupportedGrantTypes.
	GrantTypes []string
	// Scopes is what this client may be granted. A subset of SupportedScopes,
	// and always including openid.
	Scopes    []string
	CreatedAt time.Time
	RevokedAt *time.Time
	CreatedBy id.UUID
	RevokedBy *id.UUID
}

// IsActive reports whether the registration may still be used.
func (c Client) IsActive() bool { return c.RevokedAt == nil }

// AllowsRedirectURI reports whether a redirect URI is on the allow-list.
//
// An exact string comparison, and that is the whole point. The library's
// checkURIAgainstRedirects asks the same question with slices.Contains before it
// considers the optional glob interface, so a client that does not implement
// op.HasRedirectGlobs can only ever be matched exactly. The prefix case
// `https://app.example.com.evil.com/cb` against a registered
// `https://app.example.com/cb` is the test that holds this line, and it is in
// the test suite rather than in a comment.
func (c Client) AllowsRedirectURI(candidate string) bool {
	return slices.Contains(c.RedirectURIs, candidate)
}

// AllowsScope reports whether this client may be granted a scope.
func (c Client) AllowsScope(scope string) bool { return slices.Contains(c.Scopes, scope) }

// NewClientCredentials mints a client id and a client secret.
//
// Both are 32 random bytes, base64url. The id is a handle that has to be
// unguessable because it is half of the credential pair on the token endpoint;
// the secret is a bearer credential that a database dump must not yield. They
// are generated together and returned together because the caller needs the id
// to put in a response body and the secret to hand over once, and a function
// returning only one of them is a function that will eventually return the wrong
// one.
func NewClientCredentials() (clientID, secret string, err error) {
	rawID, err := randomBytes(clientIDBytes)
	if err != nil {
		return "", "", fmt.Errorf("oidc: minting a client id: %w", err)
	}
	rawSecret, err := randomBytes(clientIDBytes)
	if err != nil {
		return "", "", fmt.Errorf("oidc: minting a client secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(rawID), base64.RawURLEncoding.EncodeToString(rawSecret), nil
}

// SecretDigest is the value stored in oidc_clients.secret_digest: the lower-case
// hex SHA-256 of the presented secret.
//
// SHA-256 rather than argon2id, and internal/sessions/token.go is the precedent
// and the argument: argon2id exists to make GUESSING expensive, and a 256-bit
// random value has no guessable structure for it to slow down. A memory-hard
// hash on this column would cost tens of milliseconds on every single token
// request across the platform and buy nothing. The rule that matters on both
// columns is the one that holds everywhere in this service — the presented value
// is never stored, so a dump of the table is not a set of credentials.
//
// The comparison is an indexed equality in SQL, as it is for session tokens, and
// the same reasoning covers it: the length is not secret and an unmatched lookup
// is an ordinary indexed read.
func SecretDigest(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// randomBytes reads n bytes from crypto/rand.
//
// A failure is returned rather than swallowed, as everywhere else in this
// service: a degraded entropy source is not something to discover when a
// credential turns out to be guessable.
func randomBytes(n int) ([]byte, error) {
	raw := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return nil, fmt.Errorf("reading random bytes: %w", err)
	}
	return raw, nil
}

// ValidateRedirectURIs checks and normalizes a registration's allow-list.
//
// Three rules, each of which would otherwise be a hole:
//
//   - at least one and at most MaxRedirectURIs. A client with no allow-list can
//     be sent anywhere; a client with two hundred is an allow-list nobody reads.
//   - absolute, https, no fragment, no wildcard. A wildcard turns the exact
//     match in AllowsRedirectURI into a suggestion.
//   - http only on loopback. The library permits any registered http URI for a
//     confidential client, which is the library's call to make about a
//     registration it did not write; refusing here means a plain-http origin
//     never reaches the table, and a product developing against a local parlor
//     still works.
func ValidateRedirectURIs(give []string) ([]string, error) {
	if len(give) == 0 {
		return nil, fieldErr("redirect_uris", CodeRequired)
	}
	if len(give) > MaxRedirectURIs {
		return nil, fieldErr("redirect_uris", CodeTooMany)
	}

	out := make([]string, 0, len(give))
	for _, raw := range give {
		trimmed := strings.TrimSpace(raw)
		if err := validateRedirectURI(trimmed); err != nil {
			return nil, err
		}
		if !slices.Contains(out, trimmed) {
			out = append(out, trimmed)
		}
	}
	// Sorted so the column, the event payload and the OpenAPI example are the
	// same on every registration of the same set.
	slices.Sort(out)
	return out, nil
}

func validateRedirectURI(raw string) error {
	invalid := fieldErr("redirect_uris", CodeInvalidFormat)

	if raw == "" {
		return invalid
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return invalid
	}
	// A relative reference, or one with no host, is not somewhere a browser can
	// be sent.
	if !parsed.IsAbs() || parsed.Host == "" {
		return invalid
	}
	// The authorization response is appended to the query string, so a fragment
	// on the registered URI would end up somewhere the client never reads.
	if parsed.Fragment != "" {
		return invalid
	}
	// "https://*.example.com/cb" parses as a host with a literal asterisk. There
	// is no glob anywhere in this service's matching, so a registered asterisk
	// would be a URI that simply never matches — which reads as a working
	// configuration and is not one.
	if strings.ContainsAny(parsed.Host, "*") {
		return invalid
	}

	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(parsed.Hostname()) {
			return nil
		}
		return invalid
	default:
		// A custom scheme is a native client, and a native client cannot keep a
		// secret, which this registration model requires. Mobile and desktop
		// products use PKCE with a public client, and that is a different table
		// in a later packet.
		return invalid
	}
}

// isLoopbackHost reports whether host names the loopback interface.
//
// "localhost" is accepted alongside the addresses because that is the name
// products actually register during development, and because a name is resolved
// by the browser rather than by this service: nothing here dials it. That is
// also why it is safe to accept by name — a registration is a string in a
// table, not a connection.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

// ValidateGrantTypes checks and normalizes the grant list.
//
// Only `authorization_code` is implemented, and the absence of the others is a
// decision rather than a gap:
//
//	refresh_token       no refresh token store exists; a token that cannot be
//	                    refreshed is not a refresh token
//	client_credentials  no service identity to authenticate as
//	implicit            the brief's flow is code + PKCE, and an implicit token
//	                    arrives in a URL fragment, which is a worse place for a
//	                    credential than a POST body
//
// A product configured with a grant this service does not implement gets a 422
// naming the field at registration time, which is a better outcome than a
// 400 `unsupported_grant_type` discovered during an outage.
func ValidateGrantTypes(give []string) ([]string, error) {
	if len(give) == 0 {
		return nil, fieldErr("grant_types", CodeRequired)
	}
	out := make([]string, 0, len(give))
	for _, raw := range give {
		trimmed := strings.TrimSpace(raw)
		if !slices.Contains(SupportedGrantTypes, trimmed) {
			return nil, fieldErr("grant_types", CodeUnsupported)
		}
		if !slices.Contains(out, trimmed) {
			out = append(out, trimmed)
		}
	}
	slices.Sort(out)
	return out, nil
}

// SupportedGrantTypes is what ValidateGrantTypes accepts.
var SupportedGrantTypes = []string{GrantAuthorizationCode}

// ValidateRegistrationScopes checks and normalizes a registration's scope list.
//
// Unlike the authorization endpoint, this one CURATES rather than refuses: a
// product registering itself asks for what it would like, and the operator
// decides what it gets. Unsupported names are dropped so the column cannot
// accumulate a promise this service does not keep, and `openid` is required
// because a client that cannot ask for openid gets tokens with no identity in
// them.
func ValidateRegistrationScopes(give []string) ([]string, error) {
	scopes := NormalizeScopes(give)
	if !slices.Contains(scopes, ScopeOpenID) {
		return nil, fieldErr("scopes", CodeOpenIDRequired)
	}
	if len(scopes) == 0 {
		return nil, fieldErr("scopes", CodeRequired)
	}
	return scopes, nil
}
