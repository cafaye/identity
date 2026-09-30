// Package apikeys is the scoped API token: the credential that is not a browser
// session.
//
// A SESSION IS BROWSER-SHAPED AND AN API KEY IS NOT, and every decision in this
// package follows from that difference rather than from the two being two
// flavours of the same thing:
//
//   - a session expires in weeks, is created by a password and a second factor,
//     and lives in a `__Host-` cookie this service sets and the browser enforces;
//   - an api key expires in months, is created by a signed-in user, and lives in
//     a CI variable, a script's environment, and — eventually — somebody's shell
//     history and a paste buffer.
//
// THE TWO RULES THAT FALL OUT OF IT.
//
// ONE. A token's authority is NOT ITS SCOPES ALONE. A token names a user and an
// account, and every request it makes is re-evaluated against that user's
// CURRENT membership in that account: a role removed after the token was issued
// stops it working on the next request, with no cache to expire and nothing to
// sweep. That is the difference between a token and a permission, and it is the
// answer to "a token outlives the permission that made it". It is enforced by
// this package having no authorization logic of its own — the routes already ask
// the tenancy service what the caller's role is, and a token is just another way
// of naming a caller. See internal/httpapi's accountAccess.
//
// TWO. A token is a FIRST-PARTY credential for a MACHINE, so it is never minted,
// rotated or revoked by the OIDC surface and never exchanged for a JWT. The
// OIDC provider exists for third parties holding a browser; routing an api key
// through it would give a machine credential a refresh token, an id_token and a
// consent screen it has no use for.
//
// WHAT IS STORED IS THE DIGEST AND NEVER THE VALUE, for the reason
// internal/sessions/token.go gives, and the reading of that reason HERE is
// deliberately different from the session's:
//
//	a session is presented once a minute and lives a fortnight, so the argument
//	was "a slow hash costs every request tens of milliseconds and buys nothing".
//
//	an api key is presented on every request of a deploy and lives a quarter, so
//	the same conclusion holds for a second reason that does not hold for a
//	session: a credential this long-lived is one somebody will stop thinking
//	about, and the property that makes a leaked one survivable is not how hard
//	the digest is to invert — it is that the credential can be REVOKED, and that
//	the plaintext was never anywhere for a backup to pick up. SHA-256 of a
//	256-bit random value is not a secret even to somebody holding both the row
//	and the source code.
package apikeys

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
)

// Prefix is what every credential this platform issues begins with.
//
// IT IS A FEATURE AND THE FEATURE IS RECOGNITION. A secret that leaks — into a
// CI log, a shell history, a support ticket, a screenshot, a paste buffer — is
// recognised as a cafaye credential by its first seven characters, which turns
// "somebody has to guess which of these strings is a working key" into a grep.
// It is the same reason the OIDC client id is 32 random bytes rather than a
// counter, and the same reason guard's api key carries a prefix: a credential
// you cannot recognise is a credential you cannot revoke in time.
//
// It is the PREFIX of the value rather than a separator somewhere in the middle
// because a scanner that looks at the first bytes is looking at the bytes a
// truncated log line is most likely to have kept.
const Prefix = "cafaye_"

// SecretBytes is the entropy behind the prefix.
//
// 256 bits, which is the same budget as a session token, an invitation token and
// an OIDC client secret, and for the same reason: none of them are the weak link,
// and a credential this service issues is never guessable by anything that can
// do arithmetic in the time the universe has left.
//
// It is deliberately not larger. The prefix is public and the secret's job is to
// be unguessable; 256 bits is already past every physical attack that could ever
// be mounted against a running process, and a 512-bit token is a longer thing to
// paste, log and truncate.
const SecretBytes = 32

// DefaultTTL is how long a token lives when the caller does not say.
//
// NINETY DAYS, and the number is a judgement about two failure modes rather than
// a round number chosen for looks:
//
//   - long enough that a CI job somebody set up in a hurry does not fail on a
//     Tuesday three months later and get "just make a new one" as the answer to
//     a question they cannot ask;
//   - short enough that "we rotated our tokens" is a thing that happens without
//     anybody having to decide to make it happen.
//
// A permanent credential has no such moment. That is the whole of the expiry
// decision, and this constant is where it lives.
const DefaultTTL = 90 * 24 * time.Hour

// MaxTTL is the ceiling.
//
// A year, enforced here AND by the table's `api_keys_maximum_lifetime` CHECK, so
// a caller that reaches the database without the service cannot write a longer
// one. Two statements of one policy is the arrangement the OIDC access-token
// migration already uses, and the reason is that the drift between a constant in
// Go and a policy in SQL is always in the direction of the credential outliving
// its own rules.
const MaxTTL = 365 * 24 * time.Hour

// MinTTL is the floor: an hour.
//
// It exists for one case — a caller who meant "as long as possible" and typed
// something small — and the answer is a 422 rather than a credential that stops
// working between the 201 and the first request. An hour is long enough that a
// token minted at this floor has been used at least once.
const MinTTL = 24 * time.Hour

// LastUsedResolution is how stale `last_used_at` is allowed to get.
//
// FIVE MINUTES, and the number is a statement about writes rather than about
// time. A CI token at a thousand requests a second must not put a thousand
// UPDATE round trips a second on one row: a single row's lock is a queue, and a
// queue on the hot path of every authenticated machine request is a
// self-inflicted denial of service against the credential's own owner. The
// column is therefore advanced at most once every five minutes, and the cost is
// that it is accurate to within five minutes — which is written on the column
// in the migration rather than discovered by somebody who needed the second.
const LastUsedResolution = 5 * time.Minute

// The scope vocabulary.
//
// FOUR NAMES, and every one of them is a capability an EXISTING route already
// enforces a different way. That is the test of a real scope: it names something
// this service actually does, and removing it removes access to something that
// exists. A scope for a capability this service does not have is a promise about
// the future, and a promise is not a control.
//
// THE SHAPE IS core's: "Authorization: `scopes` for capability (`invoices:
// write`)" — docs/openapi-conventions.md. The names are this service's own
// surface, read off openapi/v1.yaml rather than invented:
//
//	accounts:read          the tenancy reads: list the caller's accounts, read
//	                       one, read its member list. The default a CI job needs
//	                       and the one that leaks the least.
//	accounts:write         create an account, rename it, invite somebody, change
//	                       a role, remove a member, redeem an invitation.
//	accounts:delete        delete the account itself. Separate from write
//	                       because it is the only one of these that cannot be
//	                       undone and because the route's minimum role is owner
//	                       where everything else is admin — a token carrying
//	                       accounts:write and held by a member is refused on the
//	                       role check, and one held by an owner should still have
//	                       to say so.
//	oidc_clients:write     register, read and revoke the account's OpenID
//	                       Connect registrations.
//
// WHAT IS NOT IN THE LIST IS THE MOST IMPORTANT PART OF IT, and every one of
// these is a refusal rather than an oversight:
//
//	there is NO scope for the second factor. A token cannot read whether an
//	account has MFA, enrol one, rotate one, or turn one off — and that is not a
//	gap in the vocabulary, it is the reason the vocabulary is safe. A machine
//	credential that could disable a second factor is a credential whose theft is
//	a downgrade rather than a break-in, and the routes refuse a token outright
//	rather than consulting a scope list.
//
//	there is NO scope for sessions. A token cannot mint, read or revoke a
//	browser session, and it cannot complete a second-factor login.
//
//	there is NO scope that means "everything". Not `*`, not `accounts:*`, not a
//	scope named `admin`. A token is granted the scopes it names, so "read this
//	account" and "delete this account" are two decisions a person makes twice.
//
// AND NOT ONE OF THEM GRANTS TENANCY. Scopes are capability; the account a
// token may act on is the account it was minted for, and a token presented
// against a different one is refused even if it holds every scope in this list.
// core: "Every query is scoped by `account_id` from the token, never from the
// request body."
const (
	// ScopeAccountsRead is the tenancy read surface.
	ScopeAccountsRead = "accounts:read"
	// ScopeAccountsWrite is every mutation of an account's membership and shape
	// except deleting the account.
	ScopeAccountsWrite = "accounts:write"
	// ScopeAccountsDelete is DELETE /v1/accounts/{accountID} and nothing else.
	ScopeAccountsDelete = "accounts:delete"
	// ScopeOIDCClientsWrite is the account's OpenID Connect registrations.
	//
	// READ AND WRITE IN ONE SCOPE, and the reason is that the two GET routes are
	// an owner's routes and their response is the integration's whole
	// configuration — client_id, redirect URIs, grant types. A separate
	// oidc_clients:read would be a scope nobody in this service has a use for,
	// and a scope nobody uses is one nobody tests.
	ScopeOIDCClientsWrite = "oidc_clients:write"
)

// AllScopes is the vocabulary, in a fixed order.
//
// A slice rather than a set for the reason internal/oidc's SupportedScopes is
// one: the order reaches an error message and a response, and a map's iteration
// order would make two identical requests answer differently.
func AllScopes() []string {
	return []string{ScopeAccountsRead, ScopeAccountsWrite, ScopeAccountsDelete, ScopeOIDCClientsWrite}
}

// IsSupportedScope reports whether this build implements a scope. Exact match,
// never a prefix: `accounts` is not `accounts:read`, and a comparison that
// accepted the first because it starts with the second would hand out a
// capability set nobody wrote down.
func IsSupportedScope(scope string) bool {
	return slices.Contains(AllScopes(), scope)
}

// Field validation codes. They land verbatim in the `errors[]` array of the
// cafaye error envelope, so they are part of the contract and clients may switch
// on them.
const (
	CodeRequired      = "required"
	CodeInvalidFormat = "invalid_format"
	CodeTooLong       = "too_long"
	CodeTooMany       = "too_many"
	CodeUnsupported   = "unsupported"
	CodeOutOfRange    = "out_of_range"
)

// MaxNameLength bounds api_keys.name. It is characters rather than bytes,
// matching the table's CHECK, because a name is typed by a person into a
// settings page and "my deploy key 🚀" is a name.
const MaxNameLength = 80

// MaxScopes bounds a single token's scope list.
//
// Eight, and the closed vocabulary has four names, so the ceiling exists only to
// stop a caller sending the list four thousand times. It is a DoS control on the
// request, not a policy.
const MaxScopes = 8

// FieldError is a per-field validation failure, rendered as one entry of a 422's
// errors[].
//
// Structurally the same type as users.FieldError and mfa.FieldError and
// deliberately a separate declaration in each package: the three do not depend
// on each other, and a shared one would be the first edge between them.
type FieldError struct {
	Field string
	Code  string
}

func (e *FieldError) Error() string { return fmt.Sprintf("%s: %s", e.Field, e.Code) }

func fieldErr(field, code string) error { return &FieldError{Field: field, Code: code} }

// NewToken mints an api key and the digest stored in its place.
//
// The pair is returned rather than a struct with an exported Token field, and it
// is the shape sessions.NewToken and accounts.NewToken both use, for the same
// reason: the two values go in opposite directions. The token reaches the client
// exactly once, in a 201 body, and the digest goes into the row and is never
// rendered anywhere. A struct with a `Token` field is a nudge towards a handler
// reaching for the wrong one.
func NewToken() (token, digest string, err error) {
	raw := make([]byte, SecretBytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		// Same reasoning as sessions.NewToken: a failure of crypto/rand means there
		// is no trustworthy entropy, and minting a credential from a degraded
		// source is not something to discover when it turns out to be guessable.
		return "", "", fmt.Errorf("reading random bytes for an api key: %w", err)
	}

	token = Prefix + base64.RawURLEncoding.EncodeToString(raw)

	return token, Digest(token), nil
}

// Digest is the value stored in api_keys.token_digest: the lower-case hex
// SHA-256 of the presented value, PREFIX INCLUDED.
//
// SHA-256 rather than argon2id, and the package comment says the whole of the
// argument; the load-bearing half is that argon2id makes GUESSING expensive and
// there is nothing here to guess. 256 bits of crypto/rand has no structure, so a
// memory-hard function over it buys nothing and would cost tens of milliseconds
// on every machine request across the platform.
//
// THE WHOLE VALUE IS HASHED, PREFIX AND ALL, and the reason is one of
// uniqueness rather than security: hashing the secret alone would mean the
// presented string and the stored digest were not the same shape, and two
// credential formats minting the same random bytes would produce the same
// digest. There is no attack there — the digests are not comparable across
// tables — and there is a real ambiguity, which is why this is a decision.
//
// A MALFORMED OR EMPTY VALUE STILL PRODUCES A WELL-FORMED DIGEST. That is the
// timing answer, and it is structural rather than a property of a comparison
// function: the store never sees the presented value at all, so a value of any
// length reaches the database as the same 64-character hex string, and the
// lookup it performs is an ordinary indexed equality in exactly one shape. There
// is no length comparison anywhere on this path for an early return to skip.
func Digest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// NormalizeName trims a caller-supplied name. It does not collapse internal
// whitespace: "CI  deploy" is a typo, and silently repairing it would store a
// name the caller did not choose.
func NormalizeName(name string) string { return strings.TrimSpace(name) }

// ValidateName checks a name and returns the normalized value.
//
// THREE RULES, and the third is the one that surprises people:
//
//	non-empty after trimming      an operator revokes by what they can read
//	within MaxNameLength          characters, because the column's CHECK counts
//	                              characters and a name that passes here and fails
//	                              there is a 500
//	no control characters         a name lands in a log line, a settings page and
//	                              an incident report, and a name carrying \n or \r
//	                              is three lines where somebody wrote one
func ValidateName(give string) (string, error) {
	normalized := NormalizeName(give)
	switch {
	case normalized == "":
		return "", fieldErr("name", CodeRequired)
	case len([]rune(normalized)) > MaxNameLength:
		return "", fieldErr("name", CodeTooLong)
	case hasControl(normalized):
		return "", fieldErr("name", CodeInvalidFormat)
	}
	return normalized, nil
}

// hasControl reports whether s holds a C0 or DEL control character. Tab and
// newline included: a newline in a name is a log-injection vector and a newline
// in a settings page is somebody else's row.
func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// ValidateScopes checks and normalizes a token's scope list.
//
// REFUSES rather than curates, which is the difference from internal/oidc's
// registration path and it is deliberate. A product registering itself asks for
// what it would like and an operator curates what it gets, so dropping an
// unsupported scope there is a convenience. Here the caller is asking for a
// credential RIGHT NOW: a CI job that asks for `accounts:admin` and silently
// receives `accounts:read` is a script that runs for a week and fails on the
// write it was written to do.
//
// Empty is refused rather than defaulted. A token with no scopes is a session
// that never expires, and it arrives as "the client did not send the field" —
// which is exactly how the dangerous case looks.
func ValidateScopes(give []string) ([]string, error) {
	if len(give) > MaxScopes {
		return nil, fieldErr("scopes", CodeTooMany)
	}

	out := make([]string, 0, len(give))
	for _, raw := range give {
		// Trim only. No case folding: `Accounts:Read` is a different string from
		// `accounts:read` and a parser that repaired it would make two answers to
		// the same question depending on who asked.
		scope := strings.TrimSpace(raw)
		if scope == "" {
			continue
		}
		if !IsSupportedScope(scope) {
			return nil, fieldErr("scopes", CodeUnsupported)
		}
		if !slices.Contains(out, scope) {
			out = append(out, scope)
		}
	}

	if len(out) == 0 {
		return nil, fieldErr("scopes", CodeRequired)
	}

	// Sorted so the column, the event payload and the OpenAPI example are the
	// same on every creation of the same set. The same rule as scopes.go.
	slices.Sort(out)
	return out, nil
}

// HasScope reports whether a granted set contains scope.
//
// EXACT MATCH, and it is the second place in this repository where a prefix
// comparison would be a vulnerability: `accounts` is not `accounts:read`, and a
// token created with a mangled scope name would otherwise receive the real one.
//
// An empty or nil set holds nothing, which is the direction that fails closed.
func HasScope(granted []string, scope string) bool {
	return slices.Contains(granted, scope)
}

// FirstUnsupported returns the first requested scope this build does not
// implement, or "" when they all are.
//
// The NAME comes back rather than a boolean because the caller of this is a 422
// naming the field, and "unknown scope" without the name leaves a developer
// editing a config file for an afternoon.
func FirstUnsupported(give []string) string {
	for _, raw := range give {
		scope := strings.TrimSpace(raw)
		if scope == "" {
			continue
		}
		if !IsSupportedScope(scope) {
			return scope
		}
	}
	return ""
}

// ResolveExpiry decides when a new credential stops working.
//
// THREE ANSWERS, and the absence of a fourth is the packet's expiry decision:
//
//	nil      DefaultTTL from created. The common case, and the one a client that
//	         does not care should not have to spell.
//	0 or <0  REFUSED. This is where "never expires" would have gone, and it is
//	         not here. A token that cannot expire is a permanent credential: it
//	         outlives the employee who minted it, the laptop it was on, and every
//	         incident it was leaked in.
//	> MaxTTL refused rather than clamped, so a client asking for ten years learns
//	         that ten years is not a thing rather than getting a year and finding
//	         out at the first expiry.
//
// The cost, stated because it is real: a CI credential that has to be replaced
// every quarter is friction on precisely the use case that motivates the
// feature. What it buys is a moment at which a credential nobody is using gets
// noticed, and `last_used_at` is how that moment is acted on rather than
// guessed at.
func ResolveExpiry(created time.Time, requested *time.Duration) (time.Time, error) {
	lifetime := DefaultTTL
	if requested != nil {
		lifetime = *requested
		switch {
		case lifetime <= 0:
			return time.Time{}, fieldErr("expires_in", CodeOutOfRange)
		case lifetime < MinTTL:
			return time.Time{}, fieldErr("expires_in", CodeOutOfRange)
		case lifetime > MaxTTL:
			return time.Time{}, fieldErr("expires_in", CodeTooLong)
		}
	}

	expiry := created.Add(lifetime)

	// Re-checked here rather than trusted from the branch above, because these
	// two constants and this package's caller all have a copy of the policy and
	// the copy in this function is the one the migration's CHECK was written
	// against.
	if expiry.After(created.Add(MaxTTL)) {
		return time.Time{}, fieldErr("expires_in", CodeTooLong)
	}

	return expiry, nil
}

// ErrNotFound means no live api key matches a presented value.
//
// It covers four situations that MUST be indistinguishable to the caller: no such
// token, a revoked token, an expired token, and a token whose user has since been
// deleted or removed from the account. One error, one status code, one response
// time — the same rule sessions.ErrNotFound follows and the same reason.
var ErrNotFound = errors.New("api key not found")

// ErrNotFound is a DECISION rather than a simplification, so it is worth saying
// what it hides. A caller who can tell "this token was revoked" from "this token
// never existed" learns whether a leaked value was live at the moment they tried
// it, which is the second question an attacker asks after "does this work".
