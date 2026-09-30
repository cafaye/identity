package apikeys

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/cafaye/identity/internal/platform/id"
)

// THE CLAIM DOCUMENT: what identity publishes about a token to whoever has to
// enforce it.
//
// IT EXISTS BECAUSE THIS TOKEN IS OPAQUE. Every other credential identity mints
// carries its own claims: the OIDC access token is a JWT and the claims are in
// it, readable by anybody holding the published JWKS with no call back to here.
// This one is `cafaye_` plus 32 random bytes, and the row holds a SHA-256 of it —
// so a resource server learns what a token may do by ASKING, and this file is the
// answer. There is no second way to read a scope off this credential.
//
// # TWO NAMES, DELIBERATELY, AND THIS IS AN INTERIM
//
// The claim is emitted TWICE — as `scopes` and as `scope` — and that is not a
// typo, not a compatibility shim somebody forgot to remove, and not this service
// having an opinion about the specification. The fleet does not agree on the
// name:
//
//	core/docs/openapi-conventions.md:134 requires a claim named `scopes`.
//	guard/src/middleware/jwt.ts:32 reads `scope`, splits it on whitespace, and
//	treats an absent claim as an empty set.
//
// The question is recorded as MD7 in the manager's DECISIONS.md and it is OPEN.
// It has been written down twice before, by `guard-02` and by `cafaye-rb-01`,
// and answered neither time. Picking a side here would mint credentials into a
// contract that does not exist yet, and the cost of being wrong is a rotation of
// every credential already in a customer's hand.
//
// So both names are emitted, byte for byte identical, and
// TestTheTwoScopeClaimNamesAreEqual holds that they cannot drift. Whichever name
// MD7 settles on, the other is a one-line deletion from this file and a token
// already in a customer's hand keeps working through the change. TWO NAMES IS NOT
// A CONTRACT. It is the cost of not rotating credentials over an unanswered
// question.
//
// The SHAPE is a space-separated string, not an array, and that is not a
// third opinion — it is the one shape both sides can read. guard's
// `principalOf` does `raw.split(/\s+)` and rejects a non-string claim outright, so
// an array is a token guard refuses to parse at all; and core's own example is a
// capability string (`invoices:write`). RFC 8693's token-introspection response
// says the same thing.
//
// # account_id IS REQUIRED AND THERE IS NO sub FALLBACK
//
// core's rule is that "every query is scoped by `account_id` from the token,
// never from the request body", and that makes `account_id` the floor rather than
// an extra. A token with no `account_id` is refused: ClaimsFor returns
// ErrNoAccountID, and the response is inactive.
//
// The alternative — falling back to `sub`, which is what guard's `limitKey` does
// today — would give a service-to-service token a USER as its tenancy key. Two
// consequences, and the second is the one that matters: a service holding a
// user-scoped key can read that user's rows across every account they belong to,
// and a bug in one service that keys on `sub` becomes a cross-tenant read rather
// than a 403. "Refuse it" costs a client one integration fix; "default it" costs
// a data breach, and the default is invisible until it is exploited.
//
// Whether guard's fallback is safe is a SEPARATE and more serious open question
// (MD8 in the manager's DECISIONS.md, proposed but not written up), and it is not
// decided here. What is decided here is that identity never produces a token that
// relies on it.

// ErrNoAccountID means a claim document was asked for from a token with no
// account, and one was refused rather than defaulted.
//
// It cannot come from a row — account_id is NOT NULL — so it is a guard on a
// future caller that assembles a Claims from something other than a stored key,
// and it is worth having because the failure it prevents is a cross-tenant read
// rather than a missing field.
var ErrNoAccountID = errors.New("an api key claim document requires an account_id and this token has none")

// ClaimNames are the two names this service publishes a token's capability set
// under, and the first one is the primary.
//
// They are constants rather than literals in the struct tags because the equality
// between them is a test and a test needs to name them.
const (
	// ClaimScopes is the primary name, and the one core's conventions require.
	ClaimScopes = "scopes"
	// ClaimScope is the exact mirror, and the one guard's middleware reads. See
	// the file comment: this is an interim pending MD7, not a contract.
	ClaimScope = "scope"
	// ClaimAccountID is the tenancy claim, and it is required.
	ClaimAccountID = "account_id"
)

// Claims is what a resource server is told about a token.
//
// Active is first and it is the load-bearing field. RFC 7662 says an
// introspection response for a token that is not usable is `{"active": false}`
// and nothing else, and the reason is the same one this package's ErrNotFound
// exists for: a response that distinguished "revoked" from "never existed" tells
// an attacker whether a leaked value was live, which is the second question they
// ask after "does this work". Every other field is zero when Active is false.
type Claims struct {
	Active bool `json:"active"`

	// Subject is `sub`, and it is the USER the token names — not the account. The
	// account is ClaimAccountID and is never derived from this.
	Subject string `json:"sub,omitempty"`
	// AccountID is `account_id`, required, and the tenancy boundary for every
	// query a resource server makes on the token's behalf.
	AccountID string `json:"account_id,omitempty"`
	// Scopes is the capability set as a space-separated string, and Scope is an
	// exact mirror of it. See the file comment; one of the two is coming out.
	Scopes string `json:"scopes,omitempty"`
	Scope  string `json:"scope,omitempty"`

	// TokenID is `jti`: the row's own id, which is what a consumer correlates on
	// and what an operator revokes by.
	TokenID string `json:"jti,omitempty"`
	// Name is the credential's name. A consumer auditing which credential is in
	// play needs it, and a token whose name nobody can read is one nobody can
	// revoke.
	Name string `json:"name,omitempty"`
	// Role is the owner's LIVE membership role, read at the instant of the claim
	// rather than snapshotted at issue. It is here for an operator reading the
	// response and is NOT an authorization input: core's rule is that services
	// check scopes and ask identity, and a role in a claim is a role a service
	// might start branching on.
	Role string `json:"role,omitempty"`

	IssuedAt  int64 `json:"iat,omitempty"`
	ExpiresAt int64 `json:"exp,omitempty"`
	// LastUsedAt is Unix seconds, and absent when the token has never been used.
	LastUsedAt int64 `json:"last_used_at,omitempty"`
}

// ClaimsFor renders the claim document for a live token.
//
// A revoked or expired token is not an error here: it is an inactive claim
// document, which is what a resource server needs to say so rather than to fail.
// A token with no account is ErrNoAccountID, which the caller renders as inactive
// too — and the reason is the one in the file comment: a token with no tenancy key
// cannot be used against any account, so "inactive" is the true answer and a
// document with a defaulted `sub` would not be.
func ClaimsFor(k Key, now time.Time) (Claims, error) {
	if k.AccountID.IsZero() {
		return Claims{}, ErrNoAccountID
	}
	if k.IsRevoked() || k.IsExpired(now) {
		return Claims{Active: false}, nil
	}

	// Sorted, so two calls for the same row produce byte-identical documents. A
	// resource server that caches on the claim's bytes must not see two shapes for
	// one credential, and a map's iteration order would do exactly that.
	scopes := slices.Clone(k.Scopes)
	slices.Sort(scopes)
	joined := strings.Join(scopes, " ")

	return Claims{
		Active:    true,
		Subject:   k.UserID.String(),
		AccountID: k.AccountID.String(),
		Scopes:    joined,
		Scope:     joined,
		TokenID:   k.ID.String(),
		Name:      k.Name,
		Role:      string(k.Role),
		IssuedAt:  k.CreatedAt.UTC().Unix(),
		ExpiresAt: k.ExpiresAt.UTC().Unix(),
	}, nil
}

// Document renders the claims as a map, for a consumer that wants to merge them
// into something else — a JWT, a log record, a proxy's context.
//
// IT IS DELIBERATELY NOT THE ONLY WAY OUT. Claims has JSON tags, so the common
// case is to hand the struct to an encoder; Document exists so that a caller
// building a map does not have to remember which two fields are mirrors, and a
// hand-written map here is exactly how the two names would drift apart.
func (c Claims) Document() map[string]any {
	doc := map[string]any{"active": c.Active}
	if !c.Active {
		return doc
	}
	doc["sub"] = c.Subject
	doc[ClaimAccountID] = c.AccountID
	doc[ClaimScopes] = c.Scopes
	doc[ClaimScope] = c.Scope
	doc["jti"] = c.TokenID
	doc["name"] = c.Name
	doc["role"] = c.Role
	doc["iat"] = c.IssuedAt
	doc["exp"] = c.ExpiresAt
	if c.LastUsedAt != 0 {
		doc["last_used_at"] = c.LastUsedAt
	}
	return doc
}

// InactiveClaims is the answer for a token nobody may be told about.
//
// It is a function rather than a variable so a caller cannot mutate the one value
// every inactive response shares, and it exists so the inactive shape is written
// down once — a hand-written `{"active": false}` in each handler is how one of
// them ends up carrying a `sub`.
func InactiveClaims() Claims { return Claims{Active: false} }

// String renders the claim document for a log line, and it is the ONLY place a
// token's scopes become a string in this service outside the wire.
//
// The reason it exists at all is that fmt on a struct would print every field
// including the subject and the token id, and a log line is the most-read copy of
// anything this process writes. This one prints the claim NAMES and the two scope
// strings and nothing else.
func (c Claims) String() string {
	if !c.Active {
		return "apikeys.claims{active=false}"
	}
	return fmt.Sprintf("apikeys.claims{active=true account_id=%s jti=%s %s=%q %s=%q}",
		c.AccountID, c.TokenID, ClaimScopes, c.Scopes, ClaimScope, c.Scope)
}

// ResolveAccountID is the tenancy key, and it never falls back.
//
// IT IS A SEPARATE FUNCTION rather than an expression at each use so the rule is
// testable on its own and so there is one place a future change would have to
// touch. A credential with no account is refused; the error is ErrNoAccountID and
// not a fabricated id, because a fabricated id is a cross-tenant read waiting for
// a request.
func ResolveAccountID(c Claims) (id.UUID, error) {
	if c.AccountID == "" {
		return id.UUID{}, ErrNoAccountID
	}
	parsed, err := id.Parse(c.AccountID)
	if err != nil {
		return id.UUID{}, ErrNoAccountID
	}
	return parsed, nil
}
