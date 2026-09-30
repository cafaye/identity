package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cafaye/identity/internal/accounts"
	"github.com/cafaye/identity/internal/apikeys"
	"github.com/cafaye/identity/internal/platform/id"
)

// The scoped API token surface: mint one, list an account's, withdraw one.
//
// THREE ROUTES, ACCOUNT-SCOPED, OWNER-ONLY, and every one of those words is a
// decision rather than a default:
//
//	owner-only    a machine credential outlives the session that made it and is
//	              exactly the thing a stolen password buys an attacker. "Can read
//	              the member list" is not authority to mint one, for the same
//	              reason registering an OIDC client is owner-only.
//	account-scoped  a token is minted FOR one account. core's rule is that
//	              "every query is scoped by account_id from the token, never from
//	              the request body", and the account here comes from the path while
//	              the token it will be presented with is bound to the account it
//	              was minted for — a token for another tenant is a 404, not a
//	              403.
//	session-only  a TOKEN may not reach this surface. There is no scope for it,
//	              and that is the point: a credential that can mint more
//	              credentials is a privilege-escalation path with a nice UI, and the
//	              route refuses a token outright rather than consulting a list.
//
// The scopes that a token DOES carry are enforced inside requireAccountRole, which
// every account-scoped route already goes through — so there is one gate and it
// reads both the caller's live role and the caller's scopes.

// APIKeys is the part of apikeys.Service the v1 routes need.
//
// An interface declared here, at the consumer, for the reason Auth and Tenancy are:
// the handlers can be tested against a programmable double, and the HTTP layer has
// no dependency on the use case's internals. Every method takes ids and a
// clock-free input, so there is no way for a handler to reach past the
// authorization decision into a query it wrote itself.
type APIKeys interface {
	Mint(ctx context.Context, in apikeys.MintInput) (apikeys.IssuedKey, error)
	List(ctx context.Context, accountID id.UUID) ([]apikeys.Key, error)
	Revoke(ctx context.Context, in apikeys.RevokeInput) (apikeys.Key, error)
}

// WithAPIKeys mounts the api key routes.
//
// It is an Option for the reason every other service here is one: with no
// DATABASE_URL there is no api_keys table, and that process must still answer
// /healthz. The routes are absent rather than present-and-500.
func WithAPIKeys(k APIKeys) Option {
	return func(o *options) {
		if k != nil {
			o.apiKeys = k
		}
	}
}

// registerAPIKeyRoutes mounts the surface on the account's.
//
// The minimum is owner, and the reason is the one at the top of this file. It is
// NOT the role any token could have: there is no scope that reaches this surface,
// so a token presenting here is refused before the role is consulted.
func (o options) registerAPIKeyRoutes(r chiRouter) {
	if o.apiKeys == nil {
		return
	}
	r.Post("/v1/accounts/{accountID}/api-keys", o.requireAccountRole(accounts.RoleOwner, o.handleMintAPIKey))
	r.Get("/v1/accounts/{accountID}/api-keys", o.requireAccountRole(accounts.RoleOwner, o.handleListAPIKeys))
	r.Delete("/v1/accounts/{accountID}/api-keys/{keyID}", o.requireAccountRole(accounts.RoleOwner, o.handleRevokeAPIKey))
}

// ---------------------------------------------------------------------------
// request and response shapes
// ---------------------------------------------------------------------------

// apiKeyResponse is a credential as the settings page sees it.
//
// NO `token` FIELD, and that is not an omission — it is the same rule the OIDC
// registration's `client_secret` follows. There is no column that holds the
// plaintext and no endpoint that re-reads one, so a response type that carried
// the field would be a type asserting something untrue. The create response below
// is the only one that has it.
//
// TokenDigest is absent for the same reason and one step further: a client has no
// use for it, and a response that echoed the row's most sensitive column would put
// it in a browser's network log for no benefit.
type apiKeyResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	AccountID string    `json:"account_id"`
	UserID    string    `json:"user_id"`
	Scopes    []string  `json:"scopes"`
	ExpiresAt time.Time `json:"expires_at"`
	// CreatedAt and LastUsedAt are what an operator reads to decide whether a
	// credential is still worth having. LastUsedAt is omitted when the token has
	// never been presented, and `omitempty` is doing real work: "never used" and
	// "used at the epoch" are different answers and only the first is true.
	CreatedAt    time.Time  `json:"created_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	RevokeReason *string    `json:"revoke_reason,omitempty"`
}

// issuedAPIKeyResponse is the 201 from POST /v1/accounts/:id/api-keys, and it is
// the ONLY response in this service that carries a credential's plaintext.
//
// `token` is here and only here. It is shown once, at creation, and there is no
// endpoint anywhere that can print it again — not because one is missing but
// because there is nothing left to print: the row holds a SHA-256 digest, and a
// digest of a 256-bit value is not a credential. A caller that loses it mints
// another.
type issuedAPIKeyResponse struct {
	apiKeyResponse
	// Token is the credential. Populated here and nowhere else, and the field is
	// absent from apiKeyResponse so a handler cannot reach it by accident.
	Token string `json:"token"`
}

// mintAPIKeyRequest is the body of POST /v1/accounts/:id/api-keys.
//
// `scopes` is required and `expires_in` is optional, and which of those is which
// is the design rather than an oversight: a credential with no scopes is a
// session that never expires, so the field a client might reasonably omit is the
// one that is refused when it is.
//
// ExpiresIn is a DURATION IN SECONDS rather than an absolute instant, and the
// field name says so. RFC 6749's token response calls the same value `expires_in`
// and every OAuth client in the world already knows what it means. The alternative
// — an RFC 3339 timestamp — invites the client to have an opinion about the
// server's clock, which is a bug in the making for a field whose only job is to
// say how long.
type mintAPIKeyRequest struct {
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	ExpiresIn *int64   `json:"expires_in"`
}

// revokeAPIKeyRequest is the body of DELETE /v1/accounts/:id/api-keys/:keyId.
//
// The reason is optional and it is NOT in the event — see outbox's note. It is on
// the row because this service's own support reads it, which is a different
// consumer with a different need than a platform event subscriber.
type revokeAPIKeyRequest struct {
	Reason string `json:"reason"`
}

// ---------------------------------------------------------------------------
// handlers
// ---------------------------------------------------------------------------

// handleMintAPIKey issues a credential.
//
//	POST /v1/accounts/:id/api-keys  {name, scopes, expires_in?}  →  201 {…, token}
func (o options) handleMintAPIKey(w http.ResponseWriter, r *http.Request) {
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}
	account, _ := accountFrom(r.Context())

	var body *mintAPIKeyRequest
	if !decodeBody(w, r, &body) {
		return
	}

	in := apikeys.MintInput{
		AccountID: account.ID,
		Name:      body.Name,
		Scopes:    body.Scopes,
		MintedBy:  user.ID,
	}
	if body.ExpiresIn != nil {
		// Converted here rather than in the use case, so the use case's input is a
		// time.Duration and the wire format is this file's business. A negative
		// value becomes a negative duration and is refused by ResolveExpiry — it
		// is not clamped to zero first, because "expires in minus one second" and
		// "expires in no time at all" are both nonsense and both should be told so.
		lifetime := time.Duration(*body.ExpiresIn) * time.Second
		in.ExpiresIn = &lifetime
	}

	issued, err := o.apiKeys.Mint(r.Context(), in)
	if err != nil {
		o.writeAPIKeyError(w, r, err)
		return
	}

	// The one place in this service where a credential's plaintext reaches a
	// response body. The cookie is NOT set and the header is NOT echoed, because a
	// machine credential in a cookie would be a machine credential a browser
	// silently attaches to a request its holder did not intend — the entire reason
	// core says "no cookies for API traffic".
	writeJSON(w, http.StatusCreated, issuedAPIKeyResponse{
		apiKeyResponse: apiKeyFrom(issued.Key),
		Token:          issued.Token,
	})
}

// handleListAPIKeys returns an account's credentials, newest first.
//
//	GET /v1/accounts/:id/api-keys  →  200 [{id, name, scopes, …}]
func (o options) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	account, _ := accountFrom(r.Context())

	listed, err := o.apiKeys.List(r.Context(), account.ID)
	if err != nil {
		o.writeAPIKeyError(w, r, err)
		return
	}

	// A non-nil empty slice, so the body is [] rather than null. An account that has
	// never minted one is an empty list, not a missing field.
	items := make([]apiKeyResponse, 0, len(listed))
	for _, k := range listed {
		items = append(items, apiKeyFrom(k))
	}

	writeJSON(w, http.StatusOK, items)
}

// handleRevokeAPIKey withdraws a credential.
//
//	DELETE /v1/accounts/:id/api-keys/:keyId  {reason?}  →  204
func (o options) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	account, _ := accountFrom(r.Context())
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	keyID, ok := apiKeyIDFrom(r)
	if !ok {
		notFound(w, r)
		return
	}

	// An empty body is a revoke with no reason, and it has to be one: "revoke this"
	// with no explanation is the common request and refusing it for want of a JSON
	// document would be a 400 on a DELETE that needs nothing else.
	reason := ""
	if r.ContentLength != 0 {
		var body *revokeAPIKeyRequest
		if !decodeBody(w, r, &body) {
			return
		}
		reason = body.Reason
	}

	if _, err := o.apiKeys.Revoke(r.Context(), apikeys.RevokeInput{
		AccountID: account.ID,
		KeyID:     keyID,
		RevokedBy: user.ID,
		Reason:    reason,
	}); err != nil {
		o.writeAPIKeyError(w, r, err)
		return
	}

	noContent(w)
}

// apiKeyFrom projects a row onto the wire.
//
// It is a dedicated constructor rather than a struct tag on apikeys.Key so nothing
// can reach a response body by being added to the domain type — which is how
// TokenDigest stayed out.
func apiKeyFrom(k apikeys.Key) apiKeyResponse {
	return apiKeyResponse{
		ID:        k.ID.String(),
		Name:      k.Name,
		AccountID: k.AccountID.String(),
		UserID:    k.UserID.String(),
		// A non-nil empty slice again, so a token with no scopes renders [] rather
		// than null. One cannot be minted — the validator refuses it — and a row
		// that somehow has none must not turn a client into one that has to handle
		// both shapes.
		Scopes:       append([]string{}, k.Scopes...),
		ExpiresAt:    k.ExpiresAt,
		CreatedAt:    k.CreatedAt,
		LastUsedAt:   k.LastUsedAt,
		RevokedAt:    k.RevokedAt,
		RevokeReason: k.RevokeReason,
	}
}

// apiKeyIDFrom reads and parses the credential id in the path, on the same terms
// as accountIDFrom: a malformed id is 404 rather than 422, because the path is
// part of a resource's identity and "not an id this service issued" has to be the
// same answer as "an id you cannot see".
func apiKeyIDFrom(r *http.Request) (id.UUID, bool) {
	raw := chi.URLParam(r, keyIDParam)
	parsed, err := id.Parse(raw)
	if err != nil || parsed.IsZero() {
		return id.UUID{}, false
	}
	return parsed, true
}

// keyIDParam is the chi URL parameter naming the credential being acted on. A
// constant for the reason accountIDParam is one: it appears in the route pattern,
// the middleware and the handler, and three spellings of it is three chances to
// read the wrong one.
const keyIDParam = "keyID"

// ---------------------------------------------------------------------------
// error mapping
// ---------------------------------------------------------------------------

// writeAPIKeyError maps a use-case error onto the response.
//
// EVERY ROW IS A DECISION.
//
//	ErrNotAuthorized  403  the caller is a member who is not an owner. A caller who
//	                        is NOT a member never reaches this: RequireAccountRole
//	                        has already answered 404, which is the same
//	                        tenant-enumeration protection every other account route
//	                        gets, and re-deciding it here would be a second place
//	                        for the two to disagree.
//	ErrNotFound       404  a key id that is not there, not theirs, or in another
//	                        account. One sentence for all three.
//	ErrAlreadyRevoked 409  the credential is already withdrawn. Distinct from 404
//	                        because an operator who clicked twice is owed the truth:
//	                        a 204 the second time would leave them believing a
//	                        second live credential had just been destroyed.
//	ErrNameTaken      409  this account already has a LIVE credential of that name.
//	                        The index behind it is partial on revoked_at IS NULL, so
//	                        rotation — revoke, then mint the same name — is two
//	                        requests and not a conflict.
//	*FieldError       422  the request is not acceptable, per field.
//
// A 409 rather than a 422 for the two conflicts, and the difference is the point:
// the request is perfectly well formed and the state it asks for collides with one
// that exists.
func (o options) writeAPIKeyError(w http.ResponseWriter, r *http.Request, err error) {
	var fieldErr *apikeys.FieldError

	switch {
	case errors.Is(err, apikeys.ErrNotAuthorized):
		problemFor(w, r, http.StatusForbidden, CodeForbidden,
			"only an owner may manage api keys for this account")

	case errors.Is(err, apikeys.ErrNotFound):
		// The same sentence as an unknown account, and for the same reason: a
		// different one would confirm that the id they guessed is a real credential.
		problemFor(w, r, http.StatusNotFound, CodeNotFound,
			"no api key matches that id in this account")

	case errors.Is(err, apikeys.ErrAlreadyRevoked):
		problemFor(w, r, http.StatusConflict, CodeConflict,
			"this api key has already been revoked")

	case errors.Is(err, apikeys.ErrNameTaken):
		problemFor(w, r, http.StatusConflict, CodeConflict,
			"an active api key with that name already exists in this account; revoke it first")

	case errors.As(err, &fieldErr):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the request has an invalid field").
			withFieldErrors([]FieldError{{Field: fieldErr.Field, Code: fieldErr.Code}}))

	default:
		unexpected(w, r, o.logger, err)
	}
}

// ---------------------------------------------------------------------------
// POST /v1/introspections
// ---------------------------------------------------------------------------

// Introspector resolves a presented token to a claim document.
//
// It is separate from APIKeys because it is a READ of a credential rather than a
// management of one, and from APIKeyCaller because that one answers "who is
// calling" while this one answers "what may this token do" — and a token asking
// the second question about itself is the case that has no analogue in the first.
type Introspector interface {
	Introspect(ctx context.Context, token string, now time.Time) (apikeys.Claims, error)
}

// WithIntrospection mounts the introspection route.
//
// Absent means the route is not mounted at all, and the OIDC provider's own
// SetIntrospectionFromToken keeps refusing — two different surfaces, two different
// credentials, and neither falling back to the other.
func WithIntrospection(i Introspector) Option {
	return func(o *options) {
		if i != nil {
			o.introspector = i
		}
	}
}

// registerIntrospectionRoute mounts it.
//
// IT IS NOT ACCOUNT-SCOPED and so it is not in registerTenancyRoutes: there is no
// account in the path, and the account in the answer is the token's own. The
// authorization is below and it is two rules, both of which are about the CALLER:
//
//	a token may ask about itself and nothing else. A credential that can read
//	  another credential's scopes is a credential that can discover what a
//	  compromised service holds, which is reconnaissance an attacker does before
//	  choosing what to escalate into.
//	a session may ask about a token in an account it OWNS, and not otherwise.
//	  Owner because this is the credential inventory of an account, and the same
//	  argument as minting one applies to reading them.
func (o options) registerIntrospectionRoute(r chiRouter) {
	if o.introspector == nil {
		return
	}
	r.Post("/v1/introspections", o.handleIntrospect)
}

// introspectRequest is the body of POST /v1/introspections.
//
// `token` is the value to resolve, and it is the credential rather than an id —
// because an id would be an enumeration oracle over somebody else's credentials,
// whereas a value is only useful to somebody who already holds it.
type introspectRequest struct {
	Token string `json:"token"`
}

// handleIntrospect resolves a presented token to its claim document.
//
//	POST /v1/introspections  {token}
//	  →  200 {active, sub, account_id, scopes, scope, jti, name, role, iat, exp}
//	  →  200 {"active": false}   unknown, revoked, expired, or its owner is no
//	                             longer a member of the account
//
// ONE 200 FOR EVERY REFUSAL OF THE TOKEN. RFC 7662 says an introspection response
// for a token that cannot be used is `{"active": false}` and nothing else, and
// the reason is the same one sessions.ErrNotFound exists for: a response that
// distinguished "revoked" from "never existed" tells an attacker whether a leaked
// value was still live, which is the second question they ask after "does this
// work". The status is 200 and not 404 for the same reason — the endpoint
// succeeded; the answer is that the token is not active.
//
// THE CALLER'S OWN STANDING IS A DIFFERENT QUESTION and gets a different status,
// because it is a different fact: 401 for no credential, 403 for a token asking
// about somebody else's. Those are decisions about the request, and the caller
// already knows which one they made.
func (o options) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if o.presentedToken(r) == "" {
		unauthorized(w, r)
		return
	}

	var body *introspectRequest
	if !decodeBody(w, r, &body) {
		return
	}

	caller, ok := o.currentCaller(w, r)
	if !ok {
		return
	}

	claims, err := o.introspector.Introspect(r.Context(), body.Token, time.Now())
	if err != nil {
		if errors.Is(err, apikeys.ErrNotFound) || errors.Is(err, apikeys.ErrNoAccountID) {
			// The two refusals that are not the caller's fault and not a leak:
			// nothing to say, and the same shape for every reason. ErrNoAccountID is
			// here because a token with no tenancy key cannot be used against any
			// account, so "inactive" is the truth and a document with a defaulted sub
			// would not be.
			writeJSON(w, http.StatusOK, apikeys.InactiveClaims())
			return
		}
		unexpected(w, r, o.logger, err)
		return
	}

	// The caller's standing, checked AFTER the token resolved and only for an active
	// one — so an unknown token is `{"active": false}` for everybody, including a
	// caller with no standing at all, and the response cannot be used to find out
	// whether a value is real.
	if !o.mayIntrospect(w, r, caller, claims) {
		return
	}

	writeJSON(w, http.StatusOK, claims)
}

// mayIntrospect decides the caller's standing over an ACTIVE claim, writing the
// refusal and reporting whether the request may proceed.
//
// A token may read itself: comparing the token ids is the whole check, and the one
// that presented the credential is the only one it may ask about. A session may
// read a token in an account it owns, and the role comes from the membership
// table on this request — so an owner who has been demoted loses this along with
// everything else.
func (o options) mayIntrospect(w http.ResponseWriter, r *http.Request, caller apikeys.Caller, claims apikeys.Claims) bool {
	// A session caller: the account in the claim is the one being asked about.
	if caller.Key.ID.IsZero() {
		accountID, err := apikeys.ResolveAccountID(claims)
		if err != nil {
			// Unreachable for an active claim — ClaimsFor refuses one without an
			// account — and refused rather than defaulted if it ever happens.
			problemFor(w, r, http.StatusForbidden, CodeForbidden,
				"this token cannot be attributed to an account")
			return false
		}
		_, role, err := o.tenancy.Get(r.Context(), accountID, caller.User.ID)
		if err != nil {
			// The caller is not in that account, and 404 rather than 403 for the
			// reason every other route does it: a 403 confirms the account exists.
			problemFor(w, r, http.StatusNotFound, CodeNotFound,
				"no api key matches that token in an account you can see")
			return false
		}
		if !role.AtLeast(accounts.RoleOwner) {
			problemFor(w, r, http.StatusForbidden, CodeForbidden,
				"only an owner may read an api key's grant in this account")
			return false
		}
		return true
	}

	// A token caller: itself, and only itself.
	if claims.TokenID != caller.Key.ID.String() {
		problemFor(w, r, http.StatusForbidden, CodeForbidden,
			"an api key may only introspect itself")
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// the credential a request presents
// ---------------------------------------------------------------------------

// presentedAPIKey returns the scoped token the request is carrying, or "".
//
// THE PREFIX IS THE DISCRIMINATOR, and that is the second thing the `cafaye_`
// prefix buys. A request arrives with either a session token or an api key, and
// the two live in different tables with different lifetimes and different
// revocation stories. Something has to decide which one this is before the
// database is asked, and the prefix decides it without a query: no presented value
// of the wrong shape ever reaches the api_keys table, so "this token is not in
// that table" cannot be a thing an attacker can measure.
//
// A request carrying BOTH — a browser session plus a pasted api key — is resolved
// as the api key, because presentedToken already established that an explicit
// Authorization header beats the cookie and this reads the same header.
func (o options) presentedAPIKey(r *http.Request) string {
	token := bearerToken(r)
	if !strings.HasPrefix(token, apikeys.Prefix) {
		return ""
	}
	return token
}

// isAPIKeyRequest reports whether the request is presenting a scoped token rather
// than a session.
//
// It is the same test as presentedAPIKey without the value, and it exists because
// the routes that must refuse a token need the answer without handling the
// credential. Every such route calls it and refuses; none of them consults a scope
// list, because there is no scope for the credential surface.
func (o options) isAPIKeyRequest(r *http.Request) bool {
	return o.presentedAPIKey(r) != ""
}

// refuseAPIKeyRequest answers 403 for a request presenting a scoped token on a
// surface a token may not reach.
//
// 403 AND NOT 404, because the caller IS authenticated and the resource does
// exist: 404 would be a lie about a route that is mounted and working, and a
// client that believed it would treat a policy decision as a routing bug. The
// detail names the reason in one sentence, which is the caller's own doing and not
// a fact about anybody else.
func refuseAPIKeyRequest(w http.ResponseWriter, r *http.Request) {
	problemFor(w, r, http.StatusForbidden, CodeForbidden,
		"an api key may not use this endpoint; use a session")
}
