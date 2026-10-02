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
	"github.com/cafaye/identity/internal/auth"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/users"
)

// The tenancy surface: accounts, memberships and invitations.
//
// The interesting part of this file is RequireAccountRole, which is the single
// place in the service that turns "who is asking, and what are they asking
// about" into an allow or a deny. Everything else here is translation.

// accountIDParam is the chi URL parameter naming the account. It is a constant
// because it appears in the route patterns, the middleware and the handlers, and
// three spellings of it is three chances to read the wrong one.
const accountIDParam = "accountID"

// userIDParam is the chi URL parameter naming the member being acted on.
const userIDParam = "userID"

// Tenancy is the part of accounts.Service the v1 routes need.
//
// It is an interface declared here, at the consumer, for the same reason Auth is:
// the handlers can then be tested against a programmable double, and the HTTP
// layer has no dependency on the use cases' internals. Every method takes only
// ids and a clock-free input, so there is no way for a handler to reach past the
// authorization decision into a query it wrote itself.
type Tenancy interface {
	Create(ctx context.Context, in accounts.CreateInput) (accounts.Created, error)
	ListMine(ctx context.Context, userID id.UUID) ([]accounts.MemberSummary, error)
	Get(ctx context.Context, accountID, userID id.UUID) (accounts.Account, accounts.Role, error)
	Members(ctx context.Context, accountID id.UUID) ([]accounts.MemberSummary, error)
	Rename(ctx context.Context, accountID id.UUID, name string) (accounts.Account, error)
	Delete(ctx context.Context, accountID id.UUID) error
	InviteRole(ctx context.Context, accountID id.UUID, email, role string, invitedBy id.UUID) (accounts.Invited, error)
	Accept(ctx context.Context, in accounts.AcceptInput) (accounts.Membership, error)
	ChangeRole(ctx context.Context, in accounts.ChangeRoleInput) (accounts.Membership, error)
	RemoveMember(ctx context.Context, in accounts.RemoveMemberInput) error
}

// WithTenancy mounts the account routes.
//
// It is an Option rather than a constructor argument for the same reason
// WithAuth is: with no DATABASE_URL there is no accounts service, and that
// process must still answer /healthz. The account routes are simply absent when
// it is not given, so a misconfiguration is a 404 rather than a pile of 500s.
//
// It is ignored without Auth, because every account route starts by resolving a
// session and a service with no way to resolve one has nothing to mount.
func WithTenancy(t Tenancy) Option {
	return func(o *options) {
		if t != nil {
			o.tenancy = t
		}
	}
}

// accountScope is what RequireAccountRole resolves and the handlers read.
//
// It is put in the request context rather than passed as a parameter so the
// middleware is genuinely middleware: the handler signature stays
// http.HandlerFunc, and the session is resolved once per request rather than once
// per handler that needs the caller.
//
// The three credential facts a handler might need, and they are deliberately
// three fields rather than one union type. A session caller has ScopeKey zero and
// KeyID zero; a token caller has all three set. A handler that needs to know which
// it is can ask, and a handler that does not — nearly all of them — never has to.
type accountScope struct {
	Account accounts.Account
	Role    accounts.Role
	User    users.User
	// Scopes is the caller's token's granted scopes, empty for a session caller.
	//
	// EMPTY FOR A SESSION IS NOT "NO AUTHORITY". A session is a human's credential
	// and it carries the full authority of its role; a token is a narrowed one. That
	// asymmetry is the reason the scope check below is skipped for sessions rather
	// than failing them, and it is the reason a session can reach a route whose
	// scope a token cannot.
	Scopes []string
	// KeyID is the api key's row id, zero for a session caller. It is what a
	// handler puts in an audit line, and the rule from the packet is that a test
	// identifying a token uses its id or its name — never the value.
	KeyID id.UUID
}

type accountContextKey struct{}

// accountFrom returns the account RequireAccountRole resolved, and whether it
// resolved one. A handler behind the middleware can rely on the second being
// true; a handler not behind it must not read the first.
func accountFrom(ctx context.Context) (accounts.Account, bool) {
	scope, ok := ctx.Value(accountContextKey{}).(accountScope)
	return scope.Account, ok
}

// roleFrom returns the caller's role in the resolved account.
func roleFrom(ctx context.Context) accounts.Role {
	scope, _ := ctx.Value(accountContextKey{}).(accountScope)
	return scope.Role
}

// scopeFrom returns the caller's token scopes, empty for a session caller.
func scopeFrom(ctx context.Context) []string {
	scope, _ := ctx.Value(accountContextKey{}).(accountScope)
	return scope.Scopes
}

// scopeRequiredBy is the account route → required scope table.
//
// IT IS A TABLE RATHER THAN A PARAMETER on requireAccountRole, and the reason is
// that a parameter would have to be restated at fourteen call sites and the table
// can be walked by a test. `TestEveryAccountRouteDeclaresItsScope` fails if a
// route is mounted without a row, and `TestEveryScopeIsEnforcedOnItsRoutes` fails
// if apikeys.AllScopes names something the router does not gate. Two lists that
// have to agree, and a disagreement is a test failure rather than a comment.
//
// The key is the chi pattern with the method, spelled exactly as the router spells
// it. chi's own RouteContext carries the matched pattern, so a request is looked up
// by the route it actually reached rather than by a string this file re-derives —
// which is what makes a route registered under a different spelling fail the test
// rather than silently escape the gate.
//
// A ROUTE WITH NO ROW IS NOT UNGATED. scopeRequiredBy returns "" for one, and
// `Allows("")` is false, so a token is refused on a route nobody declared a scope
// for. That is the fail-closed direction and it is deliberate: a new account route
// is unreachable by a token until somebody says what it may do with one.
var accountRouteScopes = map[string]string{
	// The tenancy reads. accounts:read is also the default a CI job needs and the
	// one that leaks the least.
	//
	// NOT IN THIS TABLE: `GET /v1/accounts`, `POST /v1/accounts` and
	// `POST /v1/invitations/accept`. Each is a question about the caller's WHOLE set
	// of accounts rather than about one account, and a token is bound to one
	// account — so they are refused outright by sessionCredentialOnly rather than
	// gated. A row here would be a lie twice over: they do not go through
	// requireAccountRole, and a scope that gates nothing is a comment with a type.
	"GET /v1/accounts/{accountID}":         apikeys.ScopeAccountsRead,
	"GET /v1/accounts/{accountID}/members": apikeys.ScopeAccountsRead,

	// The account's own mutations, except deleting it.
	"PATCH /v1/accounts/{accountID}":                   apikeys.ScopeAccountsWrite,
	"POST /v1/accounts/{accountID}/invitations":        apikeys.ScopeAccountsWrite,
	"PATCH /v1/accounts/{accountID}/members/{userID}":  apikeys.ScopeAccountsWrite,
	"DELETE /v1/accounts/{accountID}/members/{userID}": apikeys.ScopeAccountsWrite,

	// Deleting the account is its own scope: it is the only one of these that
	// cannot be undone, and a token carrying accounts:write held by somebody who
	// later becomes a member is already refused on the role check — so the extra
	// scope is for the owner case, where the role gate alone would let it through.
	"DELETE /v1/accounts/{accountID}": apikeys.ScopeAccountsDelete,

	// The account's OpenID Connect registrations, read and write in one scope: both
	// GETs are owner-only routes whose response IS the integration's configuration,
	// so a separate read scope would be a name nobody has a use for.
	"POST /v1/accounts/{accountID}/oidc-clients":              apikeys.ScopeOIDCClientsWrite,
	"GET /v1/accounts/{accountID}/oidc-clients":               apikeys.ScopeOIDCClientsWrite,
	"GET /v1/accounts/{accountID}/oidc-clients/{clientID}":    apikeys.ScopeOIDCClientsWrite,
	"DELETE /v1/accounts/{accountID}/oidc-clients/{clientID}": apikeys.ScopeOIDCClientsWrite,

	// The admin surface. Two scopes, and NOT one scope called `admin` — the
	// vocabulary's own comment rules that name out, because a category name is
	// where a wildcard grows back. What a token can do on this surface is exactly
	// what it is granted here.
	//
	// Reading the trail is its own scope rather than accounts:read because the two
	// answer different questions, and a record of authority being used over time
	// is a different sensitivity from the account's current shape.
	//
	// The three rows are the whole surface, and that is the privilege boundary in
	// code: a token holding neither scope reaches no admin route, and a token
	// holding both can revoke invitations and read the trail and nothing else in
	// this service. There is no fourth row to add by accident, because a new row
	// would be a new scope and a new scope is a decision somebody has to make in
	// internal/apikeys.
	"GET /v1/accounts/{accountID}/admin/audit-log":                     apikeys.ScopeAuditLogRead,
	"DELETE /v1/accounts/{accountID}/admin/invitations/{invitationID}": apikeys.ScopeAccountInvitationsWrite,
	"POST /v1/accounts/{accountID}/admin/invitation-revocations":       apikeys.ScopeAccountInvitationsWrite,
}

// scopeRequiredBy returns the scope a token needs for the route it reached, or ""
// when no row declares one.
//
// "" MEANS NO TOKEN, not "any token". `Key.Allows("")` is false for every granted
// set, so an undeclared route is closed to tokens until it is declared. That is
// the direction that matters: a new account-scoped route added by a later packet
// is unreachable by a machine credential on the day it lands, not on the day
// somebody notices it was never gated.
func scopeRequiredBy(r *http.Request) string {
	route := chi.RouteContext(r.Context()).RoutePattern()
	if route == "" {
		return ""
	}
	return accountRouteScopes[strings.ToUpper(r.Method)+" "+route]
}

// APIKeyCaller resolves a scoped api key to its caller, or reports that the
// request is not presenting one.
//
// It is on the HTTP layer's own options rather than on Auth because it is a
// DIFFERENT CREDENTIAL with a different table, a different lifetime and a
// different revocation story, and routing it through Auth would put a lookup for a
// `cafaye_…` value in the sessions table on the path of every authenticated
// request.
type APIKeyCaller interface {
	Authenticate(ctx context.Context, token string, now time.Time) (apikeys.Caller, error)
}

// WithAPIKeyCaller teaches the router how to resolve a scoped token.
//
// Without it the account-scoped routes are SESSION-ONLY: a token presented to one
// is refused with the same 401 an unknown credential gets, because there is nothing
// here that could authenticate it. That is the fail-closed direction and it is a
// supported configuration — the routes still work for browsers.
func WithAPIKeyCaller(c APIKeyCaller) Option {
	return func(o *options) {
		if c != nil {
			o.apiKeyCaller = c
		}
	}
}

// requireAccountRole is the authorization gate on every account-scoped route.
//
// It resolves the caller from their credential, the account from the path, and
// the caller's membership in that account, then compares the membership's role
// against min AND — when the caller is a scoped token rather than a session —
// the route's scope against the token's granted scopes. Three answers, and which
// one is correct is a security property rather than a formatting choice:
//
//	no usable credential            401  — who are you
//	no membership in this account    404  — this account is not visible to you
//	role below the minimum          403  — you can see it; you may not do this
//	scope not granted               403  — this credential may not do this
//
// THE 404 IS THE INTERESTING ONE. A 403 for "you are not a member" would tell
// any authenticated caller that the account id they guessed is a real account,
// which is a free tenant-enumeration oracle on a table whose ids are the only
// thing standing between one customer and another. core says the same thing —
// "403 is not allowed to leak existence" (docs/openapi-conventions.md).
//
// So the two denials are kept apart on purpose: 404 when the resource is not the
// caller's to know about, 403 when it is and they lack the permission. A caller
// who is a member of an account has already been told it exists, so 403 leaks
// nothing to them.
//
// A lookup that FAILS is a 500 and not a 403. A database blip is not evidence
// that the caller is under-privileged, and answering 403 would turn a transient
// outage into a wrong authorization answer that a client might cache.
//
// TWO CREDENTIALS, ONE GATE, AND THE ORDER MATTERS.
//
// The role is checked BEFORE the scope, and that is not arbitrary. A token
// presented against an account it was not minted for is a 404 even if it holds
// every scope in the vocabulary — the account in the path has to be one this
// token is for before "may it act here" is even a question. And the role is read
// from the membership table on this request rather than from anything the token
// carries, which is what makes a demotion or a removal take effect on the next
// request with nothing to invalidate.
//
// A SESSION CARRIES NO SCOPES AND IS NOT REFUSED FOR IT. A session is a human's
// credential with the full authority of its role; a token is a narrowed one. The
// scope check below runs only when ScopeKey is set, and the reason is written on
// the accountScope fields.
func (o options) requireAccountRole(min accounts.Role, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := o.currentCaller(w, r)
		if !ok {
			return
		}
		user := caller.User

		accountID, ok := accountIDFrom(r)
		if !ok {
			notFound(w, r)
			return
		}

		account, role, err := o.tenancy.Get(r.Context(), accountID, user.ID)
		if err != nil {
			o.writeTenancyError(w, r, err)
			return
		}

		if !role.AtLeast(min) {
			problemFor(w, r, http.StatusForbidden, CodeForbidden,
				"your role in this account does not permit this action")
			return
		}

		// A token is minted FOR one account, and core's rule is that tenancy comes
		// from the credential and never from the request body. A token reaching a
		// path for a different account is 404, the same answer a stranger gets:
		// the caller is not a non-member of that account, they are a caller whose
		// credential is not for it, and neither fact may be distinguishable.
		//
		// `!caller.Key.ID.IsZero()` is "this is a token": a session caller's Key is
		// the zero value, so the two checks below are skipped for a browser rather
		// than being satisfied by a session that happened to hold no scopes.
		if !caller.Key.ID.IsZero() && caller.Key.AccountID != accountID {
			notFound(w, r)
			return
		}

		// The scope gate. AFTER the membership and the role, so a caller who is not
		// in the account at all learns nothing about which scopes a token would
		// have needed.
		if !caller.Key.ID.IsZero() && !caller.Key.Allows(scopeRequiredBy(r)) {
			problemFor(w, r, http.StatusForbidden, CodeForbidden,
				"this api key does not carry the "+scopeRequiredBy(r)+" scope")
			return
		}

		ctx := context.WithValue(r.Context(), accountContextKey{}, accountScope{
			Account: account, Role: role, User: user,
			Scopes: caller.Key.Scopes,
			KeyID:  caller.Key.ID,
		})
		next(w, r.WithContext(ctx))
	}
}

// currentCaller resolves the request's credential to a caller: a session token or a
// scoped api key.
//
// THE PREFIX DECIDES WHICH, before any query runs. That is the second thing the
// `cafaye_` prefix buys — the first is recognition in a log — and it means a value
// of the wrong kind never reaches the wrong table. A session token is looked up in
// sessions and an api key in api_keys, and neither lookup is ever handed a value
// belonging to the other, so "is this token live" cannot be answered by the
// response time of the wrong index.
//
// A request with no usable credential is one 401, whatever was missing and
// whatever was wrong with it.
func (o options) currentCaller(w http.ResponseWriter, r *http.Request) (apikeys.Caller, bool) {
	if token := o.presentedAPIKey(r); token != "" {
		if o.apiKeyCaller == nil {
			// A process with no api key support refuses one rather than 500ing. The
			// value has the right shape and nothing here can check it, and answering
			// 401 keeps the failure indistinguishable from an unknown credential.
			unauthorized(w, r)
			return apikeys.Caller{}, false
		}
		caller, err := o.apiKeyCaller.Authenticate(r.Context(), token, o.clk.Now())
		if err != nil {
			unauthorized(w, r)
			return apikeys.Caller{}, false
		}
		return caller, true
	}

	user, ok := o.currentUser(w, r)
	if !ok {
		return apikeys.Caller{}, false
	}
	return apikeys.Caller{User: user}, true
}

// currentUser resolves the presented credential to a user, writing the problem
// and returning false if it cannot.
//
// It is one helper for every route rather than a per-handler block, so "who are
// you" has one answer in this service: no token, an unknown one, an expired one
// and a revoked one are all the same 401 with the same body.
func (o options) currentUser(w http.ResponseWriter, r *http.Request) (users.User, bool) {
	token := o.presentedToken(r)
	if token == "" {
		unauthorized(w, r)
		return users.User{}, false
	}

	user, err := o.auth.Authenticate(r.Context(), token)
	if err != nil {
		if errors.Is(err, auth.ErrUnauthenticated) {
			unauthorized(w, r)
			return users.User{}, false
		}
		unexpected(w, r, o.logger, err)
		return users.User{}, false
	}
	return user, true
}

// accountIDFrom reads and parses the account id in the path.
//
// A malformed id is ErrNotFound rather than a 422. The path is part of a
// resource's identity, and "this is not an id this service issued" has to be the
// same answer as "this id is one this service issued and you cannot see it" —
// otherwise the second becomes probeable by anyone who can send a request.
func accountIDFrom(r *http.Request) (id.UUID, bool) {
	raw := chi.URLParam(r, accountIDParam)
	parsed, err := id.Parse(raw)
	if err != nil {
		return id.UUID{}, false
	}
	if parsed.IsZero() {
		// The nil uuid is a value no row can have. Handing it to a query would be
		// a wasted round trip, and a store that treated it as a wildcard would
		// return an arbitrary account.
		return id.UUID{}, false
	}
	return parsed, true
}

// userIDFrom reads and parses a member's id in the path, on the same terms as
// accountIDFrom.
func userIDFrom(r *http.Request) (id.UUID, bool) {
	parsed, err := id.Parse(chi.URLParam(r, userIDParam))
	if err != nil || parsed.IsZero() {
		return id.UUID{}, false
	}
	return parsed, true
}

// ---------------------------------------------------------------------------
// request and response shapes
// ---------------------------------------------------------------------------

// accountResponse is the public projection of an account.
//
// It is a dedicated type rather than accounts.Account so nothing can reach a
// response body by being added to the domain struct. Every field here is either
// something a client renders or something it needs to make its next request.
//
// Role is the CALLER's role in this account, not a property of the account. It
// is here because without it a client cannot render "you are an admin" or decide
// whether to show a settings form, and answering that needs a second round trip
// for a value the authorization layer already resolved.
//
// Members is present on the detail response and absent on the list, where one
// entry per account would multiply the payload by the size of every account the
// caller belongs to. `omitempty` is doing real work: an empty list and an absent
// one are different answers.
type accountResponse struct {
	ID        string               `json:"id"`
	Name      string               `json:"name"`
	Slug      string               `json:"slug"`
	Personal  bool                 `json:"personal"`
	Role      accounts.Role        `json:"role"`
	Members   []membershipResponse `json:"members,omitempty"`
	CreatedAt time.Time            `json:"created_at"`
	UpdatedAt time.Time            `json:"updated_at"`
}

// accountListItem is one entry of GET /v1/accounts. No members, and no updated_at:
// a list is a navigation aid and carries the minimum a client needs to render a
// row and open it.
type accountListItem struct {
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	Slug      string        `json:"slug"`
	Personal  bool          `json:"personal"`
	Role      accounts.Role `json:"role"`
	CreatedAt time.Time     `json:"created_at"`
}

// membershipResponse is a membership: an account, a user, and a role.
//
// It is what POST /v1/invitations/accept returns, because the moment somebody
// accepts an invitation is the moment they need to know what they can now do.
type membershipResponse struct {
	AccountID string        `json:"account_id"`
	UserID    string        `json:"user_id"`
	Role      accounts.Role `json:"role"`
	CreatedAt time.Time     `json:"created_at"`
}

// invitationResponse is a pending invitation and, on creation, its one-time
// token.
//
// THE TOKEN IS HERE AND ONLY HERE. It is returned in the 201 and never again:
// there is no endpoint that re-reads it and no column that stores it, only its
// digest. In a later packet the invitation email is handed to courier and this
// field goes away — until courier exists, returning the token is the only way an
// invitation can be delivered at all, and a service that mints an invitation
// nobody can redeem is worse than one that returns a credential once.
//
// TokenDigest is deliberately absent. It is what the row holds, and a response
// that echoed it would tell a client something it has no use for.
type invitationResponse struct {
	ID        string        `json:"id"`
	AccountID string        `json:"account_id"`
	Email     string        `json:"email"`
	Role      accounts.Role `json:"role"`
	Token     string        `json:"token"`
	ExpiresAt time.Time     `json:"expires_at"`
	CreatedAt time.Time     `json:"created_at"`
}

// createAccountRequest is the body of POST /v1/accounts. Only a name: the slug is
// derived, the owner is the caller, and neither is the client's to choose.
type createAccountRequest struct {
	Name string `json:"name"`
}

// renameAccountRequest is the body of PATCH /v1/accounts/:id.
//
// There is no slug field, and its absence is deliberate rather than an omission:
// a slug is a handle that goes into logs, emails and a future hostname, and one
// that moved on a rename would break every link already sent. See
// accounts.Account.Slug.
type renameAccountRequest struct {
	Name string `json:"name"`
}

// inviteRequest is the body of POST /v1/accounts/:id/invitations.
type inviteRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

// acceptInvitationRequest is the body of POST /v1/invitations/accept.
type acceptInvitationRequest struct {
	Token string `json:"token"`
}

// changeRoleRequest is the body of PATCH /v1/accounts/:id/members/:userId.
type changeRoleRequest struct {
	Role string `json:"role"`
}

// ---------------------------------------------------------------------------
// handlers
// ---------------------------------------------------------------------------

// registerTenancyRoutes mounts the account surface.
//
// The paths are spelled out flat rather than nested under a chi Route, and that
// is a deliberate choice: the minimum role for a route is the thing most worth
// reading next to it, and a flat list puts every path, every method and every
// minimum on one line each — which is also exactly the shape the authorization
// matrix in the tests is written against. Nesting would save six repetitions of
// "/v1/accounts/{accountID}" and cost the reader the ability to scan the table.
//
// The minimums, read down the page:
//
//	GET    /v1/accounts/:id                        member
//	GET    /v1/accounts/:id/members                member
//	PATCH  /v1/accounts/:id                        admin
//	POST   /v1/accounts/:id/invitations            admin   (and owner for role=admin)
//	DELETE /v1/accounts/:id/members/:userId        admin   (and never an owner)
//	PATCH  /v1/accounts/:id/members/:userId        owner
//	DELETE /v1/accounts/:id                        owner
//
// The two rules that depend on the *target* rather than the caller — an admin
// may not invite an admin, an admin may not remove an owner, the last owner is
// never removed — are in the use case, not here. A route's minimum answers "may
// this caller do this at all"; the rest answers "may they do it to this".
func (o options) registerTenancyRoutes(r chiRouter) {
	// The three collection routes are SESSION-ONLY, and it is the token that makes
	// that a decision rather than a default: each of them answers a question about
	// the CALLER'S WHOLE SET of accounts rather than about one account, and a
	// credential bound to one of them has no business enumerating the others. The
	// reason in full is on sessionCredentialOnly.
	r.Post("/v1/accounts", o.sessionCredentialOnly(o.handleCreateAccount))
	r.Get("/v1/accounts", o.sessionCredentialOnly(o.handleListAccounts))
	r.Post("/v1/invitations/accept", o.sessionCredentialOnly(o.handleAcceptInvitation))

	r.Get("/v1/accounts/{accountID}", o.requireAccountRole(accounts.RoleMember, o.handleGetAccount))
	r.Patch("/v1/accounts/{accountID}", o.requireAccountRole(accounts.RoleAdmin, o.handleRenameAccount))
	r.Delete("/v1/accounts/{accountID}", o.requireAccountRole(accounts.RoleOwner, o.handleDeleteAccount))

	r.Get("/v1/accounts/{accountID}/members", o.requireAccountRole(accounts.RoleMember, o.handleListMembers))
	r.Post("/v1/accounts/{accountID}/invitations", o.requireAccountRole(accounts.RoleAdmin, o.handleInvite))
	r.Patch("/v1/accounts/{accountID}/members/{userID}", o.requireAccountRole(accounts.RoleOwner, o.handleChangeRole))
	r.Delete("/v1/accounts/{accountID}/members/{userID}", o.requireAccountRole(accounts.RoleAdmin, o.handleRemoveMember))

	// The OIDC registrations hang off the account because a registration is
	// scoped to one: an account's owner decides which products may sign users in
	// to it, and the minimum for all four routes is owner. They are mounted here
	// rather than beside the protocol routes because the authorization decision
	// is RequireAccountRole's, and it is the same decision it makes for every
	// other row of the matrix. Absent without WithOIDCClients, for the reason
	// every other route is: a misconfiguration is a 404, not a 500.
	o.registerOIDCClientRoutes(r)

	// And so do the scoped api keys, for the same reason and on the same gate.
	// They are deliberately NOT in accountRouteScopes, so a token presenting to one
	// is refused: the credential surface is the one surface a credential may not
	// manage. See the note in apikeys.go.
	o.registerAPIKeyRoutes(r)

	// And so do the admin routes, which is why this is a call from HERE rather
	// than from registerRoutes: an admin action is an action on an account, so
	// these routes are account-scoped, so they belong in the registrar that
	// TestEveryMountedRouteIsAnAccountRoute and TestEveryRouteIsInTheMatrix walk.
	// Mounted anywhere else, three account routes would sit outside both checks.
	//
	// They are in accountRouteScopes, unlike the api keys above, because a token
	// IS the right credential for them: the admin surface refuses sessions
	// outright, so an admin action is always performed by a machine credential
	// that the audit record can name.
	o.registerAdminRoutes(r)
}

// handleCreateAccount provisions an account and makes the caller its owner.
//
//	POST /v1/accounts  {name}  →  201 {id, name, slug, personal, role, ...}
func (o options) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	var body *createAccountRequest
	if !decodeBody(w, r, &body) {
		return
	}

	// The owner is the authenticated user, never anything from the body. That is
	// the line between "create an account I own" and "create an account owned by
	// somebody else", and there is no version of this request body that can cross
	// it.
	created, err := o.tenancy.Create(r.Context(), accounts.CreateInput{Name: body.Name, Owner: user.ID})
	if err != nil {
		o.writeTenancyError(w, r, err)
		return
	}

	writeJSON(w, http.StatusCreated, accountResponse{
		ID:        created.Account.ID.String(),
		Name:      created.Account.Name,
		Slug:      created.Account.Slug,
		Personal:  created.Account.Personal,
		Role:      created.Membership.Role,
		CreatedAt: created.Account.CreatedAt,
		UpdatedAt: created.Account.UpdatedAt,
	})
}

// handleListAccounts returns the caller's own accounts.
//
//	GET /v1/accounts  →  200 [{id, name, slug, personal, role, created_at}]
func (o options) handleListAccounts(w http.ResponseWriter, r *http.Request) {
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	list, err := o.tenancy.ListMine(r.Context(), user.ID)
	if err != nil {
		o.writeTenancyError(w, r, err)
		return
	}

	// A non-nil empty slice, so the body is [] rather than null. See
	// TestAccountListIsAnArrayNotNull.
	items := make([]accountListItem, 0, len(list))
	for _, m := range list {
		items = append(items, accountListItem{
			ID:        m.Account.ID.String(),
			Name:      m.Account.Name,
			Slug:      m.Account.Slug,
			Personal:  m.Account.Personal,
			Role:      m.Role,
			CreatedAt: m.Account.CreatedAt,
		})
	}

	writeJSON(w, http.StatusOK, items)
}

// handleGetAccount returns an account and its members.
//
//	GET /v1/accounts/:id  →  200 {id, name, slug, personal, role, members, ...}
func (o options) handleGetAccount(w http.ResponseWriter, r *http.Request) {
	account, _ := accountFrom(r.Context())
	role := roleFrom(r.Context())

	members, err := o.tenancy.Members(r.Context(), account.ID)
	if err != nil {
		o.writeTenancyError(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, accountResponse{
		ID:        account.ID.String(),
		Name:      account.Name,
		Slug:      account.Slug,
		Personal:  account.Personal,
		Role:      role,
		Members:   membershipResponses(members),
		CreatedAt: account.CreatedAt,
		UpdatedAt: account.UpdatedAt,
	})
}

// handleListMembers returns an account's members.
//
// It is a separate route from the account detail so a client that already has the
// account does not have to re-read it to render a member list — which is the
// common case, since a member list is a panel and the account is a header.
func (o options) handleListMembers(w http.ResponseWriter, r *http.Request) {
	account, _ := accountFrom(r.Context())

	members, err := o.tenancy.Members(r.Context(), account.ID)
	if err != nil {
		o.writeTenancyError(w, r, err)
		return
	}

	// The caller's own role is on the wrapper, so a client rendering the panel
	// knows what to offer without a third request.
	writeJSON(w, http.StatusOK, struct {
		Memberships []membershipResponse `json:"memberships"`
		Role        accounts.Role        `json:"role"`
	}{
		Memberships: membershipResponses(members),
		Role:        roleFrom(r.Context()),
	})
}

// handleRenameAccount changes an account's name.
//
//	PATCH /v1/accounts/:id  {name}  →  200 {id, name, slug, ...}
func (o options) handleRenameAccount(w http.ResponseWriter, r *http.Request) {
	account, _ := accountFrom(r.Context())

	var body *renameAccountRequest
	if !decodeBody(w, r, &body) {
		return
	}

	renamed, err := o.tenancy.Rename(r.Context(), account.ID, body.Name)
	if err != nil {
		o.writeTenancyError(w, r, err)
		return
	}

	// The slug is the account's original one. It is deliberately not re-derived,
	// and saying so in the response is how a client learns that a rename did not
	// move the handle.
	writeJSON(w, http.StatusOK, accountResponse{
		ID:        renamed.ID.String(),
		Name:      renamed.Name,
		Slug:      renamed.Slug,
		Personal:  renamed.Personal,
		Role:      roleFrom(r.Context()),
		CreatedAt: renamed.CreatedAt,
		UpdatedAt: renamed.UpdatedAt,
	})
}

// handleDeleteAccount removes an account and everything scoped by it.
//
//	DELETE /v1/accounts/:id  →  204
func (o options) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	account, _ := accountFrom(r.Context())

	if err := o.tenancy.Delete(r.Context(), account.ID); err != nil {
		o.writeTenancyError(w, r, err)
		return
	}
	noContent(w)
}

// handleInvite creates a pending invitation.
//
//	POST /v1/accounts/:id/invitations  {email, role}  →  201 {id, ..., token}
func (o options) handleInvite(w http.ResponseWriter, r *http.Request) {
	account, _ := accountFrom(r.Context())
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	var body *inviteRequest
	if !decodeBody(w, r, &body) {
		return
	}

	// The role goes over as a string and is parsed by the use case, so the owner
	// restriction and the unknown-role case are both decided in one place
	// whichever way this endpoint is reached.
	invited, err := o.tenancy.InviteRole(r.Context(), account.ID, body.Email, body.Role, user.ID)
	if err != nil {
		o.writeTenancyError(w, r, err)
		return
	}

	writeJSON(w, http.StatusCreated, invitationResponse{
		ID:        invited.Invitation.ID.String(),
		AccountID: invited.Invitation.AccountID.String(),
		Email:     invited.Invitation.Email,
		Role:      invited.Invitation.Role,
		Token:     invited.Token,
		ExpiresAt: invited.Invitation.ExpiresAt,
		CreatedAt: invited.Invitation.CreatedAt,
	})
}

// handleAcceptInvitation redeems an invitation.
//
//	POST /v1/invitations/accept  {token}  →  200 {account_id, user_id, role, created_at}
//
// There is no account in the path: the token names the account. The caller still
// has to be authenticated, because the membership created belongs to them.
func (o options) handleAcceptInvitation(w http.ResponseWriter, r *http.Request) {
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	var body *acceptInvitationRequest
	if !decodeBody(w, r, &body) {
		return
	}

	membership, err := o.tenancy.Accept(r.Context(), accounts.AcceptInput{Token: body.Token, User: user.ID})
	if err != nil {
		o.writeTenancyError(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, membershipResponse{
		AccountID: membership.AccountID.String(),
		UserID:    membership.UserID.String(),
		Role:      membership.Role,
		CreatedAt: membership.CreatedAt,
	})
}

// handleChangeRole moves a membership to a new role.
//
//	PATCH /v1/accounts/:id/members/:userId  {role}  →  200 {account_id, user_id, role, ...}
//
// The route's minimum is owner, so an admin and a member never reach this
// handler. The last-owner rule is the use case's, because it depends on how many
// owners the account has right now and not on the caller's role.
func (o options) handleChangeRole(w http.ResponseWriter, r *http.Request) {
	account, _ := accountFrom(r.Context())
	actor, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	target, ok := userIDFrom(r)
	if !ok {
		notFound(w, r)
		return
	}

	var body *changeRoleRequest
	if !decodeBody(w, r, &body) {
		return
	}

	role, err := accounts.ParseRole(body.Role)
	if err != nil {
		// A 422 naming the field, from this handler rather than from the use case,
		// because the use case is never reached: the request did not say what it
		// wanted. An empty role is the same case as an unknown one — there is no
		// "unchanged" in a PATCH body.
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the request has an invalid field").
			withFieldErrors([]FieldError{{Field: "role", Code: accounts.CodeUnknownRole}}))
		return
	}

	membership, err := o.tenancy.ChangeRole(r.Context(), accounts.ChangeRoleInput{
		AccountID: account.ID,
		UserID:    target,
		Role:      role,
		Actor:     actor.ID,
	})
	if err != nil {
		o.writeTenancyError(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, membershipResponse{
		AccountID: membership.AccountID.String(),
		UserID:    membership.UserID.String(),
		Role:      membership.Role,
		CreatedAt: membership.CreatedAt,
	})
}

// handleRemoveMember deletes a membership.
//
//	DELETE /v1/accounts/:id/members/:userId  →  204
//
// The route's minimum is admin. "An admin may not remove an owner" and "the last
// owner is never removed" are the use case's, because both depend on the target's
// role rather than the caller's.
func (o options) handleRemoveMember(w http.ResponseWriter, r *http.Request) {
	account, _ := accountFrom(r.Context())
	actor, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	target, ok := userIDFrom(r)
	if !ok {
		notFound(w, r)
		return
	}

	if err := o.tenancy.RemoveMember(r.Context(), accounts.RemoveMemberInput{
		AccountID: account.ID,
		UserID:    target,
		Actor:     actor.ID,
	}); err != nil {
		o.writeTenancyError(w, r, err)
		return
	}
	noContent(w)
}

// membershipResponses projects a member list onto the wire.
//
// EVERY FIELD IS FILLED, and that is the whole point of the function. It set only
// `Role` until packet identity-28 documented this surface, because
// `accounts.MemberSummary` was shaped for `ListMine` and carries no user — so
// the wire carried `account_id: ""`, `user_id: ""` and a zero `created_at` on
// every entry, and a member list was three rows a client could not tell apart and
// could not act on. `TestEveryMemberInAMemberListIdentifiesItself` holds it.
//
// The account id is `m.Account.ID` rather than a request parameter, so a member
// entry cannot describe an account other than the one whose members these are.
func membershipResponses(members []accounts.MemberSummary) []membershipResponse {
	out := make([]membershipResponse, 0, len(members))
	for _, m := range members {
		out = append(out, membershipResponse{
			AccountID: m.Account.ID.String(),
			UserID:    m.UserID.String(),
			Role:      m.Role,
			CreatedAt: m.JoinedAt,
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// error mapping
// ---------------------------------------------------------------------------

// writeTenancyError maps a tenancy use-case error onto the response.
//
// The table is short because the sentinels are few, and every row is a decision
// rather than a lookup:
//
//	ErrNotAMember          404  a non-member must not learn the account exists
//	ErrOwnerProtected      403  the caller may act here, just not on an owner
//	ErrLastOwner           422  understood, and describes an impossible state
//	ErrSelfRoleChange      422  the same, aimed at the caller who hit it
//	ErrRoleNotInvitable    422  a well-formed request for something that is not
//	ErrSlugTaken           409  a create-time conflict on a handle
//	ErrAlreadyAMember      409  the state the caller asked for already holds
//	ErrInvitation*Taken    409  a pending invitation for that address exists
//	ErrInvitationNotFound  404  a wrong token, and no more than that
//	ErrInvitationExpired   410  gone, and the fix is to ask for a new one
//	ErrInvitationUsed      410  gone, and asking again will not help
//
// Field errors from either package become a 422 with errors[]. The two types are
// checked separately because they are separately declared: a shared one would put
// an edge between users and accounts, and this handler is where that would have
// to be remembered.
func (o options) writeTenancyError(w http.ResponseWriter, r *http.Request, err error) {
	var (
		accountsField *accounts.FieldError
		usersField    *users.FieldError
	)

	switch {
	case errors.Is(err, accounts.ErrNotFound), errors.Is(err, accounts.ErrNotAMember):
		// One sentence, and it does not say which of the two happened. A caller who
		// is not a member learns nothing about whether the account exists.
		problemFor(w, r, http.StatusNotFound, CodeNotFound,
			"no such account is visible to you")

	case errors.Is(err, accounts.ErrOwnerProtected):
		problemFor(w, r, http.StatusForbidden, CodeForbidden,
			"only an owner may act on an owner's membership")

	case errors.Is(err, accounts.ErrLastOwner):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("this account must keep at least one owner").
			withFieldErrors([]FieldError{{Field: "role", Code: "last_owner"}}))

	case errors.Is(err, accounts.ErrSelfRoleChange):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("you are the only owner of this account and cannot change your own role").
			withFieldErrors([]FieldError{{Field: "role", Code: "last_owner"}}))

	case errors.Is(err, accounts.ErrRoleNotInvitable):
		// 422 and not 403: nothing about the caller is wrong. They asked for a
		// well-formed thing that does not exist, which is the definition of a
		// semantic failure.
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("an invitation may only carry the admin or member role").
			withFieldErrors([]FieldError{{Field: "role", Code: "not_invitable"}}))

	case errors.Is(err, accounts.ErrSlugTaken):
		problemFor(w, r, http.StatusConflict, CodeConflict,
			"an account with that name already exists; its handle is the name in lower case with dashes")

	case errors.Is(err, accounts.ErrAlreadyAMember):
		problemFor(w, r, http.StatusConflict, CodeConflict,
			"you are already a member of this account")

	case errors.Is(err, accounts.ErrInvitationEmailTaken):
		problemFor(w, r, http.StatusConflict, CodeConflict,
			"there is already a pending invitation for that address on this account")

	case errors.Is(err, accounts.ErrInvitationUsed):
		problemFor(w, r, http.StatusGone, CodeGone,
			"this invitation has already been accepted")

	case errors.Is(err, accounts.ErrInvitationExpired):
		problemFor(w, r, http.StatusGone, CodeGone,
			"this invitation has expired; ask for a new one")

	case errors.Is(err, accounts.ErrInvitationNotFound):
		// The same sentence as an unknown account, and the same status. A 403 here
		// would say the invitation exists; a 410 would say it too. Only 404 is
		// indistinguishable from an invitation that was never created, which is
		// what makes a guessed token useless.
		problemFor(w, r, http.StatusNotFound, CodeNotFound,
			"no invitation matches that token")

	case errors.As(err, &accountsField):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the request has an invalid field").
			withFieldErrors([]FieldError{{Field: accountsField.Field, Code: accountsField.Code}}))

	case errors.As(err, &usersField):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the request has an invalid field").
			withFieldErrors([]FieldError{{Field: usersField.Field, Code: usersField.Code}}))

	default:
		unexpected(w, r, o.logger, err)
	}
}
