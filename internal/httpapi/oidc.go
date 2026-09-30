package httpapi

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cafaye/identity/internal/accounts"
	"github.com/cafaye/identity/internal/auth"
	"github.com/cafaye/identity/internal/oauth"
	"github.com/cafaye/identity/internal/oidc"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/users"
)

// The OIDC surface: the protocol endpoints, the login page, and the
// registrations that decide who may use them.
//
// TWO ERROR SHAPES, AND THE SPLIT IS DELIBERATE.
//
//	/v1/* and /oidc/authorize's pre-checks   application/problem+json
//	everything else under /oidc/*            RFC 6749's {"error": ...}
//
// The protocol endpoints answer per the specifications, because the entire point
// of this packet is that an off-the-shelf OIDC client library can talk to this
// service. A client that gets a problem document where it expected `error` fails
// to parse the response, and a client library is exactly what is going to be
// pointed at this. core's convention is that "every non-2xx response is
// application/problem+json" and that is what the /v1 surface does; applying it to
// the OAuth endpoints would make this provider interop with nothing.
//
// The one exception is the pre-check below, which the brief specifies as a 400
// with the problem envelope, and which is a cafaye decision about a cafaye
// request rather than an OAuth protocol response.

// OIDC is the part of the OIDC provider the routes need.
//
// Declared here, at the consumer, for the same reason Auth and Tenancy are: the
// handlers are then testable against a double, and this file has no dependency on
// the library's types beyond the discovery document's own shape.
type OIDC interface {
	// Handler is the library's router, mounted path by path rather than at the
	// root. See oidc.Provider.Handler for why.
	Handler() http.Handler
	// Discovery is the document for a request, already narrowed.
	Discovery(r *http.Request) any
	// JWKS is the published key set, pre-rendered.
	JWKS() ([]byte, error)
	// LoginBanner is what the login page renders.
	LoginBanner(ctx context.Context, requestID string) (oidc.LoginBanner, error)
	// CompleteLogin records that a user authenticated against a request.
	CompleteLogin(ctx context.Context, requestID string, subject id.UUID) error
}

// OIDCClients is the client registration use cases, for the admin routes.
type OIDCClients interface {
	Register(ctx context.Context, in oidc.RegisterInput) (oidc.RegisteredClient, error)
	List(ctx context.Context, accountID id.UUID) ([]oidc.Client, error)
	Get(ctx context.Context, accountID, rowID id.UUID) (oidc.Client, error)
	Revoke(ctx context.Context, in oidc.RevokeInput) (oidc.Client, error)
}

// WithOIDC mounts the OIDC protocol surface and the login page.
//
// It is an Option for the reason WithAuth is: with no OIDC_SIGNING_KEY there is
// no key to sign with and no document to publish, and that process must still
// answer /healthz. The routes are absent rather than present-and-500.
func WithOIDC(p OIDC) Option {
	return func(o *options) {
		if p != nil {
			o.oidc = p
		}
	}
}

// WithOIDCClients mounts the client registration routes.
//
// Separate from WithOIDC because the registrations live in an account and are
// gated on the owner role, which is the tenancy router's business, and a process
// with a key but no tenancy service has no account to register against.
func WithOIDCClients(c OIDCClients) Option {
	return func(o *options) {
		if c != nil {
			o.oidcClients = c
		}
	}
}

// oidcRequestParam is the chi URL parameter naming the authorization request on
// the login page. A constant for the reason accountIDParam is one.
const oidcRequestParam = "requestID"

// oidcClientParam is the chi URL parameter naming a registration.
const oidcClientParam = "clientID"

// registerOIDCRoutes mounts the protocol surface and the login page.
//
// The four protocol routes and the login page are all delegations to the
// library's own router, and the delegation is per-path rather than a Mount at the
// root: mounting at the root would hand the library the unmatched-path case, and
// this service's 404 is a problem document with a trace id while the library's is
// net/http's plain-text one. A client that guessed a route wrong would then have
// two error shapes to parse.
func (o options) registerOIDCRoutes(r chiRouter) {
	if o.oidc == nil {
		return
	}

	// GET and POST, because OpenID Connect Core permits both and a product behind
	// a strict corporate proxy may have no choice. The pre-check reads r.Form,
	// which the library also reads, so parsing it here does not consume anything
	// the library has not already parsed.
	r.Get(oidc.PathAuthorize, o.handleOIDCAuthorize)
	r.Post(oidc.PathAuthorize, o.handleOIDCAuthorize)

	r.Get(oidc.PathAuthorizeCallback, o.delegateOIDC)
	r.Post(oidc.PathToken, o.delegateOIDC)
	r.Get(oidc.PathUserinfo, o.delegateOIDC)
	r.Post(oidc.PathUserinfo, o.delegateOIDC)

	r.Get(oidc.PathLogin+"/{"+oidcRequestParam+"}", o.handleOIDCLogin)
	r.Post(oidc.PathLogin+"/{"+oidcRequestParam+"}", o.handleOIDCLogin)
}

// The two well-known documents and the key set are served by this router rather
// than delegated, because each needs a content type and a cache policy this
// service owns. They are registered in New, not in registerOIDCRoutes, so they
// exist even for a process that has a tenancy service and no key — a discovery
// document for a provider with no key would be a lie, and New returns 404 for
// them in that case.
func (o options) registerOIDCWellKnownRoutes(r chiRouter) {
	if o.oidc == nil {
		return
	}
	r.Get(oidc.PathDiscovery, o.handleOIDCDiscovery)
	r.Get(oidc.PathOAuthAuthorizationServer, o.handleOIDCDiscovery)
	r.Get(oidc.PathJWKS, o.handleOIDCJWKS)
}

// delegateOIDC hands a request to the library's router unchanged.
func (o options) delegateOIDC(w http.ResponseWriter, r *http.Request) {
	o.oidc.Handler().ServeHTTP(w, r)
}

// handleOIDCDiscovery serves the metadata document at both well-known paths.
//
// Two paths, one document. RFC 8414 §3 and OpenID Connect Discovery §4 name two
// different URLs for the same metadata, and a client may fetch either. The
// library registers only the OpenID Connect one — its router has exactly one
// well-known route — so the RFC 8414 alias is mounted here rather than being left
// to a 404 that a conformant client has no way to interpret.
func (o options) handleOIDCDiscovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, o.oidc.Discovery(r))
}

// handleOIDCJWKS serves the published key set.
//
// Cache-Control is public and long because the document changes only when the
// signing key does, and guard's verifier caches it for five minutes anyway. A
// `no-store` here would mean every edge in the platform re-fetched it on a timer
// the operator cannot see.
func (o options) handleOIDCJWKS(w http.ResponseWriter, _ *http.Request) {
	document, err := o.oidc.JWKS()
	if err != nil {
		unexpected(w, nil, o.logger, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(document)
}

// handleOIDCAuthorize is the pre-check, and then the library.
//
// Four refusals, all 400 with the problem envelope, all decided before a request
// is stored and before a browser is redirected anywhere:
//
//   - an unknown scope, or a request with no openid. The library's own
//     ValidateAuthReqScopes silently DELETES a scope it does not recognise and
//     carries on, which is the wrong answer for a provider whose job is to be
//     legible to another program: the product would get a token with no claim in
//     it and nothing saying so.
//   - no code_challenge, or a method that is not S256. `plain` means the verifier
//     IS the challenge, which is only safe for a public client that has no secret
//     to steal, and every client in this table is confidential.
//   - prompt=login, consent or select_account, and max_age. This provider has no
//     consent screen and no re-authentication, and a product that asked for
//     `prompt=login` and got a silent sign-in would have been told the session was
//     re-established when it was not. Refusing is the honest answer; ignoring the
//     parameter is the one that costs somebody their account.
//
// prompt=none is NOT refused here. The library answers it with login_required,
// which is the specified answer, and it is the one interactive-free flow this
// provider gets right.
func (o options) handleOIDCAuthorize(w http.ResponseWriter, r *http.Request) {
	// Safe to call twice: net/http caches the result, and the library calls
	// ParseForm itself and gets the same values.
	if err := r.ParseForm(); err != nil {
		problemFor(w, r, http.StatusBadRequest, CodeInvalidRequest, "the authorization request could not be parsed")
		return
	}

	if detail, ok := checkAuthorizeParams(r.Form); !ok {
		problemFor(w, r, http.StatusBadRequest, CodeInvalidRequest, detail)
		return
	}

	o.delegateOIDC(w, r)
}

// checkAuthorizeParams is the pre-check, as one function returning a reason.
//
// It returns a sentence rather than a code so that the diagnosis is in `detail`,
// which core says is "specific to this occurrence and is not parsed by clients"
// — and the person reading it is a developer configuring a product, for whom
// "unknown scope: phone" is a five-minute fix and "invalid request" is an
// afternoon.
func checkAuthorizeParams(form url.Values) (string, bool) {
	scopes := strings.Fields(form.Get("scope"))
	if err := oidc.ValidateRequestedScopes(scopes); err != nil {
		return err.Error(), false
	}

	// RFC 7636 §4.3: an absent code_challenge_method means plain. Treating it as
	// S256 would accept a request that did not ask for S256.
	switch form.Get("code_challenge_method") {
	case string(oidcS256):
		if form.Get("code_challenge") == "" {
			return "code_challenge_method is S256 but no code_challenge was sent", false
		}
	case "":
		return "PKCE is required: send code_challenge with code_challenge_method=S256", false
	default:
		return fmt.Sprintf("code_challenge_method must be S256; this provider does not accept %q",
			form.Get("code_challenge_method")), false
	}

	for _, prompt := range form["prompt"] {
		switch prompt {
		case oidcPromptNone:
			// Answered by the library with login_required, which is right.
		default:
			return fmt.Sprintf("prompt=%s is not implemented; this provider has no consent screen and does not re-authenticate", prompt), false
		}
	}
	if form.Get("max_age") != "" {
		return "max_age is not implemented; this provider does not re-authenticate a signed-in user", false
	}

	return "", true
}

// The two protocol constants this file repeats rather than imports, so the
// pre-check does not have to reach into the library's packages for two strings.
const (
	oidcS256       = "S256"
	oidcPromptNone = "none"
)

// ---------------------------------------------------------------------------
// the login page
// ---------------------------------------------------------------------------

// OIDCStateProvider is the provider name this service's own state carries.
//
// oauth.NewState joins it to a random token, and oauth.VerifyState compares it
// against the route. Reusing internal/oauth's state rather than minting a second
// implementation is the brief's instruction and the right call anyway: the
// threat is identical — a browser following a URL the user did not choose — and
// two state implementations in one service is two chances to fix one of them
// wrongly.
const OIDCStateProvider = "oidc"

// OIDCStateCookiePrefix is the cookie the login form's state is sealed in.
//
// The __Host- prefix is the browser-enforced contract this service already uses
// for its session cookie: Secure, Path=/, and no Domain attribute, so a
// subdomain cannot set or overwrite it. The request id is in the name rather than
// only in the value, because one cookie for the whole service means two login
// tabs clobber each other's state and the first one to submit fails with a 400 —
// a real bug in the one page whose entire job is to work.
const OIDCStateCookiePrefix = "__Host-oidc-state-"

// OIDCStateTTL is how long a login form's state is worth accepting.
//
// It matches internal/oauth's state cookie Max-Age. A user who abandons the login
// and comes back tomorrow is not attacking anything, and a state that expired
// while they were away would be a form that cannot be submitted.
const OIDCStateTTL = 10 * time.Minute

// handleOIDCLogin is the page the protocol hands control to.
//
// GET renders the form, or completes the flow immediately for a user who already
// has a session — which is what makes silent re-authentication work for an
// `id_token_hint` and what makes signing in to a second product not require
// typing the same password twice. POST checks the password, sets the session
// cookie and completes.
func (o options) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	requestID := chi.URLParam(r, oidcRequestParam)

	if r.Method == http.MethodPost {
		o.completeOIDCLogin(w, r, requestID)
		return
	}

	banner, err := o.oidc.LoginBanner(r.Context(), requestID)
	if err != nil {
		o.writeOIDCError(w, r, err)
		return
	}

	// A user who is already signed in skips the form entirely. The state cookie
	// is not set on this path because nothing is going to be submitted.
	if user, ok := o.signedInUser(r); ok {
		o.finishOIDCLogin(w, r, banner.RequestID, user.ID)
		return
	}

	state, err := oauth.NewState(OIDCStateProvider)
	if err != nil {
		unexpected(w, r, o.logger, err)
		return
	}
	http.SetCookie(w, oidcStateCookie(banner.RequestID, state))

	writeHTML(w, http.StatusOK, oidcLoginPage(banner, state))
}

// completeOIDCLogin is the POST: verify the state, check the password, set the
// session, hand back to the library.
func (o options) completeOIDCLogin(w http.ResponseWriter, r *http.Request, requestID string) {
	if err := r.ParseForm(); err != nil {
		problemFor(w, r, http.StatusBadRequest, CodeInvalidRequest, "the login form could not be parsed")
		return
	}

	// THE CSRF CHECK. A cross-site POST to this URL would complete an
	// authorization request the user never chose and bind their browser to
	// somebody else's client. The sealed value is in a __Host- cookie the attacker's
	// origin cannot write, so a mismatch means the form and the cookie are from
	// different flows — which is the attack, or a tab that expired.
	sealed, err := r.Cookie(oidcStateCookieName(requestID))
	if err != nil || !oauth.VerifyState(OIDCStateProvider, sealed.Value, r.Form.Get("state")) {
		problemFor(w, r, http.StatusBadRequest, CodeInvalidRequest,
			"this login form has expired or was not opened by this browser; start again from the application")
		return
	}
	// Cleared as soon as it has been spent, so a replayed POST finds no cookie to
	// match even before the state check runs.
	clearOIDCStateCookie(w, requestID)

	email, password := r.Form.Get("email"), r.Form.Get("password")
	if email == "" || password == "" {
		// A 422 with the field, not a login attempt: there is nothing to check, and
		// running an argon2id verification on an empty password would cost a
		// memory-hard hash to learn that a form was submitted empty.
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the login form needs an email address and a password").
			withFieldErrors([]FieldError{
				{Field: "email", Code: "required"},
				{Field: "password", Code: "required"},
			}))
		return
	}

	result, err := o.auth.Login(r.Context(), auth.LoginInput{
		Email:     email,
		Password:  password,
		UserAgent: r.UserAgent(),
		IP:        remoteIP(r),
	})
	if err != nil {
		// The same mapping as POST /v1/session, and the same reason: a wrong
		// password and an unknown address must be one answer, or this page becomes
		// an account-enumeration oracle with a nicer coat of paint.
		o.writeAuthError(w, r, err)
		return
	}

	// The user the session belongs to. Login returned a token rather than a user
	// because the /v1 login response has no use for one, and re-reading the
	// session the service just wrote is one indexed query on a path that happens
	// once per sign-in. A failure here is a database problem and not a caller
	// problem — the session row exists — so it is a 500 with a trace id.
	user, err := o.auth.Authenticate(r.Context(), result.Token)
	if err != nil {
		unexpected(w, r, o.logger, fmt.Errorf("resolving the user behind a session this request just created: %w", err))
		return
	}

	// The session cookie is set before the redirect so a client that dies
	// mid-write is still signed in rather than holding a token nobody recorded.
	o.setSessionCookie(w, result.Token, result.ExpiresAt)
	o.finishOIDCLogin(w, r, requestID, user.ID)
}

// finishOIDCLogin completes the request and hands the browser to the library's
// callback, which is the only place an authorization code is minted.
func (o options) finishOIDCLogin(w http.ResponseWriter, r *http.Request, requestID string, subject id.UUID) {
	if err := o.oidc.CompleteLogin(r.Context(), requestID, subject); err != nil {
		o.writeOIDCError(w, r, err)
		return
	}

	// A clone with the callback's path, so the library's own router sees the URL
	// it expects. The original request is untouched: it is the caller's, and the
	// library's issuer interceptor and CORS handler both read it.
	proxied := r.Clone(r.Context())
	target := *r.URL
	target.Path = oidc.PathAuthorizeCallback
	target.RawQuery = url.Values{"id": []string{requestID}}.Encode()
	proxied.URL = &target
	proxied.RequestURI = ""

	o.delegateOIDC(w, proxied)
}

// signedInUser resolves the presented credential to a user without writing a
// response.
//
// It is silent on purpose: the login page uses it to decide whether to render a
// form, and a 401 written into the body of a page that is about to render a form
// would be a 401 in the middle of an HTML document.
func (o options) signedInUser(r *http.Request) (users.User, bool) {
	token := o.presentedToken(r)
	if token == "" {
		return users.User{}, false
	}
	user, err := o.auth.Authenticate(r.Context(), token)
	if err != nil {
		return users.User{}, false
	}
	return user, true
}

func oidcStateCookieName(requestID string) string {
	return OIDCStateCookiePrefix + requestID
}

func oidcStateCookie(requestID, state string) *http.Cookie {
	return &http.Cookie{
		Name:     oidcStateCookieName(requestID),
		Value:    state,
		Path:     "/", // required by the __Host- prefix
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(OIDCStateTTL / time.Second),
		Expires:  time.Now().Add(OIDCStateTTL),
	}
}

func clearOIDCStateCookie(w http.ResponseWriter, requestID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookieName(requestID),
		Value:    "",
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

// writeOIDCError maps the OIDC sentinels onto the cafaye envelope.
//
// These are all failures on paths a browser is on, not on a protocol endpoint, so
// the problem envelope is right here: the person reading them is a person.
func (o options) writeOIDCError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, oidc.ErrAuthRequestNotFound):
		problemFor(w, r, http.StatusNotFound, CodeNotFound,
			"this sign-in link has expired or was never valid; start again from the application")
	default:
		unexpected(w, r, o.logger, err)
	}
}

// loginPageData is what the template renders.
type loginPageData struct {
	ClientName string
	Email      string
	State      string
	Action     string
	Error      string
}

// loginTemplate is the whole login page.
//
// An inline template rather than a file because there is one page and it is
// thirty lines, and html/template rather than string concatenation because
// ClientName comes from a database row an account owner typed: escaping it by
// construction is the only way the page cannot be turned into an injection point
// by a product name. That is a real attack — register a client called
// `<script>…</script>` and the login page for EVERY product runs it — and it is
// the reason this is a template and not an fmt.Sprintf.
//
// There is no branding, no "forgot your password" link and no consent screen.
// The first two belong with the pages this service does not have yet, and the
// third would be a screen that says nothing.
var loginTemplate = template.Must(template.New("oidc-login").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in to {{.ClientName}}</title>
</head>
<body>
<main>
<h1>Sign in to {{.ClientName}}</h1>
{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}
<form method="post" action="{{.Action}}">
<input type="hidden" name="state" value="{{.State}}">
<p><label for="email">Email</label>
<input id="email" name="email" type="email" autocomplete="username" required value="{{.Email}}"></p>
<p><label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required></p>
<p><button type="submit">Sign in</button></p>
</form>
</main>
</body>
</html>
`))

// oidcLoginPage renders the form. Exported behaviour, unexported function: there
// is one caller and it is three lines above.
func oidcLoginPage(banner oidc.LoginBanner, state string) []byte {
	var out strings.Builder
	data := loginPageData{
		ClientName: banner.ClientName,
		Email:      banner.LoginHint,
		State:      state,
		Action:     banner.RequestID,
	}
	if err := loginTemplate.Execute(&out, data); err != nil {
		// A template that cannot render its own struct is a bug in this file, and
		// an empty body is the worst possible way to find out. The status is still
		// 200 because the caller has already written it by the time this returns.
		return []byte("<!DOCTYPE html><title>Sign in</title><p>Sign in is temporarily unavailable.</p>")
	}
	return []byte(out.String())
}

// writeHTML sends an HTML page.
//
// The content type is set by hand rather than by sniffing, and the security
// headers are the three that matter for a page carrying a password field: no
// framing, no sniffing, and a referrer policy that does not carry the URL — which
// for this page is an authorization request id — to anything the user clicks.
func writeHTML(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// ---------------------------------------------------------------------------
// client registration: the admin surface
// ---------------------------------------------------------------------------

// oidcClientResponse is the public projection of a registration.
//
// SecretDigest and the row id are both absent. The digest is what the row holds
// and a response that echoed it would tell a client something it has no use for;
// the row id IS returned, because it is the event subject and the path parameter
// for the revoke route, so a client that has just created a registration has to be
// able to name it again.
type oidcClientResponse struct {
	ID           string     `json:"id"`
	ClientID     string     `json:"client_id"`
	Name         string     `json:"name"`
	RedirectURIs []string   `json:"redirect_uris"`
	GrantTypes   []string   `json:"grant_types"`
	Scopes       []string   `json:"scopes"`
	CreatedAt    time.Time  `json:"created_at"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}

// oidcClientCreatedResponse adds the one-time secret.
//
// It appears in the 201 and nowhere else. There is no endpoint that re-reads it
// and no column that stores it, only its digest — the same rule that governs a
// session token, an invitation token and a password, and the reason is the same:
// a secret this service can produce again is a secret this service is storing.
type oidcClientCreatedResponse struct {
	oidcClientResponse
	ClientSecret string `json:"client_secret"`
}

// registerOIDCClientRequest is the body of POST /v1/accounts/:id/oidc-clients.
//
// It has no account_id, no created_by and no scopes the client may not have. The
// account comes from the path and the actor from the session, and the scope list
// is intersected with what this service implements at the use case — a request
// body cannot widen its own permissions by naming them.
type registerOIDCClientRequest struct {
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types"`
	Scopes       []string `json:"scopes"`
}

// registerOIDCClientRoutes mounts the registrations on the account's surface.
//
// The minimum is owner, and that is the decision this route exists to encode: a
// member of an account may read it, but adding a client is adding a new way for
// code to arrive in this product and get a token back out, and "can read the
// member list" is not authority to widen the perimeter. A non-member gets the
// usual 404 rather than a 403, because a 403 would confirm the account exists to
// somebody who has no business knowing.
func (o options) registerOIDCClientRoutes(r chiRouter) {
	if o.oidcClients == nil {
		return
	}
	r.Post("/v1/accounts/{accountID}/oidc-clients", o.requireAccountRole(accounts.RoleOwner, o.handleRegisterOIDCClient))
	r.Get("/v1/accounts/{accountID}/oidc-clients", o.requireAccountRole(accounts.RoleOwner, o.handleListOIDCClients))
	r.Get("/v1/accounts/{accountID}/oidc-clients/{clientID}",
		o.requireAccountRole(accounts.RoleOwner, o.handleGetOIDCClient))
	r.Delete("/v1/accounts/{accountID}/oidc-clients/{clientID}",
		o.requireAccountRole(accounts.RoleOwner, o.handleRevokeOIDCClient))
}

// handleRegisterOIDCClient registers a relying party for the caller's account.
//
//	POST /v1/accounts/:id/oidc-clients  {name, redirect_uris, grant_types, scopes}
//	  →  201 {id, client_id, client_secret, ...}
func (o options) handleRegisterOIDCClient(w http.ResponseWriter, r *http.Request) {
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}
	account, _ := accountFrom(r.Context())

	var body *registerOIDCClientRequest
	if !decodeBody(w, r, &body) {
		return
	}

	registered, err := o.oidcClients.Register(r.Context(), oidc.RegisterInput{
		AccountID:    account.ID,
		Name:         body.Name,
		RedirectURIs: body.RedirectURIs,
		GrantTypes:   body.GrantTypes,
		Scopes:       body.Scopes,
		RegisteredBy: user.ID,
	})
	if err != nil {
		o.writeOIDCClientError(w, r, err)
		return
	}

	writeJSON(w, http.StatusCreated, oidcClientCreatedResponse{
		oidcClientResponse: newOIDCClientResponse(registered.Client),
		ClientSecret:       registered.Secret,
	})
}

// handleListOIDCClients lists the account's registrations.
//
//	GET /v1/accounts/:id/oidc-clients  →  200 [{id, client_id, name, ...}]
//
// A bare array rather than the `data` + `page` wrapper core's pagination section
// describes, and the omission is a decision to record: the list is every
// registration one account owns, which is a handful, and a cursor over four rows
// is a wrapper a client has to unwrap to render a settings page. core's rule
// exists because offset pagination does not scale past thousands; this cannot
// reach thousands, because MaxRedirectURIs bounds a registration and the owner
// role bounds who may make one. The first account to want a hundred products gets
// the wrapper then.
func (o options) handleListOIDCClients(w http.ResponseWriter, r *http.Request) {
	account, _ := accountFrom(r.Context())

	list, err := o.oidcClients.List(r.Context(), account.ID)
	if err != nil {
		o.writeOIDCClientError(w, r, err)
		return
	}

	items := make([]oidcClientResponse, 0, len(list))
	for _, client := range list {
		items = append(items, newOIDCClientResponse(client))
	}
	writeJSON(w, http.StatusOK, items)
}

// handleGetOIDCClient reads one registration.
//
//	GET /v1/accounts/:id/oidc-clients/:clientId  →  200 {id, client_id, ...}
func (o options) handleGetOIDCClient(w http.ResponseWriter, r *http.Request) {
	account, _ := accountFrom(r.Context())

	rowID, ok := oidcClientIDFrom(r)
	if !ok {
		notFound(w, r)
		return
	}

	client, err := o.oidcClients.Get(r.Context(), account.ID, rowID)
	if err != nil {
		o.writeOIDCClientError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, newOIDCClientResponse(client))
}

// handleRevokeOIDCClient stops honouring a registration.
//
//	DELETE /v1/accounts/:id/oidc-clients/:clientId  →  204
//
// 204 rather than the revoked row, matching every other DELETE in this service:
// the caller asked for the credential to stop working, not for a description of
// its corpse. The `identity.oidc_client.revoked` event is where a consumer learns
// what happened.
func (o options) handleRevokeOIDCClient(w http.ResponseWriter, r *http.Request) {
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}
	account, _ := accountFrom(r.Context())

	rowID, ok := oidcClientIDFrom(r)
	if !ok {
		notFound(w, r)
		return
	}

	if _, err := o.oidcClients.Revoke(r.Context(), oidc.RevokeInput{
		AccountID: account.ID,
		ClientID:  rowID,
		RevokedBy: user.ID,
	}); err != nil {
		o.writeOIDCClientError(w, r, err)
		return
	}
	noContent(w)
}

// oidcClientIDFrom reads and parses the registration id in the path, on the same
// terms as accountIDFrom: a value this service did not issue is the same answer
// as one it did and the caller may not see.
func oidcClientIDFrom(r *http.Request) (id.UUID, bool) {
	parsed, err := id.Parse(chi.URLParam(r, oidcClientParam))
	if err != nil || parsed.IsZero() {
		return id.UUID{}, false
	}
	return parsed, true
}

func newOIDCClientResponse(c oidc.Client) oidcClientResponse {
	return oidcClientResponse{
		ID:           c.ID.String(),
		ClientID:     c.ClientID,
		Name:         c.Name,
		RedirectURIs: c.RedirectURIs,
		GrantTypes:   c.GrantTypes,
		Scopes:       c.Scopes,
		CreatedAt:    c.CreatedAt,
		RevokedAt:    c.RevokedAt,
	}
}

// writeOIDCClientError maps the registration errors onto the envelope.
//
//	ErrNotFound     404  the row, or the account, is not the caller's to know
//	ErrAlreadyRevoked 409  the credential is already dead; a 204 would leave an
//	                       operator believing they had just destroyed a second one
//	*FieldError     422  understood, and one field is not acceptable
//
// The secret and the revoked case are one 400 at the TOKEN endpoint and are
// deliberately indistinguishable there; they are told apart here, where the caller
// is an owner looking at a settings page and needs to know which happened.
func (o options) writeOIDCClientError(w http.ResponseWriter, r *http.Request, err error) {
	var fieldErr *oidc.FieldError

	switch {
	case errors.Is(err, oidc.ErrNotFound):
		problemFor(w, r, http.StatusNotFound, CodeNotFound, "no such OIDC client is visible to you")

	case errors.Is(err, oidc.ErrAlreadyRevoked):
		problemFor(w, r, http.StatusConflict, CodeConflict, "this OIDC client is already revoked")

	case errors.As(err, &fieldErr):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the request has an invalid field").
			withFieldErrors([]FieldError{{Field: fieldErr.Field, Code: fieldErr.Code}}))

	default:
		unexpected(w, r, o.logger, err)
	}
}
