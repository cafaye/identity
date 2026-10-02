package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cafaye/identity/internal/accounts"
	"github.com/cafaye/identity/internal/auth"
	"github.com/cafaye/identity/internal/mfa"
	"github.com/cafaye/identity/internal/oauth"
	"github.com/cafaye/identity/internal/oidc"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/sessions"
	"github.com/cafaye/identity/internal/users"
)

// The OIDC surface: the protocol endpoints, the login interaction, and the
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
//
// AND A THIRD SHAPE, ON THE INTERACTION ONLY: a refusal that can be re-shown is
// a REDIRECT to the configured login UI carrying `error` and `error_detail` in
// the query, because the reader is a page on another origin and a problem
// document is not something it can render. The section header on the interaction
// says which refusals travel and which do not, and why.

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
	// LoginBanner is what the login UI needs to render a step.
	LoginBanner(ctx context.Context, requestID string) (oidc.LoginBanner, error)
	// LoginRedirect is the absolute URL a browser is sent to in order to
	// authenticate for one authorization request. It is on this interface rather
	// than on a field because the address is PROVIDER configuration, validated
	// where it is parsed, and a second copy of it in the router is a second answer
	// to "where does a browser go to sign in".
	LoginRedirect(params oidc.LoginRedirectParams) string
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

// delegateOIDC hands a request to the library's router, and strips the body off
// any redirect it answers with.
//
// # WHY THE STRIPPING, AND IT IS NOT COSMETIC
//
// The library answers `/oidc/authorize` with `http.Redirect`, and net/http's
// Redirect writes a body when the caller has not set a Content-Type: a one-line
// anchor, `Content-Type: text/html; charset=utf-8`, the courtesy RFC 9110 §15.4
// recommends for a user agent that cannot follow a redirect. Every user agent in
// the deployment can follow one, and the claim this service would be making by
// leaving it in place is that it serves HTML. It does not, and a reviewer who
// runs `curl -i` against `/oidc/authorize` and reads `Content-Type: text/html`
// is right to say the packet did not land.
//
// So the response is buffered and, if it is a redirect, only the status and the
// headers are written. A redirect with a body is not a thing anybody reads, and
// this is the only place in the tree where a response from another library is
// rewritten — which is why it is here and not in the middleware, where it would
// silently apply to every route.
//
// # IT APPLIES TO EVERY DELEGATED REDIRECT, NOT JUST THE LOGIN ONE, and that is
// the right scope. The authorization-code redirect back to the product is the same
// kind of response: no body, no representation, and the same courtesy anchor. A
// rule that stripped the body on one path and not the other would be a rule about
// which path somebody remembered.
//
// # IT DROPS THE CONTENT TYPE AND THE LENGTH AS WELL, AND THE RED PROOF IS WHY
//
// Stripping the body alone is not enough, and that was measured rather than
// reasoned: with this function copying the library's headers verbatim and dropping
// only the bytes, `GET /oidc/authorize` answered
// `Content-Type: text/html; charset=utf-8` with an EMPTY body — which is the worst
// of both, because a client that believes the header is told to parse a document
// and finds nothing.
//
// `TestTheAuthorizeRedirectCarriesNoBody` is the test that caught it, and it
// caught it because it asserts on the headers as well as the bytes.
func (o options) delegateOIDC(w http.ResponseWriter, r *http.Request) {
	buffer := httptest.NewRecorder()
	o.oidc.Handler().ServeHTTP(buffer, r)

	header := w.Header()
	for name, values := range buffer.Header() {
		header[name] = values
	}

	if isRedirect(buffer.Code) {
		// The response no longer has the body those two headers described. Leaving
		// them is not a cosmetic choice: a Content-Type is a browser's instruction
		// about how to interpret what follows, and there is nothing following.
		header.Del("Content-Type")
		header.Del("Content-Length")
		w.WriteHeader(buffer.Code)
		return
	}

	w.WriteHeader(buffer.Code)
	_, _ = w.Write(buffer.Body.Bytes())
}

// isRedirect is the 3xx range, which is the whole of RFC 9110's "redirection
// status codes".
func isRedirect(status int) bool { return status >= 300 && status < 400 }

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

	// THE FLOW MARKER, set here because this is the only place the start of a
	// flow is observable. The browser is about to be redirected to a login URL
	// carrying a request id that is a bearer capability for that authorization
	// request, and handleOIDCLogin refuses to complete it unless this cookie is
	// present — so a browser that arrived at a login URL some other way cannot
	// spend a session it happens to hold.
	//
	// It is set AFTER the pre-check and not before it, so a request this service
	// refuses outright does not leave a marker behind. It is set on BOTH the
	// success and the library's own refusal, which is correct: the library's
	// refusals redirect back to the client rather than to the login page, so the
	// marker is spent either way and cannot accumulate meaning.
	if state, err := oauth.NewState(OIDCStateProvider); err != nil {
		unexpected(w, r, o.logger, err)
		return
	} else {
		http.SetCookie(w, oidcFlowCookie(state))
	}

	o.delegateOIDC(w, r)
}

// oidcFlowCookie writes the flow marker.
//
// Its lifetime is the login form's, because it exists to carry a browser from
// `/oidc/authorize` to `/oidc/login/{id}` and for no longer. A user who walks
// away mid-sign-in does not come back tomorrow with a marker that still works.
func oidcFlowCookie(state string) *http.Cookie {
	return &http.Cookie{
		Name:     OIDCFlowCookieName,
		Value:    state,
		Path:     "/", // required by the __Host- prefix
		Secure:   true,
		HttpOnly: true,
		// Lax, like every other cookie this service sets. The flow marker rides a
		// top-level redirect from /oidc/authorize to the login page, which is
		// exactly what Lax permits and Strict would break.
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(OIDCStateTTL / time.Second),
		Expires:  time.Now().Add(OIDCStateTTL),
	}
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
// the login interaction: identity decides, somebody else renders
// ---------------------------------------------------------------------------
//
// THE SHAPE OF IT. This service owns two of the three steps of a sign-in and
// renders none of them:
//
//	GET  /oidc/authorize            302 -> /oidc/login/{request_id}   (the library)
//	GET  /oidc/login/{request_id}   302 -> the configured login UI     (a browser)
//	POST /oidc/login/{request_id}   302 -> the client's redirect_uri, OR back to
//	                                 the login UI carrying the refusal
//
// The credentials are checked here, the session cookie is set here, and the
// authorization code is minted here. What leaves is the form. The parameter names
// in that redirect, and the codes on the way back, are a PUBLISHED contract with
// the login UI and they live in internal/oidc/loginui.go, which is also where the
// reasoning is.
//
// # WHICH REFUSALS TRAVEL AND WHICH DO NOT, AND WHY THE LINE IS WHERE IT IS
//
// A refusal that identity can answer by re-showing the step becomes a redirect
// carrying `error` and `error_detail` — the same split the problem envelope makes
// between `code` and `detail`, so a login UI already switching on
// `account_locked` needs no second vocabulary. A refusal it cannot is a problem
// document, and there are exactly four kinds:
//
//	a request id that does not exist    nothing to re-show, and no id the login
//	                                    UI could post back. A 404.
//	a body that will not parse          identity and the browser do not agree on
//	                                    what was sent, so a redirect would be a
//	                                    page asking for a form a second time. A
//	                                    400.
//	a signed-in browser with no flow    the D5 refusal. It says "this sign-in was
//	                                    cookie                             not started
//	                                    here", and the product has to restart the
//	                                    flow from its own redirect, which is
//	                                    where the flow cookie gets set. A 403.
//	anything else                      a server error, or a deployment that cannot
//	                                    verify a second factor. The reader of one
//	                                    of those is an operator with the log, and
//	                                    `trace_id` is what they need — which is
//	                                    the opposite requirement from the three
//	                                    above and the reason it is listed.
//
// # THE FOUR THINGS THAT SURVIVE THE MOVE, and why each one does
//
//  1. The flow cookie, unchanged, at the same place, and still `Lax`. The
//     browser-binding argument in handleOIDCLogin is untouched: it is a top-level
//     GET, it is answered by a handler on this origin, and the request id is
//     still a bearer capability in a URL that somebody could have sent.
//  2. The state, still sealed in a `__Host-` cookie and still minted by
//     internal/oauth's own NewState. What changed is WHEN the cookie is sent, and
//     oidcInteractionSameSite below argues why that costs nothing.
//  3. The password check, the MFA branch and the lockout, all through the same
//     internal/auth calls POST /v1/session makes. One credential store, one
//     password check, one lockout counter.
//  4. The four headers writeHTML set, minus two. See oidcRedirect.

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
// a real bug in the one interaction whose entire job is to work.
const OIDCStateCookiePrefix = "__Host-oidc-state-"

// OIDCStateTTL is how long a login form's state is worth accepting.
//
// It matches internal/oauth's state cookie Max-Age. A user who abandons the login
// and comes back tomorrow is not attacking anything, and a state that expired
// while they were away would be a form that cannot be submitted.
const OIDCStateTTL = 10 * time.Minute

// OIDCFlowCookieName marks a browser that has been handed an authorization
// request by THIS service.
//
// It is the proof that the browser holding it began the flow rather than arriving
// at a login URL somebody else chose, and it is set at handleOIDCAuthorize —
// which is the only point where the start of a flow is observable. This handler
// cannot set it, because by the time this handler runs the two cases are
// indistinguishable: a browser that legitimately followed the redirect from
// `/oidc/authorize` and a browser that followed a link to `/oidc/login/{id}` are
// the same GET with the same ambient session cookie.
//
// `__Host-`, so no other origin can write it. The property is entirely that the
// cookie could only have been set by this service on this deployment.
//
// It is deliberately NOT keyed by request id. The id does not exist until the
// library has created the row, which is after this cookie must already have been
// written, and binding it later would mean the cookie is set by the very endpoint
// the attack aims at. One cookie for the service answers "did a flow start here",
// which is a question about the browser and not about one request.
const OIDCFlowCookieName = "__Host-oidc-flow"

// handleOIDCLogin is where the protocol hands control to a person, and where
// this service hands control to whoever RENDERS a person.
//
// GET completes the flow immediately for a user who already has a session — which
// is what makes silent re-authentication work for an `id_token_hint` and what
// makes signing in to a second product not require typing the same password
// twice — and otherwise redirects the browser to the configured login UI with
// everything that page needs. POST checks the password, sets the session cookie
// and completes, or redirects back to the login UI with the refusal.
//
// THE SILENT PATH IS GATED ON OIDCFlowCookieName, and that gate is the whole of
// this handler's authorization. finishOIDCLogin completes an authorization
// request for whoever asks, so the question is not "is this user authenticated"
// — it is "did THIS BROWSER start THIS flow". A live session answers the first
// and says nothing about the second: a session is per-user, while the request
// belongs to one client, one redirect_uri and one PKCE verifier, all of which
// belong to whoever began the flow.
//
// WITHOUT THE GATE this endpoint is a login-CSRF oracle. The request id is a uuid
// in a URL, so it is not secret in any way a user-agent boundary respects: it is
// in the address bar, in history, and in whatever link somebody sent them. Anyone
// who can get a signed-in user's browser to make a top-level GET to
// `/oidc/login/{id}` — a link, an image, a redirect — has that browser complete
// the authorization request with no interaction at all, and the code is
// redirected to the redirect_uri of the client that chose it. The attacker holds
// that client's secret and its PKCE verifier, so they exchange the code and hold
// an id_token whose subject is the victim.
//
// MOVING THE FORM OUT DOES NOT WEAKEN THIS AND THE REASON IS WORTH WRITING DOWN,
// because it is the obvious objection: the flow cookie is SameSite=Lax, and a
// Lax cookie is not sent on a cross-site request, so a sign-in the victim never
// started could now complete without one. It cannot, and the reason is that the
// flow is a TWO-STEP thing in the other direction too. A stranger who sends a
// signed-in victim's browser to `/oidc/login/{attackerRequestID}` does NOT reach
// a code: the GET finds a session, finds no flow cookie, and answers 403 — the
// same 403 it has always answered. If the victim is signed OUT, the GET mints a
// state and sends them to the login UI, where they are told which product is
// asking and they type a password; and a person who types their password into a
// sign-in that names the product is not being attacked by this handler, they are
// signing in.
//
// `state` does not help, and the reason is worth stating precisely: state is the
// CLIENT's defence against CSRF against the client's own callback, and the
// attacker here IS the client, so they know their own state. `prompt=login` and
// `max_age` — the two levers a client has for demanding interaction — are both
// refused by checkAuthorizeParams, so there is nothing else to fall back on.
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

	// A user who is already signed in skips the interaction entirely — but only in
	// a browser this service handed a flow to.
	if user, ok := o.signedInUser(r); ok {
		if !o.browserStartedThisFlow(r) {
			// No flow cookie: this browser arrived at a login URL carrying nothing
			// but an ambient session. Answering 403 rather than redirecting to the
			// login UI is deliberate, and the page moving out is not the reason —
			// the login UI would happily show a password field, and completing that
			// flow would bind the victim's browser to the attacker's client. The
			// honest answer is "this sign-in was not started here", and the product
			// restarts the flow from its own redirect, which sets the cookie on the
			// way past.
			problemFor(w, r, http.StatusForbidden, CodeForbidden,
				"this sign-in was not started in this browser; start again from the application")
			return
		}
		o.finishOIDCLogin(w, r, banner.RequestID, user.ID)
		return
	}

	o.beginOIDCInteraction(w, r, banner, oidc.LoginStepPassword, oidcInteraction{})
}

// oidcInteraction is a refusal on its way back to the login UI.
//
// It is a struct rather than three arguments because the four call sites that
// build one are the four ways the interaction can fail, and a caller that
// remembered `retryAfter` but not `code` would send a UI a sentence with no code
// to switch on. The zero value is "nothing went wrong", which is the right
// default and is what the challenge step passes.
type oidcInteraction struct {
	// code is one of internal/oidc's interaction error constants. Empty means no
	// refusal, and an empty code is OMITTED from the redirect rather than sent as
	// an empty string — a login UI cannot tell those two apart with `if (error)`.
	code string
	// detail is the sentence a person reads. Never the contract.
	detail string
	// retryAfter is whole seconds, and only set with the account-locked code.
	retryAfter string
}

// beginOIDCInteraction mints a state, seals it in the cookie, and sends the
// browser to the login UI.
//
// THE STATE IS MINTED HERE AND NOT BY THE LOGIN UI, and the reason is that the
// login UI is not a party to a decision about this origin's cookies. The sealed
// copy has to be in a `__Host-` cookie on THIS origin, which the login UI's
// origin can neither read nor write, and the only party that can put one there is
// this service. So the login UI receives an opaque value and posts it back.
//
// `error` and `errorDetail` are empty on a fresh step and set on a refusal, and
// the two cases are different pages: one asks for a password, the other asks for
// the same password and says why the last one did not work.
// The banner is passed IN rather than read here, and that is why a refusal can
// reach this function at all: the caller that answers a refusal has already looked
// the banner up, and a request id that no longer exists is refused there — see
// failOIDCInteraction, which is the only place a "cannot be re-shown" is decided
// on this path.
func (o options) beginOIDCInteraction(w http.ResponseWriter, r *http.Request, banner oidc.LoginBanner, step string, failure oidcInteraction) {
	state, err := oauth.NewState(OIDCStateProvider)
	if err != nil {
		unexpected(w, r, o.logger, err)
		return
	}

	http.SetCookie(w, oidcStateCookie(banner.RequestID, state))

	oidcRedirect(w, o.oidc.LoginRedirect(oidc.LoginRedirectParams{
		RequestID:   banner.RequestID,
		State:       state,
		Step:        step,
		ClientName:  banner.ClientName,
		LoginHint:   banner.LoginHint,
		Error:       failure.code,
		ErrorDetail: failure.detail,
		RetryAfter:  failure.retryAfter,
	}))
}

// browserStartedThisFlow reports whether this browser was handed an
// authorization request by handleOIDCAuthorize.
//
// The check is on the SHAPE of the cookie rather than on a compared secret: its
// value is random and only its presence is load-bearing, so there is nothing here
// for a constant-time comparison to protect. What the `__Host-` prefix buys is
// that no other origin could have written the cookie at all, and that is the
// property being spent — so a cookie this service did not write is refused, and
// so is one written with a value this service never mints.
func (o options) browserStartedThisFlow(r *http.Request) bool {
	cookie, err := r.Cookie(OIDCFlowCookieName)
	if err != nil {
		return false
	}
	// VerifyState with the value as both arguments is a shape test that reuses
	// the one parser in the service: it requires the provider prefix and a
	// non-empty token and rejects a second separator, which is exactly what
	// "a value this service minted" means.
	return oauth.VerifyState(OIDCStateProvider, cookie.Value, cookie.Value)
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
	//
	// A MISMATCH REDIRECTS RATHER THAN ANSWERING 400, and the difference is the
	// whole of this packet's hard part. The state in the query is the very value
	// that failed to verify, so there is no state to hand the login UI — but
	// identity can mint a FRESH one, because minting a state is not a property of
	// the state. So the user is sent back to the form with a new one and a
	// sentence saying what happened, instead of being shown a problem document on
	// an origin the login UI does not own. A user whose tab expired thirty seconds
	// ago should not have to recognise a JSON document as the price of signing in.
	sealed, err := r.Cookie(oidcStateCookieName(requestID))
	if err != nil || !oauth.VerifyState(OIDCStateProvider, sealed.Value, r.Form.Get("state")) {
		o.failOIDCInteraction(w, r, requestID, oidcInteraction{
			code: oidc.LoginErrorInteractionExpired,
			detail: "this sign-in was not started in this browser, or it expired; " +
				"start again from the application",
			// The step is deliberately the PASSWORD one: a state that did not verify
			// says nothing about how far the interaction got, and the code step
			// without a live challenge would only fail again.
		}, oidc.LoginStepPassword)
		return
	}
	// Cleared as soon as it has been spent, so a replayed POST finds no cookie to
	// match even before the state check runs.
	clearOIDCStateCookie(w, requestID)

	// THE CHALLENGE STEP. The state has already been spent above, so this is a
	// second request of its own and NOT a re-render of the form: it carries a code,
	// not an email and a password.
	//
	// IT IS DISCRIMINATED BY THE PRESENCE OF THE `code` FIELD, and not by the
	// presence of a challenge cookie. A cookie is AMBIENT: a browser can easily
	// arrive at this POST holding a challenge from an earlier attempt — a user who
	// mistyped a code, went back to the product and started again — and a password
	// submission carrying a stale challenge cookie must still be a password
	// submission. Keying off the cookie sends it down the challenge path with an
	// empty code and answers 401 to a perfectly good password, which is a bug that
	// only appears on the second attempt and looks like a wrong password.
	//
	// Presence rather than non-emptiness, so a hand-written POST with an empty code
	// is answered as a refused code rather than as a request for an email address.
	if _, isChallenge := r.Form["code"]; isChallenge {
		o.completeOIDCChallenge(w, r, requestID)
		return
	}

	email, password := r.Form.Get("email"), r.Form.Get("password")
	if email == "" || password == "" {
		// A refusal, not a login attempt: there is nothing to check, and running an
		// argon2id verification on an empty password would cost a memory-hard hash
		// to learn that a form was submitted empty. One code for both fields,
		// because the login UI highlights the two of them the same way and the
		// sentence is about the form rather than about either field.
		o.failOIDCInteraction(w, r, requestID, oidcInteraction{
			code:   oidc.LoginErrorMissingCredentials,
			detail: "this sign-in needs both an email address and a password",
		}, oidc.LoginStepPassword)
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
		// password and an unknown address must be one answer, or this becomes an
		// account-enumeration oracle with a nicer coat of paint.
		o.failOIDCLogin(w, r, requestID, err)
		return
	}

	// A CORRECT PASSWORD IS NOT A SIGNED-IN USER. A user whose account has a second
	// factor gets the code step here exactly as they would through POST /v1/session,
	// and no authorization code is minted, because CompleteLogin is never called on
	// this branch. A handler that quietly completed the flow for such a user would
	// be the single worst bug this service could have: it would be invisible, it
	// would affect every MFA user of every product, and MFA would be off in
	// practice while being on in the database.
	if result.MFARequired {
		o.beginOIDCChallenge(w, r, requestID, result)
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

// failOIDCLogin maps a login failure onto the interaction, and it is the
// enumeration property in one function.
//
// A wrong password, an unregistered address, and — after the lockout trips — a
// locked account are the answers this handler has always given, and every one of
// them comes back through here so that the login UI has exactly one shape to
// render. What the login UI does NOT get is the distinction: `invalid_credentials`
// is one code and one sentence for the first two, and `account_locked` names the
// lockout, which the JSON surface has always named too. A stranger learns
// nothing they could not already learn from POST /v1/session, which is the surface
// the lockout is actually for.
func (o options) failOIDCLogin(w http.ResponseWriter, r *http.Request, requestID string, err error) {
	var (
		locked   *auth.LockedError
		fieldErr *users.FieldError
	)

	switch {
	case errors.As(err, &locked):
		o.failOIDCInteraction(w, r, requestID, oidcInteraction{
			code:       oidc.LoginErrorAccountLocked,
			detail:     "too many failed sign-in attempts for this account",
			retryAfter: retryAfterSeconds(locked.RetryAfter),
		}, oidc.LoginStepPassword)

	case errors.Is(err, auth.ErrInvalidCredentials), errors.Is(err, auth.ErrUnauthenticated):
		// ONE SENTENCE for a wrong password and for an address nobody has. The login
		// form is the most attractive enumeration oracle on the platform: it is
		// unauthenticated, it takes an address, and the first thing anybody types
		// into it is somebody else's.
		o.failOIDCInteraction(w, r, requestID, oidcInteraction{
			code:   oidc.LoginErrorInvalidCredentials,
			detail: "that email address and password were not accepted",
		}, oidc.LoginStepPassword)

	case errors.Is(err, users.ErrEmailTaken):
		// Not reachable by a person filling in a form, and refused with its own
		// sentence rather than as invalid_credentials, because it is the one answer
		// on this surface that says something about a row. Carried rather than
		// dropped: a refusal identity can name is a refusal it can hand on.
		o.failOIDCInteraction(w, r, requestID, oidcInteraction{
			code:   CodeConflict,
			detail: "an account already exists for that email address",
		}, oidc.LoginStepPassword)

	case errors.As(err, &fieldErr):
		o.failOIDCInteraction(w, r, requestID, oidcInteraction{
			code:   oidc.LoginErrorInvalidCredentials,
			detail: "that email address and password were not accepted",
		}, oidc.LoginStepPassword)

	default:
		unexpected(w, r, o.logger, err)
	}
}

// failOIDCInteraction is the one place a refusal becomes a redirect back to the
// login UI, and the step is an ARGUMENT because it is a decision and not a
// consequence: a refused code belongs on the code step, and an expired
// interaction belongs on the password step.
//
// IT IS ALSO THE ONLY PLACE ON THIS PATH A "CANNOT BE RE-SHOWN" IS DECIDED, and
// that is why the banner is read here rather than in beginOIDCInteraction. An id
// that no longer exists is one of the four refusals that must be a problem
// document: there is nothing to render, and — the part that actually forces it —
// there is no `request_id` the login UI could post back, so a redirect would send
// a page to a URL it cannot complete.
func (o options) failOIDCInteraction(w http.ResponseWriter, r *http.Request, requestID string, failure oidcInteraction, step string) {
	banner, err := o.oidc.LoginBanner(r.Context(), requestID)
	if err != nil {
		o.writeOIDCError(w, r, err)
		return
	}
	o.beginOIDCInteraction(w, r, banner, step, failure)
}

// OIDCChallengeCookiePrefix is where the challenge token waits between the two
// steps of the interaction.
//
// __Host- and per-request-id, for the same reasons as the state cookie above and
// with the same reasoning about two tabs: the request id is in the NAME, because
// one cookie for the whole service means two login tabs clobber each other's
// challenge and the first to submit fails — a real bug in the one interaction
// whose entire job is to work.
const OIDCChallengeCookiePrefix = "__Host-oidc-mfa-"

// oidcChallengeCookieName is the challenge cookie for one authorization request.
func oidcChallengeCookieName(requestID string) string {
	return OIDCChallengeCookiePrefix + requestID
}

// beginOIDCChallenge sends the browser to the code step with a fresh challenge.
//
// The state is re-minted because the first one was SPENT by the password POST: a
// sealed value that is still in the cookie after it has been used would be a CSRF
// token that works twice, and the whole point of sealing it is that it does not.
func (o options) beginOIDCChallenge(w http.ResponseWriter, r *http.Request, requestID string, result auth.LoginResult) {
	if result.Challenge == nil || result.Challenge.Token == "" {
		unexpected(w, r, o.logger, errNoChallengeToken)
		return
	}

	// The challenge cookie is written BEFORE the redirect, for the same reason the
	// session cookie is written before the one in completeOIDCLogin: a client that
	// dies mid-write has a page with no cookie and a 500, and a cookie with no page
	// is a sign-in the user can finish.
	http.SetCookie(w, oidcChallengeCookie(requestID, result.Challenge.Token, result.Challenge.ExpiresAt))

	banner, err := o.oidc.LoginBanner(r.Context(), requestID)
	if err != nil {
		o.writeOIDCError(w, r, err)
		return
	}
	o.beginOIDCInteraction(w, r, banner, oidc.LoginStepChallenge, oidcInteraction{})
}

// completeOIDCChallenge is the second POST: check the code, and only then set the
// session and hand back to the library.
//
// It goes through auth.CompleteSecondFactor, the same call POST /v1/session/mfa
// makes, because there is exactly one place in this service that turns a second
// factor into a session and having two would be the bug this packet exists to
// prevent.
func (o options) completeOIDCChallenge(w http.ResponseWriter, r *http.Request, requestID string) {
	cookie, err := r.Cookie(oidcChallengeCookieName(requestID))
	if err != nil || cookie.Value == "" {
		// The password step, not the code step: there is no challenge to answer, so
		// the only way forward is the password. See the comment at the call site in
		// completeOIDCLogin for why this used to be a 401 problem document and why
		// a login UI cannot render one.
		o.failOIDCInteraction(w, r, requestID, oidcInteraction{
			code:   oidc.LoginErrorInteractionExpired,
			detail: "this sign-in expired before the code was entered; start again from the application",
		}, oidc.LoginStepPassword)
		return
	}

	result, err := o.auth.CompleteSecondFactor(r.Context(), auth.CompleteSecondFactorInput{
		ChallengeToken: cookie.Value,
		Code:           r.Form.Get("code"),
	})
	if err != nil {
		// A wrong code goes back to the code step with a message rather than
		// stopping, so the user can type the next one. Every refusal is the same
		// sentence whatever went wrong, for the same reason as everywhere else on
		// this surface.
		o.failOIDCChallenge(w, r, requestID, err)
		return
	}

	// Spent, so a replayed POST finds nothing.
	clearOIDCChallengeCookie(w, requestID)

	user, err := o.auth.Authenticate(r.Context(), result.Token)
	if err != nil {
		unexpected(w, r, o.logger, fmt.Errorf("resolving the user behind a session this request just created: %w", err))
		return
	}
	o.setSessionCookie(w, result.Token, result.ExpiresAt)
	o.finishOIDCLogin(w, r, requestID, user.ID)
}

// failOIDCChallenge maps a second-factor failure onto the code step, and it NEVER
// says which part was wrong. A user who mistyped a code and a user replaying a
// code get the same sentence, because they are the same answer.
//
// THE CHALLENGE COOKIE SURVIVES A REFUSAL, deliberately. It is not spent by a
// wrong code — internal/mfa's per-factor lockout is what bounds that, and
// consuming the challenge as well would mean the fifth attempt starts a new
// challenge and the lockout never trips. So the user is sent back to the same
// challenge, and a correct code typed next is the code that works.
func (o options) failOIDCChallenge(w http.ResponseWriter, r *http.Request, requestID string, err error) {
	var locked *sessions.LockedError

	switch {
	case errors.As(err, &locked):
		o.failOIDCInteraction(w, r, requestID, oidcInteraction{
			code:       oidc.LoginErrorAccountLocked,
			detail:     "too many failed attempts at the second factor",
			retryAfter: retryAfterSeconds(locked.RetryAfter),
		}, oidc.LoginStepChallenge)

	case errors.Is(err, mfa.ErrInvalidFactor), errors.Is(err, auth.ErrInvalidCredentials),
		errors.Is(err, auth.ErrUnauthenticated):
		// ONE SENTENCE for every way a code can fail, and it does not say which.
		// The most common real cause is a code already used, and a user who has
		// just pasted the same digits twice needs the next code, not a diagnosis.
		o.failOIDCInteraction(w, r, requestID, oidcInteraction{
			code: oidc.LoginErrorChallengeRejected,
			detail: "that code was not accepted; codes change every 30 seconds, so use the " +
				"current one or a recovery code",
		}, oidc.LoginStepChallenge)

	default:
		o.writeMFAError(w, r, err)
	}
}

// oidcClientName is the application's name for the challenge form. It is re-read
// from the auth request rather than carried in the cookie, because a cookie holding
// a product's name is a cookie an attacker can set.
func (o options) oidcClientName(r *http.Request, requestID string) string {
	banner, err := o.oidc.LoginBanner(r.Context(), requestID)
	if err != nil {
		return "this application"
	}
	return banner.ClientName
}

// oidcChallengeCookie writes the challenge token where completeOIDCChallenge finds
// it.
func oidcChallengeCookie(requestID, token string, expiresAt time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     oidcChallengeCookieName(requestID),
		Value:    token,
		Path:     "/", // required by the __Host- prefix
		Secure:   true,
		HttpOnly: true,
		SameSite: oidcInteractionSameSite,
		Expires:  expiresAt,
	}
}

func clearOIDCChallengeCookie(w http.ResponseWriter, requestID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     oidcChallengeCookieName(requestID),
		Value:    "",
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: oidcInteractionSameSite,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

// finishOIDCLogin completes the request and hands the browser to the library's
// callback, which is the only place an authorization code is minted.
func (o options) finishOIDCLogin(w http.ResponseWriter, r *http.Request, requestID string, subject id.UUID) {
	if err := o.oidc.CompleteLogin(r.Context(), requestID, subject); err != nil {
		o.writeOIDCError(w, r, err)
		return
	}

	// A FRESH GET for the callback, not a rewritten clone of the POST.
	//
	// The clone is the obvious implementation and it is wrong: the login POST has
	// already called ParseForm, so the clone arrives with r.Form holding
	// `state=...&email=...&password=...` and ParseForm is a no-op from then on.
	// The library's callback handler reads `id` out of r.Form, finds the login
	// form instead, and answers "auth request callback is missing id" — which is
	// exactly what the first run of the round trip did.
	//
	// The headers are copied because the library's issuer interceptor and its CORS
	// handler read them, and a request with none of them would produce a document
	// with a different issuer than the one every other response carries.
	target := oidc.PathAuthorizeCallback + "?" + url.Values{"id": []string{requestID}}.Encode()
	proxied, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		unexpected(w, r, o.logger, fmt.Errorf("building the authorize callback request: %w", err))
		return
	}
	for name, values := range r.Header {
		// The cookie and the content type are the login POST's, and carrying
		// either into a GET the library answers with a redirect would be
		// confusing rather than useful. Everything else — the trace header, the
		// user agent, the accept language — is about the request and is copied.
		if name == "Cookie" || name == "Content-Type" || name == "Content-Length" {
			continue
		}
		proxied.Header[name] = values
	}

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

// oidcInteractionSameSite is the SameSite policy on the two cookies that carry
// the interaction from one step to the next: the state and the MFA challenge.
//
// IT IS `None` AND NOT `Lax`, and this is the one place the move of the form out
// of this repository changes a security header, so the argument is the whole
// comment.
//
// # WHY IT HAD TO CHANGE
//
// The login form is now a page on ANOTHER origin, and submitting it is a
// top-level cross-site POST to this one. A Lax cookie is not sent on a cross-site
// POST, so with `Lax` the state cookie would not arrive and every single sign-in
// would be refused at the CSRF check. This is not a subtle degradation; it is a
// login form that cannot be submitted, and it fails on the first person to try
// it.
//
// # WHY IT COSTS NOTHING, WHICH IS THE PART THAT HAD TO BE PROVEN
//
// `SameSite` governs WHEN a cookie is sent. It does not govern WHO can read one,
// and the property the state defends is a *binding* property, not a transport
// one:
//
//	__Host-   no Domain attribute, so no other origin can set or overwrite this
//	          cookie. A subdomain takeover, which is the realistic way to attack
//	          a cookie on a shared parent domain, cannot write it.
//	HttpOnly  no script on any origin can read its value.
//	value     unguessable: 32 bytes from crypto/rand, compared for equality.
//
// So a request originating from an attacker's page carries the cookie and cannot
// know what is in it, and `oauth.VerifyState` fails for every value the attacker
// chose. Under `Lax` the same attacker did not carry the cookie; the outcome for
// them is identical. **The CSRF defence is the unguessable value in a cookie the
// attacker's origin cannot read, and neither of those two facts changed.** What
// changed is only that the cookie now travels one hop further, to the origin that
// is supposed to have it.
//
// A same-origin XSS on either origin does not gain anything either: a script on
// the login UI's origin still cannot read this cookie, and a script on this
// origin could already read every other cookie on it.
//
// # WHAT IT DOES NOT APPLY TO
//
// The flow cookie stays `Lax`, and the session cookie stays `Lax`. The flow
// cookie is only ever read on a TOP-LEVEL GET — that is the whole of the D5
// silent-path gate — and Lax permits exactly that. The session cookie is only
// ever *set* on a top-level response, and read on top-level GETs. Neither of them
// needs to survive a cross-site POST, so neither of them is widened.
//
// `TestTheInteractionCookiesAreNoneAndTheFlowAndSessionCookiesAreNot` holds all
// four, because a change to any one of them is invisible until a sign-in breaks.
const oidcInteractionSameSite = http.SameSiteNoneMode

func oidcStateCookie(requestID, state string) *http.Cookie {
	return &http.Cookie{
		Name:     oidcStateCookieName(requestID),
		Value:    state,
		Path:     "/", // required by the __Host- prefix
		Secure:   true,
		HttpOnly: true,
		SameSite: oidcInteractionSameSite,
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
		SameSite: oidcInteractionSameSite,
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

// oidcRedirect sends a browser to the login UI.
//
// # IT IS NOT `http.Redirect`, AND THE ONE REASON IS THE WHOLE PACKET
//
// net/http's Redirect writes a body: a one-line anchor with
// `Content-Type: text/html; charset=utf-8`, because RFC 9110 §15.4 recommends it
// for a user agent that cannot follow a redirect. Every user agent in the
// deployment can follow one, and a body this service did not write is a claim
// about this service it cannot make — a reviewer running `curl -i` on
// `/oidc/authorize` and reading `Content-Type: text/html` has been told the
// thing this packet exists to remove is still here.
//
// So the status and the header are written by hand and the body is empty. There
// is no `Content-Type` either: a response with no body and no representation has
// nothing to declare, and a `Content-Type` on it would be a browser's cue to try
// to interpret what is not there.
//
// # THE TWO HEADERS THAT SURVIVED, AND WHY EACH IS STILL WORTH SENDING
//
//	Referrer-Policy: no-referrer    the Location carries an authorization request
//	                                id, a CSRF state, a product name and whatever
//	                                a client put in `login_hint`. This header is
//	                                set ON THE REDIRECT, which is what governs
//	                                what the login UI's own document may leak to
//	                                whatever that page loads next — so it is
//	                                load-bearing on a response that has no body
//	                                at all. It was load-bearing before for a
//	                                narrower reason (the id was in THIS service's
//	                                own URL); it is load-bearing now for a wider
//	                                one, because the state is a CSRF token and a
//	                                login UI's page is third-party content that
//	                                identity does not control.
//	Cache-Control: no-store         an intermediary that cached a 302 would cache
//	                                the CSRF state with it, and a replayed state
//	                                out of a shared cache is a cross-site request
//	                                with a valid token. The page it replaced had
//	                                this header for the same reason: nothing about
//	                                a sign-in belongs in a cache.
//
// # THE TWO THAT ARE GONE, AND WHY
//
//	X-Frame-Options: DENY and X-Content-Type-Options: nosniff protected a DOCUMENT
//	that carried a password field. There is no document. A 302 with no body cannot
//	be framed, because framing it does not render anything, and there is nothing
//	to sniff. Setting them would be a habit rather than a control, and this
//	repository treats a header nobody can explain as worse than a missing one.
//
// `TestTheLoginRedirectCarriesNoBodyAndTheTwoHeadersThatEarnedTheirPlace` holds
// every line of that, including the ABSENCE of the two that went.
func oidcRedirect(w http.ResponseWriter, location string) {
	header := w.Header()
	header.Set("Location", location)
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusFound)
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
