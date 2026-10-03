package httpapi

// THE SOCIAL-LOGIN SURFACE: /v1/auth/oauth/{provider} and its callback.
//
// Two routes, one redirect out and one round trip back, and both of them are
// reachable with no credential — which is the whole shape of an OAuth
// authorization-code flow and the reason this surface has its own file rather than
// being three more handlers in auth.go.
//
// # WHAT EACH ROUTE IS ANSWERABLE BY A STRANGER, AND WHAT IT DISCLOSES
//
// The start route answers a redirect and a cookie. It discloses nothing: the only
// way to tell a configured provider from an unconfigured one is that the configured
// one redirects and the other answers 404, and that is not a secret worth having —
// an operator needs to know which providers their deployment offers, and a
// deployment's provider list is published by its own login page. The callback answers
// a session, a challenge, or one of four refusals, and the only one of those that
// says anything about an account is the email-collision 409. It is safe to say out
// loud because reaching it requires an authorization code a provider issued for an
// address the provider has itself verified: internal/oauth's client refuses an
// unverified address on both providers, so the caller has already proved control of
// that mailbox and could learn the same fact by asking Google. The reasoning is in
// internal/auth/social.go and in DECISIONS.md D11.
//
// # THE INTENTION IS RECORDED WHEN THE FLOW STARTS, NOT WHEN IT RETURNS
//
// The callback has to know whether it is signing somebody in or attaching a
// provider identity to the account they are already signed in as. It cannot ask by
// looking at the request: a browser that holds a session cookie will present it on
// the callback whether or not this flow is the reason it holds one, and deciding
// from the cookie alone would mean a cross-site GET of the start route — which any
// page can cause, and which a top-level navigation sends cookies for — could turn
// into a link of the ATTACKER's provider account to the VICTIM's cafaye account.
// The whole of social login is a mechanism for turning somebody else's provider
// identity into a credential, so an authorization decision made from ambient cookie
// state is the one thing this pair of routes must not do.
//
// So the start route records what it saw, in a second HttpOnly cookie the browser
// will not let a page read or write, and the callback honours that record. An
// attacker can make a victim's browser START a flow; they cannot make it finish one
// started with somebody else's code, because the state cookie is unreadable to them
// and VerifyState refuses a mismatch. And a flow that started signed-out arrives
// signed-out even if a session appeared in between.
//
// # NO REDIRECT, NO HTML, NO SECOND ERROR SHAPE ON THE WAY BACK
//
// The callback answers 200 with a session in the cookie AND in the body, which is
// the same shape `POST /v1/session` answers, because it is the same event: a login
// that produced a session. It does not redirect to a landing page, and this is a
// decision rather than an omission.
//
// The alternative is a configured success destination and a 303 to it, which is
// what a browser-first product wants and what this service does not get to decide
// alone: the destination is a page in another repository, and adding an
// OAUTH_SUCCESS_URL to answer "where do we send people afterwards" is a product
// decision with no security content, taken here, in a packet about mounting an
// endpoint. What that costs is real and is stated rather than hidden: a human who
// clicks "Continue with Google" in a browser lands on a JSON document, and a
// product that wants them somewhere nicer needs the configured destination. The
// cookie is set either way, so the session is real on that landing page.
//
// The redirect OUT is a bare 302 with a Location and no body. `http.Redirect` would
// write a one-line HTML anchor with `Content-Type: text/html`, which RFC 9110 §15.4
// recommends for a user agent that cannot follow a redirect — and this service has
// none. Same reasoning as the OIDC login's `oidcRedirect`, for the same reason.

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cafaye/identity/internal/auth"
	"github.com/cafaye/identity/internal/oauth"
	"github.com/cafaye/identity/internal/users"
)

const (
	// socialLoginPrefix is where this surface lives.
	//
	// IT IS A CONSTANT AND NOT A BUILD-TUPLE, and the reason is that it has to be
	// equal to the path `oauth.Provider.RedirectURI` appends. That function is the
	// one that decides where the provider sends the browser, so a prefix here that
	// disagreed with it would produce a redirect_uri nobody is listening on and a
	// provider error that names neither of the two URLs that disagreed.
	// TestTheSocialLoginPrefixIsTheOneTheProviderBuilds holds the two together by
	// calling the real function rather than by re-spelling the string.
	socialLoginPrefix = "/v1/auth/oauth"

	// OAuthStateCookieName carries the CSRF state across the round trip.
	//
	// __Host- for the reason SessionCookieName says: the cookie is accepted only if
	// it is Secure, Path=/ and carries no Domain, so neither a subdomain nor a
	// plain-HTTP sibling origin can overwrite it. A state cookie a sibling can write
	// is not a state.
	OAuthStateCookieName = "__Host-oauth-state"

	// OAuthLinkCookieName records that this flow was STARTED by a signed-in caller
	// and is a link rather than a sign-in. See the file comment: the callback must
	// not decide that from the session cookie it finds.
	//
	// It carries no secret — the value is a constant — and it is HttpOnly because
	// the point is that no page on any origin can produce one. A `document.cookie`
	// this service could not have set is not an intent anybody can forge.
	OAuthLinkCookieName = "__Host-oauth-link"

	// OAuthStateTTL is how long a started flow stays startable.
	//
	// Ten minutes is long enough to consent to a new provider account and to type a
	// password into a Google screen, and short enough that a state left in a
	// browser is not a usable value for the rest of the day. It is the cookie's
	// Max-Age rather than a field inside the state, for the reason oauth.NewState
	// takes no clock: the value has to be reproducible nowhere else.
	OAuthStateTTL = 10 * time.Minute

	// oauthLinkCookieValue is what OAuthLinkCookieName carries when it is set.
	oauthLinkCookieValue = "1"
)

// Social is this surface's dependency: the configured providers, and the use case
// that finishes a round trip.
//
// One interface rather than two because a deployment that can build the redirect but
// not finish it — or the reverse — is a half-mounted flow that fails at the browser
// with a 404 on the callback, and the two halves are constructed together from one
// `oauth.Settings`.
type Social interface {
	// Lookup resolves the provider named in the URL. An unconfigured provider is an
	// error, and it is the same error as a name that does not exist.
	Lookup(provider string) (oauth.Provider, error)
	// RedirectBase is the configured public base URL every callback is built from.
	RedirectBase() string
	// Callback finishes the round trip.
	Callback(ctx context.Context, in auth.SocialCallbackInput) (auth.LoginResult, error)
}

// WithSocial mounts the social-login routes.
//
// It is an Option for the reason WithAuth is: the routes are ABSENT when no provider
// is configured, so a deployment with no OAuth client credentials serves a clean 404
// rather than a redirect to a provider it cannot authenticate with. Every other
// optional surface in this service follows the same rule, and the one that does not
// — the recovery surface — says in its own comment why it differs.
func WithSocial(s Social) Option {
	return func(o *options) {
		if s != nil {
			o.social = s
		}
	}
}

// registerSocialRoutes mounts both routes. They are registered as ONE function
// because they are one flow, and a router where the start and the callback can be
// mounted independently is a router where half of one exists.
func (o options) registerSocialRoutes(r chiRouter) {
	if o.social == nil {
		return
	}
	r.Get(socialLoginPrefix+"/{provider}", o.handleSocialStart)
	r.Get(socialLoginPrefix+"/{provider}/callback", o.handleSocialCallback)
}

// socialLinkedResponse is the callback's answer on the LINK path.
//
// A DEDICATED TYPE rather than the session response, and the empty token is the
// whole of the design: linking is not signing in, the caller already holds a session,
// and this service does not mint a second one because somebody completed a
// third-party round trip. A client that reads this and looks for `token` finds no
// field, which is the honest signal.
type socialLinkedResponse struct {
	// Provider is the one just linked. It is the answer to "did that work" without
	// a boolean that says the same thing twice.
	Provider string `json:"linked_provider"`
}

// handleSocialStart sends the browser to the provider.
//
//	GET /v1/auth/oauth/{provider}  →  302, the state cookie set
//
// It reads the caller's session ONLY to record an intention, and a session that does
// not resolve — stale cookie, revoked, expired — is "not linking" rather than an
// error. The alternative is a button that 401s forever to somebody whose cookie went
// stale, which is a support call about a sign-in that was never going to happen.
func (o options) handleSocialStart(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "provider")

	provider, err := o.social.Lookup(name)
	if err != nil {
		// 404 for "no such provider" and for "a provider this deployment has no
		// credentials for" alike. Telling them apart is a way to enumerate a
		// deployment's configuration, and there is nothing here worth enumerating.
		notFound(w, r)
		return
	}

	state, err := oauth.NewState(provider.Name)
	if err != nil {
		// A degraded entropy source. Refused rather than papered over, for the reason
		// oauth.NewState's own reader gives.
		unexpected(w, r, o.logger, err)
		return
	}

	o.setOAuthStateCookie(w, state, o.linkingAs(r))

	// The redirect_uri handed to the provider is built from the CONFIGURED base, not
	// from the Host header, for the reason oauth.Provider.RedirectURI says: a host an
	// attacker chose must not become part of a redirect_uri, or the code is delivered
	// wherever they asked.
	o.oauthRedirect(w, provider.AuthCodeURL(state, provider.RedirectURI(o.social.RedirectBase())))
}

// linkingAs reports whether this flow is a link rather than a sign-in, by asking
// whether the caller has a session that resolves.
//
// It writes NOTHING on the false path, and that asymmetry is why the link cookie is
// set separately rather than cleared here: a "not linking" flow has to be one where
// the callback can tell the ABSENCE of the cookie from the presence of it, and a
// cookie that is always written and sometimes empty is a value whose meaning depends
// on how a reader treats empty.
func (o options) linkingAs(r *http.Request) bool {
	if o.auth == nil {
		return false
	}
	token := o.presentedToken(r)
	if token == "" {
		return false
	}
	user, err := o.auth.Authenticate(r.Context(), token)
	return err == nil && !user.ID.IsZero()
}

// handleSocialCallback finishes the round trip.
//
//	GET /v1/auth/oauth/{provider}/callback?code=…&state=…
//	  →  200 {token, expires_at}          a session, and the session cookie
//	  →  202 {mfa_required, challenge, …}  the login's second step
//	  →  200 {linked_provider}             the link path, no session
//	  →  400 / 404 / 409 / 502             the refusals, each with its own code
//
// THE ORDER IS THE SECURITY PROPERTY and it is stated here rather than left to the
// reader of the code below:
//
//  1. The provider named in the URL is resolved. An unconfigured provider is a 404
//     before anything else is read.
//  2. The state cookie is read and compared. This is the CSRF check and it happens
//     BEFORE the code is used, because a code is single-use at the provider: spending
//     it on a request whose state was forged would burn a real user's sign-in and
//     teach an attacker that the check is advisory.
//  3. Both cookies are cleared, one-shot, whether or not the rest succeeds.
//  4. A provider-side `error` is answered as a refusal rather than being treated as
//     "no code", so the person who declined consent is told that and not that they
//     presented something invalid.
//  5. Only then is the code spent.
func (o options) handleSocialCallback(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "provider")

	provider, err := o.social.Lookup(name)
	if err != nil {
		notFound(w, r)
		return
	}

	if !oauth.VerifyState(provider.Name, readCookie(r, OAuthStateCookieName), r.URL.Query().Get("state")) {
		// One refusal for a missing cookie, a missing query parameter, a mismatch and
		// a state minted for another provider. There is no branch that says which,
		// because each of those is attacker-influenced and a difference between them
		// is an oracle about the cookie rather than a diagnostic for a user.
		o.clearOAuthStateCookies(w)
		problemFor(w, r, http.StatusBadRequest, CodeInvalidRequest,
			"this social sign-in did not start in this browser, so it cannot be finished here")
		return
	}
	o.clearOAuthStateCookies(w)

	if reason := r.URL.Query().Get("error"); reason != "" {
		problemFor(w, r, http.StatusBadRequest, CodeInvalidRequest,
			"the oauth provider did not return an authorization code")
		return
	}

	owner, ok := o.linkTarget(w, r)
	if !ok {
		return
	}

	result, err := o.social.Callback(r.Context(), auth.SocialCallbackInput{
		Provider:  provider.Name,
		Code:      r.URL.Query().Get("code"),
		LinkTo:    owner,
		UserAgent: r.UserAgent(),
		IP:        remoteIP(r),
	})
	if err != nil {
		o.writeSocialError(w, r, err)
		return
	}

	// WHICH OF THE THREE PATHS THIS WAS is decided by the intention recorded when the
	// flow started, not by the shape of the result. A link mints nothing, so it has
	// no token and no challenge, and reading the result instead would make an
	// accidentally-empty session response indistinguishable from a successful link.
	if !owner.ID.IsZero() {
		writeJSON(w, http.StatusOK, socialLinkedResponse{Provider: provider.Name})
		return
	}

	if result.MFARequired {
		// The SAME writer a password login's challenge uses, and that is the point:
		// an account with a confirmed second factor gets a challenge from a social
		// callback too, so a client has one code path for "the login is not finished
		// yet" rather than one per way of starting it.
		o.writeChallenge(w, r, result)
		return
	}

	if result.Token == "" {
		// Said out loud rather than rendered as an empty 200. A 200 with no token
		// leaves a client in a state it cannot finish and cannot diagnose, which is
		// the one outcome worse than a 500.
		unexpected(w, r, o.logger, errNoChallengeToken)
		return
	}

	// The cookie is set before the body, for the reason handleLogin sets it first.
	o.setSessionCookie(w, result.Token, result.ExpiresAt)
	writeJSON(w, http.StatusOK, sessionResponse{Token: result.Token, ExpiresAt: result.ExpiresAt})
}

// linkTarget resolves who this callback is linking to, and whether the answer is a
// person at all.
//
// IT IS THE RECORDED INTENTION OR NOTHING. A flow that started with the link cookie
// and whose session no longer resolves is a 401 rather than a silent sign-in: the
// person asked to attach an account to the one they were signed in as, and quietly
// signing them in as somebody else — or creating an account — would be the worst
// available answer to that request.
//
// IT RETURNS FALSE HAVING WRITTEN, which is unusual for this package and is why the
// caller checks it. Every other helper here returns a value and lets the caller
// decide the status; this one has two refusal shapes (401 and, when auth is absent,
// a 404) and folding them into a return value would mean a sentinel error compared
// at the call site, which is the shape that ends up compared wrongly once.
func (o options) linkTarget(w http.ResponseWriter, r *http.Request) (users.User, bool) {
	// No link cookie means a sign-in, whatever session happens to be in hand.
	if readCookie(r, OAuthLinkCookieName) == "" {
		return users.User{}, true
	}
	if o.auth == nil {
		notFound(w, r)
		return users.User{}, false
	}

	user, err := o.auth.Authenticate(r.Context(), o.presentedToken(r))
	if err != nil {
		unauthorized(w, r)
		return users.User{}, false
	}
	return user, true
}

// writeSocialError maps a social-login failure onto the response.
//
// THE SPLIT IS BY CAUSE, not by status code of convenience, and the two 400s are
// deliberately different codes from each other and from the CSRF refusal above even
// though all three are `CodeInvalidRequest`:
//
//	ErrCodeRefused        400  the code was no good — the person's or the provider's doing
//	ErrNoEmail            400  the provider's address is missing or unverified
//	ErrAlreadyLinked      409  that provider identity is somebody else's
//	ErrSocialEmailInUse   409  that address already belongs to an account here
//	ErrProviderUnavailable 502 the provider could not be reached
//
// 502 rather than 500 for the last one is the difference between "we are broken" and
// "somebody upstream is", and a caller retrying a 502 is behaving correctly where a
// caller retrying a 500 is not. The detail sentence is a constant and the cause goes
// to the log: a provider's error body can carry a client secret, a redirect_uri and
// an account identifier, and this is a service that logs and renders separately on
// purpose.
func (o options) writeSocialError(w http.ResponseWriter, r *http.Request, err error) {
	var fieldErr *users.FieldError

	switch {
	case errors.Is(err, oauth.ErrUnknownProvider):
		notFound(w, r)

	case errors.Is(err, oauth.ErrCodeRefused):
		problemFor(w, r, http.StatusBadRequest, CodeInvalidRequest,
			"the oauth provider refused the authorization code")

	case errors.Is(err, oauth.ErrNoEmail):
		problemFor(w, r, http.StatusBadRequest, CodeInvalidRequest,
			"the oauth provider did not return a verified email address this service will accept")

	case errors.Is(err, oauth.ErrAlreadyLinked):
		problemFor(w, r, http.StatusConflict, CodeConflict,
			"that oauth account is already linked to a different user")

	case errors.Is(err, auth.ErrSocialEmailInUse):
		problemFor(w, r, http.StatusConflict, CodeConflict,
			"an account already exists for the email address that oauth account reports, "+
				"so this sign-in was refused rather than linked. Sign in with that account instead")

	case errors.Is(err, users.ErrEmailTaken):
		// The race nobody can close: between this service's lookup and its insert,
		// somebody registered that address. It is the same fact as the branch above
		// and the same answer, which is why the sentences differ by nothing and a
		// client rendering one for the other would still be right.
		problemFor(w, r, http.StatusConflict, CodeConflict,
			"an account already exists for that email address")

	case errors.Is(err, oauth.ErrProviderUnavailable):
		o.logger.Warn("an oauth provider could not be reached", "provider", chi.URLParam(r, "provider"), "error", err)
		problemFor(w, r, http.StatusBadGateway, CodeServiceUnavailable,
			"the oauth provider could not be reached")

	case errors.Is(err, auth.ErrUnauthenticated):
		unauthorized(w, r)

	case errors.As(err, &fieldErr):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the provider reported an address this service will not store").
			withFieldErrors([]FieldError{{Field: fieldErr.Field, Code: fieldErr.Code}}))

	default:
		unexpected(w, r, o.logger, err)
	}
}

// setOAuthStateCookie writes the state, and the link intention beside it.
//
// The intention is written as its OWN cookie rather than as a second value in the
// state, because `oauth.VerifyState` refuses a state carrying anything but
// `<provider>.<token>` — which is the right rule, and re-encoding it to smuggle a
// mode through would make a security primitive carry a flag for something else.
func (o options) setOAuthStateCookie(w http.ResponseWriter, state string, linking bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     OAuthStateCookieName,
		Value:    state,
		Path:     "/", // required by the __Host- prefix
		Secure:   true,
		HttpOnly: true,
		// Lax, and not Strict, for one reason: the callback is a top-level GET
		// navigation the provider caused, and Lax is the value that sends a cookie
		// with it. Strict would drop the cookie from this very request and every
		// sign-in would fail its own CSRF check — a refusal that looks like a broken
		// provider and is a misconfigured cookie.
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(OAuthStateTTL.Seconds()),
		Expires:  time.Now().Add(OAuthStateTTL),
	})

	if linking {
		http.SetCookie(w, &http.Cookie{
			Name:     OAuthLinkCookieName,
			Value:    oauthLinkCookieValue,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(OAuthStateTTL.Seconds()),
			Expires:  time.Now().Add(OAuthStateTTL),
		})
	}
}

// clearOAuthStateCookies expires both cookies.
//
// It runs on EVERY callback outcome including a successful one, because the state is
// one-shot by construction: `oauth.VerifyState` compares a cookie against a query
// parameter and both are re-presentable, so leaving the cookie behind would let one
// captured callback be replayed. One-shot is a property of the cookie's life, not of
// the provider's code, and the provider will not enforce it for us.
func (o options) clearOAuthStateCookies(w http.ResponseWriter) {
	for _, name := range []string{OAuthStateCookieName, OAuthLinkCookieName} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
			Expires:  time.Unix(0, 0),
		})
	}
}

// readCookie returns a named cookie's value, or "".
func readCookie(r *http.Request, name string) string {
	cookie, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// oauthRedirect writes a 302 with a Location and no body.
//
// The status and the header are written by hand for the reason on this file's
// header: `http.Redirect` adds a one-line HTML anchor body and a text/html content
// type, which RFC 9110 §15.4 recommends for a user agent that cannot follow a
// redirect. This service has none, and a body on a redirect is a body somebody's
// error page will eventually render inside an iframe.
func (o options) oauthRedirect(w http.ResponseWriter, location string) {
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusFound)
}
