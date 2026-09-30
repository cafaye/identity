package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/cafaye/identity/internal/auth"
	"github.com/cafaye/identity/internal/users"
)

const (
	// SessionCookieName carries the session token to a browser.
	//
	// The __Host- prefix is not decoration. It is a contract the browser
	// enforces: a cookie with this name is accepted only if it is Secure, has
	// Path=/, and carries no Domain attribute. That makes it impossible for a
	// subdomain or a plain-HTTP sibling origin to set or overwrite the session
	// cookie — the two cookie-fixation vectors a `session` cookie leaves open.
	SessionCookieName = "__Host-session"

	// RetryAfterHeader carries the lockout window in seconds, so a client can wait
	// correctly without parsing the problem document.
	RetryAfterHeader = "Retry-After"

	// maxRequestBody caps an accepted request body.
	//
	// A registration is an address (≤320 bytes) and a password (≤1024), so a
	// legitimate body is under 2 KB and 4 KB leaves generous room for encoding
	// overhead. The cap is a DoS control: without it an unauthenticated caller
	// chooses how many bytes this service reads and parses per request, and how
	// much of them reaches the JSON decoder.
	maxRequestBody = 4 << 10
)

// Auth is the part of auth.Service the v1 routes need. It is an interface
// declared here, at the consumer, so the handlers can be tested against a
// programmable double and so the HTTP layer has no dependency on the use cases'
// internals.
type Auth interface {
	Register(ctx context.Context, in auth.RegisterInput) (auth.RegisteredUser, error)
	Login(ctx context.Context, in auth.LoginInput) (auth.LoginResult, error)
	Authenticate(ctx context.Context, token string) (users.User, error)
	Logout(ctx context.Context, token string) error
}

// WithAuth mounts the v1 routes.
//
// It is an Option rather than a constructor argument because the probes are the
// service's floor: a process with no DATABASE_URL has no auth service, and that
// process must still answer /healthz. Routes are simply absent when it is not
// given, so a misconfiguration shows up as a 404 rather than as a stack of 500s.
func WithAuth(a Auth) Option {
	return func(o *options) {
		if a != nil {
			o.auth = a
		}
	}
}

// userResponse is the public projection of a user.
//
// It is a dedicated type with two fields rather than the domain struct, so a
// digest cannot reach a response body by being added to one. TestRegisterHappyPath
// asserts the rendered shape, which is the check that actually matters.
type userResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// sessionResponse is the API surface of a login.
//
// The token is here as well as in the cookie, deliberately: a cookie is a browser
// mechanism and an API client cannot use one, and core's conventions are explicit
// that "no cookies for API traffic" is a rule about API clients, not a reason for
// the browser surface to exist. They are the same value for the same session.
type sessionResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// registerRequest is the body of POST /v1/users.
type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// loginRequest is the body of POST /v1/session.
type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// registerRoutes mounts the v1 surface on r.
func (o options) registerRoutes(r chiRouter) {
	if o.auth == nil {
		return
	}

	r.Post("/v1/users", o.handleRegister)
	r.Post("/v1/session", o.handleLogin)
	r.Delete("/v1/session", o.handleLogout)
	r.Get("/v1/me", o.handleMe)

	// The account routes need both services: a session to resolve the caller from
	// and a tenancy service to resolve their role in it. With only one of the two
	// they are not mounted at all, which is the same rule as above — a
	// misconfiguration should be a 404, not a 500 on every request.
	if o.tenancy != nil {
		o.registerTenancyRoutes(r)
	}
}

// chiRouter is the slice of *chi.Mux these routes need. Naming it keeps the
// option struct from importing chi for one method.
type chiRouter interface {
	Post(pattern string, h http.HandlerFunc)
	Delete(pattern string, h http.HandlerFunc)
	Get(pattern string, h http.HandlerFunc)
	Patch(pattern string, h http.HandlerFunc)
}

// handleRegister creates an account.
//
//	POST /v1/users  {email, password}  →  201 {id, email}
func (o options) handleRegister(w http.ResponseWriter, r *http.Request) {
	var body *registerRequest
	if !decodeBody(w, r, &body) {
		return
	}

	created, err := o.auth.Register(r.Context(), auth.RegisterInput{
		Email:    body.Email,
		Password: body.Password,
	})
	if err != nil {
		o.writeAuthError(w, r, err)
		return
	}

	writeJSON(w, http.StatusCreated, userResponse{ID: created.ID.String(), Email: created.Email})
}

// handleLogin authenticates and starts a session.
//
//	POST /v1/session  {email, password}  →  200 {token, expires_at} + cookie
func (o options) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body *loginRequest
	if !decodeBody(w, r, &body) {
		return
	}

	result, err := o.auth.Login(r.Context(), auth.LoginInput{
		Email:     body.Email,
		Password:  body.Password,
		UserAgent: r.UserAgent(),
		IP:        remoteIP(r),
	})
	if err != nil {
		o.writeAuthError(w, r, err)
		return
	}

	// The cookie is set before the body so that a client which crashes mid-write
	// is still left signed out rather than holding a token it never saw.
	o.setSessionCookie(w, result.Token, result.ExpiresAt)
	writeJSON(w, http.StatusOK, sessionResponse{Token: result.Token, ExpiresAt: result.ExpiresAt})
}

// handleLogout revokes the current session.
//
//	DELETE /v1/session  →  204, cookie cleared
func (o options) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := o.presentedToken(r)
	if token == "" {
		// No credential means no session to revoke. 401 rather than 204: a 204
		// would tell a client its request succeeded when nothing happened.
		unauthorized(w, r)
		return
	}

	if err := o.auth.Logout(r.Context(), token); err != nil {
		// A token that no longer resolves is still cleared client-side. A stale
		// cookie is the common case, and leaving it in place means the user
		// clicks "sign out" again and nothing appears to happen.
		if errors.Is(err, auth.ErrUnauthenticated) {
			o.clearSessionCookie(w)
			unauthorized(w, r)
			return
		}
		unexpected(w, r, o.logger, err)
		return
	}

	o.clearSessionCookie(w)
	noContent(w)
}

// handleMe returns the authenticated user.
//
//	GET /v1/me  →  200 {id, email}
func (o options) handleMe(w http.ResponseWriter, r *http.Request) {
	token := o.presentedToken(r)
	if token == "" {
		unauthorized(w, r)
		return
	}

	user, err := o.auth.Authenticate(r.Context(), token)
	if err != nil {
		if errors.Is(err, auth.ErrUnauthenticated) {
			unauthorized(w, r)
			return
		}
		unexpected(w, r, o.logger, err)
		return
	}

	writeJSON(w, http.StatusOK, userResponse{ID: user.ID.String(), Email: user.Email})
}

// presentedToken returns the credential the request is making, preferring an
// explicit Authorization header over the cookie.
//
// The preference is not a detail. A client holding both — a browser session plus
// an API token it pasted in — has said which one it means, and answering from the
// cookie would make the result depend on invisible browser state.
func (o options) presentedToken(r *http.Request) string {
	if token := bearerToken(r); token != "" {
		return token
	}
	return cookieToken(r)
}

// bearerToken extracts a token from an Authorization header, or "".
//
// The scheme is compared case-insensitively because RFC 7235 says it is
// case-insensitive, and a client sending "bearer" is not an attacker. Anything
// else — a bare token, a Basic header, an empty bearer — is not a credential this
// service accepts, and treating an unrecognised header as "no credential" keeps
// every malformed case on one path.
func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	const prefix = "Bearer "

	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}

// cookieToken reads the session cookie, or "".
func cookieToken(r *http.Request) string {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// setSessionCookie writes the hardened session cookie.
func (o options) setSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/", // required by the __Host- prefix
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  expiresAt,
	})
}

// clearSessionCookie expires the session cookie.
//
// Every attribute is repeated from the setting cookie. A deletion has to match
// the original on name, domain and path or the browser treats it as a different
// cookie and the stale one survives — the precise bug that makes "sign out" appear
// to do nothing.
func (o options) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

// remoteIP extracts the client address from RemoteAddr, or nil.
//
// It is recorded, never trusted: nothing in this service makes an authorization
// decision on it, and a proxy in front of the service means it is the proxy's
// address anyway. An unparseable value is nil rather than an error, because
// failing a login over a malformed header would be a denial of service anyone
// could trigger.
func remoteIP(r *http.Request) *netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return nil
	}
	return &addr
}

// decodeBody reads a JSON request body into dst, writing a problem and returning
// false if it cannot.
//
// dst must be a pointer to a pointer. That is not a quirk: decoding the literal
// `null` into a struct succeeds and leaves it zeroed, so a body of `null` would
// otherwise be indistinguishable from `{}` and would sail through to the service
// as a request with no email and no password.
//
// Four failure modes are separated, because they mean different things to a
// client and collapsing them produces unhelpful errors:
//
//	too large        413  the caller sent more than this endpoint accepts
//	not JSON         400  malformed syntax, which core scopes to 400
//	not an object    400  syntactically valid JSON of the wrong shape
//	unknown field    422  syntactically fine, semantically not what we accept
func decodeBody[T any](w http.ResponseWriter, r *http.Request, dst **T) bool {
	// Limited at the reader, so an oversized body is refused as it arrives rather
	// than after it has been buffered.
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	decoder := json.NewDecoder(r.Body)
	// An unknown field is a typo, usually. Silently dropping "emial" creates an
	// account with an address the caller did not choose and an error that points
	// at nothing.
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		var syntax *json.SyntaxError
		var unmarshalType *json.UnmarshalTypeError

		switch {
		case bodyTooLarge(err):
			problemFor(w, r, http.StatusRequestEntityTooLarge, CodePayloadTooLarge,
				fmt.Sprintf("the request body is larger than the %d bytes this endpoint accepts", maxRequestBody))
		case errors.As(err, &syntax),
			errors.As(err, &unmarshalType),
			errors.Is(err, io.EOF),
			errors.Is(err, io.ErrUnexpectedEOF):
			// io.ErrUnexpectedEOF is a truncated body, which Decode reports rather
			// than a SyntaxError. Both are malformed syntax, and core reserves 400
			// for exactly this.
			problemFor(w, r, http.StatusBadRequest, CodeInvalidJSON,
				"the request body is not a JSON object this endpoint accepts")
		default:
			// Unknown field, trailing data, and a value of the wrong JSON type all
			// land here: the JSON parsed, and what it says is not acceptable.
			problemFor(w, r, http.StatusUnprocessableEntity, CodeValidationFailed,
				"the request body has a field this endpoint does not accept")
		}
		return false
	}

	// `null` decodes without error and leaves the target nil. It is valid JSON and
	// not a request body, so it is a 400 rather than a validation failure.
	if *dst == nil {
		problemFor(w, r, http.StatusBadRequest, CodeInvalidJSON,
			"the request body must be a JSON object, not null")
		return false
	}

	return true
}

// writeAuthError maps a use-case error onto the response.
//
// The 401 for a refused login is deliberately one fixed sentence. Varying it per
// case is how a login endpoint becomes an account-enumeration oracle.
func (o options) writeAuthError(w http.ResponseWriter, r *http.Request, err error) {
	var locked *auth.LockedError
	var fieldErr *users.FieldError

	switch {
	case errors.As(err, &locked):
		// The window goes in the Retry-After header, which is where RFC 9110 puts
		// it, and in the detail sentence so a human reading the response can act on
		// it.
		//
		// It is deliberately NOT an entry in errors[]: core scopes that array to
		// 422 and describes it as per-field request failures. "retry_after" is not
		// a field of the request, and smuggling it in there would make every
		// client that renders errors[] as a form summary show a field the user
		// never typed.
		seconds := retryAfterSeconds(locked.RetryAfter)
		w.Header().Set(RetryAfterHeader, seconds)
		problemFor(w, r, http.StatusLocked, CodeAccountLocked,
			"too many failed sign-in attempts for this account; retry after "+seconds+" seconds")

	case errors.Is(err, auth.ErrInvalidCredentials), errors.Is(err, auth.ErrUnauthenticated):
		unauthorized(w, r)

	case errors.Is(err, users.ErrEmailTaken):
		problemFor(w, r, http.StatusConflict, CodeConflict,
			"an account already exists for that email address")

	case errors.As(err, &fieldErr):
		// A 422 with errors[] is core's shape for "the request was understood and
		// is not acceptable". Exactly one field failed here, because the handlers
		// stop at the first.
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the request has an invalid field").
			withFieldErrors([]FieldError{{Field: fieldErr.Field, Code: fieldErr.Code}}))

	default:
		unexpected(w, r, o.logger, err)
	}
}

// retryAfterSeconds renders a duration in whole seconds, rounding up and clamping
// at zero.
//
// Rounding up rather than truncating means the client waits at least as long as
// told; truncating would tell it to retry 0.7 seconds early and get another 423,
// which is a loop the client owns and the server caused. RFC 9110 defines
// Retry-After in seconds.
func retryAfterSeconds(d time.Duration) string {
	if d <= 0 {
		return "0"
	}
	seconds := int64(d / time.Second)
	if d%time.Second != 0 {
		seconds++
	}
	return fmt.Sprintf("%d", seconds)
}
