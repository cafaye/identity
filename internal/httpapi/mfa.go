package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cafaye/identity/internal/auth"
	"github.com/cafaye/identity/internal/mfa"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/sessions"
)

// THE MFA SURFACE.
//
// Six routes, and the one that matters is not here: POST /v1/session/mfa is the
// only path in this service that turns a second factor into a session, and it is
// mounted below the login routes because it IS the rest of the login.
//
// A CORRECT PASSWORD MINTS NO SESSION. POST /v1/session answers 202 with a
// challenge for an account that has a second factor, and the token in that body
// authenticates nothing at all until a code is presented against it. That is the
// line the whole packet is about, and everything below is arranged so that no
// route, no middleware and no error path can produce a session without it.
//
// TWO RESPONSES FROM ONE ENDPOINT, which is why the status is not incidental:
//
//	200 {token, expires_at}                 no second factor, here is your session
//	202 {mfa_required, challenge, expires_at} one is required, here is the challenge
//
// 202 rather than 200 because the request was accepted and not fulfilled: the
// credentials were right and the authentication is unfinished. A client that only
// looks at the status sees the difference, which is the whole point of having one.
//
// THE AUTHORIZATION MATRIX HAS ITS OWN TABLE for this surface rather than rows in
// the tenancy one, because the only decision here is "are you authenticated" —
// there is no account in the path and no role to compare. TestEveryMFARouteIsInTheMatrix
// walks the router and fails if a route is mounted without a row, exactly as the
// tenancy suite does.

// enrollmentIDParam is the chi URL parameter naming a pending enrollment.
const enrollmentIDParam = "enrollmentID"

// MFA is the second-factor use cases the routes need.
//
// Declared here, at the consumer, for the same reason Auth and Tenancy are: the
// handlers are testable against a double and this file has no dependency on the
// use cases' internals.
//
// The split into two interfaces is not tidiness. MANAGE is the surface that can
// read and write a secret — enrollment, rotation, recovery codes, disabling — and
// it is what a deployment with no MFA_ENCRYPTION_KEY must NOT have, because a user
// must not be talked into enrolling a factor this process could not later verify.
// CHALLENGE is what the login path needs, and it works without a key: mfa.Enabled
// needs no secret, so a keyless process still knows which of its users have a
// second factor and still refuses them rather than waving them through.
type MFA interface {
	StatusFor(ctx context.Context, userID id.UUID) (mfa.Status, error)
}

type MFAManage interface {
	MFA
	StartEnrollment(ctx context.Context, in mfa.StartEnrollmentInput) (mfa.StartedEnrollment, error)
	Confirm(ctx context.Context, in mfa.ConfirmInput) (mfa.ConfirmedEnrollment, error)
	RegenerateRecoveryCodes(ctx context.Context, in mfa.RegenerateRecoveryCodesInput) (mfa.RegeneratedRecoveryCodes, error)
	Disable(ctx context.Context, in mfa.DisableInput) error
}

// WithMFA mounts the second-factor management surface.
//
// It is an Option for the reason WithAuth and WithOIDC are: a process with no
// MFA_ENCRYPTION_KEY has nothing to seal a secret with, and that process must
// still answer /healthz and must still refuse a second-factor login. The routes
// are absent rather than present-and-failing.
func WithMFA(m MFAManage) Option {
	return func(o *options) {
		if m != nil {
			o.mfa = m
		}
	}
}

// NOTE ON WHY THERE IS NO WithMFAChallenge OPTION.
//
// The login's second step is mounted whenever the AUTH surface is, because
// auth.Service is what completes it — CompleteSecondFactor is on the Auth interface
// and cannot be anywhere else without a second way for a session to come into
// being. So it needs no option of its own, and adding one would have been a second
// way to leave it unmounted.
//
// That is also the correct DEPENDENCY, and it is what makes the keyless deployment
// safe: with a database and no MFA_ENCRYPTION_KEY the management routes are absent
// (WithMFA was never called) while this route is present, so a user who enrolled
// elsewhere is refused at their second factor rather than being let in on their
// password. The absence of the management routes says nothing about whether this
// one exists.

// ---------------------------------------------------------------------------
// routes
// ---------------------------------------------------------------------------

// registerMFARoutes mounts the management surface.
//
// The minimums, read down the page, are all the same, and that is the decision:
//
//	POST   /v1/mfa/enrollments                 a session, plus a factor if replacing
//	POST   /v1/mfa/enrollments/:id/confirm     a session (the enrollment is theirs)
//	POST   /v1/mfa/recovery-codes              a session, PLUS a second factor
//	DELETE /v1/mfa                             a session, PLUS a second factor
//
// Adding a factor is authorized by a session: the caller is making the account
// harder to get into, and a thief holding the session adds one and is locked out
// of the account they are in. Removing or replacing one is a destructive security
// action, and re-authentication is the entire reason that exists — so the last two
// routes carry a code, and the use cases refuse without one.
func (o options) registerMFARoutes(r chiRouter) {
	if o.mfa == nil {
		return
	}
	// EVERY ONE OF THESE IS SESSION-ONLY, and there is no scope for the second
	// factor in the machine vocabulary. A token that could read whether an account
	// has a second factor, enrol one, rotate one or turn one off is a credential
	// whose theft is a DOWNGRADE rather than a break-in: the attacker does not have
	// to get in, they turn the lock off. The refusal is one middleware rather than
	// five checks — see sessionCredentialOnly.
	r.Get("/v1/mfa", o.sessionCredentialOnly(o.handleMFAStatus))
	r.Post("/v1/mfa/enrollments", o.sessionCredentialOnly(o.handleStartEnrollment))
	r.Post("/v1/mfa/enrollments/{enrollmentID}/confirm", o.sessionCredentialOnly(o.handleConfirmEnrollment))
	r.Post("/v1/mfa/recovery-codes", o.sessionCredentialOnly(o.handleRegenerateRecoveryCodes))
	r.Delete("/v1/mfa", o.sessionCredentialOnly(o.handleDisableMFA))
}

// ---------------------------------------------------------------------------
// request and response shapes
// ---------------------------------------------------------------------------

// mfaStatusResponse is GET /v1/mfa.
//
// recovery_codes_remaining is on it, and that is the packet's "the honest thing is
// to tell them before they get there". A client that can render "2 codes left —
// print a new set" while there are still two is the difference between a warning
// and a locked-out user.
//
// It is a 200 with enabled:false rather than a 404 for a user who has no second
// factor: the question "do I have a second factor" has an answer for every
// signed-in user, and a settings page should not have to distinguish "you have
// none" from "this is not your account".
type mfaStatusResponse struct {
	Enabled bool `json:"enabled"`
	// Method, enrolled_at and recovery_codes_remaining are absent when there is no
	// credential. omitempty is doing real work: "totp" and "no method yet" are
	// different answers.
	Method                 string     `json:"method,omitempty"`
	EnrolledAt             *time.Time `json:"enrolled_at,omitempty"`
	RecoveryCodesRemaining *int       `json:"recovery_codes_remaining,omitempty"`
}

// startEnrollmentRequest is the body of POST /v1/mfa/enrollments.
//
// Code authorises a ROTATION and is not needed for a first enrollment. It is not
// nullable-with-a-meaning: the use case decides which case it is from the rows, so
// a client that sends one for a first enrollment is not wrong, only redundant.
type startEnrollmentRequest struct {
	Code string `json:"code,omitempty"`
}

// startedEnrollmentResponse is the 201 from POST /v1/mfa/enrollments.
//
// secret and provisioning_uri ARE HERE AND NOWHERE ELSE. They appear in this
// response, once, and there is no endpoint that re-reads them: a client that loses
// this body starts a new enrollment, which mints a new secret. The reasoning is
// internal/oidc/service.go's for a client secret, applied — a secret this service
// can produce again is a secret this service is storing, and a stored TOTP secret
// is a second factor for whoever reads the database.
//
// replaced says the previous credential is STILL LIVE behind this pending one, so
// a client can tell the user their old phone keeps working until they confirm
// rather than leaving them to discover it.
type startedEnrollmentResponse struct {
	EnrollmentID    string    `json:"enrollment_id"`
	Secret          string    `json:"secret"`
	ProvisioningURI string    `json:"provisioning_uri"`
	Method          string    `json:"method"`
	Digits          int       `json:"digits"`
	PeriodSeconds   int       `json:"period_seconds"`
	Algorithm       string    `json:"algorithm"`
	ExpiresAt       time.Time `json:"expires_at"`
	Replaced        bool      `json:"replaced"`
}

// confirmEnrollmentRequest is the body of POST /v1/mfa/enrollments/:id/confirm.
//
// Code is required always. An unconfirmed enrollment is not a second factor yet,
// so this is the only thing that makes it one, and there is no route to this
// handler that leaves it out.
type confirmEnrollmentRequest struct {
	Code string `json:"code"`
}

// confirmedEnrollmentResponse is the 200 from the confirm, and recovery_codes is
// here and nowhere else — same rule, same reason, ten of them.
type confirmedEnrollmentResponse struct {
	Enabled                bool      `json:"enabled"`
	Method                 string    `json:"method"`
	EnrolledAt             time.Time `json:"enrolled_at"`
	RecoveryCodes          []string  `json:"recovery_codes"`
	ReplacedExistingSecret bool      `json:"replaced_existing_secret"`
}

// factorRequest is the body of the two routes that change an existing credential.
//
// ONE FIELD, not `code` and `recovery_code`. The consequence of getting it wrong
// is identical, and two fields would let a client put a recovery code in the TOTP
// field and be told the code was malformed rather than not accepted — which is a
// worse error to act on.
type factorRequest struct {
	Code string `json:"code"`
}

// recoveryCodesResponse is the 200 from POST /v1/mfa/recovery-codes.
//
// The codes are here once. The count is here too, and it is what a client shows
// next to them.
type recoveryCodesResponse struct {
	RecoveryCodes          []string  `json:"recovery_codes"`
	IssuedAt               time.Time `json:"issued_at"`
	RecoveryCodesRemaining int       `json:"recovery_codes_remaining"`
}

// ---------------------------------------------------------------------------
// handlers
// ---------------------------------------------------------------------------

// handleMFAStatus reports whether the caller has a second factor.
//
//	GET /v1/mfa  →  200 {enabled, method?, enrolled_at?, recovery_codes_remaining?}
func (o options) handleMFAStatus(w http.ResponseWriter, r *http.Request) {
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	status, err := o.mfa.StatusFor(r.Context(), user.ID)
	if err != nil {
		unexpected(w, r, o.logger, err)
		return
	}

	response := mfaStatusResponse{Enabled: status.Enabled, Method: status.Method, EnrolledAt: status.EnrolledAt}
	if status.Enabled {
		remaining := status.RecoveryCodesRemaining
		response.RecoveryCodesRemaining = &remaining
	}
	writeJSON(w, http.StatusOK, response)
}

// handleStartEnrollment generates a secret and stores it, unconfirmed.
//
//	POST /v1/mfa/enrollments  {code?}  →  201 {enrollment_id, secret, ...}
//
// 201 rather than 200: something was created, and it is an enrollment — a pending
// one, which is not yet a second factor. The response says when it expires, which
// is how a client tells a user "finish this in ten minutes or start again".
func (o options) handleStartEnrollment(w http.ResponseWriter, r *http.Request) {
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	var body *startEnrollmentRequest
	if !decodeBody(w, r, &body) {
		return
	}

	started, err := o.mfa.StartEnrollment(r.Context(), mfa.StartEnrollmentInput{
		UserID: user.ID,
		Factor: body.Code,
	})
	if err != nil {
		o.writeMFAError(w, r, err)
		return
	}

	writeJSON(w, http.StatusCreated, startedEnrollmentResponse{
		EnrollmentID:    started.Credential.ID.String(),
		Secret:          started.Secret,
		ProvisioningURI: started.ProvisioningURI,
		Method:          started.Credential.Method,
		Digits:          started.Credential.Digits,
		PeriodSeconds:   started.Credential.PeriodSeconds,
		Algorithm:       started.Credential.Algorithm,
		ExpiresAt:       *started.Credential.ExpiresAt,
		Replaced:        started.Replaced,
	})
}

// handleConfirmEnrollment proves the user can produce a code from the secret.
//
//	POST /v1/mfa/enrollments/:id/confirm  {code}  →  200 {…, recovery_codes}
func (o options) handleConfirmEnrollment(w http.ResponseWriter, r *http.Request) {
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	enrollmentID, ok := enrollmentIDFrom(r)
	if !ok {
		notFound(w, r)
		return
	}

	var body *confirmEnrollmentRequest
	if !decodeBody(w, r, &body) {
		return
	}
	if body.Code == "" {
		// A 422 naming the field, and it is the only 422 on this surface: the code
		// is required rather than wrong, and telling the two apart saves a user
		// staring at a six-digit box wondering what they did.
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the request has an invalid field").
			withFieldErrors([]FieldError{{Field: "code", Code: mfa.CodeRequired}}))
		return
	}

	confirmed, err := o.mfa.Confirm(r.Context(), mfa.ConfirmInput{
		UserID:       user.ID,
		EnrollmentID: enrollmentID,
		Factor:       body.Code,
	})
	if err != nil {
		o.writeMFAError(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, confirmedEnrollmentResponse{
		Enabled:                true,
		Method:                 confirmed.Credential.Method,
		EnrolledAt:             *confirmed.Credential.ConfirmedAt,
		RecoveryCodes:          confirmed.RecoveryCodes,
		ReplacedExistingSecret: !confirmed.ReplacedCredentialID.IsZero(),
	})
}

// handleRegenerateRecoveryCodes issues a new set and destroys the old one.
//
//	POST /v1/mfa/recovery-codes  {code}  →  200 {recovery_codes, …}
//
// It takes a code because handing out ten fresh codes is handing out ten fresh
// ways into the account, and there is no route to this handler without one.
func (o options) handleRegenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	var body *factorRequest
	if !decodeBody(w, r, &body) {
		return
	}

	regenerated, err := o.mfa.RegenerateRecoveryCodes(r.Context(), mfa.RegenerateRecoveryCodesInput{
		UserID: user.ID,
		Factor: body.Code,
	})
	if err != nil {
		o.writeMFAError(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, recoveryCodesResponse{
		RecoveryCodes:          regenerated.RecoveryCodes,
		IssuedAt:               regenerated.IssuedAt,
		RecoveryCodesRemaining: RecoveryCodeCount,
	})
}

// handleDisableMFA turns the second factor off.
//
//	DELETE /v1/mfa  {code}  →  204
//
// A body on a DELETE is unusual and it is here because the request carries a
// credential, not parameters. 204 rather than the disabled row, matching every
// other DELETE in this service: the caller asked for the factor to stop working,
// not for a description of its corpse. The event is where a consumer learns.
//
// The CALLER'S OWN SESSION IS REVOKED by this call, because disabling revokes
// every session. A client that treats the 204 as "done" and then calls another
// endpoint will find itself signed out, and that is the honest outcome rather than
// an exception: a user who turns MFA off has very often had it turned off FOR them.
func (o options) handleDisableMFA(w http.ResponseWriter, r *http.Request) {
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	var body *factorRequest
	if !decodeBody(w, r, &body) {
		return
	}

	if err := o.mfa.Disable(r.Context(), mfa.DisableInput{UserID: user.ID, Factor: body.Code}); err != nil {
		o.writeMFAError(w, r, err)
		return
	}
	// The cookie is cleared as well as the row, so a browser is not left holding a
	// token that this very request revoked.
	o.clearSessionCookie(w)
	noContent(w)
}

// RecoveryCodeCount mirrors mfa.RecoveryCodeCount for the response body. It is a
// constant rather than a value read back from the service because the count of a
// freshly issued set IS the constant, and a client rendering "you now have N codes"
// wants N rather than a round trip to learn it.
const RecoveryCodeCount = mfa.RecoveryCodeCount

// enrollmentIDFrom reads and parses the pending enrollment id in the path, on the
// same terms as accountIDFrom: a value this service did not issue is the same
// answer as one it did and the caller may not see.
func enrollmentIDFrom(r *http.Request) (id.UUID, bool) {
	parsed, err := id.Parse(chi.URLParam(r, enrollmentIDParam))
	if err != nil || parsed.IsZero() {
		return id.UUID{}, false
	}
	return parsed, true
}

// ---------------------------------------------------------------------------
// the second step of a login
// ---------------------------------------------------------------------------

// MFAChallengeCookieName is where the challenge token lives in a browser.
//
// __Host- again, for the reason the session cookie uses it: Secure, Path=/, no
// Domain, so a sibling origin cannot write or overwrite it. A challenge token in a
// cookie an attacker can set is a challenge they can answer.
//
// The request id is NOT in the name, unlike the OIDC login page's state cookie:
// there is one login per browser, not one per product, so there is nothing to
// disambiguate and a per-request name would leave cookies behind.
const MFAChallengeCookieName = "__Host-mfa-challenge"

// completeSecondFactorRequest is the body of POST /v1/session/mfa.
//
// CHALLENGE IS HERE AS WELL AS IN THE COOKIE, and it has to be. core's conventions
// say "no cookies for API traffic", and this repository has already taken that
// seriously: POST /v1/session returns the session token in the BODY as well as in
// the cookie precisely so an API client has a way in. A second step that accepted
// the challenge only from a cookie would have broken that symmetry and left every
// non-browser client unable to complete a two-factor login.
//
// So the cookie is the BROWSER's route and this field is the API client's, and
// presentedChallenge prefers the explicit one for the reason presentedToken does:
// a client holding both has said which it means, and answering from ambient
// browser state would make the result depend on invisible cookies.
//
// The field is not a security hole. A cross-site form post cannot read a __Host
// cookie, so an attacker who wants to answer somebody's challenge has to have the
// token by some other means — and if they have the token they already have the
// second factor's value's container. The CSRF property rests on the token being
// unreadable by a foreign origin, which is what __Host- plus HttpOnly buys.
type completeSecondFactorRequest struct {
	Challenge string `json:"challenge,omitempty"`
	Code      string `json:"code"`
}

// presentedChallenge is the challenge this request is answering: the body first, the
// cookie second. "" when there is neither.
func presentedChallenge(r *http.Request, body *completeSecondFactorRequest) string {
	if body != nil && body.Challenge != "" {
		return body.Challenge
	}
	if cookie, err := r.Cookie(MFAChallengeCookieName); err == nil {
		return cookie.Value
	}
	return ""
}

// handleCompleteSecondFactor is the only route that turns a second factor into a
// session.
//
//	POST /v1/session/mfa  {challenge?, code}  →  200 {token, expires_at}
//
// It goes through auth.Service.CompleteSecondFactor, which is on the Auth interface
// because that is where the session is minted — inside the same transaction that
// consumes the challenge. A separate option for it would have been a second way to
// leave the whole login unreachable on a deployment that has no MFA_ENCRYPTION_KEY.
func (o options) handleCompleteSecondFactor(w http.ResponseWriter, r *http.Request) {
	var body *completeSecondFactorRequest
	if !decodeBody(w, r, &body) {
		return
	}

	challenge := presentedChallenge(r, body)
	if challenge == "" {
		// No challenge means no usable credential, and it is a 401 rather than a
		// 422: the caller is not authenticated, whatever they put in the body.
		unauthorized(w, r)
		return
	}

	result, err := o.auth.CompleteSecondFactor(r.Context(), auth.CompleteSecondFactorInput{
		ChallengeToken: challenge,
		Code:           body.Code,
	})
	if err != nil {
		// writeMFAError and not writeAuthError, because every error this route can
		// produce is a second-factor error: there is no password here to be wrong.
		// The two mappers share the 401 and the 423 cases, and a route that could
		// only reach one of them would be a route that silently rendered a wrong
		// code as a 500.
		o.writeMFAError(w, r, err)
		return
	}

	// The challenge cookie is spent as soon as it is used, so a replayed POST finds
	// nothing to match even before the store says the challenge is gone. The BODY
	// token is not cleared, because a body field is not a cookie: a browser that
	// read one out of a 202 and posted it back has no state for this to clear, and
	// the challenge row is the thing that actually expires.
	o.clearMFAChallengeCookie(w)
	o.setSessionCookie(w, result.Token, result.ExpiresAt)
	writeJSON(w, http.StatusOK, sessionResponse{Token: result.Token, ExpiresAt: result.ExpiresAt})
}

// setMFAChallengeCookie writes the challenge token where handleCompleteSecondFactor
// will find it.
func (o options) setMFAChallengeCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     MFAChallengeCookieName,
		Value:    token,
		Path:     "/", // required by the __Host- prefix
		Secure:   true,
		HttpOnly: true,
		// Lax, like the session cookie. The challenge is posted from this origin's
		// own form, so Strict buys nothing and would break a legitimate arrival
		// from a link the user followed to sign in to another product.
		SameSite: http.SameSiteLaxMode,
		Expires:  expiresAt,
	})
}

func (o options) clearMFAChallengeCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     MFAChallengeCookieName,
		Value:    "",
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

// ---------------------------------------------------------------------------
// error mapping
// ---------------------------------------------------------------------------

// writeMFAError maps the second-factor sentinels onto the envelope.
//
//	ErrInvalidFactor          401  one answer for a wrong code, a spent code, a
//	                                malformed one and a rotated-away secret
//	ErrEnrollmentNotFound     404  not yours, gone, expired, or already confirmed
//	ErrChallengeNotFound      404  not yours, expired, spent, or the user is gone
//	ErrNotEnabled             409  asked to change something that does not exist
//	ErrNoVault                503  a deployment problem, and the caller can act on it
//	*sessions.LockedError     423  with Retry-After, whichever factor ran out
//	*mfa.FieldError           422  understood, and one field is not acceptable
//
// THE 401 IS ONE SENTENCE AND ONE STATUS, and that is the security property
// rather than a simplification. Five different ways for a code to fail are five
// different facts, and an attacker who can tell them apart learns which to keep
// trying. A legitimate user's most common cause is a code they already used, and
// the honest response to that is the same sentence as for everything else.
func (o options) writeMFAError(w http.ResponseWriter, r *http.Request, err error) {
	var (
		locked   *sessions.LockedError
		fieldErr *mfa.FieldError
	)

	switch {
	case errors.Is(err, sessions.ErrNotFound), errors.Is(err, mfa.ErrEnrollmentNotFound),
		errors.Is(err, mfa.ErrChallengeNotFound):
		// 404 for all four, and 404 rather than 403 because a 403 would confirm the
		// enrollment or challenge exists to somebody who has no business knowing.
		problemFor(w, r, http.StatusNotFound, CodeNotFound,
			"no pending multi-factor enrollment or sign-in challenge matches that")

	case errors.Is(err, mfa.ErrNotEnabled):
		// 409 rather than 404: the caller is asking to change something that does
		// not exist, which is a different question from "is this yours".
		problemFor(w, r, http.StatusConflict, CodeConflict,
			"multi-factor authentication is not enabled for this account")

	case errors.Is(err, mfa.ErrInvalidFactor), errors.Is(err, auth.ErrInvalidCredentials),
		errors.Is(err, auth.ErrUnauthenticated):
		// The same 401 as a refused login, and deliberately the same sentence: the
		// two are the same answer to "you are not signed in". auth.ErrInvalidCredentials
		// is in the list because a login's own refusal can reach this route on the
		// OIDC login page's second step, and a 500 there would be a lie.
		unauthorized(w, r)

	case errors.As(err, &locked):
		seconds := retryAfterSeconds(locked.RetryAfter)
		w.Header().Set(RetryAfterHeader, seconds)
		problemFor(w, r, http.StatusLocked, CodeAccountLocked,
			"too many failed second-factor attempts for this account; retry after "+seconds+" seconds")

	case errors.Is(err, mfa.ErrNoVault):
		// 503, and the sentence says what is wrong rather than "try later". This is
		// a deployment problem, it is not the caller's fault, and a user who is told
		// only "try later" retries forever.
		problemFor(w, r, http.StatusServiceUnavailable, CodeServiceUnavailable,
			"this deployment cannot verify a second factor; MFA_ENCRYPTION_KEY is not configured")

	case errors.As(err, &fieldErr):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the request has an invalid field").
			withFieldErrors([]FieldError{{Field: fieldErr.Field, Code: fieldErr.Code}}))

	default:
		unexpected(w, r, o.logger, err)
	}
}

// compile-time proof that the two interfaces the router holds are the ones the use
// cases satisfy. It is a build-time assertion rather than a test because a change
// to either signature should stop the build, not a test run.
var (
	_ MFAManage = (*mfa.Service)(nil)
	_ MFA       = (*mfa.Service)(nil)
)

var _ = fmt.Sprintf
