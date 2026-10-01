package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/recovery"
	"github.com/cafaye/identity/internal/users"
)

// THE RECOVERY SURFACE.
//
// Eight routes, and the interesting one is not here: the token that redeems a
// password reset is a credential, and it is redeemed by a caller with NO session.
// Everything else in this file either starts a flow or reads its state.
//
//	POST /v1/password-resets                 {email}            anonymous
//	POST /v1/password-resets/confirm         {token, password}  anonymous, the token IS the credential
//	POST /v1/email-verifications             {email}            anonymous
//	POST /v1/email-verifications/confirm     {token}            anonymous, the token IS the credential
//	GET  /v1/email-verification                                 session only
//	POST /v1/email-changes                   {email}            session only
//	POST /v1/email-changes/current-address   {token}            anonymous, the token IS the credential
//	POST /v1/email-changes/new-address       {token}            anonymous, the token IS the credential
//
// # EVERY ONE OF THEM IS SESSION-ONLY IN THE OTHER DIRECTION
//
// `sessionCredentialOnly` wraps all eight, and the reason for the four anonymous
// ones is the same as for every other route in this service: a scoped api key has
// no scope here, and the ones on this surface are the ones where having one would
// be worst. A credential that could start an email change is a credential that can
// move an account's recovery path. A credential that could mint a password reset
// is a credential whose theft is a takeover with a delay rather than a break-in.
//
// # THE TWO REQUEST ROUTES ANSWER THE SAME THING FOR EVERY ADDRESS
//
// `acceptedResponse` is a constant. It is not a template with a field that happens
// to be equal either way round — there is no field. `202 {"status":"accepted"}` is
// what a registered address gets, what an unregistered one gets, and what an
// address inside the cooldown gets.
//
// The status is 202 rather than 200 and 204 rather than a 200 with a body, and it
// is 202 because the request WAS accepted for processing: the message is either
// being delivered or is not going to be, and neither is something the caller is
// entitled to know before they have proved which account they are asking about.

// Recovery is the part of recovery.Service the v1 routes need.
//
// Declared here, at the consumer, for the reason Auth and MFA are: the handlers
// are testable against a programmable double, and this file has no dependency on
// the use cases' internals. Every method takes an id or a clock-free input, so
// there is no way for a handler to reach past an authorization decision into a
// query it wrote itself.
type Recovery interface {
	RequestPasswordReset(ctx context.Context, email string) error
	RedeemPasswordReset(ctx context.Context, in recovery.RedeemPasswordResetInput) (recovery.RedeemPasswordResult, error)
	RequestVerification(ctx context.Context, email string) error
	RedeemVerification(ctx context.Context, in recovery.RedeemVerificationInput) error
	VerificationStatus(ctx context.Context, userID id.UUID) (recovery.Verification, error)
	RequestEmailChange(ctx context.Context, in recovery.RequestEmailChangeInput) (recovery.EmailChange, error)
	ConfirmEmailChangeCurrent(ctx context.Context, in recovery.ConfirmEmailChangeCurrentInput) (recovery.EmailChange, error)
	ConfirmEmailChangeNew(ctx context.Context, in recovery.ConfirmEmailChangeNewInput) (users.User, error)
}

// WithRecovery mounts the recovery surface.
//
// It is an Option for the reason every other service here is one: with no
// DATABASE_URL there is no recovery_tokens table, and that process must still answer
// /healthz. The routes are absent rather than present-and-500.
//
// IT IS NOT CONDITIONAL ON A MAILER. A deployment that cannot deliver answers 503
// on the routes that need to send one, with a sentence saying why — for the reason
// the login's second step is mounted without MFA_ENCRYPTION_KEY: a 404 here would
// tell a product this service has never heard of password recovery, which is the
// one answer that is both false and useless.
func WithRecovery(r Recovery) Option {
	return func(o *options) {
		if r != nil {
			o.recovery = r
		}
	}
}

// registerRecoveryRoutes mounts the surface.
func (o options) registerRecoveryRoutes(r chiRouter) {
	if o.recovery == nil {
		return
	}
	r.Post("/v1/password-resets", o.sessionCredentialOnly(o.handleRequestPasswordReset))
	r.Post("/v1/password-resets/confirm", o.sessionCredentialOnly(o.handleRedeemPasswordReset))
	r.Post("/v1/email-verifications", o.sessionCredentialOnly(o.handleRequestVerification))
	r.Post("/v1/email-verifications/confirm", o.sessionCredentialOnly(o.handleRedeemVerification))
	r.Get("/v1/email-verification", o.sessionCredentialOnly(o.handleVerificationStatus))
	r.Post("/v1/email-changes", o.sessionCredentialOnly(o.handleRequestEmailChange))
	r.Post("/v1/email-changes/current-address", o.sessionCredentialOnly(o.handleConfirmEmailChangeCurrent))
	r.Post("/v1/email-changes/new-address", o.sessionCredentialOnly(o.handleConfirmEmailChangeNew))
}

// ---------------------------------------------------------------------------
// request and response shapes
// ---------------------------------------------------------------------------

// acceptedResponse is the body of every "we have been asked to send a message"
// route, and it is a CONSTANT.
//
// That is the whole of the account-enumeration defence on those routes, and it is
// a constant rather than a template with a field that happens to render the same
// either way: a field is a field, and the next person to add one — a `expires_at`,
// an `email`, a `sent` boolean — reintroduces the oracle in a single line without
// touching a test that asserts the body says nothing.
type acceptedResponse struct {
	Status string `json:"status"`
}

// accepted is the one value every accepted response renders.
func accepted() acceptedResponse { return acceptedResponse{Status: "accepted"} }

// emailRequest is the body of the two routes that ask for a message to be sent.
// One type for both because the two have identical inputs and identical answers,
// which is the property TestTheTwoRequestRoutesAnswerIdentically holds.
type emailRequest struct {
	Email string `json:"email"`
}

// tokenRequest is the body of the three routes that redeem a token and need
// nothing else.
//
// It is one field and the three routes do not all use it: a password reset adds
// `password` in its own type below. A shared type would invite a client to send a
// password to a verification endpoint, where it would be ignored — and "ignored" is
// a worse answer than "refused", because a caller that believed the field was
// accepted would not know to retry.
type tokenRequest struct {
	Token string `json:"token"`
}

// passwordResetRequest is the body of POST /v1/password-resets/confirm.
type passwordResetRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

// verificationStatusResponse is GET /v1/email-verification.
//
// IT IS A SEPARATE ROUTE RATHER THAN A FIELD ON /v1/me, and the reason is that
// /v1/me's projection is asserted field-by-field to be exactly id and email — a
// test that fails if a domain struct ever grows a field that could reach a
// response body. Adding email_verified there would either break that invariant or
// weaken it, and the status a settings page wants ("is this address proved") is
// not the same question as "who am I".
type verificationStatusResponse struct {
	Email string `json:"email"`
	// EmailVerified and EmailVerifiedAt say the same thing in two shapes, and both
	// are here because a client needs one of them and the other is the one it does
	// not: a boolean for a conditional render, an instant for "verified on".
	// `omitempty` is doing real work on the timestamp — "never verified" and
	// "verified at the epoch" are different answers and only the first is true.
	EmailVerified   bool       `json:"email_verified"`
	EmailVerifiedAt *time.Time `json:"email_verified_at,omitempty"`
}

// emailChangeResponse is the 201 from POST /v1/email-changes, and the 200 from
// both confirmation steps.
//
// IT NAMES BOTH ADDRESSES because both are already known to the caller and neither
// is secret: `current_email` is the address they signed in with, and `new_email` is
// the one they typed. What it does NOT carry is a token, a digest, or a row id —
// the change is addressed by its tokens, and there is no id in this flow for a
// client to hold.
type emailChangeResponse struct {
	CurrentEmail string    `json:"current_email"`
	NewEmail     string    `json:"new_email"`
	ExpiresAt    time.Time `json:"expires_at"`
	// EmailVerified is the state of `new_email` after the move completes, and it is
	// present only on the 200 from the new-address confirmation. An email change
	// CLEARS the verification, so a client that reads this has to prompt for a
	// fresh verification rather than assuming the address it just moved to is
	// proved.
	EmailVerified *bool `json:"email_verified,omitempty"`
}

// ---------------------------------------------------------------------------
// handlers
// ---------------------------------------------------------------------------

// handleRequestPasswordReset asks for a reset link.
//
//	POST /v1/password-resets  {email}  →  202 {"status": "accepted"}
func (o options) handleRequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var body *emailRequest
	if !decodeBody(w, r, &body) {
		return
	}
	if err := o.recovery.RequestPasswordReset(r.Context(), body.Email); err != nil {
		o.writeRecoveryError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, accepted())
}

// handleRedeemPasswordReset spends a reset token and changes the password.
//
//	POST /v1/password-resets/confirm  {token, password}  →  204
//
// 204 and no body, and the caller's own session is revoked by the same transaction
// that changes the password — so a caller that was signed in when it started is
// signed out when it finishes, and cannot use this route to keep itself signed in.
// There is no session in the 204 because minting one here would be a second way to
// turn a mailbox into a credential without answering a second factor.
func (o options) handleRedeemPasswordReset(w http.ResponseWriter, r *http.Request) {
	var body *passwordResetRequest
	if !decodeBody(w, r, &body) {
		return
	}
	if _, err := o.recovery.RedeemPasswordReset(r.Context(), recovery.RedeemPasswordResetInput{
		Token:    body.Token,
		Password: body.Password,
	}); err != nil {
		o.writeRecoveryError(w, r, err)
		return
	}
	// The cookie is cleared as well as the row, so a browser is not left holding a
	// token this very request revoked.
	o.clearSessionCookie(w)
	noContent(w)
}

// handleRequestVerification asks for a link that proves the caller reads the
// account's address.
//
//	POST /v1/email-verifications  {email}  →  202 {"status": "accepted"}
func (o options) handleRequestVerification(w http.ResponseWriter, r *http.Request) {
	var body *emailRequest
	if !decodeBody(w, r, &body) {
		return
	}
	if err := o.recovery.RequestVerification(r.Context(), body.Email); err != nil {
		o.writeRecoveryError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, accepted())
}

// handleRedeemVerification spends a verification token.
//
//	POST /v1/email-verifications/confirm  {token}  →  204
//
// It revokes nothing and mints nothing. See recovery.Service.RedeemVerification for
// why both of those are deliberate: a verification changes no secret, so ending
// the account's sessions over it would punish somebody for clicking a link.
func (o options) handleRedeemVerification(w http.ResponseWriter, r *http.Request) {
	var body *tokenRequest
	if !decodeBody(w, r, &body) {
		return
	}
	if err := o.recovery.RedeemVerification(r.Context(), recovery.RedeemVerificationInput{
		Token: body.Token,
	}); err != nil {
		o.writeRecoveryError(w, r, err)
		return
	}
	noContent(w)
}

// handleVerificationStatus reports whether the caller's own address is proved.
//
//	GET /v1/email-verification  →  200 {email, email_verified, email_verified_at?}
func (o options) handleVerificationStatus(w http.ResponseWriter, r *http.Request) {
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	status, err := o.recovery.VerificationStatus(r.Context(), user.ID)
	if err != nil {
		o.writeRecoveryError(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, verificationStatusResponse{
		Email:           status.Email,
		EmailVerified:   status.Verified,
		EmailVerifiedAt: status.VerifiedAt,
	})
}

// handleRequestEmailChange starts a move to a new address.
//
//	POST /v1/email-changes  {email}  →  201 {current_email, new_email, expires_at}
//
// A SESSION IS REQUIRED and the middleware is the reason rather than the handler:
// the request is destructive and the first message goes to the account's own
// inbox, so a credential that could start one could move an account's recovery
// path. There is no scope in the machine vocabulary for that, and there is not
// going to be one.
func (o options) handleRequestEmailChange(w http.ResponseWriter, r *http.Request) {
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	var body *emailRequest
	if !decodeBody(w, r, &body) {
		return
	}

	change, err := o.recovery.RequestEmailChange(r.Context(), recovery.RequestEmailChangeInput{
		UserID: user.ID,
		Email:  body.Email,
	})
	if err != nil {
		o.writeRecoveryError(w, r, err)
		return
	}

	writeJSON(w, http.StatusCreated, emailChangeResponse{
		CurrentEmail: change.CurrentEmail,
		NewEmail:     change.NewEmail,
		ExpiresAt:    change.ExpiresAt,
	})
}

// handleConfirmEmailChangeCurrent proves control of the address the account has now.
//
//	POST /v1/email-changes/current-address  {token}  →  202 {"status": "accepted"}
//
// THE 202 BODY SAYS NOTHING ABOUT THE SECOND LINK, and that is the point: the
// caller has just proved they can read the current inbox, so they know they asked
// for this, and telling them which address the next message goes to would tell a
// hijacked session — which can reach this route with a token it does not have —
// nothing at all, while telling a legitimate user nothing they need.
func (o options) handleConfirmEmailChangeCurrent(w http.ResponseWriter, r *http.Request) {
	var body *tokenRequest
	if !decodeBody(w, r, &body) {
		return
	}
	if _, err := o.recovery.ConfirmEmailChangeCurrent(r.Context(), recovery.ConfirmEmailChangeCurrentInput{
		Token: body.Token,
	}); err != nil {
		o.writeRecoveryError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, accepted())
}

// handleConfirmEmailChangeNew completes a move to a new address.
//
//	POST /v1/email-changes/new-address  {token}  →  200 {…, email_verified: false}
//
// The 200 rather than a 204 is because this route DOES change something the caller
// needs to know: the address has moved, the verification has been cleared, and
// every session the account had is gone. A 204 would leave a client to rediscover
// all three by making three other requests.
//
// email_verified is FALSE and that is not a bug: clicking a link proves you can
// read an inbox, not that the new address is this account's, and
// `users.Store.SetEmail` clears the column in the same statement that moves the
// address. A client rendering "your address is updated" from this body and nothing
// else is correct; a client rendering "your address is verified" is not.
func (o options) handleConfirmEmailChangeNew(w http.ResponseWriter, r *http.Request) {
	var body *tokenRequest
	if !decodeBody(w, r, &body) {
		return
	}

	updated, err := o.recovery.ConfirmEmailChangeNew(r.Context(), recovery.ConfirmEmailChangeNewInput{
		Token: body.Token,
	})
	if err != nil {
		o.writeRecoveryError(w, r, err)
		return
	}

	// Every session is revoked by this call, including one this same browser is
	// holding, so the cookie is cleared rather than left behind as a credential
	// that no longer resolves.
	o.clearSessionCookie(w)

	verified := updated.IsVerified()
	writeJSON(w, http.StatusOK, emailChangeResponse{
		CurrentEmail:  updated.Email,
		NewEmail:      updated.Email,
		EmailVerified: &verified,
	})
}

// ---------------------------------------------------------------------------
// error mapping
// ---------------------------------------------------------------------------

// writeRecoveryError maps the recovery sentinels onto the envelope.
//
//	ErrTokenNotFound  404  one answer for four cases: a token that never existed,
//	                       one that expired, one already spent, and one minted for
//	                       another flow. 404 rather than 401 because the caller is
//	                       not asking who they are — they are following a link, and
//	                       "there is no such link" is the answer for every link they
//	                       did not receive. 401 would also be a lie about a caller
//	                       this service deliberately does not authenticate.
//	ErrNoMailer       503  a deployment problem, and the caller can act on it: a
//	                       product that sees this knows not to render "check your
//	                       inbox", which is the whole reason this is not a 500.
//	ErrEmailTaken     409  the state the request asks for collides with one that
//	                       exists. The caller is authenticated and typed the address,
//	                       so this is the same disclosure POST /v1/users already
//	                       makes and the one place in this service it is safe.
//	ErrSameAddress    422  a well-formed request for something that is not a change.
//	ErrAlreadyVerified 409 the request was understood and asks for something that
//	                       already holds.
//	*users.FieldError 422  the request is not acceptable, per field.
func (o options) writeRecoveryError(w http.ResponseWriter, r *http.Request, err error) {
	var fieldErr *users.FieldError

	switch {
	case errors.Is(err, recovery.ErrTokenNotFound):
		problemFor(w, r, http.StatusNotFound, CodeNotFound,
			"no such link, or it has already been used")

	case errors.Is(err, recovery.ErrNoMailer):
		problemFor(w, r, http.StatusServiceUnavailable, CodeServiceUnavailable,
			"this deployment cannot send email, so it cannot send that link")

	case errors.Is(err, recovery.ErrEmailTaken):
		problemFor(w, r, http.StatusConflict, CodeConflict,
			"an account already exists for that email address")

	case errors.Is(err, recovery.ErrAlreadyVerified):
		problemFor(w, r, http.StatusConflict, CodeConflict,
			"this account's email address is already verified")

	case errors.Is(err, recovery.ErrSameAddress):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("that is already the address on this account").
			withFieldErrors([]FieldError{{Field: "email", Code: "already_current"}}))

	case errors.As(err, &fieldErr):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the request has an invalid field").
			withFieldErrors([]FieldError{{Field: fieldErr.Field, Code: fieldErr.Code}}))

	default:
		unexpected(w, r, o.logger, err)
	}
}

// compile-time proof that the interface the router holds is the one the use cases
// satisfy. It is a build-time assertion rather than a test because a change to
// either signature should stop the build, not a test run.
var _ Recovery = (*recovery.Service)(nil)
