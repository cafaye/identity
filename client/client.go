// Package client is the cafaye Go client for identity: a generated transport over
// `openapi/v1.yaml`, and a hand-written wrapper over that transport.
//
// # WHY GO GENERATES AND PYTHON DOES NOT
//
// MD6 ruled "generate for TypeScript and Go, hand-write the unified client, and do
// not generate Python yet", and the asymmetry is deliberate rather than accidental.
// Go has oapi-codegen, which emits typed structs and a `Client` interface and whose
// output reaches this repository's stack with no new dependency in the shipped
// binary. Python's generators impose a runtime model layer or a dependency the user
// must install, and a hand-written Python client has the smaller attack surface of
// the two.
//
// **One correction to MD6's stated reason, measured while building this package.**
// MD6 says the Go client "reaches `identity`'s existing stack with no new dependency
// at runtime". That is true of the SERVICE and false of the generated code, and the
// distinction matters because it is the whole argument. `client/generated` imports
// `github.com/oapi-codegen/runtime`, so `go.mod` gains three modules. What it does
// not do is reach the binary: `go list -deps ./cmd/identity` does not contain
// `github.com/oapi-codegen/runtime`, because nothing under `cmd/` imports this
// package. The generated client has a dependency; the shipped artefact does not.
// See `TestTheServiceBinaryDoesNotReachTheGeneratedClient`, which holds it.
//
// # WHAT IS HERE
//
//	client/generated/   oapi-codegen v2.8.0 output, COMMITTED, lint-excluded
//	transport.go        the interface the generated client satisfies
//	client.go           the hand-written client: forty-one operations, typed results
//	credentials.go      which credential this is, and where it may be sent
//	baseurl.go          where requests go, in a documented order
//	errors.go           RFC 9457 problem to typed error, with a typed fallback
//	redact.go           the scrubber, and the all-or-nothing rule
//
// # THE SECURITY INVARIANT
//
// **No credential ever reaches a string a human reads.** Not in a log, not in an
// error message, not in a serialised form, not in a `fmt.Stringer`, not in a
// `%v`. This package holds the token for its whole life, and `error.Error()` and
// `fmt.Sprintf("%v", …)` reach a log file, a crash report and a support ticket with
// no configuration.
//
// The rule is structural rather than a matter of care: every string this package
// builds out of anything a caller or a service supplied passes through
// `Redactor.String` first, and redaction is all-or-nothing — a string comes back
// whole or comes back as `Redacted`. `TestTheClientNeverPrintsACredential` is what
// holds it.
//
// # WHAT THIS PACKAGE DELIBERATELY DOES NOT DO
//
// No retry, no pagination helper, no token refresh, no cache, no response
// validation, no method spanning two operations. MD6 named four responsibilities —
// credentials, base URLs, RFC 9457 mapping, and being the public surface — and this
// has those four. The one exception is `Transport()`, an escape hatch for an
// operation the document gained after generation, named so its cost is visible:
// errors from it are not typed.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	openapiTypes "github.com/oapi-codegen/runtime/types"

	"github.com/cafaye/identity/client/generated"
)

// DefaultTimeout bounds a request when the caller sets none.
//
// Not `http.Client`'s zero value, which means "no timeout at all": a client for the
// platform's security boundary that can hang forever on a socket is a resource leak
// with a credential attached. Thirty seconds is generous for every operation in
// this document — all forty-one are row reads, row writes, and one argon2id
// verification — and short enough that a caller is not left holding a goroutine.
const DefaultTimeout = 30 * time.Second

// maxResponseBytes bounds what a single response body may cost.
//
// A bound, not a limit that is never reached: without one, a misbehaving or
// impersonating endpoint streams as much as it likes into this process's memory
// while the caller waits. Eight MiB is far above any response in this document —
// the largest is a member list — so hitting it means something is wrong.
//
// `io.LimitReader` reads one byte more than the limit, so the truncation is
// detectable rather than silent.
const maxResponseBytes = 8 << 20

// Options configures a Client.
//
// A struct so a caller names what they set, and so the next field is additive rather
// than a positional argument somebody has to remember the order of.
type Options struct {
	// BaseURL is where identity is. Required unless `CAFAYE_IDENTITY_BASE_URL` or
	// `CAFAYE_BASE_URL` is set — see ResolveBaseURL for the precedence and for why
	// there is no default.
	BaseURL string

	// Token is the credential. Empty means an anonymous client, which is
	// legitimate: `GET /healthz`, `GET /readyz`, `POST /v1/session` and
	// `POST /v1/users` are all served without one.
	Token string

	// Timeout bounds one request. Zero means DefaultTimeout.
	Timeout time.Duration

	// LookupEnv reads the environment. nil means `os.Getenv`. Present so every test
	// in this package exercises precedence without mutating the process environment,
	// which would race every other test in the package and leak past its end.
	LookupEnv LookupEnv

	// HTTPClient replaces the transport entirely. nil means a client built from
	// Timeout.
	//
	// The seam that makes this package testable without a network: a test points
	// this at an `httptest.Server`. No test in this package reaches the internet —
	// a client suite that did would fail on somebody else's outage.
	HTTPClient *http.Client
}

// Client is the hand-written cafaye identity client.
//
// Immutable after construction: every method takes a context and returns, and
// nothing mutates the struct. One Client may therefore be shared across goroutines
// with no locking, which is worth stating because it is not Go's default. The
// embedded `*http.Client` is safe for concurrent use and the token is read-only, so
// the only thing that could break this is a cache or a counter added later — and
// `TestTheClientIsSafeForConcurrentUse` runs calls under `-race` to keep that
// honest rather than assumed.
// There is NO `token` field, and that is the security design rather than an
// oversight. Every `fmt` verb prints a struct's exported fields by value under
// `%#v`, so a `token string` field would be a credential leak to `fmt.Printf("%#v",
// client)` — a verb that does not consult `String()` and cannot be intercepted.
//
// The credential therefore exists only inside two closures' environments: the one
// `redactor` holds and the request editor installed on the transport. Go renders a
// func value as `(func(...))(0xADDR)` for EVERY verb, so no formatting path can print
// what a closure captured. `String()` below covers the four verbs `fmt` would
// otherwise route to a default struct rendering, and the closures are what make
// `%#v` safe too.
//
// `hasCredential` is a bool rather than a second copy of the token for the same
// reason.
type Client struct {
	baseURL string

	// hasCredential is what `HasCredential` reports. A bool, so the accessor cannot
	// be the leak.
	hasCredential bool

	// transport is the generated client behind the `Transport` interface.
	transport Transport

	// redactor carries this client's credential inside a closure, so every string
	// this package builds can be scrubbed without the caller passing it in each
	// time — and without the redactor itself being printable.
	redactor Redactor
}

// String makes this client safe to print.
//
// `fmt` calls this for `%v`, `%+v`, `%s` and `%q`, which together are effectively
// every way a value reaches a log line. It reports the two things a reader of a log
// needs — where requests go, and whether this client holds a credential — and
// deliberately does NOT print the transport, whose pointer is noise and whose
// request editors close over the token.
//
// `%#v` bypasses this method by design in Go, and cannot be intercepted; that is why
// the credential is in closures rather than in a field. See the type's comment.
func (c *Client) String() string {
	credential := "no credential"
	if c.hasCredential {
		credential = "a credential, redacted"
	}
	return "client.Client{baseURL: " + c.redactor.String(c.baseURL) +
		", holds " + credential + "}"
}

// New builds a client.
//
// The base URL is resolved eagerly rather than per request, so a missing one is a
// construction-time error naming the variable to set rather than a connection refused
// on the fifth call from a function that has nothing to do with configuration.
//
// A credential `ClassifyCredential` refuses fails here too, for the same reason: a
// credential carrying a newline is a configuration mistake, and finding it at
// construction is worth more than a 401 from a service hours later.
func New(opts Options) (*Client, error) {
	base, err := ResolveBaseURL(BaseURLOptions{BaseURL: opts.BaseURL, LookupEnv: opts.LookupEnv})
	if err != nil {
		return nil, err
	}

	if opts.Token != "" {
		if _, err := ClassifyCredential(opts.Token); err != nil {
			return nil, err
		}
	}

	transport, err := newTransport(base, opts.Token)
	if err != nil {
		return nil, err
	}

	return &Client{
		baseURL:       base,
		hasCredential: opts.Token != "",
		transport:     transport,
		redactor:      NewRedactor(opts.Token),
	}, nil
}

// BaseURL is where this client sends requests.
//
// Exported because a self-hoster debugging a misconfiguration needs to see which
// value won. There is deliberately no `Token()` and no `String()`: an accessor that
// returns a credential is an accessor somebody will put in a log.
func (c *Client) BaseURL() string { return c.baseURL }

// HasCredential reports whether this client holds one, without revealing it.
//
// A caller that needs to branch on "am I authenticated" gets an answer and not the
// thing itself, which is the whole difference between a useful accessor and a
// credential in somebody's structured log.
func (c *Client) HasCredential() bool { return c.hasCredential }

// Transport returns the underlying generated client.
//
// **Errors from it are not typed.** It hands back `*http.Response`, so a 401 is a
// response rather than a `*UnauthenticatedError`, and a caller using this is back to
// reading statuses.
//
// It exists for one reason: an operation added to `openapi/v1.yaml` after this
// client was generated. That is a real and expected event — the drift gate makes it
// visible rather than preventing it, and this hatch is what makes it acceptable.
func (c *Client) Transport() Transport { return c.transport }

// call runs one operation and turns the outcome into (result, error).
//
// The one place a response becomes a decision, so every operation gets identical
// treatment: a 2xx decodes into `out`, anything else becomes a typed error, and an
// empty body on a success is not an error.
//
// `operation` is the `operationId` — the name of the generated method and therefore
// what a reader recognises in a log line.
//
// The body is always closed here, which is the most common defect in a hand-written
// HTTP client and the reason `bodyclose` is in kit's linter set. It is closed on the
// error paths too, and the read is bounded by `maxResponseBytes` for the reason on
// that constant.
func call[Out any](
	c *Client,
	operation string,
	send func() (*http.Response, error),
	out *Out,
) error {
	res, err := send()
	if err != nil {
		// A transport failure has no response and no status.
		return c.transportError(operation, err)
	}
	// The body is closed on the way out of THIS function, not at the end of the
	// caller's, because `call` is the only place that reads one. A `defer` here
	// would be right and this is one — the explicitness is because errcheck is in
	// kit's set and `bodyclose` is the linter that catches a missing one, and the
	// cheapest way to keep both happy is to have exactly one reader.
	defer closeBody(res)

	body, readErr := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if len(body) > maxResponseBytes {
		return &CallError{
			Operation: operation,
			Status:    res.StatusCode,
			redactor:  c.redactor,
			message: "the response exceeded this client's " +
				itoa(maxResponseBytes) + "-byte limit for a single body. Nothing in this " +
				"document is that large, so this is a misconfigured or impersonating endpoint.",
		}
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return ProblemFrom(operation, res.StatusCode, res.Header.Get("Content-Type"),
			res.Header.Get(RetryAfterHeader), body, c.redactor)
	}

	if readErr != nil {
		return &CallError{
			Operation: operation,
			Status:    res.StatusCode,
			redactor:  c.redactor,
			message:   c.redactor.String("the response body could not be read: " + readErr.Error()),
		}
	}

	// A 204, and any success with no body, is a success with nothing to decode.
	// Treating "empty" as an error would make every DELETE in this document — eight
	// of the forty-one operations — fail while succeeding.
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}

	if err := json.Unmarshal(body, out); err != nil {
		return &CallError{
			Operation: operation,
			Status:    res.StatusCode,
			redactor:  c.redactor,
			message: "the response was 2xx but its body is not the result the contract " +
				"promises for " + operation + ": " + c.redactor.String(err.Error()),
		}
	}

	return nil
}

// callVoid is `call` for an operation whose contract is a 204 with no body.
//
// It exists because Go cannot infer a type parameter from an untyped `nil`, and the
// alternative — passing a `*struct{}` and hoping — is how a caller ends up with a
// method that returns a value the contract says does not exist. Nine of the forty-one
// operations in this document answer 204, so this is not a rare shape.
//
// `ctx` is accepted and ignored for symmetry with `call`; the context reaches the
// request through the transport, not through here.
func callVoid(ctx context.Context, c *Client, operation string, send func() (*http.Response, error)) error {
	return call[struct{}](c, operation, send, nil)
}

// --- the forty-one operations ------------------------------------------------
//
// One per `operationId`, named exactly as the document names them. That naming is
// not a style choice: `operationId` is the contract, it is what every generated
// client in the fleet uses as its method name, and a Go client calling this `GetMe`
// where `cafaye-ts` says `getCurrentUser` would be a divergence in three clients for
// one platform, which the fleet treats as a defect in the platform.
//
// Each is one call through `call`. There is no per-operation validation, no retry
// and no transformation, because any of those is a policy this package should not
// own — see the file header.

// Liveness answers whether the process is running, without touching a dependency.
// Corresponds to `GET /healthz`.
func (c *Client) Liveness(ctx context.Context) (*generated.Health, error) {
	var out generated.Health
	err := call(c, "liveness", func() (*http.Response, error) {
		return c.transport.Liveness(ctx)
	}, &out)
	return &out, err
}

// Readiness answers whether the process can serve traffic. Corresponds to
// `GET /readyz`.
//
// Its 503 is `{status, deps}` rather than a problem document — this repository's
// document records that as known gap 4, a conflict with core's conventions — so a
// failing probe arrives as `errUnavailable` rather than a `*ProblemError`, which is
// the honest reading: a dependency being down is the definition of retryable.
func (c *Client) Readiness(ctx context.Context) (*generated.Health, error) {
	var out generated.Health
	err := call(c, "readiness", func() (*http.Response, error) {
		return c.transport.Readiness(ctx)
	}, &out)

	var call *CallError
	if errors.As(err, &call) && call.Status == http.StatusServiceUnavailable {
		return nil, ErrUnavailable
	}
	return &out, err
}

// RegisterUser creates a user. Corresponds to `POST /v1/users`.
func (c *Client) RegisterUser(ctx context.Context, body generated.RegisterUserJSONRequestBody) (*generated.User, error) {
	var out generated.User
	err := call(c, "registerUser", func() (*http.Response, error) {
		return c.transport.RegisterUser(ctx, body)
	}, &out)
	return &out, err
}

// CreateSession logs in. Corresponds to `POST /v1/session`.
//
// **The 202 is not a session.** An account with a second factor gets a challenge
// back and no token, and the document says so explicitly: "there is no `token` field
// in this schema, and that is deliberate". A caller who treats a 202 as a login
// success is holding an unauthenticated client, so the 202 is an error — a
// `*MFARequiredError` carrying the challenge — and the one caller who should handle
// it does so with `errors.As`.
//
// `POST /v1/session` is also the one mutating POST in this document that accepts no
// `Idempotency-Key`, on purpose: a login is not safely repeatable, since retrying it
// mints a second session rather than returning the first. Which is why this package
// retries nothing.
func (c *Client) CreateSession(ctx context.Context, body generated.LoginRequest) (*generated.Session, error) {
	var session generated.Session
	var challenge generated.MFAChallenge

	// The status has to be read here rather than left to `call`, because the two
	// outcomes are both 2xx: 200 carries a session and 202 carries a challenge and
	// no session at all. `call` is written for "2xx is one shape", and this is the
	// one operation in the document where it is not — so it does not go through
	// `call`, and the reason is written here rather than left to be rediscovered.
	res, err := c.transport.CreateSession(ctx, body)
	if err != nil {
		return nil, c.transportError("createSession", err)
	}
	defer closeBody(res)

	payload, readErr := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, ProblemFrom("createSession", res.StatusCode,
			res.Header.Get("Content-Type"), res.Header.Get(RetryAfterHeader), payload, c.redactor)
	}
	if readErr != nil {
		return nil, &CallError{
			Operation: "createSession", Status: res.StatusCode, redactor: c.redactor,
			message: c.redactor.String("the response body could not be read: " + readErr.Error()),
		}
	}

	// 202 first, before decoding anything: the two bodies decode into different
	// types and decoding the challenge into a Session would produce a Session whose
	// Token is the empty string — a credential-shaped value that is not a
	// credential, which is the exact shape of bug this repository's `MFAChallenge`
	// comment says a client must not introduce.
	if res.StatusCode == http.StatusAccepted {
		if err := json.Unmarshal(payload, &challenge); err != nil {
			return nil, &CallError{
				Operation: "createSession", Status: res.StatusCode, redactor: c.redactor,
				message: "the service answered 202 but its body is not an MFAChallenge: " +
					c.redactor.String(err.Error()),
			}
		}
		return nil, &MFARequiredError{
			CallError: CallError{
				Operation: "createSession", Status: res.StatusCode, redactor: c.redactor,
			},
			Challenge: challenge,
		}
	}

	if err := json.Unmarshal(payload, &session); err != nil {
		return nil, &CallError{
			Operation: "createSession", Status: res.StatusCode, redactor: c.redactor,
			message: "the response was 2xx but its body is not a Session: " +
				c.redactor.String(err.Error()),
		}
	}
	return &session, nil
}

// closeBody closes a response body and ignores its error, on purpose and in one
// place.
//
// The error from `Close` on a fully-read body is not actionable: the connection is
// being returned to the pool either way, and there is nothing a caller could do
// with "the body could not be signalled closed". Discarding it is correct — but
// discarding it with a bare `_ =` is a decision that should be written down once
// rather than argued about at forty call sites, and `bodyclose`/`errcheck` are in
// the fleet's linter set precisely so that "did anybody close it" is never a
// question.
func closeBody(res *http.Response) {
	_ = res.Body.Close()
}

// transportError turns a `net/http` failure into a CallError.
//
// Its own method rather than inlined because three call paths need it and the
// redaction is the point: `*url.Error`'s text embeds the request URL, and a URL is
// the one place a caller can have put a credential in a query parameter.
func (c *Client) transportError(operation string, err error) error {
	return &CallError{
		Operation: operation,
		redactor:  c.redactor,
		message:   c.redactor.String(err.Error()),
	}
}

// DeleteSession revokes the session the presented credential names.
// Corresponds to `DELETE /v1/session`.
//
// Returns no value: the contract is a 204, and a method returning a `*Session` would
// invite a caller to read a revoked session's fields. A scoped API token is refused
// here with 403 rather than accepted, which is what `POST /v1/session` returning a
// `Session` value and not a token would otherwise invite somebody to try.
func (c *Client) DeleteSession(ctx context.Context) error {
	return callVoid(ctx, c, "deleteSession", func() (*http.Response, error) {
		return c.transport.DeleteSession(ctx)
	})
}

// CompleteSecondFactor answers a second factor and starts the session. Corresponds
// to `POST /v1/session/mfa`.
func (c *Client) CompleteSecondFactor(ctx context.Context, body generated.CompleteSecondFactorJSONRequestBody) (*generated.Session, error) {
	var out generated.Session
	err := call(c, "completeSecondFactor", func() (*http.Response, error) {
		return c.transport.CompleteSecondFactor(ctx, body)
	}, &out)
	return &out, err
}

// GetMFAStatus reports whether the caller has a second factor. Corresponds to
// `GET /v1/mfa`.
func (c *Client) GetMFAStatus(ctx context.Context) (*generated.MFAStatus, error) {
	var out generated.MFAStatus
	err := call(c, "getMFAStatus", func() (*http.Response, error) {
		return c.transport.GetMFAStatus(ctx)
	}, &out)
	return &out, err
}

// StartMFAEnrollment generates a TOTP secret, unconfirmed. Corresponds to
// `POST /v1/mfa/enrollments`.
//
// The response carries the only copy of `secret` and `provisioning_uri` this service
// will ever produce for this enrollment, and it is not a session and not MFA — a
// pending enrollment is unread by the login path until `/confirm`. So this method
// returns the value and the caller is responsible for it; a client that logged it
// would be logging a second factor.
func (c *Client) StartMFAEnrollment(ctx context.Context, body generated.StartEnrollmentRequest) (*generated.StartedEnrollment, error) {
	var out generated.StartedEnrollment
	err := call(c, "startMFAEnrollment", func() (*http.Response, error) {
		return c.transport.StartMFAEnrollment(ctx, body)
	}, &out)
	return &out, err
}

// ConfirmMFAEnrollment proves a code can be produced, and makes MFA live. Corresponds
// to `POST /v1/mfa/enrollments/{enrollmentId}/confirm`.
//
// **Every session the user holds is revoked by this call, including the caller's
// own**, and the recovery codes in the response exist exactly once. Both are in the
// contract and neither is enforced by the client; they are stated here so a caller
// does not discover them from a 401.
func (c *Client) ConfirmMFAEnrollment(ctx context.Context, enrollmentId openapiTypes.UUID, body generated.ConfirmEnrollmentRequest) (*generated.ConfirmedEnrollment, error) {
	var out generated.ConfirmedEnrollment
	err := call(c, "confirmMFAEnrollment", func() (*http.Response, error) {
		return c.transport.ConfirmMFAEnrollment(ctx, enrollmentId, body)
	}, &out)
	return &out, err
}

// RegenerateMFARecoveryCodes issues a fresh set and destroys the old one.
// Corresponds to `POST /v1/mfa/recovery-codes`.
func (c *Client) RegenerateMFARecoveryCodes(ctx context.Context, body generated.FactorRequest) (*generated.RecoveryCodesResponse, error) {
	var out generated.RecoveryCodesResponse
	err := call(c, "regenerateMFARecoveryCodes", func() (*http.Response, error) {
		return c.transport.RegenerateMFARecoveryCodes(ctx, body)
	}, &out)
	return &out, err
}

// DisableMFA turns the second factor off. Corresponds to `DELETE /v1/mfa`.
//
// Also revokes every session the user holds. The contract is a 204 with no body, so
// this returns only an error.
func (c *Client) DisableMFA(ctx context.Context, body generated.FactorRequest) error {
	return callVoid(ctx, c, "disableMFA", func() (*http.Response, error) {
		return c.transport.DisableMFA(ctx, body)
	})
}

// GetCurrentUser resolves the presented credential. Corresponds to `GET /v1/me`.
func (c *Client) GetCurrentUser(ctx context.Context) (*generated.User, error) {
	var out generated.User
	err := call(c, "getCurrentUser", func() (*http.Response, error) {
		return c.transport.GetCurrentUser(ctx)
	}, &out)
	return &out, err
}

// RequestPasswordReset asks for a reset link. Corresponds to `POST /v1/password-resets`.
//
// **The response carries nothing about the address.** A registered address, an
// unregistered one and one inside the cooldown all return the same body, and the
// client must not attempt to tell them apart — an argument that this method exists
// to make, because a caller that branched on the response would be inventing an
// enumeration oracle in the product. The returned `Accepted` has one field with one
// value; treat a non-nil result as "asked", never as "sent".
func (c *Client) RequestPasswordReset(ctx context.Context, body generated.RequestPasswordResetJSONRequestBody) (*generated.Accepted, error) {
	var out generated.Accepted
	err := call(c, "requestPasswordReset", func() (*http.Response, error) {
		return c.transport.RequestPasswordReset(ctx, body)
	}, &out)
	return &out, err
}

// ConfirmPasswordReset spends a reset link. Corresponds to `POST /v1/password-resets/confirm`.
//
// **Every session and every live OIDC access token is revoked, and no session is
// returned.** A caller that was signed in before this call is signed out by it, so a
// client rendering a "password changed, stay signed in" transition is promising
// something this service does not do — sign in again with the new password.
//
// The token in `body` is a live credential until it is spent. It is passed through
// and not logged, redacted or retained by this client; the generated
// `ConfirmPasswordResetRequest` has no redacting `String()`, so a caller printing it
// whole is printing a credential that was valid a moment ago.
func (c *Client) ConfirmPasswordReset(ctx context.Context, body generated.ConfirmPasswordResetJSONRequestBody) error {
	return callVoid(ctx, c, "confirmPasswordReset", func() (*http.Response, error) {
		return c.transport.ConfirmPasswordReset(ctx, body)
	})
}

// RequestEmailVerification asks for a link proving the account's own address.
// Corresponds to `POST /v1/email-verifications`.
//
// Registration does not send one, so a product that wants an address proved calls
// this after `RegisterUser`. Same constant response as every other request route;
// same rule — a non-nil result means "asked", not "sent".
//
// **IT ANSWERED 409 FOR AN ALREADY-PROVED ADDRESS UNTIL 2026-10-02, and this method
// has no conflict case to hand a caller.** That 409 was an account-enumeration oracle
// on a route that requires no credential: `security` on this operation is `[]`, so
// posting a list of addresses and reading the statuses back was a list of verified
// accounts. A caller that needs to know whether an address is already proved must ask
// `GetEmailVerification`, which requires a session and answers for the caller alone.
// `ConflictError` is still returned by this client for the routes where a 409 is the
// honest answer — registering a taken address, and starting an email change to one.
func (c *Client) RequestEmailVerification(ctx context.Context, body generated.RequestEmailVerificationJSONRequestBody) (*generated.Accepted, error) {
	var out generated.Accepted
	err := call(c, "requestEmailVerification", func() (*http.Response, error) {
		return c.transport.RequestEmailVerification(ctx, body)
	}, &out)
	return &out, err
}

// ConfirmEmailVerification spends a verification link. Corresponds to `POST /v1/email-verifications/confirm`.
//
// **Nothing is revoked and nothing is minted.** A verification is not a credential,
// it is a fact about an address — so a caller must not sign anybody out here, and
// must not expect a session in the response.
func (c *Client) ConfirmEmailVerification(ctx context.Context, body generated.ConfirmEmailVerificationJSONRequestBody) error {
	return callVoid(ctx, c, "confirmEmailVerification", func() (*http.Response, error) {
		return c.transport.ConfirmEmailVerification(ctx, body)
	})
}

// GetEmailVerificationStatus reports whether the caller's own address is proved.
// Corresponds to `GET /v1/email-verification`.
//
// A separate method rather than a field on `GetCurrentUser`, because `generated.User`
// is asserted field-by-field to be exactly an id and an email. `EmailVerifiedAt` is
// absent when the address was never verified, which is a different state from a
// verified address that has since been changed — and `EmailVerified` alone cannot
// tell those two apart.
func (c *Client) GetEmailVerificationStatus(ctx context.Context) (*generated.VerificationStatus, error) {
	var out generated.VerificationStatus
	err := call(c, "getEmailVerificationStatus", func() (*http.Response, error) {
		return c.transport.GetEmailVerificationStatus(ctx)
	}, &out)
	return &out, err
}

// RequestEmailChange starts a move to a new address. Corresponds to
// `POST /v1/email-changes`.
//
// **Nothing has moved yet, and this is not a three-request transaction the client may
// abandon halfway without consequence.** The first link goes to the address the
// account has now; only when it is redeemed is a second one minted for the new
// address. A caller that starts a change and never finishes it leaves a message in
// the user's current inbox saying their address is being changed, which is the only
// warning they get.
func (c *Client) RequestEmailChange(ctx context.Context, body generated.RequestEmailChangeJSONRequestBody) (*generated.EmailChange, error) {
	var out generated.EmailChange
	err := call(c, "requestEmailChange", func() (*http.Response, error) {
		return c.transport.RequestEmailChange(ctx, body)
	}, &out)
	return &out, err
}

// ConfirmEmailChangeCurrentAddress proves control of the current address. Corresponds
// to `POST /v1/email-changes/current-address`.
//
// **The `Accepted` response says nothing about where the second link went, and this
// client must not guess.** The caller already knows the address they typed, so naming
// the destination here would tell a hijacked session — which can reach this route
// with a token it does not have — something it does not already know.
func (c *Client) ConfirmEmailChangeCurrentAddress(ctx context.Context, body generated.ConfirmEmailChangeCurrentAddressJSONRequestBody) (*generated.Accepted, error) {
	var out generated.Accepted
	err := call(c, "confirmEmailChangeCurrentAddress", func() (*http.Response, error) {
		return c.transport.ConfirmEmailChangeCurrentAddress(ctx, body)
	}, &out)
	return &out, err
}

// ConfirmEmailChangeNewAddress completes a move to a new address. Corresponds to
// `POST /v1/email-changes/new-address`.
//
// **Every session and every live OIDC access token is revoked, and the address is now
// unverified.** `out.EmailVerified` is a `*bool` and this call always leaves it
// present and false: clicking a link proves you can read an inbox, not that the new
// address belongs to the account. A client that renders "your address is verified"
// from this response is wrong; it should prompt for
// `RequestEmailVerification`, which now targets the new address.
func (c *Client) ConfirmEmailChangeNewAddress(ctx context.Context, body generated.ConfirmEmailChangeNewAddressJSONRequestBody) (*generated.EmailChange, error) {
	var out generated.EmailChange
	err := call(c, "confirmEmailChangeNewAddress", func() (*http.Response, error) {
		return c.transport.ConfirmEmailChangeNewAddress(ctx, body)
	}, &out)
	return &out, err
}

// CreateAccount provisions an account and makes the caller its owner.
// Corresponds to `POST /v1/accounts`.
//
// **The caller has to hold a session, not an API token**, and the service answers
// 403 to one — this operation, `ListAccounts` and `AcceptInvitation` are the three
// on this surface that refuse a token, because each answers a question about the
// caller's whole set of accounts and a token is bound to one of them. A caller
// building an onboarding flow therefore needs a session for this step even when
// every step after it is done with a token.
//
// `body.Name` is the only field: the owner is the caller and the slug is derived,
// so there is nothing a caller can send that puts an account in somebody else's
// hands. A **409** means the derived slug is taken, and the detail says how it is
// derived, so pick another name rather than retrying with the same one.
func (c *Client) CreateAccount(ctx context.Context, body generated.CreateAccountJSONRequestBody) (*generated.Account, error) {
	var out generated.Account
	err := call(c, "createAccount", func() (*http.Response, error) {
		return c.transport.CreateAccount(ctx, body)
	}, &out)
	return &out, err
}

// ListAccounts lists the accounts the presented session's user belongs to.
// Corresponds to `GET /v1/accounts`.
//
// Session only, same as `CreateAccount`. Each entry's `Role` is the caller's role
// **in that account**, so one user is an owner of one row and a member of
// another; a client that renders one `role` for the whole page is reading a
// thing this service does not have. An account with none is an empty slice and
// not `null`.
func (c *Client) ListAccounts(ctx context.Context) ([]generated.AccountSummary, error) {
	var out []generated.AccountSummary
	err := call(c, "listAccounts", func() (*http.Response, error) {
		return c.transport.ListAccounts(ctx)
	}, &out)
	return out, err
}

// GetAccount reads one account and its members. Corresponds to
// `GET /v1/accounts/{account_id}`.
//
// `out.Role` is the CALLER's role in this account, and `out.Members` is the same
// array `ListMembers` returns — the document puts it on both so a client that
// already holds the account does not re-read it for a member panel.
//
// **A non-member gets 404, never 403**, and so does an account that does not
// exist: the two are deliberately the same answer, because a 403 would confirm
// that a guessed account id is real. A client that renders "forbidden" here has
// read a 404 as a 403.
func (c *Client) GetAccount(ctx context.Context, accountId openapiTypes.UUID) (*generated.Account, error) {
	var out generated.Account
	err := call(c, "getAccount", func() (*http.Response, error) {
		return c.transport.GetAccount(ctx, accountId)
	}, &out)
	return &out, err
}

// RenameAccount changes an account's name. Corresponds to
// `PATCH /v1/accounts/{account_id}`.
//
// **The returned `Slug` is the account's ORIGINAL handle and does not change.** A
// slug goes into logs, into invitation emails and into a future hostname, and one
// that moved on a rename would break every link already sent — so the response
// repeats the old value and a client must not derive an expected slug from the
// name it just sent. Admin only, and `accounts:write` for a token.
func (c *Client) RenameAccount(ctx context.Context, accountId openapiTypes.UUID, body generated.RenameAccountJSONRequestBody) (*generated.Account, error) {
	var out generated.Account
	err := call(c, "renameAccount", func() (*http.Response, error) {
		return c.transport.RenameAccount(ctx, accountId, body)
	}, &out)
	return &out, err
}

// DeleteAccount removes an account and everything scoped by it. Corresponds to
// `DELETE /v1/accounts/{account_id}`.
//
// **Irreversible, and it is the only operation on this surface that takes
// `accounts:delete`.** Owner only; a token holding `accounts:write` is refused.
// There is no `confirm` field on this route — the URL names the one thing being
// destroyed — so a caller that wants a confirmation dialog draws one itself
// rather than expecting the service to ask.
func (c *Client) DeleteAccount(ctx context.Context, accountId openapiTypes.UUID) error {
	return callVoid(ctx, c, "deleteAccount", func() (*http.Response, error) {
		return c.transport.DeleteAccount(ctx, accountId)
	})
}

// ListMembers lists an account's memberships. Corresponds to
// `GET /v1/accounts/{account_id}/members`.
//
// `out.Role` is the caller's own role, on the wrapper rather than inside the
// array, so a client rendering the panel knows what to offer without scanning the
// list for itself. Every entry names the `user_id` that `ChangeMemberRole` and
// `RemoveMember` need — an entry without one is a membership nothing can be acted
// on, and this client does not paper over that by inventing an id.
func (c *Client) ListMembers(ctx context.Context, accountId openapiTypes.UUID) (*generated.MemberList, error) {
	var out generated.MemberList
	err := call(c, "listMembers", func() (*http.Response, error) {
		return c.transport.ListMembers(ctx, accountId)
	}, &out)
	return &out, err
}

// InviteMember creates a pending membership. Corresponds to
// `POST /v1/accounts/{account_id}/invitations`.
//
// **`out.Token` is the only copy of the redemption token that will ever exist.** It
// is not stored, only a SHA-256 of it is, and no operation re-reads one — so a
// caller that drops it invites again rather than looking for a way to fetch it.
// The generated `IssuedInvitation` carries `Token` and has no redacting
// `String()`, so this is a value that must not be logged; see
// `TestTheGeneratedSecretBearingTypesAreSafeToPrint`.
//
// **Nothing is mailed.** Until invitation mail is handed to the courier service,
// this token IS the delivery mechanism and a caller that sends it itself owns the
// whole invitation. `role` is `member` or `admin`: `owner` is a 422, and so is an
// admin inviting an `admin`.
func (c *Client) InviteMember(ctx context.Context, accountId openapiTypes.UUID, body generated.InviteMemberJSONRequestBody) (*generated.IssuedInvitation, error) {
	var out generated.IssuedInvitation
	err := call(c, "inviteMember", func() (*http.Response, error) {
		return c.transport.InviteMember(ctx, accountId, body)
	}, &out)
	return &out, err
}

// ChangeMemberRole moves one membership to a new role. Corresponds to
// `PATCH /v1/accounts/{account_id}/members/{user_id}`.
//
// **Owner only** — an admin and a member never reach it. The 422s here are about
// the target rather than the caller, and a caller must not read one as "your role
// is too low": `last_owner` means the change would leave the account with no
// owner, or that the caller is the only owner demoting themselves, and both are
// answered by granting a second owner rather than by retrying.
//
// Removing somebody is `RemoveMember`, not a change to a lower role: a membership
// that should not exist should be deleted, so that withdrawing the credentials the
// person held is part of the same request.
func (c *Client) ChangeMemberRole(ctx context.Context, accountId, userId openapiTypes.UUID, body generated.ChangeMemberRoleJSONRequestBody) (*generated.Membership, error) {
	var out generated.Membership
	err := call(c, "changeMemberRole", func() (*http.Response, error) {
		return c.transport.ChangeMemberRole(ctx, accountId, userId, body)
	}, &out)
	return &out, err
}

// RemoveMember deletes one membership. Corresponds to
// `DELETE /v1/accounts/{account_id}/members/{user_id}`.
//
// **It also stops the credentials that membership justified**, on the removed
// user's next request, and a re-invitation does not bring them back. An OIDC
// access token is the exception: a JWT is verifiable until its `exp`, so one this
// user obtained through a product keeps working for what is left of its lifetime
// and nothing here revokes it.
//
// A 204, so this returns no body. A 422 is `last_owner`; a 403 is an admin
// reaching for an owner's membership.
func (c *Client) RemoveMember(ctx context.Context, accountId, userId openapiTypes.UUID) error {
	return callVoid(ctx, c, "removeMember", func() (*http.Response, error) {
		return c.transport.RemoveMember(ctx, accountId, userId)
	})
}

// AcceptInvitation redeems an invitation token. Corresponds to
// `POST /v1/invitations/accept`.
//
// **The caller must already hold a session**, and this client does not mint one:
// the membership belongs to the caller, so an anonymous redemption would create a
// membership for nobody, and the route answers 401 rather than signing anybody in.
// Sign in, then redeem.
//
// The token is a credential for as long as it is live. The generated
// `AcceptInvitationRequest` has no redacting `String()`, so a caller printing
// `body` whole prints a value that is dead the moment this returns — and a 410
// means it is already dead, where asking for a new invitation is the only next
// step. A 404 is one answer for every token that is not live, and a caller must
// not attempt to tell a wrong one from an expired one.
func (c *Client) AcceptInvitation(ctx context.Context, body generated.AcceptInvitationJSONRequestBody) (*generated.Membership, error) {
	var out generated.Membership
	err := call(c, "acceptInvitation", func() (*http.Response, error) {
		return c.transport.AcceptInvitation(ctx, body)
	}, &out)
	return &out, err
}

// RegisterOIDCClient registers a relying party. Corresponds to
// `POST /v1/accounts/{account_id}/oidc-clients`.
//
// The response carries `client_secret` once and unrecoverably. The generated type
// has no redacting `String()`, so `TestTheGeneratedSecretBearingTypesAreSafeToPrint`
// is what stops a caller logging this value whole.
func (c *Client) RegisterOIDCClient(ctx context.Context, accountId openapiTypes.UUID, body generated.RegisterOIDCClientRequest) (*generated.RegisteredOIDCClient, error) {
	var out generated.RegisteredOIDCClient
	err := call(c, "registerOIDCClient", func() (*http.Response, error) {
		return c.transport.RegisterOIDCClient(ctx, accountId, body)
	}, &out)
	return &out, err
}

// ListOIDCClients lists an account's registrations. Corresponds to
// `GET /v1/accounts/{account_id}/oidc-clients`.
func (c *Client) ListOIDCClients(ctx context.Context, accountId openapiTypes.UUID) ([]generated.OIDCClient, error) {
	var out []generated.OIDCClient
	err := call(c, "listOIDCClients", func() (*http.Response, error) {
		return c.transport.ListOIDCClients(ctx, accountId)
	}, &out)
	return out, err
}

// GetOIDCClient reads one registration. Corresponds to
// `GET /v1/accounts/{account_id}/oidc-clients/{client_id}`.
func (c *Client) GetOIDCClient(ctx context.Context, accountId, clientId openapiTypes.UUID) (*generated.OIDCClient, error) {
	var out generated.OIDCClient
	err := call(c, "getOIDCClient", func() (*http.Response, error) {
		return c.transport.GetOIDCClient(ctx, accountId, clientId)
	}, &out)
	return &out, err
}

// RevokeOIDCClient revokes a registration. Corresponds to
// `DELETE /v1/accounts/{account_id}/oidc-clients/{client_id}`.
func (c *Client) RevokeOIDCClient(ctx context.Context, accountId, clientId openapiTypes.UUID) error {
	return callVoid(ctx, c, "revokeOIDCClient", func() (*http.Response, error) {
		return c.transport.RevokeOIDCClient(ctx, accountId, clientId)
	})
}

// MintAPIKey mints a scoped API token. Corresponds to
// `POST /v1/accounts/{account_id}/api-keys`.
//
// **The response is the only place the plaintext token will ever exist.** It is not
// stored, only a SHA-256 of it is, and there is no endpoint that re-reads one — so a
// caller who loses this value mints another. The document makes the same point about
// the `cafaye_` prefix being a feature: a secret that reaches a CI log is recognised
// as a cafaye credential by its first seven characters.
//
// The generated `IssuedAPIKey` carries `Token` and has no redacting `String()`, so
// this is the single most loggable value in the package. See
// `TestTheGeneratedSecretBearingTypesAreSafeToPrint`.
func (c *Client) MintAPIKey(ctx context.Context, accountId openapiTypes.UUID, body generated.MintAPIKeyRequest) (*generated.IssuedAPIKey, error) {
	var out generated.IssuedAPIKey
	err := call(c, "mintAPIKey", func() (*http.Response, error) {
		return c.transport.MintAPIKey(ctx, accountId, body)
	}, &out)
	return &out, err
}

// ListAPIKeys lists an account's tokens. Corresponds to
// `GET /v1/accounts/{account_id}/api-keys`.
//
// Returns `[]generated.APIKey`, which is the type with NO `token` field — the
// document nests `IssuedAPIKey` around it for exactly this reason, so a list handler
// cannot reach a secret even by accident. That the type system enforces it is worth
// one comment, because it is the strongest guarantee in this document.
func (c *Client) ListAPIKeys(ctx context.Context, accountId openapiTypes.UUID) ([]generated.APIKey, error) {
	var out []generated.APIKey
	err := call(c, "listAPIKeys", func() (*http.Response, error) {
		return c.transport.ListAPIKeys(ctx, accountId)
	}, &out)
	return out, err
}

// RevokeAPIKey revokes a token. Corresponds to
// `DELETE /v1/accounts/{account_id}/api-keys/{key_id}`.
//
// The body is optional in the strongest sense — a DELETE with no body is a revoke —
// so this takes no body. A caller that wants to record a reason marshals the request
// through `Transport`, which is the documented cost of that hatch.
func (c *Client) RevokeAPIKey(ctx context.Context, accountId, keyId openapiTypes.UUID) error {
	return callVoid(ctx, c, "revokeAPIKey", func() (*http.Response, error) {
		// The zero body, which marshals to `{}`. The document is explicit that a
		// DELETE with no body at all is a revoke — "refusing it for want of a JSON
		// document would be a 400 on a DELETE that needs nothing else" — and
		// `RevokeAPIKeyRequest` has exactly one optional field, so an empty object
		// is indistinguishable from no reason having been given.
		return c.transport.RevokeAPIKey(ctx, accountId, keyId, generated.RevokeAPIKeyJSONRequestBody{})
	})
}

// IntrospectAPIKey resolves a presented API token to its claims. Corresponds to
// `POST /v1/introspections`.
//
// The body carries the CREDENTIAL, not an id — an id would be an enumeration oracle
// over somebody else's credentials. So this method's argument is a secret, it is
// never redacted on its way out, and it must never be logged by a caller. The
// response for a token that cannot be used is `{"active": false}` and nothing else,
// which `IntrospectionResponse.Active` reports without the caller having to
// distinguish four different refusals.
func (c *Client) IntrospectAPIKey(ctx context.Context, body generated.IntrospectRequest) (*generated.IntrospectionResponse, error) {
	var out generated.IntrospectionResponse
	err := call(c, "introspectAPIKey", func() (*http.Response, error) {
		return c.transport.IntrospectAPIKey(ctx, body)
	}, &out)
	return &out, err
}

// ListAccountAuditLog reads one page of an account's admin audit trail. Corresponds to
// `GET /v1/accounts/{account_id}/admin/audit-log`.
//
// The trail is append-only in the DATABASE, so this is a read of a record nothing can
// edit — which is the reason an audit log is worth keeping and the reason a caller
// cannot ask for a correction. `Next` is an opaque cursor to pass back as `Before`;
// empty means the page is the last one.
func (c *Client) ListAccountAuditLog(ctx context.Context, accountId openapiTypes.UUID, params *generated.ListAccountAuditLogParams) (*generated.AuditLogPage, error) {
	var out generated.AuditLogPage
	err := call(c, "listAccountAuditLog", func() (*http.Response, error) {
		return c.transport.ListAccountAuditLog(ctx, accountId, params)
	}, &out)
	return &out, err
}

// RevokeAccountInvitation withdraws one pending invitation. Corresponds to
// `DELETE /v1/accounts/{account_id}/admin/invitations/{invitation_id}`.
//
// A 204, so this returns no body: the invitation's address is freed to be invited
// again, and the audit record naming the credential that did it exists in the same
// transaction. An invitation that was already revoked, already accepted, or belongs
// to another account is a 404 — this operation cannot report on somebody else's row.
func (c *Client) RevokeAccountInvitation(ctx context.Context, accountId, invitationId openapiTypes.UUID) error {
	return callVoid(ctx, c, "revokeAccountInvitation", func() (*http.Response, error) {
		return c.transport.RevokeAccountInvitation(ctx, accountId, invitationId)
	})
}

// RevokeAccountInvitations withdraws up to 50 pending invitations in one transaction.
// Corresponds to `POST /v1/accounts/{account_id}/admin/invitation-revocations`.
//
// **The two counts in the result differ, and both are returned.** `Requested` is how
// many ids the body named after de-duplication; `Revoked` is how many rows the
// database actually changed. Ids that were already revoked, already accepted, or
// belong to another account are not an error — they change nothing and are not
// counted — so a caller that reports `Requested` as done has reported a lie.
func (c *Client) RevokeAccountInvitations(ctx context.Context, accountId openapiTypes.UUID, body generated.BulkInvitationRevocation) (*generated.BulkRevocationResult, error) {
	var out generated.BulkRevocationResult
	err := call(c, "revokeAccountInvitations", func() (*http.Response, error) {
		return c.transport.RevokeAccountInvitations(ctx, accountId, body)
	}, &out)
	return &out, err
}

// itoa avoids importing strconv for one call in a message string.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
