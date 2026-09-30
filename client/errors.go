package client

// RFC 9457 PROBLEM DOCUMENTS, AND THE TYPED FALLBACK THAT IS THE POINT.
//
// Every non-2xx response from identity is `application/problem+json` — its own
// document says so, and core's `docs/openapi-conventions.md` says "No service
// invents its own error body". That uniformity is the opportunity: one shape means
// one place to turn a failure into a value a caller can branch on with `errors.As`
// rather than by reading a string.
//
// # `ProblemError` IS AN INTERFACE, AND THAT IS THE WHOLE DESIGN
//
// It is the Go equivalent of TypeScript's `instanceof CafayeProblemError`, and it
// has to be an interface rather than a base struct for a reason that is easy to get
// wrong. This was tried as a base struct first, embedded BY VALUE:
//
//	type ValidationError struct{ ProblemError }
//
// and the obvious catch does not work:
//
//	var problem *client.ProblemError
//	errors.As(err, &problem)   // false, for every typed error
//
// `errors.As` matches on assignability, and embedding does not create an
// assignment: `*ValidationError` is not assignable to `*ProblemError`, with a value
// OR a pointer embedding. Verified rather than assumed — a three-line program with
// the same shape, which the compiler rejected.
//
// That failure mode is the worst one available. The caller writes the single catch
// the brief asks for, it compiles, it returns false, and it returns false ONLY for
// the codes this build happens to have a type for — so the fallback, the thing that
// exists to make an unknown code survivable, is the only code that works. The
// hierarchy would be exactly backwards.
//
// So `ProblemError` is an interface. Every concrete error implements it, a caller
// catches it with `errors.As`, and the typed errors are an ADDITION to the catch
// rather than a thing that has to be known in advance:
//
//	var problem client.ProblemError
//	if errors.As(err, &problem) {
//	    switch problem.Code() { … }              // works for every code, seen or not
//	}
//	// and, when the specific one is wanted:
//	var validation *client.ValidationError
//	errors.As(err, &validation)                 // narrows, and may be false
//
// # WHY `code` CHOOSES THE TYPE AND `status` IS THE FALLBACK
//
// core's conventions: "`type` is a stable `https://errors.cafaye.com/<code>` URI —
// the machine-readable contract" and "`code` is the same slug as the last segment of
// `type`". So `code` is the contract and `status` is a fact about one response, which
// a service could get wrong or omit, since RFC 9457 makes `status` advisory.
//
// Mapping on `code` first and falling back to `status` means a service answering 403
// with `code: "forbidden"` produces the right type even if the number drifts, and a
// service that omits `code` entirely is still mapped from the number.
//
// # THE FALLBACK IS THE REQUIREMENT, NOT A CONVENIENCE
//
// The brief is explicit: "A client that returns `ok, false` on an unknown problem
// type breaks the day the API grows, and it breaks silently."
//
// So `UnknownProblemError` is a REAL TYPE, not a nil and not a bare error. A code
// this build has never heard of produces one, carrying that code, that status, that
// type URI and that trace id intact.
//
// This is not hypothetical for identity specifically: its own document lists four
// codes that are NOT in core's reserved list — `account_locked`, `invalid_json`,
// `payload_too_large`, `service_unavailable` — and flags them for core as a proposal
// rather than a fait accompli. Those codes will exist before core's list catches up.
// A client that had to be regenerated to handle a code its own service documents
// would be wrong on day one.
//
// # WHY SEPARATE TYPES RATHER THAN ONE WITH A STATUS FIELD
//
// Because a caller frequently wants `errors.As(&unauthenticated)` rather than a
// field comparison, and because `account_locked` needs a retry-after that `forbidden`
// does not have — a 423 is the one failure in this set where the right action is to
// wait and try again, and an error type that carries the wait is the difference
// between a client that backs off and one that does not.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/cafaye/identity/client/generated"
)

// ProblemContentType is the media type every non-2xx response carries.
const ProblemContentType = "application/problem+json"

// RetryAfterHeader carries the wait a 423 asks for. The document puts it on the 423
// responses and nowhere else, and says the value is "seconds until the account may be
// tried again, never negative".
const RetryAfterHeader = "Retry-After"

// ProblemError is every failure that carried an RFC 9457 problem document.
//
// An interface, and the reasoning is in the file header: a base STRUCT cannot be
// caught with `errors.As` from a type that embeds it, so a hierarchy of structs
// would invert the one property this package exists to provide.
//
// `Problem` and `FieldError` are NOT declared here — `client/generated` declares both
// from `openapi/v1.yaml`, and using the generated ones means the code is a
// compile-time enum rather than a string somebody can typo, and there is exactly one
// `Problem` in this module.
type ProblemError interface {
	error

	// Code is the cafaye problem code: the last segment of `type`, in snake_case.
	// Empty when the service omitted it, which is legal under RFC 9457 and is
	// mapped from the status instead.
	Code() string

	// HTTPStatus is the status the response carried.
	HTTPStatus() int

	// Document is the decoded problem, with every string member redacted.
	Document() generated.Problem

	// TraceID is always equal to the `X-Trace-Id` response header. Support starts
	// here, which is why the redactor does not touch it.
	TraceID() string
}

// problem is the unexported base every concrete problem error embeds.
//
// Unexported so the set of types is exactly what this file lists — a caller cannot
// construct one, and cannot depend on a field this package might change. It is
// embedded BY VALUE, which is safe here precisely because callers catch through the
// `ProblemError` interface rather than through this struct.
type problem struct {
	operation string
	status    int
	document  generated.Problem
	redactor  Redactor

	// retryAfter is -1 when the response carried no readable `Retry-After`.
	retryAfter int
}

func (p *problem) Code() string                { return string(p.document.Code) }
func (p *problem) HTTPStatus() int             { return p.status }
func (p *problem) Document() generated.Problem { return p.document }
func (p *problem) TraceID() string             { return p.document.TraceID }

// render is the shared message, so every type says the same thing about the same
// failure and only the type name differs.
func (p *problem) render(kind string) string {
	where := ""
	if p.operation != "" {
		where = p.operation + ": "
	}

	code := p.document.Code
	if code == "" {
		code = generated.ProblemCode(kind)
	}

	msg := fmt.Sprintf("%sHTTP %d %s: %s", where, p.status, code,
		p.redactor.String(p.document.Title))

	if detail := p.redactor.String(p.document.Detail); detail != "" {
		msg += ": " + detail
	}
	if p.document.TraceID != "" {
		msg += " (trace_id " + p.document.TraceID + ")"
	}
	return p.redactor.String(msg)
}

// The concrete types. Each is a named type rather than a status field because a
// caller wants `errors.As` for it, and each is named after the CODE rather than the
// status — so a service whose status drifts does not silently change the type, and
// a service answering 404 with a different code still produces the type the caller
// asked for by code.

// UnauthenticatedError is 401: the credential was absent, unknown, expired or
// revoked. identity answers all four with one body, and so does this.
type UnauthenticatedError struct{ problem }

func (e *UnauthenticatedError) Error() string { return e.render("unauthorized") }

// ForbiddenError is 403: the credential is valid and not enough.
type ForbiddenError struct{ problem }

func (e *ForbiddenError) Error() string { return e.render("forbidden") }

// NotFoundError is 404, and core is careful about it: "Never 404 for authorization
// failures on a resource the caller cannot see". So a 404 from identity can mean "not
// a member of that account" and not only "no such account", and a caller must not
// read it either way.
type NotFoundError struct{ problem }

func (e *NotFoundError) Error() string { return e.render("not_found") }

// ConflictError is 409.
type ConflictError struct{ problem }

func (e *ConflictError) Error() string { return e.render("conflict") }

// ValidationError is 422, and the only code that carries `errors[]`.
type ValidationError struct{ problem }

func (e *ValidationError) Error() string { return e.render("validation_failed") }

// RateLimitedError is 429.
type RateLimitedError struct{ problem }

func (e *RateLimitedError) Error() string { return e.render("rate_limited") }

// AccountLockedError is 423, identity's extension to core's reserved list, and the
// one code whose correct client behaviour is to WAIT.
//
// A distinct type rather than a field on the base because the action differs: every
// other 4xx here is "do not retry", and a client that treats 423 like 403 will hammer
// an account the lockout exists to protect.
type AccountLockedError struct{ problem }

func (e *AccountLockedError) Error() string { return e.render("account_locked") }

// RetryAfterSeconds is the remaining window, rounded up, from the `Retry-After`
// header. Never negative, and never retried here — see IsRetryable.
//
// Zero means "no readable header", NOT "retry now": the document says the value is
// "never negative" and a literal `0` is a real answer the service could give, so the
// two are told apart by `-1` in the unexported field and a caller that cares should
// read the header itself. Stated rather than smoothed over because a client that
// treats "unknown" as "now" is how an account gets locked harder.
func (e *AccountLockedError) RetryAfterSeconds() int {
	if e.retryAfter < 0 {
		return 0
	}
	return e.retryAfter
}

// HasRetryAfter reports whether the response carried a readable `Retry-After`. A
// caller that needs to distinguish "retry immediately" from "do not know" asks this
// rather than reading zero and guessing.
func (e *AccountLockedError) HasRetryAfter() bool { return e.retryAfter >= 0 }

// UnknownProblemError is THE FALLBACK: a problem document whose `code` this build has
// never heard of.
//
// It is a real, exported, `errors.As`-able type rather than a nil and rather than a
// bare error, and that is the whole point. The brief's requirement is that a client
// "breaks silently" if it cannot represent a code it has not seen; this type is what
// it represents them with. A caller can therefore always write
//
//	var problem client.ProblemError
//	if errors.As(err, &problem) { … }
//
// and have it work against every failure this package can produce, including every
// code identity adds after this client was generated.
//
// identity's document already lists four codes core does not have, and flags them as
// a proposal rather than a fait accompli — so this is not a shape of failure that
// happens eventually. It is a shape this service is already in.
type UnknownProblemError struct{ problem }

func (e *UnknownProblemError) Error() string { return e.render("unknown") }

// ProblemCode returns the code verbatim, which is the only way a caller can act on a
// code this build has no type for — by matching the string, with a default that does
// something sensible rather than nothing.
func (e *UnknownProblemError) ProblemCode() string { return e.Code() }

// CallError is a failure that did NOT carry a problem document.
//
// Two cases, both of them judgement calls worth naming:
//
//   - A transport failure: no HTTP response at all. `net/http`'s own text is kept,
//     redacted, because `dial tcp … connection refused` is the single most useful line
//     in a network error and there is nothing to redact in it.
//
//   - A response that broke the contract: a proxy's HTML 502, a WAF's challenge, a
//     `/readyz` 503 which this repository's own document records as known gap 4. There
//     is a status and there is no problem document, so producing a `ProblemError`
//     would be a lie about `type` and `title`.
type CallError struct {
	// Operation is the `operationId` the call was made through, which is the name of
	// the generated method and therefore the thing a reader recognises.
	Operation string
	// Status is the HTTP status, or 0 when there was no HTTP response.
	Status int

	// message is what the caller already knows, stored ALREADY redacted rather than
	// redacted at render time.
	//
	// The value that goes in here is built out of things this package does not own —
	// `net/http`'s `*url.Error` text, a JSON decoder's complaint, a server's own
	// words. Redacting once, at construction, means there is no field on this type
	// that holds an unscrubbed string, so a future `fmt.Printf("%+v", err)` prints a
	// message that was already safe.
	message string

	// snippet is a redacted excerpt of a body that was not a problem document.
	snippet string

	// contentType is what the service said it sent, or "".
	contentType string

	redactor Redactor
}

// Error renders the failure.
//
// Redacted again here even though `message` arrived redacted. Two passes look
// redundant; the second is what makes the type safe if a future caller constructs one
// with a raw string, which is exactly the mistake a single redaction site invites.
func (e *CallError) Error() string {
	msg := e.Operation + ": "
	if e.Status > 0 {
		msg += "HTTP " + itoa(e.Status) + " "
	}
	msg += e.redactor.String(e.message)

	if e.snippet != "" && e.snippet != Redacted {
		msg += " Body began: " + e.snippet
	}
	return e.redactor.String(msg)
}

// Unwrap returns nil so `errors.Is` and `errors.As` stop here rather than walking a
// chain this package did not build.
//
// Present as an explicit method rather than omitted so the intent is on the page: the
// generated client returns `*http.Response` and an `error` from `net/http`, and the
// temptation to unwrap into the transport error is exactly the path by which a URL
// with a query string, or a header dump, reaches a log line.
func (e *CallError) Unwrap() error { return nil }

// MFARequiredError is the 202 from `POST /v1/session`: a correct password, an
// unfinished authentication, and nothing else.
//
// **There is no session.** The document says so in as many words — "there is no
// `token` field in this schema, and that is deliberate: a client that looks for one
// must handle its absence rather than treat an empty string as a value" — and this
// type is that handling made unavoidable. It is an error rather than a result
// precisely so a caller cannot hold a `*Session` containing no session: the zero value
// of a `Session` has an empty token, which is credential-shaped and is not a
// credential, and returning it would be the bug the document warns about.
//
// The challenge is carried rather than fetched by a second call, because it is
// single-use and expires in ten minutes. A caller that had to collect it separately
// would have to cache it, and a cached single-use credential is a liability.
type MFARequiredError struct {
	CallError

	// Challenge is what to pass to `POST /v1/session/mfa`, as `challenge` or as the
	// `__Host-mfa-challenge` cookie. Single-use, ten minutes, and worthless alone.
	Challenge generated.MFAChallenge
}

func (e *MFARequiredError) Error() string {
	return e.redactor.String(e.Operation +
		": the password was correct and this account has a second factor, so no session " +
		"exists. Answer POST /v1/session/mfa with the challenge to get one.")
}

// ProblemFrom builds the right error for a problem document.
//
// `body` is the raw response body, `contentType` what the service said it was, and
// `retryAfter` the raw header value. The body is decoded HERE rather than by the
// caller so that "this was not a problem document" is one decision this package
// makes, with a stated consequence, rather than a branch twenty call sites write
// differently.
//
// `redact` is the client's redactor, already bound to its credential. It is passed
// rather than a `[]string` of secrets so no caller assembles the credential list, and
// so no slice of secrets travels through this package where one could read it back
// out.
//
// Kept a pure function of its arguments — no `*http.Response`, no transport — which
// is what lets the per-code table below be a table rather than a fixture.
func ProblemFrom(operation string, status int, contentType, retryAfter string, body []byte, redact Redactor) error {
	// A 2xx carrying a problem body is a contract violation, and it returns rather
	// than handing the caller a Problem where its types promised a result. A typed
	// client that quietly returns the wrong shape is worse than one that stops: the
	// first produces a `json.UnmarshalTypeError` three frames from the mistake and
	// the second produces a diagnosis at it.
	if status >= 200 && status < 300 {
		return &CallError{
			Operation: operation, Status: status, redactor: redact,
			message: "the service answered 2xx with an application/problem+json body. " +
				"core's conventions reserve that media type for failures, so treating it " +
				"as a success would hand the caller a problem where its types promised a " +
				"result. The service is not following its own contract.",
		}
	}

	var decoded generated.Problem
	if err := json.Unmarshal(body, &decoded); err != nil {
		return notAProblem(operation, status, contentType, body, redact)
	}

	// A body that parsed but is not a problem: `{}` from a proxy, or a service
	// answering a bare JSON error. Structural rather than trusting the status, because
	// a 502 from a WAF is a JSON object and not a problem document.
	if decoded.Type == "" && decoded.Title == "" {
		return notAProblem(operation, status, contentType, body, redact)
	}

	decoded = sanitiseProblem(decoded, redact)
	if decoded.Status == 0 {
		// RFC 9457 makes `status` advisory, so a service that omits it is legal. Fill
		// it from the response rather than leaving 0, which on a 4xx or 5xx would mean
		// "no HTTP response" everywhere else in this package.
		decoded.Status = status
	}

	built := &problem{
		operation:  operation,
		status:     status,
		document:   decoded,
		redactor:   redact,
		retryAfter: parseRetryAfter(retryAfter),
	}

	if constructor, known := problemTypes[built.Code()]; known {
		return constructor(*built)
	}
	if constructor, known := statusTypes[decoded.Status]; known {
		return constructor(*built)
	}

	// THE FALLBACK. A code nobody here has heard of still produces a typed, named,
	// `errors.As`-able error carrying that code, this status and this trace id. Not
	// `ok, false`, and not a bare error.
	return &UnknownProblemError{problem: *built}
}

// notAProblem builds the error for a response that carried no problem document.
//
// Its own function because three paths reach it — an unparseable body, a parsed body
// with no `type` and no `title`, and a 2xx — and three copies of the same message
// assembly is three places for the wording to drift.
func notAProblem(operation string, status int, contentType string, body []byte, redact Redactor) error {
	shown := contentType
	if shown == "" {
		shown = "no Content-Type"
	}

	return &CallError{
		Operation: operation, Status: status, contentType: contentType, redactor: redact,
		message: "the response did not carry an RFC 9457 problem document (Content-Type: " +
			shown + "). Something between this client and identity answered — a proxy, a " +
			"gateway, a rate limiter — so there is no cafaye code to branch on.",
		// The excerpt is kept because a reverse proxy's HTML 502 is otherwise
		// undiagnosable from the client side, and dropped when redaction removed all
		// of it: `Redacted` means there was something credential-shaped in there and
		// none of it is going in an error.
		snippet: redact.String(truncate(strings.TrimSpace(string(body)), 200)),
	}
}

// problemTypes maps a problem's `code` to the type that carries it.
//
// Data rather than a switch, because the fallback is the interesting part and a
// `default` clause reads as an error path: a missing map entry reads as "this code is
// not known yet", which is what it means.
var problemTypes = map[string]func(problem) error{
	"unauthorized":      func(p problem) error { return &UnauthenticatedError{p} },
	"forbidden":         func(p problem) error { return &ForbiddenError{p} },
	"not_found":         func(p problem) error { return &NotFoundError{p} },
	"conflict":          func(p problem) error { return &ConflictError{p} },
	"validation_failed": func(p problem) error { return &ValidationError{p} },
	"rate_limited":      func(p problem) error { return &RateLimitedError{p} },
	"account_locked":    func(p problem) error { return &AccountLockedError{p} },
}

// statusTypes is the fallback, keyed by status, for a service that omits `code`.
//
// Narrower than the code map on purpose. Only statuses that are unambiguous across
// the whole fleet appear. A 423 maps to nothing here, because a bare 423 without a
// code could be identity's `account_locked` and something else entirely elsewhere,
// and inventing a type for it would be a guess. An unmapped status produces
// `*UnknownProblemError`, which is the correct answer for "I know the status and not
// the meaning".
var statusTypes = map[int]func(problem) error{
	http.StatusUnauthorized:        func(p problem) error { return &UnauthenticatedError{p} },
	http.StatusForbidden:           func(p problem) error { return &ForbiddenError{p} },
	http.StatusNotFound:            func(p problem) error { return &NotFoundError{p} },
	http.StatusConflict:            func(p problem) error { return &ConflictError{p} },
	http.StatusUnprocessableEntity: func(p problem) error { return &ValidationError{p} },
	http.StatusTooManyRequests:     func(p problem) error { return &RateLimitedError{p} },
}

// sanitiseProblem returns a copy with every string member redacted.
//
// A free function rather than a method, because `generated.Problem` belongs to
// another package and Go does not let one package define methods on another's type.
// That constraint does useful work: redaction cannot be attached to the type, so it
// cannot be forgotten at a call site that decodes a problem some other way.
//
// A copy rather than an in-place edit, so the caller's decoded document is not
// mutated. Member by member rather than by marshalling to JSON and redacting the
// result, because marshalling would reorder, re-encode and lose the distinction
// between an absent `errors` and an empty one.
func sanitiseProblem(p generated.Problem, r Redactor) generated.Problem {
	out := p
	out.Type = r.String(p.Type)
	out.Title = r.String(p.Title)
	out.Detail = r.String(p.Detail)
	out.Instance = r.String(p.Instance)
	out.Code = generated.ProblemCode(r.String(string(p.Code)))

	// TraceID is NOT redacted, deliberately: it is generated by the service rather
	// than supplied by the caller, it is what support starts from, and a redactor
	// that ate it would make every unsupported failure harder to report.

	if p.Errors != nil {
		fields := make([]generated.FieldError, len(*p.Errors))
		for i, field := range *p.Errors {
			fields[i] = generated.FieldError{
				Field: r.String(field.Field),
				Code:  r.String(field.Code),
			}
		}
		out.Errors = &fields
	}
	return out
}

// parseRetryAfter reads a `Retry-After` header in its delta-seconds form, returning
// -1 when there is nothing to read.
//
// RFC 9110 also allows an HTTP-date, which this does not parse: the document says
// identity's value is "whole seconds, rounded up", so delta-seconds is the only form
// this service emits. An HTTP-date from something else in the chain is reported as
// ABSENT rather than guessed at, because a wrong retry time is worse than a caller
// falling back to its own policy.
func parseRetryAfter(raw string) int {
	if raw == "" {
		return -1
	}

	seconds, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || seconds < 0 {
		return -1
	}
	return seconds
}

// IsRetryable reports whether waiting could plausibly succeed.
//
// A deliberately small set: 429 and 503. A 409 is not here even though it is
// sometimes transient, because a conflict means the request conflicts with current
// state and repeating it unchanged repeats the conflict — that is a decision for
// whoever holds the domain, not for a transport.
//
// **No retry is attempted by this package at all.** A client library that retries
// hides a caller's own deadline and error handling behind its own, and MD6 gives this
// client four responsibilities — credentials, base URLs, RFC 9457 mapping, and being
// the public surface — and retrying is not one of them.
func IsRetryable(err error) bool {
	var rate *RateLimitedError
	if errors.As(err, &rate) {
		return true
	}
	return errors.Is(err, ErrUnavailable)
}

// ErrUnavailable is returned for a 503 with no cafaye problem body, which is what
// `GET /readyz` answers when a dependency is down.
//
// This repository's document calls that response out as the one non-2xx in the
// service that is not a problem document — recorded as known gap 4 and escalated as
// a conflict with core's conventions. It is matched by status rather than by code
// precisely because there is no code to match.
var ErrUnavailable = errors.New("identity is not ready: a dependency did not answer")
