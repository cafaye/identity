package httpapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
)

// errorTypeBase is the stable URI prefix for the `type` attribute. core:
// "type is a stable https://errors.cafaye.com/<code> URI — the machine-readable
// contract". Changing this is a breaking change to every client.
const errorTypeBase = "https://errors.cafaye.com/"

// Problem codes.
//
// The first group is core's reserved list verbatim (docs/openapi-conventions.md).
// The second group is this service's extension to it, and every code in it is a
// case core does not currently describe:
//
//	account_locked      423  a login refused by the brute-force lockout
//	invalid_json        400  a body that is not JSON at all
//	payload_too_large   413  a body past the accepted size
//	invalid_request     400  a request this service understood and named a
//	                       specific problem with, on a surface it owns
//	not_a_member        404  covered by not_found; the sentence carries the reason
//
// They are listed together in openapi/v1.yaml and flagged there for the
// manager: core owns the set, and a service that quietly invents codes is the
// drift the document exists to prevent. A 423 is required by the lockout the
// packet specifies, and the other two are the honest answers for a malformed or
// oversized request — folding them into validation_failed would have reported a
// syntactically broken body as a semantic failure.
const (
	CodeUnauthorized     = "unauthorized"
	CodeForbidden        = "forbidden"
	CodeValidationFailed = "validation_failed"
	CodeConflict         = "conflict"
	CodeNotFound         = "not_found"
	CodeInternal         = "internal"

	// CodeGone is core's own name for 410, from its deprecation section: "the old
	// surface returns 410 gone with a Link to its replacement". An expired or
	// already-redeemed invitation is the same shape of answer — the thing is
	// permanently not redeemable and there is a next step — so it reuses the
	// reserved code rather than inventing one.
	CodeGone = "gone"

	CodeAccountLocked    = "account_locked"
	CodeMethodNotAllowed = "method_not_allowed"
	CodeInvalidJSON      = "invalid_json"
	CodePayloadTooLarge  = "payload_too_large"

	// CodeInvalidRequest is 400 for a request this service understood well enough
	// to name a specific problem with, on a surface it owns. It is the OAuth 2.0
	// error name for the same class of thing, which is deliberate: the one place
	// this service answers with the cafaye envelope for an OAuth-shaped refusal is
	// the /oidc/authorize pre-check, and a client debugging it will search for
	// `invalid_request` in the specifications.
	CodeInvalidRequest = "invalid_request"
)

// titles is the fixed human-readable summary per code. core: "title is a fixed,
// human-readable summary for that code; it may be reworded without a version
// bump" — which is precisely why it is a constant here and never assembled from
// the occurrence's detail.
var titles = map[string]string{
	CodeUnauthorized:     "Unauthorized",
	CodeForbidden:        "Forbidden",
	CodeValidationFailed: "Validation failed",
	CodeConflict:         "Conflict",
	CodeNotFound:         "Not found",
	CodeInternal:         "Internal server error",
	CodeGone:             "Gone",

	CodeAccountLocked:    "Account locked",
	CodeMethodNotAllowed: "Method not allowed",
	CodeInvalidJSON:      "Malformed request body",
	CodePayloadTooLarge:  "Request body too large",
	CodeInvalidRequest:   "Invalid request",
}

func titleFor(code string) string {
	if title, ok := titles[code]; ok {
		return title
	}
	// An unrecognised code still has to render a document a client will accept,
	// so it falls back to the most generic summary there is rather than to "".
	return "Request failed"
}

// FieldError is one entry of a problem's `errors[]`, present only on a 422.
//
// It has exactly the two fields core's example shows. A `message` is tempting and
// wrong: it duplicates `detail` per field, it is not in the contract, and clients
// that render it end up showing an untranslated server string to a user.
type FieldError struct {
	Field string `json:"field"`
	Code  string `json:"code"`
}

// Problem is the cafaye error envelope: RFC 9457 (application/problem+json) plus
// core's `code` and `trace_id` extensions.
//
// core sets no additionalProperties rule on the error body, so the seven fields
// below are the whole document.
type Problem struct {
	Type     string       `json:"type"`
	Title    string       `json:"title"`
	Status   int          `json:"status"`
	Detail   string       `json:"detail"`
	Instance string       `json:"instance"`
	Code     string       `json:"code"`
	TraceID  string       `json:"trace_id"`
	Errors   []FieldError `json:"errors,omitempty"`
}

// newProblem builds a problem for a status and code. The status/code pairing is
// the caller's to get right; TestProblemStatusAndCodeAgree pins the pairs this
// service uses.
func newProblem(status int, code string) Problem {
	return Problem{
		Type:   errorTypeBase + code,
		Title:  titleFor(code),
		Status: status,
		Code:   code,
	}
}

// withDetail attaches the occurrence-specific sentence.
//
// It is set deliberately and never from an internal error: a driver message
// carries a host, a role, sometimes a fragment of a query, and this body is
// rendered to anonymous callers. Internal failures go to the log with the trace
// id, and support starts from that id.
func (p Problem) withDetail(detail string) Problem {
	p.Detail = detail
	return p
}

func (p Problem) withFieldErrors(errs []FieldError) Problem {
	p.Errors = errs
	return p
}

// writeProblem renders p as the response.
//
// The trace id is read from the request rather than passed in, because core
// requires the body's trace_id and the response header to be the same value and
// the cheapest way to guarantee that is to have exactly one source.
func writeProblem(w http.ResponseWriter, r *http.Request, p Problem) {
	p.Instance = r.URL.Path
	p.TraceID = traceIDFrom(r.Context())

	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set(TraceHeader, p.TraceID)
	w.WriteHeader(p.Status)
	// The body is the last thing written and a write failure cannot be reported to
	// the client that just failed, so it is logged rather than propagated.
	if err := json.NewEncoder(w).Encode(p); err != nil {
		slog.Default().Warn("writing a problem response failed", "code", p.Code, "error", err)
	}
}

// problemFor is the shorthand used by the handlers: build, describe, write.
func problemFor(w http.ResponseWriter, r *http.Request, status int, code, detail string) {
	writeProblem(w, r, newProblem(status, code).withDetail(detail))
}

// unauthorized is the single answer to "who are you" for every unusable
// credential: no token, an unknown one, an expired one, a revoked one, and a
// wrong password alike.
//
// The detail is fixed. Varying it per case — "session expired", "no such user" —
// is how a login endpoint becomes an account-enumeration oracle, and the
// underlying causes are already distinguishable in the log by trace id.
func unauthorized(w http.ResponseWriter, r *http.Request) {
	problemFor(w, r, http.StatusUnauthorized, CodeUnauthorized,
		"authentication is required to access this resource")
}

// unexpected renders a 500 and puts the real cause in the log.
//
// The split is the whole point: the caller gets a trace id they can quote and the
// operator gets the driver error, and neither has to be leaked to the other.
func unexpected(w http.ResponseWriter, r *http.Request, logger *slog.Logger, err error) {
	if logger != nil {
		logger.Error("request failed",
			"error", err,
			"trace_id", traceIDFrom(r.Context()),
			"method", r.Method,
			"path", r.URL.Path,
		)
	}
	problemFor(w, r, http.StatusInternalServerError, CodeInternal,
		"the request could not be completed. Quote the trace id when reporting this.")
}

// writeJSON is the 2xx counterpart to writeProblem, and the only way a handler
// writes a success body.
//
// It lives beside writeProblem rather than in the router file because the pair
// *is* core's rule: "Every non-2xx response is application/problem+json ... No
// service invents its own error body" (docs/openapi-conventions.md). A handler
// has exactly two writers, both here, so there is nowhere to reach for a third.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// noContent answers 204 with no body and no content type. A 204 that carries a
// JSON content type is a lie about a body that is not there.
func noContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

// bodyTooLarge says whether err is the sentinel http.MaxBytesError, which is how
// a body past the cap is recognised without matching on a message string.
func bodyTooLarge(err error) bool {
	var tooLarge *http.MaxBytesError
	return errors.As(err, &tooLarge)
}
