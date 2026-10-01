package courier

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// problem is courier's error envelope.
//
// `detail` IS DECODED AND THEN NEVER USED, and that looks like a waste of a field
// until you read `Error()`: the string a human reads is assembled from `code`,
// `trace_id` and the field names, because courier's `detail` is prose about a
// person's mailbox — one of its two 409s is a sentence explaining that somebody's
// inbox hard-bounced — and this is the platform's mail path, whose errors end up
// in a log aggregator. `trace_id` is the handle courier's own document offers for
// the cause, so nothing an operator could have used is lost.
type problem struct {
	Status  int          `json:"status"`
	Code    string       `json:"code"`
	TraceID string       `json:"trace_id"`
	Errors  []FieldError `json:"errors"`
}

// codeUnreadable is the code an `*Error` carries when the body was not a problem
// document.
//
// It is a value and not the empty string so that a reader of a log line can tell
// "courier said something" from "courier said something this client could not
// parse", and the second is the one that means a version skew.
const codeUnreadable = "unreadable_problem"

// classify turns a non-2xx answer into a typed, printable error.
//
// THE TABLE IS THIS PACKET'S ANSWER TO "WHAT DOES IDENTITY DO WITH EACH OF THESE",
// and every row is a decision rather than a default:
//
//	409 conflict                 the recipient's mailbox cannot be written to
//	422 declined preference      the recipient asked not to receive this type
//	422 anything else            this client's own request was refused
//	401, 403                     the service credential is wrong
//	503, 502, 504, 500           courier cannot deliver
//	everything else              courier is not what this document describes
//
// The last row is the one worth arguing about. A status nobody here has heard of
// must not become a success and must not become a 409; it becomes a loud,
// non-retryable `ErrRefused` carrying the status and courier's trace id, because
// "courier answered something new" is a fact about a deployment and the right
// response to it is for somebody to read the log.
//
// THE 409 IS SPLIT IN TWO, and that split is the reason this function looks at
// `code` and not only at the status. courier's route has two conflicts:
// `conflict`, which is a suppressed mailbox, and `idempotency_key_reused`, which
// is THIS CLIENT'S BUG — it sent a key it had already used for a different body.
// Reading every 409 as suppression would report a mailbox that cannot receive mail
// for a key collision, and `recovery` would then CONCEAL it from an anonymous
// caller on the strength of a fact that has nothing to do with the recipient.
func classify(op string, resp *http.Response, raw []byte) error {
	if resp == nil {
		return &Error{Op: op, Code: codeUnreadable, sentinel: ErrUnavailable, retry: true,
			cause: errNoResponse}
	}

	var doc problem
	if len(raw) > 0 {
		// A body that is not a problem document is not itself an error to report.
		// It is courier — or something in front of it — having answered with
		// something else, and "the status, and no code" is the honest description.
		_ = json.Unmarshal(raw, &doc)
	}

	code := doc.Code
	if code == "" {
		code = codeUnreadable
	}
	trace := doc.TraceID
	if trace == "" {
		// courier puts the id in the body AND in a header, and the header is the
		// one that survives a body this client could not read.
		trace = resp.Header.Get("x-trace-id")
	}

	status := resp.StatusCode
	refused := &Error{
		Op:      op,
		Status:  status,
		Code:    code,
		TraceID: trace,
		Fields:  doc.Errors,
		retry:   retryable(status, code),
	}

	switch {
	case status == http.StatusConflict && code == "conflict":
		refused.sentinel = ErrSuppressed
	case status == http.StatusConflict:
		// `idempotency_key_reused`, and the only other thing on this route that
		// conflicts. It is this client's fault and it is not a fact about a
		// recipient, so it must not be concealed by anybody downstream.
		refused.sentinel = ErrRefused
	case status == http.StatusUnprocessableEntity && hasField(doc.Errors, FieldPreferencesDisabled):
		refused.sentinel = ErrDeclined
	case status == http.StatusUnprocessableEntity:
		refused.sentinel = ErrRefused
	case status == http.StatusUnauthorized, status == http.StatusForbidden:
		refused.sentinel = ErrUnauthenticated
	case status == http.StatusServiceUnavailable, status == http.StatusInternalServerError,
		status == http.StatusBadGateway, status == http.StatusGatewayTimeout:
		refused.sentinel = ErrUnavailable
	default:
		refused.sentinel = ErrRefused
	}
	return refused
}

// retryable reports whether courier's document promises that another attempt can
// help.
//
// IT IS KEYED ON THE CLASS AND NOT ONLY THE STATUS, and it is a separate function
// from `classify` so that a reader can hold this list up against courier's
// openapi table — "retry? yes, same key" beside the 503 and "no" beside the 409 —
// and see the two agreeing.
//
// The 503 is the one that matters and the promise behind it is courier's own: "the
// retry is safe in both cases: nothing was sent, and no outbox row was written, so
// nothing claims a delivery that did not happen. A failed request also RELEASES
// its Idempotency-Key rather than storing the failure, so retrying with the same
// key is not locked out for 24 hours."
func retryable(status int, code string) bool {
	switch {
	case status == http.StatusServiceUnavailable, status == http.StatusInternalServerError,
		status == http.StatusBadGateway, status == http.StatusGatewayTimeout:
		return true
	case status == http.StatusConflict, status == http.StatusUnprocessableEntity,
		status == http.StatusUnauthorized, status == http.StatusForbidden:
		// Waiting does not unsuppress a mailbox, does not re-enable a preference a
		// person turned off, and does not make a credential courier has already
		// refused into one it will take.
		return false
	case code == codeUnreadable:
		// A body this client cannot read is not a courier whose answer to this same
		// request will be readable on the next attempt; retrying it would be a loop
		// that ends in a mailbox with two messages in it.
		return false
	default:
		return false
	}
}

// hasField reports whether courier's `errors[]` carries a code.
//
// It matches on CODE and not on field, because courier names the field `type` for
// this one and the field is what changes when courier decides to phrase the
// refusal differently; the code is the machine-readable half its conventions
// promise a client may branch on.
func hasField(fields []FieldError, code string) bool {
	for _, f := range fields {
		if f.Code == code {
			return true
		}
	}
	return false
}

// Status renders a status for an error message.
//
// It is a function because an error message is the most likely string in a process
// to reach a log, and a helper keeps the one formatting decision in one place
// rather than in two `Error()` variants.
func statusText(status int) string {
	if text := http.StatusText(status); text != "" {
		return text + " (" + strconv.Itoa(status) + ")"
	}
	return strconv.Itoa(status)
}

// fieldsString renders courier's `errors[]` compactly, from the enum-ish halves of
// each entry only.
func fieldsString(fields []FieldError) string {
	parts := make([]string, 0, len(fields))
	for _, f := range fields {
		parts = append(parts, f.Field+"="+f.Code)
	}
	return strings.Join(parts, ",")
}
