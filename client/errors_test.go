package client

// RFC 9457, ONE TEST PER PROBLEM TYPE, PLUS THE FALLBACK THAT IS THE REQUIREMENT.
//
// The brief asks for "one per problem type **plus the unknown fallback**". The
// unknown case is the important half and gets its own file section, because the
// brief's own words are that a client which "returns `ok, false` on an unknown
// problem type breaks the day the API grows, and it breaks silently".

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/cafaye/identity/client/generated"
)

// problemBody builds a well-formed problem document, so each case differs only in the
// one field under test.
//
// Built rather than pasted because a fixture per case is a fixture that can drift
// from the contract independently of the code, and the point of these tests is the
// MAPPING, not the JSON.
func problemBody(code string, status int) []byte {
	document := map[string]any{
		"type":     "https://errors.cafaye.com/" + code,
		"title":    "A fixed summary for " + code,
		"status":   status,
		"detail":   "something specific to this occurrence",
		"instance": "/v1/me",
		"code":     code,
		"trace_id": "0af7651916cd43dd8448eb211c80319c",
	}
	if status == http.StatusUnprocessableEntity {
		document["errors"] = []map[string]string{
			{"field": "password", "code": "too_short"},
		}
	}

	body, err := json.Marshal(document)
	if err != nil {
		panic("fixture problem body: " + err.Error())
	}
	return body
}

// TestEveryProblemCodeMapsToItsOwnType is the per-code table.
//
// Every case asserts THREE things, because each can fail independently and a test
// that checks only one of them can pass while the mapping is wrong:
//
//   - the concrete type, by `errors.As` — so the branch is taken
//   - `Code()`, so the code survives onto the error rather than being consumed
//   - `ProblemError` as the INTERFACE — so the single catch a caller writes works
//
// The third assertion is the one this package's shape exists for. A base struct
// embedded by value would satisfy the first two and fail the third for every typed
// error, which is the failure that inverts the fallback story.

func TestEveryProblemCodeMapsToItsOwnType(t *testing.T) {
	for _, tc := range []struct {
		code   string
		status int
		assert func(*testing.T, error) bool
	}{
		{
			code: "unauthorized", status: http.StatusUnauthorized,
			assert: func(t *testing.T, err error) bool { return isType[*UnauthenticatedError](err) },
		},
		{
			code: "forbidden", status: http.StatusForbidden,
			assert: func(t *testing.T, err error) bool { return isType[*ForbiddenError](err) },
		},
		{
			code: "not_found", status: http.StatusNotFound,
			assert: func(t *testing.T, err error) bool { return isType[*NotFoundError](err) },
		},
		{
			code: "conflict", status: http.StatusConflict,
			assert: func(t *testing.T, err error) bool { return isType[*ConflictError](err) },
		},
		{
			code: "validation_failed", status: http.StatusUnprocessableEntity,
			assert: func(t *testing.T, err error) bool { return isType[*ValidationError](err) },
		},
		{
			code: "rate_limited", status: http.StatusTooManyRequests,
			assert: func(t *testing.T, err error) bool { return isType[*RateLimitedError](err) },
		},
		{
			code: "account_locked", status: http.StatusLocked,
			assert: func(t *testing.T, err error) bool { return isType[*AccountLockedError](err) },
		},
	} {
		t.Run(tc.code, func(t *testing.T) {
			err := ProblemFrom("getCurrentUser", tc.status, ProblemContentType, "",
				problemBody(tc.code, tc.status), NewRedactor())

			var problem ProblemError
			if !errorsAs(err, &problem) {
				t.Fatalf("%s produced %T, which does not satisfy client.ProblemError.\n"+
					"This is the catch a caller writes once. If it fails here it would "+
					"fail in their code too, and only for codes this build knows.",
					tc.code, err)
			}

			if problem.Code() != tc.code {
				t.Errorf("Code() is %q, want %q.\n"+
					"`code` is the contract — core says `type` is a stable URI and `code` "+
					"is its last segment — so it has to survive onto the error rather "+
					"than being consumed by the mapping.", problem.Code(), tc.code)
			}

			if problem.HTTPStatus() != tc.status {
				t.Errorf("HTTPStatus() is %d, want %d", problem.HTTPStatus(), tc.status)
			}

			if problem.TraceID() != "0af7651916cd43dd8448eb211c80319c" {
				t.Errorf("TraceID() is %q.\n"+
					"Support starts from the trace id, and the redactor deliberately does "+
					"not touch it — a scrubber that ate it would make every unsupported "+
					"failure harder to report.", problem.TraceID())
			}

			if !tc.assert(t, err) {
				t.Errorf("%s did not produce its own concrete type: %T.\n"+
					"Each code a caller may branch on gets its own type, because a "+
					"`switch` on a status or a string is what this replaces.",
					tc.code, err)
			}
		})
	}
}

// isType is a small generic helper so each table row is one line rather than four.
func isType[T error](err error) bool {
	var target T
	return errors.As(err, &target)
}

// TestAnUnknownProblemCodeStillProducesATypedError is THE FALLBACK, and the brief's
// central requirement.
//
// identity's own document lists four codes that are NOT in core's reserved list —
// `account_locked`, `invalid_json`, `payload_too_large`, `service_unavailable` — and
// flags them for core as a proposal rather than a fait accompli. So "a code this
// build has never heard of" is not a hypothetical state for this service; it is a
// state this service is already in, for the code that has not been typed here.
//
// Three assertions, and the first is the one the brief names:
//
//   - `errors.As(err, &ProblemError)` succeeds — the caller's single catch works
//   - the code survives verbatim on `Code()`, so the caller can act on it
//   - the status and trace id survive, so a support ticket is possible
func TestAnUnknownProblemCodeStillProducesATypedError(t *testing.T) {
	const unknownCode = "quantum_entanglement_revoked"

	err := ProblemFrom("getCurrentUser", http.StatusTeapot, ProblemContentType, "",
		problemBody(unknownCode, http.StatusTeapot), NewRedactor())

	var problem ProblemError
	if !errorsAs(err, &problem) {
		t.Fatalf("an unknown code produced %T, which does not satisfy client.ProblemError.\n"+
			"This is the failure the brief names: \"a client that returns ok, false on "+
			"an unknown problem type breaks the day the API grows, and it breaks "+
			"silently.\" There is no `ok` in this signature, so the equivalent failure is "+
			"an error a caller cannot catch.", err)
	}

	if got := problem.Code(); got != unknownCode {
		t.Errorf("Code() is %q, want the code verbatim.\n"+
			"A caller that wants to act on a code this build has no type for has exactly "+
			"one thing to match on, and losing it would leave the fallback able to say "+
			"\"something failed\" and nothing more.", got)
	}

	if problem.HTTPStatus() != http.StatusTeapot {
		t.Errorf("HTTPStatus() is %d, want %d", problem.HTTPStatus(), http.StatusTeapot)
	}

	var unknown *UnknownProblemError
	if !errorsAs(err, &unknown) {
		t.Errorf("the error is %T, not *UnknownProblemError.\n"+
			"A caller may reasonably want to tell \"a code I have a type for\" from \"a "+
			"code this build does not\" — that is the difference between handling it and "+
			"logging it and moving on.", err)
	}

	// And the rendered message names the code, because the whole point of the
	// fallback is that somebody can read what happened without a debugger.
	if rendered := err.Error(); !strings.Contains(rendered, unknownCode) {
		t.Errorf("the message does not name the code: %s", rendered)
	}
}

// TestTheCodeChoosesTheTypeAndTheStatusOnlyBreaksTies covers the precedence, which
// is a decision rather than an accident.
//
// core makes `code` the contract and `status` "repeated in the body" — advisory, and
// RFC 9457 permits a service to omit it. So a service that answers 403 with
// `code: "forbidden"` must produce a `ForbiddenError` even if the number drifts, and
// a service that omits `code` entirely must still be mapped from the number.
func TestTheCodeChoosesTheTypeAndTheStatusOnlyBreaksTies(t *testing.T) {
	t.Run("the code wins over a drifted status", func(t *testing.T) {
		// A 401 body that says `forbidden`. Contradictory on purpose.
		err := ProblemFrom("getCurrentUser", http.StatusUnauthorized, ProblemContentType, "",
			problemBody("forbidden", http.StatusUnauthorized), NewRedactor())

		if !isType[*ForbiddenError](err) {
			t.Errorf("a `forbidden` code on a 401 produced %T, want *ForbiddenError.\n"+
				"`code` is the documented machine-readable contract; `status` is one "+
				"response's opinion about itself.", err)
		}
	})

	t.Run("the status is used when the code is absent", func(t *testing.T) {
		body := []byte(`{"type":"https://errors.cafaye.com/","title":"Unauthorized",` +
			`"status":401,"detail":"","instance":"/v1/me","trace_id":"abc"}`)

		err := ProblemFrom("getCurrentUser", http.StatusUnauthorized, ProblemContentType, "",
			body, NewRedactor())

		if !isType[*UnauthenticatedError](err) {
			t.Errorf("a 401 with no code produced %T, want *UnauthenticatedError.\n"+
				"RFC 9457 makes `code` a cafaye extension rather than a required member, "+
				"so a service may omit it. Falling back to the status is what keeps a "+
				"conforming-but-terse service from landing on the fallback type.", err)
		}
	})
}

// TestAResponseThatIsNotAProblemDocumentIsNotAProblemError covers the two edges the
// problem hierarchy cannot, both of which are judgement calls worth stating.
func TestAResponseThatIsNotAProblemDocumentIsNotAProblemError(t *testing.T) {
	t.Run("a proxy's html 502", func(t *testing.T) {
		err := ProblemFrom("getCurrentUser", http.StatusBadGateway, "text/html", "",
			[]byte("<html><body>502 Bad Gateway</body></html>"), NewRedactor())

		var problem ProblemError
		if errorsAs(err, &problem) {
			t.Errorf("an HTML 502 produced a ProblemError: %T.\n"+
				"There is no problem document here, so `type` and `title` would both be a "+
				"lie. The excerpt is kept because a proxy's HTML 502 is otherwise "+
				"undiagnosable from the client side.", err)
		}
		if !isType[*CallError](err) {
			t.Errorf("an HTML 502 produced %T, want *CallError", err)
		}
		if !strings.Contains(err.Error(), "502 Bad Gateway") {
			t.Errorf("the excerpt was dropped, so a proxy failure is undiagnosable: %s", err)
		}
	})

	t.Run("a 2xx carrying a problem document", func(t *testing.T) {
		err := ProblemFrom("getCurrentUser", http.StatusOK, ProblemContentType, "",
			problemBody("internal", http.StatusInternalServerError), NewRedactor())

		if err == nil {
			t.Fatal("a 200 carrying a problem document returned no error.\n" +
				"core reserves application/problem+json for failures, so treating this as " +
				"a success would hand the caller a Problem where its types promised a " +
				"result. A typed client that quietly returns the wrong shape produces a " +
				"TypeError three frames from the mistake.")
		}
		if !isType[*CallError](err) {
			t.Errorf("produced %T, want *CallError", err)
		}
	})
}

// TestAccountLockedCarriesTheRetryAfter covers the one code where waiting is the
// right answer, and asserts both the present and absent cases.
//
// Zero and absent are told apart on purpose. The document says the value is "never
// negative", so a literal `0` is a real answer the service can give — "retry
// immediately" — and it is not the same as "there was no header". A client that
// collapsed them would hammer an account the lockout exists to protect.
func TestAccountLockedCarriesTheRetryAfter(t *testing.T) {
	body := problemBody("account_locked", http.StatusLocked)

	t.Run("a readable header", func(t *testing.T) {
		err := ProblemFrom("createSession", http.StatusLocked, ProblemContentType, "900",
			body, NewRedactor())

		var locked *AccountLockedError
		if !errorsAs(err, &locked) {
			t.Fatalf("produced %T, want *AccountLockedError", err)
		}
		if locked.RetryAfterSeconds() != 900 {
			t.Errorf("RetryAfterSeconds() is %d, want 900", locked.RetryAfterSeconds())
		}
		if !locked.HasRetryAfter() {
			t.Error("HasRetryAfter() is false for a response carrying `Retry-After: 900`")
		}
	})

	t.Run("a zero header means retry now, not unknown", func(t *testing.T) {
		err := ProblemFrom("createSession", http.StatusLocked, ProblemContentType, "0",
			body, NewRedactor())

		var locked *AccountLockedError
		if !errorsAs(err, &locked) {
			t.Fatalf("produced %T, want *AccountLockedError", err)
		}
		if !locked.HasRetryAfter() {
			t.Error("HasRetryAfter() is false for `Retry-After: 0`.\n" +
				"The document says the value is never negative, so 0 is a real answer — " +
				"\"retry immediately\" — and it is not the same as no header at all.")
		}
	})

	t.Run("an absent header is reported as absent", func(t *testing.T) {
		err := ProblemFrom("createSession", http.StatusLocked, ProblemContentType, "",
			body, NewRedactor())

		var locked *AccountLockedError
		if !errorsAs(err, &locked) {
			t.Fatalf("produced %T, want *AccountLockedError", err)
		}
		if locked.HasRetryAfter() {
			t.Error("HasRetryAfter() is true with no header at all")
		}
		if locked.RetryAfterSeconds() != 0 {
			t.Errorf("RetryAfterSeconds() is %d; an unknown wait must read as 0 so a "+
				"caller that ignores HasRetryAfter backs off rather than hammering.",
				locked.RetryAfterSeconds())
		}
	})

	t.Run("an http-date is reported as absent rather than guessed at", func(t *testing.T) {
		err := ProblemFrom("createSession", http.StatusLocked, ProblemContentType,
			"Wed, 30 Sep 2026 12:15:00 GMT", body, NewRedactor())

		var locked *AccountLockedError
		if !errorsAs(err, &locked) {
			t.Fatalf("produced %T, want *AccountLockedError", err)
		}
		if locked.HasRetryAfter() {
			t.Error("an HTTP-date was parsed as delta-seconds.\n" +
				"RFC 9110 allows both forms; identity's document says its value is whole " +
				"seconds, so the date form comes from something else in the chain. A wrong " +
				"retry time is worse than a caller falling back to its own policy.")
		}
	})
}

// TestValidationCarriesTheFieldErrors is the only code that does, per the document.
func TestValidationCarriesTheFieldErrors(t *testing.T) {
	err := ProblemFrom("registerUser", http.StatusUnprocessableEntity, ProblemContentType, "",
		problemBody("validation_failed", http.StatusUnprocessableEntity), NewRedactor())

	var problem ProblemError
	if !errorsAs(err, &problem) {
		t.Fatalf("produced %T, want a ProblemError", err)
	}

	fields := problem.Document().Errors
	if fields == nil {
		t.Fatal("Errors is nil; the document says `errors[]` is present on a 422")
	}
	if len(*fields) != 1 || (*fields)[0].Field != "password" || (*fields)[0].Code != "too_short" {
		t.Errorf("Errors is %v, want one entry of {password, too_short}", *fields)
	}
}

// TestIsRetryableIsNarrow is the assertion that this package does not retry, and
// does not encourage a caller to retry something that cannot succeed.
//
// A 409 is deliberately absent even though it is sometimes transient: a conflict
// means the request conflicts with current state, and repeating it unchanged repeats
// the conflict. That is a decision for whoever holds the domain, not for a transport.
func TestIsRetryableIsNarrow(t *testing.T) {
	retryable := ProblemFrom("getCurrentUser", http.StatusTooManyRequests,
		ProblemContentType, "", problemBody("rate_limited", http.StatusTooManyRequests),
		NewRedactor())
	if !IsRetryable(retryable) {
		t.Error("a 429 is not reported as retryable")
	}

	for _, tc := range []struct {
		name string
		err  error
	}{
		{"a 409", ProblemFrom("x", http.StatusConflict, ProblemContentType, "",
			problemBody("conflict", http.StatusConflict), NewRedactor())},
		{"a 403", ProblemFrom("x", http.StatusForbidden, ProblemContentType, "",
			problemBody("forbidden", http.StatusForbidden), NewRedactor())},
		{"a 422", ProblemFrom("x", http.StatusUnprocessableEntity, ProblemContentType, "",
			problemBody("validation_failed", http.StatusUnprocessableEntity), NewRedactor())},
		{"nil", nil},
	} {
		if IsRetryable(tc.err) {
			t.Errorf("%s is reported as retryable.\n"+
				"Retrying a request that cannot succeed is how a client turns a "+
				"conflict into an incident.", tc.name)
		}
	}
}

// TestProblemFieldsAreRedacted is the contract half of the leak invariant, stated
// where the problem is built rather than only in the credential-leak file.
//
// Every member goes through the redactor INCLUDING the ones this package did not
// know the contract had, because a service that adds an extension member tomorrow
// must not be able to start leaking through a client that predates it.
func TestProblemFieldsAreRedacted(t *testing.T) {
	// Built with %q-escaped JSON rather than a hand-written literal with spliced
	// quotes: single quotes are not valid JSON, and a fixture that does not parse
	// exercises the "not a problem document" branch instead of the redaction this
	// test is about. It cost one run to find out.
	leaky, marshalErr := json.Marshal(map[string]any{
		"type":     "https://errors.cafaye.com/validation_failed",
		"title":    "Validation failed",
		"status":   422,
		"detail":   "the token " + apiCredential + " was rejected",
		"instance": "/v1/me",
		"code":     "validation_failed",
		"trace_id": "0af7651916cd43dd8448eb211c80319c",
		"errors":   []map[string]string{{"field": "token", "code": "invalid_format"}},
		// A member this client knows nothing about, carrying the credential. The
		// generator's struct has no field for it, so it cannot reach the error type —
		// which is the point: an unknown member is dropped, not forwarded.
		"an_extension_member_nobody_declared": apiCredential,
	})
	if marshalErr != nil {
		t.Fatalf("building the fixture: %v", marshalErr)
	}

	err := ProblemFrom("getCurrentUser", http.StatusUnprocessableEntity, ProblemContentType, "",
		leaky, NewRedactor(apiCredential))

	var problem ProblemError
	if !errorsAs(err, &problem) {
		t.Fatalf("produced %T, want a ProblemError", err)
	}

	document := problem.Document()
	for name, value := range map[string]string{
		"detail":    document.Detail,
		"type":      document.Type,
		"title":     document.Title,
		"instance":  document.Instance,
		"the error": err.Error(),
	} {
		if strings.Contains(value, apiCredential) {
			t.Errorf("the credential appears in the problem's %s:\n%s", name, value)
		}
	}

	// And the trace id survived, because a redactor that ate it would make every
	// unsupported failure harder to report.
	if document.TraceID != "0af7651916cd43dd8448eb211c80319c" {
		t.Errorf("TraceID is %q; it must survive redaction", document.TraceID)
	}
}

// TestTheGeneratedProblemTypeIsTheOneUsed is a small guard against the day somebody
// declares a second `Problem` struct by hand.
//
// `client/generated` declares `Problem`, `FieldError` and a `ProblemCode` enum from
// the document. This package uses them rather than restating them, which is what
// makes the code a compile-time enum and keeps the drift gate meaningful.
func TestTheGeneratedProblemTypeIsTheOneUsed(t *testing.T) {
	var document generated.Problem
	document.Code = generated.ProblemCodeUnauthorized

	if string(document.Code) != "unauthorized" {
		t.Fatalf("the generated ProblemCode enum does not carry %q; this test is "+
			"checking a shape the document no longer has", "unauthorized")
	}
}
