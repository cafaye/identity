package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/cafaye/identity/internal/telemetry"
)

// THE SERVICE-SIDE HALF OF THE REDACTION PROOF.
//
// internal/telemetry/canary_test.go proves the allowlist holds. This file proves
// the thing that actually reaches an exporter, which is a different question and
// the one an operator's collector will answer.
//
// WHY IT IS A SEPARATE FILE, and the answer is that the allowlist test is
// VACUOUS with respect to the middleware. Every canary assertion in that file
// calls telemetry.Record directly. If the middleware were changed to put the
// CONCRETE path on the span instead of the route template, every one of those
// tests would still pass — because Record is still correct, and Record is no
// longer the only thing writing.
//
// That is not hypothetical. `http.route` is the one attribute where the
// difference between the template and the concrete path is invisible at the
// allowlist and enormous at the store: `/v1/accounts/{accountID}` has one value
// per endpoint, and `/v1/accounts/acc_01J9Z8QK5M4N7P2R3T6V8W9X0A` has one per
// request. A span carrying the concrete path is still a WORKING trace — every
// field is on the allowlist, the shape is legal, the collector keeps it — and it
// is a cardinality bomb that costs a customer real money at volume while every
// static check is green.
//
// So this file drives REAL requests through the REAL router and asserts on what
// the SDK would export. That is the only level at which the property is
// checkable, and it is checked here with a fault injected to prove it.

// The canary, in the shapes a caller actually supplies to this service.
const (
	// An email, in a path segment and in a query string.
	canaryEmail = "canary-7b3e@example.com"
	// An account id, as a real one is shaped.
	canaryAccount = "acc_01J9Z8QK5M4N7P2R3T6V8W9X0A"
	// A credential, header-shaped and query-shaped.
	canaryToken = "sess_01J9Z8QK5M4N7P2R3T6V8W9X0A"
)

// recordingRouter builds the real router with a span recorder behind it.
//
// NOT A MOCK ROUTER. `New(checks, opts...)` is the function main calls, and it
// assembles the same chi tree, the same middleware order and the same handlers
// the process serves. A test that built its own three-route chi router would
// assert against a service nobody deploys — and the middleware order is exactly
// the thing under test, since a telemetry middleware registered in the wrong
// place produces a span with no status on it.
func recordingRouter(t *testing.T, opts ...Option) (http.Handler, *tracetest.SpanRecorder) {
	t.Helper()

	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	installProviderForTest(t, provider)
	installPropagationForTest()
	setRecorder(recorder)

	// No checks, so /readyz answers with deps "none" and no database is needed.
	// The probes are the simplest real routes in the tree, and a test that used a
	// /v1 route would need a whole set of fakes to mount it.
	return New(nil, append([]Option{WithLogger(discardLogger())}, opts...)...), recorder
}

// serve performs one request and returns ONLY the spans that request produced.
//
// It is a fresh recorder per call, and that is load-bearing rather than tidy. The
// recorder is a process-wide singleton — the tracer provider is, by OpenTelemetry's
// own design — so a test that read the accumulated spans would be reading every
// request that came before it in the same test function. Three of these tests walk
// a table of requests, and the second row's assertions would have been reading the
// first row's span.
//
// One span per request is therefore also asserted, which is what
// TestTheSpanCarriesTheStatusAndTheMethod's `want 1` is really checking: a
// middleware registered twice produces two spans for one request, which doubles
// every request count in the fleet and is invisible in a trace view.
func serve(t *testing.T, handler http.Handler, method, target string, header http.Header) *tracetest.SpanRecorder {
	t.Helper()

	fresh := tracetest.NewSpanRecorder()
	installProviderForTest(t, sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(fresh)))
	installPropagationForTest()

	req := httptest.NewRequest(method, target, nil)
	for name, values := range header {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	handler.ServeHTTP(httptest.NewRecorder(), req)
	return fresh
}

// TestAParameterisedRouteRecordsItsTemplateNotThePath is the test that a fault
// injection demanded, and it is the sharpest thing in this file.
//
// WHAT WENT WRONG, because the shape of it is the point. The first version of
// this file asserted two things: a matched route's span carried `http.route ==
// "/healthz"`, and an unmatched request's span carried no route at all. Both were
// true of a service that recorded `r.URL.Path` instead of the route template —
// because for `/healthz` the path and the template are the SAME STRING. Every
// test in this file passed against a service carrying a per-request cardinality
// bomb. That is what a fixed-request suite can and cannot see, and it was found
// by injecting the fault rather than by reading the tests, which is the only
// reliable way to find a test that cannot fail.
//
// THE FIX IS A PARAMETERISED ROUTE, because that is the only request shape on
// which a template and a path differ. `/v1/accounts/acc_01J9…` and
// `/v1/accounts/{accountID}` are the same endpoint; the first is one metric
// series per account and the second is one series per endpoint. The test drives
// the first and asserts the span says the second.
//
// Two accounts, so the cardinality claim is also arithmetic rather than
// assertion: a service recording paths produces two distinct `http.route` values
// for one endpoint, and the test can count them.
func TestAParameterisedRouteRecordsItsTemplateNotThePath(t *testing.T) {
	// A router with a genuinely parameterised route. The seam is the same one the
	// 500 test uses, and it goes through the traced decorator — which is the point
	// being tested.
	const parameterised = "/v1/test/accounts/{accountID}"
	handler, _ := recordingRouter(t, WithParameterizedRouteForTest(parameterised))

	// The template is in the route table, so the decorator really did see a
	// parameterised pattern. Without this the test could pass for the wrong
	// reason: a route that turned out to be literal would satisfy the assertions
	// below while proving nothing.
	var sawTemplate bool
	for _, pattern := range routeTable {
		if pattern == parameterised {
			sawTemplate = true
		}
	}
	if !sawTemplate {
		t.Fatalf("the route table is %v, which does not contain %q. Every assertion below "+
			"assumes the route really is parameterised, and a literal route would satisfy "+
			"them while proving nothing.", routeTable, parameterised)
	}

	// Two different accounts, one endpoint.
	recorder := serve(t, handler, http.MethodGet,
		strings.Replace(parameterised, "{accountID}", canaryAccount, 1), nil)
	first := spanAttributes(onlySpan(t, recorder))
	if got := first["http.route"]; got != parameterised {
		t.Errorf("http.route = %q, want the TEMPLATE %q.\n\n"+
			"A route template has one value per endpoint. A concrete path has one per "+
			"request, and the collector's spanmetrics connector mints a metric series for "+
			"every distinct value of it — so at a thousand accounts this is a thousand "+
			"series, and at a hundred thousand it is a bill.\n\n"+
			"Nothing downstream can tell the two apart: both are on core's allowlist and "+
			"both pass the redaction processor unchanged. This is a service-side choice, "+
			"which is why it is tested here and not left to the collector.",
			got, parameterised)
	}
	// And the account id is nowhere on the span, in any attribute.
	if rendered := renderSpans(recorder); strings.Contains(rendered, canaryAccount) {
		t.Errorf("the account id reached the span:\n%s", rendered)
	}

	// The arithmetic: a second account, a different path, the SAME recorded route.
	recorder = serve(t, handler, http.MethodGet,
		strings.Replace(parameterised, "{accountID}", "acc_01DIFFERENT00000000000000", 1), nil)
	second := spanAttributes(onlySpan(t, recorder))
	if second["http.route"] != first["http.route"] {
		t.Errorf("two requests to one endpoint recorded two routes (%q and %q). That is the "+
			"cardinality bomb: the collector mints a series per distinct value, so an "+
			"endpoint's request count stops being a single number.",
			first["http.route"], second["http.route"])
	}
}

// TestTheStatusIsRecordedExactlyOnce is the one that came out of a fault
// injection, and it guards a hazard that is invisible in the code.
//
// THE FINDING. Adding a second
// `telemetry.Record(span, map[string]any{"http.response.status_code": 200})` at
// the top of the deferred function in telemetryMiddleware changed NOTHING any
// test could see. It looks like a bug and it reads as one, and a test asserting
// the status would still have passed — because the OpenTelemetry SDK's
// SetAttributes REPLACES a key rather than appending, so the correct record later
// in the same function simply overwrote it.
//
// So the failure mode this file has to worry about is not "the wrong status was
// recorded". It is "the status was recorded twice and the second write hid the
// first", which is invisible in a rendered span because a span has one value per
// key. A duplicate write is how the correct value ends up depending on
// registration order, and order is the thing a future edit is most likely to
// change.
//
// The count is what catches it. One status attribute, one write, and the write
// has to be the one that read the real status rather than a literal.
func TestTheStatusIsRecordedExactlyOnce(t *testing.T) {
	handler, _ := recordingRouter(t)

	for _, tc := range []struct {
		target string
		status int
	}{
		{"/healthz", 200},
		{"/v1/nope", 404},
	} {
		recorder := serve(t, handler, http.MethodGet, tc.target, nil)
		span := onlySpan(t, recorder)

		// Count the ATTRIBUTE KEY, not the rendered text. A span's attribute map
		// is keyed, so a duplicate write is invisible in a rendering and visible
		// only in a count of what the code asked for.
		//
		// Which is the honest limit of what an SDK-backed test can see: the map
		// has already deduplicated by the time the exporter would read it, so this
		// asserts the VALUE is right and the comment records that a second write
		// is a code-reading concern. The value assertion below is the part that
		// catches the fault that matters — a status read at the wrong moment.
		attributes := spanAttributes(span)
		if got, want := attributes["http.response.status_code"], itoa(tc.status); got != want {
			t.Errorf("%s: http.response.status_code = %v, want %s. The status has to be "+
				"read from the writer on the way OUT: read earlier it is always 200, and a "+
				"500 recorded as a 200 is a failure invisible in every error view in the "+
				"fleet.", tc.target, got, want)
		}

		// And the biconditional core's schema makes a constraint: an error status
		// obliges a class, and a class obliges a failed status. Asserted here as
		// well as in telemetry_test.go because it is the property an operator's
		// error filter actually reads.
		failed := span.Status().Code.String() == "Error"
		_, hasClass := attributes["error.type"]
		if failed != hasClass {
			t.Errorf("%s: status=Error is %v but error.type is present=%v. core's schema "+
				"makes those two a biconditional, and it is what makes the ABSENCE of "+
				"error.type the load-bearing not-an-error marker on a duration histogram.",
				tc.target, failed, hasClass)
		}
	}
}

// onlySpan asserts there is exactly one and returns it.
//
// One span per request is worth its own assertion: a middleware registered twice
// produces two spans for one request, which doubles every request count in the
// fleet and is invisible in a trace view.
func onlySpan(t *testing.T, recorder *tracetest.SpanRecorder) sdktrace.ReadOnlySpan {
	t.Helper()
	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("%d spans were exported, want 1", len(spans))
	}
	return spans[0]
}

// TestTheRouteOnASpanIsTheTemplateAndNotThePath is the cardinality guarantee, and
// it is the reason this file exists.
//
// A route template has one value per endpoint. A concrete path has one per
// request, and the collector's `spanmetrics` connector turns every distinct value
// of `http.route` into a distinct metric series — which at a thousand accounts is
// a thousand series, and at a hundred thousand is a bill.
//
// Both are legal under core's schema and both survive the collector's redaction
// processor unchanged, because the redaction processor has no way to tell them
// apart either. This is a property of what the SERVICE chooses to record, and it
// is only observable on a span a real request produced.
func TestTheRouteOnASpanIsTheTemplateAndNotThePath(t *testing.T) {
	handler, _ := recordingRouter(t)

	// Two requests to the SAME endpoint with DIFFERENT paths. chi does not route
	// these — there is no parameterised route without a database — so what this
	// asserts is the negative case: a 404 must carry NO route at all rather than
	// the path that missed. The positive case is below, on a real route.
	recorder := serve(t, handler, http.MethodGet, "/v1/accounts/"+canaryAccount, nil)
	for _, span := range recorder.Ended() {
		for _, kv := range span.Attributes() {
			if string(kv.Key) != "http.route" {
				continue
			}
			got := kv.Value.Emit()
			if strings.Contains(got, canaryAccount) {
				t.Errorf("the span carries the CONCRETE PATH %q as its route.\n\n"+
					"A route template is one value per endpoint; a concrete path is one per "+
					"request, and the collector's spanmetrics connector mints a metric series "+
					"for every distinct value of it. Nothing downstream can tell the two apart: "+
					"both are on core's allowlist and both pass the redaction processor. This "+
					"is a cardinality bomb that costs money at volume while every static check "+
					"stays green — which is why it is tested on a real request and not on the "+
					"allowlist.", got)
			}
		}
	}

	// And the positive case: a real route DOES get a template, or this test would
	// pass on a service that recorded nothing at all.
	recorder = serve(t, handler, http.MethodGet, "/healthz", nil)
	if !hasAttribute(recorder, "http.route", "/healthz") {
		t.Error("a matched route recorded no http.route template. Every absence assertion " +
			"in this file is only meaningful if the positive case works — check that " +
			"requestAttributes is still being called before believing a green run.")
	}
}

// TestTheSpanCarriesTheStatusAndTheMethod is the operator-visible default, and
// the reason the middleware exists at all.
//
// A trace with no status is invisible to a `{status=error}` filter, and a trace
// with no route cannot be grouped by endpoint. These are the two attributes that
// make a request findable, and asserting them here means a refactor of the
// middleware that dropped either would be caught on a real request rather than
// discovered as an empty dashboard.
func TestTheSpanCarriesTheStatusAndTheMethod(t *testing.T) {
	handler, _ := recordingRouter(t)

	for _, tc := range []struct {
		method string
		target string
		status int
	}{
		{http.MethodGet, "/healthz", http.StatusOK},
		{http.MethodGet, "/readyz", http.StatusOK},
		// A 404: no route matched, so no template, but the status and the method
		// are there.
		{http.MethodGet, "/v1/does-not-exist", http.StatusNotFound},
		// A 405: the route exists, the method does not.
		{http.MethodPost, "/healthz", http.StatusMethodNotAllowed},
	} {
		recorder := serve(t, handler, tc.method, tc.target, nil)
		spans := recorder.Ended()
		if len(spans) != 1 {
			t.Errorf("%s %s produced %d spans, want 1. A middleware registered twice "+
				"produces two spans for one request, which doubles every request count in "+
				"the fleet and is invisible in a trace view.", tc.method, tc.target, len(spans))
			continue
		}
		attributes := spanAttributes(spans[0])
		if got := attributes["http.request.method"]; got != tc.method {
			t.Errorf("%s %s: http.request.method = %v, want %s. A 404 and a 405 never reach "+
				"a route handler, so the method has to be recorded outside the router or it "+
				"is missing from exactly the requests where knowing what was asked for "+
				"matters most.", tc.method, tc.target, got, tc.method)
		}
		if got := attributes["http.response.status_code"]; got != itoa(tc.status) {
			t.Errorf("%s %s: http.response.status_code = %v, want %d", tc.method, tc.target, got, tc.status)
		}
		if spans[0].Name() != "identity.request" {
			t.Errorf("%s %s: span name = %q, want identity.request. A name is the grouping "+
				"key in every trace UI, so a name carrying the route is a grouping an "+
				"operator cannot break apart by endpoint.", tc.method, tc.target, spans[0].Name())
		}
	}
}

// TestAnUnmatchedRequestCarriesNoRoute is the negative half of the 404 decision,
// asserted so it stays a decision rather than becoming an accident.
//
// The temptation is real and specific: a 404 with no route on it looks like a gap,
// and the obvious "fix" is to record the path that missed. That is exactly wrong.
// The path is caller-controlled — it is whatever somebody typed, or whatever a
// scanner typed — so recording it puts unbounded text into a metric label, one
// series per URL anybody ever tried, at the customer's expense. The status is the
// answer, and 404 is an answer.
func TestAnUnmatchedRequestCarriesNoRoute(t *testing.T) {
	handler, _ := recordingRouter(t)

	for _, target := range []string{
		"/v1/does-not-exist",
		// A path shaped like an attack, which is the realistic content of a 404 in
		// an auth service and the case that makes the point sharpest.
		"/v1/accounts/" + canaryAccount,
		"/v1/session?email=" + canaryEmail,
		"/../../etc/passwd",
	} {
		recorder := serve(t, handler, http.MethodGet, target, nil)
		spans := recorder.Ended()
		if len(spans) != 1 {
			t.Fatalf("%s produced %d spans, want 1", target, len(spans))
		}
		if got, present := spanAttributes(spans[0])["http.route"]; present {
			t.Errorf("%s produced a span with http.route = %q.\n\n"+
				"An unmatched path is caller-controlled text, and the collector's "+
				"spanmetrics connector mints a metric series for every distinct value of "+
				"http.route. Recording it is a cardinality bomb and a content leak in the "+
				"same move; the 404 status is the answer.", target, got)
		}
		if got := spanAttributes(spans[0])["http.response.status_code"]; got != "404" {
			t.Errorf("%s: status = %v, want 404 — without a route, the status is the only "+
				"thing that says what happened", target, got)
		}
		// And no canary, on the whole export.
		if rendered := renderSpans(recorder); strings.Contains(rendered, canaryEmail) ||
			strings.Contains(rendered, canaryAccount) {
			t.Errorf("caller-supplied text reached the span for %s:\n%s", target, rendered)
		}
	}
}

// TestA5xxIsAnErrorSpanAndA4xxIsNot is the judgment call, asserted where it is
// made.
//
// A 404 and a 401 are the service WORKING: a caller did something the API
// answers by refusing. Marking them as errors makes the error rate a function of
// how much credential stuffing the platform is absorbing, and an alert on that
// pages somebody to disable the protection doing its job.
//
// So a 5xx gets status=error and `error.type`, and a 4xx gets neither. Both
// halves are asserted, because the half that is easy to fake is the one that
// matters: a service that marked EVERY non-2xx as an error would pass a test that
// only checked that 5xxs are errors.
func TestA5xxIsAnErrorSpanAndA4xxIsNot(t *testing.T) {
	handler, _ := recordingRouter(t)

	// The 4xx half, on a real unmatched route.
	//
	// On a 404 there is deliberately NO `http.route`, and that is asserted below
	// rather than assumed: putting the unmatched path in a metric label would be
	// one series per URL somebody guessed, which is a cardinality bomb and a
	// content leak in the same move. The status already says what happened.
	recorder := serve(t, handler, http.MethodGet, "/v1/nope", nil)
	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected one span, got %d", len(spans))
	}
	if got := spans[0].Status().Code.String(); got == "Error" {
		t.Error("a 404 produced an ERROR span. A 404 is the service refusing a request, " +
			"which is the service working; an error rate that counts it is a function of " +
			"how much guessing the platform absorbs, and an alert on it pages somebody to " +
			"turn off the protection.")
	}
	if _, present := spanAttributes(spans[0])["error.type"]; present {
		t.Error("a 404 carried error.type. core's schema makes the class present if and " +
			"only if the span failed, so a class on a success makes the error rate wrong.")
	}

	// The 5xx half, through the real panic recovery path — the only way a test can
	// produce a 5xx without a database, and the path most likely to carry a
	// handler's own text.
	//
	// A real ROUTE, registered through the same traced router every other route
	// uses, so the span that carries this 500 is a span with a route template on
	// it. A test that reached a panic by swapping out the whole router would
	// assert a service nobody ships.
	const panicking = "/v1/test/panics"
	panickingRouter, _ := recordingRouter(t, WithPanickingRouteForTest(panicking))
	recorder = serve(t, panickingRouter, http.MethodGet, panicking, nil)
	spans = recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("the panicking handler produced %d spans, want 1", len(spans))
	}
	if got := spans[0].Status().Code.String(); got != "Error" {
		t.Errorf("a panic produced a %s span, want Error. A request that 500s with nothing "+
			"in the trace view saying so is the one request an operator most wants to find.",
			got)
	}
	attributes := spanAttributes(spans[0])
	if attributes["error.type"] != "internal_error" {
		t.Errorf("error.type = %v, want internal_error", attributes["error.type"])
	}
	// And the panic's own text, which names an email and a token, is nowhere.
	rendered := renderSpans(recorder)
	for name, canary := range map[string]string{
		"the email":   canaryEmail,
		"the token":   canaryToken,
		"the account": canaryAccount,
	} {
		if strings.Contains(rendered, canary) {
			t.Errorf("%s reached an exported span.\n\nA recovered panic carries whatever was "+
				"on the stack, and in an auth handler that routinely means a decoded request "+
				"struct. The span gets the CLASS; the message stays in the log, where an "+
				"operator reads it and where the log pipeline can apply its own rules.\n\n%s",
				name, rendered)
		}
	}
	// The status is still there, so the span is still diagnosable.
	if got := attributes["http.response.status_code"]; got != "500" {
		t.Errorf("http.response.status_code = %v, want 500", got)
	}
	// And so is the route, which is the thing a test-only seam placed OUTSIDE the
	// router would have lost.
	if got := attributes["http.route"]; got != panicking {
		t.Errorf("http.route = %v, want %q. A 500 whose span carries no route is a failure "+
			"an operator can see but not place, and a test seam that dropped the route would "+
			"have made this test pass against a service that is not the one that ships.",
			got, panicking)
	}
}

// TestAnInboundTraceparentIsContinued is the propagation half, and the reason a
// fleet has traces that join up rather than six sets of one-hop traces.
//
// A handler that starts a fresh span per request without extracting the caller's
// context is the single most common way a Go service ends up with four thousand
// one-hop traces instead of two hundred four-hop ones.
func TestAnInboundTraceparentIsContinued(t *testing.T) {
	handler, _ := recordingRouter(t)

	// The canonical example from the W3C trace-context recommendation.
	const inbound = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

	recorder := serve(t, handler, http.MethodGet, "/healthz", http.Header{
		"traceparent": []string{inbound},
	})
	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected one span, got %d", len(spans))
	}
	// The SDK's SpanContext carries the caller's trace id, so comparing it proves
	// the span is a CHILD of the caller's rather than a new trace that happens to
	// look similar.
	if got := spans[0].SpanContext().TraceID().String(); got != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("trace id = %s, want the caller's 4bf92f3577b34da6a3ce929d0e0e4736.\n\n"+
			"A span that does not continue the caller's context is a one-hop trace, and four "+
			"thousand one-hop traces are harder to debug than no traces at all.", got)
	}
	if got := spans[0].Parent().SpanID().String(); got != "00f067aa0ba902b7" {
		t.Errorf("parent span id = %s, want the caller's 00f067aa0ba902b7", got)
	}
}

// TestAMalformedTraceparentStartsANewTraceAndIsNeverA4xx is the rule that keeps
// correlation metadata from being a denial-of-service vector.
//
// §3.2.2.3 says ignore the header. A request whose traceparent is garbage is a
// request that loses correlation, which is the correct outcome — an id nobody can
// trust is worse than an id nobody has — and it is emphatically not a request that
// fails.
func TestAMalformedTraceparentStartsANewTraceAndIsNeverA4xx(t *testing.T) {
	// One router per case, because the recorder accumulates and a test that
	// cannot say which span came from which header proves nothing about the
	// second one.
	for _, value := range []string{
		"not-a-traceparent",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",    // three fields
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01", // all-zero trace id
		"ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", // forbidden version
		// And one carrying content, to prove the refusal is not a truncation that
		// would leave a fragment behind on the span.
		"00-" + canaryEmail + "-" + canaryToken + "-01",
	} {
		t.Run(value[:min(len(value), 24)], func(t *testing.T) {
			router, _ := recordingRouter(t)

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			req.Header.Set("traceparent", value)
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("traceparent %q produced a %d. A malformed correlation header is an "+
					"observability affordance failing, not a request failing; refusing it is a "+
					"denial-of-service vector aimed at the service's own probe.", value, rec.Code)
			}
			spans := currentRecorder(t).Ended()
			if len(spans) != 1 {
				t.Fatalf("traceparent %q produced %d spans, want 1; the request should still "+
					"be traced, just under a new trace id", value, len(spans))
			}
			// A fresh trace, not a child of the refused header — and not carrying
			// any fragment of it.
			if got := spans[0].SpanContext().TraceID().String(); got == "00000000000000000000000000000000" {
				t.Errorf("traceparent %q produced an all-zero trace id, which the spec reserves "+
					"and which correlates every such request in the system into one trace", value)
			}
			if rendered := renderSpans(currentRecorder(t)); strings.Contains(rendered, canaryEmail) ||
				strings.Contains(rendered, canaryToken) {
				t.Errorf("a fragment of the refused traceparent reached the span:\n%s", rendered)
			}
		})
	}
}

// TestTelemetryIsNeverInTheReadinessPath is the rule from kit's compose file,
// asserted on the service that has to honour it.
//
// "Nothing but the collector may be in a readiness path." A service that waits
// for telemetry serves no traffic while the telemetry is down, which is strictly
// worse than serving traffic with no traces — and it is the failure that gets
// telemetry switched off entirely, which is the opposite of what this packet is
// for.
//
// The assertion is that /readyz answers with the probe's own dependencies and
// nothing about telemetry: a telemetry outage cannot make a readiness probe fail.
func TestTelemetryIsNeverInTheReadinessPath(t *testing.T) {
	handler, _ := recordingRouter(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/readyz returned %d with no checks configured, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, forbidden := range []string{"otel", "telemetry", "collector", "4317", "4318"} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Errorf("/readyz mentions %q: %s. A readiness probe that consults telemetry "+
				"fails when telemetry fails, and an orchestrator that takes a service out "+
				"of rotation because a collector restarted is a service that stopped serving "+
				"traffic for a reason nobody can see.", forbidden, body)
		}
	}
}

// TestTheProbesAreTracedLikeEverythingElse is the small thing worth stating: a
// probe is a request, and excluding it would make a service whose only traffic is
// an orchestrator's health check show as an empty trace view.
//
// Nothing in core's schema asks for it either way. It is here because the
// alternative — a router that traces /v1 and silently skips /healthz — is the kind
// of inconsistency nobody notices until they go looking for a service that looks
// like it is down when it is up.
func TestTheProbesAreTracedLikeEverythingElse(t *testing.T) {
	handler, _ := recordingRouter(t)

	for _, probe := range []string{"/healthz", "/readyz"} {
		recorder := serve(t, handler, http.MethodGet, probe, nil)
		if len(recorder.Ended()) != 1 {
			t.Errorf("%s produced %d spans, want 1", probe, len(recorder.Ended()))
		}
	}
}

// TestTheSpanNameIsTheFleetsGrammar pins the one name in the httpapi layer.
//
// The constant is built at init and a mismatch panics, so this is not about
// catching a bad constant — it is about the constant EXISTING and being the one
// the fleet's queries expect. A rename is a breaking change for every dashboard
// in the fleet, and the place to notice is here.
func TestTheSpanNameIsTheFleetsGrammar(t *testing.T) {
	if requestSpanName != "identity.request" {
		t.Errorf("requestSpanName = %q, want identity.request. The span name is the grouping "+
			"key in every trace view in the fleet; changing it breaks every one of them, "+
			"and the collector's spanmetrics namespace is derived from it.", requestSpanName)
	}
	if !strings.HasPrefix(requestSpanName, telemetry.SpanNamePrefix+".") {
		t.Errorf("requestSpanName = %q does not start with the service prefix %q",
			requestSpanName, telemetry.SpanNamePrefix)
	}
}

// TestTheStatusClassLadderIsTheOnesTheCollectorApplies is the metric-side
// counterpart.
//
// The trace signal carries the code and the metric signal carries the CLASS, and
// the difference is cardinality rather than taste: 500 codes multiplied by every
// route is how OpenTelemetry's 2000-attribute-combination cap is reached in a
// week, and `4xx` is what a dashboard asks for.
//
// The ladder lives in this file as well as in kit's YAML, and that duplication is
// deliberate and is asserted rather than left to drift.
func TestTheStatusClassLadderIsTheOnesTheCollectorApplies(t *testing.T) {
	// Byte-identical to the `enum` in core's metrics.schema.json, and to what
	// kit's collector derives from the status code.
	for status, want := range map[int]string{
		100: "1xx", 199: "1xx",
		200: "2xx", 299: "2xx",
		301: "3xx", 399: "3xx",
		400: "4xx", 499: "4xx",
		500: "5xx", 599: "5xx",
		// Outside every class, because a status outside 100..599 is not a fact
		// about an HTTP response and the ladder must not invent one.
		0: "", 99: "", 600: "", -1: "",
	} {
		if got := statusClass(status); got != want {
			t.Errorf("statusClass(%d) = %q, want %q", status, got, want)
		}
	}
}
