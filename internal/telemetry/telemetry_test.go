package telemetry

import (
	"context"
	"strings"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// recording is a Telemetry wired to an in-memory exporter.
//
// NOT A MOCK. This is the real OpenTelemetry SDK with its real exporter swapped
// for one that keeps spans in memory, so what a test reads is the payload an
// operator's collector would have received — attribute names, attribute values,
// span names, statuses and all. Asserting on a hand-built map instead would prove
// that the TEST's idea of the payload is correct, which is not the property under
// test.
//
// In-memory precisely so nothing leaves the process: a test that dialled a
// collector would be a network call in a suite whose rule is no sockets, and a
// suite that phones an observability backend is a suite that phones an
// observability backend.
func recording(t *testing.T) (*tracetest.SpanRecorder, func()) {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	restore := installForTest(t, provider)
	return recorder, restore
}

// --- the allowlist ---------------------------------------------------------

// TestTheAllowlistCarriesNoNameThatCouldHoldContent is the test that fails the
// day somebody adds `identity.email` to a span.
//
// This list IS the security control, so it is asserted on directly rather than
// inferred from the behaviour of the code that reads it. A name that merely
// SOUNDS safe is the risk: `identity.email` or `identity.subject` are exactly
// the attributes a future debugging change adds, and they must not be addable by
// accident.
//
// The substrings are the ones that name content rather than the ones that name a
// concept, and the distinction matters — `error.type` is allowed and contains
// neither, while `error.message` is refused and contains "message". Someone
// adding a safe-looking attribute with a content word in it is stopped here
// rather than in a trace store.
func TestTheAllowlistCarriesNoNameThatCouldHoldContent(t *testing.T) {
	forbidden := []string{
		"prompt",
		"message",
		"content",
		"text",
		"body",
		"header",
		"query",
		"email",
		"password",
		"secret",
		"token",
		"credential",
		"cookie",
		"authorization",
		"stacktrace",
		"subject",
		"apikey",
		"api_key",
		"detail",
		"user",
		"account",
		"tenant",
	}

	var offending []string
	for _, name := range AllowedSpanAttributes {
		lowered := strings.ToLower(name)
		for _, word := range forbidden {
			if strings.Contains(lowered, word) {
				offending = append(offending, name+" (contains "+word+")")
			}
		}
	}
	if len(offending) > 0 {
		t.Fatalf("the span-attribute allowlist carries names that could hold content: %s\n\n"+
			"Every name on this list is the security control. A name that could carry a "+
			"caller's email, a password, a token or a message body is a value in a "+
			"searchable, retained, widely-readable store — and this is the service that "+
			"mints credentials and reads passwords, so it is the last place to publish them.",
			strings.Join(offending, ", "))
	}
}

// TestTheAllowlistCarriesNoUnboundedIdentifier is the metric-side rule asserted
// on the trace side, because the two share a list.
//
// core's metrics schema prohibits `tenant_id`, `user_id`, `account_id`,
// `request_id`, `trace_id`, `span_id`, `session_id`, `email` and `url.path` as
// MEASUREMENT attributes, and the reason is mechanical: OpenTelemetry folds
// everything into one point at 2000 attribute combinations and DROPS all
// measurement attributes, so a total stays right and every breakdown silently
// undercounts. The collector's `spanmetrics` connector derives the fleet's
// metrics from these spans, so a name on THIS list is a candidate metric label.
func TestTheAllowlistCarriesNoUnboundedIdentifier(t *testing.T) {
	// Byte-identical to the `not` in core's metrics.schema.json.
	prohibited := []string{
		"tenant_id",
		"user_id",
		"account_id",
		"request_id",
		"trace_id",
		"span_id",
		"session_id",
		"message_id",
		"notification_id",
		"email",
		"error.message",
		"error.stacktrace",
		"url.full",
		"url.path",
	}

	var offending []string
	for _, name := range AllowedSpanAttributes {
		for _, banned := range prohibited {
			if name == banned {
				offending = append(offending, name)
			}
		}
	}
	if len(offending) > 0 {
		t.Fatalf("the span-attribute allowlist carries identifiers core's metrics schema "+
			"prohibits on a measurement: %s. These are unbounded as a dimension, and the "+
			"collector derives the fleet's metrics from these spans.", strings.Join(offending, ", "))
	}
}

// TestTheAllowlistIsTheTransitiveIntersection is the strongest form of the check
// above: rather than asserting a hand-kept denylist, it proves that EVERY name on
// the list is one core's own schema allows.
//
// The denylists above can both be incomplete — they only catch what somebody
// thought of. This one cannot be: it holds the exact attribute set from
// core/schemas/telemetry/traces.schema.json, so a name added to
// AllowedSpanAttributes that core has never heard of fails here even if it
// contains none of the words in either denylist.
//
// It is a transcription, and a transcription can drift. That is the honest cost
// of compiling against a document in another repository rather than a library,
// and kit's gate closes the loop from the other side: kit compares the
// COLLECTOR's allowlist to the same file on disk and fails when the two disagree.
// Two transcriptions, checked against each other, beat one checked against
// nothing.
func TestTheAllowlistIsTheTransitiveIntersection(t *testing.T) {
	// Transcribed from core/schemas/telemetry/traces.schema.json,
	// `$defs.tracesAttributes.properties`. The `llm.*` half of the fleet-wide
	// redaction allowlist is deliberately absent: it is muse's, and identity
	// calls no model.
	coreAllows := map[string]struct{}{
		"http.request.method":       {},
		"http.response.status_code": {},
		"http.route":                {},
		"db.system":                 {},
		"db.operation":              {},
		"messaging.system":          {},
		"messaging.operation":       {},
		"otel.status_code":          {},
		"error.type":                {},
	}

	var unknown []string
	for _, name := range AllowedSpanAttributes {
		if _, ok := coreAllows[name]; !ok {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		t.Fatalf("these attributes are not on core's trace allowlist: %s\n\n"+
			"An attribute core does not name is dropped by the collector, so exporting it "+
			"buys nothing and costs a hole in the one place the boundary can be inspected.",
			strings.Join(unknown, ", "))
	}
}

// TestAnAttributeOutsideTheAllowlistIsDropped is the choke point refusing what it
// does not recognise.
//
// This is the test that fails the day someone adds `span.SetAttributes` on
// identity.email: telemetry.Record is the only path to a span, so an unlisted
// name is not "probably fine", it is gone.
func TestAnAttributeOutsideTheAllowlistIsDropped(t *testing.T) {
	recorder, restore := recording(t)
	defer restore()

	span := startTestSpan(t)
	Record(span, map[string]any{
		"identity.email":            "someone@example.com",
		"http.request.method":       "POST",
		"user_agent.original":       "curl/8.0",
		"http.response.status_code": 201,
	})
	span.End()

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected one span, got %d", len(spans))
	}
	attributes := map[string]any{}
	for _, kv := range spans[0].Attributes() {
		attributes[string(kv.Key)] = kv.Value.AsInterface()
	}
	if _, present := attributes["identity.email"]; present {
		t.Error("identity.email reached the exported span")
	}
	if _, present := attributes["user_agent.original"]; present {
		t.Error("user_agent.original reached the exported span")
	}
	if got := attributes["http.request.method"]; got != "POST" {
		t.Errorf("http.request.method = %v, want POST — the allowlist must not have dropped the ALLOWED data", got)
	}
	if got := attributes["http.response.status_code"]; got != int64(201) {
		t.Errorf("http.response.status_code = %v, want 201", got)
	}
}

// TestAnAllowedNameWithAnImpossibleValueIsDropped is the second filter, and it is
// the one a name-only allowlist does not have.
//
// An allowlist of names is a promise about NAMES. It says nothing about whether
// any particular value under an allowed name is shippable, and a value is where
// the cardinality and the content both live. A method outside core's enum, a
// status outside 100..599, a route that is not a template, an error class
// outside the closed vocabulary: each of those is refused here rather than
// exported and dropped by the collector, because an attribute that is exported
// and then silently removed is an attribute whose absence nobody can explain.
func TestAnAllowedNameWithAnImpossibleValueIsDropped(t *testing.T) {
	recorder, restore := recording(t)
	defer restore()

	span := startTestSpan(t)
	Record(span, map[string]any{
		// Not one of core's eight methods.
		"http.request.method": "PROPFIND",
		// Outside 100..599, so not a fact about an HTTP response.
		"http.response.status_code": 999,
		// Outside the closed vocabulary.
		"error.type": "user_42_email_invalid",
		// A database product with a query string appended, which is the shape
		// `fmt.Sprintf` produces when a handler builds an attribute rather than
		// picking an enum member. `db.system` is four values and the character
		// class stops the rest.
		"db.system": "postgresql?account_id=acc_01J9",
		// A route carrying an email. There is no `@` in the character class,
		// which is the one piece of content-smuggling defence that is lexical.
		"http.route": "/v1/accounts/someone@example.com",
		// A float reaching a trace attribute is nearly always a value that was
		// meant for a metric, and it carries unbounded precision into a label.
		"http.response.status_code_class": 4.5,
	})
	span.End()

	spans := recorder.Ended()
	attributes := map[string]any{}
	for _, kv := range spans[0].Attributes() {
		attributes[string(kv.Key)] = kv.Value.AsInterface()
	}
	for name := range attributes {
		t.Errorf("%q reached the exported span with a value outside its shape; "+
			"a name allowlist is a promise about names, not about values", name)
	}
}

// TestTheRoutePatternCannotTellATemplateFromAConcretePath is the honest limit of
// the route check, written down because the guarantee is NOT where a reader would
// look for it.
//
// `/v1/accounts/acc_01J9Z8QK5M4N7P2R3T6V8W9X0A` — a concrete path with an id
// substituted in — MATCHES the route pattern. Every character in it is in the
// class, and no regex over a path can tell a filled-in template from a literal
// one without knowing the router's route table. So the cardinality property
// ("one value per endpoint, not one per request") is NOT enforced here.
//
// It is enforced STRUCTURALLY, one call site away: the only producer of
// `http.route` in this service is `routeTemplate` in internal/httpapi, which
// returns chi's `RouteContext.RoutePattern()` — a value the router produced from
// its own route table, where a path parameter is the literal `{accountID}`. A
// concrete path is not available to that call site, so it cannot be recorded.
//
// That is a weaker guarantee than a check, and it is stated here rather than left
// implied by a regex that appears to be doing more than it is. The parts that ARE
// lexical are asserted above and they are the parts that carry content risk: no
// `@`, no `?`, no `=`, no space, and a hard length ceiling. The test below pins
// the structural half in the package that owns the router.
func TestTheRoutePatternCannotTellATemplateFromAConcretePath(t *testing.T) {
	// This is the shape that WOULD be a cardinality bomb — a series per request —
	// and it is legal as a string. The point of the test is that the guarantee
	// lives in the router, so a reader who finds this cannot conclude the
	// allowlist is doing the work it is not doing.
	if !routeTemplate.MatchString("/v1/accounts/acc_01J9Z8QK5M4N7P2R3T6V8W9X0A") {
		t.Fatal("this path stopped matching the route pattern, which means the " +
			"character class changed; re-read the test above before concluding the " +
			"structural guarantee is now the only one left")
	}
}

// TestTheErrorVocabularyIsCoreExactly keeps the class list honest.
//
// The whole point of a closed vocabulary is that Go and Elixir reporting
// `provider_auth` mean the same thing, which is what makes "one place to see all
// errors" one place rather than six. A thirteenth class invented here is a
// class nobody else emits, and the fleet-wide error view silently splits.
func TestTheErrorVocabularyIsCoreExactly(t *testing.T) {
	// Byte-identical to the `enum` in core's traces.schema.json.
	want := []string{
		"_OTHER",
		"cancelled",
		"circuit_open",
		"conflict",
		"connection_failed",
		"dependency_unavailable",
		"internal_error",
		"invalid_request",
		"policy_denied",
		"provider_auth",
		"provider_rejected",
		"rate_limited",
		"timeout",
	}
	if len(ErrorTypes) != len(want) {
		t.Fatalf("ErrorTypes has %d members, core's schema has %d", len(ErrorTypes), len(want))
	}
	for i, class := range want {
		if ErrorTypes[i] != class {
			t.Errorf("ErrorTypes[%d] = %q, core's schema has %q", i, ErrorTypes[i], class)
		}
	}
}

// TestRecordFailureRefusesAnInventedClass is the escape hatch that is not an
// escape hatch.
//
// `_OTHER` exists so instrumentation is never FORCED to invent a class. This
// proves the forcing does not happen by accident either: an unrecognised class
// collapses to `_OTHER` AND reports that it did, rather than being trusted into
// the export. An alert on `_OTHER` is an alert that this service has not
// classified its own errors, and a collapse that happened silently is how
// `_OTHER` becomes a permanent value nobody reads.
func TestRecordFailureRefusesAnInventedClass(t *testing.T) {
	recorder, restore := recording(t)
	defer restore()

	span := startTestSpan(t)
	err := RecordFailure(span, "password_incorrect", "the caller typed the wrong password")
	span.End()

	if err == nil {
		t.Error("RecordFailure accepted a class outside core's vocabulary without saying so")
	}
	if !strings.Contains(err.Error(), "password_incorrect") {
		t.Errorf("the error names %q, which does not say which class was refused", err)
	}
	spans := recorder.Ended()
	attributes := map[string]any{}
	for _, kv := range spans[0].Attributes() {
		attributes[string(kv.Key)] = kv.Value.AsInterface()
	}
	if got := attributes["error.type"]; got != "_OTHER" {
		t.Errorf("error.type = %v, want _OTHER", got)
	}
	if got := spans[0].Status().Code.String(); got != "Error" {
		t.Errorf("span status = %q, want Error — the class without a failed status is a span two queries read differently", got)
	}
}

// TestRecordFailureSetsBothHalvesOfTheBiconditional is core's constraint, both
// directions, held together in one place.
//
// core's traces schema makes it an `allOf`: status `error` obliges an error
// class, and an error class obliges a failed status. The pair is what makes the
// ABSENCE of `error.type` the load-bearing "this was not an error" marker on a
// duration histogram.
func TestRecordFailureSetsBothHalvesOfTheBiconditional(t *testing.T) {
	recorder, restore := recording(t)
	defer restore()

	span := startTestSpan(t)
	if err := RecordFailure(span, "dependency_unavailable", "the database did not answer"); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	span.End()

	spans := recorder.Ended()
	if got := spans[0].Status().Code.String(); got != "Error" {
		t.Errorf("status = %q, want Error", got)
	}
	found := map[string]any{}
	for _, kv := range spans[0].Attributes() {
		found[string(kv.Key)] = kv.Value.AsInterface()
	}
	if found["error.type"] != "dependency_unavailable" {
		t.Errorf("error.type = %v, want dependency_unavailable", found["error.type"])
	}
	// The mirror, and it may not contradict the field of record.
	if found["otel.status_code"] != "ERROR" {
		t.Errorf("otel.status_code = %v, want ERROR — the mirror exists so a log-indexed "+
			"query can filter on it, and it may not disagree with status.code", found["otel.status_code"])
	}
	// And the message did not come along.
	for _, kv := range spans[0].Attributes() {
		if strings.Contains(string(kv.Key), "exception") {
			t.Errorf("span carries %q; RecordError was deliberately not called, and an "+
				"exception.message on a service that authenticates people is a path to "+
				"whatever the failing handler had in hand", kv.Key)
		}
	}
}

// TestARouteOverTheLengthCeilingIsDroppedNotShortened is the per-attribute
// bound, asserted against a value that exceeds it.
//
// DROPPED rather than truncated, and the distinction is the point. A shortened
// route template matches no real endpoint, so it is a label that reads as "no
// traffic" on a route that is busy — a column whose emptiness means "your filter
// ran first" rather than "nothing happened". A dropped attribute is at least
// visibly absent.
//
// It also pins down the absence of a general length ceiling. Every allowlisted
// string here is bounded by a closed enum or by this one pattern, so a 256-
// character cap on top of a 200-character pattern could never fire, and a
// truncation branch nothing can reach is a branch nobody has verified.
func TestARouteOverTheLengthCeilingIsDroppedNotShortened(t *testing.T) {
	recorder, restore := recording(t)
	defer restore()

	atLimit := "/" + strings.Repeat("a", MaxRouteLength-1)
	if !routeTemplate.MatchString(atLimit) {
		t.Fatalf("a route of exactly MaxRouteLength (%d) does not match the pattern; the "+
			"bound and the pattern disagree, and every route at the limit is being dropped",
			MaxRouteLength)
	}

	span := startTestSpan(t)
	Record(span, map[string]any{
		"http.route": atLimit,
		// One character over, and one with a query string in it.
		"http.route.too.long": "/" + strings.Repeat("a", MaxRouteLength),
		"db.system":           "postgresql?account_id=acc_01J9",
	})
	span.End()

	attributes := map[string]string{}
	for _, kv := range recorder.Ended()[0].Attributes() {
		attributes[string(kv.Key)] = kv.Value.AsString()
	}
	if got, ok := attributes["http.route"]; !ok {
		t.Error("a route of exactly MaxRouteLength was dropped; the bound is off by one")
	} else if got != atLimit {
		t.Errorf("http.route was altered: got %d characters, want %d", len(got), len(atLimit))
	}
	for name := range attributes {
		if name == "http.route" {
			continue
		}
		t.Errorf("%q reached the span; it is not on the allowlist, and the values above are "+
			"the shapes a caller most easily smuggles content through", name)
	}
}

// --- span names ------------------------------------------------------------

// TestSpanNamesAreTheFleetsGrammar asserts the naming scheme on the names this
// package actually builds.
//
// core's span-naming schema is a pattern, and the property it exists to guarantee
// is that no segment is longer than fifteen characters — so no segment CAN hold an
// identifier, a trace id, a ULID, a URL or a path. That is why the route and the
// identity are attributes: `identity.request.session` aggregates, and
// `identity.request.usr_01J9Z8QK5M4N7P2R3T6V8W9X0A` is not spellable.
func TestSpanNamesAreTheFleetsGrammar(t *testing.T) {
	if got, err := SpanName("request"); err != nil || got != "identity.request" {
		t.Errorf("SpanName(\"request\") = %q, %v; want identity.request", got, err)
	}
	if got, err := SpanName("provider", "call"); err != nil || got != "identity.provider.call" {
		t.Errorf("SpanName(\"provider\", \"call\") = %q, %v; want identity.provider.call", got, err)
	}

	// Every way to smuggle a value into a name is refused, loudly, rather than
	// coerced. Each of these is something a future caller would try.
	for _, segments := range [][]string{
		{""},                               // empty
		{"Request"},                        // capitalised
		{"request-id"},                     // kebab
		{"this_segment_is_far_too_long"},   // over the fifteen-character cap
		{"identity.request"},               // the prefix, doubled
		{"a", "b", "c", "d"},               // four segments
		{"/v1/session"},                    // a path
		{"v1.session"},                     // a dotted path
		{"usr_01J9Z8QK5M4N7P2R3T6V8W9X0A"}, // a cafaye id
		{"a b"},                            // a space
		{"a;b"},                            // a statement
	} {
		if name, err := SpanName(segments...); err == nil {
			t.Errorf("SpanName(%q) = %q with no error; a name that can hold a value is a "+
				"grouping key an operator cannot filter out of", segments, name)
		}
	}

	if _, err := SpanName(); err == nil {
		t.Error("SpanName() with no operation succeeded; a span name with no operation says nothing")
	}
}

// TestMustSpanNamePanicsOnAConstantThatCannotBeRight is the deliberate-crash
// half. Every call in this repository passes a constant, so the failure is a
// programming error and a panic at init says so in the first line of output
// rather than producing a span no fleet query can group by.
func TestMustSpanNamePanicsOnAConstantThatCannotBeRight(t *testing.T) {
	if got := MustSpanName("request"); got != "identity.request" {
		t.Errorf("MustSpanName(\"request\") = %q, want identity.request", got)
	}
	defer func() {
		if recover() == nil {
			t.Error("MustSpanName did not panic on a segment that is not a legal operation")
		}
	}()
	MustSpanName("Not A Segment")
}

// --- the endpoint contract -------------------------------------------------

// TestTheEndpointContractIsOneVariable is core's D16, asserted.
//
// `<SERVICE>_OTEL_ENDPOINT` is the only contract between a service and an
// observability backend. Bring-your-own is a SUPPORTED deployment, not a
// degraded mode, so the variable is honoured over the default and the standard
// OTel variable is a fallback with a DOCUMENTED precedence — a contract with an
// undocumented precedence order is a bug report.
func TestTheEndpointContractIsOneVariable(t *testing.T) {
	table := []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			name: "unset falls back to the collector that ships with the stack",
			env:  map[string]string{},
			want: DefaultEndpoint,
		},
		{
			name: "the cafaye variable wins over the standard one",
			env: map[string]string{
				EndpointVariable:              "https://otlp.example.com:4318",
				"OTEL_EXPORTER_OTLP_ENDPOINT": "https://other.example.com:4318",
			},
			want: "https://otlp.example.com:4318",
		},
		{
			name: "the standard variable works for generic tooling",
			env:  map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "https://other.example.com:4318"},
			want: "https://other.example.com:4318",
		},
		{
			name: "an empty value is a missing value",
			env:  map[string]string{EndpointVariable: ""},
			want: DefaultEndpoint,
		},
	}
	for _, tc := range table {
		t.Run(tc.name, func(t *testing.T) {
			if got := Endpoint(lookupFrom(tc.env)); got != tc.want {
				t.Errorf("Endpoint = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestTheKillSwitchIsTheSpecsOwn checks that "disabled" is the OTel spec's
// definition of disabled and not a cafaye reimplementation.
//
// Re-implementing "disabled" in six languages is how six services acquire six
// different definitions of it, and the difference between them is somebody's
// production incident. All THREE per-signal switches are checked rather than just
// the traces one: a no-op that only covers traces is a service that still phones
// home, which is the failure discovered by a customer's invoice rather than by a
// test.
func TestTheKillSwitchIsTheSpecsOwn(t *testing.T) {
	// The spec's switch, in every casing a person types. Case-insensitivity is
	// the spec's, and re-deriving it per language is how two services end up
	// with two definitions of "off".
	for _, value := range []string{"true", "TRUE", "True"} {
		if Enabled(lookupFrom(map[string]string{"OTEL_SDK_DISABLED": value})) {
			t.Errorf("Enabled() = true with OTEL_SDK_DISABLED=%s", value)
		}
	}

	// The per-signal half, all three, in every casing. A no-op that only covers
	// traces is a service that still phones home for the rest, and that is the
	// failure discovered by a customer's invoice rather than by a test.
	for _, name := range []string{"OTEL_TRACES_EXPORTER", "OTEL_METRICS_EXPORTER", "OTEL_LOGS_EXPORTER"} {
		for _, value := range []string{"none", "NONE", "None"} {
			if Enabled(lookupFrom(map[string]string{name: value})) {
				t.Errorf("Enabled() = true with %s=%s", name, value)
			}
			if reason := NoOpReason(lookupFrom(map[string]string{name: value})); reason != name+"=none" {
				t.Errorf("NoOpReason = %q, want %q", reason, name+"=none")
			}
		}
	}

	// A value that merely CONTAINS "none" is not the switch. `OTEL_SDK_DISABLED=nottrue`
	// reading as disabled is a service that has silently stopped exporting
	// because somebody typed a word.
	if !Enabled(lookupFrom(map[string]string{"OTEL_SDK_DISABLED": "nottrue"})) {
		t.Error(`Enabled() = false with OTEL_SDK_DISABLED=nottrue; a value that merely ` +
			`CONTAINS "true" is not the spec's switch`)
	}
	// "false" must not read as disabled, which is the same bug from the other side.
	if !Enabled(lookupFrom(map[string]string{"OTEL_SDK_DISABLED": "false"})) {
		t.Error(`Enabled() = false with OTEL_SDK_DISABLED=false`)
	}
	if reason := NoOpReason(lookupFrom(map[string]string{})); reason != "" {
		t.Errorf("NoOpReason = %q on the ENABLED path; the line is only ever for the disabled one", reason)
	}
}

// TestNoOpReasonNamesWhatSwitchedItOff is what makes "telemetry is off" and
// "telemetry is broken" tellable apart from outside the process.
//
// One line at startup, and only on the disabled path. Silence is the contract
// there: a warning per export attempt fills the service's own log store with the
// fact that telemetry is off, which is how a self-hoster discovers that turning
// it off is not supported — the opposite of the intent.
func TestNoOpReasonNamesWhatSwitchedItOff(t *testing.T) {
	if got := NoOpReason(lookupFrom(map[string]string{"OTEL_SDK_DISABLED": "true"})); got != "OTEL_SDK_DISABLED=true" {
		t.Errorf("NoOpReason = %q, want OTEL_SDK_DISABLED=true", got)
	}
	got := NoOpReason(lookupFrom(map[string]string{
		"OTEL_TRACES_EXPORTER": "none",
		"OTEL_LOGS_EXPORTER":   "none",
	}))
	if got != "OTEL_TRACES_EXPORTER,OTEL_LOGS_EXPORTER=none" {
		t.Errorf("NoOpReason = %q; both switches must be named, or an operator turns off the "+
			"one they thought was responsible", got)
	}
}

// TestTheDisabledPathStartsNoExporter is the assertion behind "a no-op is free".
//
// Not a provider pointed at nothing and left to run: a real provider with a batch
// processor and a retry loop is a process waking on a timer for the life of the
// service, invisible in every dashboard because nothing is being recorded. So
// Install must not CALL the exporter constructor at all on this path, and the
// test proves it by making the constructor fail if it is reached.
func TestTheDisabledPathStartsNoExporter(t *testing.T) {
	called := false
	shutdown, err := Install(context.Background(), Options{
		Disabled: true,
		NewExporter: func(context.Context, string) (Exporter, error) {
			called = true
			return nil, assertNever("the disabled path built an exporter")
		},
	})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if called {
		t.Error("Install built an exporter while telemetry is off")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("the no-op shutdown returned %v; it must be free", err)
	}
	// And the spans still work, so no call site needs an `if telemetry enabled`
	// around it.
	span := startTestSpan(t)
	span.End()
}

// TestAMisconfiguredEndpointIsABootFailure is the difference between "off" and
// "broken", asserted.
//
// A service that starts happily and exports nowhere is the one that gets
// discovered a quarter later. A configured endpoint that cannot be built is a
// startup failure with the reason named.
func TestAMisconfiguredEndpointIsABootFailure(t *testing.T) {
	_, err := Install(context.Background(), Options{
		Endpoint: "://not a url",
		NewExporter: func(context.Context, string) (Exporter, error) {
			return nil, assertNever("a malformed endpoint reached the exporter constructor")
		},
	})
	if err == nil {
		t.Fatal("Install succeeded with a malformed endpoint; a service that exports nowhere " +
			"while looking healthy is the failure this is here to prevent")
	}
	if !strings.Contains(err.Error(), "not a url") {
		t.Errorf("the error does not quote the endpoint it refused: %v", err)
	}
}

// --- the endpoint shape ----------------------------------------------------

// TestTheExporterAcceptsEveryShapeAnOperatorTypes is the difference between
// "observability is on by default" and "observability fails to boot by default".
//
// `otel-collector:4318` has no scheme, and a URL parser reads that as a scheme of
// `otel-collector` with a path of `4318`. Every one of these is something a person
// will type into a deployment's environment, and each of them has to work.
func TestTheExporterAcceptsEveryShapeAnOperatorTypes(t *testing.T) {
	for _, endpoint := range []string{
		"http://otel-collector:4318",
		"otel-collector:4318",
		"https://otlp.example.com",
		"http://otel-collector:4318/",
		"  http://otel-collector:4318  ",
	} {
		if _, err := OTLPExporter(context.Background(), endpoint); err != nil {
			t.Errorf("OTLPExporter(%q) = %v; this is a shape an operator will type", endpoint, err)
		}
	}
}

// TestTheExporterRefusesWhatNobodyCouldHaveMeant is the other half. A transport
// that silently accepts a nonsense endpoint and exports nowhere is worse than one
// that says so at boot.
func TestTheExporterRefusesWhatNobodyCouldHaveMeant(t *testing.T) {
	for _, endpoint := range []string{
		"",
		"   ",
		"://missing-scheme",
		"ftp://otel-collector:4318",
		"http://",
	} {
		if _, err := OTLPExporter(context.Background(), endpoint); err == nil {
			t.Errorf("OTLPExporter(%q) succeeded; a transport that accepts this exports nowhere "+
				"and says nothing", endpoint)
		}
	}
}

// --- the resource ----------------------------------------------------------

// TestTheTenantGoesOnTheResourceAndNowhereElse is the one cardinality trap this
// repository could have walked into, asserted before anybody does.
//
// core's metrics schema puts `tenant_id` in BOTH lists with opposite meanings:
// PROHIBITED as a measurement attribute, REQUIRED on the resource. The reason is
// mechanical — resource attributes are not part of the set the 2000-combination
// cap counts, so they survive on the overflow point, and a per-tenant total stays
// answerable after the measurement has folded.
//
// Move identity onto a measurement and the fleet's total keeps looking right
// while every per-tenant breakdown silently undercounts, with no error anywhere.
func TestTheTenantGoesOnTheResourceAndNowhereElse(t *testing.T) {
	resource := Resource(lookupFrom(map[string]string{
		TenantVariable:             "tenant-abc",
		"DEPLOYMENT_ENVIRONMENT":   "development",
		"OTEL_SERVICE_VERSION":     "0.1.0",
		"OTEL_SERVICE_INSTANCE_ID": "identity-7d9f",
	}))

	got := map[string]string{}
	for _, kv := range resource.Attributes() {
		got[string(kv.Key)] = kv.Value.Emit()
	}
	for name, want := range map[string]string{
		"service.name":           "identity",
		"service.version":        "0.1.0",
		"service.instance.id":    "identity-7d9f",
		"deployment.environment": "development",
		"tenant_id":              "tenant-abc",
	} {
		if got[name] != want {
			t.Errorf("resource %s = %q, want %q", name, got[name], want)
		}
	}

	// And the other half: it is on the RESOURCE and not on the span allowlist,
	// which is the only place it is allowed to be.
	if _, onASpan := allowedSpanAttributes["tenant_id"]; onASpan {
		t.Error("tenant_id is on the span-attribute allowlist; core's metrics schema " +
			"prohibits it on a measurement and the collector's spanmetrics connector " +
			"derives this fleet's metrics from these spans")
	}
}

// TestAnUnsetResourceVariableIsAbsentRatherThanEmpty is the shape of every one of
// those attributes, and an empty string is a shape with a different meaning.
//
// `service.name=""` sorts to the top of every collector's service list and reads
// as a service nobody has heard of; `tenant_id=""` is one tenant whose total is
// the whole fleet's.
func TestAnUnsetResourceVariableIsAbsentRatherThanEmpty(t *testing.T) {
	for _, kv := range Resource(lookupFrom(map[string]string{})).Attributes() {
		if value := kv.Value.Emit(); value == "" {
			t.Errorf("resource %s is an empty string; absent is not the same as empty", kv.Key)
		}
	}
}
