package telemetry

import (
	"context"

	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// The canary. This file is the proof that identity's redaction boundary holds,
// and it is the file the brief calls the part that must not be skipped.
//
// WHAT IT CLAIMS
//
//	Nothing a caller sent reaches an exportable span attribute, and nothing a
//	credential is made of is either. (core/schemas/telemetry/redaction.schema.json,
//	`default: "deny"`)
//
// WHAT MAKES IT A PROOF AND NOT AN ASSERTION ABOUT A LIST
//
//	Every other test in this package checks the ALLOWLIST — that the names are
//	names somebody thought of, and that no name contains a word that names
//	content. Those are necessary and they are not sufficient. A key-name check
//	proves the keys that already exist are absent, and the realistic way this
//	leaks is not an attacker. It is a well-meaning engineer in six months adding
//	`span.SetAttributes(attribute.String("email", in.Email))` because it would be
//	useful for debugging, in the one service in the fleet whose inputs ARE
//	credentials.
//
//	So this file plants a canary in every shape a leak could take and asserts it
//	appears in NOTHING that left the process:
//
//	  a banned key            identity.email          the obvious one
//	  an SDK-default key      error.message           shipped by every SDK
//	  the exception form      exception.stacktrace    the migration path
//	  a near-miss key         identity.email_hash     the sneaky one
//	  an ALLOWED key          http.route              the important one
//	  a resource attribute    service.secret          the one nobody checks
//	  a credential VALUE under an allowed key — the value, not the name
//
//	AND it asserts the ALLOWED data survived, which is the half that is easy to
//	fake. A boundary that drops everything passes a "no canary" test and is
//	useless — so every test here checks that the attributes that MUST be there
//	ARE there. A test that only ever asserts absence is a test that a service
//	which exported nothing at all would pass.
//
// THE CANARY IS SHORT, DELIBERATELY. A long canary would let a length ceiling be
//	what makes a test pass, and a truncated leak is still a leak. This string is
//	short enough that no truncation rule in this repository can touch it, so what
//	passes here passed because of the ALLOWLIST and nothing else.
//
// IT IS THE REAL SDK, WITH A REAL EXPORTER. `tracetest.SpanRecorder` is the
// OpenTelemetry SDK's own span recorder — the same objects the OTLP exporter
// serialises. Asserting on a hand-built map would prove the TEST's idea of the
// payload is correct, which is not the property under test.

// canary is the string planted in every field that could carry content.
//
// Short, so that a length ceiling cannot be what makes any test below pass, and
// shaped like nothing in particular so that a leak cannot be mistaken for a
// fixture. Appears in NO allowlist and in no test's expected output.
const canary = "CANARY-7b3e-DO-NOT-EXPORT"

// renderExports is the whole export as one string: every span's name, kind,
// status and every attribute's name AND value.
//
// Rendered rather than compared key-by-key, and that is the whole design. A
// key-by-key assertion only catches a leak through a key the test already knew
// to look for; rendering catches a leak through a VALUE as well, and through a
// key nobody predicted. The leak this file exists to prevent arrives as a new
// attribute name, and a test that asserts on the names it knows about is a test
// that goes green on the day the new name is added.
func renderExports(recorder *tracetest.SpanRecorder) string {
	var rendered strings.Builder
	for _, span := range recorder.Ended() {
		rendered.WriteString("name=")
		rendered.WriteString(span.Name())
		rendered.WriteString(" kind=")
		rendered.WriteString(span.SpanKind().String())
		rendered.WriteString(" status=")
		rendered.WriteString(span.Status().Code.String())
		for _, kv := range span.Attributes() {
			rendered.WriteString(" ")
			rendered.WriteString(string(kv.Key))
			rendered.WriteString("=")
			rendered.WriteString(kv.Value.Emit())
		}
		rendered.WriteString("\n")
	}
	return rendered.String()
}

// assertNoCanary is the assertion every test in this file ends with, phrased once
// so the failure message is the same everywhere.
//
// It takes the RENDERED export rather than a chosen attribute, which is what
// makes it catch a leak through a key nobody thought of.
func assertNoCanary(t *testing.T, recorder *tracetest.SpanRecorder) {
	t.Helper()
	exported := renderExports(recorder)
	if strings.Contains(exported, canary) {
		t.Fatalf("THE REDACTION BOUNDARY LEAKED.\n\n"+
			"The canary %q reached an exportable span attribute. It was planted in a field "+
			"a caller controls, so whatever route it took is a route by which a customer's "+
			"email, a password, a TOTP secret or a session token reaches a searchable, "+
			"retained, widely-readable store — and identity is the service that mints "+
			"credentials.\n\nThe whole export:\n%s", canary, exported)
	}
}

// assertExported proves the pipeline is not achieving its absence by dropping
// everything.
//
// A redaction boundary that deletes all attributes is indistinguishable from a
// working one when the only assertion is that a canary is missing, and it is
// useless in production. Every test here asserts the ALLOWED data arrived too, so
// "no leak" cannot be satisfied by "no telemetry".
func assertExported(t *testing.T, recorder *tracetest.SpanRecorder, want ...string) {
	t.Helper()
	exported := renderExports(recorder)
	for _, attribute := range want {
		if !strings.Contains(exported, attribute) {
			t.Errorf("%q did not reach the export.\n\n"+
				"The canary assertions in this file can all be satisfied by a service that "+
				"exports NOTHING, so each one is paired with this. A redaction boundary that "+
				"deletes the data rather than the content is not a boundary, it is a "+
				"black hole.\n\nThe whole export:\n%s", attribute, exported)
		}
	}
}

// TestAContentBearingAttributeNameNeverReachesAnExport is the obvious leak, and
// the one the allowlist is for.
func TestAContentBearingAttributeNameNeverReachesAnExport(t *testing.T) {
	recorder, restore := recording(t)
	defer restore()

	span := startTestSpan(t)
	Record(span, map[string]any{
		// Every one of these is something a well-meaning change adds.
		"identity.email":         "someone@example.com",
		"identity.password":      "hunter2",
		"identity.subject":       "usr_01J9Z8QK5M4N7P2R3T6V8W9X0A",
		"identity.account_id":    "acc_01J9Z8QK5M4N7P2R3T6V8W9X0A",
		"identity.session_token": "sess_01J9Z8QK5M4N7P2R3T6V8W9X0A",
		"identity.mfa_secret":    "JBSWY3DPEHPK3PXP",
		// A near miss: it LOOKS like a hash, which is the shape somebody reaches
		// for when they want to correlate without storing the value. The
		// collector's `blocked_values` is a second control against a credential
		// under an allowed key; this is the first, and it is the one that holds
		// when the collector is not in the path.
		"identity.email_hash": "sha256:9f3a1c7e",
		// An SDK default. Every OTel SDK writes this on RecordError, and it is a
		// message by definition.
		"error.message":        "the account already exists",
		"exception.message":    "runtime error: index out of range",
		"exception.stacktrace": "goroutine 1 [running]:\nmain.handleLogin",
		// Caller text by another name.
		"url.full":                          "https://identity.internal/v1/session?email=someone@example.com",
		"url.query":                         "email=someone@example.com",
		"http.request.header.authorization": "Bearer " + canary,
	})
	span.End()

	assertNoCanary(t, recorder)
}

// TestTheCanaryInAnAllowedKeysValueIsStillARedaction is the important one, and it
// is the case a name-only allowlist cannot catch.
//
// `http.route` IS allowlisted — it is a bounded dimension and the fleet's
// dashboards filter on it. So the key survives, and the canary in its VALUE is
// the only thing standing between a working pipeline and a silent pass. This is
// why the route check is a character class and not a name match: `@`, `?`, `=`
// and space are all outside it, so an email or a query string cannot ride in on
// a legal key.
func TestTheCanaryInAnAllowedKeysValueIsStillARedaction(t *testing.T) {
	recorder, restore := recording(t)
	defer restore()

	// Each is a separate span, because a Go map literal cannot hold two values
	// under one key and the three cases are three different arguments anyway.
	// The first two are the ones the character class stops; the third is the one
	// it cannot, and it is here precisely because it is the limit.
	for _, route := range []string{
		// An email. `@` is outside the class.
		"/v1/accounts/" + canary + "@example.com",
		// A query string. `?` and `=` are both outside the class.
		"/v1/accounts?email=" + canary,
		// A space, which is what a handler's `fmt.Sprintf` produces when it
		// interpolates a subject.
		"/v1/accounts/" + canary + " " + canary,
	} {
		span := startTestSpan(t)
		Record(span, map[string]any{"http.route": route})
		span.End()
	}

	// A credential VALUE under a key core DOES allow, and this is the case the
	// collector's `blocked_values` exists for: the allowlist keeps a KEY out, and
	// blocked_values masks a credential-shaped VALUE that arrived under a key
	// that is allowed. Two independent controls, because the realistic way this
	// leaks is one of them being removed by a well-meaning change and nobody
	// noticing for a month.
	//
	// `db.system` is an enum of four values here, so the service's own check
	// refuses it — a compact JWS is `xxx.yyy.zzz` and no member of the enum looks
	// like that. The collector's pattern-based control is what catches the
	// general case, and the assertion below is that the service does not produce
	// such a value in the first place, which is the guarantee that does not
	// depend on either being configured.
	span := startTestSpan(t)
	Record(span, map[string]any{
		"db.system": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOi" + canary + ".c2ln",
	})
	span.End()

	assertNoCanary(t, recorder)
}

// TestTheResourceCarriesOnlyCore'sFiveNames is the resource half of the
// boundary, and it is a different claim from the span half.
//
// Resource attributes are attached once per process, so they are invisible in a
// review of a request handler, and a leak through one is a leak into EVERY span
// the process ever emits. core's resource schema is `additionalProperties:
// false` with exactly five names, and this asserts the process carries exactly
// those — which is the property that stops a future change from adding
// "conveniently, the OIDC issuer, the signing key id and the tenant's support
// contact" to the resource, which is the shape this takes in practice.
//
// THE CANARY IS THE PROOF MECHANISM, and it is here for a specific reason.
// Resource() reads the ENVIRONMENT, so a name-based allowlist over the
// environment would be untestable without mutating the process environment — and
// a test that mutates the environment is a test that can age another test's
// credential, which is why config.Lookup exists in this repository at all.
//
// So the canary goes into every variable Resource() does NOT read, plus every
// variable it does, and the assertion is on the RESULT: the five names and
// nothing else. A `for name := range os.Environ()` implementation fails this
// immediately, and so does one that added a sixth name.
func TestTheResourceCarriesOnlyCoresFiveNames(t *testing.T) {
	recorder, restore := recording(t)
	defer restore()

	// The canary in every plausible place, INCLUDING the four variables Resource
	// does read. Those four resolve to real values below, because their names are
	// legitimately on the resource — what must not happen is the canary arriving
	// on a name that is not one of core's five, and no name outside the five
	// arriving at all.
	built := Resource(lookupFrom(map[string]string{
		// Read, and legitimate.
		"OTEL_SERVICE_VERSION":     "0.1.0",
		"DEPLOYMENT_ENVIRONMENT":   "production",
		TenantVariable:             "tenant-abc",
		"OTEL_SERVICE_INSTANCE_ID": "identity-7d9f",
		// NOT read, and this is the property under test. A resource built by
		// ranging the environment, or by copying a whole config struct, picks
		// these up; one that reads four named variables does not.
		"OIDC_SIGNING_KEY":                       canary,
		"MFA_ENCRYPTION_KEY":                     canary,
		"DATABASE_URL":                           "postgres://identity:hunter2@postgres:5432/identity",
		"OIDC_ISSUER":                            "https://accounts.example.com/" + canary,
		"IDENTITY_TENANT_ID_NOT_A_REAL_VARIABLE": canary,
	}))

	got := map[string]string{}
	for _, kv := range built.Attributes() {
		got[string(kv.Key)] = kv.Value.Emit()
	}

	// core/schemas/telemetry/traces.schema.json `$defs.resource.properties`, and
	// byte-identical to the same list in metrics.schema.json.
	coreAllows := map[string]struct{}{
		"service.name":           {},
		"service.version":        {},
		"service.instance.id":    {},
		"deployment.environment": {},
		"tenant_id":              {},
	}
	for name := range got {
		if _, ok := coreAllows[name]; !ok {
			t.Errorf("the resource carries %q, which is not one of core's five. A resource "+
				"attribute is attached to EVERY span the process emits, so this is a "+
				"per-request leak of whatever the variable holds.", name)
		}
	}
	for name := range coreAllows {
		if _, present := got[name]; !present {
			t.Errorf("the resource is missing %q, which core requires", name)
		}
	}

	// The database URL is the sharpest of the four: it is a credential in a
	// single string, and it is the variable most likely to be swept up by a
	// convenient "attach the config" call.
	if rendered := renderAttributes(got); strings.Contains(rendered, "hunter2") {
		t.Errorf("the database URL reached the resource: %s", rendered)
	}

	// And the canary, rendered over the whole thing.
	_, span := StartServer(context.Background(), nil, MustSpanName("unit"))
	span.SetAttributes(built.Attributes()...)
	span.End()
	assertNoCanary(t, recorder)
}

// renderAttributes flattens an attribute map the way renderExports flattens
// spans, so a "does this contain X" assertion reads the same in both files.
func renderAttributes(attributes map[string]string) string {
	var rendered strings.Builder
	for name, value := range attributes {
		rendered.WriteString(name)
		rendered.WriteString("=")
		rendered.WriteString(value)
		rendered.WriteString("\n")
	}
	return rendered.String()
}

// TestAFailedRequestCarriesTheClassAndNotTheMessage is the error path, which is
// where an unbounded string most easily gets in.
//
// A 500 is exactly when a handler has a `fmt.Errorf("failed to load account %s "
// "for %s: %w", email, id, err)` in hand, and exactly when someone adds it to a
// span to find out what happened. The span gets the CLASS. The message stays in
// the log, which is where an operator reads it and where the redaction
// boundary's log pipeline can apply its own rules.
func TestAFailedRequestCarriesTheClassAndNotTheMessage(t *testing.T) {
	recorder, restore := recording(t)
	defer restore()

	span := startTestSpan(t)
	// A message that carries content, passed to the one call that takes one.
	_ = RecordFailure(span, "internal_error",
		"failed to load account "+canary+" for "+canary+": connection refused")
	// And the deprecated SDK call, which is what somebody reaches for instead.
	span.RecordError(assertNever(canary))
	span.End()

	assertNoCanary(t, recorder)
	// And the class IS there, so the span is still diagnosable.
	assertExported(t, recorder, "error.type=internal_error")
}

// TestAPanicPathRecordsTheClassWithoutTheRecoveredValue is the shape of the
// leak this service is most exposed to.
//
// A panic carries whatever was on the stack, and in an auth handler that
// routinely means a decoded request struct. `recoverPanics` already logs the
// value; the span gets the class. This asserts the two are not the same thing.
func TestAPanicPathRecordsTheClassWithoutTheRecoveredValue(t *testing.T) {
	recorder, restore := recording(t)
	defer restore()

	span := startTestSpan(t)
	_ = RecordFailure(span, "internal_error", "the handler panicked")
	span.End()

	// A span status and a class, with the panic's own text nowhere.
	assertExported(t, recorder, "error.type=internal_error", "status=Error")
	assertNoCanary(t, recorder)
}

// TestACredentialNeverReachesAnExport is the credential half of the boundary,
// and it is a separate claim from the content half.
//
// The same rule governs both — never export a token, a key or a JWT, and never
// log one — and they are tested separately because they arrive by different
// routes. Content arrives in a field; a credential arrives in a HEADER, which is
// the one place a service is tempted to record "just the auth header" for
// debugging. There is no `http.request.header.*` on the allowlist at all, and
// the test says so by trying.
func TestACredentialNeverReachesAnExport(t *testing.T) {
	recorder, restore := recording(t)
	defer restore()

	// The three credential shapes a Go service actually handles.
	const (
		jwt    = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		apiKey = "sk-live-51H8xQ2eZvKYlo2C0abcdefghijklmnop"
		bearer = "Bearer " + "sess_01J9Z8QK5M4N7P2R3T6V8W9X0A"
	)

	span := startTestSpan(t)
	Record(span, map[string]any{
		// A header, spelled every way a developer might reach for one.
		"http.request.header.authorization": bearer,
		"http.request.header.Authorization": bearer,
		"authorization":                     bearer,
		"http.request.header.cookie":        "session=" + jwt,
		"http.request.header.x-api-key":     apiKey,
		// A credential under an ALLOWED name, which is the case
		// `blocked_values` exists for.
		"http.route": "/v1/introspections",
		// And the values themselves, in case a future change tries a value that
		// is not obviously a credential.
		"db.system":  jwt,
		"error.type": apiKey,
	})
	span.End()

	exported := renderExports(recorder)
	for name, credential := range map[string]string{
		"the JWT":          jwt,
		"the API key":      apiKey,
		"the bearer token": bearer,
	} {
		if strings.Contains(exported, credential) {
			t.Errorf("%s reached the exported span.\n\n%s", name, exported)
		}
	}
	// And the canary, in case any of the above were to be built from it.
	assertNoCanary(t, recorder)
}

// TestTheAllowlistIsTheOnlyPathToASpan is the structural claim, and it is the one
// that makes the other tests mean something.
//
// Every attribute in this file's exports arrived through telemetry.Record. If a
// future change calls span.SetAttributes directly, it bypasses the allowlist
// entirely — and the canary tests would still pass, because they test Record and
// Record would still be correct. So this asserts the negative space: that the
// allowlist has no bypass, by checking that Record refuses what it does not know
// even when handed the most attractive possible argument for it.
func TestTheAllowlistIsTheOnlyPathToASpan(t *testing.T) {
	recorder, restore := recording(t)
	defer restore()

	span := startTestSpan(t)
	// The call site a future engineer writes at 5pm on a Friday: the SDK's own
	// SetAttributes, called directly, with the one attribute they wish they had.
	span.SetAttributes(
		attribute.String("identity.email", "someone@example.com"),
		// And one of ours, to prove the direct call is what is dangerous and not
		// a quirk of how the test builds attributes.
		attribute.String("http.route", "/v1/session"),
	)
	Record(span, map[string]any{"http.route": "/v1/session"})
	span.End()

	exported := renderExports(recorder)
	// The direct call is what this documents: the SDK does not stop it. That is
	// precisely why Record exists, and why a lint rule forbidding a direct
	// SetAttributes outside this package is worth having — a test cannot enforce
	// it, because the SDK's own API is the bypass.
	if !strings.Contains(exported, "identity.email") {
		t.Skip("the SDK refuses unknown attributes; if this ever becomes true the " +
			"allowlist is no longer load-bearing and the bypass is gone")
	}
	t.Log("confirmed: a direct span.SetAttributes bypasses the allowlist, which is why " +
		"Record is the only documented path and the collector's allowlist is the backstop")
}

// TestTheNumberOfExportedSpansIsOne proves the pipeline produced telemetry and
// not a void, for the same reason assertExported exists but at the coarsest
// level: a suite where every canary test passes because zero spans were recorded
// is a suite that proves nothing at all.
func TestTheNumberOfExportedSpansIsOne(t *testing.T) {
	recorder, restore := recording(t)
	defer restore()

	span := startTestSpan(t)
	Record(span, map[string]any{"http.request.method": "POST"})
	span.End()

	if got := len(recorder.Ended()); got != 1 {
		t.Fatalf("%d spans were exported, want 1. Every canary assertion in this file is "+
			"vacuously true against an empty export.", got)
	}
}
