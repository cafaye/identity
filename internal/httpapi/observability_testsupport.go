package httpapi

import (
	"io"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// The test-only half of the observability layer's seams.
//
// A NON-test file on purpose, for the same reason internal/telemetry has one: Go
// excludes `_test.go` from the package's own build, so helpers here are invisible
// to the production binary, and a test that needs to observe the tracer this
// package installed has to be able to reach them.

// The recorder the observability tests read.
//
// A package variable rather than a return value threaded through every helper,
// and the reason is that the tracer provider is a PROCESS-WIDE singleton by
// OpenTelemetry's own design — the middleware resolves it through
// `otel.Tracer`, not through a parameter. Threading a recorder alongside would
// imply the tests can install one provider while the code under test uses
// another, and they cannot; that gap is exactly what makes these tests worth
// having.
var (
	recorderMu sync.Mutex
	recorder   *tracetest.SpanRecorder
)

// installProviderForTest points the global tracer provider at a recorder and
// returns the restore.
//
// The restore is registered with t.Cleanup rather than returned-and-deferred,
// because a provider left behind by one test is a provider the next test exports
// into — and these tests are not parallel, so they share one process and one
// global.
func installProviderForTest(t *testing.T, provider *sdktrace.TracerProvider) func() {
	t.Helper()
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	t.Cleanup(func() { otel.SetTracerProvider(previous) })
	return func() { otel.SetTracerProvider(previous) }
}

// installPropagationForTest sets the W3C propagator, and the reason it exists
// separately from the provider is that they are two different globals.
//
// telemetry.Install sets both, and it is the production path. A test that only
// installed a provider would leave the propagator at the SDK's no-op default, and
// every traceparent test in this file would then pass for the wrong reason: the
// span would have a fresh root context because nothing was extracting, not because
// the propagation worked. A test suite that is green because the thing it tests was
// never wired up is worse than a red one, because it reports a property that does
// not exist.
func installPropagationForTest() func() {
	previous := otel.GetTextMapPropagator()
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	return func() { otel.SetTextMapPropagator(previous) }
}

// setRecorder publishes the recorder the helpers read.
func setRecorder(r *tracetest.SpanRecorder) {
	recorderMu.Lock()
	defer recorderMu.Unlock()
	recorder = r
}

// currentRecorder returns the recorder, failing the test if there is none —
// because a helper that returned nil would turn every downstream assertion into
// a panic rather than a named failure.
func currentRecorder(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	recorderMu.Lock()
	defer recorderMu.Unlock()
	if recorder == nil {
		t.Fatal("no span recorder is installed; the test must call recordingRouter first")
	}
	return recorder
}

// discardLogger is a logger that throws everything away.
//
// The observability tests are about spans, and a logger writing to stderr makes
// the suite's output unreadable without adding a single assertion. The logging
// boundary is proved separately, in mfa_logging_canary_test.go.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// WithPanickingRouteForTest mounts a ROUTE that panics, rather than replacing the
// router.
//
// The first version of this seam replaced the whole mux, and it was wrong in a
// way the test caught immediately: a replaced router never passes through chi, so
// the request never gets a route template, and the 500 the panic produced was
// recorded against a span with no route on it. That is a test asserting a
// half-built service — the real one has a route, and the real one is what an
// operator will be reading at 3am.
//
// Replacing a route instead keeps everything the production path does: the span
// opens outside, the template is recorded inside, the panic is recovered inside
// that, and the status is read on the way out. The only difference from
// production is which handler the route points at.
func WithPanickingRouteForTest(pattern string) Option {
	return func(o *options) {
		o.panicOnRoute = pattern
	}
}

// WithParameterizedRouteForTest mounts a route whose pattern carries a path
// parameter.
//
// It exists because of the fault injection on tracedRouter, and specifically
// because a suite of fixed requests cannot tell a route template from a concrete
// path: for `GET /healthz` they are the same string, so a service recording
// `r.URL.Path` passed every assertion in the file. A parameterised pattern is the
// only request shape on which the two differ, so it is the only one on which the
// property is testable.
//
// Registered through the traced decorator like every other route, so the test is
// asserting about the production path rather than about a special case.
func WithParameterizedRouteForTest(pattern string) Option {
	return func(o *options) {
		o.parameterizedRoute = pattern
	}
}

// spanAttributes flattens one span's attributes into strings.
//
// Sorted by key and rendered as text, so an assertion reads as a list of facts
// rather than as iteration over a Go map — and so `assertNoCanary`-style
// assertions can be written against a single string.
func spanAttributes(span sdktrace.ReadOnlySpan) map[string]string {
	attributes := make(map[string]string, len(span.Attributes()))
	for _, kv := range span.Attributes() {
		attributes[string(kv.Key)] = kv.Value.Emit()
	}
	return attributes
}

// renderSpans is the whole export as one string: every span's name, kind, status
// and every attribute's name and value.
//
// Rendered rather than compared key-by-key, because a key-by-key assertion only
// catches a leak through a key the test already knew to look for. This is the
// whole reason a canary test can catch a leak through an attribute nobody
// predicted.
func renderSpans(r *tracetest.SpanRecorder) string {
	var rendered strings.Builder
	// Sorted by key. A rendered export whose order varies between runs makes a
	// failure message that differs every time, and a failure message that
	// differs every time is one nobody compares against the last one.
	spans := r.Ended()
	sort.Slice(spans, func(i, j int) bool { return spans[i].Name() < spans[j].Name() })
	for _, span := range spans {
		rendered.WriteString("name=")
		rendered.WriteString(span.Name())
		rendered.WriteString(" kind=")
		rendered.WriteString(span.SpanKind().String())
		rendered.WriteString(" status=")
		rendered.WriteString(span.Status().Code.String())
		pairs := append([]attribute.KeyValue(nil), span.Attributes()...)
		sort.Slice(pairs, func(i, j int) bool { return pairs[i].Key < pairs[j].Key })
		for _, kv := range pairs {
			rendered.WriteString(" ")
			rendered.WriteString(string(kv.Key))
			rendered.WriteString("=")
			rendered.WriteString(kv.Value.Emit())
		}
		rendered.WriteString("\n")
	}
	return rendered.String()
}

// hasAttribute reports whether any finished span carries a name with a value.
func hasAttribute(r *tracetest.SpanRecorder, name, value string) bool {
	for _, span := range r.Ended() {
		for _, kv := range span.Attributes() {
			if string(kv.Key) == name && kv.Value.Emit() == value {
				return true
			}
		}
	}
	return false
}

// itoa is strconv.Itoa under a name that reads better in an assertion table.
func itoa(v int) string { return strconv.Itoa(v) }
