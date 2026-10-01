package telemetry

import (
	"context"
	"fmt"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// This file is the test-only half of the package's seams. It is a NON-test file
// on purpose: Go excludes `_test.go` from the package's own build, so a helper
// here is invisible to the production binary, while a helper in a `_test.go` file
// cannot be reached by the httpapi package's own canary test.
//
// Nothing here changes what the production path does.

// installForTest points the global tracer provider at a test provider and returns
// the function that puts the previous one back.
//
// The global is not a shortcut. It is the OpenTelemetry SDK's own design — the
// propagator and the provider are process-wide singletons by specification — and
// the canary test depends on it: the middleware resolves its tracer through
// `otel.Tracer`, so a test that installed a provider some other way would be
// asserting against a span the request path never touched.
//
// The restore is not optional bookkeeping. Tests in this package are not parallel
// and share one process, so a provider left behind by one test is a provider the
// next test exports into.
func installForTest(t *testing.T, provider *sdktrace.TracerProvider) func() {
	t.Helper()
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	return func() { otel.SetTracerProvider(previous) }
}

// startTestSpan begins a span the way a request would, so a test's span has the
// same parentage and context as the code under test's.
//
// The operation is `unit` rather than something descriptive, because a span NAME
// is a grouping key: every test span in this package sharing one name is what
// lets a test say "the one span this produced" without a name that has to be
// unique per test, and a per-test name would be a series per test.
func startTestSpan(t *testing.T) trace.Span {
	t.Helper()
	_, span := StartServer(context.Background(), nil, MustSpanName("unit"))
	return span
}

// lookupFrom is an environment lookup over a map, which is how these tests read
// configuration without mutating the process environment — the same reason
// config.Lookup exists.
func lookupFrom(env map[string]string) func(string) string {
	return func(key string) string { return env[key] }
}

// assertNever fails a test if the code path that reaches it is taken. Used where
// "this must not happen" is the property, and returning a non-nil error from a
// constructor the test expects to be skipped would otherwise look like the test
// passing.
func assertNever(what string) error { return fmt.Errorf("telemetry: %s", what) }
