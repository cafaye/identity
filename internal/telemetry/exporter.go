package telemetry

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
)

// OTLPExporter is the production Exporter: OTLP over HTTP.
//
// HTTP rather than gRPC, and the reason is that it is the address the fleet
// already agrees on. `<SERVICE>_OTEL_ENDPOINT` defaults to
// `http://otel-collector:4318`, which is the collector's HTTP receiver, and the
// Elixir and Python SDKs this fleet ships both speak OTLP/HTTP. One port, one
// ingestion point, three languages.
//
// WHAT THIS DOES NOT BUY, recorded because a reader would otherwise assume it
// does: it is NOT a way to keep gRPC out of the binary. The HTTP exporter shares
// its configuration package with the gRPC one —
//
//	$ go mod why -m google.golang.org/grpc
//	github.com/cafaye/identity/internal/telemetry
//	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp
//	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp/internal/otlpconfig
//	google.golang.org/grpc
//
// — so `grpc`, `grpc-gateway`, `genproto` and `protobuf` are in the module graph
// either way. The choice is about which port and which wire format, not about
// the dependency count. Measured on this tree rather than assumed; the obvious
// justification was available and would have been wrong.
//
// The endpoint is normalised rather than trusted. `otlptracehttp.WithEndpointURL`
// wants a URL, and every spelling of "where does telemetry go" that an operator
// will actually type is not one: a bare `host:port`, a trailing slash, a path.
// Refusing to start on a shape nobody could have meant is better than exporting
// nowhere with a log line naming a URL that parsed.
func OTLPExporter(ctx context.Context, endpoint string) (Exporter, error) {
	target, err := normaliseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	// No retry and no queue, for the reason kit's collector config states and
	// this repository holds to: a retry loop against a dead collector is a
	// goroutine waking on a timer for the life of the process, invisible in
	// every dashboard because nothing is being recorded, and a queue that
	// accepts spans and holds them is a memory leak with a telemetry-shaped
	// trigger. Losing a span is strictly better than becoming a slow service.
	//
	// The SDK's defaults are `retry_on_failure: enabled` and
	// `sending_queue: enabled`, so BOTH are stated as disabled rather than left
	// to a default that is the opposite of the fleet's rule.
	return otlptracehttp.New(ctx,
		otlptracehttp.WithEndpointURL(target),
		otlptracehttp.WithRetry(otlptracehttp.RetryConfig{Enabled: false}),
		// A bounded export, for the same reason the queue and the retry are off:
		// the collector is a local process on the compose network, and a slow
		// export is a latency bug in development caused by an observability tool.
		otlptracehttp.WithTimeout(5*time.Second),
	)
}

// normaliseEndpoint turns the shapes an operator writes into the one shape the
// exporter takes.
//
// A bare `host:port` is the most likely thing to be typed and the most likely to
// be rejected by a URL parser, because `otel-collector:4318` parses as a scheme
// of `otel-collector` and a path of `4318`. Prefixing a schemeless endpoint with
// `http://` is what makes the documented default work, and it is the difference
// between a service that exports by default and one that fails to boot by
// default.
func normaliseEndpoint(endpoint string) (string, error) {
	trimmed := strings.TrimSpace(endpoint)
	if trimmed == "" {
		return "", fmt.Errorf("telemetry: the OTLP endpoint is empty")
	}
	if !strings.Contains(trimmed, "://") {
		trimmed = "http://" + trimmed
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("telemetry: %q is not a usable OTLP endpoint: %w", endpoint, err)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("telemetry: %q has no host", endpoint)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("telemetry: %q has scheme %q; an OTLP endpoint is http or https", endpoint, parsed.Scheme)
	}
	// A trailing slash on the path is the difference between a request for `/` and
	// a request for `//v1/traces` once the exporter appends its own path.
	parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	return parsed.String(), nil
}

// compile-time proof that the OTLP exporter satisfies the seam Install takes, so
// a signature change in the SDK is caught here rather than at the first boot of
// a deployment.
var _ Exporter = (*otlptrace.Exporter)(nil)
