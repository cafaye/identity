package httpapi

import (
	"context"
	"net/http"

	"github.com/cafaye/identity/internal/platform/id"
)

// TraceHeader is the request and response header carrying the trace id. core:
// "trace_id is always present and always matches the X-Trace-Id response header."
const TraceHeader = "X-Trace-Id"

// maxInboundTraceID caps an inbound trace id. The value is reflected into a
// response header and into a log line, so an unbounded inbound header would let
// a caller put a megabyte into both.
const maxInboundTraceID = 200

type traceIDKey struct{}

// withTraceID stores a trace id on a context. It is the single place one is
// attached, so the middleware and the tests agree on how to read it back.
func withTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, traceIDKey{}, traceID)
}

// traceIDFrom returns the trace id on ctx, or "" if there is none.
//
// It never invents one. Generating a second id here would desynchronise the
// header from the body, which is the one thing core says must not happen.
func traceIDFrom(ctx context.Context) string {
	if id, ok := ctx.Value(traceIDKey{}).(string); ok {
		return id
	}
	return ""
}

// traceMiddleware puts a trace id on every request and echoes it on every
// response, successful or not.
//
// An inbound id is reused so a trace survives a hop through guard, a load
// balancer or a proxy; anything unusable is replaced rather than rejected,
// because refusing a request because its correlation header is untidy is not a
// useful behaviour for a security boundary to have.
func traceMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		traceID := inboundTraceID(r)
		if traceID == "" {
			generated, err := id.New()
			if err != nil {
				// crypto/rand has failed, which is not a condition with a
				// per-request workaround. The id is only a correlation handle, so
				// the request continues without one rather than becoming a 500 for
				// every caller on the machine.
				next.ServeHTTP(w, r)
				return
			}
			traceID = generated.String()
		}

		// Set before the handler runs so a handler that fails without writing a
		// header still gets one, which is what makes the id quotable.
		w.Header().Set(TraceHeader, traceID)
		next.ServeHTTP(w, r.WithContext(withTraceID(r.Context(), traceID)))
	})
}

// inboundTraceID returns a usable trace id from the request, or "".
func inboundTraceID(r *http.Request) string {
	traceID := r.Header.Get(TraceHeader)
	if traceID == "" || len(traceID) > maxInboundTraceID {
		return ""
	}
	// Restricted to a conservative printable set. The value is reflected into a
	// header and a log line, and a control character there is a log-injection
	// primitive.
	for _, r := range traceID {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.', r == ':':
		default:
			return ""
		}
	}
	return traceID
}
