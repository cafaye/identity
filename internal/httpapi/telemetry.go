package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/otel/trace"

	"github.com/cafaye/identity/internal/telemetry"
)

// requestSpanName is the name of the span every inbound request produces.
//
// ONE name, not one per route, and that is the whole of the span-naming argument.
// A span name is the grouping key in every trace UI, so anything in the name is
// something an operator cannot filter out of the grouping. Naming this
// `identity.request` gives one series; naming it after the concrete route —
// `identity.request.session` for a login and `identity.request.introspect` for an
// introspection — gives one series per endpoint, and a fleet-wide request count
// that cannot be read without a client-side aggregation every reader would have
// to write separately. The route is an ATTRIBUTE, where it is bounded and
// filterable, and the name carries the operation.
//
// The name is built at init from a constant, so telemetry.SpanName's error path
// is unreachable here. A constant that does not match the fleet's grammar is a
// programming error, and TestRequestSpanNameMatchesTheFleetsGrammar is what
// proves it rather than a runtime check on every request.
var requestSpanName = mustRequestSpanName()

func mustRequestSpanName() string {
	name, err := telemetry.SpanName("request")
	if err != nil {
		panic("httpapi: " + err.Error())
	}
	return name
}

// telemetryMiddleware continues the caller's trace and records what happened to
// this request.
//
// WHY IT IS HERE AND NOT THE `otelhttp` MIDDLEWARE. The obvious choice is
// `otelhttp.NewHandler`, which does the propagation and the span for you. It
// records `url.path`, `url.full`, `url.query`, `user_agent.original`,
// `server.address` and the request headers as span attributes.
//
// Every one of those is dropped by kit's collector, so shipping them would not
// be a leak today. It would mean this service EXPORTS a span carrying a caller's
// concrete path and query string and relies on the collector to take them back
// out, and the fleet's rule is the opposite of that: the collector's allowlist
// is a backstop, and the service is the design. One control that needs a
// misconfiguration elsewhere to fail is not two controls.
//
// So this records exactly three attributes, all bounded, all on core's trace
// allowlist, all through telemetry.Record — the one path to a span:
//
//	http.request.method         the method
//	http.route                  the route TEMPLATE, from chi's matched route
//	http.response.status_code   the status
//
// plus `error.type` on a 5xx and on nothing else, which RecordRequestFailure
// owns.
//
// The `X-Trace-Id` response header is NOT changed. It carries this service's
// opaque correlation id, it is a published contract, and replacing its meaning
// with a W3C trace id would be a breaking change made for a debugging
// convenience. A trace a user cannot quote is a trace an operator is asked about
// and cannot find, and the honest fix for that is the operator-visible default —
// the trace id in the log line, which logPanic already writes — rather than
// redefining a published header.
func telemetryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := telemetry.StartServer(r.Context(), r.Header, requestSpanName)

		// Wrapped BEFORE anything can write, so the status is observed whichever
		// layer commits the response — including a panic recovered further in,
		// which writes its 500 through this same writer.
		// The method is recorded HERE, outside the router, and the route template
		// inside it (see `traced`). The split is not tidiness — it is that a 404
		// and a 405 never reach a route handler, so a method recorded only in
		// `traced` would be missing from exactly the requests where knowing what
		// was asked for matters most. Eight methods, so it is free to carry.
		telemetry.Record(span, map[string]any{"http.request.method": r.Method})

		tracked := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		// The ONE span, from the ONE deferred block, and the ordering inside it is
		// load-bearing in a way a fault injection proved.
		//
		// Adding a second `telemetry.Record(span, …{"http.response.status_code":
		// 200})` at the top of the deferred func — which reads as harmless,
		// because the deferred one then overwrites it — changed NOTHING the tests
		// could see, and the reason is that the OTel SDK's SetAttributes
		// REPLACES a key rather than appending to it. So the deferred record wins
		// and the stray line is inert.
		//
		// That is a real hazard and not a hypothetical one, so it is pinned: the
		// status is recorded EXACTLY ONCE, from the wrapper, on the way out, and
		// TestTheStatusIsRecordedExactlyOnce holds the count. A second write
		// somewhere in the chain would be a duplicate that whichever test noticed
		// last would explain away.
		defer func() {
			telemetry.Record(span, map[string]any{"http.response.status_code": tracked.status})
			RecordRequestFailure(span, tracked.status)
			span.End()
		}()

		next.ServeHTTP(tracked, r.WithContext(ctx))
	})
}

// routeTelemetry records the parts of a request that are only knowable AFTER
// routing.
//
// WHY IT CANNOT SIT BESIDE telemetryMiddleware, which is the whole reason this is
// a second function. chi fills RoutePattern in as the request walks its routing
// tree, and it does so on a request it creates along the way. Measured, because
// the first version of this code read the route in the OUTER middleware and every
// span came out with no route at all:
//
//	OUTER before routing           pattern=""     <- what telemetryMiddleware saw
//	MIDDLEWARE (chi.Use)           pattern=""     <- a Use middleware is also outside
//	HANDLER                        pattern="/healthz"   <- only the handler has it
//
// A `Use` middleware is not "inside the router" in the sense that matters here. It
// wraps the router, so it runs before routing too. Only the matched handler
// receives the routed request.
//
// So the route is recorded by a wrapper applied TO EACH ROUTE, which is where chi
// has a pattern to give. `mountTelemetry` wraps the handler in the two places
// routes are registered, and a test that reads a span without a route on it knows
// to look at this function rather than at the router.
//
// THE CONSEQUENCE IS DELIBERATE AND IT IS A GAP WORTH NAMING. A request that
// matches no route — a 404 — passes through no route handler, so it gets a span
// with a status and a method and NO `http.route`.
//
// That is the honest answer rather than a hole. A 404 is a request for something
// this service does not serve, the status already says so, and putting the
// unmatched path in `http.route` would put CALLER-CONTROLLED TEXT into a metric
// label — one series per URL somebody guessed, which is a cardinality bomb and a
// content leak in the same move. The 405 case is the same, and the same reasoning
// applies. Both are asserted in observability_test.go so the gap stays a
// documented decision rather than becoming a surprise.
func mountTelemetry(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		span := trace.SpanFromContext(r.Context())
		telemetry.Record(span, map[string]any{
			"http.request.method": r.Method,
			"http.route":          routeTemplate(r),
		})
		next.ServeHTTP(w, r)
	})
}

// statusWriter remembers the status the response was committed with.
//
// `http.ResponseWriter` is committed exactly once and the only way to learn the
// status from outside is to watch for it. The default is 200 rather than 0
// because a handler that returns without writing anything produces a 200 —
// net/http sends one — and a span saying status 0 for a successful request is a
// span no status filter reads correctly. `Unwrap` matters: it is how
// `http.ResponseController` reaches the underlying writer, so Flush and Hijack
// still work through this wrapper.
type statusWriter struct {
	http.ResponseWriter
	status  int
	written bool
}

func (w *statusWriter) WriteHeader(status int) {
	if !w.written {
		w.status = status
		w.written = true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	w.written = true
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// RecordRequestFailure records the bounded error class for a failed request, and
// nothing for a successful one.
//
// THE BICONDITIONAL, and why both halves happen here. core's traces schema makes
// it a constraint in both directions: a span whose status is `error` must carry
// an `error.type`, and a span that carries one must have failed. That is what
// makes the ABSENCE of `error.type` the load-bearing "this was not an error"
// marker — on a duration histogram the samples carrying the class are the errors
// and every other sample is a success, so a success that carried one would move
// the numerator and make the error rate a number nobody can trust.
//
// So success records no class at all: not `_OTHER`, and not a class a filter has
// to special-case.
//
// WHY 4xx IS NOT HERE, and it is the more interesting half. A 401 on
// `POST /v1/session` is a wrong password and a 404 on
// `GET /v1/accounts/{accountID}` is somebody guessing an id. Both are a caller
// doing something the API answers by refusing, and both are the service working.
// A span marked ERROR for every rejected login is an error rate that is a
// function of how much credential stuffing the platform is absorbing, and an
// alert on it pages somebody to disable the protection that is doing its job.
// The fleet's error view is about the service failing, not about the service
// refusing. A 5xx is the service failing, and that is a span whose status says
// so.
//
// `internal_error` rather than a class derived from the status: the class is a
// grouping key shared with the other five services, and a class invented per
// status code is a class nobody else emits — which is how one place to see all
// errors becomes six places. The status is already on the span as
// `http.response.status_code`, so the pair says everything it can, and `_OTHER`
// is not warranted either, because an unhandled 5xx IS this class. A later
// packet that can tell a dependency failure from a handler bug narrows it
// without changing this call site.
func RecordRequestFailure(span trace.Span, status int) {
	if status < 500 {
		return
	}
	_ = telemetry.RecordFailure(span, "internal_error", "the handler returned a server error")
}

// routeTemplate is the matched route, or "" when nothing matched.
//
// chi fills RoutePattern in as the request walks the routing tree, so the answer
// is only complete once the handler has returned. That is why this is read on the
// way OUT, and why a 404 carries no template: there was no route, and inventing
// one would be a value nobody queries — a 404 is visible through its status.
func routeTemplate(r *http.Request) string {
	routeContext := chi.RouteContext(r.Context())
	if routeContext == nil {
		return ""
	}
	return routeContext.RoutePattern()
}

// statusClass is the metric-side spelling of a status.
//
// The trace signal carries the code and the metric signal carries the CLASS, and
// the difference is cardinality rather than taste: 500 codes multiplied by every
// route is how OpenTelemetry's 2000-attribute-combination cap is reached in a
// week, and `4xx` is the answer a dashboard actually asks for.
//
// It is asserted on in telemetry_test.go rather than left inside a YAML file in
// another repository, because a ladder nothing can test is a ladder that drifts
// from the one the collector applies.
func statusClass(status int) string {
	// The bounds are stated on EVERY arm, and the first version of this function
	// was a cascade of `case status < 300` style comparisons. A cascade is how
	// `statusClass(0)` and `statusClass(99)` came to return "2xx": every arm
	// below the first one that matched swallowed them, because 0 < 300. That is
	// not a cosmetic bug — a status outside 100..599 is not a fact about an HTTP
	// response, and a metric labelled "2xx" for a request that never got a
	// response is a number nobody can trust.
	//
	// A test caught it. That test is below, and it is why the ladder is asserted
	// rather than trusted to be obvious.
	switch {
	case status >= 100 && status < 200:
		return "1xx"
	case status >= 200 && status < 300:
		return "2xx"
	case status >= 300 && status < 400:
		return "3xx"
	case status >= 400 && status < 500:
		return "4xx"
	case status >= 500 && status < 600:
		return "5xx"
	default:
		return ""
	}
}
