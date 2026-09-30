// Package httpapi wires the identity service's HTTP surface.
//
// The scaffold exposes only the two endpoints every service in the platform
// must have: liveness (/healthz) and readiness (/readyz). Auth routes land in
// later packets.
package httpapi

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// DefaultReadinessTimeout bounds a single readiness probe so a hung
// dependency cannot pin the orchestrator's health check open.
const DefaultReadinessTimeout = 2 * time.Second

// Check is a named dependency that readiness probes. Name is reported in the
// readiness response so an operator can see what failed.
type Check struct {
	Name string
	Ping func(ctx context.Context) error
}

type options struct {
	logger           *slog.Logger
	readinessTimeout time.Duration
	auth             Auth
	tenancy          Tenancy
	oidc             OIDC
	oidcClients      OIDCClients
}

// Option customises the handler built by New.
type Option func(*options)

// WithLogger sets the logger used to report probe failures.
func WithLogger(logger *slog.Logger) Option {
	return func(o *options) {
		if logger != nil {
			o.logger = logger
		}
	}
}

// WithReadinessTimeout overrides how long a probe may take before it is
// treated as unavailable.
func WithReadinessTimeout(d time.Duration) Option {
	return func(o *options) {
		if d > 0 {
			o.readinessTimeout = d
		}
	}
}

// New builds the service router. With no checks there is nothing to probe, so
// readiness succeeds with "deps":"none" — the shape v0 ships in, before
// DATABASE_URL exists. With no Auth there are no /v1 routes at all, so a process
// without a database still serves its probes and nothing else.
func New(checks []Check, opts ...Option) http.Handler {
	o := options{
		logger:           slog.New(slog.DiscardHandler),
		readinessTimeout: DefaultReadinessTimeout,
	}
	for _, opt := range opts {
		opt(&o)
	}

	r := chi.NewRouter()
	r.NotFound(notFound)
	r.MethodNotAllowed(methodNotAllowed)
	r.Get("/healthz", handleHealthz)
	r.Get("/readyz", o.handleReadyz(checks))
	// The well-known documents are registered before the /v1 and /oidc routes
	// because they are reachable without a session, a database or a signing key
	// being configured, and a process with no DATABASE_URL should still be able
	// to answer a probe for its own metadata.
	o.registerOIDCWellKnownRoutes(r)
	o.registerRoutes(r)

	// Outermost first: the trace id must exist before anything can log or report
	// one, and recovery must sit inside it so the panic handler can quote the id.
	return traceMiddleware(recoverPanics(o.logger, r))
}

// HealthResponse is the /healthz body. Liveness answers whether this process
// is running, never whether its dependencies are healthy.
type HealthResponse struct {
	Status string `json:"status"`
}

// ReadyResponse is the /readyz body. Deps lists the dependencies that were
// probed ("none" when there are none) and Status is "ok" or "unavailable".
type ReadyResponse struct {
	Status string `json:"status"`
	Deps   string `json:"deps"`
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, HealthResponse{Status: "ok"})
}

func (o options) handleReadyz(checks []Check) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(checks) == 0 {
			writeJSON(w, http.StatusOK, ReadyResponse{Status: "ok", Deps: "none"})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), o.readinessTimeout)
		defer cancel()

		var failed []string
		for _, check := range checks {
			if err := probe(ctx, check); err != nil {
				failed = append(failed, check.Name)
				o.logger.Warn("readiness probe failed", "dep", check.Name, "error", err)
			}
		}

		// The response names the dependencies that were checked; the underlying
		// error stays in the log so nothing internal leaks to anonymous callers.
		deps := joinNames(checks)
		if len(failed) > 0 {
			writeJSON(w, http.StatusServiceUnavailable, ReadyResponse{Status: "unavailable", Deps: deps})
			return
		}
		writeJSON(w, http.StatusOK, ReadyResponse{Status: "ok", Deps: deps})
	}
}

// notFound and methodNotAllowed are problem documents like every other non-2xx
// response, per core's error envelope. A bespoke JSON body here is how a client
// ends up with two error shapes to parse.
func notFound(w http.ResponseWriter, r *http.Request) {
	problemFor(w, r, http.StatusNotFound, CodeNotFound, "no route matches this request")
}

func methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	problemFor(w, r, http.StatusMethodNotAllowed, CodeMethodNotAllowed,
		"this route does not implement the request's method")
}

// probe runs one readiness check. A panicking dependency is a failed probe,
// not a dead process: the net/http recover would otherwise close the
// connection and leave the orchestrator guessing.
func probe(ctx context.Context, check Check) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("probe panicked: %v", r)
		}
	}()

	return check.Ping(ctx)
}

func joinNames(checks []Check) string {
	names := make([]string, 0, len(checks))
	for _, check := range checks {
		names = append(names, check.Name)
	}
	return strings.Join(names, ",")
}
