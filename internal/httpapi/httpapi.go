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

	"github.com/cafaye/identity/internal/platform/clock"
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
	// clk is the service's clock, and it exists because the HTTP layer has to pass
	// an INSTANT to the stores rather than let them read one.
	//
	// The alternative — time.Now() at the call site — is how a credential ends up
	// judged against a different second than the one its row was written with, and
	// it is untestable: a suite cannot age a token out without sleeping. Every use
	// case in this service reads time through internal/platform/clock, and this is
	// the seam that lets the HTTP layer do the same.
	clk     clock.Clock
	auth    Auth
	tenancy Tenancy
	// apiKeyCaller resolves a scoped token to its caller. Absent means the account
	// routes are session-only and a token presented to one is refused.
	apiKeyCaller APIKeyCaller
	// introspector serves POST /v1/introspections. Absent means the route is not
	// mounted.
	introspector Introspector
	// apiKeys is the scoped-token surface. It is separate from oidcClients because
	// it is a different credential with a different lifetime and a different
	// storage, and a deployment with one configured and not the other is a real one:
	// a first-party machine credential has no key to sign with.
	apiKeys     APIKeys
	oidc        OIDC
	oidcClients OIDCClients
	// mfa is the MANAGEMENT surface — the routes that read and write a TOTP secret.
	// It needs MFA_ENCRYPTION_KEY and is absent without it.
	//
	// The login's second step is NOT here: it goes through Auth, because
	// auth.Service is where a session is minted. See the note in mfa.go.
	mfa MFAManage
	// admin is the ADMIN surface: revoking invitations and reading the immutable
	// audit trail. It is token-only (see requireAdminToken) and absent without it,
	// like every other optional surface here.
	admin Admin
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

// WithClock sets the instant the HTTP layer hands to the stores.
//
// It is only interesting to a test, and it is here rather than a package variable
// for the reason every other dependency is: a mutable global clock is a way for
// one test to age another test's credential. The default is the real clock.
func WithClock(c clock.Clock) Option {
	return func(o *options) {
		if c != nil {
			o.clk = c
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
		// The real clock, and it is a value rather than a package variable so two
		// servers in one test binary cannot age each other's credentials.
		clk: clock.System{},
	}
	for _, opt := range opts {
		opt(&o)
	}

	// Outermost first: the trace id must exist before anything can log or report
	// one, and recovery must sit inside it so the panic handler can quote the id.
	return traceMiddleware(recoverPanics(o.logger, newMux(checks, o)))
}

// newMux is the router, without the two middlewares, so that a test which has to
// enumerate the routes can walk the tree this assembles rather than a second
// assembly of the same routes written out in a test.
//
// The alternative is a test that calls registerRoutes itself, and that is a
// second list of what a deployed process mounts — the exact thing the tripwire in
// openapi_drift_test.go exists to refuse. This is the whole of the change: the
// wiring below is the wiring that was inline, and New is the only caller.
func newMux(checks []Check, o options) *chi.Mux {
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
	return r
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
