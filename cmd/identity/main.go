// Command identity runs the cafaye identity service.
//
// main stays thin on purpose: read the configuration, build the app, hand the
// process lifetime to the app. Everything testable lives in the app and in
// internal/.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cafaye/identity/internal/auth"
	"github.com/cafaye/identity/internal/config"
	"github.com/cafaye/identity/internal/httpapi"
	"github.com/cafaye/identity/internal/outbox"
	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/sessions"
	"github.com/cafaye/identity/internal/users"
)

// shutdownTimeout is how long in-flight requests get to finish once a
// termination signal arrives.
const shutdownTimeout = 15 * time.Second

func main() {
	if err := run(); err != nil {
		slog.Error("identity exited with an error", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.LookupEnv)
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.SlogLevel()}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a, err := newApp(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer a.Close()

	if err := a.Listen(); err != nil {
		return err
	}

	logger.Info("starting identity", "addr", a.Addr(), "database", cfg.DatabaseURL != "")

	if err := a.Run(ctx); err != nil {
		return err
	}

	logger.Info("identity stopped")
	return nil
}

// app owns the process's HTTP server and, when a database is configured, the
// connection pool behind the readiness probe.
type app struct {
	cfg      config.Config
	logger   *slog.Logger
	pool     *pgxpool.Pool
	srv      *http.Server
	listener net.Listener
	timeout  time.Duration
}

// newApp wires the service together. With no DATABASE_URL it builds no pool,
// registers no readiness dependency, and mounts no /v1 routes — the v0 default,
// where the process serves its probes and nothing else. With one, it builds the
// pools, the stores and the use cases, and mounts the auth surface.
func newApp(ctx context.Context, cfg config.Config, logger *slog.Logger) (*app, error) {
	var pool *pgxpool.Pool
	checks := make([]httpapi.Check, 0, 1)

	if cfg.DatabaseURL != "" {
		p, err := db.Open(ctx, cfg.DatabaseURL, db.DefaultOptions())
		if err != nil {
			return nil, fmt.Errorf("opening database pool: %w", err)
		}
		pool = p
		checks = append(checks, httpapi.Check{Name: db.CheckName, Ping: pool.Ping})
	}

	opts := []httpapi.Option{httpapi.WithLogger(logger)}
	if svc := buildAuth(pool, logger); svc != nil {
		opts = append(opts, httpapi.WithAuth(svc))
	} else {
		// Said out loud, because a process serving probes and no auth surface is a
		// valid configuration and a surprising one.
		logger.Warn("no DATABASE_URL configured; the /v1 auth routes are not mounted")
	}

	handler := httpapi.New(checks, opts...)

	return &app{
		cfg:    cfg,
		logger: logger,
		pool:   pool,
		srv: &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
		},
		timeout: shutdownTimeout,
	}, nil
}

// buildAuth assembles the use cases over a pool, or returns nil when there is no
// pool to build them on.
//
// The outbox publisher is deliberately NOT started here. The loop and the
// Publisher interface exist and are tested, but the only implementation in this
// packet is a no-op: starting it would mark every event published and drain the
// outbox into nowhere, and a service that silently discards the events announcing
// its own registrations is worse than one that has not started the loop. The NATS
// connection is the next packet. See README.md, "Not built yet".
func buildAuth(pool *pgxpool.Pool, logger *slog.Logger) *auth.Service {
	if pool == nil {
		return nil
	}

	return auth.NewService(
		// Registration's user row and its event, and login's session and cleared
		// failure counter, are each one transaction.
		db.TxRunner{Pool: pool},
		// Everything else is a single statement and does not need one.
		db.Direct{Pool: pool},
		users.NewStore(pool),
		sessions.NewStore(pool),
		outbox.NewStore(pool),
		// Built once and shared: the hasher derives a dummy digest in its
		// constructor, and a per-request hasher would derive one per request.
		users.NewHasher(),
		// The real clock. Every window in the service reads time through this, which
		// is what lets a test move time exactly.
		clock.System{},
		auth.DefaultSessionTTL,
	)
}

// Listen binds the socket. It is separate from Run so the address is known —
// and reported — before the first request is served.
func (a *app) Listen() error {
	listener, err := net.Listen("tcp", a.cfg.Addr())
	if err != nil {
		return fmt.Errorf("listening on %s: %w", a.cfg.Addr(), err)
	}
	a.listener = listener
	return nil
}

// Addr is the bound address, empty until Listen succeeds.
func (a *app) Addr() string {
	if a.listener == nil {
		return ""
	}
	return a.listener.Addr().String()
}

// Run serves until ctx is cancelled (SIGTERM, SIGINT, or a test's context),
// then drains in-flight requests before returning.
func (a *app) Run(ctx context.Context) error {
	if a.listener == nil {
		return errors.New("Run called before Listen")
	}

	serveErr := make(chan error, 1)
	go func() {
		a.logger.Info("listening", "addr", a.Addr())
		serveErr <- a.srv.Serve(a.listener)
	}()

	select {
	case err := <-serveErr:
		return a.serveResult(err)
	case <-ctx.Done():
		a.logger.Info("shutdown requested", "in_flight_drain", a.timeout)
	}

	// Shutdown gets a fresh context: the cancelled one cannot be used to wait.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()

	if err := a.srv.Shutdown(shutdownCtx); err != nil {
		// Drain deadline blown: drop the connections rather than hang.
		_ = a.srv.Close()
		return fmt.Errorf("graceful shutdown: %w", err)
	}

	return a.serveResult(<-serveErr)
}

// Close releases the connection pool.
func (a *app) Close() error {
	if a.pool == nil {
		return nil
	}
	a.pool.Close()
	return nil
}

// serveResult normalises http.ErrServerClosed, which is how Serve reports a
// server stopped by Shutdown rather than a failure.
func (a *app) serveResult(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
