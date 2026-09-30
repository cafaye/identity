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

	"github.com/cafaye/identity/internal/config"
	"github.com/cafaye/identity/internal/httpapi"
	"github.com/cafaye/identity/internal/platform/db"
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

// newApp wires the service together. With no DATABASE_URL it builds no pool and
// registers no readiness dependency, which is the v0 default.
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

	handler := httpapi.New(checks, httpapi.WithLogger(logger))

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
