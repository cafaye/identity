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

	"github.com/cafaye/identity/internal/accounts"
	"github.com/cafaye/identity/internal/auth"
	"github.com/cafaye/identity/internal/config"
	"github.com/cafaye/identity/internal/httpapi"
	"github.com/cafaye/identity/internal/mfa"
	"github.com/cafaye/identity/internal/oidc"
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
	authSvc, tenancy, secondFactor, mfaUsable, err := buildAuth(cfg, pool, logger)
	if err != nil {
		return nil, err
	}
	if authSvc != nil {
		opts = append(opts,
			httpapi.WithAuth(authSvc),
			httpapi.WithTenancy(tenancy),
			// The login's second step rides on WithAuth, because auth.Service is what
			// mints the session behind it. Only the MANAGEMENT routes are conditional,
			// and only on a usable key: such a process must not be able to enroll a
			// factor it could never verify, while still refusing the users who enrolled
			// elsewhere. Mounting both, or neither, is a bypass in one direction or
			// the other.
		)
		if mfaUsable {
			opts = append(opts, httpapi.WithMFA(secondFactor))
		}
	} else {
		// Said out loud, because a process serving probes and no auth surface is a
		// valid configuration and a surprising one.
		logger.Warn("no DATABASE_URL configured; the /v1 auth routes are not mounted")
	}

	provider, clients, err := buildOIDC(cfg, pool, logger)
	if err != nil {
		return nil, err
	}
	switch {
	case provider == nil && cfg.OIDCEnabled():
		// The opposite surprise: keys are configured and there is nowhere to keep
		// the registrations, so the provider would sign tokens for clients that
		// cannot be registered or revoked.
		logger.Warn("OIDC is configured but there is no DATABASE_URL; the OIDC surface is not mounted")
	case provider != nil:
		opts = append(opts, httpapi.WithOIDC(provider), httpapi.WithOIDCClients(clients))
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
// It returns the MFA use cases alongside the auth ones because auth.Login cannot
// work without them: a correct password must not mint a session for an account
// that has a second factor, and the only way to know is to ask.
// The fourth return is mfaUsable: whether this deployment can encrypt and decrypt a
// TOTP secret, which is exactly whether the MANAGEMENT routes may be mounted.
func buildAuth(cfg config.Config, pool *pgxpool.Pool, logger *slog.Logger) (*auth.Service, *accounts.Service, *mfa.Service, bool, error) {
	if pool == nil {
		return nil, nil, nil, false, nil
	}

	// One outbox store, shared. It is stateless apart from its pool, and two of
	// them would be two objects that have to be configured identically.
	events := outbox.NewStore(pool)

	// Tenancy is built first because registration needs it: a new user gets a
	// personal account, and both writes are one transaction. The order of these
	// two blocks is the dependency order, which is the reason they share a
	// function rather than being two independent builders in newApp.
	tenancy := accounts.NewService(
		db.TxRunner{Pool: pool},
		accounts.NewStore(pool),
		events,
		clock.System{},
		db.Direct{Pool: pool},
	)

	// The second factor is built before auth for the reason the comment above says:
	// auth takes it as a required dependency, so it has to exist before NewService
	// is called.
	//
	// NO MFA_ENCRYPTION_KEY means the vault is mfa.Unavailable{}, never nil. Every
	// path that reads or writes a secret fails with ErrNoVault, and the ENROLLMENT
	// ROUTES ARE NOT MOUNTED — a user must not be talked into enrolling a factor
	// this process could not later verify.
	//
	// The login path still works and still creates a challenge for users who
	// enrolled elsewhere, because mfa.Enabled needs no key. That is the fail-closed
	// direction: such a user is refused rather than let in on their password.
	// A wrong key is a startup failure and not a warning: an operator who
	// configured a 16-byte key believes they have 128 bits of entropy protecting
	// every second factor on the platform, and they do not.
	vault, err := buildMFASecret(cfg, logger)
	if err != nil {
		return nil, nil, nil, false, err
	}
	_, mfaUsable := vault.(mfa.Unavailable)
	mfaUsable = !mfaUsable
	secondFactor := mfa.NewService(
		db.TxRunner{Pool: pool},
		db.Direct{Pool: pool},
		mfa.NewStore(pool),
		events,
		sessions.NewStore(pool),
		vault,
		clock.System{},
		cfg.MFAIssuer(),
	)
	if mfaUsable {
		logger.Info("multi-factor authentication is available",
			"issuer", cfg.MFAIssuer(),
			"period_seconds", int(mfa.Period.Seconds()),
			"digits", mfa.Digits,
			"skew_steps", mfa.SkewSteps,
			"recovery_codes", mfa.RecoveryCodeCount,
		)
	} else {
		logger.Warn("MFA_ENCRYPTION_KEY is not configured; the MFA management routes are not mounted " +
			"and this process cannot verify a second factor for anybody")
	}

	authSvc := auth.NewService(
		// Registration's user row, personal account, owner membership and two
		// events; login's session and cleared failure counter; and the
		// second-factor login's session, challenge consumption and two cleared
		// counters, are each one transaction.
		db.TxRunner{Pool: pool},
		// Everything else is a single statement and does not need one.
		db.Direct{Pool: pool},
		users.NewStore(pool),
		sessions.NewStore(pool),
		events,
		tenancy,
		secondFactor,
		// Built once and shared: the hasher derives a dummy digest in its
		// constructor, and a per-request hasher would derive one per request.
		users.NewHasher(),
		// The real clock. Every window in the service reads time through this, which
		// is what lets a test move time exactly.
		clock.System{},
		auth.DefaultSessionTTL,
	)

	return authSvc, tenancy, secondFactor, mfaUsable, nil
}

// buildMFASecret returns the vault for the configured key, or mfa.Unavailable{}.
//
// Three outcomes, and the third is a startup failure rather than a warning:
//
//	key absent   Unavailable{} — a deployment that has not turned MFA on
//	key present  a real AES-256-GCM vault
//	key wrong    an error
//
// It is NEVER generated at boot. A generated key would mean every restart
// invalidates every enrolled user's secret, and a restart is not something anybody
// decides to do — which is the same rule AGENTS.md states for OIDC_SIGNING_KEY.
func buildMFASecret(cfg config.Config, logger *slog.Logger) (mfa.Vault, error) {
	key, err := cfg.MFAEncryptionKey()
	switch {
	case errors.Is(err, config.ErrNoMFAEncryptionKey):
		logger.Warn("MFA_ENCRYPTION_KEY is not set")
		return mfa.Unavailable{}, nil
	case err != nil:
		return nil, fmt.Errorf("reading MFA_ENCRYPTION_KEY: %w", err)
	}

	vault, err := mfa.NewAESCipher(key)
	if err != nil {
		return nil, fmt.Errorf("building the MFA encryption key: %w", err)
	}
	return vault, nil
}

// buildOIDC assembles the OpenID Connect provider, or returns nils when this
// process is not one.
//
// Three conditions, and all three are required. A signing key with no database has
// nowhere to keep a registration, so the provider could sign tokens for clients
// that can never be registered or revoked. A database with no key cannot sign. And
// no issuer means the provider is not configured at all, which is the legitimate
// deployment — a courier, or a local stack that has no key yet.
//
// The order inside is the dependency order: the key, because the storage adapter
// needs it to publish the key set; the storage, because the provider needs it for
// every protocol decision; then the provider and the registration use cases,
// which share the one store.
func buildOIDC(cfg config.Config, pool *pgxpool.Pool, logger *slog.Logger) (*oidc.Provider, *oidc.Service, error) {
	if !cfg.OIDCEnabled() || pool == nil {
		return nil, nil, nil
	}

	key, err := oidc.LoadSigningKey(cfg.OIDCSigningKey, cfg.OIDCKeyID)
	if err != nil {
		// A startup failure, not a warning. The alternative is a provider that
		// signs with a key it invented, publishes a document nobody has cached and
		// rotates its own trust anchor on every restart.
		return nil, nil, fmt.Errorf("loading the OIDC signing key: %w", err)
	}

	store := oidc.NewStore(pool)
	storage := oidc.NewStorage(store, oidc.NewProfileReader(), key, clock.System{}, db.Direct{Pool: pool}, oidc.PathLogin)

	provider, err := oidc.NewProvider(oidc.Config{
		Issuer:        cfg.OIDCIssuer,
		SigningKey:    key,
		AllowInsecure: cfg.OIDCAllowInsecure,
	}, storage)
	if err != nil {
		return nil, nil, fmt.Errorf("building the OIDC provider: %w", err)
	}

	// One store, one event appender, one clock. Two of each would be two objects
	// that have to be configured identically and nothing that stops them drifting.
	events := outbox.NewStore(pool)
	clients := oidc.NewService(
		db.TxRunner{Pool: pool},
		store,
		events,
		storage,
		clock.System{},
		db.Direct{Pool: pool},
	)

	logger.Info("the OIDC provider is mounted",
		"issuer", provider.Issuer(),
		"key_id", key.ID(),
		"authorize", oidc.PathAuthorize,
	)

	return provider, clients, nil
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
