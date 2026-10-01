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
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cafaye/identity/internal/accounts"
	"github.com/cafaye/identity/internal/apikeys"
	"github.com/cafaye/identity/internal/auth"
	"github.com/cafaye/identity/internal/config"
	"github.com/cafaye/identity/internal/courier"
	"github.com/cafaye/identity/internal/httpapi"
	"github.com/cafaye/identity/internal/mfa"
	"github.com/cafaye/identity/internal/oidc"
	"github.com/cafaye/identity/internal/outbox"
	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/recovery"
	"github.com/cafaye/identity/internal/sessions"
	"github.com/cafaye/identity/internal/telemetry"
	"github.com/cafaye/identity/internal/users"
)

// shutdownTimeout is how long in-flight requests get to finish once a
// termination signal arrives.
const shutdownTimeout = 15 * time.Second

func main() {
	// `-healthcheck` is the container health probe, and it is a flag on this binary
	// rather than a `curl` in the compose file for one reason: the runtime image is
	// `gcr.io/distroless/static-debian12:nonroot`, which has no shell and no HTTP
	// client. The alternatives were a `build:` stanza that adds curl (a supply
	// chain in a security service's image) or no healthcheck at all.
	//
	// It matters more than a dev-loop convenience, because `docker compose up
	// --wait` is only as good as the health signals it waits on, and without this
	// it considers the service up the instant the process starts — which is before
	// the pools are built and long before /readyz would answer 200.
	//
	// It probes /readyz and not /healthz, because readiness is the one that
	// consults the database. A probe that reports healthy against a database that
	// is gone is a probe that reports a working service that answers 503 to
	// everybody.
	if len(os.Args) == 2 && os.Args[1] == "-healthcheck" {
		os.Exit(healthcheck())
	}

	if err := run(); err != nil {
		slog.Error("identity exited with an error", "error", err)
		os.Exit(1)
	}
}

// healthcheckTimeout bounds the probe. Short, because a compose healthcheck that
// takes thirty seconds to fail is a healthcheck whose interval is a lie, and this
// one runs every few seconds for the life of the container.
const healthcheckTimeout = 2 * time.Second

// healthcheck probes this process's own readiness endpoint and reports the result
// as an exit status. 0 healthy, 1 not.
//
// The address comes from PORT rather than being hardcoded, because a container
// started with a different PORT has to be probeable and a probe aimed at 8080
// would report a perfectly healthy service as dead.
func healthcheck() int {
	port := os.Getenv("PORT")
	if port == "" {
		port = config.DefaultPort
	}
	ctx, cancel := context.WithTimeout(context.Background(), healthcheckTimeout)
	defer cancel()

	// The response body is read and discarded rather than the connection simply
	// being closed: closing without draining means the server sees a broken pipe
	// on a request it already answered, which shows up in its own logs as an error
	// every few seconds forever.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+port+"/readyz", nil)
	if err != nil {
		return 1
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
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

	// Telemetry is installed BEFORE the app, so a span can exist for anything
	// that happens while the pools and the providers are being built — a boot
	// that takes ninety seconds because the database is slow is exactly the boot
	// an operator is watching for, and it is invisible without this.
	shutdownTelemetry, err := installTelemetry(ctx, logger)
	if err != nil {
		return err
	}
	defer func() {
		// A separate context: `ctx` is already cancelled by the time this runs,
		// because a SIGTERM is what usually got us here, and a cancelled context
		// cannot be used to wait for a flush. Bounded by the SDK's own timeout,
		// because a telemetry flush must not be able to hold up a shutdown.
		flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdownTelemetry(flushCtx); err != nil {
			logger.Warn("flushing telemetry on the way out failed", "error", err)
		}
	}()

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

// installTelemetry starts OpenTelemetry, or stands the no-op up in its place.
//
// ONE LINE, AND ONLY ON THE DISABLED PATH. Silence is the contract there: a
// warning per export attempt fills the service's own log store with the fact that
// telemetry is off, which is how a self-hoster discovers that turning it off is
// not supported — the opposite of the intent. One line at startup is not spam,
// and it is the difference between "telemetry is off" and "telemetry is broken",
// which look identical from outside.
//
// The endpoint is logged WITH ITS QUERY AND FRAGMENT REMOVED. A bring-your-own
// backend puts its API key in the path or the query string, and a startup line
// that quoted the whole thing would write that key into the same log store the
// redaction boundary is trying to keep it out of.
//
// A configured endpoint that cannot be built is a BOOT FAILURE, not a silent
// no-op. "Telemetry is silently absent" and "telemetry is off" look identical
// from outside and only one of them is what anybody meant, so a service that
// starts happily and exports nowhere is the one that gets discovered a quarter
// later.
func installTelemetry(ctx context.Context, logger *slog.Logger) (telemetry.Shutdown, error) {
	lookup := os.Getenv
	shutdown, err := telemetry.Install(ctx, telemetry.Options{
		ServiceName: telemetry.ServiceName,
		Endpoint:    telemetry.Endpoint(lookup),
		Disabled:    !telemetry.Enabled(lookup),
		LookupEnv:   lookup,
	})
	if err != nil {
		return nil, err
	}

	if reason := telemetry.NoOpReason(lookup); reason != "" {
		logger.Info("telemetry is off", "reason", reason)
		return shutdown, nil
	}
	logger.Info("telemetry is on",
		"service", telemetry.ServiceName,
		"endpoint", redactEndpoint(telemetry.Endpoint(lookup)),
	)
	return shutdown, nil
}

// redactEndpoint is a hostname and a port, or nothing else. A bring-your-own
// backend's key lives in the path or the query string, and a self-hoster has to
// be able to confirm which backend their service is pointed at without that key
// landing in a log store.
func redactEndpoint(endpoint string) string {
	if index := strings.IndexAny(endpoint, "?#"); index >= 0 {
		return endpoint[:index]
	}
	return endpoint
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

	// ONE HASHER FOR THE WHOLE PROCESS, and it is built here rather than inside
	// buildAuth because two surfaces need one: a password reset hashes a new
	// password through the same code a registration does, and the constructor
	// derives an argon2id digest for the login's timing equaliser — so a second
	// Hasher would derive a second dummy digest and cost a hundred milliseconds of
	// memory-hard work at boot for nothing.
	hasher := users.NewHasher()

	authSvc, tenancy, secondFactor, mfaUsable, err := buildAuth(cfg, pool, hasher, logger)
	if err != nil {
		return nil, err
	}
	if authSvc != nil {
		machineCredentials, err := buildAPIKeys(cfg, pool, tenancy, logger)
		if err != nil {
			return nil, err
		}

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
		// The recovery surface. It is mounted unconditionally inside this branch —
		// not gated on a mailer — because a 404 on /v1/password-resets would tell a
		// product this service has never heard of password recovery, which is both
		// false and useless. A deployment that cannot send a message answers 503 on
		// the routes that need one, with a sentence saying so.
		recoverySvc, err := buildRecovery(cfg, pool, hasher, logger)
		if err != nil {
			return nil, err
		}
		if recoverySvc != nil {
			opts = append(opts, httpapi.WithRecovery(recoverySvc))
		}
		if machineCredentials != nil {
			// Four options from one service, and each is a different capability rather
			// than a different spelling of the same one: the management surface
			// (mint/list/revoke), resolving a presented token to its caller so the
			// account routes accept one, and the introspection surface a resource
			// server asks because the token is opaque and carries no claims of its
			// own. WithAPIKeyCaller is what makes the scope gate reachable at all —
			// without it every account route is session-only.
			opts = append(opts,
				httpapi.WithAPIKeys(machineCredentials),
				httpapi.WithAPIKeyCaller(machineCredentials),
				httpapi.WithIntrospection(machineCredentials),
			)
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
func buildAuth(
	cfg config.Config, pool *pgxpool.Pool, hasher *users.Hasher, logger *slog.Logger,
) (*auth.Service, *accounts.Service, *mfa.Service, bool, error) {
	if pool == nil {
		return nil, nil, nil, false, nil
	}

	// One outbox store, shared. It is stateless apart from its pool, and two of
	// them would be two objects that have to be configured identically.
	events := outbox.NewStore(pool)

	// The api key store, built BEFORE tenancy and handed to it. The dependency runs
	// backwards from the rest of this file and the reason is a security rule rather
	// than a convenience: removing a member from an account revokes the machine
	// credentials they held in it, in the same transaction as the membership delete,
	// and accounts.Service can only do that with a revoker to call. It is an
	// interface declared in accounts and satisfied here, so neither package imports
	// the other.
	//
	// One store, two services: apikeys.Service below takes the same *Store, so the
	// table has a single owner in this process and there is no second object to
	// configure identically.
	apiKeyStore := apikeys.NewStore(pool)

	// Tenancy is built first because registration needs it: a new user gets a
	// personal account, and both writes are one transaction. The order of these
	// two blocks is the dependency order, which is the reason they share a
	// function rather than being two independent builders in newApp.
	tenancy := accounts.NewService(
		db.TxRunner{Pool: pool},
		accounts.NewStore(pool),
		events,
		apiKeyStore,
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
		// Built once by newApp and shared with the recovery surface, because the
		// constructor derives a dummy digest in the login's timing equaliser and a
		// second Hasher would derive a second one for the same purpose.
		hasher,
		// The real clock. Every window in the service reads time through this, which
		// is what lets a test move time exactly.
		clock.System{},
		auth.DefaultSessionTTL,
	)

	return authSvc, tenancy, secondFactor, mfaUsable, nil
}

// buildRecovery assembles the account-recovery use cases: password reset, address
// verification and email change.
//
// # THE MAILER IS courier's, AND `Unavailable{}` IS ONLY FOR A DEPLOYMENT THAT HAS
// NOT CONFIGURED IT
//
// `buildMailer` returns one of two things, and the difference is the whole of this
// function's mailer wiring:
//
//	configured    a courier.RecoveryMailer, which speaks POST /v1/messages
//	absent        recovery.Unavailable{}, which fails every send with ErrNoMailer
//
// The absent case is a SUPPORTED DEPLOYMENT rather than a gap: a local stack with
// no courier, or one where mail has not been turned on. It is loud in the log
// because a 404 on `/v1/password-resets` would tell a product this service has
// never heard of password recovery, which is both false and useless — so the routes
// stay mounted and answer 503 with a sentence naming the problem. The shape is the
// one `buildMFASecret`'s absent key already produces, and for the same reason: a
// user told "try later" retries forever and an operator told `internal` goes
// looking for a database problem that is not there.
//
// # NEITHER ALTERNATIVE WAS AVAILABLE
//
// A LOGGER was the alternative that was weighed and refused, and the reason is
// unchanged from when the seam was declared: every message this service sends
// contains a live credential until it is spent, and a reset token in an operator's
// log aggregator is a reset token anybody who can read the logs can redeem. The
// flows would work in every test and in a staging stack, and the first production
// deployment would be the first time a real user found their password reset had
// been written to a log file.
//
// # AND `Unavailable{}` IS STILL HERE FOR A REASON
//
// It is not reachable by accident and it is not dead: it is what a deployment with
// no `COURIER_TOKEN` mounts, and `TestAMailerIsCouriersOrUnavailableAndNothing
// Else` holds that the two are the only possibilities. It is the fail-loud design
// the seam was written for — every path that needs a message answers 503 rather
// than dropping one — and that is worth keeping for a deployment that has not
// finished the configuration rather than deleting.
func buildRecovery(
	cfg config.Config, pool *pgxpool.Pool, hasher *users.Hasher, logger *slog.Logger,
) (*recovery.Service, error) {
	if pool == nil {
		return nil, nil
	}

	mailer, err := buildMailer(cfg, logger)
	if err != nil {
		// A courier block that is PRESENT and unreadable is a startup failure, and
		// `config.Load` has already refused the obviously broken ones. This is the
		// remaining case, and it fails startup rather than warning because a
		// deployment that believes it can send mail and cannot is worse than one
		// that refuses to start: the first person to find out is a user waiting on
		// a password reset that was never sent.
		return nil, fmt.Errorf("building the mailer: %w", err)
	}

	service := recovery.NewService(
		// A spent token and the state it changes are one transaction, so every
		// redemption runs on the runner rather than on a bare querier.
		db.TxRunner{Pool: pool},
		// Everything else is a single statement: the lookup that decides whether
		// the account exists, the cooldown read, and the resolution of a presented
		// token.
		db.Direct{Pool: pool},
		recovery.NewStore(pool),
		users.NewStore(pool),
		sessions.NewStore(pool),
		// oidc.Store rather than the storage adapter, and deliberately: this is one
		// UPDATE over oidc_access_tokens that needs no signing key, and a password
		// reset has to be able to end a user's JWTs on a deployment where the OIDC
		// provider is not mounted at all.
		oidc.NewStore(pool),
		outbox.NewStore(pool),
		mailer,
		hasher,
		clock.System{},
	)

	return service, nil
}

// buildMailer returns the Mailer this deployment has: courier's, or a refusing one.
//
// # THE SERVICE CREDENTIAL, AND WHY IT IS A BEARER TOKEN
//
// courier's document declares `security: [bearerAuth: [messages:write]]` and says
// identity is the only issuer, so this service presents
// `Authorization: Bearer <COURIER_TOKEN>` and nothing else. The alternatives were
// weighed:
//
//   - A SHARED SECRET on a header of our own. courier's
//     `CourierWeb.Plugs.IngestToken` does this, and its moduledoc gives the reason
//     it is right THERE: the callers are three services holding a Sentry DSN and
//     there is no identity service in that path to mint one. There IS one in this
//     path, and that plug is wired to a different route — a header courier's
//     `:authenticated` pipeline does not read produces a request that is still a
//     401.
//   - A USER'S SESSION OR API KEY. Both are a person's credential, and the
//     `account_id` courier takes from the principal is the tenancy of the mail.
//     Attributing the platform's password resets to whichever user happened to
//     trigger one would put a stranger's recovery in somebody else's tenant.
//
// # AND THE TOKEN IS NEVER LOGGED, WHICH IS WHY THE STARTUP LINE NAMES NOTHING
//
// The credential lives inside a closure in `internal/courier` and the line below
// reports the base URL, which is not a secret and is the thing an operator has to be
// able to confirm. `%#v` prints an exported struct field by value and does not
// consult `String()`, so a `token` field on the client would be a leak no method
// could intercept; `TestTheClientNeverPrintsACredential` drives a real request
// against a server that echoes the credential back and sweeps every formatting verb
// for it.
func buildMailer(cfg config.Config, logger *slog.Logger) (recovery.Mailer, error) {
	if !cfg.CourierEnabled() {
		logger.Warn("account recovery is mounted, but this deployment cannot send email. " +
			"Set COURIER_BASE_URL, COURIER_TOKEN and RECOVERY_LINK_TEMPLATE to enable it; " +
			"until then POST /v1/password-resets answers 503.")
		return recovery.Unavailable{}, nil
	}

	client, err := courier.New(courier.Config{
		BaseURL: cfg.CourierBaseURL,
		Token:   cfg.CourierTokenValue,
	})
	if err != nil {
		return nil, fmt.Errorf("building the courier client: %w", err)
	}
	mailer, err := courier.NewRecoveryMailer(courier.RecoveryMailerConfig{
		Client:       client,
		LinkTemplate: cfg.RecoveryLinkTemplate,
		Logger:       logger,
	})
	if err != nil {
		return nil, fmt.Errorf("building the courier mailer: %w", err)
	}

	// THE LINE, AND WHAT IT DOES NOT SAY. It does not say mail will be sent.
	// courier's `/readyz` is outside every pipeline and answers for courier's
	// DATABASE; it does not say courier can deliver, because courier's adapter check
	// is scoped to production. A green readiness probe and this line together are
	// "courier is reachable", and a send is where a misconfigured provider is
	// found. An operator who reads "mail is wired" as "mail is being sent" has been
	// told something this process cannot support.
	logger.Info("account recovery can send email through courier",
		"courier", cfg.CourierBaseURL,
		"send_timeout", courier.DefaultTimeout,
		"probe_timeout", courier.DefaultProbeTimeout,
		"link_template", cfg.RecoveryLinkTemplate,
	)
	// WHAT IS AND IS NOT DELIVERABLE, said out loud. courier's NotificationType is
	// [welcome, password_reset, team_invitation], which covers this service's
	// password reset and its address verification — the latter through courier's
	// `welcome` template, whose words are true for an account that has never proved
	// an address. The two halves of an EMAIL CHANGE are not covered by any of them,
	// and the current-address half is the only warning an account owner gets that
	// somebody is moving their address, so it is refused rather than translated onto
	// a template that would say something false. See internal/courier's
	// RecoveryMailer for that argument in full.
	logger.Warn("courier cannot render this service's email change messages, so " +
		"POST /v1/email-changes answers 503 until courier's vocabulary includes them; " +
		"password reset and address verification are delivered")

	return mailer, nil
}

// buildAPIKeys assembles the scoped-token use cases, or returns nil when this
// process cannot have them.
//
// THE ONE CONDITION is a pool, and it is the same one auth needs — a table with no
// process writing to it is not a capability, it is a 500 waiting for the first
// request. So this is called from inside the `authSvc != nil` branch and never
// decides anything of its own.
//
// It takes NO CONFIGURATION, and that is worth a line because every other surface
// in this file does. An api key is not a secret this deployment generates and has
// to keep: it is a random value whose only stored form is a SHA-256 of it, and
// there is no key to load, no key to rotate and no key to lose. The costs of
// having a signing key configured for the OIDC provider — a startup failure on a
// wrong one, a trust anchor that changes on a restart — do not exist here, which
// is one of the reasons this credential is a row lookup rather than a JWT.
//
// The outbox store is a second one rather than the one buildAuth made, and that is
// deliberate: the two have no state to share, and threading buildAuth's outbox
// through a second return value would couple two builders that have nothing else to
// do with each other. The same reasoning is in buildOIDC's last paragraph.
func buildAPIKeys(
	cfg config.Config,
	pool *pgxpool.Pool,
	tenancy *accounts.Service,
	logger *slog.Logger,
) (*apikeys.Service, error) {
	if pool == nil || tenancy == nil {
		return nil, nil
	}

	service := apikeys.NewService(
		db.TxRunner{Pool: pool},
		db.Direct{Pool: pool},
		apikeys.NewStore(pool),
		outbox.NewStore(pool),
		tenancy,
		users.NewStore(pool),
		clock.System{},
	)

	// The startup line is the same one MFA gets, and for the same reason: an
	// operator who does not know a capability is mounted will discover it from a
	// 404, and one who believes it is mounted when it is not will discover it from
	// a 404 too. The scopes are in the line because they are the vocabulary a
	// consumer has to match against, and a list that changes with a release belongs
	// in the log at boot rather than in a document somebody has to find.
	logger.Info("scoped api tokens are mounted",
		"prefix", apikeys.Prefix,
		"secret_bytes", apikeys.SecretBytes,
		"scopes", strings.Join(apikeys.AllScopes(), " "),
		"default_ttl", apikeys.DefaultTTL,
		"max_ttl", apikeys.MaxTTL,
	)

	return service, nil
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
