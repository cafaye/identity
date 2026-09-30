// Package db owns the Postgres connection pool.
//
// It is deliberately thin: parse the DSN, build a pool, hand back a pool whose
// Ping is safe to call from a readiness probe. No queries, no schema, no ORM —
// migrations are goose SQL files under migrations/.
package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultMaxConns       int32 = 8
	defaultMinConns       int32 = 1
	defaultMaxIdle              = 30 * time.Minute
	defaultMaxLifetime          = time.Hour
	defaultConnectTimeout       = 5 * time.Second
)

// Errors returned by Open.
var (
	// ErrNoDatabaseURL means DATABASE_URL was not configured. In v0 that is a
	// supported state: the service runs without a database.
	ErrNoDatabaseURL = errors.New("no DATABASE_URL configured")
	// ErrInvalidOptions means the pool options cannot describe a working pool.
	ErrInvalidOptions = errors.New("invalid pool options")
)

// Options tunes the connection pool. Zero values fall back to the defaults, so
// callers only set what they care about.
type Options struct {
	MaxConns        int32
	MinConns        int32
	MaxConnIdleTime time.Duration
	MaxConnLifetime time.Duration
	ConnectTimeout  time.Duration
}

// DefaultOptions returns the pool sizing used by the service.
func DefaultOptions() Options {
	return Options{
		MaxConns:        defaultMaxConns,
		MinConns:        defaultMinConns,
		MaxConnIdleTime: defaultMaxIdle,
		MaxConnLifetime: defaultMaxLifetime,
		ConnectTimeout:  defaultConnectTimeout,
	}
}

// Open builds a connection pool for dsn.
//
// The pool is lazy: constructing it does not dial, so a database that is down
// at startup shows up as a failing readiness probe instead of a crash loop.
func Open(ctx context.Context, dsn string, opts Options) (*pgxpool.Pool, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, ErrNoDatabaseURL
	}

	opts = opts.withDefaults()
	if err := opts.validate(); err != nil {
		return nil, err
	}

	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing DATABASE_URL: %w", err)
	}

	poolConfig.MaxConns = opts.MaxConns
	poolConfig.MinConns = opts.MinConns
	poolConfig.MaxConnIdleTime = opts.MaxConnIdleTime
	poolConfig.MaxConnLifetime = opts.MaxConnLifetime
	if poolConfig.ConnConfig.ConnectTimeout == 0 {
		poolConfig.ConnConfig.ConnectTimeout = opts.ConnectTimeout
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("creating pool: %w", err)
	}

	return pool, nil
}

// CheckName is the dependency name reported by readiness probes.
const CheckName = "postgres"

func (o Options) withDefaults() Options {
	defaults := DefaultOptions()
	if o.MaxConns == 0 {
		o.MaxConns = defaults.MaxConns
	}
	if o.MinConns == 0 {
		o.MinConns = defaults.MinConns
	}
	if o.MaxConnIdleTime == 0 {
		o.MaxConnIdleTime = defaults.MaxConnIdleTime
	}
	if o.MaxConnLifetime == 0 {
		o.MaxConnLifetime = defaults.MaxConnLifetime
	}
	if o.ConnectTimeout == 0 {
		o.ConnectTimeout = defaults.ConnectTimeout
	}
	return o
}

func (o Options) validate() error {
	if o.MaxConns < 1 {
		return fmt.Errorf("%w: MaxConns must be at least 1, got %d", ErrInvalidOptions, o.MaxConns)
	}
	if o.MinConns < 0 {
		return fmt.Errorf("%w: MinConns must not be negative, got %d", ErrInvalidOptions, o.MinConns)
	}
	if o.MinConns > o.MaxConns {
		return fmt.Errorf("%w: MinConns (%d) must not exceed MaxConns (%d)", ErrInvalidOptions, o.MinConns, o.MaxConns)
	}
	if o.ConnectTimeout < 0 {
		return fmt.Errorf("%w: ConnectTimeout must not be negative, got %s", ErrInvalidOptions, o.ConnectTimeout)
	}
	return nil
}
