package db

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestOpenWithoutDSN(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		dsn  string
	}{
		{name: "empty", dsn: ""},
		{name: "whitespace only", dsn: "   "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pool, err := Open(context.Background(), tt.dsn, DefaultOptions())

			if !errors.Is(err, ErrNoDatabaseURL) {
				t.Errorf("Open() error = %v, want errors.Is(_, ErrNoDatabaseURL)", err)
			}
			if pool != nil {
				t.Error("Open() returned a pool for an empty DSN, want nil")
			}
		})
	}
}

func TestOptionsWithDefaults(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give Options
		want Options
	}{
		{
			name: "zero value falls back to defaults",
			give: Options{},
			want: DefaultOptions(),
		},
		{
			name: "partial override keeps the other defaults",
			give: Options{MaxConns: 5},
			want: Options{
				MaxConns:        5,
				MinConns:        DefaultOptions().MinConns,
				MaxConnIdleTime: DefaultOptions().MaxConnIdleTime,
				MaxConnLifetime: DefaultOptions().MaxConnLifetime,
				ConnectTimeout:  DefaultOptions().ConnectTimeout,
			},
		},
		{
			name: "explicit values are preserved",
			give: Options{
				MaxConns:        3,
				MinConns:        1,
				MaxConnIdleTime: time.Minute,
				MaxConnLifetime: time.Hour,
				ConnectTimeout:  5 * time.Second,
			},
			want: Options{
				MaxConns:        3,
				MinConns:        1,
				MaxConnIdleTime: time.Minute,
				MaxConnLifetime: time.Hour,
				ConnectTimeout:  5 * time.Second,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.give.withDefaults(); got != tt.want {
				t.Errorf("withDefaults() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestOptionsValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		give    Options
		wantErr error
	}{
		{name: "defaults are valid", give: DefaultOptions()},
		{name: "explicit values are valid", give: Options{MaxConns: 4, MinConns: 1}},
		{name: "negative MaxConns", give: Options{MaxConns: -1}, wantErr: ErrInvalidOptions},
		{name: "negative MinConns", give: Options{MinConns: -1}, wantErr: ErrInvalidOptions},
		{name: "MinConns above MaxConns", give: Options{MaxConns: 2, MinConns: 3}, wantErr: ErrInvalidOptions},
		{name: "negative ConnectTimeout", give: Options{ConnectTimeout: -time.Second}, wantErr: ErrInvalidOptions},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.give.validate()

			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("validate() unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("validate() error = %v, want errors.Is(_, %v)", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultOptionsAreSelfConsistent(t *testing.T) {
	t.Parallel()

	opts := DefaultOptions()
	if err := opts.validate(); err != nil {
		t.Fatalf("DefaultOptions() is not valid: %v", err)
	}
	if opts.MaxConns < 2 {
		t.Errorf("DefaultOptions().MaxConns = %d, want room for at least one request plus one probe", opts.MaxConns)
	}
	if opts.ConnectTimeout <= 0 {
		t.Errorf("DefaultOptions().ConnectTimeout = %v, want a positive startup bound", opts.ConnectTimeout)
	}
}

// TestOpenAndPingIntegration is the real Postgres path. It is skipped unless
// TEST_DATABASE_URL points at a reachable database, so the default suite needs
// no Postgres and CI runs it against the compose service.
func TestOpenAndPingIntegration(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres integration test")
	}

	pool, err := Open(context.Background(), dsn, DefaultOptions())
	if err != nil {
		t.Fatalf("Open(%q) unexpected error: %v", dsn, err)
	}
	defer pool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}

	var version string
	if err := pool.QueryRow(ctx, "select version()").Scan(&version); err != nil {
		t.Fatalf("querying version() error = %v", err)
	}
	if version == "" {
		t.Error("version() returned an empty string")
	}
}

// TestOpenAppliesConfiguredPoolSize proves the pool honours Options, again
// only when a real database is available.
func TestOpenAppliesConfiguredPoolSize(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres integration test")
	}

	pool, err := Open(context.Background(), dsn, Options{MaxConns: 7, MinConns: 2})
	if err != nil {
		t.Fatalf("Open() unexpected error: %v", err)
	}
	defer pool.Close()

	if got := pool.Config().MaxConns; got != 7 {
		t.Errorf("pool MaxConns = %d, want 7", got)
	}
	if got := pool.Config().MinConns; got != 2 {
		t.Errorf("pool MinConns = %d, want 2", got)
	}
}
