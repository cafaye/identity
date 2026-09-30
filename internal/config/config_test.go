package config

import (
	"errors"
	"log/slog"
	"testing"
)

// lookupFrom builds a Lookup from a map, mirroring os.LookupEnv semantics
// (absent key -> ok=false, present-but-empty key -> ok=true, "").
func lookupFrom(env map[string]string) Lookup {
	return func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}
}

func TestLoad(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		env     map[string]string
		want    Config
		wantErr error
	}{
		{
			name: "defaults when nothing is set",
			env:  map[string]string{},
			want: Config{Port: "8080", DatabaseURL: "", LogLevel: "info"},
		},
		{
			name: "every value overridden",
			env: map[string]string{
				"PORT":         "3000",
				"DATABASE_URL": "postgres://identity@localhost:5432/identity",
				"LOG_LEVEL":    "debug",
			},
			want: Config{Port: "3000", DatabaseURL: "postgres://identity@localhost:5432/identity", LogLevel: "debug"},
		},
		{
			name: "empty DATABASE_URL means no database in v0",
			env:  map[string]string{"DATABASE_URL": ""},
			want: Config{Port: "8080", DatabaseURL: "", LogLevel: "info"},
		},
		{
			name: "LOG_LEVEL is normalised to lower case",
			env:  map[string]string{"LOG_LEVEL": "WARN"},
			want: Config{Port: "8080", DatabaseURL: "", LogLevel: "warn"},
		},
		{
			name: "unset values fall back to defaults one at a time",
			env:  map[string]string{"PORT": "9090"},
			want: Config{Port: "9090", DatabaseURL: "", LogLevel: "info"},
		},
		{
			name:    "empty PORT is a misconfiguration, not a default",
			env:     map[string]string{"PORT": ""},
			wantErr: ErrInvalidPort,
		},
		{
			name:    "non numeric PORT is rejected",
			env:     map[string]string{"PORT": "http"},
			wantErr: ErrInvalidPort,
		},
		{
			name:    "PORT zero is rejected",
			env:     map[string]string{"PORT": "0"},
			wantErr: ErrInvalidPort,
		},
		{
			name:    "PORT above the TCP range is rejected",
			env:     map[string]string{"PORT": "70000"},
			wantErr: ErrInvalidPort,
		},
		{
			name:    "negative PORT is rejected",
			env:     map[string]string{"PORT": "-1"},
			wantErr: ErrInvalidPort,
		},
		{
			name:    "unknown LOG_LEVEL is rejected",
			env:     map[string]string{"LOG_LEVEL": "chatty"},
			wantErr: ErrInvalidLogLevel,
		},
		{
			name:    "empty LOG_LEVEL is a misconfiguration",
			env:     map[string]string{"LOG_LEVEL": ""},
			wantErr: ErrInvalidLogLevel,
		},
		{
			name:    "non postgres DATABASE_URL is rejected",
			env:     map[string]string{"DATABASE_URL": "mysql://localhost/identity"},
			wantErr: ErrInvalidDatabaseURL,
		},
		{
			name:    "DATABASE_URL without a scheme is rejected",
			env:     map[string]string{"DATABASE_URL": "localhost:5432/identity"},
			wantErr: ErrInvalidDatabaseURL,
		},
		{
			name: "postgresql scheme is accepted",
			env:  map[string]string{"DATABASE_URL": "postgresql://localhost/identity?sslmode=disable"},
			want: Config{Port: "8080", DatabaseURL: "postgresql://localhost/identity?sslmode=disable", LogLevel: "info"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Load(lookupFrom(tt.env))

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Load() error = %v, want errors.Is(_, %v)", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("Load() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestLoadNilLookupReturnsDefaults(t *testing.T) {
	t.Parallel()

	got, err := Load(nil)
	if err != nil {
		t.Fatalf("Load(nil) unexpected error: %v", err)
	}
	want := Config{Port: DefaultPort, DatabaseURL: "", LogLevel: DefaultLogLevel}
	if got != want {
		t.Errorf("Load(nil) = %+v, want %+v", got, want)
	}
}

func TestConfigAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		port string
		want string
	}{
		{name: "default port", port: "8080", want: ":8080"},
		{name: "explicit port", port: "3000", want: ":3000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := (Config{Port: tt.port}).Addr(); got != tt.want {
				t.Errorf("Addr() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConfigSlogLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		logLevel string
		want     slog.Level
	}{
		{logLevel: "debug", want: slog.LevelDebug},
		{logLevel: "info", want: slog.LevelInfo},
		{logLevel: "warn", want: slog.LevelWarn},
		{logLevel: "error", want: slog.LevelError},
	}

	for _, tt := range tests {
		t.Run(tt.logLevel, func(t *testing.T) {
			t.Parallel()

			if got := (Config{LogLevel: tt.logLevel}).SlogLevel(); got != tt.want {
				t.Errorf("SlogLevel() = %v, want %v", got, tt.want)
			}
		})
	}
}
