package id

import (
	"encoding/json"
	"testing"
)

// The dependency budget for this service is argon2id, pgx and the router
// (AGENTS.md: "no dependency without a cause stated in review"). A UUID type is
// a hundred lines of formatting, and a fourth direct dependency to get it is
// not a trade this repository makes. Underlying [16]byte is also what pgx scans
// a Postgres uuid column into, so there is no conversion layer.

func TestNewProducesAWellFormedVersion4UUID(t *testing.T) {
	t.Parallel()

	got, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if got.Version() != 4 {
		t.Errorf("Version() = %d, want 4", got.Version())
	}
	if got.Variant() != RFC4122 {
		t.Errorf("Variant() = %v, want RFC4122", got.Variant())
	}
	if got.IsZero() {
		t.Error("New() produced the nil UUID")
	}
}

func TestNewIsUnique(t *testing.T) {
	t.Parallel()

	// 100k collisions in 122 bits of entropy is not a thing that happens; if it
	// does, the source is not random and every other guarantee here is void.
	const n = 100_000

	seen := make(map[UUID]struct{}, n)
	for range n {
		u, err := New()
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, dup := seen[u]; dup {
			t.Fatalf("New() repeated %s after a few thousand calls", u)
		}
		seen[u] = struct{}{}
	}
}

func TestStringIsLowercaseCanonicalForm(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give UUID
		want string
	}{
		{
			// The RFC 4122 example, which pins the layout: 8-4-4-4-12 lower hex.
			name: "all zero bits",
			give: UUID{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			want: "00112233-4455-6677-8899-aabbccddeeff",
		},
		{name: "all ones", give: UUID{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, want: "ffffffff-ffff-ffff-ffff-ffffffffffff"},
		{name: "nil", give: UUID{}, want: "00000000-0000-0000-0000-000000000000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.give.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseAndStringRoundTrip(t *testing.T) {
	t.Parallel()

	const canonical = "00112233-4455-6677-8899-aabbccddeeff"

	parsed, err := Parse(canonical)
	if err != nil {
		t.Fatalf("Parse(%q): %v", canonical, err)
	}
	if got := parsed.String(); got != canonical {
		t.Errorf("round trip = %q, want %q", got, canonical)
	}
}

func TestParseAcceptsTheFormsPostgresHandsBack(t *testing.T) {
	t.Parallel()

	const canonical = "00112233-4455-6677-8899-aabbccddeeff"
	want, err := Parse(canonical)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	tests := []struct {
		name string
		give string
	}{
		{name: "canonical", give: canonical},
		{name: "upper case", give: "00112233-4455-6677-8899-AABBCCDDEEFF"},
		{name: "braced, as some drivers return it", give: "{00112233-4455-6677-8899-aabbccddeeff}"},
		{name: "surrounding whitespace", give: "  00112233-4455-6677-8899-aabbccddeeff\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Parse(tt.give)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tt.give, err)
			}
			if got != want {
				t.Errorf("Parse(%q) = %s, want %s", tt.give, got, want)
			}
		})
	}
}

func TestParseRejectsAnythingElse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
	}{
		{name: "empty", give: ""},
		{name: "not a uuid", give: "nope"},
		{name: "too short", give: "00112233-4455-6677-8899-aabbccddee"},
		{name: "too long", give: "00112233-4455-6677-8899-aabbccddeeffff"},
		{name: "missing a dash", give: "00112233445566778899aabbccddeeff"},
		{name: "a dash in the wrong place", give: "0011223-34455-6677-8899-aabbccddeeff"},
		{name: "non-hex characters", give: "00112233-4455-6677-8899-aabbccddeezz"},
		{name: "a sql injection attempt", give: "00112233-4455-6677-8899-aabbccddeeff' OR '1'='1"},
		{name: "a uuid namespace instead of a uuid", give: "urn:uuid:00112233-4455-6677-8899-aabbccddeeff"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got, err := Parse(tt.give); err == nil {
				t.Errorf("Parse(%q) = %s, want an error", tt.give, got)
			}
		})
	}
}

// IsZero is how a caller tells "no id" from "the id that happens to be all
// zeros". Used to keep a zero id out of a WHERE clause.
func TestIsZero(t *testing.T) {
	t.Parallel()

	if !(UUID{}).IsZero() {
		t.Error("the nil UUID does not report IsZero")
	}
	if u, err := New(); err != nil {
		t.Fatalf("New: %v", err)
	} else if u.IsZero() {
		t.Error("a generated UUID reports IsZero")
	}
}

// The id appears in every response body, so it has to marshal as the canonical
// string and unmarshal back. A [16]byte would otherwise render as a byte array.
func TestJSONRoundTrip(t *testing.T) {
	t.Parallel()

	const canonical = "00112233-4455-6677-8899-aabbccddeeff"
	parsed, err := Parse(canonical)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	encoded, err := json.Marshal(parsed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(encoded) != `"`+canonical+`"` {
		t.Errorf("Marshal() = %s, want %q", encoded, canonical)
	}

	var back UUID
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back != parsed {
		t.Errorf("Unmarshal() = %s, want %s", back, parsed)
	}
}

func TestScanAndValueForPostgres(t *testing.T) {
	t.Parallel()

	const canonical = "00112233-4455-6677-8899-aabbccddeeff"
	parsed, err := Parse(canonical)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// Postgres sends uuid as text; a driver that does not use pgx's native
	// [16]byte path still goes through database/sql's Scanner/Valuer pair.
	text, err := parsed.Value()
	if err != nil {
		t.Fatalf("Value: %v", err)
	}
	if text != canonical {
		t.Errorf("Value() = %v, want %q", text, canonical)
	}

	var scanned UUID
	if err := scanned.Scan([]byte(canonical)); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if scanned != parsed {
		t.Errorf("Scan() = %s, want %s", scanned, parsed)
	}
	if err := scanned.Scan(42); err == nil {
		t.Error("Scan(42) returned no error, want a rejection")
	}
}
