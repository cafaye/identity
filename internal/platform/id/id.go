// Package id is the service's identifier type: RFC 4122 version 4 UUIDs.
//
// It exists instead of github.com/google/uuid because this service's dependency
// budget is argon2id, pgx and the router (AGENTS.md: "no dependency without a
// cause stated in review"). A canonical UUID is sixteen bytes and a formatting
// loop, and a fourth direct dependency to obtain it is not a trade this
// repository makes.
//
// The underlying type is [16]byte on purpose: that is exactly what pgx scans a
// Postgres uuid column into, so ids cross the database boundary with no
// conversion layer on the hot path.
package id

import (
	"crypto/rand"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// UUID is a 128-bit RFC 4122 identifier.
type UUID [16]byte

// Variant identifies how the high bits of byte 8 are set.
type Variant byte

const (
	// RFC4122 is the variant every UUID this package generates uses.
	RFC4122 Variant = iota
	// NReserved covers the other three variants, which this package never
	// generates. Parse accepts them so it can read a value from anywhere; New
	// cannot produce them.
	NReserved
)

// ErrInvalid is returned by Parse for anything that is not a UUID. It is wrapped
// with the offending input's length only — never the input itself, which may be
// caller-supplied and end up in a log line.
var ErrInvalid = errors.New("invalid UUID")

// hyphens are the four fixed dashes of the canonical 8-4-4-4-12 form.
var hyphens = [4]int{8, 13, 18, 23}

// New returns a random version 4 UUID.
//
// The error is surfaced rather than swallowed: a failure of crypto/rand means
// the process has no trustworthy entropy, and minting ids from a degraded
// source is exactly the kind of thing that should stop a process rather than be
// discovered later as duplicate keys.
func New() (UUID, error) {
	var u UUID

	if _, err := io.ReadFull(rand.Reader, u[:]); err != nil {
		return UUID{}, fmt.Errorf("reading random bytes for a UUID: %w", err)
	}

	u[6] = (u[6] & 0x0f) | 0x40 // version 4
	u[8] = (u[8] & 0x3f) | 0x80 // RFC 4122 variant

	return u, nil
}

// MustNew is New for call sites that cannot fail meaningfully — test fixtures and
// package-level examples. It is not used in request paths.
func MustNew() UUID {
	u, err := New()
	if err != nil {
		panic("id: " + err.Error())
	}
	return u
}

// Parse reads a UUID in any of the forms Postgres and Go hand back: the
// canonical 8-4-4-4-12 string in either case, optionally wrapped in braces, with
// surrounding whitespace ignored.
//
// It is deliberately not lenient beyond that. A permissive parser is how a
// truncated value becomes a valid-looking one and a WHERE clause silently
// matches the wrong row.
func Parse(s string) (UUID, error) {
	var u UUID

	trimmed := strings.TrimSpace(s)
	trimmed = strings.TrimPrefix(trimmed, "{")
	trimmed = strings.TrimSuffix(trimmed, "}")

	if len(trimmed) != 36 {
		return UUID{}, fmt.Errorf("%w: length %d, want 36", ErrInvalid, len(trimmed))
	}

	// Strip the dashes, then require exactly 32 hex characters. Checking the
	// dash positions afterwards is what rejects "0011223-34455-..." — 32 hex
	// characters in the wrong places is not a UUID.
	var hexDigits [32]byte
	n := 0
	for i := 0; i < len(trimmed); i++ {
		if isHyphenPosition(i) {
			continue
		}
		c := trimmed[i]
		if !isHexDigit(c) {
			return UUID{}, fmt.Errorf("%w: non-hex character at offset %d", ErrInvalid, i)
		}
		hexDigits[n] = c
		n++
	}
	if n != 32 {
		return UUID{}, fmt.Errorf("%w: %d hex digits, want 32", ErrInvalid, n)
	}
	for _, at := range hyphens {
		if trimmed[at] != '-' {
			return UUID{}, fmt.Errorf("%w: expected a dash at offset %d", ErrInvalid, at)
		}
	}

	raw, err := hex.DecodeString(string(hexDigits[:]))
	if err != nil {
		return UUID{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	copy(u[:], raw)

	return u, nil
}

// String returns the canonical lower-case 8-4-4-4-12 form.
func (u UUID) String() string {
	var buf [36]byte

	hex.Encode(buf[0:8], u[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], u[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], u[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], u[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:36], u[10:16])

	return string(buf[:])
}

// IsZero reports whether u is the nil UUID, which is how a caller tells "no id"
// from "an id that happens to be all zero bits".
func (u UUID) IsZero() bool { return u == UUID{} }

// Version returns the version nibble, so 4 for a value from New.
func (u UUID) Version() int { return int(u[6] >> 4) }

// Variant returns the variant encoded in byte 8.
func (u UUID) Variant() Variant {
	switch {
	case u[8]&0x80 == 0x00:
		return NReserved
	default:
		return RFC4122
	}
}

// MarshalJSON encodes the canonical string. Without this a UUID would marshal as
// a sixteen-element byte array, and every response body would carry it.
func (u UUID) MarshalJSON() ([]byte, error) {
	return json.Marshal(u.String())
}

// UnmarshalJSON accepts the canonical string and nothing else, so a malformed id
// in a request body is a decode error rather than a silently zeroed field.
func (u *UUID) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("UUID must be a string: %w", err)
	}
	parsed, err := Parse(s)
	if err != nil {
		return err
	}
	*u = parsed
	return nil
}

// Value implements driver.Valuer for drivers that do not use pgx's native
// [16]byte uuid support.
func (u UUID) Value() (driver.Value, error) { return u.String(), nil }

// Scan implements sql.Scanner.
func (u *UUID) Scan(src any) error {
	switch v := src.(type) {
	case string:
		parsed, err := Parse(v)
		if err != nil {
			return err
		}
		*u = parsed
		return nil
	case []byte:
		parsed, err := Parse(string(v))
		if err != nil {
			return err
		}
		*u = parsed
		return nil
	default:
		return fmt.Errorf("%w: cannot scan %T", ErrInvalid, src)
	}
}

func isHyphenPosition(i int) bool {
	for _, at := range hyphens {
		if i == at {
			return true
		}
	}
	return false
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
