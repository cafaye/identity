// Package users owns the user aggregate: the row, the credential, and the rules
// about what a valid email and password are.
//
// It knows nothing about HTTP. Handlers translate domain errors into the cafaye
// error envelope; they do not define the rules.
package users

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/cafaye/identity/internal/platform/id"
)

// Errors returned by the store and the validators. Callers match them with
// errors.Is; nothing here is compared by string.
var (
	// ErrNotFound means no such user. It is deliberately indistinguishable from
	// "no such user" in every other sense: the HTTP layer renders it as a
	// generic 401 so the response cannot be used to enumerate accounts.
	ErrNotFound = errors.New("user not found")
	// ErrEmailTaken means the address is already registered. A registration
	// endpoint is the one place this is safe to reveal, and it maps to 409.
	ErrEmailTaken = errors.New("email already registered")
)

// Field validation codes. These land verbatim in the `errors[]` array of the
// cafaye error envelope (core: docs/openapi-conventions.md), so they are part of
// the contract and clients may switch on them.
const (
	CodeRequired      = "required"
	CodeInvalidFormat = "invalid_format"
	CodeTooShort      = "too_short"
	CodeTooLong       = "too_long"
)

// MaxEmailLength is the RFC 5321 limit on a full address. It is also the upper
// bound on the bytes that reach the UNIQUE index on users.email.
const MaxEmailLength = 320

// MinPasswordLength is the floor the brief sets. There is deliberately no
// composition rule: requiring a mix of character classes reliably produces
// "Password1!" and reliably rejects passphrases. Length is the property that
// actually tracks entropy.
const MinPasswordLength = 8

// MaxPasswordLength bounds what argon2id will be asked to hash. The cost of an
// argon2id call is fixed in memory, but its input is not bounded, so without
// this an unauthenticated caller can choose the size of every login's work.
const MaxPasswordLength = 1024

// FieldError is a per-field validation failure. The HTTP layer turns one of
// these into a single entry of `errors[]` without needing to know which rules
// produced it.
type FieldError struct {
	Field string
	Code  string
}

func (e *FieldError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Code)
}

func fieldErr(field, code string) error {
	return &FieldError{Field: field, Code: code}
}

// User is the row as the domain sees it. PasswordDigest is carried because
// login has to read it; it is never rendered and never leaves this package in a
// response body.
type User struct {
	ID id.UUID
	// Email is stored normalized: lower case and trimmed. See NormalizeEmail.
	Email string
	// PasswordDigest is an argon2id encoded digest, never a plaintext password.
	PasswordDigest      string
	FailedLoginAttempts int
	// LockedUntil is nil when the account is not locked. A pointer, not a zero
	// time, because "never locked" and "locked until 1970" are different answers
	// and only one of them is true.
	LockedUntil *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// IsLocked reports whether the account is locked as of now. A lock whose instant
// has arrived is not a lock: expiry is checked on read rather than by a sweeper,
// so there is no window where the row says "locked" and the answer is "yes,
// sorry" for a window that already closed.
func (u User) IsLocked(now time.Time) bool {
	return u.LockedUntil != nil && u.LockedUntil.After(now)
}

// RetryAfter is how much longer the caller must wait. It never returns a
// negative or zero-but-locked answer: a body saying "retry in 0s" on a 423 is a
// busy loop written by whoever reads it.
func (u User) RetryAfter(now time.Time) time.Duration {
	if !u.IsLocked(now) {
		return 0
	}
	return u.LockedUntil.Sub(now)
}

// NormalizeEmail is the single definition of what "the same address" means.
//
// Registration, login and every lookup run it, so an address typed as
// "Kaka@Example.com" finds the row stored as "kaka@example.com". The database
// enforces the same invariant with a CHECK constraint; this is where it is
// established.
//
// Inner whitespace is preserved rather than stripped: "ka ka@example.com" is a
// typo, and silently repairing it would create a second account for what the
// caller believes is one address. Validation rejects it instead.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// emailPattern is deliberately stricter than RFC 5322. It requires at least one
// dot in the domain, rejects empty adjacent labels, and rejects domains whose
// labels start or end with a hyphen. The goal is not "any string mail clients
// accept" — it is "an address that could be delivered to by a real MTA", which
// rules out the shapes that make header injection and typo-typos useful.
var emailPattern = regexp.MustCompile(`^[a-z0-9!#$%&'*+/=?^_` + "`" + `{|}~.-]{1,64}@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidateEmail checks an already-normalized address. Passing a raw address is a
// bug: it would reject "Kaka@Example.com" and read as a format problem rather
// than a missing normalization step.
func ValidateEmail(normalized string) error {
	if normalized == "" {
		return fieldErr("email", CodeRequired)
	}
	if len(normalized) > MaxEmailLength {
		return fieldErr("email", CodeTooLong)
	}
	if !emailPattern.MatchString(normalized) {
		return fieldErr("email", CodeInvalidFormat)
	}
	return nil
}

// ValidatePassword enforces the length rules and nothing else. See
// MinPasswordLength for why there is no composition rule.
func ValidatePassword(password string) error {
	switch {
	case password == "":
		return fieldErr("password", CodeRequired)
	case len(password) < MinPasswordLength:
		return fieldErr("password", CodeTooShort)
	case len(password) > MaxPasswordLength:
		return fieldErr("password", CodeTooLong)
	}
	return nil
}
