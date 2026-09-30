package users

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNormalizeEmail(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
		want string
	}{
		{name: "already normalized", give: "kaka@example.com", want: "kaka@example.com"},
		{name: "upper case is lowered", give: "Kaka@Example.COM", want: "kaka@example.com"},
		{name: "surrounding space is trimmed", give: "  kaka@example.com  ", want: "kaka@example.com"},
		{name: "both at once", give: "\t KAKA@Example.com \n", want: "kaka@example.com"},
		{name: "inner space is preserved so validation can reject it", give: "ka ka@example.com", want: "ka ka@example.com"},
		{name: "empty stays empty", give: "", want: ""},
		{name: "whitespace only becomes empty", give: "   ", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := NormalizeEmail(tt.give); got != tt.want {
				t.Errorf("NormalizeEmail(%q) = %q, want %q", tt.give, got, tt.want)
			}
		})
	}
}

func TestNormalizeEmailIsIdempotent(t *testing.T) {
	t.Parallel()

	// Registration and login both normalize. If normalizing twice were not the
	// same as normalizing once, the second pass would look up a different string
	// than the first one stored.
	once := NormalizeEmail("  Kaka@Example.com ")
	twice := NormalizeEmail(once)

	if once != twice {
		t.Errorf("NormalizeEmail is not idempotent: %q then %q", once, twice)
	}
}

func TestValidateEmail(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		give     string
		wantCode string
	}{
		{name: "a plain address", give: "kaka@example.com"},
		{name: "plus addressing is preserved", give: "kaka+cafaye@example.com"},
		{name: "subdomains are fine", give: "kaka@mail.eu.example.com"},
		{name: "digits and hyphens in the local part", give: "kaka-2@example.com"},
		{name: "digits in the domain", give: "kaka@example2.com"},
		{name: "a long local part at the RFC limit", give: strings.Repeat("a", 64) + "@example.com"},
		{name: "the dot in the domain is required", give: "kaka@example", wantCode: "invalid_format"},
		{name: "no at sign", give: "kaka.example.com", wantCode: "invalid_format"},
		{name: "two at signs", give: "kaka@@example.com", wantCode: "invalid_format"},
		{name: "empty local part", give: "@example.com", wantCode: "invalid_format"},
		{name: "empty domain", give: "kaka@", wantCode: "invalid_format"},
		{name: "empty adjacent labels", give: "kaka@example..com", wantCode: "invalid_format"},
		{name: "a leading hyphen is not a domain label", give: "kaka@-example.com", wantCode: "invalid_format"},
		{name: "a trailing hyphen is not a domain label", give: "kaka@example-.com", wantCode: "invalid_format"},
		{name: "an inner space is not allowed", give: "ka ka@example.com", wantCode: "invalid_format"},
		{name: "a tab is not allowed", give: "kaka@exa\tmple.com", wantCode: "invalid_format"},
		{name: "a newline cannot be smuggled in", give: "kaka@example.com\nBcc: victim@example.com", wantCode: "invalid_format"},
		{name: "empty", give: "", wantCode: "required"},
		{name: "whitespace only", give: "   ", wantCode: "required"},
		{name: "over the RFC 5321 length limit", give: strings.Repeat("a", 310) + "@example.com", wantCode: "too_long"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateEmail(NormalizeEmail(tt.give))

			if tt.wantCode == "" {
				if err != nil {
					t.Errorf("ValidateEmail(%q) = %v, want nil", tt.give, err)
				}
				return
			}

			assertFieldError(t, err, "email", tt.wantCode)
		})
	}
}

func TestValidatePassword(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		give     string
		wantCode string
	}{
		{name: "exactly the minimum", give: "12345678"},
		{name: "longer than the minimum", give: "correct horse battery staple"},
		// The brief says min 8 characters, not min 8 of one class. Composition
		// rules push people toward "Password1!", which is weaker than a long
		// passphrase, so the only length rules enforced are the two below.
		{name: "a passphrase with spaces is allowed", give: "correct horse battery staple"},
		{name: "one under the minimum", give: "1234567", wantCode: "too_short"},
		{name: "empty", give: "", wantCode: "required"},
		// argon2id hashes its input; an unbounded password is a cheap way to make
		// one request cost a gigabyte of hashing.
		{name: "over the hashing input limit", give: strings.Repeat("a", MaxPasswordLength+1), wantCode: "too_long"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidatePassword(tt.give)

			if tt.wantCode == "" {
				if err != nil {
					t.Errorf("ValidatePassword(%q) = %v, want nil", tt.give, err)
				}
				return
			}

			assertFieldError(t, err, "password", tt.wantCode)
		})
	}
}

func TestFieldErrorCarriesTheFieldAndTheCode(t *testing.T) {
	t.Parallel()

	err := ValidateEmail("nope")

	var fe *FieldError
	if !errors.As(err, &fe) {
		t.Fatalf("ValidateEmail() = %v (%T), want a *FieldError", err, err)
	}
	if fe.Field != "email" {
		t.Errorf("Field = %q, want email", fe.Field)
	}
	if fe.Code == "" {
		t.Error("Code is empty; the HTTP layer has nothing to put in errors[].code")
	}
	if fe.Error() == "" {
		t.Error("Error() is empty")
	}
}

func assertFieldError(t *testing.T, err error, wantField, wantCode string) {
	t.Helper()

	if err == nil {
		t.Fatalf("got nil error, want field %q with code %q", wantField, wantCode)
	}

	var fe *FieldError
	if !errors.As(err, &fe) {
		t.Fatalf("error = %v (%T), want a *FieldError", err, err)
	}
	if fe.Field != wantField {
		t.Errorf("Field = %q, want %q", fe.Field, wantField)
	}
	if fe.Code != wantCode {
		t.Errorf("Code = %q, want %q", fe.Code, wantCode)
	}
}

func TestUserIsLockedOnlyWhileTheInstantIsInTheFuture(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Second)
	future := now.Add(time.Second)

	tests := []struct {
		name string
		give *time.Time
		want bool
	}{
		{name: "never locked", give: nil, want: false},
		{name: "lock has expired", give: &past, want: false},
		{name: "lock expires exactly now is not locked", give: &now, want: false},
		{name: "lock is in the future", give: &future, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			u := User{LockedUntil: tt.give}

			if got := u.IsLocked(now); got != tt.want {
				t.Errorf("IsLocked(%s) with locked_until=%v = %v, want %v", now, tt.give, got, tt.want)
			}
		})
	}
}

// RetryAfter is what the 423 body reports, so it must be the real remaining
// window and never negative or zero — "retry in 0 seconds" is a busy loop.
func TestRetryAfterCountsDownAndNeverGoesNegative(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	u := User{LockedUntil: ptr(now.Add(15 * time.Minute))}

	if got, want := u.RetryAfter(now), 15*time.Minute; got != want {
		t.Errorf("RetryAfter at lock time = %s, want %s", got, want)
	}
	if got, want := u.RetryAfter(now.Add(14*time.Minute)), time.Minute; got != want {
		t.Errorf("RetryAfter one minute later = %s, want %s", got, want)
	}
	if got := u.RetryAfter(now.Add(time.Hour)); got != 0 {
		t.Errorf("RetryAfter after the window closed = %s, want 0", got)
	}
	// Asked before the window opens the account really is still locked, so the
	// answer is the full remaining time — longer than the nominal duration, and
	// still never negative.
	if got, want := u.RetryAfter(now.Add(-time.Hour)), 75*time.Minute; got != want {
		t.Errorf("RetryAfter an hour before the lock = %s, want %s", got, want)
	}
}

func TestRetryAfterOnAnUnlockedUserIsZero(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	u := User{}

	if got := u.RetryAfter(now); got != 0 {
		t.Errorf("RetryAfter() on an unlocked user = %s, want 0", got)
	}
}

func ptr(t time.Time) *time.Time { return &t }
