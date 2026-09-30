package mfa

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
)

// A fixed instant, and a fixed secret. Nothing in this file sleeps or reads the
// wall clock: every window assertion is a function of the instant it is handed,
// which is the reason internal/platform/clock exists (PLAN.md §3).
var (
	at       = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	rawKey   = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	stepBase = StepAt(at, Period)
)

// codeFor is the code an authenticator would be showing for a step.
func codeFor(t *testing.T, secret string, step int64) string {
	t.Helper()
	code, err := hotp.GenerateCodeCustom(secret, uint64(step), hotp.ValidateOpts{
		Digits:    six,
		Algorithm: sha1,
	})
	if err != nil {
		t.Fatalf("generating a code for step %d: %v", step, err)
	}
	return code
}

// TestTheSkewWindowIsExactlyWhatTheCommentSays is the assertion the packet asks
// for by name, and it is a table because the answer has edges.
//
// The window is one step either side. Two steps out is refused — that is what
// makes it one and not two — and the refusal is a refusal, not a different code.
func TestTheSkewWindowIsExactlyWhatTheCommentSays(t *testing.T) {
	cases := []struct {
		name  string
		steps int64
		want  bool
	}{
		{"two steps back is refused", -2, false},
		{"one step back is accepted", -1, true},
		{"the current step is accepted", 0, true},
		{"one step forward is accepted", 1, true},
		{"two steps forward is refused", 2, false},
		{"ten steps forward is refused", 10, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, got := MatchStep(rawKey, codeFor(t, rawKey, stepBase+c.steps), at,
				DigitSix, AlgorithmSHA1, Period, SkewSteps)
			if got != c.want {
				t.Errorf("MatchStep = %v, want %v", got, c.want)
			}
		})
	}
}

// TestTheWindowIsTheSameForEveryInstant is what makes it a policy rather than an
// accident of the fixture's timestamp. A window that only held at a
// second-aligned instant would be a bug that a single test at 12:00:00 would pass.
func TestTheWindowIsTheSameForEveryInstant(t *testing.T) {
	// Deliberately unaligned: 12:00:17 is seventeen seconds into a step, so the
	// previous step's code is only thirteen seconds old and a code generated for
	// it is genuinely still on somebody's screen.
	for _, offset := range []time.Duration{0, 7 * time.Second, 17 * time.Second, 29 * time.Second} {
		instant := at.Add(offset)
		base := StepAt(instant, Period)

		if _, ok := MatchStep(rawKey, codeFor(t, rawKey, base-1), instant, DigitSix, AlgorithmSHA1, Period, SkewSteps); !ok {
			t.Errorf("at +%s: the previous step's code was refused", offset)
		}
		if _, ok := MatchStep(rawKey, codeFor(t, rawKey, base+2), instant, DigitSix, AlgorithmSHA1, Period, SkewSteps); ok {
			t.Errorf("at +%s: a code two steps ahead was accepted", offset)
		}
	}
}

// TestMatchStepSaysWHICHStepMatched is the reason this package walks the window
// itself instead of calling the library's ValidateCustom and getting a bool.
//
// The replay guard stores a step. A bool cannot be stored, and a bool is all
// pquerna/otp's own windowed validation offers.
func TestMatchStepSaysWHICHStepMatched(t *testing.T) {
	step, ok := MatchStep(rawKey, codeFor(t, rawKey, stepBase-1), at, DigitSix, AlgorithmSHA1, Period, SkewSteps)
	if !ok {
		t.Fatal("MatchStep did not match a code inside the window")
	}
	if step != stepBase-1 {
		t.Errorf("MatchStep = step %d, want %d", step, stepBase-1)
	}
}

// TestCandidateStepsIsTheDocumentedWindow pins the shape of the list, because the
// argument in SkewSteps is about how many entries it has and an entry that
// appeared without anyone deciding would be thirty more seconds of a phished
// code's life.
func TestCandidateStepsIsTheDocumentedWindow(t *testing.T) {
	got := CandidateSteps(100, SkewSteps)
	want := []int64{100, 101, 99}

	if len(got) != len(want) {
		t.Fatalf("CandidateSteps = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("CandidateSteps = %v, want %v", got, want)
		}
	}
	if len(CandidateSteps(100, 0)) != 1 {
		t.Error("a skew of zero must still admit the current step")
	}
}

// TestACodeIsRefusedForADifferentSecret is the rotation property at the level
// below the database: a code is a function of the secret and nothing else.
func TestACodeIsRefusedForADifferentSecret(t *testing.T) {
	other := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	code := codeFor(t, other, stepBase)

	if _, ok := MatchStep(rawKey, code, at, DigitSix, AlgorithmSHA1, Period, SkewSteps); ok {
		t.Error("a code from a rotated-away secret was accepted")
	}
	if _, ok := MatchStep(other, code, at, DigitSix, AlgorithmSHA1, Period, SkewSteps); !ok {
		t.Error("a code from the current secret was refused")
	}
}

// TestTheRefusalsAreRefusalsRatherThanPanics. A corrupt row must fail closed,
// not take the process down, and must not be distinguishable from a wrong code.
func TestTheRefusalsAreRefusalsRatherThanPanics(t *testing.T) {
	cases := []struct {
		name      string
		secret    string
		code      string
		digits    string
		algorithm string
	}{
		{"an empty secret", "", "123456", DigitSix, AlgorithmSHA1},
		{"an empty code", rawKey, "", DigitSix, AlgorithmSHA1},
		{"a secret that is not base32", "not base32 at all!", "123456", DigitSix, AlgorithmSHA1},
		{"a secret of the wrong length", "JBSWY3DP", "123456", DigitSix, AlgorithmSHA1},
		{"a digit count this service cannot verify", rawKey, "123456", "7", AlgorithmSHA1},
		{"an algorithm this service cannot verify", rawKey, "123456", DigitSix, "SHA512"},
		{"a code with a letter in it", rawKey, "12345a", DigitSix, AlgorithmSHA1},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// A negative instant would produce a negative counter, which uint64
			// turns into a step in the year 584 billion. It must be skipped, not
			// computed.
			if _, ok := MatchStep(c.secret, c.code, at, c.digits, c.algorithm, Period, SkewSteps); ok {
				t.Error("a value this service cannot interpret was accepted")
			}
			if _, ok := MatchStep(c.secret, c.code, time.Unix(-600, 0), c.digits, c.algorithm, Period, SkewSteps); ok {
				t.Error("a pre-epoch instant produced a match")
			}
		})
	}
}

// TestCodeAgreesWithTheLibrary is a cross-check on the wiring: this package's Code
// and the library's own ValidateCustom must see the same window, or the tests
// above would be asserting against a window nothing else in the ecosystem uses.
//
// Without it, a future edit that passed SkewSteps: 0 here and left the library's
// own default of 1 somewhere would not be caught by anything in this repository.
func TestCodeAgreesWithTheLibrary(t *testing.T) {
	for _, offset := range []int64{-1, 0, 1} {
		code := codeFor(t, rawKey, stepBase+offset)

		ok, err := totp.ValidateCustom(code, rawKey, at, totp.ValidateOpts{
			Period:    uint(Period / time.Second),
			Skew:      SkewSteps,
			Digits:    six,
			Algorithm: sha1,
		})
		if err != nil {
			t.Fatalf("the library refused to validate: %v", err)
		}
		if !ok {
			t.Errorf("offset %d: the library's own windowed validation refused the code", offset)
		}

		_, ours := MatchStep(rawKey, code, at, DigitSix, AlgorithmSHA1, Period, SkewSteps)
		if !ours {
			t.Errorf("offset %d: MatchStep refused a code the library accepted", offset)
		}
	}
}

// TestStepAtIsTheDocumentedCounter pins the arithmetic the replay table is keyed
// on, because a step is stored forever and a rounding change would strand rows
// that nothing can ever prune.
func TestStepAtIsTheDocumentedCounter(t *testing.T) {
	cases := []struct {
		at   time.Time
		want int64
	}{
		{time.Unix(0, 0), 0},
		{time.Unix(29, 0), 0},
		{time.Unix(30, 0), 1},
		{time.Unix(59, 0), 1},
		{time.Unix(60, 0), 2},
	}

	for _, c := range cases {
		if got := StepAt(c.at, Period); got != c.want {
			t.Errorf("StepAt(%s) = %d, want %d", c.at, c.want, got)
		}
	}
}

// TestCodeTTLIsTheWindowAndNotThePeriod. The value the pruning query and any
// prose about a code's life are both derived from, asserted once so neither can be
// quietly halved.
func TestCodeTTLIsTheWindowAndNotThePeriod(t *testing.T) {
	if CodeTTL != 90*time.Second {
		t.Errorf("CodeTTL = %s, want 90s (one step, either side, plus the step itself)", CodeTTL)
	}
	if CodeTTL <= Period {
		t.Error("CodeTTL must exceed the period, or there is no window at all")
	}
}

// TestIsTOTPCode is the shape test, and the six-and-six-syllables rule is why the
// two kinds of factor can share one request field.
func TestIsTOTPCode(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"123456", true},
		{"000000", true},
		{"999999", true},
		{"12345", false},
		{"1234567", false},
		{"12345a", false},
		{"123 456", false},
		{"-12345", false},
		{"", false},
		{strings.Repeat("1", 8), false},
	}

	for _, c := range cases {
		if got := isTOTPCode(c.in); got != c.want {
			t.Errorf("isTOTPCode(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
