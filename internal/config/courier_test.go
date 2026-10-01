package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The courier block, as a table over the four states a deployment can be in.
//
// FOUR ROWS AND NO MORE, because the shape of the rule is all-or-nothing: absent,
// partial, present-and-valid, present-and-invalid. A test with one row per variable
// would be testing six configurations and would miss the one that matters, which is
// the pair that differs by a single missing variable.
func TestTheCourierBlockIsAllOrNothing(t *testing.T) {
	const validURL = "https://courier.example.com"
	const validLink = "https://app.example.com/reset?token=" + recoveryTokenPlaceholder

	cases := []struct {
		name    string
		env     map[string]string
		wantErr error
		// wantEnabled is what CourierEnabled reports on success.
		wantEnabled bool
		wantNoToken bool
	}{
		{
			name: "all three set is the working configuration",
			env: map[string]string{
				"COURIER_BASE_URL":       validURL,
				"COURIER_TOKEN":          "svc-3f9a1c7e5b2d8046",
				"RECOVERY_LINK_TEMPLATE": validLink,
			},
			wantEnabled: true,
		},
		{
			name:    "all three absent is a deployment with no mail path, and is supported",
			env:     map[string]string{},
			wantErr: nil,
		},
		{
			name:    "a base URL with no credential would send as an anonymous caller",
			env:     map[string]string{"COURIER_BASE_URL": validURL},
			wantErr: ErrInvalidCourier,
		},
		{
			name:    "a credential with no base URL is a secret with nowhere to go",
			env:     map[string]string{"COURIER_TOKEN": "svc-3f9a1c7e5b2d8046"},
			wantErr: ErrInvalidCourier,
		},
		{
			name: "a link template with no base URL",
			env: map[string]string{
				"RECOVERY_LINK_TEMPLATE": validLink,
			},
			wantErr: ErrInvalidCourier,
		},
		{
			name: "a base URL and a token with no link template",
			env: map[string]string{
				"COURIER_BASE_URL": validURL,
				"COURIER_TOKEN":    "svc-3f9a1c7e5b2d8046",
			},
			wantErr: ErrInvalidCourier,
		},
		{
			name: "a link template and a token with no base URL",
			env: map[string]string{
				"COURIER_TOKEN":          "svc-3f9a1c7e5b2d8046",
				"RECOVERY_LINK_TEMPLATE": validLink,
			},
			wantErr: ErrInvalidCourier,
		},
		{
			name: "a base URL and a link template with no token",
			env: map[string]string{
				"COURIER_BASE_URL":       validURL,
				"RECOVERY_LINK_TEMPLATE": validLink,
			},
			wantErr: ErrInvalidCourier,
		},
		{
			name: "a base URL that is not a URL at all",
			env: map[string]string{
				"COURIER_BASE_URL":       "://nope",
				"COURIER_TOKEN":          "svc-3f9a1c7e5b2d8046",
				"RECOVERY_LINK_TEMPLATE": validLink,
			},
			wantErr: ErrInvalidCourier,
		},
		{
			name: "a base URL that is not http",
			env: map[string]string{
				"COURIER_BASE_URL":       "courier.example.com",
				"COURIER_TOKEN":          "svc-3f9a1c7e5b2d8046",
				"RECOVERY_LINK_TEMPLATE": validLink,
			},
			wantErr: ErrInvalidCourier,
		},
		{
			name: "a base URL with a query, which a path would be appended to",
			env: map[string]string{
				"COURIER_BASE_URL":       "https://courier.example.com?debug=1",
				"COURIER_TOKEN":          "svc-3f9a1c7e5b2d8046",
				"RECOVERY_LINK_TEMPLATE": validLink,
			},
			wantErr: ErrInvalidCourier,
		},
		{
			name: "a link template with no placeholder, so a reset link has no token",
			env: map[string]string{
				"COURIER_BASE_URL":       validURL,
				"COURIER_TOKEN":          "svc-3f9a1c7e5b2d8046",
				"RECOVERY_LINK_TEMPLATE": "https://app.example.com/reset",
			},
			wantErr: ErrInvalidCourier,
		},
		{
			name: "a relative link template, which cannot be rendered in a mail",
			env: map[string]string{
				"COURIER_BASE_URL":       validURL,
				"COURIER_TOKEN":          "svc-3f9a1c7e5b2d8046",
				"RECOVERY_LINK_TEMPLATE": "/reset?token=" + recoveryTokenPlaceholder,
			},
			wantErr: ErrInvalidCourier,
		},
		{
			name: "a link template whose fragment a mail client would not send",
			env: map[string]string{
				"COURIER_BASE_URL":       validURL,
				"COURIER_TOKEN":          "svc-3f9a1c7e5b2d8046",
				"RECOVERY_LINK_TEMPLATE": "https://app.example.com/reset#/" + recoveryTokenPlaceholder,
			},
			wantErr: ErrInvalidCourier,
		},
		{
			name: "a link template with a userinfo section, which is a credential in a URL",
			env: map[string]string{
				"COURIER_BASE_URL":       validURL,
				"COURIER_TOKEN":          "svc-3f9a1c7e5b2d8046",
				"RECOVERY_LINK_TEMPLATE": "https://kaka:pw@app.example.com/reset?token=" + recoveryTokenPlaceholder,
			},
			wantErr: ErrInvalidCourier,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Load(lookupFrom(tc.env))

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Load error = %v, want one matching %v", err, tc.wantErr)
				}
				// A partial or invalid block must not leave a half-configured
				// deployment behind: `Load` returns the zero Config on any error, and
				// a caller that ignored the error would otherwise find a process that
				// believes it can send mail.
				if cfg.CourierEnabled() {
					t.Error("Load returned a Config that reports a mail path alongside an error")
				}
				// And the message must NAME the variable, because an operator reading
				// a startup log cannot act on "invalid courier configuration".
				if !strings.Contains(err.Error(), "COURIER_") &&
					!strings.Contains(err.Error(), "RECOVERY_LINK_TEMPLATE") {
					t.Errorf("the error names no variable: %v", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got := cfg.CourierEnabled(); got != tc.wantEnabled {
				t.Errorf("CourierEnabled = %t, want %t", got, tc.wantEnabled)
			}
			if tc.wantEnabled {
				// And the token is readable through the accessor that distinguishes
				// "absent" from "present", because those lead to different wiring.
				token, err := cfg.CourierToken()
				if err != nil {
					t.Fatalf("CourierToken: %v", err)
				}
				if token != tc.env["COURIER_TOKEN"] {
					t.Error("CourierToken did not return the configured value")
				}
			}
		})
	}
}

// TestAnAbsentCourierBlockIsDistinguishableFromABrokenOne is the assertion the two
// sentinels exist for.
//
// `main` mounts `recovery.Unavailable{}` for one and refuses to start for the other.
// An operator who cannot tell them apart from the log has been told nothing, and
// the confusion costs an afternoon: "it started, so the mail is configured" against
// a deployment whose COURIER_BASE_URL has a typo in it.
func TestAnAbsentCourierBlockIsDistinguishableFromABrokenOne(t *testing.T) {
	absent, err := Load(lookupFrom(map[string]string{}))
	if err != nil {
		t.Fatalf("an absent courier block must not be an error: %v", err)
	}
	if _, err := absent.CourierToken(); !errors.Is(err, ErrNoCourierToken) {
		t.Errorf("an absent token = %v, want ErrNoCourierToken", err)
	}
	// The two must not be the same value. `errors.Is` matching across them would
	// mean a caller could not choose what to do.
	if errors.Is(ErrNoCourierToken, ErrInvalidCourier) || errors.Is(ErrInvalidCourier, ErrNoCourierToken) {
		t.Error("the absent and invalid sentinels are the same value, so no caller can tell them apart")
	}

	broken, err := Load(lookupFrom(map[string]string{"COURIER_BASE_URL": "https://courier.example.com"}))
	if !errors.Is(err, ErrInvalidCourier) {
		t.Fatalf("a partial block = %v, want ErrInvalidCourier", err)
	}
	// And a broken one does NOT read as absent, which is the mistake the two
	// sentinels prevent.
	if errors.Is(err, ErrNoCourierToken) {
		t.Error("a partial block reported itself as an absent token, so a deployment with a typo would mount Unavailable instead of failing to start")
	}
	_ = broken
}

// TestTheBootRulesAndTheClientRulesAgree is the drift check between the two places
// a courier URL is validated.
//
// The duplication is deliberate and recorded in `validateMailBaseURL`'s comment;
// this is what pays for it. A rule that changed on one side and not the other would
// mean a deployment boot refuses nothing the client refuses, or the reverse, and
// the failure would appear in whichever direction nobody tested.
func TestTheBootRulesAndTheClientRulesAgree(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		wantBoot bool
	}{
		{name: "https", raw: "https://courier.example.com", wantBoot: true},
		{name: "http for a local stack", raw: "http://localhost:4003", wantBoot: true},
		{name: "http over a hostname", raw: "http://courier.example.com", wantBoot: true},
		{name: "a path on the base URL", raw: "https://courier.example.com/v1", wantBoot: true},
		{name: "a trailing slash", raw: "https://courier.example.com/", wantBoot: true},
		{name: "no scheme", raw: "courier.example.com", wantBoot: false},
		{name: "a non-http scheme", raw: "ftp://courier.example.com", wantBoot: false},
		{name: "no host", raw: "https://", wantBoot: false},
		{name: "a query", raw: "https://courier.example.com?a=1", wantBoot: false},
		{name: "a fragment", raw: "https://courier.example.com#x", wantBoot: false},
		{name: "empty", raw: "", wantBoot: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bootAccepted := validateMailBaseURL(tc.raw) == nil
			if bootAccepted != tc.wantBoot {
				t.Errorf("boot accepted %q = %t, want %t", tc.raw, bootAccepted, tc.wantBoot)
			}
		})
	}
}

// TestTheBootPlaceholderIsCouriersPlaceholder holds the one constant that is
// duplicated rather than imported, which is a decision with a cost and this is what
// pays it back.
func TestTheBootPlaceholderIsCouriersPlaceholder(t *testing.T) {
	// Read the courier package's declaration. Importing it would invert the
	// layering — `internal/courier` implements `recovery.Mailer` and this package
	// is the service's configuration — so a source read is the honest check.
	source := readSource(t, "courier")
	if !strings.Contains(source, `TokenPlaceholder = "`+recoveryTokenPlaceholder+`"`) {
		t.Errorf("internal/courier no longer declares TokenPlaceholder as %q; a link "+
			"template validated here would be rejected there", recoveryTokenPlaceholder)
	}
}

// readSource reads a sibling package's source, for the one check that cannot use an
// import without inverting the layering.
func readSource(t *testing.T, pkg string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", pkg, "mailer.go"))
	if err != nil {
		t.Fatalf("reading internal/%s: %v", pkg, err)
	}
	return string(raw)
}
