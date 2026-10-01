package config

import (
	"errors"
	"strings"
	"testing"

	"github.com/cafaye/identity/internal/recovery"
)

// # PER-PURPOSE LINK TEMPLATES, AS A DEPLOYMENT SEES THEM
//
// Three variables, and the shape of the rule is a default plus two overrides:
//
//	RECOVERY_LINK_TEMPLATE            the link for EVERY purpose that has no
//	                                  variable of its own. This is the variable that
//	                                  existed before there were per-purpose ones.
//	PASSWORD_RESET_LINK_TEMPLATE      the password reset link, and only that.
//	EMAIL_VERIFICATION_LINK_TEMPLATE  the address-confirmation link, and only that.
//
// The default is not a convenience. It is what keeps every deployment configured
// before this change booting, and the cost of it — that an unmigrated deployment's
// verification link still points at whatever its one template says — is stated in
// `internal/courier/link_purpose_test.go` and warned about at startup by
// `buildMailer`. The alternative, deriving a verification path from the reset one,
// is the platform picking a product's URL, which is the thing `LinkTemplate` exists
// to avoid.
//
// # WHAT IS ASSERTED HERE, AND WHAT IS ASSERTED NEXT DOOR
//
// HERE: that a deployment's environment resolves to one template per purpose, that
// the old environment still resolves to two, that a purpose with neither its own
// variable nor the default is a STARTUP FAILURE rather than a silent fallback, and
// that every refusal names the variable that caused it.
//
// NEXT DOOR, in `internal/courier`: that the resolved templates actually produce
// two different links and that each carries a credential its own endpoint accepts.
// Neither file can hold the other's half — this one has no adapter and that one has
// no environment.

// defaultTemplate is the single template a deployment configured before this
// change, named here so the compatibility tests and the drift check below cannot
// drift apart from the fixture they describe.
const defaultTemplate = "https://app.example.com/reset?token=" + recoveryTokenPlaceholder

// TestTheDefaultLinkTemplateIsTheDefaultForEveryPurpose is the backwards
// compatibility claim, as a table over the four configurations a deployment can be
// in once the per-purpose variables exist.
//
// EVERY ROW IS A DEPLOYMENT SOMEONE CAN ACTUALLY RUN, which is why the middle two
// are here rather than being described in a comment. A deployment that migrates one
// purpose at a time — set `EMAIL_VERIFICATION_LINK_TEMPLATE`, leave the reset alone
// — is the row that keeps working, and it is the row that is easy to break by
// treating the per-purpose variables as required-together.
func TestTheDefaultLinkTemplateIsTheDefaultForEveryPurpose(t *testing.T) {
	const resetLink = "https://app.example.com/reset?token=" + recoveryTokenPlaceholder
	const verifyLink = "https://app.example.com/verify-email?token=" + recoveryTokenPlaceholder

	credentials := map[string]string{
		"COURIER_BASE_URL": "https://courier.example.com",
		"COURIER_TOKEN":    "svc-3f9a1c7e5b2d8046",
	}

	cases := []struct {
		name string
		env  map[string]string
		// want is the template each purpose must resolve to, and a purpose absent
		// from it is a purpose `Load` must have refused.
		want map[recovery.Purpose]string
	}{
		{
			// THE COMPATIBILITY ROW, and the reason this packet does not break every
			// install that exists. One variable, two purposes, both links exactly as
			// they were — which is to say: the reset one is right and the verification
			// one is what identity-24 found. The compatibility promise is about BOOTING
			// and about the reset link, and the migration is one more variable.
			name: "the single template an existing deployment has",
			env:  map[string]string{"RECOVERY_LINK_TEMPLATE": resetLink},
			want: map[recovery.Purpose]string{
				recovery.PurposePasswordReset: resetLink,
				recovery.PurposeVerifyEmail:   resetLink,
			},
		},
		{
			// THE MIGRATION ROW. One variable added, nothing changed, and the defect
			// this packet is about is gone.
			name: "the default plus a verification link of its own",
			env: map[string]string{
				"RECOVERY_LINK_TEMPLATE":           resetLink,
				"EMAIL_VERIFICATION_LINK_TEMPLATE": verifyLink,
			},
			want: map[recovery.Purpose]string{
				recovery.PurposePasswordReset: resetLink,
				recovery.PurposeVerifyEmail:   verifyLink,
			},
		},
		{
			name: "the default plus a reset link of its own",
			env: map[string]string{
				"RECOVERY_LINK_TEMPLATE":           resetLink,
				"PASSWORD_RESET_LINK_TEMPLATE":     "https://app.example.com/forgot?token=" + recoveryTokenPlaceholder,
				"EMAIL_VERIFICATION_LINK_TEMPLATE": verifyLink,
			},
			want: map[recovery.Purpose]string{
				recovery.PurposePasswordReset: "https://app.example.com/forgot?token=" + recoveryTokenPlaceholder,
				recovery.PurposeVerifyEmail:   verifyLink,
			},
		},
		{
			// The default is OPTIONAL once every purpose has a variable of its own. A
			// deployment that has finished migrating should be able to delete the
			// legacy variable and not think about it again.
			name: "per purpose only, with the legacy variable removed",
			env: map[string]string{
				"PASSWORD_RESET_LINK_TEMPLATE":     resetLink,
				"EMAIL_VERIFICATION_LINK_TEMPLATE": verifyLink,
			},
			want: map[recovery.Purpose]string{
				recovery.PurposePasswordReset: resetLink,
				recovery.PurposeVerifyEmail:   verifyLink,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{}
			for key, value := range credentials {
				env[key] = value
			}
			for key, value := range tc.env {
				env[key] = value
			}

			cfg, err := Load(lookupFrom(env))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if !cfg.CourierEnabled() {
				t.Fatal("CourierEnabled = false for a fully configured deployment")
			}
			if len(cfg.LinkTemplates) != len(tc.want) {
				t.Fatalf("LinkTemplates has %d purposes (%v), want %d",
					len(cfg.LinkTemplates), cfg.LinkTemplates, len(tc.want))
			}
			for purpose, want := range tc.want {
				if got := cfg.LinkTemplates[purpose]; got != want {
					t.Errorf("the %s link is %q, want %q", purpose, got, want)
				}
			}
			// And the resolved set is what `main` hands the adapter, so it must be a
			// map rather than a value computed at the point of use: a caller that
			// resolved a purpose itself would be the second place the default lives.
			if cfg.LinkTemplateFor(recovery.PurposeVerifyEmail) != tc.want[recovery.PurposeVerifyEmail] {
				t.Error("LinkTemplateFor disagrees with LinkTemplates")
			}
		})
	}
}

// TestAPurposeWithNeitherItsOwnVariableNorTheDefaultRefusesToBoot is the failure
// direction, and it is a startup failure because every alternative is worse.
//
// The configuration is reachable by accident: a deployment sets
// `PASSWORD_RESET_LINK_TEMPLATE` and forgets that doing so also means it no longer
// has a default for anything else. The two ways to answer are both bad, and the
// packet's subject is the second one:
//
//	fall back to another purpose's template   every mail gets a link, the reset one
//	                                         is right, the verification one is a
//	                                         button that lands on the wrong screen,
//	                                         and nothing anywhere is red.
//	refuse to start                          one line in a startup log naming the
//	                                         variable, and a deployment that is fixed
//	                                         before a user finds out.
//
// So the test asserts the refusal AND that the message names the missing variable,
// because "invalid courier configuration" is a symptom and an operator needs the
// name.
func TestAPurposeWithNeitherItsOwnVariableNorTheDefaultRefusesToBoot(t *testing.T) {
	cases := []struct {
		name        string
		env         map[string]string
		wantNamed   string
		wantMissing bool
	}{
		{
			name:      "a reset link configured and nothing to fall back to",
			env:       map[string]string{"PASSWORD_RESET_LINK_TEMPLATE": defaultTemplate},
			wantNamed: "EMAIL_VERIFICATION_LINK_TEMPLATE",
		},
		{
			name:      "a verification link configured and nothing to fall back to",
			env:       map[string]string{"EMAIL_VERIFICATION_LINK_TEMPLATE": defaultTemplate},
			wantNamed: "PASSWORD_RESET_LINK_TEMPLATE",
		},
		{
			name:      "no link template at all, so no mail has anything to click",
			env:       map[string]string{},
			wantNamed: "RECOVERY_LINK_TEMPLATE",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{
				"COURIER_BASE_URL": "https://courier.example.com",
				"COURIER_TOKEN":    "svc-3f9a1c7e5b2d8046",
			}
			for key, value := range tc.env {
				env[key] = value
			}

			cfg, err := Load(lookupFrom(env))
			if !errors.Is(err, ErrInvalidCourier) {
				t.Fatalf("Load = %v, want one matching ErrInvalidCourier; a deployment that "+
					"can send mail and cannot say where one of its links points must not boot", err)
			}
			if !strings.Contains(err.Error(), tc.wantNamed) {
				t.Errorf("the refusal names %s rather than %s, so an operator reading the "+
					"startup log cannot act on it: %v", err, tc.wantNamed, err)
			}
			if cfg.CourierEnabled() {
				t.Error("Load returned a Config that reports a mail path alongside an error")
			}
		})
	}
}

// TestALinkTemplateIsSetWithoutCredentialsIsRefused is the rest of the
// all-or-nothing rule, restated for the variables that did not exist when it was
// written.
//
// A deployment that sets a link template and no courier credential believes it can
// send mail. It cannot: `buildMailer` mounts `recovery.Unavailable{}` and every
// route that needs a message answers 503, and the template it wrote is read by
// nothing.
func TestALinkTemplateIsSetWithoutCredentialsIsRefused(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
	}{
		{
			name: "the legacy template with no credentials",
			env:  map[string]string{"RECOVERY_LINK_TEMPLATE": defaultTemplate},
		},
		{
			name: "a per-purpose template with no credentials",
			env:  map[string]string{"EMAIL_VERIFICATION_LINK_TEMPLATE": defaultTemplate},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(lookupFrom(tc.env))
			if !errors.Is(err, ErrInvalidCourier) {
				t.Fatalf("Load = %v, want one matching ErrInvalidCourier", err)
			}
			if !strings.Contains(err.Error(), "COURIER_BASE_URL") ||
				!strings.Contains(err.Error(), "COURIER_TOKEN") {
				t.Errorf("the refusal does not name the credentials it is about: %v", err)
			}
		})
	}
}

// TestEveryLinkTemplateIsHeldToTheSameRefusalsAndNamesItsOwnVariable is
// `ValidateLinkTemplate`'s table applied to EVERY variable that carries one, at
// boot rather than at construction.
//
// THE REASON IT IS PER VARIABLE is that the refusal a boot produces names the
// variable that caused it, and a single shared message cannot do that: an operator
// who set four variables and gets "the link template is invalid" has to diff four
// values against a rule they have to remember. So each variable's refusals are
// separate cases here, and the assertion is on the variable's name appearing in its
// own error.
//
// THE THREE REFUSALS ARE THE SAME THREE `internal/courier` applies, and this is
// where the duplication between boot and construction is paid for back:
// `TestTheBootRulesAndTheClientRulesAgree` holds the base-URL rule in step between
// the two, and this test holds the same question for the link templates — a boot
// that accepts a template the client would refuse means a deployment that starts
// and then cannot send, which is the failure the all-or-nothing rule exists to
// prevent.
func TestEveryLinkTemplateIsHeldToTheSameRefusalsAndNamesItsOwnVariable(t *testing.T) {
	refusals := []struct {
		name     string
		template string
	}{
		{name: "no placeholder", template: "https://app.example.com/reset"},
		{name: "relative", template: "/reset?token=" + recoveryTokenPlaceholder},
		{name: "a fragment a mail client would not send", template: "https://app.example.com/reset#/" + recoveryTokenPlaceholder},
		{name: "a userinfo section", template: "https://kaka:pw@app.example.com/reset?token=" + recoveryTokenPlaceholder},
		{name: "a scheme courier's schema rejects", template: "javascript:alert(" + recoveryTokenPlaceholder + ")"},
		{name: "not a URL", template: "://nope?token=" + recoveryTokenPlaceholder},
		{name: "no host", template: "https://?token=" + recoveryTokenPlaceholder},
	}

	variables := []string{
		"RECOVERY_LINK_TEMPLATE",
		"PASSWORD_RESET_LINK_TEMPLATE",
		"EMAIL_VERIFICATION_LINK_TEMPLATE",
	}

	for _, variable := range variables {
		t.Run(variable, func(t *testing.T) {
			// A WORKING value in the two variables this one does not cover, so the
			// refusal under test is the one being injected and not a configuration
			// that was already incomplete.
			for _, tc := range refusals {
				t.Run(tc.name, func(t *testing.T) {
					env := map[string]string{
						"COURIER_BASE_URL": "https://courier.example.com",
						"COURIER_TOKEN":    "svc-3f9a1c7e5b2d8046",
						variable:           tc.template,
					}
					if variable != "RECOVERY_LINK_TEMPLATE" {
						env["RECOVERY_LINK_TEMPLATE"] = defaultTemplate
					} else {
						env["PASSWORD_RESET_LINK_TEMPLATE"] = defaultTemplate
						env["EMAIL_VERIFICATION_LINK_TEMPLATE"] =
							"https://app.example.com/verify-email?token=" + recoveryTokenPlaceholder
					}
					// The other per-purpose variable is covered by the default above,
					// and the default is validated whatever else is set, so a refusal
					// here can only be about the injected value.
					_, err := Load(lookupFrom(env))
					if !errors.Is(err, ErrInvalidCourier) {
						t.Fatalf("Load accepted %s=%q, want one matching ErrInvalidCourier", variable, tc.template)
					}
					if !strings.Contains(err.Error(), variable) {
						t.Errorf("the refusal does not name %s: %v", variable, err)
					}
				})
			}
		})
	}
}

// TestAnInsecureLinkTemplateIsDescribedAsThoughHTTPSWereTheOnlyOneAccepted is the
// cosmetic defect identity-24 found alongside the real one, and it is a test
// because "the message and the code disagree" is exactly the kind of thing that
// comes back.
//
// # WHAT WAS WRONG
//
// `validateMailBaseURL` and the link-template validator both said
//
//	COURIER_BASE_URL scheme is "ftp", want https
//
// while the line above it accepts `http` and the table in
// `TestTheBootRulesAndTheClientRulesAgree` says `http://localhost:4003` BOOTS. So
// the message told an operator that a scheme this service accepts is not one it
// accepts, and the only way to reconcile the two is to distrust one of them. The
// acceptance is deliberate — a compose stack serves courier over http and
// `OIDC_ALLOW_INSECURE` is the same shape of decision — so the message is what was
// wrong.
//
// # WHY A WORDING ASSERTION IS THE RIGHT TEST HERE
//
// The claim being held is a claim ABOUT A MESSAGE, so the message is the thing under
// test. `TestTheBootRulesAndTheClientRulesAgree` already holds that http boots, and
// this holds that the refusal for everything else says so.
func TestAnInsecureLinkTemplateIsDescribedAsThoughHTTPSWereTheOnlyOneAccepted(t *testing.T) {
	t.Run("the courier base URL", func(t *testing.T) {
		_, err := Load(lookupFrom(map[string]string{
			"COURIER_BASE_URL":       "ftp://courier.example.com",
			"COURIER_TOKEN":          "svc-3f9a1c7e5b2d8046",
			"RECOVERY_LINK_TEMPLATE": defaultTemplate,
		}))
		if !errors.Is(err, ErrInvalidCourier) {
			t.Fatalf("Load = %v, want one matching ErrInvalidCourier", err)
		}
		if !strings.Contains(err.Error(), "http or https") {
			t.Errorf("the refusal does not say which schemes are accepted, while http is "+
				"one this service boots with: %v", err)
		}
	})

	t.Run("a link template", func(t *testing.T) {
		_, err := Load(lookupFrom(map[string]string{
			"COURIER_BASE_URL":       "https://courier.example.com",
			"COURIER_TOKEN":          "svc-3f9a1c7e5b2d8046",
			"RECOVERY_LINK_TEMPLATE": "ftp://app.example.com/reset?token=" + recoveryTokenPlaceholder,
		}))
		if !errors.Is(err, ErrInvalidCourier) {
			t.Fatalf("Load = %v, want one matching ErrInvalidCourier", err)
		}
		if !strings.Contains(err.Error(), "http or https") {
			t.Errorf("the refusal does not say which schemes are accepted, while http is "+
				"one this service boots with: %v", err)
		}
	})
}

// TestLinkTemplateVariableNamesEveryPurposeThatCanHaveALink is the exported half of
// the drift check, and it exists so `internal/courier` can hold the two closed sets
// together without either of them having to import the other.
//
// The set here is the purposes a deployment can configure a link FOR, and the set
// in `internal/courier` is the purposes it can DELIVER. They are equal today and
// nothing in the type system says so, which is why `link_purpose_test.go` walks
// both — and why this function is exported at all: the check has to be able to ask
// the question, and asking it by reading a source file is how it was going to be
// done otherwise.
func TestLinkTemplateVariableNamesEveryPurposeThatCanHaveALink(t *testing.T) {
	// The two purposes that have messages a courier can render today. `email_change`
	// is deliberately absent: courier has no type for it, its messages are refused
	// before a link is ever rendered, and a variable for it would be a setting an
	// operator changes and nothing happens.
	want := map[recovery.Purpose]string{
		recovery.PurposePasswordReset: "PASSWORD_RESET_LINK_TEMPLATE",
		recovery.PurposeVerifyEmail:   "EMAIL_VERIFICATION_LINK_TEMPLATE",
	}

	got := map[recovery.Purpose]string{}
	for _, purpose := range []recovery.Purpose{
		recovery.PurposePasswordReset,
		recovery.PurposeVerifyEmail,
		recovery.PurposeEmailChange,
	} {
		if variable, ok := LinkTemplateVariable(purpose); ok {
			got[purpose] = variable
		}
	}

	if len(got) != len(want) {
		t.Errorf("LinkTemplateVariable names %d purposes (%v), want %d (%v)",
			len(got), got, len(want), want)
	}
	for purpose, variable := range want {
		if got[purpose] != variable {
			t.Errorf("the %s link is configured by %q, want %q", purpose, got[purpose], variable)
		}
	}
	// And a purpose with no link of its own says so rather than returning a name
	// that would be set and ignored.
	if variable, ok := LinkTemplateVariable(recovery.PurposeEmailChange); ok {
		t.Errorf("the email change has a link variable (%s) and no message that carries "+
			"one; courier refuses both of its messages before a link is rendered", variable)
	}
}

// TestABlankLinkTemplateIsAbsentRatherThanBroken is the convention, made explicit
// because it is the one row in the table above that is not a refusal.
//
// `lookupValue` trims every variable this package reads, so a value of `"   "` is
// the same as an absent one — for `COURIER_TOKEN`, for `MFA_ISSUER`, for
// `RECOVERY_LINK_TEMPLATE` and for every per-purpose variable alike. The
// alternative, treating a blank as a value and failing on it, would mean a
// whitespace-only `COURIER_TOKEN` is a startup failure while a whitespace-only
// `RECOVERY_LINK_TEMPLATE` is not, which is worse than either being uniform.
//
// # AND WHAT IT MEANS FOR A DEPLOYMENT, WHICH IS THE PART THAT MATTERS
//
// A blank per-purpose variable FALLS BACK to the default rather than becoming a
// broken link — and the default is the shared one, so `buildMailer` warns about it
// like any other purpose that resolved to it. An operator who blanked
// `EMAIL_VERIFICATION_LINK_TEMPLATE` expecting to turn the link off gets the shared
// template and a warning naming the variable, which is the correct answer: there is
// no state in which a purpose has no link, because a message with no link is the
// defect this packet exists to stop.
func TestABlankLinkTemplateIsAbsentRatherThanBroken(t *testing.T) {
	cfg, err := Load(lookupFrom(map[string]string{
		"COURIER_BASE_URL":                 "https://courier.example.com",
		"COURIER_TOKEN":                    "svc-3f9a1c7e5b2d8046",
		"RECOVERY_LINK_TEMPLATE":           defaultTemplate,
		"EMAIL_VERIFICATION_LINK_TEMPLATE": "   ",
	}))
	if err != nil {
		t.Fatalf("a blank variable must be absent, not a startup failure: %v", err)
	}
	if got := cfg.LinkTemplateFor(recovery.PurposeVerifyEmail); got != defaultTemplate {
		t.Errorf("the %s link is %q, want the default %q; a blank value is absent and "+
			"absent means the default, not an empty link",
			recovery.PurposeVerifyEmail, got, defaultTemplate)
	}
	// And it is reported as sharing the default, so the startup warning names it.
	shared := cfg.LinkPurposesUsingTheDefault()
	found := false
	for _, purpose := range shared {
		if purpose == recovery.PurposeVerifyEmail {
			found = true
		}
	}
	if !found {
		t.Errorf("LinkPurposesUsingTheDefault = %v, which omits the %s purpose a blank "+
			"variable resolved; the startup warning would not name it",
			shared, recovery.PurposeVerifyEmail)
	}

	// The same rule with no default to fall back to: a blank variable is then a
	// purpose with nothing, which is the refusal the other test asserts.
	if _, err := Load(lookupFrom(map[string]string{
		"COURIER_BASE_URL":                 "https://courier.example.com",
		"COURIER_TOKEN":                    "svc-3f9a1c7e5b2d8046",
		"PASSWORD_RESET_LINK_TEMPLATE":     defaultTemplate,
		"EMAIL_VERIFICATION_LINK_TEMPLATE": "   ",
	})); !errors.Is(err, ErrInvalidCourier) {
		t.Errorf("Load = %v, want one matching ErrInvalidCourier; a blank variable with no "+
			"default leaves the purpose with nothing", err)
	}
}
