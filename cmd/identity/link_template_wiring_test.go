package main

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/cafaye/identity/internal/config"
	"github.com/cafaye/identity/internal/recovery"
)

// # THE SHARED DEFAULT, AS AN OPERATOR SEES IT
//
// Everything in `internal/courier/link_purpose_test.go` and `internal/config` is
// about whether the CONFIGURATION says where each kind of link goes. This file is
// about the one thing configuration cannot decide on its own: a deployment
// configured before per-purpose templates existed still boots, and its
// address-verification link therefore still points wherever its single template says
// — which, for the configuration that shape was introduced to replace, is the
// password reset screen.
//
// So the compatibility promise has two halves and both need a check.
// `internal/config` holds that the old environment RESOLVES; this file holds that
// the process it produces says so out loud, because a deployment that quietly keeps
// sending verification links to the reset screen has no other way to find out.

// courierEnv is a deployment with both credentials and the given link variables.
func courierEnv(links map[string]string) map[string]string {
	env := map[string]string{
		"COURIER_BASE_URL": "https://courier.example.com",
		"COURIER_TOKEN":    "svc-7f3a9c1e4b8d2056-the-credential",
	}
	for key, value := range links {
		env[key] = value
	}
	return env
}

// buildWithEnv runs the real wiring and hands back what it logged.
func buildWithEnv(t *testing.T, env map[string]string) string {
	t.Helper()
	cfg, err := config.Load(lookupFrom(env))
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	var log strings.Builder
	if _, err := buildMailer(cfg, slog.New(slog.NewTextHandler(&log, nil))); err != nil {
		t.Fatalf("buildMailer: %v", err)
	}
	return log.String()
}

// TestADeploymentConfiguredBeforePerPurposeTemplatesStillBootsAndIsToldAboutIt is
// the backwards-compatibility claim from the process's side.
//
// FOUR THINGS ARE ASSERTED, and the last is the one that matters most:
//
//  1. it BOOTS                    — a deployment in the field is not broken by this
//     change. It gets the real adapter, not
//     `recovery.Unavailable{}`.
//  2. its LINKS RESOLVE           — both purposes have a template, because a boot
//     that left one of them without would send a
//     verification mail with no button at all.
//  3. the startup line NAMES EACH PURPOSE'S LINK — an operator has to be able to
//     confirm where a verification link points, and a
//     single shared `link_template` attribute cannot
//     answer that.
//  4. it WARNS                   — the whole point. Nothing else in the process can
//     see this: the send succeeds, the token redeems at
//     its own endpoint, and the reader is the only one
//     who finds out they are on the wrong screen.
func TestADeploymentConfiguredBeforePerPurposeTemplatesStillBootsAndIsToldAboutIt(t *testing.T) {
	const legacy = "https://app.example.com/reset?token={token}"
	env := courierEnv(map[string]string{"RECOVERY_LINK_TEMPLATE": legacy})

	written := buildWithEnv(t, env)

	// (1) AND (2). It booted with a mail path, and both purposes resolved.
	cfg, err := config.Load(lookupFrom(env))
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if !cfg.CourierEnabled() {
		t.Fatal("a deployment with the single legacy template reports no mail path, so " +
			"every install that exists breaks at this change")
	}
	for _, purpose := range []recovery.Purpose{
		recovery.PurposePasswordReset,
		recovery.PurposeVerifyEmail,
	} {
		if got := cfg.LinkTemplateFor(purpose); got != legacy {
			t.Errorf("the %s link is %q, want the configured %q", purpose, got, legacy)
		}
	}

	// (3) The startup line names each purpose's link separately, so the two can be
	// told apart in a log.
	for _, want := range []string{
		"link_template.password_reset",
		"link_template.verify_email",
		legacy,
	} {
		if !strings.Contains(written, want) {
			t.Errorf("the startup log does not carry %q:\n%s", want, written)
		}
	}

	// (4) And it warns, naming the consequence AND the variables that fix it.
	for _, want := range []string{
		"RECOVERY_LINK_TEMPLATE",
		"PASSWORD_RESET_LINK_TEMPLATE",
		"EMAIL_VERIFICATION_LINK_TEMPLATE",
		string(recovery.PurposePasswordReset),
		string(recovery.PurposeVerifyEmail),
	} {
		if !strings.Contains(written, want) {
			t.Errorf("the shared-default warning does not mention %q:\n%s", want, written)
		}
	}
	// The warning has to SAY what happens to a user who follows the link, not merely
	// that something is shared. A warning an operator reads as "consider configuring
	// these separately" has been told a symptom.
	if !strings.Contains(written, "404") {
		t.Errorf("the warning does not say what happens to a reader who follows the "+
			"link:\n%s", written)
	}
}

// TestADeploymentThatHasConfiguredEachPurposeIsNotWarned is the other half, and it
// is a separate test because a warning that fires when everything is correct trains
// an operator to ignore warnings.
//
// A migration that has finished — both per-purpose variables set, the legacy one
// deleted — must produce no shared-default warning at all, and the startup line must
// name two DIFFERENT links.
func TestADeploymentThatHasConfiguredEachPurposeIsNotWarned(t *testing.T) {
	const reset = "https://app.example.com/reset?token={token}"
	const verify = "https://app.example.com/verify-email?token={token}"

	written := buildWithEnv(t, courierEnv(map[string]string{
		"PASSWORD_RESET_LINK_TEMPLATE":     reset,
		"EMAIL_VERIFICATION_LINK_TEMPLATE": verify,
	}))

	if strings.Contains(written, "RECOVERY_LINK_TEMPLATE") {
		t.Errorf("the startup log warns about the shared default for a deployment that "+
			"never set it:\n%s", written)
	}
	for _, want := range []string{"link_template.password_reset", "link_template.verify_email"} {
		if !strings.Contains(written, want) {
			t.Errorf("the startup log does not carry %q:\n%s", want, written)
		}
	}
	// Both values are in the line, so the two screens are distinguishable at a glance.
	if !strings.Contains(written, reset) || !strings.Contains(written, verify) {
		t.Errorf("the startup log does not carry both configured links:\n%s", written)
	}
}

// TestAMigrationInProgressStillGetsWorkingLinks is the mixed state: the legacy
// variable plus ONE per-purpose override, which is how a deployment actually gets
// from one configuration to the other.
//
// IT IS WORTH A TEST because it is the state a careful operator reaches first — "I
// will add the verification link now and sort the reset path out later" — and the
// reset link must keep working exactly as it was while they do.
func TestAMigrationInProgressStillGetsWorkingLinks(t *testing.T) {
	const reset = "https://app.example.com/reset?token={token}"
	const verify = "https://app.example.com/verify-email?token={token}"
	env := courierEnv(map[string]string{
		"RECOVERY_LINK_TEMPLATE":           reset,
		"EMAIL_VERIFICATION_LINK_TEMPLATE": verify,
	})

	cfg, err := config.Load(lookupFrom(env))
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if got := cfg.LinkTemplateFor(recovery.PurposePasswordReset); got != reset {
		t.Errorf("the reset link is %q, want the unchanged default %q", got, reset)
	}
	if got := cfg.LinkTemplateFor(recovery.PurposeVerifyEmail); got != verify {
		t.Errorf("the verification link is %q, want the new %q", got, verify)
	}

	// The reset purpose still resolves to the default, so the warning still fires —
	// correctly, because it is TRUE: that purpose does not have a link of its own.
	// What must not happen is the warning asking for a variable that is already set,
	// which is the failure mode of a check that compares values rather than reading
	// which variables were written.
	written := buildWithEnv(t, env)
	if !strings.Contains(written, "RECOVERY_LINK_TEMPLATE") {
		t.Errorf("the warning does not fire for the purpose that still falls back:\n%s", written)
	}
	shared := strings.Index(written, "RECOVERY_LINK_TEMPLATE is the link")
	if shared < 0 {
		t.Fatalf("the shared-default warning is not in the startup log:\n%s", written)
	}
	rest := written[shared:]
	if !strings.Contains(rest, "PASSWORD_RESET_LINK_TEMPLATE") {
		t.Errorf("the warning does not name the variable for the purpose that needs it:\n%s", rest)
	}
	if strings.Contains(rest, "EMAIL_VERIFICATION_LINK_TEMPLATE") {
		t.Errorf("the warning asks for EMAIL_VERIFICATION_LINK_TEMPLATE, which this "+
			"deployment has already set:\n%s", rest)
	}
}
