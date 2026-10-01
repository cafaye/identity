package main

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/cafaye/identity/internal/config"
	"github.com/cafaye/identity/internal/courier"
	"github.com/cafaye/identity/internal/recovery"
)

// # WHAT THIS FILE HOLDS, AND WHY IT IS NOT A COMMENT
//
// `buildMailer` is the one function in this repository that decides whether a user's
// password reset can be delivered, and its two answers — courier's client, or
// `recovery.Unavailable{}` — are a security boundary in the same way the scope
// table is: a mistake in it is not a crash, it is a service that tells a user their
// reset is on its way.
//
// So the two answers are pinned here rather than described in `buildMailer`'s
// comment. A comment that says "this returns a courier mailer or Unavailable" and a
// test that says it are the same claim, and only one of them is red when the day
// comes that somebody adds a third possibility.

// TestAMailerIsCouriersOrUnavailableAndNothingElse is the whole of the wiring
// contract, as a table over the configurations a deployment can be in.
func TestAMailerIsCouriersOrUnavailableAndNothingElse(t *testing.T) {
	const token = "svc-7f3a9c1e4b8d2056-the-credential"

	cases := []struct {
		name string
		env  map[string]string
		// wantCourier is what the test asserts the returned Mailer is.
		wantCourier bool
	}{
		{
			name: "a fully configured deployment gets courier",
			env: map[string]string{
				"COURIER_BASE_URL":       "https://courier.example.com",
				"COURIER_TOKEN":          token,
				"RECOVERY_LINK_TEMPLATE": "https://app.example.com/reset?token={token}",
			},
			wantCourier: true,
		},
		{
			// THE STATE A DEFAULT DEPLOYMENT IS IN, and the one this packet exists to
			// change. `Unavailable{}` is a SUPPORTED state rather than a gap: the
			// routes stay mounted and answer 503 with a sentence naming the problem,
			// which is the difference between "this deployment cannot send email" and
			// a 404 that tells a product identity has never heard of recovery.
			name:        "an unconfigured deployment refuses loudly",
			env:         map[string]string{},
			wantCourier: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.Load(lookupFrom(tc.env))
			if err != nil {
				t.Fatalf("config.Load: %v", err)
			}
			var log strings.Builder
			mailer, err := buildMailer(cfg, slog.New(slog.NewTextHandler(&log, nil)))
			if err != nil {
				t.Fatalf("buildMailer: %v", err)
			}
			if mailer == nil {
				t.Fatal("buildMailer returned nil, which is not a Mailer and would panic " +
					"the recovery flows on their first send")
			}

			_, isCourier := mailer.(*courier.RecoveryMailer)
			_, isUnavailable := mailer.(recovery.Unavailable)

			if tc.wantCourier {
				if !isCourier {
					t.Errorf("got %T, want *courier.RecoveryMailer", mailer)
				}
				// And the refusing implementation must NOT be reachable on a configured
				// deployment. This is the assertion that matters: a deployment that
				// configured a mail path and got the refusing one would report itself
				// as configured while answering 503 to everybody.
				if isUnavailable {
					t.Error("a configured deployment got recovery.Unavailable{}, which would " +
						"answer 503 to a user who configured a mail path")
				}
			} else {
				if !isUnavailable {
					t.Errorf("got %T, want recovery.Unavailable{}", mailer)
				}
			}

			// THE CREDENTIAL NEVER REACHES THE LOG, in either state. It is asserted
			// here rather than only in `internal/courier` because this is the function
			// that decides to hand the logger to something holding the credential, and
			// a log line written here would be outside the sweep in that package.
			if strings.Contains(log.String(), token) {
				t.Errorf("the startup log carries the service credential:\n%s", log.String())
			}
		})
	}
}

// TestAnUnconfiguredDeploymentIsLoudAtStartup is the other half of the refusing
// state, and it is separate because it is a claim about the LOG rather than about
// the returned value.
//
// A deployment that cannot send mail and says nothing is a deployment that finds out
// from a user. The warning has to be there, and it has to name the variables — an
// operator reading "cannot send email" without being told what to set has been told
// a symptom.
func TestAnUnconfiguredDeploymentIsLoudAtStartup(t *testing.T) {
	cfg, err := config.Load(lookupFrom(map[string]string{}))
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	var log strings.Builder
	if _, err := buildMailer(cfg, slog.New(slog.NewTextHandler(&log, nil))); err != nil {
		t.Fatalf("buildMailer: %v", err)
	}

	written := log.String()
	for _, want := range []string{"COURIER_BASE_URL", "COURIER_TOKEN", "RECOVERY_LINK_TEMPLATE"} {
		if !strings.Contains(written, want) {
			t.Errorf("the startup warning does not name %s:\n%s", want, written)
		}
	}
	if !strings.Contains(written, "503") {
		t.Errorf("the startup warning does not say what the routes will answer:\n%s", written)
	}
}

// TestAConfiguredDeploymentSaysWhatItCanAndCannotSend is the honesty check on the
// success path, and it is the one that would otherwise get skipped.
//
// The line must say the base URL — an operator has to be able to confirm which
// courier this process is pointed at — and it must NOT claim mail is being sent,
// because it cannot know that: courier's `/readyz` answers for its DATABASE, and
// its adapter check is scoped to production, so a green probe and a wired mailer
// together mean "courier is reachable" and nothing more. It must also say that two
// of this service's flows cannot be delivered, because the alternative is a 503
// somebody reads as an identity bug.
func TestAConfiguredDeploymentSaysWhatItCanAndCannotSend(t *testing.T) {
	cfg, err := config.Load(lookupFrom(map[string]string{
		"COURIER_BASE_URL":       "https://courier.example.com",
		"COURIER_TOKEN":          "svc-7f3a9c1e4b8d2056-the-credential",
		"RECOVERY_LINK_TEMPLATE": "https://app.example.com/reset?token={token}",
	}))
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	var log strings.Builder
	if _, err := buildMailer(cfg, slog.New(slog.NewTextHandler(&log, nil))); err != nil {
		t.Fatalf("buildMailer: %v", err)
	}

	written := log.String()
	if !strings.Contains(written, "https://courier.example.com") {
		t.Errorf("the startup line does not say which courier this is pointed at:\n%s", written)
	}
	if strings.Contains(written, "svc-7f3a9c1e4b8d2056-the-credential") {
		t.Error("the startup line carries the credential")
	}
	// The two flows courier cannot render must be named. A silence here is what
	// turns a courier contract gap into a week of somebody debugging identity.
	for _, want := range []string{"email change"} {
		if !strings.Contains(written, want) {
			t.Errorf("the startup line does not mention that %s cannot be delivered:\n%s", want, written)
		}
	}
	// And it must not overclaim.
	for _, overclaim := range []string{"mail will be sent", "delivery is working", "ready"} {
		if strings.Contains(written, overclaim) {
			t.Errorf("the startup line claims %q, which a readiness probe cannot establish:\n%s",
				overclaim, written)
		}
	}
}

// TestTheRefusingMailerStillRefuses is the check that the absent state is a REFUSAL
// and not a `nil` that panics.
//
// It is here rather than in `internal/recovery` because the question is "what does a
// deployment with no mail path actually do", and the answer has to be the same
// whichever package you ask.
func TestTheRefusingMailerStillRefuses(t *testing.T) {
	cfg, err := config.Load(lookupFrom(map[string]string{}))
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	mailer, err := buildMailer(cfg, slog.New(slog.NewTextHandler(&strings.Builder{}, nil)))
	if err != nil {
		t.Fatalf("buildMailer: %v", err)
	}

	ctx := context.Background()
	if err := mailer.Ready(ctx); err == nil {
		t.Error("Ready returned nil for a deployment that cannot send mail, which would " +
			"let a reset request mint a token for a message nobody can deliver")
	}
	// And Send fails rather than dropping the message, which is the whole of
	// `Unavailable`'s design.
	if err := mailer.Send(ctx, recovery.Message{To: "kaka@example.com"}); err == nil {
		t.Error("Send returned nil for a deployment that cannot send mail")
	}
}

// lookupFrom builds a Lookup from a map, mirroring os.LookupEnv.
func lookupFrom(env map[string]string) config.Lookup {
	return func(key string) (string, bool) {
		value, present := env[key]
		return value, present
	}
}
