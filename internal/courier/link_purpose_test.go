package courier

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/cafaye/identity/internal/config"
	"github.com/cafaye/identity/internal/recovery"
)

// # THE TEST THAT WOULD HAVE CAUGHT THE BUTTON THAT LIES
//
// identity-24 drove the flows end to end against a real courier and the password
// reset path was perfect while the verification path was broken for the human: the
// `welcome` mail's button said `https://app.example.com/reset?token=…`, so a user
// who clicked "Confirm your email address" landed on the password-reset screen,
// where a verification token answers **404**.
//
// The token was fine. The token redeemed. Nothing was malformed. **The mail was
// well-formed, passed every test, and sent the user somewhere useless**, which is
// why it survived: every assertion in the repository was about the BYTES, and the
// bytes were correct. What no assertion was about was whether the link suited the
// purpose it was carrying.
//
// So this file is about the purpose of a link rather than its shape.
//
// # THE TWO THINGS THAT WERE WRONG, AND THEY ARE SEPARATE
//
//  1. **STRUCTURAL.** `RecoveryMailer` held ONE `LinkTemplate` for all four of its
//     messages. The single-template design is defended at length in `mailer.go`,
//     and the argument is sound FOR A RECOVERY LINK: a template with `{token}`
//     beats a base URL plus a platform-chosen convention. It was then applied to a
//     verification link, which is not a recovery link. One template for two
//     purposes is a template that must be wrong for one of them.
//
//  2. **THE CHECK.** Courier cannot know that a verify link and a reset link want
//     different screens — courier renders what identity sends. So the relationship
//     belongs in identity, and it belongs where a deployment DECLARES its URLs.
//     That is `internal/config`'s environment, and the configuration in these tests
//     is built from one rather than from a Go literal, so a test cannot assert a
//     relationship the product has no way to express.
//
// # WHAT IS ASSERTED, AND WHY IT IS NOT ENOUGH TO COMPARE TWO STRINGS
//
// The obvious assertion — "the two links are different" — passes for a link with
// the wrong token in it, or a link whose path is right and whose query is not.
// So each link's token is also taken out of the URL and presented at the endpoint
// that purpose is redeemed at, and at the other one. That is the half only identity
// can assert, because these are identity's own endpoints: a purpose's link has to
// carry a credential its own flow accepts, and NOT one the other flow accepts.
//
// The rows that follow the claim are the ones that keep it honest: a mailer given
// ONE template for both purposes is shown to render one link for both messages,
// which is what makes the inequality in the first test a comparison rather than a
// tautology.

// allPurposes is `recovery`'s closed set of what a token can be for, spelled out
// here so the drift check can walk the purposes this adapter does NOT deliver.
//
// IT IS DECLARED RATHER THAN DERIVED because `recovery.Purpose` is a string type
// with no enumeration to range over, and a list that only contained the deliverable
// purposes could not answer "is there a purpose nobody gives a link to" — which is
// half of what the drift check is for.
var allPurposes = []recovery.Purpose{
	recovery.PurposePasswordReset,
	recovery.PurposeVerifyEmail,
	recovery.PurposeEmailChange,
}

// deploymentEnv is what a deployment writes when it has said where EACH purpose's
// link goes.
//
// IT IS AN ENVIRONMENT AND NOT A `map[recovery.Purpose]string` LITERAL, and that is
// the point of the file: a relationship between two links can only be tested by
// something that can express it, so the configuration under test is the shape a
// deployer actually has. A Go literal would let this file pass on a repository
// where no deployment could ever say what it says.
func deploymentEnv(overrides map[string]string) map[string]string {
	env := map[string]string{
		"COURIER_BASE_URL":                 "https://courier.example.com",
		"COURIER_TOKEN":                    "svc-4b1d7e0a3c95f28",
		"PASSWORD_RESET_LINK_TEMPLATE":     "https://app.example.com/reset?token={token}",
		"EMAIL_VERIFICATION_LINK_TEMPLATE": "https://app.example.com/verify-email?token={token}",
	}
	for key, value := range overrides {
		if value == "" {
			delete(env, key)
			continue
		}
		env[key] = value
	}
	return env
}

// configLookup is `config.Lookup` over a map, so no test here mutates the process
// environment — the same rule `internal/config` holds for the same reason.
func configLookup(env map[string]string) config.Lookup {
	return func(key string) (string, bool) {
		value, present := env[key]
		return value, present
	}
}

// mailerFromEnv is the production wiring in two lines: `config.Load` resolves the
// deployment's environment and `NewRecoveryMailer` takes the resolved templates.
// `main`'s `buildMailer` is those two lines plus a client and a logger, so a
// relationship this file proves is one the shipped binary has.
func mailerFromEnv(t *testing.T, env map[string]string, baseURL string) *RecoveryMailer {
	t.Helper()

	cfg, err := config.Load(configLookup(env))
	if err != nil {
		t.Fatalf("config.Load on a deployment that says where each link goes: %v", err)
	}
	if !cfg.CourierEnabled() {
		t.Fatal("the deployment reported no mail path, so nothing below could be proven")
	}

	mailer, err := NewRecoveryMailer(RecoveryMailerConfig{
		Client:        newTestClient(t, baseURL, cfg.CourierTokenValue),
		LinkTemplates: cfg.LinkTemplates,
	})
	if err != nil {
		t.Fatalf("NewRecoveryMailer: %v", err)
	}
	return mailer
}

// TestAVerificationLinkIsNotThePasswordResetLinkAndEachRedeemsAtItsOwnEndpoint is
// the packet's claim, end to end and over the deployment's own configuration.
//
// THE CHAIN:
//
//	recovery renders two messages  (internal/recovery)
//	  -> RecoveryMailer.Send      (internal/courier, the real adapter)
//	    -> the configured TEMPLATE for that message's purpose
//	      -> POST /v1/messages     (courier's door)
//	  -> the token is taken back OUT OF THE RENDERED URL
//	    -> recovery.Service.RedeemVerification / RedeemPasswordReset
//	      (the real service, over a real Postgres, real tables, real SQL)
//
// # WHAT IS REAL AND WHAT IS NOT, because "end to end" is a claim worth bounding
//
//	REAL     the message bodies, the tokens, `recovery`'s own store and SQL, both
//	         redemption paths, Postgres, and the adapter's own template selection —
//	         which is the part under test.
//	STAND-IN courier is `courierStub`, the same enforcing `httptest` server
//	         `flow_test.go` uses, and it is the right way round: a stand-in can
//	         FALSIFY THE REQUEST, which is a real risk here, and it cannot answer
//	         for courier. `e2e_support_test.go` covers the other direction — a real
//	         courier's answer to bytes this composes — so nothing between the two is
//	         unexamined.
//
// THE ASSERTION, in three parts:
//
//  1. the two messages carry two DIFFERENT links, and the difference is in the
//     path, which is the part a product chooses;
//  2. the token in the VERIFICATION link is accepted by the verification endpoint
//     and REFUSED by the reset endpoint;
//  3. the token in the RESET link is accepted by the reset endpoint and REFUSED by
//     the verification endpoint.
//
// # AND WHY THE REFUSALS ARE THE INTERESTING HALF
//
// A verification token that the reset endpoint accepts would be a token that can
// change a password, which is exactly what the `purpose` column on
// `recovery_tokens` exists to prevent. `internal/recovery` asserts that directly
// (`TestAResetTokenIsNotAVerificationToken`). What it cannot assert is that the
// credential a USER HOLDS came out of the verification link — because the token
// in the mail and the row in the table are joined only by a link, and identity-24
// proved the token redeems while the button sent the user to the wrong screen. So
// the value here is not the two refusals; it is that the value is read back out of
// the URL rather than out of the message.
func TestAVerificationLinkIsNotThePasswordResetLinkAndEachRedeemsAtItsOwnEndpoint(t *testing.T) {
	stub := newCourierStub(t)
	mailer := mailerFromEnv(t, deploymentEnv(nil), stub.server.URL)
	flow := newRecoveryFlow(t, mailer)

	ctx := context.Background()
	if err := flow.svc.RequestPasswordReset(ctx, flow.who.email); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if err := flow.svc.RequestVerification(ctx, flow.who.email); err != nil {
		t.Fatalf("RequestVerification: %v", err)
	}

	if len(stub.sent) != 2 {
		t.Fatalf("courier saw %d requests, want 2 (one reset, one verification)", len(stub.sent))
	}
	resetLink := stringOf(stub.sent[0].Body["url"])
	verifyLink := stringOf(stub.sent[1].Body["url"])

	// (1) TWO LINKS, AND THE DIFFERENCE IS THE PATH.
	//
	// THE PATH AND NOT THE URL, because a link that differs only in its query is
	// still the same SCREEN, and the screen is the thing that answers 404 — a
	// template that put the token in a different parameter would satisfy a
	// whole-URL comparison while opening the wrong page. And it is compared as a
	// parsed path, so a `?token=` that differs cannot make two identical screens
	// look different either. Both failure directions are closed by parsing.
	resetPath := pathOf(t, resetLink)
	verifyPath := pathOf(t, verifyLink)
	if resetPath == verifyPath {
		t.Fatalf("both messages carried a link to %s. The deployment configured a "+
			"verification link separately and it was not used, so a verification mail "+
			"lands the reader on the reset screen, where a verification token answers 404.",
			resetPath)
	}
	if verifyPath != "/verify-email" {
		t.Errorf("the verification link is %q, want the configured %q", verifyPath, "/verify-email")
	}
	if resetPath != "/reset" {
		t.Errorf("the reset link is %q, want the configured %q", resetPath, "/reset")
	}

	// Neither link may carry the other's credential. The two are minted in separate
	// requests and neither message mentions the other, so a link carrying both
	// would mean a credential in a message it does not belong to.
	resetToken := tokenIn(t, resetLink)
	verifyToken := tokenIn(t, verifyLink)
	if resetToken == verifyToken {
		t.Fatal("the reset and the verification link carry the same token")
	}
	if strings.Contains(resetLink, verifyToken) || strings.Contains(verifyLink, resetToken) {
		t.Error("one purpose's link carries the other purpose's token")
	}

	// (2) AND (3). THE CROSS REDEMPTIONS FIRST, because a refused one spends
	// nothing: `Live` filters on `purpose` and returns ErrTokenNotFound before any
	// write, so asserting the refusals first leaves each token live for the
	// acceptance that follows.
	if _, err := flow.svc.RedeemPasswordReset(ctx, recovery.RedeemPasswordResetInput{
		Token: verifyToken, Password: "correct-horse-battery-staple",
	}); !isError(err, recovery.ErrTokenNotFound) {
		t.Errorf("the reset endpoint on a VERIFICATION token = %v, want ErrTokenNotFound; a "+
			"verification link that could change a password is a takeover", err)
	}
	if err := flow.svc.RedeemVerification(ctx,
		recovery.RedeemVerificationInput{Token: resetToken}); !isError(err, recovery.ErrTokenNotFound) {
		t.Errorf("the verification endpoint on a RESET token = %v, want ErrTokenNotFound", err)
	}

	// And then each at its own endpoint, which is the other half of "a path its own
	// endpoint accepts": a link can be well-formed, distinct, correctly-scoped and
	// STILL carry a token nothing accepts, and that is the state this test exists
	// to rule out.
	if err := flow.svc.RedeemVerification(ctx,
		recovery.RedeemVerificationInput{Token: verifyToken}); err != nil {
		t.Errorf("the verification token from the verification link was refused: %v", err)
	}
	if _, err := flow.svc.RedeemPasswordReset(ctx, recovery.RedeemPasswordResetInput{
		Token: resetToken, Password: "correct-horse-battery-staple-2",
	}); err != nil {
		t.Errorf("the reset token from the reset link was refused: %v", err)
	}
}

// TestOneTemplateForBothPurposesRendersOneLinkForBothMessages is the NEGATIVE
// CONTROL, and it is here rather than left implicit because a comparison that
// cannot come back equal is not a comparison.
//
// It drives today's configuration — one `RECOVERY_LINK_TEMPLATE`, no per-purpose
// variables — and asserts that both messages come out with the SAME link. That is
// the backwards-compatible behaviour, pinned rather than merely permitted: it is
// what every deployment configured before this packet has, and it is the state
// identity-24 found.
//
// So the two tests together say exactly what this packet changed: the DEPLOYMENT
// can now say otherwise, and until it does, a verification mail still points at
// whatever the one template says. That is the honest shape of a compatibility
// promise, and it is why `buildMailer` warns at boot about it.
func TestOneTemplateForBothPurposesRendersOneLinkForBothMessages(t *testing.T) {
	const legacy = "https://app.example.com/reset?token={token}"

	env := deploymentEnv(map[string]string{
		"PASSWORD_RESET_LINK_TEMPLATE":     "",
		"EMAIL_VERIFICATION_LINK_TEMPLATE": "",
		"RECOVERY_LINK_TEMPLATE":           legacy,
	})

	stub := newCourierStub(t)
	flow := newRecoveryFlow(t, mailerFromEnv(t, env, stub.server.URL))

	ctx := context.Background()
	if err := flow.svc.RequestPasswordReset(ctx, flow.who.email); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if err := flow.svc.RequestVerification(ctx, flow.who.email); err != nil {
		t.Fatalf("RequestVerification: %v", err)
	}
	if len(stub.sent) != 2 {
		t.Fatalf("courier saw %d requests, want 2", len(stub.sent))
	}

	resetLink := stringOf(stub.sent[0].Body["url"])
	verifyLink := stringOf(stub.sent[1].Body["url"])
	// THE TEMPLATE, NOT THE RENDERED URL. The two flows mint two different
	// credentials, so the two rendered links CANNOT be byte-equal, and asserting
	// that they were would be asserting that the flows share a token. What the
	// default means is that both links came out of the SAME template, so the
	// credential is put back and what is left is compared.
	if got, want := withoutToken(resetLink), withoutToken(verifyLink); got != want {
		t.Errorf("with one RECOVERY_LINK_TEMPLATE the two purposes rendered from different "+
			"templates (%q and %q), so the default is not the default", got, want)
	}
	if pathOf(t, resetLink) != pathOf(t, verifyLink) {
		t.Errorf("with one RECOVERY_LINK_TEMPLATE the two purposes rendered links to %q and "+
			"%q, so the default is not the default", pathOf(t, resetLink), pathOf(t, verifyLink))
	}

	// Each token still REDEEMS, which is the other half of what "still works" means
	// for a deployment that has not migrated: the links are wrong, and they are not
	// broken. A compatibility promise that quietly stopped delivering would be worse
	// than the defect this packet fixes.
	resetToken := tokenIn(t, resetLink)
	verifyToken := tokenIn(t, verifyLink)
	if resetToken == verifyToken {
		t.Error("the two links carry the same token, so the flows minted one credential between them")
	}
	if err := flow.svc.RedeemVerification(ctx,
		recovery.RedeemVerificationInput{Token: verifyToken}); err != nil {
		t.Errorf("the verification token from the legacy link was refused: %v", err)
	}
	if _, err := flow.svc.RedeemPasswordReset(ctx, recovery.RedeemPasswordResetInput{
		Token: resetToken, Password: "correct-horse-battery-staple-3",
	}); err != nil {
		t.Errorf("the reset token from the legacy link was refused: %v", err)
	}
}

// TestEveryPurposeThisAdapterCanDeliverHasAVariableToConfigureItsLink is the drift
// check between the two closed sets, and it runs in BOTH directions on purpose.
//
// THE TWO SETS. `internal/courier` knows which of `recovery`'s messages courier can
// render, and therefore which purposes need a link; `internal/config` knows which
// environment variables name those links. Nothing in the type system joins them:
// a purpose with a variable courier never asks for is a variable an operator sets
// and nothing happens, and a purpose courier asks for with no variable is a link
// with nowhere to point.
//
// THE SECOND DIRECTION IS NOT HYPOTHETICAL. It is what happens if somebody adds
// `EMAIL_CHANGE_LINK_TEMPLATE` to `config`'s table before courier's vocabulary
// includes an address change — which is the next thing that will happen here, and
// the mailer refuses it at construction precisely so the operator finds out at
// boot rather than at an account's first address change.
//
// So the second half of this test does not inspect a table; it builds a Config
// from an environment with EVERY variable set and refuses to build a mailer from
// it. A declared variable that this adapter cannot honour is a promise the service
// does not keep, and the constructor says so.
func TestEveryPurposeThisAdapterCanDeliverHasAVariableToConfigureItsLink(t *testing.T) {
	// First: every deliverable message has a variable that configures its link.
	for subject, purpose := range linkPurposeFor {
		if _, ok := config.LinkTemplateVariable(purpose); !ok {
			t.Errorf("%q is deliverable and needs a %s link, but no environment variable "+
				"configures one; a deployment would have no way to say where that link "+
				"points", subject, purpose)
		}
	}

	// SECOND DIRECTION: no variable may configure a link for a purpose this adapter
	// cannot deliver. `email_change` is that purpose today — it has two messages and
	// no courier type, so its messages are refused before a link is ever rendered —
	// and a variable for it would be a setting an operator changes and nothing
	// happens.
	//
	// IT IS ASSERTED AGAINST THE CONSTRUCTOR rather than against `config`'s table,
	// because the constructor is the thing that would have to honour it. `config` has
	// no way to know which purposes courier can deliver, and it must not be made to:
	// that knowledge is courier's adapter's, and a table in `config` listing
	// `EMAIL_CHANGE_LINK_TEMPLATE` is exactly the drift this catches.
	for _, purpose := range allPurposes {
		deliverable := false
		for _, deliverablePurpose := range linkPurposeFor {
			if deliverablePurpose == purpose {
				deliverable = true
			}
		}
		if deliverable {
			continue
		}
		if variable, ok := config.LinkTemplateVariable(purpose); ok {
			t.Errorf("config declares %s for the %q purpose, which this adapter cannot "+
				"deliver; a variable an operator sets and nothing honours is a promise "+
				"this service does not keep", variable, purpose)
		}
	}

	// AND THE HALF THAT CANNOT BE A TABLE LOOKUP: a template handed in for a purpose
	// with no courier message is refused, at construction, naming the purpose. This
	// is the fault `config`'s table cannot currently express and the constructor has
	// to catch anyway, because `main` passes `Config.LinkTemplates` straight through.
	_, err := NewRecoveryMailer(RecoveryMailerConfig{
		Client: newTestClient(t, "https://courier.example.com", "svc-4b1d7e0a3c95f28"),
		LinkTemplates: map[recovery.Purpose]string{
			recovery.PurposePasswordReset: "https://app.example.com/reset?token={token}",
			recovery.PurposeVerifyEmail:   "https://app.example.com/verify-email?token={token}",
			recovery.PurposeEmailChange:   "https://app.example.com/confirm-change?token={token}",
		},
	})
	if err == nil {
		t.Fatal("a link template for the email change was accepted, and courier has no " +
			"message for an address change; the setting would be honoured nowhere")
	}
	if !strings.Contains(err.Error(), string(recovery.PurposeEmailChange)) {
		t.Errorf("the refusal does not name the purpose it is about: %v", err)
	}
}

// TestTheConstructorRefusesAPurposeWithNoLinkTemplate is the completeness
// obligation, at the one place it can be enforced structurally.
//
// A purpose with no template is a mail whose button does nothing, and the packet's
// whole subject is a mail that renders perfectly and sends the reader nowhere
// useful. Refusing to CONSTRUCT is the answer, for the reason the package already
// gives for validating a template at boot: a deployment that is wrong about its
// links should find out when it starts, not when somebody's account needs one.
//
// SO THE FAILURE DIRECTION IS THE TEST. Falling back to another purpose's template
// would make every row below pass — every mail would have a link — and it is the
// exact defect being fixed. That is why the assertions are on the error and not on
// a fallback value.
func TestTheConstructorRefusesAPurposeWithNoLinkTemplate(t *testing.T) {
	cases := []struct {
		name string
		// templates is what the deployment named, with the purposes it did NOT name
		// absent rather than defaulted.
		templates map[recovery.Purpose]string
		wantNamed recovery.Purpose
	}{
		{
			name: "no template for the password reset",
			templates: map[recovery.Purpose]string{
				recovery.PurposeVerifyEmail: "https://app.example.com/verify-email?token={token}",
			},
			wantNamed: recovery.PurposePasswordReset,
		},
		{
			name: "no template for the verification",
			templates: map[recovery.Purpose]string{
				recovery.PurposePasswordReset: "https://app.example.com/reset?token={token}",
			},
			wantNamed: recovery.PurposeVerifyEmail,
		},
		{
			name:      "no template for either",
			templates: map[recovery.Purpose]string{},
			wantNamed: recovery.PurposePasswordReset,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewRecoveryMailer(RecoveryMailerConfig{
				Client:        newTestClient(t, "https://courier.example.com", "svc-4b1d7e0a3c95f28"),
				LinkTemplates: tc.templates,
			})
			if err == nil {
				t.Fatal("a mailer was built with a purpose that has no link; every message " +
					"of that purpose would carry a link to nowhere")
			}
			if !strings.Contains(err.Error(), string(tc.wantNamed)) {
				t.Errorf("the refusal does not name the %s purpose: %v", tc.wantNamed, err)
			}
		})
	}
}

// TestEachPurposesLinkTemplateIsHeldToTheSameThreeRefusals is
// `TestTheLinkTemplateIsRefusedWhenItCannotMakeAWorkingLink` applied PER PURPOSE.
//
// # WHY THE TABLE IS THE SAME ONE
//
// `ValidateLinkTemplate`'s three refusals — no `{token}`, not absolute, a fragment
// rather than a query — are each a link that does not work, and they are a property
// of a TEMPLATE rather than of a message. One template used to be validated once,
// which meant one validation covered four messages by accident of there being one
// of it. Four templates means four validations, and a rule that was applied at
// construction for one purpose and not for the next is the same class of defect
// this packet is about: something that works and is not checked.
//
// SO EVERY ROW IS RUN FOR EVERY PURPOSE, and the row count is asserted. A table
// that quietly lost a purpose would otherwise pass by checking the one that
// remained.
func TestEachPurposesLinkTemplateIsHeldToTheSameThreeRefusals(t *testing.T) {
	refusals := []struct {
		name     string
		template string
	}{
		{name: "no placeholder", template: "https://app.example.com/reset"},
		{name: "relative", template: "/reset?token={token}"},
		{name: "a fragment a mail client would not send", template: "https://app.example.com/reset#/{token}"},
		{name: "a userinfo section", template: "https://kaka:pw@app.example.com/reset?token={token}"},
		{name: "a scheme courier's schema rejects", template: "javascript:alert({token})"},
		{name: "empty", template: ""},
	}

	accepted := map[recovery.Purpose]string{
		recovery.PurposePasswordReset: "https://app.example.com/reset?token={token}",
		recovery.PurposeVerifyEmail:   "https://app.example.com/verify-email?token={token}",
	}

	purposes := make([]recovery.Purpose, 0, len(linkPurposeFor))
	for _, purpose := range linkPurposeFor {
		purposes = append(purposes, purpose)
	}
	if len(purposes) != 2 {
		t.Fatalf("%d purposes have a link, want 2 (password reset and address "+
			"verification); the two email-change messages are refused before a link is "+
			"ever rendered and must not grow a template here", len(purposes))
	}

	for _, purpose := range purposes {
		t.Run(string(purpose), func(t *testing.T) {
			// A working template first, so every refusal below is about the template
			// rather than about a fixture that never worked.
			if _, err := NewRecoveryMailer(RecoveryMailerConfig{
				Client: newTestClient(t, "https://courier.example.com", "svc-4b1d7e0a3c95f28"),
				LinkTemplates: map[recovery.Purpose]string{
					recovery.PurposePasswordReset: accepted[recovery.PurposePasswordReset],
					recovery.PurposeVerifyEmail:   accepted[recovery.PurposeVerifyEmail],
				},
			}); err != nil {
				t.Fatalf("a working configuration was refused: %v", err)
			}

			for _, tc := range refusals {
				t.Run(tc.name, func(t *testing.T) {
					// The OTHER purpose is valid in every row, so the refusal under
					// test is the one being injected rather than a configuration
					// that was already broken. Otherwise every row would pass for
					// the wrong reason and the table would prove nothing about
					// the template.
					templates := map[recovery.Purpose]string{purpose: tc.template}
					for _, other := range allPurposes {
						if other != purpose && other != recovery.PurposeEmailChange {
							templates[other] = accepted[other]
						}
					}
					_, err := NewRecoveryMailer(RecoveryMailerConfig{
						Client:        newTestClient(t, "https://courier.example.com", "svc-4b1d7e0a3c95f28"),
						LinkTemplates: templates,
					})
					if err == nil {
						t.Fatalf("the %s link template %q was accepted", purpose, tc.template)
					}
					// The refusal names the purpose, so an operator reading a startup
					// log knows which variable to fix.
					if !strings.Contains(err.Error(), string(purpose)) {
						t.Errorf("the refusal does not name the %s purpose: %v", purpose, err)
					}
				})
			}
		})
	}
}

// TestEveryRecoverableMessageHasALinkPurposeAndOneDoesNot holds `courierTypeFor` and
// `linkPurposeFor` to the same keys, in BOTH directions.
//
// # WHY TWO TABLES AND NOT ONE, RESTATED AS A CHECK
//
// `courierTypeFor` says which of courier's three messages can express a message of
// `internal/recovery`'s, and `linkPurposeFor` says what the token in that message is
// FOR. They are kept apart because they are different vocabularies with different
// owners — courier's and `recovery`'s — and because they will diverge: the moment
// courier grows an `email_verification` type, the two answers to "which message is
// this" stop being the same shape, and a struct that held both would have made that
// a change to a struct rather than a change to one table.
//
// # WHAT EACH DIRECTION COSTS IF IT DRIFTS
//
//	a deliverable message with no purpose   `Send` refuses it, so a message this
//	                                        adapter can deliver stops being
//	                                        delivered — a regression that only
//	                                        shows up when somebody tries to send.
//	a purpose no message carries            the constructor refuses it, so a
//	                                        deployment that configured a link gets
//	                                        a startup failure naming a message
//	                                        that does not exist.
//
// The refusal is the right answer in both cases and neither is silent, which is why
// this test exists to keep the two tables from making them necessary.
func TestEveryRecoverableMessageHasALinkPurposeAndOneDoesNot(t *testing.T) {
	for subject := range courierTypeFor {
		if _, present := linkPurposeFor[subject]; !present {
			t.Errorf("%q is deliverable but has no link purpose, so `Send` would refuse "+
				"it and no link could ever be rendered for it", subject)
		}
	}
	for subject := range linkPurposeFor {
		if _, deliverable := courierTypeFor[subject]; !deliverable {
			t.Errorf("%q has a link purpose but no courier type, so a deployment "+
				"configuring a template for it would be refused at boot for a message "+
				"that is never sent", subject)
		}
	}
	// And the count, so a purpose added to both tables without the fixture being
	// updated is a visible edit here rather than a silent widening.
	if len(linkPurposeFor) != len(courierTypeFor) {
		t.Errorf("linkPurposeFor has %d entries and courierTypeFor has %d; they are "+
			"meant to cover the same messages", len(linkPurposeFor), len(courierTypeFor))
	}
}

// pathOf is the path of a rendered link, parsed.
//
// IT PARSES RATHER THAN STRINGS-CUTS because the comparison this file exists to
// make is between SCREENS, and a `?token=` difference is not a different screen.
// Cutting at `?` would have made a defect that changes only the query parameter
// look like a fixed one.
func pathOf(t *testing.T, link string) string {
	t.Helper()
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatalf("the rendered link %q is not a URL: %v", link, err)
	}
	if parsed.Path == "" {
		t.Errorf("the rendered link %q has no path, so it has no screen to point at", link)
	}
	return parsed.Path
}

// withoutToken puts the credential back into a rendered link, so what is left is
// the TEMPLATE that produced it.
//
// IT EXISTS because "the two links are the same" and "the two links were rendered
// from the same template" are different claims, and only the second is true of a
// single-template configuration: the two flows mint two tokens, so the rendered
// links differ in exactly the one place that is supposed to differ. Comparing the
// rendered forms would have made this negative control pass for the wrong reason —
// and would have made the assertion in the test above, which compares paths, look
// like it needed a helper it does not.
func withoutToken(link string) string {
	parsed, err := url.Parse(link)
	if err != nil {
		return link
	}
	query := parsed.Query()
	if query.Has("token") {
		query.Set("token", TokenPlaceholder)
		parsed.RawQuery = query.Encode()
	}
	return parsed.String()
}

// tokenIn reads the credential out of a rendered link.
//
// IT READS THE LINK AND NOT THE DATABASE OR THE MESSAGE, because the link is the
// only place the plaintext exists and the claim is about what the RECIPIENT holds.
// A token read from the message body would prove the flows mint correctly, which
// identity-24 already proved, rather than that the mail carried it.
func tokenIn(t *testing.T, link string) string {
	t.Helper()
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatalf("the rendered link %q is not a URL: %v", link, err)
	}
	token := parsed.Query().Get("token")
	if token == "" {
		t.Fatalf("the rendered link %q carries no token; a link with nothing in it is a "+
			"mail a user can follow and cannot use", link)
	}
	return token
}
