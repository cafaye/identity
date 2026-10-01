package courier

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/recovery"
)

// # THE END-TO-END TEST, AND WHAT IT IS ALLOWED TO CLAIM
//
// It drives the real `Client` and the real `RecoveryMailer` against a REAL courier
// process — courier master `f776b86`, the repository's own Phoenix application, its
// own migrations, its own `Deliver` context — over HTTP. Nothing in this file is a
// double: the server on the other end parses the body, checks the closed
// vocabulary, consults its suppression table, renders its own template and writes
// its own outbox row.
//
// # WHY IT IS GATED, AND WHY IT SKIPS WITH A NAME RATHER THAN FAILING
//
// It needs a courier, so it reads `TEST_COURIER_URL` and `TEST_COURIER_TOKEN`. When
// the variable is absent this file SKIPS, and says what it would have proven and how
// to run it.
//
// # THAT IS A CHANGE OF MIND, AND THE REASONING IS WORTH RECORDING
//
// This file used to FAIL on an absent `TEST_COURIER_URL`, argued by analogy with
// `internal/mfa`'s database tier: "A skip is honest; a test that silently passes
// without proving anything is not." That reasoning was applied to the wrong tier,
// and the difference between the two tiers is not a matter of taste — it is whether
// the thing the test needs is something CI can supply.
//
//	`internal/mfa`   needs a DATABASE.  CI supplies one: the `gate` job declares
//	                 postgres as a service container and applies the migrations above
//	                 the gate. So an absent `TEST_DATABASE_URL` in that package means
//	                 the RUN is misconfigured, and failing is the honest answer. The
//	                 rule holds there, and `TestTheDatabaseTierActuallyRan` still
//	                 enforces it, in this package's sibling and in `internal/mfa`'s.
//
//	here            needs a COURIER.  CI supplies no courier and cannot without
//	                 standing up a second service, its own database and its own
//	                 principal resolver — which is the same reason the `ci` job's
//	                 header records for the database tier not being reachable inside
//	                 kit's reusable workflow. So an absent `TEST_COURIER_URL` here
//	                 means the test is not RUNNABLE in this environment, not that it
//	                 was asked for and failed.
//
// A test that hard-fails on the absence of something the environment cannot provide
// makes the whole package unrunnable, and an unrunnable package is a worse lie than
// an honest skip: it is red on every machine, including CI, so the signal it carries
// is "this package is broken" on every run, and a permanently red suite is a red
// suite people learn to ignore. The fix is not to delete the proof — the proof is
// the reason this file exists — but to make the skip say everything the failure was
// saying, which is what `skipWithoutCourier` does.
//
// # AND CI KNOWS ABOUT THE SKIP RATHER THAN DISCOVERING IT
//
// A skip that CI tolerates silently is how a gate goes green by not checking, so
// `.github/workflows/ci.yml` names these tests in `E2E_SKIP_EXCEPTIONS`: any other
// `--- SKIP:` line anywhere still fails the job, and `internal/platform/ci` holds
// that list to exactly these three names and fails when one grows or disappears.
// The exemption is declared, narrow, and under test — the same shape as every other
// exception in this repository (the lint exclusion, the coverage exclusions, and
// `knownDrift`).
//
// To run it, see the script at the bottom of this file.

const (
	// courierURLVariable is where the live courier is.
	courierURLVariable = "TEST_COURIER_URL"

	// courierTokenVariable is the service credential the live courier accepts.
	//
	// IT IS READ FROM THE ENVIRONMENT AND NEVER PRINTED, and a test that fails
	// because of it says so in one line naming the variable rather than dumping
	// the value.
	courierTokenVariable = "TEST_COURIER_TOKEN"
)

// TestAPasswordResetGoesOutThroughARealCourier is the packet's end-to-end proof.
//
// THE CHAIN, and every link in it is real:
//
//	recovery renders a Message  (internal/recovery, no double)
//	  -> RecoveryMailer.Send     (internal/courier, no double)
//	    -> Client.SendMessage    (internal/courier, no double)
//	      -> POST /v1/messages   (courier master f776b86, a real process)
//	        -> Courier.Deliver   (courier, real: preferences, suppression, render)
//	          -> provider        (Swoosh.Adapters.Local: renders, mails nobody)
//	            -> 200 accepted
//
// AND WHAT IT PROVES. It proves that a password reset identity composes produces a
// request courier accepts, with the credential in the link and nowhere else, and
// that the answer is read as an accepted send. It proves the four fields are right
// for a real validator rather than for a fixture.
//
// AND WHAT IT DOES NOT PROVE, stated here rather than left to a reader:
//
//   - It does not prove a DEPLOYMENT can authenticate. courier's default principal
//     resolver authenticates nobody, so a stock courier answers 401; the live
//     courier this runs against has a resolver configured, which is the state
//     courier will be in once its JWT-verifier packet lands. The 401 is recorded
//     and asserted in `recorded_test.go`.
//   - It does not prove delivery. courier answers `accepted` because a submission
//     protocol says nothing about arrival, and `Swoosh.Adapters.Local` renders the
//     mail into memory. Nothing here claims a message arrived.
//   - It does not prove the other three messages. courier has no type for them and
//     this adapter refuses them, which `TestAMessageCourierHasNoTypeForIsRefused`
//     holds and which is a courier contract gap rather than an identity one.
func TestAPasswordResetGoesOutThroughARealCourier(t *testing.T) {
	live := requireLiveCourier(t)

	const recipient = "identity-e2e@example.com"
	// A token that is a real 256-bit value's shape, because a courier that
	// validated it would reject anything else — and this is the value that must
	// reach the link and nothing else.
	token := liveToken(t)

	message := resetMessageFor(recipient, token)
	message.UserID = testUserID

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := live.mailer.client.SendMessage(ctx, MessageRequest{
		Type:   TypePasswordReset,
		UserID: message.UserID.String(),
		To:     recipient,
		URL:    renderTestLink(t, token),
	})
	if err != nil {
		t.Fatalf("a real courier refused a password reset identity can compose: %v", err)
	}

	// Every field courier documents, checked. A 200 with a body this client read as
	// nothing would be the failure mode worth guarding, and each field is one a
	// bounce or a consumer needs.
	if result.Status != StatusAccepted {
		t.Errorf("Status = %q, want %q", result.Status, StatusAccepted)
	}
	if result.Type != TypePasswordReset {
		t.Errorf("Type = %q, want %q", result.Type, TypePasswordReset)
	}
	if result.MessageID == "" {
		t.Error("MessageID is empty; a bounce quoting it would tie back to nothing")
	}
	if result.EventID == "" {
		t.Error("EventID is empty; it is the outbox row every bus subscriber sees")
	}
	if result.UserID != message.UserID.String() {
		t.Errorf("UserID = %q, want the one sent (%q)", result.UserID, message.UserID)
	}
	// courier's own message id carries its prefix, and that prefix is how an
	// operator tells a courier send from anything else with an id in a log.
	if !strings.HasPrefix(result.MessageID, "courier-") {
		t.Errorf("MessageID = %q, want courier's own id shape", result.MessageID)
	}

	// AND THE WHOLE ADAPTER, not just the client: `RecoveryMailer.Send` is the path
	// `recovery` calls, and driving only the client would leave the translation
	// untested against a real validator.
	if err := live.mailer.Send(ctx, message); err != nil {
		t.Fatalf("RecoveryMailer.Send against a real courier: %v", err)
	}
}

// TestAVerificationLinkReachesCouriersWelcomeTemplate is the second deliverable,
// and it is here against a REAL courier because the claim is about courier's
// template rather than about this client.
//
// # THE DOCUMENT IS WRONG ABOUT ONE THING, AND THE CODE IS RIGHT
//
// courier's `openapi.yaml` says `url` is "unused by `welcome`", and its
// `welcome.text.eex` renders `@url` when it is present:
//
//	<%= @greeting %>
//
//	Welcome aboard. Confirm your address and you are in.
//	<%= if @url do %>
//	Confirm your email address: <%= @url %>
//	<% end %>
//
// So a `welcome` WITH a link is legal — `Courier.Mailers.required/1` asks only for
// `email` — and the confirmation link appears in the rendered mail. The recorded
// requests below are what a real courier answered: a 200 `accepted` for the
// `welcome` carrying a `url`, with courier's own `message_id` and `event_id`.
//
// This is why `verify_email` maps to `welcome` and is not refused like the two
// email-change messages are: the words are true. `recovery.RequestVerification`
// already refuses with `ErrAlreadyVerified` for an account that has proved its
// address, so this message only reaches an account that never has — which is what
// "Welcome aboard" describes.
func TestAVerificationLinkReachesCouriersWelcomeTemplate(t *testing.T) {
	live := requireLiveCourier(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := live.mailer.client.SendMessage(ctx, MessageRequest{
		Type:   TypeWelcome,
		UserID: "7e8f9a0b-1c2d-4e3f-9a4b-5c6d7e8f9a0b",
		To:     "identity-e2e-welcome@example.com",
		URL:    renderTestLink(t, liveToken(t)),
	})
	if err != nil {
		t.Fatalf("a real courier refused a verification welcome: %v", err)
	}
	if result.Type != TypeWelcome {
		t.Errorf("notification_type = %q, want %q", result.Type, TypeWelcome)
	}
	if result.Status != StatusAccepted {
		t.Errorf("Status = %q, want %q", result.Status, StatusAccepted)
	}
	if result.MessageID == "" {
		t.Error("MessageID is empty")
	}
}

// TestTheTwoEmailChangeMessagesCourierCannotSendAreRefused is the negative half,
// and it is two rows rather than three because `verify_email` now has a courier
// type — see the test above for why `welcome` is the true one.
//
// courier has no message about an address change, and the two templates that exist
// both say something false about one:
//
//   - `password_reset` tells the account owner that SOMEBODY ASKED TO RESET THEIR
//     PASSWORD. The current-address half is the ONLY warning the owner of an account
//     has that somebody is moving its address — the whole of the hijack property
//     `internal/recovery` is built around. A wrong-but-delivered security notice is
//     worse than a loud failure.
//   - `welcome` says "Welcome aboard" to somebody being told a hijacked session is
//     moving their address.
//
// So both are refused BEFORE the wire, which means no token reaches a courier that
// would render it, and the flow answers 503 with a sentence an operator can read.
// The recorded 422 `unknown_notification_type` in `recorded_test.go` is what the
// alternative produced.
func TestTheTwoEmailChangeMessagesCourierCannotSendAreRefused(t *testing.T) {
	live := requireLiveCourier(t)

	token := liveToken(t)
	cases := []struct {
		name    string
		message recovery.Message
	}{
		{name: "the current-address half of an email change", message: changeCurrentMessage(token)},
		{name: "the new-address half of an email change", message: changeNewMessage(token)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := live.mailer.Send(context.Background(), tc.message)
			if !isError(err, ErrUnsupportedMessage) {
				t.Fatalf("Send = %v, want ErrUnsupportedMessage. courier's NotificationType "+
					"is [welcome, password_reset, team_invitation] and neither template "+
					"describes an address change truthfully", err)
			}
		})
	}
}

// # THE HARNESS

// liveCourier is a courier this test suite is talking to for real.
type liveCourier struct {
	// mailer is the whole adapter, so a test can drive either layer.
	mailer *RecoveryMailer

	// userID is an account courier will accept an arbitrary `user_id` for. courier
	// holds no foreign key to identity's users, so any well-formed uuid works and
	// the preferences lookup finds nothing, which means the default (enabled)
	// applies.
	userID string
}

// requireLiveCourier builds the adapter against a real courier, or SKIPS BY NAME.
//
// # THE THREE STATES, AND THEY ARE NOT THE SAME ANSWER
//
//	absent     the test is not runnable here  -> a named skip (this file's header)
//	present    the courier is unreachable     -> a FAILURE
//	present    the courier refuses our bytes -> a FAILURE
//
// The split is the whole of it. An absent variable is a statement about the
// ENVIRONMENT, and the honest answer to "this cannot run here" is a skip that says
// so. A variable that is SET and whose courier is down or misconfigured is a
// statement about a DEPLOYMENT somebody is relying on, and answering that with a
// skip would hide a real outage behind a green suite — which is the exact failure
// this repository's rules exist to prevent. So `skipWithoutCourier` is reached only
// when the variable is absent, and everything after it fails.
//
// That is also why the token is checked AFTER the skip rather than before it: a
// developer who set neither variable should see one message about the one they need
// first, not two.
func requireLiveCourier(t *testing.T) *liveCourier {
	t.Helper()

	raw, present := os.LookupEnv(courierURLVariable)
	if !present || strings.TrimSpace(raw) == "" {
		skipWithoutCourier(t)
	}
	token, present := os.LookupEnv(courierTokenVariable)
	if !present || token == "" {
		// The VALUE is never printed. Naming the variable is the whole of what an
		// operator needs, and it is the same rule this package holds for its errors.
		//
		// AND IT FAILS rather than skipping, because reaching here means
		// TEST_COURIER_URL IS set: somebody asked for this proof and did not
		// finish setting it up.
		t.Fatalf("%s is not set while %s is, so the courier is pointed at and cannot be "+
			"authenticated to. The value is never printed; set it to the service "+
			"credential your courier accepts.", courierTokenVariable, courierURLVariable)
	}

	client, err := New(Config{
		BaseURL: raw,
		Token:   token,
		Timeout: 20 * time.Second,
	})
	if err != nil {
		t.Fatalf("building a client for %s: %v", courierURLVariable, err)
	}
	mailer, err := NewRecoveryMailer(RecoveryMailerConfig{
		Client:       client,
		LinkTemplate: "https://app.example.com/reset?token=" + TokenPlaceholder,
	})
	if err != nil {
		t.Fatalf("NewRecoveryMailer: %v", err)
	}

	// A readiness probe first, so a failure here is courier's unavailability rather
	// than a confusing 422 about something this test got wrong.
	probe, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := client.Ready(probe); err != nil {
		t.Fatalf("the courier at %s is not ready: %v", courierURLVariable, err)
	}

	return &liveCourier{mailer: mailer}
}

// skipWithoutCourier skips with the two facts a reader needs, and it is a NAMED
// helper rather than an inline `t.Skipf` in three tests because the message is the
// only thing a skip leaves behind.
//
// It says WHAT WOULD HAVE BEEN PROVEN and HOW TO RUN IT. A bare `t.Skip` says
// nothing, so a reader in CI sees a line that means "something did not run" and
// learns no more than that — which is the property this repository calls a test that
// silently passes without proving anything. This one names the claim, names the
// variable, names the second variable, and points at the script that starts a
// courier. A developer who reads it in a CI log can act on it without opening this
// file.
//
// IT NAMES BOTH VARIABLES because setting one without the other is the mistake a
// reader is most likely to have made, and the second failure would otherwise cost
// them a second round trip to find out.
//
// The message deliberately does NOT claim the proof was made elsewhere as a
// substitute. The offline wiring in `wiring_test.go`, the request contract in
// `client_test.go` and the byte-for-byte responses in `recorded_test.go` cover
// everything a client can be wrong about without a second process, and none of them
// can assert that a real implementation of courier's document accepts these bytes.
// This file is still the only thing that says that, which is why it is skipped and
// not deleted.
func skipWithoutCourier(t *testing.T) {
	t.Helper()

	t.Skipf("SKIPPED A LIVE-PROOF, NOT A BEHAVIOUR: %s is not set, so this test could not "+
		"prove that a message identity rendered by internal/recovery traverses courier's own "+
		"validation and comes back accepted.\n"+
		"  Every other property of this integration IS asserted offline: the request identity "+
		"and its stable Idempotency-Key in wiring_test.go, courier's request contract in "+
		"client_test.go, and courier's byte-for-byte recorded answers in recorded_test.go. "+
		"What is left for this file is the one claim a fixture cannot make about itself.\n"+
		"  TO RUN IT: start a courier with its own principal resolver and provider — the "+
		"script is at the bottom of %s — then:\n"+
		"    TEST_COURIER_URL=http://127.0.0.1:4014 TEST_COURIER_TOKEN=\"$(openssl rand -hex 16)\" "+
		"go test ./internal/courier/ -v\n"+
		"  (%s is the service credential that courier accepts. Both are needed: a URL with no "+
		"token is a skip above and a token with no URL is nothing at all.)",
		courierURLVariable, "internal/courier/e2e_support_test.go", courierTokenVariable)
}

// TestTheDatabaseTierActuallyRan is the counterpart to `skipWithoutCourier`, and it
// is here for the same reason with the OPPOSITE answer.
//
// `flow_test.go` opens a pool, so this package is one of the database-tier packages
// CI derives from the tree and counts towards DATABASE_TIER_FLOOR. Every one of
// those tests SKIPS itself when TEST_DATABASE_URL is absent, so without a guard in
// this package a run on a machine without Postgres reports `ok` here having proved
// nothing about the flows — and this file's header has just argued that the courier
// tier is a different case, which is exactly why the boundary has to be drawn in
// code rather than left to be remembered.
//
// IT FAILS rather than skips, and the asymmetry with the courier tier above is the
// point rather than an inconsistency:
//
//	the DATABASE  CI supplies one, as a service container in the `gate` job, with
//	               the migrations applied above the gate. An absent variable here is
//	               a misconfigured RUN, and failing is the honest answer.
//	the COURIER    CI supplies none and cannot without a second service, so an
//	               absent variable is an environment that cannot run the test, and
//	               skipping with a name is the honest answer.
//
// A package that opens a pool needs the first; a package with a live-service tier
// needs the second. This package now has both, and each is the right one for what
// it guards.
func TestTheDatabaseTierActuallyRan(t *testing.T) {
	if os.Getenv(dbtest.EnvVar) == "" {
		t.Fatalf("%s is not set, so every database test in this package skipped. The courier "+
			"tier in this file skipping for want of a courier is a different case and has its "+
			"own reason above; this one is not it. Run `goose -dir migrations postgres "+
			"\"$DATABASE_URL\" up` and then `TEST_DATABASE_URL=\"$DATABASE_URL\" go test ./...`; "+
			"see README.md, Testing.", dbtest.EnvVar)
	}
}

// liveToken mints a credential-shaped token, from the same source `recovery` uses
// so the shape is the production one rather than a fixture that happens to be long.
func liveToken(t *testing.T) string {
	t.Helper()
	token, err := newUUIDv4()
	if err != nil {
		t.Fatalf("minting a token: %v", err)
	}
	return strings.ReplaceAll(token, "-", "")
}

// renderTestLink builds the link the same way the adapter does, so this test does
// not assert against a URL the production path would not produce.
func renderTestLink(t *testing.T, token string) string {
	t.Helper()
	rendered, err := LinkTemplate("https://app.example.com/reset?token=" + TokenPlaceholder).render(token)
	if err != nil {
		t.Fatalf("rendering the link: %v", err)
	}
	return rendered
}

// # HOW TO RUN IT, EXACTLY AS THE RECORDED FIXTURES WERE TAKEN
//
// The recorded interactions in `recorded_test.go` came from this setup, and so does
// this test. `mix run --no-start <script>` starts courier's own application with a
// principal resolver and a provider configured from outside its config files — the
// repository is not modified, and `Courier.MailerAdapter`'s refusing default is not
// bypassed, only satisfied.
//
// # PICK BOTH PORTS, AND THE HTTP ONE IS NOT OPTIONAL
//
// The two numbers below (55433 and 4014) were free when the fixtures were
// recorded. They are not free now, and an occupied one fails in a way that
// invalidates the proof rather than refusing to run it:
//
//   - **The postgres port collides loudly.** `docker run` refuses to publish an
//     already-bound port, so you find out immediately. Pick another.
//   - **The HTTP port does NOT collide loudly, and this is the dangerous one.**
//     Two processes can hold `4014` at once when one binds `127.0.0.1` and the
//     other `0.0.0.0`, because the more specific bind wins the loopback traffic
//     and the wildcard keeps the rest. Nothing errors. Instead your sends land in
//     the OTHER courier's database, so a green live tier is a tier somebody
//     else's process answered — which is precisely the false claim this file
//     exists to rule out.
//     Before you start, check the port is free (`lsof -nP -iTCP:4014 -sTCP:LISTEN`)
//     and pick one nothing is on. The one hardcoded in this recipe and in
//     `skipWithoutCourier` is a default to edit, not a default to trust.
//   - The defence that does not depend on the port: after the run, confirm the
//     rows are in the database you started. `select subject, data->>'email' from
//     outbox_events` is the whole check, and it is the only one that distinguishes
//     "a real courier accepted these bytes" from "a real courier accepted these
//     bytes, the one you happened to be talking to".
//
// # AND DO NOT SET `OTEL_SDK_DISABLED` TO QUIETEN THE LOG
//
// It is a reasonable thing to try, and on courier master `a8f15cc` it stops the
// boot. `Courier.Telemetry.sdk_config/0`'s disabled branch returns the bare atom
// `span_processor: :otel_simple_processor`, and opentelemetry 1.7.0 needs a named
// tuple whose options are a map — the same shape courier's ENABLED branch already
// uses. A bare atom is a `FunctionClauseError` in `otel_configuration:processors/2`
// and the application refuses to start. `OTEL_TRACES_EXPORTER=none` (and the
// metrics and logs equivalents) reach the same branch and fail the same way. That
// is courier's defect and not this repository's; the exporter failing to reach a
// collector is harmless noise in a run, so leave it on.
//
//	# 1. a database
//	docker run -d --name courier-e2e-pg -e POSTGRES_DB=courier_test \
//	  -e POSTGRES_USER=courier -e POSTGRES_PASSWORD=courier \
//	  -p 55433:5432 postgres:17-alpine
//
//	# 2. a principal resolver and a provider.
//
//	# `Courier.Principal.Reject` is the SHIPPED default and authenticates nobody,
//	# so `/v1/messages` is a 401 until a resolver is configured. That is courier's
//	# own documented two-step, not a workaround: its plug's moduledoc says "a
//	# missing verifier is a locked door, not an open one", and the real verifier is
//	# its JWT packet. The resolver below accepts a bearer of any shape, which is
//	# enough to prove this client puts the credential where the pipeline reads it.
//
//	# The provider is `Swoosh.Adapters.Local`: it renders into memory and returns a
//	# provider-shaped id. The proof is that courier VALIDATED and ACCEPTED the
//	# message; mailing a real inbox is neither necessary nor a thing a test should
//	# do.
//	cat > /tmp/courier-e2e.exs <<'ELIXIR'
//	defmodule E2EPrincipal do
//	  @behaviour Courier.Principal.Resolver
//
//	  def resolve(conn) do
//	    case Plug.Conn.get_req_header(conn, "authorization") do
//	      ["Bearer " <> token] when byte_size(token) > 0 ->
//	        {:ok, %Courier.Principal{account_id: account_for(token), subject: "identity"}}
//	      _ -> :error
//	    end
//	  end
//
//	  defp account_for(token) do
//	    hash = :md5 |> :crypto.hash(token) |> Base.encode16(case: :lower)
//	    hyphenate(hash)
//	  end
//
//	  defp hyphenate(<<a::binary-size(8), b::binary-size(4), c::binary-size(4),
//	                 d::binary-size(4), e::binary-size(12)>>) do
//	    a <> "-" <> b <> "-" <> c <> "-" <> d <> "-" <> e
//	  end
//	end
//
//	Application.put_env(:courier, Courier.Repo,
//	  username: "courier", password: "courier", hostname: "localhost",
//	  port: 55433, database: "courier_test", pool_size: 5)
//
//	Application.put_env(:courier, :principal, E2EPrincipal)
//	Application.put_env(:courier, Courier.Mailer, adapter: Swoosh.Adapters.Local)
//
//	endpoint = :courier |> Application.get_env(CourierWeb.Endpoint, [])
//	  |> Keyword.put(:server, true)
//	  |> Keyword.put(:http, ip: {0, 0, 0, 0}, port: 4014)
//	  |> Keyword.put(:code_reloader, false)
//	  |> Keyword.put(:debug_errors, false)
//	Application.put_env(:courier, CourierWeb.Endpoint, endpoint)
//
//	{:ok, _} = Application.ensure_all_started(:courier)
//	Ecto.Migrator.run(Courier.Repo, "priv/repo/migrations", :up, all: true)
//	Process.sleep(:infinity)
//	ELIXIR
//
//	cd ../courier
//	COURIER_SECRET_BOX_KEY="$(openssl rand -base64 32)" COURIER_MAIL_ADAPTER=none \
//	  mix run --no-start /tmp/courier-e2e.exs &
//
//	# 3. the tests
//	cd ../identity
//	TEST_COURIER_URL=http://127.0.0.1:4014 \
//	TEST_COURIER_TOKEN="$(openssl rand -hex 16)" \
//	  go test ./internal/courier/ -v
//
// For the `503` fixture, put the adapter on a relay that is not there — `relay:
// "127.0.0.1", port: 1, tls: :never, username: "x", password: "x"` — and the send
// fails inside courier's transaction. Swoosh requires `relay:` rather than `server:`
// and refuses a nil `username`, both of which cost a recording attempt each; the
// fixture is real and the two dead ends are the reason the file says so.
//
// # WHAT THIS FILE MUST NOT BECOME
//
// A place that asserts identity's own behaviour. Everything here is about the wire
// and about courier's answers. A test that could pass with courier replaced by a
// fixture belongs in `client_test.go` or `fakecourier_test.go`, where a failure is
// fast and hermetic, and this file is for the one claim a fixture cannot make about
// itself: that a real implementation of courier's document accepts these bytes.
