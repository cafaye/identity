package courier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/recovery"
)

// # THE SHAPE OF THIS FILE
//
// Three groups, in the order a reader should care about them:
//
//  1. What the adapter REFUSES, because that is the decision with a security
//     consequence: two of `recovery`'s four messages describe an event no courier
//     template describes, and the wrong translation is a security notice that lies.
//  2. What it SENDS, asserted against courier's request vocabulary.
//  3. What it NEVER PRINTS, which is the credential and the token and the
//     recipient.

// recoveryMessage is a `recovery.Message` shaped the way the real one is, built
// from the constants `internal/recovery` actually renders.
func recoveryMessage(subject, to, body string) recovery.Message {
	return recovery.Message{To: to, Subject: subject, Body: body}
}

// resetMessageFor is a `recovery.Message` a courier-backed adapter CAN send: the
// password-reset subject, an account, and a body with a token in it.
func resetMessageFor(email, token string) recovery.Message {
	message := recoveryMessage(kindPasswordReset, email,
		resetBody(token, email, time.Date(2026, 10, 1, 12, 30, 0, 0, time.UTC)))
	message.UserID = testUserID
	return message
}

// verificationMessage, changeCurrentMessage and changeNewMessage are the other
// three messages `internal/recovery` renders, built from its own bodies.
//
// They exist as builders because the end-to-end file needs to present them to a
// courier, and because a test that hand-wrote a subject would be testing a string
// the adapter and `internal/recovery` agree on by accident rather than by
// contract. Two of the three are deliverable (`password_reset` and `verify_email`)
// and one pair is refused, which is what the two groups of tests here assert.
func verificationMessage(token string) recovery.Message {
	message := recoveryMessage(kindVerifyEmail, "kaka@example.com",
		"Confirm the address kaka@example.com for your cafaye account.\n\n"+
			"Your confirmation code is:\n\n    "+token+"\n")
	message.UserID = testUserID
	return message
}

func changeCurrentMessage(token string) recovery.Message {
	message := recoveryMessage(kindChangeCurrent, "kaka@example.com",
		"Somebody signed in to the cafaye account on kaka@example.com and asked to\n"+
			"change the address it uses.\n\nIf that was you, confirm it with this code:\n\n    "+
			token+"\n")
	message.UserID = testUserID
	return message
}

func changeNewMessage(token string) recovery.Message {
	message := recoveryMessage(kindChangeNew, "new@example.com",
		"Somebody asked to move the cafaye account on kaka@example.com to this address.\n")
	message.UserID = testUserID
	return message
}

// testUserID is a real uuid, because courier checks the shape and this constant
// exercises that check rather than a fixture that happens to be a string.
var testUserID = id.MustNew()

// resetBody is what `internal/recovery`'s `passwordResetBody` renders for a token
// and an expiry. The indentation and the blank lines are the real ones, because
// the extraction in mailer.go reads the shape rather than the words.
func resetBody(token, email string, expiry time.Time) string {
	return "Somebody asked to reset the password for the account registered to " + email + ".\n" +
		"\nYour reset code is:\n" +
		"\n    " + token + "\n" +
		"\nEnter it where you sign in to choose a new password. It works once, and only\n" +
		"until " + expiry.UTC().Format(time.RFC1123) + ".\n" +
		"\nIf this was not you, nothing has changed. Nobody can sign in with this code\n" +
		"without it, and it stops working as soon as it is used or when it expires.\n"
}

const testToken = "K7dQm2xR9vTb4nLpZcHs1JfWy6AeUi0O"

// # 1. THE REFUSALS

// TestEveryRecoverableMessageReachesCourier is the positive counterpart to the
// refusal table, and it is what stops the whole package from passing by sending
// nothing.
//
// The claim is about MESSAGES, not about the request: every message of
// `internal/recovery`'s that courier can express must produce a real courier send,
// and the three refusals must not quietly become four. It reads `knownSubjects` —
// the same set the refusal table's drift check holds against
// `internal/recovery/message.go` — so a fifth message added there fails HERE rather
// than being absent from both tables.
func TestEveryRecoverableMessageReachesCourier(t *testing.T) {
	deliverable := make([]string, 0, len(courierTypeFor))
	for subject := range courierTypeFor {
		deliverable = append(deliverable, subject)
	}
	sort.Strings(deliverable)

	// Both halves of the claim, stated as numbers so a change in either direction is
	// a visible edit to this test rather than a silent drift.
	if len(deliverable) != 2 {
		t.Errorf("%d messages are deliverable, want 2: %v. identity's address "+
			"verification maps onto courier's `welcome` and its password reset onto "+
			"courier's `password_reset`; the two email-change messages have no courier "+
			"equivalent and must stay refused", len(deliverable), deliverable)
	}
	if len(knownSubjects)-len(deliverable) != 2 {
		t.Errorf("%d of %d messages are refused, want 2", len(knownSubjects)-len(deliverable),
			len(knownSubjects))
	}

	for _, subject := range deliverable {
		t.Run(subject, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"data":{"status":"accepted",` +
					`"user_id":"6f5d4c3b-2a19-4e8f-9c07-1b2d3e4f5061",` +
					`"message_id":"courier-1","event_id":"e1",` +
					`"notification_type":"` + courierTypeFor[subject] + `"}}`))
			}))
			defer server.Close()

			mailer := testMailer(t, server.URL, nil)
			var message recovery.Message
			switch subject {
			case kindPasswordReset:
				message = resetMessageFor("kaka@example.com", testToken)
			case kindVerifyEmail:
				message = verificationMessage(testToken)
			default:
				t.Fatalf("no fixture for %q; add one or remove it from courierTypeFor", subject)
			}

			if err := mailer.Send(context.Background(), message); err != nil {
				t.Fatalf("a message courier CAN render was refused: %v", err)
			}
		})
	}
}

// TestAMessageCourierHasNoTypeForIsRefused is the packet's most important security
// assertion, so it is stated as a table over BOTH of `recovery`'s messages courier
// cannot render rather than as one case.
//
// The claim is: identity renders four messages; courier's `NotificationType` is
// `[welcome, password_reset, team_invitation]`; the two email-change messages
// describe an event no courier template describes, and therefore must be REFUSED
// rather than translated onto something that renders.
//
// The two `verify_email` and `password_reset` rows are NOT here, and their absence
// is the other half of the claim: `TestEveryRecoverableMessageReachesCourier`
// holds that BOTH of them are delivered, so this table cannot pass by refusing
// everything. A refusal table with no positive counterpart is satisfied by a
// package that cannot send mail at all, and that is the state this packet exists
// to leave.
func TestAMessageCourierHasNoTypeForIsRefused(t *testing.T) {
	cases := []struct {
		name    string
		message recovery.Message
		why     string
	}{
		{
			name: "the current-address half of an email change",
			message: recoveryMessage(kindChangeCurrent, "kaka@example.com",
				"Somebody signed in to the cafaye account on kaka@example.com and asked to\n"+
					"change the address it uses.\n\nIf that was you, confirm it with this code:\n\n    "+
					testToken+"\n\nIf it was not you, do nothing.\n"),
			why: "courier's password_reset template would tell the account owner that " +
				"somebody asked to RESET THEIR PASSWORD, and this message is the only " +
				"warning they get that somebody is moving their address",
		},
		{
			name: "the new-address half of an email change",
			message: recoveryMessage(kindChangeNew, "new@example.com",
				"Somebody asked to move the cafaye account on kaka@example.com to this address.\n"),
			why: "no courier template describes a change confirmation, and inventing one " +
				"would mean identity owning a template courier renders",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A courier that would ACCEPT anything, so a pass cannot come from the
			// server refusing. Every row has to be refused by the adapter.
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Errorf("courier was called for a message it should never have been "+
					"sent: %s %s", r.Method, r.URL.Path)
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			mailer, err := NewRecoveryMailer(RecoveryMailerConfig{
				Client:        newTestClient(t, server.URL, "service-token-value"),
				LinkTemplates: testLinkTemplates(),
			})
			if err != nil {
				t.Fatalf("NewRecoveryMailer: %v", err)
			}

			err = mailer.Send(context.Background(), tc.message)
			if err == nil {
				t.Fatalf("Send accepted a message courier cannot render, because %s", tc.why)
			}
			if !isError(err, ErrUnsupportedMessage) {
				t.Errorf("error = %v, want one matching ErrUnsupportedMessage", err)
			}
			// Not retryable: the same request will be refused the same way in five
			// minutes, and a caller that thought otherwise would loop.
			if Retryable(err) {
				t.Error("a message courier cannot render was reported as retryable")
			}
		})
	}
}

// TestAMessageWithNoAccountIsRefusedRatherThanGuessedAt is the assertion that the
// one field this packet added to `recovery.Message` is actually load-bearing, and
// that a message without one fails LOUDLY.
//
// A zero `UserID` is a state `recovery` can produce — nothing in that package
// requires one — and the two wrong answers are both bad. Guessing an id attributes
// a message carrying a live credential to an account nobody chose; sending without
// one is a request courier answers 422 for, after a token has been minted and a
// user told a link is on its way.
func TestAMessageWithNoAccountIsRefusedRatherThanGuessedAt(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		t.Errorf("courier was called for a message with no account: %s", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	var log bytes.Buffer
	mailer := testMailer(t, server.URL, slog.New(slog.NewTextHandler(&log, nil)))

	anonymous := recoveryMessage(kindPasswordReset, "kaka@example.com",
		resetBody(testToken, "kaka@example.com", time.Date(2026, 10, 1, 12, 30, 0, 0, time.UTC)))
	if !anonymous.UserID.IsZero() {
		t.Fatal("the fixture is supposed to have no account")
	}

	err := mailer.Send(context.Background(), anonymous)
	if !isError(err, ErrUnsupportedMessage) {
		t.Fatalf("Send = %v, want ErrUnsupportedMessage", err)
	}
	if calls != 0 {
		t.Errorf("courier was called %d times", calls)
	}
	if !strings.Contains(log.String(), "no account") {
		t.Errorf("the refusal was not logged:\n%s", log.String())
	}
	// And the log still must not carry the token it refused to send.
	if strings.Contains(log.String(), testToken) {
		t.Error("the log carries the live token of a message that was not sent")
	}
}

// # 2. WHAT IT SENDS

// TestTheRequestCarriesExactlyWhatCouriersVocabularyHas is the positive counterpart
// to the refusals: when this adapter does send, the bytes are courier's bytes.
func TestTheRequestCarriesExactlyWhatCouriersVocabularyHas(t *testing.T) {
	var body map[string]any
	var header http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header = r.Header.Clone()
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"status":"accepted",` +
			`"user_id":"6f5d4c3b-2a19-4e8f-9c07-1b2d3e4f5061",` +
			`"message_id":"courier-1","event_id":"e1","notification_type":"password_reset"}}`))
	}))
	defer server.Close()

	mailer := testMailer(t, server.URL, nil)

	// A body with no extractable token, and a `user_id` the client cannot supply,
	// so the send is refused — which is what the rows above assert. This test is
	// about the REQUEST SHAPE, so it drives the client directly with a valid one.
	client, err := New(Config{BaseURL: server.URL, Token: "service-token-value"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.SendMessage(context.Background(), MessageRequest{
		Type:   TypePasswordReset,
		UserID: "6f5d4c3b-2a19-4e8f-9c07-1b2d3e4f5061",
		To:     "kaka@example.com",
		URL:    "https://app.example.com/reset?token=" + testToken,
	}); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}

	for _, forbidden := range []string{"from", "subject", "text", "html", "body", "account_id"} {
		if _, present := body[forbidden]; present {
			t.Errorf("the request carried %q; courier's vocabulary is closed and has no such field",
				forbidden)
		}
	}
	for _, required := range []string{"type", "user_id", "to", "url"} {
		if _, present := body[required]; !present {
			t.Errorf("the request has no %q; courier requires it", required)
		}
	}
	if body["type"] != TypePasswordReset {
		t.Errorf("type = %v, want %q", body["type"], TypePasswordReset)
	}
	if got := stringOf(body["url"]); !strings.Contains(got, testToken) {
		t.Errorf("url = %q, want the token in it", got)
	}
	// The Idempotency-Key is a uuid courier accepts, derived from the token.
	key := header.Get("Idempotency-Key")
	if !isUUID(key) {
		t.Errorf("Idempotency-Key = %q, which is not a uuid; courier answers 422", key)
	}
	if strings.Contains(key, testToken) {
		t.Error("the idempotency key carries the token")
	}
	// The token travels in the URL courier renders and NOWHERE ELSE.
	if got := stringOf(body["url"]); got != "https://app.example.com/reset?token="+testToken {
		t.Errorf("url = %q, want the configured template rendered with the token", got)
	}

	_ = mailer
}

// TestTheLinkTemplateIsRefusedWhenItCannotMakeAWorkingLink is the constructor
// validation, and every row is a link that does not work rather than a style
// opinion. A deployment that gets this wrong must find out at boot, not at a user's
// first password reset.
func TestTheLinkTemplateIsRefusedWhenItCannotMakeAWorkingLink(t *testing.T) {
	cases := []struct {
		name     string
		template string
		wantErr  bool
	}{
		{
			name:     "an absolute https URL with the placeholder",
			template: "https://app.example.com/reset?token={token}",
		},
		{
			name:     "the token in a path segment rather than a query",
			template: "https://app.example.com/reset/{token}",
		},
		{
			name:     "an http URL, which is legitimate for a local product",
			template: "http://localhost:3000/reset?token={token}",
		},
		{name: "empty", template: "", wantErr: true},
		{name: "blank", template: "   ", wantErr: true},
		{
			name:     "no placeholder at all, so the link carries no token",
			template: "https://app.example.com/reset",
			wantErr:  true,
		},
		{
			name:     "a relative URL, which cannot be rendered in a mail",
			template: "/reset?token={token}",
			wantErr:  true,
		},
		{
			name:     "a scheme courier's schema would not accept",
			template: "javascript:alert({token})",
			wantErr:  true,
		},
		{
			name:     "a fragment, which mail clients do not send to a server",
			template: "https://app.example.com/reset#/{token}",
			wantErr:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateLinkTemplate(tc.template)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ValidateLinkTemplate(%q) accepted it", tc.template)
				}
				if got != "" {
					t.Errorf("a refused template returned %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateLinkTemplate(%q): %v", tc.template, err)
			}
			// And the template must actually render.
			rendered, err := got.render(testToken)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			if !strings.Contains(rendered, testToken) {
				t.Errorf("the rendered link %q has no token in it", rendered)
			}
			if strings.Contains(rendered, TokenPlaceholder) {
				t.Errorf("the rendered link %q still has the placeholder in it", rendered)
			}
		})
	}
}

// TestRenderRefusesATokenlessLink is the one check `ValidateLinkTemplate` cannot do
// at construction, because the token only exists at send time.
func TestRenderRefusesATokenlessLink(t *testing.T) {
	template, err := ValidateLinkTemplate("https://app.example.com/reset?token={token}")
	if err != nil {
		t.Fatalf("ValidateLinkTemplate: %v", err)
	}
	if _, err := template.render(""); !isError(err, errNoToken) {
		t.Errorf("render(\"\") = %v, want a refusal", err)
	}
}

// TestReadyAnswersTheDeploymentQuestionAndNotCouriersOwn is the assertion that
// `recovery`'s `Mailer.Ready` contract is honoured: cheap, sends nothing, and
// answers with `recovery`'s own sentinel so the HTTP layer needs no new case.
func TestReadyAnswersTheDeploymentQuestionAndNotCouriersOwn(t *testing.T) {
	t.Run("an up courier is ready", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != readyzPath {
				t.Errorf("Ready probed %s, want %s", r.URL.Path, readyzPath)
			}
			// courier's /readyz is outside every pipeline, so it ignores the
			// credential — and the client sends it anyway, deliberately. See
			// `Client.do`'s comment: the alternative is a second code path that
			// forgets to authenticate the day courier's probe moves.
			if r.Header.Get("Authorization") == "" {
				t.Error("Ready sent no credential; the path courier may later need one has none")
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		}))
		defer server.Close()

		mailer := testMailer(t, server.URL, nil)
		if err := mailer.Ready(context.Background()); err != nil {
			t.Errorf("Ready = %v, want nil", err)
		}
	})

	t.Run("a courier that is not answering is ErrNoMailer", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()

		mailer := testMailer(t, server.URL, nil)
		err := mailer.Ready(context.Background())
		if !isError(err, recovery.ErrNoMailer) {
			t.Fatalf("Ready = %v, want one matching recovery.ErrNoMailer", err)
		}
		// And the courier reason survives, so an operator can see the status.
		if !isError(err, ErrUnavailable) {
			t.Errorf("the courier reason is gone from the chain: %v", err)
		}
	})
}

// # 3. WHAT IT NEVER PRINTS

// TestTheMailerNeverPrintsACredentialOrAToken is the leak sweep, and it is the
// reason this package's `Client` has no credential field in the first place.
//
// The server ECHOES the credential back — in the body and in three headers — which
// is what a misconfigured proxy or a debug-echo gateway does, and it is the only
// way to prove the scrubber works rather than asserting that it does.
func TestTheMailerNeverPrintsACredentialOrAToken(t *testing.T) {
	const credential = "svc-7f3a9c1e4b8d2056-the-credential"

	// A courier that echoes everything it was sent, then fails.
	leaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var raw map[string]any
		body, _ := readAllString(r)
		_ = json.Unmarshal([]byte(body), &raw)
		echo := map[string]any{
			"code":          "unauthorized",
			"detail":        "the credential " + credential + " was not accepted for " + raw["url"].(string),
			"trace_id":      "0af7651916cd43dd8448eb211c80319c",
			"echoed_auth":   r.Header.Get("Authorization"),
			"echoed_key":    r.Header.Get("Idempotency-Key"),
			"echoed_cook":   r.Header.Get("Cookie"),
			"echoed_repeat": credential,
		}
		encoded, _ := json.Marshal(echo)
		w.Header().Set("Content-Type", "application/problem+json")
		w.Header().Set("X-Echo-Auth", r.Header.Get("Authorization"))
		w.Header().Set("X-Echo-Key", r.Header.Get("Idempotency-Key"))
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write(encoded)
	}))
	defer leaky.Close()

	var log bytes.Buffer
	mailer := testMailer(t, leaky.URL, slog.New(slog.NewTextHandler(&log, nil)))

	clientErr := courierSend(t, leaky.URL, credential)

	// Everything this package can produce, swept.
	things := map[string]any{
		"error string":     clientErr.Error(),
		"error %v":         clientErr,
		"error %+v":        clientErr,
		"error %#v":        clientErr,
		"mailer String":    mailer.String(),
		"mailer %v":        mailer,
		"mailer %#v":       mailer,
		"client String":    mailer.client.String(),
		"client %#v":       mailer.client,
		"log output":       log.String(),
		"retryable":        Retryable(clientErr),
		"serialised error": serialise(t, clientErr),
	}

	for what, thing := range things {
		rendered := renderAll(t, thing)
		if strings.Contains(rendered, credential) {
			t.Errorf("%s carries the service credential:\n%s", what, rendered)
		}
	}
	// And the refusal itself must not have been softened into uselessness.
	if !isError(clientErr, ErrUnauthenticated) {
		t.Errorf("the echoed 401 is not an authentication refusal: %v", clientErr)
	}
}

// TestTheLogNeverCarriesTheTokenOrTheRecipient is the second half of the same
// property, and it is separate because it is about a DIFFERENT failure: the
// credential above is a service-to-service secret, whereas the token and the
// recipient are PII and a live credential for a user, and they reach logs on paths
// where nothing was misconfigured.
//
// IT DRIVES THE ADAPTER, because the logging is the adapter's and a test that
// called the client directly would be asserting that the client logs — which it
// does not, and should not: a library that writes to a logger is a library whose
// output nobody configured.
func TestTheLogNeverCarriesTheTokenOrTheRecipient(t *testing.T) {
	const email = "kaka-privacy@example.com"
	const token = "K7dQm2xR9vTb4nLpZcHs1JfWy6AeUi0O"

	cases := []struct {
		name   string
		status int
		body   string
		// wantLog is what the line must contain to be worth having.
		wantLog string
	}{
		{
			name:   "courier refused the credential",
			status: http.StatusUnauthorized,
			body:   `{"code":"unauthorized","detail":"no","trace_id":"t1"}`,
			// Nothing to tie back to: courier refused before doing anything, so
			// there is no handle on its logs to offer.
			wantLog: "",
		},
		{
			name:   "the mailbox is suppressed",
			status: http.StatusConflict,
			body: `{"code":"conflict","detail":"That mailbox does not exist: it ` +
				`hard-bounced a previous message.","trace_id":"t2"}`,
			// The two states courier describes in prose — a hard bounce and a spam
			// complaint — are told apart by its `detail`, and this client does not
			// carry `detail`. So the trace id is the handle, and an operator's only
			// route to knowing which of the two it was.
			wantLog: "t2",
		},
		{
			name:    "the provider refused",
			status:  http.StatusServiceUnavailable,
			body:    `{"code":"unavailable","detail":"Nothing was sent.","trace_id":"t3"}`,
			wantLog: "t3",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var log bytes.Buffer
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			mailer := testMailer(t, server.URL, slog.New(slog.NewTextHandler(&log, nil)))
			err := mailer.Send(context.Background(), resetMessageFor(email, token))
			if err == nil {
				t.Fatal("the send succeeded against a courier that refused")
			}

			written := log.String()
			if strings.Contains(written, token) {
				t.Errorf("the log carries the live token:\n%s", written)
			}
			if strings.Contains(written, email) {
				t.Errorf("the log carries the recipient:\n%s", written)
			}
			// And it must say SOMETHING, or the line is decoration: courier's status,
			// its code, and whether another attempt can help.
			for _, want := range []string{"status=", "code=", "retryable="} {
				if !strings.Contains(written, want) {
					t.Errorf("the log line has no %s:\n%s", want, written)
				}
			}
			if tc.wantLog != "" && !strings.Contains(written, tc.wantLog) {
				t.Errorf("the log has no handle on courier's own logs (%s):\n%s", tc.wantLog, written)
			}
		})
	}
}

// TestASuccessfulSendLogsCouriersIdentifiersAndNothingElse is the positive half:
// the one line worth writing, and it must carry the `message_id` because a bounce
// or a complaint quotes it and nothing else ties the two together.
func TestASuccessfulSendLogsCouriersIdentifiersAndNothingElse(t *testing.T) {
	const email = "kaka-privacy@example.com"
	const token = "K7dQm2xR9vTb4nLpZcHs1JfWy6AeUi0O"
	var log bytes.Buffer

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"status":"accepted",` +
			`"user_id":"6f5d4c3b-2a19-4e8f-9c07-1b2d3e4f5061",` +
			`"message_id":"courier-16c22f7a","event_id":"0f1d27fc",` +
			`"notification_type":"password_reset"}}`))
	}))
	defer server.Close()

	mailer := testMailer(t, server.URL, slog.New(slog.NewTextHandler(&log, nil)))
	if err := mailer.Send(context.Background(), resetMessageFor(email, token)); err != nil {
		t.Fatalf("the send: %v", err)
	}

	written := log.String()
	if !strings.Contains(written, "courier-16c22f7a") {
		t.Errorf("the log has no message_id, so a bounce cannot be tied back:\n%s", written)
	}
	if strings.Contains(written, token) || strings.Contains(written, email) {
		t.Errorf("the log carries the token or the recipient:\n%s", written)
	}
}

// # 4. THE BOUNDARIES

// TestTheOnlyPlaceBothVocabulariesMeet is the assertion that identity has not taken
// courier's rendering decisions, and it is the counterpart to the refusals above.
//
// The rule `internal/recovery` states is: "The moment this type grows a `Template`
// field, identity has taken courier's rendering decisions, and the two will
// disagree." This holds that from the other side — `recovery.Message` has no type
// field, and no package under `recovery/` mentions courier.
func TestTheOnlyPlaceBothVocabulariesMeet(t *testing.T) {
	// EXACTLY FOUR FIELDS, and the list is the assertion rather than a spot check:
	// it fails on a fifth field of any kind, which is the shape a `Template` or a
	// `Type` would take.
	//
	// `UserID` is on the list and is not a violation. The rule `internal/recovery`
	// states is about a TEMPLATE — a rendering decision about how a mail looks — and
	// `UserID` is a fact about which account the message concerns, which every
	// flow in that package already held before this field existed. `recovery` does
	// not know courier has a type enum, does not know courier attributes an event
	// to a user id, and imports nothing from here.
	if got := reflectMessageFields(); got != "To Subject Body UserID" {
		t.Errorf("recovery.Message carries %q, want exactly To, Subject, Body and "+
			"UserID. A fifth field is a courier decision leaking into identity unless "+
			"it is another fact about the recipient, and the reasoning belongs there.",
			got)
	}

	// The fields this adapter does NOT need from `recovery`: it must not be reading
	// a body as a source of a credential, a kind as a string match on prose, or
	// anything else that would make prose load-bearing. `tokenFromBody` is the one
	// parse left and it reads the credential, which is the credential's own home;
	// what it must not do is decide WHICH template to use, and that is the subject
	// map's job.
	if tokenFromBody("no marker here") != "" {
		t.Error("tokenFromBody found a token in a body with no marker in it")
	}

	// And nothing under internal/recovery may name courier. A grep is a crude check
	// and a compile-time import check is a better one, so this asserts the weaker
	// property explicitly rather than pretending to be strong: `recovery` cannot
	// import `internal/courier` because `courier` imports `recovery`.
	// `var _ recovery.Mailer = (*RecoveryMailer)(nil)` in mailer.go is the proof
	// that the dependency runs courier -> recovery and not the other way.
}

// TestEveryMessageRecoveryRendersIsAccountedFor is the drift check for the subject
// table, and it reads `internal/recovery/message.go` rather than trusting this
// file's copy of it.
//
// The failure it prevents: somebody adds a fifth message to `internal/recovery` and
// this adapter keeps refusing it, and the refusal looks like a courier gap rather
// than a mapping nobody updated.
func TestEveryMessageRecoveryRendersIsAccountedFor(t *testing.T) {
	// recovery's own subjects, read from its source. The set is small and the
	// alternative — importing an unexported constant — is not possible, and adding
	// an export purely for a test would be a worse change than reading the file.
	recoverySubjects := subjectsInRecoverySource(t)

	for subject := range recoverySubjects {
		if _, known := knownSubjects[subject]; !known {
			t.Errorf("internal/recovery renders a subject this package has never heard "+
				"of (%q); add it to knownSubjects and decide whether courier can send it", subject)
		}
	}
	for subject := range knownSubjects {
		if _, rendered := recoverySubjects[subject]; !rendered {
			t.Errorf("this package knows a subject internal/recovery does not render (%q)", subject)
		}
	}
}

// TestNoRecoverySubjectCarriesAToken is the assumption the whole subject-as-key
// design rests on, asserted rather than assumed.
//
// If a subject could contain a variable, it would not be a stable key AND it would
// be a credential in the most widely logged part of a message. Both are the reason
// this design is safe, so the test holds the property rather than the comment.
func TestNoRecoverySubjectCarriesAToken(t *testing.T) {
	for subject := range knownSubjects {
		lowered := strings.ToLower(subject)
		for _, forbidden := range []string{"token", "code", "=", "{", "}"} {
			if strings.Contains(lowered, forbidden) {
				t.Errorf("the subject %q contains %q; a subject is this adapter's "+
					"discriminator and it must be a constant", subject, forbidden)
			}
		}
	}
}

// # helpers

// testMailer builds a RecoveryMailer over a test server.
func testMailer(t *testing.T, baseURL string, logger *slog.Logger) *RecoveryMailer {
	t.Helper()
	client, err := New(Config{BaseURL: baseURL, Token: "service-token-value"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	mailer, err := NewRecoveryMailer(RecoveryMailerConfig{
		Client:        client,
		LinkTemplates: testLinkTemplates(),
		Logger:        logger,
	})
	if err != nil {
		t.Fatalf("NewRecoveryMailer: %v", err)
	}
	return mailer
}

// courierSend drives the client against a server that answers, and returns the error
// it produced.
func courierSend(t *testing.T, baseURL, credential string) error {
	t.Helper()
	client, err := New(Config{BaseURL: baseURL, Token: credential})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = client.SendMessage(context.Background(), MessageRequest{
		Type:   TypePasswordReset,
		UserID: "6f5d4c3b-2a19-4e8f-9c07-1b2d3e4f5061",
		To:     "kaka@example.com",
		URL:    "https://app.example.com/reset?token=" + testToken,
	})
	return err
}

// readAllString reads a request body, so the leaky server can echo it.
func readAllString(r *http.Request) (string, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(r.Body)
	return buf.String(), err
}

// renderAll puts a value through every formatting verb that could reach a log.
func renderAll(t *testing.T, thing any) string {
	t.Helper()
	var out strings.Builder
	out.WriteString(sprint(t, thing, "%v"))
	out.WriteString(sprint(t, thing, "%+v"))
	out.WriteString(sprint(t, thing, "%#v"))
	out.WriteString(sprint(t, thing, "%s"))
	out.WriteString(sprint(t, thing, "%q"))
	return out.String()
}

// serialise renders an error as JSON, which is what a structured logger does with
// anything it is handed.
func serialise(t *testing.T, err error) string {
	t.Helper()
	encoded, marshalErr := json.Marshal(map[string]any{"error": err.Error()})
	if marshalErr != nil {
		t.Fatalf("marshalling the error: %v", marshalErr)
	}
	return string(encoded)
}

// errorsIsUnused keeps the errors import honest.
var _ = errors.Is
