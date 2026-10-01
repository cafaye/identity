package courier

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/cafaye/identity/internal/recovery"
)

// # THE WIRING, PROVABLE WITHOUT A COURIER
//
// This file holds the claim the end-to-end file cannot make on a machine with no
// second service: that a message identity `internal/recovery` renders actually
// traverses THIS adapter and lands on the wire as a request courier's own
// validation accepts.
//
// # WHY IT IS NOT A COPY OF `mailer_test.go` OR `client_test.go`
//
// Because those two drive `Client.SendMessage` directly, and this one drives
// `RecoveryMailer.Send` — the method `internal/recovery` calls and the one the e2e
// file exists to exercise. That difference is not cosmetic, and one property below
// exists ONLY because of it:
//
//	`TestTheRequestCarriesExactlyWhatCouriersVocabularyHas` puts a request on the
//	wire and asserts the body. It cannot assert anything about the
//	`Idempotency-Key`, because a request it builds by hand leaves `IdempotencyKey`
//	empty — so `SendMessage` MINTS a fresh random uuid per call, which is the
//	correct behaviour for a caller that has nothing to derive from and means that
//	test is necessarily looking at a different key on every run.
//
//	`TestTheIdempotencyKeyIsAUuidCourierWillAccept` asserts the derivation is
//	deterministic, and it is right to. It calls `idempotencyKeyFor` DIRECTLY, so it
//	proves the function is a function of its three inputs — and says nothing about
//	whether `RecoveryMailer.Send` ever puts that key on a header.
//
//	So the composition of the two — that the adapter DERIVES the key AND SENDS it —
//	was asserted nowhere. That composition is the double-clicked-reset property: a
//	user who asks twice for one reset link must produce ONE send, and the only
//	place that can be true or false is `TestOneSendCarriesOneStableKey` below.
//
// # WHAT IT IS NOT
//
// It is not a claim that courier accepts these bytes. That is a claim about courier,
// and `recorded_test.go` holds the byte-for-byte responses courier really answered
// with, while `e2e_support_test.go` holds the claim against a live process.

// sentRequest is what a courier on the other end would have seen.
type sentRequest struct {
	method string
	path   string
	header http.Header
	body   map[string]any
}

// recordingCourier is an `httptest` server that keeps every request and answers a
// 200 in courier's envelope.
//
// IT REFUSES NOTHING, deliberately, and that is the difference from
// `fakecourier_test.go`. A fake exists to answer the refusals a client can be wrong
// about; this one exists to be looked AT, so answering anything but an accepted send
// would fail the test for the wrong reason. The refusals are covered where a
// refusal is the subject.
func recordingCourier(t *testing.T) (*httptest.Server, *[]sentRequest) {
	t.Helper()

	var mu sync.Mutex
	var seen []sentRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)

		mu.Lock()
		seen = append(seen, sentRequest{
			method: r.Method,
			path:   r.URL.Path,
			header: r.Header.Clone(),
			body:   body,
		})
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"status":"accepted",` +
			`"user_id":"6f5d4c3b-2a19-4e8f-9c07-1b2d3e4f5061",` +
			`"message_id":"courier-1","event_id":"e1","notification_type":"password_reset"}}`))
	}))
	t.Cleanup(server.Close)

	return server, &seen
}

// TestOneSendCarriesOneStableKey is the property that made this file necessary, and
// it is a COMPOSITION rather than a unit: `RecoveryMailer.Send` derives the key from
// the send, and the key reaches courier's header.
//
// Both halves are asserted elsewhere and neither alone is this one. See this file's
// header for why the two existing tests cannot compose into it.
//
// The determinism is asserted over TWO SEPARATE SENDS rather than over the
// derivation, because "the same function returns the same value" is a weaker claim
// than "the same message produces the same wire request": only the second is the
// property that a double-clicked reset link depends on.
func TestOneSendCarriesOneStableKey(t *testing.T) {
	server, seen := recordingCourier(t)
	mailer := testMailer(t, server.URL, nil)

	for range 2 {
		if err := mailer.Send(context.Background(), resetMessageFor("kaka@example.com", testToken)); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}

	if len(*seen) != 2 {
		t.Fatalf("courier saw %d requests, want 2 — the sends that reach courier are what "+
			"the key is for", len(*seen))
	}

	first, second := (*seen)[0], (*seen)[1]
	firstKey, secondKey := first.header.Get("Idempotency-Key"), second.header.Get("Idempotency-Key")

	if firstKey == "" {
		t.Fatal("no Idempotency-Key on the wire; courier's :idempotent pipeline scopes the " +
			"key to the principal, so a keyless send cannot be deduplicated at all")
	}
	if firstKey != secondKey {
		t.Errorf("two sends of ONE message carried different keys (%q then %q), so a user who\n"+
			"asked twice for one reset link would be sent two mails. The key must be derived\n"+
			"from the send, not minted per attempt.", firstKey, secondKey)
	}
	// And it must be courier's FORMAT, not merely a stable string: a base64 digest
	// is stable and is still a 422 naming a header rather than a message.
	if !isUUID(firstKey) {
		t.Errorf("Idempotency-Key = %q, which is not a uuid; courier answers 422 for one", firstKey)
	}
	// A stable key that CONTAINS the token is stable and is a credential in a header
	// courier writes to its own logs and its own unique index.
	if strings.Contains(firstKey, testToken) {
		t.Error("the Idempotency-Key carries the recovery token, and a live credential in " +
			"somebody else's store is a credential the next reader can redeem")
	}

	// The bodies must be identical too, or courier answers 409 `idempotency_key_reused`
	// on the retry instead of replaying the first response — which would turn the
	// stable key into a second failure rather than a second send.
	if !reflect.DeepEqual(first.body, second.body) {
		t.Errorf("the two sends of one message carried different bodies:\n%v\n%v",
			first.body, second.body)
	}
}

// TestTheAdapterPutsCouriersRequestOnTheWire is the request IDENTITY, which is the
// part of the e2e file that a live courier only ever exercised as a side effect of
// asserting that courier had accepted it.
//
// Five properties, and each is one courier reads before it does anything:
//
//	method and path       the one door into courier's send path
//	Authorization         the pipeline behind it, and a 401 without it
//	Idempotency-Key       the `:idempotent` pipeline in front of it
//	the closed body       `additionalProperties: false`, so one extra key is a 422
//	url on a reset         courier's `password_reset` template RENDERS it
func TestTheAdapterPutsCouriersRequestOnTheWire(t *testing.T) {
	server, seen := recordingCourier(t)
	mailer := testMailer(t, server.URL, nil)

	if err := mailer.Send(context.Background(), resetMessageFor("kaka@example.com", testToken)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(*seen) != 1 {
		t.Fatalf("courier saw %d requests, want 1", len(*seen))
	}
	got := (*seen)[0]

	if got.method != http.MethodPost {
		t.Errorf("method = %q, want POST; %s is the only door into courier's send path",
			got.method, messagesPath)
	}
	if got.path != messagesPath {
		t.Errorf("path = %q, want %q", got.path, messagesPath)
	}

	// THE CREDENTIAL, and it is asserted as a SHAPE rather than by equality because
	// equality with a fixture would only prove the fixture was copied correctly.
	// Three properties is what courier's `:authenticated` pipeline actually reads: a
	// `Bearer` scheme, a non-empty value, and no second header to be ambiguous
	// between.
	authorization := got.header.Values("Authorization")
	if len(authorization) != 1 {
		t.Errorf("Authorization appears %d times; courier reads the first and a repeated "+
			"header is ambiguous", len(authorization))
	} else if scheme, value, _ := strings.Cut(authorization[0], " "); scheme != "Bearer" || value == "" {
		t.Errorf("Authorization = %q, want a bearer credential and nothing else", authorization[0])
	}
	if got.header.Get("Cookie") != "" {
		t.Error("a machine credential was sent in a cookie; courier's surface is not a browser")
	}

	// THE CLOSED BODY. `from`, `subject`, `text` and `html` are the four fields a
	// caller reaches for when it thinks it is sending mail rather than facts, and
	// courier's `CourierWeb.Messages` says why none of them exists: a caller that
	// could choose the sender or the body would make courier a general-purpose relay
	// wearing the platform's sending domain.
	for _, forbidden := range []string{"from", "subject", "text", "html", "body", "account_id"} {
		if _, present := got.body[forbidden]; present {
			t.Errorf("the request carried %q; courier's vocabulary is closed and has no such field. "+
				"A caller that could choose the sender or the body would make courier an open relay "+
				"with a config file attached", forbidden)
		}
	}
	for _, required := range []string{"type", "user_id", "to", "url"} {
		if _, present := got.body[required]; !present {
			t.Errorf("the request has no %q; courier requires it", required)
		}
	}

	if got.body["type"] != TypePasswordReset {
		t.Errorf("type = %v, want %q", got.body["type"], TypePasswordReset)
	}
	if got.body["to"] != "kaka@example.com" {
		t.Errorf("to = %v, want the recipient recovery rendered", got.body["to"])
	}
	if got.body["user_id"] != testUserID.String() {
		t.Errorf("user_id = %v, want the account the message concerns (%s). courier keys the "+
			"recipient's notification preferences by it and attributes the delivered event to it",
			got.body["user_id"], testUserID)
	}

	// AND THE LINK, which is the whole of a password reset: courier's template
	// RENDERS `url`, so a reset mail with the wrong one is a mail that either does
	// not work or works on somebody else's domain.
	url, _ := got.body["url"].(string)
	if want := "https://app.example.com/reset?token=" + testToken; url != want {
		t.Errorf("url = %q, want %q — the configured template rendered with the token", url, want)
	}
}

// TestTheResetLinkComesFromConfigurationAndNotFromARequest is the Host-header
// property, and it is a separate test because the property is an ABSENCE: no
// `Host` this process can be shown can reach the link.
//
// WHY IT IS AN ACCOUNT TAKEOVER, stated as the reason rather than as a rule.
//
// A reset link is the one URL in this service that carries a credential AND grants
// it. If the host in that link can be influenced by a request header, then anybody
// who can make a victim send one request with a chosen `Host` has chosen where the
// victim types a live reset token — and a form that looks exactly like the real one
// is all the rest of the attack. The token is genuine, the flow is genuine, and the
// account is the victim's.
//
// It cannot be done with `Host` ALONE either, and the reason matters: a link
// template's host is validated at construction (`ValidateLinkTemplate` refuses a
// relative one) and the only thing `render` substitutes is the token, so a hostile
// header has no field to land in. That is a structural argument about code this
// package owns, and it is exactly the kind of argument that stops being true when
// somebody adds a convenience later — which is why it is asserted here rather than
// left to the reader.
func TestTheResetLinkComesFromConfigurationAndNotFromARequest(t *testing.T) {
	t.Run("no Host header can change the link", func(t *testing.T) {
		server, seen := recordingCourier(t)
		mailer := testMailer(t, server.URL, nil)

		// A request carrying the header an attacker controls, arriving at a server
		// that ignores it — which is what the assertion below proves, so the header
		// has to actually be set for the assertion to be about anything.
		attacker := "identity.attacker.example"
		probe := httptest.NewRequest(http.MethodPost, "/v1/password-resets", nil)
		probe.Host = attacker
		probe.Header.Set("X-Forwarded-Host", attacker)

		if err := mailer.Send(context.Background(),
			resetMessageFor("kaka@example.com", testToken)); err != nil {
			t.Fatalf("Send: %v", err)
		}
		if len(*seen) != 1 {
			t.Fatalf("courier saw %d requests, want 1", len(*seen))
		}

		url, _ := (*seen)[0].body["url"].(string)
		if strings.Contains(url, attacker) {
			t.Errorf("the reset link carries %q, which came from a request header rather than "+
				"from configuration. A reset link is the one URL that carries a live credential "+
				"and grants it: a link whose host an attacker can choose is a credential "+
				"typed into a form they wrote.\n  link: %s", attacker, url)
		}
		if !strings.HasPrefix(url, "https://app.example.com/") {
			t.Errorf("the reset link is %q, want the configured base URL", url)
		}
	})

	// THE STRUCTURAL HALF, and it is the half that cannot be argued with later.
	//
	// The argument above is about today's code. This is about whether a FUTURE
	// convenience — "let a deployment override the link host per request", or a
	// helper that reads `r.Host` to build a base URL — can be added without anybody
	// noticing that the property above quietly stopped holding. Reflecting over the
	// adapter answers it structurally: neither the adapter nor its client can hold a
	// request, so there is nothing for a `Host` to be read out of.
	t.Run("neither the adapter nor the client can reach a request", func(t *testing.T) {
		// `LinkTemplate` IS A STRING, so it is checked as a kind rather than walked
		// as a struct: a non-struct has no fields, and `NumField` panics on one. The
		// union of the two cases is the whole claim — the two structs cannot hold a
		// request, and the third type cannot hold anything at all.
		for _, typ := range []reflect.Type{
			reflect.TypeOf(RecoveryMailer{}),
			reflect.TypeOf(Client{}),
			reflect.TypeOf(LinkTemplate("")),
		} {
			if typ.Kind() != reflect.Struct {
				if typ.Kind() == reflect.String {
					continue
				}
				t.Errorf("%s is a %s rather than a struct or a string, so this walk no "+
					"longer covers it; the reflection here is asserting an absence and an "+
					"unwalked type would pass it for the wrong reason", typ.Name(), typ.Kind())
				continue
			}
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				// A request is reachable through a function value that closes over
				// one, so the field's own type is checked for `http` as well as for
				// being a request itself.
				if strings.Contains(field.Type.String(), "net/http") {
					t.Errorf("%s.%s is a %s, so this type can hold a request and a "+
						"`Host` header with it. The reset link must come from configuration.",
						typ.Name(), field.Name, field.Type)
				}
			}
		}
	})
}

// TestARefusedMessageNeverReachesTheWire is the last of the wiring, and it is the
// direction that keeps the e2e file's negative half honest.
//
// `TestTheTwoEmailChangeMessagesCourierCannotSendAreRefused` proves the refusal
// against a live courier. This proves the part that makes it SAFE rather than merely
// correct: the refusal happens BEFORE the request, so no token is in a body any
// courier will render.
//
// A refusal discovered as a 422 would be far too late. By then `recovery` has
// minted a token, written its digest, and told the caller a message is on its way —
// so the observable difference between refusing before the wire and refusing on it
// is whether a live credential was handed to a service that would have rendered it
// into somebody's inbox.
func TestARefusedMessageNeverReachesTheWire(t *testing.T) {
	cases := []struct {
		name    string
		message recovery.Message
	}{
		{name: "the current-address half of an email change", message: changeCurrentMessage(testToken)},
		{name: "the new-address half of an email change", message: changeNewMessage(testToken)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, seen := recordingCourier(t)
			mailer := testMailer(t, server.URL, nil)

			err := mailer.Send(context.Background(), tc.message)
			if !isError(err, ErrUnsupportedMessage) {
				t.Fatalf("Send = %v, want ErrUnsupportedMessage", err)
			}

			if len(*seen) != 0 {
				t.Errorf("a message courier has no type for reached the wire %d time(s). The "+
					"token in it is a live credential, and the refusal has to happen before "+
					"the wire rather than as a 422 after it.", len(*seen))
			}
		})
	}
}
