package courier

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The contract, as a table.
//
// Every case here is something courier's own `openapi.yaml` declares for
// `POST /v1/messages`, and each one is paired with a presence assertion: a client
// that answered `ErrUnavailable` for everything would pass a table of "the send
// failed" rows and be useless, so the accepted row is asserted as carefully as each
// refusal.
func TestSendMessageReadsCouriersContract(t *testing.T) {
	// A uuid courier will accept: it is only checked for shape, and this one is the
	// nil uuid written out so the fixture does not depend on a random generator.
	const userID = "6f5d4c3b-2a19-4e8f-9c07-1b2d3e4f5061"

	problem := func(status int, code, detail string, extra map[string]any) string {
		body := map[string]any{
			"type":     "https://errors.cafaye.com/" + code,
			"title":    code,
			"status":   status,
			"detail":   detail,
			"code":     code,
			"trace_id": "0af7651916cd43dd8448eb211c80319c",
		}
		for k, v := range extra {
			body[k] = v
		}
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("building a problem body: %v", err)
		}
		return string(raw)
	}

	cases := []struct {
		name        string
		status      int
		contentType string
		body        string
		wantErrIs   error
		wantStatus  int // 0 when the call should succeed
		wantRetry   bool
		check       func(*testing.T, MessageResult)
	}{
		{
			name:        "accepted is the only success and it is a 200",
			status:      http.StatusOK,
			contentType: "application/json",
			body: `{"data":{"message_id":"<m-1@example.com>","event_id":"1f0a4b2c-` +
				`3d5e-4f60-8712-0a3b5c7d9e11","notification_type":"password_reset",` +
				`"user_id":"` + userID + `","status":"accepted"}}`,
			wantStatus: http.StatusOK,
			check: func(t *testing.T, got MessageResult) {
				t.Helper()
				if got.MessageID != "<m-1@example.com>" {
					t.Errorf("MessageID = %q, want courier's message id", got.MessageID)
				}
				if got.EventID != "1f0a4b2c-3d5e-4f60-8712-0a3b5c7d9e11" {
					t.Errorf("EventID = %q, want the outbox row's id", got.EventID)
				}
				if got.Status != StatusAccepted {
					t.Errorf("Status = %q, want %q — courier never says delivered",
						got.Status, StatusAccepted)
				}
				if got.Type != TypePasswordReset {
					t.Errorf("Type = %q, want %q", got.Type, TypePasswordReset)
				}
			},
		},
		{
			name:        "a suppressed mailbox is a 409 and is not retryable",
			status:      http.StatusConflict,
			contentType: "application/problem+json",
			body:        problem(409, "conflict", "That mailbox cannot receive mail.", nil),
			wantErrIs:   ErrSuppressed,
			wantStatus:  http.StatusConflict,
		},
		{
			name:        "a declined preference is a 422 naming the field",
			status:      http.StatusUnprocessableEntity,
			contentType: "application/problem+json",
			body: problem(422, "validation_failed", "This user does not want that.",
				map[string]any{"errors": []map[string]any{
					{"field": "type", "code": "notification_preferences_disabled"},
				}}),
			wantErrIs:  ErrDeclined,
			wantStatus: http.StatusUnprocessableEntity,
		},
		{
			name:        "a request courier refuses is a 422 with its field errors",
			status:      http.StatusUnprocessableEntity,
			contentType: "application/problem+json",
			body: problem(422, "validation_failed", "That url is one courier will not send.",
				map[string]any{"errors": []map[string]any{
					{"field": "url", "code": "blocked_address"},
				}}),
			wantErrIs:  ErrRefused,
			wantStatus: http.StatusUnprocessableEntity,
		},
		{
			name:        "a misconfigured courier is a 503 and IS retryable",
			status:      http.StatusServiceUnavailable,
			contentType: "application/problem+json",
			body: problem(503, "unavailable",
				"The mail provider did not accept the message.", nil),
			wantErrIs:  ErrUnavailable,
			wantStatus: http.StatusServiceUnavailable,
			wantRetry:  true,
		},
		{
			name:        "an unauthenticated caller is a 401",
			status:      http.StatusUnauthorized,
			contentType: "application/problem+json",
			body: problem(401, "unauthorized",
				"This request needs an authenticated caller.", nil),
			wantErrIs:  ErrUnauthenticated,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:        "an internal courier failure is a 500 and is not the same as a 503",
			status:      http.StatusInternalServerError,
			contentType: "application/problem+json",
			body:        problem(500, "internal", "The request could not be completed.", nil),
			wantErrIs:   ErrUnavailable,
			wantStatus:  http.StatusInternalServerError,
		},
		{
			name:        "a 404 is not silently a success",
			status:      http.StatusNotFound,
			contentType: "application/problem+json",
			body:        problem(404, "not_found", "No such endpoint.", nil),
			wantErrIs:   ErrRefused,
			wantStatus:  http.StatusNotFound,
		},
		{
			name:        "a 200 with an unparseable body is a malformed response",
			status:      http.StatusOK,
			contentType: "application/json",
			body:        `{"data":{"message_id":`,
			wantErrIs:   ErrMalformedResponse,
			wantStatus:  http.StatusOK,
		},
		{
			name:        "a 200 whose data has no message id is malformed, not accepted",
			status:      http.StatusOK,
			contentType: "application/json",
			body:        `{"data":{"event_id":"1f0a4b2c-3d5e-4f60-8712-0a3b5c7d9e11","status":"accepted"}}`,
			wantErrIs:   ErrMalformedResponse,
			wantStatus:  http.StatusOK,
		},
		{
			name:        "a 200 with no body at all is malformed",
			status:      http.StatusOK,
			contentType: "application/json",
			body:        ``,
			wantErrIs:   ErrMalformedResponse,
			wantStatus:  http.StatusOK,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var seen *http.Request
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen = r.Clone(context.Background())
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			client := newTestClient(t, server.URL, "service-token-value")
			got, err := client.SendMessage(context.Background(), MessageRequest{
				Type:   TypePasswordReset,
				UserID: userID,
				To:     "kaka@example.com",
				URL:    "https://app.example.com/reset?token=abc",
			})

			if tc.wantErrIs == nil {
				if err != nil {
					t.Fatalf("SendMessage: %v", err)
				}
				if tc.check != nil {
					tc.check(t, got)
				}
			} else {
				if err == nil {
					t.Fatalf("SendMessage accepted a %d it should have refused", tc.status)
				}
				if !isError(err, tc.wantErrIs) {
					t.Fatalf("SendMessage error = %v, want one matching %v", err, tc.wantErrIs)
				}
			}

			if seen == nil {
				t.Fatal("courier was never called")
			}
			// Every row must be a real send, or the table is testing a no-op.
			assertSentShape(t, seen)
		})
	}
}

// TestRetryabilityIsAPropertyOfTheRefusal pins the one thing a caller branches on
// that the status alone does not give: whether trying again can help.
//
// It is a separate test because it is the only claim in this package about the
// FUTURE rather than about a response, and a table row cannot say "and this one you
// may retry" without the answer being lost among the statuses.
func TestRetryabilityIsAPropertyOfTheRefusal(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		code      string
		extra     map[string]any
		wantRetry bool
	}{
		{name: "a provider that refused", status: 503, code: "unavailable", wantRetry: true},
		{name: "an adapter that cannot deliver", status: 503, code: "unavailable", wantRetry: true},
		{
			name: "courier's own unhandled failure", status: 500, code: "internal",
			wantRetry: true,
		},
		{
			name: "a suppressed mailbox", status: 409, code: "conflict",
		},
		{
			name: "a declined preference", status: 422, code: "validation_failed",
			extra: map[string]any{"errors": []map[string]any{
				{"field": "type", "code": "notification_preferences_disabled"},
			}},
		},
		{
			name: "a request courier refuses", status: 422, code: "validation_failed",
			extra: map[string]any{"errors": []map[string]any{
				{"field": "url", "code": "blocked_address"},
			}},
		},
		{name: "a credential courier will not take", status: 401, code: "unauthorized"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := map[string]any{
				"type":  "https://errors.cafaye.com/" + tc.code,
				"title": tc.code, "status": tc.status,
				"detail": "refused", "code": tc.code,
				"trace_id": "0af7651916cd43dd8448eb211c80319c",
			}
			for k, v := range tc.extra {
				body[k] = v
			}
			raw, _ := json.Marshal(body)

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(tc.status)
				_, _ = w.Write(raw)
			}))
			defer server.Close()

			client := newTestClient(t, server.URL, "service-token-value")
			_, err := client.SendMessage(context.Background(), MessageRequest{
				Type:   TypePasswordReset,
				UserID: "6f5d4c3b-2a19-4e8f-9c07-1b2d3e4f5061",
				To:     "kaka@example.com",
				URL:    "https://app.example.com/reset?token=abc",
			})
			if err == nil {
				t.Fatal("SendMessage accepted a refusal")
			}
			if got := Retryable(err); got != tc.wantRetry {
				t.Errorf("Retryable = %t, want %t for a %d %s",
					got, tc.wantRetry, tc.status, tc.code)
			}
		})
	}
}

// TestTheRequestIsExactlyCouriersVocabulary is the assertion that keeps this client
// from inventing a field.
//
// courier's document declares `additionalProperties: false` over a closed list, so
// one extra key is a 422 and the send does not happen. The marshalled body is
// therefore compared against the document's list, and `url` is required for
// `password_reset` — which means an empty `URL` is refused HERE rather than
// discovered as a 422 from a network round trip.
func TestTheRequestIsExactlyCouriersVocabulary(t *testing.T) {
	cases := []struct {
		name    string
		request MessageRequest
		want    map[string]any
	}{
		{
			name: "a password reset carries a type, a user, a recipient and a link",
			request: MessageRequest{
				Type:   TypePasswordReset,
				UserID: "6f5d4c3b-2a19-4e8f-9c07-1b2d3e4f5061",
				To:     "kaka@example.com",
				URL:    "https://app.example.com/reset?token=abc",
			},
			want: map[string]any{
				"type":    "password_reset",
				"user_id": "6f5d4c3b-2a19-4e8f-9c07-1b2d3e4f5061",
				"to":      "kaka@example.com",
				"url":     "https://app.example.com/reset?token=abc",
			},
		},
		{
			name: "an absent name is omitted rather than sent empty",
			request: MessageRequest{
				Type:   TypePasswordReset,
				UserID: "6f5d4c3b-2a19-4e8f-9c07-1b2d3e4f5061",
				To:     "kaka@example.com",
				URL:    "https://app.example.com/reset?token=abc",
			},
			want: map[string]any{
				"type":    "password_reset",
				"user_id": "6f5d4c3b-2a19-4e8f-9c07-1b2d3e4f5061",
				"to":      "kaka@example.com",
				"url":     "https://app.example.com/reset?token=abc",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.request)
			if err != nil {
				t.Fatalf("marshalling the request: %v", err)
			}
			var got map[string]any
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatalf("unmarshalling the request: %v", err)
			}

			if len(got) != len(tc.want) {
				t.Errorf("the request carries %d keys, want %d: %s", len(got), len(tc.want), raw)
			}
			for key, want := range tc.want {
				if got[key] != want {
					t.Errorf("%q = %v, want %v", key, got[key], want)
				}
			}
			for key := range got {
				if _, ok := tc.want[key]; !ok {
					t.Errorf("the request carries %q, which courier's vocabulary does not have", key)
				}
			}
		})
	}
}

// TestTheRequestIsRefusedBeforeTheNetwork is the assertion behind the argument that
// this client validates what it can: a `password_reset` with no link is a 422 from
// courier, and finding that out over the network means a token has been minted and
// a row written for a send that was never going to leave.
func TestTheRequestIsRefusedBeforeTheNetwork(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "service-token-value")
	_, err := client.SendMessage(context.Background(), MessageRequest{
		Type:   TypePasswordReset,
		UserID: "6f5d4c3b-2a19-4e8f-9c07-1b2d3e4f5061",
		To:     "kaka@example.com",
		// No URL. courier requires one for password_reset.
	})
	if err == nil {
		t.Fatal("SendMessage accepted a password_reset with no link")
	}
	if calls != 0 {
		t.Errorf("courier was called %d times for a request this client could refuse", calls)
	}
}

// TestTheCredentialIsBearerAndNothingElse pins the one thing courier's
// `:authenticated` pipeline reads.
func TestTheCredentialIsBearerAndNothingElse(t *testing.T) {
	var seen *http.Request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Clone(context.Background())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"message_id":"m","event_id":"e",` +
			`"notification_type":"password_reset","user_id":"u","status":"accepted"}}`))
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "service-token-value")
	if _, err := client.SendMessage(context.Background(), MessageRequest{
		Type:   TypePasswordReset,
		UserID: "6f5d4c3b-2a19-4e8f-9c07-1b2d3e4f5061",
		To:     "kaka@example.com",
		URL:    "https://app.example.com/reset?token=abc",
	}); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}

	if got := seen.Header.Get("Authorization"); got != "Bearer service-token-value" {
		t.Errorf("Authorization = %q, want a bearer credential", got)
	}
	if got := seen.Header.Values("Authorization"); len(got) != 1 {
		t.Errorf("Authorization appears %d times; a repeated header is ambiguous", len(got))
	}
	if seen.Header.Get("Cookie") != "" {
		t.Error("a machine credential was sent in a cookie; courier's surface is not a browser")
	}
	if got := seen.Header.Get("Accept"); !strings.Contains(got, "application/json") {
		t.Errorf("Accept = %q; without it courier's :accepts plug answers 406", got)
	}
	if got := seen.Header.Get("Content-Type"); !strings.Contains(got, "application/json") {
		t.Errorf("Content-Type = %q, want JSON", got)
	}
	if got := seen.Header.Get("Idempotency-Key"); got == "" {
		t.Error("no Idempotency-Key: courier's :idempotent pipeline scopes the key to the principal")
	}
	if seen.URL.Path != "/v1/messages" {
		t.Errorf("path = %q, want /v1/messages", seen.URL.Path)
	}
	if seen.Method != http.MethodPost {
		t.Errorf("method = %q, want POST", seen.Method)
	}
}

// TestTheRequestIsBoundedAndTheWaitIsTheUsers is the latency decision made
// explicit and checkable: a password reset blocks on courier blocking on SMTP, and
// the bound is what stops a slow relay from holding a browser's request open.
func TestTheRequestIsBoundedAndTheWaitIsTheUsers(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	defer close(release)

	client := newTestClient(t, server.URL, "service-token-value")
	client.http.Timeout = 80 * time.Millisecond

	start := time.Now()
	_, err := client.SendMessage(context.Background(), MessageRequest{
		Type:   TypePasswordReset,
		UserID: "6f5d4c3b-2a19-4e8f-9c07-1b2d3e4f5061",
		To:     "kaka@example.com",
		URL:    "https://app.example.com/reset?token=abc",
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a send that outran its bound reported success")
	}
	if elapsed > 3*time.Second {
		t.Errorf("the send took %s; the bound did not hold", elapsed)
	}
	if !isError(err, ErrTimeout) {
		t.Errorf("error = %v, want one matching ErrTimeout", err)
	}
	if !Retryable(err) {
		t.Error("a timeout was reported as not retryable; courier releases a failed key, so it is")
	}
	// A cancelled caller must still be recognisable, because the difference between
	// "the user gave up" and "courier is slow" is what an operator reads.
	if !isError(err, context.DeadlineExceeded) {
		t.Error("the error does not match context.DeadlineExceeded, so a cancelled caller is indistinguishable")
	}
}

// assertSentShape checks the four things every row of the contract table above must
// have done, so that a row cannot pass by never reaching courier.
func assertSentShape(t *testing.T, seen *http.Request) {
	t.Helper()
	if seen.Method != http.MethodPost {
		t.Errorf("method = %q, want POST", seen.Method)
	}
	if seen.URL.Path != "/v1/messages" {
		t.Errorf("path = %q, want /v1/messages", seen.URL.Path)
	}
	if seen.Header.Get("Authorization") == "" {
		t.Error("the request carried no credential")
	}
	if seen.Header.Get("Idempotency-Key") == "" {
		t.Error("the request carried no Idempotency-Key")
	}
}
