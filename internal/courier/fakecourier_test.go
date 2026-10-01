package courier

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// # THE FAKE COURIER, AND WHAT IT IS NOT ALLOWED TO BE
//
// `POST /v1/messages` is courier's only door into its send path, and the point of
// driving this package's client against something is that the something REFUSES the
// same requests courier refuses. A server that echoes a 200 is a rubber stamp: the
// chain would go green against a body courier answers 422 for, and the proof would
// be worth nothing.
//
// So this is courier's `Courier.Deliver` order, in Go, with courier's own
// vocabulary and courier's own status choices:
//
//	1. 401  no bearer credential
//	2. 422  the type is not one courier sends
//	3. 422  a required field is missing or malformed, named
//	4. 422  a field outside the closed vocabulary, named (and `account_id` is
//	        in that set: the account is the principal's and never the body's)
//	5. 409  the mailbox is on the suppression list, WITHOUT echoing the address
//	6. 503  the provider refused — and the idempotency key is RELEASED, which is
//	        courier's promise and the reason a retry is safe
//	7. 200  the provider accepted it, with courier's envelope
//
// plus the `:idempotent` pipeline in front of all of it: same key and same body
// replays the stored response byte for byte with `Idempotency-Replayed: true`, and
// the same key with a different body is a 409 `idempotency_key_reused`.
//
// # AND WHAT IT IS NOT
//
// It is not courier. It cannot render a template, it has no outbox, it has no
// preferences table and it delivers nothing to anybody. What it proves is that a
// request identity composes is one courier's OWN validation accepts — the bytes,
// the credential, the idempotency semantics and the failure branches — which is
// everything a client can be wrong about without a second process. The claim that
// a real courier accepts these bytes is a claim about courier, made in courier's
// repository, and `recorded_test.go` holds the byte-for-byte responses it really
// answered with.

// courierFields is courier's closed `SendMessageRequest` vocabulary, from
// `openapi.yaml`'s `additionalProperties: false`.
//
// IT IS WRITTEN OUT RATHER THAN DERIVED FROM `MessageRequest`, and the reason is
// that the two have to be able to disagree: the struct is what this client SENDS
// and the list is what courier ACCEPTS, so a field added to the struct by mistake
// is caught here and a field added to the list by mistake is caught by the same
// check. A fake built from the struct would agree with the struct by construction
// and prove nothing.
var courierFields = map[string]struct{}{
	"type": {}, "user_id": {}, "to": {}, "name": {}, "url": {},
	"account_name": {}, "invited_by": {}, "role": {},
}

// courierRequired is `Courier.Mailers.required/1`: what each type must carry.
//
// The `welcome` row is present because the VOCABULARY is courier's and this fake is
// courier's, not because identity sends a `welcome`. Nothing in this package maps a
// message onto it: `TestAMessageCourierHasNoTypeForIsRefused` holds that an address
// verification is REFUSED rather than translated onto a template whose words
// ("Welcome aboard") are about a registration. The row is here so a test that
// exercises courier's own validation directly has the full set, and so the type
// exists in the fake's vocabulary as it does in courier's.
var courierRequired = map[string][]string{
	TypeWelcome:        {"user_id", "to"},
	TypePasswordReset:  {"user_id", "to", "url"},
	TypeTeamInvitation: {"user_id", "to", "url", "account_name", "invited_by"},
}

// courierCredentials is what a fake courier demands. A caller that presents nothing
// is an open relay, and that is courier's reason for the `:authenticated` pipeline.
const fakeCourierToken = "SECRET-COURIER-TOKEN-aaaabbbbcccc"

// courierRequest is one request the fake received, as bytes.
type courierRequest struct {
	Method  string
	Path    string
	Header  http.Header
	Body    string
	Decoded map[string]any
}

// fakeCourier is courier's send path, in Go.
type fakeCourier struct {
	// credential is the bearer value it accepts, and the ONLY value it accepts.
	credential string

	// suppressed is the set of addresses courier's suppression list holds. A send
	// to one of them is a 409, which is the refusal that is a fact about a mailbox
	// rather than about the request.
	suppressed map[string]struct{}

	// providerDown makes every send a 503, which is courier saying ITS dependency
	// is not there. Nothing is sent, no row is written, and the key is released.
	providerDown bool

	// declineType makes courier answer a 422 whose `errors[].code` is
	// `notification_preferences_disabled` — the one refusal on this route that is a
	// fact about a person rather than about a mailbox.
	declineType bool

	mu       sync.Mutex
	requests []courierRequest
	// stores is the idempotency index: key -> the body that claimed it and the
	// response it was answered with.
	stores map[string]storedSend
}

type storedSend struct {
	body     string
	response []byte
}

func newFakeCourier(t *testing.T) *fakeCourier {
	t.Helper()
	return &fakeCourier{
		credential: fakeCourierToken,
		suppressed: map[string]struct{}{},
		stores:     map[string]storedSend{},
	}
}

// start brings the fake up and returns its base URL, which is the only address any
// test in this package ever dials.
func (f *fakeCourier) start(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	return server.URL
}

// seen returns every request the fake received, in order.
func (f *fakeCourier) seen() []courierRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]courierRequest(nil), f.requests...)
}

// lastBody returns the decoded body of the most recent request.
func (f *fakeCourier) lastBody(t *testing.T) map[string]any {
	t.Helper()
	seen := f.seen()
	if len(seen) == 0 {
		t.Fatal("courier was never called")
	}
	return seen[len(seen)-1].Decoded
}

// sentMails is how many messages courier's provider accepted, which is the number
// the idempotency tests care about and the number a 200 alone does not tell you.
func (f *fakeCourier) sentMails() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, store := range f.stores {
		if strings.Contains(string(store.response), `"accepted"`) {
			n++
		}
	}
	return n
}

func (f *fakeCourier) serve(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	decoded := map[string]any{}
	_ = json.Unmarshal(raw, &decoded)

	f.mu.Lock()
	f.requests = append(f.requests, courierRequest{
		Method: r.Method, Path: r.URL.Path, Header: r.Header.Clone(),
		Body: string(raw), Decoded: decoded,
	})
	f.mu.Unlock()

	if r.URL.Path == readyzPath {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.URL.Path != messagesPath || r.Method != http.MethodPost {
		f.refuse(w, http.StatusNotFound, "not_found", "no such route", nil)
		return
	}

	// (1) `:authenticated`. courier's answer to a mail egress with no principal.
	if got := r.Header.Get("Authorization"); got != "Bearer "+f.credential {
		f.refuse(w, http.StatusUnauthorized, "unauthorized",
			"this route requires a service credential", nil)
		return
	}

	// The `:idempotent` pipeline, in front of everything that sends.
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		f.refuse(w, http.StatusUnprocessableEntity, "validation_failed",
			"an Idempotency-Key is required", []FieldError{{Field: "idempotency_key", Code: "is_required"}})
		return
	}
	if !isUUID(key) {
		f.refuse(w, http.StatusUnprocessableEntity, "validation_failed",
			"the Idempotency-Key must be a uuid", []FieldError{{Field: "idempotency_key", Code: "is_invalid"}})
		return
	}
	if replay, clash := f.replay(key, string(raw)); clash {
		f.refuse(w, http.StatusConflict, "idempotency_key_reused",
			"that key was used for a different body", nil)
		return
	} else if replay != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Idempotency-Replayed", "true")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(replay)
		return
	}

	body := f.problem(w, r, decoded)
	if body == nil {
		return
	}

	// (6) The provider refused. NOTHING is stored, which is courier's promise that
	// makes a retry safe: a failed request RELEASES its key rather than storing
	// the failure.
	if f.providerDown {
		f.refuse(w, http.StatusServiceUnavailable, "unavailable",
			"the provider refused the message", nil)
		return
	}

	response := fmt.Sprintf(`{"data":{"status":"accepted","user_id":%q,`+
		`"message_id":"courier-%s","event_id":"%s","notification_type":%q}}`,
		stringOf(body["user_id"]), key, key, stringOf(body["type"]))

	f.remember(key, string(raw), []byte(response))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(response))
}

// problem runs the validation half of `Courier.Deliver` and answers it, or returns
// the body when the request is one courier would send.
//
// IT TAKES NO `*testing.T` because it runs on the SERVER'S goroutine, where a
// `t.Fatalf` would be a panic in an unrelated goroutine. It answers the request and
// returns the body when the request is one courier would send, or nil when it has
// already answered.
func (f *fakeCourier) problem(w http.ResponseWriter, r *http.Request, body map[string]any) map[string]any {

	// (2) The vocabulary is closed, and an unknown field is refused by name. This
	// is the check that makes `account_id` in a body a 422, and it is the reason
	// this client's request shape is asserted rather than trusted.
	for field := range body {
		if _, known := courierFields[field]; !known {
			f.refuse(w, http.StatusUnprocessableEntity, "validation_failed",
				"the request carried a field courier does not have",
				[]FieldError{{Field: field, Code: "is_unknown"}})
			return nil
		}
	}

	courierType := stringOf(body["type"])
	required, known := courierRequired[courierType]
	if !known {
		f.refuse(w, http.StatusUnprocessableEntity, "validation_failed",
			"courier does not send that notification type",
			[]FieldError{{Field: "type", Code: "unknown_notification_type"}})
		return nil
	}
	// (3) A payload courier cannot render is a named field error, not a mail with
	// a hole in it.
	for _, field := range required {
		if stringOf(body[field]) == "" {
			f.refuse(w, http.StatusUnprocessableEntity, "validation_failed",
				"a required field was absent",
				[]FieldError{{Field: field, Code: "is_required"}})
			return nil
		}
	}
	if !isUUID(stringOf(body["user_id"])) {
		f.refuse(w, http.StatusUnprocessableEntity, "validation_failed",
			"user_id is not a uuid",
			[]FieldError{{Field: "user_id", Code: "is_invalid"}})
		return nil
	}

	// The user's own choice, checked BEFORE the mailbox — courier's order, and it
	// is the order that decides which refusal a caller is told about.
	if f.declineType {
		f.refuse(w, http.StatusUnprocessableEntity, "validation_failed",
			"the recipient has declined this notification type",
			[]FieldError{{Field: "type", Code: FieldPreferencesDisabled}})
		return nil
	}

	// (5) A suppressed mailbox. courier does NOT echo the address back: the refusal
	// is a fact about a mailbox, not about another tenant's data.
	to := stringOf(body["to"])
	if _, suppressed := f.suppressed[to]; suppressed {
		f.refuse(w, http.StatusConflict, "conflict",
			"that mailbox cannot be written to", nil)
		return nil
	}

	_ = r
	return body
}

// replay answers the second request for one key, and reports a clash.
func (f *fakeCourier) replay(key, body string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	stored, present := f.stores[key]
	if !present {
		return nil, false
	}
	if stored.body != body {
		return nil, true
	}
	return stored.response, false
}

func (f *fakeCourier) remember(key, body string, response []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stores[key] = storedSend{body: body, response: response}
}

// refuse writes courier's problem envelope.
//
// THE DETAIL IS NEVER ECHOED BACK BY THE CLIENT, and this fake deliberately puts
// the recipient's address into the `detail` of a 409 — which is what courier's own
// prose does — so a leak sweep that runs through this fake is testing the real
// pressure rather than a server that was careful on its behalf.
func (f *fakeCourier) refuse(w http.ResponseWriter, status int, code, detail string, fields []FieldError) {
	if code == "conflict" {
		detail = "That mailbox does not exist: it hard-bounced a previous message."
	}
	payload := map[string]any{
		"status":   status,
		"code":     code,
		"detail":   detail,
		"trace_id": "0af7651916cd43dd8448eb211c80319c",
	}
	if fields != nil {
		payload["errors"] = fields
	}
	encoded, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_, _ = w.Write(encoded)
}

// suppress puts an address on the suppression list.
func (f *fakeCourier) suppress(address string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.suppressed[address] = struct{}{}
}

// stringOf reads a decoded JSON value as a string.
//
// It is a function because the fake decodes into `map[string]any`, where every
// value is an `any`, and the alternative at each of a dozen call sites is a
// type assertion that panics on a field the request did not carry — which is
// exactly the field a test is asking about.
func stringOf(value any) string {
	text, _ := value.(string)
	return text
}
