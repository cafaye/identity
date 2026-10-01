package courier

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/outbox"
	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/recovery"
	"github.com/cafaye/identity/internal/sessions"
	"github.com/cafaye/identity/internal/users"
)

// # THIS IS THE PROOF, AND ITS BOUNDARIES ARE WHY IT IS WRITTEN LIKE THIS
//
// `TestTheWholePasswordResetPathReachesCouriersDoor` drives identity's REAL recovery
// flow — `recovery.Service.RequestPasswordReset`, its real `Mailer.Ready` check
// before the lookup, its real mint-and-write, its real cooldown — against a real
// Postgres, with `internal/courier`'s `RecoveryMailer` on the seam and a courier-
// shaped server at the end of it.
//
// # WHAT IS REAL
//
//   - the token is minted by `sessions.NewToken` and its SHA-256 written by
//     `recovery`'s own store, into the migrated table;
//   - the message is rendered by `internal/recovery/message.go`;
//   - `Ready` runs BEFORE the account lookup, so the enumeration ordering is
//     `recovery`'s own and is genuinely exercised;
//   - the adapter translates, and the asserted bytes are the bytes that crossed the
//     wire;
//   - the credential is courier's bearer token, attached by the real client.
//
// # WHAT IS A STAND-IN, AND WHY THAT IS THE RIGHT WAY ROUND
//
// courier is an `httptest` server enforcing courier's four validation rules, and
// that is deliberate: a stand-in for courier can falsify the REQUEST, which is what
// this test is about. It asserts every field, enforces the closed vocabulary, and
// answers 422 for anything courier would refuse — so a request identity composes
// wrongly is red here. `e2e_support_test.go` covers the other direction, a real
// courier's ANSWER to the bytes this test composes, so nothing in between is
// unexamined.
//
// Postgres is real rather than faked for the opposite reason. The properties that
// matter to this flow — "the digest is written before the send", "the cooldown is
// consulted", "an unrefused request mints nothing" — are properties of SQL, and
// `internal/recovery`'s own suite already holds them against a real database. A
// fake store here would test the fake.
//
// # WHAT IT DOES NOT PROVE
//
// Authentication. courier's shipped principal resolver authenticates nobody, so a
// real deployment needs courier's JWT-verifier packet before identity can send at
// all. The 401 is recorded in `recorded_test.go` and `buildMailer`'s comment says why
// the credential is presented as a bearer token anyway.

// noOpAccessRevoker stands in for the OIDC access-token sweep.
//
// It is a stand-in and the reason is that the sweep is ONE UPDATE whose SQL
// `internal/oidc`'s store test holds against a real database; what a password
// REQUEST does is mint and send, and no token is redeemed, so the sweep never runs
// on this path. A test that claimed to cover it would be asserting nothing.
type noOpAccessRevoker struct{}

func (noOpAccessRevoker) RevokeAccessTokensForUser(context.Context, db.Querier, id.UUID, time.Time) error {
	return nil
}

// recoveryFlow is a `recovery.Service` over a real pool, with a mailer on the seam.
type recoveryFlow struct {
	svc *recovery.Service
	who registeredAccount
}

// registeredAccount is a row of `users` this test created.
type registeredAccount struct {
	id    id.UUID
	email string
}

// newRecoveryFlow registers one account and builds the real flow over it.
//
// THE HARNESS IS `dbtest.Pool` — the same one `internal/recovery` uses — so the
// tables are the migrated ones and not a schema invented here.
func newRecoveryFlow(t *testing.T, mailer recovery.Mailer) *recoveryFlow {
	t.Helper()

	pool := dbtest.Pool(t)
	// The pool IS a Querier — `db.Pool` embeds it — and `users.Store.Create` takes
	// one directly. Passing a `db.Direct` here would be a second object configured
	// identically, which is the thing this repository keeps refusing.
	store := users.NewStore(pool)

	// A unique address per test, because `dbtest.Pool` is a SHARED pool and a fixed
	// one would collide with any other test that registered the same address.
	//
	// IT IS A HASH PLUS FRESH RANDOMNESS, and both halves are load-bearing. The hash
	// is of the test NAME, because a name contains `/` and `users.ValidateEmail`
	// refuses it — the first version of this fixture built the address from the name
	// and every request failed with `email: invalid_format`, which is the service
	// being right and the fixture being wrong. The randomness is because
	// `dbtest.Pool` is a SHARED pool that survives between runs: a name-derived
	// address alone collides on the second `go test` with `email already
	// registered`, which reads like a uniqueness defect and is a fixture that
	// assumed a clean database.
	sum := sha256.Sum256([]byte(t.Name()))
	var noise [4]byte
	if _, err := rand.Read(noise[:]); err != nil {
		t.Fatalf("generating an address suffix: %v", err)
	}
	email := "flow-" + hex.EncodeToString(sum[:6]) + "-" + hex.EncodeToString(noise[:]) +
		"@example.com"

	user, err := store.Create(context.Background(), pool, users.CreateParams{
		Email:          email,
		PasswordDigest: testPasswordDigest(t),
	})
	if err != nil {
		t.Fatalf("registering %s: %v", email, err)
	}

	return &recoveryFlow{
		who: registeredAccount{id: user.ID, email: user.Email},
		svc: recovery.NewService(
			db.TxRunner{Pool: pool},
			db.Direct{Pool: pool},
			recovery.NewStore(pool),
			store,
			sessions.NewStore(pool),
			noOpAccessRevoker{},
			outbox.NewStore(pool),
			mailer,
			testHasher(t),
			clock.System{},
		),
	}
}

// testPasswordDigest is a real argon2id digest.
//
// IT MATTERS THAT IT IS REAL rather than a string, and the reason is that this test
// is not about passwords — but a flow that reached a redemption with a fake digest
// would be testing a path the service cannot take, and the cheap version of "close
// enough" is how a suite starts asserting things that do not happen.
func testPasswordDigest(t *testing.T) string {
	t.Helper()
	digest, err := testHasher(t).Hash("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}
	return digest
}

// testHasher is a real argon2id hasher with cheap parameters, for the reason
// `internal/recovery`'s own `testHasher` gives.
func testHasher(t *testing.T) *users.Hasher {
	t.Helper()
	params := users.DefaultParams()
	params.Memory = 8 * 1024
	params.Iterations = 1
	params.Parallelism = 1
	return users.NewHasherWithParams(params)
}

// TestTheWholePasswordResetPathReachesCouriersDoor is the packet's central claim:
// a user's password reset comes out of identity as a send courier accepts.
func TestTheWholePasswordResetPathReachesCouriersDoor(t *testing.T) {
	stub := newCourierStub(t)
	flow := newRecoveryFlow(t, stub.mailer(t))

	if err := flow.svc.RequestPasswordReset(context.Background(), flow.who.email); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}

	if len(stub.sent) != 1 {
		t.Fatalf("courier saw %d requests, want 1", len(stub.sent))
	}
	sent := stub.sent[0]

	// The request courier's `:authenticated` and `:idempotent` pipelines read.
	if sent.Method != http.MethodPost || sent.Path != messagesPath {
		t.Errorf("courier saw %s %s, want POST %s", sent.Method, sent.Path, messagesPath)
	}
	if !strings.HasPrefix(sent.Authorization, "Bearer ") {
		t.Errorf("Authorization = %q, want a bearer credential; courier's /v1 is behind "+
			":authenticated and an anonymous send is an open relay", sent.Authorization)
	}
	if !isUUID(sent.IdempotencyKey) {
		t.Errorf("Idempotency-Key = %q; courier answers 422 for anything that is not a uuid",
			sent.IdempotencyKey)
	}
	if sent.Accept != "application/json" {
		t.Errorf("Accept = %q; courier's :accepts plug answers 406 without it", sent.Accept)
	}

	// courier's required fields.
	if sent.Body["type"] != TypePasswordReset {
		t.Errorf("type = %v, want %q", sent.Body["type"], TypePasswordReset)
	}
	if sent.Body["to"] != flow.who.email {
		t.Errorf("to = %v, want the account's own address %q", sent.Body["to"], flow.who.email)
	}
	if sent.Body["user_id"] != flow.who.id.String() {
		t.Errorf("user_id = %v, want the account the flow looked up (%s)",
			sent.Body["user_id"], flow.who.id)
	}

	// THE LINK: the credential's only home, in the CONFIGURED template's shape.
	link := stringOf(sent.Body["url"])
	if !strings.HasPrefix(link, testLinkPrefix) {
		t.Errorf("url = %q, want the configured template's shape; the adapter must not "+
			"invent a product's path", link)
	}
	token := stub.tokenFromLastRequest(t)
	if token == "" {
		t.Fatal("no token reached courier's request; a reset link with nothing in it is a " +
			"mail a user can follow and cannot use")
	}
	if !strings.Contains(link, token) {
		t.Errorf("url = %q, want the token in it", link)
	}
	// Nowhere else. A credential in two fields of a request is a credential in two
	// places somebody has to remember to redact.
	for field, value := range sent.Body {
		if field == "url" {
			continue
		}
		if strings.Contains(stringOf(value), token) {
			t.Errorf("the token also appears in %q", field)
		}
	}
	// And no field courier does not have. Its recorded 422 for `subject` is the proof
	// that adding one is a refusal, not a harmless extra.
	for _, forbidden := range []string{"from", "subject", "text", "html", "body", "account_id"} {
		if _, present := sent.Body[forbidden]; present {
			t.Errorf("the request carried %q, which courier's closed vocabulary does not have",
				forbidden)
		}
	}
}

// TestAnUnregisteredAddressNeverReachesCourier is the enumeration property, end to
// end.
//
// `recovery` asserts it and `internal/httpapi` holds the constant response body; what
// this adds is the last link — an address nobody registered does not reach courier AT
// ALL, so there is nothing in courier's request log to compare. A test that only
// checked the HTTP response would miss a service that mailed an unregistered address
// anyway.
func TestAnUnregisteredAddressNeverReachesCourier(t *testing.T) {
	stub := newCourierStub(t)
	flow := newRecoveryFlow(t, stub.mailer(t))

	const nobody = "nobody-registered-this-address@example.com"
	if err := flow.svc.RequestPasswordReset(context.Background(), nobody); err != nil {
		t.Fatalf("RequestPasswordReset for an unregistered address returned %v; it must "+
			"return nil so the two cases are indistinguishable", err)
	}
	if len(stub.sent) != 0 {
		t.Errorf("courier saw %d requests for an unregistered address, want 0", len(stub.sent))
	}

	// And the registered one does, so the assertion above is not passing because
	// nothing is ever sent.
	if err := flow.svc.RequestPasswordReset(context.Background(), flow.who.email); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if len(stub.sent) != 1 {
		t.Errorf("courier saw %d requests for a registered address, want 1", len(stub.sent))
	}
}

// TestTheTwoOutcomesAgreeOnEverythingACallerCanSee is the same property stated the
// way an attacker would use it.
func TestTheTwoOutcomesAgreeOnEverythingACallerCanSee(t *testing.T) {
	stub := newCourierStub(t)
	flow := newRecoveryFlow(t, stub.mailer(t))

	registered := flow.requestReset(t, flow.who.email)
	unregistered := flow.requestReset(t, "still-nobody@example.com")

	if registered != unregistered {
		t.Errorf("a registered address produced %v and an unregistered one %v; that "+
			"difference is the oracle", registered, unregistered)
	}
}

// TestACourierThatIsDownRefusesBeforeAnythingIsMinted is the ordering property that
// keeps "courier is misconfigured" from becoming an oracle of its own.
//
// `recovery` checks `Mailer.Ready` BEFORE the lookup, so a deployment that cannot
// deliver refuses a registered address and an unregistered one at the same place. The
// other order would make 503-against-202 a probe for which addresses exist.
func TestACourierThatIsDownRefusesBeforeAnythingIsMinted(t *testing.T) {
	// A courier whose readiness probe fails and whose send path would answer 200.
	// Any request reaching the send path fails the test, which is the property.
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == readyzPath {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		t.Errorf("a request reached courier's send path while courier was down: %s", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(acceptedBody))
	}))
	defer down.Close()

	flow := newRecoveryFlow(t, testMailer(t, down.URL, nil))

	err := flow.svc.RequestPasswordReset(context.Background(), flow.who.email)
	if !isError(err, recovery.ErrNoMailer) {
		t.Fatalf("RequestPasswordReset = %v, want recovery.ErrNoMailer, which the HTTP "+
			"layer answers 503 so a product knows not to render \"check your inbox\"", err)
	}
	if got := flow.liveTokens(t); got != 0 {
		t.Errorf("%d recovery tokens exist after a refused request; the check is supposed "+
			"to happen before a credential is minted", got)
	}
}

// TestASuppressedMailboxIsRefusedRatherThanReportedAsSent is the 409 question,
// answered as a test.
//
// courier answers 409 `conflict` and does NOT echo the address — recorded, and
// asserted in `recorded_test.go`. So identity must not turn it into a 202. The
// caller is anonymous here, and a 503 for a suppressed address against a 202 for an
// unregistered one would be a probe for "does this address exist and is it
// suppressed".
//
// WHAT THE TEST ASSERTS, and it is the part that is identity's to assert: the send
// failed, it failed in a way that names the problem for an operator, the failure is
// not retryable, and the row written before the send is there. The status code is
// the HTTP layer's, and it is uniform with every other failure of the seam.
func TestASuppressedMailboxIsRefusedRatherThanReportedAsSent(t *testing.T) {
	suppressed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == readyzPath {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		// courier's recorded 409: a hard bounce, naming no address.
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"code":"conflict","detail":"That mailbox does not ` +
			`exist: it hard-bounced a previous message.","instance":"/v1/messages",` +
			`"status":409,"title":"Conflict","trace_id":"sup-1",` +
			`"type":"https://errors.cafaye.com/conflict"}`))
	}))
	defer suppressed.Close()

	flow := newRecoveryFlow(t, testMailer(t, suppressed.URL, nil))

	err := flow.svc.RequestPasswordReset(context.Background(), flow.who.email)
	if err == nil {
		t.Fatal("RequestPasswordReset reported success for a suppressed mailbox; the user " +
			"would wait for a message courier will never send")
	}
	// The error IS a courier suppression, so an operator reading the log can see that
	// a mailbox is undeliverable. courier does not expose its suppression list through
	// any route, so this is the only place the fact surfaces — which is why it must
	// reach the log and not the response.
	if !isError(err, ErrSuppressed) {
		t.Errorf("error = %v, want one matching ErrSuppressed", err)
	}
	if Retryable(err) {
		t.Error("a suppression was reported as retryable; waiting does not unsuppress a mailbox")
	}
	// The token's row exists, because the row is written before the send. It expires
	// harmlessly. Asserted because a send attempted with no row would mean a message
	// whose link cannot be redeemed.
	if got := flow.liveTokens(t); got != 1 {
		t.Errorf("%d recovery tokens exist, want 1: the digest is written before the send "+
			"and the row expires harmlessly", got)
	}
}

// TestTheSuppressionNeverReachesTheAddress is the narrower half of the 409 property,
// and it is separate because it is a LEAK rather than a decision.
//
// courier's 409 does not name the address, and this client's error must not either —
// it carries the status, the code, courier's trace id and the field names, and no
// prose. An operator gets the trace id and looks in courier's logs, which is exactly
// the handle courier's own document offers.
func TestTheSuppressionNeverReachesTheAddress(t *testing.T) {
	suppressed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == readyzPath {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"code":"conflict","detail":"That mailbox does not ` +
			`exist.","status":409,"trace_id":"sup-2",` +
			`"type":"https://errors.cafaye.com/conflict"}`))
	}))
	defer suppressed.Close()

	var log strings.Builder
	flow := newRecoveryFlow(t, testMailer(t, suppressed.URL, slog.New(slog.NewTextHandler(&log, nil))))

	// The flow's OWN account, and that is not incidental: a reset for an address
	// nobody registered never reaches the seam, so asking about "somebody-private"
	// would assert the absence of a log line about a request that was never made.
	address := flow.who.email

	err := flow.svc.RequestPasswordReset(context.Background(), address)
	if err == nil {
		t.Fatal("the send succeeded against a courier that refused it")
	}

	// courier's `detail` said "that mailbox does not exist" and this client's error
	// must not carry it: it is prose about a person, and this is a path whose errors
	// end up in a log aggregator.
	if strings.Contains(err.Error(), "does not exist") {
		t.Errorf("the error carries courier's prose: %v", err)
	}
	if strings.Contains(log.String(), address) {
		t.Errorf("the log carries the recipient:\n%s", log.String())
	}
	// But the handle survives, or the refusal is unreadable.
	if !strings.Contains(log.String(), "sup-2") {
		t.Errorf("the log has no handle on courier's logs:\n%s", log.String())
	}
}

// # FLOW HELPERS

// requestReset runs a reset request and reports what the flow returned, which is the
// whole of what a caller can observe at this layer.
func (f *recoveryFlow) requestReset(t *testing.T, email string) error {
	t.Helper()
	return f.svc.RequestPasswordReset(context.Background(), email)
}

// liveTokens counts this account's live recovery rows.
//
// IT QUERIES THE DATABASE rather than counting messages, because the claim is about
// rows: a token that was minted and whose message was never sent leaves a row that
// expires, and that is the state the ordering produces.
func (f *recoveryFlow) liveTokens(t *testing.T) int {
	t.Helper()
	pool := dbtest.Pool(t)
	var count int
	// `recovery_tokens` is `recovery`'s table and this query is a read of it from a
	// test in another package. It is here rather than in `recovery` because the
	// assertion belongs to the ordering, which is what this file is about.
	err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM recovery_tokens WHERE user_id = $1 AND expires_at > now()`,
		f.who.id).Scan(&count)
	if err != nil {
		t.Fatalf("counting recovery tokens: %v", err)
	}
	return count
}

// # THE COURIER STAND-IN

// testLinkPrefix is the shape of the link template the tests configure.
const testLinkPrefix = "https://app.example.com/reset"

// acceptedBody is the 200 courier answers a valid send with.
const acceptedBody = `{"data":{"status":"accepted",` +
	`"user_id":"6f5d4c3b-2a19-4e8f-9c07-1b2d3e4f5061",` +
	`"message_id":"courier-16c22f7a-deda-443c-bdac-d7dcf2405b70",` +
	`"event_id":"0f1d27fc-47ed-4547-aba6-3e98aeaaa198",` +
	`"notification_type":"password_reset"}}`

// stubbedRequest is one request that reached the door.
type stubbedRequest struct {
	Method         string
	Path           string
	Authorization  string
	IdempotencyKey string
	Accept         string
	ContentType    string
	Body           map[string]any
}

// courierStub is an httptest server enforcing courier's contract as its document
// declares it.
//
// IT IS STRICT ON PURPOSE. It answers 422 for an unknown field, a type outside the
// enum, a `user_id` that is not a uuid and a `password_reset` with no `url`, because
// a lenient stand-in would let identity compose something courier refuses and this
// file would stay green — which is the failure the file exists to prevent.
type courierStub struct {
	server *httptest.Server
	sent   []stubbedRequest
}

// newCourierStub starts a courier that accepts anything it considers valid.
func newCourierStub(t *testing.T) *courierStub {
	t.Helper()
	stub := &courierStub{}

	stub.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// `/readyz` is outside every pipeline in courier and answers for its
		// database. Honouring it is what makes the flow reach the send path at all,
		// and it is the same route the real client probes.
		if r.URL.Path == readyzPath {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}

		body := map[string]any{}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		stub.sent = append(stub.sent, stubbedRequest{
			Method:         r.Method,
			Path:           r.URL.Path,
			Authorization:  r.Header.Get("Authorization"),
			IdempotencyKey: r.Header.Get("Idempotency-Key"),
			Accept:         r.Header.Get("Accept"),
			ContentType:    r.Header.Get("Content-Type"),
			Body:           body,
		})

		if field := courierRefusal(body); field != "" {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"code":"validation_failed","detail":"` + field +
				`","errors":[{"code":"invalid_format","field":"` + field + `"}],` +
				`"status":422,"trace_id":"stub-1",` +
				`"type":"https://errors.cafaye.com/validation_failed"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(acceptedBody))
	}))
	t.Cleanup(stub.server.Close)
	return stub
}

// mailer builds the real adapter over this stub.
func (s *courierStub) mailer(t *testing.T) recovery.Mailer {
	t.Helper()
	return testMailer(t, s.server.URL, nil)
}

// tokenFromLastRequest reads the credential out of the LAST request's link.
//
// IT READS THE WIRE rather than the database, and that is the point: the plaintext
// exists in exactly one place in this whole path — the link courier was handed — so a
// test that wanted it from the row would be asserting about a value the service never
// stored.
func (s *courierStub) tokenFromLastRequest(t *testing.T) string {
	t.Helper()
	if len(s.sent) == 0 {
		t.Fatal("no request reached courier")
	}
	link := stringOf(s.sent[len(s.sent)-1].Body["url"])
	_, after, found := strings.Cut(link, "token=")
	if !found {
		return ""
	}
	token, _, _ := strings.Cut(after, "&")
	return token
}

// courierRefusal applies courier's own validation to a body and returns the field to
// complain about, or "".
//
// IT IS A SHORT, HONEST SUBSET of `CourierWeb.Messages.validate` and
// `Courier.Mailers`' changeset: the closed field list, the closed type enum, a
// uuid-shaped `user_id`, a non-empty `to`, and `url` required for a reset. Those are
// the rules identity can violate by accident. A stub enforcing more would be
// reimplementing courier's changesets in Go, and the recorded interactions in
// `recorded_test.go` already hold courier's own answers.
func courierRefusal(body map[string]any) string {
	for field := range body {
		switch field {
		case "type", "user_id", "to", "name", "url", "account_name", "invited_by", "role":
		default:
			return field
		}
	}
	if !IsType(stringOf(body["type"])) {
		return "type"
	}
	if !isUUID(stringOf(body["user_id"])) {
		return "user_id"
	}
	if stringOf(body["to"]) == "" {
		return "to"
	}
	if stringOf(body["type"]) == TypePasswordReset && stringOf(body["url"]) == "" {
		return "url"
	}
	return ""
}
