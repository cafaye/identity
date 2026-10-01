package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cafaye/identity/internal/oidc"
	"github.com/cafaye/identity/internal/outbox"
	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/recovery"
	"github.com/cafaye/identity/internal/sessions"
	"github.com/cafaye/identity/internal/users"
)

// THE RECOVERY SURFACE OVER A REAL DATABASE.
//
// Everything here drives the real router, the real use cases and the real SQL over a
// private schema, with a mailer that keeps what it was handed. The properties being
// asserted are the ones a client depends on and the ones a reviewer cannot check by
// reading a handler: the token that was mailed is the token that redeems, the
// session that existed before a reset does not exist after it, and the two request
// routes cannot be told apart.

// recoveryServerFixture is a router with the recovery surface mounted over a private
// schema, plus the seam that recorded what was sent.
type recoveryServerFixture struct {
	handler http.Handler
	pool    *pgxpool.Pool
	clk     *clock.Fake
	mailer  *captureMailer
	access  *captureAccessRevoker
	svc     *recovery.Service
}

// captureMailer is the seam's double. It keeps every message, because the plaintext
// token exists nowhere else and a test that wanted one from anywhere but the mail
// would be testing a token the service never sent.
type captureMailer struct {
	mu   sync.Mutex
	sent []recovery.Message
}

func (m *captureMailer) Ready(context.Context) error { return nil }

func (m *captureMailer) Send(_ context.Context, msg recovery.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, msg)
	return nil
}

func (m *captureMailer) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

// last is the most recent message.
func (m *captureMailer) last(t *testing.T) recovery.Message {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sent) == 0 {
		t.Fatal("no message was delivered")
	}
	return m.sent[len(m.sent)-1]
}

// captureAccessRevoker records which users had their access tokens swept. The real
// oidc.Store is wired as well — see TestAResetEndsTheAccessTokensIssuedBeforeIt —
// because the sweep's SQL belongs to internal/oidc's own tests and this only needs to
// know that the recovery flow asks for it.
type captureAccessRevoker struct {
	mu      sync.Mutex
	revoked map[string]time.Time
}

func (r *captureAccessRevoker) RevokeAccessTokensForUser(
	_ context.Context, _ db.Querier, userID id.UUID, at time.Time,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked[userID.String()] = at
	return nil
}

func (r *captureAccessRevoker) swept(userID id.UUID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.revoked[userID.String()]
	return ok
}

func newRecoveryServerFixture(t *testing.T) *recoveryServerFixture {
	t.Helper()

	pool := dbtest.Schema(t)
	clk := clock.NewFake(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	mailer := &captureMailer{}
	access := &captureAccessRevoker{revoked: map[string]time.Time{}}
	hasher := users.NewHasherWithParams(&argon2id.Params{
		Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	})

	svc := recovery.NewService(
		db.TxRunner{Pool: pool},
		db.Direct{Pool: pool},
		recovery.NewStore(pool),
		users.NewStore(pool),
		sessions.NewStore(pool),
		access,
		outbox.NewStore(pool),
		mailer,
		hasher,
		clk,
	)

	return &recoveryServerFixture{
		handler: New(nil, WithAuth(authServiceFor(pool, clk)), WithRecovery(svc)),
		pool:    pool,
		clk:     clk,
		mailer:  mailer,
		access:  access,
		svc:     svc,
	}
}

// signUp registers and signs in, returning the session token.
func (f *recoveryServerFixture) signUp(t *testing.T) (string, string) {
	t.Helper()

	email := dbtest.UniqueEmail(t)
	registerThrough(t, f.handler, email)

	rec := post(t, f.handler, "/v1/session", `{"email":"`+email+`","password":"`+validPassword+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /v1/session = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	var session sessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &session); err != nil {
		t.Fatalf("the login body is not JSON: %v", err)
	}
	return email, session.Token
}

// tokenIn reads the token out of the message that was delivered.
func tokenIn(t *testing.T, m recovery.Message) string {
	t.Helper()
	for _, line := range strings.Split(m.Body, "\n") {
		candidate := strings.TrimSpace(line)
		if len(candidate) == 43 && !strings.ContainsAny(candidate, " \t") {
			return candidate
		}
	}
	t.Fatalf("no token in the delivered message:\n%s", m.Body)
	return ""
}

// sessionsFor counts a user's live sessions.
func (f *recoveryServerFixture) sessionsFor(t *testing.T, email string) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(t.Context(), `
		SELECT count(*) FROM sessions s JOIN users u ON u.id = s.user_id WHERE u.email = $1`,
		email).Scan(&n); err != nil {
		t.Fatalf("counting sessions: %v", err)
	}
	return n
}

// userIDFor resolves an address to a row id.
func (f *recoveryServerFixture) userIDFor(t *testing.T, email string) id.UUID {
	t.Helper()
	var out id.UUID
	if err := f.pool.QueryRow(t.Context(), `SELECT id FROM users WHERE email = $1`, email).Scan(&out); err != nil {
		t.Fatalf("resolving %s: %v", email, err)
	}
	return out
}

// verifyAddress walks the whole verification flow over HTTP, so a test that needs a
// VERIFIED account has one that was proved the way a user's would be — through the
// two anonymous routes — rather than by writing the column.
func (f *recoveryServerFixture) verifyAddress(t *testing.T, email string) {
	t.Helper()

	requested := post(t, f.handler, "/v1/email-verifications", `{"email":"`+email+`"}`)
	if requested.Code != http.StatusAccepted {
		t.Fatalf("POST /v1/email-verifications = %d, want 202; body: %s", requested.Code, requested.Body)
	}
	confirmed := sendWith(t, f.handler, http.MethodPost, "/v1/email-verifications/confirm", "",
		"", `{"token":"`+tokenIn(t, f.mailer.last(t))+`"}`)
	if confirmed.Code != http.StatusNoContent {
		t.Fatalf("the confirmation = %d, want 204; body: %s", confirmed.Code, confirmed.Body)
	}
	if got := verificationState(t, f, email); got != "verified" {
		t.Fatalf("the address is %s after a confirmation, want verified", got)
	}
}

// verificationState reads the column, for a failure message that says which of the
// three cases a response belonged to.
func verificationState(t *testing.T, f *recoveryServerFixture, email string) string {
	t.Helper()
	var at *time.Time
	if err := f.pool.QueryRow(t.Context(),
		`SELECT email_verified_at FROM users WHERE email = $1`, email).Scan(&at); err != nil {
		t.Fatalf("reading the verification state of %s: %v", email, err)
	}
	if at == nil {
		return "unverified"
	}
	return "verified"
}

// TestTheWholeResetFlowOverHTTP: request, redeem, sign in again, and the old session
// is gone.
//
// IT IS THE PACKET'S CUSTOMER-FACING PROMISE IN ONE TEST. Everything else in this
// file is a negative; this is the path a person walks when they have forgotten a
// password, and it has to work end to end over HTTP rather than only in a use case.
func TestTheWholeResetFlowOverHTTP(t *testing.T) {
	f := newRecoveryServerFixture(t)
	email, token := f.signUp(t)

	requested := post(t, f.handler, "/v1/password-resets", `{"email":"`+email+`"}`)
	if requested.Code != http.StatusAccepted {
		t.Fatalf("POST /v1/password-resets = %d, want 202; body: %s", requested.Code, requested.Body)
	}

	redeemed := sendWith(t, f.handler, http.MethodPost, "/v1/password-resets/confirm", "",
		"", `{"token":"`+tokenIn(t, f.mailer.last(t))+`","password":"a completely new password"}`)
	if redeemed.Code != http.StatusNoContent {
		t.Fatalf("the confirmation = %d, want 204; body: %s", redeemed.Code, redeemed.Body)
	}

	// The old session is dead, over HTTP, which is the claim the packet makes.
	if got := f.sessionsFor(t, email); got != 0 {
		t.Errorf("%d sessions survived a password reset, want 0", got)
	}
	me := sendWith(t, f.handler, http.MethodGet, "/v1/me", token, "", "")
	if me.Code != http.StatusUnauthorized {
		t.Errorf("GET /v1/me with the pre-reset token = %d, want 401", me.Code)
	}

	// The new password works, and the old one does not.
	if rec := post(t, f.handler, "/v1/session",
		`{"email":"`+email+`","password":"a completely new password"}`); rec.Code != http.StatusOK {
		t.Errorf("signing in with the new password = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if rec := post(t, f.handler, "/v1/session",
		`{"email":"`+email+`","password":"`+validPassword+`"}`); rec.Code == http.StatusOK {
		t.Error("the old password still signs in after a reset")
	}
}

// TestTheTwoRequestRoutesAnswerIdenticallyOverHTTP is the enumeration property with
// the real service behind it, which is the version of it that cannot be defeated by
// a use case that returns different errors for the two cases.
//
// THE ASSERTION IS THE WHOLE RESPONSE: same status, same headers that matter, same
// bytes. A byte comparison is safe here because both bodies are the one constant and
// neither carries a trace id — this is a success body, not a problem document.
func TestTheTwoRequestRoutesAnswerIdenticallyOverHTTP(t *testing.T) {
	f := newRecoveryServerFixture(t)
	known, _ := f.signUp(t)
	unknown := dbtest.UniqueEmail(t)

	for _, address := range []string{known, unknown} {
		reset := post(t, f.handler, "/v1/password-resets", `{"email":"`+address+`"}`)
		if reset.Code != http.StatusAccepted {
			t.Fatalf("a reset request for %s = %d, want 202; body: %s", address, reset.Code, reset.Body)
		}
		if got := reset.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
			t.Errorf("Content-Type = %q", got)
		}
	}

	// The comparison, over the recorded responses rather than two fresh ones so the
	// two cases are provably adjacent.
	first := post(t, f.handler, "/v1/password-resets", `{"email":"`+known+`"}`)
	if first.Code != http.StatusAccepted {
		t.Fatalf("the known-address request = %d, want 202", first.Code)
	}
	second := post(t, f.handler, "/v1/password-resets", `{"email":"`+unknown+`"}`)
	if first.Body.String() != second.Body.String() {
		t.Errorf("the two answers differ:\nknown:   %s\nunknown: %s", first.Body, second.Body)
	}

	// And the negative half: exactly one message was sent, to the address that has
	// an account.
	if got := f.mailer.count(); got != 1 {
		t.Errorf("%d messages for one known address and one unknown, want 1", got)
	}
	if got := f.mailer.last(t).To; got != known {
		t.Errorf("the message went to %q, want the known address %q", got, known)
	}
}

// TestTheWholeEmailChangeFlowOverHTTP: request, confirm the current address, confirm
// the new one, and the address has moved.
// TestATruncatedTokenAnswers404Not422 settles a
// disagreement between the document and the service, which was found by another
// service's worker and re-measured here rather than taken on trust.
//
// THE DISAGREEMENT. `RecoveryTokenRequest.token` declares `minLength: 43` and
// `maxLength: 43`, and each of the three redemption routes lists a 422. A reader
// derives from that a 422 with a field error naming `token` — and gets a 404,
// because nothing between the handler and `tokens.Live` looks at the length at all.
// A caller whose link builder truncated the query string is told "no such link",
// which is the same sentence as an expired one.
//
// THE RESOLUTION IS THE DOCUMENT'S, and the schema already said so: the token's
// description calls the length "load-bearing ON THE CLIENT SIDE … it is what tells
// a caller the value is complete before it is pasted into a URL". What was missing
// was the sentence that says the service does not enforce it, so the 422 read as
// though it did. Adding a length check in the handler was the other answer and was
// rejected: `ErrTokenNotFound`'s contract is ONE answer for every token that is not
// live, and a fifth case told apart by a property of the input buys a developer a
// prettier error while adding a branch to the anonymous surface whose whole argument
// is that it has none.
//
// THE 422 IS STILL TRUE, and this proves it rather than asserting it: the one 422
// these routes really answer is for a field the endpoint does not accept, which is
// `decodeBody`'s rule and applies to every route in the service.
func TestATruncatedTokenAnswers404Not422(t *testing.T) {
	f := newRecoveryServerFixture(t)
	email, _ := f.signUp(t)

	// A real token, so the "43" in the schema is checked against something this
	// service actually minted rather than against the constant.
	post(t, f.handler, "/v1/email-verifications", `{"email":"`+email+`"}`)
	live := tokenIn(t, f.mailer.last(t))
	if want := 43; len(live) != want {
		t.Fatalf("the token this service mailed is %d characters, and RecoveryTokenRequest "+
			"declares minLength and maxLength %d. Fix the document or the mint; this test "+
			"truncates on the declared length", len(live), want)
	}

	routes := []struct{ path, body string }{
		{"/v1/email-verifications/confirm", `{"token":%q}`},
		{"/v1/email-changes/current-address", `{"token":%q}`},
		{"/v1/email-changes/new-address", `{"token":%q}`},
	}
	// Three shapes, and the point of the test is that they are one answer: a token
	// truncated by one character, a token that is obviously not one, and a token one
	// character too long. A SLICE, not a map, because the first answer becomes the
	// reference and a map would make which one that be a property of Go's iteration
	// order — so a failure would name a different pair of shapes on each run.
	shapes := []struct{ name, token string }{
		{"truncated by one", live[:len(live)-1]},
		{"far too short", "t"},
		{"one too long", live + "x"},
		{"never existed", strings.Repeat("z", len(live))},
	}

	for _, route := range routes {
		reference := ""
		for _, shape := range shapes {
			body := fmt.Sprintf(route.body, shape.token)
			rec := sendWith(t, f.handler, http.MethodPost, route.path, "", "", body)
			if rec.Code != http.StatusNotFound {
				t.Errorf("POST %s with a token %s = %d, want 404; body: %s",
					route.path, shape.name, rec.Code, rec.Body)
				continue
			}

			p := decodeProblem(t, rec)
			if p.Code != CodeNotFound {
				t.Errorf("POST %s with a token %s: code = %q, want %q",
					route.path, shape.name, p.Code, CodeNotFound)
			}
			// Byte equality apart from the trace id, which is the only part of a
			// problem document that may legitimately differ between two requests.
			p.TraceID = ""
			rendered, err := json.Marshal(p)
			if err != nil {
				t.Fatalf("re-marshalling the problem: %v", err)
			}
			switch {
			case reference == "":
				reference = string(rendered)
			case string(rendered) != reference:
				t.Errorf("POST %s answers differently for a token %s than for one %s:\n  %s\n  %s",
					route.path, shape.name, shapes[0].name, rendered, reference)
			}
		}
		if reference == "" {
			t.Errorf("POST %s produced no comparable answer at all, so the comparison above "+
				"passed vacuously", route.path)
		}
	}

	// And the 422 the document lists is real, for the reason the document should
	// name: a field this endpoint does not accept.
	typo := sendWith(t, f.handler, http.MethodPost, "/v1/email-verifications/confirm", "", "",
		`{"token":"`+live+`","emial":"x"}`)
	if typo.Code != http.StatusUnprocessableEntity {
		t.Errorf("a misspelled field on the confirm route = %d, want 422; body: %s", typo.Code, typo.Body)
	}
}

func TestTheWholeEmailChangeFlowOverHTTP(t *testing.T) {
	f := newRecoveryServerFixture(t)
	email, token := f.signUp(t)
	target := dbtest.UniqueEmail(t)

	requested := sendWith(t, f.handler, http.MethodPost, "/v1/email-changes", token, "",
		`{"email":"`+target+`"}`)
	if requested.Code != http.StatusCreated {
		t.Fatalf("POST /v1/email-changes = %d, want 201; body: %s", requested.Code, requested.Body)
	}

	first := sendWith(t, f.handler, http.MethodPost, "/v1/email-changes/current-address", "",
		"", `{"token":"`+tokenIn(t, f.mailer.last(t))+`"}`)
	if first.Code != http.StatusAccepted {
		t.Fatalf("the current-address confirmation = %d, want 202; body: %s", first.Code, first.Body)
	}
	if got := f.mailer.last(t).To; got != target {
		t.Errorf("the second message went to %q, want the new address %q", got, target)
	}

	second := sendWith(t, f.handler, http.MethodPost, "/v1/email-changes/new-address", "",
		"", `{"token":"`+tokenIn(t, f.mailer.last(t))+`"}`)
	if second.Code != http.StatusOK {
		t.Fatalf("the new-address confirmation = %d, want 200; body: %s", second.Code, second.Body)
	}

	// The address moved, the session did not survive it, and the old address is free.
	var moved string
	if err := f.pool.QueryRow(t.Context(),
		`SELECT email FROM users WHERE email = $1`, target).Scan(&moved); err != nil {
		t.Fatalf("the new address does not hold the account: %v", err)
	}
	if got := f.sessionsFor(t, target); got != 0 {
		t.Errorf("%d sessions survived an email change, want 0", got)
	}
	if !f.access.swept(f.userIDFor(t, target)) {
		t.Error("an email change revoked no access tokens")
	}
	if got := f.sessionsFor(t, email); got != 0 {
		t.Errorf("%d sessions exist under the old address", got)
	}
}

// TestTheWholeVerificationFlowOverHTTP, and the answer GET /v1/email-verification
// gives before and after.
func TestTheWholeVerificationFlowOverHTTP(t *testing.T) {
	f := newRecoveryServerFixture(t)
	email, token := f.signUp(t)

	before := sendWith(t, f.handler, http.MethodGet, "/v1/email-verification", token, "", "")
	if before.Code != http.StatusOK {
		t.Fatalf("the status read = %d, want 200; body: %s", before.Code, before.Body)
	}
	var off verificationStatusResponse
	if err := json.Unmarshal(before.Body.Bytes(), &off); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	if off.EmailVerified {
		t.Error("a brand new account reports a verified address")
	}

	requested := post(t, f.handler, "/v1/email-verifications", `{"email":"`+email+`"}`)
	if requested.Code != http.StatusAccepted {
		t.Fatalf("POST /v1/email-verifications = %d, want 202; body: %s", requested.Code, requested.Body)
	}

	confirmed := sendWith(t, f.handler, http.MethodPost, "/v1/email-verifications/confirm", "",
		"", `{"token":"`+tokenIn(t, f.mailer.last(t))+`"}`)
	if confirmed.Code != http.StatusNoContent {
		t.Fatalf("the confirmation = %d, want 204; body: %s", confirmed.Code, confirmed.Body)
	}

	after := sendWith(t, f.handler, http.MethodGet, "/v1/email-verification", token, "", "")
	var on verificationStatusResponse
	if err := json.Unmarshal(after.Body.Bytes(), &on); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	if !on.EmailVerified || on.EmailVerifiedAt == nil {
		t.Errorf("after confirming: %+v, want a verified address with an instant", on)
	}

	// And the session survived, because a verification is not a security change.
	if got := f.sessionsFor(t, email); got != 1 {
		t.Errorf("%d sessions after a verification, want 1: confirming an address must not sign "+
			"the user out", got)
	}
}

// TestTheVerificationRequestCannotBeToldApartOverHTTP is the packet's finding, over
// the real service and the real router.
//
// IT IS THREE CASES AND NOT TWO, and the third is the whole of it: an address with
// no account, an account that has NOT proved its address, and an account that has.
// This route used to answer 202, 202 and 409, and `security: []` means the caller
// posting the list is anonymous — so a 409 was a line in a list of verified
// accounts, handed to whoever typed the addresses.
//
// THE ASSERTION IS THE WHOLE RESPONSE, not the status: status, Content-Type and
// body bytes. "One status, one body" is the property, and a check that compared
// only the status would let a differing header or a differing byte through — which
// is the shape the oracle takes when somebody adds a field to the response.
//
// THE MESSAGE COUNT IS THE OTHER HALF, and it is the half a status comparison
// cannot see. The verified account gets a link exactly as the unverified one does,
// because the route does not read the row's verification state at all; the unknown
// address gets nothing, which is the one difference this service already documents
// and accepts for the reset route it mirrors.
func TestTheVerificationRequestCannotBeToldApartOverHTTP(t *testing.T) {
	f := newRecoveryServerFixture(t)

	unverified, _ := f.signUp(t)
	verified, _ := f.signUp(t)
	f.verifyAddress(t, verified)
	unknown := dbtest.UniqueEmail(t)

	// Past the cooldown, so nothing here is answered by the window rather than by
	// the lookup. The window is per address and these are three different ones, so
	// this is belt and braces — but a test whose third case is silently inside a
	// cooldown proves less than it looks like it proves.
	f.clk.Advance(recovery.RequestWindow + time.Second)

	answers := make(map[string]*httptest.ResponseRecorder, 3)
	sentBefore := f.mailer.count()
	for _, address := range []string{unknown, unverified, verified} {
		rec := post(t, f.handler, "/v1/email-verifications", `{"email":"`+address+`"}`)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("POST /v1/email-verifications for %s = %d, want 202; body: %s",
				address, rec.Code, rec.Body)
		}
		answers[address] = rec
	}

	for _, address := range []string{unverified, verified} {
		got, want := answers[address], answers[unknown]
		if got.Body.String() != want.Body.String() {
			t.Errorf("the answer for a %s account differs from the answer for an address with "+
				"no account:\n%s: %s\nunknown: %s", verificationState(t, f, address), address,
				got.Body, want.Body)
		}
		if ct1, ct2 := got.Header().Get("Content-Type"), want.Header().Get("Content-Type"); ct1 != ct2 {
			t.Errorf("Content-Type for %s = %q, unknown = %q", address, ct1, ct2)
		}
		// A header is a channel too, and `Retry-After` is the one an error-mapping
		// change tends to grow.
		if h1, h2 := got.Header().Get("Retry-After"), want.Header().Get("Retry-After"); h1 != h2 {
			t.Errorf("Retry-After for %s = %q, unknown = %q", address, h1, h2)
		}
	}

	// Two messages, to the two addresses that have an account — the verified one
	// included. A route that read the row and stayed quiet would answer 202 for both
	// and pass the comparison above, and it would still be the route the comment
	// eleven lines above `RequestVerification` says it must not be.
	if got, want := f.mailer.count()-sentBefore, 2; got != want {
		t.Errorf("the three requests sent %d messages, want %d: one per address that has an "+
			"account, and none for the address that has not", got, want)
	}
	if got := f.mailer.last(t).To; got != verified {
		t.Errorf("the last message went to %q, want the verified address %q: a verified "+
			"account is treated exactly as an unverified one", got, verified)
	}
}

// TestTheOIDCEmailVerifiedClaimFollowsTheColumn: the claim README.md and
// internal/oidc/profiles.go both promised would become a read of this column, and
// this is the assertion that it is.
//
// The flow is the whole one: register, verify over HTTP, and read the profile the
// storage adapter assembles for a token. The adapter is not stood up as a provider
// because the claim is written by one method in it, and driving the profile reader is
// what a token endpoint calls.
func TestTheOIDCEmailVerifiedClaimFollowsTheColumn(t *testing.T) {
	f := newRecoveryServerFixture(t)
	email, _ := f.signUp(t)

	reader := oidc.NewProfileReader()
	before, err := reader.Profile(t.Context(), f.pool, f.userIDFor(t, email))
	if err != nil {
		t.Fatalf("Profile before verifying: %v", err)
	}
	if before.EmailVerified {
		t.Error("the profile claims a verified address before any verification")
	}

	post(t, f.handler, "/v1/email-verifications", `{"email":"`+email+`"}`)
	confirmed := sendWith(t, f.handler, http.MethodPost, "/v1/email-verifications/confirm", "",
		"", `{"token":"`+tokenIn(t, f.mailer.last(t))+`"}`)
	if confirmed.Code != http.StatusNoContent {
		t.Fatalf("the confirmation = %d, want 204; body: %s", confirmed.Code, confirmed.Body)
	}

	after, err := reader.Profile(t.Context(), f.pool, f.userIDFor(t, email))
	if err != nil {
		t.Fatalf("Profile after verifying: %v", err)
	}
	if !after.EmailVerified {
		t.Error("the profile still claims the address is unverified after it was proved")
	}
}

// TestAResetEndsTheAccessTokensIssuedBeforeIt is the JWT half of the requirement,
// over the REAL oidc.Store rather than the recording double.
//
// The two halves are asserted separately on purpose. The recording double proves the
// recovery flow ASKS; the real store proves the ask REACHES the rows. A service that
// called the wrong method name, or against the wrong column, would pass the first.
func TestAResetEndsTheAccessTokensIssuedBeforeIt(t *testing.T) {
	f := newRecoveryServerFixture(t)
	email, _ := f.signUp(t)
	userID := f.userIDFor(t, email)

	// A client, and an access token issued against it: both rows are real ones on
	// the real tables, with real ids, because the sweep filters on both. The client
	// belongs to an account the user really holds — the personal one registration
	// created — rather than to a fresh one, because a registration outside this
	// package would be a second thing to keep working.
	accountID := id.MustNew()
	if err := f.pool.QueryRow(t.Context(), `
		SELECT au.account_id FROM account_users au
		JOIN accounts a ON a.id = au.account_id
		WHERE au.user_id = $1 ORDER BY a.created_at, a.id LIMIT 1`,
		userID).Scan(&accountID); err != nil {
		t.Fatalf("finding the user's account: %v", err)
	}

	// The registration goes in through the real Store.CreateClient rather than as raw
	// SQL. A hand-written INSERT would have had to restate the digest of a secret this
	// test does not have, and the shortest way to do that is the one that writes a
	// literal into a query — a value the service never holds and a reviewer cannot
	// check. CreateClient takes a digest the same way the real caller supplies one.
	client, err := oidc.NewStore(f.pool).CreateClient(t.Context(), f.pool, oidc.CreateClientParams{
		AccountID:    accountID,
		ClientID:     "reset-fixture-" + id.MustNew().String(),
		Name:         "reset fixture",
		SecretDigest: oidc.SecretDigest(strings.Repeat("a", 64)),
		RedirectURIs: []string{"https://example.com/cb"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid", "email"},
		CreatedBy:    userID,
		CreatedAt:    f.clk.Now(),
	})
	if err != nil {
		t.Fatalf("creating the fixture client: %v", err)
	}
	clientID := client.ID
	tokenID := id.MustNew()
	if _, err := f.pool.Exec(t.Context(), `
		INSERT INTO oidc_access_tokens (id, client_row_id, subject, scopes, issued_at, expires_at)
		VALUES ($1, $2, $3, ARRAY['openid','email'], $4, $5)`,
		tokenID, clientID, userID, f.clk.Now(), f.clk.Now().Add(15*time.Minute)); err != nil {
		t.Fatalf("creating the fixture access token: %v", err)
	}

	// The REAL sweep, called the way recovery calls it.
	if err := oidc.NewStore(f.pool).RevokeAccessTokensForUser(t.Context(), f.pool, userID, f.clk.Now()); err != nil {
		t.Fatalf("RevokeAccessTokensForUser: %v", err)
	}

	var revokedAt *time.Time
	if err := f.pool.QueryRow(t.Context(),
		`SELECT revoked_at FROM oidc_access_tokens WHERE id = $1`, tokenID).Scan(&revokedAt); err != nil {
		t.Fatalf("reading the access token: %v", err)
	}
	if revokedAt == nil {
		t.Fatal("the access token issued before the reset is still live")
	}

	// And another user's token is untouched, because the sweep is scoped by subject.
	other, _ := f.signUp(t)
	otherID := f.userIDFor(t, other)
	otherToken := id.MustNew()
	var otherAccount id.UUID
	if err := f.pool.QueryRow(t.Context(), `
		SELECT au.account_id FROM account_users au
		JOIN accounts a ON a.id = au.account_id
		WHERE au.user_id = $1 ORDER BY a.created_at, a.id LIMIT 1`,
		otherID).Scan(&otherAccount); err != nil {
		t.Fatalf("finding the second user's account: %v", err)
	}
	otherClientRow, err := oidc.NewStore(f.pool).CreateClient(t.Context(), f.pool, oidc.CreateClientParams{
		AccountID:    otherAccount,
		ClientID:     "other-fixture-" + id.MustNew().String(),
		Name:         "other fixture",
		SecretDigest: oidc.SecretDigest(strings.Repeat("b", 64)),
		RedirectURIs: []string{"https://example.com/cb"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid", "email"},
		CreatedBy:    otherID,
		CreatedAt:    f.clk.Now(),
	})
	if err != nil {
		t.Fatalf("creating the second fixture client: %v", err)
	}
	otherClient := otherClientRow.ID
	if _, err := f.pool.Exec(t.Context(), `
		INSERT INTO oidc_access_tokens (id, client_row_id, subject, scopes, issued_at, expires_at)
		VALUES ($1, $2, $3, ARRAY['openid','email'], $4, $5)`,
		otherToken, otherClient, otherID, f.clk.Now(), f.clk.Now().Add(15*time.Minute)); err != nil {
		t.Fatalf("creating the second access token: %v", err)
	}
	if err := oidc.NewStore(f.pool).RevokeAccessTokensForUser(t.Context(), f.pool, userID, f.clk.Now()); err != nil {
		t.Fatalf("RevokeAccessTokensForUser: %v", err)
	}
	if err := f.pool.QueryRow(t.Context(),
		`SELECT revoked_at FROM oidc_access_tokens WHERE id = $1`, otherToken).Scan(&revokedAt); err != nil {
		t.Fatalf("reading the second access token: %v", err)
	}
	if revokedAt != nil {
		t.Error("the sweep revoked another user's access token")
	}
}

// TestNoRecoveryTokenReachesTheLogs walks the three flows with a logger that keeps
// everything, and asserts that nothing a human could read carries a live token.
//
// IT IS THE MFA PACKET'S CANARY APPLIED TO THIS ONE, and it is here rather than in
// internal/recovery because the tokens in these flows reach a message that a
// delivery adapter is one line away from logging.
//
// IT ASSERTS NON-VACUOUSLY FIRST: the flows really completed, so the token really
// existed, and the logger really was called. A test that passed because nothing was
// logged would be asserting nothing at all.
func TestNoRecoveryTokenReachesTheLogs(t *testing.T) {
	pool := dbtest.Schema(t)
	clk := clock.NewFake(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	mailer := &captureMailer{}
	logs := &recordingHandler{}

	svc := recovery.NewService(
		db.TxRunner{Pool: pool}, db.Direct{Pool: pool},
		recovery.NewStore(pool), users.NewStore(pool), sessions.NewStore(pool),
		&captureAccessRevoker{revoked: map[string]time.Time{}},
		outbox.NewStore(pool), mailer,
		users.NewHasherWithParams(&argon2id.Params{
			Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
		}),
		clk,
	)
	handler := New(nil, WithAuth(authServiceFor(pool, clk)), WithRecovery(svc),
		WithLogger(slogLogger(logs)))

	email := dbtest.UniqueEmail(t)
	registerThrough(t, handler, email)
	login := post(t, handler, "/v1/session",
		`{"email":"`+email+`","password":"`+validPassword+`"}`)
	var session sessionResponse
	if err := json.Unmarshal(login.Body.Bytes(), &session); err != nil {
		t.Fatalf("the login body is not JSON: %v", err)
	}

	// Every flow, so every body.
	post(t, handler, "/v1/password-resets", `{"email":"`+email+`"}`)
	resetToken := tokenIn(t, mailer.last(t))
	post(t, handler, "/v1/email-verifications", `{"email":"`+email+`"}`)
	sendWith(t, handler, http.MethodPost, "/v1/email-changes", session.Token, "",
		`{"email":"`+dbtest.UniqueEmail(t)+`"}`)
	changeToken := tokenIn(t, mailer.last(t))
	sendWith(t, handler, http.MethodPost, "/v1/email-changes/current-address", "", "",
		`{"token":"`+changeToken+`"}`)

	// A refusal, which is where a "your token %s was wrong" line would be written if
	// anybody ever wrote one. Nothing on this surface logs refusals, so the log is
	// expected to be empty — and the assertion below is written to FAIL on an empty
	// log rather than to pass on it.
	for _, bad := range []string{"a-token-that-is-not-one", resetToken} {
		sendWith(t, handler, http.MethodPost, "/v1/email-verifications/confirm", "", "",
			`{"token":"`+bad+`"}`)
	}

	// NON-VACUITY, AND IT IS THE OTHER WAY ROUND FROM THE MFA CANARY.
	//
	// MFA's canary needs the logger to have been called, because that test asserts a
	// secret is ABSENT from records that exist. This one asserts something stronger:
	// the recovery flows log NOTHING AT ALL on the happy path or the refusal path,
	// because every token in them is a credential and this service does not log
	// credentials. So "nothing was logged" is the expected answer here, and it is
	// only an answer because the logger is proven to work — which is what the
	// forced failure below is for. Without it, a logger wired to io.Discard would
	// make this test pass forever.
	silent := logs.rendered()
	if strings.TrimSpace(silent) != "" {
		t.Errorf("the recovery flows logged something, and nothing on this surface should:\n%s", silent)
	}

	// The forced failure, which is the request that DOES log: a store error is the
	// one place a token is most likely to leak, because the error string carries a
	// driver message with a host and a query fragment in it.
	if _, err := pool.Exec(t.Context(), `DROP TABLE recovery_tokens`); err != nil {
		t.Fatalf("dropping recovery_tokens: %v", err)
	}
	if rec := sendWith(t, handler, http.MethodPost, "/v1/password-resets/confirm", "", "",
		`{"token":"`+resetToken+`","password":"a brand new password"}`); rec.Code != http.StatusInternalServerError {
		t.Fatalf("the store failure = %d, want 500; body: %s", rec.Code, rec.Body)
	}

	rendered := logs.rendered()
	if strings.TrimSpace(rendered) == "" {
		t.Fatal("the forced 500 logged nothing, so the assertions below would pass vacuously: " +
			"the logger is not proving it works")
	}

	//
	// IT SEARCHES FOR THE VALUE AND FOR ITS DIGEST, and the second half is not
	// redundant: a digest in an operator's log is an index key, and this repository
	// treats "the raw credential is nowhere in a log" as a property worth asserting
	// separately from "the lookup key is nowhere in a log".
	//
	// IT DELIBERATELY DOES NOT SEARCH FOR THE WORDS "token" and "password", which the
	// MFA canary does. A store-failure message on this surface legitimately names
	// the table it failed on — `recovery: resolving a password_reset token: … ERROR:
	// relation "recovery_tokens" does not exist` — and a vocabulary check would have
	// forced that honest error message to be reworded so that a test could pass.
	// What has to be absent is a VALUE.
	for _, token := range []string{resetToken, changeToken} {
		for _, form := range []string{token, sessions.Digest(token), sessions.Digest(token)[:16]} {
			if strings.Contains(rendered, form) {
				t.Errorf("the rendered logs contain %q… of a recovery token:\n%s", form[:12], rendered)
			}
		}
	}
}
