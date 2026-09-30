package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cafaye/identity/internal/accounts"
	"github.com/cafaye/identity/internal/apikeys"
	"github.com/cafaye/identity/internal/oidc"
	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/users"
)

// EVERYTHING THE PACKET ASKS TO BE PROVEN, OVER THE REAL ROUTER AND THE REAL SQL.
//
// The unit tests in apikeys_test.go and apikeys_test.go's store half assert the
// use cases and the schema. This file asserts the thing a client and a resource
// server actually experiences, which is the only place four of the packet's
// requirements can be proven at all:
//
//   - the secret is shown once, and nowhere else on the wire or at rest;
//   - a token's authority is re-evaluated, so a membership removed after issuance
//     stops it on the next request;
//   - a scope is enforced ON A ROUTE, not in a comparison function;
//   - nothing about a credential reaches a log, on the success path or the 500
//     path.

// apiKeyServer is the real service over a private schema.
type apiKeyServer struct {
	handler http.Handler
	pool    *pgxpool.Pool
	clk     *clock.Fake
	keys    *apikeys.Service
	logs    *recordingHandler

	// session is the browser credential for the fixture's user, and token is the
	// scoped credential the tests mint through the API. The plaintext is held here
	// and nowhere else on purpose: a field on a fixture that a failing assertion
	// might print is the leak this packet exists to avoid, and the brief is explicit
	// that a test which prints a created credential is a leak with a test-shaped
	// hat. A test that needs to identify a token uses its id or its name.
	session string
	token   string
	// keyID is the row id of `token`, which is what an audit line or a revoke
	// request uses.
	keyID id.UUID

	user    users.User
	email   string
	account id.UUID
	// elsewhere is a second account the user owns, for the "a token is bound to one
	// account" case. The user's own personal account is this one.
	elsewhere id.UUID
}

func newAPIKeyServer(t *testing.T) *apiKeyServer {
	t.Helper()

	pool := dbtest.Schema(t)
	clk := clock.NewFake(time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))
	tenancy := realTenancy(pool, clk)
	authSvc := authServiceFor(pool, clk)
	keys := matrixAPIKeys(pool, clk, tenancy)
	logs := &recordingHandler{}

	s := &apiKeyServer{
		pool: pool, clk: clk, keys: keys, logs: logs,
		handler: New(nil,
			WithAuth(authSvc),
			WithTenancy(tenancy),
			WithOIDCClients(matrixOIDCClients(t, pool, clk)),
			WithOIDC(newFakeOIDC()),
			WithAPIKeys(keys),
			WithAPIKeyCaller(keys),
			WithIntrospection(keys),
			// The same fake clock the use cases read, handed to the HTTP layer so a
			// token is resolved against the same instant its row was written with. It
			// is what lets a test age a credential out without sleeping — and what
			// would have made the expiry case below silently test nothing if the
			// layer were calling time.Now() itself.
			WithClock(clk),
			WithLogger(slogLogger(logs)),
		),
	}

	// The user is created through the real registration, so the personal account,
	// the owner membership and the session are all rows the production path
	// wrote. A fixture that hand-inserted them could not catch a route that
	// assumed something about the account a registration creates.
	email := dbtest.UniqueEmail(t)
	registered := post(t, s.handler, "/v1/users",
		`{"email":"`+email+`","password":"`+matrixPassword+`"}`)
	if registered.Code != http.StatusCreated {
		t.Fatalf("registering: %d; body: %s", registered.Code, registered.Body)
	}
	var created userResponse
	if err := json.Unmarshal(registered.Body.Bytes(), &created); err != nil {
		t.Fatalf("decoding the registration: %v", err)
	}
	parsed, err := id.Parse(created.ID)
	if err != nil {
		t.Fatalf("the service returned an id that does not parse: %v", err)
	}
	s.user = users.User{ID: parsed, Email: created.Email}
	s.email = created.Email

	login := post(t, s.handler, "/v1/session",
		`{"email":"`+email+`","password":"`+matrixPassword+`"}`)
	if login.Code != http.StatusOK {
		t.Fatalf("signing in: %d; body: %s", login.Code, login.Body)
	}
	var session sessionResponse
	if err := json.Unmarshal(login.Body.Bytes(), &session); err != nil {
		t.Fatalf("decoding the login: %v", err)
	}
	s.session = session.Token

	// The personal account the registration created, and a second one to act on.
	list := apiKeyGet(t, s.handler, "/v1/accounts", s.session)
	if list.Code != http.StatusOK {
		t.Fatalf("listing accounts: %d; body: %s", list.Code, list.Body)
	}
	var listed []accountListItem
	if err := json.Unmarshal(list.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decoding the account list: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("a fresh registration holds %d accounts, want 1", len(listed))
	}
	if s.account, err = id.Parse(listed[0].ID); err != nil {
		t.Fatalf("parsing the account id: %v", err)
	}

	second, err := tenancy.Create(context.Background(), accounts.CreateInput{
		Name: "Second account", Owner: s.user.ID,
	})
	if err != nil {
		t.Fatalf("creating the second account: %v", err)
	}
	s.elsewhere = second.Account.ID

	return s
}

// mint creates a credential through the API and keeps the plaintext in s.token.
//
// The secret is returned to the CALLER rather than stored on the fixture alone,
// because several tests need two live tokens at once and a single field cannot
// hold both. A test that needs to identify a token afterwards uses keyID or the
// name.
func (s *apiKeyServer) mint(t *testing.T, name string, scopes ...string) (id.UUID, string) {
	t.Helper()

	body := fmt.Sprintf(`{"name":%q,"scopes":[`, name)
	for i, scope := range scopes {
		if i > 0 {
			body += ","
		}
		body += fmt.Sprintf("%q", scope)
	}
	body += `]}`

	rec := apiKeyPost(t, s.handler, apiKeyPath(s.account), s.session, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("minting %q: %d; body: %s", name, rec.Code, rec.Body)
	}

	var issued issuedAPIKeyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &issued); err != nil {
		t.Fatalf("decoding the issued key: %v\n%s", err, rec.Body)
	}
	parsed, err := id.Parse(issued.ID)
	if err != nil {
		t.Fatalf("the service returned an id that does not parse: %v", err)
	}
	return parsed, issued.Token
}

// mintInto mints against a named account rather than the fixture's own.
func (s *apiKeyServer) mintInto(t *testing.T, account id.UUID, name string, scopes ...string) (id.UUID, string) {
	t.Helper()

	body := fmt.Sprintf(`{"name":%q,"scopes":[`, name)
	for i, scope := range scopes {
		if i > 0 {
			body += ","
		}
		body += fmt.Sprintf("%q", scope)
	}
	body += `]}`

	rec := apiKeyPost(t, s.handler, apiKeyPath(account), s.session, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("minting %q into %s: %d; body: %s", name, account, rec.Code, rec.Body)
	}
	var issued issuedAPIKeyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &issued); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	parsed, err := id.Parse(issued.ID)
	if err != nil {
		t.Fatalf("parsing the id: %v", err)
	}
	return parsed, issued.Token
}

// bearer issues a request as a scoped token.
func (s *apiKeyServer) bearer(t *testing.T, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	return apiKeySend(t, s.handler, method, path, token, body)
}

// ---------------------------------------------------------------------------
// the secret, once
// ---------------------------------------------------------------------------

// TestTheSecretIsOnTheWireOnceAndNowhereElse is the packet's one-time-display
// requirement, proven on the wire and at rest.
//
// FOUR CLAIMS, and the last two are the ones that are easy to claim and easy to
// get subtly untrue:
//
//  1. the 201 carries it;
//  2. the list, the single-token reads and the introspection response do not;
//  3. the DATABASE does not — every text column of the row, the whole table, and
//     every event payload in the outbox, searched for the plaintext, for the
//     plaintext without its prefix, and for the plaintext's digest;
//  4. the LOGS do not, asserted non-vacuously below.
func TestTheSecretIsOnTheWireOnceAndNowhereElse(t *testing.T) {
	s := newAPIKeyServer(t)

	keyID, secret := s.mint(t, "ci-deploy", apikeys.ScopeAccountsRead)
	s.keyID, s.token = keyID, secret

	// (1) it came back once.
	if !strings.HasPrefix(secret, apikeys.Prefix) {
		t.Fatalf("the issued token does not carry the %q prefix", apikeys.Prefix)
	}

	// (2) no other response on the surface carries it.
	withoutPrefix := strings.TrimPrefix(secret, apikeys.Prefix)
	for _, tt := range []struct {
		name string
		do   func() *httptest.ResponseRecorder
	}{
		{"the list", func() *httptest.ResponseRecorder {
			return apiKeyGet(t, s.handler, apiKeyPath(s.account), s.session)
		}},
		{"the account", func() *httptest.ResponseRecorder {
			return apiKeyGet(t, s.handler, "/v1/accounts/"+s.account.String(), s.session)
		}},
		{"the members", func() *httptest.ResponseRecorder {
			return apiKeyGet(t, s.handler, "/v1/accounts/"+s.account.String()+"/members", s.session)
		}},
		{"introspection of itself", func() *httptest.ResponseRecorder {
			return apiKeySend(t, s.handler, http.MethodPost, "/v1/introspections", s.session,
				`{"token":"`+secret+`"}`)
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rec := tt.do()
			for _, forbidden := range []string{secret, withoutPrefix} {
				if strings.Contains(rec.Body.String(), forbidden) {
					t.Errorf("the %s response carries the secret: %s", tt.name, rec.Body)
				}
			}
		})
	}

	// (3) at rest. The row, the whole table, and every event payload.
	digest := apikeys.Digest(secret)
	rendered := s.renderEverywhere(t, keyID)
	for _, forbidden := range []string{secret, withoutPrefix, strings.ToLower(secret)} {
		if strings.Contains(rendered, forbidden) {
			t.Errorf("the plaintext is at rest somewhere; the rendered row, table and outbox contain %q", forbidden)
		}
	}
	// The digest IS there — otherwise this test would pass on a table that stored
	// nothing at all, which is a different bug and a worse one.
	if !strings.Contains(rendered, digest) {
		t.Errorf("the digest is not in the row, so the search above proves nothing:\n%s", rendered)
	}
	if digest == secret {
		t.Error("the digest IS the secret")
	}
}

// renderEverywhere is every place this credential could be at rest, as one string:
// the whole row, the whole table, and every event the mint and the revoke
// announced.
//
// It is a real search over the database and not a comment, which is the packet's
// explicit requirement — "the test should be a real one (search the row, search the
// audit/outbox payload), not a comment".
func (s *apiKeyServer) renderEverywhere(t *testing.T, keyID id.UUID) string {
	t.Helper()
	ctx := context.Background()

	var row string
	if err := s.pool.QueryRow(ctx,
		`SELECT row_to_json(api_keys)::text FROM api_keys WHERE id = $1`, keyID).Scan(&row); err != nil {
		t.Fatalf("rendering the row: %v", err)
	}

	var table string
	if err := s.pool.QueryRow(ctx,
		`SELECT coalesce(string_agg(row_to_json(api_keys)::text, E'\n'), '') FROM api_keys`).Scan(&table); err != nil {
		t.Fatalf("rendering the table: %v", err)
	}

	// The outbox is a separate store with its own retention, which is precisely
	// why a secret in an event would outlive the row it came from.
	var events string
	if err := s.pool.QueryRow(ctx,
		`SELECT coalesce(string_agg(envelope::text, E'\n'), '') FROM outbox_events`).Scan(&events); err != nil {
		t.Fatalf("rendering the outbox: %v", err)
	}

	return "ROW:\n" + row + "\nTABLE:\n" + table + "\nOUTBOX:\n" + events
}

// ---------------------------------------------------------------------------
// a token outlives nothing
// ---------------------------------------------------------------------------

// TestARemovedMembershipStopsTheTokenOnTheNextRequest is the case the brief calls
// "the one that is usually missed", asserted where it is felt: at a route.
//
// A token is minted while the user owns the account and works. The membership is
// then removed — an offboarding, not a revocation — and the SAME request that
// worked a moment ago is refused. Nothing about the token was changed: not its
// scopes, not its expiry, not its row. What changed is the membership, and the
// route reads that on every request.
//
// The second half is the one that makes it a design rather than an accident: the
// user is RE-INVITED at the same role, and the token does not come back. A token
// whose authority were snapshotted would revive with the membership, which is the
// resurrection this packet exists to prevent.
func TestARemovedMembershipStopsTheTokenOnTheNextRequest(t *testing.T) {
	s := newAPIKeyServer(t)
	keyID, secret := s.mint(t, "deploy", apikeys.ScopeAccountsRead)
	s.keyID, s.token = keyID, secret

	// Live: the tenant read the scope names.
	read := s.bearer(t, http.MethodGet, "/v1/accounts/"+s.account.String(), secret, "")
	if read.Code != http.StatusOK {
		t.Fatalf("a fresh token reading its account = %d, want 200; body: %s", read.Code, read.Body)
	}

	// Removed. accounts.Service.RemoveMember, so the write is the one the admin API
	// will make and the membership row is really gone. A helper owner performs it,
	// because the last owner of an account may not be removed and because the user
	// being removed is the caller whose token is under test.
	helper := s.promoteHelper(t, s.account)
	if err := s.removeMember(t, s.account, s.user.ID, helper); err != nil {
		t.Fatalf("removing the membership: %v", err)
	}

	refused := s.bearer(t, http.MethodGet, "/v1/accounts/"+s.account.String(), secret, "")
	if refused.Code != http.StatusUnauthorized {
		t.Fatalf("after the membership was removed the token got %d, want 401; body: %s",
			refused.Code, refused.Body)
	}
	// 401 AND NOT 404, and the reason is worth a line because it is the opposite of
	// what a reader might expect from the account routes' non-member rule.
	//
	// That 404 is about a SESSION caller who is not in the account: they are
	// authenticated, and the account is not theirs to know about. Here the CREDENTIAL
	// is dead — the token resolves to no caller at all, because its owner holds no
	// membership — so it is the same 401 as a revoked or expired one, and saying so
	// is what keeps the four indistinguishable. Turning it into a 404 would tell a
	// caller holding a leaked token that its value was once live in this account.
	if p := decodeProblem(t, refused); p.Code != CodeUnauthorized {
		t.Errorf("code = %q, want %q", p.Code, CodeUnauthorized)
	}

	// Re-invited at the same role, through the real invitation flow.
	if err := s.readmit(t, helper); err != nil {
		t.Fatalf("re-inviting: %v", err)
	}
	resurrected := s.bearer(t, http.MethodGet, "/v1/accounts/"+s.account.String(), secret, "")
	if resurrected.Code == http.StatusOK {
		t.Error("the token works again after the user was re-invited. Its authority was " +
			"snapshotted somewhere, or a removed contractor's credential revives with a " +
			"membership — which is the resurrection this packet exists to prevent")
	}
	if resurrected.Code != http.StatusUnauthorized {
		t.Errorf("after re-invitation the token got %d, want 401; body: %s", resurrected.Code, resurrected.Body)
	}

	// The row is still there — a revocation, not a delete — and it says honestly WHY
	// it stopped working. "membership removed" is a closed value rather than free
	// text, so an operator reading the list and a consumer reading the row can both
	// tell this apart from a credential somebody withdrew by hand.
	stored := s.row(t, s.keyID)
	if stored == "" {
		t.Fatal("the row was deleted; an operator asking whether a credential was revoked " +
			"or the membership was removed has no answer")
	}
	if strings.Contains(stored, `"revoked_at":null`) {
		t.Errorf("the row is not marked revoked, so the removal did not revoke it and the "+
			"token is only dead while the membership is missing — which is the "+
			"resurrection:\n%s", stored)
	}
	if !strings.Contains(stored, "membership removed") {
		t.Errorf("the row does not say the membership was removed:\n%s", stored)
	}
}

// TestADemotionStopsTheTokenOnOwnerOnlyRoutes is the same property one step down,
// and it is the one that is easy to miss in the OTHER direction: the token keeps
// working, and what changes is which routes it can reach.
func TestADemotionStopsTheTokenOnOwnerOnlyRoutes(t *testing.T) {
	s := newAPIKeyServer(t)
	// Both scopes, so the refusal below is about the ROLE and not about a scope the
	// token happens not to carry. A test that minted only the owner-only scope would
	// see 403 for the wrong reason on the member-level route, and would pass while
	// proving nothing about the demotion.
	_, secret := s.mint(t, "deploy", apikeys.ScopeOIDCClientsWrite, apikeys.ScopeAccountsRead)

	before := s.bearer(t, http.MethodGet,
		"/v1/accounts/"+s.account.String()+"/oidc-clients", secret, "")
	if before.Code != http.StatusOK {
		t.Fatalf("an owner's token listing clients = %d, want 200; body: %s", before.Code, before.Body)
	}

	if err := s.demote(t, s.account, s.user.ID, accounts.RoleMember); err != nil {
		t.Fatalf("demoting: %v", err)
	}

	after := s.bearer(t, http.MethodGet,
		"/v1/accounts/"+s.account.String()+"/oidc-clients", secret, "")
	if after.Code != http.StatusForbidden {
		t.Fatalf("after the demotion the same request got %d, want 403; body: %s", after.Code, after.Body)
	}
	// 403 and not 404, because the caller IS still a member: a 404 would tell a
	// member their own account does not exist, and 403 leaks nothing to somebody who
	// can already see it.
	if p := decodeProblem(t, after); p.Code != CodeForbidden {
		t.Errorf("code = %q, want %q", p.Code, CodeForbidden)
	}

	// And a route the demotion does not close still works, which is what proves the
	// role is being re-read rather than the token being disabled wholesale.
	stillWorks := s.bearer(t, http.MethodGet, "/v1/accounts/"+s.account.String(), secret, "")
	if stillWorks.Code != http.StatusOK {
		t.Errorf("a demoted member's token lost a member-level route too: %d; body: %s",
			stillWorks.Code, stillWorks.Body)
	}
}

// TestATokenIsBoundToTheAccountItWasMintedFor: core's rule is that tenancy comes
// from the credential and never from the path, and this is the cross-tenant case
// with the caller holding every scope in the vocabulary.
func TestATokenIsBoundToTheAccountItWasMintedFor(t *testing.T) {
	s := newAPIKeyServer(t)
	// Every scope, so nothing about the refusal can be a missing scope.
	_, secret := s.mint(t, "deploy", apikeys.AllScopes()...)

	// Its own account: fine.
	own := s.bearer(t, http.MethodGet, "/v1/accounts/"+s.account.String(), secret, "")
	if own.Code != http.StatusOK {
		t.Fatalf("= %d, want 200; body: %s", own.Code, own.Body)
	}

	// The other account, which the same user also owns. The caller is a member
	// there — the ROLE check passes — and the account binding is the only thing
	// that refuses. 404, the same answer a stranger gets, because a token reaching
	// across tenants must be indistinguishable from one that has never heard of it.
	other := s.bearer(t, http.MethodGet, "/v1/accounts/"+s.elsewhere.String(), secret, "")
	if other.Code != http.StatusNotFound {
		t.Fatalf("a token for one account reaching another = %d, want 404; body: %s", other.Code, other.Body)
	}

	// A write is refused the same way. A read-only answer here would mean the
	// binding is enforced on some routes and not others.
	otherWrite := s.bearer(t, http.MethodPatch, "/v1/accounts/"+s.elsewhere.String(), secret, `{"name":"x"}`)
	if otherWrite.Code != http.StatusNotFound {
		t.Errorf("a cross-tenant write = %d, want 404; body: %s", otherWrite.Code, otherWrite.Body)
	}
}

// ---------------------------------------------------------------------------
// scope enforcement, at the point of use
// ---------------------------------------------------------------------------

// TestScopeEnforcementIsWiredToTheRoutes is the packet's "a scope check that is not
// wired to a route is a comment with a type", asserted by making requests.
//
// IT IS A TABLE AND NOT A UNIT TEST of HasScope, and the reason is that a
// comparison function cannot fail this way: it is possible to write a perfect
// HasScope, wire it into nothing, and have every test of the function pass. So
// every row here is a real HTTP request against the real router with a real token
// carrying exactly one scope, and the expected answer is derived from the route's
// own declared scope rather than written out longhand.
func TestScopeEnforcementIsWiredToTheRoutes(t *testing.T) {
	type routeCase struct {
		method string
		path   string
		body   string
	}

	// ONE SERVER PER SCOPE, not one server and four tokens. The table includes
	// `DELETE /v1/accounts/{id}`, and a token holding `accounts:delete` really does
	// delete its own account — which is the route working. On a shared fixture that
	// would take the account out from under the three subtests after it, and the
	// next mint would 404 for a reason that has nothing to do with scopes. The
	// paths are built per server for the same reason: each has its own account id.
	for _, scope := range apikeys.AllScopes() {
		t.Run(scope, func(t *testing.T) {
			s := newAPIKeyServer(t)
			account := s.account.String()

			routes := []routeCase{
				// The collection route, which has NO row in the scope table: a token
				// is refused there outright, whatever it holds. It is in the table so
				// that the "no scope for this" case is a request and not an absence.
				{http.MethodGet, "/v1/accounts", ""},
				{http.MethodGet, "/v1/accounts/" + account, ""},
				{http.MethodGet, "/v1/accounts/" + account + "/members", ""},
				{http.MethodPatch, "/v1/accounts/" + account, `{"name":"Renamed"}`},
				{http.MethodPost, "/v1/accounts/" + account + "/invitations",
					`{"email":"` + dbtest.UniqueEmail(t) + `","role":"member"}`},
				{http.MethodGet, "/v1/accounts/" + account + "/oidc-clients", ""},
				{http.MethodPost, "/v1/accounts/" + account + "/oidc-clients",
					`{"name":"c","redirect_uris":["https://c.example.com/cb"],"grant_types":["authorization_code"],"scopes":["openid"]}`},
				// The credential surface, which is closed to EVERY token including one
				// holding accounts:write. It has no row in the scope table and that is
				// the refusal.
				{http.MethodGet, apiKeyPath(s.account), ""},
				{http.MethodPost, apiKeyPath(s.account), `{"name":"nested","scopes":["accounts:read"]}`},
			}

			_, secret := s.mint(t, "only-"+strings.ReplaceAll(scope, ":", "-"), scope)

			for _, route := range routes {
				s.expectScopeAnswer(t, route.method, route.path, route.body, scope, secret)
			}

			// The destructive route is LAST and on its own server. A token holding
			// accounts:delete really does delete the account it was issued for — that
			// is the route working — so running it in the table above would take the
			// fixture out from under the rows after it, and every one of those would
			// then be asserting about a cascade rather than about a scope.
			own := newAPIKeyServer(t)
			_, deleteSecret := own.mint(t, "only-delete", scope)
			own.expectScopeAnswer(t, http.MethodDelete, "/v1/accounts/"+own.account.String(), "",
				scope, deleteSecret)
		})
	}
}

// expectScopeAnswer is one row of the table: the expected answer is DERIVED from
// the route's declared scope and the token's, so a route that changes its scope
// changes this test's expectation rather than needing a new row written out.
func (s *apiKeyServer) expectScopeAnswer(t *testing.T, method, path, body, held, secret string) {
	t.Helper()

	required := s.requiredScope(method, path)
	rec := s.bearer(t, method, path, secret, body)

	switch {
	case required == "":
		// No declared scope, so no token may reach it — whatever it holds. 403
		// rather than 401, because the caller IS authenticated and a 401 would send
		// the developer looking for a login problem.
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s with %q = %d, want 403: no scope reaches this route",
				method, path, held, rec.Code)
		}
	case required == held:
		// Allowed by the scope. It may still be refused for a reason the scope is
		// not about — the route's minimum role, a body this fixture did not render —
		// and those are not what this test is for. What must not happen is a scope
		// refusal.
		if rec.Code == http.StatusForbidden && strings.Contains(rec.Body.String(), "does not carry the") {
			t.Errorf("%s %s refused a token holding %q", method, path, held)
		}
	default:
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s with only %q = %d, want 403; body: %s",
				method, path, held, rec.Code, rec.Body)
			return
		}
		// The refusal names the scope that is missing, which is guard's own detail
		// wording and the reason a developer can fix it.
		if !strings.Contains(rec.Body.String(), required) {
			t.Errorf("%s %s refused without naming %q: %s", method, path, required, rec.Body)
		}
	}
}

// requiredScope is the scope the route table declares for a path, matched on the
// chi pattern rather than on the concrete ids.
func (s *apiKeyServer) requiredScope(method, path string) string {
	for route, scope := range accountRouteScopes {
		parts := strings.SplitN(route, " ", 2)
		if len(parts) != 2 || parts[0] != method {
			continue
		}
		pattern := parts[1]
		// The concrete path has uuids where the pattern has parameters; compare the
		// shape by replacing every uuid in the path with the parameter name is not
		// possible, so the table is walked the other way: build the pattern from
		// this path and see whether it is one of the table's.
		if matchesPattern(pattern, path) {
			return scope
		}
	}
	return ""
}

// matchesPattern reports whether a chi pattern accounts for a concrete path.
func matchesPattern(pattern, path string) bool {
	patternParts := strings.Split(strings.Trim(pattern, "/"), "/")
	pathParts := strings.Split(strings.Trim(path, "/"), "/")
	if len(patternParts) != len(pathParts) {
		return false
	}
	for i, want := range patternParts {
		got := pathParts[i]
		if strings.HasPrefix(want, "{") && strings.HasSuffix(want, "}") {
			if _, err := id.Parse(got); err != nil {
				return false
			}
			continue
		}
		if want != got {
			return false
		}
	}
	return true
}

// TestATokenCannotManageTheCredentialSurfaceOverTheRealRouter is the negative
// case with a real token: every scope in the vocabulary, and the three routes that
// have no scope for them.
func TestATokenCannotManageTheCredentialSurfaceOverTheRealRouter(t *testing.T) {
	s := newAPIKeyServer(t)
	_, secret := s.mint(t, "everything", apikeys.AllScopes()...)

	for _, tt := range []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, apiKeyPath(s.account), ""},
		{http.MethodPost, apiKeyPath(s.account), `{"name":"nested","scopes":["accounts:read"]}`},
		{http.MethodDelete, apiKeyPath(s.account) + "/" + s.keyID.String(), ""},
	} {
		rec := s.bearer(t, tt.method, tt.path, secret, tt.body)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s with every scope = %d, want 403; body: %s",
				tt.method, tt.path, rec.Code, rec.Body)
		}
	}
	// And no row was written by the refused mint.
	if n := s.countKeys(t); n != 1 {
		t.Errorf("a refused mint left %d keys, want 1", n)
	}
}

// TestATokenCannotReachTheSecondFactor: there is no scope for MFA, and a token
// presenting to the management surface is refused outright rather than having a
// scope list consulted. The detail says why, so a developer can tell a policy
// decision from a typo.
func TestATokenCannotReachTheSecondFactor(t *testing.T) {
	s := newAPIKeyServer(t)
	_, secret := s.mint(t, "deploy", apikeys.AllScopes()...)

	for _, tt := range []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/v1/mfa", ""},
		{http.MethodPost, "/v1/mfa/enrollments", `{}`},
		{http.MethodPost, "/v1/mfa/recovery-codes", `{"code":"000000"}`},
		{http.MethodDelete, "/v1/mfa", `{"code":"000000"}`},
		// And it cannot log out a browser session either.
		{http.MethodDelete, "/v1/session", ""},
	} {
		rec := s.bearer(t, tt.method, tt.path, secret, tt.body)
		if rec.Code == http.StatusOK || rec.Code == http.StatusCreated || rec.Code == http.StatusNoContent {
			t.Errorf("%s %s with every scope = %d; a machine credential reached a surface "+
				"it has no scope for", tt.method, tt.path, rec.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// refusals are indistinguishable
// ---------------------------------------------------------------------------

// TestEveryRefusalIsTheSameResponse is the timing story's other half, and it is
// testable without a clock: a caller who can tell two refusals apart has an oracle
// whether the tell is a status code, a body, a header or a query plan.
//
// THE CASES ARE THE FOUR THE PACKET NAMES plus the two that arrive from a paste
// accident. A session token, an OIDC-shaped JWT, a truncated value and the digest
// itself are all things a machine will present at this endpoint eventually, and
// each of them has to cost the same answer.
func TestEveryRefusalIsTheSameResponse(t *testing.T) {
	s := newAPIKeyServer(t)
	revokedID, revokedSecret := s.mint(t, "to-revoke", apikeys.ScopeAccountsRead)
	if rec := s.bearer(t, http.MethodDelete, apiKeyPath(s.account)+"/"+revokedID.String(), s.session, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("revoking: %d; body: %s", rec.Code, rec.Body)
	}

	// An expired one. The lifetime is asked for through the API in SECONDS, which is
	// the wire shape, and the clock is moved past it — moving the clock by the
	// default lifetime instead would be a slower test that proves the same thing.
	shortRec := apiKeyPost(t, s.handler, apiKeyPath(s.account), s.session,
		`{"name":"to-expire","scopes":["accounts:read"],"expires_in":86400}`)
	if shortRec.Code != http.StatusCreated {
		t.Fatalf("minting a short-lived key: %d; body: %s", shortRec.Code, shortRec.Body)
	}
	var short issuedAPIKeyResponse
	if err := json.Unmarshal(shortRec.Body.Bytes(), &short); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	shortSecret := short.Token
	s.clk.Advance(25 * time.Hour)

	cases := []struct {
		name  string
		token string
	}{
		{name: "a revoked token", token: revokedSecret},
		{name: "an expired token", token: shortSecret},
		{name: "a token that never existed", token: apikeys.Prefix + strings.Repeat("Z", 43)},
		{name: "a truncated paste", token: revokedSecret[:20]},
		{name: "the prefix alone", token: apikeys.Prefix},
		{name: "an empty bearer", token: ""},
		{name: "a session token", token: s.session},
		{name: "an OIDC-shaped JWT", token: "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln"},
		{name: "the digest, presented as a token", token: apikeys.Digest(revokedSecret)},
		{name: "binary noise", token: "\x00\x01\x02\x03"},
	}

	var reference *httptest.ResponseRecorder
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			rec := s.bearer(t, http.MethodGet, "/v1/accounts/"+s.account.String(), tt.token, "")
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("= %d, want 401; body: %s", rec.Code, rec.Body)
			}
			p := decodeProblem(t, rec)
			if p.Code != CodeUnauthorized {
				t.Errorf("code = %q, want %q", p.Code, CodeUnauthorized)
			}
			// The trace id is per-request and is allowed to differ; the problem's
			// type, title, status and code are not, because they are the part a
			// caller can compare.
			if reference == nil {
				reference = rec
				return
			}
			if rec.Header().Get("Content-Type") != reference.Header().Get("Content-Type") {
				t.Errorf("Content-Type = %q, want the same as every other refusal (%q)",
					rec.Header().Get("Content-Type"), reference.Header().Get("Content-Type"))
			}
			var got, want Problem
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("decoding: %v", err)
			}
			if err := json.Unmarshal(reference.Body.Bytes(), &want); err != nil {
				t.Fatalf("decoding the reference: %v", err)
			}
			if got.Type != want.Type || got.Title != want.Title || got.Status != want.Status ||
				got.Code != want.Code || got.Detail != want.Detail {
				t.Errorf("the refusal differs from every other refusal:\n got %+v\nwant %+v", got, want)
			}
		})
	}

	// And no timing comment is needed for the reason: the store never sees the
	// presented value, so there is no comparison to branch on. What IS asserted is
	// that no case above reached a different query — every one of them is a single
	// digest lookup, and the only way to make that false is to add a length check
	// somewhere on the path, which would be visible in this table as a different
	// answer for one of the malformed cases.
}

// ---------------------------------------------------------------------------
// nothing logged
// ---------------------------------------------------------------------------

// TestNoCredentialReachesTheLogs is this packet's logging constraint, and it is
// the test that has to be non-vacuous or it proves nothing.
//
// THE CANARY IS THE SERVICE'S OWN SECRET: the token this test mints, captured out
// of the 201 and searched for in every rendered log record afterwards. Nothing is
// put into the input, so a test that merely searched the logs could not pass —
// there is nothing to find unless the service put it there.
//
// NON-VACUITY IS ASSERTED FIRST. A run that only exercised the happy path would
// leave the log nearly empty and every absence below would pass for the wrong
// reason, so a 500 is provoked — by dropping the table the list reads — and the
// assertion that the logger really was called comes before the absence checks.
func TestNoCredentialReachesTheLogs(t *testing.T) {
	s := newAPIKeyServer(t)
	keyID, secret := s.mint(t, "ci-deploy", apikeys.ScopeAccountsRead, apikeys.ScopeAccountsWrite)
	s.keyID, s.token = keyID, secret

	// The whole surface with the secret in hand: the account routes the scopes
	// name, the list, a revoke, and introspection.
	s.bearer(t, http.MethodGet, "/v1/accounts", secret, "")
	s.bearer(t, http.MethodGet, "/v1/accounts/"+s.account.String(), secret, "")
	s.bearer(t, http.MethodGet, "/v1/accounts/"+s.account.String()+"/members", secret, "")
	s.bearer(t, http.MethodGet, apiKeyPath(s.account), s.session, "")
	s.bearer(t, http.MethodPost, "/v1/introspections", s.session, `{"token":"`+secret+`"}`)
	s.bearer(t, http.MethodPost, "/v1/introspections", secret, `{"token":"`+secret+`"}`)
	if rec := s.bearer(t, http.MethodDelete, apiKeyPath(s.account)+"/"+keyID.String(), s.session, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("revoking: %d; body: %s", rec.Code, rec.Body)
	}

	// A REFUSAL with a secret-shaped value in it, because a 401 that echoes the
	// presented credential is the most likely way for one to leak and no
	// happy-path run reaches it.
	s.bearer(t, http.MethodGet, "/v1/accounts/"+s.account.String(), secret, "")

	// AND A 500, which is where a driver error is most likely to carry a query, a
	// column name and whatever the driver had in its string. Dropping the table the
	// list reads is the same technique the MFA canary uses.
	if _, err := s.pool.Exec(context.Background(), `DROP TABLE api_keys`); err != nil {
		t.Fatalf("dropping api_keys: %v", err)
	}
	rec := apiKeyGet(t, s.handler, apiKeyPath(s.account), s.session)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("the store failure = %d, want 500; body: %s", rec.Code, rec.Body)
	}

	// NON-VACUITY, asserted before any absence check: the logger really ran.
	logs := s.logs.rendered()
	if strings.TrimSpace(logs) == "" {
		t.Fatal("nothing was logged at all, so every absence assertion below would pass " +
			"vacuously. The store failure above is the request that should have logged, " +
			"so an empty log means the harness is wrong rather than the code.")
	}

	// The absence, over every rendered record: message plus every attribute key and
	// value, so a filter that only caught the attributes somebody thought of does
	// not pass here.
	for _, forbidden := range []string{
		secret,
		strings.TrimPrefix(secret, apikeys.Prefix),
		apikeys.Digest(secret),
		apikeys.Prefix,
	} {
		if strings.Contains(logs, forbidden) {
			t.Errorf("the rendered logs contain %q, which is the credential or a container for it.\nRendered logs:\n%s",
				forbidden, logs)
		}
	}

	// And the words. NOT "token", and the omission is deliberate: this service
	// legitimately logs its own vocabulary — a driver error says `relation
	// "api_keys" does not exist` and a handler error says "reading an account's
	// tokens" — and a canary that fails on the word a failure line has to contain
	// teaches the next person to rename an error string rather than to stop leaking
	// a value. The value checks above are the real assertion; these are the words
	// that would only appear if something had been rendered INTO a field.
	for _, word := range []string{"digest", "secret", "password", apikeys.Prefix} {
		if strings.Contains(strings.ToLower(logs), word) {
			t.Errorf("the rendered logs mention %q, which is the vocabulary of a credential "+
				"even with no value attached.\nRendered logs:\n%s", word, logs)
		}
	}
}

// ---------------------------------------------------------------------------
// fixture helpers that need the database
// ---------------------------------------------------------------------------

// removeMember deletes a membership through the tenancy use case, so the write is
// the one the admin API will make and the account_users row really goes.
//
// The actor is a helper owner rather than the caller, for two reasons that are
// both real: the last owner of an account may not be removed, and the person being
// removed is the one whose token is under test, so using them as the actor would
// be asking them to offboard themselves.
func (s *apiKeyServer) removeMember(t *testing.T, account, member, actor id.UUID) error {
	t.Helper()
	return realTenancy(s.pool, s.clk).RemoveMember(context.Background(), accounts.RemoveMemberInput{
		AccountID: account,
		UserID:    member,
		Actor:     actor,
	})
}

// promoteHelper makes a fresh user an owner of the account and returns their id,
// so a removal or a role change has an actor with the standing to perform it.
func (s *apiKeyServer) promoteHelper(t *testing.T, account id.UUID) id.UUID {
	t.Helper()
	ctx := context.Background()

	email := dbtest.UniqueEmail(t)
	registered := post(t, s.handler, "/v1/users",
		`{"email":"`+email+`","password":"`+matrixPassword+`"}`)
	if registered.Code != http.StatusCreated {
		t.Fatalf("registering the helper: %d; body: %s", registered.Code, registered.Body)
	}
	var created userResponse
	if err := json.Unmarshal(registered.Body.Bytes(), &created); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	helper, err := id.Parse(created.ID)
	if err != nil {
		t.Fatalf("parsing the helper's id: %v", err)
	}
	if _, err := accounts.NewStore(s.pool).AddMember(ctx, s.pool, accounts.Membership{
		AccountID: account, UserID: helper, Role: accounts.RoleOwner,
	}); err != nil {
		t.Fatalf("promoting the helper: %v", err)
	}
	return helper
}

// readmit puts the fixture's user back in the account as an OWNER, through the
// real flow rather than by inserting a membership.
//
// IT IS TWO STEPS BECAUSE OWNERSHIP IS NEVER INVITED. accounts.Service.Invite
// refuses the owner role on purpose — an account whose owner appears by accepting a
// link is an account with an owner nobody chose — so the honest path is invite as a
// member, accept, and then promote. That is what an operator does, and it is the
// state the resurrection case has to be tested against: the user is back at the
// role they held when the token was minted, which is the strongest version of the
// question. A weaker version — back as a member — would be refused on the role gate
// even if the token's authority had been snapshotted, and would prove nothing.
func (s *apiKeyServer) readmit(t *testing.T, actor id.UUID) error {
	t.Helper()
	ctx := context.Background()
	tenancy := realTenancy(s.pool, s.clk)

	// The actor is the helper, not the user being re-invited: the user is not in the
	// account at this point and has no standing in it to invite anybody.
	invited, err := tenancy.Invite(ctx, accounts.InviteInput{
		AccountID: s.account,
		Email:     dbtest.UniqueEmail(t),
		Role:      accounts.RoleMember,
		InvitedBy: actor,
	})
	if err != nil {
		return err
	}
	if _, err := tenancy.Accept(ctx, accounts.AcceptInput{Token: invited.Token, User: s.user.ID}); err != nil {
		return err
	}
	_, err = accounts.NewStore(s.pool).SetRole(ctx, s.pool, s.account, s.user.ID, accounts.RoleOwner)
	return err
}

// demote moves a membership to a role through the store, which is what the
// PATCH /v1/accounts/:id/members/:userId route calls.
func (s *apiKeyServer) demote(t *testing.T, account, member id.UUID, to accounts.Role) error {
	t.Helper()
	_, err := accounts.NewStore(s.pool).SetRole(context.Background(), s.pool, account, member, to)
	return err
}

func (s *apiKeyServer) row(t *testing.T, keyID id.UUID) string {
	t.Helper()
	var out string
	if err := s.pool.QueryRow(context.Background(),
		`SELECT coalesce(row_to_json(api_keys)::text, '') FROM api_keys WHERE id = $1`, keyID).Scan(&out); err != nil {
		t.Fatalf("reading the row: %v", err)
	}
	return out
}

func (s *apiKeyServer) countKeys(t *testing.T) int {
	t.Helper()
	var n int
	if err := s.pool.QueryRow(context.Background(), `SELECT count(*) FROM api_keys`).Scan(&n); err != nil {
		if errors.Is(err, context.Canceled) {
			t.Fatalf("counting keys: %v", err)
		}
		t.Fatalf("counting keys: %v", err)
	}
	return n
}

// Compile-time proof the fixture mounts the same surfaces production does.
var (
	_ = oidc.ScopeOpenID
	_ = clock.System{}
)
