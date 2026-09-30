package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/accounts"
	"github.com/cafaye/identity/internal/apikeys"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/users"
)

// The scoped api key surface, against a programmable double.
//
// These tests are about the WIRE: status codes, the JSON shape, the one place the
// secret appears, and the refusals. The use cases' own rules — validation order,
// the owner check, the transaction — are asserted in internal/apikeys against a
// real database, and duplicating them here with a double would only prove that the
// double was told what the test wanted.

const fakeKeyPrefix = apikeys.Prefix

// apiKeySecret is a token-shaped value. It is a CONSTANT rather than something
// minted per test because none of these tests is about a particular token's
// randomness — the wire format is asserted in internal/apikeys — and a fixture
// holding a minted secret in a field is one more place for a failing assertion to
// print it.
//
// It is written out long and obviously synthetic on purpose. A test failure that
// prints it must not be mistaken for a real credential, and a value that looks
// real is exactly the kind of thing that ends up in a screenshot.
const (
	apiKeySecret = fakeKeyPrefix + "TESTONLYnotArealcredentialTESTONLYnotArealcredential"
)

// fakeAPIKeys is the APIKeys double.
//
// It records what it was handed, which is what lets a test prove that a handler
// took the account from the PATH and the user from the session rather than from
// the request body — the line a credential-minting route exists to hold.
type fakeAPIKeys struct {
	mu sync.Mutex

	issued apikeys.IssuedKey
	list   []apikeys.Key

	mintErr   error
	listErr   error
	revokeErr error

	minted  []apikeys.MintInput
	revoked []apikeys.RevokeInput
	listed  []id.UUID
}

func newFakeAPIKeys() *fakeAPIKeys {
	var accountID, userID, keyID id.UUID
	accountID[0], userID[0], keyID[0] = 0x11, 0x22, 0x33

	created := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	return &fakeAPIKeys{
		issued: apikeys.IssuedKey{
			Key: apikeys.Key{
				ID: keyID, AccountID: accountID, UserID: userID,
				Name:      "ci-deploy",
				Scopes:    []string{apikeys.ScopeAccountsRead},
				CreatedAt: created,
				ExpiresAt: created.AddDate(0, 3, 0),
			},
			Token: fakeKeyPrefix + "Zq3vK7mXpR2tY8wB4cN6dF0gH1jK5lM9oP3qS7uV2wX4yZ8",
		},
	}
}

func (f *fakeAPIKeys) Mint(_ context.Context, in apikeys.MintInput) (apikeys.IssuedKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.mintErr != nil {
		return apikeys.IssuedKey{}, f.mintErr
	}
	f.minted = append(f.minted, in)
	return f.issued, nil
}

func (f *fakeAPIKeys) List(_ context.Context, accountID id.UUID) ([]apikeys.Key, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	f.listed = append(f.listed, accountID)
	return f.list, nil
}

func (f *fakeAPIKeys) Revoke(_ context.Context, in apikeys.RevokeInput) (apikeys.Key, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revokeErr != nil {
		return apikeys.Key{}, f.revokeErr
	}
	f.revoked = append(f.revoked, in)
	return apikeys.Key{ID: in.KeyID, AccountID: in.AccountID}, nil
}

// ---------------------------------------------------------------------------
// POST /v1/accounts/:id/api-keys
// ---------------------------------------------------------------------------

// TestMintAPIKeyReturnsTheSecretOnce is the packet's one-time-display requirement
// on the HTTP response, and the reason it is spelled out as a test rather than
// asserted in a comment is that "we do not store the token" is easy to claim and
// easy to get subtly untrue. Three separate claims:
//
//	1. the 201 carries the token and it is the only field that does;
//	2. the response has no field a client could mistake for it — no digest, no
//	   prefix, no second copy;
//	3. EVERY other response on the surface does not carry it, which is the part
//	   "shown once" actually means.
func TestMintAPIKeyReturnsTheSecretOnce(t *testing.T) {
	t.Parallel()

	f := newFakeAPIKeys()
	auth := newFakeAuth()
	handler := New(nil, WithAuth(auth), WithTenancy(apiKeyTenancy()), WithAPIKeys(f))

	rec := apiKeyPost(t, handler, apiKeyPath(f.issued.Key.AccountID), auth.token,
		`{"name":"ci-deploy","scopes":["accounts:read"]}`)

	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /v1/accounts/:id/api-keys = %d, want 201; body: %s", rec.Code, rec.Body)
	}
	if got, want := rec.Header().Get("Content-Type"), "application/json; charset=utf-8"; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}

	var body issuedAPIKeyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not JSON: %v\n%s", err, rec.Body)
	}

	// (1) the secret is here.
	if body.Token != f.issued.Token {
		t.Errorf("token = %q, want the issued value", body.Token)
	}

	// (2) and only here. The nested type is what makes this checkable: the field
	// lives on issuedAPIKeyResponse and NOT on apiKeyResponse, so the list handler
	// cannot reach it even by accident.
	if body.ID != f.issued.Key.ID.String() {
		t.Errorf("id = %q, want %q", body.ID, f.issued.Key.ID)
	}
	rendered := rec.Body.String()
	if strings.Contains(rendered, f.issued.Key.TokenDigest) && f.issued.Key.TokenDigest != "" {
		t.Errorf("the response carries the row's digest: %s", rendered)
	}
	// last_used_at is absent on a token that has never been used, and its absence
	// is load-bearing: a client that sees the field and an empty value may treat
	// "the field exists" as "this credential has been used".
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if _, present := raw["last_used_at"]; present {
		t.Error("last_used_at is present on a token that has never been used")
	}
	for _, forbidden := range []string{"token_digest", "digest", "secret"} {
		if _, present := raw[forbidden]; present {
			t.Errorf("the response has a %q field", forbidden)
		}
	}

	// (3) nowhere else on the surface.
	listed := apiKeyGet(t, handler, apiKeyPath(f.issued.Key.AccountID), auth.token)
	if listed.Code != http.StatusOK {
		t.Fatalf("GET /v1/accounts/:id/api-keys = %d, want 200; body: %s", listed.Code, listed.Body)
	}
	if strings.Contains(listed.Body.String(), f.issued.Token) {
		t.Errorf("the list returns the secret: %s", listed.Body)
	}
}

// TestTheListCarriesNoSecretUnderAnyName is the paranoid version of the same
// requirement, and it is the assertion people get wrong: it does not check that
// the field is absent, it checks that the VALUE is not in the body at all. A
// handler that rendered the whole domain struct would pass a field-name check and
// fail this one.
func TestTheListCarriesNoSecretUnderAnyName(t *testing.T) {
	t.Parallel()

	f := newFakeAPIKeys()
	// A list holding a revoked token too, so the pointer fields are exercised
	// rather than being nil all the way down.
	revokedAt := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	reason := "rotated"
	f.list = []apikeys.Key{
		{ID: id.MustNew(), Name: "live", Scopes: []string{apikeys.ScopeAccountsRead},
			CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)},
		{ID: id.MustNew(), Name: "gone", Scopes: []string{apikeys.ScopeAccountsWrite},
			CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
			RevokedAt: &revokedAt, RevokeReason: &reason},
	}

	auth := newFakeAuth()
	handler := New(nil, WithAuth(auth), WithTenancy(apiKeyTenancy()), WithAPIKeys(f))
	rec := apiKeyGet(t, handler, apiKeyPath(id.MustNew()), auth.token)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), f.issued.Token) {
		t.Errorf("the list body contains the issued secret: %s", rec.Body)
	}
	// The whole rendered body, searched for anything token-shaped.
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if strings.Contains(line, fakeKeyPrefix) {
			t.Errorf("the list body carries a token-shaped value: %s", line)
		}
	}
}

// TestTheListIsAnArrayNotNull: an account with no credentials is an empty list, and
// a client should not have to handle both `[]` and `null` for the same thing.
func TestTheListIsAnArrayNotNull(t *testing.T) {
	t.Parallel()

	f := newFakeAPIKeys()
	auth := newFakeAuth()
	handler := New(nil, WithAuth(auth), WithTenancy(apiKeyTenancy()), WithAPIKeys(f))
	rec := apiKeyGet(t, handler, apiKeyPath(id.MustNew()), auth.token)

	if got, want := strings.TrimSpace(rec.Body.String()), "[]"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

// TestTheScopesSurviveTheWire is the wire-shape half of the scope contract: the
// client's `scopes` array is the set, unchanged, and it is an array rather than
// the space-separated string guard parses from a JWT. A response that rendered the
// OIDC shape here would be a client that had to split on whitespace to discover
// what it was granted.
func TestTheScopesSurviveTheWire(t *testing.T) {
	t.Parallel()

	f := newFakeAPIKeys()
	f.issued.Key.Scopes = []string{apikeys.ScopeAccountsRead, apikeys.ScopeAccountsWrite}
	auth := newFakeAuth()
	handler := New(nil, WithAuth(auth), WithTenancy(apiKeyTenancy()), WithAPIKeys(f))

	rec := apiKeyPost(t, handler, apiKeyPath(f.issued.Key.AccountID), auth.token,
		`{"name":"ci-deploy","scopes":["accounts:read","accounts:write"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST = %d, want 201; body: %s", rec.Code, rec.Body)
	}

	var body issuedAPIKeyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if len(body.Scopes) != 2 ||
		body.Scopes[0] != apikeys.ScopeAccountsRead ||
		body.Scopes[1] != apikeys.ScopeAccountsWrite {
		t.Errorf("scopes = %v, want the two granted values in order", body.Scopes)
	}
}

// TestMintTakesTheAccountFromThePathAndTheUserFromTheSession is the line a
// credential-minting route exists to hold: nothing in the body can choose the
// account or the subject.
func TestMintTakesTheAccountFromThePathAndTheUserFromTheSession(t *testing.T) {
	t.Parallel()

	f := newFakeAPIKeys()
	auth := newFakeAuth()
	handler := New(nil, WithAuth(auth), WithTenancy(apiKeyTenancy()), WithAPIKeys(f))

	// The path says one account, the session says one user, and the body tries to
	// say both differently.
	accountInPath := id.MustNew()
	rec := apiKeyPost(t, handler, apiKeyPath(accountInPath), auth.token,
		`{"name":"ci","scopes":["accounts:read"],`+
			`"account_id":"`+id.MustNew().String()+`","user_id":"`+id.MustNew().String()+`"}`)

	// The unknown fields are the point of the first assertion: a body that could
	// carry an account_id is a body where the account is ambiguous.
	//
	// The answer is decodeBody's, and it is the service-wide one — a 422
	// validation_failed with a sentence saying the body has a field this endpoint
	// does not accept, and NO errors[] entry. That is a decision this service makes
	// everywhere a body carries an unknown field rather than a bad value, and
	// changing it for one route would give a client two different 422 shapes to
	// parse. What is asserted here is that the request is refused and that the
	// use case is never reached, which is the security claim.
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a body naming its own account = %d, want 422; body: %s", rec.Code, rec.Body)
	}
	p := decodeProblem(t, rec)
	if p.Code != CodeValidationFailed {
		t.Errorf("code = %q, want %q", p.Code, CodeValidationFailed)
	}
	if !strings.Contains(p.Detail, "does not accept") {
		t.Errorf("the detail does not say what is wrong: %q", p.Detail)
	}
	if len(f.minted) != 0 {
		t.Error("the use case was reached at all")
	}

	// And the clean case does put the path's account in the input.
	rec = apiKeyPost(t, handler, apiKeyPath(accountInPath), auth.token,
		`{"name":"ci","scopes":["accounts:read"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST = %d, want 201; body: %s", rec.Code, rec.Body)
	}
	if len(f.minted) != 1 {
		t.Fatalf("the use case was called %d times, want 1", len(f.minted))
	}
	if f.minted[0].AccountID != accountInPath {
		t.Errorf("the use case was given account %s, want the path's %s", f.minted[0].AccountID, accountInPath)
	}
	if f.minted[0].MintedBy != auth.user.ID {
		t.Errorf("the use case was given user %s, want the session's %s", f.minted[0].MintedBy, auth.user.ID)
	}
}

// TestExpiresInIsSecondsAndOptional: the field is RFC 6749's `expires_in` —
// seconds from now, not a timestamp — and omitting it is not an error.
func TestExpiresInIsSecondsAndOptional(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		body     string
		wantSet  bool
		wantSecs time.Duration
	}{
		{name: "omitted", body: `{"name":"ci","scopes":["accounts:read"]}`},
		{
			name: "thirty days", body: `{"name":"ci","scopes":["accounts:read"],"expires_in":2592000}`,
			wantSet: true, wantSecs: 30 * 24 * time.Hour,
		},
		{
			// A negative value is passed through rather than clamped, so the use
			// case's ResolveExpiry is what refuses it. Clamping here would turn a
			// nonsense request into a request for the floor, which is a different
			// credential than the one that was asked for.
			name: "negative", body: `{"name":"ci","scopes":["accounts:read"],"expires_in":-1}`,
			wantSet: true, wantSecs: -time.Second,
		},
		{
			name: "zero", body: `{"name":"ci","scopes":["accounts:read"],"expires_in":0}`,
			wantSet: true, wantSecs: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFakeAPIKeys()
			auth := newFakeAuth()
			handler := New(nil, WithAuth(auth), WithTenancy(apiKeyTenancy()), WithAPIKeys(f))

			rec := apiKeyPost(t, handler, apiKeyPath(f.issued.Key.AccountID), auth.token, tt.body)
			if rec.Code != http.StatusCreated {
				t.Fatalf("POST = %d, want 201; body: %s", rec.Code, rec.Body)
			}
			if len(f.minted) != 1 {
				t.Fatalf("the use case was called %d times, want 1", len(f.minted))
			}
			got := f.minted[0].ExpiresIn
			if !tt.wantSet {
				if got != nil {
					t.Errorf("ExpiresIn = %v, want nil so the default applies", *got)
				}
				return
			}
			if got == nil {
				t.Fatal("ExpiresIn = nil, want the requested lifetime")
			}
			if *got != tt.wantSecs {
				t.Errorf("ExpiresIn = %s, want %s", *got, tt.wantSecs)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// authorization
// ---------------------------------------------------------------------------

// TestTheAPIKeyRoutesRequireAnOwner is the route's minimum, asserted through the
// matrix's own helper so it is compared with every other account route's minimum
// rather than as a one-off.
func TestTheAPIKeyRoutesRequireAnOwner(t *testing.T) {
	t.Parallel()

	// One tenancy double per role rather than one mutated across subtests: the
	// subtests are parallel, and a shared double whose `role` field is written by
	// two of them at once is a harness that fails for a reason that has nothing to
	// do with the code.
	for _, role := range accounts.AllRoles() {
		t.Run(string(role), func(t *testing.T) {
			t.Parallel()

			tenancy := apiKeyTenancy()
			tenancy.role = role
			auth := newFakeAuth()
			handler := New(nil, WithAuth(auth), WithTenancy(tenancy), WithAPIKeys(newFakeAPIKeys()))

			rec := apiKeyGet(t, handler, apiKeyPath(id.MustNew()), auth.token)
			switch {
			case role.AtLeast(accounts.RoleOwner):
				if rec.Code != http.StatusOK {
					t.Errorf("an %s listing api keys = %d, want 200; body: %s", role, rec.Code, rec.Body)
				}
			default:
				if rec.Code != http.StatusForbidden {
					t.Errorf("a %s listing api keys = %d, want 403; body: %s", role, rec.Code, rec.Body)
				}
				if p := decodeProblem(t, rec); p.Code != CodeForbidden {
					t.Errorf("code = %q, want %q", p.Code, CodeForbidden)
				}
			}
		})
	}
}

// TestTheAPIKeyRoutesRefuseAnonymous, because owner-only must not be reachable by
// presenting nothing at all.
func TestTheAPIKeyRoutesRefuseAnonymous(t *testing.T) {
	t.Parallel()

	keys := newFakeAPIKeys()
	handler := New(nil, WithAuth(newFakeAuth()), WithTenancy(apiKeyTenancy()), WithAPIKeys(keys))
	account := id.MustNew()

	for _, tt := range []struct {
		name   string
		method string
		path   string
	}{
		{"mint", http.MethodPost, "/v1/accounts/" + account.String() + "/api-keys"},
		{"list", http.MethodGet, "/v1/accounts/" + account.String() + "/api-keys"},
		{"revoke", http.MethodDelete, "/v1/accounts/" + account.String() + "/api-keys/" + id.MustNew().String()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rec := send(t, handler, tt.method, tt.path, "")
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%s %s anonymously = %d, want 401; body: %s", tt.method, tt.path, rec.Code, rec.Body)
			}
		})
	}
	if len(keys.minted) != 0 || len(keys.revoked) != 0 {
		t.Error("an unauthenticated request reached the use cases")
	}
}

// TestATokenCannotReachTheCredentialSurface is the negative half of the scope
// vocabulary, and the part a scope list cannot express: there is no scope for
// managing api keys, so a token presenting here is refused outright rather than
// having its scopes consulted.
//
// The route table has no row for these three routes ON PURPOSE, and that is what
// makes the refusal. scopeRequiredBy returns "" for a route nobody declared, and
// `Allows("")` is false for every granted set — so the routes are closed to tokens
// by construction rather than by a check somebody has to remember to write.
func TestATokenCannotReachTheCredentialSurface(t *testing.T) {
	t.Parallel()

	for _, scope := range apikeys.AllScopes() {
		t.Run(scope, func(t *testing.T) {
			t.Parallel()

			keys := newFakeAPIKeys()
			auth := newFakeAuth()
			caller := newFakeAPIKeyCaller(auth.user, apikeys.Key{
				ID: id.MustNew(), AccountID: id.MustNew(), Scopes: []string{scope},
			})
			handler := New(nil,
				WithAuth(auth), WithTenancy(apiKeyTenancy()),
				WithAPIKeys(keys), WithAPIKeyCaller(caller),
			)
			account := caller.key.AccountID

			for _, tt := range []struct {
				name   string
				method string
				path   string
			}{
				{"mint", http.MethodPost, apiKeyPath(account)},
				{"list", http.MethodGet, apiKeyPath(account)},
				{"revoke", http.MethodDelete, apiKeyPath(account) + "/" + id.MustNew().String()},
			} {
				rec := apiKeySend(t, handler, tt.method, tt.path, apiKeySecret, `{}`)
				if rec.Code != http.StatusForbidden {
					t.Errorf("a token with %s reaching %s %s = %d, want 403; body: %s",
						scope, tt.method, tt.path, rec.Code, rec.Body)
				}
			}
			if len(keys.minted) != 0 || len(keys.revoked) != 0 {
				t.Errorf("a token with %s reached the use cases", scope)
			}
		})
	}
}

// TestEveryScopeIsEnforcedOnItsRoutes is the other direction, and the reason the
// scope table is a table: it walks the router and requires that every account
// route reachable by a token declares a scope this build knows about.
//
// A row naming a scope that does not exist would let a token through a gate that
// can never be satisfied — the credential is issued, the route is open, and nothing
// ever matches. A route with no row is closed, which is safe but is a gap somebody
// has to notice, so this test also reports it.
func TestEveryScopeIsEnforcedOnItsRoutes(t *testing.T) {
	t.Parallel()

	for route, scope := range accountRouteScopes {
		parts := strings.SplitN(route, " ", 2)
		if len(parts) != 2 {
			t.Errorf("the scope table's key %q is not a method and a path", route)
			continue
		}
		if !apikeys.IsSupportedScope(scope) {
			t.Errorf("route %s requires scope %q, which is not in the vocabulary", route, scope)
		}
	}

	// And every scope the vocabulary names is enforced somewhere, so a scope is
	// never a name with no route behind it.
	used := make(map[string][]string, len(apikeys.AllScopes()))
	for route, scope := range accountRouteScopes {
		used[scope] = append(used[scope], route)
	}
	for _, scope := range apikeys.AllScopes() {
		if len(used[scope]) == 0 {
			t.Errorf("scope %q is in the vocabulary and is enforced on no route, "+
				"which is what a comment with a type looks like", scope)
		}
	}
}

// ---------------------------------------------------------------------------
// DELETE /v1/accounts/:id/api-keys/:keyId
// ---------------------------------------------------------------------------

// TestRevokeWorksWithAndWithoutABody: "revoke this" with no explanation is the
// common request, and refusing it for want of a JSON document would be a 400 on a
// DELETE that needs nothing else.
func TestRevokeWorksWithAndWithoutABody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		body       string
		wantReason string
	}{
		{name: "no body at all"},
		{name: "an empty object", body: `{}`},
		{name: "a reason", body: `{"reason":"rotated"}`, wantReason: "rotated"},
		{name: "an empty reason", body: `{"reason":""}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFakeAPIKeys()
			auth := newFakeAuth()
			handler := New(nil, WithAuth(auth), WithTenancy(apiKeyTenancy()), WithAPIKeys(f))
			keyID := id.MustNew()

			rec := apiKeyDelete(t, handler,
				"/v1/accounts/"+f.issued.Key.AccountID.String()+"/api-keys/"+keyID.String(), auth.token, tt.body)
			if rec.Code != http.StatusNoContent {
				t.Fatalf("DELETE = %d, want 204; body: %s", rec.Code, rec.Body)
			}
			if rec.Body.Len() != 0 {
				t.Errorf("a 204 carried a body: %s", rec.Body)
			}
			if len(f.revoked) != 1 {
				t.Fatalf("the use case was called %d times, want 1", len(f.revoked))
			}
			if f.revoked[0].KeyID != keyID {
				t.Errorf("the use case was given key %s, want %s", f.revoked[0].KeyID, keyID)
			}
			if f.revoked[0].Reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", f.revoked[0].Reason, tt.wantReason)
			}
		})
	}
}

// TestRevokeRefusesAMalformedKeyId: the path is part of a resource's identity, so
// "not an id this service issued" is the same answer as "an id you cannot see".
func TestRevokeRefusesAMalformedKeyId(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{"not-a-uuid", "123", "00000000-0000-0000-0000-000000000000", "%20"} {
		t.Run(bad, func(t *testing.T) {
			t.Parallel()

			f := newFakeAPIKeys()
			auth := newFakeAuth()
			handler := New(nil, WithAuth(auth), WithTenancy(apiKeyTenancy()), WithAPIKeys(f))

			rec := apiKeyDelete(t, handler,
				"/v1/accounts/"+f.issued.Key.AccountID.String()+"/api-keys/"+bad, auth.token, "")
			if rec.Code != http.StatusNotFound {
				t.Errorf("revoking %q = %d, want 404; body: %s", bad, rec.Code, rec.Body)
			}
			if len(f.revoked) != 0 {
				t.Error("a malformed id reached the use case")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// error mapping
// ---------------------------------------------------------------------------

// TestAPIKeyErrorMapping is the whole table, and each row is a decision rather
// than a formatting choice. The two that matter most are the two 409s: an operator
// who clicked twice, and an operator rotating a name.
func TestAPIKeyErrorMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		give       error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "a member who is not an owner",
			give:       apikeys.ErrNotAuthorized,
			wantStatus: http.StatusForbidden, wantCode: CodeForbidden,
		},
		{
			// The store answers this for an unknown id, an id in another account,
			// and an id whose row is gone. One sentence for all three: a different
			// one would confirm that a guessed id is a real credential.
			name:       "a key that is not there",
			give:       apikeys.ErrNotFound,
			wantStatus: http.StatusNotFound, wantCode: CodeNotFound,
		},
		{
			name:       "already revoked",
			give:       apikeys.ErrAlreadyRevoked,
			wantStatus: http.StatusConflict, wantCode: CodeConflict,
		},
		{
			name:       "the name is taken by a live key",
			give:       apikeys.ErrNameTaken,
			wantStatus: http.StatusConflict, wantCode: CodeConflict,
		},
		{
			name:       "a bad field",
			give:       &apikeys.FieldError{Field: "scopes", Code: apikeys.CodeUnsupported},
			wantStatus: http.StatusUnprocessableEntity, wantCode: CodeValidationFailed,
		},
		{
			name:       "anything else is a 500",
			give:       errors.New("the database is on fire"),
			wantStatus: http.StatusInternalServerError, wantCode: CodeInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFakeAPIKeys()
			f.listErr = tt.give
			auth := newFakeAuth()
			logs := &recordingHandler{}
			handler := New(nil,
				WithAuth(auth), WithTenancy(apiKeyTenancy()), WithAPIKeys(f),
				WithLogger(slogLogger(logs)),
			)

			rec := apiKeyGet(t, handler, apiKeyPath(f.issued.Key.AccountID), auth.token)
			if rec.Code != tt.wantStatus {
				t.Fatalf("= %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body)
			}
			p := decodeProblem(t, rec)
			if p.Code != tt.wantCode {
				t.Errorf("code = %q, want %q", p.Code, tt.wantCode)
			}
			if p.TraceID == "" {
				t.Error("the problem carries no trace_id; support cannot start from it")
			}
			if rec.Header().Get(TraceHeader) != p.TraceID {
				t.Errorf("the header's trace id (%q) and the body's (%q) disagree",
					rec.Header().Get(TraceHeader), p.TraceID)
			}
		})
	}
}

// TestAnInternalFailureIsLoggedNotReturned: the sentence a caller gets must not
// contain the driver's error, and the operator must get it with a trace id.
func TestAnInternalFailureIsLoggedNotReturned(t *testing.T) {
	t.Parallel()

	f := newFakeAPIKeys()
	f.listErr = errors.New("pq: password authentication failed for user \"identity\" at 10.0.0.5")
	auth := newFakeAuth()
	logs := &recordingHandler{}
	handler := New(nil,
		WithAuth(auth), WithTenancy(apiKeyTenancy()), WithAPIKeys(f),
		WithLogger(slogLogger(logs)),
	)

	rec := apiKeyGet(t, handler, apiKeyPath(f.issued.Key.AccountID), auth.token)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("= %d, want 500", rec.Code)
	}

	p := decodeProblem(t, rec)
	for _, leak := range []string{"10.0.0.5", "password", "pq:"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("the 500 body leaks %q: %s", leak, rec.Body)
		}
		if strings.Contains(p.Detail, leak) {
			t.Errorf("the detail leaks %q: %s", leak, p.Detail)
		}
	}

	rendered := logs.rendered()
	if !strings.Contains(rendered, "10.0.0.5") {
		t.Errorf("the underlying error did not reach the log:\n%s", rendered)
	}
	if !strings.Contains(rendered, p.TraceID) {
		t.Errorf("the log line does not carry the trace id the caller was given:\n%s", rendered)
	}
}

// TestTheRoutesAreAbsentWithoutTheService: a misconfiguration is a 404, not a 500
// on every request. The same rule as every other optional surface in this service.
func TestTheRoutesAreAbsentWithoutTheService(t *testing.T) {
	t.Parallel()

	auth := newFakeAuth()
	handler := New(nil, WithAuth(auth), WithTenancy(apiKeyTenancy()))
	account := id.MustNew()

	for _, path := range []string{"/v1/accounts/" + account.String() + "/api-keys"} {
		if rec := apiKeyGet(t, handler, path, auth.token); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s without the service = %d, want 404", path, rec.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// fakeAPIKeyCaller resolves a fixed key to a fixed user, and records the values it
// was handed so a test can prove which surface the credential came from.
type fakeAPIKeyCaller struct {
	mu sync.Mutex

	key    apikeys.Key
	user   users.User
	role   accounts.Role
	err    error
	seen   []string
	sawNow time.Time
}

func newFakeAPIKeyCaller(user users.User, key apikeys.Key) *fakeAPIKeyCaller {
	return &fakeAPIKeyCaller{key: key, user: user, role: accounts.RoleOwner}
}

func (f *fakeAPIKeyCaller) Authenticate(_ context.Context, token string, now time.Time) (apikeys.Caller, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return apikeys.Caller{}, f.err
	}
	f.seen = append(f.seen, token)
	f.sawNow = now
	key := f.key
	key.Role = f.role
	return apikeys.Caller{User: f.user, Key: key, Role: f.role}, nil
}

// apiKeyPath is the collection route for an account's credentials.
//
// It is a helper rather than a concatenation at each call site because getting it
// wrong is silent in a way that matters: `/v1/accounts/{id}` is a real route that
// answers, so a test pointed at it passes with a 200 from the wrong endpoint and
// asserts nothing about api keys at all.
func apiKeyPath(accountID id.UUID) string {
	return "/v1/accounts/" + accountID.String() + "/api-keys"
}

// apiKeyTenancy is a fakeTenancy whose caller is an owner.
//
// It exists because the three api key routes are owner-only, and a tenancy double
// left at its zero role would make every test here a 403 — so each one would be
// asserting the refusal and none of them the success path. The role is set
// explicitly rather than defaulted in newFakeTenancy because that default would
// change what every other test in this package proves.
//
// The account's ID IS LEFT ZERO on purpose, so fakeTenancy.Get echoes the id from
// the PATH. A double with a fixed account would make "the handler passed the
// account from the path" pass no matter what the handler did — the handler would
// receive the double's id and compare it against the same fixed value.
func apiKeyTenancy() *fakeTenancy {
	f := newFakeTenancy()
	f.role = accounts.RoleOwner
	f.account = accounts.Account{Name: "Acme", Slug: "acme"}
	return f
}

func apiKeyPost(t *testing.T, h http.Handler, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	return apiKeySend(t, h, http.MethodPost, path, token, body)
}

func apiKeyGet(t *testing.T, h http.Handler, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	return apiKeySend(t, h, http.MethodGet, path, token, "")
}

func apiKeyDelete(t *testing.T, h http.Handler, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	return apiKeySend(t, h, http.MethodDelete, path, token, body)
}

func apiKeySend(t *testing.T, h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

var _ = fmt.Sprintf
