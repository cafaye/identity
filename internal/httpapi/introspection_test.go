package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/accounts"
	"github.com/cafaye/identity/internal/apikeys"
	"github.com/cafaye/identity/internal/platform/id"
)

// POST /v1/introspections.
//
// The surface exists because the credential is opaque: a resource server has no
// other way to learn what a cafaye api key may do. Two things are asserted here
// that are easy to get wrong — the dual claim name over the wire, and the fact
// that the caller's standing is decided separately from the token's own state.

// fakeIntrospector is the Introspector double. It records what it was asked, so a
// test can prove the route passed the BODY's token and not the caller's.
type fakeIntrospector struct {
	mu sync.Mutex

	claims map[string]apikeys.Claims
	err    error

	asked []string
	at    time.Time
}

func newFakeIntrospector() *fakeIntrospector {
	return &fakeIntrospector{claims: map[string]apikeys.Claims{}}
}

func (f *fakeIntrospector) Introspect(_ context.Context, token string, now time.Time) (apikeys.Claims, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, token)
	f.at = now
	if f.err != nil {
		return apikeys.Claims{}, f.err
	}
	if claims, ok := f.claims[token]; ok {
		return claims, nil
	}
	return apikeys.Claims{}, apikeys.ErrNotFound
}

// activeClaims is an active claim document for a token owned by owner in account.
func activeClaims(account, owner, tokenID id.UUID, scopes ...string) apikeys.Claims {
	joined := strings.Join(scopes, " ")
	created := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	return apikeys.Claims{
		Active:    true,
		Subject:   owner.String(),
		AccountID: account.String(),
		Scopes:    joined,
		Scope:     joined,
		TokenID:   tokenID.String(),
		Name:      "ci-deploy",
		Role:      "owner",
		IssuedAt:  created.Unix(),
		ExpiresAt: created.AddDate(0, 3, 0).Unix(),
	}
}

// TestIntrospectionPublishesBothScopeClaimNames is the addendum's requirement at
// the only place it can be observed by a consumer: on the wire.
//
// A test inside the package proved the two names are equal in a struct; this
// proves it in the bytes a resource server parses, because that is the surface
// where a drift would break a customer rather than a test.
func TestIntrospectionPublishesBothScopeClaimNames(t *testing.T) {
	t.Parallel()

	account, owner := id.MustNew(), id.MustNew()
	subject := apiKeySecret
	introspector := newFakeIntrospector()
	introspector.claims[subject] = activeClaims(account, owner, id.MustNew(),
		apikeys.ScopeAccountsRead, apikeys.ScopeAccountsWrite)

	auth := newFakeAuth()
	handler := New(nil, WithAuth(auth), WithTenancy(apiKeyTenancy()), WithIntrospection(introspector))

	rec := introspect(t, handler, apiKeySecret, auth.token)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /v1/introspections = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("the body is not JSON: %v\n%s", err, rec.Body)
	}

	primary, ok := doc[apikeys.ClaimScopes].(string)
	if !ok {
		t.Fatalf("the document has no %q string: %s", apikeys.ClaimScopes, rec.Body)
	}
	mirror, ok := doc[apikeys.ClaimScope].(string)
	if !ok {
		t.Fatalf("the document has no %q string: %s", apikeys.ClaimScope, rec.Body)
	}
	if primary != mirror {
		t.Errorf("%s = %q and %s = %q; a consumer's answer must not depend on which name it reads",
			apikeys.ClaimScopes, primary, apikeys.ClaimScope, mirror)
	}
	// Space-separated, because guard splits on whitespace and refuses anything else.
	if strings.Contains(primary, ",") || strings.Contains(primary, "[") {
		t.Errorf("the scope claim is not a space-separated string: %q", primary)
	}
	for _, want := range []string{apikeys.ScopeAccountsRead, apikeys.ScopeAccountsWrite} {
		if !strings.Contains(" "+primary+" ", " "+want+" ") {
			t.Errorf("the claim does not carry %q: %q", want, primary)
		}
	}
}

// TestIntrospectionAlwaysCarriesAccountIDAndNeverSubstitutesIt is the tenancy half
// of the addendum, on the wire.
func TestIntrospectionAlwaysCarriesAccountIDAndNeverSubstitutesIt(t *testing.T) {
	t.Parallel()

	account, owner := id.MustNew(), id.MustNew()
	subject := apiKeySecret
	introspector := newFakeIntrospector()
	introspector.claims[subject] = activeClaims(account, owner, id.MustNew(), apikeys.ScopeAccountsRead)

	auth := newFakeAuth()
	handler := New(nil, WithAuth(auth), WithTenancy(apiKeyTenancy()), WithIntrospection(introspector))

	rec := introspect(t, handler, subject, auth.token)
	if rec.Code != http.StatusOK {
		t.Fatalf("= %d, want 200; body: %s", rec.Code, rec.Body)
	}

	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if doc[apikeys.ClaimAccountID] != account.String() {
		t.Errorf("account_id = %v, want %q. A token with no tenancy key is refused, never "+
			"answered with the subject", doc[apikeys.ClaimAccountID], account)
	}
	if doc["sub"] == doc[apikeys.ClaimAccountID] {
		t.Error("sub and account_id are the same value")
	}
	if _, present := doc[apikeys.ClaimAccountID]; !present {
		t.Error("the document has no account_id at all")
	}
}

// TestAnUnusableTokenIsInactiveAndCarriesNothingElse: RFC 7662's shape, and the
// one-error rule in its HTTP form. Three different reasons for the token not to
// work and one identical body.
func TestAnUnusableTokenIsInactiveAndCarriesNothingElse(t *testing.T) {
	t.Parallel()

	unknown := apiKeySecret + "never-issued"

	tests := []struct {
		name string
		give func(f *fakeIntrospector)
	}{
		{
			// The double's own ErrNotFound, which is what the real store returns.
			name: "a token that never existed",
			give: func(*fakeIntrospector) {},
		},
		{
			// What a revoked or expired one looks like at this layer: the service
			// resolved it and then declined to say anything about it. ClaimsFor does
			// not return an error for those — it returns an inactive document — and
			// the route must not turn that into a 401.
			name: "a resolved but inactive token",
			give: func(f *fakeIntrospector) {
				f.claims[apiKeySecret] = apikeys.InactiveClaims()
			},
		},
		{
			name: "a token with no account",
			give: func(f *fakeIntrospector) {
				f.err = apikeys.ErrNoAccountID
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			account, owner := id.MustNew(), id.MustNew()
			f := newFakeIntrospector()
			f.claims[apiKeySecret] = activeClaims(account, owner, id.MustNew(), apikeys.ScopeAccountsRead)
			tt.give(f)

			auth := newFakeAuth()
			handler := New(nil, WithAuth(auth), WithTenancy(apiKeyTenancy()), WithIntrospection(f))

			rec := introspect(t, handler, unknown, auth.token)
			if rec.Code != http.StatusOK {
				t.Fatalf("= %d, want 200; an unusable token is an answer, not a failure; body: %s",
					rec.Code, rec.Body)
			}
			if got, want := strings.TrimSpace(rec.Body.String()), `{"active":false}`; got != want {
				t.Errorf("body = %s, want exactly %s. A refusal that carries a subject is a "+
					"user id handed to whoever asked, and one that differs per reason is an "+
					"oracle for whether a leaked value was live", got, want)
			}
		})
	}
}

// TestTheCallersStandingIsDecidedSeparatelyFromTheTokens: the two questions are
// different and must not share a status. A caller with no credential gets 401; a
// token asking about somebody else's gets 403; a session that is not an owner of
// the token's account gets 404 or 403 depending on whether they are a member. All
// of those are about the REQUEST, and none of them is `{"active": false}` — which
// would tell an unauthorised caller that the token they named is real.
func TestTheCallersStandingIsDecidedSeparatelyFromTheTokens(t *testing.T) {
	t.Parallel()

	account, owner := id.MustNew(), id.MustNew()
	otherKey := id.MustNew()

	t.Run("no credential at all", func(t *testing.T) {
		t.Parallel()

		f := newFakeIntrospector()
		f.claims[apiKeySecret] = activeClaims(account, owner, otherKey, apikeys.ScopeAccountsRead)
		handler := New(nil, WithAuth(newFakeAuth()), WithTenancy(apiKeyTenancy()), WithIntrospection(f))

		rec := introspect(t, handler, apiKeySecret, "")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("= %d, want 401; body: %s", rec.Code, rec.Body)
		}
		if len(f.asked) != 0 {
			t.Error("an unauthenticated request reached the introspector, so the refusal " +
				"and the resolution could be told apart")
		}
	})

	t.Run("a token asking about itself", func(t *testing.T) {
		t.Parallel()

		key := apikeys.Key{ID: otherKey, AccountID: account, Scopes: []string{apikeys.ScopeAccountsRead}}
		auth := newFakeAuth()
		f := newFakeIntrospector()
		f.claims[apiKeySecret] = activeClaims(account, owner, otherKey, apikeys.ScopeAccountsRead)
		handler := New(nil,
			WithAuth(auth), WithTenancy(apiKeyTenancy()),
			WithAPIKeyCaller(newFakeAPIKeyCaller(auth.user, key)), WithIntrospection(f),
		)

		rec := introspect(t, handler, apiKeySecret, apiKeySecret)
		if rec.Code != http.StatusOK {
			t.Fatalf("a token introspecting itself = %d, want 200; body: %s", rec.Code, rec.Body)
		}
		if !strings.Contains(rec.Body.String(), otherKey.String()) {
			t.Errorf("the document does not name the credential: %s", rec.Body)
		}
	})

	t.Run("a token asking about somebody else's", func(t *testing.T) {
		t.Parallel()

		key := apikeys.Key{ID: id.MustNew(), AccountID: account, Scopes: []string{apikeys.ScopeAccountsRead}}
		auth := newFakeAuth()
		f := newFakeIntrospector()
		f.claims[apiKeySecret] = activeClaims(account, owner, otherKey, apikeys.ScopeAccountsRead)
		handler := New(nil,
			WithAuth(auth), WithTenancy(apiKeyTenancy()),
			WithAPIKeyCaller(newFakeAPIKeyCaller(auth.user, key)), WithIntrospection(f),
		)

		rec := introspect(t, handler, apiKeySecret, apiKeySecret)
		if rec.Code != http.StatusForbidden {
			t.Errorf("= %d, want 403; body: %s", rec.Code, rec.Body)
		}
		if strings.Contains(rec.Body.String(), otherKey.String()) {
			t.Errorf("the refusal names the credential being asked about: %s", rec.Body)
		}
	})

	t.Run("a session that is a plain member of the token's account", func(t *testing.T) {
		t.Parallel()

		tenancy := apiKeyTenancy()
		tenancy.role = accounts.RoleMember
		auth := newFakeAuth()
		f := newFakeIntrospector()
		f.claims[apiKeySecret] = activeClaims(account, owner, otherKey, apikeys.ScopeAccountsRead)
		handler := New(nil, WithAuth(auth), WithTenancy(tenancy), WithIntrospection(f))

		rec := introspect(t, handler, apiKeySecret, auth.token)
		if rec.Code != http.StatusForbidden {
			t.Errorf("a member reading the grant = %d, want 403; body: %s", rec.Code, rec.Body)
		}
	})

	t.Run("a session that is not in the token's account", func(t *testing.T) {
		t.Parallel()

		tenancy := apiKeyTenancy()
		tenancy.getErr = accounts.ErrNotAMember
		auth := newFakeAuth()
		f := newFakeIntrospector()
		f.claims[apiKeySecret] = activeClaims(account, owner, otherKey, apikeys.ScopeAccountsRead)
		handler := New(nil, WithAuth(auth), WithTenancy(tenancy), WithIntrospection(f))

		rec := introspect(t, handler, apiKeySecret, auth.token)
		// 404, not 403: a 403 would confirm the account the token belongs to exists,
		// which is the same tenant-enumeration oracle every account route avoids.
		if rec.Code != http.StatusNotFound {
			t.Errorf("= %d, want 404; body: %s", rec.Code, rec.Body)
		}
	})
}

// TestIntrospectionPassesTheBodyToken: the route resolves what the body named,
// which is the whole point of the endpoint, and a test that only checked the
// status would pass against a route that ignored the body and answered about the
// caller's own credential.
func TestIntrospectionPassesTheBodyToken(t *testing.T) {
	t.Parallel()

	account, owner := id.MustNew(), id.MustNew()
	auth := newFakeAuth()
	f := newFakeIntrospector()
	f.claims["another-token"] = activeClaims(account, owner, id.MustNew(), apikeys.ScopeAccountsRead)
	handler := New(nil, WithAuth(auth), WithTenancy(apiKeyTenancy()), WithIntrospection(f))

	rec := introspect(t, handler, "another-token", auth.token)
	if rec.Code != http.StatusOK {
		t.Fatalf("= %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if len(f.asked) != 1 || f.asked[0] != "another-token" {
		t.Errorf("the introspector was asked about %v, want [another-token]", f.asked)
	}
}

// TestTheIntrospectionRouteIsAbsentWithoutTheService, for the reason every other
// optional route in this service is absent rather than 500.
func TestTheIntrospectionRouteIsAbsentWithoutTheService(t *testing.T) {
	t.Parallel()

	handler := New(nil, WithAuth(newFakeAuth()), WithTenancy(apiKeyTenancy()))
	rec := introspect(t, handler, apiKeySecret, newFakeAuth().token)
	if rec.Code != http.StatusNotFound {
		t.Errorf("= %d, want 404 when introspection is not configured", rec.Code)
	}
}

// TestAnIntrospectionFailureIsLoggedNotReturned: same rule as everywhere else —
// the caller gets a trace id, the operator gets the driver's error.
func TestAnIntrospectionFailureIsLoggedNotReturned(t *testing.T) {
	t.Parallel()

	f := newFakeIntrospector()
	f.err = errors.New("pq: could not reach the api_keys table at 10.0.0.5")
	auth := newFakeAuth()
	logs := &recordingHandler{}
	handler := New(nil,
		WithAuth(auth), WithTenancy(apiKeyTenancy()),
		WithIntrospection(f), WithLogger(slogLogger(logs)),
	)

	rec := introspect(t, handler, apiKeySecret, auth.token)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("= %d, want 500; body: %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "10.0.0.5") {
		t.Errorf("the 500 body leaks the host: %s", rec.Body)
	}
	if !strings.Contains(logs.rendered(), "10.0.0.5") {
		t.Errorf("the underlying error did not reach the log:\n%s", logs.rendered())
	}
}

// TestTheIntrospectionRequestCarriesNoCredentialInItsShape is a documentation
// test: the body takes a VALUE, never an id, and the comment on the type says why.
// If somebody changes it to an id this is the test that fails.
func TestTheIntrospectionRequestCarriesNoCredentialInItsShape(t *testing.T) {
	t.Parallel()

	var body introspectRequest
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("rendering: %v", err)
	}
	if strings.Contains(string(raw), "id") {
		t.Errorf("the request shape has an id field: %s. An id would be an enumeration "+
			"oracle over somebody else's credentials; only a value is useful to somebody "+
			"who already has the credential", raw)
	}
}

// introspect issues one introspection request. subject is what the body asks
// about; credential is what the caller presents, and they are different strings
// in every test that is about the difference between them.
func introspect(t *testing.T, h http.Handler, subject, credential string) *httptest.ResponseRecorder {
	t.Helper()
	return apiKeySend(t, h, http.MethodPost, "/v1/introspections", credential,
		`{"token":"`+subject+`"}`)
}
