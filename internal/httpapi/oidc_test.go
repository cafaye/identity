package httpapi

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/cafaye/identity/internal/oidc"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
)

// The authorization code + PKCE round trip, and every refusal the security
// checklist for this packet asks about.
//
// Each test names the attack it is standing in front of. A test that only
// asserted "400" would pass if the service were refusing for the wrong reason, so
// the body is checked as well as the status wherever the body carries the
// diagnosis.

// THE ROUND TRIP.
//
// authorize -> login -> code -> token -> userinfo, over the real router and the
// real SQL, asserting the ID token's claims against the PUBLISHED key set rather
// than against the private one. A signature check against the key that signed it
// proves nothing about whether a verifier on the edge could check it.
func TestOIDCAuthorizationCodeRoundTrip(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	tokens := f.roundTrip(t, client)

	if tokens["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", tokens["token_type"])
	}
	accessToken, _ := tokens["access_token"].(string)
	if accessToken == "" {
		t.Fatal("the token response carried no access_token")
	}
	idToken, _ := tokens["id_token"].(string)
	if idToken == "" {
		t.Fatal("the token response carried no id_token")
	}
	if got, _ := tokens["scope"].(string); got != "openid email profile accounts" {
		t.Errorf("scope = %q, want the four granted scopes", got)
	}
	if expires, _ := tokens["expires_in"].(float64); expires > 15*60 || expires <= 0 {
		t.Errorf("expires_in = %v, want a positive number at or under core's fifteen-minute cap", expires)
	}

	// The ID token's claims. iss, aud, sub, exp, iat, jti and nonce are the
	// protocol's; email, email_verified, name and accounts are the four the brief
	// names.
	idClaims := f.verify(t, idToken)

	if idClaims["iss"] != oidcTestIssuer {
		t.Errorf("id_token iss = %v, want %q; every verifier compares this for equality", idClaims["iss"], oidcTestIssuer)
	}
	// `aud` is an array here: RFC 7519 allows a string or an array of them, and
	// the library always emits the array form. A verifier that compares it to a
	// string is a verifier that has to handle both, and this test is where that is
	// pinned.
	if !audienceContains(idClaims["aud"], client.ClientID) {
		t.Errorf("id_token aud = %v, want it to contain the client %q", idClaims["aud"], client.ClientID)
	}
	if idClaims["sub"] != f.owner.String() {
		t.Errorf("id_token sub = %v, want the user %s", idClaims["sub"], f.owner)
	}
	if idClaims["nonce"] != "nonce-round-trip" {
		t.Errorf("id_token nonce = %v, want the one the client sent; a token that does not echo it is a "+
			"replayable token", idClaims["nonce"])
	}
	if idClaims["email"] != f.email {
		t.Errorf("id_token email = %v, want %q", idClaims["email"], f.email)
	}
	// Present AND false. The claim is written explicitly because
	// oidc.UserInfo.EmailVerified carries `omitempty` and a false bool would
	// otherwise vanish — leaving a relying party to assume the provider does not
	// support verification and treat the address as good.
	verified, present := idClaims["email_verified"]
	if !present {
		t.Error("id_token has no email_verified claim; a relying party that cannot see it has to assume it is verified")
	}
	if verified != false {
		t.Errorf("id_token email_verified = %v, want false: identity cannot prove an address yet", verified)
	}
	if name, _ := idClaims["name"].(string); name == "" {
		t.Error("id_token has no name claim; the profile scope was granted")
	}
	if _, present := idClaims["auth_time"]; !present {
		t.Error("id_token has no auth_time; the user authenticated and the moment is a protocol claim")
	}
	amr, _ := idClaims["amr"].([]any)
	if !slices.Contains(amr, "pwd") {
		t.Errorf("id_token amr = %v, want it to include pwd; a token that claimed no method is a token a "+
			"relying party might make a decision on", idClaims["amr"])
	}
	accounts, _ := idClaims["accounts"].([]any)
	if len(accounts) == 0 {
		t.Fatal("id_token has no accounts claim; the accounts scope was granted and the user owns one account")
	}
	first, _ := accounts[0].(map[string]any)
	if first["account_id"] != f.account.String() {
		t.Errorf("accounts[0].account_id = %v, want %s", first["account_id"], f.account)
	}
	if first["role"] != "owner" {
		t.Errorf("accounts[0].role = %v, want owner", first["role"])
	}
	if first["personal"] != true {
		t.Errorf("accounts[0].personal = %v, want true", first["personal"])
	}

	// The access token. RS256, the same key, and the claims guard reads.
	accessClaims := f.verify(t, accessToken)
	if accessClaims["iss"] != oidcTestIssuer {
		t.Errorf("access_token iss = %v, want %q", accessClaims["iss"], oidcTestIssuer)
	}
	if accessClaims["sub"] != f.owner.String() {
		t.Errorf("access_token sub = %v, want %s", accessClaims["sub"], f.owner)
	}
	if scope, _ := accessClaims["scope"].(string); scope != "accounts openid" {
		t.Errorf("access_token scope = %q, want the granted scopes space-delimited; guard splits this on whitespace",
			scope)
	}
	if _, present := accessClaims["jti"]; !present {
		t.Error("access_token has no jti; it is the only handle userinfo has on the token")
	}
	if _, present := accessClaims["accounts"]; !present {
		t.Error("access_token has no accounts claim; core asks for the account claims on service traffic")
	}

	// The at_hash binds the ID token to the access token, which is what stops one
	// being paired with a different one.
	if _, present := idClaims["at_hash"]; !present {
		t.Error("id_token has no at_hash; it is what binds it to this access token")
	}

	// userinfo, with the access token.
	info := f.do(t, http.MethodGet, oidc.PathUserinfo, "", nil)
	if info.Code != http.StatusUnauthorized {
		t.Fatalf("GET userinfo with no token = %d, want 401", info.Code)
	}

	rec := newResponse(serveRecorder(f.handler, newRequestWithBearer(http.MethodGet, oidc.PathUserinfo, accessToken)))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET userinfo = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	var claims map[string]any
	mustJSON(t, rec.Body.Bytes(), &claims)
	if claims["sub"] != f.owner.String() {
		t.Errorf("userinfo sub = %v, want %s", claims["sub"], f.owner)
	}
	if claims["email"] != f.email {
		t.Errorf("userinfo email = %v, want %q", claims["email"], f.email)
	}
	if verified, present := claims["email_verified"]; !present || verified != false {
		t.Errorf("userinfo email_verified = %v (present %t), want false and present", verified, present)
	}
	if name, _ := claims["name"].(string); name == "" {
		t.Error("userinfo has no name")
	}
	if list, _ := claims["accounts"].([]any); len(list) == 0 {
		t.Error("userinfo has no accounts; the brief asks for the account/role claims from account_users")
	}
	// Nothing internal. The brief says never leak an internal id that is not
	// already in the token, and the row ids of accounts, memberships and the
	// client itself are not.
	for _, forbidden := range []string{"password_digest", "secret", "digest", "client_id", "row_id"} {
		if _, present := claims[forbidden]; present {
			t.Errorf("userinfo carries %q", forbidden)
		}
	}
}

// An authorization code is a bearer credential for sixty seconds, and a second
// use of it is either an attacker replaying a captured code or a product retrying
// a request it already had answered. Both get the same answer.
func TestOIDCReplayedCodeIsRefused(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	verifier, challenge := codeVerifier(t)
	loginURL := f.authorize(t, client, challenge, "state-replay", "nonce-replay", nil)

	rec := f.login(t, loginURL, client.Email, client.Password)
	if rec.Code != http.StatusFound {
		t.Fatalf("POST the login form = %d, want 302; body: %s", rec.Code, rec.Body)
	}
	code := mustCode(t, rec.Header().Get("Location"))

	first := f.exchange(t, client, code, verifier, oidcTestRedirect)
	if first.Code != http.StatusOK {
		t.Fatalf("the first exchange = %d, want 200; body: %s", first.Code, first.Body)
	}

	second := f.exchange(t, client, code, verifier, oidcTestRedirect)
	if second.Code != http.StatusBadRequest {
		t.Fatalf("the second exchange of the same code = %d, want 400; body: %s", second.Code, second.Body)
	}
	if err, _ := second.JSON["error"].(string); err != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant; the protocol's name for a code that will not redeem", err)
	}
}

// The single-use gate is one conditional UPDATE rather than a read followed by a
// delete, and this is what proves the two are different: the storage layer's own
// test races eight goroutines on one code. Here the point is the HTTP answer.
func TestOIDCReplayedCodeWithAFreshVerifierIsStillRefused(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	verifier, challenge := codeVerifier(t)
	loginURL := f.authorize(t, client, challenge, "state-replay-2", "nonce-replay-2", nil)
	rec := f.login(t, loginURL, client.Email, client.Password)
	code := mustCode(t, rec.Header().Get("Location"))

	if got := f.exchange(t, client, code, verifier, oidcTestRedirect).Code; got != http.StatusOK {
		t.Fatalf("the first exchange = %d, want 200", got)
	}

	// A different verifier, so nothing about the replay can be blamed on PKCE.
	other, _ := codeVerifier(t)
	again := f.exchange(t, client, code, other, oidcTestRedirect)
	if again.Code != http.StatusBadRequest {
		t.Fatalf("the replay = %d, want 400; body: %s", again.Code, again.Body)
	}
}

// PKCE is not optional here, and the three ways to be without it are three
// separate tests because a table that asserted only "400" would pass for a
// service that refused all of them for the same unrelated reason.
func TestOIDCPKCERefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// challenge and method are the two parameters as sent, so a case can send
		// neither, one, or the other and the table stays readable.
		challenge  string
		method     string
		wantDetail string
	}{ //nolint:govet // the field alignment is the point
		{name: "neither parameter", wantDetail: "PKCE is required"},
		{name: "the method alone", method: "S256", wantDetail: "no code_challenge"},
		{name: "the challenge alone, which RFC 7636 says is plain", challenge: "not-hashed", wantDetail: "PKCE is required"},
		{name: "plain, spelled out", challenge: "not-hashed", method: "plain", wantDetail: "must be S256"},
		{name: "an unknown method", challenge: "not-hashed", method: "S512", wantDetail: "must be S256"},
		{name: "S256, spelled exactly", challenge: "s256-challenge", method: "s256", wantDetail: "must be S256"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newOIDCFixture(t)
			client := f.registerClient(t)

			query := url.Values{
				"client_id":     []string{client.ClientID},
				"redirect_uri":  []string{oidcTestRedirect},
				"response_type": []string{"code"},
				"scope":         []string{"openid email"},
				"state":         []string{"state-pkce"},
				"nonce":         []string{"nonce-pkce"},
			}
			if tt.challenge != "" {
				query.Set("code_challenge", tt.challenge)
			}
			if tt.method != "" {
				query.Set("code_challenge_method", tt.method)
			}

			rec := f.do(t, http.MethodGet, oidc.PathAuthorize+"?"+query.Encode(), "", nil)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("GET /oidc/authorize = %d, want 400; body: %s", rec.Code, rec.Body)
			}
			if rec.Header().Get("Content-Type") != "application/problem+json" {
				t.Errorf("Content-Type = %q, want application/problem+json", rec.Header().Get("Content-Type"))
			}
			if !strings.Contains(rec.Body.String(), tt.wantDetail) {
				t.Errorf("the detail does not mention %q:\n%s", tt.wantDetail, rec.Body)
			}
		})
	}
}

// THE OPEN-REDIRECT TEST.
//
// `https://app.example.com.evil.com/cb` shares a prefix with the registered
// origin and belongs to an attacker. A redirect check that used HasPrefix, or a
// glob, or "starts with the registered host", would send a user there with a
// valid authorization code attached.
//
// Every variant below is the same attack in a different costume, and each is a
// separate case because each is a separate way to write a broken comparison.
func TestOIDCRedirectURINotOnTheAllowList(t *testing.T) {
	t.Parallel()

	offList := []struct {
		name   string
		target string
	}{
		{name: "the prefix-confusion case", target: "https://app.example.com.evil.com/cb"},
		{name: "a different host entirely", target: "https://evil.com/cb"},
		{name: "the same host over http", target: "http://app.example.com/cb"},
		{name: "a subdomain", target: "https://evil.app.example.com/cb"},
		{name: "a deeper path", target: "https://app.example.com/cb/attacker"},
		{name: "a trailing path segment", target: "https://app.example.com/cbevil"},
		{name: "an explicit port", target: "https://app.example.com:8443/cb"},
		{name: "a userinfo trick", target: "https://app.example.com@evil.com/cb"},
		{name: "no scheme at all", target: "app.example.com/cb"},
		{name: "empty", target: ""},
		{name: "a javascript scheme", target: "javascript:alert(1)"},
	}

	for _, tt := range offList {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newOIDCFixture(t)
			client := f.registerClient(t)

			_, challenge := codeVerifier(t)
			query := url.Values{
				"client_id":             []string{client.ClientID},
				"redirect_uri":          []string{tt.target},
				"response_type":         []string{"code"},
				"scope":                 []string{"openid email"},
				"state":                 []string{"state-redirect"},
				"nonce":                 []string{"nonce-redirect"},
				"code_challenge":        []string{challenge},
				"code_challenge_method": []string{"S256"},
			}

			rec := f.do(t, http.MethodGet, oidc.PathAuthorize+"?"+query.Encode(), "", nil)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("GET /oidc/authorize with redirect_uri %q = %d, want 400; body: %s",
					tt.target, rec.Code, rec.Body)
			}
			// The refusal must never itself be a redirect: an error page at the
			// attacker's origin would be the same attack with better manners.
			if location := rec.Header().Get("Location"); location != "" {
				t.Errorf("the refusal carried Location %q; a redirect to an unregistered origin is the bug", location)
			}
			if tt.target == "" && !strings.Contains(rec.Body.String(), "redirect_uri") {
				t.Errorf("the refusal does not say what was missing:\n%s", rec.Body)
			}
		})
	}
}

// The same check runs at the TOKEN endpoint, because the redirect_uri in the
// token request is attacker-controlled too: a client that registered two origins
// and then swapped the one in the token request is asking for a code to be
// delivered somewhere its own registration did not sanction for this flow.
func TestOIDCTokenRedirectURIMustMatchTheAuthorizationRequest(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	verifier, challenge := codeVerifier(t)
	loginURL := f.authorize(t, client, challenge, "state-token-redirect", "nonce-token-redirect", nil)
	rec := f.login(t, loginURL, client.Email, client.Password)
	code := mustCode(t, rec.Header().Get("Location"))

	swapped := f.exchange(t, client, code, verifier, "https://app.example.com.evil.com/cb")
	if swapped.Code != http.StatusBadRequest {
		t.Fatalf("the exchange with a swapped redirect_uri = %d, want 400; body: %s", swapped.Code, swapped.Body)
	}
	if err, _ := swapped.JSON["error"].(string); err != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", err)
	}

	// The registered one still works, so the refusal above is about the mismatch
	// and not about the code having been spent by the failed attempt.
	// (The code was already consumed by the swapped attempt, so this asserts the
	// 400 rather than a 200: a single-use gate that a rejected request could
	// bypass would let an attacker burn nothing and learn nothing.)
	again := f.exchange(t, client, code, verifier, oidcTestRedirect)
	if again.Code != http.StatusBadRequest {
		t.Errorf("the code survived a rejected exchange: %d, want 400", again.Code)
	}
}

// A wrong client secret and a revoked client get one indistinguishable answer.
// Anything more is an oracle: a caller who can tell "no such client" from "wrong
// secret" learns which products are registered here.
func TestOIDCRevokedClientAndWrongSecret(t *testing.T) {
	t.Parallel()

	t.Run("a wrong secret", func(t *testing.T) {
		t.Parallel()

		f := newOIDCFixture(t)
		client := f.registerClient(t)
		client.ClientSecret = "not-the-secret"

		verifier, challenge := codeVerifier(t)
		loginURL := f.authorize(t, client, challenge, "state-badsecret", "nonce-badsecret", nil)
		rec := f.login(t, loginURL, client.Email, client.Password)
		code := mustCode(t, rec.Header().Get("Location"))

		refused := f.exchange(t, client, code, verifier, oidcTestRedirect)
		if refused.Code != http.StatusUnauthorized {
			t.Fatalf("the exchange with a wrong secret = %d, want 401; body: %s", refused.Code, refused.Body)
		}
		if err, _ := refused.JSON["error"].(string); err != "invalid_client" {
			t.Errorf("error = %q, want invalid_client", err)
		}
	})

	t.Run("a revoked client", func(t *testing.T) {
		t.Parallel()

		f := newOIDCFixture(t)
		client := f.registerClient(t)

		verifier, challenge := codeVerifier(t)
		loginURL := f.authorize(t, client, challenge, "state-revoked", "nonce-revoked", nil)
		rec := f.login(t, loginURL, client.Email, client.Password)
		code := mustCode(t, rec.Header().Get("Location"))

		f.revoke(t, client)

		refused := f.exchange(t, client, code, verifier, oidcTestRedirect)
		if refused.Code != http.StatusUnauthorized {
			t.Fatalf("the exchange as a revoked client = %d, want 401; body: %s", refused.Code, refused.Body)
		}
		if err, _ := refused.JSON["error"].(string); err != "invalid_client" {
			t.Errorf("error = %q, want invalid_client; a revoked client and a wrong secret are one answer", err)
		}
	})

	t.Run("a revoked client cannot start a flow at all", func(t *testing.T) {
		t.Parallel()

		f := newOIDCFixture(t)
		client := f.registerClient(t)
		f.revoke(t, client)

		_, challenge := codeVerifier(t)
		query := url.Values{
			"client_id":             []string{client.ClientID},
			"redirect_uri":          []string{oidcTestRedirect},
			"response_type":         []string{"code"},
			"scope":                 []string{"openid email"},
			"state":                 []string{"state-revoked-authorize"},
			"nonce":                 []string{"nonce-revoked-authorize"},
			"code_challenge":        []string{challenge},
			"code_challenge_method": []string{"S256"},
		}

		rec := f.do(t, http.MethodGet, oidc.PathAuthorize+"?"+query.Encode(), "", nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("authorize as a revoked client = %d, want 400; body: %s", rec.Code, rec.Body)
		}
		if location := rec.Header().Get("Location"); location != "" {
			t.Errorf("the refusal redirected to %q", location)
		}
	})
}

// A revocation has to actually stop the tokens it already issued. A JWT is
// verifiable by anybody with the published key set, so revoking the registration
// is not enough on its own and the service knows it: the revocation and the bulk
// token revocation are one transaction.
func TestOIDCRevocationStopsIssuedTokens(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	tokens := f.roundTrip(t, client)
	accessToken, _ := tokens["access_token"].(string)

	before := newResponse(serveRecorder(f.handler, newRequestWithBearer(http.MethodGet, oidc.PathUserinfo, accessToken)))
	if before.Code != http.StatusOK {
		t.Fatalf("userinfo before the revocation = %d, want 200; body: %s", before.Code, before.Body)
	}

	f.revoke(t, client)

	after := newResponse(serveRecorder(f.handler, newRequestWithBearer(http.MethodGet, oidc.PathUserinfo, accessToken)))
	if after.Code == http.StatusOK {
		t.Errorf("userinfo after the revocation = 200, want a refusal; the token is still live:\n%s", after.Body)
	}
}

// The login form's state is the CSRF defence on the one page where a user types a
// password into a form this service rendered for a third party. A cross-site
// POST would complete an authorization request the user never chose.
func TestOIDCLoginStateMustMatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// presented is what the form posts back.
		presented string
		// dropCookie removes the sealed value entirely, which is what a cross-site
		// request looks like: the attacker's origin cannot write a __Host- cookie.
		dropCookie bool
	}{
		{name: "a state from a different flow", presented: "oidc.not-the-one-that-was-issued"},
		{name: "an empty state", presented: ""},
		{name: "a state with no provider prefix", presented: "some-random-value"},
		{name: "no cookie at all", dropCookie: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newOIDCFixture(t)
			client := f.registerClient(t)

			_, challenge := codeVerifier(t)
			loginURL := f.authorize(t, client, challenge, "state-csrf", "nonce-csrf", nil)

			f.signOut()
			form := f.do(t, http.MethodGet, loginURL, "", nil)
			if form.Code != http.StatusOK {
				t.Fatalf("GET the login page = %d, want 200; body: %s", form.Code, form.Body)
			}
			sealed := hiddenState(t, form.Body.String())
			if sealed == "" {
				t.Fatal("the form carried no state")
			}

			presented := tt.presented
			if presented == "" && !tt.dropCookie {
				presented = "oidx.something-else-entirely"
			}

			jar := &cookieJar{}
			if !tt.dropCookie {
				for _, c := range form.Result().Cookies() {
					jar.absorb([]*http.Cookie{c})
				}
			}

			post := url.Values{
				"state":    []string{presented},
				"email":    []string{client.Email},
				"password": []string{client.Password},
			}
			req := newRequestForm(http.MethodPost, loginURL, post)
			if cookie := jar.header(); cookie != "" {
				req.Header.Set("Cookie", cookie)
			}

			rec := newResponse(serveRecorder(f.handler, req))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("POST the login form = %d, want 400; body: %s", rec.Code, rec.Body)
			}
			if rec.Header().Get("Content-Type") != "application/problem+json" {
				t.Errorf("Content-Type = %q, want application/problem+json", rec.Header().Get("Content-Type"))
			}
			if location := rec.Header().Get("Location"); location != "" {
				t.Errorf("the refusal redirected to %q; a completed request is exactly what the attack wanted", location)
			}
		})
	}
}

// The state this service verifies is internal/oauth's, reused rather than
// reimplemented. The test is that the value in the cookie is one that
// oauth.VerifyState accepts, which is the whole contract between the two.
func TestOIDCLoginStateIsOauthPackageState(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	_, challenge := codeVerifier(t)
	loginURL := f.authorize(t, client, challenge, "state-reuse", "nonce-reuse", nil)

	f.signOut()
	form := f.do(t, http.MethodGet, loginURL, "", nil)
	sealed := hiddenState(t, form.Body.String())

	if !strings.HasPrefix(sealed, OIDCStateProvider+oauthStateSeparator) {
		t.Errorf("the state %q is not one oauth.NewState(%q) could have minted", sealed, OIDCStateProvider)
	}
	if !oauthVerifyState(OIDCStateProvider, sealed, sealed) {
		t.Error("the service's own state does not satisfy oauth.VerifyState against itself")
	}
	if oauthVerifyState(OIDCStateProvider, sealed, sealed+"x") {
		t.Error("a state one character longer verifies; the comparison is not exact")
	}
}

// The scope set is closed, and a product asking for something identity cannot
// produce gets a 400 naming it rather than a token with the field quietly
// missing. The library's own validator deletes an unrecognised scope and carries
// on, which is the failure this pre-check exists to stop.
func TestOIDCUnknownScope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		scope string
		// want is matched against the DECODED detail. The raw body JSON-escapes
		// the quotes around the offending scope, so a substring check against it
		// would be asserting on the encoder.
		want string
	}{
		{name: "a standard scope identity does not implement", scope: "openid phone", want: `unknown scope "phone"`},
		{name: "address", scope: "openid address", want: `unknown scope "address"`},
		{name: "offline_access, which needs a refresh token store", scope: "openid offline_access", want: `unknown scope "offline_access"`},
		{name: "a plural of one of ours", scope: "openid profiles", want: `unknown scope "profiles"`},
		{name: "no openid", scope: "email profile", want: "openid scope is required"},
		{name: "no scope at all", scope: "", want: "openid scope is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newOIDCFixture(t)
			client := f.registerClient(t)

			_, challenge := codeVerifier(t)
			query := url.Values{
				"client_id":             []string{client.ClientID},
				"redirect_uri":          []string{oidcTestRedirect},
				"response_type":         []string{"code"},
				"state":                 []string{"state-scope"},
				"nonce":                 []string{"nonce-scope"},
				"code_challenge":        []string{challenge},
				"code_challenge_method": []string{"S256"},
			}
			if tt.scope != "" {
				query.Set("scope", tt.scope)
			}

			rec := f.do(t, http.MethodGet, oidc.PathAuthorize+"?"+query.Encode(), "", nil)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("authorize with scope %q = %d, want 400; body: %s", tt.scope, rec.Code, rec.Body)
			}
			if rec.Header().Get("Content-Type") != "application/problem+json" {
				t.Errorf("Content-Type = %q, want application/problem+json", rec.Header().Get("Content-Type"))
			}
			// The problem envelope's own shape, not just a 400.
			p := decodeProblem(t, rec.ResponseRecorder)
			if !strings.Contains(p.Detail, tt.want) {
				t.Errorf("detail = %q, want it to mention %q", p.Detail, tt.want)
			}
			if p.Code != CodeInvalidRequest {
				t.Errorf("code = %q, want %q", p.Code, CodeInvalidRequest)
			}
			if p.Status != http.StatusBadRequest {
				t.Errorf("status field = %d, want 400", p.Status)
			}
			if p.Type != "https://errors.cafaye.com/"+CodeInvalidRequest {
				t.Errorf("type = %q, want the cafaye error URI for %q", p.Type, CodeInvalidRequest)
			}
			if p.TraceID == "" {
				t.Error("the problem has no trace_id; core requires it on every non-2xx")
			}
		})
	}
}

// A scope the CLIENT registered is granted; one it did not is not, even if the
// authorization request asks for it. Otherwise a client could widen its own
// permissions at the authorize endpoint, and the registration would be
// decorative.
func TestOIDCAcceptedScopeIsClippedToTheRegistration(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)

	// Register with email only.
	body := fmt.Sprintf(`{"name":"Anytalk","redirect_uris":[%q],"grant_types":["authorization_code"],`+
		`"scopes":["openid","email"]}`, oidcTestRedirect)
	rec := f.do(t, http.MethodPost, "/v1/accounts/"+f.account.String()+"/oidc-clients", body, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering a client: %d; body: %s", rec.Code, rec.Body)
	}
	var created oidcClientCreatedResponse
	mustJSON(t, rec.Body.Bytes(), &created)
	client := registered{ID: created.ID, ClientID: created.ClientID, ClientSecret: created.ClientSecret, Email: f.email, Password: oidcTestPassword}

	verifier, challenge := codeVerifier(t)
	loginURL := f.authorize(t, client, challenge, "state-clip", "nonce-clip", nil)
	rec2 := f.login(t, loginURL, client.Email, client.Password)
	code := mustCode(t, rec2.Header().Get("Location"))

	tokens := f.exchange(t, client, code, verifier, oidcTestRedirect)
	if tokens.Code != http.StatusOK {
		t.Fatalf("the exchange = %d, want 200; body: %s", tokens.Code, tokens.Body)
	}

	var body2 map[string]any
	mustJSON(t, tokens.Body.Bytes(), &body2)
	// The authorization request asked for accounts; the registration does not
	// have it, so the token must not carry the claim.
	idToken, _ := body2["id_token"].(string)
	claims := f.verify(t, idToken)
	if _, present := claims[oidc.ClaimAccounts]; present {
		t.Errorf("the id_token carries an accounts claim from a scope the client never registered:\n%v", claims)
	}
	if claims["email"] != f.email {
		t.Errorf("the registered email scope was not granted: %v", claims["email"])
	}
}

// The protocol parameters this provider does not implement are refused rather
// than ignored. A product that asked for prompt=login and got a silent sign-in
// has been told the session was re-established when it was not.
func TestOIDCUnimplementedParametersAreRefused(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		extra      url.Values
		wantDetail string
	}{
		{
			name:       "prompt=login",
			extra:      url.Values{"prompt": []string{"login"}},
			wantDetail: `prompt=login is not implemented`,
		},
		{
			name:       "prompt=consent",
			extra:      url.Values{"prompt": []string{"consent"}},
			wantDetail: `prompt=consent is not implemented`,
		},
		{
			name:       "max_age",
			extra:      url.Values{"max_age": []string{"300"}},
			wantDetail: "max_age is not implemented",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newOIDCFixture(t)
			client := f.registerClient(t)

			_, challenge := codeVerifier(t)
			query := url.Values{
				"client_id":             []string{client.ClientID},
				"redirect_uri":          []string{oidcTestRedirect},
				"response_type":         []string{"code"},
				"scope":                 []string{"openid email"},
				"state":                 []string{"state-params"},
				"nonce":                 []string{"nonce-params"},
				"code_challenge":        []string{challenge},
				"code_challenge_method": []string{"S256"},
			}
			for key, values := range tt.extra {
				query[key] = values
			}

			got := f.do(t, http.MethodGet, oidc.PathAuthorize+"?"+query.Encode(), "", nil)
			if got.Code != http.StatusBadRequest {
				t.Fatalf("authorize with %v = %d, want 400; body: %s", tt.extra, got.Code, got.Body)
			}
			if !strings.Contains(got.Body.String(), tt.wantDetail) {
				t.Errorf("the detail does not mention %q:\n%s", tt.wantDetail, got.Body)
			}
		})
	}
}

// prompt=none is the one interactive-free flow this provider gets right, and the
// answer is the specified one: an error REDIRECTED to the client's registered
// redirect_uri, because RFC 6749 §4.1.2.1 says an authorization failure after a
// valid redirect_uri is reported to the client and not rendered here. Rendering
// it would put a cafaye error page on a URL the client owns, and the client
// would never learn why.
func TestOIDCPromptNoneIsLoginRequired(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	_, challenge := codeVerifier(t)
	query := url.Values{
		"client_id":             []string{client.ClientID},
		"redirect_uri":          []string{oidcTestRedirect},
		"response_type":         []string{"code"},
		"scope":                 []string{"openid email"},
		"state":                 []string{"state-none"},
		"nonce":                 []string{"nonce-none"},
		"prompt":                []string{"none"},
		"code_challenge":        []string{challenge},
		"code_challenge_method": []string{"S256"},
	}

	rec := f.do(t, http.MethodGet, oidc.PathAuthorize+"?"+query.Encode(), "", nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize with prompt=none = %d, want 302; body: %s", rec.Code, rec.Body)
	}

	redirect, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("the redirect is not a URL: %v", err)
	}
	if got := redirect.Scheme + "://" + redirect.Host + redirect.Path; got != oidcTestRedirect {
		t.Errorf("the error went to %q, want the registered %q", got, oidcTestRedirect)
	}
	if err := redirect.Query().Get("error"); err != "login_required" {
		t.Errorf("error = %q, want login_required", err)
	}
	if got := redirect.Query().Get("state"); got != "state-none" {
		t.Errorf("state = %q, want the client's own value echoed back", got)
	}
}

// The two well-known documents and the key set, fetched by a client before it has
// authenticated anything.
func TestOIDCWellKnownDocuments(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)

	t.Run("discovery", func(t *testing.T) {
		t.Parallel()

		for _, path := range []string{oidc.PathDiscovery, oidc.PathOAuthAuthorizationServer} {
			rec := f.do(t, http.MethodGet, path, "", nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s = %d, want 200; body: %s", path, rec.Code, rec.Body)
			}
			if rec.Header().Get("Content-Type") != "application/json; charset=utf-8" {
				t.Errorf("%s Content-Type = %q", path, rec.Header().Get("Content-Type"))
			}
			if rec.JSON["issuer"] != oidcTestIssuer {
				t.Errorf("%s issuer = %v, want %q", path, rec.JSON["issuer"], oidcTestIssuer)
			}
			if rec.JSON["jwks_uri"] != oidcTestIssuer+oidc.PathJWKS {
				t.Errorf("%s jwks_uri = %v, want the path guard hardcodes", path, rec.JSON["jwks_uri"])
			}
		}
	})

	t.Run("the key set", func(t *testing.T) {
		t.Parallel()

		rec := f.do(t, http.MethodGet, oidc.PathJWKS, "", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET the jwks = %d, want 200; body: %s", rec.Code, rec.Body)
		}
		if got := rec.JSON["keys"]; got == nil {
			t.Fatal("the key set has no keys array; guard's isKeySet refuses an empty one")
		}
		keys, _ := rec.JSON["keys"].([]any)
		if len(keys) != 1 {
			t.Fatalf("the key set has %d keys, want exactly 1", len(keys))
		}
		first, _ := keys[0].(map[string]any)
		if first["kid"] != oidcTestKeyID {
			t.Errorf("kid = %v, want %q; the id in the document has to be the one the token header carries", first["kid"], oidcTestKeyID)
		}
		if first["alg"] != "RS256" {
			t.Errorf("alg = %v, want RS256", first["alg"])
		}
		if first["use"] != "sig" {
			t.Errorf("use = %v, want sig", first["use"])
		}
		if _, present := first["d"]; present {
			t.Error("the published key set carries the private exponent")
		}
		if rec.Header().Get("Cache-Control") == "" {
			t.Error("the key set has no Cache-Control; every edge in the platform re-fetches it")
		}
	})
}

// The endpoints this service does not serve are absent from the document, and a
// request to one is a 404 with this service's own problem envelope rather than a
// hang or a bare text response.
func TestOIDCUnmountedEndpointsAre404(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)

	for _, target := range []string{"/oidc/introspect", "/oidc/revoke", "/oidc/end-session", "/oidc/device_authorization"} {
		rec := f.do(t, http.MethodPost, target, "", nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("POST %s = %d, want 404", target, rec.Code)
		}
		if rec.Header().Get("Content-Type") != "application/problem+json" {
			t.Errorf("POST %s Content-Type = %q, want the cafaye problem envelope rather than the library's",
				target, rec.Header().Get("Content-Type"))
		}
	}
}

// A user who already has a session skips the form. That is what makes signing in
// to a second product not require typing the same password again, and it is why
// the login page reads the session rather than demanding credentials.
func TestOIDCLoginSkipsTheFormForASignedInUser(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	verifier, challenge := codeVerifier(t)
	loginURL := f.authorize(t, client, challenge, "state-silent", "nonce-silent", nil)

	// The fixture's jar already holds the owner's session, so this GET is a
	// signed-in user arriving at the login page.
	rec := f.do(t, http.MethodGet, loginURL, "", nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("GET the login page while signed in = %d, want 302 straight to the client; body: %s", rec.Code, rec.Body)
	}
	redirect, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("the redirect is not a URL: %v", err)
	}
	code := redirect.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in the redirect: %s", redirect)
	}
	if got := f.exchange(t, client, code, verifier, oidcTestRedirect).Code; got != http.StatusOK {
		t.Errorf("the exchange after a silent login = %d, want 200", got)
	}
}

// The nonce is the client's own replay defence and the provider's obligation to
// echo it. A token without it, or with somebody else's, is a token a client
// cannot safely accept.
func TestOIDCNonceIsEchoedUnchanged(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	const nonce = "a-nonce-a-client-generated-and-would-recognise"
	verifier, challenge := codeVerifier(t)
	loginURL := f.authorize(t, client, challenge, "state-nonce", nonce, nil)
	rec := f.login(t, loginURL, client.Email, client.Password)
	code := mustCode(t, rec.Header().Get("Location"))

	tokens := f.exchange(t, client, code, verifier, oidcTestRedirect)
	if tokens.Code != http.StatusOK {
		t.Fatalf("the exchange = %d, want 200; body: %s", tokens.Code, tokens.Body)
	}
	var body map[string]any
	mustJSON(t, tokens.Body.Bytes(), &body)
	claims := f.verify(t, body["id_token"].(string))

	if claims["nonce"] != nonce {
		t.Errorf("id_token nonce = %v, want %q", claims["nonce"], nonce)
	}
}

// The authorization code is single-use AND bound to the verifier that asked for
// it. A captured code with the wrong verifier is the other half of PKCE and it
// has to fail.
func TestOIDCWrongCodeVerifierIsRefused(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	_, challenge := codeVerifier(t)
	loginURL := f.authorize(t, client, challenge, "state-verifier", "nonce-verifier", nil)
	rec := f.login(t, loginURL, client.Email, client.Password)
	code := mustCode(t, rec.Header().Get("Location"))

	wrong, _ := codeVerifier(t)
	refused := f.exchange(t, client, code, wrong, oidcTestRedirect)
	if refused.Code != http.StatusBadRequest {
		t.Fatalf("the exchange with the wrong verifier = %d, want 400; body: %s", refused.Code, refused.Body)
	}
	if err, _ := refused.JSON["error"].(string); err != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", err)
	}
}

// A login form submitted with no credentials is a 422 naming the fields, and it
// does not run an argon2id verification: there is nothing to check, and a
// memory-hard hash on an empty password would cost a real attacker's nothing and
// a legitimate user's page load.
func TestOIDCLoginWithNoCredentials(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	_, challenge := codeVerifier(t)
	loginURL := f.authorize(t, client, challenge, "state-empty", "nonce-empty", nil)

	f.signOut()
	form := f.do(t, http.MethodGet, loginURL, "", nil)
	sealed := hiddenState(t, form.Body.String())

	jar := &cookieJar{}
	jar.absorb(form.Result().Cookies())

	req := newRequestForm(http.MethodPost, loginURL, url.Values{
		"state":    []string{sealed},
		"email":    []string{""},
		"password": []string{""},
	})
	req.Header.Set("Cookie", jar.header())

	rec := newResponse(serveRecorder(f.handler, req))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("an empty login = %d, want 422; body: %s", rec.Code, rec.Body)
	}
	p := decodeProblem(t, rec.ResponseRecorder)
	if p.Code != CodeValidationFailed {
		t.Errorf("code = %q, want %q", p.Code, CodeValidationFailed)
	}
	if len(p.Errors) != 2 {
		t.Errorf("errors = %+v, want one per field", p.Errors)
	}
}

// A wrong password on the login page is the same answer as an unknown address,
// and one sentence. The login page is the most attractive enumeration oracle on
// the platform: it is unauthenticated, it takes an email, and it is the first
// thing an attacker types somebody else's address into.
func TestOIDCLoginDoesNotEnumerateAccounts(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	_, challenge := codeVerifier(t)
	loginURL := f.authorize(t, client, challenge, "state-enum", "nonce-enum", nil)

	submit := func(email, password string) Problem {
		t.Helper()

		f.signOut()
		form := f.do(t, http.MethodGet, loginURL, "", nil)
		sealed := hiddenState(t, form.Body.String())
		jar := &cookieJar{}
		jar.absorb(form.Result().Cookies())

		req := newRequestForm(http.MethodPost, loginURL, url.Values{
			"state":    []string{sealed},
			"email":    []string{email},
			"password": []string{password},
		})
		req.Header.Set("Cookie", jar.header())
		return decodeProblem(t, serveRecorder(f.handler, req))
	}

	wrongPassword := submit(f.email, "not the password at all")
	noSuchUser := submit("nobody-at-all@example.com", "not the password at all")

	if wrongPassword.Status != noSuchUser.Status {
		t.Errorf("a wrong password answered %d and an unknown address %d; the two must be one",
			wrongPassword.Status, noSuchUser.Status)
	}
	if wrongPassword.Detail != noSuchUser.Detail {
		t.Errorf("the two answers differ:\n  wrong password: %q\n  unknown address: %q",
			wrongPassword.Detail, noSuchUser.Detail)
	}
	if wrongPassword.Status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", wrongPassword.Status)
	}
}

// An authorization request id that never existed, and one that has expired, are
// the same 404. The id arrives in a URL, so distinguishing them would make it a
// probe for which authorizations are in flight.
func TestOIDCLoginWithAnUnknownRequestIs404(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)

	for _, target := range []string{oidc.PathLogin + "/00000000-0000-4000-8000-000000000000", oidc.PathLogin + "/not-an-id"} {
		rec := f.do(t, http.MethodGet, target, "", nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404; body: %s", target, rec.Code, rec.Body)
		}
		if p := decodeProblem(t, rec.ResponseRecorder); p.Code != CodeNotFound {
			t.Errorf("GET %s code = %q, want %q", target, p.Code, CodeNotFound)
		}
	}
}

// The discovery document, over the wire, from the handler the process serves. The
// provider package's tests assert the same fields on the object; this one proves
// the route is mounted and the bytes are JSON.
func TestOIDCDiscoveryOverHTTP(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)

	rec := f.do(t, http.MethodGet, oidc.PathDiscovery, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET discovery = %d, want 200", rec.Code)
	}
	for _, field := range []string{
		"issuer", "authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri",
		"scopes_supported", "response_types_supported", "grant_types_supported", "subject_types_supported",
		"id_token_signing_alg_values_supported", "token_endpoint_auth_methods_supported",
		"claims_supported", "code_challenge_methods_supported",
	} {
		if _, present := rec.JSON[field]; !present {
			t.Errorf("the document served at %s has no %q", oidc.PathDiscovery, field)
		}
	}
}

// A request for a route that does not exist is this service's problem document,
// not the library's. The library's router is mounted path by path precisely so
// that this stays true, and this is the test that holds the line.
func TestOIDCUnknownPathIsTheCafayeProblemEnvelope(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)

	for _, target := range []string{"/oidc/nope", "/oidc/authorize/extra", "/.well-known/nope"} {
		rec := f.do(t, http.MethodGet, target, "", nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", target, rec.Code)
			continue
		}
		if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
			t.Errorf("GET %s Content-Type = %q, want application/problem+json", target, got)
		}
	}
}

// The login page must not leak the session or be framed. A login form for a
// third party, on this service's own domain, is a target worth hardening and the
// three headers cost nothing.
func TestOIDCLoginPageHeaders(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	_, challenge := codeVerifier(t)
	loginURL := f.authorize(t, client, challenge, "state-headers", "nonce-headers", nil)

	// Signed out, so the form renders.
	f.signOut()
	req := newRequestNoCookie(http.MethodGet, loginURL)
	rec := serveRecorder(f.handler, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET the login page = %d, want 200", rec.Code)
	}

	for header, want := range map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
		"Cache-Control":          "no-store",
	} {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", got)
	}
}

// A registration is announced in the same transaction as the row, and a
// revocation in the same transaction as the bulk token revocation. An outbox row
// that outlives its transaction would announce a credential that does not exist.
func TestOIDCRegistrationEvents(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)

	var before, after int
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM outbox_events WHERE type = $1`,
		"identity.oidc_client.created").Scan(&before); err != nil {
		t.Fatalf("counting the created events: %v", err)
	}
	if before != 0 {
		t.Fatalf("there are %d created events before any registration", before)
	}

	client := f.registerClient(t)

	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM outbox_events WHERE type = $1`,
		"identity.oidc_client.created").Scan(&after); err != nil {
		t.Fatalf("counting the created events: %v", err)
	}
	if after != 1 {
		t.Fatalf("a registration wrote %d created events, want 1", after)
	}

	// The payload carries what a consumer auditing trust needs, and no credential.
	var envelope []byte
	if err := f.pool.QueryRow(t.Context(),
		`SELECT envelope FROM outbox_events WHERE type = $1`, "identity.oidc_client.created").Scan(&envelope); err != nil {
		t.Fatalf("reading the envelope: %v", err)
	}
	for _, forbidden := range []string{"secret", "digest", client.ClientSecret} {
		if strings.Contains(string(envelope), forbidden) {
			t.Errorf("the created envelope mentions %q:\n%s", forbidden, envelope)
		}
	}

	f.revoke(t, client)

	var revoked int
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM outbox_events WHERE type = $1`,
		"identity.oidc_client.revoked").Scan(&revoked); err != nil {
		t.Fatalf("counting the revoked events: %v", err)
	}
	if revoked != 1 {
		t.Errorf("a revocation wrote %d revoked events, want 1", revoked)
	}
}

// A second revocation is a 409 and not a 204. An operator who clicks twice should
// be told the credential is already dead rather than believing they had just
// destroyed a second one.
func TestOIDCRevokingTwiceIs409(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	first := f.do(t, http.MethodDelete, "/v1/accounts/"+f.account.String()+"/oidc-clients/"+client.ID, "", nil)
	if first.Code != http.StatusNoContent {
		t.Fatalf("the first revocation = %d, want 204; body: %s", first.Code, first.Body)
	}

	second := f.do(t, http.MethodDelete, "/v1/accounts/"+f.account.String()+"/oidc-clients/"+client.ID, "", nil)
	if second.Code != http.StatusConflict {
		t.Fatalf("the second revocation = %d, want 409; body: %s", second.Code, second.Body)
	}
	if p := decodeProblem(t, second.ResponseRecorder); p.Code != CodeConflict {
		t.Errorf("code = %q, want %q", p.Code, CodeConflict)
	}
}

// The registration response is the only place the secret exists. It is not
// stored, it is not in the list, and it is not in the detail view — a client that
// loses it registers again, which is the same rule a session token follows.
func TestOIDCClientSecretIsReturnedOnce(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	list := f.do(t, http.MethodGet, "/v1/accounts/"+f.account.String()+"/oidc-clients", "", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("listing clients = %d, want 200; body: %s", list.Code, list.Body)
	}
	if strings.Contains(list.Body.String(), client.ClientSecret) {
		t.Error("the list carries the client secret")
	}
	if strings.Contains(list.Body.String(), "secret_digest") {
		t.Error("the list carries the secret digest")
	}

	detail := f.do(t, http.MethodGet, "/v1/accounts/"+f.account.String()+"/oidc-clients/"+client.ID, "", nil)
	if detail.Code != http.StatusOK {
		t.Fatalf("reading a client = %d, want 200; body: %s", detail.Code, detail.Body)
	}
	for _, forbidden := range []string{client.ClientSecret, "secret_digest"} {
		if strings.Contains(detail.Body.String(), forbidden) {
			t.Errorf("the detail carries %q", forbidden)
		}
	}

	// And it is in the row only as a digest.
	var digest string
	if err := f.pool.QueryRow(t.Context(),
		`SELECT secret_digest FROM oidc_clients WHERE id = $1`, mustParseID(t, client.ID)).Scan(&digest); err != nil {
		t.Fatalf("reading the stored digest: %v", err)
	}
	if digest == client.ClientSecret {
		t.Error("the row holds the secret in plaintext")
	}
	if len(digest) != 64 {
		t.Errorf("the stored digest is %d characters, want 64", len(digest))
	}
}

// A registration an operator cannot see is a 404, not a 403, and it is the same
// 404 as one that does not exist.
func TestOIDCClientIsScopedToItsAccount(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	other, otherSession := f.otherAccount(t)

	rec := f.doAs(t, otherSession, http.MethodGet, "/v1/accounts/"+other.String()+"/oidc-clients/"+client.ID, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("reading another account's client = %d, want 404; body: %s", rec.Code, rec.Body)
	}
	if p := decodeProblem(t, rec.ResponseRecorder); p.Code != CodeNotFound {
		t.Errorf("code = %q, want %q", p.Code, CodeNotFound)
	}

	revoked := f.doAs(t, otherSession, http.MethodDelete, "/v1/accounts/"+other.String()+"/oidc-clients/"+client.ID, "")
	if revoked.Code != http.StatusNotFound {
		t.Errorf("revoking another account's client = %d, want 404; body: %s", revoked.Code, revoked.Body)
	}
}

// The registration rules, through the route. A product that configures one of
// these wrong finds out at registration time with a field name, not at 3am from a
// user whose sign-in silently does not work.
func TestOIDCClientRegistrationValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		body      string
		wantField string
	}{
		{
			name: "no name",
			body: fmt.Sprintf(`{"redirect_uris":[%q],"grant_types":["authorization_code"],"scopes":["openid"]}`,
				oidcTestRedirect),
			wantField: "name",
		},
		{
			name: "no redirect URIs",
			body: `{"name":"Anytalk","redirect_uris":[],"grant_types":["authorization_code"],"scopes":["openid"]}`,
			// An empty allow-list is not a client with no origins; it is a client
			// that can be sent anywhere, and the difference matters.
			wantField: "redirect_uris",
		},
		{
			name: "a plain-http origin",
			body: `{"name":"Anytalk","redirect_uris":["http://app.example.com/cb"],` +
				`"grant_types":["authorization_code"],"scopes":["openid"]}`,
			wantField: "redirect_uris",
		},
		{
			name: "a wildcard origin",
			body: `{"name":"Anytalk","redirect_uris":["https://*.example.com/cb"],` +
				`"grant_types":["authorization_code"],"scopes":["openid"]}`,
			wantField: "redirect_uris",
		},
		{
			name: "a grant this service does not implement",
			body: fmt.Sprintf(`{"name":"Anytalk","redirect_uris":[%q],"grant_types":["refresh_token"],`+
				`"scopes":["openid"]}`, oidcTestRedirect),
			wantField: "grant_types",
		},
		{
			name: "scopes with no openid",
			body: fmt.Sprintf(`{"name":"Anytalk","redirect_uris":[%q],"grant_types":["authorization_code"],`+
				`"scopes":["email"]}`, oidcTestRedirect),
			wantField: "scopes",
		},
		{
			name: "an unknown field",
			body: fmt.Sprintf(`{"name":"Anytalk","redirect_uris":[%q],"grant_types":["authorization_code"],`+
				`"scopes":["openid"],"is_admin":true}`, oidcTestRedirect),
			wantField: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newOIDCFixture(t)
			rec := f.do(t, http.MethodPost, "/v1/accounts/"+f.account.String()+"/oidc-clients", tt.body, nil)

			if tt.wantField == "" {
				if rec.Code != http.StatusUnprocessableEntity {
					t.Fatalf("= %d, want 422; body: %s", rec.Code, rec.Body)
				}
				return
			}

			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("= %d, want 422; body: %s", rec.Code, rec.Body)
			}
			p := decodeProblem(t, rec.ResponseRecorder)
			if len(p.Errors) != 1 || p.Errors[0].Field != tt.wantField {
				t.Errorf("errors = %+v, want one entry on %q", p.Errors, tt.wantField)
			}
		})
	}
}

// The registration response's shape, asserted field by field. A response that
// returns 201 with the wrong body is a failure, not a pass.
func TestOIDCClientRegistrationResponse(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)
	client := f.registerClient(t)

	rec := f.do(t, http.MethodGet, "/v1/accounts/"+f.account.String()+"/oidc-clients/"+client.ID, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("= %d, want 200; body: %s", rec.Code, rec.Body)
	}

	want := []string{"id", "client_id", "name", "redirect_uris", "grant_types", "scopes", "created_at"}
	if len(rec.JSON) != len(want) {
		t.Errorf("the body has %d fields (%v), want exactly %d", len(rec.JSON), sortedKeys(rec.JSON), len(want))
	}
	for _, field := range want {
		if _, present := rec.JSON[field]; !present {
			t.Errorf("the body has no %q", field)
		}
	}
	if rec.JSON["name"] != "Anytalk" {
		t.Errorf("name = %v, want Anytalk", rec.JSON["name"])
	}
	if uris, _ := rec.JSON["redirect_uris"].([]any); len(uris) != 1 || uris[0] != oidcTestRedirect {
		t.Errorf("redirect_uris = %v, want the one registered", rec.JSON["redirect_uris"])
	}
	if grants, _ := rec.JSON["grant_types"].([]any); len(grants) != 1 || grants[0] != "authorization_code" {
		t.Errorf("grant_types = %v, want [authorization_code]", rec.JSON["grant_types"])
	}
	if scopes, _ := rec.JSON["scopes"].([]any); !slices.Contains(scopes, "openid") {
		t.Errorf("scopes = %v, want them to include openid", rec.JSON["scopes"])
	}
}

// An empty list is [] and not null, for the same reason the account list is.
func TestOIDCClientListIsAnArrayNotNull(t *testing.T) {
	t.Parallel()

	f := newOIDCFixture(t)

	rec := f.do(t, http.MethodGet, "/v1/accounts/"+f.account.String()+"/oidc-clients", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("= %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if trimmed := strings.TrimSpace(rec.Body.String()); trimmed != "[]" {
		t.Errorf("body = %s, want []", trimmed)
	}
}

// ---------------------------------------------------------------------------
// helpers the cases above share
// ---------------------------------------------------------------------------

// revoke revokes a registration through the real route, as the owner.
func (f *oidcFixture) revoke(t *testing.T, client registered) {
	t.Helper()

	rec := f.do(t, http.MethodDelete, "/v1/accounts/"+f.account.String()+"/oidc-clients/"+client.ID, "", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoking a client = %d, want 204; body: %s", rec.Code, rec.Body)
	}
}

// otherAccount creates a second account owned by a second user, and returns the
// account and that user's session token.
func (f *oidcFixture) otherAccount(t *testing.T) (id.UUID, string) {
	t.Helper()

	email := dbtest.UniqueEmail(t)
	rec := f.do(t, http.MethodPost, "/v1/users", `{"email":"`+email+`","password":"`+oidcTestPassword+`"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering a second user: %d; body: %s", rec.Code, rec.Body)
	}
	var created userResponse
	mustJSON(t, rec.Body.Bytes(), &created)

	login := f.do(t, http.MethodPost, "/v1/session", `{"email":"`+email+`","password":"`+oidcTestPassword+`"}`, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("signing the second user in: %d; body: %s", login.Code, login.Body)
	}
	var session sessionResponse
	mustJSON(t, login.Body.Bytes(), &session)

	owner := mustParseID(t, created.ID)
	created2, err := f.tenantAccount(t, owner)
	if err != nil {
		t.Fatalf("creating a second account: %v", err)
	}
	return created2, session.Token
}

// doAs issues a request as a specific bearer token, ignoring the jar. Used for
// the cross-account cases, where using the owner's session would be the point.
func (f *oidcFixture) doAs(t *testing.T, token, method, target, body string) *oidcResponse {
	t.Helper()

	return f.doWithSession(t, token, method, target, body, nil)
}
