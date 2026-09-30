package oidc

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
)

// The library's Storage, over this service's tables.
//
// THIS IS WHERE THE PACKET'S DECISIONS LIVE. Everything else in internal/oidc is
// data; this file is the adapter that answers the OAuth 2.0 state machine's
// questions from rows identity owns, and the places it says "no" are the security
// properties the brief asks for:
//
//   - a client is looked up by exact handle and a revoked one is refused
//   - the client secret is matched as a digest and never as a value
//   - an authorization code is redeemed by one conditional UPDATE
//   - a request whose code challenge is absent or not S256 cannot be redeemed
//   - the redirect URI is checked against the registration by the library, using
//     an exact match, because nothing here implements op.HasRedirectGlobs
//
// Three methods return errors rather than doing something half-way, and each
// says why at its own definition: refresh tokens, client credentials and the JWT
// profile grant are all unimplemented, and a provider that pretended otherwise
// would be a provider whose discovery document lies.

// Storage is this service's op.Storage.
//
// It is built once and shared. Every field is immutable after construction and
// none of them is per-request state, so there is nothing to synchronize.
type Storage struct {
	store    *Store
	profiles ProfileReader
	key      *SigningKey
	clk      clock.Clock
	read     db.QuerierSource
	// loginBase is the path the login UI is mounted at, and it is here rather
	// than in a constant because the router and the client implementation have
	// to agree on it and one of the two is going to move first.
	loginBase string
}

// Compile-time proof that the adapter is the library's Storage, and that the
// auth request is its AuthRequest. A method-set change upstream fails here with
// a message naming the interface rather than in a call site three layers down.
var (
	_ op.Storage                   = (*Storage)(nil)
	_ op.AuthRequest               = (*AuthRequest)(nil)
	_ op.CanSetUserinfoFromRequest = (*Storage)(nil)
)

// NewStorage wires the adapter.
func NewStorage(store *Store, profiles ProfileReader, key *SigningKey, clk clock.Clock, read db.QuerierSource, loginBase string) *Storage {
	return &Storage{store: store, profiles: profiles, key: key, clk: clk, read: read, loginBase: loginBase}
}

// ---------------------------------------------------------------------------
// clients
// ---------------------------------------------------------------------------

// GetClientByClientID returns a registration, or an error the library turns into
// a 400 on the authorization endpoint.
//
// A revoked client is ErrRevoked rather than ErrNotFound, and the difference
// does not reach a caller: the library renders both as the same invalid_request
// with the same description. It is kept apart internally so the log says which
// happened, because "a revoked client is still being called" is an incident and
// "a client id does not exist" is a typo.
func (s *Storage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	client, err := s.store.ClientByClientID(ctx, s.read.Queryer(), clientID)
	if err != nil {
		return nil, err
	}
	return s.protocolClient(client)
}

// AuthorizeClientIDSecret checks a token request's credential.
//
// Two refusals and one answer, all constant in what they disclose. The digest
// comparison is an indexed SQL equality, the same construction
// internal/sessions uses, and the reason is written there: the presented value
// is 32 random bytes with no structure to time an attack against, and the lookup
// is an ordinary indexed read either way.
func (s *Storage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	client, err := s.store.ClientByClientID(ctx, s.read.Queryer(), clientID)
	if err != nil {
		// Not distinguished from a wrong secret at the boundary. A caller that
		// could tell "no such client" from "wrong secret" would have an oracle
		// for which products are registered on this platform.
		return ErrInvalidSecret
	}
	if !client.IsActive() {
		return ErrRevoked
	}
	if client.SecretDigest != SecretDigest(clientSecret) {
		return ErrInvalidSecret
	}
	return nil
}

// protocolClient wraps a domain Client in the library's op.Client.
//
// The wrapper exists so the domain type carries no protocol methods: a change to
// what identity stores and a change to what the library asks for are then two
// edits in two files, and reading client.go does not require knowing the
// library's interface.
type protocolClient struct {
	client    Client
	loginBase string
}

func (s *Storage) protocolClient(c Client) (op.Client, error) {
	if !c.IsActive() {
		return nil, ErrRevoked
	}
	return protocolClient{client: c, loginBase: s.loginBase}, nil
}

func (c protocolClient) GetID() string { return c.client.ClientID }

// RedirectURIs is the allow-list, and this service implements NO glob interface.
//
// op.HasRedirectGlobs is the library's escape hatch for pattern matching, and
// not implementing it is the decision: checkURIAgainstRedirects asks
// slices.Contains first and only then consults the optional interface, so a
// client that does not implement it can be matched by nothing but equality.
// That is what makes `https://app.example.com.evil.com/cb` a refusal against a
// registered `https://app.example.com/cb`.
func (c protocolClient) RedirectURIs() []string { return c.client.RedirectURIs }

func (c protocolClient) PostLogoutRedirectURIs() []string { return nil }

// ApplicationType is web: a confidential client that keeps a secret.
//
// Native and user-agent applications cannot keep a secret, and this
// registration model requires one — so a mobile or desktop product is a public
// client with PKCE and no secret, which is a different table in a later packet.
func (c protocolClient) ApplicationType() op.ApplicationType { return op.ApplicationTypeWeb }

// AuthMethod is HTTP Basic, which is what a confidential client uses and what
// every OIDC client library implements first.
func (c protocolClient) AuthMethod() oidc.AuthMethod { return oidc.AuthMethodBasic }

// ResponseTypes is code only. No implicit flow: an implicit token arrives in a
// URL fragment, which is a worse place for a credential than a POST body, and
// the brief's flow is code + PKCE.
func (c protocolClient) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}

// GrantTypes comes from the registration, so a client that registered
// authorization_code and nothing else is refused anything else at the token
// endpoint.
func (c protocolClient) GrantTypes() []oidc.GrantType {
	out := make([]oidc.GrantType, 0, len(c.client.GrantTypes))
	for _, g := range c.client.GrantTypes {
		out = append(out, oidc.GrantType(g))
	}
	return out
}

// LoginURL is where the browser goes to authenticate.
//
// This is the one place the protocol hands control to something that is not the
// protocol, and it is this service's own login page — the same sessions, the
// same cookie, the same password check as POST /v1/session. A separate sign-in
// for OIDC would be a second credential store, which is the thing a security
// boundary is not allowed to have.
func (c protocolClient) LoginURL(requestID string) string {
	return c.loginBase + "/" + requestID
}

// AccessTokenType is JWT, so the access token is signed with the published key
// and verifiable by guard without a round trip to this service.
func (c protocolClient) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeJWT }

// IDTokenLifetime is core's access-token cap, applied to the id_token as well. An
// id_token is a credential, and a product holding one for a week is holding a
// week-old assertion about who somebody is.
func (c protocolClient) IDTokenLifetime() time.Duration { return IDTokenTTL }

// DevMode is false. DevMode relaxes the library's redirect-URI rules — plain
// http, native loopback — and those are already handled by refusing non-loopback
// http at REGISTRATION time. Two places to relax a rule is one too many.
func (c protocolClient) DevMode() bool { return false }

// RestrictAdditionalIdTokenScopes and RestrictAdditionalAccessTokenScopes pass
// through. A client may only be granted scopes it registered for, and that is
// enforced in validateScopes below rather than here: this hook is a narrowing
// filter and implementing it as one would be a second answer to the same
// question.
func (c protocolClient) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(scopes []string) []string { return scopes }
}

func (c protocolClient) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(scopes []string) []string { return scopes }
}

// IsScopeAllowed is the client's own scope list, which is what lets a custom
// scope — `accounts` — survive the library's ValidateAuthReqScopes, which drops
// anything it does not recognise.
func (c protocolClient) IsScopeAllowed(scope string) bool { return c.client.AllowsScope(scope) }

// IDTokenUserinfoClaimsAssertion is true, so the id_token carries the email and
// the name as well as the sub.
//
// A product that has to make a second round trip to userinfo to learn a user's
// email is a product with a second failure mode on its sign-in path, and the
// claims are already in the rows this service just read. It also means the
// `email` scope has to be granted for them to appear — a client that did not ask
// for email gets a token with no email in it.
func (c protocolClient) IDTokenUserinfoClaimsAssertion() bool { return true }

// ClockSkew is zero. The provider and the verifier are the same deployment's
// concern, and a skew that hides a clock disagreement is a skew that hides it
// until the token is out of tolerance in the other direction.
func (c protocolClient) ClockSkew() time.Duration { return 0 }

// ---------------------------------------------------------------------------
// the signing key
// ---------------------------------------------------------------------------

func (s *Storage) SigningKey(context.Context) (op.SigningKey, error) {
	if s.key == nil {
		return nil, ErrNoSigningKey
	}
	return s.key, nil
}

// SignatureAlgorithms is RS256 and nothing else. guard pins RS256 before it
// fetches anything, and a discovery document advertising a second algorithm is a
// document promising a key this service does not publish.
func (s *Storage) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}

// KeySet is the published set: the one public key.
func (s *Storage) KeySet(context.Context) ([]op.Key, error) {
	if s.key == nil {
		return nil, ErrNoSigningKey
	}
	return []op.Key{PublicKeyOf(s.key)}, nil
}

// ---------------------------------------------------------------------------
// authorization requests and codes
// ---------------------------------------------------------------------------

// CreateAuthRequest records a validated request.
//
// prompt=none is refused here rather than answered: with no interaction there is
// no way for the user to log in, so the honest answer is login_required, and
// answering it from the storage layer means every route into the flow gets it.
func (s *Storage) CreateAuthRequest(ctx context.Context, authReq *oidc.AuthRequest, _ string) (op.AuthRequest, error) {
	if slices.Contains(authReq.Prompt, oidc.PromptNone) {
		return nil, oidc.ErrLoginRequired()
	}

	client, err := s.store.ClientByClientID(ctx, s.read.Queryer(), authReq.ClientID)
	if err != nil {
		return nil, err
	}

	now := s.clk.Now()
	request, err := s.store.CreateAuthRequest(ctx, s.read.Queryer(), NewAuthRequest{
		ClientRowID:         client.ID,
		RedirectURI:         authReq.RedirectURI,
		State:               authReq.State,
		Nonce:               authReq.Nonce,
		ResponseType:        string(authReq.ResponseType),
		ResponseMode:        string(authReq.ResponseMode),
		Scopes:              authReq.Scopes,
		CodeChallenge:       authReq.CodeChallenge,
		CodeChallengeMethod: string(authReq.CodeChallengeMethod),
		LoginHint:           authReq.LoginHint,
		CreatedAt:           now,
		ExpiresAt:           now.Add(AuthRequestTTL),
	})
	if err != nil {
		return nil, err
	}
	return &request, nil
}

func (s *Storage) AuthRequestByID(ctx context.Context, requestID string) (op.AuthRequest, error) {
	rowID, err := id.Parse(requestID)
	if err != nil {
		return nil, fmt.Errorf("%w: not an id this service issued", ErrAuthRequestNotFound)
	}
	request, err := s.store.AuthRequestByID(ctx, s.read.Queryer(), rowID, s.clk.Now())
	if err != nil {
		return nil, err
	}
	return &request, nil
}

// AuthRequestByCode redeems an authorization code.
//
// The single-use gate is inside the store's one conditional UPDATE, so this
// method is a thin wrapper — and the PKCE rule is enforced here, on the
// REQUEST rather than on the token request. A request that was stored without an
// S256 challenge cannot be redeemed even if something upstream let it through:
// the authorize handler refuses one, the table's CHECK refuses one, and this
// refuses one. Three gates for one rule is one more than a careful reader needs,
// and the cost of the extra is a line.
func (s *Storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	request, err := s.store.ConsumeAuthCode(ctx, s.read.Queryer(), SecretDigest(code), s.clk.Now())
	if err != nil {
		return nil, err
	}
	if err := requireS256(request.CodeChallengeMethod); err != nil {
		return nil, err
	}
	return &request, nil
}

// requireS256 refuses anything but S256.
//
// The library verifies a `plain` challenge happily — plain means "the verifier
// IS the challenge", which is only safe for a public client that has no secret to
// steal. Every client in this service is confidential, so a plain challenge would
// mean an intercepted code is redeemable by whoever intercepted it.
func requireS256(method string) error {
	if method != string(oidc.CodeChallengeMethodS256) {
		return fmt.Errorf("%w: this provider requires PKCE with S256, the request carried %q", ErrNoAuthCode, method)
	}
	return nil
}

// SaveAuthCode stores the digest of a freshly minted code.
func (s *Storage) SaveAuthCode(ctx context.Context, requestID, code string) error {
	rowID, err := id.Parse(requestID)
	if err != nil {
		return ErrNoAuthCode
	}
	return s.store.SaveAuthCode(ctx, s.read.Queryer(), rowID, SecretDigest(code), s.clk.Now().Add(AuthorizationCodeTTL))
}

// DeleteAuthRequest tidies up after a token response. Idempotent; see the store.
func (s *Storage) DeleteAuthRequest(ctx context.Context, requestID string) error {
	rowID, err := id.Parse(requestID)
	if err != nil {
		return nil
	}
	return s.store.DeleteAuthRequest(ctx, s.read.Queryer(), rowID)
}

// ---------------------------------------------------------------------------
// op.AuthRequest
// ---------------------------------------------------------------------------

// The op.AuthRequest implementation, on the domain type. Read one section at a
// time: what the request SAYS, and what it produced.

func (r *AuthRequest) GetID() string { return r.ID.String() }

// GetACR is empty. This provider does not assert an authentication context class
// and a token that carried one would be a claim about a mechanism identity does
// not have yet.
func (r *AuthRequest) GetACR() string { return "" }

// GetAMR is `pwd` once a user has authenticated, and nothing before. A token
// that claimed a method nobody used is a token a relying party might make a
// decision on.
func (r *AuthRequest) GetAMR() []string {
	if r.AuthTime == nil {
		return nil
	}
	return []string{"pwd"}
}

// GetAudience is the client itself, which is the only audience an OIDC token has.
func (r *AuthRequest) GetAudience() []string { return []string{r.ClientID} }

func (r *AuthRequest) GetAuthTime() time.Time {
	if r.AuthTime == nil {
		return time.Time{}
	}
	return *r.AuthTime
}

func (r *AuthRequest) GetClientID() string { return r.ClientID }

func (r *AuthRequest) GetCodeChallenge() *oidc.CodeChallenge {
	return &oidc.CodeChallenge{
		Challenge: r.CodeChallenge,
		Method:    oidc.CodeChallengeMethod(r.CodeChallengeMethod),
	}
}

func (r *AuthRequest) GetNonce() string                   { return r.Nonce }
func (r *AuthRequest) GetRedirectURI() string             { return r.RedirectURI }
func (r *AuthRequest) GetResponseType() oidc.ResponseType { return oidc.ResponseType(r.ResponseType) }
func (r *AuthRequest) GetResponseMode() oidc.ResponseMode { return oidc.ResponseMode(r.ResponseMode) }
func (r *AuthRequest) GetScopes() []string                { return r.Scopes }
func (r *AuthRequest) GetState() string                   { return r.State }

// GetSubject is the authenticated user, or "" before anyone has logged in.
func (r *AuthRequest) GetSubject() string {
	if r.Subject == nil {
		return ""
	}
	return r.Subject.String()
}

// Done reads auth_time rather than subject, and the distinction is load-bearing.
// A request can know who is expected — that is what an `id_token_hint` carries,
// and the library hands its subject to CreateAuthRequest — without anyone having
// authenticated, and a Done() that read the subject would let such a request
// build a token response with no user having typed a password.
func (r *AuthRequest) Done() bool { return r.AuthTime != nil }

// ---------------------------------------------------------------------------
// tokens
// ---------------------------------------------------------------------------

// CreateAccessToken records an access token and returns its id and expiry.
//
// The id becomes the token's `jti` and is the only handle userinfo has on it, so
// it is minted here, once, and written and signed from the same value.
func (s *Storage) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	subject, err := subjectOf(request)
	if err != nil {
		return "", time.Time{}, err
	}

	clientRow, err := s.clientRowFor(ctx, request.GetAudience())
	if err != nil {
		return "", time.Time{}, err
	}

	now := s.clk.Now()
	expiresAt := now.Add(AccessTokenTTL)
	tokenID := id.MustNew()

	if err := s.store.CreateAccessToken(ctx, s.read.Queryer(), NewAccessToken{
		ID:          tokenID,
		ClientRowID: clientRow.ID,
		Subject:     subject,
		Scopes:      request.GetScopes(),
		IssuedAt:    now,
		ExpiresAt:   expiresAt,
	}); err != nil {
		return "", time.Time{}, err
	}
	return tokenID.String(), expiresAt, nil
}

// CreateAccessAndRefreshTokens refuses, and says why at the point of refusal.
//
// The interface requires it and this service has no refresh token store. An
// implementation that minted an opaque value and kept it in memory would look
// like a working refresh grant until the first restart, and an implementation
// that returned an error is what a client would then have to handle anyway —
// so it is the error, at registration time the client was already told about.
func (s *Storage) CreateAccessAndRefreshTokens(context.Context, op.TokenRequest, string) (string, string, time.Time, error) {
	return "", "", time.Time{}, errRefreshTokenUnsupported
}

var errRefreshTokenUnsupported = errors.New("oidc: the refresh_token grant is not implemented; " +
	"this provider issues short-lived access tokens and no refresh token")

// TokenRequestByRefreshToken refuses, for the same reason.
func (s *Storage) TokenRequestByRefreshToken(context.Context, string) (op.RefreshTokenRequest, error) {
	return nil, errRefreshTokenUnsupported
}

// GetRefreshTokenInfo refuses, for the same reason. It must return
// op.ErrInvalidRefreshToken for anything that is not a refresh token, and this
// provider has none, so every input is one.
func (s *Storage) GetRefreshTokenInfo(context.Context, string, string) (string, string, error) {
	return "", "", op.ErrInvalidRefreshToken
}

// TerminateSession is a no-op, and it is honest about why.
//
// There is no per-client session store: an OIDC token is a signed JWT with a row
// behind it, and "logging out of a product" in this service means the user
// revokes the session that minted the code, which is DELETE /v1/session and has
// nothing to do with a client id. Deleting rows here would be a plausible-looking
// implementation of a feature that does not exist.
func (s *Storage) TerminateSession(context.Context, string, string) error { return nil }

// RevokeAccessTokensForClient stops every token issued to a registration.
//
// It runs from RevokeClient, not from the revocation endpoint: a revoked
// registration whose access tokens keep working for up to fifteen more minutes
// is a revoked registration that is not revoked. It is a bulk UPDATE and it is
// idempotent.
func (s *Storage) RevokeAccessTokensForClient(ctx context.Context, q db.Querier, clientRowID id.UUID, at time.Time) error {
	const query = `UPDATE oidc_access_tokens SET revoked_at = $2 WHERE client_row_id = $1 AND revoked_at IS NULL`
	if _, err := q.Exec(ctx, query, clientRowID, at); err != nil {
		return fmt.Errorf("oidc: revoking a client's access tokens: %w", err)
	}
	return nil
}

// RevokeToken implements RFC 7009 for one token.
//
// The endpoint is NOT mounted in this packet, so this method is unreachable
// today. It is implemented rather than stubbed because the interface requires it
// and a method that returned a fake success would be a lie waiting for the day
// somebody mounts the endpoint. Revoking an unknown token returns nil, which is
// what RFC 7009 §2.2 requires: "the authorization server responds with HTTP
// status code 200" whether or not the token existed.
func (s *Storage) RevokeToken(ctx context.Context, tokenOrTokenID, _, _ string) *oidc.Error {
	parsed, err := id.Parse(tokenOrTokenID)
	if err != nil {
		return nil
	}
	if err := s.store.RevokeAccessToken(ctx, s.read.Queryer(), parsed, s.clk.Now()); err != nil {
		return oidc.ErrServerError().WithParent(err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// claims
// ---------------------------------------------------------------------------

// SetUserinfoFromScopes is empty on purpose.
//
// The library marks it deprecated and calls SetUserinfoFromRequest instead. An
// implementation here would be a second answer to the same question, and the
// second one is the one a later reader would trust.
func (s *Storage) SetUserinfoFromScopes(context.Context, *oidc.UserInfo, string, string, []string) error {
	return nil
}

// SetUserinfoFromRequest fills an id_token's claims.
func (s *Storage) SetUserinfoFromRequest(ctx context.Context, userinfo *oidc.UserInfo, request op.IDTokenRequest, scopes []string) error {
	return s.setUserinfo(ctx, userinfo, request.GetSubject(), request.GetClientID(), scopes)
}

// SetUserinfoFromToken fills a userinfo response.
//
// The scopes come from the TOKEN, not from the request and not from the client:
// a token granted `openid email` must not be able to ask userinfo for `accounts`,
// because userinfo is called with whatever token a caller has and the caller's
// holding it proves nothing about what it was granted.
func (s *Storage) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, _, _ string) error {
	parsed, err := id.Parse(tokenID)
	if err != nil {
		return ErrNoAccessToken
	}
	token, err := s.store.AccessToken(ctx, s.read.Queryer(), parsed)
	if err != nil {
		return err
	}
	client, err := s.store.ClientByRowID(ctx, s.read.Queryer(), token.ClientRowID)
	if err != nil {
		return err
	}
	return s.setUserinfo(ctx, userinfo, token.Subject.String(), client.ClientID, token.Scopes)
}

// setUserinfo is the one place a claim is decided.
//
// The scopes are intersected with the client's registration before anything is
// read, so a token cannot be widened by naming a scope the client never
// registered — the intersection is the answer, and it is taken from both sides
// because a token could otherwise have been issued with a scope the registration
// has since been narrowed to exclude.
func (s *Storage) setUserinfo(ctx context.Context, userinfo *oidc.UserInfo, subject, clientID string, scopes []string) error {
	client, err := s.store.ClientByClientID(ctx, s.read.Queryer(), clientID)
	if err != nil {
		return err
	}

	granted := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if client.AllowsScope(scope) {
			granted = append(granted, scope)
		}
	}
	if !slices.Contains(granted, ScopeOpenID) {
		// No openid, no sub, and therefore no identity at all. The library's own
		// removeUserinfoScopes keeps `openid` precisely so this case is
		// reachable rather than silent.
		return fmt.Errorf("%w: this token was granted no openid scope, so it identifies nobody", ErrNoProfile)
	}

	parsed, err := id.Parse(subject)
	if err != nil {
		return fmt.Errorf("%w: the subject on this token is not an id", ErrNoProfile)
	}
	profile, err := s.profiles.Profile(ctx, s.read.Queryer(), parsed)
	if err != nil {
		return err
	}

	userinfo.Subject = profile.UserID.String()

	if slices.Contains(granted, ScopeEmail) {
		userinfo.Email = profile.Email
		// Explicitly, because oidc.UserInfo.EmailVerified is an omitempty bool and
		// a false one would otherwise be missing from the token. A relying party
		// that cannot see the claim has to decide whether the provider supports it,
		// and "the field is absent" is the one answer that means "assume verified".
		userinfo.AppendClaims(ClaimEmailVerified, false)
	}
	if slices.Contains(granted, ScopeProfile) {
		userinfo.Name = profile.Name
	}
	if slices.Contains(granted, ScopeAccounts) {
		userinfo.AppendClaims(ClaimAccounts, accountsClaim(profile.Accounts))
	}
	return nil
}

// ClaimEmailVerified and ClaimAccounts are the two claim names this package
// writes by hand rather than through a struct field. They are exported because
// the OpenAPI document and the tests name them, and a claim name that only
// exists as a string literal in one file is a name nobody can grep for.
const (
	// ClaimEmailVerified is a registered OIDC claim. See setUserinfo for why it
	// is written explicitly rather than through oidc.UserInfo.EmailVerified.
	ClaimEmailVerified = "email_verified"
	// ClaimAccounts is this service's one custom claim, released on the `accounts`
	// scope.
	ClaimAccounts = "accounts"
)

// GetPrivateClaimsFromScopes fills the access token's custom claims.
//
// Two claims, both of which core's conventions ask for by a name that does not
// fit what this service knows:
//
//   - `scope`, a space-delimited string. RFC 9068 registers that name, guard's
//     verifier reads exactly that, and it is the one a scope gate in any
//     language will look for. core's prose says `scopes`; the disagreement is
//     recorded in README.md and is a one-line change if the manager rules the
//     other way.
//   - `accounts`, the array. core's prose asks for `account_id`, singular, and
//     this service has no single one: a user of a cafaye product is a member of a
//     personal account and usually of several team accounts, and a token
//     carrying one of them would be wrong for all the others.
func (s *Storage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]any, error) {
	claims := map[string]any{"scope": spaceDelimited(scopes)}

	if !slices.Contains(scopes, ScopeAccounts) {
		return claims, nil
	}
	parsed, err := id.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("%w: the subject on this token is not an id", ErrNoProfile)
	}
	profile, err := s.profiles.Profile(ctx, s.read.Queryer(), parsed)
	if err != nil {
		return nil, err
	}
	claims[ClaimAccounts] = accountsClaim(profile.Accounts)
	return claims, nil
}

// SetIntrospectionFromToken refuses, because the endpoint is not mounted.
//
// Introspection is how a resource server asks "is this token still good", and
// this service answers that question locally: guard verifies the signature
// against the published JWKS and the row behind the `jti` is what stops a revoked
// token. A second mechanism would be a second answer.
func (s *Storage) SetIntrospectionFromToken(context.Context, *oidc.IntrospectionResponse, string, string, string) error {
	return errors.New("oidc: token introspection is not implemented; verify against the published JWKS")
}

// GetKeyByIDAndClientID refuses: no client in this service authenticates with a
// private key JWT, so there is no key to find.
func (s *Storage) GetKeyByIDAndClientID(context.Context, string, string) (*jose.JSONWebKey, error) {
	return nil, errors.New("oidc: private_key_jwt client authentication is not implemented")
}

// ValidateJWTProfileScopes refuses, for the same reason. The library's
// GrantTypes() advertises the JWT profile grant unconditionally and this method is
// the only place a service can say no to it at the token endpoint.
func (s *Storage) ValidateJWTProfileScopes(context.Context, string, []string) ([]string, error) {
	return nil, errors.New("oidc: the JWT profile authorization grant is not implemented")
}

// Health is nil. The provider's own /ready endpoint is not mounted — this
// service's /readyz is the one that probes Postgres — and this method exists only
// because op.Storage declares it.
func (s *Storage) Health(context.Context) error { return nil }

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// subjectOf reads the subject out of whichever request shape arrived.
//
// A code exchange and a future client-credentials request are different types
// with the same accessor, and a type switch that named both would be a promise
// about a grant this service does not support.
func subjectOf(request op.TokenRequest) (id.UUID, error) {
	parsed, err := id.Parse(request.GetSubject())
	if err != nil {
		return id.UUID{}, fmt.Errorf("%w: the request's subject is not an id this service issued", ErrNoProfile)
	}
	return parsed, nil
}

// clientRowFor resolves the audience back to a registration row.
//
// The audience of an OIDC token is the client that asked for it, so this is a
// lookup by handle with a shape check: a request whose audience is not one
// registered handle has no client to attribute the token to, and writing a row
// keyed on nothing is how a token ends up owned by no client.
func (s *Storage) clientRowFor(ctx context.Context, audience []string) (Client, error) {
	if len(audience) == 0 {
		return Client{}, fmt.Errorf("%w: this token would have no audience", ErrNoProfile)
	}
	client, err := s.store.ClientByClientID(ctx, s.read.Queryer(), audience[0])
	if err != nil {
		return Client{}, err
	}
	if !client.IsActive() {
		return Client{}, ErrRevoked
	}
	return client, nil
}

// spaceDelimited renders a scope list the way a scope claim is written.
//
// Sorted, because a claim whose bytes differ between two identical tokens is a
// claim two verifiers will cache differently.
func spaceDelimited(scopes []string) string {
	sorted := slices.Clone(scopes)
	slices.Sort(sorted)
	out := ""
	for i, scope := range sorted {
		if i > 0 {
			out += " "
		}
		out += scope
	}
	return out
}
