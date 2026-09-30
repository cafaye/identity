package oidc

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/cafaye/identity/internal/platform/id"
)

// The provider: the library's state machine, pointed at this service's storage,
// and the discovery document narrowed to what this service actually does.
//
// THE NARROWING IS THE POINT OF THIS FILE.
//
// op.Provider's discovery describes what the LIBRARY can do. This service does
// less than the library: it mounts four of the nine endpoints, issues no refresh
// token, supports no implicit flow, no public client and no private_key_jwt. A
// document that advertised all of it would be a document a product configures
// against and then discovers does not work — at their outage, not ours. So
// every field this service does not serve is emptied, and the assertions in
// provider_test.go are on the emptied document rather than on the library.

// Endpoint paths.
//
// The protocol endpoints live under /oidc so that the two cafaye surfaces stay
// distinguishable at a glance in an access log: /v1 is the JSON API this service
// defines and /oidc is the OAuth 2.0 surface a standard client expects. The two
// well-known paths are not under /oidc because the specifications fix them.
const (
	// PathAuthorize is where an authorization request arrives.
	PathAuthorize = "/oidc/authorize"
	// PathToken is where a code is exchanged for tokens.
	PathToken = "/oidc/token"
	// PathUserinfo is where an access token is presented for claims.
	PathUserinfo = "/oidc/userinfo"
	// PathLogin is where the browser goes to authenticate. The request id is a
	// path segment under it.
	PathLogin = "/oidc/login"
	// PathJWKS is where the signing keys are published. It is the path core's
	// conventions name and the one guard's verifier hardcodes:
	// JWKS_PATH = "/.well-known/jwks.json" in guard/src/middleware/jwt.ts.
	PathJWKS = "/.well-known/jwks.json"
	// PathDiscovery is the OpenID Connect Discovery path.
	PathDiscovery = "/.well-known/openid-configuration"
	// PathOAuthAuthorizationServer is the RFC 8414 metadata path, served as an
	// alias for the same document. The library does not register it — its router
	// has exactly one well-known route — so identity mounts it itself.
	PathOAuthAuthorizationServer = "/.well-known/oauth-authorization-server"
)

// Config is what it takes to be an OpenID Connect provider.
type Config struct {
	// Issuer is the value of the `iss` claim, the discovery document's `issuer`,
	// and the base every endpoint URL is built from. It is compared for equality
	// by every verifier on the platform, so a trailing slash or a path here is a
	// startup error rather than a discovery document nobody's tokens match.
	Issuer string
	// SigningKey is the one RSA key. See keys.go.
	SigningKey *SigningKey
	// AllowInsecure permits an http issuer. It exists for `localhost` and for
	// tests, and it is a field rather than a behaviour because "this deployment
	// is local" is a fact about the deployment.
	AllowInsecure bool
}

// Provider is the assembled OpenID Connect provider.
type Provider struct {
	op      *op.Provider
	storage *Storage
	issuer  string
}

// NewProvider builds the provider.
//
// The issuer is static rather than derived from the request Host. A provider
// whose issuer depends on the Host header publishes a different `iss` per request
// and every token it mints is rejected by a verifier configured with any other
// name for it — which is the failure mode RFC 8414 §3.3 warns about by name.
func NewProvider(cfg Config, storage *Storage) (*Provider, error) {
	if err := validateIssuer(cfg.Issuer); err != nil {
		return nil, err
	}
	if cfg.SigningKey == nil {
		return nil, ErrNoSigningKey
	}

	encryptionKey, encryptionKeyID := deriveEncryptionKey(cfg.SigningKey)

	options := []op.Option{
		// The library's own defaults are /authorize, /oauth/token, /userinfo and
		// /keys. The protocol paths here are this service's, under /oidc so the
		// two surfaces are distinguishable in an access log; the well-known path
		// is the one core's conventions name and guard's verifier hardcodes.
		//
		// The four this service does NOT serve are configured too, and it looks
		// like an oversight until you read Discovery: the library builds its
		// endpoint URLs from these values, so they have to be set for the
		// endpoints that ARE served to be configured at all, and the URLs for the
		// rest are emptied in the document rather than published.
		op.WithCustomEndpoints(
			op.NewEndpoint(strings.TrimPrefix(PathAuthorize, "/")),
			op.NewEndpoint(strings.TrimPrefix(PathToken, "/")),
			op.NewEndpoint(strings.TrimPrefix(PathUserinfo, "/")),
			op.NewEndpoint("oidc/revoke"),
			op.NewEndpoint("oidc/end-session"),
			op.NewEndpoint(strings.TrimPrefix(PathJWKS, "/")),
		),
	}
	if cfg.AllowInsecure {
		options = append(options, op.WithAllowInsecure())
	}

	handler, err := op.NewProvider(
		&op.Config{
			// The library needs a 32-byte key to encrypt the OPAQUE tokens it can
			// issue. This provider issues JWTs and never mints one — but the
			// userinfo handler DECRYPTS before it verifies, so a zero key here
			// would be a key an attacker could encrypt a forged token under.
			CryptoKey:   encryptionKey,
			CryptoKeyId: encryptionKeyID,

			// PKCE with S256, and only S256. The discovery document then advertises
			// `["S256"]` rather than the specification's full set, which is the
			// whole point of configuring it.
			CodeMethodS256: true,

			// A confidential client authenticates with HTTP Basic. Both of these
			// are off because a form-posted secret ends up in a request body that
			// gets logged, and a private_key_jwt key would be a second credential
			// per product to store.
			AuthMethodPost:          false,
			AuthMethodPrivateKeyJWT: false,

			// No refresh token grant. See Storage.CreateAccessAndRefreshTokens.
			GrantTypeRefreshToken: false,

			// No `request` object: a signed request object is a second way to
			// carry claims into an authorization request and there is no product
			// that needs one.
			RequestObjectSupported: false,

			// The four scopes this service implements, and the claims it actually
			// asserts. Both lists are the package's own rather than the library's
			// defaults, which name phone and address.
			SupportedScopes: SupportedScopes,
			SupportedClaims: supportedClaims(),
		},
		storage,
		op.StaticIssuer(cfg.Issuer),
		options...,
	)
	if err != nil {
		return nil, fmt.Errorf("oidc: building the provider: %w", err)
	}

	return &Provider{op: handler, storage: storage, issuer: cfg.Issuer}, nil
}

// Handler is the library's router.
//
// It is mounted path by path on this service's own router rather than at the
// root. Mounting it at "/" would give it the unmatched-path case too, and this
// service's 404 is an RFC 9457 problem document with a trace id — the library's
// router answers a miss with net/http's plain-text one, and a client would then
// have two error shapes to parse depending on which route it guessed wrong.
func (p *Provider) Handler() http.Handler { return p.op }

// Storage is the adapter, for the routes that need to complete a login.
func (p *Provider) Storage() *Storage { return p.storage }

// Issuer is the configured issuer, which is also the expected `iss` on a token
// this service verifies.
func (p *Provider) Issuer() string { return p.issuer }

// Discovery is the document for one request.
//
// The issuer is put into the context here rather than read out of it, because the
// interceptor that would normally do that lives inside the library's router and
// this document is served by this service's own router. p.issuer is the same
// static value that interceptor would have installed, so the two paths cannot
// disagree.
func (p *Provider) Discovery(r *http.Request) any {
	return p.discovery(op.ContextWithIssuer(r.Context(), p.issuer))
}

// DiscoveryFor is the document for an explicit context, which is what the tests
// use so they can assert on it without a request in hand.
func (p *Provider) DiscoveryFor(ctx context.Context) *oidc.DiscoveryConfiguration {
	return p.discovery(ctx)
}

// JWKS is the published key set.
//
// It is rendered once per request rather than cached, and the cost is a
// base64url encoding of a 256-byte modulus — a few microseconds, against a
// document that a caching verifier may ask for every five minutes. Caching it
// would be a second place for the key to live.
func (p *Provider) JWKS() ([]byte, error) { return p.op.Storage().(*Storage).key.JWKS() }

// LoginBanner is what the login page renders.
func (p *Provider) LoginBanner(ctx context.Context, requestID string) (LoginBanner, error) {
	return p.storage.LoginBanner(ctx, requestID)
}

// CompleteLogin records that a user authenticated against a request.
func (p *Provider) CompleteLogin(ctx context.Context, requestID string, subject id.UUID) error {
	return p.storage.CompleteLogin(ctx, requestID, subject)
}

// validateIssuer refuses an issuer a verifier could not reproduce.
//
// Two rules, both from RFC 8414 §3.3 and both of which produce a provider whose
// tokens nobody can verify: no query or fragment, and no path unless the path is
// "/" — a path issuer means every endpoint URL needs it prefixed, and the
// library's endpoint helpers do not do that for the well-known paths.
func validateIssuer(issuer string) error {
	if issuer == "" {
		return fmt.Errorf("oidc: the issuer is required; it is the `iss` on every token and the `issuer` in discovery")
	}
	parsed, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("oidc: the issuer is not a URL: %w", err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("oidc: the issuer scheme is %q, want https", parsed.Scheme)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("oidc: the issuer must not carry a query or a fragment")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return fmt.Errorf("oidc: the issuer must not carry a path; every endpoint URL is built by appending to it")
	}
	return nil
}

// deriveEncryptionKey produces the library's 32-byte encryption key, and its id.
//
// It is DERIVED from the signing key rather than configured separately, and the
// derivation is domain-separated so the two never coincide. Three reasons:
//
//   - One configured secret is one thing to rotate, and a deployment that has to
//     set two will eventually set only one.
//   - The value really is used. The userinfo handler decrypts an access token
//     before it verifies one, so a zero or shared key would let anybody encrypt
//     a forged `tokenID:subject` pair and be believed. It is not dead code that
//     happens to be configured, and a comment saying otherwise would be wrong.
//   - When the signing key rotates, the encryption key rotates with it, which is
//     correct: a rotation exists because something was exposed.
//
// It is a SHA-256 over a fixed label and the key's DER bytes. There is no
// derivation function to get wrong and no salt to lose, and the label is what
// keeps the result from being the signing key itself.
func deriveEncryptionKey(k *SigningKey) ([32]byte, string) {
	der, err := marshalPKCS8(k)
	if err != nil {
		// Unreachable: the key was parsed from a PEM to be constructed, so it
		// marshals again. Falling back to the kid keeps the provider buildable
		// rather than panicking inside a constructor, and the key is still
		// derived from something unique to this deployment.
		der = []byte(k.ID())
	}
	sum := sha256.Sum256(append([]byte("cafaye/identity/oidc/token-encryption/v1\x00"), der...))
	return sum, k.ID() + "-enc"
}

// supportedClaims is what this service actually asserts, in the order the
// discovery document lists them.
//
// The library's DefaultSupportedClaims names address, phone_number, locale,
// picture, website, birthdate, gender and zoneinfo, none of which identity has a
// column for. Advertising a claim is a promise to a product's rendering code, and
// this list is the set that promise is actually kept for.
func supportedClaims() []string {
	return []string{
		"sub",
		"iss",
		"aud",
		"exp",
		"iat",
		"jti",
		"nonce",
		"auth_time",
		"amr",
		"azp",
		"at_hash",
		"c_hash",
		"client_id",
		"scope",
		ScopeEmail,
		ClaimEmailVerified,
		"name",
		ClaimAccounts,
	}
}

// Discovery is the document served at the two well-known paths.
//
// Built from the library's own configuration and then narrowed, so the endpoint
// URLs, the issuer and the algorithms come from the same place the router does
// and cannot describe a route this service does not mount.
func (p *Provider) discovery(ctx context.Context) *oidc.DiscoveryConfiguration {
	doc := op.CreateDiscoveryConfig(ctx, p.op, p.op.Storage())

	// The four endpoints this service mounts.
	doc.AuthorizationEndpoint = p.op.AuthorizationEndpoint().Absolute(p.issuer)
	doc.TokenEndpoint = p.op.TokenEndpoint().Absolute(p.issuer)
	doc.UserinfoEndpoint = p.op.UserinfoEndpoint().Absolute(p.issuer)
	doc.JwksURI = p.op.KeysEndpoint().Absolute(p.issuer)

	// The five it does not. Each is emptied rather than left at the library's
	// default, because a discovery document is a menu and an entry for an
	// endpoint that answers 404 is a product configured against a route that does
	// not exist. Introspection, revocation, end-session, device authorization and
	// the session-management iframe are all later packets; the discovery document
	// says so by omission, which is the only way it can.
	doc.IntrospectionEndpoint = ""
	doc.RevocationEndpoint = ""
	doc.EndSessionEndpoint = ""
	doc.DeviceAuthorizationEndpoint = ""
	doc.CheckSessionIframe = ""

	// …and the two that go with them. These are the fields the FIRST live run of
	// the provider caught and the object-level test did not: blanking an endpoint
	// leaves its `*_auth_methods_supported` sibling behind, and a document
	// advertising how to authenticate to an introspection endpoint this service
	// does not have is a document describing a machine. TestDiscoveryOmitsWhatThis
	// ServiceDoesNotServe now asserts the whole set rather than the endpoints
	// alone.
	doc.IntrospectionEndpointAuthMethodsSupported = nil
	doc.IntrospectionEndpointAuthSigningAlgValuesSupported = nil
	doc.RevocationEndpointAuthMethodsSupported = nil
	doc.RevocationEndpointAuthSigningAlgValuesSupported = nil

	// Authorization code and nothing else: no implicit flow, and no JWT profile
	// grant despite the library advertising it unconditionally.
	doc.ResponseTypesSupported = []string{string(oidc.ResponseTypeCode)}
	doc.GrantTypesSupported = []oidc.GrantType{oidc.GrantTypeCode}

	// HTTP Basic only. The library's list always includes `none`, which tells a
	// client it may skip authenticating — true of a public client with PKCE, and
	// false of every client in this table, which all hold a secret.
	doc.TokenEndpointAuthMethodsSupported = []oidc.AuthMethod{oidc.AuthMethodBasic}
	doc.TokenEndpointAuthSigningAlgValuesSupported = nil
	doc.RequestObjectSigningAlgValuesSupported = nil

	// PKCE with S256 and nothing else, matching requireS256 on the token side.
	doc.CodeChallengeMethodsSupported = []oidc.CodeChallengeMethod{oidc.CodeChallengeMethodS256}

	// S256 for the id_token, from the one key this service publishes.
	doc.IDTokenSigningAlgValuesSupported = []string{"RS256"}
	doc.SubjectTypesSupported = []string{"public"}
	doc.ScopesSupported = SupportedScopes
	doc.ClaimsSupported = supportedClaims()

	// The library leaves these nil because this service configured them off, and
	// a nil list is omitted from the JSON. Sliced for the same reason as the
	// endpoints above: an empty list and an absent one are the same answer here,
	// and absent is the one that does not read as support.
	doc.UILocalesSupported = nil
	doc.ScopesSupported = slices.Clone(SupportedScopes)
	return doc
}
