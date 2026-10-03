package client

// THE TRANSPORT, AND WHY IT IS A SUBPACKAGE AND A SEPARATE FILE.
//
// `client/generated` is oapi-codegen's output and this file is the only place that
// imports it. Three things are true of that arrangement and all three are load-
// bearing.
//
// # WHY A SUBPACKAGE
//
// The generated code declares its own `Client` and `ClientInterface`, and this
// repository's hand-written client is also a `Client`. In one package those
// collide.
//
// The collision is not the interesting part. The interesting part is what resolving
// it the other way — renaming the hand-written client, or renaming the generated one
// — would cost. Either way the GENERATED types stay exported from the package a
// consumer imports, and MD6's whole argument for generating at all is that
// "generated code stays an implementation detail, so a generator upgrade can never
// break the public API". A generator that renamed `MintAPIKeyJSONRequestBody` would
// then be a breaking change to `client`, which is precisely the lock-in that killed
// Stainless.
//
// A subpackage makes the generated surface unreachable except through this wrapper.
// A consumer cannot construct `generated.Client` by accident, cannot depend on its
// types, and is unaffected by a regeneration that renames anything in it — as long
// as this file is updated in the same commit, which the drift gate forces.
//
// # WHY `Transport` IS DECLARED HERE AND NOT ALIASED
//
// Declaring the interface in this package rather than writing
// `type Transport = generated.ClientInterface` keeps the dependency on the METHOD
// SET, not on the generated type. A document change that renames a method changes
// this interface and fails the build here, in one place — which is what makes the
// regeneration gate's blast radius visible instead of spread across twenty call
// sites.
//
// The forty-one methods below are the document's forty-one `operationId`s, in
// the document's order, with the generated parameter types. The compile-time
// assertion at the bottom is what proves the generated `*generated.Client` still
// satisfies it, so a mismatch is a build failure rather than a runtime surprise.

import (
	"context"
	"net/http"

	openapiTypes "github.com/oapi-codegen/runtime/types"

	"github.com/cafaye/identity/client/generated"
)

// Transport is the generated transport's shape, restated as this package's own
// interface.
//
// One method per `operationId`. The names are the contract: `operationId` is what
// every generated client in the fleet names its method after, so a Go client that
// called this `GetMe` where `cafaye-ts` says `getCurrentUser` would be a divergence
// in three clients for one platform — which the fleet treats as a defect in the
// platform, not a style difference.
type Transport interface {
	CreateSession(ctx context.Context, body generated.CreateSessionJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	RegisterUser(ctx context.Context, body generated.RegisterUserJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	DeleteSession(ctx context.Context, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	CompleteSecondFactor(ctx context.Context, body generated.CompleteSecondFactorJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	GetMFAStatus(ctx context.Context, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	DisableMFA(ctx context.Context, body generated.DisableMFAJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	StartMFAEnrollment(ctx context.Context, body generated.StartMFAEnrollmentJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	ConfirmMFAEnrollment(ctx context.Context, enrollmentId openapiTypes.UUID, body generated.ConfirmMFAEnrollmentJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	RegenerateMFARecoveryCodes(ctx context.Context, body generated.RegenerateMFARecoveryCodesJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	GetCurrentUser(ctx context.Context, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	RequestPasswordReset(ctx context.Context, body generated.RequestPasswordResetJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	ConfirmPasswordReset(ctx context.Context, body generated.ConfirmPasswordResetJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	RequestEmailVerification(ctx context.Context, body generated.RequestEmailVerificationJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	ConfirmEmailVerification(ctx context.Context, body generated.ConfirmEmailVerificationJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	GetEmailVerificationStatus(ctx context.Context, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	RequestEmailChange(ctx context.Context, body generated.RequestEmailChangeJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	ConfirmEmailChangeCurrentAddress(ctx context.Context, body generated.ConfirmEmailChangeCurrentAddressJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	ConfirmEmailChangeNewAddress(ctx context.Context, body generated.ConfirmEmailChangeNewAddressJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	CreateAccount(ctx context.Context, body generated.CreateAccountJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	ListAccounts(ctx context.Context, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	GetAccount(ctx context.Context, accountId openapiTypes.UUID, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	RenameAccount(ctx context.Context, accountId openapiTypes.UUID, body generated.RenameAccountJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	DeleteAccount(ctx context.Context, accountId openapiTypes.UUID, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	ListMembers(ctx context.Context, accountId openapiTypes.UUID, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	InviteMember(ctx context.Context, accountId openapiTypes.UUID, body generated.InviteMemberJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	ChangeMemberRole(ctx context.Context, accountId openapiTypes.UUID, userId openapiTypes.UUID, body generated.ChangeMemberRoleJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	RemoveMember(ctx context.Context, accountId openapiTypes.UUID, userId openapiTypes.UUID, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	AcceptInvitation(ctx context.Context, body generated.AcceptInvitationJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	RegisterOIDCClient(ctx context.Context, accountId openapiTypes.UUID, body generated.RegisterOIDCClientJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	ListOIDCClients(ctx context.Context, accountId openapiTypes.UUID, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	GetOIDCClient(ctx context.Context, accountId openapiTypes.UUID, clientId openapiTypes.UUID, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	RevokeOIDCClient(ctx context.Context, accountId openapiTypes.UUID, clientId openapiTypes.UUID, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	MintAPIKey(ctx context.Context, accountId openapiTypes.UUID, body generated.MintAPIKeyJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	ListAPIKeys(ctx context.Context, accountId openapiTypes.UUID, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	RevokeAPIKey(ctx context.Context, accountId openapiTypes.UUID, keyId openapiTypes.UUID, body generated.RevokeAPIKeyJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	IntrospectAPIKey(ctx context.Context, body generated.IntrospectAPIKeyJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	Liveness(ctx context.Context, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	Readiness(ctx context.Context, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	ListAccountAuditLog(ctx context.Context, accountId openapiTypes.UUID, params *generated.ListAccountAuditLogParams, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	RevokeAccountInvitation(ctx context.Context, accountId openapiTypes.UUID, invitationId openapiTypes.UUID, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	RevokeAccountInvitations(ctx context.Context, accountId openapiTypes.UUID, body generated.BulkInvitationRevocation, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	// The social-login round trip is here for completeness of the METHOD SET, which
	// is all this interface promises, and neither of these two is a call a machine
	// client should make.
	//
	// `StartSocialLogin` answers 302 with a Location and no body, and
	// `CompleteSocialLogin` is the far side of that redirect — the browser is
	// supposed to arrive, holding nothing but the `__Host-oauth-state` cookie this
	// service set. A caller presenting an `Authorization` header to either is
	// sending a credential to a route that ignores it, because the surface is
	// `security: []` in the document. The wrapper in client.go says the same thing
	// where somebody will actually read it.
	StartSocialLogin(ctx context.Context, provider generated.StartSocialLoginParamsProvider, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	CompleteSocialLogin(ctx context.Context, provider generated.CompleteSocialLoginParamsProvider, params *generated.CompleteSocialLoginParams, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
}

// The proof that the generated client still satisfies the interface above.
//
// A compile-time assertion, not a test: a generated `*Client` that stopped matching
// is a BUILD failure in this file, which is the earliest and loudest place it could
// be caught, and it costs one line. `TestTheTransportCoversEveryOperationInTheDocument`
// is the companion that checks the other direction — that this interface has not
// quietly LOST a method to a document that gained one — because an interface can
// match while being incomplete.
var _ Transport = (*generated.Client)(nil)

// newTransport builds the generated client for one base URL and credential.
//
// The credential is attached HERE rather than per call, as a request editor, so that
// it cannot be forgotten by a call site. A transport that attaches a credential in
// twenty places is one where the twenty-first call site forgets, and the twentieth
// is the one somebody reads.
//
// The editor is installed on the generated client rather than passed to each method,
// which is what `WithRequestEditorFn` is for and which is why `Transport`'s methods
// do not take one from the caller: the wrapper is the only thing that constructs one
// of these, so there is no path to a client that sends unauthenticated requests.
func newTransport(baseURL, token string) (Transport, error) {
	// THE REDIRECT POLICY IS NOT A DETAIL, and this is the one place it belongs.
	//
	// `net/http`'s default follows up to ten 3xx hops. That is right for a browser
	// and wrong here twice over: `StartSocialLogin`'s 302 carries a third party's
	// authorization endpoint, which is an instruction to a BROWSER and not a hop
	// this client should make — following it turns a method that returns a URL into
	// one that makes an authenticated request to Google — and every other operation
	// in this document has no 3xx at all, so there is nothing else here to follow.
	//
	// `http.ErrUseLastResponse` rather than an error of our own, and the reason is
	// that it is the one return value `net/http` documents as "give me the
	// response": the 302 comes back with its `Location` intact and its body
	// unread, and `StartSocialLogin` reads the header. Returning an error instead
	// would discard the very thing the caller came for, and the wrapper would have
	// no status to inspect — which is the shape of a transport that refuses to
	// redirect rather than declining to follow one.
	//
	// What it costs, stated plainly: this is a policy change for the WHOLE client,
	// not a per-call option, because `Transport`'s methods take no per-call
	// `http.Client`. In practice it changes nothing else, because no other
	// operation in this document answers 3xx — and if one starts to, refusing to
	// follow it is the safe direction: a server choosing where this client goes
	// next is not something a machine credential should be replayed across.
	httpClient := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	options := []generated.ClientOption{generated.WithHTTPClient(httpClient)}
	if token != "" {
		options = append(options, generated.WithRequestEditorFn(
			func(ctx context.Context, req *http.Request) error {
				return AttachCredential(req, token)
			}))
	}

	return generated.NewClient(baseURL, options...)
}
