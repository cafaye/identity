package oidc

import (
	"errors"
	"fmt"
	"net/url"
)

// WHERE A BROWSER GOES TO AUTHENTICATE, AND WHAT IT CARRIES WHEN IT GETS THERE.
//
// # WHY THERE IS A LOGIN UI AT ALL, AND WHY IT IS NOT IN THIS REPOSITORY
//
// OpenID Connect Core §3.1.2.1 makes authenticating the end user part of the
// authorization server's job, and §3.1.2.6 is about the credentials themselves.
// So a provider without a user-agent interaction is not conformant, and "this
// service renders no HTML" cannot mean "this service has no login". It means the
// interaction is somebody else's to render, and this file is the seam.
//
// THE FLOW IS FOUR MOVES AND TWO OF THEM ARE REDIRECTS.
//
//	GET  /oidc/authorize            302 -> /oidc/login/{request_id}    (this service)
//	GET  /oidc/login/{request_id}   302 -> <OIDC_LOGIN_UI_URL>?…       (the login UI)
//	POST /oidc/login/{request_id}   302 -> <redirect_uri>?code=…       (this service)
//	                                 on a refusal: 302 back to the login UI
//
// The first and third hops stay here, and the reason is not tidiness: they are
// the AUTHORIZATION decisions — is this browser signed in, did it start this
// flow, is this password correct, may an authorization code be minted — and an
// authorization decision that can be made by a page on another origin is not an
// authorization decision this service made. What leaves is the RENDERING.
//
// # THE CONTRACT IS PUBLISHED, WHICH IS WHY THE NAMES ARE CONSTANTS
//
// A login UI in another repository has to read every parameter below by name and
// has to post back to a path it did not choose. That makes this the one file in
// this package whose contents are an interface, so:
//
//   - every parameter name is a constant rather than a literal at a call site, so
//     there is one spelling to publish and one to change.
//   - `TestEveryLoginRedirectParameterIsCarriedAndEveryCarriedOneIsNamed` walks
//     the list against a redirect built from a fully populated
//     `LoginRedirectParams`, in BOTH directions. A parameter added to the struct
//     and not to the list is a name the contract does not publish; a constant
//     with nothing that sets it is a parameter the UI is told to expect and never
//     receives.
//   - `openid/openid.yaml` documents the same thing, and
//     `internal/httpapi`'s drift walk holds the two surfaces to the router.
//
// # WHAT IS AND IS NOT IN THE URL, AND WHY
//
// `client_name` and `login_hint` are here because the page has to render them and
// the login UI cannot ask this service for them: a cross-origin read would need
// CORS, and identity does not send CORS headers (see the packet that forbids
// `Access-Control-Allow-Origin: *`). So they travel in the redirect, which makes
// the login UI's escaping load-bearing and says so in the document:
//
//	CLIENT_NAME IS A DATABASE ROW AN ACCOUNT OWNER TYPED. A registration called
//	`<script>…</script>` is legal here and identity does not refuse it, so a login
//	UI that interpolates client_name into a page without escaping it runs that
//	script for every product on the platform. It was the same risk on this
//	service's own login page, which is why it was an html/template there.
//
// `login_hint` is a string the CLIENT chose, and it has never been trusted: it
// pre-fills a field and the password is still checked against the address the
// user types.

// LoginUIEnvVar is the variable that names the login UI.
//
// It is exported so the refusal an operator reads names the variable they have
// to set, which is the same reason `LinkTemplateVariable` is exported and for a
// narrower reason: there is one login UI, so there is nothing to walk.
const LoginUIEnvVar = "OIDC_LOGIN_UI_URL"

// Errors ValidateLoginUIURL returns. Callers match them with errors.Is.
var (
	// ErrNoLoginUI means the login UI is not configured at all.
	//
	// IT IS A CONSTRUCTION FAILURE RATHER THAN A DEGRADED MODE, and the reason is
	// the whole of this file: an authorization server that cannot send a browser
	// anywhere to authenticate is a provider that publishes a working discovery
	// document and then cannot complete a single flow. That is worse than not
	// being a provider, because the failure is discovered by a user at a product
	// rather than by an operator at boot.
	ErrNoLoginUI = errors.New("no OIDC login UI configured")

	// ErrInvalidLoginUI means the login UI is configured and is not an address a
	// browser can be sent to with an authorization request on it.
	ErrInvalidLoginUI = errors.New("the OIDC login UI URL is not usable")
)

// The query parameters this service adds to the login UI URL.
//
// `request_id`, `state` and `step` are always present. The rest are present when
// they have something to say, and their absence is meaningful rather than empty:
// no `error` means the interaction is proceeding normally, which is the answer a
// login UI needs in order not to show a failure nobody reported.
const (
	// LoginParamRequestID names the authorization request. It is the value the
	// login UI puts in its form's action path, so it is the one parameter the
	// other side must not lose.
	LoginParamRequestID = "request_id"
	// LoginParamState is the CSRF state. The login UI posts it back verbatim; the
	// sealed copy is in a `__Host-` cookie on THIS origin, which the login UI's
	// origin cannot read and cannot write.
	LoginParamState = "state"
	// LoginParamStep is which of the two steps to render. See LoginStepPassword
	// and LoginStepChallenge.
	LoginParamStep = "step"
	// LoginParamClientName is the registration's display name. Untrusted text; see
	// the file header.
	LoginParamClientName = "client_name"
	// LoginParamLoginHint is the client's `login_hint`, when it sent one. Also
	// untrusted text, and also never load-bearing: the password is checked against
	// the address the user types.
	LoginParamLoginHint = "login_hint"
	// LoginParamError is the stable code for a refusal. It is the contract; see
	// the interaction error constants below.
	LoginParamError = "error"
	// LoginParamErrorDetail is the sentence a person reads. It is NOT parsed by
	// anything and it is not the contract — the same split the problem envelope
	// makes between `code` and `detail`.
	LoginParamErrorDetail = "error_detail"
	// LoginParamRetryAfter is whole seconds, on `account_locked` and nowhere else.
	// It is in the query rather than in a `Retry-After` header because a browser
	// following a 302 does not read headers, and a lockout the UI cannot render
	// as a wait is a lockout the user experiences as a frozen page.
	LoginParamRetryAfter = "retry_after"
)

// The two steps of the interaction.
//
// They are constants here because they are the login UI's switch: "which form do
// I render" is a question the two repositories share, and an answer written down
// in a struct field at a call site is an answer with two spellings.
const (
	// LoginStepPassword is the address-and-password form.
	LoginStepPassword = "password"
	// LoginStepChallenge is the one-time-code form, which takes a TOTP code or a
	// recovery code in the same field.
	LoginStepChallenge = "challenge"
)

// The interaction error codes.
//
// THEY MIRROR `internal/httpapi`'s problem codes WHERE THEY MEAN THE SAME THING,
// and `TestAnInteractionErrorCodeThatMeansTheSameThingAsAProblemCodeIsTheSame
// String` holds the overlap. One vocabulary for one set of facts is worth more
// than the tidiness of two namespaces, and a UI that already switches on
// `account_locked` for a 423 must not have to learn a second spelling of it.
//
// They are NOT the full set of `internal/httpapi`'s codes, and the difference is
// the point: only the refusals a redirect can CARRY are here. A request id that
// does not exist cannot be re-shown, so it is a 404 problem document and not a
// code in a query string. See `internal/httpapi`'s interaction code for the whole
// rule.
const (
	// LoginErrorInteractionExpired means there was no live state for this
	// request, or no live second-factor challenge. It is one code for both because
	// from the login UI they are one situation — the interaction this page was
	// rendering is no longer the interaction this service remembers — and because
	// the difference between them is a fact about this service's own storage that
	// a page has no use for.
	LoginErrorInteractionExpired = "interaction_expired"
	// LoginErrorMissingCredentials means the form arrived with an empty address
	// or an empty password. It is not a login attempt: nothing was checked, and
	// running an argon2id verification on an empty password would cost a
	// memory-hard hash to learn that a form was submitted blank.
	LoginErrorMissingCredentials = "missing_credentials"
	// LoginErrorInvalidCredentials means a wrong password OR an unregistered
	// address. ONE code and ONE sentence for both, and it is the whole of the
	// enumeration property on this surface: the login form is unauthenticated, it
	// takes an address, and the first thing anybody types into it is somebody
	// else's.
	LoginErrorInvalidCredentials = "invalid_credentials"
	// LoginErrorChallengeRejected means a one-time code that was not accepted —
	// wrong, replayed, or expired. It never says which, and neither did the page
	// it replaced: a user who has just pasted the same digits twice needs the next
	// code, not a diagnosis.
	LoginErrorChallengeRejected = "challenge_rejected"
	// LoginErrorAccountLocked means too many consecutive failures, against the
	// account or against the second factor. It is the same code the JSON surface
	// uses for the same lockout, and it carries `retry_after`.
	LoginErrorAccountLocked = "account_locked"
)

// LoginRedirectParams is one redirect to the login UI.
//
// A struct rather than a url.Values at the call site because the parameter NAMES
// are a contract with another repository and a bag of strings is where a
// contract goes to be misspelled. Every field is optional except RequestID, State
// and Step, and an empty optional field is omitted rather than sent empty — an
// absent `error` and an empty `error` must not both be readable as "no error",
// because a login UI that renders `if (params.error)` would show an empty
// failure banner.
type LoginRedirectParams struct {
	// RequestID is the authorization request. Required.
	RequestID string
	// State is the CSRF state this service sealed in a cookie for RequestID.
	// Required.
	State string
	// Step is LoginStepPassword or LoginStepChallenge. Required.
	Step string
	// ClientName is the registration's display name.
	ClientName string
	// LoginHint is the client's `login_hint`, if it sent one.
	LoginHint string
	// Error is one of the interaction error codes, and the reason Detail is set.
	Error string
	// ErrorDetail is the sentence a person reads. It is not the contract.
	ErrorDetail string
	// RetryAfter is whole seconds, and is only carried with
	// LoginErrorAccountLocked.
	RetryAfter string
}

// Values is the query this service adds, as url.Values.
//
// Exported through the type rather than kept private because the two tests that
// hold the contract — the one in this package and the one in `internal/httpapi`
// that asserts on a real response — should both read the names from here rather
// than from a list of literals that happens to match.
func (p LoginRedirectParams) Values() url.Values {
	out := url.Values{}
	out.Set(LoginParamRequestID, p.RequestID)
	out.Set(LoginParamState, p.State)
	out.Set(LoginParamStep, p.Step)
	// Set only when non-empty, so an absent parameter is absent. See the type's
	// comment for why that is not the same as an empty one.
	for name, value := range map[string]string{
		LoginParamClientName:  p.ClientName,
		LoginParamLoginHint:   p.LoginHint,
		LoginParamError:       p.Error,
		LoginParamErrorDetail: p.ErrorDetail,
		LoginParamRetryAfter:  p.RetryAfter,
	} {
		if value != "" {
			out.Set(name, value)
		}
	}
	return out
}

// ValidateLoginUIURL refuses a login UI address this service cannot send a
// browser to.
//
// IT IS EXPORTED AND CALLED BY BOTH SIDES — `NewProvider` here and
// `internal/config` at boot — rather than duplicated, and the reason is stated
// because the courier's boot rule IS duplicated and the contrast is the
// argument. `internal/courier` is a platform adapter that has to be correct on
// its own whether or not this service validated anything, so the rule is written
// twice and a test holds the copies in step. `internal/oidc` is not an adapter:
// it is what the provider IS, the same way `internal/recovery` is what a mailer
// implements. One rule in one place, and the two callers cannot disagree because
// there is only one to disagree with.
//
// # THE REFUSALS, AND WHY EACH IS THE FAILURE DIRECTION
//
//	empty        an authorization server with nowhere to send a browser is a
//	             provider that cannot complete a flow. Construction failure.
//	not a URL    a typo. Found at boot, it costs one log line; found by the first
//	             user, it costs an afternoon.
//	wrong scheme a `javascript:` or `data:` login UI is an injection primitive
//	             aimed at a redirect this service issues, and the value it would
//	             carry is an authorization request id.
//	no host      same class: not an address.
//	userinfo     `https://parlor@evil.example.com/login` reads as a login UI and
//	             resolves to an attacker's host. Refused for the same reason
//	             `validateLinkTemplate` refuses one.
//	fragment     a fragment is not sent to a server, so a login UI that expected
//	             to read the request id from one would never see it.
//	query        THE ONE THAT LOOKS HARMLESS. This service MERGES its parameters
//	             into the query rather than appending to it, so a configured
//	             query would be preserved rather than mangled — and a preserved
//	             query is a query this service did not write appearing in a URL
//	             that also carries an authorization request id, a CSRF state and
//	             whatever a client put in `login_hint`. `internal/config` refuses
//	             COURIER_BASE_URL for exactly this reason, and the rule is the
//	             same here. A deployment that needs a tenant or a variant in the
//	             path puts it in the path.
func ValidateLoginUIURL(raw string) error {
	if raw == "" {
		return ErrNoLoginUI
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: it is not a URL: %v", ErrInvalidLoginUI, err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("%w: its scheme is %q, want http or https", ErrInvalidLoginUI, parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%w: it has no host, so there is nowhere to send a browser", ErrInvalidLoginUI)
	}
	if parsed.RawQuery != "" {
		return fmt.Errorf("%w: it carries a query (%q). This service adds its own parameters to "+
			"the query, and a configured one would be preserved — so the URL would carry an "+
			"authorization request id, a CSRF state and a client's login_hint alongside a "+
			"string this service did not write. Put a tenant or a variant in the PATH instead",
			ErrInvalidLoginUI, parsed.RawQuery)
	}
	if parsed.Fragment != "" {
		return fmt.Errorf("%w: it carries a fragment, which is not sent to a server", ErrInvalidLoginUI)
	}
	if parsed.User != nil {
		return fmt.Errorf("%w: it has a userinfo section, so the host in it is not the host it "+
			"resolves to", ErrInvalidLoginUI)
	}
	return nil
}

// LoginRedirect is the absolute URL a browser is sent to in order to authenticate
// for one authorization request.
//
// It is a method on *Provider rather than a free function because the URL is
// configuration the provider already validated, and re-parsing a configured
// string at every redirect would be a second answer to "where does a browser go
// to sign in" that nothing holds in step with the first.
//
// The base is COPIED and the query is MERGED rather than appended, so a caller
// cannot mutate the provider's own configuration by holding on to the result and
// the output is deterministic: url.Values.Encode sorts by key, so the same
// interaction always produces byte-identical Location headers, which is what
// makes a test able to assert on one and a reviewer able to read one.
func (p *Provider) LoginRedirect(params LoginRedirectParams) string {
	target := *p.loginUI
	target.RawQuery = params.Values().Encode()
	return target.String()
}
