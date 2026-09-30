package client

// WHICH CREDENTIAL IS THIS, AND WHERE MAY IT GO?
//
// identity serves two auth models and MD6 made naming them a wrapper's job
// rather than a generated client's: the document declares `sessionCookie` (an
// `apiKey` in cookie `__Host-session`) and `bearerToken` (`http`/`bearer`), and a
// generated client cannot hide the difference between them, because the choice of
// where to put the value is not something a generator knows how to decide.
//
// # THREE SHAPES, TWO AUTH MODELS
//
// There are two auth MODELS (a cookie and a bearer header) and three credential
// SHAPES, which is not the same count and the difference is the interesting part:
//
//	session     opaque, 43 base64url characters. A human's browser credential.
//	apiToken    `cafaye_` + 43 base64url characters. A scoped machine credential.
//	jwt         three dot-separated base64url segments. The other five services'
//	            service-to-service credential, verified against a JWKS.
//
// identity-08 added the second shape after MD6's sentence was written, and it is
// why the split is three-way rather than two: a scoped token pasted into a logout
// call is a real mistake, and identity's own document calls it out because
// `DELETE /v1/session` answers 403 to a scoped token rather than 204.
//
// # THE PREFIX IS THE DISCRIMINATOR, AND IDENTITY ALREADY DECIDED THAT
//
// `internal/apikeys/apikeys.go` says it outright: a session token and a scoped API
// key are both opaque bearer values, and `apikeys.Prefix` decides which table a
// presented value is looked up in before any query runs. Nothing else may — not a
// length, not a character class, not a "does it look like a JWT" check.
//
// So this package reads the same prefix, for the same reason. Inventing a parallel
// scheme here would mean a client that classifies a credential one way and the
// service classifies it another, and the disagreement would be invisible until a
// credential reached the wrong table.
//
// # WHY A SESSION CONTRIBUTES BOTH FORMS AND AN API TOKEN CONTRIBUTES ONE
//
// This is the load-bearing decision in the file, and it is the asymmetry the
// other two clients encode too.
//
// A session attaches `Authorization: Bearer` AND `Cookie: __Host-session`. Both on
// purpose, and not as redundancy: identity resolves a request carrying both by
// preferring the header — "an `Authorization: Bearer` header is preferred over the
// cookie when both are present, because a client holding both has said which one
// it means" — so sending both is unambiguous by the server's own rule, and it is
// what lets one credential work against identity (which takes the cookie) and
// against the other five services (which take a bearer and nothing else) with no
// choice at the call site.
//
// An apiToken attaches `Authorization: Bearer` and NOTHING else. core's
// conventions are explicit that API traffic does not travel in cookies, and a
// credential in a cookie is one a browser silently attaches to a request its holder
// did not intend. A `cafaye_` value has no business in a `Cookie` header, and
// putting one there would publish a machine credential onto the browser surface.
//
// A jwt attaches `Authorization: Bearer` and nothing else, for the same reason.
//
// The asymmetry decides the fallback direction, and it is worth stating which way
// it errs: a session misread as something else loses a cookie it did not strictly
// need — the bearer header is still attached and identity prefers it — while a
// fleet-wide credential misread as a session publishes itself onto the wrong
// surface. So the ambiguous case resolves to the safer of the two.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// APITokenPrefix is identity's `apikeys.Prefix`, read as the discriminator exactly
// as identity reads it.
//
// Duplicated rather than imported: `internal/apikeys` is an `internal/` package and
// this one is not — a client that cannot be imported by a consumer is not a client
// — and the whole module is the service, whose binary must not depend on a client.
// `TestThePrefixIsTheOneIdentityUses` states the two must agree, so the copy
// cannot drift silently.
const APITokenPrefix = "cafaye_"

// SessionCookieName is identity's `httpapi.SessionCookieName`.
//
// The `__Host-` prefix is not cosmetic: it is a browser-enforced contract
// requiring `Secure`, `Path=/` and no `Domain`, and a request that names the cookie
// wrongly is a request that looks authenticated and is not.
const SessionCookieName = "__Host-session"

// CredentialKind is what a credential is, which decides where it may be sent.
type CredentialKind int

const (
	// KindSession is an opaque session token: a human's browser credential, and the
	// only shape that may travel in a cookie.
	KindSession CredentialKind = iota
	// KindAPIToken is a `cafaye_` scoped API token: a machine credential, refused
	// by identity on the session surface and on the credential surface.
	KindAPIToken
	// KindJWT is a JWS compact serialization, which is what the other five
	// services issue and verify against a JWKS.
	KindJWT
)

// String names the kind, and deliberately names the DISCRIMINATOR rather than the
// internal value: "apiToken" is what a reader of a log line or a support ticket
// needs, and an integer index would be meaningless to them and would change meaning
// if a constant were ever inserted.
func (k CredentialKind) String() string {
	switch k {
	case KindAPIToken:
		return "apiToken"
	case KindJWT:
		return "jwt"
	case KindSession:
		return "session"
	}
	return "unknown"
}

// ErrInvalidCredential is returned for a credential this package refuses to send.
//
// A sentinel so a caller can match it with `errors.Is` and decide, which is the
// same shape `internal/config`'s sentinels take in the service half of this
// repository.
var ErrInvalidCredential = errors.New("invalid credential")

// forbiddenInCredential is a safety floor, not a definition.
//
// The point is not to enumerate the alphabet — which would break the first time
// identity mints something new — but to refuse anything that could terminate a
// header line or a cookie attribute. CR, LF and NUL are header injection; the other
// C0 controls, DEL and the space have no legitimate use in any of the three shapes.
// A credential containing one is a configuration mistake whatever produced it, and
// reporting it at construction is worth more than a 401 from a service hours later.
//
// A REGEXP rather than `strings.ContainsAny`, and the reason is a bug this packet
// wrote and this test caught: in a Go string literal `"\x00-\x20\x7f"` is four
// characters — NUL, `-`, space, DEL — and `ContainsAny` takes a SET rather than a
// RANGE. The first version therefore accepted a credential carrying a carriage
// return or a line feed, which is the exact header-injection case the check exists
// for. A character class in a regexp is the range it looks like.
var forbiddenInCredential = regexp.MustCompile(`[\x00-\x20\x7f]`)

// ClassifyCredential decides what a credential is, and refuses one that could
// break a header.
//
// It returns a `CredentialKind` and an error rather than panicking, because the
// caller is a library: a credential from an operator's configuration file is not a
// programming mistake, and taking a process down over one is worse than refusing
// the request.
//
// **The offending value is never quoted back in the error.** A credential that
// reached an error message has leaked, and this is one of the two places that has
// to be true for that not to have happened — the other is the error type's own
// `Error()`.
func ClassifyCredential(token string) (CredentialKind, error) {
	// `%w`, not `errors.New(sentinel.Error() + …)`, and that is a bug this file
	// shipped first: concatenating the sentinel's text produces an error whose
	// message is right and whose identity is not, so `errors.Is(err,
	// ErrInvalidCredential)` is false and every caller that branches on it falls
	// through. A test that only checked `err != nil` passed.
	if token == "" || forbiddenInCredential.MatchString(token) {
		return KindSession, fmt.Errorf("%w: a cafaye credential must be a non-empty string "+
			"containing no control characters, spaces, CR or LF. Refusing it here rather "+
			"than sending it, because a value carrying CR or LF would be a header-injection "+
			"attempt and a blank one is a configuration mistake that would otherwise surface "+
			"as a 401 from a service hours later", ErrInvalidCredential)
	}

	// The prefix first, and before the JWT shape, because identity's discriminator
	// is the prefix and a `cafaye_` value is never a JWT whatever else it looks
	// like.
	if strings.HasPrefix(token, APITokenPrefix) {
		return KindAPIToken, nil
	}
	if isJWSCompact(token) {
		return KindJWT, nil
	}
	return KindSession, nil
}

// jwsCompact is three dot-separated base64url segments, the third possibly empty
// (an unsigned JWS has one).
//
// base64url only, which is what excludes a bare host with dots in it
// (`identity.example.com` is three segments and is not a JWT).
const jwsCompact = "^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*$"

// isJWSCompact is the shape check, and it is necessary and NOT sufficient — which is
// why the header segment is decoded and parsed.
//
// `one.two.three` is three segments and not a JWT. Without the header check a
// base64url value that happens to contain dots would be classified as a JWT and
// then never sent in a cookie, which is the safe direction to be wrong in — but
// `one.two.three` in a config file is far more likely to be a hostname or a
// version string than a credential, and mislabelling it produces a confusing
// classification error for something that was never a credential.
func isJWSCompact(token string) bool {
	if !regexp.MustCompile(jwsCompact).MatchString(token) {
		return false
	}

	first, _, _ := strings.Cut(token, ".")
	raw, err := base64URLDecode(first)
	if err != nil {
		return false
	}

	var header struct {
		Alg string `json:"alg"`
	}
	if err := jsonUnmarshal(raw, &header); err != nil {
		return false
	}
	return header.Alg != ""
}

// AttachCredential puts the credential on a request, in the one place that does it.
//
// Three rules, all of them load-bearing:
//
//   - A session contributes BOTH the bearer header and the cookie, for the reason
//     in the file header: identity prefers the header when both are present, so
//     the pair is unambiguous by the server's own rule and one credential works
//     against every service in the fleet.
//
//   - An apiToken and a jwt contribute the bearer header ONLY. core's conventions
//     reserve cookies for browser sessions, and a machine credential in a cookie is
//     one a browser attaches without the holder intending it.
//
//   - An existing header is never overwritten. The generated client applies the
//     same rule to the same problem (`checkForExistence` in its own utils), and
//     matching it means a caller passing their own `Authorization` per request
//     gets theirs rather than a surprise about which of two values won.
//
// The cookie is set with `Header.Set` rather than `http.Cookie` because a `Cookie`
// request header is exactly one line and `http.Cookie.String()` adds `Path=/`,
// which is wrong for a request header and is the sort of detail that gets a cookie
// silently ignored.
func AttachCredential(req *http.Request, token string) error {
	kind, err := ClassifyCredential(token)
	if err != nil {
		return err
	}

	if req.Header.Get("Authorization") == "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	if kind == KindSession && req.Header.Get("Cookie") == "" {
		req.Header.Set("Cookie", SessionCookieName+"="+token)
	}

	return nil
}

// base64URLDecode and jsonUnmarshal are thin wrappers so this file does not import
// `encoding/base64` and `encoding/json` under names that shadow anything, and so
// the two error paths that matter — a segment that is not base64url, and a header
// that is not JSON — are named rather than inlined at the call site.
func base64URLDecode(segment string) ([]byte, error) {
	// `RawURLEncoding`, not `URLEncoding`: a JWS segment has no `=` padding, and
	// the padded decoder rejects an unpadded input outright.
	return base64.RawURLEncoding.DecodeString(segment)
}

func jsonUnmarshal(raw []byte, into any) error {
	return json.Unmarshal(raw, into)
}
