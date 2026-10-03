package httpapi

// THE SOCIAL-LOGIN DOUBLE, and why the walk needed one before the docs did.
//
// ## The third instance of the walk bug, and this time it blinded the tripwire
//
// `internal/httpapi/oauth.go` mounts two routes behind `options.social`, and
// `registerSocialRoutes` returns immediately when that field is nil — exactly the
// shape router_walk_test.go was written for. `social` was not in
// `conditionalSurfaces`, and `servedRoutes` and `walkOptions` did not set it, so:
//
//   - `TestEveryServedRouteIsDocumentedOrNamed` reported the OpenAPI documents and
//     the router in agreement while two undocumented operations were mounted;
//   - the README claim checks compared a README against a router that did not have
//     the social routes in it, in BOTH directions, and agreed;
//   - and `oauth_absent_test.go`, the tripwire whose failure message was the work
//     order for mounting the surface, was GREEN. Not red with its checklist: green,
//     because the walk it was handed had nothing under the prefix in it.
//
// That last one is the finding worth having. The tripwire was not a tripwire at
// the moment it mattered. Its argument was "the day the surface mounts, this test
// goes red" and the day came and it stayed green, for the reason
// router_walk_test.go's own header calls "the one outcome this repository names as
// the failure mode these files exist to prevent". The check went green by not
// checking, and it was the check for this exact surface.
//
// It did not catch it because nobody ran it: `go vet ./internal/httpapi/...` failed
// on the `socialLoginPrefix` redeclaration, so this package's tests had not been
// executable at all since the surface landed. A compile break in the test package
// is not a neutral event for the tripwire — it is the one thing that can hide a
// red test, and this repository spent a whole packet unable to run the check that
// would have told it the routes were undocumented.
//
// ## What the double is, and what it deliberately is not
//
// It returns a REAL `oauth.Provider` — `oauth.Google()` — rather than a struct that
// satisfies an interface, because `Social.Lookup` returns a concrete type and there
// is nothing else to return. That matters more than it looks: `oauth.Google()` is
// the value whose `RedirectURI` `TestTheSocialLoginPrefixIsTheOneTheProviderBuilds`
// ties `socialLoginPrefix` to, so a double built from it cannot disagree with the
// constant the walks are looking under.
//
// `Callback` records the call and returns a refusal. No test in this package needs
// a social callback to SUCCEED — the round trip is `internal/auth`'s to test, over
// its own registry and its own store — and a double that minted a session here
// would be a second, easier way to get one, which is the hole this whole surface is
// built to not have. The walk only needs the routes to EXIST.

import (
	"context"

	"github.com/cafaye/identity/internal/auth"
	"github.com/cafaye/identity/internal/oauth"
)

// fakeSocial is the double behind `walkOptions` and `servedRoutes`.
type fakeSocial struct {
	// base is the configured public base every callback is built from, and the
	// double does not take it from the request for the reason oauth.go does not: a
	// Host header an attacker chose must not become part of a redirect_uri.
	base string

	// requested records the providers the router was asked to look up, so a test
	// about the mounted routes can assert the double was reached rather than that a
	// field was set.
	requested []string

	// callbackErr is what Callback answers with. A refusal is the default and the
	// reason is the header: nothing here needs the round trip to succeed.
	callbackErr error
}

func newFakeSocial() *fakeSocial {
	return &fakeSocial{base: "https://identity.test"}
}

// Lookup resolves the provider the router named.
//
// It refuses anything but google, because a provider this deployment has no
// credentials for and a provider that does not exist have to be the same answer —
// the router renders both as 404 and the distinction is a way to enumerate a
// deployment's configuration. A double that accepted every name would quietly make
// that refusal untested.
func (f *fakeSocial) Lookup(provider string) (oauth.Provider, error) {
	f.requested = append(f.requested, provider)
	if provider != oauth.Google().Name {
		return oauth.Provider{}, auth.ErrSocialNoProviders
	}
	return oauth.Google(), nil
}

func (f *fakeSocial) RedirectBase() string { return f.base }

func (f *fakeSocial) Callback(_ context.Context, in auth.SocialCallbackInput) (auth.LoginResult, error) {
	f.requested = append(f.requested, in.Provider)
	return auth.LoginResult{}, f.callbackErr
}
