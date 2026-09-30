package oidc

import (
	"context"
	"fmt"

	"github.com/cafaye/identity/internal/platform/id"
)

// The two operations the login page needs from the provider, kept off the HTTP
// handler so that the handler holds no storage machinery and the provider holds
// no knowledge of a form.
//
// They are methods on *Storage rather than on *Provider because that is where
// the statements are, and *Provider is the library's configuration.

// PathAuthorizeCallback is where the library sends the browser back to once the
// login UI has authenticated somebody.
//
// It is derived rather than spelled out because it has to be the library's path
// and the library builds it from its own endpoint configuration: a second
// spelling of it would be a second answer to where the redirect goes.
const PathAuthorizeCallback = PathAuthorize + "/callback"

// LoginBanner is what the login page renders before anybody has typed anything.
//
// The product's name is the load-bearing field. A login page that cannot say
// which application is asking for a password is the setup for a credential
// phishing page hosted on this service's own domain, and the `client_id` cannot
// do the job: it is 43 characters of base64url chosen for entropy, so displaying
// it tells a user nothing they could recognise or check against the product they
// meant to sign in to.
type LoginBanner struct {
	// RequestID names the authorization request this login completes.
	RequestID string
	// ClientName is the registration's display name.
	ClientName string
	// LoginHint is the `login_hint` the client sent, if any. It pre-fills the
	// form and is never trusted: it is a string a third party chose, and the
	// password is still checked against the address the user types.
	LoginHint string
}

// LoginBanner returns what the login page needs for a request id.
//
// An unknown or expired id is ErrAuthRequestNotFound, and the handler answers 404
// with it. The id arrived in a URL, so the two cases — never existed, and
// outlived its ten minutes — are the same answer.
func (s *Storage) LoginBanner(ctx context.Context, requestID string) (LoginBanner, error) {
	rowID, err := id.Parse(requestID)
	if err != nil {
		return LoginBanner{}, fmt.Errorf("%w: not an id this service issued", ErrAuthRequestNotFound)
	}
	request, err := s.store.AuthRequestByID(ctx, s.read.Queryer(), rowID, s.clk.Now())
	if err != nil {
		return LoginBanner{}, err
	}
	return LoginBanner{
		RequestID:  request.ID.String(),
		ClientName: request.ClientName,
		LoginHint:  request.LoginHint,
	}, nil
}

// CompleteLogin records that a user authenticated against a request.
//
// It does NOT redirect. The redirect carries an authorization code, and building
// that is the library's job over a request it considers done — so the handler
// completes the request here and then hands the browser back to the library's own
// callback, which is the only place a code is minted.
func (s *Storage) CompleteLogin(ctx context.Context, requestID string, subject id.UUID) error {
	rowID, err := id.Parse(requestID)
	if err != nil {
		return fmt.Errorf("%w: not an id this service issued", ErrAuthRequestNotFound)
	}
	return s.store.CompleteAuthRequest(ctx, s.read.Queryer(), rowID, subject, s.clk.Now())
}
