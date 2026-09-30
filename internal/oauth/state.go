package oauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

// StateSeparator joins the provider name to the random token inside a state.
//
// It is a character that cannot appear in either part: a provider name is a bare
// lowercase word from the registry, and the token is base64url.
const StateSeparator = "."

// stateBytes is the entropy of a state token. 32 bytes is the same budget as a
// session token (internal/sessions), for the same reason: the value is a one-shot
// bearer secret an attacker would have to guess, and 256 bits is not a problem
// anyone has solved.
const stateBytes = 32

// NewState returns a CSRF state value bound to provider.
//
// It takes no clock and no store, deliberately: the expiry is the cookie's
// Max-Age, which the handler sets from StateTTL, and the value itself has to be
// reproducible nowhere else. A state that could be recomputed from a timestamp
// would be forgeable by anyone who guessed the timestamp.
func NewState(provider string) (string, error) {
	if provider == "" {
		// A state with no provider could not be bound to a callback, so it would
		// verify at every provider. Refusing here keeps the invariant total.
		return "", fmt.Errorf("oauth state needs a provider, got %q", provider)
	}

	raw := make([]byte, stateBytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("reading random bytes for an oauth state: %w", err)
	}

	return provider + StateSeparator + base64.RawURLEncoding.EncodeToString(raw), nil
}

// VerifyState reports whether presented is the state this service put in the
// cookie for provider.
//
// All three arguments are attacker-influenced: provider comes from the URL, and
// the cookie and the query parameter are both under the browser's control in a
// cross-site request. So every rejection is a plain `false` and there is no branch
// that reveals which part failed.
func VerifyState(provider, sealed, presented string) bool {
	sealedProvider, sealedToken, ok := splitState(sealed)
	if !ok {
		return false
	}
	presentedProvider, presentedToken, ok := splitState(presented)
	if !ok {
		return false
	}

	// Compared against the route, not against the cookie: a flow started for GitHub
	// must not be finishable at Google's callback, and the only place that knows
	// which provider is being served is the path.
	if subtle.ConstantTimeCompare([]byte(sealedProvider), []byte(provider)) != 1 {
		return false
	}
	if sealedProvider != presentedProvider {
		return false
	}

	// Constant time on the token. The length is not secret — the attacker chose
	// whatever they presented — and ConstantTimeCompare returns 0 for a mismatch in
	// length, which is the answer we want anyway.
	return subtle.ConstantTimeCompare([]byte(sealedToken), []byte(presentedToken)) == 1
}

// splitState cuts at the FIRST separator and requires a non-empty token on both
// sides. "google." and "google" are both refused: they are what a truncated or
// half-populated cookie produces, and neither is a state this service minted.
func splitState(value string) (provider, token string, ok bool) {
	provider, token, found := strings.Cut(value, StateSeparator)
	if !found || provider == "" || token == "" {
		return "", "", false
	}
	if strings.Contains(token, StateSeparator) {
		return "", "", false
	}
	return provider, token, true
}
