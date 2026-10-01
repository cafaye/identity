package outbox

import (
	"fmt"
	"time"

	"github.com/cafaye/identity/internal/platform/id"
)

// The recovery events: an address was proved, and a set of credentials was ended.
//
// # WHY THERE ARE TWO AND NOT FOUR
//
// A password reset and an email change are different facts and they are announced
// differently — `identity.user.email_verified` is about an address, and
// `identity.session.revoked` is about credentials. But both of the flows that END
// credentials emit the same event, because a consumer's question is the same in
// each case and identical answers are what let it write one subscriber: "this
// person's sessions are gone; drop whatever you cached against them".
//
// The reason travels in the payload rather than being left out, and the reason is
// that a consumer acting on it sometimes needs to know whether to expect a
// sign-in. `reason` is a closed set in this package rather than free text, for the
// reason api_keys' `revoke_reason` is a closed value on the row: nothing typed
// this, so a consumer can switch on it.

// The event types this service publishes for the recovery flows. Both are core's
// catalog rows under these exact names (docs/event-naming.md, the identity
// table), and both are three-segment with this service's own prefix.
const (
	// EventUserEmailVerified is emitted when somebody redeems a verification link
	// for the address on their own account.
	//
	// core's row says "The verification link is redeemed", and that is the only
	// case: an email change CLEARS the verification rather than setting it, so a
	// moved address produces this event only when the new one is confirmed in its
	// own right.
	EventUserEmailVerified = "identity.user.email_verified"

	// EventSessionsRevoked is emitted when every credential a user holds is ended
	// by one of this service's own flows: a password reset, or an email address
	// change.
	//
	// IT IS CORE'S ROW UNDER THIS EXACT NAME, and its catalog wording is the
	// definition — "Password change, 'sign out everywhere', or admin
	// revocation" — which is exactly the set of things this event reports. What is
	// deliberate is WHERE this service emits it: only for the "every credential is
	// gone" case, and never for DELETE /v1/session, which ends ONE session and is
	// a different fact with a different consequence for a consumer. So a subscriber
	// that sees this type can treat it as "this account's credentials are all gone,
	// drop whatever you cached against them", and the gap — a single logout
	// announces nothing — is recorded in README.md rather than papered over by
	// emitting a wrong type for it.
	EventSessionsRevoked = "identity.session.revoked"
)

// The closed set of reasons a set of credentials was ended.
const (
	// ReasonPasswordReset is a password recovered through a mailed link.
	ReasonPasswordReset = "password reset"

	// ReasonEmailChanged is an account whose address moved, which ends every
	// credential it had.
	ReasonEmailChanged = "email address changed"
)

// validateReason refuses a reason this build does not know.
//
// IT IS THE SAME FAIL-CLOSED SHAPE AS admin's validateAction and apikeys' scope
// validation: a row holding a value this build does not implement must be refused
// when it is read, because treating an unknown reason as "and so anything goes" is
// the bug a later change would otherwise introduce silently.
func validateReason(reason string) error {
	switch reason {
	case ReasonPasswordReset, ReasonEmailChanged:
		return nil
	default:
		return fmt.Errorf("outbox: %q is not a reason this service ends credentials for", reason)
	}
}

// NewUserEmailVerified builds the event emitted when an address is proved.
//
// THERE IS NO SECRET IN THIS PAYLOAD, and the omission is the interesting part: no
// token, no digest, and no address beyond the one already on the account row. Every
// event on the platform reaches every subscriber, which is exactly the wrong place
// for a credential, and the address is a fact every consumer can already read from
// the user it is about.
func NewUserEmailVerified(now time.Time, userID id.UUID) (Envelope, error) {
	return newSubjectEvent(now, EventUserEmailVerified, userID.String(), struct {
		UserID string `json:"user_id"`
	}{
		UserID: userID.String(),
	})
}

// NewSessionsRevoked builds the event emitted when every credential a user holds
// is ended.
//
// `reason` is required and is one of the two constants above. It is validated here
// rather than at the call site because a caller that passed an arbitrary string
// would produce an envelope that satisfies the schema and says nothing a consumer
// can act on.
func NewSessionsRevoked(now time.Time, userID id.UUID, reason string) (Envelope, error) {
	if err := validateReason(reason); err != nil {
		return Envelope{}, err
	}
	return newSubjectEvent(now, EventSessionsRevoked, userID.String(), struct {
		UserID string `json:"user_id"`
		Reason string `json:"reason"`
	}{
		UserID: userID.String(),
		Reason: reason,
	})
}
