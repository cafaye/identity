package outbox

import (
	"time"

	"github.com/cafaye/identity/internal/platform/id"
)

// The MFA events: a second factor went on, and a second factor went off.
//
// The names are core's, fixed before this packet: `identity.mfa.enabled` and
// `identity.mfa.disabled`, both three-segment, both in core's catalog under
// "the user" as the subject (docs/event-naming.md). This file is the publisher
// side of two rows another repository is writing the schema for, so the payload
// is the narrowest thing that is still useful rather than a guess at what the
// schema will turn out to want.
//
// THE SUBJECT IS THE USER, and for this pair that is not a judgement call the
// way the tenancy events' subject was. A membership change is about an account's
// member list, so five acceptances are five events in one ordered stream. A
// factor changing is about one person and one device they carry, and a consumer
// that cares means "this person's security posture changed" — which is a stream
// keyed on the user. core's catalog already says so, and the event id is what
// makes two rapid changes (rotate, then disable) two ordered facts about one
// person rather than an ambiguous pair.

// The event types this service publishes for MFA. These are core's catalog rows;
// see the note above on the payload shape.
const (
	// EventMFAEnabled is emitted when a TOTP credential is confirmed.
	//
	// It fires for the FIRST enrollment and for every rotation after it, and both
	// are the same fact: a second factor is live for this user now. A consumer
	// that wants to tell the two apart reads whether it had already seen one,
	// which is information it has, rather than a field on the event that would be
	// a boolean meaning nothing to anybody else.
	//
	// A rotation is a genuine change — a new secret, a new device, a new set of
	// recovery codes — and a consumer that only heard about the first enrollment
	// would be holding a stale picture of how the account is protected.
	EventMFAEnabled = "identity.mfa.enabled"

	// EventMFADisabled is emitted when a user turns their second factor off with a
	// valid factor of their own. There is no other way to reach it from this
	// service.
	EventMFADisabled = "identity.mfa.disabled"
)

// NewMFAEnabled builds the event emitted when a second factor goes live.
//
// THERE IS NO SECRET IN THIS PAYLOAD, and the omissions are the interesting part:
//
//   - no TOTP secret, and no `otpauth://` URI, which contains the secret and would
//     carry it to every subscriber on the platform
//   - no recovery code, and no digest of one
//   - no code, presented or expected
//
// Every event on the platform reaches every subscriber, which is exactly the wrong
// place for a credential. The same reasoning is in NewOIDCClientCreated, and it
// is the rule rather than a coincidence: the raw values exist once, in the
// response to whoever asked, and the rows hold digests.
func NewMFAEnabled(now time.Time, userID, credentialID id.UUID, method string) (Envelope, error) {
	return newSubjectEvent(now, EventMFAEnabled, userID.String(), struct {
		UserID       string `json:"user_id"`
		CredentialID string `json:"credential_id"`
		Method       string `json:"method"`
	}{
		UserID:       userID.String(),
		CredentialID: credentialID.String(),
		Method:       method,
	})
}

// NewMFADisabled builds the event emitted when a second factor goes off.
//
// It carries the method and the credential that is gone, and nothing about WHY.
// "Why" is operator-facing context typed by a human at a call site — a lost
// phone, a support ticket, somebody else telling them to — and a field whose
// values vary per operator is a field every consumer learns to ignore. The
// credential id is in the payload rather than only in the subject so a consumer
// can tell a rotation-then-disable from a disable of a long-standing factor,
// which is the difference between a lost phone and an account being cleaned up.
func NewMFADisabled(now time.Time, userID id.UUID, method string) (Envelope, error) {
	return newSubjectEvent(now, EventMFADisabled, userID.String(), struct {
		UserID string `json:"user_id"`
		Method string `json:"method"`
	}{
		UserID: userID.String(),
		Method: method,
	})
}
