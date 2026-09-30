package outbox

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/cafaye/identity/internal/platform/id"
)

// The tenancy events: an account came into being, somebody was invited, the
// invitation was accepted, a role moved, a member left.
//
// Every one of them has its subject set to the *account*, including the three
// that are obviously about a person. That is the decision core's "Why subject is
// required" section is about: subject is the entity the event is about and the
// value a consumer correlates per-entity ordering on. A membership change is
// about the account's member list — five members accepting five invitations is
// five events in one ordered stream, and a consumer that cared about the order
// of one person's memberships across accounts would correlate on the user id
// instead, which is a different question and gets a different event.
//
// The time is the moment of the state change, taken from the injected clock for
// the same reason NewUserCreated takes it: the event and the row it describes
// have to agree, and only one of the two is under test control.
//
// ROLES ARE STRINGS HERE, NOT accounts.Role.
//
// This package is transport: it knows the envelope and the payload schemas and
// nothing about the domain those payloads describe. Taking accounts.Role would
// make outbox import accounts, and accounts import outbox to append its events —
// a cycle that exists only because a role happens to be a string on the wire.
// The caller writes string(role), which is what goes into the JSON anyway, and
// the two packages stay independent: outbox is reusable by a service with no
// accounts in it, and accounts can change its role type without touching a
// published event's shape.

// The event types this service publishes for tenancy.
//
// The three-segment form is core's since v0.2 and the packet specifies it. Each
// is in core's catalog under these exact names except identity.member.accepted
// — see the note on that constant.
const (
	// EventAccountCreated is emitted when an account is provisioned — by
	// POST /v1/accounts, and by a registration creating its personal account.
	EventAccountCreated = "identity.account.created"

	// EventMemberInvited is emitted when an invitation is created. Its
	// data.invitation_id is the thing to act on (core's catalog).
	EventMemberInvited = "identity.member.invited"

	// EventMemberAccepted is emitted when an invitation is redeemed and the
	// membership is created.
	//
	// CORE DISAGREES WITH THIS NAME, AND THE MANAGER HAS TO RULE ON IT.
	//
	// core's docs/event-naming.md catalog has a row for this fact and calls it
	// `identity.member.joined` ("An invitation is accepted"), and `accepted` is
	// not in core's action vocabulary — the document says "Stick to this list for
	// v0; anything else is a manager decision".
	//
	// This service follows the packet for identity-04, which specifies
	// `identity.member.accepted` in its event list, for the same reason
	// identity-02 followed the packet for `identity.user.created`: the packet is
	// the manager's decision and the divergence is recorded rather than silently
	// resolved. The cost is that identity's cafaye.yml now advertises a type core's
	// catalog does not have, while core's catalog row has no publisher.
	//
	// Flipping it is this constant and the matching line in cafaye.yml. Nothing
	// else moves: the payload schema, the subject, and every consumer keyed on the
	// account id are unaffected.
	EventMemberAccepted = "identity.member.accepted"

	// EventMemberRoleChanged is emitted when a role is granted or revoked. The
	// payload carries the old and the new role, per core's catalog.
	EventMemberRoleChanged = "identity.member.role_changed"

	// EventMemberRemoved is emitted when a member is removed. The payload carries
	// the role they held, because "who was removed" is not the question a
	// downstream service asks; "what could they do until now" is.
	EventMemberRemoved = "identity.member.removed"
)

// NewAccountCreated builds the event emitted when an account is provisioned.
//
// It fires twice in the life of a user who signs up: once for the personal
// account the registration creates, and once for every team account they make
// afterwards. Both are the same fact — an account now exists and this user owns
// it — and a consumer that wants to tell them apart reads data.personal.
func NewAccountCreated(now time.Time, accountID id.UUID, name, slug string, personal bool, ownerID id.UUID) (Envelope, error) {
	return newTenancyEvent(now, EventAccountCreated, accountID, struct {
		AccountID string `json:"account_id"`
		Name      string `json:"name"`
		Slug      string `json:"slug"`
		Personal  bool   `json:"personal"`
		OwnerID   string `json:"owner_id"`
	}{
		AccountID: accountID.String(),
		Name:      name,
		Slug:      slug,
		Personal:  personal,
		OwnerID:   ownerID.String(),
	})
}

// NewMemberInvited builds the event emitted when an invitation is created.
//
// The email is in the payload because a consumer that mails the invitation needs
// it and there is no other way to get it: this service does not send mail. It
// carries no token, and that is the important omission — the raw invitation
// token exists once, in the 201 response, and no event on the platform carries a
// usable credential.
func NewMemberInvited(now time.Time, accountID, invitationID id.UUID, email, role string, inviterID id.UUID) (Envelope, error) {
	return newTenancyEvent(now, EventMemberInvited, accountID, struct {
		AccountID    string `json:"account_id"`
		InvitationID string `json:"invitation_id"`
		Email        string `json:"email"`
		Role         string `json:"role"`
		InvitedByID  string `json:"invited_by_id"`
	}{
		AccountID:    accountID.String(),
		InvitationID: invitationID.String(),
		Email:        email,
		Role:         role,
		InvitedByID:  inviterID.String(),
	})
}

// NewMemberAccepted builds the event emitted when an invitation is redeemed.
//
// It is emitted in the same transaction as the membership it describes. An
// event without a membership announces somebody joined who did not, and a
// membership without the event leaves a consumer's member list permanently one
// short with no way to notice.
func NewMemberAccepted(now time.Time, accountID, userID id.UUID, role string) (Envelope, error) {
	return newTenancyEvent(now, EventMemberAccepted, accountID, struct {
		AccountID string `json:"account_id"`
		UserID    string `json:"user_id"`
		Role      string `json:"role"`
	}{
		AccountID: accountID.String(),
		UserID:    userID.String(),
		Role:      role,
	})
}

// NewMemberRoleChanged builds the event emitted when a role is granted or
// revoked.
//
// Both roles are in the payload. One of them is not enough in either direction:
// the old role is what a consumer needs to revoke what it previously granted,
// and the new role is what it needs to grant. A consumer that only receives the
// new role has to remember the old one, and a consumer that forgot is the bug
// this is here to prevent.
func NewMemberRoleChanged(now time.Time, accountID, userID id.UUID, previous, current string) (Envelope, error) {
	return newTenancyEvent(now, EventMemberRoleChanged, accountID, struct {
		AccountID    string `json:"account_id"`
		UserID       string `json:"user_id"`
		PreviousRole string `json:"previous_role"`
		Role         string `json:"role"`
	}{
		AccountID:    accountID.String(),
		UserID:       userID.String(),
		PreviousRole: previous,
		Role:         current,
	})
}

// NewMemberRemoved builds the event emitted when a member is removed.
//
// The role they held travels with it. "user X was removed from account Y" tells
// a downstream service very little; "user X, who was an owner, is no longer an
// owner of account Y" tells it whether to re-check its own authorization cache.
func NewMemberRemoved(now time.Time, accountID, userID id.UUID, role string) (Envelope, error) {
	return newTenancyEvent(now, EventMemberRemoved, accountID, struct {
		AccountID string `json:"account_id"`
		UserID    string `json:"user_id"`
		Role      string `json:"role"`
	}{
		AccountID: accountID.String(),
		UserID:    userID.String(),
		Role:      role,
	})
}

// newTenancyEvent is the shared construction: a fresh envelope id, the tenancy
// subject, the injected time, and a payload marshalled from a struct.
//
// The struct-and-marshal is not ceremony. Concatenating these fields into a JSON
// string by hand is how a name containing a quote produces a payload that is not
// a JSON object, and Validate would then reject the event at the one place that
// could have caught it with a useful message.
func newTenancyEvent(now time.Time, eventType string, accountID id.UUID, payload any) (Envelope, error) {
	eventID, err := id.New()
	if err != nil {
		return Envelope{}, fmt.Errorf("outbox: minting an envelope id: %w", err)
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return Envelope{}, fmt.Errorf("outbox: building the %s payload: %w", eventType, err)
	}

	return Envelope{
		SpecVersion: SpecVersion,
		ID:          eventID,
		Type:        eventType,
		Source:      SourceIdentity,
		Subject:     accountID.String(),
		Time:        now.UTC(),
		Data:        data,
	}, nil
}
