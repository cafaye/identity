// Package outbox is the transactional outbox: the table an event is written to in
// the same transaction as the state change it describes, and the loop that moves
// those rows onto the bus.
//
// The point of the table is atomicity. A user row and its `identity.user.created`
// event either both exist or neither does. Publishing inside the request would
// mean an event about a user who was never created, or a user nobody downstream
// ever hears about; publishing from a queue fed after commit would mean the same
// two failures with a queue in between. The insert commits with the row, and a
// separate loop moves it.
package outbox

import (
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/cafaye/identity/internal/platform/id"
)

const (
	// SpecVersion pins the envelope dialect. core's schema makes it a const "1.0"
	// and the description says it increments only for a breaking envelope change.
	SpecVersion = "1.0"

	// SourceIdentity is the publishing service. core's event-naming.md: it "must
	// equal `name` in that service's cafaye.yml", and identity's is `identity`.
	SourceIdentity = "identity"

	// EventUserCreated is emitted when a registration succeeds, before any email
	// verification.
	//
	// This is the three-segment form `identity.user.created`, which the packet for
	// this service specifies. Note that core's docs/event-naming.md is currently
	// against it: rule 2 asks for the service prefix only when the bare entity
	// name is generic (key, token, event, file, job, config, webhook, asset,
	// secret), `user` is not on that list, and the catalog row plus
	// examples/valid/go-api.cafaye.yml both spell it `user.created`. The same
	// document records this as an open decision (D1) with the three-segment form
	// named as the alternative.
	//
	// The two spellings differ in one constant and one line of cafaye.yml, so a
	// manager ruling the other way is a one-line change. What must not happen is
	// the drift where the code emits one and the manifest advertises the other.
	EventUserCreated = "identity.user.created"
)

// Envelope is the cafaye event envelope, reproducing
// cafaye/core/schemas/event-envelope.schema.json.
//
// The JSON tags are the wire contract. core sets additionalProperties:false, so
// every attribute is declared here and nothing else is ever added: an undeclared
// attribute is rejected by every consumer on the platform.
//
// `subject` is omitempty because core requires minLength 1 on it — emitting
// `""` for an event with no entity would fail validation, whereas omitting it
// passes. Entity events in this service always have one.
type Envelope struct {
	SpecVersion string          `json:"specversion"`
	ID          id.UUID         `json:"id"`
	Type        string          `json:"type"`
	Source      string          `json:"source"`
	Subject     string          `json:"subject,omitempty"`
	Time        time.Time       `json:"time"`
	Data        json.RawMessage `json:"data"`
}

// eventTypePattern and serviceNamePattern are copied verbatim from core's
// $defs, so that a value this package accepts is one core's schema accepts.
//
// core's tests/test_specs.py asserts the envelope and manifest schemas agree on
// these two patterns, so they cannot drift apart inside core. Copying them here
// is the duplication that keeps a malformed type from being written at all.
var (
	eventTypePattern   = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*(\.[a-z][a-z0-9]*(_[a-z0-9]+)*){1,2}$`)
	serviceNamePattern = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)
	// core's subject pattern. A subject is an identifier interpolated into
	// consumer logs and routing keys, so the character set is deliberately narrow.
	subjectPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/-]*$`)
)

// Length bounds copied from core's schema: subject 1-200, source 2-40,
// type 5-120.
const (
	maxSubjectLength = 200
	minSourceLength  = 2
	maxSourceLength  = 40
	minTypeLength    = 5
	maxTypeLength    = 120
)

// Validate reports whether the envelope satisfies core's schema.
//
// It is called before every append. The alternative is letting a bad envelope
// reach the table and fail at every consumer instead of at the one place that
// wrote it — and the table's CHECK constraints would catch the two patterns, but
// not a missing subject or an unparseable payload.
func (e Envelope) Validate() error {
	if e.SpecVersion != SpecVersion {
		return fmt.Errorf("outbox: specversion is %q, want %q", e.SpecVersion, SpecVersion)
	}
	if e.ID.IsZero() {
		return fmt.Errorf("outbox: id is required; consumers deduplicate on it")
	}
	if !validEventType(e.Type) {
		return fmt.Errorf("outbox: type %q does not match core's eventType pattern", e.Type)
	}
	if !validServiceName(e.Source) {
		return fmt.Errorf("outbox: source %q does not match core's serviceName pattern", e.Source)
	}
	if e.Subject != "" {
		if len(e.Subject) > maxSubjectLength {
			return fmt.Errorf("outbox: subject is %d characters, want at most %d", len(e.Subject), maxSubjectLength)
		}
		if !subjectPattern.MatchString(e.Subject) {
			return fmt.Errorf("outbox: subject %q does not match core's subject pattern", e.Subject)
		}
	}
	if e.Time.IsZero() {
		return fmt.Errorf("outbox: time is required")
	}
	if !json.Valid(e.Data) {
		return fmt.Errorf("outbox: data is not valid JSON")
	}
	return nil
}

// NewUserCreated builds the event emitted when a registration succeeds.
//
// now is the moment of the state change, not the moment of publishing, and it
// comes from the injected clock for the same reason every other timestamp in this
// service does: the two must agree, and only one of them is under test control.
//
// The payload carries the user id and email and nothing else. In particular no
// password digest and no lockout state: the envelope goes to every subscriber on
// the platform, and this is the only place where that boundary is enforced.
func NewUserCreated(now time.Time, userID id.UUID, email string) (Envelope, error) {
	eventID, err := id.New()
	if err != nil {
		return Envelope{}, fmt.Errorf("outbox: minting an envelope id: %w", err)
	}

	// json.Marshal of a struct cannot fail on these two string fields, and using
	// it rather than string concatenation is what keeps a crafted email from
	// producing a payload that is not a JSON object.
	payload, err := json.Marshal(struct {
		UserID string `json:"user_id"`
		Email  string `json:"email"`
	}{UserID: userID.String(), Email: email})
	if err != nil {
		return Envelope{}, fmt.Errorf("outbox: building the user.created payload: %w", err)
	}

	return Envelope{
		SpecVersion: SpecVersion,
		ID:          eventID,
		Type:        EventUserCreated,
		Source:      SourceIdentity,
		Subject:     userID.String(),
		Time:        now.UTC(),
		Data:        payload,
	}, nil
}

func validEventType(s string) bool {
	if len(s) < minTypeLength || len(s) > maxTypeLength {
		return false
	}
	return eventTypePattern.MatchString(s)
}

func validServiceName(s string) bool {
	if len(s) < minSourceLength || len(s) > maxSourceLength {
		return false
	}
	return serviceNamePattern.MatchString(s)
}
