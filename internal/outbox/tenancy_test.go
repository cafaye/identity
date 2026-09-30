package outbox

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/platform/id"
)

// The five tenancy events. Every one of them is about an account, so the
// envelope's subject is the account id in all five cases — which is what lets a
// consumer that needs "everything that happened to this account, in order"
// correlate on one value and nothing else (core: docs/event-naming.md, "Why
// subject is required").
//
// Every one is validated here against core's envelope rules, because the
// alternative is a malformed event reaching the table and being rejected by
// every consumer on the platform instead of at the one place that wrote it.

func tenancyTestIDs() (account, user, invitation id.UUID) {
	return id.MustNew(), id.MustNew(), id.MustNew()
}

func TestAccountCreatedEnvelope(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	accountID, ownerID, _ := tenancyTestIDs()

	e, err := NewAccountCreated(now, accountID, "Acme Corp", "acme-corp", false, ownerID)
	if err != nil {
		t.Fatalf("NewAccountCreated: %v", err)
	}

	if err := e.Validate(); err != nil {
		t.Fatalf("the envelope does not satisfy core's schema: %v", err)
	}
	if e.Type != EventAccountCreated {
		t.Errorf("type = %q, want %q", e.Type, EventAccountCreated)
	}
	if e.Source != SourceIdentity {
		t.Errorf("source = %q, want %q", e.Source, SourceIdentity)
	}
	if e.Subject != accountID.String() {
		t.Errorf("subject = %q, want the account id %q", e.Subject, accountID)
	}
	if e.SpecVersion != SpecVersion {
		t.Errorf("specversion = %q, want %q", e.SpecVersion, SpecVersion)
	}
	if !e.Time.Equal(now) {
		t.Errorf("time = %s, want the injected %s — the event is stamped when the state changed, not when it was queued", e.Time, now)
	}

	// The payload is the promise to consumers, so it is asserted field by field
	// rather than as a marshalled blob.
	var data struct {
		AccountID string `json:"account_id"`
		Name      string `json:"name"`
		Slug      string `json:"slug"`
		Personal  bool   `json:"personal"`
		OwnerID   string `json:"owner_id"`
	}
	decodeData(t, e, &data)

	if data.AccountID != accountID.String() || data.OwnerID != ownerID.String() {
		t.Errorf("payload ids = %+v, want account %s and owner %s", data, accountID, ownerID)
	}
	if data.Name != "Acme Corp" || data.Slug != "acme-corp" || data.Personal {
		t.Errorf("payload = %+v, want the account that was created", data)
	}
}

func TestMemberInvitedEnvelope(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	accountID, inviterID, _ := tenancyTestIDs()
	invitationID := id.MustNew()

	e, err := NewMemberInvited(now, accountID, invitationID, "invitee@example.com", "member", inviterID)
	if err != nil {
		t.Fatalf("NewMemberInvited: %v", err)
	}

	if err := e.Validate(); err != nil {
		t.Fatalf("the envelope does not satisfy core's schema: %v", err)
	}
	if e.Type != EventMemberInvited {
		t.Errorf("type = %q, want %q", e.Type, EventMemberInvited)
	}
	// The subject is the account even though data.invitation_id is the thing to
	// act on: subject carries per-entity ordering, and the entity here is the
	// account whose membership list changed.
	if e.Subject != accountID.String() {
		t.Errorf("subject = %q, want the account id %q", e.Subject, accountID)
	}

	var data struct {
		AccountID    string `json:"account_id"`
		InvitationID string `json:"invitation_id"`
		Email        string `json:"email"`
		Role         string `json:"role"`
		InvitedByID  string `json:"invited_by_id"`
	}
	decodeData(t, e, &data)

	if data.InvitationID != invitationID.String() {
		t.Errorf("invitation_id = %q, want %q", data.InvitationID, invitationID)
	}
	if data.Email != "invitee@example.com" || data.Role != "member" || data.InvitedByID != inviterID.String() {
		t.Errorf("payload = %+v", data)
	}
}

func TestMemberAcceptedEnvelope(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	accountID, userID, _ := tenancyTestIDs()

	e, err := NewMemberAccepted(now, accountID, userID, "admin")
	if err != nil {
		t.Fatalf("NewMemberAccepted: %v", err)
	}

	if err := e.Validate(); err != nil {
		t.Fatalf("the envelope does not satisfy core's schema: %v", err)
	}
	if e.Type != EventMemberAccepted {
		t.Errorf("type = %q, want %q", e.Type, EventMemberAccepted)
	}
	if e.Subject != accountID.String() {
		t.Errorf("subject = %q, want the account id", e.Subject)
	}

	var data struct {
		AccountID string `json:"account_id"`
		UserID    string `json:"user_id"`
		Role      string `json:"role"`
	}
	decodeData(t, e, &data)

	if data.AccountID != accountID.String() || data.UserID != userID.String() || data.Role != "admin" {
		t.Errorf("payload = %+v, want the membership that was created", data)
	}
}

func TestMemberRoleChangedCarriesBothRoles(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	accountID, userID, _ := tenancyTestIDs()

	e, err := NewMemberRoleChanged(now, accountID, userID, "member", "admin")
	if err != nil {
		t.Fatalf("NewMemberRoleChanged: %v", err)
	}

	if err := e.Validate(); err != nil {
		t.Fatalf("the envelope does not satisfy core's schema: %v", err)
	}
	if e.Subject != accountID.String() {
		t.Errorf("subject = %q, want the account id", e.Subject)
	}

	// core's catalog row: "data carries old and new role". A consumer that only
	// learns the new role cannot build an audit trail, and one that only learns
	// the old one cannot rebuild the current state.
	var data struct {
		AccountID    string `json:"account_id"`
		UserID       string `json:"user_id"`
		PreviousRole string `json:"previous_role"`
		Role         string `json:"role"`
	}
	decodeData(t, e, &data)

	if data.PreviousRole != "member" || data.Role != "admin" {
		t.Errorf("payload = %+v, want member -> admin", data)
	}
}

func TestMemberRemovedEnvelope(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	accountID, userID, _ := tenancyTestIDs()

	e, err := NewMemberRemoved(now, accountID, userID, "owner")
	if err != nil {
		t.Fatalf("NewMemberRemoved: %v", err)
	}

	if err := e.Validate(); err != nil {
		t.Fatalf("the envelope does not satisfy core's schema: %v", err)
	}
	if e.Subject != accountID.String() {
		t.Errorf("subject = %q, want the account id", e.Subject)
	}

	// The removed role travels because "who was removed" is not the interesting
	// question downstream; "what could they do until now" is.
	var data struct {
		AccountID string `json:"account_id"`
		UserID    string `json:"user_id"`
		Role      string `json:"role"`
	}
	decodeData(t, e, &data)

	if data.UserID != userID.String() || data.Role != "owner" {
		t.Errorf("payload = %+v, want the role that was held", data)
	}
}

// Every tenancy event is three segments with the service prefix, which is the
// form core froze in v0.2. A constant that lost its prefix would still pass
// Validate's pattern — it allows two or three segments — so the shape is pinned
// here rather than inferred.
func TestTenancyEventTypesAreThreeSegment(t *testing.T) {
	types := []string{
		EventAccountCreated,
		EventMemberInvited,
		EventMemberAccepted,
		EventMemberRoleChanged,
		EventMemberRemoved,
	}

	for _, typ := range types {
		t.Run(typ, func(t *testing.T) {
			segments := 0
			current := ""
			for _, r := range typ {
				if r == '.' {
					segments++
					current = ""
					continue
				}
				current += string(r)
			}
			if segments != 2 {
				t.Errorf("%q has %d dots, want exactly 2 (three segments)", typ, segments)
			}
			if got := typ[:len("identity.")]; got != "identity." {
				t.Errorf("%q does not start with the publishing service's name", typ)
			}
			if current == "" {
				t.Errorf("%q ends with a dot", typ)
			}
		})
	}
}

// Every type is distinct. Two constants sharing a value would mean two facts
// published under one name, which is the drift core's catalog check exists to
// catch and which no single test of any one event would notice.
func TestTenancyEventTypesAreDistinct(t *testing.T) {
	seen := map[string]string{}
	for name, typ := range map[string]string{
		"account.created":     EventAccountCreated,
		"member.invited":      EventMemberInvited,
		"member.accepted":     EventMemberAccepted,
		"member.role_changed": EventMemberRoleChanged,
		"member.removed":      EventMemberRemoved,
	} {
		if previous, clash := seen[typ]; clash {
			t.Errorf("%q and %q are both %q", previous, name, typ)
		}
		seen[typ] = name
	}
}

// The five types are declared here and in cafaye.yml. Those are the same fact
// stated twice and core asserts they agree, so a type that exists in one and
// not the other is drift this repository is not allowed to ship.
func TestTenancyEventTypesMatchTheManifest(t *testing.T) {
	// The manifest is not read at run time — it lives in the repository root and
	// this is an internal package. What is pinned here is the set, and
	// TestManifestDeclaresEveryEmittedEvent in the httpapi package's tests is
	// where the two are actually compared.
	want := map[string]bool{
		EventAccountCreated:    true,
		EventMemberInvited:     true,
		EventMemberAccepted:    true,
		EventMemberRoleChanged: true,
		EventMemberRemoved:     true,
	}
	if len(want) != 5 {
		t.Fatalf("the expected set has %d entries, want 5", len(want))
	}
}

func decodeData(t *testing.T, e Envelope, into any) {
	t.Helper()

	if err := json.Unmarshal(e.Data, into); err != nil {
		t.Fatalf("the payload is not the object the test expects: %v\n%s", err, e.Data)
	}
}
