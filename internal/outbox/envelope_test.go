package outbox

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/platform/id"
)

// Every assertion here is traceable to a rule in
// cafaye/core/schemas/event-envelope.schema.json. That file is the contract; this
// test is the service's half of keeping to it.

func TestEnvelopeValidatesAgainstCoreSchema(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		give    Envelope
		wantErr string
	}{
		{
			name: "a well-formed envelope",
			give: Envelope{
				SpecVersion: SpecVersion,
				ID:          id.MustNew(),
				Type:        EventUserCreated,
				Source:      SourceIdentity,
				Subject:     "usr_01J9Z8QK5M4N7P2R3T6V8W9X0A",
				Time:        time.Date(2026, 9, 30, 4, 19, 0, 0, time.UTC),
				Data:        json.RawMessage(`{"user_id":"usr_01J9Z8QK5M4N7P2R3T6V8W9X0A"}`),
			},
		},
		{
			// core: required is ["specversion","id","type","source","time","data"]
			name: "a wrong specversion",
			give: Envelope{SpecVersion: "0.9", ID: id.MustNew(), Type: EventUserCreated, Source: SourceIdentity,
				Subject: "usr_1", Time: time.Now().UTC(), Data: json.RawMessage(`{}`)},
			wantErr: "specversion",
		},
		{
			name: "a missing id",
			give: Envelope{SpecVersion: SpecVersion, Type: EventUserCreated, Source: SourceIdentity,
				Subject: "usr_1", Time: time.Now().UTC(), Data: json.RawMessage(`{}`)},
			wantErr: "id",
		},
		{
			name: "the nil id",
			give: Envelope{SpecVersion: SpecVersion, ID: id.UUID{}, Type: EventUserCreated, Source: SourceIdentity,
				Subject: "usr_1", Time: time.Now().UTC(), Data: json.RawMessage(`{}`)},
			wantErr: "id",
		},
		{
			// core $defs.eventType: ^[a-z][a-z0-9]*(_[a-z0-9]+)*(\.…){1,2}$
			name: "an upper-case segment",
			give: Envelope{SpecVersion: SpecVersion, ID: id.MustNew(), Type: "identity.User.created", Source: SourceIdentity,
				Subject: "usr_1", Time: time.Now().UTC(), Data: json.RawMessage(`{}`)},
			wantErr: "type",
		},
		{
			name: "camelCase is not snake_case",
			give: Envelope{SpecVersion: SpecVersion, ID: id.MustNew(), Type: "identity.userCreated", Source: SourceIdentity,
				Subject: "usr_1", Time: time.Now().UTC(), Data: json.RawMessage(`{}`)},
			wantErr: "type",
		},
		{
			// core's grammar allows two or three segments. One is not a type.
			name: "a single segment",
			give: Envelope{SpecVersion: SpecVersion, ID: id.MustNew(), Type: "created", Source: SourceIdentity,
				Subject: "usr_1", Time: time.Now().UTC(), Data: json.RawMessage(`{}`)},
			wantErr: "type",
		},
		{
			// Four segments: core's invalid example asserts exactly this.
			name: "four segments",
			give: Envelope{SpecVersion: SpecVersion, ID: id.MustNew(), Type: "a.b.c.d", Source: SourceIdentity,
				Subject: "usr_1", Time: time.Now().UTC(), Data: json.RawMessage(`{}`)},
			wantErr: "type",
		},
		{
			// core $defs.serviceName: ^[a-z][a-z0-9]*(-[a-z0-9]+)*$
			name: "an upper-case source",
			give: Envelope{SpecVersion: SpecVersion, ID: id.MustNew(), Type: EventUserCreated, Source: "Identity",
				Subject: "usr_1", Time: time.Now().UTC(), Data: json.RawMessage(`{}`)},
			wantErr: "source",
		},
		{
			name: "a source with an underscore",
			give: Envelope{SpecVersion: SpecVersion, ID: id.MustNew(), Type: EventUserCreated, Source: "my_service",
				Subject: "usr_1", Time: time.Now().UTC(), Data: json.RawMessage(`{}`)},
			wantErr: "source",
		},
		{
			// core's `required` is ["specversion","id","type","source","time","data"]
			// — subject is not on it, and the schema describes a literal
			// `platform` subject for events with no single entity. An empty
			// subject serializes as absent (omitempty), which core accepts.
			// TestEnvelopeOmitsAnEmptySubject pins that it is really absent and
			// not sent as "".
			name: "an empty subject means no single entity",
			give: Envelope{SpecVersion: SpecVersion, ID: id.MustNew(), Type: EventUserCreated, Source: SourceIdentity,
				Subject: "", Time: time.Now().UTC(), Data: json.RawMessage(`{}`)},
		},
		{
			// The literal escape hatch core's docs describe (D2).
			name: "the platform subject",
			give: Envelope{SpecVersion: SpecVersion, ID: id.MustNew(), Type: EventUserCreated, Source: SourceIdentity,
				Subject: "platform", Time: time.Now().UTC(), Data: json.RawMessage(`{}`)},
		},
		{
			name: "an over-long subject",
			give: Envelope{SpecVersion: SpecVersion, ID: id.MustNew(), Type: EventUserCreated, Source: SourceIdentity,
				Subject: strings.Repeat("u", 201), Time: time.Now().UTC(), Data: json.RawMessage(`{}`)},
			wantErr: "subject",
		},
		{
			// core subject pattern: ^[A-Za-z0-9][A-Za-z0-9._:@/-]*$
			name: "a subject containing a space",
			give: Envelope{SpecVersion: SpecVersion, ID: id.MustNew(), Type: EventUserCreated, Source: SourceIdentity,
				Subject: "usr 1", Time: time.Now().UTC(), Data: json.RawMessage(`{}`)},
			wantErr: "subject",
		},
		{
			name: "a zero time",
			give: Envelope{SpecVersion: SpecVersion, ID: id.MustNew(), Type: EventUserCreated, Source: SourceIdentity,
				Subject: "usr_1", Time: time.Time{}, Data: json.RawMessage(`{}`)},
			wantErr: "time",
		},
		{
			name: "absent data",
			give: Envelope{SpecVersion: SpecVersion, ID: id.MustNew(), Type: EventUserCreated, Source: SourceIdentity,
				Subject: "usr_1", Time: time.Now().UTC()},
			wantErr: "data",
		},
		{
			// core's data is opaque and may be any JSON value including null —
			// but the key must be present, so a missing one is not a null one.
			name: "data that is not JSON at all",
			give: Envelope{SpecVersion: SpecVersion, ID: id.MustNew(), Type: EventUserCreated, Source: SourceIdentity,
				Subject: "usr_1", Time: time.Now().UTC(), Data: json.RawMessage(`{broken`)},
			wantErr: "data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.give.Validate()

			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want an error about %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Validate() = %v, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

func TestEnvelopeMarshalsToExactlyTheCoreAttributeSet(t *testing.T) {
	t.Parallel()

	e := Envelope{
		SpecVersion: SpecVersion,
		ID:          id.MustNew(),
		Type:        EventUserCreated,
		Source:      SourceIdentity,
		Subject:     "usr_01J9Z8QK5M4N7P2R3T6V8W9X0A",
		Time:        time.Date(2026, 9, 30, 4, 19, 0, 0, time.UTC),
		Data:        json.RawMessage(`{"user_id":"usr_1","email":"kaka@example.com"}`),
	}

	encoded, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	// core sets additionalProperties:false. An extra attribute is rejected by
	// every consumer, so the Go struct must not emit one.
	want := map[string]bool{
		"specversion": true, "id": true, "type": true,
		"source": true, "subject": true, "time": true, "data": true,
	}
	for name := range decoded {
		if !want[name] {
			t.Errorf("envelope carries %q, which core's schema does not define", name)
		}
		delete(want, name)
	}
	for name := range want {
		t.Errorf("envelope is missing %q", name)
	}

	if got := decoded["specversion"]; got != "1.0" {
		t.Errorf("specversion = %v, want \"1.0\"", got)
	}
	// RFC3339, UTC, second-or-finer precision — core declares format: date-time.
	if got := decoded["time"]; got != "2026-09-30T04:19:00Z" {
		t.Errorf("time = %v, want 2026-09-30T04:19:00Z", got)
	}
	// data is opaque to core, so it must round-trip as the object it was, not as
	// a re-encoded string.
	data, ok := decoded["data"].(map[string]any)
	if !ok {
		t.Fatalf("data = %#v, want a JSON object", decoded["data"])
	}
	if data["email"] != "kaka@example.com" {
		t.Errorf("data.email = %v, want kaka@example.com", data["email"])
	}
}

// The subject is optional in core's `required` list but the catalog and
// docs/event-naming.md (D2) treat it as required for entity events. The
// registration event has a user, so it always has one; the field is omitted from
// the wire only when empty, because core rejects an empty string.
func TestEnvelopeOmitsAnEmptySubject(t *testing.T) {
	t.Parallel()

	e := Envelope{
		SpecVersion: SpecVersion, ID: id.MustNew(), Type: EventUserCreated, Source: SourceIdentity,
		Time: time.Now().UTC(), Data: json.RawMessage(`{}`),
	}

	encoded, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(encoded), "subject") {
		t.Errorf("envelope %s carries an empty subject; core's pattern requires minLength 1", encoded)
	}
}

func TestUserCreatedEnvelope(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 30, 4, 19, 0, 0, time.UTC)
	userID := id.MustNew()

	e, err := NewUserCreated(now, userID, "kaka@example.com")
	if err != nil {
		t.Fatalf("NewUserCreated: %v", err)
	}

	if err := e.Validate(); err != nil {
		t.Errorf("the envelope this service builds does not satisfy its own contract: %v", err)
	}
	if e.Type != EventUserCreated {
		t.Errorf("Type = %q, want %q", e.Type, EventUserCreated)
	}
	if e.Source != SourceIdentity {
		t.Errorf("Source = %q, want %q — it must equal `name` in cafaye.yml", e.Source, SourceIdentity)
	}
	// Subject is the entity the event is *about*, not the actor.
	if e.Subject != userID.String() {
		t.Errorf("Subject = %q, want the user id %q", e.Subject, userID)
	}
	if !e.Time.Equal(now) {
		t.Errorf("Time = %s, want %s — it is the state change, not the publish", e.Time, now)
	}
	if e.ID.IsZero() {
		t.Error("ID is zero; consumers deduplicate on it")
	}

	encoded, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded struct {
		Data struct {
			UserID string `json:"user_id"`
			Email  string `json:"email"`
		} `json:"data"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded.Data.UserID != userID.String() {
		t.Errorf("data.user_id = %q, want %q", decoded.Data.UserID, userID)
	}
	if decoded.Data.Email != "kaka@example.com" {
		t.Errorf("data.email = %q, want kaka@example.com", decoded.Data.Email)
	}
}

// Two registrations of different users must produce different envelope ids, and
// the ids are the consumers' dedupe key. A shared id would make courier silently
// drop the second user.
func TestNewUserCreatedIsUniquePerCall(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()

	first, err := NewUserCreated(now, id.MustNew(), "a@example.com")
	if err != nil {
		t.Fatalf("NewUserCreated: %v", err)
	}
	second, err := NewUserCreated(now, id.MustNew(), "b@example.com")
	if err != nil {
		t.Fatalf("NewUserCreated: %v", err)
	}

	if first.ID == second.ID {
		t.Error("two registrations produced the same envelope id")
	}
}

// The serialized payload is stored verbatim in outbox_events.payload, so its
// shape is worth pinning: a consumer parsing `data` should not have to cope with
// a field appearing, disappearing or moving.
func TestUserCreatedDataIsStable(t *testing.T) {
	t.Parallel()

	userID := id.MustNew()

	e, err := NewUserCreated(time.Now().UTC(), userID, "kaka@example.com")
	if err != nil {
		t.Fatalf("NewUserCreated: %v", err)
	}

	want := `{"user_id":"` + userID.String() + `","email":"kaka@example.com"}`
	if got := string(e.Data); got != want {
		t.Errorf("Data = %s, want %s", got, want)
	}
}
