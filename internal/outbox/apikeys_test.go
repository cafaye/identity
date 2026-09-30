package outbox

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/platform/id"
)

// The api key events: a scoped machine credential was issued, and it stopped
// working.
//
// These tests assert three things and the third is the one that matters: the
// envelope satisfies core's schema, the payload carries the GRANT (so a consumer
// can audit who holds what), and no field of it is a usable credential. The last
// is the same assertion TestOIDCEventsCarryNoClientSecret makes, and it is here
// because an api key is the longest-lived credential this service issues and the
// envelope is the widest pipe it goes down.

func TestAPIKeyEventsValidateAgainstCoreSchema(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 30, 4, 19, 0, 0, time.UTC)
	keyRow, account, owner := id.MustNew(), id.MustNew(), id.MustNew()

	tests := []struct {
		name string
		give func() (Envelope, error)
	}{
		{
			name: "a credential is issued",
			give: func() (Envelope, error) {
				return NewAPIKeyCreated(now, keyRow, account, owner, "ci-deploy",
					[]string{"accounts:read"}, now.AddDate(0, 3, 0))
			},
		},
		{
			name: "a credential is withdrawn",
			give: func() (Envelope, error) {
				return NewAPIKeyRevoked(now, keyRow, account, owner)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := tt.give()
			if err != nil {
				t.Fatalf("building the envelope: %v", err)
			}
			if err := got.Validate(); err != nil {
				t.Errorf("the envelope does not satisfy core's schema: %v", err)
			}
			if got.Source != SourceIdentity {
				t.Errorf("source = %q, want %q", got.Source, SourceIdentity)
			}
			// core's catalog names both types, and the prefix check is what would
			// catch a typo in either constant that still satisfies the schema.
			if !strings.HasPrefix(got.Type, SourceIdentity+".api_key.") {
				t.Errorf("type = %q, want the %q prefix on a catalog name", got.Type, SourceIdentity)
			}
			if got.Subject != keyRow.String() {
				t.Errorf("subject = %q, want the key's own row id %q", got.Subject, keyRow)
			}
			if !got.Time.Equal(now) {
				t.Errorf("time = %s, want the injected instant %s", got.Time, now)
			}
		})
	}
}

// The event types are core's published vocabulary, and this asserts the two
// strings rather than trusting a comment in apikeys.go about them.
func TestAPIKeyEventTypesAreCoreNames(t *testing.T) {
	t.Parallel()

	for _, want := range []string{"identity.api_key.created", "identity.api_key.revoked"} {
		switch want {
		case EventAPIKeyCreated, EventAPIKeyRevoked:
		default:
			t.Errorf("no event constant publishes core's %q", want)
		}
	}
}

// The created payload is the grant. A consumer auditing "who holds a credential
// into which account, for what" cannot answer that from an announcement that
// carries ids and nothing else, so the name and the scopes are in here and this
// test is what holds them there.
func TestAPIKeyCreatedPayloadIsTheGrant(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 30, 4, 19, 0, 0, time.UTC)
	keyRow, account, owner := id.MustNew(), id.MustNew(), id.MustNew()
	expires := now.AddDate(0, 3, 0)
	scopes := []string{"accounts:read", "accounts:write"}

	e, err := NewAPIKeyCreated(now, keyRow, account, owner, "ci-deploy", scopes, expires)
	if err != nil {
		t.Fatalf("building the envelope: %v", err)
	}

	var data struct {
		AccountID string   `json:"account_id"`
		UserID    string   `json:"user_id"`
		Name      string   `json:"name"`
		Scopes    []string `json:"scopes"`
		ExpiresAt string   `json:"expires_at"`
	}
	if err := json.Unmarshal(e.Data, &data); err != nil {
		t.Fatalf("the payload is not JSON: %v", err)
	}

	if data.AccountID != account.String() {
		t.Errorf("account_id = %q, want %q", data.AccountID, account)
	}
	if data.UserID != owner.String() {
		t.Errorf("user_id = %q, want %q", data.UserID, owner)
	}
	if data.Name != "ci-deploy" {
		t.Errorf("name = %q, want ci-deploy; it is the only handle a human can revoke by", data.Name)
	}
	if len(data.Scopes) != len(scopes) {
		t.Fatalf("scopes = %v, want %v; the scopes are the entire content of the grant", data.Scopes, scopes)
	}
	for i, want := range scopes {
		if data.Scopes[i] != want {
			t.Errorf("scopes[%d] = %q, want %q", i, data.Scopes[i], want)
		}
	}
	// RFC 3339 in UTC, and not Go's default rendering: this string is read by
	// consumers in other languages and a nanosecond-precision Go timestamp is a
	// parsing bug waiting to happen.
	if data.ExpiresAt != "2026-12-30T04:19:00Z" {
		t.Errorf("expires_at = %q, want RFC 3339 in UTC", data.ExpiresAt)
	}
}

// NO EVENT CARRIES A USABLE CREDENTIAL. The envelope reaches every subscriber on
// the platform, the plaintext exists exactly once in the 201 body, and the row
// holds a SHA-256 of a 256-bit value which is not a credential either.
//
// The forbidden list includes the words as well as the values, because a log line
// or a payload that mentions "token_digest" is a pointer to where the sensitive
// column is, and a payload that grew a `digest` field to save somebody a join
// would be the regression this catches.
func TestAPIKeyEventsCarryNoCredential(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 30, 4, 19, 0, 0, time.UTC)
	keyRow, account, owner := id.MustNew(), id.MustNew(), id.MustNew()

	created, err := NewAPIKeyCreated(now, keyRow, account, owner, "ci-deploy",
		[]string{"accounts:read"}, now.AddDate(0, 3, 0))
	if err != nil {
		t.Fatalf("building the created envelope: %v", err)
	}
	revoked, err := NewAPIKeyRevoked(now, keyRow, account, owner)
	if err != nil {
		t.Fatalf("building the revoked envelope: %v", err)
	}

	for _, e := range []Envelope{created, revoked} {
		for _, forbidden := range []string{"token", "secret", "digest", "prefix", "cafaye_", "password"} {
			if strings.Contains(string(e.Data), forbidden) {
				t.Errorf("%s payload %s mentions %q", e.Type, e.Data, forbidden)
			}
		}
	}
}
