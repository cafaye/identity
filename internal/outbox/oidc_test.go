package outbox

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/platform/id"
)

// The OIDC events: a product registered itself as a relying party, and one was
// revoked.
//
// The subject is the OIDC client, not the account it was registered under and
// certainly not the human who registered it. core's rule is that the subject is
// "the entity the event is about, not the actor", and the entity here is the
// credential: a consumer that has to stop trusting a client correlates on the
// client, and a consumer watching an account's registrations correlates on the
// account. Both questions are real; this event answers the first.

func TestOIDCClientEventsValidateAgainstCoreSchema(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 30, 4, 19, 0, 0, time.UTC)
	clientRow := id.MustNew()
	account := id.MustNew()
	actor := id.MustNew()

	tests := []struct {
		name string
		give func() (Envelope, error)
	}{
		{
			name: "a client is registered",
			give: func() (Envelope, error) {
				return NewOIDCClientCreated(now, clientRow, account, "anytalk-web", []string{"https://app.anytalk.test/cb"},
					[]string{"authorization_code"}, []string{"openid", "email", "profile", "accounts"}, actor)
			},
		},
		{
			name: "a client is revoked",
			give: func() (Envelope, error) {
				return NewOIDCClientRevoked(now, clientRow, account, "anytalk-web", actor)
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
			if !strings.HasPrefix(got.Type, SourceIdentity+".") {
				t.Errorf("type = %q, want the %q prefix", got.Type, SourceIdentity)
			}
			if got.Subject != clientRow.String() {
				t.Errorf("subject = %q, want the client row id %q", got.Subject, clientRow)
			}
			if !got.Time.Equal(now) {
				t.Errorf("time = %s, want the injected instant %s", got.Time, now)
			}
		})
	}
}

func TestOIDCClientCreatedPayload(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 30, 4, 19, 0, 0, time.UTC)
	clientRow, account, actor := id.MustNew(), id.MustNew(), id.MustNew()
	redirects := []string{"https://app.anytalk.test/cb"}

	e, err := NewOIDCClientCreated(now, clientRow, account, "anytalk-web", redirects,
		[]string{"authorization_code"}, []string{"openid", "email"}, actor)
	if err != nil {
		t.Fatalf("building the envelope: %v", err)
	}

	var data struct {
		ClientID     string   `json:"client_id"`
		AccountID    string   `json:"account_id"`
		RedirectURIs []string `json:"redirect_uris"`
		Scopes       []string `json:"scopes"`
		GrantTypes   []string `json:"grant_types"`
		RegisteredBy string   `json:"registered_by"`
	}
	if err := json.Unmarshal(e.Data, &data); err != nil {
		t.Fatalf("the payload is not JSON: %v", err)
	}

	if data.ClientID != "anytalk-web" {
		t.Errorf("client_id = %q, want anytalk-web", data.ClientID)
	}
	if data.AccountID != account.String() {
		t.Errorf("account_id = %q, want %q", data.AccountID, account)
	}
	if data.RegisteredBy != actor.String() {
		t.Errorf("registered_by = %q, want %q", data.RegisteredBy, actor)
	}
	// The redirect list is in the payload because it is the fact a consumer
	// auditing trust needs: which origins this credential can be delivered to.
	if len(data.RedirectURIs) != 1 || data.RedirectURIs[0] != redirects[0] {
		t.Errorf("redirect_uris = %v, want %v", data.RedirectURIs, redirects)
	}
	if len(data.Scopes) != 2 || len(data.GrantTypes) != 1 {
		t.Errorf("scopes = %v, grant_types = %v; want the registered values", data.Scopes, data.GrantTypes)
	}
}

// No event on the platform carries a usable credential, so no OIDC event may
// carry the client secret. This is the assertion that keeps that true: the
// envelope goes to every subscriber, and the secret exists exactly once, in the
// 201 response to whoever registered the client.
func TestOIDCEventsCarryNoClientSecret(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 30, 4, 19, 0, 0, time.UTC)
	clientRow, account, actor := id.MustNew(), id.MustNew(), id.MustNew()

	created, err := NewOIDCClientCreated(now, clientRow, account, "anytalk-web",
		[]string{"https://app.anytalk.test/cb"}, []string{"authorization_code"}, []string{"openid"}, actor)
	if err != nil {
		t.Fatalf("building the created envelope: %v", err)
	}
	revoked, err := NewOIDCClientRevoked(now, clientRow, account, "anytalk-web", actor)
	if err != nil {
		t.Fatalf("building the revoked envelope: %v", err)
	}

	for _, e := range []Envelope{created, revoked} {
		for _, forbidden := range []string{"secret", "digest", "client_secret", "password"} {
			if strings.Contains(string(e.Data), forbidden) {
				t.Errorf("%s payload %s mentions %q", e.Type, e.Data, forbidden)
			}
		}
	}
}
