package outbox

import (
	"time"

	"github.com/cafaye/identity/internal/platform/id"
)

// The OIDC events: a relying party registered itself, and one was revoked.
//
// The entity is `oidc_client` and not `client`, even though the table is called
// oidc_clients. A bare `client` is exactly the kind of generic name core's rule
// 2 exists to push a prefix onto — but the prefix here is the SERVICE, not a
// disambiguator, so the spelling is `identity.oidc_client.created` and not
// `identity.client.created`. The service is the only thing on the platform that
// issues OIDC registrations, and saying so in the name is free.
//
// core's catalog has no row for either type yet. core is a different repository
// and this packet does not touch it, so the reconciliation is the one
// EventMemberAccepted already documents: the publisher entry in cafaye.yml and
// the code here agree, and core's catalog gains the rows when the manager merges
// them.

// The event types this service publishes for OIDC client registrations.
const (
	// EventOIDCClientCreated is emitted when a product registers itself as an
	// OpenID Connect relying party.
	EventOIDCClientCreated = "identity.oidc_client.created"

	// EventOIDCClientRevoked is emitted when a registration stops being honoured.
	// The row is kept rather than deleted: an audit of which credentials existed
	// is worth more than a tidier table, and `revoked_at` is what makes the
	// difference readable afterwards.
	EventOIDCClientRevoked = "identity.oidc_client.revoked"
)

// NewOIDCClientCreated builds the event emitted when a client is registered.
//
// The redirect URIs, the grant types and the scopes are all in the payload
// because the registration's whole content is "this credential may now be
// delivered to these origins, for these capabilities". A consumer auditing who
// holds a credential into a product cannot answer that from the bare fact that
// a client exists.
//
// There is no secret here, and no digest of one. The raw client secret exists
// exactly once, in the 201 response to whoever registered it; the row holds a
// SHA-256 digest, and a digest of a 256-bit random value is of no use to anyone.
// Every event on the platform reaches every subscriber, which is exactly the
// wrong place for a credential.
//
// rowID is the row's own uuid and the event's subject; clientID is the
// `client_id` string the relying party will present at the token endpoint. They
// are different values and conflating them is how a consumer ends up correlating
// on something it cannot look up.
func NewOIDCClientCreated(
	now time.Time,
	rowID, accountID id.UUID,
	clientID string,
	redirectURIs, grantTypes, scopes []string,
	registeredBy id.UUID,
) (Envelope, error) {
	return newSubjectEvent(now, EventOIDCClientCreated, rowID.String(), struct {
		ClientID     string   `json:"client_id"`
		AccountID    string   `json:"account_id"`
		RedirectURIs []string `json:"redirect_uris"`
		GrantTypes   []string `json:"grant_types"`
		Scopes       []string `json:"scopes"`
		RegisteredBy string   `json:"registered_by"`
	}{
		ClientID:     clientID,
		AccountID:    accountID.String(),
		RedirectURIs: redirectURIs,
		GrantTypes:   grantTypes,
		Scopes:       scopes,
		RegisteredBy: registeredBy.String(),
	})
}

// NewOIDCClientRevoked builds the event emitted when a registration is revoked.
//
// It carries no reason. A reason is operator-facing context typed by a human at
// a call site, it is not a fact about the credential, and a field whose values
// vary per operator is a field every consumer learns to ignore.
func NewOIDCClientRevoked(now time.Time, rowID, accountID id.UUID, clientID string, revokedBy id.UUID) (Envelope, error) {
	return newSubjectEvent(now, EventOIDCClientRevoked, rowID.String(), struct {
		ClientID  string `json:"client_id"`
		AccountID string `json:"account_id"`
		RevokedBy string `json:"revoked_by"`
	}{
		ClientID:  clientID,
		AccountID: accountID.String(),
		RevokedBy: revokedBy.String(),
	})
}
