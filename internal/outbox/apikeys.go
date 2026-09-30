package outbox

import (
	"time"

	"github.com/cafaye/identity/internal/platform/id"
)

// The api key events: a scoped machine credential was issued, and it stopped
// working.
//
// BOTH NAMES ARE CORE'S AND ARE NOT A CHOICE. docs/event-naming.md carries a row
// for each — `identity.api_key.created` and `identity.api_key.revoked`, subject
// "the api key" — so this file is the publisher side of two rows another
// repository is writing the schema for. It is also the second piece of evidence
// for the table being named api_keys rather than api_tokens: the published
// vocabulary is the one thing in the schema another repository has already
// committed to, and a different table name would have meant asking core to change
// it.
//
// THE SUBJECT IS THE KEY'S OWN ROW ID, and that is a real choice rather than the
// tenancy package's "the account". Two accounts can each hold a credential, and a
// consumer that wants per-credential ordering — "this was revoked after that was
// created", which is the question a rotation asks — correlates on the credential.
// A consumer that wants per-tenant ordering correlates on data.account_id, which
// is in every payload for exactly that reason. The MFA events took the user for
// the same kind of reason and said so there.
//
// `identity.api_key.revoked` IS ALSO THE EVENT FOR AN EXPIRY, which is core's own
// wording — "A scoped API token is revoked or expired" — and this service has no
// sweeper, so nothing emits that second case yet. See README.md, "Not built yet".

// The event types this service publishes for scoped API tokens.
const (
	// EventAPIKeyCreated is emitted when a credential is minted.
	//
	// It fires for the first credential a user mints and for every rotation after
	// it, and both are the same fact: this account now holds a machine credential
	// with these capabilities. A consumer that wants to tell a first mint from a
	// rotation has the information it needs already — it has seen the earlier
	// event — which is information a field on this one would not add.
	EventAPIKeyCreated = "identity.api_key.created"

	// EventAPIKeyRevoked is emitted when a credential stops being honoured,
	// whether a person withdrew it or its window closed.
	EventAPIKeyRevoked = "identity.api_key.revoked"
)

// NewAPIKeyCreated builds the event emitted when a credential is issued.
//
// THE PAYLOAD IS THE GRANT, and it carries no secret — that is the whole
// discipline, and it is the same one NewOIDCClientCreated and NewMFAEnabled follow.
// Every event on the platform reaches every subscriber, which is exactly the wrong
// place for a credential, so:
//
//   - no `token`, because the plaintext exists exactly once, in the 201 body;
//   - no `token_digest`, which is not a secret either but is of no use to a
//     consumer and would be a second copy of the row's most sensitive column in a
//     store with a different retention policy;
//   - no `prefix`.
//
// It DOES carry the name and the scopes, and both are load-bearing rather than
// decorative. A consumer auditing "who holds a credential into which account, for
// what" cannot answer it from "a key exists": the scopes are the entire content of
// the grant, and the name is the only thing a human can revoke by. An event whose
// payload were just ids would be an announcement with nothing announced.
//
// The name is included even though the row has it, for the same reason clientID
// is in NewOIDCClientCreated alongside the row id: the id is how a consumer looks
// the row up and the string is what appears in the audit.
func NewAPIKeyCreated(
	now time.Time,
	rowID, accountID, userID id.UUID,
	name string,
	scopes []string,
	expiresAt time.Time,
) (Envelope, error) {
	return newSubjectEvent(now, EventAPIKeyCreated, rowID.String(), struct {
		AccountID string   `json:"account_id"`
		UserID    string   `json:"user_id"`
		Name      string   `json:"name"`
		Scopes    []string `json:"scopes"`
		ExpiresAt string   `json:"expires_at"`
	}{
		AccountID: accountID.String(),
		UserID:    userID.String(),
		Name:      name,
		Scopes:    scopes,
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339),
	})
}

// NewAPIKeyRevoked builds the event emitted when a credential is withdrawn.
//
// IT CARRIES NO REASON, and the omission is the same decision
// internal/oidc's NewOIDCClientRevoked makes. revoke_reason is a sentence an
// operator typed at a support call site; the set of values is open, it is not a
// fact about the credential, and a field whose values vary per operator is a field
// every consumer learns to ignore. It is kept on the row, where this service's own
// support reads it, which is a different consumer with a different need.
//
// It does not carry `last_used_at`, and the omission is worth one line: whether a
// withdrawn credential was in use is the single most useful thing an operator wants
// to know afterwards, and it is a join away on a row that still exists. Putting it
// on the event freezes one reading of it in a store with a different lifetime.
func NewAPIKeyRevoked(now time.Time, rowID, accountID, revokedBy id.UUID) (Envelope, error) {
	return newSubjectEvent(now, EventAPIKeyRevoked, rowID.String(), struct {
		AccountID string `json:"account_id"`
		RevokedBy string `json:"revoked_by"`
	}{
		AccountID: accountID.String(),
		RevokedBy: revokedBy.String(),
	})
}
