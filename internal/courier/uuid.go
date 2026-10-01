package courier

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/cafaye/identity/internal/platform/id"
)

// Two small things this package needs from a uuid, and neither of them is a
// dependency.
//
// The rule in AGENTS.md is that a package arrives with a stated cause and nothing
// else, and a uuid library for two functions would be a second answer to a
// question `internal/platform/id` already answers — including the wrong one the
// day the two disagree about which version a value is. So these use `id.UUID` and
// its `String()`, which is the canonical hyphenated form that courier's unique
// index and its `format: uuid` schema both mean.
//
// The reasons they exist at all are courier's own: "the header is a uuid because
// an unbounded string in a unique index is a cost every write pays."

// Errors the helpers below can return.
var (
	errNoResponse = errors.New("no response was read")

	errNotOK = errors.New("the response was not 200")
)

// newUUIDv4 mints a random uuid for an `Idempotency-Key` the caller did not supply.
//
// IT IS v4 AND NOT A DERIVATION, because the key's job when nothing else is known
// is to distinguish this request from every other one. `RecoveryMailer` supplies
// its own key where a derivation IS right, because it has a token to derive from —
// see `idempotencyKeyFor`.
func newUUIDv4() (string, error) {
	value, err := id.New()
	if err != nil {
		return "", fmt.Errorf("minting a uuid: %w", err)
	}
	return value.String(), nil
}

// idempotencyKeyFor derives a stable `Idempotency-Key` from the send it names.
//
// # THE THREE THINGS THAT GO IN, AND WHY EACH ONE IS THERE
//
//	(purpose, user_id, token)  ->  one uuid, every time
//
// `purpose` is the courier notification type the message maps to, which is the
// send's identity as courier understands it and a closed vocabulary of three
// values. `userID` is the account the message concerns, and `token` is the
// credential the message carries.
//
// THE TOKEN IS THE PART THAT MAKES THE KEY UNIQUE, and including the other two is
// what makes it IDENTIFY a send rather than merely differ from other keys: a
// derived key courier stores in a unique index should be answerable to "this
// reset, for this user, of this kind" by a reader who is not holding a reset
// token. It is a derivation rather than the token itself because the token is a
// LIVE CREDENTIAL and an `Idempotency-Key` is a header courier writes to its own
// logs and its own database — a credential in somebody else's store is a
// credential the next person to read it can redeem.
//
// # AND IT IS A DERIVATION AND NOT A FRESH RANDOM VALUE PER ATTEMPT
//
// A random key per call would make the header decorative, which is the exact
// failure `Idempotency-Key` exists to prevent: a user who double-clicks "send me
// a link" gets two reset mails, and the platform's suppression and preference
// rules are checked twice for one request. Stability is the whole feature — two
// calls for the same send produce the same key, so if the first attempt is
// replayed (by a retry, by an operator, by a proxy that duplicated the request)
// courier answers with the first response and sends ONE mail.
//
// # THE VERSION IS 8 AND NOT 5, DELIBERATELY
//
// RFC 9562 reserves 8 for a vendor-specific derivation, and a v5 name-based uuid
// carries a SHA-1 namespace construction whose collision properties nobody would
// choose for a key that must be unique across a fleet. The bytes are SHA-256
// truncated to 128 with the version and variant bits set as any uuid sets them,
// so the value is a well-formed uuid to anything that parses one — which is all
// courier does with it.
//
// THE FIELDS ARE SEPARATED BY A NUL so that no two different triples can produce
// the same input: "password_reset" + "ab" + "c" and "password_reset" + "a" + "bc"
// hash the same bytes otherwise, and a key that collides is a send that returns
// somebody else's stored response.
func idempotencyKeyFor(purpose, userID, token string) (string, error) {
	if token == "" {
		return "", errors.New("courier: refusing to derive an idempotency key from nothing")
	}
	digest := sha256.Sum256([]byte(idempotencyKeyDomain + "\x00" +
		purpose + "\x00" + userID + "\x00" + token))

	var value id.UUID
	copy(value[:], digest[:16])
	value[6] = (value[6] & 0x0f) | 0x80
	value[8] = (value[8] & 0x3f) | 0x80

	return value.String(), nil
}

// isUUID reports whether a value is a uuid in the shape courier accepts.
//
// IT IS `id.Parse` AND NOT A SHAPE CHECK WRITTEN HERE, because the rule that a
// `user_id` is a uuid is courier's document and identity's `users` table at the
// same time, and there is one implementation of that rule in this repository
// rather than two. `id.Parse` is stricter than a regex — it checks the version and
// the variant — and being stricter than courier is the safe direction: the worst
// outcome of a value this rejects and courier accepts is a message that was not
// needed.
func isUUID(value string) bool {
	if _, err := id.Parse(value); err != nil {
		return false
	}
	return true
}

// idempotencyKeyDomain is the domain separator, and it is a constant rather than an
// inline literal so a reader can see that it is a choice: the same token used for
// something else in this codebase must not produce the same key.
const idempotencyKeyDomain = "cafaye/identity/recovery/idempotency/v1"
