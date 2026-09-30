// Package accounts owns tenancy: the account, the memberships that give a user
// a role in it, and the invitations that create new memberships.
//
// It is the package that answers "may this user do this thing in this account",
// and it answers it from one idea: a membership is a single role, and the roles
// form a total order — member < admin < owner. That is what makes
// RequireAccountRole(min) a comparison rather than a lookup, and it is why the
// packet calls the minimum a minimum.
//
// PLAN.md §7 records that OpenFGA is deferred and that this service hand-rolls
// "Jumpstart-level RBAC (owner/admin/member) with OpenFGA-compatible semantics".
// A single ordered role is exactly that: a relation between a user and an account
// whose name is the set of things they may do there. The migration path is to
// replace AtLeast with a ReBAC check behind the same signature.
//
// Nothing here knows about HTTP. Handlers translate the errors below into the
// cafaye error envelope; they do not define the rules.
package accounts

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cafaye/identity/internal/platform/id"
)

// Errors the store, the service and the validators return. Callers match them
// with errors.Is; nothing here is compared by string.
var (
	// ErrNotFound means the account, membership or invitation is not there — or,
	// for a lookup scoped to a caller, is not *visible* to that caller.
	//
	// Those are deliberately one error. A caller who is not a member of an
	// account learns nothing about whether it exists, which is core's rule: "403
	// is not allowed to leak existence" (docs/openapi-conventions.md). The
	// authorization layer turns a membership miss into 404 for the same reason a
	// wrong password is a 401.
	ErrNotFound = errors.New("account not found")

	// ErrNotAMember means the caller is authenticated and the account exists, but
	// holds no membership in it. It is separate from ErrNotFound precisely so the
	// HTTP layer can decide which of the two to say out loud; see
	// RequireAccountRole.
	ErrNotAMember = errors.New("caller is not a member of this account")

	// ErrSlugTaken means the derived slug is already in use. Registration and
	// account creation map it to 409.
	ErrSlugTaken = errors.New("account slug already in use")

	// ErrAlreadyAMember means the user is already in the account. It is what an
	// invitation for someone who has since accepted another one produces, and it
	// is a 409 rather than a silent no-op: the caller's intent was to add a
	// membership and the state they asked for already holds.
	ErrAlreadyAMember = errors.New("user is already a member of this account")

	// ErrInvitationNotFound means no pending invitation matches. It covers a
	// wrong token, an unknown token and a malformed one identically.
	ErrInvitationNotFound = errors.New("invitation not found")

	// ErrInvitationExpired means the invitation existed and its window has
	// closed. It is distinct from ErrInvitationNotFound because the caller can
	// act on it — ask for a new one — and core's 410 is exactly "the old surface
	// is gone, here is what replaced it".
	ErrInvitationExpired = errors.New("invitation has expired")

	// ErrInvitationUsed means the invitation was already accepted. Same status as
	// expired and the same reasoning: it is not redeemable any more.
	ErrInvitationUsed = errors.New("invitation has already been accepted")

	// ErrInvitationRevoked means the invitation was withdrawn by an admin before
	// it was redeemed.
	//
	// IT IS DISTINCT FROM ErrInvitationUsed even though both mean "not
	// redeemable any more", and the difference is what an operator needs: a used
	// invitation became a membership, and the question "where is the membership
	// this link created?" is a support question. A revoked one never became
	// anything, and the question is "who withdrew it and when" — which the
	// account's audit trail answers, and which is the entire reason the admin
	// surface that produces this error writes a row when it does.
	ErrInvitationRevoked = errors.New("invitation has been revoked")

	// ErrInvitationEmailTaken means this account already has a pending
	// invitation for that address. Answering 409 rather than minting a second
	// token stops an admin from filling the table with invitations that all say
	// the same thing.
	ErrInvitationEmailTaken = errors.New("an invitation for that email is already pending")

	// ErrLastOwner is returned by a role change or a removal that would leave the
	// account with no owner. It is a 422: the request was understood, is
	// syntactically fine, and describes a state the account cannot be left in.
	ErrLastOwner = errors.New("an account must keep at least one owner")

	// ErrOwnerProtected is returned when a caller who is not an owner tries to
	// remove one. An admin may remove members and other admins; the owner's
	// membership is a different object, and only an owner touches it.
	ErrOwnerProtected = errors.New("only an owner may remove an owner")

	// ErrRoleNotInvitable is returned when a role outside {admin, member} is
	// asked of an invitation. Ownership is granted, never invited: an account
	// whose owner appears by accepting a link has an owner nobody chose.
	ErrRoleNotInvitable = errors.New("an invitation may only carry the admin or member role")

	// ErrSelfRoleChange is returned when an owner tries to change their own role
	// when they are the only one. It is the same invariant as ErrLastOwner, given
	// its own name because the packet names it and a client should be able to
	// tell the two apart.
	ErrSelfRoleChange = errors.New("the only owner of an account cannot change their own role")
)

// Field validation codes. These land verbatim in the `errors[]` array of the
// cafaye error envelope, so they are part of the contract and clients may switch
// on them.
const (
	CodeRequired      = "required"
	CodeInvalidFormat = "invalid_format"
	CodeTooLong       = "too_long"
	CodeUnknownRole   = "unknown_role"
)

// MaxNameLength bounds accounts.name. It is also the upper bound on the bytes
// that reach the name column; 120 is generous for a workspace name and small
// enough that an account list is not a payload.
const MaxNameLength = 120

// MaxSlugLength is 63, the length of a single DNS label. A slug is chosen here so
// that a later packet can put one in a hostname without a second normalisation
// pass, and the accounts table's CHECK enforces the same bound.
const MaxSlugLength = 63

// FieldError is a per-field validation failure. It is structurally the same type
// as users.FieldError and deliberately a separate declaration: the two packages
// do not depend on each other, and a shared type would be the first edge between
// them.
type FieldError struct {
	Field string
	Code  string
}

func (e *FieldError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Code)
}

func fieldErr(field, code string) error {
	return &FieldError{Field: field, Code: code}
}

// Role is a membership's authority in an account.
//
// It is a string rather than an integer because it is a wire and a database
// value: it appears in the account_users.role enum, in request bodies, in
// responses, and in the `identity.member.*` event payloads. The ordering lives
// in the declaration order of AllRoles, not in the numeric value of the type, so
// that reordering the constants cannot silently invert the hierarchy.
type Role string

const (
	// RoleMember may read the account and nothing else.
	RoleMember Role = "member"
	// RoleAdmin may also rename the account, invite members, and remove members.
	RoleAdmin Role = "admin"
	// RoleOwner may additionally change roles, invite admins, and delete the
	// account.
	RoleOwner Role = "owner"
)

// AllRoles is every role, weakest first.
//
// The order is the whole point: AtLeast walks it, and the tests assert it
// explicitly so a future role cannot be appended in the wrong place.
func AllRoles() []Role {
	return []Role{RoleMember, RoleAdmin, RoleOwner}
}

// AtLeast reports whether the role is at or above the minimum.
//
// This is the single comparison behind every authorization decision in the
// service, and it is deliberately a total order rather than a set of booleans. A
// set (Jumpstart's `store_accessor :roles` with admin?/owner? predicates) means
// "owner but not admin" is expressible, and then every check has to decide what
// that combination is allowed to do. A total order means the question has one
// answer, which is what makes the authorization matrix writable as a table.
//
// An unknown role is below everything. A row in the database with a role this
// build does not know about must fail closed — a future role added by a later
// migration should never be readable as "and so anything goes" here.
func (r Role) AtLeast(min Role) bool {
	return r.rank() >= min.rank()
}

func (r Role) rank() int {
	switch r {
	case RoleMember:
		return 1
	case RoleAdmin:
		return 2
	case RoleOwner:
		return 3
	default:
		return 0
	}
}

// Valid reports whether the role is one this build knows.
func (r Role) Valid() bool { return r.rank() > 0 }

// String makes Role print as its wire value in a log line and a test failure.
func (r Role) String() string { return string(r) }

// ParseRole reads a role from a request body.
//
// It is exact: no case folding, no trimming, no partial match. A role arrives
// from a client and is compared against an enum in the database, and a parser
// that quietly repaired its argument would make "Admin" and "admin" two
// different answers to the same question depending on who asked.
func ParseRole(s string) (Role, error) {
	role := Role(s)
	if !role.Valid() {
		return "", fieldErr("role", CodeUnknownRole)
	}
	return role, nil
}

// InvitableRoles is the set of roles an invitation may carry. It is
// {admin, member} and deliberately excludes owner — see ErrRoleNotInvitable.
func InvitableRoles() []Role {
	return []Role{RoleMember, RoleAdmin}
}

// Invitable reports whether a role may arrive on an invitation.
func (r Role) Invitable() bool {
	return r == RoleAdmin || r == RoleMember
}

// ParseInvitableRole reads an invitation's role, refusing owner.
//
// It is a separate function from ParseRole rather than a flag on it, because the
// two have different failure meanings: an unknown string is a typo (422) and
// "owner" is a well-formed request for something that does not exist.
func ParseInvitableRole(s string) (Role, error) {
	role, err := ParseRole(s)
	if err != nil {
		return "", err
	}
	if !role.Invitable() {
		return "", ErrRoleNotInvitable
	}
	return role, nil
}

// Account is a row in the accounts table.
type Account struct {
	ID id.UUID
	// Name is what a human sees. Personal accounts are named after the email's
	// local part; team accounts are named by whoever creates them.
	Name string
	// Slug is derived from Name at creation and never changes. It is a stable
	// handle for logs, emails and a future hostname, which is why a rename does
	// not re-derive it: a slug that moved would break every link already sent.
	Slug string
	// Personal marks the account a registration creates for its user. Personal
	// accounts are created by the system rather than by a request, and the
	// distinction is what lets a later packet say "you always have exactly one
	// personal account" without a second table.
	Personal  bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Membership is a row in the account_users table: a user's role in an account.
type Membership struct {
	AccountID id.UUID
	UserID    id.UUID
	Role      Role
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Invitation is a row in the account_invitations table.
//
// TokenDigest is the stored credential and Token is not a field at all: the raw
// token exists exactly once, in the response to the create call, and there is no
// column and no field that could hold it later. The same shape as
// sessions.NewSession, for the same reason.
type Invitation struct {
	ID          id.UUID
	AccountID   id.UUID
	Email       string
	Role        Role
	TokenDigest string
	ExpiresAt   time.Time
	// AcceptedAt is nil until the invitation is redeemed. A pointer because
	// "never accepted" and "accepted at the epoch" are different answers and only
	// one of them is true.
	AcceptedAt *time.Time
	InvitedBy  id.UUID
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// Slugify turns a human name into a storable slug.
//
// The rules are: lower case, ASCII alphanumerics kept, every other run of
// characters becomes a single dash, leading and trailing dashes trimmed,
// truncated to MaxSlugLength on a dash boundary. Non-ASCII is *dropped* rather
// than transliterated, because a transliteration table is a large amount of
// surface for a name that only has to be unique and printable.
//
// The result may be empty (a name of "東京" has no ASCII in it). Callers turn
// that into a 422 rather than inventing a slug, and ValidateName is where that
// check lives.
func Slugify(name string) string {
	var b strings.Builder
	b.Grow(len(name))

	dash := false
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			dash = false
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			dash = false
			b.WriteRune(r - ('A' - 'a'))
		default:
			// Everything else — space, punctuation, non-ASCII, control characters
			// — is a separator. A pending dash is left to the next alphanumeric so
			// that a run of them collapses to one.
			dash = b.Len() > 0
		}
	}

	return truncateSlug(b.String())
}

// truncateSlug cuts s to MaxSlugLength and then drops any dash the cut left
// dangling, so a truncated slug still satisfies the table's CHECK.
func truncateSlug(s string) string {
	if len(s) <= MaxSlugLength {
		return s
	}
	return strings.TrimRight(s[:MaxSlugLength], "-")
}

// PersonalName is the name a registration gives the account it creates: the
// email's local part.
//
// The local part and not the whole address, because an account name shows up in
// a list, a log line and eventually a UI, and "kaka" is a name while
// "kaka@example.com" is a credential. A local part with nothing sluggable in it
// falls back to the address, which is always at least as long as the account's
// own id suffix.
func PersonalName(email string) string {
	local, _, found := strings.Cut(email, "@")
	if !found || local == "" {
		return email
	}
	return local
}

// PersonalSlug is the slug of a registration's personal account.
//
// The local part alone is not enough: two people can both be kaka@example.com
// and kaka@other.com, and the second registration would be a 409 on a table the
// human never knew they were competing for. So the user id is folded in — the
// first eight hex characters, which is 32 bits of a v4 UUID, enough to separate
// two people and short enough to read.
//
// It is deterministic. A retried registration re-derives the same slug, so a
// unique violation means the slug really is taken rather than that the code
// rolled a die twice and lost.
func PersonalSlug(email string, userID id.UUID) string {
	base := Slugify(PersonalName(email))
	if base == "" {
		base = "account"
	}

	var hexID [8]byte
	copy(hexID[:], userID[:4])
	suffix := hex.EncodeToString(hexID[:])

	// The suffix is nine characters including the dash, so the base has to make
	// room for it or the result would be cut and two long names could collide on
	// the same truncated prefix.
	room := MaxSlugLength - len(suffix) - 1
	if room < 1 {
		room = 1
	}
	base = truncateSlug(base)
	if len(base) > room {
		base = strings.TrimRight(base[:room], "-")
	}
	if base == "" {
		return suffix
	}
	return base + "-" + suffix
}

// ValidateName checks a caller-supplied account name.
//
// The rules are the length bound and the requirement that the name has something
// sluggable in it. The second rule is not cosmetic: a name that slugifies to
// nothing has no slug, and a slug is NOT NULL and unique, so accepting one turns
// a 422 into a 500.
//
// A name that is empty or all whitespace is `required` rather than
// `invalid_format`, and the two are kept apart because they mean different things
// to the person filling in the form: one is "you left it blank", the other is
// "we cannot make a slug out of this". NormalizeName trims before this is called,
// so a blank name is normally already "" — the whitespace case is handled anyway
// so a caller that forgets to normalize still gets the honest code.
func ValidateName(normalized string) error {
	switch {
	case strings.TrimSpace(normalized) == "":
		return fieldErr("name", CodeRequired)
	case len([]rune(normalized)) > MaxNameLength:
		return fieldErr("name", CodeTooLong)
	case Slugify(normalized) == "":
		return fieldErr("name", CodeInvalidFormat)
	}
	return nil
}

// NormalizeName trims a caller-supplied name. It does not collapse internal
// whitespace: "Acme  Corp" is a typo, and silently repairing it makes the stored
// name differ from what the caller chose.
func NormalizeName(name string) string {
	return strings.TrimSpace(name)
}
