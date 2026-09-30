package accounts

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cafaye/identity/internal/outbox"
	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/users"
)

// The use cases. Everything a client can do to an account, a membership or an
// invitation, and the rules that govern each of them.
//
// It sits above the store because the interesting part of tenancy is not any one
// table — it is the ordering and the transactions. Creating an account writes
// three rows and an event; accepting an invitation creates a membership, marks
// the invitation and announces the membership, and any two of the three without
// the third is a bug rather than a state. Those are properties of the use case,
// not of a handler and not of a schema.
//
// NOTHING HERE KNOWS ABOUT HTTP. The handlers translate the errors below into
// the cafaye error envelope; they do not define the rules.

// UnitOfWork runs a function inside a transaction. db.TxRunner implements it;
// the interface is the seam that lets these rules be tested without Postgres.
type UnitOfWork interface {
	Do(ctx context.Context, fn func(ctx context.Context, q db.Querier) error) error
}

// AccountStore is the slice of Store the use cases need.
//
// It is declared here rather than taking *Store so a test can program a failure
// at the exact write that matters — a slug conflict, a pending invitation, a
// membership that is already there — without standing up a database.
type AccountStore interface {
	Create(ctx context.Context, q db.Querier, p CreateParams) (Account, error)
	ByID(ctx context.Context, q db.Querier, id id.UUID) (Account, error)
	Rename(ctx context.Context, q db.Querier, id id.UUID, name string) (Account, error)
	Delete(ctx context.Context, q db.Querier, id id.UUID) error
	AddMember(ctx context.Context, q db.Querier, m Membership) (Membership, error)
	Member(ctx context.Context, q db.Querier, accountID, userID id.UUID) (Membership, error)
	Members(ctx context.Context, q db.Querier, accountID id.UUID) ([]MemberSummary, error)
	CountOwners(ctx context.Context, q db.Querier, accountID id.UUID) (int, error)
	SetRole(ctx context.Context, q db.Querier, accountID, userID id.UUID, role Role) (Membership, error)
	RemoveMember(ctx context.Context, q db.Querier, accountID, userID id.UUID) error
	ListForUser(ctx context.Context, q db.Querier, userID id.UUID) ([]MemberSummary, error)
	CreateInvitation(ctx context.Context, q db.Querier, n NewInvitation) (Invitation, error)
	InvitationByToken(ctx context.Context, q db.Querier, digest string) (Invitation, error)
	MarkInvitationAccepted(ctx context.Context, q db.Querier, id id.UUID, at time.Time) error
}

// EventAppender is the slice of outbox.Store the tenancy use cases need. Every
// event this service emits about an account is written inside the transaction
// that changed the account, which is the entire reason the outbox exists.
type EventAppender interface {
	Append(ctx context.Context, q db.Querier, e outbox.Envelope) error
}

// Service is the tenancy use cases.
type Service struct {
	uow    UnitOfWork
	store  AccountStore
	events EventAppender
	clock  clock.Clock
	read   db.QuerierSource
}

// NewService wires the use cases.
func NewService(uow UnitOfWork, store AccountStore, events EventAppender, clk clock.Clock, read db.QuerierSource) *Service {
	return &Service{uow: uow, store: store, events: events, clock: clk, read: read}
}

// CreateInput is a request to create an account.
type CreateInput struct {
	// Name is what a human sees; the slug is derived from it.
	Name string
	// Owner is the user creating it, who becomes its first and (for now) only
	// owner. It is the caller's authenticated user, never something from a body.
	Owner id.UUID
}

// Created is a new account and the caller's membership in it.
type Created struct {
	Account    Account
	Membership Membership
}

// Create provisions an account and makes the caller its owner.
//
// Three rows and an event, in one transaction. The account without its owner
// membership is an account nobody can administer, and the event without the
// account announces a tenant that does not exist, so none of the three is
// written unless all of them are.
func (s *Service) Create(ctx context.Context, in CreateInput) (Created, error) {
	name := NormalizeName(in.Name)
	if err := ValidateName(name); err != nil {
		return Created{}, err
	}
	if in.Owner.IsZero() {
		return Created{}, ErrNotAMember
	}

	now := s.clock.Now()
	var out Created

	err := s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		account, err := s.store.Create(ctx, q, CreateParams{
			Name: name,
			Slug: Slugify(name),
		})
		if err != nil {
			return err
		}

		membership, err := s.addOwner(ctx, q, account, in.Owner)
		if err != nil {
			return err
		}

		event, err := outbox.NewAccountCreated(now, account.ID, account.Name, account.Slug, false, in.Owner)
		if err != nil {
			return err
		}
		if err := s.events.Append(ctx, q, event); err != nil {
			return err
		}

		out = Created{Account: account, Membership: membership}
		return nil
	})
	if err != nil {
		return Created{}, err
	}
	return out, nil
}

// Provision creates the account a registration gives its user, and
// AddOwner gives that user the owner role in it.
//
// Neither opens a transaction and neither may: they run inside the
// registration's, which is what makes "the personal account and the user exist
// together or not at all" true rather than aspirational. A registration that
// commits a user with no account is a user who cannot do anything, and it is
// exactly the half-written state a later packet would have to repair.
//
// The slug is derived from the user id rather than the name, because two people
// can share an email local part and the second must still be able to sign up.
// See PersonalSlug.
func (s *Service) Provision(ctx context.Context, q db.Querier, userID id.UUID, email string) (Account, error) {
	if userID.IsZero() {
		return Account{}, ErrNotAMember
	}

	name := PersonalName(email)
	if name == "" {
		name = "Personal"
	}
	if err := ValidateName(name); err != nil {
		// A local part that cannot be a name — "東京", or one over the limit — is
		// repaired rather than refused, because refusing here would fail a
		// registration over the *name* of an account the user never chose. The
		// fallback is the address, which is always sluggable and always unique
		// once the id is folded in.
		name = truncateName(email)
	}

	return s.store.Create(ctx, q, CreateParams{
		Name:     name,
		Slug:     PersonalSlug(email, userID),
		Personal: true,
	})
}

// AddOwner creates an owner's membership and announces the account. It pairs
// with Provision inside a registration's transaction.
func (s *Service) AddOwner(ctx context.Context, q db.Querier, accountID, userID id.UUID) (Membership, error) {
	account, err := s.store.ByID(ctx, q, accountID)
	if err != nil {
		return Membership{}, err
	}
	membership, err := s.addOwner(ctx, q, account, userID)
	if err != nil {
		return Membership{}, err
	}
	// The event belongs to the registration, not to the membership: there is one
	// account.created for the account, and writing it here rather than in
	// Provision is what keeps it next to the row it announces.
	event, err := outbox.NewAccountCreated(s.clock.Now(), account.ID, account.Name, account.Slug, account.Personal, userID)
	if err != nil {
		return Membership{}, err
	}
	if err := s.events.Append(ctx, q, event); err != nil {
		return Membership{}, err
	}
	return membership, nil
}

// addOwner creates a membership with the owner role, inside the caller's
// transaction.
func (s *Service) addOwner(ctx context.Context, q db.Querier, account Account, userID id.UUID) (Membership, error) {
	return s.store.AddMember(ctx, q, Membership{
		AccountID: account.ID,
		UserID:    userID,
		Role:      RoleOwner,
	})
}

// ListMine returns every account the user belongs to, with their role in each.
//
// Scoped by the authenticated user's id and nothing else. A query scoped by an
// account id from the request body is how one tenant's data reaches another's.
func (s *Service) ListMine(ctx context.Context, userID id.UUID) ([]MemberSummary, error) {
	if userID.IsZero() {
		return nil, ErrNotAMember
	}
	return s.store.ListForUser(ctx, s.read.Queryer(), userID)
}

// Get returns an account and the caller's membership in it.
//
// It returns ErrNotAMember for both "you are not in this account" and "there is
// no such account", and that is the security property rather than a
// convenience: a 403 for the first and a 404 for the second is an existence
// oracle for anybody who can guess an id.
//
// The second return value is the caller's own Role, which the handler needs to
// render "you are an admin of this" without a second query.
func (s *Service) Get(ctx context.Context, accountID, userID id.UUID) (Account, Role, error) {
	q := s.read.Queryer()

	membership, err := s.store.Member(ctx, q, accountID, userID)
	if err != nil {
		if errors.Is(err, ErrNotAMember) {
			return Account{}, "", ErrNotAMember
		}
		return Account{}, "", fmt.Errorf("looking up a membership: %w", err)
	}

	account, err := s.store.ByID(ctx, q, accountID)
	if err != nil {
		// A membership with no account is not a state the foreign keys allow, so
		// this is a database problem rather than a caller one. It is mapped to
		// the same error anyway: the caller learns nothing about the account's
		// existence either way.
		return Account{}, "", ErrNotAMember
	}

	return account, membership.Role, nil
}

// Members lists an account's memberships.
//
// It does not check the caller's own role. Authorization is
// RequireAccountRole's job in the HTTP layer, and duplicating it here would give
// the service two answers to the same question. This is a use case for the
// authorized caller, and the tests above prove the middleware calls it in the
// right order.
func (s *Service) Members(ctx context.Context, accountID id.UUID) ([]MemberSummary, error) {
	return s.store.Members(ctx, s.read.Queryer(), accountID)
}

// Member returns one user's membership, for the assertions above and for the
// removal path. A miss is ErrNotAMember, not ErrNotFound.
func (s *Service) Member(ctx context.Context, accountID, userID id.UUID) (Membership, error) {
	return s.store.Member(ctx, s.read.Queryer(), accountID, userID)
}

// Account returns an account without any authorization check, for the handlers
// that have already established the caller's role.
func (s *Service) Account(ctx context.Context, accountID id.UUID) (Account, error) {
	return s.store.ByID(ctx, s.read.Queryer(), accountID)
}

// Rename changes an account's name.
//
// It does not re-derive the slug, and it cannot conflict: a slug is set once, at
// creation, and a rename is therefore never a 409. See accounts.Account.Slug.
func (s *Service) Rename(ctx context.Context, accountID id.UUID, name string) (Account, error) {
	normalized := NormalizeName(name)
	if err := ValidateName(normalized); err != nil {
		return Account{}, err
	}
	return s.store.Rename(ctx, s.read.Queryer(), accountID, normalized)
}

// Delete removes an account. Its memberships and pending invitations go with it
// through the ON DELETE CASCADE the migrations declare.
func (s *Service) Delete(ctx context.Context, accountID id.UUID) error {
	return s.store.Delete(ctx, s.read.Queryer(), accountID)
}

// InviteInput is a request to invite somebody to an account.
type InviteInput struct {
	AccountID id.UUID
	Email     string
	Role      Role
	// InvitedBy is the authenticated caller. The inviter's own role is resolved
	// from the database rather than taken from a request, and it decides whether
	// an admin may be invited.
	InvitedBy id.UUID
}

// Invited is a new invitation and the one-time token that redeems it.
//
// The token is returned exactly once, here, and is never stored. A caller that
// loses it mints a new invitation; there is no way to recover it, which is the
// same rule that governs a session token and a password.
type Invited struct {
	Invitation Invitation
	Token      string
}

// Invite creates a pending membership and announces it.
//
// The inviter's own role is read here rather than assumed from the middleware,
// because the rule "only an owner may invite an admin" is about the *inviter*
// and there is one more hop between the request and this decision than there is
// for the caller's minimum role. Checking it in one place means the rule holds
// however the use case is reached.
func (s *Service) Invite(ctx context.Context, in InviteInput) (Invited, error) {
	email := users.NormalizeEmail(in.Email)
	if err := users.ValidateEmail(email); err != nil {
		// The address rules belong to users — one emailPattern, one
		// MaxEmailLength, one NormalizeEmail — and reusing them is why an
		// invitation address and a registered address cannot disagree about what
		// "the same address" means. The error is re-wrapped in this package's own
		// FieldError so that a caller of this service never has to know which
		// package a validation type came from; the field and code survive intact,
		// which is all a client reads.
		return Invited{}, asFieldError(err)
	}
	if !in.Role.Invitable() {
		return Invited{}, ErrRoleNotInvitable
	}

	inviter, err := s.store.Member(ctx, s.read.Queryer(), in.AccountID, in.InvitedBy)
	if err != nil {
		if errors.Is(err, ErrNotAMember) {
			return Invited{}, ErrOwnerProtected
		}
		return Invited{}, fmt.Errorf("looking up the inviter: %w", err)
	}
	if !inviter.Role.AtLeast(RoleAdmin) {
		return Invited{}, ErrOwnerProtected
	}
	// An admin may invite a member; only an owner may hand out admin. The
	// privilege has to be granted by somebody who already holds it, or an admin
	// can clone themselves into a second admin who answers to nobody.
	if in.Role == RoleAdmin && !inviter.Role.AtLeast(RoleOwner) {
		return Invited{}, ErrRoleNotInvitable
	}

	token, digest, err := NewToken()
	if err != nil {
		return Invited{}, err
	}
	now := s.clock.Now()

	var out Invited
	err = s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		invitation, err := s.store.CreateInvitation(ctx, q, NewInvitation{
			AccountID:   in.AccountID,
			Email:       email,
			Role:        in.Role,
			TokenDigest: digest,
			ExpiresAt:   now.Add(InvitationTTL),
			InvitedBy:   in.InvitedBy,
		})
		if err != nil {
			return err
		}

		event, err := outbox.NewMemberInvited(now, in.AccountID, invitation.ID, email, string(in.Role), in.InvitedBy)
		if err != nil {
			return err
		}
		if err := s.events.Append(ctx, q, event); err != nil {
			return err
		}

		out = Invited{Invitation: invitation, Token: token}
		return nil
	})
	if err != nil {
		return Invited{}, err
	}
	return out, nil
}

// InviteRole is Invite for a caller that has a role as a string, which is what a
// request body carries.
//
// It is a separate method rather than a ParseRole at the handler, so the owner
// restriction is applied on the same path however the use case is reached: a
// handler that parsed "owner" into accounts.RoleOwner and called Invite would
// otherwise skip nothing — Invite re-checks Invitable — but the two entry points
// would still be two places to keep in step.
func (s *Service) InviteRole(ctx context.Context, accountID id.UUID, email, role string, invitedBy id.UUID) (Invited, error) {
	parsed, err := ParseInvitableRole(role)
	if err != nil {
		return Invited{}, err
	}
	return s.Invite(ctx, InviteInput{
		AccountID: accountID,
		Email:     email,
		Role:      parsed,
		InvitedBy: invitedBy,
	})
}

// AcceptInput is a request to redeem an invitation.
type AcceptInput struct {
	// Token is the raw token from the invitation's 201 response.
	Token string
	// User is the authenticated caller redeeming it.
	User id.UUID
}

// Accept redeems an invitation: it creates the membership, marks the invitation
// accepted and announces the membership, in one transaction.
//
// The three are one fact. A membership with an invitation still pending is an
// invitation that can be redeemed again; an invitation marked accepted with no
// membership is a link that has been spent on nothing; and either without the
// event leaves a consumer's member list permanently one short with no way to
// notice.
//
// The token is not bound to the email it was sent to. Possession of a 256-bit
// token is the credential, the same rule as a session token, and binding it to an
// address would break the legitimate case of inviting somebody who already has
// an account under a different one. The consequence is that an admin can invite
// an address they do not control and the person who clicks the link is who joins
// — which is already true, because an admin can invite any address they like.
func (s *Service) Accept(ctx context.Context, in AcceptInput) (Membership, error) {
	if in.User.IsZero() {
		return Membership{}, ErrNotAMember
	}

	now := s.clock.Now()
	q := s.read.Queryer()

	invitation, err := s.store.InvitationByToken(ctx, q, Digest(in.Token))
	if err != nil {
		if errors.Is(err, ErrInvitationNotFound) {
			return Membership{}, ErrInvitationNotFound
		}
		return Membership{}, fmt.Errorf("looking up the invitation: %w", err)
	}

	// Order matters and it is the order a client would want them in: used before
	// expired, because an invitation that was accepted and has since expired is
	// "used" — the caller's link was already spent, and telling them to request a
	// new one would be wrong advice.
	if invitation.AcceptedAt != nil {
		return Membership{}, ErrInvitationUsed
	}
	if !invitation.ExpiresAt.After(now) {
		return Membership{}, ErrInvitationExpired
	}

	var out Membership
	err = s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		membership, err := s.store.AddMember(ctx, q, Membership{
			AccountID: invitation.AccountID,
			UserID:    in.User,
			Role:      invitation.Role,
		})
		if err != nil {
			return err
		}

		// Conditional: a second redemption of the same token updates zero rows
		// and rolls the whole transaction back, so two concurrent redemptions
		// cannot both produce a membership.
		if err := s.store.MarkInvitationAccepted(ctx, q, invitation.ID, now); err != nil {
			if errors.Is(err, ErrInvitationUsed) {
				return ErrInvitationUsed
			}
			return err
		}

		event, err := outbox.NewMemberAccepted(now, invitation.AccountID, in.User, string(invitation.Role))
		if err != nil {
			return err
		}
		if err := s.events.Append(ctx, q, event); err != nil {
			return err
		}

		out = membership
		return nil
	})
	if err != nil {
		return Membership{}, err
	}
	return out, nil
}

// ChangeRoleInput is a request to change a membership's role.
type ChangeRoleInput struct {
	AccountID id.UUID
	UserID    id.UUID
	Role      Role
	// Actor is the authenticated caller. It is separate from UserID because the
	// two roles in the decision are different: the caller's authority to change
	// roles, and whose role is changing.
	Actor id.UUID
}

// ChangeRole moves a membership to a new role.
//
// The last-owner check and the role change are in one transaction, and the count
// is taken under a row lock (see Store.CountOwners). Without the lock two owners
// demoting each other at the same moment both see two owners, both succeed, and
// the account is left with nobody who can administer it — a state no later
// request can repair, because every one of them now fails the role check.
func (s *Service) ChangeRole(ctx context.Context, in ChangeRoleInput) (Membership, error) {
	if !in.Role.Valid() {
		return Membership{}, &FieldError{Field: "role", Code: CodeUnknownRole}
	}

	now := s.clock.Now()
	var out Membership

	err := s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		target, err := s.store.Member(ctx, q, in.AccountID, in.UserID)
		if err != nil {
			return err
		}
		if target.Role == in.Role {
			// A no-op is still a fact worth recording as a no-op, but it is not
			// worth an event: "the role changed" would be false.
			return nil
		}

		if err := s.guardLastOwner(ctx, q, in.AccountID, target, in.Role); err != nil {
			// The caller is the owner who would be left with nothing to run. That
			// is the case a person hits by accident, so it gets its own error and
			// its own sentence.
			if errors.Is(err, ErrLastOwner) && target.UserID == in.Actor {
				return ErrSelfRoleChange
			}
			return err
		}

		updated, err := s.store.SetRole(ctx, q, in.AccountID, in.UserID, in.Role)
		if err != nil {
			return err
		}

		event, err := outbox.NewMemberRoleChanged(now, in.AccountID, in.UserID, string(target.Role), string(in.Role))
		if err != nil {
			return err
		}
		if err := s.events.Append(ctx, q, event); err != nil {
			return err
		}

		out = updated
		return nil
	})
	if err != nil {
		return Membership{}, err
	}
	return out, nil
}

// guardLastOwner refuses a change that would leave the account with no owner.
//
// The count is read through CountOwners, which takes a row lock on the owner
// rows, so a concurrent change to a *different* membership cannot interleave
// between the check and the write. That is the whole reason the check is inside
// the transaction rather than before it: two owners demoting each other at the
// same moment both see two owners, both succeed, and the account is left with
// nobody who can administer it — a state no later request can repair, because
// every one of them now fails the role check.
//
// It returns ErrLastOwner in every case. ChangeRole upgrades that to
// ErrSelfRoleChange when the caller is the owner being demoted, because "you
// cannot demote yourself out of the last account you run" is more use to the
// person who hit it than the general form.
func (s *Service) guardLastOwner(ctx context.Context, q db.Querier, accountID id.UUID, target Membership, next Role) error {
	// Only a demotion can lose an owner. Promoting one adds to the count, and a
	// change between admin and member does not touch it.
	if target.Role != RoleOwner || next == RoleOwner {
		return nil
	}

	owners, err := s.store.CountOwners(ctx, q, accountID)
	if err != nil {
		return err
	}
	if owners > 1 {
		return nil
	}
	return ErrLastOwner
}

// RemoveMemberInput is a request to remove a membership.
type RemoveMemberInput struct {
	AccountID id.UUID
	UserID    id.UUID
	Actor     id.UUID
}

// RemoveMember deletes a membership and announces it.
//
// Two rules beyond the minimum role, which the middleware checks: an owner is
// only removed by an owner, and the last owner is never removed. The first is
// about the target's role rather than the caller's minimum, so it belongs here;
// the second is the same invariant ChangeRole guards.
func (s *Service) RemoveMember(ctx context.Context, in RemoveMemberInput) error {
	now := s.clock.Now()

	return s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		target, err := s.store.Member(ctx, q, in.AccountID, in.UserID)
		if err != nil {
			return err
		}

		if target.Role == RoleOwner {
			actor, err := s.store.Member(ctx, q, in.AccountID, in.Actor)
			if err != nil {
				return err
			}
			// An admin may remove members and other admins; the owner's
			// membership is a different object and only an owner touches it.
			if !actor.Role.AtLeast(RoleOwner) {
				return ErrOwnerProtected
			}
			if err := s.guardLastOwner(ctx, q, in.AccountID, target, RoleMember); err != nil {
				return err
			}
		}

		if err := s.store.RemoveMember(ctx, q, in.AccountID, in.UserID); err != nil {
			return err
		}

		event, err := outbox.NewMemberRemoved(now, in.AccountID, in.UserID, string(target.Role))
		if err != nil {
			return err
		}
		return s.events.Append(ctx, q, event)
	})
}

// truncateName shortens an over-long personal account name to MaxNameLength.
//
// It exists for one case: a registration whose email local part is longer than a
// name may be. Refusing the registration over the name of an account the user
// never chose would be the wrong trade, and the name is the only field that has
// to be shortened — the slug is derived from the user id regardless.
func truncateName(name string) string {
	runes := []rune(name)
	if len(runes) <= MaxNameLength {
		return name
	}
	return string(runes[:MaxNameLength])
}

// asFieldError converts a users.FieldError into this package's own.
//
// The two types are structurally identical and deliberately separately declared:
// a shared one would put an edge between users and accounts for the sake of four
// fields, and the HTTP layer would then have to know that an accounts endpoint
// can fail with a users error. Everything that is not a *users.FieldError is
// returned unchanged, so a store failure does not come back as a 422.
func asFieldError(err error) error {
	var fe *users.FieldError
	if !errors.As(err, &fe) {
		return err
	}
	return &FieldError{Field: fe.Field, Code: fe.Code}
}
