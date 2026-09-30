// Package admin is the admin surface: the operations an account administrator
// may perform on their own account, and the immutable audit trail every one of
// them writes.
//
// # THE PRIVILEGE BOUNDARY, IN ONE SENTENCE
//
// An account admin may revoke pending invitations to their own account and read
// that account's admin audit log — authority over other people's pending access,
// and nothing else. A member's only self-service is their own session and their
// own credentials, and the rest of this service's authorization is unchanged by
// anything in this package.
//
// It is one sentence and the code says exactly it. There are two admin
// operations and one admin read, and this package adds no third: a capability
// that is not in that sentence has no route, so the sentence cannot drift from
// the surface without a test failing rather than a reader noticing.
//
// # WHY THE OPERATIONS AND THE AUDIT TRAIL ARE ONE PACKAGE
//
// Because they cannot be separated. A mutation that commits and an audit row
// that does not is a mutation nobody can account for, and the only way that is
// impossible rather than merely unlikely is for there to be no way to run one
// without the other. Every operation on this Service goes through Audited, which
// takes the mutation as a callback and runs it inside the transaction that also
// writes the record. There is no exported method that mutates without recording,
// so "somebody added an admin action and forgot the audit row" is not a mistake
// this package's shape permits — it is a mistake that needs a new exported
// method to make, which a review sees.
//
// # WHY THE RECORD CANNOT BE EDITED, INCLUDING BY THE ADMIN WHO WROTE IT
//
// Three things, in the order they would otherwise be questioned:
//
//  1. No route mutates it. GET is the only method the router mounts on the audit
//     path, and a test walks the router to hold that.
//  2. No method on this Service updates or deletes it. AuditStore has Append and
//     List and nothing else, so there is no function to call.
//  3. The DATABASE refuses UPDATE and DELETE, with a BEFORE UPDATE OR DELETE
//     trigger (migrations/00012). This is the one that actually settles it,
//     because the first two only describe this codebase: a repair script, an
//     operator with psql, or a future packet all bypass Go entirely, and the
//     requirement is that the record survives the admin whose action is in it.
//
// # WHAT THIS PACKAGE CANNOT HOLD
//
// A credential value. Actor carries the api key's row id and its owner's user
// id, and there is no field anywhere in this package that a token could be
// written into. That is deliberate and structural rather than a convention:
// apikeys.Key has a TokenDigest field, a handler holds one, and an audit log is
// exactly the place a `%+v` of it would end up. TestNothingOnThisSurfaceCanRecordAToken
// walks the types that reach the table and fails if any of them grows a field
// that could hold a value.
package admin

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
)

// Action is one of the things the admin surface can do.
//
// IT IS A CLOSED SET IN GO AND NOT A CHECK IN THE SCHEMA, and the reason is the
// one 00011 gives for api_keys.scopes: a closed vocabulary is a code fact, and
// putting it in the schema would make adding an action a migration. A row holding
// an action this build does not know about is refused when it is read, which is
// the fail-closed direction — treating an unknown action as "and so anything
// goes" is the bug a future migration would otherwise introduce silently.
type Action string

const (
	// ActionInvitationRevoked is one pending invitation, revoked by id.
	ActionInvitationRevoked Action = "invitation.revoked"

	// ActionInvitationsRevoked is the bulk route: many pending invitations, in
	// one request, in one transaction, in one row.
	//
	// A SEPARATE ACTION AND NOT A REPEATED ONE, because the two are different
	// events. One invitation revoked is a decision about a person; a hundred at
	// once is a decision about the account, it needs a higher minimum role, and
	// an operator reading the trail afterwards is asking "was that one, or was
	// that all of them". Collapsing them into one name would lose the answer.
	ActionInvitationsRevoked Action = "invitations.revoked"
)

// AllActions is the vocabulary, in a fixed order, for the same reason
// apikeys.AllScopes is: the order reaches a response and a map's iteration order
// would make two identical requests answer differently.
func AllActions() []Action {
	return []Action{ActionInvitationRevoked, ActionInvitationsRevoked}
}

// ErrUnknownAction is a row or a request naming an action this build does not
// implement.
var ErrUnknownAction = errors.New("not an action the admin surface performs")

func validateAction(action string) error {
	for _, known := range AllActions() {
		if string(known) == action {
			return nil
		}
	}
	return fmt.Errorf("%w: %q", ErrUnknownAction, action)
}

// Errors the operations return.
var (
	// ErrInvitationNotRevocable is an invitation that cannot be revoked: it is
	// gone, it belongs to another account, it has already been redeemed, or it
	// has already been revoked.
	//
	// ONE ERROR FOR ALL FOUR, and the reason is the same one accountIDFrom's is:
	// this is 404, and 404 is the answer for every one of them. A caller who
	// could tell "already redeemed" from "belongs to somebody else" would be
	// able to probe which invitation ids exist in accounts they are not a member
	// of, which is the same tenant-enumeration oracle the account routes refuse
	// to build.
	ErrInvitationNotRevocable = errors.New("no revocable invitation with that id in this account")

	// ErrNoInvitations is a bulk request naming nothing. It is refused rather
	// than treated as a no-op, because a request that revoked nothing and
	// reported success is indistinguishable from one that revoked everything and
	// under-reported.
	ErrNoInvitations = errors.New("a bulk revocation must name at least one invitation")

	// ErrTooManyInvitations is a bulk request above MaxBulkInvitationIDs. Refused
	// and not clamped: a caller that asked for a thousand and was given fifty has
	// been told a lie about what happened, and the audit row would record the lie.
	ErrTooManyInvitations = errors.New("too many invitation ids in one bulk revocation")

	// ErrBadCursor is a page token this build did not issue — truncated,
	// hand-typed, or from a different encoding.
	//
	// IT IS REFUSED AND NOT IGNORED. A cursor that cannot be decoded could be
	// answered with the first page, and to an operator paging through a trail
	// that looks exactly like a gap: they would conclude the records are missing
	// rather than that their token was wrong. On an audit trail those are very
	// different conclusions, and only one of them is usually true.
	ErrBadCursor = errors.New("the page cursor is not one this service issued")

	// ErrBadLimit is a page size that is not usable: negative, or above the
	// ceiling.
	//
	// ZERO IS NOT THIS ERROR. Zero is how a request says "no limit named", and it
	// becomes DefaultAuditLogLimit — the same answer a client gets by omitting the
	// parameter, which is what a generated client does. Refusing zero would make
	// the zero value of a Go struct's field un-sendable, and a bound that rejects
	// the default is a bound that a client works around by sending 1.
	ErrBadLimit = errors.New("page size is outside the range the audit trail accepts")
)

// The bounds. Every list is bounded and every bulk request is bounded, and both
// are enforced rather than documented — an admin surface is the last place a
// denial of service with a clean audit trail belongs.
const (
	// DefaultAuditLogLimit is a page of the trail with no limit named.
	DefaultAuditLogLimit = 25

	// MaxAuditLogLimit is the most rows one page may return.
	//
	// A hundred, and not "unbounded": the trail is read by an operator during an
	// incident and a page larger than a screenful helps nobody, while a caller who
	// can ask for a million rows at a time is a caller who can hold a connection
	// open on this service. The cursor is the way to read more, and a cursor
	// cannot be expensive.
	MaxAuditLogLimit = 100

	// MaxBulkInvitationIDs is the most invitations one bulk revocation may name.
	//
	// Fifty. A bulk revocation that names more than this is not an incident
	// response, it is a migration, and a migration is several requests with a
	// person watching — which is the entire reason the bulk route exists a
	// different shape from the single one.
	MaxBulkInvitationIDs = 50

	// maxTargetLength bounds Entry.Target, and matches the CHECK on the column.
	// Two places rather than one because the column's constraint is the database
	// and this is the request, and a value that passes the request check but
	// fails the column CHECK is a 500 on a well-formed request.
	maxTargetLength = 64
)

// Page is one page of the audit trail, as the route's query string spells it.
type Page struct {
	// Limit is the page size. Zero means DefaultAuditLogLimit; a value outside
	// 1..MaxAuditLogLimit is refused rather than clamped.
	Limit int
	// Before is an OPAQUE keyset cursor naming the last row of the previous page.
	// Empty means "from the newest".
	//
	// It is opaque and it carries BOTH the instant and the row's id, and the
	// second half is not decoration. The first version of this query paged on
	// `occurred_at < $before` alone, and the test for it failed: two records
	// sharing an instant — which the service's clock makes entirely ordinary,
	// since it is a timestamp and not a sequence — put one of them on each side
	// of the boundary and it was never returned at all. A cursor that is a
	// timestamp is a cursor that drops rows.
	//
	// It is opaque rather than two query parameters because a client handed
	// `?occurred_at=…&id=…` will eventually send one without the other, and each
	// half alone is the bug above. A single value the client passes back verbatim
	// is the only shape where that cannot happen.
	//
	// And it is a keyset and not an OFFSET, which is the reason this surface
	// needs one at all: an offset is wrong the moment a row is appended between
	// two requests, and on this surface a row is appended by somebody performing
	// an admin action while somebody else pages through the record of them.
	Before string
}

// Normalised resolves the page to a usable limit, or refuses it.
//
// It is exported because the HTTP layer validates the query string against it, so
// the 422 can name the field that was wrong. The use case calls it again on the
// way in, and the two agreeing is the point: the handler's check produces a good
// error, the use case's is the guarantee a caller cannot route around by calling
// the service directly.
func (p Page) Normalised() (int, error) {
	switch {
	case p.Limit < 0, p.Limit > MaxAuditLogLimit:
		return 0, fmt.Errorf("%w: %d is outside 1..%d", ErrBadLimit, p.Limit, MaxAuditLogLimit)
	case p.Limit == 0:
		return DefaultAuditLogLimit, nil
	default:
		return p.Limit, nil
	}
}

// Cursor decodes the opaque page token into the (instant, id) pair the keyset
// comparison needs. An empty cursor is the first page, and a malformed one is an
// error rather than a silent first page.
//
// It is exported so the HTTP layer can name `before` as the field that was wrong;
// the decoding itself is not reimplemented there.
//
// IT REFUSES RATHER THAN DEGRADES. A client that sends a cursor this build cannot
// read — a truncated one, one from a future build, a hand-typed value — gets
// ErrBadCursor. Answering it with the first page instead would look like data
// loss to an operator paging through a trail, and they would conclude the rows
// are missing rather than that their token was wrong.
func (p Page) Cursor() (time.Time, id.UUID, error) {
	if p.Before == "" {
		return time.Time{}, id.UUID{}, nil
	}

	raw, err := base64.RawURLEncoding.DecodeString(p.Before)
	if err != nil {
		return time.Time{}, id.UUID{}, fmt.Errorf("%w: not a cursor this build issued", ErrBadCursor)
	}

	instant, rowID, found := strings.Cut(string(raw), "|")
	if !found {
		return time.Time{}, id.UUID{}, fmt.Errorf("%w: not a cursor this build issued", ErrBadCursor)
	}
	parsed, err := time.Parse(time.RFC3339Nano, instant)
	if err != nil {
		return time.Time{}, id.UUID{}, fmt.Errorf("%w: not a cursor this build issued", ErrBadCursor)
	}
	uuid, err := id.Parse(rowID)
	if err != nil || uuid.IsZero() {
		return time.Time{}, id.UUID{}, fmt.Errorf("%w: not a cursor this build issued", ErrBadCursor)
	}
	return parsed, uuid, nil
}

// encodeCursor renders the keyset pair as the opaque token a client passes back.
//
// RawURLEncoding and not StdEncoding: the token goes in a query string, and the
// padded form contains `=` and `+` that a client would helpfully re-encode on
// the way out, so the round trip would fail for reasons that look like a
// corrupted token.
func encodeCursor(occurredAt time.Time, rowID id.UUID) string {
	return base64.RawURLEncoding.EncodeToString(
		[]byte(occurredAt.UTC().Format(time.RFC3339Nano) + "|" + rowID.String()))
}

// Actor is who performed an admin action.
//
// TWO IDS AND A TRACE ID, and the absence of a third field is the design. Actor
// is what reaches account_audit_log, and the api key's VALUE must never reach a
// table an operator reads during an incident; its row id is what an operator
// needs anyway, because that is the id they revoke by.
type Actor struct {
	// UserID is the human the token was minted for.
	UserID id.UUID
	// KeyID is WHICH token. "Somebody in the account" is not an answer an
	// incident review can use.
	//
	// REQUIRED, and the reason is that this surface is token-only: a session is a
	// browser credential and the HTTP layer refuses one before it gets here, so
	// every action on this surface was performed by a machine credential. An
	// action with no key id is an action nobody can attribute to a credential.
	KeyID id.UUID
	// TraceID joins the audit row to the request's log line. Never a token, and
	// the reason is the same one: a trace id is safe to print in both places.
	TraceID string
}

func (a Actor) validate() error {
	if a.UserID.IsZero() || a.KeyID.IsZero() {
		// A zero actor means the row would name nobody, and a record that names
		// nobody is a record of an action with no responsible party.
		return errors.New("an admin action must name both the user and the api key that performed it")
	}
	return nil
}

// Entry is a request to record one admin action. It is what an operation builds
// from its own inputs; Record is what comes back out of the table.
type Entry struct {
	AccountID id.UUID
	Action    Action
	Actor     Actor
	// Target is a short label for what was acted on: an invitation id for the
	// single operation, the collection's own name for the bulk one. It is a
	// label and not a list, so one row stays one row however large the request
	// was.
	Target string
	// Affected is how many rows the action changed, and it is set by Audited from
	// the mutation's own return rather than by the caller who builds the Entry.
	//
	// IT IS A FIELD RATHER THAN AN ARGUMENT TO Append because the number is not
	// knowable until after the mutation has run, and the alternative — passing it
	// to Append separately — would let a caller write a record claiming a count
	// the mutation never reported. There is one way to set it and it is the
	// truthful one.
	Affected int
	// OccurredAt is the service's clock, passed in so the row and the request that
	// made it agree and only one of the two is under test control.
	OccurredAt time.Time
}

// Record is one row of account_audit_log.
type Record struct {
	ID          id.UUID
	AccountID   id.UUID
	Action      Action
	ActorUserID id.UUID
	ActorKeyID  id.UUID
	Target      string
	Affected    int
	TraceID     string
	OccurredAt  time.Time
	// Next is the opaque cursor for the page AFTER this one, empty on the last
	// page of the trail.
	//
	// IT IS A FIELD AND NOT SOMETHING THE CALLER BUILDS, because a caller that
	// forgot to thread it back would hand an operator a first page and no way to
	// ask for a second — which reads as "there is nothing after this", the one
	// answer an operator must never be given about a trail.
	Next string
}

func (e Entry) validate() error {
	if e.AccountID.IsZero() {
		return errors.New("an audit record must name the account it was taken in")
	}
	if err := validateAction(string(e.Action)); err != nil {
		return err
	}
	if err := e.Actor.validate(); err != nil {
		return err
	}
	if strings.TrimSpace(e.Target) == "" {
		return errors.New("an audit record must name what the action was taken on")
	}
	if len(e.Target) > maxTargetLength {
		return fmt.Errorf("an audit record's target is %d characters, over the %d accepted", len(e.Target), maxTargetLength)
	}
	if e.Affected < 0 {
		return fmt.Errorf("an audit record's affected count is %d, which no action can report", e.Affected)
	}
	return nil
}

// UnitOfWork runs a function inside a transaction. db.TxRunner implements it; the
// interface is what lets the atomicity below be tested without Postgres, and
// store_test.go and the HTTP layer's integration test are what prove it against
// a real database.
type UnitOfWork interface {
	Do(ctx context.Context, fn func(ctx context.Context, q db.Querier) error) error
}

// AuditStore is the slice of the audit table these use cases need.
//
// APPEND AND LIST AND NOTHING ELSE. There is no Update and no Delete method, and
// that is not an omission waiting to be filled: the table refuses both at the
// database (migrations/00012), so a method here would be a function that can only
// ever return an error. The interface is the shape, and the trigger is the
// guarantee.
type AuditStore interface {
	Append(ctx context.Context, q db.Querier, e Entry) (Record, error)
	List(ctx context.Context, q db.Querier, accountID id.UUID, page Page) ([]Record, error)
}

// InvitationRevoker is the slice of the accounts store the two operations need.
//
// Declared here rather than taking *accounts.Store so a test can program a
// failure at the exact statement that matters — the mutation failing is how the
// "no audit record for an action that did not happen" test is written.
type InvitationRevoker interface {
	// RevokePendingInvitation revokes one, and reports how many rows it changed.
	// Zero is not an error: an invitation that is already revoked changes no rows
	// and the operation still succeeded.
	RevokePendingInvitation(ctx context.Context, q db.Querier, accountID, invitationID id.UUID) (int, error)
	// RevokePendingInvitations revokes many, scoped to the account, and reports
	// how many rows it changed — which is the number the audit row records, and
	// the two differ whenever a request names an id that was already revoked.
	RevokePendingInvitations(ctx context.Context, q db.Querier, accountID id.UUID, ids []id.UUID) (int, error)
}

// Service is the admin surface's use cases.
type Service struct {
	tx      UnitOfWork
	store   AuditStore
	revoker InvitationRevoker
	clock   clock.Clock
	// reads is where a page of the trail comes from, and it is a separate querier
	// from the transaction one. A list is a single statement with no atomicity
	// requirement, and routing it through a transaction would mean a BEGIN and a
	// COMMIT for an operator's first request after an incident.
	reads db.QuerierSource
}

// NewService builds the admin use cases.
//
// reads is separate from tx on purpose, for the reason on the field: writes are
// transactional and reads are not, and a Service with one querier for both would
// have to open a transaction to serve a GET.
func NewService(tx UnitOfWork, store AuditStore, revoker InvitationRevoker, reads db.QuerierSource, clk clock.Clock) *Service {
	return &Service{tx: tx, store: store, revoker: revoker, reads: reads, clock: clk}
}

// Mutation is the work an admin action performs.
//
// IT RETURNS THE COUNT IT CHANGED rather than just an error, and the reason is
// that the count is a fact about the database that only the mutation knows: the
// audit row records what actually changed, not what was asked for. A request
// naming six invitations where two were already revoked must record six, because
// six is the truth.
type Mutation func(ctx context.Context, q db.Querier) (int, error)

// Audited runs a mutation and records it, in ONE transaction.
//
// This is the whole of the atomicity property and it is deliberately the only
// way an operation on this Service touches the database. The order inside the
// transaction is mutation-then-record, and it is that order for the count: the
// record needs the number the mutation reports.
//
// The failure direction is the one that matters and it falls out of the
// transaction rather than being checked:
//
//   - the record fails  → the transaction rolls back → the mutation did not happen
//   - the mutation fails → the transaction rolls back → no record claims it did
//
// Neither needs a compensating action, which is the property a same-transaction
// guarantee is for: there is no interleaving in which one of the two is visible
// without the other.
func (s *Service) Audited(ctx context.Context, e Entry, mutate Mutation) (int, error) {
	if err := e.validate(); err != nil {
		// Before the transaction, not inside it. A malformed request should not
		// open one.
		return 0, err
	}
	if mutate == nil {
		return 0, db.ErrNilTxFunc
	}

	var affected int
	err := s.tx.Do(ctx, func(ctx context.Context, q db.Querier) error {
		count, err := mutate(ctx, q)
		if err != nil {
			return fmt.Errorf("performing the admin action: %w", err)
		}
		affected = count

		// The count and the instant are set HERE, after the mutation, rather than
		// by the caller. Both are facts about what happened rather than about what
		// was asked for, and setting either before the mutation ran is how a trail
		// ends up claiming a number nobody measured.
		e.Affected = count
		e.OccurredAt = s.clock.Now()
		rec, err := s.store.Append(ctx, q, e)
		if err != nil {
			// Wrapped, and returned, so the transaction rolls back with the audit
			// failure as its reason. The caller reports a 500 with this trace id and
			// the mutation is gone.
			return fmt.Errorf("appending the audit record: %w", err)
		}
		if rec.ID.IsZero() {
			// A store that reports success and hands back no id has written a row
			// this service cannot name. Treated as a failure, because a record that
			// cannot be pointed at is not a record anybody will find again.
			return errors.New("appending the audit record reported success and returned no id")
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return affected, nil
}

// RevokeInvitationInput is one invitation and the admin removing it.
type RevokeInvitationInput struct {
	AccountID    id.UUID
	InvitationID id.UUID
	Actor        Actor
}

// RevokeInvitation revokes one pending invitation.
//
// ErrInvitationNotRevocable and nothing else: the store cannot tell the caller
// which of the four reasons applied, and a caller that could is a caller probing
// which invitation ids exist.
//
// It reports how many rows changed, which is 0 for an invitation that was already
// revoked and 1 otherwise. A repeated call is not an error — revoking twice is
// idempotent, and a client retrying after a timeout must not get a 404 for a
// revocation that did happen.
func (s *Service) RevokeInvitation(ctx context.Context, in RevokeInvitationInput) (int, error) {
	if in.InvitationID.IsZero() {
		return 0, ErrInvitationNotRevocable
	}

	entry := Entry{
		AccountID: in.AccountID,
		Action:    ActionInvitationRevoked,
		Actor:     in.Actor,
		Target:    in.InvitationID.String(),
	}
	return s.Audited(ctx, entry, func(ctx context.Context, q db.Querier) (int, error) {
		return s.revoker.RevokePendingInvitation(ctx, q, in.AccountID, in.InvitationID)
	})
}

// RevokeInvitationsInput is many invitations and the admin revoking them.
type RevokeInvitationsInput struct {
	AccountID id.UUID
	// InvitationIDs is the array, and it is bounded on the way in. See
	// MaxBulkInvitationIDs.
	InvitationIDs []id.UUID
	Actor         Actor
}

// RevokeInvitations revokes many pending invitations in one transaction and
// writes ONE audit row for the lot.
//
// The bounds are refused rather than clamped, and this is the packet's third
// property stated as code: a bulk operation is the one where an off-by-one is an
// outage, so it does not get the same shape as a single operation and it does
// not get a silent answer.
//
// A duplicate id inside the array is not an error and not double-counted: the
// store's count is the number of rows that changed, so naming the same
// invitation twice records one revocation, which is the truth.
func (s *Service) RevokeInvitations(ctx context.Context, in RevokeInvitationsInput) (int, error) {
	ids, err := validateBulkIDs(in.InvitationIDs)
	if err != nil {
		return 0, err
	}

	entry := Entry{
		AccountID: in.AccountID,
		Action:    ActionInvitationsRevoked,
		Actor:     in.Actor,
		// The collection's own name rather than the ids, because the ids are
		// already gone by the time anybody reads this and a list of fifty uuids in
		// a column bounded to 64 characters would have to be truncated into
		// something that reads like a different set.
		Target: "invitation-revocations",
	}
	return s.Audited(ctx, entry, func(ctx context.Context, q db.Querier) (int, error) {
		return s.revoker.RevokePendingInvitations(ctx, q, in.AccountID, ids)
	})
}

// validateBulkIDs refuses an empty or over-sized array and drops duplicates.
func validateBulkIDs(ids []id.UUID) ([]id.UUID, error) {
	if len(ids) == 0 {
		return nil, ErrNoInvitations
	}
	if len(ids) > MaxBulkInvitationIDs {
		return nil, fmt.Errorf("%w: %d is over the %d accepted", ErrTooManyInvitations, len(ids), MaxBulkInvitationIDs)
	}

	// Duplicates are collapsed, and the ceiling is checked against the CALLER'S
	// count rather than the deduplicated one: a request of five hundred copies of
	// one id is a request of five hundred things, and it is refused before the
	// deduplication that would make it look small.
	seen := make(map[id.UUID]bool, len(ids))
	out := make([]id.UUID, 0, len(ids))
	for _, one := range ids {
		if one.IsZero() || seen[one] {
			continue
		}
		seen[one] = true
		out = append(out, one)
	}
	if len(out) == 0 {
		return nil, ErrNoInvitations
	}
	return out, nil
}

// List returns one bounded page of an account's audit trail, newest first.
//
// It is the only read on this surface, and it is bounded twice over: the page
// size is checked here rather than trusted, and the cursor is a keyset rather
// than an offset so a concurrent append cannot make the operator skip or repeat
// a row.
//
// The returned records carry the cursor for the NEXT page in Record.Next, already
// encoded. A handler that forgot to thread it back would return a first page and
// an operator would have no way to ask for the second — so the cursor is a field
// on the row rather than something the caller assembles.
func (s *Service) List(ctx context.Context, accountID id.UUID, page Page) ([]Record, error) {
	if accountID.IsZero() {
		return nil, ErrInvitationNotRevocable
	}
	limit, err := page.Normalised()
	if err != nil {
		return nil, err
	}
	_, _, err = page.Cursor()
	if err != nil {
		return nil, err
	}
	return s.store.List(ctx, s.reads.Queryer(), accountID, Page{Limit: limit, Before: page.Before})
}
