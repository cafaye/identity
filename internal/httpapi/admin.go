package httpapi

// THE ADMIN SURFACE.
//
// Three routes, and the design is in three properties rather than in the handlers:
//
//  1. THE PRIVILEGE BOUNDARY IS EXPLICIT AND NARROW. An admin token may do
//     exactly two things a member's token may not: revoke invitations, and read
//     the audit trail. Stated once, in internal/admin's package comment, and
//     expressed here by the scope table and nothing else. There is no
//     "isAdmin" check in a handler, because a role checked in thirty places is a
//     role that will be checked in twenty-nine of them — the authority here is
//     `accountRouteScopes`, the same table every other route uses.
//
//  2. NO ADMIN ROUTE IS REACHABLE WITH A USER SESSION ALONE. R4. Every route here
//     is wrapped in adminTokenOnly, which REFUSES a session rather than merely
//     ignoring one. A session is a browser credential, and an admin surface a
//     session cookie opens is an admin surface one CSRF away from being somebody
//     else's. This is the mirror image of sessionCredentialOnly: that one refuses
//     tokens on session surfaces, this one refuses sessions on admin surfaces,
//     and the two together mean no route in the service is reachable by both
//     kinds of credential unless somebody wrote that down deliberately.
//
//  3. THE BLAST RADIUS IS BOUNDED AND THE BOUND IS VISIBLE IN THE API. The
//     single-operation route and the bulk route do not look alike. Revoking one
//     invitation is a DELETE on a named resource with no body; revoking many is a
//     POST that REQUIRES `{"confirm": true}` and a non-empty array. An off-by-one
//     in the second is an outage, and the difference is in the request shape
//     rather than in a UI's confirmation dialog, because a dialog is not
//     something an API client has.
//
// # WHY THE AUDIT TRAIL IS NOT WRITABLE THROUGH THIS API
//
// GET is the only method mounted on the audit-log path, and
// TestTheAuditTrailIsNotWritableThroughThisAPI walks the router to hold that. It
// is the right check for the right reason: the property is about the SURFACE, and
// a check inside the handler would pass if a future packet mounted a DELETE beside
// it. (The table itself refuses UPDATE and DELETE at the database — see
// migrations/00012 — but that is a second line of defence behind this one.)

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cafaye/identity/internal/accounts"
	"github.com/cafaye/identity/internal/admin"
	"github.com/cafaye/identity/internal/apikeys"
	"github.com/cafaye/identity/internal/platform/id"
)

// chiURLParam reads a URL parameter, named so this file does not import chi for
// one function — the same reason chiRouter exists in auth.go.
func chiURLParam(r *http.Request, name string) string {
	return chi.URLParam(r, name)
}

// adminPrefix is the path segment that marks the admin surface.
//
// IT IS A SEGMENT AND NOT A SEPARATE TOP-LEVEL TREE (`/v1/admin/accounts/…`) for
// a reason that is about tenancy rather than taste: an admin action is an action
// ON AN ACCOUNT, and a token is bound to one account. Putting the account in the
// path — as it already is for every other account-scoped route — means the
// tenancy check is `requireAccountRole`'s existing membership lookup, and an admin
// token presented against a path naming a different account is a 404 from the
// same code that already produces it. A separate tree would need a second tenancy
// check written from scratch, and the two would eventually disagree.
const adminPrefix = "admin"

// Admin is the slice of the admin use cases these handlers need.
type Admin interface {
	RevokeInvitation(ctx context.Context, in admin.RevokeInvitationInput) (int, error)
	RevokeInvitations(ctx context.Context, in admin.RevokeInvitationsInput) (int, error)
	List(ctx context.Context, accountID id.UUID, page admin.Page) ([]admin.Record, error)
}

// WithAdmin mounts the admin surface.
//
// Like every other optional surface here it is ABSENT rather than present-and-500:
// a deployment with no admin wiring gets a 404 on these three routes, which is
// the same answer it gets for a route that does not exist, and an operator who
// meant to enable them finds a 404 rather than a stack trace in their log.
func WithAdmin(a Admin) Option {
	return func(o *options) {
		if a != nil {
			o.admin = a
		}
	}
}

// registerAdminRoutes mounts the three admin routes.
//
// IT IS CALLED FROM registerTenancyRoutes, not from registerRoutes, and that is
// load-bearing rather than tidiness: `TestEveryMountedRouteIsAnAccountRoute`
// asserts that everything registerTenancyRoutes mounts is a tenancy route, and
// `TestEveryRouteIsInTheMatrix` walks the same registrar. Mounting the admin
// surface anywhere else would put three account-scoped routes outside both
// checks, which is precisely the hole those checks exist to close.
//
// The minimums, read down the page:
//
//	GET    /v1/accounts/:id/admin/audit-log                        admin
//	DELETE /v1/accounts/:id/admin/invitations/:invitationID        admin
//	POST   /v1/accounts/:id/admin/invitation-revocations           owner
//
// AND THE BULK ROUTE'S MINIMUM IS HIGHER ON PURPOSE. The single revocation is one
// person's pending access; revoking every one of them is a decision about the
// account, it is the operation where an off-by-one is an outage, and it is the one
// a departing employee's automation might fire on a schedule. An owner rather
// than an admin is the whole of that argument — there are only two roles above
// member and the smaller one already has the single-revocation route.
func (o options) registerAdminRoutes(r chiRouter) {
	if o.admin == nil {
		return
	}

	r.Get("/v1/accounts/{accountID}/"+adminPrefix+"/audit-log",
		o.requireAdminToken(o.requireAccountRole(accounts.RoleAdmin, o.handleListAuditLog)))

	r.Delete("/v1/accounts/{accountID}/"+adminPrefix+"/invitations/{invitationID}",
		o.requireAdminToken(o.requireAccountRole(accounts.RoleAdmin, o.handleRevokeInvitation)))

	r.Post("/v1/accounts/{accountID}/"+adminPrefix+"/invitation-revocations",
		o.requireAdminToken(o.requireAccountRole(accounts.RoleOwner, o.handleRevokeInvitations)))
}

// requireAdminToken is R4: a user session alone is not enough, and a session
// presented here is REFUSED rather than ignored.
//
// 403 and not 401, and the detail says why rather than naming a fact about
// anybody: the caller IS authenticated, so a 401 would send a client looking for
// a login problem that does not exist, and 404 would be a lie about the route.
//
// It runs BEFORE requireAccountRole rather than inside it, which is what makes it
// a property of the SURFACE. Wrapped outside, every admin route has it; a check
// inside a handler, it has whatever that handler remembered, and the route added
// next is the one without it.
func (o options) requireAdminToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !o.isAPIKeyRequest(r) {
			problemFor(w, r, http.StatusForbidden, CodeForbidden,
				"the admin surface is reachable by a scoped api key only; a browser session may not use it. "+
					"An admin action is taken by a machine credential that can be named in an audit record, "+
					"and a session cookie is neither")
			return
		}
		next(w, r)
	}
}

// ---------------------------------------------------------------------------
// request and response shapes
// ---------------------------------------------------------------------------

// bulkRevokeRequest is the body of the bulk revocation route.
//
// Confirm is a REQUIRED field and not an optional one, and it is not a query
// parameter: a POST whose body is `{"invitation_ids": [...]}` and a POST whose
// body is `{"invitation_ids": [...], "confirm": true}` are different requests to
// two different people reading the log, and the one that is missing the field is
// the one that revokes every pending invitation by accident. Absent, false, and
// the wrong JSON type are all refused with the same 422 — a client that gets a
// different answer for `false` than for absent has learned which one it sent.
type bulkRevokeRequest struct {
	InvitationIDs []string `json:"invitation_ids"`
	Confirm       bool     `json:"confirm"`
}

// auditLogResponse is one page of the trail.
type auditLogResponse struct {
	Entries []auditLogEntry `json:"entries"`
	// Next is the opaque cursor for the following page, empty on the last one.
	Next string `json:"next,omitempty"`
}

// auditLogEntry is one record, projected.
//
// The actor is the api key's ROW ID and its owner's user id. There is no field
// here a token could be written into, and that is the point: this is the response
// an operator reads during an incident and copies into a ticket, and a response
// shape with a `token` field is one somebody will eventually populate.
type auditLogEntry struct {
	ID string `json:"id"`
	// Action is the closed set, e.g. "invitation.revoked".
	Action string `json:"action"`
	// ActorUserID and ActorKeyID are ids, never credentials.
	ActorUserID string `json:"actor_user_id"`
	ActorKeyID  string `json:"actor_key_id"`
	Target      string `json:"target"`
	Affected    int    `json:"affected"`
	TraceID     string `json:"trace_id"`
	OccurredAt  string `json:"occurred_at"`
}

func entryResponse(rec admin.Record) auditLogEntry {
	return auditLogEntry{
		ID:          rec.ID.String(),
		Action:      string(rec.Action),
		ActorUserID: rec.ActorUserID.String(),
		ActorKeyID:  rec.ActorKeyID.String(),
		Target:      rec.Target,
		Affected:    rec.Affected,
		TraceID:     rec.TraceID,
		OccurredAt:  rec.OccurredAt.UTC().Format(time.RFC3339),
	}
}

// bulkRevokeResponse is the bulk route's answer.
//
// Requested AND Revoked, both of them, and the second is frequently smaller than
// the first: an id that was already revoked, or one belonging to another account,
// changes no rows. A response carrying only a count would be a client unable to
// tell "you asked for four and four went" from "you asked for four and two went
// because two of them were never there" — and on an admin surface that is the
// difference between a completed task and an incident.
type bulkRevokeResponse struct {
	Requested int `json:"requested"`
	Revoked   int `json:"revoked"`
}

// ---------------------------------------------------------------------------
// handlers
// ---------------------------------------------------------------------------

// handleListAuditLog returns one bounded page of the account's admin trail.
//
//	GET /v1/accounts/:id/admin/audit-log?limit=&before=
//	  →  200 {entries: [...], next}
func (o options) handleListAuditLog(w http.ResponseWriter, r *http.Request) {
	account, ok := accountFrom(r.Context())
	if !ok {
		notFound(w, r)
		return
	}

	page, queryErr := auditLogPage(r)
	if queryErr != nil {
		// A bad limit or a cursor this build did not issue is a 422 on the
		// request, and the field errors name which one — the same shape every
		// other validation failure in this service uses.
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the audit log query is not one this endpoint accepts").
			withFieldErrors(queryErr.fieldErrors()))
		return
	}

	records, err := o.admin.List(r.Context(), account.ID, page)
	if err != nil {
		o.writeAdminError(w, r, err)
		return
	}

	// An empty trail and a trail with no entries are the same answer, and
	// `entries` is present and empty rather than omitted: a client that has to
	// distinguish "no entries" from "the server left the field out" is a client
	// that will eventually get it wrong.
	entries := make([]auditLogEntry, 0, len(records))
	for _, rec := range records {
		entries = append(entries, entryResponse(rec))
	}

	out := auditLogResponse{Entries: entries}
	if len(records) > 0 {
		// The cursor comes from the LAST record, which the store attached. See
		// admin.Record.Next for why it is a field on the row.
		out.Next = records[len(records)-1].Next
	}
	writeJSON(w, http.StatusOK, out)
}

// handleRevokeInvitation revokes ONE pending invitation.
//
//	DELETE /v1/accounts/:id/admin/invitations/:invitationID  →  204
//
// NO BODY AND NO CONFIRMATION, and the absence is the difference from the bulk
// route rather than an oversight. The URL names the one thing being changed, so
// the request is self-describing: there is nothing in it that could be misread as
// "and everything else". A `confirm` field here would be a field a client has to
// remember to set, and a client that forgets it would be refusing a safe,
// idempotent, single-row operation for no benefit.
func (o options) handleRevokeInvitation(w http.ResponseWriter, r *http.Request) {
	account, ok := accountFrom(r.Context())
	if !ok {
		notFound(w, r)
		return
	}

	invitationID, ok := invitationIDFrom(r)
	if !ok {
		// A malformed id is a 404, on the same terms as accountIDFrom: "this is
		// not an id this service issued" and "this id is one you may not see" must
		// be indistinguishable, or the second becomes probeable.
		notFound(w, r)
		return
	}

	// The actor is assembled from the context requireAccountRole resolved, and
	// the key id is REQUIRED. A zero key id here would mean an audit record naming
	// no credential, which is a record of an action with no responsible party — so
	// the handler refuses rather than writing one. requireAdminToken above has
	// already established that this is a token call, so a zero id is a wiring
	// fault rather than a request the caller got wrong.
	actor, ok := adminActorFrom(r.Context())
	if !ok {
		unexpected(w, r, o.logger, errNoAdminActor)
		return
	}

	if _, err := o.admin.RevokeInvitation(r.Context(), admin.RevokeInvitationInput{
		AccountID:    account.ID,
		InvitationID: invitationID,
		Actor:        actor,
	}); err != nil {
		o.writeAdminError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleRevokeInvitations revokes MANY pending invitations.
//
//	POST /v1/accounts/:id/admin/invitation-revocations  {invitation_ids, confirm}
//	  →  200 {requested, revoked}
//
// THE CONFIRMATION IS IN THE BODY AND NOT A QUERY PARAMETER, so that the request
// that performs the operation and the request that describes it are the same
// bytes. A `?confirm=true` is one link-builder's accident away from being sent
// without the operator reading it, and the array is exactly the thing that must
// not be sent by accident.
func (o options) handleRevokeInvitations(w http.ResponseWriter, r *http.Request) {
	account, ok := accountFrom(r.Context())
	if !ok {
		notFound(w, r)
		return
	}

	var body *bulkRevokeRequest
	if !decodeBody(w, r, &body) {
		return
	}
	if fieldErrs := validateBulkRevoke(body); len(fieldErrs) > 0 {
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("a bulk revocation must name the invitations and confirm the action").
			withFieldErrors(fieldErrs))
		return
	}

	actor, ok := adminActorFrom(r.Context())
	if !ok {
		unexpected(w, r, o.logger, errNoAdminActor)
		return
	}

	// Parsed here rather than in the use case, so a malformed uuid is a 422 on a
	// field the caller can point at instead of a 500 from a parse deep in a
	// transaction. The slice is preallocated at the bound so a caller naming
	// MaxBulkInvitationIDs entries allocates once.
	ids := make([]id.UUID, 0, len(body.InvitationIDs))
	for _, raw := range body.InvitationIDs {
		parsed, err := id.Parse(raw)
		if err != nil || parsed.IsZero() {
			writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
				withDetail("every invitation id must be a uuid this service issued").
				withFieldErrors([]FieldError{{Field: "invitation_ids", Code: "invalid_format"}}))
			return
		}
		ids = append(ids, parsed)
	}

	revoked, err := o.admin.RevokeInvitations(r.Context(), admin.RevokeInvitationsInput{
		AccountID:     account.ID,
		InvitationIDs: ids,
		Actor:         actor,
	})
	if err != nil {
		o.writeAdminError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, bulkRevokeResponse{Requested: len(ids), Revoked: revoked})
}

// errNoAdminActor means an admin handler reached the actor assembly without a
// key id, which requireAdminToken should have made impossible. It is a 500 and
// not a 403: nothing about the caller is wrong, and answering 403 would tell a
// client its credential was insufficient when the real fault is the wiring.
var errNoAdminActor = errors.New("an admin route reached its handler with no api key in context")

// adminActorFrom assembles the audit actor from what requireAccountRole resolved.
//
// IT REFUSES A SESSION EXPLICITLY, with the same zero-id check twice over. The
// KeyID field on accountScope is zero for a session caller, and an admin action
// whose audit record cannot name a credential is an action nobody can attribute
// — so a session reaching this point is a fault to be loud about rather than a
// request to be served.
func adminActorFrom(ctx context.Context) (admin.Actor, bool) {
	scope, ok := ctx.Value(accountContextKey{}).(accountScope)
	if !ok {
		return admin.Actor{}, false
	}
	if scope.KeyID.IsZero() {
		return admin.Actor{}, false
	}
	return admin.Actor{
		UserID:  scope.User.ID,
		KeyID:   scope.KeyID,
		TraceID: traceIDFrom(ctx),
	}, true
}

// validateBulkRevoke is the request-level half of the bound, and it is HERE
// rather than only in the use case because the field errors need to name the
// field. The use case re-checks, and the two agreeing is deliberate: this one
// produces a good 422 and that one is the guarantee a caller cannot route around.
func validateBulkRevoke(body *bulkRevokeRequest) []FieldError {
	var errs []FieldError

	// Checked FIRST so the common accident — an array with no confirm — is
	// answered with the field the caller forgot rather than a complaint about the
	// array as well.
	if !body.Confirm {
		errs = append(errs, FieldError{Field: "confirm", Code: apikeys.CodeRequired})
	}

	switch {
	case len(body.InvitationIDs) == 0:
		errs = append(errs, FieldError{Field: "invitation_ids", Code: apikeys.CodeRequired})
	case len(body.InvitationIDs) > admin.MaxBulkInvitationIDs:
		// too_many and not out_of_range: the field is a list and the problem is
		// how many of them there are.
		errs = append(errs, FieldError{Field: "invitation_ids", Code: "too_many"})
	}
	return errs
}

// auditLogQueryError is a rejected query string, carrying the field errors that
// describe it.
//
// A type rather than a bare error because the handler has to render field errors
// and a sentinel cannot carry them — and rendering "there was a problem with the
// query" on an audit trail is exactly the kind of message that sends an operator
// looking in the wrong place.
type auditLogQueryError struct {
	detail string
	fields []FieldError
}

func (e auditLogQueryError) Error() string { return e.detail }

func (e auditLogQueryError) fieldErrors() []FieldError { return e.fields }

// auditLogPage reads the query string into a Page.
//
// IT REFUSES RATHER THAN DEFAULTS on a value it cannot read. `limit=abc` becoming
// the default is a silent wrong answer, and a client that believes it asked for
// fifty rows and silently received twenty-five has a trail it is reading
// incompletely. A bound that is enforced by guessing is not enforced.
func auditLogPage(r *http.Request) (admin.Page, *auditLogQueryError) {
	query := r.URL.Query()
	page := admin.Page{Before: query.Get("before")}

	if raw := query.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return admin.Page{}, &auditLogQueryError{
				detail: "the page size must be a whole number",
				fields: []FieldError{{Field: "limit", Code: apikeys.CodeInvalidFormat}},
			}
		}
		page.Limit = limit
	}

	// The bound is checked here so the failure names `limit` rather than arriving
	// from the use case as a generic error. The use case checks it again: this is
	// the good 422, that one is the guarantee.
	if _, err := page.Normalised(); err != nil {
		return admin.Page{}, &auditLogQueryError{
			detail: fmt.Sprintf("the page size must be between 1 and %d", admin.MaxAuditLogLimit),
			fields: []FieldError{{Field: "limit", Code: apikeys.CodeOutOfRange}},
		}
	}

	// The cursor is checked HERE as well as in the use case, and the reason is
	// which error the caller gets. A cursor this build did not issue is a bad
	// FIELD on a query string, and only the handler can say so — the use case
	// reports ErrBadCursor with no idea whether it arrived in `before`,
	// `cursor` or a path segment. An operator who has lost their place in a trail
	// needs to be told which part of their request to fix.
	//
	// The use case re-checks it, which is the guarantee: this is the good error,
	// that one is what a caller cannot route around.
	if _, _, err := page.Cursor(); err != nil {
		return admin.Page{}, &auditLogQueryError{
			detail: "the page cursor is not one this service issued",
			fields: []FieldError{{Field: "before", Code: apikeys.CodeInvalidFormat}},
		}
	}
	return page, nil
}

// invitationIDFrom reads and parses the invitation id in the path, on the same
// terms as accountIDFrom and userIDFrom.
func invitationIDFrom(r *http.Request) (id.UUID, bool) {
	parsed, err := id.Parse(chiURLParam(r, "invitationID"))
	if err != nil || parsed.IsZero() {
		return id.UUID{}, false
	}
	return parsed, true
}

// writeAdminError maps the admin use cases' errors onto problem documents.
//
// IT IS SEPARATE FROM writeTenancyError rather than an arm added to it, and the
// reason is that the two surfaces answer different questions: writeTenancyError
// has an arm for ErrInvitationEmailTaken, which is about CREATING an invitation,
// and reusing it here would mean the admin surface inherits a mapping for a case
// it cannot produce. The two lists are short, and a shared one would grow an arm
// per surface until neither could be read.
func (o options) writeAdminError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, admin.ErrInvitationNotRevocable),
		errors.Is(err, accounts.ErrInvitationNotFound):
		// 404, and one sentence for all of them: gone, another account's, or
		// malformed. A caller who could tell those apart would have a probe for
		// which invitation ids exist.
		problemFor(w, r, http.StatusNotFound, CodeNotFound,
			"no revocable invitation with that id is visible to you")

	case errors.Is(err, accounts.ErrInvitationUsed),
		errors.Is(err, accounts.ErrInvitationRevoked):
		// 409, and the same reasoning the accept route uses for a second
		// redemption: the request was understood and the resource is in a state
		// that contradicts it. The detail says which, because it is a fact about
		// the caller's own resource and not about anybody else.
		detail := "that invitation has already been accepted and cannot be revoked"
		if errors.Is(err, accounts.ErrInvitationRevoked) {
			detail = "that invitation has already been revoked"
		}
		problemFor(w, r, http.StatusConflict, CodeConflict, detail)

	case errors.Is(err, admin.ErrNoInvitations):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("a bulk revocation must name at least one invitation").
			withFieldErrors([]FieldError{{Field: "invitation_ids", Code: apikeys.CodeRequired}}))

	case errors.Is(err, admin.ErrTooManyInvitations):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail(fmt.Sprintf("a bulk revocation may name at most %d invitations", admin.MaxBulkInvitationIDs)).
			withFieldErrors([]FieldError{{Field: "invitation_ids", Code: "too_many"}}))

	case errors.Is(err, admin.ErrBadLimit):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail(fmt.Sprintf("the page size must be between 1 and %d", admin.MaxAuditLogLimit)).
			withFieldErrors([]FieldError{{Field: "limit", Code: apikeys.CodeOutOfRange}}))

	case errors.Is(err, admin.ErrBadCursor):
		// 400 and not 422: the cursor is a well-formed query parameter carrying a
		// value this build did not issue, which is closer to core's
		// CodeInvalidRequest than to a field validation failure — and a client
		// that needs to fix its cursor is not the client that needs to fix its
		// body.
		problemFor(w, r, http.StatusBadRequest, CodeInvalidRequest,
			"the page cursor is not one this service issued")

	default:
		// Everything else is a 500, and the cause goes to the log rather than the
		// body. This includes the audit-write failure that rolls the mutation
		// back: the caller is told the request failed, the mutation did not
		// happen, and the operator has a trace id.
		unexpected(w, r, o.logger, err)
	}
}
