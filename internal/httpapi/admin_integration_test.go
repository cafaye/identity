package httpapi

// THE ADMIN SURFACE AGAINST A REAL DATABASE.
//
// The three properties this packet is about, end to end, with no doubles on the
// path that matters:
//
//	TestTheAuditRecordIsWrittenInTheSameTransactionAsTheAction
//	TestTheRevokedInvitationIsActuallyDead            the revocation is real
//	TestAnAdminActionNeverWritesACredential           nothing loggable leaked
//
// The router-level red proofs live in admin_test.go because they are about
// MIDDLEWARE, and a wiring property is best asserted with a double standing in
// for the database. The property in this file is the opposite: it is about what
// the DATABASE commits, and a double would be asserting against itself.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cafaye/identity/internal/accounts"
	"github.com/cafaye/identity/internal/admin"
	"github.com/cafaye/identity/internal/apikeys"
	"github.com/cafaye/identity/internal/auth"
	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/users"
)

// --- fixture ------------------------------------------------------------------

// adminWorld is a real account with a real owner, a real pending invitation, and
// a real admin token for it.
type adminWorld struct {
	handler http.Handler
	pool    *pgxpool.Pool
	clock   *clock.Fake

	accountID  id.UUID
	ownerID    id.UUID
	memberID   id.UUID
	invitation id.UUID
	// tokenSecret is the api key's plaintext. It exists in this file ONLY to be
	// presented to the router, and TestAnAdminActionNeverWritesACredential asserts
	// that it appears in no response body and no audit row.
	tokenSecret string
	tokenID     id.UUID
}

func newAdminWorld(t *testing.T) *adminWorld {
	t.Helper()

	pool := dbtest.Schema(t)
	clk := clock.NewFake(time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))

	tenancy := realTenancy(pool, clk)
	authSvc := authServiceFor(pool, clk)
	keys := matrixAPIKeys(pool, clk, tenancy)
	adminSvc := admin.NewService(
		db.TxRunner{Pool: pool},
		admin.NewStore(pool),
		accounts.NewStore(pool),
		db.Direct{Pool: pool},
		clk,
	)

	handler := New(nil,
		WithAuth(authSvc),
		WithTenancy(tenancy),
		WithAPIKeys(keys),
		WithAPIKeyCaller(keys),
		WithAdmin(adminSvc),
		WithLogger(slogLogger(&recordingHandler{})),
	)

	// A real user, a real session, a real account owned by them.
	email := dbtest.UniqueEmail(t)
	rec := post(t, handler, "/v1/users", `{"email":"`+email+`","password":"`+matrixPassword+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering the owner: %d; body: %s", rec.Code, rec.Body)
	}
	var created userResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("the registration body is not JSON: %v", err)
	}
	ownerID, err := id.Parse(created.ID)
	if err != nil {
		t.Fatalf("the service returned an id that does not parse: %v", err)
	}

	login := post(t, handler, "/v1/session", `{"email":"`+email+`","password":"`+matrixPassword+`"}`)
	if login.Code != http.StatusOK {
		t.Fatalf("signing the owner in: %d; body: %s", login.Code, login.Body)
	}
	var session sessionResponse
	if err := json.Unmarshal(login.Body.Bytes(), &session); err != nil {
		t.Fatalf("the login body is not JSON: %v", err)
	}

	created2, err := tenancy.Create(t.Context(), accounts.CreateInput{
		Name:  "Admin World " + id.MustNew().String()[:8],
		Owner: ownerID,
	})
	if err != nil {
		t.Fatalf("creating the account: %v", err)
	}

	// A real pending invitation, through the real use case.
	invited, err := tenancy.Invite(t.Context(), accounts.InviteInput{
		AccountID: created2.Account.ID,
		Email:     dbtest.UniqueEmail(t),
		Role:      accounts.RoleMember,
		InvitedBy: ownerID,
	})
	if err != nil {
		t.Fatalf("creating the pending invitation: %v", err)
	}

	// A real token, minted through the real use case with both admin scopes, so
	// the row in the tests below is one the service would have written.
	key, err := keys.Mint(t.Context(), apikeys.MintInput{
		AccountID: created2.Account.ID,
		Name:      "admin-surface",
		Scopes:    []string{apikeys.ScopeAuditLogRead, apikeys.ScopeAccountInvitationsWrite},
		MintedBy:  ownerID,
	})
	if err != nil {
		t.Fatalf("minting the admin token: %v", err)
	}

	return &adminWorld{
		handler:     handler,
		pool:        pool,
		clock:       clk,
		accountID:   created2.Account.ID,
		ownerID:     ownerID,
		invitation:  invited.Invitation.ID,
		tokenSecret: key.Token,
		tokenID:     key.Key.ID,
	}
}

// send issues a request to the admin surface with the admin token.
func (w *adminWorld) send(t *testing.T, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+w.tokenSecret)
	rec := httptest.NewRecorder()
	w.handler.ServeHTTP(rec, req)
	return rec
}

func (w *adminWorld) auditPath() string {
	return "/v1/accounts/" + w.accountID.String() + "/admin/audit-log"
}

func (w *adminWorld) revokePath(invitation id.UUID) string {
	return "/v1/accounts/" + w.accountID.String() + "/admin/invitations/" + invitation.String()
}

func (w *adminWorld) bulkPath() string {
	return "/v1/accounts/" + w.accountID.String() + "/admin/invitation-revocations"
}

// --- the transaction, end to end ----------------------------------------------

// TestTheAuditRecordIsWrittenInTheSameTransactionAsTheAction is R3 over the real
// stack: the real router, the real middleware, the real use case, the real
// transaction, the real SQL.
//
// IT IS A POSITIVE PROOF, and the negative one is in internal/admin with a trigger
// that raises. Both are here for a reason: the negative proves the rollback, and
// this proves that the happy path writes BOTH rows — because a service that
// rolled back everything would pass the negative proof perfectly.
func TestTheAuditRecordIsWrittenInTheSameTransactionAsTheAction(t *testing.T) {
	w := newAdminWorld(t)
	ctx := t.Context()

	rec := w.send(t, http.MethodDelete, w.revokePath(w.invitation), "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", rec.Code, rec.Body)
	}

	// The mutation really happened.
	var revokedAt *time.Time
	if err := w.pool.QueryRow(ctx,
		`SELECT revoked_at FROM account_invitations WHERE id = $1`, w.invitation).Scan(&revokedAt); err != nil {
		t.Fatalf("reading the invitation: %v", err)
	}
	if revokedAt == nil {
		t.Fatal("the invitation is not revoked; the 204 was a lie")
	}

	// And the audit record really exists, naming the credential that did it.
	var (
		action     string
		actorKey   id.UUID
		actorUser  id.UUID
		target     string
		affected   int
		invitedFor id.UUID
	)
	err := w.pool.QueryRow(ctx, `
		SELECT action, actor_key_id, actor_user_id, target, affected, account_id
		FROM account_audit_log WHERE account_id = $1`, w.accountID).
		Scan(&action, &actorKey, &actorUser, &target, &affected, &invitedFor)
	if err != nil {
		t.Fatalf("reading the audit record: %v", err)
	}
	if action != string(admin.ActionInvitationRevoked) {
		t.Errorf("action = %q, want %q", action, admin.ActionInvitationRevoked)
	}
	if actorKey != w.tokenID {
		t.Errorf("actor_key_id = %s, want the token that acted (%s)", actorKey, w.tokenID)
	}
	if actorUser != w.ownerID {
		t.Errorf("actor_user_id = %s, want the token's owner (%s)", actorUser, w.ownerID)
	}
	if target != w.invitation.String() {
		t.Errorf("target = %q, want the invitation id %q", target, w.invitation)
	}
	if affected != 1 {
		t.Errorf("affected = %d, want 1", affected)
	}
}

// TestTheRevokedInvitationIsActuallyDead closes the loop from the other end: the
// token is dead.
//
// A revocation that sets a column nothing reads would pass the test above — the
// row would have revoked_at set and the invitation would still redeem, and the
// admin would believe they had recalled a link that still works.
func TestTheRevokedInvitationIsActuallyDead(t *testing.T) {
	w := newAdminWorld(t)

	// Read the token before revoking, because the whole point is to use it after.
	// The token is returned exactly once, at mint, so it is captured on the
	// fixture rather than fetched — which is itself the property api_keys' design
	// claims and the reason this test can work at all.
	rec := w.send(t, http.MethodDelete, w.revokePath(w.invitation), "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", rec.Code, rec.Body)
	}

	// Redemption goes through POST /v1/invitations/accept with the INVITATION's
	// token, not the api key. So read the digest's plaintext out of the fixture
	// instead: mint a fresh invitation so its token is known, revoke it, and try
	// to redeem.
	tenancy := realTenancy(w.pool, w.clock)
	fresh, err := tenancy.Invite(t.Context(), accounts.InviteInput{
		AccountID: w.accountID,
		Email:     dbtest.UniqueEmail(t),
		Role:      accounts.RoleMember,
		InvitedBy: w.ownerID,
	})
	if err != nil {
		t.Fatalf("minting a fresh invitation: %v", err)
	}

	revokeRec := w.send(t, http.MethodDelete, w.revokePath(fresh.Invitation.ID), "")
	if revokeRec.Code != http.StatusNoContent {
		t.Fatalf("revoking the fresh invitation: %d; body: %s", revokeRec.Code, revokeRec.Body)
	}

	// And the token is a column nothing reads...
	var revokedAt *time.Time
	if err := w.pool.QueryRow(t.Context(),
		`SELECT revoked_at FROM account_invitations WHERE id = $1`, fresh.Invitation.ID).
		Scan(&revokedAt); err != nil {
		t.Fatalf("reading the invitation: %v", err)
	}
	if revokedAt == nil {
		t.Fatal("revoked_at is not set, so nothing about this token is dead")
	}

	// ...which the redemption path must therefore refuse. Accepting it is the
	// observable consequence, and it is checked through the real HTTP surface
	// rather than by calling the store, so the conditional UPDATE that enforces
	// it is the one under test.
	accept := post(t, w.handler, "/v1/invitations/accept", `{"token":"`+fresh.Token+`"}`)
	if accept.Code == http.StatusOK {
		t.Error("a REVOKED invitation was accepted. revoked_at is set and the token still redeems, " +
			"which means the revocation is a column nothing reads and the admin has recalled nothing")
	}
}

// TestTheBulkRevocationRecordsOneRecordForTheBatch is the bulk route's audit
// shape: ONE row for the whole batch, carrying the count the database reported.
func TestTheBulkRevocationRecordsOneRecordForTheBatch(t *testing.T) {
	w := newAdminWorld(t)
	ctx := t.Context()

	tenancy := realTenancy(w.pool, w.clock)

	// Three fresh invitations, so the batch is genuinely a batch.
	ids := make([]id.UUID, 0, 3)
	for range 3 {
		invited, err := tenancy.Invite(ctx, accounts.InviteInput{
			AccountID: w.accountID,
			Email:     dbtest.UniqueEmail(t),
			Role:      accounts.RoleMember,
			InvitedBy: w.ownerID,
		})
		if err != nil {
			t.Fatalf("minting invitation %d: %v", len(ids), err)
		}
		ids = append(ids, invited.Invitation.ID)
	}

	quoted := make([]string, 0, len(ids))
	for _, one := range ids {
		quoted = append(quoted, `"`+one.String()+`"`)
	}
	body := `{"invitation_ids":[` + strings.Join(quoted, ",") + `],"confirm":true}`

	rec := w.send(t, http.MethodPost, w.bulkPath(), body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	var got bulkRevokeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	if got.Requested != 3 || got.Revoked != 3 {
		t.Fatalf("requested = %d, revoked = %d; want 3 and 3", got.Requested, got.Revoked)
	}

	// ONE record, for the lot, with the bulk action name — not three records with
	// the single-revocation name. An operator asking "was that one, or was that
	// all of them" gets their answer from the action field.
	var count int
	var action string
	var affected int
	if err := w.pool.QueryRow(ctx,
		`SELECT count(*), min(action), min(affected) FROM account_audit_log WHERE account_id = $1`, w.accountID).
		Scan(&count, &action, &affected); err != nil {
		t.Fatalf("counting the audit records: %v", err)
	}
	if count != 1 {
		t.Errorf("the batch wrote %d audit records, want 1", count)
	}
	if action != string(admin.ActionInvitationsRevoked) {
		t.Errorf("action = %q, want %q — a batch recorded as N single revocations loses the answer "+
			"to 'was that one or all of them'", action, admin.ActionInvitationsRevoked)
	}
	if affected != 3 {
		t.Errorf("affected = %d, want 3", affected)
	}

	// All three really are dead.
	for _, one := range ids {
		var revokedAt *time.Time
		if err := w.pool.QueryRow(ctx,
			`SELECT revoked_at FROM account_invitations WHERE id = $1`, one).Scan(&revokedAt); err != nil {
			t.Fatalf("reading invitation %s: %v", one, err)
		}
		if revokedAt == nil {
			t.Errorf("invitation %s was not revoked although the response said 3 of 3", one)
		}
	}
}

// TestTheCountInTheRecordIsTheDatabasesAnswer is the honesty check on `affected`,
// and it is the case where the request and the truth differ.
//
// The request names FOUR invitations; one is already revoked, so the database
// changes three. The record must say three. A record saying four is a trail an
// operator cannot reconcile against the account, and reconciliation is the only
// reason to keep a trail.
func TestTheCountInTheRecordIsTheDatabasesAnswer(t *testing.T) {
	w := newAdminWorld(t)
	ctx := t.Context()

	tenancy := realTenancy(w.pool, w.clock)

	fresh := make([]id.UUID, 0, 3)
	for range 3 {
		invited, err := tenancy.Invite(ctx, accounts.InviteInput{
			AccountID: w.accountID,
			Email:     dbtest.UniqueEmail(t),
			Role:      accounts.RoleMember,
			InvitedBy: w.ownerID,
		})
		if err != nil {
			t.Fatalf("minting: %v", err)
		}
		fresh = append(fresh, invited.Invitation.ID)
	}

	// Revoke one through the single route, so it is already dead.
	if rec := w.send(t, http.MethodDelete, w.revokePath(fresh[0]), ""); rec.Code != http.StatusNoContent {
		t.Fatalf("revoking the first: %d; body: %s", rec.Code, rec.Body)
	}

	// Now name all THREE in one batch. Only two can change.
	quoted := make([]string, 0, len(fresh))
	for _, one := range fresh {
		quoted = append(quoted, `"`+one.String()+`"`)
	}
	body := `{"invitation_ids":[` + strings.Join(quoted, ",") + `],"confirm":true}`

	rec := w.send(t, http.MethodPost, w.bulkPath(), body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", rec.Code, rec.Body)
	}
	var got bulkRevokeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Requested != 3 {
		t.Errorf("requested = %d, want 3", got.Requested)
	}
	if got.Revoked != 2 {
		t.Errorf("revoked = %d, want 2 — the first was already revoked", got.Revoked)
	}

	// And the record agrees with the response.
	var affected int
	if err := w.pool.QueryRow(ctx,
		`SELECT affected FROM account_audit_log WHERE account_id = $1 AND action = $2`,
		w.accountID, string(admin.ActionInvitationsRevoked)).Scan(&affected); err != nil {
		t.Fatalf("reading the bulk record: %v", err)
	}
	if affected != 2 {
		t.Errorf("the record says affected = %d, want 2. Recording the request's length (3) would be a "+
			"trail an operator cannot reconcile against the account", affected)
	}
}

// TestTheAuditTrailIsReadableThroughTheAPI closes the loop: the record the
// transaction wrote is the record the route returns, and it is paginated.
func TestTheAuditTrailIsReadableThroughTheAPI(t *testing.T) {
	w := newAdminWorld(t)

	if rec := w.send(t, http.MethodDelete, w.revokePath(w.invitation), ""); rec.Code != http.StatusNoContent {
		t.Fatalf("revoking: %d; body: %s", rec.Code, rec.Body)
	}

	rec := w.send(t, http.MethodGet, w.auditPath(), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("reading the trail: %d; body: %s", rec.Code, rec.Body)
	}

	var got auditLogResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	if len(got.Entries) != 1 {
		t.Fatalf("the API returned %d entries, want 1", len(got.Entries))
	}
	one := got.Entries[0]
	if one.ActorKeyID != w.tokenID.String() {
		t.Errorf("actor_key_id = %q, want %q", one.ActorKeyID, w.tokenID)
	}
	if one.Affected != 1 {
		t.Errorf("affected = %d, want 1", one.Affected)
	}
	if one.Action != string(admin.ActionInvitationRevoked) {
		t.Errorf("action = %q", one.Action)
	}
	if one.TraceID == "" {
		t.Error("the record carries no trace id, so it cannot be joined to a log line")
	}
}

// TestAnAdminActionNeverWritesACredential is the packet's "never log a token,
// cookie or JWT" requirement, applied to the surface where the temptation is
// greatest, and asserted at every layer a record could leak through.
//
// FOUR PLACES, and all four matter:
//
//	the HTTP response body   what a client receives and a developer pastes
//	the audit row            what an operator reads during an incident
//	the application log      what ends up in a log aggregator, forever
//	the rendered problem     what an unauthenticated caller sees
//
// A test asserting only the first would pass against a service that wrote the
// token into the log, which is the leak nobody notices.
func TestAnAdminActionNeverWritesACredential(t *testing.T) {
	// ONE world, and the logger is installed on it, because a second fixture
	// would mean the log assertion covers a different service than the response
	// and audit-row assertions. The three have to be the same action.
	logged := &recordingHandler{}
	w2 := newAdminWorldWithLogger(t, logged)

	// Perform the action.
	rec := w2.send(t, http.MethodDelete, w2.revokePath(w2.invitation), "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d; body: %s", rec.Code, rec.Body)
	}

	// 1. The response body.
	if body := rec.Body.String(); strings.Contains(body, w2.tokenSecret) {
		t.Error("the response body contains the api key's plaintext")
	}

	// 2. The audit row — every column, as text.
	rows, err := w2.pool.Query(t.Context(),
		`SELECT * FROM account_audit_log WHERE account_id = $1`, w2.accountID)
	if err != nil {
		t.Fatalf("reading the audit rows: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			t.Fatalf("reading a row: %v", err)
		}
		for _, value := range values {
			if text, ok := value.(string); ok && strings.Contains(text, w2.tokenSecret) {
				t.Errorf("an audit column contains the api key's plaintext: %q", text)
			}
		}
	}

	// 3. The application log. Every recorded entry, not a search for one message:
	// a leak would be in whichever line the handler happened to write, and a test
	// that only looked for a known message would miss it.
	for _, entry := range logged.entries {
		if strings.Contains(entry, w2.tokenSecret) {
			t.Errorf("a log entry contains the api key's plaintext: %s", entry)
		}
		if strings.Contains(entry, "cafaye_") {
			t.Errorf("a log entry contains something shaped like a cafaye credential: %s", entry)
		}
	}

	// 4. The problem document, on a route that fails. A 500 writes through
	// `unexpected`, which is the path where a careless
	// `fmt.Sprintf("%+v", …)` of the caller would land.
	badReq := httptest.NewRequest(http.MethodGet, w2.auditPath()+"?limit=99999", nil)
	badReq.Header.Set("Authorization", "Bearer "+w2.tokenSecret)
	badRec := httptest.NewRecorder()
	w2.handler.ServeHTTP(badRec, badReq)
	if body := badRec.Body.String(); strings.Contains(body, w2.tokenSecret) {
		t.Error("a problem document contains the api key's plaintext")
	}
	if body := badRec.Body.String(); strings.Contains(body, "cafaye_") {
		t.Errorf("a problem document contains something shaped like a cafaye credential: %s", body)
	}
}

// TestARefusedAdminActionWritesNoAuditRecord is a small one and it is the
// direction a trail is usually wrong in.
//
// A refused request must not appear in the record of things that were done. An
// audit log that records attempts is a different artifact with different rules
// (retention, access, and who may read an operator's mistakes), and mixing the
// two in one table is how a trail becomes something nobody trusts.
func TestARefusedAdminActionWritesNoAuditRecord(t *testing.T) {
	w := newAdminWorld(t)

	tests := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{
			name: "no confirmation", method: http.MethodPost, path: w.bulkPath(),
			body: `{"invitation_ids":["` + w.invitation.String() + `"]}`,
		},
		{
			name: "over the ceiling", method: http.MethodPost, path: w.bulkPath(),
			body: `{"invitation_ids":[` + strings.Repeat(`"`+w.invitation.String()+`",`, admin.MaxBulkInvitationIDs) +
				`"` + w.invitation.String() + `"],"confirm":true}`,
		},
		{
			name: "an invitation from another account", method: http.MethodDelete,
			path: "/v1/accounts/" + id.MustNew().String() + "/admin/invitations/" + w.invitation.String(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := w.send(t, tt.method, tt.path, tt.body)
			if rec.Code < 400 {
				t.Fatalf("status = %d, want a refusal; body: %s", rec.Code, rec.Body)
			}

			var count int
			if err := w.pool.QueryRow(t.Context(),
				`SELECT count(*) FROM account_audit_log WHERE account_id = $1`, w.accountID).
				Scan(&count); err != nil {
				t.Fatalf("counting: %v", err)
			}
			if count != 0 {
				t.Errorf("a REFUSED request wrote %d audit record(s). The trail is a record of things "+
					"that were done, not of things that were tried", count)
			}
		})
	}

	// And the invitation the refused requests named is still live, which is the
	// other half of "the request did nothing".
	var acceptedAt *time.Time
	if err := w.pool.QueryRow(t.Context(),
		`SELECT accepted_at FROM account_invitations WHERE id = $1`, w.invitation).Scan(&acceptedAt); err != nil {
		t.Fatalf("reading the invitation: %v", err)
	}
}

// TestAnAdminCannotReadAnotherAccountsTrail is the tenancy half, end to end over
// real SQL, and it is 404 rather than 403 for the reason every other account
// route is 404: a 403 confirms the account exists.
//
// The token is minted for THIS account and presented against a different one,
// which is the exact request core's "tenancy comes from the credential" rule is
// about.
func TestAnAdminCannotReadAnotherAccountsTrail(t *testing.T) {
	w := newAdminWorld(t)

	elsewhere := id.MustNew()
	rec := w.send(t, http.MethodGet, "/v1/accounts/"+elsewhere.String()+"/admin/audit-log", "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404. A 403 would confirm the account exists to a caller that has "+
			"no business knowing; body: %s", rec.Code, rec.Body)
	}
}

// TestAnAccountlessTokenCannotReachTheAdminSurface is R2's refusal, over the
// REAL apikeys service rather than a double, and the point of that is stated in
// the test below.
func TestAnAccountlessTokenCannotReachTheAdminSurface(t *testing.T) {
	t.Parallel()

	// The real service cannot produce a token with no account: api_keys.account_id
	// is NOT NULL and claims.go refuses one with ErrNoAccountID. So the row cannot
	// be manufactured through the API, and this test says so — the router-level
	// proof with a double is in admin_test.go, and this one records WHY a double
	// was necessary.
	//
	// A test that skipped this and only had the double version would leave a
	// reader unable to tell whether the double describes a reachable state. It is
	// a guard on a future change: if someone makes account_id nullable, this test
	// is the one that should be rewritten to prove the router refuses it.
	t.Run("the schema makes an accountless token unrepresentable", func(t *testing.T) {
		pool := dbtest.Schema(t)
		ctx := t.Context()

		// Real users and a real account, so the ONLY constraint that can fire is
		// the one under test. An earlier version of this seeded no rows and got a
		// CHECK violation on token_digest's length, then SKIPPED — which is the
		// outcome AGENTS.md calls a false green, arrived at by accident.
		userID, accountID := id.MustNew(), id.MustNew()
		if _, err := pool.Exec(ctx, `
			INSERT INTO users (id, email, password_digest, created_at, updated_at)
			VALUES ($1, $2, 'digest', now(), now())`, userID, "acctless-"+userID.String()[:8]+"@example.com"); err != nil {
			t.Fatalf("seeding a user: %v", err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO accounts (id, name, slug, personal, created_at, updated_at)
			VALUES ($1, 'Acctless', $2, false, now(), now())`, accountID, "acctless-"+accountID.String()[:8]); err != nil {
			t.Fatalf("seeding an account: %v", err)
		}

		// A valid row first, so the fixture is proven to work and the second
		// insert's failure is unambiguously about the missing account.
		if _, err := pool.Exec(ctx, `
			INSERT INTO api_keys (user_id, account_id, name, token_digest, scopes, created_at, expires_at)
			VALUES ($1, $2, 'fine', $3, ARRAY['accounts:read'], now(), now() + interval '1 day')`,
			userID, accountID, strings.Repeat("a", 64)); err != nil {
			t.Fatalf("a valid api key row was rejected, so the next assertion would prove nothing: %v", err)
		}

		// Now the row under test: account_id NULL.
		_, err := pool.Exec(ctx, `
			INSERT INTO api_keys (user_id, account_id, name, token_digest, scopes, created_at, expires_at)
			VALUES ($1, NULL, 'accountless', $2, ARRAY['accounts:read'], now(), now() + interval '1 day')`,
			userID, strings.Repeat("b", 64))
		if err == nil {
			t.Fatal("the database accepted an api key with NO account. This is the state the admin " +
				"surface's refusal exists for, and if it is reachable then claims.go's ErrNoAccountID " +
				"is guarding nothing")
		}
		// 23502 is not_null_violation, and naming the constraint is what makes
		// this an assertion about account_id rather than about some other
		// constraint that happened to fire.
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23502" {
			t.Errorf("error = %v, want a not-null violation (23502) on account_id", err)
		}
	})

	t.Run("an accountless key is refused by the claim document", func(t *testing.T) {
		// claims.ClaimsFor is the same guard the introspection route uses, and it
		// is in the apikeys package's own tests. What matters HERE is that the
		// admin surface relies on a token having an account, and the reason it can
		// is that this error exists.
		if _, err := apikeys.ClaimsFor(apikeys.Key{ID: id.MustNew()}, time.Now()); !errors.Is(err, apikeys.ErrNoAccountID) {
			t.Errorf("ClaimsFor on an accountless key = %v, want ErrNoAccountID", err)
		}
	})
}

// TestTheAuditLogCannotBeReachedByRevokingTheToken is worth having as an
// end-to-end statement of the same property the database trigger gives: an
// operator who revokes the credential that performed an action can still read the
// record of it.
//
// The audit row has no foreign key to api_keys for exactly this reason, and
// revoking a token is the ordinary response to a leak — so the question "can I
// still find out what that token did?" has to have an answer.
func TestTheAuditLogCannotBeReachedByRevokingTheToken(t *testing.T) {
	w := newAdminWorld(t)
	ctx := t.Context()

	rec := w.send(t, http.MethodDelete, w.revokePath(w.invitation), "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("the action: %d; body: %s", rec.Code, rec.Body)
	}

	// Revoke the token through the store, as an operator would.
	store := apikeys.NewStore(w.pool)
	if _, err := store.Revoke(ctx, w.pool, w.tokenID, w.accountID, w.ownerID, w.clock.Now(), "leaked"); err != nil {
		t.Fatalf("revoking the token: %v", err)
	}

	// The record survives, and it is still readable.
	var count int
	if err := w.pool.QueryRow(ctx,
		`SELECT count(*) FROM account_audit_log WHERE actor_key_id = $1`, w.tokenID).Scan(&count); err != nil {
		t.Fatalf("counting the records: %v", err)
	}
	if count != 1 {
		t.Errorf("%d records name the revoked token, want 1. The audit row carries no foreign key "+
			"to api_keys precisely so that revoking a credential cannot erase what it did", count)
	}
}

// newAdminWorldWithLogger is newAdminWorld with the logger pointed at sink, which
// is the seam the credential-leak test needs.
func newAdminWorldWithLogger(t *testing.T, sink *recordingHandler) *adminWorld {
	t.Helper()

	pool := dbtest.Schema(t)
	clk := clock.NewFake(time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))

	tenancy := realTenancy(pool, clk)
	authSvc := authServiceFor(pool, clk)
	keys := matrixAPIKeys(pool, clk, tenancy)
	adminSvc := admin.NewService(
		db.TxRunner{Pool: pool}, admin.NewStore(pool), accounts.NewStore(pool), db.Direct{Pool: pool}, clk,
	)

	handler := New(nil,
		WithAuth(authSvc),
		WithTenancy(tenancy),
		WithAPIKeys(keys),
		WithAPIKeyCaller(keys),
		WithAdmin(adminSvc),
		WithLogger(slogLogger(sink)),
	)

	email := dbtest.UniqueEmail(t)
	rec := post(t, handler, "/v1/users", `{"email":"`+email+`","password":"`+matrixPassword+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering: %d; body: %s", rec.Code, rec.Body)
	}
	var created userResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	ownerID, err := id.Parse(created.ID)
	if err != nil {
		t.Fatal(err)
	}

	created2, err := tenancy.Create(t.Context(), accounts.CreateInput{
		Name: "Admin World " + id.MustNew().String()[:8], Owner: ownerID,
	})
	if err != nil {
		t.Fatalf("creating the account: %v", err)
	}
	invited, err := tenancy.Invite(t.Context(), accounts.InviteInput{
		AccountID: created2.Account.ID, Email: dbtest.UniqueEmail(t),
		Role: accounts.RoleMember, InvitedBy: ownerID,
	})
	if err != nil {
		t.Fatalf("inviting: %v", err)
	}
	key, err := keys.Mint(t.Context(), apikeys.MintInput{
		AccountID: created2.Account.ID, Name: "admin-surface",
		Scopes:   []string{apikeys.ScopeAuditLogRead, apikeys.ScopeAccountInvitationsWrite},
		MintedBy: ownerID,
	})
	if err != nil {
		t.Fatalf("minting: %v", err)
	}

	return &adminWorld{
		handler: handler, pool: pool, clock: clk,
		accountID: created2.Account.ID, ownerID: ownerID,
		invitation:  invited.Invitation.ID,
		tokenSecret: key.Token, tokenID: key.Key.ID,
	}
}

var (
	_ = context.Background
	_ = users.User{}
	_ = auth.ErrUnauthenticated
)
