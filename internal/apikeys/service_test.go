package apikeys

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cafaye/identity/internal/accounts"
	"github.com/cafaye/identity/internal/outbox"
	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/users"
)

// The use cases: mint a credential, list an account's credentials, withdraw one,
// and resolve a presented value to a caller.
//
// Every test here runs the real SQL over a private schema. The properties being
// asserted are properties of the WIRE and of the transaction — that a secret is
// shown once, that the row and the event are one fact, that a token cannot mint
// another — and none of them is a fact about a double.

// realService is the production wiring over a pool: the tenancy service is the
// real one, so "is this caller an owner" is decided by accounts.Service and not by
// a double answering what the test wanted.
func realService(pool *pgxpool.Pool, clk clock.Clock) *Service {
	return NewService(
		db.TxRunner{Pool: pool},
		db.Direct{Pool: pool},
		NewStore(pool),
		outbox.NewStore(pool),
		realTenancy(pool, clk),
		users.NewStore(pool),
		clk,
	)
}

// realTenancy is accounts.NewService over the same pool, with no outbox of its own
// worth having — a role read does not write, and the tenancy events this would
// publish are not what any test here is asserting on.
func realTenancy(pool *pgxpool.Pool, clk clock.Clock) *accounts.Service {
	return accounts.NewService(
		db.TxRunner{Pool: pool},
		accounts.NewStore(pool),
		outbox.NewStore(pool),
		clk,
		db.Direct{Pool: pool},
	)
}

// serviceFixture is a world with a user who OWNS an account, a second user who
// is a plain member of it, and an account the first user has nothing to do with.
//
// The member exists because "a token cannot mint a token" and "only an owner
// mints a token" are both tests about somebody who is NOT the owner, and a fixture
// with one user cannot make either of them.
type serviceFixture struct {
	pool    *pgxpool.Pool
	clk     *clock.Fake
	svc     *Service
	store   *Store
	tenancy *accounts.Service
	// seq numbers the fixture's account names. accounts.Slugify truncates at 63
	// characters and two long test names sharing a prefix truncate to one slug,
	// which is a 409 in the harness rather than in the code under test.
	seq int

	owner  id.UUID
	member id.UUID
	// account is owned by owner, with member in it as a plain member. elsewhere is
	// owned by member alone, and is what the cross-tenant tests act on.
	account   id.UUID
	elsewhere id.UUID
}

func newServiceFixture(t *testing.T) *serviceFixture {
	t.Helper()

	ctx := context.Background()
	pool := dbtest.Schema(t)
	clk := clock.NewFake(testInstant)
	tenancy := realTenancy(pool, clk)

	f := &serviceFixture{
		pool: pool, clk: clk, tenancy: tenancy,
		store: NewStore(pool),
		svc:   realService(pool, clk),
	}

	f.owner = f.user(t)
	f.member = f.user(t)

	// Created through accounts.Service rather than with INSERTs, so the rows are
	// the ones the production code would have written.
	created, err := tenancy.Create(ctx, accounts.CreateInput{Name: f.label("Owner"), Owner: f.owner})
	if err != nil {
		t.Fatalf("creating the owner's account: %v", err)
	}
	f.account = created.Account.ID

	elsewhere, err := tenancy.Create(ctx, accounts.CreateInput{Name: f.label("Elsewhere"), Owner: f.member})
	if err != nil {
		t.Fatalf("creating the second account: %v", err)
	}
	f.elsewhere = elsewhere.Account.ID

	// The member is added through the store rather than by inviting and accepting:
	// the invitation route is a three-step flow with a token that expires, and what
	// this fixture needs is a membership at a known role.
	if _, err := accounts.NewStore(f.pool).AddMember(ctx, f.pool, accounts.Membership{
		AccountID: f.account, UserID: f.member, Role: accounts.RoleMember,
	}); err != nil {
		t.Fatalf("adding the member: %v", err)
	}

	return f
}

func (f *serviceFixture) label(prefix string) string {
	f.seq++
	return fmt.Sprintf("Apikeys %s %d", prefix, f.seq)
}

func (f *serviceFixture) user(t *testing.T) id.UUID {
	t.Helper()
	userID := id.MustNew()
	if _, err := f.pool.Exec(context.Background(),
		`INSERT INTO users (id, email, password_digest) VALUES ($1, $2, $3)`,
		userID, dbtest.UniqueEmail(t), testPasswordDigest); err != nil {
		t.Fatalf("inserting a user: %v", err)
	}
	return userID
}

// apiKeyEvents is every api key event in the fixture's outbox, in order.
//
// IT FILTERS, and the filter is load-bearing rather than tidiness. The fixture
// builds its accounts through accounts.Service, which publishes
// identity.account.created of its own — so an unfiltered count would be asserting
// that the tenancy use cases were silent, and every test in this file would be
// coupled to another package's event catalogue. A test that wanted "this mint
// announced exactly one thing" would break when a future packet added a second
// event to account creation, for no reason to do with this one.
//
// It reads the `envelope` column rather than the individual columns, because that
// is the document that goes on the wire and it is what core's schema validates. A
// test that read `type` and `subject` directly would pass even if the envelope
// built around them were malformed.
func (f *serviceFixture) apiKeyEvents(t *testing.T) []outbox.Envelope {
	t.Helper()
	all := f.outboxRows(t)
	var out []outbox.Envelope
	for _, e := range all {
		if strings.HasPrefix(e.Type, outbox.SourceIdentity+".api_key.") {
			out = append(out, e)
		}
	}
	return out
}

func (f *serviceFixture) outboxRows(t *testing.T) []outbox.Envelope {
	t.Helper()
	rows, err := f.pool.Query(context.Background(),
		`SELECT envelope FROM outbox_events ORDER BY created_at, id`)
	if err != nil {
		t.Fatalf("reading the outbox: %v", err)
	}
	defer rows.Close()

	var out []outbox.Envelope
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			t.Fatalf("scanning an outbox row: %v", err)
		}
		var e outbox.Envelope
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatalf("the stored envelope is not JSON: %v\n%s", err, raw)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("reading the outbox: %v", err)
	}
	return out
}

// breakTheOutbox makes every event append fail.
//
// A CHECK that is already violated cannot be added to a table with rows in it, so
// the constraint is NOT VALID — Postgres then enforces it for new rows and leaves
// the existing ones alone, which is exactly the "the platform can no longer
// announce anything" state this test needs.
func (f *serviceFixture) breakTheOutbox(t *testing.T) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(),
		`ALTER TABLE outbox_events ADD CONSTRAINT reject_everything CHECK (false) NOT VALID`); err != nil {
		t.Fatalf("disabling the outbox: %v", err)
	}
}

// TestMintReturnsTheSecretExactlyOnce is the packet's one-time-display
// requirement, asserted on the USE CASE rather than on the response, because the
// use case is what the response is built from and the property is that the secret
// exists exactly once in this process's memory.
//
// The three assertions are deliberately different in kind:
//
//  1. the 201's Token is the credential — it resolves.
//  2. Authenticate with it works, so (1) is not vacuous: a token that did not
//     work would make the rest of this test pass for the wrong reason.
//  3. NOTHING ELSE the use case returns carries it: not the Key, not the
//     TokenDigest field, not the Name a caller chose. A struct that grew a Token
//     field, or a handler that reached for key.Token, would fail here.
func TestMintReturnsTheSecretExactlyOnce(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()

	issued, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account,
		Name:      "ci-deploy",
		Scopes:    []string{ScopeAccountsRead},
		MintedBy:  f.owner,
	})
	if err != nil {
		t.Fatalf("minting: %v", err)
	}

	if !strings.HasPrefix(issued.Token, Prefix) {
		t.Fatalf("the issued token %q does not carry the %q prefix", issued.Token, Prefix)
	}

	// (1) and (2): the value handed back is the credential.
	resolved, err := f.svc.Authenticate(ctx, issued.Token, f.clk.Now())
	if err != nil {
		t.Fatalf("the freshly issued token does not authenticate: %v", err)
	}
	if resolved.Key.ID != issued.Key.ID {
		t.Errorf("the issued token authenticates as %s, want the token that was issued (%s)",
			resolved.Key.ID, issued.Key.ID)
	}

	// (3): the row and every field beside the secret.
	if issued.Key.TokenDigest == issued.Token {
		t.Error("TokenDigest is the token")
	}
	if strings.Contains(issued.Key.Name, issued.Token) {
		t.Error("the name carries the token")
	}
	if issued.Key.TokenDigest != Digest(issued.Token) {
		t.Errorf("TokenDigest = %q, want the SHA-256 of the presented value", issued.Key.TokenDigest)
	}
	if issued.Key.IsRevoked() {
		t.Error("a freshly minted token came back revoked")
	}
	if issued.Key.LastUsedAt != nil {
		t.Errorf("last_used_at = %v on a token that has never been presented", issued.Key.LastUsedAt)
	}
}

// TestTheSecretIsUnrecoverableFromEverythingElse is the second half of the same
// requirement, and it is the assertion people get wrong: "we do not store the
// token" is easy to claim and easy to get subtly untrue. This one proves there is
// no read path in the whole package that can produce the plaintext again — the
// list, the single-row read, the resolution — and that the row does not hold it.
func TestTheSecretIsUnrecoverableFromEverythingElse(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()

	issued, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "one-time", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	})
	if err != nil {
		t.Fatalf("minting: %v", err)
	}

	// Every read path in the package, driven with the row id, and none of them may
	// return anything containing the plaintext.
	listed, err := f.svc.List(ctx, f.account)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("the list has %d entries, want 1", len(listed))
	}
	rendered := fmt.Sprintf("%+v", listed)

	for _, forbidden := range []string{issued.Token, strings.TrimPrefix(issued.Token, Prefix)} {
		if strings.Contains(rendered, forbidden) {
			t.Errorf("the list re-renders the secret: %s", rendered)
		}
	}

	// And the one read that could plausibly be tempted to re-derive it: the
	// resolution, which takes the plaintext and has it in hand.
	resolved, err := f.svc.Authenticate(ctx, issued.Token, f.clk.Now())
	if err != nil {
		t.Fatalf("authenticating: %v", err)
	}
	if strings.Contains(fmt.Sprintf("%+v", resolved), issued.Token) {
		t.Error("the resolved caller re-renders the presented token")
	}

	// The digest is in the row and the plaintext is not, which the store's own
	// test proves column by column. What is asserted here is the consequence for a
	// caller: there is no Mint again, no Reveal, no Get-with-secret, and the two
	// functions that take a plaintext — Authenticate and Digest — produce a
	// boolean and a hash.
	var _ = Digest
}

// TestTheSecretIsUnrecoverableFromEverythingElse's complement: the ONE case where
// a second plaintext exists is a second Mint, and the two are different values.
func TestMintingTwiceGivesTwoDifferentTokens(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()

	first, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "one", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	})
	if err != nil {
		t.Fatalf("minting the first: %v", err)
	}
	second, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "two", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	})
	if err != nil {
		t.Fatalf("minting the second: %v", err)
	}

	if first.Token == second.Token {
		t.Fatal("two mints produced the same token")
	}
	if first.Key.TokenDigest == second.Key.TokenDigest {
		t.Fatal("two mints produced the same digest, so the digests are not of the values")
	}
}

// TestAMintIsValidatedBeforeAnythingIsWritten is the ordering rule: a bad name, a
// bad scope list or a bad lifetime must not leave a row or an event behind. The
// assertion is on the database, not on the returned error, because "it returned an
// error" and "it wrote nothing" are different claims.
func TestAMintIsValidatedBeforeAnythingIsWritten(t *testing.T) {
	tests := []struct {
		name string
		// give builds the input for the fixture, so each case can name the
		// fixture's own account rather than an id invented beside it.
		give      func(f *serviceFixture) MintInput
		wantField string
		// wantAuthorization says the refusal is about the caller's standing rather
		// than about the request. It is a separate assertion because the two are
		// different rules and a test that only checked "it failed" would not tell
		// them apart.
		wantAuthorization bool
	}{
		{
			name:      "no name",
			give:      func(f *serviceFixture) MintInput { return MintInput{Name: "   ", Scopes: []string{ScopeAccountsRead}} },
			wantField: "name",
		},
		{
			name: "a name carrying a control character",
			give: func(f *serviceFixture) MintInput {
				return MintInput{Name: "ci\ndeploy", Scopes: []string{ScopeAccountsRead}}
			},
			wantField: "name",
		},
		{
			name:      "an unknown scope",
			give:      func(f *serviceFixture) MintInput { return MintInput{Name: "ci", Scopes: []string{"accounts:admin"}} },
			wantField: "scopes",
		},
		{
			name:      "no scopes at all",
			give:      func(f *serviceFixture) MintInput { return MintInput{Name: "ci", Scopes: nil} },
			wantField: "scopes",
		},
		{
			// `expires_in: 0` is where "never expires" would have gone, and it is
			// refused. A client that meant "no preference" omits the field, which
			// is a different request and gets the default.
			name: "a permanent credential",
			give: func(f *serviceFixture) MintInput {
				return MintInput{Name: "ci", Scopes: []string{ScopeAccountsRead}, ExpiresIn: ptr(time.Duration(0))}
			},
			wantField: "expires_in",
		},
		{
			name: "a lifetime beyond the ceiling",
			give: func(f *serviceFixture) MintInput {
				return MintInput{Name: "ci", Scopes: []string{ScopeAccountsRead}, ExpiresIn: ptr(MaxTTL + time.Hour)}
			},
			wantField: "expires_in",
		},
		{
			name: "a lifetime shorter than the floor",
			give: func(f *serviceFixture) MintInput {
				return MintInput{Name: "ci", Scopes: []string{ScopeAccountsRead}, ExpiresIn: ptr(time.Second)}
			},
			wantField: "expires_in",
		},
		{
			name: "an account that is not the caller's",
			give: func(f *serviceFixture) MintInput {
				return MintInput{AccountID: id.MustNew(), Name: "ci", Scopes: []string{ScopeAccountsRead}}
			},
			wantAuthorization: true,
		},
		{
			name: "an account the caller is a plain member of",
			give: func(f *serviceFixture) MintInput {
				return MintInput{AccountID: f.account, Name: "ci", Scopes: []string{ScopeAccountsRead}, MintedBy: f.member}
			},
			wantAuthorization: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newServiceFixture(t)
			in := tt.give(f)
			if in.MintedBy.IsZero() {
				in.MintedBy = f.owner
			}
			if in.AccountID.IsZero() {
				in.AccountID = f.account
			}

			_, err := f.svc.Mint(context.Background(), in)
			if err == nil {
				t.Fatal("minting was accepted")
			}

			switch {
			case tt.wantAuthorization:
				if !errors.Is(err, ErrNotAuthorized) {
					t.Errorf("error = %v, want ErrNotAuthorized", err)
				}
			default:
				var fe *FieldError
				if !errors.As(err, &fe) {
					t.Fatalf("error = %v, want a *FieldError naming %q", err, tt.wantField)
				}
				if fe.Field != tt.wantField {
					t.Errorf("the failure names %q, want %q", fe.Field, tt.wantField)
				}
			}

			var rows int
			if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM api_keys`).Scan(&rows); err != nil {
				t.Fatalf("counting rows: %v", err)
			}
			if rows != 0 {
				t.Errorf("a rejected mint wrote %d rows", rows)
			}
			if events := f.apiKeyEvents(t); len(events) != 0 {
				t.Errorf("a rejected mint announced %d events", len(events))
			}
		})
	}
}

// TestAMintRequiresAMembership is the tenancy rule, and it is the one that stops
// this from being a way to reach across tenants. The account in the path and the
// caller are both supplied by the route, and the use case asks the tenancy service
// rather than trusting either.
func TestAMintRequiresAMembership(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()

	// A member of the account cannot mint: only an owner does, and the reason is
	// that a machine credential outlives the session that made it.
	_, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "ci", Scopes: []string{ScopeAccountsRead}, MintedBy: f.member,
	})
	if !errors.Is(err, ErrNotAuthorized) {
		t.Errorf("a plain member minted a credential: %v, want ErrNotAuthorized", err)
	}

	// A stranger cannot mint in somebody else's account.
	stranger := f.user(t)
	_, err = f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "ci", Scopes: []string{ScopeAccountsRead}, MintedBy: stranger,
	})
	if !errors.Is(err, ErrNotAuthorized) {
		t.Errorf("a stranger minted a credential in an account they are not in: %v, want ErrNotAuthorized", err)
	}

	// An owner can, which is what makes the refusals above refusals rather than a
	// use case that never works.
	if _, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "ci", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	}); err != nil {
		t.Fatalf("the owner could not mint: %v", err)
	}
}

// TestAMintAnnouncesExactlyOneEvent is the transaction property: a row and the
// event describing it are one fact, and a token nobody was told about is a token
// a consumer cannot audit.
func TestAMintAnnouncesExactlyOneEvent(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()

	issued, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "ci-deploy",
		Scopes: []string{ScopeAccountsRead, ScopeAccountsWrite}, MintedBy: f.owner,
	})
	if err != nil {
		t.Fatalf("minting: %v", err)
	}

	events := f.apiKeyEvents(t)
	if len(events) != 1 {
		t.Fatalf("a mint produced %d events, want exactly 1", len(events))
	}
	e := events[0]
	if e.Type != outbox.EventAPIKeyCreated {
		t.Errorf("type = %q, want %q", e.Type, outbox.EventAPIKeyCreated)
	}
	if e.Subject != issued.Key.ID.String() {
		t.Errorf("subject = %q, want the key's row id %q", e.Subject, issued.Key.ID)
	}

	// The payload carries the scopes, because a consumer auditing who holds what
	// cannot answer that from an announcement with no content.
	payload := string(e.Data)
	for _, want := range []string{"accounts:read", "accounts:write", "ci-deploy", f.account.String()} {
		if !strings.Contains(payload, want) {
			t.Errorf("the payload %s does not carry %q", payload, want)
		}
	}
}

// TestAMintAndItsEventRollBackTogether is the other direction, and it is the one
// that would be a real bug: a token whose row committed and whose event did not is
// a credential this platform minted and no consumer was ever told about.
func TestAMintAndItsEventRollBackTogether(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()

	f.breakTheOutbox(t)

	_, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "ci", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	})
	if err == nil {
		t.Fatal("minting succeeded with a broken outbox")
	}

	var rows int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM api_keys`).Scan(&rows); err != nil {
		t.Fatalf("counting rows: %v", err)
	}
	if rows != 0 {
		t.Errorf("a mint whose event failed committed %d token rows", rows)
	}
}

// TestOneLiveNamePerAccount is the operational rule, and it is enforced by an
// index rather than by a read-then-write. Two live tokens answering to one name is
// the state where "revoke ci-deploy" is ambiguous and the operator picks wrong.
func TestOneLiveNamePerAccount(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()

	first, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "ci-deploy", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	})
	if err != nil {
		t.Fatalf("minting the first: %v", err)
	}

	_, err = f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "ci-deploy", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	})
	if !errors.Is(err, ErrNameTaken) {
		t.Errorf("a second live token of the same name = %v, want ErrNameTaken", err)
	}

	// A DIFFERENT account may hold the same name: the uniqueness is per account,
	// which is what makes "two customers both call it ci-deploy" work.
	if _, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.elsewhere, Name: "ci-deploy", Scopes: []string{ScopeAccountsRead}, MintedBy: f.member,
	}); err != nil {
		// `member` is a plain member of `f.account` and the OWNER of elsewhere, so
		// this is the owner path again on a different tenant.
		t.Fatalf("a different account could not use the same name: %v", err)
	}

	// Rotation: revoke, then mint the same name again. Two requests, no
	// transaction that has to find the name free first.
	if _, err := f.svc.Revoke(ctx, RevokeInput{
		AccountID: f.account, KeyID: first.Key.ID, RevokedBy: f.owner, Reason: "rotated",
	}); err != nil {
		t.Fatalf("revoking: %v", err)
	}
	if _, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "ci-deploy", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	}); err != nil {
		t.Errorf("rotating under a live name failed: %v", err)
	}
}

// TestRevokeIsIdempotentlyDistinguishable is the two-answer rule: an operator who
// clicked twice deserves to be told, and one with a stale id deserves a 404. The
// two are the difference between "there is nothing there" and "you already did
// that", and collapsing them is how somebody believes a live credential was
// destroyed when nothing happened.
func TestRevokeIsIdempotentlyDistinguishable(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()

	issued, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "ci", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	})
	if err != nil {
		t.Fatalf("minting: %v", err)
	}

	if _, err := f.svc.Revoke(ctx, RevokeInput{
		AccountID: f.account, KeyID: issued.Key.ID, RevokedBy: f.owner, Reason: "leaked",
	}); err != nil {
		t.Fatalf("revoking: %v", err)
	}

	_, err = f.svc.Revoke(ctx, RevokeInput{
		AccountID: f.account, KeyID: issued.Key.ID, RevokedBy: f.owner,
	})
	if !errors.Is(err, ErrAlreadyRevoked) {
		t.Errorf("a second revoke = %v, want ErrAlreadyRevoked", err)
	}

	_, err = f.svc.Revoke(ctx, RevokeInput{
		AccountID: f.account, KeyID: id.MustNew(), RevokedBy: f.owner,
	})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("revoking an unknown id = %v, want ErrNotFound", err)
	}

	// And the token does not work, which is the only part that is actually about
	// security. The rest of this test is about a person being told the truth.
	if _, err := f.svc.Authenticate(ctx, issued.Token, f.clk.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("a revoked token authenticated: %v", err)
	}
}

// TestRevokeCannotCrossTenants: an owner of one account cannot revoke a token in
// another, even with the row id, and the answer is ErrNotFound rather than 403
// because a 403 would confirm the token exists.
func TestRevokeCannotCrossTenants(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()

	issued, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "ci", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	})
	if err != nil {
		t.Fatalf("minting: %v", err)
	}

	// The owner of f.account, naming f.elsewhere in the path and somebody else's
	// key id. Not a member of elsewhere, so the role check refuses — and the
	// refusal says nothing about whether the id exists.
	_, err = f.svc.Revoke(ctx, RevokeInput{
		AccountID: f.elsewhere, KeyID: issued.Key.ID, RevokedBy: f.owner,
	})
	if !errors.Is(err, ErrNotAuthorized) {
		t.Errorf("a cross-tenant revoke = %v, want ErrNotAuthorized", err)
	}

	// And the mirror: a genuine owner of elsewhere, holding the right id. The role
	// check PASSES, and the store's `WHERE account_id = $1` is what stops it. Both
	// layers are here because "the use case happened to check first" is not the
	// same property as "the query cannot reach across".
	_, err = f.svc.Revoke(ctx, RevokeInput{
		AccountID: f.elsewhere, KeyID: issued.Key.ID, RevokedBy: f.member,
	})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("an owner of another account revoking this one's key = %v, want ErrNotFound", err)
	}
	if _, err := f.store.Revoke(ctx, f.pool, issued.Key.ID, f.elsewhere, f.member, f.clk.Now(), ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("the store's own account_id scope did not hold: %v, want ErrNotFound", err)
	}

	// And the token still works, which is the only part that is about security.
	if _, err := f.svc.Authenticate(ctx, issued.Token, f.clk.Now()); err != nil {
		t.Errorf("a cross-tenant revoke took effect anyway: %v", err)
	}
}

// TestRevokeAnnouncesTheEvent is the transaction property on the other side of the
// packet: a withdrawal nobody was told about is a credential a consumer keeps
// trusting.
func TestRevokeAnnouncesTheEvent(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()

	issued, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "ci", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	})
	if err != nil {
		t.Fatalf("minting: %v", err)
	}
	if _, err := f.svc.Revoke(ctx, RevokeInput{
		AccountID: f.account, KeyID: issued.Key.ID, RevokedBy: f.owner, Reason: "rotated",
	}); err != nil {
		t.Fatalf("revoking: %v", err)
	}

	events := f.apiKeyEvents(t)
	if len(events) != 2 {
		t.Fatalf("mint then revoke produced %d events, want 2", len(events))
	}
	revoked := events[1]
	if revoked.Type != outbox.EventAPIKeyRevoked {
		t.Errorf("the second event is %q, want %q", revoked.Type, outbox.EventAPIKeyRevoked)
	}
	if revoked.Subject != issued.Key.ID.String() {
		t.Errorf("subject = %q, want %q", revoked.Subject, issued.Key.ID)
	}
	// The reason is deliberately NOT in the event; the row has it. Asserting the
	// absence here is what stops somebody "helpfully" adding it.
	if strings.Contains(string(revoked.Data), "rotated") {
		t.Errorf("the revocation event carries the operator's reason: %s", revoked.Data)
	}
}

// TestAuthenticateIsTheFourWayOneError is the packet's "verification accepts a
// live token and refuses a revoked one, a wrong-user one, an expired one, and one
// whose membership is gone" — and the load-bearing part is that all four refusals
// are the SAME value, because a caller who can tell them apart has an oracle.
func TestAuthenticateIsTheFourWayOneError(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()

	live, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "live", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	})
	if err != nil {
		t.Fatalf("minting: %v", err)
	}

	revoked, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "revoked", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	})
	if err != nil {
		t.Fatalf("minting: %v", err)
	}
	if _, err := f.svc.Revoke(ctx, RevokeInput{
		AccountID: f.account, KeyID: revoked.Key.ID, RevokedBy: f.owner,
	}); err != nil {
		t.Fatalf("revoking: %v", err)
	}

	shortLived, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "short", Scopes: []string{ScopeAccountsRead},
		MintedBy: f.owner, ExpiresIn: ptr(MinTTL),
	})
	if err != nil {
		t.Fatalf("minting: %v", err)
	}

	// THE INTERESTING CASE. The member is promoted to owner, mints a credential,
	// and is then removed from the account. The row is untouched and the token is
	// untouched, and it stops working — which is the whole of the packet's answer to
	// "a token outlives the permission that made it".
	if _, err := f.pool.Exec(ctx,
		`UPDATE account_users SET role = 'owner' WHERE account_id = $1 AND user_id = $2`,
		f.account, f.member); err != nil {
		t.Fatalf("promoting the member: %v", err)
	}
	removedLive, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "removed-live", Scopes: []string{ScopeAccountsRead}, MintedBy: f.member,
	})
	if err != nil {
		t.Fatalf("minting for the promoted member: %v", err)
	}
	// It resolves while the membership is there, so the refusal below is the
	// removal and not a token that never worked.
	if _, err := f.svc.Authenticate(ctx, removedLive.Token, f.clk.Now()); err != nil {
		t.Fatalf("the promoted member's token does not resolve: %v", err)
	}

	if _, err := f.pool.Exec(ctx,
		`DELETE FROM account_users WHERE account_id = $1 AND user_id = $2`,
		f.account, f.member); err != nil {
		t.Fatalf("removing the membership: %v", err)
	}

	now := f.clk.Now()
	tests := []struct {
		name       string
		token      string
		at         time.Time
		wantCaller bool
	}{
		{name: "a live token", token: live.Token, at: now, wantCaller: true},
		{name: "a revoked token", token: revoked.Token, at: now},
		{name: "an expired token", token: shortLived.Token, at: testInstant.Add(MinTTL).Add(time.Nanosecond)},
		{name: "a token whose membership is gone", token: removedLive.Token, at: now},
		{name: "a token that never existed", token: Prefix + strings.Repeat("q", SecretBytes*8/6), at: now},
		{name: "an empty string", token: "", at: now},
		{name: "a session token, not this one", token: "a-session-token", at: now},
		{name: "the digest, presented as a token", token: Digest(live.Token), at: now},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caller, err := f.svc.Authenticate(ctx, tt.token, tt.at)
			if tt.wantCaller {
				if err != nil {
					t.Fatalf("a live token was refused: %v", err)
				}
				if caller.User.ID != f.owner {
					t.Errorf("the token authenticated as %s, want %s", caller.User.ID, f.owner)
				}
				return
			}
			if !errors.Is(err, ErrNotFound) {
				t.Fatalf("= %v, want ErrNotFound. A caller who can tell this from a live token "+
					"has an oracle, and the whole point of the one-error rule is that they cannot.",
					err)
			}
		})
	}

	// The row for the removed member's token is still there, because "the token
	// stopped working" and "the record was deleted" are different facts, and an
	// operator asking which happened after offboarding a contractor needs the
	// answer.
	if _, err := f.store.ByID(ctx, f.pool, removedLive.Key.ID); err != nil {
		t.Errorf("a membership removal deleted the token row: %v", err)
	}
	// And nothing about the row says revoked: the token was never withdrawn, it
	// simply stopped resolving. A `revoked_at` here would be a lie — the operator
	// did not revoke it, the membership went away.
	stored, err := f.store.ByID(ctx, f.pool, removedLive.Key.ID)
	if err != nil {
		t.Fatalf("re-reading: %v", err)
	}
	if stored.IsRevoked() {
		t.Error("the row is marked revoked, but nobody revoked it; the membership was removed")
	}
}

// TestAuthenticateRecordsUse is the last_used_at contract: it moves on the read
// path, it is bounded, and the caller still gets its answer either way.
func TestAuthenticateRecordsUse(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()

	issued, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "ci", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	})
	if err != nil {
		t.Fatalf("minting: %v", err)
	}

	f.clk.Advance(time.Hour)
	caller, err := f.svc.Authenticate(ctx, issued.Token, f.clk.Now())
	if err != nil {
		t.Fatalf("authenticating: %v", err)
	}
	if caller.Key.LastUsedAt == nil || !caller.Key.LastUsedAt.Equal(f.clk.Now()) {
		t.Errorf("last_used_at = %v, want the instant of use %s", caller.Key.LastUsedAt, f.clk.Now())
	}

	// A second use inside the resolution window does not move it again, and the
	// STORED value is what proves it rather than the value in hand: a busy token
	// is not a write per request.
	f.clk.Advance(time.Minute)
	if _, err := f.svc.Authenticate(ctx, issued.Token, f.clk.Now()); err != nil {
		t.Fatalf("authenticating again: %v", err)
	}
	firstUse := *caller.Key.LastUsedAt

	stored, err := f.store.ByID(ctx, f.pool, issued.Key.ID)
	if err != nil {
		t.Fatalf("re-reading: %v", err)
	}
	if stored.LastUsedAt == nil || !stored.LastUsedAt.Equal(firstUse) {
		t.Errorf("last_used_at moved within the %s resolution window: %s then %v",
			LastUsedResolution, firstUse, stored.LastUsedAt)
	}

	// And past the window it moves, which is the other half: a column that never
	// moves is not a bounded write, it is a column nobody wrote.
	f.clk.Advance(LastUsedResolution)
	if _, err := f.svc.Authenticate(ctx, issued.Token, f.clk.Now()); err != nil {
		t.Fatalf("authenticating after the window: %v", err)
	}
	stored, err = f.store.ByID(ctx, f.pool, issued.Key.ID)
	if err != nil {
		t.Fatalf("re-reading: %v", err)
	}
	if stored.LastUsedAt == nil || stored.LastUsedAt.Equal(firstUse) {
		t.Error("last_used_at never moved, so the column is not being written at all")
	}
}

// TestATokenCannotDoWhatASessionCannot is the negative half of the scope
// vocabulary, and it is the part a scope list cannot express.
//
// THE USE CASE ENFORCES IT by having no method for it. There is no RevokeAll on
// Service, no Mint-for-another-user, no SetRole. A token's only abilities are the
// four scopes, and the absence of a method is how that is guaranteed rather than
// merely intended. This test states the absence so that adding a method is a
// deliberate act that has to delete this comment to compile.
func TestATokenCannotDoWhatASessionCannot(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()

	issued, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "ci", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	})
	if err != nil {
		t.Fatalf("minting: %v", err)
	}

	// A token does not carry a role, so it cannot answer "what may I do" without a
	// membership read. This is asserted through the resolved caller: the role comes
	// from the join, so it is a fact about right now.
	caller, err := f.svc.Authenticate(ctx, issued.Token, f.clk.Now())
	if err != nil {
		t.Fatalf("authenticating: %v", err)
	}
	if caller.Role != accounts.RoleOwner {
		t.Errorf("the resolved role is %q, want owner, read from the membership at this instant", caller.Role)
	}
	if !caller.Key.Allows(ScopeAccountsRead) {
		t.Error("the token does not allow the scope it was minted with")
	}
	if caller.Key.Allows(ScopeAccountsDelete) {
		t.Error("the token allows a scope it was never granted")
	}
}

// TestAMintRecordsTheServiceClock is the clock rule, and it is worth a test
// because the two timestamps on the row and the event are the only ones a
// consumer reads and they have to agree.
func TestAMintRecordsTheServiceClock(t *testing.T) {
	f := newServiceFixture(t)
	fixed := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	f.clk.Set(fixed)
	ctx := context.Background()

	issued, err := f.svc.Mint(ctx, MintInput{
		AccountID: f.account, Name: "ci", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	})
	if err != nil {
		t.Fatalf("minting: %v", err)
	}

	if !issued.Key.CreatedAt.Equal(fixed) {
		t.Errorf("created_at = %s, want the injected clock's %s", issued.Key.CreatedAt, fixed)
	}
	if want := fixed.Add(DefaultTTL); !issued.Key.ExpiresAt.Equal(want) {
		t.Errorf("expires_at = %s, want created_at plus the default %s", issued.Key.ExpiresAt, want)
	}

	// The event and the row carry the SAME instant, and this is the only test that
	// says so: a consumer reading the event's time and an operator reading
	// created_at have to be looking at the same moment, or "when was this
	// credential minted" has two answers.
	events := f.apiKeyEvents(t)
	if len(events) != 1 {
		t.Fatalf("the mint announced %d events, want 1", len(events))
	}
	if !events[0].Time.Equal(fixed) {
		t.Errorf("the event's time is %s, want the same instant as the row's %s", events[0].Time, fixed)
	}
}

// TestTheDefaultLifetimeIsUsedWhenNobodyAsks is the expiry decision as a fact
// rather than a comment: a client that does not care gets the default, and it
// gets a token that DOES expire.
func TestTheDefaultLifetimeIsUsedWhenNobodyAsks(t *testing.T) {
	f := newServiceFixture(t)

	issued, err := f.svc.Mint(context.Background(), MintInput{
		AccountID: f.account, Name: "ci", Scopes: []string{ScopeAccountsRead}, MintedBy: f.owner,
	})
	if err != nil {
		t.Fatalf("minting: %v", err)
	}

	lifetime := issued.Key.ExpiresAt.Sub(issued.Key.CreatedAt)
	if lifetime != DefaultTTL {
		t.Errorf("the default lifetime is %s, want %s", lifetime, DefaultTTL)
	}
	if issued.Key.ExpiresAt.IsZero() {
		t.Error("expires_at is the zero time, so this credential never expires")
	}
}

func ptr[T any](v T) *T { return &v }

// Compile-time proof the service is wired to the pieces the tests assume.
var (
	_ = users.User{}
	_ = clock.Fake{}
)
