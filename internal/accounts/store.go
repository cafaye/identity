package accounts

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
)

// Postgres SQLSTATE 23505, unique_violation. Every mapping in this file is off
// that one code, and each maps it only for the statement where it is the
// obvious cause — see the comment on each isX method.
const uniqueViolation = "23505"

// errNoRows is pgx's "the query matched nothing", aliased so the intent reads at
// the call site.
var errNoRows = pgx.ErrNoRows

// InvitationTTL is how long an invitation stays redeemable.
//
// Seven days is the packet's number. It is a balance rather than a
// consideration: long enough that somebody invited on Monday finds the link on
// Wednesday, short enough that a link forwarded to an address list in March is
// dead before somebody clicks it.
const InvitationTTL = 7 * 24 * time.Hour

// tokenBytes is the entropy of an invitation token: 32 bytes, 256 bits, the same
// as a session token and for the same reason.
const tokenBytes = 32

// NewToken mints an invitation token and the digest stored in its place.
//
// The pair is returned rather than a struct with a Token field because the two
// go in opposite directions: the token reaches the client exactly once, in the
// 201 body, and the digest goes into the row and is never rendered. See
// sessions.NewToken, which says the same thing about the same shape.
func NewToken() (token, digest string, err error) {
	raw := make([]byte, tokenBytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		// A failure of crypto/rand means there is no trustworthy entropy, and
		// minting a credential from a degraded source is not something to
		// discover later.
		return "", "", fmt.Errorf("reading random bytes for an invitation token: %w", err)
	}

	token = base64.RawURLEncoding.EncodeToString(raw)

	return token, Digest(token), nil
}

// Digest is the value stored in account_invitations.token_digest: the lower-case
// hex SHA-256 of the presented token.
//
// SHA-256 rather than argon2id, unlike the password column, and for the reason
// sessions.Digest gives: argon2id exists to make *guessing* expensive, and a
// 256-bit random token has no guessable structure. A memory-hard hash would cost
// tens of milliseconds per redemption and buy nothing. The rule that matters on
// both columns is that the presented value is never stored.
func Digest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// CreateParams is the input to Store.Create.
//
// Slug is passed in rather than derived here, because deriving it is a decision
// with two answers: a caller-chosen name slugs to Slugify(name), and a
// registration's personal account slugs from a user id (see PersonalSlug). The
// store stores what it is told and lets the CHECK constraints say no.
type CreateParams struct {
	Name     string
	Slug     string
	Personal bool
}

// NewInvitation is the input to Store.CreateInvitation. It carries the digest
// and never the token, so the raw credential cannot be written by accident from
// here.
type NewInvitation struct {
	AccountID   id.UUID
	Email       string
	Role        Role
	TokenDigest string
	ExpiresAt   time.Time
	InvitedBy   id.UUID
}

// MemberSummary is an account paired with a membership in it.
//
// It exists because both list endpoints need exactly that and neither can get it
// from the accounts table alone: accounts has no role, account_users has no name.
// Returning the pair from one query is what keeps "list my accounts" from being
// an N+1.
//
// UserID and JoinedAt name WHICH membership, and they were added when packet
// identity-28 documented this surface. The struct was written for `ListMine` —
// "which accounts does this user belong to" — where the user is the caller and
// the account is the answer, so the user id is redundant. `Members` reuses it
// for the other direction, and there it is the whole content: a member list of
// entries carrying no user id is a list nothing can be acted on, because
// `PATCH` and `DELETE /v1/accounts/{account_id}/members/{user_id}` both need
// one. Carried on the shared struct rather than a second type so a future caller
// of either query cannot reach the anonymous shape by accident.
type MemberSummary struct {
	Account Account
	Role    Role
	// UserID is who holds Role. For `ListMine` it is the caller, every time.
	UserID id.UUID
	// JoinedAt is when that membership was created — NOT the account's, which is
	// on Account.CreatedAt and is a different fact. The two are both called
	// `created_at` on their own rows and mixing them up is a plausible bug.
	JoinedAt time.Time
}

// Store is the accounts, account_users and account_invitations tables.
type Store struct {
	pool db.Pool
}

// NewStore returns a Store backed by pool.
func NewStore(pool db.Pool) *Store { return &Store{pool: pool} }

// accountColumns is the select list, in the order scanAccount expects. One
// constant, so a column added here cannot be forgotten in one query and present
// in another.
const accountColumns = `id, name, slug, personal, created_at, updated_at`

const membershipColumns = `account_id, user_id, role, created_at, updated_at`

const invitationColumns = `id, account_id, email, role, token_digest, expires_at, accepted_at, invited_by, created_at, updated_at`

// membersSelectList is the accounts column list qualified with the `a` alias plus
// the membership's own three columns, for the two statements that join
// account_users to accounts.
//
// It is a var rather than a const because it is built from prefixed() at run
// time: the point of the helper is that a column added to accountColumns cannot
// be forgotten here, and a constant cannot call a function.
//
// The three are qualified rather than taken from membershipColumns, because that
// list opens with `account_id` and this query already has the account's own
// columns — selecting it twice under two names is how a scan ends up reading one
// row's account_id into another's.
var membersSelectList = prefixed("a", accountColumns) + `, au.role, au.user_id, au.created_at`

// Create inserts an account and returns the stored row.
//
// q is a db.Querier rather than the pool so the caller decides the transaction
// boundary: a registration writes a user, an account, a membership and two
// events, and those are one transaction or nothing. See internal/auth.
func (s *Store) Create(ctx context.Context, q db.Querier, p CreateParams) (Account, error) {
	const query = `
		INSERT INTO accounts (name, slug, personal)
		VALUES ($1, $2, $3)
		RETURNING ` + accountColumns

	row := q.QueryRow(ctx, query, p.Name, p.Slug, p.Personal)

	var a Account
	if err := row.Scan(&a.ID, &a.Name, &a.Slug, &a.Personal, &a.CreatedAt, &a.UpdatedAt); err != nil {
		if isUniqueViolation(err) {
			return Account{}, ErrSlugTaken
		}
		return Account{}, fmt.Errorf("inserting an account: %w", err)
	}
	return a, nil
}

// ByID looks an account up by primary key. The zero id is rejected before the
// query runs: it is not a value any row can have, and a lookup that treated it
// as a wildcard would hand out an arbitrary account.
func (s *Store) ByID(ctx context.Context, q db.Querier, want id.UUID) (Account, error) {
	if want.IsZero() {
		return Account{}, ErrNotFound
	}

	const query = `SELECT ` + accountColumns + ` FROM accounts WHERE id = $1`

	row := q.QueryRow(ctx, query, want)

	var a Account
	if err := row.Scan(&a.ID, &a.Name, &a.Slug, &a.Personal, &a.CreatedAt, &a.UpdatedAt); err != nil {
		if errors.Is(err, errNoRows) {
			return Account{}, ErrNotFound
		}
		return Account{}, fmt.Errorf("scanning an account: %w", err)
	}
	return a, nil
}

// Rename changes an account's name.
//
// The slug is NOT updated, and that is the whole design of accounts.Account.Slug
// rather than an omission: a slug is a handle that goes into logs, emails and a
// future hostname, and one that moved would break every link already sent. A
// rename is therefore never a slug collision, which is why a 409 on rename is
// impossible and why the store does not map one.
func (s *Store) Rename(ctx context.Context, q db.Querier, accountID id.UUID, name string) (Account, error) {
	if accountID.IsZero() {
		return Account{}, ErrNotFound
	}

	const query = `
		UPDATE accounts
		SET name = $2, updated_at = now()
		WHERE id = $1
		RETURNING ` + accountColumns

	row := q.QueryRow(ctx, query, accountID, name)

	var a Account
	if err := row.Scan(&a.ID, &a.Name, &a.Slug, &a.Personal, &a.CreatedAt, &a.UpdatedAt); err != nil {
		if errors.Is(err, errNoRows) {
			return Account{}, ErrNotFound
		}
		return Account{}, fmt.Errorf("renaming an account: %w", err)
	}
	return a, nil
}

// Delete removes an account. Its memberships and invitations go with it through
// the ON DELETE CASCADE declared in 00006 and 00007.
func (s *Store) Delete(ctx context.Context, q db.Querier, accountID id.UUID) error {
	if accountID.IsZero() {
		return ErrNotFound
	}

	tag, err := q.Exec(ctx, `DELETE FROM accounts WHERE id = $1`, accountID)
	if err != nil {
		return fmt.Errorf("deleting an account: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// AddMember creates a membership.
func (s *Store) AddMember(ctx context.Context, q db.Querier, m Membership) (Membership, error) {
	const query = `
		INSERT INTO account_users (account_id, user_id, role)
		VALUES ($1, $2, $3)
		RETURNING ` + membershipColumns

	row := q.QueryRow(ctx, query, m.AccountID, m.UserID, m.Role)

	out, err := scanMembership(row)
	if err != nil {
		// The primary key is the only unique constraint on this table, so a 23505
		// here can only mean the membership already exists.
		if isUniqueViolation(err) {
			return Membership{}, ErrAlreadyAMember
		}
		return Membership{}, err
	}
	return out, nil
}

// Member returns one user's membership in one account.
//
// A miss is ErrNotAMember rather than ErrNotFound, and the distinction is the
// point: the HTTP layer renders ErrNotAMember as 404 for a caller who is not in
// the account, because a 403 would confirm the account exists to somebody who
// has no business knowing. The two sentinels exist so that *this* package can
// tell the cases apart and the HTTP layer can decide which to say out loud.
func (s *Store) Member(ctx context.Context, q db.Querier, accountID, userID id.UUID) (Membership, error) {
	if accountID.IsZero() {
		return Membership{}, ErrNotAMember
	}

	const query = `SELECT ` + membershipColumns + ` FROM account_users WHERE account_id = $1 AND user_id = $2`

	m, err := scanMembership(q.QueryRow(ctx, query, accountID, userID))
	if err != nil {
		if errors.Is(err, errNoRows) {
			return Membership{}, ErrNotAMember
		}
		return Membership{}, fmt.Errorf("scanning a membership: %w", err)
	}
	return m, nil
}

// Members lists an account's memberships, newest first.
//
// The order is by created_at then user_id so it is total: a batch of rows
// written in one transaction shares a timestamp, and a list whose order wobbles
// between two identical requests is a list a client cannot paginate.
func (s *Store) Members(ctx context.Context, q db.Querier, accountID id.UUID) ([]MemberSummary, error) {
	if accountID.IsZero() {
		return []MemberSummary{}, nil
	}

	query := `
		SELECT ` + membersSelectList + `
		FROM accounts a
		JOIN account_users au ON au.account_id = a.id
		WHERE a.id = $1
		ORDER BY au.created_at DESC, au.user_id`

	rows, err := q.Query(ctx, query, accountID)
	if err != nil {
		return nil, fmt.Errorf("listing members: %w", err)
	}
	defer rows.Close()

	out := make([]MemberSummary, 0, 8)
	for rows.Next() {
		var (
			m   MemberSummary
			a   Account
			err error
		)
		if err = rows.Scan(&a.ID, &a.Name, &a.Slug, &a.Personal, &a.CreatedAt, &a.UpdatedAt, &m.Role, &m.UserID, &m.JoinedAt); err != nil {
			return nil, fmt.Errorf("scanning a member: %w", err)
		}
		m.Account = a
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading the member list: %w", err)
	}
	return out, nil
}

// CountOwners is how many users hold RoleOwner in an account.
//
// It exists for the last-owner check, and the check calls it inside the
// transaction that changes the role — see Service.ChangeRole. Counting separately
// from the update is what would make two concurrent demotions both succeed; the
// row lock that Service takes is what stops that, and this is the value it reads
// while holding it.
func (s *Store) CountOwners(ctx context.Context, q db.Querier, accountID id.UUID) (int, error) {
	if accountID.IsZero() {
		return 0, nil
	}

	// The subquery with FOR UPDATE is what takes the lock on the owner rows.
	// Without it the count is a plain read and the check is advisory.
	const query = `
		SELECT count(*)
		FROM (SELECT user_id FROM account_users WHERE account_id = $1 AND role = 'owner' FOR UPDATE) AS owners`

	var n int
	if err := q.QueryRow(ctx, query, accountID).Scan(&n); err != nil {
		return 0, fmt.Errorf("counting owners: %w", err)
	}
	return n, nil
}

// SetRole changes a membership's role.
func (s *Store) SetRole(ctx context.Context, q db.Querier, accountID, userID id.UUID, role Role) (Membership, error) {
	const query = `
		UPDATE account_users
		SET role = $3, updated_at = now()
		WHERE account_id = $1 AND user_id = $2
		RETURNING ` + membershipColumns

	m, err := scanMembership(q.QueryRow(ctx, query, accountID, userID, role))
	if err != nil {
		if errors.Is(err, errNoRows) {
			return Membership{}, ErrNotAMember
		}
		return Membership{}, fmt.Errorf("setting a membership's role: %w", err)
	}
	return m, nil
}

// RemoveMember deletes a membership.
func (s *Store) RemoveMember(ctx context.Context, q db.Querier, accountID, userID id.UUID) error {
	tag, err := q.Exec(ctx,
		`DELETE FROM account_users WHERE account_id = $1 AND user_id = $2`,
		accountID, userID)
	if err != nil {
		return fmt.Errorf("removing a membership: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotAMember
	}
	return nil
}

// ListForUser returns every account a user belongs to, with their role in each.
//
// Ordered personal first, then name — the order a sidebar wants, and the same
// one jumpstart's `sorted` scope produces. The slice is never nil, so a JSON
// encoder renders `[]` rather than `null` for a user with no accounts.
func (s *Store) ListForUser(ctx context.Context, q db.Querier, userID id.UUID) ([]MemberSummary, error) {
	out := make([]MemberSummary, 0, 4)
	if userID.IsZero() {
		return out, nil
	}

	query := `
		SELECT ` + membersSelectList + `
		FROM account_users au
		JOIN accounts a ON a.id = au.account_id
		WHERE au.user_id = $1
		ORDER BY a.personal DESC, a.name ASC, a.id ASC`

	rows, err := q.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("listing a user's accounts: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			m MemberSummary
			a Account
		)
		if err := rows.Scan(&a.ID, &a.Name, &a.Slug, &a.Personal, &a.CreatedAt, &a.UpdatedAt, &m.Role, &m.UserID, &m.JoinedAt); err != nil {
			return nil, fmt.Errorf("scanning an account: %w", err)
		}
		m.Account = a
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading the account list: %w", err)
	}
	return out, nil
}

// CreateInvitation inserts a pending invitation.
//
// The partial unique index on (account_id) WHERE accepted_at IS NULL means a
// second pending invitation for the same address is a 23505 here, and the store
// maps it to ErrInvitationEmailTaken so the handler can answer 409. The mapping
// is scoped to this statement on purpose: a 23505 on account_invitations can
// only be that index, because token_digest's is a 256-bit collision and the id
// is generated.
func (s *Store) CreateInvitation(ctx context.Context, q db.Querier, n NewInvitation) (Invitation, error) {
	const query = `
		INSERT INTO account_invitations (account_id, email, role, token_digest, expires_at, invited_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING ` + invitationColumns

	row := q.QueryRow(ctx, query, n.AccountID, n.Email, n.Role, n.TokenDigest, n.ExpiresAt, n.InvitedBy)

	inv, err := scanInvitation(row)
	if err != nil {
		if isUniqueViolation(err) {
			return Invitation{}, ErrInvitationEmailTaken
		}
		return Invitation{}, err
	}
	return inv, nil
}

// InvitationByToken looks an invitation up by its stored digest.
//
// A miss is ErrInvitationNotFound and covers a wrong token, an unknown token and
// a malformed one identically. The caller then decides whether the row it found
// has expired or was already used — that distinction needs a row, and a caller
// with no row learns nothing either way.
func (s *Store) InvitationByToken(ctx context.Context, q db.Querier, digest string) (Invitation, error) {
	if digest == "" {
		return Invitation{}, ErrInvitationNotFound
	}

	const query = `SELECT ` + invitationColumns + ` FROM account_invitations WHERE token_digest = $1`

	inv, err := scanInvitation(q.QueryRow(ctx, query, digest))
	if err != nil {
		if errors.Is(err, errNoRows) {
			return Invitation{}, ErrInvitationNotFound
		}
		return Invitation{}, fmt.Errorf("scanning an invitation: %w", err)
	}
	return inv, nil
}

// MarkInvitationAccepted stamps accepted_at.
//
// It is the second half of a redemption and it is conditional: the WHERE clause
// requires accepted_at IS NULL, so a second redemption of the same token updates
// zero rows and reports ErrInvitationUsed rather than overwriting the first
// acceptance time. That is the whole reason this is not a plain UPDATE — an
// unconditional one would let two concurrent redemptions both report success and
// produce two memberships, or one membership and two "accepted" answers.
func (s *Store) MarkInvitationAccepted(ctx context.Context, q db.Querier, invitationID id.UUID, at time.Time) error {
	if invitationID.IsZero() {
		return ErrInvitationNotFound
	}

	tag, err := q.Exec(ctx,
		`UPDATE account_invitations SET accepted_at = $2, updated_at = now()
		 WHERE id = $1 AND accepted_at IS NULL`,
		invitationID, at)
	if err != nil {
		return fmt.Errorf("marking an invitation accepted: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Either the invitation is gone or somebody else got there first. Both
		// mean this redemption did not happen.
		return ErrInvitationUsed
	}
	return nil
}

// RevokePendingInvitation stamps revoked_at on one pending invitation.
//
// IT IS CONDITIONAL, and every clause in the WHERE is load-bearing:
//
//	id              the invitation named
//	account_id      THIS account — the tenancy check, and the reason a caller
//	                cannot revoke an invitation belonging to somebody else even
//	                having guessed its id
//	accepted_at IS NULL   a redeemed invitation is not a pending one, and
//	                revoking it would be a lie: the membership already exists and
//	                the row says so
//	revoked_at IS NULL    idempotence, and it is what makes a second call
//	                report ErrInvitationRevoked rather than refreshing the
//	                timestamp and pretending it happened again
//
// Zero rows is the ambiguous answer — gone, another account's, already accepted,
// or already revoked — and it is disambiguated by one follow-up read rather than
// by four queries, because two of the four must be reported identically and
// telling them apart is the whole job of the read.
//
// The invitation is KEPT rather than deleted, and the reason is 00013's header:
// a deleted invitation cannot answer "was this revoked, or was it always
// broken?", and the same support question is why api_keys and oidc_clients both
// keep their revoked rows.
func (s *Store) RevokePendingInvitation(ctx context.Context, q db.Querier, accountID, invitationID id.UUID) (int, error) {
	if invitationID.IsZero() || accountID.IsZero() {
		return 0, ErrInvitationNotFound
	}

	const query = `
		UPDATE account_invitations SET revoked_at = now(), updated_at = now()
		WHERE id = $1 AND account_id = $2 AND accepted_at IS NULL AND revoked_at IS NULL`

	tag, err := q.Exec(ctx, query, invitationID, accountID)
	if err != nil {
		return 0, fmt.Errorf("revoking an invitation: %w", err)
	}
	if tag.RowsAffected() > 0 {
		return int(tag.RowsAffected()), nil
	}
	return 0, s.classifyUnrevocable(ctx, q, accountID, invitationID)
}

// RevokePendingInvitations stamps revoked_at on as many of ids as are pending
// invitations of this account, and reports how many rows it changed.
//
// The count is the number that went into the audit record, and it is the number
// the database says rather than the length of the request: a request naming six
// ids where two were already revoked changes four rows, and recording six is a
// trail that cannot be reconciled against the account.
//
// ids that are not revocable are silently not revoked here. The caller decides
// whether that is acceptable, and the reason it is not an error at this level is
// that "revoke these fifty, forty-eight of which are already gone" is a request a
// caller should be able to make idempotently — returning an error would make a
// retried batch fail forever on an id that was never going to work.
func (s *Store) RevokePendingInvitations(ctx context.Context, q db.Querier, accountID id.UUID, ids []id.UUID) (int, error) {
	if accountID.IsZero() || len(ids) == 0 {
		return 0, ErrInvitationNotFound
	}

	const query = `
		UPDATE account_invitations SET revoked_at = now(), updated_at = now()
		WHERE account_id = $1 AND id = ANY($2)
		  AND accepted_at IS NULL AND revoked_at IS NULL`

	tag, err := q.Exec(ctx, query, accountID, ids)
	if err != nil {
		return 0, fmt.Errorf("revoking invitations: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// classifyUnrevocable turns "the UPDATE changed nothing" into the one of three
// answers that are actually distinguishable, and it is a read rather than three
// more UPDATEs because the point of the conditional statement above is that it
// touches no row it should not.
//
// A row that exists and is NOT revocable is reported as revoked-or-used, and a
// row that does not exist is ErrInvitationNotFound — which is also what another
// account's invitation looks like, because the lookup is scoped to accountID and
// a row in somebody else's account is a row this query cannot see. That is the
// same conflation accountIDFrom makes in the path, and it is deliberate: a caller
// who could distinguish "no such invitation" from "an invitation in an account you
// are not in" would have a tenant-probe.
func (s *Store) classifyUnrevocable(ctx context.Context, q db.Querier, accountID, invitationID id.UUID) error {
	const query = `
		SELECT accepted_at IS NOT NULL, revoked_at IS NOT NULL
		FROM account_invitations WHERE id = $1 AND account_id = $2`

	var accepted, revoked bool
	err := q.QueryRow(ctx, query, invitationID, accountID).Scan(&accepted, &revoked)
	if errors.Is(err, errNoRows) {
		return ErrInvitationNotFound
	}
	if err != nil {
		return fmt.Errorf("classifying an unrevocable invitation: %w", err)
	}
	if accepted {
		return ErrInvitationUsed
	}
	// revoked is true here, and an invitation with neither accepted nor revoked
	// cannot reach this branch: the UPDATE would have matched it.
	return ErrInvitationRevoked
}

// scanMembership reads one membership row.
func scanMembership(row interface{ Scan(...any) error }) (Membership, error) {
	var m Membership
	err := row.Scan(&m.AccountID, &m.UserID, &m.Role, &m.CreatedAt, &m.UpdatedAt)
	if err != nil {
		if errors.Is(err, errNoRows) {
			return Membership{}, errNoRows
		}
		return Membership{}, fmt.Errorf("scanning a membership: %w", err)
	}
	return m, nil
}

// scanInvitation reads one invitation row.
func scanInvitation(row interface{ Scan(...any) error }) (Invitation, error) {
	var inv Invitation
	err := row.Scan(&inv.ID, &inv.AccountID, &inv.Email, &inv.Role, &inv.TokenDigest,
		&inv.ExpiresAt, &inv.AcceptedAt, &inv.InvitedBy, &inv.CreatedAt, &inv.UpdatedAt)
	if err != nil {
		if errors.Is(err, errNoRows) {
			return Invitation{}, errNoRows
		}
		return Invitation{}, fmt.Errorf("scanning an invitation: %w", err)
	}
	return inv, nil
}

// prefixed qualifies a bare column list with a table alias, so the two list
// queries that join can share the one column constant.
func prefixed(alias, columns string) string {
	out := make([]byte, 0, len(columns)+16)
	start := 0
	for i := 0; i <= len(columns); i++ {
		if i == len(columns) || columns[i] == ',' {
			out = append(out, alias...)
			out = append(out, '.')
			out = append(out, columns[start:i]...)
			if i < len(columns) {
				out = append(out, ',')
			}
			start = i + 1
		}
	}
	return string(out)
}

// isUniqueViolation reports whether err is a unique_violation.
//
// It matches on the SQLSTATE alone, which is load-bearing rather than lazy: each
// caller uses it for a statement whose only unique constraint is the one it is
// looking for. Matching the constraint *name* instead would be more precise in
// principle and is in practice brittle — Postgres renames an index when a table
// is cloned with LIKE ... INCLUDING INDEXES, which is exactly what the
// integration tests do, and a future migration could rename one legitimately. A
// silently mis-detected duplicate turns a 409 into a 500.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == uniqueViolation
}
