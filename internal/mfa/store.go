package mfa

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/sessions"
)

// errNoRows is pgx's "the query matched nothing", aliased so the intent reads at
// the call site.
var errNoRows = pgx.ErrNoRows

// The four tables, and one idea that shapes every method here.
//
// THE CLAIMS ARE CONDITIONAL UPDATES.
//
// Nothing in this file reads a row, decides something in Go, and writes it back.
// Every state change that has to be safe against a concurrent request is a
// single UPDATE whose WHERE clause IS the check:
//
//	ClaimStep        INSERT ... ON CONFLICT DO NOTHING   a step is spent
//	ConsumeRecovery  UPDATE ... WHERE used_at IS NULL    a code is spent
//	ConsumeChallenge UPDATE ... WHERE consumed_at IS NULL a challenge is spent
//	ConfirmCredential UPDATE ... WHERE confirmed_at IS NULL an enrollment lands
//
// A read-then-write in front of any of those has a window between the two
// statements, two requests walk through it, and both believe they won. That is
// not a theoretical concern for a login: a replayed TOTP code and the legitimate
// user pasting it at the same moment is the exact scenario the replay guard
// exists for, and the moment is the scenario an attacker picks.
//
// Each of those methods returns a bool, and the bool is the answer. A caller that
// gets false has lost a race it should have expected to lose, and refuses.

// Store is the four tables this package owns.
type Store struct {
	pool db.Pool
}

// NewStore returns a Store backed by pool.
func NewStore(pool db.Pool) *Store { return &Store{pool: pool} }

const credentialColumns = `id, user_id, method, secret_ciphertext, digits, period_seconds,
	algorithm, label, confirmed_at, expires_at, failed_attempts, locked_until, created_at, updated_at`

// CreateCredentialParams is everything a new credential row needs.
//
// SecretCiphertext, never Secret: the store has no way to produce a secret, so the
// raw value cannot be written from here even by accident. The same rule as
// sessions.NewSession's TokenDigest.
type CreateCredentialParams struct {
	UserID           id.UUID
	Method           string
	SecretCiphertext string
	Digits           int
	PeriodSeconds    int
	Algorithm        string
	Label            string
	ExpiresAt        *time.Time
	CreatedAt        time.Time
}

// CreateCredential inserts a pending credential and returns the stored row.
func (s *Store) CreateCredential(ctx context.Context, q db.Querier, p CreateCredentialParams) (Credential, error) {
	const query = `
		INSERT INTO mfa_credentials
			(user_id, method, secret_ciphertext, digits, period_seconds, algorithm, label, expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)
		RETURNING ` + credentialColumns

	var out Credential
	err := scanCredential(q.QueryRow(ctx, query,
		p.UserID, p.Method, p.SecretCiphertext, p.Digits, p.PeriodSeconds,
		p.Algorithm, p.Label, p.ExpiresAt, p.CreatedAt,
	), &out)
	if err != nil {
		return Credential{}, fmt.Errorf("inserting an mfa credential: %w", err)
	}
	return out, nil
}

// CredentialByID reads one credential by primary key.
func (s *Store) CredentialByID(ctx context.Context, q db.Querier, rowID id.UUID) (Credential, error) {
	if rowID.IsZero() {
		return Credential{}, ErrNotFound
	}
	const query = `SELECT ` + credentialColumns + ` FROM mfa_credentials WHERE id = $1`
	return scanCredentialRow(q.QueryRow(ctx, query, rowID), "looking up an mfa credential")
}

// ConfirmedCredential is THE login read: the one live credential for a user.
//
// Scoped to confirmed rows in the WHERE clause rather than filtered in Go, so a
// pending enrollment is never returned even to be discarded — the same rule
// sessions.ByToken follows for an expired session.
func (s *Store) ConfirmedCredential(ctx context.Context, q db.Querier, userID id.UUID) (Credential, error) {
	if userID.IsZero() {
		return Credential{}, ErrNotFound
	}
	const query = `
		SELECT ` + credentialColumns + `
		FROM mfa_credentials
		WHERE user_id = $1 AND confirmed_at IS NOT NULL
		ORDER BY confirmed_at DESC
		LIMIT 1`

	out, err := scanCredentialRow(q.QueryRow(ctx, query, userID), "looking up a user's live mfa credential")
	if errors.Is(err, ErrNotFound) {
		return Credential{}, ErrNotEnabled
	}
	return out, err
}

// PendingCredential reads an unconfirmed credential, and only the caller's own.
//
// Both conditions are in the WHERE clause. The user_id is there so one user
// cannot confirm another's enrollment — a bug that would otherwise be a way to
// take over an account with no factor at all — and confirmed_at IS NULL so a
// replayed confirm is a refusal rather than a second confirmation of a rotated
// secret.
func (s *Store) PendingCredential(ctx context.Context, q db.Querier, userID, rowID id.UUID) (Credential, error) {
	if userID.IsZero() || rowID.IsZero() {
		return Credential{}, ErrEnrollmentNotFound
	}
	const query = `
		SELECT ` + credentialColumns + `
		FROM mfa_credentials
		WHERE id = $1 AND user_id = $2 AND confirmed_at IS NULL`

	out, err := scanCredentialRow(q.QueryRow(ctx, query, rowID, userID), "looking up a pending enrollment")
	if errors.Is(err, ErrNotFound) {
		return Credential{}, ErrEnrollmentNotFound
	}
	return out, err
}

// DeleteUnconfirmedFor removes a user's pending enrollments, whatever their
// expiry.
//
// Called when a new enrollment starts, so a user who opens the setup page ten
// times holds one pending secret and not ten. An unconfirmed secret authenticates
// nothing, so throwing one away is free, and the alternative — accumulating one
// per abandoned setup — is an encrypted secret at rest per abandoned setup.
func (s *Store) DeleteUnconfirmedFor(ctx context.Context, q db.Querier, userID id.UUID) error {
	const query = `DELETE FROM mfa_credentials WHERE user_id = $1 AND confirmed_at IS NULL`

	if _, err := q.Exec(ctx, query, userID); err != nil {
		return fmt.Errorf("deleting pending mfa enrollments: %w", err)
	}
	return nil
}

// ConfirmCredential turns a pending row into the live one, and reports whether it
// was the one that did it.
//
// The WHERE clause carries the whole rule: a row that is already confirmed, or
// belongs to nobody, returns false. A rotation is therefore a single statement —
// confirm the replacement, and the partial unique index
// mfa_credentials_one_live_per_user rejects the confirmation if there were ever
// two live rows for the user.
//
// expires_at is cleared in the same statement as confirmed_at is set, because the
// table's CHECK constraint requires the two to move together and a caller should
// not have to know that.
func (s *Store) ConfirmCredential(ctx context.Context, q db.Querier, rowID id.UUID, at time.Time) (Credential, bool, error) {
	const query = `
		UPDATE mfa_credentials
		SET confirmed_at = $2, expires_at = NULL, updated_at = $2
		WHERE id = $1 AND confirmed_at IS NULL
		RETURNING ` + credentialColumns

	var out Credential
	err := scanCredential(q.QueryRow(ctx, query, rowID, at), &out)
	if errors.Is(err, errNoRows) {
		return Credential{}, false, nil
	}
	if err != nil {
		return Credential{}, false, fmt.Errorf("confirming an mfa enrollment: %w", err)
	}
	return out, true, nil
}

// DeleteCredential removes a credential. The recovery codes and the spent TOTP
// steps go with it, by the foreign keys in the schema.
func (s *Store) DeleteCredential(ctx context.Context, q db.Querier, rowID id.UUID) error {
	const query = `DELETE FROM mfa_credentials WHERE id = $1`

	if _, err := q.Exec(ctx, query, rowID); err != nil {
		return fmt.Errorf("deleting an mfa credential: %w", err)
	}
	return nil
}

// RecordFactorFailure persists the second factor's lockout state.
//
// The columns are the credential's own, and NOT the users row's. That separation
// is the security property the packet asks for: exhausting five TOTP guesses has
// not spent a password guess, and five wrong passwords have not moved this. The
// arithmetic is sessions.Lockout's, so the two counters run the same policy and
// there is one implementation of it.
func (s *Store) RecordFactorFailure(ctx context.Context, q db.Querier, rowID id.UUID, attempts int, lockedUntil *time.Time) error {
	const query = `
		UPDATE mfa_credentials
		SET failed_attempts = $2, locked_until = $3, updated_at = now()
		WHERE id = $1`

	tag, err := q.Exec(ctx, query, rowID, attempts, lockedUntil)
	if err != nil {
		return fmt.Errorf("recording a failed second factor: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ClearFactorFailures resets the second factor's failure run.
//
// Called on the same transaction that accepts a factor, so "the factor was
// accepted" and "the run against this factor is over" are one fact. It is the
// mirror of users.ClearFailures, on a different row.
func (s *Store) ClearFactorFailures(ctx context.Context, q db.Querier, rowID id.UUID) error {
	const query = `
		UPDATE mfa_credentials
		SET failed_attempts = 0, locked_until = NULL, updated_at = now()
		WHERE id = $1`

	tag, err := q.Exec(ctx, query, rowID)
	if err != nil {
		return fmt.Errorf("clearing second-factor failures: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// InsertRecoveryCodes writes a whole set in one statement.
//
// One statement rather than ten because a set is one fact: a user with four of
// ten codes is a user whose regeneration half-applied, and a per-row loop in a
// transaction is a partial write waiting for the connection to drop.
func (s *Store) InsertRecoveryCodes(ctx context.Context, q db.Querier, credentialID id.UUID, digests []string, at time.Time) error {
	const query = `
		INSERT INTO mfa_recovery_codes (credential_id, code_digest, created_at)
		SELECT $1, d, $3
		FROM unnest($2::text[]) AS d`

	if _, err := q.Exec(ctx, query, credentialID, digests, at); err != nil {
		return fmt.Errorf("inserting recovery codes: %w", err)
	}
	return nil
}

// DeleteRecoveryCodesFor empties a credential's code set.
//
// The first half of a regeneration, and it runs in the same transaction as the
// insert of the new set. A regeneration is "delete the old, insert the new", and
// a partial write leaves a user with two live sets — a second recovery path
// through a code nobody audited, which is worse than no recovery path at all.
func (s *Store) DeleteRecoveryCodesFor(ctx context.Context, q db.Querier, credentialID id.UUID) error {
	const query = `DELETE FROM mfa_recovery_codes WHERE credential_id = $1`

	if _, err := q.Exec(ctx, query, credentialID); err != nil {
		return fmt.Errorf("deleting recovery codes: %w", err)
	}
	return nil
}

// UnusedRecoveryCode finds the row for a code that has not been spent.
//
// Scoped to used_at IS NULL in the WHERE clause, so a spent code is not returned
// even to be discarded by the caller. Whether a code is live is a question about
// the row, and it is answered by the row.
func (s *Store) UnusedRecoveryCode(ctx context.Context, q db.Querier, credentialID id.UUID, digest string) (id.UUID, error) {
	const query = `
		SELECT id FROM mfa_recovery_codes
		WHERE credential_id = $1 AND code_digest = $2 AND used_at IS NULL`

	var out id.UUID
	err := q.QueryRow(ctx, query, credentialID, digest).Scan(&out)
	if errors.Is(err, errNoRows) {
		return id.UUID{}, ErrInvalidFactor
	}
	if err != nil {
		return id.UUID{}, fmt.Errorf("looking up a recovery code: %w", err)
	}
	return out, nil
}

// ConsumeRecoveryCode spends a code, and reports whether it was still unspent.
//
// This is the single-use guarantee, and it is one statement. Two requests
// carrying the same recovery code — the legitimate user on two devices, or an
// attacker replaying a phished one — both find the row with UnusedRecoveryCode,
// and then exactly one of them gets true from here.
func (s *Store) ConsumeRecoveryCode(ctx context.Context, q db.Querier, codeID id.UUID, at time.Time) (bool, error) {
	const query = `
		UPDATE mfa_recovery_codes SET used_at = $2
		WHERE id = $1 AND used_at IS NULL`

	tag, err := q.Exec(ctx, query, codeID, at)
	if err != nil {
		return false, fmt.Errorf("consuming a recovery code: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// CountUnusedRecoveryCodes is how many are left.
//
// Asked on every recovery-code sign-in and by GET /v1/mfa, which is the packet's
// "tell them before they get there" — a user with zero left and a lost phone is
// a support ticket, and the honest thing is to say so while there is still one
// code left to spend.
func (s *Store) CountUnusedRecoveryCodes(ctx context.Context, q db.Querier, credentialID id.UUID) (int, error) {
	const query = `SELECT count(*) FROM mfa_recovery_codes WHERE credential_id = $1 AND used_at IS NULL`

	var out int
	if err := q.QueryRow(ctx, query, credentialID).Scan(&out); err != nil {
		return 0, fmt.Errorf("counting unused recovery codes: %w", err)
	}
	return out, nil
}

// ClaimStep records that a TOTP step has been spent, and reports whether this
// caller is the one that spent it.
//
// THIS IS THE REPLAY GUARD, and the primary key on (credential_id, step) is the
// entire mechanism. Three properties fall out of it that a column would not have:
//
//   - It refuses a step that was spent and accepts one that was not, in any order.
//     A single "highest step accepted" bigint cannot make that distinction: below
//     its mark it does not know whether a step was spent or merely old, so it
//     refuses unspent steps — which is a user with a phone whose clock moved
//     backwards being told their correct code is wrong.
//   - It is atomic without a lock. ON CONFLICT DO NOTHING is one statement, so two
//     requests carrying the same code resolve to one winner and one loser with
//     nothing to roll back and no row to clean up if the loser goes on to fail
//     something else.
//   - It is bounded. PruneSteps runs in the same transaction as the acceptance, so
//     a credential holds at most a handful of rows and this table is the size of
//     the enrolled population rather than the size of the login history.
func (s *Store) ClaimStep(ctx context.Context, q db.Querier, credentialID id.UUID, step int64, at time.Time) (bool, error) {
	const query = `
		INSERT INTO mfa_used_totp_steps (credential_id, step, used_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (credential_id, step) DO NOTHING`

	tag, err := q.Exec(ctx, query, credentialID, step, at)
	if err != nil {
		return false, fmt.Errorf("claiming a TOTP step: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// PruneSteps drops the steps that can no longer be replayed.
//
// Everything at or below the oldest step still inside the acceptance window is
// gone, because a code for such a step is refused by the time anyone could
// present it. It is a DELETE rather than a sweeper because it needs the
// credential's current step, which only the acceptance knows, and because a
// sweeper is a job somebody has to run and this service does not have one.
func (s *Store) PruneSteps(ctx context.Context, q db.Querier, credentialID id.UUID, below int64) error {
	const query = `DELETE FROM mfa_used_totp_steps WHERE credential_id = $1 AND step <= $2`

	if _, err := q.Exec(ctx, query, credentialID, below); err != nil {
		return fmt.Errorf("pruning spent TOTP steps: %w", err)
	}
	return nil
}

// NewChallengeParams is a challenge to create.
type NewChallengeParams struct {
	UserID      id.UUID
	TokenDigest string
	UserAgent   string
	IP          *netip.Addr
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// CreateChallenge records a login that has a correct password and no session.
func (s *Store) CreateChallenge(ctx context.Context, q db.Querier, p NewChallengeParams) (Challenge, error) {
	const query = `
		INSERT INTO mfa_challenges (user_id, token_digest, user_agent, ip, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, user_id, user_agent, ip, created_at, expires_at, consumed_at`

	var out Challenge
	var userAgent *string
	err := q.QueryRow(ctx, query, p.UserID, p.TokenDigest, nullString(p.UserAgent), p.IP, p.CreatedAt, p.ExpiresAt).
		Scan(&out.ID, &out.UserID, &userAgent, &out.IP, &out.CreatedAt, &out.ExpiresAt, &out.ConsumedAt)
	if err != nil {
		return Challenge{}, fmt.Errorf("inserting an mfa challenge: %w", err)
	}
	if userAgent != nil {
		out.UserAgent = *userAgent
	}
	return out, nil
}

// DeleteSupersededChallenges removes a user's other live challenges.
//
// A second login supersedes the first, which bounds this table at one row per
// user with no sweeper and no scheduled job. It is also the right semantics: a
// challenge is a short-lived permission to finish one sign-in, and two of them
// for the same person is two permissions to finish a sign-in.
func (s *Store) DeleteSupersededChallenges(ctx context.Context, q db.Querier, userID id.UUID, keep id.UUID) error {
	const query = `DELETE FROM mfa_challenges WHERE user_id = $1 AND id <> $2`

	if _, err := q.Exec(ctx, query, userID, keep); err != nil {
		return fmt.Errorf("deleting superseded mfa challenges: %w", err)
	}
	return nil
}

// LiveChallenge resolves a presented challenge token to a challenge that may still
// be answered.
//
// Both conditions are in the WHERE clause, for the reason sessions.ByToken puts
// its expiry comparison there: an expired or already-spent challenge is never
// returned even to be discarded by the caller, so "no such challenge" is one
// answer and one response time for four different situations.
func (s *Store) LiveChallenge(ctx context.Context, q db.Querier, token string, now time.Time) (Challenge, error) {
	const query = `
		SELECT id, user_id, user_agent, ip, created_at, expires_at, consumed_at
		FROM mfa_challenges
		WHERE token_digest = $1 AND consumed_at IS NULL AND expires_at > $2`

	var out Challenge
	var userAgent *string
	err := q.QueryRow(ctx, query, sessions.Digest(token), now).
		Scan(&out.ID, &out.UserID, &userAgent, &out.IP, &out.CreatedAt, &out.ExpiresAt, &out.ConsumedAt)
	if errors.Is(err, errNoRows) {
		return Challenge{}, ErrChallengeNotFound
	}
	if err != nil {
		return Challenge{}, fmt.Errorf("looking up an mfa challenge: %w", err)
	}
	if userAgent != nil {
		out.UserAgent = *userAgent
	}
	return out, nil
}

// ConsumeChallenge spends a challenge, and reports whether it was still live.
//
// Same conditional-UPDATE argument as ConsumeRecoveryCode. It is called on
// success only: a wrong code does not spend the challenge, because the per-factor
// lockout is what bounds a wrong code, and spending the challenge as well would
// turn five guesses into one.
func (s *Store) ConsumeChallenge(ctx context.Context, q db.Querier, challengeID id.UUID, at time.Time) (bool, error) {
	const query = `
		UPDATE mfa_challenges SET consumed_at = $2
		WHERE id = $1 AND consumed_at IS NULL`

	tag, err := q.Exec(ctx, query, challengeID, at)
	if err != nil {
		return false, fmt.Errorf("consuming an mfa challenge: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// scanCredentialRow turns "no rows" into ErrNotFound and wraps everything else,
// so callers match one sentinel.
func scanCredentialRow(row pgx.Row, what string) (Credential, error) {
	var out Credential
	err := scanCredential(row, &out)
	if errors.Is(err, errNoRows) {
		return Credential{}, ErrNotFound
	}
	if err != nil {
		return Credential{}, fmt.Errorf("%s: %w", what, err)
	}
	return out, nil
}

func scanCredential(row pgx.Row, out *Credential) error {
	return row.Scan(
		&out.ID, &out.UserID, &out.Method, &out.SecretCiphertext, &out.Digits, &out.PeriodSeconds,
		&out.Algorithm, &out.Label, &out.ConfirmedAt, &out.ExpiresAt,
		&out.FailedAttempts, &out.LockedUntil, &out.CreatedAt, &out.UpdatedAt,
	)
}

// nullString turns an empty user agent into SQL NULL. An empty string and "not
// recorded" are the same answer here, and NULL is the one that says so.
func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
