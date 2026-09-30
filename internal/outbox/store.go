package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
)

// ErrNotInBatch means a caller tried to mark an event that the batch it holds
// does not contain. It is a bug in the loop, not a runtime condition, and
// silently accepting it would let the loop believe it had published something it
// never touched.
var ErrNotInBatch = errors.New("event is not in this batch")

// Store is the outbox_events table.
type Store struct {
	pool db.Pool
}

// NewStore returns a Store backed by pool.
func NewStore(pool db.Pool) *Store { return &Store{pool: pool} }

// Append writes one event, inside the caller's transaction.
//
// The transaction is the entire reason this table exists: the caller is expected
// to have just written the row the event is about, and passing the pool itself
// would let that pair come apart. See internal/auth.
func (s *Store) Append(ctx context.Context, q db.Querier, e Envelope) error {
	// Validated here rather than left to the table. The CHECK constraints catch a
	// malformed type or source, but not a missing subject, a zero time or
	// unparseable data, and the caller learns about those at this line.
	if err := e.Validate(); err != nil {
		return err
	}

	envelope, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("outbox: marshalling the envelope: %w", err)
	}

	// ON CONFLICT DO NOTHING, not an upsert. The envelope id is the consumers'
	// dedupe key, so a retried transaction must leave the committed row exactly as
	// it is; an upsert would let a retry rewrite the event a consumer already has.
	const query = `
		INSERT INTO outbox_events (id, type, source, subject, occurred_at, payload, envelope)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (id) DO NOTHING`

	_, err = q.Exec(ctx, query, e.ID, e.Type, e.Source, nullString(e.Subject), e.Time, e.Data, envelope)
	if err != nil {
		return fmt.Errorf("outbox: appending %s: %w", e.Type, err)
	}
	return nil
}

// Batch is a claimed set of events held under a row lock until it is committed or
// released.
type Batch interface {
	// Events returns the claimed envelopes.
	Events() []Envelope
	// MarkPublished records that an event reached the bus.
	MarkPublished(ctx context.Context, eventID id.UUID) error
	// MarkFailed records a failed attempt, leaving the event claimable.
	MarkFailed(ctx context.Context, eventID id.UUID, reason string) error
	// Commit releases the row locks and makes the marks durable.
	Commit(ctx context.Context) error
	// Release rolls back, leaving every claimed event claimable again. It is safe
	// to call after Commit and safe to call twice.
	Release(ctx context.Context) error
}

// Claim selects up to limit unpublished events and holds them for the duration of
// a transaction.
//
// The query is the standard transactional-outbox claim:
//
//	SELECT … WHERE published_at IS NULL ORDER BY created_at, id LIMIT $1
//	FOR UPDATE SKIP LOCKED
//
// SKIP LOCKED is what lets several publisher instances run at once: each takes a
// disjoint set of rows and none of them blocks on another's lock. Without it, two
// instances would serialise on the head of the table and the second would wait out
// the first's entire publish.
//
// The transaction stays open until Commit or Release. That is the trade: holding
// it means a crashed publisher's rows are released by Postgres rather than
// stranded, and it means a published event is marked in the same transaction that
// claimed it.
func (s *Store) Claim(ctx context.Context, limit int) (Batch, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("outbox: claim limit must be positive, got %d", limit)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("outbox: beginning the claim transaction: %w", err)
	}

	const query = `
		SELECT id, type, source, subject, occurred_at, envelope
		FROM outbox_events
		WHERE published_at IS NULL
		ORDER BY created_at, id
		LIMIT $1
		FOR UPDATE SKIP LOCKED`

	rows, err := tx.Query(ctx, query, limit)
	if err != nil {
		_ = tx.Rollback(ctx)
		return nil, fmt.Errorf("outbox: claiming a batch: %w", err)
	}
	defer rows.Close()

	events, err := scanEnvelopes(rows)
	if err != nil {
		_ = tx.Rollback(ctx)
		return nil, err
	}

	return &pgBatch{tx: tx, events: events}, nil
}

// scanEnvelopes reads the claimed rows. The stored `envelope` column is
// authoritative: it is the exact document that was validated on the way in, so
// re-deriving it from the individual columns would risk publishing something
// subtly different from what a consumer's contract test saw.
func scanEnvelopes(rows pgx.Rows) ([]Envelope, error) {
	events := make([]Envelope, 0, 16)

	for rows.Next() {
		var (
			raw     []byte
			idOnly  id.UUID
			eType   string
			eSource string
			subject *string
			eTime   time.Time
		)
		if err := rows.Scan(&idOnly, &eType, &eSource, &subject, &eTime, &raw); err != nil {
			return nil, fmt.Errorf("outbox: scanning a claimed event: %w", err)
		}

		var e Envelope
		if err := json.Unmarshal(raw, &e); err != nil {
			return nil, fmt.Errorf("outbox: the stored envelope for %s is not valid JSON: %w", idOnly, err)
		}
		events = append(events, e)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("outbox: reading the claimed batch: %w", err)
	}

	return events, nil
}

// pgBatch is a Batch backed by an open pgx transaction.
type pgBatch struct {
	tx      pgx.Tx
	events  []Envelope
	claimed map[id.UUID]struct{}

	mu        sync.Mutex
	settled   bool
	committed bool
}

func (b *pgBatch) Events() []Envelope { return b.events }

func (b *pgBatch) MarkPublished(ctx context.Context, eventID id.UUID) error {
	return b.mark(ctx, eventID, `
		UPDATE outbox_events
		SET published_at = now(), attempts = attempts + 1, last_error = NULL
		WHERE id = $1`)
}

func (b *pgBatch) MarkFailed(ctx context.Context, eventID id.UUID, reason string) error {
	return b.mark(ctx, eventID, `
		UPDATE outbox_events
		SET attempts = attempts + 1, last_error = $2
		WHERE id = $1`, reason)
}

func (b *pgBatch) mark(ctx context.Context, eventID id.UUID, query string, args ...any) error {
	if !b.holds(eventID) {
		return fmt.Errorf("outbox: %w: %s", ErrNotInBatch, eventID)
	}

	full := append([]any{eventID}, args...)
	tag, err := b.tx.Exec(ctx, query, full...)
	if err != nil {
		return fmt.Errorf("outbox: marking %s: %w", eventID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("outbox: %w: %s (no row was updated)", ErrNotInBatch, eventID)
	}
	return nil
}

// holds reports whether the batch claimed eventID. A caller that marks something
// it never claimed is usually a loop that invented an event, and the UPDATE would
// otherwise hit a row belonging to another instance's batch.
func (b *pgBatch) holds(eventID id.UUID) bool {
	if b.claimed == nil {
		b.claimed = make(map[id.UUID]struct{}, len(b.events))
		for _, e := range b.events {
			b.claimed[e.ID] = struct{}{}
		}
	}
	_, ok := b.claimed[eventID]
	return ok
}

func (b *pgBatch) Commit(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.settled {
		return nil
	}
	if err := b.tx.Commit(ctx); err != nil {
		return fmt.Errorf("outbox: committing the batch: %w", err)
	}
	b.settled = true
	return nil
}

// Release rolls the claim back so the events are available again.
//
// It runs against a fresh context when the caller's is already cancelled — which
// is exactly when a publisher is shutting down — because a rollback issued on a
// dead context would fail and leave the connection until the pool reaped it. If
// even that fails the transaction is discarded, which is still the outcome
// Release is asking for.
func (b *pgBatch) Release(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.settled {
		return nil
	}
	b.settled = true

	if err := b.tx.Rollback(ctx); err == nil || errors.Is(err, pgx.ErrTxClosed) {
		return nil
	}

	return b.tx.Rollback(context.WithoutCancel(ctx))
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
