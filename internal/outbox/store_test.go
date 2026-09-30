package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
)

var at = time.Date(2026, 9, 30, 4, 19, 0, 0, time.UTC)

func mustUserCreated(t *testing.T, email string) Envelope {
	t.Helper()

	e, err := NewUserCreated(at, id.MustNew(), email)
	if err != nil {
		t.Fatalf("NewUserCreated: %v", err)
	}
	return e
}

func TestStoreAppendAndReadBack(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	ctx := context.Background()

	e := mustUserCreated(t, dbtest.UniqueEmail(t))

	if err := store.Append(ctx, pool, e); err != nil {
		t.Fatalf("Append: %v", err)
	}

	var (
		storedType    string
		storedSource  string
		storedSubject string
		storedAt      time.Time
		storedPayload []byte
		storedEnv     []byte
		publishedAt   *time.Time
		attempts      int
	)
	err := pool.QueryRow(ctx, `
		SELECT type, source, subject, occurred_at, payload, envelope, published_at, attempts
		FROM outbox_events WHERE id = $1`, e.ID).
		Scan(&storedType, &storedSource, &storedSubject, &storedAt, &storedPayload, &storedEnv, &publishedAt, &attempts)
	if err != nil {
		t.Fatalf("reading the event back: %v", err)
	}

	if storedType != e.Type || storedSource != e.Source || storedSubject != e.Subject {
		t.Errorf("stored type/source/subject = %q/%q/%q, want %q/%q/%q",
			storedType, storedSource, storedSubject, e.Type, e.Source, e.Subject)
	}
	if !storedAt.Equal(e.Time) {
		t.Errorf("stored occurred_at = %s, want %s", storedAt, e.Time)
	}
	if publishedAt != nil {
		t.Errorf("published_at = %v, want NULL for a newly appended event", *publishedAt)
	}
	if attempts != 0 {
		t.Errorf("attempts = %d, want 0", attempts)
	}

	// The envelope is stored whole so that what is published is byte-identical to
	// what was committed. It has to be the same document core's schema validates.
	var decoded Envelope
	if err := json.Unmarshal(storedEnv, &decoded); err != nil {
		t.Fatalf("the stored envelope does not parse: %v", err)
	}
	if err := decoded.Validate(); err != nil {
		t.Errorf("the stored envelope fails core's schema: %v", err)
	}
	if decoded.ID != e.ID {
		t.Errorf("stored envelope id = %s, want %s", decoded.ID, e.ID)
	}
}

// A malformed envelope must not reach the table. The CHECK constraints would
// catch a bad type, but Append refuses first so the caller learns about it at the
// call site rather than as a constraint violation three layers down.
func TestStoreAppendRejectsAnInvalidEnvelope(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)

	tests := []struct {
		name string
		give Envelope
	}{
		{name: "a bad type", give: Envelope{SpecVersion: SpecVersion, ID: id.MustNew(), Type: "NOT A TYPE", Source: SourceIdentity, Time: at, Data: json.RawMessage(`{}`)}},
		{name: "a bad source", give: Envelope{SpecVersion: SpecVersion, ID: id.MustNew(), Type: EventUserCreated, Source: "Identity Service", Time: at, Data: json.RawMessage(`{}`)}},
		{name: "the nil id", give: Envelope{SpecVersion: SpecVersion, Type: EventUserCreated, Source: SourceIdentity, Time: at, Data: json.RawMessage(`{}`)}},
		{name: "a zero time", give: Envelope{SpecVersion: SpecVersion, ID: id.MustNew(), Type: EventUserCreated, Source: SourceIdentity, Data: json.RawMessage(`{}`)}},
		{name: "unparseable data", give: Envelope{SpecVersion: SpecVersion, ID: id.MustNew(), Type: EventUserCreated, Source: SourceIdentity, Time: at, Data: json.RawMessage(`{oops`)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.Append(context.Background(), pool, tt.give)
			if err == nil {
				t.Fatal("Append accepted an invalid envelope, want a rejection")
			}
		})
	}
}

// The whole point of the table. The event is written inside the caller's
// transaction, so a failure anywhere in that transaction takes the event with it
// and no consumer is ever told about a user that does not exist.
func TestStoreAppendInsideATransactionRollsBackWithIt(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	ctx := context.Background()

	e := mustUserCreated(t, dbtest.UniqueEmail(t))

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := store.Append(ctx, tx, e); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	batch, err := store.Claim(ctx, 10)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	defer batch.Release(ctx)

	for _, got := range batch.Events() {
		if got.ID == e.ID {
			t.Error("the event survived the rollback of its transaction; it would be published for a user who was never created")
		}
	}
}

// Re-appending the same envelope is a no-op rather than an error. The envelope id
// is the consumers' dedupe key, so a retried transaction must not mint a second
// copy of an event they have already seen.
func TestStoreAppendIsIdempotent(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	ctx := context.Background()

	e := mustUserCreated(t, dbtest.UniqueEmail(t))

	if err := store.Append(ctx, pool, e); err != nil {
		t.Fatalf("first Append: %v", err)
	}
	if err := store.Append(ctx, pool, e); err != nil {
		t.Errorf("second Append = %v, want the same event id to be accepted", err)
	}

	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM outbox_events WHERE id = $1`, e.ID).Scan(&n); err != nil {
		t.Fatalf("counting: %v", err)
	}
	if n != 1 {
		t.Errorf("outbox_events has %d rows with id %s, want 1", n, e.ID)
	}
}

func TestStoreClaimReturnsUnpublishedEventsInOrder(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	ctx := context.Background()

	// Three events, each with its own email so the fixture is identifiable.
	events := []Envelope{
		mustUserCreated(t, dbtest.UniqueEmail(t)),
		mustUserCreated(t, dbtest.UniqueEmail(t)),
		mustUserCreated(t, dbtest.UniqueEmail(t)),
	}
	for i := range events {
		events[i].Time = at.Add(time.Duration(i) * time.Second)
		if err := store.Append(ctx, pool, events[i]); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	batch, err := store.Claim(ctx, 10)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	defer batch.Release(ctx)

	claimed := batch.Events()
	if len(claimed) < len(events) {
		t.Fatalf("Claim returned %d events, want at least the %d just written", len(claimed), len(events))
	}

	// The claim must be ordered by (created_at, id) so a consumer sees them in
	// the order they happened.
	for i := 1; i < len(claimed); i++ {
		if claimed[i].Time.Before(claimed[i-1].Time) {
			t.Errorf("Claim returned %s before %s; ordering is by occurrence",
				claimed[i].Time, claimed[i-1].Time)
			break
		}
	}

	for i := range events {
		if claimed[i].Validate() != nil {
			t.Errorf("a claimed event does not satisfy core's schema: %v", claimed[i].Validate())
		}
	}
}

func TestStoreClaimRespectsTheLimit(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	ctx := context.Background()

	for range 5 {
		if err := store.Append(ctx, pool, mustUserCreated(t, dbtest.UniqueEmail(t))); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	batch, err := store.Claim(ctx, 2)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	defer batch.Release(ctx)

	if got := len(batch.Events()); got != 2 {
		t.Errorf("Claim(2) returned %d events, want 2", got)
	}
}

// Published events must not come back. A loop that re-published everything would
// be indistinguishable from one that works, right up until a consumer's
// deduplication table filled up.
func TestStoreClaimSkipsPublishedEvents(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	ctx := context.Background()

	done := mustUserCreated(t, dbtest.UniqueEmail(t))
	if err := store.Append(ctx, pool, done); err != nil {
		t.Fatalf("Append: %v", err)
	}

	first, err := store.Claim(ctx, 1)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := first.MarkPublished(ctx, done.ID); err != nil {
		t.Fatalf("MarkPublished: %v", err)
	}
	if err := first.Commit(ctx); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	second, err := store.Claim(ctx, 10)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	defer second.Release(ctx)

	for _, e := range second.Events() {
		if e.ID == done.ID {
			t.Error("Claim returned an event that was already published")
		}
	}
}

// A failed publish is recorded and the batch still commits. If it rolled back,
// the event would be re-claimed forever and one poison message would wedge the
// whole outbox — which is exactly what core's event-naming.md warns against.
func TestStoreMarkFailedKeepsTheEventForRetry(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	ctx := context.Background()

	e := mustUserCreated(t, dbtest.UniqueEmail(t))
	if err := store.Append(ctx, pool, e); err != nil {
		t.Fatalf("Append: %v", err)
	}

	batch, err := store.Claim(ctx, 1)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := batch.MarkFailed(ctx, e.ID, "nats: connection refused"); err != nil {
		t.Fatalf("MarkFailed: %v", err)
	}
	if err := batch.Commit(ctx); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	var (
		attempts  int
		lastError *string
		published *time.Time
	)
	if err := pool.QueryRow(ctx, `SELECT attempts, last_error, published_at FROM outbox_events WHERE id = $1`, e.ID).
		Scan(&attempts, &lastError, &published); err != nil {
		t.Fatalf("reading the failed event: %v", err)
	}

	if attempts != 1 {
		t.Errorf("attempts = %d, want 1", attempts)
	}
	if lastError == nil || *lastError != "nats: connection refused" {
		t.Errorf("last_error = %v, want the publish failure recorded", lastError)
	}
	if published != nil {
		t.Errorf("published_at = %v, want NULL so the event is retried", *published)
	}

	// And it is still claimable, so the retry is real.
	again, err := store.Claim(ctx, 10)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	defer again.Release(ctx)

	found := false
	for _, got := range again.Events() {
		if got.ID == e.ID {
			found = true
		}
	}
	if !found {
		t.Error("the failed event is no longer claimable")
	}
}

func TestStoreClaimOnAnEmptyOutbox(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)

	batch, err := store.Claim(context.Background(), 10)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	defer batch.Release(context.Background())

	// An empty batch is the normal state of a healthy service, not an error.
	if got := len(batch.Events()); got != 0 {
		t.Errorf("Claim on an idle outbox returned %d events, want 0", got)
	}
}

func TestStoreClaimRejectsANonPositiveLimit(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)

	for _, limit := range []int{0, -1} {
		if _, err := store.Claim(context.Background(), limit); err == nil {
			t.Errorf("Claim(limit=%d) returned no error, want a rejection", limit)
		}
	}
}

// Releasing without committing must leave the events claimable, and must not
// error. A double release is a no-op.
func TestStoreBatchReleaseIsSafeToRepeat(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	ctx := context.Background()

	e := mustUserCreated(t, dbtest.UniqueEmail(t))
	if err := store.Append(ctx, pool, e); err != nil {
		t.Fatalf("Append: %v", err)
	}

	batch, err := store.Claim(ctx, 1)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := batch.Release(ctx); err != nil {
		t.Errorf("first Release: %v", err)
	}
	if err := batch.Release(ctx); err != nil {
		t.Errorf("second Release: %v, want a no-op", err)
	}
}

func TestStoreMarkPublishedRejectsAnUnknownID(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	ctx := context.Background()

	batch, err := store.Claim(ctx, 1)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	defer batch.Release(ctx)

	// Marking something that was not in this batch is a programming error, and
	// silently succeeding would let a loop believe it had published an event.
	if err := batch.MarkPublished(ctx, id.MustNew()); !errors.Is(err, ErrNotInBatch) {
		t.Errorf("MarkPublished of an unknown id = %v, want errors.Is(_, ErrNotInBatch)", err)
	}
	if err := batch.MarkFailed(ctx, id.MustNew(), "boom"); !errors.Is(err, ErrNotInBatch) {
		t.Errorf("MarkFailed of an unknown id = %v, want errors.Is(_, ErrNotInBatch)", err)
	}
}

func TestStoreClaimedEnvelopesSurviveTheRoundTrip(t *testing.T) {
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	ctx := context.Background()

	original := mustUserCreated(t, dbtest.UniqueEmail(t))
	if err := store.Append(ctx, pool, original); err != nil {
		t.Fatalf("Append: %v", err)
	}

	batch, err := store.Claim(ctx, 100)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	defer batch.Release(ctx)

	for _, got := range batch.Events() {
		if got.ID != original.ID {
			continue
		}
		if got.Type != original.Type || got.Source != original.Source || got.Subject != original.Subject {
			t.Errorf("claimed envelope = %+v, want %+v", got, original)
		}
		if !got.Time.Equal(original.Time) {
			t.Errorf("claimed Time = %s, want %s", got.Time, original.Time)
		}
		if string(got.Data) != string(original.Data) {
			t.Errorf("claimed Data = %s, want %s", got.Data, original.Data)
		}
		if got.SpecVersion != original.SpecVersion {
			t.Errorf("claimed SpecVersion = %q, want %q", got.SpecVersion, original.SpecVersion)
		}
		return
	}
	t.Errorf("the event %s was not claimed", original.ID)
}

// Guard against a future edit that swaps the pool for something narrower: the
// store is handed a db.Pool and the tests hand it a real one.
var _ db.Pool = (*pgxpool.Pool)(nil)
