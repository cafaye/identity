package outbox

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/platform/id"
)

// The loop is exercised against a fake Claimer and a recording Publisher rather
// than a database: the interesting behaviour is what it does when a publish
// fails, and that is far easier to arrange deterministically here than through
// a transport.

var errBusDown = errors.New("nats: no servers available for connection")

// recordingPublisher captures what it was asked to publish and can be told to
// fail for a chosen event.
type recordingPublisher struct {
	mu        sync.Mutex
	published []Envelope
	// failFor is keyed by envelope id, not by type: the loop's contract is about
	// one event failing while the rest go out, and two events of the same type is
	// the normal case for this service.
	failFor map[id.UUID]error
	// blocked, when non-nil, is waited on before each publish.
	blocked chan struct{}
}

func newRecordingPublisher() *recordingPublisher {
	return &recordingPublisher{failFor: map[id.UUID]error{}}
}

// fail makes the publisher reject one specific event.
func (p *recordingPublisher) fail(eventID id.UUID, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failFor[eventID] = err
}

func (p *recordingPublisher) Publish(ctx context.Context, e Envelope) error {
	if p.blocked != nil {
		<-p.blocked
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if err, bad := p.failFor[e.ID]; bad {
		return err
	}
	p.published = append(p.published, e)
	return nil
}

func (p *recordingPublisher) seen() []Envelope {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Envelope(nil), p.published...)
}

// fakeBatch is a Batch with no transaction behind it.
type fakeBatch struct {
	events    []Envelope
	published []id.UUID
	failed    []id.UUID
	reasons   []string
	committed bool
	released  bool
}

func (b *fakeBatch) Events() []Envelope { return b.events }

func (b *fakeBatch) MarkPublished(_ context.Context, eventID id.UUID) error {
	b.published = append(b.published, eventID)
	return nil
}

func (b *fakeBatch) MarkFailed(_ context.Context, eventID id.UUID, reason string) error {
	b.failed = append(b.failed, eventID)
	b.reasons = append(b.reasons, reason)
	return nil
}

func (b *fakeBatch) Commit(context.Context) error {
	b.committed = true
	return nil
}

func (b *fakeBatch) Release(context.Context) error {
	b.released = true
	return nil
}

// fakeClaimer hands out a fixed sequence of batches and records how many were
// taken.
type fakeClaimer struct {
	mu       sync.Mutex
	batches  []*fakeBatch
	claimErr error
	taken    int
}

func (c *fakeClaimer) Claim(_ context.Context, _ int) (Batch, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.claimErr != nil {
		return nil, c.claimErr
	}
	if len(c.batches) == 0 {
		return &fakeBatch{}, nil
	}
	c.taken++
	return c.batches[c.taken-1], nil
}

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func TestServiceRunOncePublishesTheWholeBatch(t *testing.T) {
	t.Parallel()

	first := mustUserCreated(t, "a@example.com")
	second := mustUserCreated(t, "b@example.com")
	batch := &fakeBatch{events: []Envelope{first, second}}
	pub := newRecordingPublisher()
	svc := NewService(&fakeClaimer{batches: []*fakeBatch{batch}}, pub, discardLogger(), 0)

	n, err := svc.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 2 {
		t.Errorf("RunOnce reported %d published, want 2", n)
	}

	seen := pub.seen()
	if len(seen) != 2 {
		t.Fatalf("the publisher saw %d events, want 2", len(seen))
	}
	if seen[0].ID != first.ID || seen[1].ID != second.ID {
		t.Error("the publisher saw the events out of order")
	}
	if !batch.committed {
		t.Error("the batch was not committed; the events would be re-claimed forever")
	}
	if len(batch.published) != 2 {
		t.Errorf("MarkPublished was called %d times, want 2", len(batch.published))
	}
}

// An idle outbox is the normal state of a healthy service. RunOnce must report
// zero and no error, and must not have claimed anything to complain about.
func TestServiceRunOnceOnAnIdleOutbox(t *testing.T) {
	t.Parallel()

	pub := newRecordingPublisher()
	svc := NewService(&fakeClaimer{}, pub, discardLogger(), 0)

	n, err := svc.RunOnce(context.Background())
	if err != nil {
		t.Errorf("RunOnce on an idle outbox = %v, want no error", err)
	}
	if n != 0 {
		t.Errorf("RunOnce published %d events on an idle outbox, want 0", n)
	}
	if len(pub.seen()) != 0 {
		t.Error("the publisher was called with nothing to publish")
	}
}

// One poison event must not stop the ones behind it. core's event-naming.md:
// "A consumer that cannot process an event must not block the queue: park it,
// alert, keep going." The same reasoning applies to the publisher: a single
// unserializable event cannot be allowed to wedge the outbox.
func TestServiceKeepsGoingAfterAFailedPublish(t *testing.T) {
	t.Parallel()

	poison := mustUserCreated(t, "poison@example.com")
	good := mustUserCreated(t, "good@example.com")
	batch := &fakeBatch{events: []Envelope{poison, good}}

	pub := newRecordingPublisher()
	pub.fail(poison.ID, errBusDown)
	svc := NewService(&fakeClaimer{batches: []*fakeBatch{batch}}, pub, discardLogger(), 0)

	n, err := svc.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce returned %v; a single failed publish must not fail the batch", err)
	}
	if n != 1 {
		t.Errorf("RunOnce reported %d published, want 1 (the poison event should not be counted)", n)
	}

	// The good one went out.
	if len(pub.seen()) != 1 || pub.seen()[0].ID != good.ID {
		t.Errorf("the publisher saw %v, want just the good event", ids(pub.seen()))
	}
	// The poison one is marked failed, not published, and the batch still commits
	// so the good one is not re-sent on the next pass.
	if len(batch.failed) != 1 || batch.failed[0] != poison.ID {
		t.Errorf("MarkFailed was called for %v, want just %s", batch.failed, poison.ID)
	}
	if len(batch.published) != 1 || batch.published[0] != good.ID {
		t.Errorf("MarkPublished was called for %v, want just %s", batch.published, good.ID)
	}
	if !batch.committed {
		t.Error("the batch was not committed after a partial failure")
	}
}

// The failure reason goes into the row. An operator seeing attempts climb with no
// explanation has nothing to act on.
func TestServiceRecordsWhyAPublishFailed(t *testing.T) {
	t.Parallel()

	poison := mustUserCreated(t, "poison@example.com")
	batch := &fakeBatch{events: []Envelope{poison}}

	pub := newRecordingPublisher()
	pub.fail(poison.ID, errBusDown)
	svc := NewService(&fakeClaimer{batches: []*fakeBatch{batch}}, pub, discardLogger(), 0)

	if _, err := svc.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	if len(batch.reasons) != 1 {
		t.Fatalf("MarkFailed was called %d times, want 1", len(batch.reasons))
	}
	if batch.reasons[0] == "" {
		t.Error("the failure reason is empty; last_error would be useless to an operator")
	}
}

// If the batch cannot even be claimed, that is an infrastructure failure and the
// caller has to hear about it. A loop that swallowed it would spin silently
// forever with a broken database and a green process.
func TestServiceRunOnceReportsAClaimFailure(t *testing.T) {
	t.Parallel()

	svc := NewService(&fakeClaimer{claimErr: errBusDown}, newRecordingPublisher(), discardLogger(), 0)

	if _, err := svc.RunOnce(context.Background()); !errors.Is(err, errBusDown) {
		t.Errorf("RunOnce = %v, want the claim error to surface", err)
	}
}

// The batch is always released, even when the loop is cancelled mid-publish. A
// leaked claim holds a transaction and a row lock until the pool reaps it.
func TestServiceReleasesTheBatchWhenTheContextIsCancelled(t *testing.T) {
	t.Parallel()

	e := mustUserCreated(t, "a@example.com")
	batch := &fakeBatch{events: []Envelope{e}}

	ctx, cancel := context.WithCancel(context.Background())
	pub := newRecordingPublisher()
	pub.blocked = make(chan struct{})
	svc := NewService(&fakeClaimer{batches: []*fakeBatch{batch}}, pub, discardLogger(), 0)

	done := make(chan error, 1)
	go func() {
		_, err := svc.RunOnce(ctx)
		done <- err
	}()

	cancel()
	close(pub.blocked)

	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("RunOnce = %v, want context.Canceled", err)
	}
	if !batch.released {
		t.Error("the batch was not released after cancellation")
	}
	if batch.committed {
		t.Error("a cancelled batch was committed")
	}
}

// The loop stops on its own when its context is done. It must not need an
// external signal, or a SIGTERM would leave it running until the process dies.
func TestServiceRunStopsOnContextCancellation(t *testing.T) {
	t.Parallel()

	pub := newRecordingPublisher()
	svc := NewService(&fakeClaimer{}, pub, discardLogger(), 0)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- svc.Run(ctx) }()

	cancel()

	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("Run = %v, want nil or context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s of its context being cancelled")
	}
}

// NoopPublisher is what ships in this packet: the interface exists, the NATS
// connection is a later one. It must accept events and report success, or the
// loop would mark everything published and the outbox would silently empty into
// nowhere.
func TestNoopPublisherAcceptsWithoutError(t *testing.T) {
	t.Parallel()

	if err := (NoopPublisher{}).Publish(context.Background(), mustUserCreated(t, "a@example.com")); err != nil {
		t.Errorf("NoopPublisher.Publish = %v, want nil", err)
	}
}

// The default batch size has to be a real number, and settable, because a loop
// claiming one event at a time is a loop that cannot catch up.
func TestServiceBatchSize(t *testing.T) {
	t.Parallel()

	if got := NewService(&fakeClaimer{}, newRecordingPublisher(), discardLogger(), 0).BatchSize(); got != DefaultBatchSize {
		t.Errorf("BatchSize() = %d, want the default %d", got, DefaultBatchSize)
	}

	svc := NewService(&fakeClaimer{}, newRecordingPublisher(), discardLogger(), 250)
	if got := svc.BatchSize(); got != 250 {
		t.Errorf("BatchSize() = %d, want 250", got)
	}
}

func ids(events []Envelope) []id.UUID {
	out := make([]id.UUID, 0, len(events))
	for _, e := range events {
		out = append(out, e.ID)
	}
	return out
}
