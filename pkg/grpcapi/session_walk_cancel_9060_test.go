package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// cancelCountDP9060 offers a fixed number of synthetic forward sessions and
// records how many the walk actually visited before it stopped. Same shape as
// pkg/api's cancelCountDP, which guards the REST side of the identical
// property.
type cancelCountDP9060 struct {
	*dataplane.Manager
	nV4, nV6 int
	visited  int
	cancel   context.CancelFunc
	after    int
}

func (d *cancelCountDP9060) IsLoaded() bool { return true }

func (d *cancelCountDP9060) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for i := 0; i < d.nV4; i++ {
		d.visited++
		// Cancel from INSIDE the walk, at a known point. A cancel before the
		// call would be answered by an entry check and would not prove the
		// walk itself can be interrupted, which is the property.
		if d.cancel != nil && d.visited == d.after {
			d.cancel()
		}
		var k dataplane.SessionKey
		var v dataplane.SessionValue // IsReverse == 0 -> matchV4 admits it
		if !fn(k, v) {
			return nil
		}
	}
	return nil
}

func (d *cancelCountDP9060) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	for i := 0; i < d.nV6; i++ {
		d.visited++
		var k dataplane.SessionKeyV6
		var v dataplane.SessionValueV6
		if !fn(k, v) {
			return nil
		}
	}
	return nil
}

// #9060: the legacy GetSessions walk had no cancellation. Both callbacks
// unconditionally returned true, so once started it ran to EOF — holding one of
// four session-walk slots that REST SHARES. Four abandoned legacy calls block
// every REST and gRPC session scan until each finishes on its own, so a poller
// that times out keeps paying, on a surface it did not call.
//
// Both shipped clients take this path: cmd/cli sends Limit:100 with no PageSize
// and pkg/cli sends Limit:10000, and only PageSize > 0 reaches the bounded
// cursor walk.
func TestLegacySessionWalkAbortsOnCancel9060(t *testing.T) {
	// Many sampling windows past the interval, so a correct abort visits far
	// fewer than the whole table and the difference is unambiguous.
	const n = 20 * sessionWalkCancelInterval9060

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dp := &cancelCountDP9060{
		Manager: dataplane.New(), nV4: n,
		cancel: cancel, after: sessionWalkCancelInterval9060 / 2,
	}
	s := newViewServer(t, dp)

	_, err := s.getSessionsLegacy(ctx, &pb.GetSessionsRequest{Limit: 10000})

	if dp.visited >= n {
		t.Errorf("the walk visited %d of %d entries after the caller went away; it "+
			"cannot be aborted, and it holds one of four slots REST shares",
			dp.visited, n)
	}
	if err == nil {
		t.Error("a cancelled walk returned success. Its Total counts only the rows " +
			"seen so far, so a client reading that as an answer concludes sessions " +
			"disappeared — the #2469 partial-as-success shape")
	} else if status.Code(err) != codes.Canceled {
		t.Errorf("a cancelled walk must report Canceled so a caller can tell "+
			"'you went away' from 'the walk broke', got %v", status.Code(err))
	}
}

// NARROWNESS: an UNCANCELLED walk must still complete and return every row.
// Without this, "abort the walk" is satisfied by a walk that always aborts.
func TestUncancelledSessionWalkStillCompletes9060(t *testing.T) {
	const n = 3 * sessionWalkCancelInterval9060
	dp := &cancelCountDP9060{Manager: dataplane.New(), nV4: n}
	s := newViewServer(t, dp)

	resp, err := s.getSessionsLegacy(context.Background(), &pb.GetSessionsRequest{Limit: 10000})
	if err != nil {
		t.Fatalf("an uncancelled walk must succeed: %v", err)
	}
	if dp.visited != n {
		t.Errorf("the walk visited %d of %d entries with no cancellation", dp.visited, n)
	}
	if resp.GetTotal() != int32(n) {
		t.Errorf("Total = %d, want %d", resp.GetTotal(), n)
	}
}

// The sampler's contract, driven directly: it must LATCH (so a walk cannot
// resume after observing cancellation) and it must sample rather than probe
// every call (a ctx.Err() read per entry adds lock traffic across a
// multi-million-entry table, which is why REST samples too).
func TestCancelSamplerLatchesAndSamples9060(t *testing.T) {
	const every = 4

	// SAMPLING: with the context already cancelled, the sampler must not
	// observe it until the window elapses. Asserting this is what stops a later
	// "fix" from probing ctx.Err() per entry — the reason it samples is that a
	// per-entry read adds lock traffic across a multi-million-entry table, and a
	// change that quietly made it exact would look like an improvement.
	dead, cancelDead := context.WithCancel(context.Background())
	cancelDead()
	sampler := newSessionWalkCancelSampler(dead, every)
	for i := 1; i < every; i++ {
		if sampler() {
			t.Fatalf("the sampler observed cancellation at call %d of a %d-call "+
				"window; it is probing per entry, not sampling", i, every)
		}
	}
	if !sampler() {
		t.Fatalf("the sampler did not observe cancellation at call %d, the end of "+
			"its window; a walk would keep running past a dead client", every)
	}
	// LATCHING: once observed it must stay observed, or a walk could resume
	// after deciding to stop. Note this is a property of the captured flag, not
	// of the early-return fast path in the sampler -- deleting that early return
	// survives this assertion, correctly, because it guards nothing.
	for i := 0; i < 5; i++ {
		if !sampler() {
			t.Fatal("the sampler un-latched after observing cancellation")
		}
	}

	// And on a LIVE context it must never report cancelled, however long the
	// walk runs — otherwise it aborts healthy walks.
	live := newSessionWalkCancelSampler(context.Background(), every)
	for i := 0; i < 10*every; i++ {
		if live() {
			t.Fatalf("the sampler reported cancellation at call %d of a LIVE "+
				"context", i)
		}
	}
}
