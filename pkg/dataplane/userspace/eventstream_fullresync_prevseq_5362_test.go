package userspace

import (
	"context"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// TestEventStreamFullResyncAdvancesPrevSeq_5362 pins that a FullResync(S)
// barrier advances prevSeq to S so the first live delta (S+1) is contiguous and
// does NOT trip the session-sync gap check — i.e. no spurious reconnect on the
// active-traffic recovery path.
//
// Setup:
//   - seq 1        session delta          -> establishes prevSeq = 1 (>0, so the
//     gap check is armed)
//   - FullResync(100) barrier             -> re-baselines the sequence; with the
//     fix prevSeq advances to 100
//   - seq 101      session delta (S+1)    -> must be applied contiguously
//
// A session-sync gap firing is observed via SessionSyncResyncs, which is
// incremented ONLY in handleSessionSyncGap (eventstream.go). onFullResync is
// counted too: the barrier legitimately calls it once, but a gap-triggered
// resync would call it a second time.
//
// Fail-on-revert: remove `prevSeq = seq` from the EventTypeFullResync success
// path and prevSeq stays 1 across the barrier, so seq 101 satisfies
// `seq > prevSeq+1 && prevSeq > 0` (101 > 2) → handleSessionSyncGap fires,
// SessionSyncResyncs becomes 1, the connection drops, and seq 101 is never
// applied. The SessionSyncResyncs==0 assertion then goes RED.
func TestEventStreamFullResyncAdvancesPrevSeq_5362(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	es.SetOnEvent(func(uint8, uint64, SessionDeltaInfo) bool { return true })
	var resyncCount atomic.Uint64
	es.SetOnFullResync(func() bool {
		resyncCount.Add(1)
		return true
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	dl := time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(dl) {
			t.Fatal("not connected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	payload := buildSessionOpenV4Payload(
		6, 1000, 80,
		[4]byte{10, 0, 1, 1}, [4]byte{10, 0, 2, 1},
		[4]byte{}, [4]byte{},
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		[6]byte{}, [6]byte{}, [4]byte{},
	)

	const barrierSeq = uint64(100)

	// Establish a contiguous baseline at seq 1 so prevSeq > 0 arms the gap
	// check, then wait for it to be applied.
	if err := writeFrame(conn, EventTypeSessionOpen, 1, payload); err != nil {
		t.Fatalf("write seq 1: %v", err)
	}
	dl = time.Now().Add(2 * time.Second)
	for es.lastAppliedSeq.Load() != 1 {
		if time.Now().After(dl) {
			t.Fatalf("seq 1 not applied; lastApplied=%d", es.lastAppliedSeq.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}

	// FullResync(100) barrier: the sequence jumps far ahead of the pre-barrier
	// prevSeq (a replayed re-baseline). Wait until the barrier is processed
	// (onFullResync called once + applied).
	if err := writeFrame(conn, EventTypeFullResync, barrierSeq, nil); err != nil {
		t.Fatalf("write FullResync(%d): %v", barrierSeq, err)
	}
	dl = time.Now().Add(2 * time.Second)
	for es.lastAppliedSeq.Load() != barrierSeq {
		if time.Now().After(dl) {
			t.Fatalf("FullResync(%d) not applied; lastApplied=%d", barrierSeq, es.lastAppliedSeq.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := resyncCount.Load(); got != 1 {
		t.Fatalf("onFullResync called %d times after the barrier; want exactly 1", got)
	}

	// The first live delta after the barrier is S+1. It must apply contiguously
	// with NO session-sync gap. Wait for it to be applied OR for a gap to fire.
	if err := writeFrame(conn, EventTypeSessionOpen, barrierSeq+1, payload); err != nil {
		t.Fatalf("write seq %d: %v", barrierSeq+1, err)
	}
	dl = time.Now().Add(2 * time.Second)
	for es.lastAppliedSeq.Load() != barrierSeq+1 && es.SessionSyncResyncs.Load() == 0 {
		if time.Now().After(dl) {
			t.Fatalf("post-barrier delta seq %d neither applied nor gapped; lastApplied=%d",
				barrierSeq+1, es.lastAppliedSeq.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}

	if got := es.SessionSyncResyncs.Load(); got != 0 {
		t.Fatalf("session-sync gap fired after FullResync(%d) + delta %d "+
			"(SessionSyncResyncs=%d): the barrier did not advance prevSeq, so the "+
			"first post-barrier delta tripped a spurious reconnect (#5362)",
			barrierSeq, barrierSeq+1, got)
	}
	if got := resyncCount.Load(); got != 1 {
		t.Fatalf("onFullResync called %d times total; want exactly 1 (barrier only, "+
			"no gap-triggered resync)", got)
	}
	if got := es.lastAppliedSeq.Load(); got != barrierSeq+1 {
		t.Fatalf("lastAppliedSeq = %d after the post-barrier delta; want %d "+
			"(the delta must be applied contiguously, not dropped by a gap)", got, barrierSeq+1)
	}
}
