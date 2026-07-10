package lldp

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestRxLoopTTL0WithdrawsNeighborImmediately_5123 is the regression test for
// #5123. IEEE 802.1AB defines a TTL=0 LLDPDU as an explicit shutdown: the
// receiver MUST remove the neighbor immediately. Before the fix the RX path
// stored the shutdown frame as an ordinary neighbor with ExpiresAt==now, so a
// departed peer stayed visible in Neighbors() until the next ~10s expiryLoop
// tick.
//
// The test drives the real rxLoop through the recvFn seam with a deterministic,
// synchronous handshake (no sleeps, no ticker wait): frame 1 is a normal
// (TTL>0) advertisement, frame 2 is that same peer's TTL=0 shutdown. rxLoop
// only calls recvFn for the next frame after it has fully processed the current
// one, so blocking inside recvFn lets the test observe each post-processing
// state exactly once.
//
// RED-on-revert: with the production TTL==0 branch removed, frame 2 refreshes
// the existing key in place (ExpiresAt==now) instead of deleting it, so
// Neighbors() still reports the peer after the shutdown and the final assertion
// fails. expiryLoop does not run in this test, so nothing else can mask the
// lingering entry.
func TestRxLoopTTL0WithdrawsNeighborImmediately_5123(t *testing.T) {
	peerMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x42}

	learnFrame, err := BuildFrame(peerMAC, "peer0", 120, "peer-node", "")
	if err != nil {
		t.Fatalf("BuildFrame (learn): %v", err)
	}
	shutdownFrame, err := BuildFrame(peerMAC, "peer0", 0, "peer-node", "")
	if err != nil {
		t.Fatalf("BuildFrame (shutdown): %v", err)
	}

	var step int32
	gotFrame1 := make(chan struct{}) // closed once rxLoop asks for frame 2 (frame 1 processed)
	releaseFrame2 := make(chan struct{})
	gotFrame2 := make(chan struct{}) // closed once rxLoop asks for frame 3 (frame 2 processed)
	park := make(chan struct{})

	sess := &ifSession{
		iface: &net.Interface{Name: "test0", Index: 1},
		recvFn: func(buf []byte) (int, int, error) {
			switch atomic.AddInt32(&step, 1) {
			case 1:
				return copy(buf, learnFrame), unix.PACKET_HOST, nil
			case 2:
				// Reached only after frame 1 was fully processed
				// (learnNeighbor returned). Signal, then wait for the test to
				// verify the neighbor is present before delivering the shutdown.
				close(gotFrame1)
				<-releaseFrame2
				return copy(buf, shutdownFrame), unix.PACKET_HOST, nil
			case 3:
				// Reached only after the TTL=0 shutdown was fully processed.
				close(gotFrame2)
				<-park
				return 0, 0, unix.EBADF
			default:
				<-park
				return 0, 0, unix.EBADF
			}
		},
	}

	m := New()
	ctx, cancel := context.WithCancel(context.Background())
	loopDone := make(chan struct{})
	go func() {
		m.rxLoop(ctx, sess)
		close(loopDone)
	}()

	// Frame 1 (TTL>0) must learn the neighbor.
	select {
	case <-gotFrame1:
	case <-time.After(2 * time.Second):
		t.Fatal("rxLoop did not process the learn frame")
	}
	if got := len(m.Neighbors()); got != 1 {
		t.Fatalf("after TTL>0 advert: want 1 neighbor, got %d", got)
	}

	// Frame 2 (TTL=0) must withdraw it immediately — no ticker wait.
	close(releaseFrame2)
	select {
	case <-gotFrame2:
	case <-time.After(2 * time.Second):
		t.Fatal("rxLoop did not process the shutdown frame")
	}
	if got := len(m.Neighbors()); got != 0 {
		t.Fatalf("after TTL=0 shutdown: want 0 neighbors (immediate withdrawal), got %d "+
			"(neighbor lingered — TTL=0 was cached instead of deleted)", got)
	}

	cancel()
	close(park)
	select {
	case <-loopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("rxLoop did not exit after ctx cancellation")
	}
}

// TestRxLoopTTL0UnknownNeighborNoInsert_5123 asserts a TTL=0 shutdown for a peer
// that was never learned is a harmless no-op: it must not insert a spurious
// (already-departed) neighbor into the table.
//
// RED-on-revert: without the TTL==0 branch, the shutdown frame is routed through
// learnNeighbor and inserted as a brand-new neighbor (under the cap), so
// Neighbors() reports 1 and the assertion fails.
func TestRxLoopTTL0UnknownNeighborNoInsert_5123(t *testing.T) {
	shutdownFrame, err := BuildFrame(net.HardwareAddr{0x02, 0, 0, 0, 0, 0x99}, "peer9", 0, "ghost", "")
	if err != nil {
		t.Fatalf("BuildFrame (shutdown): %v", err)
	}

	var step int32
	gotFrame := make(chan struct{})
	park := make(chan struct{})

	sess := &ifSession{
		iface: &net.Interface{Name: "test0", Index: 1},
		recvFn: func(buf []byte) (int, int, error) {
			switch atomic.AddInt32(&step, 1) {
			case 1:
				return copy(buf, shutdownFrame), unix.PACKET_HOST, nil
			case 2:
				close(gotFrame) // frame 1 fully processed
				<-park
				return 0, 0, unix.EBADF
			default:
				<-park
				return 0, 0, unix.EBADF
			}
		},
	}

	m := New()
	ctx, cancel := context.WithCancel(context.Background())
	loopDone := make(chan struct{})
	go func() {
		m.rxLoop(ctx, sess)
		close(loopDone)
	}()

	select {
	case <-gotFrame:
	case <-time.After(2 * time.Second):
		t.Fatal("rxLoop did not process the shutdown frame")
	}
	if got := len(m.Neighbors()); got != 0 {
		t.Fatalf("TTL=0 for an unknown peer: want 0 neighbors (no spurious insert), got %d", got)
	}

	cancel()
	close(park)
	select {
	case <-loopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("rxLoop did not exit after ctx cancellation")
	}
}

// TestRxLoopNonZeroTTLStillLearnsAndRefreshes_5123 guards the non-zero TTL path
// against regression from the #5123 change: a normal advertisement still learns
// the neighbor, and a later re-advertisement of the same key refreshes it in
// place (updating the TTL) without growing or dropping the table.
func TestRxLoopNonZeroTTLStillLearnsAndRefreshes_5123(t *testing.T) {
	peerMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x07}
	frame120, err := BuildFrame(peerMAC, "peer7", 120, "peer-node", "")
	if err != nil {
		t.Fatalf("BuildFrame (120): %v", err)
	}
	frame90, err := BuildFrame(peerMAC, "peer7", 90, "peer-node", "")
	if err != nil {
		t.Fatalf("BuildFrame (90): %v", err)
	}

	var step int32
	gotFrame1 := make(chan struct{})
	releaseFrame2 := make(chan struct{})
	gotFrame2 := make(chan struct{})
	park := make(chan struct{})

	sess := &ifSession{
		iface: &net.Interface{Name: "test0", Index: 1},
		recvFn: func(buf []byte) (int, int, error) {
			switch atomic.AddInt32(&step, 1) {
			case 1:
				return copy(buf, frame120), unix.PACKET_HOST, nil
			case 2:
				close(gotFrame1)
				<-releaseFrame2
				return copy(buf, frame90), unix.PACKET_HOST, nil
			case 3:
				close(gotFrame2)
				<-park
				return 0, 0, unix.EBADF
			default:
				<-park
				return 0, 0, unix.EBADF
			}
		},
	}

	m := New()
	ctx, cancel := context.WithCancel(context.Background())
	loopDone := make(chan struct{})
	go func() {
		m.rxLoop(ctx, sess)
		close(loopDone)
	}()

	select {
	case <-gotFrame1:
	case <-time.After(2 * time.Second):
		t.Fatal("rxLoop did not process the first advert")
	}
	if got := m.Neighbors(); len(got) != 1 || got[0].TTL != 120 {
		t.Fatalf("after first advert: want 1 neighbor TTL=120, got %+v", got)
	}

	close(releaseFrame2)
	select {
	case <-gotFrame2:
	case <-time.After(2 * time.Second):
		t.Fatal("rxLoop did not process the refresh advert")
	}
	if got := m.Neighbors(); len(got) != 1 || got[0].TTL != 90 {
		t.Fatalf("after refresh: want 1 neighbor TTL=90 (refreshed in place), got %+v", got)
	}

	cancel()
	close(park)
	select {
	case <-loopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("rxLoop did not exit after ctx cancellation")
	}
}
