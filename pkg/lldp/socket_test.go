package lldp

import (
	"context"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// newSocketpairSession builds an ifSession whose rxFD and txFD are both set
// to one end of a socketpair(2) (fds[0]). A parked unix.Recvfrom on rxFD
// blocks until bytes are written to peerFD (fds[1]) or rxFD is closed, so it
// faithfully reproduces the AF_PACKET RX socket's blocking behaviour without
// CAP_NET_RAW or a real interface. peerFD lets a test feed a frame to recv or
// just sit idle to keep recv parked. The caller owns peerFD and must close it.
//
// SOCK_SEQPACKET (not SOCK_STREAM): the production RX socket is AF_PACKET
// SOCK_RAW, a message-oriented datagram socket where one frame is one recv.
// SEQPACKET preserves that one-write-one-read boundary (so a fed LLDP frame is
// never split across two recv calls), while still being connection-oriented so
// shutdown(SHUT_RDWR)+close on rxFD unblocks a parked reader exactly as the
// close-to-unblock design relies on. SOCK_STREAM would not preserve boundaries
// and could deliver a partial frame to rxLoop.
func newSocketpairSession(t *testing.T, iface *net.Interface) (sess *ifSession, peerFD int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	// fds[0] is the session's rx/tx fd; fds[1] is the test-controlled peer.
	return &ifSession{iface: iface, rxFD: fds[0], txFD: fds[0]}, fds[1]
}

// TestSessionRecvUnblocksOnClose proves the core latency fix: a goroutine parked
// in ifSession.recv returns immediately when close() is called, rather than
// waiting out any read timeout. Without the SO_RCVTIMEO removal + fd-close
// design this could only be observed on a timeout boundary.
func TestSessionRecvUnblocksOnClose(t *testing.T) {
	sess, peerFD := newSocketpairSession(t, &net.Interface{Name: "test0", Index: 1})
	defer unix.Close(peerFD)

	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 64)
		close(started)           // signal: about to enter recv
		_, _, _ = sess.recv(buf) // blocks until close() unblocks the fd
		close(done)
	}()

	// Wait until the goroutine has signalled it is about to call recv, then
	// yield the scheduler so the goroutine has a chance to actually enter the
	// blocking syscall before close() is issued.  This does not provide a
	// hard guarantee that the goroutine is IN recv — a non-blocking wakeup
	// (EBADF on an already-closed fd) would also close done promptly — but
	// the window is negligibly small after Gosched().  The mutation-verified
	// guarantee lives in TestStopUnblocksParkedRX which uses frame injection.
	<-started
	runtime.Gosched()
	select {
	case <-done:
		t.Fatal("recv returned before close() — it should block while no data and fd open")
	default:
	}

	sess.close()

	select {
	case <-done:
		// recv unblocked promptly.
	case <-time.After(2 * time.Second):
		t.Fatal("recv did not unblock within 2s after close() — Stop would stall")
	}
}

// TestSessionCloseIdempotent confirms close() can be called multiple times
// (Stop may race with a never-started generation) without panic or double-close.
func TestSessionCloseIdempotent(t *testing.T) {
	sess, peerFD := newSocketpairSession(t, &net.Interface{Name: "test0", Index: 1})
	defer unix.Close(peerFD)
	sess.close()
	sess.close() // must be a no-op via closeOnce
}

// TestStopUnblocksParkedRX is the regression test for the 0-2s shutdown tail
// (#2035). It installs a socketpair-backed session via the newIfSessionFn seam,
// starts the RX goroutine through the normal Manager.Apply path, then asserts
// Stop() returns well within a deadline far below the old 2s SO_RCVTIMEO floor.
//
// Against the pre-fix code (SO_RCVTIMEO=2s, cancel-then-Wait with no fd close)
// this Stop would block up to ~2s; the 250ms deadline makes the test fail if
// that behaviour is reintroduced.
func TestStopUnblocksParkedRX(t *testing.T) {
	var peerFDs []int
	var mu sync.Mutex
	prev := newIfSessionFn
	newIfSessionFn = func(iface *net.Interface) (*ifSession, error) {
		sess, peerFD := newSocketpairSession(t, iface)
		mu.Lock()
		peerFDs = append(peerFDs, peerFD)
		mu.Unlock()
		return sess, nil
	}
	t.Cleanup(func() {
		newIfSessionFn = prev
		for _, fd := range peerFDs {
			unix.Close(fd)
		}
	})

	m := New()
	// Use loopback so net.InterfaceByName resolves on any host; the real socket
	// is never opened because newIfSessionFn is stubbed.
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("no loopback interface: %v", err)
	}
	cfg := &LLDPConfig{
		Interfaces: []LLDPInterface{{Name: lo.Name}},
		Interval:   30,
	}
	m.Apply(context.Background(), cfg)

	// Inject a valid LLDP frame on each peer fd so rxLoop processes it and
	// then parks in recv again — this proves the goroutine has actually entered
	// the recv syscall at least once before Stop() is called, making the
	// timing assertion meaningful.  A bare sleep cannot guarantee this.
	frame, frameErr := BuildFrame(lo.HardwareAddr, lo.Name, 120, "test-node", "")
	if frameErr != nil {
		t.Fatalf("BuildFrame: %v", frameErr)
	}
	mu.Lock()
	peers := make([]int, len(peerFDs))
	copy(peers, peerFDs)
	mu.Unlock()
	for _, fd := range peers {
		if _, err := unix.Write(fd, frame); err != nil {
			t.Fatalf("write LLDP frame to peer fd: %v", err)
		}
	}
	// Poll until rxLoop has processed the frame (proves recv ran at least once).
	// There is no subscription API on Manager; polling is the simplest
	// race-free alternative to a bare sleep.
	const pollLimit = 500 * time.Millisecond
	pollDeadline := time.Now().Add(pollLimit)
	for time.Now().Before(pollDeadline) {
		if len(m.Neighbors()) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(m.Neighbors()) == 0 {
		t.Fatalf("rxLoop did not process the injected LLDP frame within %v", pollLimit)
	}

	start := time.Now()
	doneCh := make(chan struct{})
	go func() {
		m.Stop()
		close(doneCh)
	}()
	select {
	case <-doneCh:
		if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
			t.Fatalf("Stop() took %v with a parked RX goroutine; "+
				"expected well under 250ms (the old SO_RCVTIMEO floor was ~2s)", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() did not return within 2s with a parked RX goroutine — " +
			"the shutdown stall regressed")
	}

	// Stop cleared sessions; a second Stop must remain a safe no-op.
	m.Stop()
}

// TestRxLoopRetriesTransientRecvErrors is the regression test for the rxLoop
// transient-error fix (#2035 review). On a long-running daemon, unix.Recvfrom
// can return EINTR (signal forwarded through the Go runtime) or, defensively,
// EAGAIN. The pre-fix rxLoop returned on the first non-cancel error, silently
// killing neighbor discovery until the next Apply(). The fix retries EINTR and
// EAGAIN/EWOULDBLOCK and keeps the loop alive.
//
// This drives rxLoop directly through the recvFn seam: it returns EINTR, then
// EAGAIN, then exactly one valid LLDP frame, then blocks until ctx is cancelled.
// Without the retry the loop exits before the frame is delivered and no neighbor
// is learned; with the retry the neighbor appears. The loop must then exit
// cleanly when ctx is cancelled (proving cancellation still wins).
func TestRxLoopRetriesTransientRecvErrors(t *testing.T) {
	frame, err := BuildFrame(net.HardwareAddr{0x02, 0, 0, 0, 0, 1}, "test0", 120, "peer-node", "")
	if err != nil {
		t.Fatalf("BuildFrame: %v", err)
	}
	// BuildFrame already includes the Ethernet header; rxLoop skips ethHdrLen
	// bytes before parsing TLVs, so confirm the frame is longer than the header.
	if len(frame) <= ethHdrLen {
		t.Fatalf("frame too short: %d bytes", len(frame))
	}

	gate := make(chan struct{})
	var step int32
	sess := &ifSession{
		iface: &net.Interface{Name: "test0", Index: 1},
		recvFn: func(buf []byte) (int, int, error) {
			switch atomic.AddInt32(&step, 1) {
			case 1:
				return 0, 0, unix.EINTR // must be retried, not fatal
			case 2:
				return 0, 0, unix.EAGAIN // must be retried, not fatal
			case 3:
				return copy(buf, frame), unix.PACKET_HOST, nil // the one real frame
			default:
				// Park until ctx is cancelled, then report a fatal error so
				// rxLoop takes the cancel-exit path.
				<-gate
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

	// The neighbor only appears if rxLoop survived the EINTR + EAGAIN returns.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(m.Neighbors()) > 0 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if got := len(m.Neighbors()); got != 1 {
		t.Fatalf("rxLoop did not survive transient recv errors: want 1 neighbor, got %d "+
			"(it exited on EINTR/EAGAIN instead of retrying)", got)
	}

	// Cancellation must still terminate the loop promptly.
	cancel()
	close(gate)
	select {
	case <-loopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("rxLoop did not exit after ctx cancellation")
	}
}

// TestRxLoopSurvivesNonTransientRecvError is the regression test for the #2040
// MAJOR: an UNEXPECTED recv error (not EINTR/EAGAIN, and ctx still live — e.g.
// ENETDOWN from a flapped interface) must NOT permanently kill the RX loop.
// Nothing restarts rxLoop short of a daemon restart (LLDP is Apply()'d once at
// startup), so a pre-fix `return` on such an error silently ends neighbor
// discovery for the life of the process. The fix backs off and retries.
//
// Non-tautological: step 1 returns ENETDOWN with the context live; the real
// frame is only delivered on step 2. If rxLoop returned on the ENETDOWN (the
// pre-fix behavior), the loop would exit before step 2 and no neighbor would
// ever appear, failing the assertion.
func TestRxLoopSurvivesNonTransientRecvError(t *testing.T) {
	// Shrink the backoff so the retry happens within the test's poll window
	// instead of the 1s production default.
	prevBackoff := rxErrorBackoff
	rxErrorBackoff = 1 * time.Millisecond
	t.Cleanup(func() { rxErrorBackoff = prevBackoff })

	frame, err := BuildFrame(net.HardwareAddr{0x02, 0, 0, 0, 0, 1}, "test0", 120, "peer-node", "")
	if err != nil {
		t.Fatalf("BuildFrame: %v", err)
	}
	if len(frame) <= ethHdrLen {
		t.Fatalf("frame too short: %d bytes", len(frame))
	}

	gate := make(chan struct{})
	var step int32
	sess := &ifSession{
		iface: &net.Interface{Name: "test0", Index: 1},
		recvFn: func(buf []byte) (int, int, error) {
			switch atomic.AddInt32(&step, 1) {
			case 1:
				// Non-transient operational error with ctx live: the loop must
				// back off and retry, NOT exit.
				return 0, 0, unix.ENETDOWN
			case 2:
				return copy(buf, frame), unix.PACKET_HOST, nil // the one real frame, post-recovery
			default:
				// Park until ctx is cancelled, then report a fatal error so
				// rxLoop takes the cancel-exit path.
				<-gate
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

	// The neighbor only appears if rxLoop survived the ENETDOWN by backing off
	// and retrying into step 2.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(m.Neighbors()) > 0 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if got := len(m.Neighbors()); got != 1 {
		t.Fatalf("rxLoop did not survive a non-transient recv error: want 1 neighbor, got %d "+
			"(it exited on ENETDOWN instead of backing off and retrying)", got)
	}

	// Cancellation must still terminate the loop promptly, including when the
	// loop is parked in recv (not in the backoff).
	cancel()
	close(gate)
	select {
	case <-loopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("rxLoop did not exit after ctx cancellation")
	}
}

// TestRxLoopBackoffInterruptedByCancel proves the backoff sleep itself is
// interruptible: if Stop() cancels the context while rxLoop is sleeping out the
// post-error backoff, the loop returns promptly rather than waiting out the
// delay. Uses a long backoff so a non-interruptible sleep would blow the
// deadline.
func TestRxLoopBackoffInterruptedByCancel(t *testing.T) {
	prevBackoff := rxErrorBackoff
	rxErrorBackoff = 30 * time.Second // long enough that a blocking sleep fails the test
	t.Cleanup(func() { rxErrorBackoff = prevBackoff })

	entered := make(chan struct{})
	var once sync.Once
	sess := &ifSession{
		iface: &net.Interface{Name: "test0", Index: 1},
		recvFn: func(buf []byte) (int, int, error) {
			// Signal once that we have entered recv and are about to return the
			// non-transient error that drives rxLoop into the backoff select.
			once.Do(func() { close(entered) })
			return 0, 0, unix.ENETDOWN
		},
	}

	m := New()
	ctx, cancel := context.WithCancel(context.Background())
	loopDone := make(chan struct{})
	go func() {
		m.rxLoop(ctx, sess)
		close(loopDone)
	}()

	<-entered
	// Give rxLoop a moment to reach the backoff select, then cancel.
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case <-loopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("rxLoop did not exit during the backoff after ctx cancellation (backoff not interruptible)")
	}
}

// TestApplySkipsInterfaceOnSocketError verifies that a session construction
// failure (e.g. CAP_NET_RAW missing) is surfaced at Apply time by skipping the
// interface, and that Stop() afterwards is still a clean no-op.
func TestApplySkipsInterfaceOnSocketError(t *testing.T) {
	prev := newIfSessionFn
	newIfSessionFn = func(iface *net.Interface) (*ifSession, error) {
		return nil, unix.EPERM
	}
	t.Cleanup(func() { newIfSessionFn = prev })

	m := New()
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("no loopback interface: %v", err)
	}
	m.Apply(context.Background(), &LLDPConfig{
		Interfaces: []LLDPInterface{{Name: lo.Name}},
	})

	m.mu.RLock()
	nSessions := len(m.sessions)
	m.mu.RUnlock()
	if nSessions != 0 {
		t.Fatalf("expected 0 sessions when socket setup fails, got %d", nSessions)
	}

	// No goroutines bound to a session should be running; Stop must return at
	// once (the expiry loop is the only goroutine, cancel unblocks it).
	doneCh := make(chan struct{})
	go func() { m.Stop(); close(doneCh) }()
	select {
	case <-doneCh:
	case <-time.After(time.Second):
		t.Fatal("Stop() stalled after Apply skipped all interfaces")
	}
}

// TestRxLoopSkipsSelfTransmittedFrames is the fail-on-revert regression test
// for #2992. The LLDP RX AF_PACKET socket is bound to ETH_P_LLDP and also
// receives this host's OWN transmitted LLDP advertisements, which the kernel
// loops back marked PACKET_OUTGOING. Without a pkttype filter the daemon parses
// those frames and learns itself as a neighbor on every LLDP-enabled link.
//
// This drives rxLoop through the recvFn seam: step 1 delivers a valid LLDP
// frame marked PACKET_OUTGOING (the host's own advertisement looped back) — it
// MUST be skipped; step 2 delivers an otherwise-identical valid LLDP frame
// marked PACKET_HOST (a genuine inbound peer frame) — it MUST be learned.
//
// Non-tautological / fail-on-revert: if the `pkttype == unix.PACKET_OUTGOING`
// skip in rxLoop is removed, the step-1 self frame is learned too, so the
// neighbor table holds the self chassis and the strict "exactly the peer,
// never the self" assertions fail.
func TestRxLoopSkipsSelfTransmittedFrames(t *testing.T) {
	selfMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0xAA}
	peerMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0xBB}

	selfFrame, err := BuildFrame(selfMAC, "self0", 120, "self-node", "")
	if err != nil {
		t.Fatalf("BuildFrame self: %v", err)
	}
	peerFrame, err := BuildFrame(peerMAC, "peer0", 120, "peer-node", "")
	if err != nil {
		t.Fatalf("BuildFrame peer: %v", err)
	}

	// ParseTLVs renders a MAC chassis ID via net.HardwareAddr.String().
	selfChassis := selfMAC.String()
	peerChassis := peerMAC.String()

	gate := make(chan struct{})
	var step int32
	sess := &ifSession{
		iface: &net.Interface{Name: "test0", Index: 1},
		recvFn: func(buf []byte) (int, int, error) {
			switch atomic.AddInt32(&step, 1) {
			case 1:
				// The host's own advertisement looped back on the RX socket.
				// MUST be skipped (not learned).
				return copy(buf, selfFrame), unix.PACKET_OUTGOING, nil
			case 2:
				// A genuine inbound peer frame. MUST be learned.
				return copy(buf, peerFrame), unix.PACKET_HOST, nil
			default:
				// Park until ctx is cancelled, then report a fatal error so
				// rxLoop takes the cancel-exit path.
				<-gate
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

	// Wait until the peer frame has been processed (the only frame that should
	// ever produce a neighbor).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(m.Neighbors()) > 0 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}

	neighbors := m.Neighbors()
	if len(neighbors) != 1 {
		t.Fatalf("want exactly 1 learned neighbor (the peer), got %d: %+v "+
			"(the PACKET_OUTGOING self frame must be skipped, not learned)",
			len(neighbors), neighbors)
	}
	got := neighbors[0]
	if got.ChassisID == selfChassis {
		t.Fatalf("daemon learned its OWN transmitted frame (chassis %q) as a neighbor", selfChassis)
	}
	if got.ChassisID != peerChassis {
		t.Fatalf("learned neighbor chassis = %q, want peer %q (self %q must be skipped)",
			got.ChassisID, peerChassis, selfChassis)
	}

	cancel()
	close(gate)
	select {
	case <-loopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("rxLoop did not exit after ctx cancellation")
	}
}
