package cluster

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// preAuthTestAddr is a minimal net.Addr with a settable "ip:port" string so a
// #5303 admission test can present peer vs. non-peer remote addresses.
type preAuthTestAddr string

func (a preAuthTestAddr) Network() string { return "tcp" }
func (a preAuthTestAddr) String() string  { return string(a) }

// preAuthTestConn is a stub net.Conn that records Close() and reports a fixed
// remote address. Read returns EOF and Write is a sink — no test drives real
// I/O through it; it only exercises the admission/tracking bookkeeping.
type preAuthTestConn struct {
	remote preAuthTestAddr
	closed atomic.Bool
}

func newPreAuthTestConn(remote string) *preAuthTestConn {
	return &preAuthTestConn{remote: preAuthTestAddr(remote)}
}

func (c *preAuthTestConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *preAuthTestConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *preAuthTestConn) Close() error                     { c.closed.Store(true); return nil }
func (c *preAuthTestConn) LocalAddr() net.Addr              { return preAuthTestAddr("127.0.0.1:0") }
func (c *preAuthTestConn) RemoteAddr() net.Addr             { return c.remote }
func (c *preAuthTestConn) SetDeadline(time.Time) error      { return nil }
func (c *preAuthTestConn) SetReadDeadline(time.Time) error  { return nil }
func (c *preAuthTestConn) SetWriteDeadline(time.Time) error { return nil }

// TestPreAuthAdmissionCapReservesPeerSlot verifies the #5303 fix: a flood of
// pre-auth connections beyond the general pool is closed immediately, AND a
// reserved slot still admits the legitimate peer even while the general pool is
// saturated (the DoS-denies-reconnect property).
//
// RED on revert: neutralizing the reservation subtraction in beginSetup
// (`limit = preAuthSetupCap - preAuthPeerReserve` → `limit = preAuthSetupCap`)
// lets a non-peer flood fill all preAuthSetupCap slots, so the excess flood
// connection is admitted and the "excess rejected" assertion fails.
func TestPreAuthAdmissionCapReservesPeerSlot(t *testing.T) {
	s := NewSessionSync("10.0.0.1:9999", "10.0.0.2:9999", nil)

	// A non-peer flood can fill only the general pool (cap minus the peer
	// reserve). Each admitted connection holds a counted slot.
	general := preAuthSetupCap - preAuthPeerReserve
	for i := 0; i < general; i++ {
		c := newPreAuthTestConn("10.0.0.99:40000")
		if !s.beginSetup(c, true) {
			t.Fatalf("flood conn %d denied while the general pool still had room "+
				"(in-flight=%d, general=%d)", i, i, general)
		}
	}

	// General pool full: the next non-peer connection is rejected and closed
	// immediately, without allocating the large socket buffers.
	excess := newPreAuthTestConn("10.0.0.99:40001")
	if s.beginSetup(excess, true) {
		t.Fatalf("excess flood connection admitted past the general-pool cap (%d) — "+
			"the #5303 admission cap does not bound the flood", general)
	}
	s.notePreAuthRejected(excess)
	excess.Close()
	if !excess.closed.Load() {
		t.Fatal("rejected flood connection was not closed immediately")
	}

	// The legitimate peer STILL gets a reserved slot even though the general
	// pool is saturated — a peer must always be able to reconnect under flood.
	peer := newPreAuthTestConn("10.0.0.2:55555")
	if !s.beginSetup(peer, true) {
		t.Fatal("legitimate peer denied admission while a flood saturated the general " +
			"pool (#5303 reservation reverted): the peer must always be able to reconnect")
	}

	if got := s.stats.PreAuthRejected.Load(); got != 1 {
		t.Fatalf("PreAuthRejected = %d, want 1", got)
	}

	// finishSetup frees a counted slot so a later connection is re-admitted.
	s.finishSetup(peer)
	reuse := newPreAuthTestConn("10.0.0.2:55556")
	if !s.beginSetup(reuse, true) {
		t.Fatal("slot not freed after finishSetup — a peer reconnect should be re-admitted")
	}
}

// TestPreAuthOutboundBypassesCap verifies that our own outbound dials are never
// rejected by the inbound flood cap and do not consume a counted slot: even
// with the whole cap saturated by inbound setups, an outbound registration
// succeeds. This keeps a peer we dial from being starved by an inbound flood.
func TestPreAuthOutboundBypassesCap(t *testing.T) {
	s := NewSessionSync("10.0.0.1:9999", "10.0.0.2:9999", nil)
	// Saturate the entire inbound cap with peer-sourced inbound setups.
	for i := 0; i < preAuthSetupCap; i++ {
		c := newPreAuthTestConn("10.0.0.2:40000")
		if !s.beginSetup(c, true) {
			t.Fatalf("inbound peer conn %d denied below cap", i)
		}
	}
	if s.beginSetup(newPreAuthTestConn("10.0.0.2:40001"), true) {
		t.Fatal("inbound admitted past a saturated cap")
	}
	// Outbound is never capped.
	out := newPreAuthTestConn("10.0.0.2:9999")
	if !s.beginSetup(out, false) {
		t.Fatal("outbound dial rejected by the inbound admission cap (#5303): " +
			"our own dial must never be starved by an inbound flood")
	}
	// It must be tracked for shutdown but must NOT have consumed a counted slot.
	s.finishSetup(out)
	if s.preAuthInFlight != preAuthSetupCap {
		t.Fatalf("outbound registration perturbed the inbound in-flight count: got %d, want %d",
			s.preAuthInFlight, preAuthSetupCap)
	}
}

// TestPreAuthDefersBufferSizingUntilAuth binds the #5303 buffer deferral: the
// large (256 KiB) socket buffers must not be sized until AFTER the handshake
// succeeds. It drives handleNewConnection with a keyed node whose handshake
// FAILS and asserts configureConnFn was never invoked.
//
// RED on revert: moving the configureConnFn(conn) call from after the
// handshake-success check back to the top of handleNewConnection (the pre-fix
// placement) sizes the buffers unconditionally, so it runs even when the
// handshake fails and this assertion goes RED.
func TestPreAuthDefersBufferSizingUntilAuth(t *testing.T) {
	var configured atomic.Bool
	orig := configureConnFn
	configureConnFn = func(c net.Conn) {
		configured.Store(true)
		orig(c)
	}
	defer func() { configureConnFn = orig }()

	// Keyed node — a handshake is attempted (and here, forced to fail).
	s := newAuthSync(t, []byte("psk-secret-key-for-5303-deferral-test"))

	cli, srv := net.Pipe()
	// Mirror the accept path: register the inbound connection, then run setup.
	if !s.beginSetup(srv, true) {
		t.Fatal("beginSetup should admit the first inbound connection")
	}
	done := make(chan struct{})
	go func() {
		s.handleNewConnection(context.Background(), 0, srv)
		close(done)
	}()

	// Peer side reads the server's HELLO, then closes — failing the handshake.
	_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := readSyncFrameRaw(cli); err != nil {
		t.Fatalf("did not receive server HELLO: %v", err)
	}
	cli.Close()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handleNewConnection did not return after handshake failure")
	}

	if configured.Load() {
		t.Fatal("large socket buffers were sized before the handshake succeeded " +
			"(#5303 deferral reverted): configureConnFn must run only AFTER " +
			"performSyncHandshake succeeds")
	}
	// The failed-handshake connection must have released its admission slot.
	if s.preAuthInFlight != 0 {
		t.Fatalf("pre-auth slot not released after handshake failure: in-flight=%d, want 0",
			s.preAuthInFlight)
	}
}

// TestStopClosesInFlightSetupConns verifies the #5303 shutdown fix: Stop()
// closes every connection still in its pre-auth setup window so a stalled
// handshake unblocks and shutdown does not hang.
//
// RED on revert: removing the s.closeSetupConns() call from Stop() leaves the
// in-flight setup connections open and this assertion goes RED.
func TestStopClosesInFlightSetupConns(t *testing.T) {
	s := newAuthSync(t, nil)

	conns := make([]*preAuthTestConn, 0, 3)
	for i := 0; i < 3; i++ {
		c := newPreAuthTestConn("10.0.0.50:6000")
		if !s.beginSetup(c, true) {
			t.Fatalf("beginSetup %d failed", i)
		}
		conns = append(conns, c)
	}

	// Stop() on a never-Started SessionSync: cancel is nil (guarded), listeners
	// are nil (guarded), conn0/conn1 are nil, and the wait group is empty — so it
	// only exercises closeSetupConns and returns immediately.
	s.Stop()

	for i, c := range conns {
		if !c.closed.Load() {
			t.Fatalf("Stop did not close in-flight setup conn %d (#5303 close-on-stop "+
				"reverted): a stalled pre-auth connection would hang shutdown", i)
		}
	}
}
