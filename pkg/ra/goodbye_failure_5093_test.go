package ra

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/mdlayher/ndp"

	"github.com/psaab/xpf/pkg/config"
)

// installFailingWriteListen wires listenFn/ensureLinkLocalFn so every opened
// conn BINDS successfully but FAILS every WriteTo with writeErr — simulating an
// interface that goes down between the bind and the lifetime-0 goodbye write.
// It is the seam that forces the goodbye path's write failure so a test can
// prove the failure is surfaced, not swallowed (#5093).
func installFailingWriteListen(t *testing.T, writeErr error) {
	t.Helper()
	origListen := listenFn
	origEnsure := ensureLinkLocalFn
	t.Cleanup(func() { listenFn = origListen; ensureLinkLocalFn = origEnsure })
	ensureLinkLocalFn = func(*net.Interface) error { return nil }
	listenFn = func(iface *net.Interface, _ ndp.Addr) (ndpConn, netip.Addr, error) {
		fc := newFakeConn()
		fc.setWriteErr(writeErr)
		return fc, netip.MustParseAddr("fe80::1"), nil
	}
}

// TestSendGoodbyeStandaloneSurfacesWriteFailure is the signature-stable
// behavioral guard for the swallow fix. With the bind succeeding but every
// WriteTo failing, sendGoodbyeStandalone MUST return a non-nil error wrapping
// errGoodbyeWrite. Before #5093 it discarded sendGoodbyeRA's bool and returned
// nil after any successful bind, so a failed goodbye looked like a success.
// Reverting the fix flips the return back to nil and this test fails RED.
func TestSendGoodbyeStandaloneSurfacesWriteFailure(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	writeErr := errors.New("simulated interface-down write failure")
	installFailingWriteListen(t, writeErr)

	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("InterfaceByName(lo): %v", err)
	}
	s := newSender(testCfg("lo"), iface)
	err = s.sendGoodbyeStandalone()
	if err == nil {
		t.Fatal("sendGoodbyeStandalone returned nil on a failed goodbye write (swallowed failure)")
	}
	if !errors.Is(err, errGoodbyeWrite) {
		t.Fatalf("want error wrapping errGoodbyeWrite, got %v", err)
	}
}

// TestWithdrawOnceSurfacesGoodbyeWriteFailure proves the cold-boot entry point
// reports a per-interface failure (Sent=false, Err set) instead of returning
// silently, so the daemon can retain retry debt. Before #5093 WithdrawOnce was
// void — a failed goodbye produced no signal at all.
func TestWithdrawOnceSurfacesGoodbyeWriteFailure(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	installFailingWriteListen(t, errors.New("simulated write failure"))

	m := New()
	results := m.WithdrawOnce([]*config.RAInterfaceConfig{testCfg("lo")})
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d: %+v", len(results), results)
	}
	r := results[0]
	if r.Interface != "lo" {
		t.Fatalf("result interface = %q, want lo", r.Interface)
	}
	if r.Sent {
		t.Fatal("goodbye write failed but result reports Sent=true (swallowed failure)")
	}
	if r.Skipped {
		t.Fatal("interface was claimed and attempted; Skipped must be false")
	}
	if r.Err == nil {
		t.Fatal("goodbye write failed but Err is nil (swallowed failure)")
	}
	if !errors.Is(r.Err, errGoodbyeWrite) {
		t.Fatalf("want error wrapping errGoodbyeWrite, got %v", r.Err)
	}
}

// TestWithdrawOnceReportsSuccess proves the happy path reports Sent=true with
// no error, and that the RA actually emitted was a lifetime-0 goodbye (never a
// normal RA that would re-advertise the router being withdrawn).
func TestWithdrawOnceReportsSuccess(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	getConn, _ := installFakeListen(t)

	m := New()
	results := m.WithdrawOnce([]*config.RAInterfaceConfig{testCfg("lo")})
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d: %+v", len(results), results)
	}
	r := results[0]
	if !r.Sent || r.Err != nil || r.Skipped {
		t.Fatalf("want Sent=true Err=nil Skipped=false, got %+v", r)
	}

	conn := getConn("lo")
	if conn == nil {
		t.Fatal("no conn opened for lo")
	}
	writes := conn.snapshot()
	if len(writes) == 0 {
		t.Fatal("no RA written for the goodbye")
	}
	for i, w := range writes {
		if w.lifetime != 0 {
			t.Fatalf("goodbye write %d had router lifetime %v, want 0", i, w.lifetime)
		}
	}
}
