package ra

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"

	"github.com/psaab/xpf/pkg/config"
)

// #5302 (codex-review-178 A5-b1-F5): sender.go marshals the ICMPv6 source
// link-layer address (SLLA) from s.iface.HardwareAddr, a net.Interface value
// snapshot taken at Start. After a day-2 RETH/VLAN virtual-MAC change, RA
// reconciliation keeps the sender and only requests a burst — so without a
// pre-burst re-resolve the burst advertises the OLD cached MAC and hosts point
// the router's neighbor entry at a MAC the active node no longer owns (IPv6
// blackhole). The fix re-resolves the interface (owner-serialized) in the
// burstCh handler before the burst.

// captureConn is a minimal ndpConn double recording the Source LLA of every RA
// written, so a test can assert which MAC the burst advertised. ReadFrom
// mirrors fakeConn (serialize_test.go): a timeout so rsReceiver polls stopCh,
// and errClosed once Close is called.
type captureConn struct {
	mu     sync.Mutex
	slla   []net.HardwareAddr
	closed chan struct{}
	once   sync.Once
}

func newCaptureConn() *captureConn { return &captureConn{closed: make(chan struct{})} }

func (c *captureConn) WriteTo(m ndp.Message, _ *ipv6.ControlMessage, _ netip.Addr) error {
	ra, ok := m.(*ndp.RouterAdvertisement)
	if !ok {
		return nil
	}
	for _, opt := range ra.Options {
		if lla, ok := opt.(*ndp.LinkLayerAddress); ok && lla.Direction == ndp.Source {
			c.mu.Lock()
			c.slla = append(c.slla, append(net.HardwareAddr(nil), lla.Addr...))
			c.mu.Unlock()
		}
	}
	return nil
}

func (c *captureConn) ReadFrom() (ndp.Message, *ipv6.ControlMessage, netip.Addr, error) {
	select {
	case <-c.closed:
		return nil, nil, netip.Addr{}, errClosed{}
	case <-time.After(20 * time.Millisecond):
		return nil, nil, netip.Addr{}, errTimeout{}
	}
}

func (c *captureConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *captureConn) SetReadDeadline(time.Time) error                 { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error                { return nil }
func (c *captureConn) JoinGroup(netip.Addr) error                      { return nil }
func (c *captureConn) SetICMPFilter(*ipv6.ICMPFilter) error            { return nil }
func (c *captureConn) SetControlMessage(ipv6.ControlFlags, bool) error { return nil }

func (c *captureConn) sawSLLA(mac net.HardwareAddr) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, a := range c.slla {
		if a.String() == mac.String() {
			return true
		}
	}
	return false
}

func (c *captureConn) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.slla)
}

func (c *captureConn) all() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.slla))
	for i, a := range c.slla {
		out[i] = a.String()
	}
	return out
}

func waitFor5302(cond func() bool) bool {
	for i := 0; i < 200; i++ { // up to ~4s
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cond()
}

func installRARefreshSeams(t *testing.T, cc *captureConn, ifByName func(string) (*net.Interface, error)) {
	t.Helper()
	oL, oE, oI := listenFn, ensureLinkLocalFn, interfaceByNameFn
	t.Cleanup(func() {
		listenFn, ensureLinkLocalFn, interfaceByNameFn = oL, oE, oI
	})
	ensureLinkLocalFn = func(*net.Interface) error { return nil }
	listenFn = func(*net.Interface, ndp.Addr) (ndpConn, netip.Addr, error) {
		return cc, netip.MustParseAddr("fe80::1"), nil
	}
	interfaceByNameFn = ifByName
}

// TestResendBurstRefreshesSLLAAfterMACChange_5302 is the fail-on-revert guard:
// after a simulated virtual-MAC change (A -> B), a requested burst must
// advertise the REFRESHED MAC B, not the cached MAC A.
func TestResendBurstRefreshesSLLAAfterMACChange_5302(t *testing.T) {
	macA := net.HardwareAddr{0x02, 0xbf, 0x72, 0xcc, 0x00, 0x0a}
	macB := net.HardwareAddr{0x02, 0xbf, 0x72, 0xcc, 0x00, 0x0b}

	var mu sync.Mutex
	cur := macA
	getMAC := func() net.HardwareAddr { mu.Lock(); defer mu.Unlock(); return cur }
	setMAC := func(m net.HardwareAddr) { mu.Lock(); cur = m; mu.Unlock() }

	cc := newCaptureConn()
	installRARefreshSeams(t, cc, func(name string) (*net.Interface, error) {
		return &net.Interface{Index: 7, Name: name, HardwareAddr: getMAC()}, nil
	})

	// Large MaxAdvInterval so the periodic timer never fires during the test —
	// the only sends are the startup burst and the requested burst.
	cfg := &config.RAInterfaceConfig{Interface: "ra-5302", MaxAdvInterval: 1800}
	s := newSender(cfg, &net.Interface{Index: 7, Name: "ra-5302", HardwareAddr: macA})
	go s.run()
	defer s.stop()

	// Startup burst advertises the initial MAC A.
	if !waitFor5302(func() bool { return cc.sawSLLA(macA) }) {
		t.Fatalf("startup burst never advertised the initial SLLA %s; captured=%v", macA, cc.all())
	}

	// Simulate the day-2 RETH/VLAN virtual-MAC change, then request the
	// post-link-cycle burst (as daemon_apply's ResendBurst does).
	setMAC(macB)
	s.requestBurst()

	if !waitFor5302(func() bool { return cc.sawSLLA(macB) }) {
		t.Fatalf("burst after the MAC change did not advertise the refreshed SLLA %s (stale cached MAC); captured=%v", macB, cc.all())
	}
}

// TestResendBurstSkipsOnRefreshFailure_5302 asserts that when the interface
// cannot be re-resolved, the burst is SKIPPED (no RA sent) rather than
// advertising the stale cached SLLA.
func TestResendBurstSkipsOnRefreshFailure_5302(t *testing.T) {
	macA := net.HardwareAddr{0x02, 0xbf, 0x72, 0xcc, 0x01, 0x0a}

	cc := newCaptureConn()
	installRARefreshSeams(t, cc, func(string) (*net.Interface, error) {
		return nil, errors.New("interface disappeared")
	})

	cfg := &config.RAInterfaceConfig{Interface: "ra-5302f", MaxAdvInterval: 1800}
	s := newSender(cfg, &net.Interface{Index: 9, Name: "ra-5302f", HardwareAddr: macA})
	go s.run()
	defer s.stop()

	// Startup burst (interfaceByNameFn is not consulted for the startup burst).
	if !waitFor5302(func() bool { return cc.sawSLLA(macA) }) {
		t.Fatalf("startup burst never advertised MAC %s", macA)
	}
	// Let the 3-RA startup burst fully drain, then snapshot.
	time.Sleep(400 * time.Millisecond)
	before := cc.count()

	// Request a burst while the interface cannot be re-resolved: it MUST be
	// skipped (no new RA), never advertise the stale cached SLLA.
	s.requestBurst()
	time.Sleep(400 * time.Millisecond)
	if after := cc.count(); after != before {
		t.Fatalf("burst sent %d RA(s) despite a failed interface refresh; want 0 (must skip, not advertise a stale SLLA)", after-before)
	}
}

// TestRefreshInterfaceForBurst_5302 unit-tests the refresh helper directly
// (single goroutine, deterministic): success re-resolves s.iface; failure
// returns false and leaves s.iface unchanged (no stale/garbage overwrite).
func TestRefreshInterfaceForBurst_5302(t *testing.T) {
	macA := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x0a}
	macB := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x0b}

	oI := interfaceByNameFn
	t.Cleanup(func() { interfaceByNameFn = oI })

	s := &sender{iface: &net.Interface{Index: 3, Name: "ra-u", HardwareAddr: macA}}

	interfaceByNameFn = func(name string) (*net.Interface, error) {
		return &net.Interface{Index: 4, Name: name, HardwareAddr: macB}, nil
	}
	if !s.refreshInterfaceForBurst() {
		t.Fatal("refreshInterfaceForBurst returned false on a successful re-resolve")
	}
	if s.iface.HardwareAddr.String() != macB.String() || s.iface.Index != 4 {
		t.Fatalf("iface not refreshed after success: %+v", s.iface)
	}

	interfaceByNameFn = func(string) (*net.Interface, error) { return nil, errors.New("gone") }
	if s.refreshInterfaceForBurst() {
		t.Fatal("refreshInterfaceForBurst returned true on a re-resolve error")
	}
	if s.iface.HardwareAddr.String() != macB.String() || s.iface.Index != 4 {
		t.Fatalf("failed refresh mutated s.iface: %+v", s.iface)
	}
}
