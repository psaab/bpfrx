package dhcprelay

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/config"
)

func TestAddOption82(t *testing.T) {
	pkt, err := dhcpv4.New()
	if err != nil {
		t.Fatal(err)
	}

	addOption82(pkt, "trust0")

	opt := pkt.Options.Get(option82)
	if opt == nil {
		t.Fatal("Option 82 not found")
	}

	// Parse sub-option: type(1) + length + value
	if len(opt) < 2 {
		t.Fatalf("Option 82 too short: %d bytes", len(opt))
	}
	if opt[0] != suboption1CircuitID {
		t.Errorf("sub-option type: got %d, want %d", opt[0], suboption1CircuitID)
	}
	if opt[1] != byte(len("trust0")) {
		t.Errorf("sub-option length: got %d, want %d", opt[1], len("trust0"))
	}
	circuitID := string(opt[2:])
	if circuitID != "trust0" {
		t.Errorf("circuit-id: got %q, want %q", circuitID, "trust0")
	}
}

func TestStripOption82(t *testing.T) {
	pkt, err := dhcpv4.New()
	if err != nil {
		t.Fatal(err)
	}

	addOption82(pkt, "trust0")
	if pkt.Options.Get(option82) == nil {
		t.Fatal("Option 82 should be present before strip")
	}

	stripOption82(pkt)
	if pkt.Options.Get(option82) != nil {
		t.Error("Option 82 should be removed after strip")
	}
}

func TestAddOption82_Replaces(t *testing.T) {
	pkt, err := dhcpv4.New()
	if err != nil {
		t.Fatal(err)
	}

	addOption82(pkt, "trust0")
	addOption82(pkt, "dmz0")

	opt := pkt.Options.Get(option82)
	if opt == nil {
		t.Fatal("Option 82 not found")
	}
	circuitID := string(opt[2:])
	if circuitID != "dmz0" {
		t.Errorf("circuit-id should be replaced: got %q, want %q", circuitID, "dmz0")
	}
}

func TestInterfaceIPv4_Loopback(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skip("no loopback interface")
	}
	ip, err := interfaceIPv4(lo)
	if err == nil {
		t.Errorf("expected error for loopback, got IP %s", ip)
	}
}

// TestClientRequestRelayable asserts the client->server forwarding gate
// (#2153): a relay must forward DISCOVER, REQUEST, and INFORM, but not server
// reply types or client-to-server-direct types (DECLINE/RELEASE). The INFORM
// case is the regression target — before #2153 the gate dropped it, so a
// domain-joined client that holds its own address never received DNS/domain/NTP
// options from the central server. This test FAILS against the pre-fix gate
// (which returned false for INFORM).
func TestClientRequestRelayable(t *testing.T) {
	cases := []struct {
		msgType dhcpv4.MessageType
		want    bool
	}{
		{dhcpv4.MessageTypeDiscover, true},
		{dhcpv4.MessageTypeRequest, true},
		{dhcpv4.MessageTypeInform, true}, // #2153 regression target
		{dhcpv4.MessageTypeDecline, false},
		{dhcpv4.MessageTypeRelease, false},
		{dhcpv4.MessageTypeOffer, false},
		{dhcpv4.MessageTypeAck, false},
		{dhcpv4.MessageTypeNak, false},
		{dhcpv4.MessageType(0), false}, // missing/zero message type
	}
	for _, tc := range cases {
		if got := clientRequestRelayable(tc.msgType); got != tc.want {
			t.Errorf("clientRequestRelayable(%v) = %v, want %v",
				tc.msgType, got, tc.want)
		}
	}
}

// TestRunRelay_RelaysInform is the end-to-end gate proof for #2153: a real
// BOOTREQUEST/INFORM datagram pushed through the live runRelay loop must be
// forwarded to the server conn (not silently dropped). It drives the production
// path via Apply + the recording factory; the client conn delivers one INFORM
// then blocks. The assertion FAILS against the pre-#2153 gate, which `continue`d
// on INFORM and never wrote to the server conn.
func TestRunRelay_RelaysInform(t *testing.T) {
	// Build a client INFORM: BOOTREQUEST with ciaddr set (client owns its
	// address) and no yiaddr — the canonical DHCPINFORM shape (RFC 2131 §3.4).
	inform, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("dhcpv4.New: %v", err)
	}
	inform.OpCode = dhcpv4.OpcodeBootRequest
	inform.ClientHWAddr = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	inform.ClientIPAddr = net.IPv4(192, 0, 2, 50)
	inform.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeInform))

	// The factory hands out the client conn first (runRelay's first newConn
	// call) then the server conn. Seed the client conn with the INFORM; after
	// it is consumed ReadFrom blocks until Stop.
	client := newFakeConn()
	client.pending = [][]byte{inform.ToBytes()}
	server := newFakeConn()
	factory, _ := recordingFactory(client, server)
	m := testManager(factory)

	m.Apply(context.Background(), singleInterfaceConfig())
	defer m.Stop()

	// Wait for the INFORM to be relayed onto the server conn.
	deadline := time.Now().Add(2 * time.Second)
	for server.writeCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if server.writeCount() == 0 {
		t.Fatal("INFORM was not relayed to the server within 2s " +
			"(pre-#2153 gate dropped it)")
	}

	// The relayed datagram must parse, be a BOOTREQUEST/INFORM, and carry the
	// relay-set giaddr (10.0.0.254, from testManager's resolver).
	relayed, err := dhcpv4.FromBytes(server.firstWrite(t))
	if err != nil {
		t.Fatalf("relayed datagram does not parse: %v", err)
	}
	if relayed.OpCode != dhcpv4.OpcodeBootRequest {
		t.Errorf("relayed opcode = %v, want BOOTREQUEST", relayed.OpCode)
	}
	if relayed.MessageType() != dhcpv4.MessageTypeInform {
		t.Errorf("relayed message type = %v, want INFORM", relayed.MessageType())
	}
	if !relayed.GatewayIPAddr.Equal(net.IPv4(10, 0, 0, 254)) {
		t.Errorf("relayed giaddr = %v, want 10.0.0.254", relayed.GatewayIPAddr)
	}
}

// TestRunRelay_HopCountLimit asserts the RFC 1542 §4.1.1 hop limit is enforced
// before the uint8 increment, so a request whose HopCount has already reached
// (or maxed out) the limit is dropped rather than wrapped past the check.
// HopCount==255 is the regression case: a post-increment "> 16" test wraps it
// to 0 and relays it, defeating loop protection.
func TestRunRelay_HopCountLimit(t *testing.T) {
	cases := []struct {
		name        string
		hops        uint8
		wantRelayed bool
		wantHops    uint8 // relayed hop count (only checked when wantRelayed)
	}{
		{"below_limit", 15, true, 16},
		{"at_limit", 16, false, 0},
		{"wrap_boundary_255", 255, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := dhcpv4.New()
			if err != nil {
				t.Fatalf("dhcpv4.New: %v", err)
			}
			req.OpCode = dhcpv4.OpcodeBootRequest
			req.ClientHWAddr = net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
			req.HopCount = tc.hops
			req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeRequest))

			client := newFakeConn()
			client.pending = [][]byte{req.ToBytes()}
			server := newFakeConn()
			factory, _ := recordingFactory(client, server)
			m := testManager(factory)
			m.Apply(context.Background(), singleInterfaceConfig())
			defer m.Stop()

			// Give the loop time to consume the datagram and act on it.
			deadline := time.Now().Add(1 * time.Second)
			for client.readCalls.Load() < 2 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}

			got := server.writeCount()
			if tc.wantRelayed && got == 0 {
				t.Fatalf("hops=%d: expected relay, got none", tc.hops)
			}
			if !tc.wantRelayed && got != 0 {
				t.Fatalf("hops=%d: expected drop, but %d datagram(s) relayed", tc.hops, got)
			}
			if tc.wantRelayed {
				relayed, err := dhcpv4.FromBytes(server.firstWrite(t))
				if err != nil {
					t.Fatalf("relayed datagram does not parse: %v", err)
				}
				if relayed.HopCount != tc.wantHops {
					t.Errorf("relayed HopCount = %d, want %d", relayed.HopCount, tc.wantHops)
				}
			}
		})
	}
}

// --- Lifecycle test scaffolding (#1915) ---

// fakeConn is a fake net.PacketConn whose ReadFrom blocks until Close (unless
// readErr or pending datagrams are set). It records writes and the close call
// so lifecycle tests assert bounded teardown and goroutine joins with no real
// sockets and no root.
type fakeConn struct {
	mu        sync.Mutex
	closed    bool
	closeCh   chan struct{}
	readCalls atomic.Int64
	pending   [][]byte // datagrams ReadFrom returns before blocking
	writes    []fakeWrite
	// readErr, if set, is returned by ReadFrom (instead of blocking) once
	// pending is exhausted — used to simulate an early one-sided close.
	readErr error
}

type fakeWrite struct {
	data []byte
	addr net.Addr
}

func newFakeConn() *fakeConn {
	return &fakeConn{closeCh: make(chan struct{})}
}

func (f *fakeConn) ReadFrom(p []byte) (int, net.Addr, error) {
	f.readCalls.Add(1)
	f.mu.Lock()
	if len(f.pending) > 0 {
		d := f.pending[0]
		f.pending = f.pending[1:]
		f.mu.Unlock()
		n := copy(p, d)
		return n, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 68}, nil
	}
	rerr := f.readErr
	f.mu.Unlock()
	if rerr != nil {
		return 0, nil, rerr
	}
	<-f.closeCh
	return 0, nil, net.ErrClosed
}

func (f *fakeConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, net.ErrClosed
	}
	cp := make([]byte, len(p))
	copy(cp, p)
	f.writes = append(f.writes, fakeWrite{data: cp, addr: addr})
	return len(p), nil
}

func (f *fakeConn) Close() error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return net.ErrClosed
	}
	f.closed = true
	close(f.closeCh)
	f.mu.Unlock()
	return nil
}

func (f *fakeConn) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// writeCount returns the number of datagrams written to this conn.
func (f *fakeConn) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.writes)
}

// firstWrite returns a copy of the first datagram written to this conn.
func (f *fakeConn) firstWrite(t *testing.T) []byte {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.writes) == 0 {
		t.Fatal("no datagram was written to the conn")
	}
	return append([]byte(nil), f.writes[0].data...)
}

func (f *fakeConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (f *fakeConn) SetDeadline(t time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

// factoryCall records one packetConnFactory invocation.
type factoryCall struct {
	ifaceName string
	reusePort bool
	broadcast bool
	bindAddr  *net.UDPAddr
}

// recordingFactory returns a packetConnFactory that records each call and
// hands back the next conn from the supplied list (sequential); calls beyond
// the supplied conns get a fresh fakeConn. The getter returns a snapshot.
func recordingFactory(conns ...*fakeConn) (packetConnFactory, func() []factoryCall) {
	var mu sync.Mutex
	var calls []factoryCall
	idx := 0
	f := func(ctx context.Context, ifaceName string, reusePort, broadcast bool,
		bindAddr *net.UDPAddr) (net.PacketConn, error) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, factoryCall{
			ifaceName: ifaceName,
			reusePort: reusePort,
			broadcast: broadcast,
			bindAddr:  bindAddr,
		})
		var c *fakeConn
		if idx < len(conns) {
			c = conns[idx]
		} else {
			c = newFakeConn()
		}
		idx++
		return c, nil
	}
	getter := func() []factoryCall {
		mu.Lock()
		defer mu.Unlock()
		out := make([]factoryCall, len(calls))
		copy(out, calls)
		return out
	}
	return f, getter
}

// testManager builds a Manager with mocked seams: an immediately-succeeding
// giaddr resolver, the supplied factory, and a tiny retry interval.
func testManager(factory packetConnFactory) *Manager {
	m := NewManager()
	m.newConn = factory
	m.resolveGIAddr = func(ifaceName string) (net.IP, error) {
		return net.IPv4(10, 0, 0, 254), nil
	}
	m.retryInterval = time.Millisecond
	// Default to a stable ifindex with the #2347 drift watcher effectively off
	// (a long interval) so pre-existing lifecycle tests see no extra churn.
	// Drift tests override resolveIfindex + ifindexCheck.
	m.resolveIfindex = func(ifaceName string) (int, error) { return 100, nil }
	m.ifindexCheck = time.Hour
	// Default to a no-op fake L2 sender so lifecycle tests do not depend on
	// CAP_NET_RAW or a real NIC (#2076). Individual tests override m.newL2.
	m.newL2 = func(ifaceName string) (l2Replier, error) {
		return &fakeL2{}, nil
	}
	return m
}

func singleInterfaceConfig() *config.DHCPRelayConfig {
	return &config.DHCPRelayConfig{
		ServerGroups: map[string]*config.DHCPRelayServerGroup{
			"sg": {Name: "sg", Servers: []string{"192.0.2.1"}},
		},
		Groups: map[string]*config.DHCPRelayGroup{
			"g": {Name: "g", Interfaces: []string{"ge-0-0-0"}, ActiveServerGroup: "sg"},
		},
	}
}

func twoInterfaceConfig() *config.DHCPRelayConfig {
	return &config.DHCPRelayConfig{
		ServerGroups: map[string]*config.DHCPRelayServerGroup{
			"sg": {Name: "sg", Servers: []string{"192.0.2.1"}},
		},
		Groups: map[string]*config.DHCPRelayGroup{
			"g": {
				Name:              "g",
				Interfaces:        []string{"ge-0-0-0", "ge-0-0-1"},
				ActiveServerGroup: "sg",
			},
		},
	}
}

// waitRelays blocks until the manager reports n relays or the deadline passes.
func waitRelays(t *testing.T, m *Manager, n int, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if len(m.Stats()) >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("expected >= %d relays, got %d", n, len(m.Stats()))
}

// waitCalls blocks until the factory has been called n times or deadline.
func waitCalls(t *testing.T, getCalls func() []factoryCall, n int, d time.Duration) []factoryCall {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if c := getCalls(); len(c) >= n {
			return c
		}
		time.Sleep(time.Millisecond)
	}
	c := getCalls()
	t.Fatalf("expected >= %d factory calls, got %d: %+v", n, len(c), c)
	return c
}

// TestApply_MultiInterface_NoCollision proves the EADDRINUSE fix by
// construction: two interfaces each get a 0.0.0.0:67 client listener with
// reusePort=true AND a distinct non-empty ifaceName (the BINDTODEVICE
// invariant), plus a server conn each — four factory calls, no error.
func TestApply_MultiInterface_NoCollision(t *testing.T) {
	factory, getCalls := recordingFactory()
	m := testManager(factory)
	defer m.Stop()

	m.Apply(context.Background(), twoInterfaceConfig())
	waitRelays(t, m, 2, 2*time.Second)
	calls := waitCalls(t, getCalls, 4, 2*time.Second)
	if len(calls) != 4 {
		t.Fatalf("expected exactly 4 factory calls, got %d: %+v", len(calls), calls)
	}

	clientIfaces := map[string]bool{}
	clientListeners, serverListeners := 0, 0
	for _, c := range calls {
		if c.bindAddr.Port == relayPort {
			clientListeners++
			if !c.reusePort {
				t.Errorf("client listener on :67 must set reusePort: %+v", c)
			}
			if !c.broadcast {
				t.Errorf("client listener must set broadcast (SO_BROADCAST): %+v", c)
			}
			if c.ifaceName == "" {
				t.Errorf("client listener MUST have non-empty BINDTODEVICE ifaceName: %+v", c)
			}
			if !c.bindAddr.IP.Equal(net.IPv4zero) {
				t.Errorf("client listener must bind 0.0.0.0: %+v", c)
			}
			clientIfaces[c.ifaceName] = true
		} else {
			serverListeners++
			if c.reusePort {
				t.Errorf("server conn must NOT set reusePort: %+v", c)
			}
			if c.ifaceName != "" {
				t.Errorf("server conn must NOT set BINDTODEVICE: %+v", c)
			}
		}
	}
	if clientListeners != 2 {
		t.Errorf("expected 2 client listeners, got %d", clientListeners)
	}
	if serverListeners != 2 {
		t.Errorf("expected 2 server conns, got %d", serverListeners)
	}
	if len(clientIfaces) != 2 {
		t.Errorf("expected 2 distinct client ifaceNames, got %v", clientIfaces)
	}
}

// TestStop_BoundedNoPackets starts a relay whose fake conns block in ReadFrom
// and asserts Stop() returns promptly (close-on-cancel unblocks the reads).
func TestStop_BoundedNoPackets(t *testing.T) {
	client := newFakeConn()
	server := newFakeConn()
	factory, getCalls := recordingFactory(client, server)
	m := testManager(factory)

	m.Apply(context.Background(), singleInterfaceConfig())
	waitRelays(t, m, 1, 2*time.Second)
	waitCalls(t, getCalls, 2, 2*time.Second) // both conns created

	done := make(chan struct{})
	go func() { m.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() did not return within 2s — blocking ReadFrom not unblocked")
	}
	if !client.isClosed() || !server.isClosed() {
		t.Error("both conns must be closed after Stop()")
	}
}

// TestApply_Reapply_DoesNotHang calls Apply twice; the second Stops gen-1 and
// must return bounded with gen-1 conns closed.
func TestApply_Reapply_DoesNotHang(t *testing.T) {
	gen1Client := newFakeConn()
	gen1Server := newFakeConn()
	factory, getCalls := recordingFactory(gen1Client, gen1Server)
	m := testManager(factory)
	defer m.Stop()

	cfg := singleInterfaceConfig()
	m.Apply(context.Background(), cfg)
	waitRelays(t, m, 1, 2*time.Second)
	waitCalls(t, getCalls, 2, 2*time.Second)

	done := make(chan struct{})
	go func() { m.Apply(context.Background(), cfg); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("second Apply() hung — Stop() inside Apply did not return")
	}
	if !gen1Client.isClosed() || !gen1Server.isClosed() {
		t.Error("gen-1 conns must be closed after reapply")
	}
}

// TestServerGoroutine_Joined asserts the response goroutine's serverConn is
// closed (and thus the goroutine returned) after Stop — proving the WaitGroup
// join completes (Stop would hang if the join did not).
func TestServerGoroutine_Joined(t *testing.T) {
	client := newFakeConn()
	server := newFakeConn()
	factory, getCalls := recordingFactory(client, server)
	m := testManager(factory)

	m.Apply(context.Background(), singleInterfaceConfig())
	waitRelays(t, m, 1, 2*time.Second)
	waitCalls(t, getCalls, 2, 2*time.Second)

	m.Stop() // would hang here if the join did not complete
	if !server.isClosed() {
		t.Error("server conn must be closed (response goroutine joined)")
	}
}

// TestRunRelay_StartupRetry injects a resolver that fails the first K calls
// (covering BOTH the interface-missing and address-missing cases) and asserts
// the relay does not die: it eventually creates sockets. Stop then returns.
func TestRunRelay_StartupRetry(t *testing.T) {
	client := newFakeConn()
	server := newFakeConn()
	factory, getCalls := recordingFactory(client, server)
	m := testManager(factory)

	const k = 3
	var attempts atomic.Int64
	m.resolveGIAddr = func(ifaceName string) (net.IP, error) {
		n := attempts.Add(1)
		if n <= k {
			if n == 1 {
				return nil, errors.New("interface lookup: not found") // interface missing
			}
			return nil, errors.New("no IPv4 address") // address missing
		}
		return net.IPv4(10, 0, 0, 254), nil
	}

	m.Apply(context.Background(), singleInterfaceConfig())

	calls := waitCalls(t, getCalls, 2, 2*time.Second)
	if len(calls) < 2 {
		t.Fatalf("relay died during retry: only %d factory calls (attempts=%d)", len(calls), attempts.Load())
	}
	if attempts.Load() <= k {
		t.Errorf("expected resolver retried past %d attempts, got %d", k, attempts.Load())
	}

	done := make(chan struct{})
	go func() { m.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() did not return")
	}
}

// TestRunRelay_StopDuringRetry cancels while the resolver is still failing;
// Stop must return promptly (the retry select is ctx-cancelable) and no
// sockets are created.
func TestRunRelay_StopDuringRetry(t *testing.T) {
	factory, getCalls := recordingFactory()
	m := testManager(factory)
	m.retryInterval = 50 * time.Millisecond
	m.resolveGIAddr = func(ifaceName string) (net.IP, error) {
		return nil, errors.New("never ready")
	}

	m.Apply(context.Background(), singleInterfaceConfig())
	time.Sleep(20 * time.Millisecond)

	done := make(chan struct{})
	go func() { m.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() during retry did not return promptly")
	}
	if got := len(getCalls()); got != 0 {
		t.Errorf("no sockets should be created during failing retry, got %d calls", got)
	}
}

// TestRunRelay_OneSidedExitNoHang makes the response goroutine's serverConn
// return ErrClosed while ctx is NOT cancelled. Per the cross-cancellation
// design the response loop returns -> defer cancel() fires -> watcher closes
// both conns -> the main loop returns -> runRelay completes.
func TestRunRelay_OneSidedExitNoHang(t *testing.T) {
	client := newFakeConn()
	server := newFakeConn()
	server.mu.Lock()
	server.readErr = net.ErrClosed // one-sided exit, no ctx cancel
	server.mu.Unlock()
	factory, _ := recordingFactory(client, server)
	m := testManager(factory)

	m.Apply(context.Background(), singleInterfaceConfig())

	// The relay self-terminates via cross-cancellation: the response loop's
	// cancel drives the watcher to close the client conn, which unblocks the
	// main loop. Wait for the client conn to be closed.
	deadline := time.Now().Add(2 * time.Second)
	for !client.isClosed() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !client.isClosed() {
		t.Fatal("one-sided response-loop exit did not cross-cancel + close the client conn")
	}

	done := make(chan struct{})
	go func() { m.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() hung after one-sided exit")
	}
}

// TestRunRelay_ClosedNoSpin closes the client conn while ctx is not cancelled;
// the main loop must return (not hot-spin on ErrClosed). Bound the ReadFrom
// call count after the close.
func TestRunRelay_ClosedNoSpin(t *testing.T) {
	client := newFakeConn()
	server := newFakeConn()
	factory, getCalls := recordingFactory(client, server)
	m := testManager(factory)

	m.Apply(context.Background(), singleInterfaceConfig())
	waitRelays(t, m, 1, 2*time.Second)
	waitCalls(t, getCalls, 2, 2*time.Second)

	client.Close() // external close, ctx still alive
	time.Sleep(100 * time.Millisecond)
	before := client.readCalls.Load()
	time.Sleep(200 * time.Millisecond)
	after := client.readCalls.Load()
	if after-before > 1 {
		t.Errorf("main loop hot-spun on ErrClosed: %d extra ReadFrom calls", after-before)
	}

	m.Stop()
}

// --- #2076 lifecycle / fail-soft tests ---

// countingL2Factory returns an l2SenderFactory that records open attempts and
// returns the supplied sender (or error).
func countingL2Factory(s l2Replier, err error) (l2SenderFactory, func() int) {
	var mu sync.Mutex
	var opens int
	f := func(ifaceName string) (l2Replier, error) {
		mu.Lock()
		opens++
		mu.Unlock()
		if err != nil {
			return nil, err
		}
		return s, nil
	}
	getter := func() int {
		mu.Lock()
		defer mu.Unlock()
		return opens
	}
	return f, getter
}

// TestRunRelay_L2OpenFailure_RelayStaysUp proves that an L2 open failure (e.g.
// no CAP_NET_RAW) is fail-soft: the relay still creates its UDP sockets and
// Stop returns. runRelay must NOT return early on L2 open error (#2076 §7.3).
func TestRunRelay_L2OpenFailure_RelayStaysUp(t *testing.T) {
	client := newFakeConn()
	server := newFakeConn()
	factory, getCalls := recordingFactory(client, server)
	m := testManager(factory)
	l2f, getOpens := countingL2Factory(nil, errors.New("EPERM: no CAP_NET_RAW"))
	m.newL2 = l2f

	m.Apply(context.Background(), singleInterfaceConfig())
	calls := waitCalls(t, getCalls, 2, 2*time.Second)
	if len(calls) < 2 {
		t.Fatalf("relay died on L2 open failure: only %d UDP conns", len(calls))
	}
	if getOpens() == 0 {
		t.Errorf("expected at least one L2 open attempt")
	}

	done := make(chan struct{})
	go func() { m.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() did not return after L2 open failure")
	}
}

// TestRunRelay_AlwaysBroadcast_SkipsL2Open proves that when overrides
// always-broadcast is set, the relay never opens the L2 socket (#2076 §7.1:
// override wins before the L2 path is even considered).
func TestRunRelay_AlwaysBroadcast_SkipsL2Open(t *testing.T) {
	client := newFakeConn()
	server := newFakeConn()
	factory, getCalls := recordingFactory(client, server)
	m := testManager(factory)
	l2f, getOpens := countingL2Factory(&fakeL2{}, nil)
	m.newL2 = l2f

	cfg := singleInterfaceConfig()
	cfg.Groups["g"].AlwaysBroadcast = true
	m.Apply(context.Background(), cfg)
	waitCalls(t, getCalls, 2, 2*time.Second)

	// Give runRelay a beat to reach (and skip) the L2 open.
	time.Sleep(50 * time.Millisecond)
	if getOpens() != 0 {
		t.Errorf("always-broadcast must NOT open the L2 socket, got %d opens", getOpens())
	}
	m.Stop()
}

// TestRunRelay_L2Closed_AfterStop proves the L2 sender is closed (exactly once)
// when the relay stops — closure happens after wg.Wait() (#2076 §7.3).
func TestRunRelay_L2Closed_AfterStop(t *testing.T) {
	client := newFakeConn()
	server := newFakeConn()
	factory, getCalls := recordingFactory(client, server)
	m := testManager(factory)
	fl2 := &fakeL2{}
	l2f, _ := countingL2Factory(fl2, nil)
	m.newL2 = l2f

	m.Apply(context.Background(), singleInterfaceConfig())
	waitCalls(t, getCalls, 2, 2*time.Second)
	m.Stop()

	fl2.mu.Lock()
	cc := fl2.closeCount
	fl2.mu.Unlock()
	if cc != 1 {
		t.Errorf("L2 sender Close count = %d, want exactly 1", cc)
	}
}

// TestL2Sender_CloseIdempotent proves the real *l2Sender Close is idempotent
// (sync.Once). It uses a sentinel fd; the second Close must be a no-op even
// though the fd was already closed.
func TestL2Sender_CloseIdempotent(t *testing.T) {
	// A nil *l2Sender Close must be safe.
	var nilSender *l2Sender
	if err := nilSender.Close(); err != nil {
		t.Errorf("nil l2Sender.Close() = %v, want nil", err)
	}

	// Use a real, closeable fd (a pipe read end) to prove Close idempotency
	// without a NIC. The first Close closes it; the second must be a no-op
	// (sync.Once), NOT a double-close EBADF.
	var p [2]int
	if err := unix.Pipe(p[:]); err != nil {
		t.Skipf("pipe unavailable: %v", err)
	}
	_ = unix.Close(p[1]) // close the unused write end
	s := &l2Sender{fd: p[0], ifaceName: "test"}
	if err := s.Close(); err != nil {
		t.Errorf("first Close = %v, want nil", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close = %v, want nil (idempotent)", err)
	}
}

// --- #2347 ifindex-drift detection ---

// driftResolver returns an ifindexResolver backed by an atomic value (so a test
// can flip the live ifindex mid-flight) plus an atomic error toggle (so a test
// can simulate a transient resolve failure). It also counts calls.
func driftResolver(initial int) (ifindexResolver, *atomic.Int64, *atomic.Bool, *atomic.Int64) {
	idx := &atomic.Int64{}
	idx.Store(int64(initial))
	failing := &atomic.Bool{}
	calls := &atomic.Int64{}
	r := func(ifaceName string) (int, error) {
		calls.Add(1)
		if failing.Load() {
			return 0, errors.New("transient resolve failure")
		}
		return int(idx.Load()), nil
	}
	return r, idx, failing, calls
}

// TestRunRelay_IfindexDrift_RebindsListener proves the #2347 fix: when the
// interface's live ifindex changes under unchanged config, the relay tears down
// the stale-bound session and rebinds a fresh client listener to the new
// ifindex. Asserted by construction via the factory call count: the first
// session opens 2 conns (client+server); after drift the supervisor rebuilds,
// opening 2 more — 4 total — and the rebuilt client listener still carries the
// SO_BINDTODEVICE ifaceName invariant.
func TestRunRelay_IfindexDrift_RebindsListener(t *testing.T) {
	factory, getCalls := recordingFactory()
	m := testManager(factory)
	defer m.Stop()

	resolve, liveIdx, _, _ := driftResolver(100)
	m.resolveIfindex = resolve
	m.ifindexCheck = 5 * time.Millisecond

	m.Apply(context.Background(), singleInterfaceConfig())
	waitRelays(t, m, 1, 2*time.Second)
	waitCalls(t, getCalls, 2, 2*time.Second) // gen-1 client + server

	// Interface deleted+recreated -> new kernel ifindex.
	liveIdx.Store(200)

	// The drift watcher must cancel the session and the supervisor must rebuild,
	// producing 2 more factory calls (gen-2 client + server).
	calls := waitCalls(t, getCalls, 4, 2*time.Second)

	// The rebound client listener (a :67 call after the first two) must keep the
	// per-interface SO_BINDTODEVICE ifaceName.
	clientListeners := 0
	for _, c := range calls {
		if c.bindAddr.Port == relayPort {
			clientListeners++
			if c.ifaceName != "ge-0-0-0" {
				t.Errorf("rebound client listener lost BINDTODEVICE ifaceName: %+v", c)
			}
		}
	}
	if clientListeners < 2 {
		t.Errorf("expected >=2 client listeners (original + rebind), got %d", clientListeners)
	}
}

// TestRunRelay_IfindexStable_NoRebind proves idempotency: with the live ifindex
// never changing, the drift watcher fires repeatedly but never restarts the
// session. The factory is called exactly twice (one session) for the lifetime.
func TestRunRelay_IfindexStable_NoRebind(t *testing.T) {
	factory, getCalls := recordingFactory()
	m := testManager(factory)
	defer m.Stop()

	resolve, _, _, calls := driftResolver(100)
	m.resolveIfindex = resolve
	m.ifindexCheck = 2 * time.Millisecond

	m.Apply(context.Background(), singleInterfaceConfig())
	waitRelays(t, m, 1, 2*time.Second)
	waitCalls(t, getCalls, 2, 2*time.Second)

	// Let the watcher tick many times against a stable ifindex.
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) && calls.Load() < 10 {
		time.Sleep(2 * time.Millisecond)
	}
	if calls.Load() < 5 {
		t.Fatalf("drift watcher did not run enough to be meaningful (%d resolves)", calls.Load())
	}

	// No rebind: still exactly the original 2 factory calls.
	if got := len(getCalls()); got != 2 {
		t.Errorf("stable ifindex must NOT rebind: got %d factory calls, want 2", got)
	}
}

// TestRunRelay_IfindexResolveFailure_KeepsListener proves the tolerant-resolve
// invariant: a transient ifindex resolve failure must NOT tear down a working
// listener (no rebind, no socket close), mirroring #2294's tolerant probe.
func TestRunRelay_IfindexResolveFailure_KeepsListener(t *testing.T) {
	client := newFakeConn()
	server := newFakeConn()
	factory, getCalls := recordingFactory(client, server)
	m := testManager(factory)
	defer m.Stop()

	resolve, _, failing, calls := driftResolver(100)
	m.resolveIfindex = resolve
	m.ifindexCheck = 2 * time.Millisecond

	m.Apply(context.Background(), singleInterfaceConfig())
	waitRelays(t, m, 1, 2*time.Second)
	waitCalls(t, getCalls, 2, 2*time.Second)

	// Resolver now fails on every tick.
	failing.Store(true)

	// Let it fail many times.
	deadline := time.Now().Add(200 * time.Millisecond)
	base := calls.Load()
	for time.Now().Before(deadline) && calls.Load() < base+10 {
		time.Sleep(2 * time.Millisecond)
	}

	// The working session must be intact: no rebind (still 2 factory calls) and
	// the gen-1 conns must NOT be closed.
	if got := len(getCalls()); got != 2 {
		t.Errorf("resolve failure must NOT rebind: got %d factory calls, want 2", got)
	}
	if client.isClosed() || server.isClosed() {
		t.Error("resolve failure must NOT tear down the working listener")
	}
}

// TestRunRelay_IfindexDrift_StopStillBounded proves a #1915 non-regression: even
// after a drift rebind, Stop() returns under a bounded timeout (the supervisor
// observes ctx cancellation and the close-on-cancel + WaitGroup join still
// unblock the rebuilt session's blocking ReadFrom).
func TestRunRelay_IfindexDrift_StopStillBounded(t *testing.T) {
	factory, getCalls := recordingFactory()
	m := testManager(factory)

	resolve, liveIdx, _, _ := driftResolver(100)
	m.resolveIfindex = resolve
	m.ifindexCheck = 5 * time.Millisecond

	m.Apply(context.Background(), singleInterfaceConfig())
	waitRelays(t, m, 1, 2*time.Second)
	waitCalls(t, getCalls, 2, 2*time.Second)

	liveIdx.Store(200) // force a rebind
	waitCalls(t, getCalls, 4, 2*time.Second)

	done := make(chan struct{})
	go func() { m.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() after ifindex-drift rebind did not return within 2s (#1915 regression)")
	}
}

// TestRunRelay_DegradedBaseline_AdoptsFirstRealIfindex proves that a failed
// baseline capture at bind (boundIfindex==0) does NOT cause a spurious rebind:
// the first real resolve is adopted as the baseline, and only a subsequent
// change triggers a rebind.
func TestRunRelay_DegradedBaseline_AdoptsFirstRealIfindex(t *testing.T) {
	factory, getCalls := recordingFactory()
	m := testManager(factory)
	defer m.Stop()

	// First resolve (the bind-time baseline capture) fails; later resolves
	// return a stable real index.
	var first atomic.Bool
	first.Store(true)
	m.resolveIfindex = func(ifaceName string) (int, error) {
		if first.Swap(false) {
			return 0, errors.New("baseline capture failed")
		}
		return 300, nil
	}
	m.ifindexCheck = 2 * time.Millisecond

	m.Apply(context.Background(), singleInterfaceConfig())
	waitRelays(t, m, 1, 2*time.Second)
	waitCalls(t, getCalls, 2, 2*time.Second)

	// Watcher adopts 300 as baseline then sees 300 forever -> no rebind.
	time.Sleep(150 * time.Millisecond)
	if got := len(getCalls()); got != 2 {
		t.Errorf("degraded baseline must adopt first real ifindex, not rebind: got %d calls, want 2", got)
	}
}
