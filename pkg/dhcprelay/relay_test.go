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
