package cluster

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// mockLink implements netlink.Link for testing.
type mockLink struct {
	attrs netlink.LinkAttrs
}

func (m *mockLink) Attrs() *netlink.LinkAttrs { return &m.attrs }
func (m *mockLink) Type() string              { return "mock" }

// mockNlHandle implements nlLinkGetter for testing.
type mockNlHandle struct {
	links map[string]*mockLink
}

func (h *mockNlHandle) LinkByName(name string) (netlink.Link, error) {
	if link, ok := h.links[name]; ok {
		return link, nil
	}
	return nil, net.UnknownNetworkError("not found: " + name)
}

func newMockNlHandle() *mockNlHandle {
	return &mockNlHandle{links: make(map[string]*mockLink)}
}

func (h *mockNlHandle) setLink(name string, up bool) {
	var state netlink.LinkOperState = netlink.OperDown
	if up {
		state = netlink.OperUp
	}
	h.links[name] = &mockLink{
		attrs: netlink.LinkAttrs{Name: name, OperState: state},
	}
}

// setNoDampening configures the monitor for immediate state changes (no dampening).
func setNoDampening(mon *Monitor) {
	mon.FailThreshold = 1
	mon.PassThreshold = 1
	mon.HoldDown = 1 * time.Nanosecond
}

func TestMonitor_InterfaceStateChange(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200},
			&config.InterfaceMonitor{Interface: "trust0", Weight: 100},
			&config.InterfaceMonitor{Interface: "untrust0", Weight: 150},
		),
	)
	m.UpdateConfig(cfg)
	// Drain election events.
	drainEvents(m, 1)

	nlh := newMockNlHandle()
	nlh.setLink("trust0", true)
	nlh.setLink("untrust0", true)

	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.nlHandle = nlh
	setNoDampening(mon)

	// Initial poll: all up, no weight change.
	mon.poll()

	states := m.GroupStates()
	if states[0].Weight != 255 {
		t.Errorf("initial weight = %d, want 255", states[0].Weight)
	}

	// Bring trust0 down.
	nlh.setLink("trust0", false)
	mon.poll()

	states = m.GroupStates()
	if states[0].Weight != 155 {
		t.Errorf("weight after trust0 down = %d, want 155", states[0].Weight)
	}

	// Recover trust0.
	nlh.setLink("trust0", true)
	mon.poll()

	states = m.GroupStates()
	if states[0].Weight != 255 {
		t.Errorf("weight after recovery = %d, want 255", states[0].Weight)
	}
}

func TestMonitor_AllInterfacesDown(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200},
			&config.InterfaceMonitor{Interface: "trust0", Weight: 200},
			&config.InterfaceMonitor{Interface: "untrust0", Weight: 100},
		),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	nlh := newMockNlHandle()
	nlh.setLink("trust0", false)
	nlh.setLink("untrust0", false)

	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.nlHandle = nlh
	setNoDampening(mon)

	mon.poll()

	states := m.GroupStates()
	if states[0].Weight != 0 {
		t.Errorf("weight = %d, want 0 (all down, clamped)", states[0].Weight)
	}
	if m.IsLocalPrimary(0) {
		t.Error("should not be primary with weight 0")
	}
}

func TestMonitor_NoChangeNoCall(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200},
			&config.InterfaceMonitor{Interface: "trust0", Weight: 100},
		),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	nlh := newMockNlHandle()
	nlh.setLink("trust0", true)

	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.nlHandle = nlh
	setNoDampening(mon)

	// Poll twice with same state — weight should remain 255.
	mon.poll()
	mon.poll()

	states := m.GroupStates()
	if states[0].Weight != 255 {
		t.Errorf("weight = %d, want 255 (no change)", states[0].Weight)
	}
}

func TestMonitor_StartStop(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200},
			&config.InterfaceMonitor{Interface: "trust0", Weight: 100},
		),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	nlh := newMockNlHandle()
	nlh.setLink("trust0", false)

	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.nlHandle = nlh
	setNoDampening(mon)

	ctx, cancel := context.WithCancel(context.Background())
	mon.Start(ctx)

	// Wait for at least one poll.
	time.Sleep(1200 * time.Millisecond)

	states := m.GroupStates()
	if states[0].Weight != 155 {
		t.Errorf("weight after monitor start = %d, want 155", states[0].Weight)
	}

	cancel()
	mon.Stop()

	// Verify stop completes without panic.
}

func TestMonitor_UpdateGroups(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200},
			&config.InterfaceMonitor{Interface: "trust0", Weight: 100},
		),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	nlh := newMockNlHandle()
	nlh.setLink("trust0", true)
	nlh.setLink("dmz0", false)

	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.nlHandle = nlh
	setNoDampening(mon)
	mon.poll()

	// Now add a second RG with dmz0 monitor.
	cfg2 := makeConfig(
		makeRG(0, false, map[int]int{0: 200},
			&config.InterfaceMonitor{Interface: "trust0", Weight: 100},
		),
		makeRG(1, false, map[int]int{0: 150},
			&config.InterfaceMonitor{Interface: "dmz0", Weight: 255},
		),
	)
	m.UpdateConfig(cfg2)
	drainEvents(m, 1) // RG 1 election
	mon.UpdateGroups(cfg2.RedundancyGroups)
	mon.poll()

	states := m.GroupStates()
	// RG 0: trust0 up -> weight 255
	for _, st := range states {
		if st.GroupID == 0 && st.Weight != 255 {
			t.Errorf("RG 0 weight = %d, want 255", st.Weight)
		}
		if st.GroupID == 1 && st.Weight != 0 {
			t.Errorf("RG 1 weight = %d, want 0 (dmz0 down)", st.Weight)
		}
	}
}

func TestMonitor_IPMonitoring(t *testing.T) {
	m := NewManager(0, 1)
	rg := &config.RedundancyGroup{
		ID:             0,
		NodePriorities: map[int]int{0: 200},
		IPMonitoring: &config.IPMonitoring{
			GlobalWeight:    100,
			GlobalThreshold: 200,
			Targets: []*config.IPMonitorTarget{
				{Address: "10.0.1.1", Weight: 50},
			},
		},
	}
	cfg := &config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{rg},
	}
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	reachable := true
	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.icmpDialer = func(network string) (icmpConn, error) {
		return &mockICMPConn{reachable: reachable}, nil
	}
	setNoDampening(mon)

	// Initial: reachable.
	mon.poll()
	states := m.GroupStates()
	if states[0].Weight != 255 {
		t.Errorf("weight = %d, want 255 (IP reachable)", states[0].Weight)
	}

	// Make IP unreachable.
	reachable = false
	mon.poll()
	states = m.GroupStates()
	if states[0].Weight != 205 {
		t.Errorf("weight = %d, want 205 (255-50)", states[0].Weight)
	}

	// Recover.
	reachable = true
	mon.poll()
	states = m.GroupStates()
	if states[0].Weight != 255 {
		t.Errorf("weight after recovery = %d, want 255", states[0].Weight)
	}
}

func TestMonitor_Dampening(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200},
			&config.InterfaceMonitor{Interface: "trust0", Weight: 100},
		),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	nlh := newMockNlHandle()
	nlh.setLink("trust0", true)

	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.nlHandle = nlh
	// Use default thresholds (3/3), disable hold-down for this test.
	mon.HoldDown = 1 * time.Nanosecond

	// Initial poll: up.
	mon.poll()
	states := m.GroupStates()
	if states[0].Weight != 255 {
		t.Fatalf("initial weight = %d, want 255", states[0].Weight)
	}

	// Bring down. First 2 polls should NOT trigger (threshold=3).
	nlh.setLink("trust0", false)
	mon.poll()
	states = m.GroupStates()
	if states[0].Weight != 255 {
		t.Errorf("weight after 1 failure = %d, want 255 (dampened)", states[0].Weight)
	}

	mon.poll()
	states = m.GroupStates()
	if states[0].Weight != 255 {
		t.Errorf("weight after 2 failures = %d, want 255 (dampened)", states[0].Weight)
	}

	// 3rd poll triggers the state change.
	mon.poll()
	states = m.GroupStates()
	if states[0].Weight != 155 {
		t.Errorf("weight after 3 failures = %d, want 155", states[0].Weight)
	}

	// Recovery: first 2 passes should NOT trigger.
	nlh.setLink("trust0", true)
	mon.poll()
	states = m.GroupStates()
	if states[0].Weight != 155 {
		t.Errorf("weight after 1 pass = %d, want 155 (dampened)", states[0].Weight)
	}

	mon.poll()
	states = m.GroupStates()
	if states[0].Weight != 155 {
		t.Errorf("weight after 2 passes = %d, want 155 (dampened)", states[0].Weight)
	}

	// 3rd pass triggers recovery.
	mon.poll()
	states = m.GroupStates()
	if states[0].Weight != 255 {
		t.Errorf("weight after 3 passes = %d, want 255", states[0].Weight)
	}
}

func TestMonitor_HoldDown(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200},
			&config.InterfaceMonitor{Interface: "trust0", Weight: 100},
		),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	nlh := newMockNlHandle()
	nlh.setLink("trust0", true)

	now := time.Now()
	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.nlHandle = nlh
	mon.FailThreshold = 1
	mon.PassThreshold = 1
	mon.HoldDown = 5 * time.Second
	mon.nowFunc = func() time.Time { return now }

	// Initial poll.
	mon.poll()

	// Bring down — immediate (threshold=1).
	nlh.setLink("trust0", false)
	mon.poll()
	states := m.GroupStates()
	if states[0].Weight != 155 {
		t.Fatalf("weight after down = %d, want 155", states[0].Weight)
	}

	// Bring up immediately — should be blocked by hold-down.
	nlh.setLink("trust0", true)
	mon.poll()
	states = m.GroupStates()
	if states[0].Weight != 155 {
		t.Errorf("weight during hold-down = %d, want 155 (held)", states[0].Weight)
	}

	// Advance time but not past hold-down.
	now = now.Add(3 * time.Second)
	mon.poll()
	states = m.GroupStates()
	if states[0].Weight != 155 {
		t.Errorf("weight during hold-down (3s) = %d, want 155 (held)", states[0].Weight)
	}

	// Advance past hold-down.
	now = now.Add(3 * time.Second)
	mon.poll()
	states = m.GroupStates()
	if states[0].Weight != 255 {
		t.Errorf("weight after hold-down = %d, want 255", states[0].Weight)
	}
}

func TestMonitor_Flapping(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200},
			&config.InterfaceMonitor{Interface: "trust0", Weight: 100},
		),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	nlh := newMockNlHandle()
	nlh.setLink("trust0", true)

	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.nlHandle = nlh
	// Use default thresholds (3/3), disable hold-down.
	mon.HoldDown = 1 * time.Nanosecond

	mon.poll() // initial: up

	// Alternate up/down rapidly — consecutive count resets each flip,
	// so threshold is never reached.
	for i := 0; i < 20; i++ {
		nlh.setLink("trust0", false)
		mon.poll()
		nlh.setLink("trust0", true)
		mon.poll()
	}

	states := m.GroupStates()
	if states[0].Weight != 255 {
		t.Errorf("weight after flapping = %d, want 255 (dampened)", states[0].Weight)
	}
}

func TestMonitor_IPDampening(t *testing.T) {
	m := NewManager(0, 1)
	rg := &config.RedundancyGroup{
		ID:             0,
		NodePriorities: map[int]int{0: 200},
		IPMonitoring: &config.IPMonitoring{
			GlobalWeight: 100,
			Targets: []*config.IPMonitorTarget{
				{Address: "10.0.1.1", Weight: 80},
			},
		},
	}
	cfg := &config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{rg},
	}
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	reachable := true
	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.icmpDialer = func(network string) (icmpConn, error) {
		return &mockICMPConn{reachable: reachable}, nil
	}
	// Default thresholds (3/3), disable hold-down.
	mon.HoldDown = 1 * time.Nanosecond

	// Initial polls: reachable.
	mon.poll()
	states := m.GroupStates()
	if states[0].Weight != 255 {
		t.Fatalf("initial weight = %d, want 255", states[0].Weight)
	}

	// First two unreachable polls — dampened.
	reachable = false
	mon.poll()
	mon.poll()
	states = m.GroupStates()
	if states[0].Weight != 255 {
		t.Errorf("weight after 2 failures = %d, want 255 (dampened)", states[0].Weight)
	}

	// Third unreachable poll — triggers.
	mon.poll()
	states = m.GroupStates()
	if states[0].Weight != 175 {
		t.Errorf("weight after 3 failures = %d, want 175 (255-80)", states[0].Weight)
	}
}

func TestMonitor_IPv6IPMonitoring(t *testing.T) {
	m := NewManager(0, 1)
	rg := &config.RedundancyGroup{
		ID:             0,
		NodePriorities: map[int]int{0: 200},
		IPMonitoring: &config.IPMonitoring{
			GlobalWeight: 100,
			Targets: []*config.IPMonitorTarget{
				{Address: "2001:db8::1", Weight: 60},
			},
		},
	}
	cfg := &config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{rg},
	}
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	reachable := true
	var gotNetwork string
	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.icmpDialer = func(network string) (icmpConn, error) {
		gotNetwork = network
		return &mockICMPConn{reachable: reachable, v6: true}, nil
	}
	setNoDampening(mon)

	// IPv6 target reachable.
	mon.poll()
	if gotNetwork != "udp6" {
		t.Errorf("network = %q, want \"udp6\"", gotNetwork)
	}
	states := m.GroupStates()
	if states[0].Weight != 255 {
		t.Errorf("weight = %d, want 255 (IPv6 reachable)", states[0].Weight)
	}

	// IPv6 target unreachable.
	reachable = false
	mon.poll()
	states = m.GroupStates()
	if states[0].Weight != 195 {
		t.Errorf("weight = %d, want 195 (255-60)", states[0].Weight)
	}

	// Recover.
	reachable = true
	mon.poll()
	states = m.GroupStates()
	if states[0].Weight != 255 {
		t.Errorf("weight after recovery = %d, want 255", states[0].Weight)
	}
}

func TestMonitor_IPv4ProbeUsesUDP4(t *testing.T) {
	m := NewManager(0, 1)
	rg := &config.RedundancyGroup{
		ID:             0,
		NodePriorities: map[int]int{0: 200},
		IPMonitoring: &config.IPMonitoring{
			GlobalWeight: 100,
			Targets: []*config.IPMonitorTarget{
				{Address: "10.0.1.1", Weight: 50},
			},
		},
	}
	cfg := &config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{rg},
	}
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	var gotNetwork string
	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.icmpDialer = func(network string) (icmpConn, error) {
		gotNetwork = network
		return &mockICMPConn{reachable: true}, nil
	}
	setNoDampening(mon)

	mon.poll()
	if gotNetwork != "udp4" {
		t.Errorf("network = %q, want \"udp4\"", gotNetwork)
	}
}

func TestMonitor_InvalidAddress(t *testing.T) {
	m := NewManager(0, 1)
	rg := &config.RedundancyGroup{
		ID:             0,
		NodePriorities: map[int]int{0: 200},
		IPMonitoring: &config.IPMonitoring{
			GlobalWeight: 100,
			Targets: []*config.IPMonitorTarget{
				{Address: "not-an-ip", Weight: 50},
			},
		},
	}
	cfg := &config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{rg},
	}
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	dialerCalled := false
	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.icmpDialer = func(network string) (icmpConn, error) {
		dialerCalled = true
		return &mockICMPConn{reachable: true}, nil
	}
	setNoDampening(mon)

	// Invalid address should not crash and should be treated as unreachable.
	mon.poll()
	if dialerCalled {
		t.Error("dialer should not be called for invalid address")
	}
}

// mockICMPConn simulates ICMP for testing.
type mockICMPConn struct {
	reachable bool
	v6        bool // if true, return ICMPv6 echo reply
}

func (c *mockICMPConn) WriteTo(b []byte, dst net.Addr) (int, error) {
	return len(b), nil
}

func (c *mockICMPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if !c.reachable {
		return 0, nil, net.UnknownNetworkError("timeout")
	}
	if c.v6 {
		// ICMPv6 echo reply: Type=129, Code=0, Checksum, ID, Seq
		reply := []byte{0x81, 0x00, 0x00, 0x00, 0x00, 0xbf, 0x00, 0x01}
		// Checksum is validated by kernel for UDP-based ICMP, set to zero.
		n := copy(b, reply)
		return n, &net.UDPAddr{IP: net.ParseIP("2001:db8::1")}, nil
	}
	// ICMPv4 echo reply: Type=0, Code=0, Checksum, ID, Seq
	reply := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0xbf, 0x00, 0x01}
	// Fix checksum
	reply[2] = 0xff
	reply[3] = 0x40
	n := copy(b, reply)
	return n, &net.UDPAddr{IP: net.ParseIP("10.0.1.1")}, nil
}

func (c *mockICMPConn) SetReadDeadline(t time.Time) error { return nil }
func (c *mockICMPConn) Close() error                      { return nil }

func TestMonitor_LocalStatusesConcurrent(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200},
			&config.InterfaceMonitor{Interface: "trust0", Weight: 100},
		),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	nlh := newMockNlHandle()
	nlh.setLink("trust0", true)

	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.nlHandle = nlh
	setNoDampening(mon)

	ctx, cancel := context.WithCancel(context.Background())
	mon.Start(ctx)
	defer func() {
		cancel()
		mon.Stop()
	}()

	// Hammer LocalInterfaceStatuses concurrently with poll() to trigger
	// the race detector if the lock is not held properly.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 500; i++ {
			_ = mon.LocalInterfaceStatuses()
		}
	}()

	<-done
}

// drainEvents is defined in election_test.go
