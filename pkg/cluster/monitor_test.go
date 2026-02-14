package cluster

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/psaab/bpfrx/pkg/config"
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
	mon.icmpDialer = func() (icmpConn, error) {
		return &mockICMPConn{reachable: reachable}, nil
	}

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

// mockICMPConn simulates ICMP for testing.
type mockICMPConn struct {
	reachable bool
}

func (c *mockICMPConn) WriteTo(b []byte, dst net.Addr) (int, error) {
	return len(b), nil
}

func (c *mockICMPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if !c.reachable {
		return 0, nil, net.UnknownNetworkError("timeout")
	}
	// Return a valid ICMP echo reply.
	// Type=0 (echo reply), Code=0, Checksum, ID, Seq
	reply := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0xbf, 0x00, 0x01}
	// Fix checksum
	reply[2] = 0xff
	reply[3] = 0x40
	n := copy(b, reply)
	return n, &net.UDPAddr{IP: net.ParseIP("10.0.1.1")}, nil
}

func (c *mockICMPConn) SetReadDeadline(t time.Time) error { return nil }
func (c *mockICMPConn) Close() error                      { return nil }

// drainEvents is defined in election_test.go
