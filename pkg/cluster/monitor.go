package cluster

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/psaab/bpfrx/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// Monitor periodically checks interface link states and IP reachability,
// updating the cluster Manager's monitor weights when changes occur.
type Monitor struct {
	mgr    *Manager
	groups []*config.RedundancyGroup

	mu     sync.Mutex
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Track last-known states to only call SetMonitorWeight on changes.
	ifaceDown map[monitorKey]bool
	ipDown    map[ipMonitorKey]bool

	// nlHandle is the netlink handle for link state queries.
	// Can be overridden for testing.
	nlHandle nlLinkGetter

	// icmpDialer can be overridden for testing.
	icmpDialer func() (icmpConn, error)
}

// nlLinkGetter abstracts netlink.Handle.LinkByName for testing.
type nlLinkGetter interface {
	LinkByName(name string) (netlink.Link, error)
}

// icmpConn abstracts an ICMP connection for testing.
type icmpConn interface {
	WriteTo(b []byte, dst net.Addr) (int, error)
	ReadFrom(b []byte) (int, net.Addr, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

type ipMonitorKey struct {
	rgID    int
	address string
}

// NewMonitor creates a monitor that will poll interface and IP states.
func NewMonitor(mgr *Manager, groups []*config.RedundancyGroup) *Monitor {
	return &Monitor{
		mgr:       mgr,
		groups:    groups,
		ifaceDown: make(map[monitorKey]bool),
		ipDown:    make(map[ipMonitorKey]bool),
	}
}

// Start begins periodic monitoring. Safe to call multiple times (stops previous).
func (mon *Monitor) Start(ctx context.Context) {
	mon.Stop()

	mon.mu.Lock()
	defer mon.mu.Unlock()

	ctx, cancel := context.WithCancel(ctx)
	mon.cancel = cancel

	mon.wg.Add(1)
	go mon.loop(ctx)
}

// Stop halts the monitoring goroutine and waits for it to exit.
func (mon *Monitor) Stop() {
	mon.mu.Lock()
	cancel := mon.cancel
	mon.cancel = nil
	mon.mu.Unlock()

	if cancel != nil {
		cancel()
		mon.wg.Wait()
	}
}

// UpdateGroups replaces the monitored redundancy groups.
func (mon *Monitor) UpdateGroups(groups []*config.RedundancyGroup) {
	mon.mu.Lock()
	defer mon.mu.Unlock()
	mon.groups = groups
}

func (mon *Monitor) loop(ctx context.Context) {
	defer mon.wg.Done()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// Run immediately on start.
	mon.poll()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			mon.poll()
		}
	}
}

func (mon *Monitor) poll() {
	mon.mu.Lock()
	groups := mon.groups
	mon.mu.Unlock()

	for _, rg := range groups {
		mon.pollInterfaceMonitors(rg)
		mon.pollIPMonitors(rg)
	}
}

func (mon *Monitor) pollInterfaceMonitors(rg *config.RedundancyGroup) {
	nlh := mon.getNlHandle()

	for _, im := range rg.InterfaceMonitors {
		key := monitorKey{rgID: rg.ID, iface: im.Interface}
		up := false

		link, err := nlh.LinkByName(im.Interface)
		if err == nil {
			up = link.Attrs().OperState == netlink.OperUp ||
				link.Attrs().Flags&net.FlagUp != 0
		}

		wasDown := mon.ifaceDown[key]
		isDown := !up

		if isDown != wasDown {
			mon.ifaceDown[key] = isDown
			mon.mgr.SetMonitorWeight(rg.ID, im.Interface, isDown, im.Weight)
			slog.Info("cluster monitor: interface state changed",
				"rg", rg.ID, "interface", im.Interface,
				"up", up, "weight", im.Weight)
		}
	}
}

func (mon *Monitor) pollIPMonitors(rg *config.RedundancyGroup) {
	if rg.IPMonitoring == nil || len(rg.IPMonitoring.Targets) == 0 {
		return
	}

	for _, target := range rg.IPMonitoring.Targets {
		key := ipMonitorKey{rgID: rg.ID, address: target.Address}

		reachable := mon.probeICMP(target.Address)

		wasDown := mon.ipDown[key]
		isDown := !reachable

		weight := target.Weight
		if weight == 0 {
			weight = rg.IPMonitoring.GlobalWeight
		}

		// Use "ip:" prefix to distinguish from interface monitors.
		monName := "ip:" + target.Address

		if isDown != wasDown {
			mon.ipDown[key] = isDown
			mon.mgr.SetMonitorWeight(rg.ID, monName, isDown, weight)
			slog.Info("cluster monitor: IP probe state changed",
				"rg", rg.ID, "address", target.Address,
				"reachable", reachable, "weight", weight)
		}
	}
}

func (mon *Monitor) probeICMP(addr string) bool {
	dialer := mon.icmpDialer
	if dialer == nil {
		dialer = defaultICMPDialer
	}

	conn, err := dialer()
	if err != nil {
		return false
	}
	defer conn.Close()

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   0xbf,
			Seq:  1,
			Data: []byte("bpfrx"),
		},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return false
	}

	dst := &net.UDPAddr{IP: net.ParseIP(addr)}
	if _, err := conn.WriteTo(b, dst); err != nil {
		return false
	}

	conn.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
	reply := make([]byte, 1500)
	n, _, err := conn.ReadFrom(reply)
	if err != nil {
		return false
	}

	parsed, err := icmp.ParseMessage(1, reply[:n])
	if err != nil {
		return false
	}
	return parsed.Type == ipv4.ICMPTypeEchoReply
}

func defaultICMPDialer() (icmpConn, error) {
	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (mon *Monitor) getNlHandle() nlLinkGetter {
	if mon.nlHandle != nil {
		return mon.nlHandle
	}
	h, err := netlink.NewHandle()
	if err != nil {
		slog.Warn("cluster monitor: failed to create netlink handle", "err", err)
		return &noopNlHandle{}
	}
	return h
}

type noopNlHandle struct{}

func (n *noopNlHandle) LinkByName(name string) (netlink.Link, error) {
	return nil, net.UnknownNetworkError("no netlink handle")
}
