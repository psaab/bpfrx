package cluster

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/psaab/bpfrx/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// monitorState tracks the dampened state for a single monitor probe.
type monitorState struct {
	down            bool      // dampened state (what we've reported to SetMonitorWeight)
	consecutiveFail int       // consecutive polls seeing failure
	consecutivePass int       // consecutive polls seeing success
	holdDownUntil   time.Time // earliest allowed next state change
}

// Dampening defaults.
const (
	DefaultMonitorFailThreshold = 3              // consecutive failures before marking down
	DefaultMonitorPassThreshold = 3              // consecutive successes before marking up
	DefaultMonitorHoldDown      = 5 * time.Second // hold-down after state change
)

// Monitor periodically checks interface link states and IP reachability,
// updating the cluster Manager's monitor weights when changes occur.
// State changes are dampened: an interface must fail/recover for multiple
// consecutive polls before the weight is adjusted, and a hold-down timer
// prevents rapid oscillation after each transition.
type Monitor struct {
	mgr    *Manager
	groups []*config.RedundancyGroup

	mu     sync.Mutex
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Dampened state per interface/IP monitor.
	ifaceState map[monitorKey]*monitorState
	ipState    map[ipMonitorKey]*monitorState

	// localStatuses holds the latest local interface monitor states,
	// rebuilt on every poll cycle. Used to populate heartbeat packets.
	localStatuses []InterfaceMonitorInfo

	// nlHandle is the netlink handle for link state queries.
	// Can be overridden for testing.
	nlHandle nlLinkGetter

	// cachedNlHandle is the production netlink handle created on first use.
	// Stored separately so Stop() can close it without adding Close() to
	// the nlLinkGetter test interface.
	cachedNlHandle *netlink.Handle

	// icmpDialer can be overridden for testing.
	// network is "udp4" or "udp6".
	icmpDialer func(network string) (icmpConn, error)

	// Dampening thresholds (0 means use default).
	FailThreshold int
	PassThreshold int
	HoldDown      time.Duration

	// nowFunc can be overridden for testing time-dependent behavior.
	nowFunc func() time.Time
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
		mgr:        mgr,
		groups:     groups,
		ifaceState: make(map[monitorKey]*monitorState),
		ipState:    make(map[ipMonitorKey]*monitorState),
	}
}

func (mon *Monitor) failThreshold() int {
	if mon.FailThreshold > 0 {
		return mon.FailThreshold
	}
	return DefaultMonitorFailThreshold
}

func (mon *Monitor) passThreshold() int {
	if mon.PassThreshold > 0 {
		return mon.PassThreshold
	}
	return DefaultMonitorPassThreshold
}

func (mon *Monitor) holdDownDuration() time.Duration {
	if mon.HoldDown > 0 {
		return mon.HoldDown
	}
	return DefaultMonitorHoldDown
}

func (mon *Monitor) now() time.Time {
	if mon.nowFunc != nil {
		return mon.nowFunc()
	}
	return time.Now()
}

// evaluateTransition applies dampening logic and returns true if the
// dampened state has changed (caller should fire SetMonitorWeight).
func (mon *Monitor) evaluateTransition(state *monitorState, currentlyDown bool) bool {
	now := mon.now()

	if currentlyDown {
		state.consecutiveFail++
		state.consecutivePass = 0
		if !state.down && state.consecutiveFail >= mon.failThreshold() && now.After(state.holdDownUntil) {
			state.down = true
			state.holdDownUntil = now.Add(mon.holdDownDuration())
			return true
		}
	} else {
		state.consecutivePass++
		state.consecutiveFail = 0
		if state.down && state.consecutivePass >= mon.passThreshold() && now.After(state.holdDownUntil) {
			state.down = false
			state.holdDownUntil = now.Add(mon.holdDownDuration())
			return true
		}
	}
	return false
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
	nlh := mon.cachedNlHandle
	mon.cachedNlHandle = nil
	mon.mu.Unlock()

	if cancel != nil {
		cancel()
		mon.wg.Wait()
	}
	if nlh != nil {
		nlh.Close()
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

	// Rebuild local statuses into a local slice, then swap under lock
	// to avoid racing with LocalInterfaceStatuses().
	var statuses []InterfaceMonitorInfo

	for _, rg := range groups {
		statuses = mon.pollInterfaceMonitors(rg, statuses)
		mon.pollIPMonitors(rg)
	}

	mon.mu.Lock()
	mon.localStatuses = statuses
	mon.mu.Unlock()
}

// LocalInterfaceStatuses returns the latest snapshot of local interface monitor states.
// Used to populate heartbeat packets with per-interface status.
func (mon *Monitor) LocalInterfaceStatuses() []InterfaceMonitorInfo {
	mon.mu.Lock()
	defer mon.mu.Unlock()
	if len(mon.localStatuses) == 0 {
		return nil
	}
	cp := make([]InterfaceMonitorInfo, len(mon.localStatuses))
	copy(cp, mon.localStatuses)
	return cp
}

func (mon *Monitor) pollInterfaceMonitors(rg *config.RedundancyGroup, statuses []InterfaceMonitorInfo) []InterfaceMonitorInfo {
	nlh := mon.getNlHandle()

	for _, im := range rg.InterfaceMonitors {
		key := monitorKey{rgID: rg.ID, iface: im.Interface}

		// Translate Junos name (ge-0/0/0) to Linux name (ge-0-0-0).
		linuxName := config.LinuxIfName(im.Interface)
		link, err := nlh.LinkByName(linuxName)
		if err != nil {
			// Interface doesn't exist on this node — belongs to peer
			// (e.g. ge-7/0/x on node 0). Skip without counting as down.
			continue
		}

		up := link.Attrs().OperState == netlink.OperUp ||
			link.Attrs().Flags&net.FlagUp != 0

		// Track local interface status for heartbeat propagation.
		statuses = append(statuses, InterfaceMonitorInfo{
			Interface:       im.Interface,
			Weight:          im.Weight,
			Up:              up,
			RedundancyGroup: rg.ID,
		})

		state := mon.ifaceState[key]
		if state == nil {
			state = &monitorState{}
			mon.ifaceState[key] = state
		}

		if mon.evaluateTransition(state, !up) {
			mon.mgr.SetMonitorWeight(rg.ID, im.Interface, state.down, im.Weight)
			if state.down {
				mon.mgr.RecordEvent(EventMonitor, rg.ID, fmt.Sprintf(
					"Interface %s state changed to down, weight %d", im.Interface, im.Weight))
			} else {
				mon.mgr.RecordEvent(EventMonitor, rg.ID, fmt.Sprintf(
					"Interface %s state changed to up", im.Interface))
			}
			slog.Info("cluster monitor: interface state changed",
				"rg", rg.ID, "interface", im.Interface,
				"up", up, "weight", im.Weight)
		}
	}
	return statuses
}

func (mon *Monitor) pollIPMonitors(rg *config.RedundancyGroup) {
	if rg.IPMonitoring == nil || len(rg.IPMonitoring.Targets) == 0 {
		return
	}

	for _, target := range rg.IPMonitoring.Targets {
		key := ipMonitorKey{rgID: rg.ID, address: target.Address}

		reachable := mon.probeICMP(target.Address)

		weight := target.Weight
		if weight == 0 {
			weight = rg.IPMonitoring.GlobalWeight
		}

		// Use "ip:" prefix to distinguish from interface monitors.
		monName := "ip:" + target.Address

		state := mon.ipState[key]
		if state == nil {
			state = &monitorState{}
			mon.ipState[key] = state
		}

		if mon.evaluateTransition(state, !reachable) {
			mon.mgr.SetMonitorWeight(rg.ID, monName, state.down, weight)
			if state.down {
				mon.mgr.RecordEvent(EventMonitor, rg.ID, fmt.Sprintf(
					"IP %s unreachable, weight %d", target.Address, weight))
			} else {
				mon.mgr.RecordEvent(EventMonitor, rg.ID, fmt.Sprintf(
					"IP %s reachable", target.Address))
			}
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

	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}

	isIPv6 := ip.To4() == nil

	var network string
	var echoType icmp.Type
	var replyType icmp.Type
	var proto int // IANA protocol number for icmp.ParseMessage

	if isIPv6 {
		network = "udp6"
		echoType = ipv6.ICMPTypeEchoRequest
		replyType = ipv6.ICMPTypeEchoReply
		proto = 58 // ICMPv6
	} else {
		network = "udp4"
		echoType = ipv4.ICMPTypeEcho
		replyType = ipv4.ICMPTypeEchoReply
		proto = 1 // ICMPv4
	}

	conn, err := dialer(network)
	if err != nil {
		return false
	}
	defer conn.Close()

	msg := icmp.Message{
		Type: echoType,
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

	dst := &net.UDPAddr{IP: ip}
	if _, err := conn.WriteTo(b, dst); err != nil {
		return false
	}

	conn.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
	reply := make([]byte, 1500)
	n, _, err := conn.ReadFrom(reply)
	if err != nil {
		return false
	}

	parsed, err := icmp.ParseMessage(proto, reply[:n])
	if err != nil {
		return false
	}
	return parsed.Type == replyType
}

func defaultICMPDialer(network string) (icmpConn, error) {
	var listenAddr string
	if network == "udp6" {
		listenAddr = "::"
	} else {
		listenAddr = "0.0.0.0"
	}
	c, err := icmp.ListenPacket(network, listenAddr)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// RGInterfaceReady checks if all local required interfaces for the given RG
// exist and are operationally up. Returns (true, nil) if all ready, or
// (false, reasons) with a list of missing/down interface names.
func (mon *Monitor) RGInterfaceReady(rgID int) (bool, []string) {
	mon.mu.Lock()
	groups := mon.groups
	mon.mu.Unlock()

	nlh := mon.getNlHandle()

	var reasons []string
	found := false
	for _, rg := range groups {
		if rg.ID != rgID {
			continue
		}
		found = true
		for _, im := range rg.InterfaceMonitors {
			linuxName := config.LinuxIfName(im.Interface)
			link, err := nlh.LinkByName(linuxName)
			if err != nil {
				reasons = append(reasons, fmt.Sprintf("interface %s not found", im.Interface))
				continue
			}
			up := link.Attrs().OperState == netlink.OperUp ||
				link.Attrs().Flags&net.FlagUp != 0
			if !up {
				reasons = append(reasons, fmt.Sprintf("interface %s down", im.Interface))
			}
		}
	}
	if !found {
		// No RG config found — treat as ready (nothing to check).
		return true, nil
	}
	if len(reasons) > 0 {
		return false, reasons
	}
	return true, nil
}

func (mon *Monitor) getNlHandle() nlLinkGetter {
	if mon.nlHandle != nil {
		return mon.nlHandle
	}
	// Cache the production handle to avoid leaking netlink sockets.
	if mon.cachedNlHandle != nil {
		return mon.cachedNlHandle
	}
	h, err := netlink.NewHandle()
	if err != nil {
		slog.Warn("cluster monitor: failed to create netlink handle", "err", err)
		return &noopNlHandle{}
	}
	mon.cachedNlHandle = h
	return h
}

type noopNlHandle struct{}

func (n *noopNlHandle) LinkByName(name string) (netlink.Link, error) {
	return nil, net.UnknownNetworkError("no netlink handle")
}
