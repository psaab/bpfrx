// Package routing manages static routes and GRE tunnels via netlink.
package routing

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// KeepaliveState tracks the status of a GRE tunnel keepalive probe.
type KeepaliveState struct {
	mu          sync.Mutex
	Up          bool // true if tunnel is considered up
	Failures    int  // consecutive probe failures
	LastSuccess time.Time
	LastFailure time.Time
	RemoteAddr  string // remote endpoint being probed
	Interval    int    // probe interval in seconds
	MaxRetries  int    // failures before declaring down
}

// InterfaceMonitorStatus tracks the link state of a monitored interface.
type InterfaceMonitorStatus struct {
	Interface string
	Weight    int
	Up        bool // true if link is operationally up
}

// Manager handles tunnel and VRF lifecycle.
type Manager struct {
	nlHandle   *netlink.Handle
	keepalives map[string]*keepaliveRunner // tunnel name -> runner

	// #848: ifaceMu serializes all reads and writes of the
	// tunnels/xfrmis/bonds slices. ApplyTunnels/ApplyXfrmi/
	// ApplyBonds and their Clear counterparts hold it for the full
	// duration including netlink calls; GetTunnelStatus snapshots
	// the slice under the lock and iterates lock-free so a long
	// gRPC read can't block applyConfig.
	ifaceMu sync.Mutex
	tunnels []string // currently created tunnel interface names
	xfrmis  []string // currently created xfrmi interface names
	bonds   []string // currently created bond interface names

	// vrfsMu serializes all reads and writes of vrfs, and is held for
	// the full duration of ReconcileVRFs/CreateVRF including the
	// netlink operations. Callers must not assume ReconcileVRFs is
	// re-entrant. See docs/pr/844-vrf-idempotent/plan.md.
	vrfsMu sync.Mutex
	vrfs   []string // currently managed VRF device names

	mu            sync.Mutex
	monitorStatus map[int][]InterfaceMonitorStatus // redundancy-group ID -> monitor states
}

// VRFSpec describes a single VRF by its logical name (no "vrf-"
// prefix) and its kernel routing table ID.
type VRFSpec struct {
	Name    string
	TableID int
}

// keepaliveRunner manages the goroutine for a single tunnel's keepalive.
//
// #848: `done` is closed by keepaliveLoop just before it returns.
// Close() / stopAllKeepalives drain on this channel so the netlink
// handle is not closed while a keepalive goroutine is still in
// flight (use-after-close on m.nlHandle).
type keepaliveRunner struct {
	cancel context.CancelFunc
	state  *KeepaliveState
	done   chan struct{}
}

// New creates a new routing Manager.
func New() (*Manager, error) {
	h, err := netlink.NewHandle()
	if err != nil {
		return nil, fmt.Errorf("netlink handle: %w", err)
	}
	return &Manager{
		nlHandle:   h,
		keepalives: make(map[string]*keepaliveRunner),
	}, nil
}

// Close releases the netlink handle and stops all keepalive probes.
func (m *Manager) Close() error {
	m.ifaceMu.Lock()
	m.stopAllKeepalives()
	m.ifaceMu.Unlock()
	if m.nlHandle != nil {
		m.nlHandle.Close()
	}
	return nil
}

// CreateVRF creates a Linux VRF device and assigns it a routing table.
// Prefer ReconcileVRFs for multi-VRF config apply; CreateVRF is retained
// for callers that need single-VRF semantics.
func (m *Manager) CreateVRF(name string, tableID int) error {
	m.vrfsMu.Lock()
	defer m.vrfsMu.Unlock()
	return m.createVRFLocked(name, tableID)
}

// createVRFLocked creates a VRF and appends it to m.vrfs. Caller must
// hold vrfsMu. External VRFs (already present) are left alone and not
// adopted into m.vrfs.
func (m *Manager) createVRFLocked(name string, tableID int) error {
	vrfName := "vrf-" + name
	if existing, err := m.nlHandle.LinkByName(vrfName); err == nil {
		if err := m.nlHandle.LinkSetUp(existing); err != nil {
			slog.Debug("failed to set existing VRF up", "name", vrfName, "err", err)
		}
		slog.Debug("VRF already exists", "name", vrfName, "table", tableID)
		return nil
	}
	added, err := createLinkedVRF(m.nlHandle, vrfName, tableID)
	if added {
		m.vrfs = append(m.vrfs, vrfName)
	}
	return err
}

// vrfOps is the minimal netlink surface ReconcileVRFs needs. Satisfied
// by *netlink.Handle in production; tests substitute a fake.
type vrfOps interface {
	LinkByName(string) (netlink.Link, error)
	LinkAdd(netlink.Link) error
	LinkDel(netlink.Link) error
	LinkSetUp(netlink.Link) error
}

// IsManagedVRF reports whether the given logical VRF name (e.g. "mgmt",
// "sfmix") is currently in the manager's tracked set. Used by callers
// that need to gate downstream actions on successful VRF creation.
func (m *Manager) IsManagedVRF(name string) bool {
	vrfName := "vrf-" + name
	m.vrfsMu.Lock()
	defer m.vrfsMu.Unlock()
	for _, n := range m.vrfs {
		if n == vrfName {
			return true
		}
	}
	return false
}

// ReconcileVRFs brings the manager's owned-VRF set to match desired.
//
// Ownership rules — xpfd is authoritative for the "vrf-<name>"
// namespace of names appearing in desired. Any VRF whose name appears
// in desired is considered ours regardless of creator:
//   - Desired VRF, present in kernel with matching table: no-op
//     (preserve ifindex). Adopted into m.vrfs if not already there.
//   - Desired VRF, present in kernel with mismatching table:
//     LinkDel + LinkAdd (recreate). Adopted into m.vrfs.
//   - Desired VRF, absent from kernel: LinkAdd, adopted into m.vrfs.
//   - Non-desired VRF in kernel but NOT in m.vrfs: never touched
//     (truly external — outside our namespace claim).
//   - Managed VRF in m.vrfs not in desired: LinkDel, removed from m.vrfs.
//
// Holds vrfsMu for the full body including netlink operations. VRF
// reconcile is low-frequency; lock contention is not a concern and
// serialized reconciles avoid TOCTOU between concurrent callers.
func (m *Manager) ReconcileVRFs(desired []VRFSpec) error {
	m.vrfsMu.Lock()
	defer m.vrfsMu.Unlock()
	newVrfs, err := reconcileVRFs(m.nlHandle, m.vrfs, desired)
	m.vrfs = newVrfs
	return err
}

// errLinkNotFound is an internal sentinel wrapper used when the
// manager generates its own "not found" errors (e.g. from fakes in
// tests, or from any path not going through the netlink library).
// netlink.LinkNotFoundError cannot be constructed outside the
// netlink package because its embedded error field is unexported.
type errLinkNotFound struct{ error }

// isLinkNotFound reports whether err is a "link not found" error
// from either the netlink library or the internal sentinel. Other
// errors (EINVAL, EBUSY, transport failure) must NOT be treated as
// absence.
func isLinkNotFound(err error) bool {
	if err == nil {
		return false
	}
	var nlNotFound netlink.LinkNotFoundError
	if errors.As(err, &nlNotFound) {
		return true
	}
	var internal errLinkNotFound
	return errors.As(err, &internal)
}

// reconcileVRFs is the pure core of ReconcileVRFs, parameterised on a
// vrfOps so tests can inject a fake. Returns the new tracked set and
// the first error encountered (others are logged).
//
// Ownership semantics: a VRF is "ours" if its name appears in desired.
// xpfd is authoritative for the "vrf-<instance>" namespace derived
// from configured routing instances (plus the well-known "vrf-mgmt").
// If such a VRF already exists in the kernel (e.g. surviving from a
// previous daemon instance), reconcileVRFs ADOPTS it into m.vrfs so
// a later reconcile can manage or delete it. Non-desired kernel VRFs
// are left strictly alone.
//
// Partial-failure contract: if LinkAdd succeeds but a follow-up
// (LinkByName / LinkSetUp) fails, the VRF is still recorded in the
// tracked set. Similarly, LinkDel failures retain ownership. This
// ensures a future reconcile can retry.
func reconcileVRFs(ops vrfOps, tracked []string, desired []VRFSpec) ([]string, error) {
	desiredByName := make(map[string]int, len(desired))
	for _, spec := range desired {
		desiredByName["vrf-"+spec.Name] = spec.TableID
	}
	managed := make(map[string]bool, len(tracked))
	for _, name := range tracked {
		managed[name] = true
	}

	var firstErr error
	recordErr := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	newTracked := make([]string, 0, len(desired))

	for _, spec := range desired {
		vrfName := "vrf-" + spec.Name
		link, kerErr := ops.LinkByName(vrfName)

		if kerErr != nil {
			if !isLinkNotFound(kerErr) {
				// Transient netlink error — don't assume the VRF is
				// absent and don't attempt to create it. Next
				// reconcile will retry. CRUCIALLY: if this name was
				// already in m.vrfs, retain ownership — otherwise a
				// transient blip would silently drop us from the
				// managed set and IsManagedVRF would start lying.
				if managed[vrfName] {
					newTracked = append(newTracked, vrfName)
				}
				recordErr(fmt.Errorf("lookup VRF %s: %w", vrfName, kerErr))
				continue
			}
			// Genuinely not in kernel — create it.
			added, err := createLinkedVRF(ops, vrfName, spec.TableID)
			if added {
				newTracked = append(newTracked, vrfName)
			}
			recordErr(err)
			continue
		}

		// Present in kernel. Adopt it — the vrf-<desired-name>
		// namespace is ours, regardless of who created the device.
		currentTable := vrfTable(link)
		if currentTable == uint32(spec.TableID) {
			if err := ops.LinkSetUp(link); err != nil {
				slog.Debug("VRF set-up failed (non-fatal)", "name", vrfName, "err", err)
			}
			newTracked = append(newTracked, vrfName)
			continue
		}

		// Table mismatch — recreate with desired table.
		slog.Warn("VRF table ID mismatches desired, recreating",
			"name", vrfName, "old_table", currentTable, "new_table", spec.TableID)
		if err := ops.LinkDel(link); err != nil {
			// Delete failed — VRF still exists with wrong table.
			// Retain ownership so a future reconcile can retry.
			newTracked = append(newTracked, vrfName)
			recordErr(fmt.Errorf("delete stale VRF %s: %w", vrfName, err))
			continue
		}
		added, err := createLinkedVRF(ops, vrfName, spec.TableID)
		if added {
			newTracked = append(newTracked, vrfName)
		}
		recordErr(err)
	}

	// Delete managed VRFs no longer in desired.
	for _, existing := range tracked {
		if _, stillDesired := desiredByName[existing]; stillDesired {
			continue
		}
		link, err := ops.LinkByName(existing)
		if err != nil {
			if !isLinkNotFound(err) {
				// Transient — retain ownership; don't drop silently.
				newTracked = append(newTracked, existing)
				recordErr(fmt.Errorf("lookup VRF %s for delete: %w", existing, err))
			}
			// Not found: already gone; nothing to do.
			continue
		}
		if err := ops.LinkDel(link); err != nil {
			// Delete failed — VRF still exists. Retain in tracked so
			// next reconcile retries instead of losing ownership.
			newTracked = append(newTracked, existing)
			recordErr(fmt.Errorf("delete VRF %s: %w", existing, err))
			continue
		}
		slog.Info("VRF removed", "name", existing)
	}

	return newTracked, firstErr
}

// createLinkedVRF creates a VRF. Returns (added, err) where added is
// true if LinkAdd succeeded (even if a follow-up step failed). This
// lets callers record ownership of partially-created VRFs so a future
// reconcile can clean them up. Does not append to any tracked list —
// caller owns tracked-set updates.
func createLinkedVRF(ops vrfOps, vrfName string, tableID int) (bool, error) {
	vrf := &netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{Name: vrfName},
		Table:     uint32(tableID),
	}
	if err := ops.LinkAdd(vrf); err != nil {
		return false, fmt.Errorf("create VRF %s: %w", vrfName, err)
	}
	link, err := ops.LinkByName(vrfName)
	if err != nil {
		return true, fmt.Errorf("find VRF %s after add: %w", vrfName, err)
	}
	if err := ops.LinkSetUp(link); err != nil {
		return true, fmt.Errorf("set VRF %s up: %w", vrfName, err)
	}
	slog.Info("VRF created", "name", vrfName, "table", tableID)
	return true, nil
}

// vrfTable returns the routing table of a VRF link, or 0 if the link
// is not a VRF (which indicates a namespace collision with a
// non-VRF device of the same name).
func vrfTable(link netlink.Link) uint32 {
	if v, ok := link.(*netlink.Vrf); ok {
		return v.Table
	}
	return 0
}

// BindInterfaceToVRF binds a network interface to a VRF device.
func (m *Manager) BindInterfaceToVRF(ifaceName, instanceName string) error {
	vrfName := "vrf-" + instanceName

	iface, err := m.nlHandle.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}
	vrf, err := m.nlHandle.LinkByName(vrfName)
	if err != nil {
		return fmt.Errorf("VRF %s not found: %w", vrfName, err)
	}
	if err := m.nlHandle.LinkSetMaster(iface, vrf); err != nil {
		return fmt.Errorf("bind %s to VRF %s: %w", ifaceName, vrfName, err)
	}
	slog.Info("interface bound to VRF", "interface", ifaceName, "vrf", vrfName)
	return nil
}

// GetRoutesForTable reads routes from a specific kernel routing table.
func (m *Manager) GetRoutesForTable(tableID int) ([]RouteEntry, error) {
	var entries []RouteEntry

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		filter := &netlink.Route{Table: tableID}
		routes, err := m.nlHandle.RouteListFiltered(family, filter, netlink.RT_FILTER_TABLE)
		if err != nil {
			continue
		}
		for _, r := range routes {
			entries = append(entries, routeToEntry(m, r, family))
		}
	}

	return entries, nil
}

// routeToEntry converts a netlink route to a RouteEntry.
func routeToEntry(m *Manager, r netlink.Route, family int) RouteEntry {
	entry := RouteEntry{
		Preference: r.Priority,
		Protocol:   rtProtoName(r.Protocol),
	}

	if r.Dst != nil {
		entry.Destination = r.Dst.String()
	} else {
		if family == netlink.FAMILY_V6 {
			entry.Destination = "::/0"
		} else {
			entry.Destination = "0.0.0.0/0"
		}
	}

	if r.Gw != nil {
		entry.NextHop = r.Gw.String()
	} else if r.Type == unix.RTN_BLACKHOLE {
		entry.NextHop = "discard"
	} else {
		entry.NextHop = "direct"
	}

	if r.LinkIndex > 0 {
		link, err := m.nlHandle.LinkByIndex(r.LinkIndex)
		if err == nil {
			entry.Interface = link.Attrs().Name
		} else {
			entry.Interface = strconv.Itoa(r.LinkIndex)
		}
	}

	return entry
}

// ApplyTunnels creates GRE tunnel interfaces, brings them up, and assigns addresses.
// Previous tunnels are removed first. Starts keepalive probes for tunnels that have
// keepalive configured.
func (m *Manager) ApplyTunnels(tunnels []*config.TunnelConfig) error {
	m.ifaceMu.Lock()
	defer m.ifaceMu.Unlock()
	if err := m.clearTunnelsLocked(); err != nil {
		slog.Warn("failed to clear previous tunnels", "err", err)
	}

	for _, tc := range tunnels {
		if existing, err := m.nlHandle.LinkByName(tc.Name); err == nil {
			if err := m.nlHandle.LinkDel(existing); err != nil {
				slog.Warn("failed to replace existing tunnel link",
					"name", tc.Name, "existing_type", existing.Type(), "err", err)
				continue
			}
			slog.Info("removed existing tunnel link before apply",
				"name", tc.Name, "existing_type", existing.Type())
		}

		if tc.AnchorOnly {
			anchor := &netlink.Tuntap{
				LinkAttrs:  netlink.LinkAttrs{Name: tc.Name},
				Mode:       netlink.TUNTAP_MODE_TUN,
				Flags:      netlink.TUNTAP_NO_PI | netlink.TUNTAP_ONE_QUEUE,
				Queues:     1,
				NonPersist: false,
			}
			if err := m.nlHandle.LinkAdd(anchor); err != nil {
				// Handle upgrade from dummy-anchor to TUN: if a link with
				// this name already exists, check if it's already a TUN.
				// If it's a different type (e.g. dummy), delete and recreate.
				if existing, lookupErr := m.nlHandle.LinkByName(tc.Name); lookupErr == nil {
					if _, isTun := existing.(*netlink.Tuntap); isTun {
						slog.Info("tunnel anchor already exists as TUN, reusing",
							"name", tc.Name)
						goto anchorReady
					}
					slog.Info("replacing non-TUN tunnel anchor",
						"name", tc.Name, "type", existing.Type())
					_ = m.nlHandle.LinkDel(existing)
					if retryErr := m.nlHandle.LinkAdd(anchor); retryErr != nil {
						slog.Warn("failed to recreate tunnel anchor",
							"name", tc.Name, "err", retryErr)
						continue
					}
				} else {
					slog.Warn("failed to create tunnel anchor",
						"name", tc.Name, "err", err)
					continue
				}
			}
		anchorReady:
			closeTuntapFiles(anchor.Fds)
			if err := m.nlHandle.LinkSetUp(anchor); err != nil {
				slog.Warn("failed to bring up tunnel anchor",
					"name", tc.Name, "err", err)
			}
			for _, addrStr := range tc.Addresses {
				addr, err := netlink.ParseAddr(addrStr)
				if err != nil {
					slog.Warn("invalid tunnel anchor address",
						"name", tc.Name, "addr", addrStr, "err", err)
					continue
				}
				if err := m.nlHandle.AddrAdd(anchor, addr); err != nil {
					slog.Warn("failed to add tunnel anchor address",
						"name", tc.Name, "addr", addrStr, "err", err)
				}
			}
			if tc.RoutingInstance != "" {
				if err := m.BindInterfaceToVRF(tc.Name, tc.RoutingInstance); err != nil {
					slog.Warn("failed to bind tunnel anchor to VRF",
					"name", tc.Name, "vrf", tc.RoutingInstance, "err", err)
				}
			}
			slog.Info("tunnel anchor created", "name", tc.Name, "mode", "tun")
			m.tunnels = append(m.tunnels, tc.Name)
			continue
		}

		localIP := net.ParseIP(tc.Source)
		remoteIP := net.ParseIP(tc.Destination)
		if localIP == nil || remoteIP == nil {
			slog.Warn("invalid tunnel endpoints",
				"name", tc.Name, "src", tc.Source, "dst", tc.Destination)
			continue
		}

		ttl := tc.TTL
		if ttl == 0 {
			ttl = 64
		}

		isIPv6 := localIP.To4() == nil

		var tunnelLink netlink.Link
		switch tc.Mode {
		case "ipip":
			if isIPv6 {
				// IPIP over IPv6: use ip6tnl with IPPROTO_IPIP
				tunnelLink = &netlink.Ip6tnl{
					LinkAttrs: netlink.LinkAttrs{Name: tc.Name},
					Local:     localIP,
					Remote:    remoteIP,
					Ttl:       uint8(ttl),
					Proto:     4, // IPPROTO_IPIP
				}
			} else {
				tunnelLink = &netlink.Iptun{
					LinkAttrs: netlink.LinkAttrs{Name: tc.Name},
					Local:     localIP,
					Remote:    remoteIP,
					Ttl:       uint8(ttl),
				}
			}
		default: // "gre" or ""
			// Gretun.Type() auto-detects IPv6 → returns "ip6gre"
			greLink := &netlink.Gretun{
				LinkAttrs: netlink.LinkAttrs{Name: tc.Name},
				Local:     localIP,
				Remote:    remoteIP,
				Ttl:       uint8(ttl),
			}
			if tc.Key > 0 {
				greLink.IKey = tc.Key
				greLink.OKey = tc.Key
			}
			tunnelLink = greLink
		}

		if err := m.nlHandle.LinkAdd(tunnelLink); err != nil {
			slog.Warn("failed to create tunnel",
				"name", tc.Name, "mode", tc.Mode, "err", err)
			continue
		}

		// IPv6 GRE: disable encaplimit to avoid adding an IPv6
		// Destination Options extension header.  Many transit networks
		// drop IPv6 packets with extension headers (RFC 7872).
		if isIPv6 && (tc.Mode == "gre" || tc.Mode == "") {
			if out, err := exec.Command("ip", "link", "set", tc.Name,
				"type", "ip6gre", "encaplimit", "none").CombinedOutput(); err != nil {
				slog.Warn("failed to set tunnel encaplimit",
					"name", tc.Name, "err", err, "output", string(out))
			}
		}

		if err := m.nlHandle.LinkSetUp(tunnelLink); err != nil {
			slog.Warn("failed to bring up tunnel",
				"name", tc.Name, "err", err)
		}

		// Assign IP addresses
		for _, addrStr := range tc.Addresses {
			addr, err := netlink.ParseAddr(addrStr)
			if err != nil {
				slog.Warn("invalid tunnel address",
					"name", tc.Name, "addr", addrStr, "err", err)
				continue
			}
			if err := m.nlHandle.AddrAdd(tunnelLink, addr); err != nil {
				slog.Warn("failed to add tunnel address",
					"name", tc.Name, "addr", addrStr, "err", err)
			}
		}

		// Bind tunnel to VRF if routing-instance is configured.
		if tc.RoutingInstance != "" {
			if err := m.BindInterfaceToVRF(tc.Name, tc.RoutingInstance); err != nil {
				slog.Warn("failed to bind tunnel to VRF",
					"name", tc.Name, "vrf", tc.RoutingInstance, "err", err)
			}
		}

		slog.Info("tunnel created", "name", tc.Name,
			"src", tc.Source, "dst", tc.Destination)
		m.tunnels = append(m.tunnels, tc.Name)

		// Start keepalive probe if configured
		if tc.Keepalive > 0 {
			m.startKeepalive(tc.Name, tc.Destination, tc.Keepalive, tc.KeepaliveRetry)
		}
	}

	return nil
}

func closeTuntapFiles(files []*os.File) {
	for _, file := range files {
		if file != nil {
			_ = file.Close()
		}
	}
}

// stopAllKeepalives cancels all running keepalive goroutines and
// waits for them to exit. Caller MUST hold ifaceMu.
//
// #848: draining (not just cancelling) is required because
// keepaliveLoop touches m.nlHandle on bring-up/down. Close() then
// closes nlHandle, so any in-flight tick that hadn't yet checked
// ctx.Done() would use-after-close. The done channel makes the
// drain explicit.
func (m *Manager) stopAllKeepalives() {
	runners := m.keepalives
	m.keepalives = make(map[string]*keepaliveRunner)
	for name, runner := range runners {
		runner.cancel()
		<-runner.done
		slog.Debug("stopped keepalive", "tunnel", name)
	}
}

// startKeepalive starts a keepalive probe goroutine for a tunnel.
// Caller MUST hold ifaceMu.
func (m *Manager) startKeepalive(tunnelName, remoteAddr string, interval, maxRetries int) {
	// Stop existing keepalive for this tunnel if any. Drain on done
	// so the replacement doesn't race the old goroutine on m.nlHandle.
	if runner, ok := m.keepalives[tunnelName]; ok {
		runner.cancel()
		<-runner.done
	}

	if maxRetries <= 0 {
		maxRetries = 3
	}

	state := &KeepaliveState{
		Up:         true,
		RemoteAddr: remoteAddr,
		Interval:   interval,
		MaxRetries: maxRetries,
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	m.keepalives[tunnelName] = &keepaliveRunner{
		cancel: cancel,
		state:  state,
		done:   done,
	}

	go m.keepaliveLoop(ctx, done, tunnelName, state)
	slog.Info("started keepalive", "tunnel", tunnelName,
		"remote", remoteAddr, "interval", interval, "retries", maxRetries)
}

// keepaliveLoop runs periodic ICMP probes to the tunnel remote endpoint.
// Closes `done` when it returns so stopAllKeepalives can drain.
func (m *Manager) keepaliveLoop(ctx context.Context, done chan struct{}, tunnelName string, state *KeepaliveState) {
	defer close(done)
	ticker := time.NewTicker(time.Duration(state.Interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ok := probeICMP(state.RemoteAddr)
			state.mu.Lock()
			if ok {
				state.LastSuccess = time.Now()
				if !state.Up {
					slog.Info("tunnel keepalive recovered", "tunnel", tunnelName,
						"remote", state.RemoteAddr)
					state.Up = true
					state.Failures = 0
					// Bring tunnel back up
					if link, err := m.nlHandle.LinkByName(tunnelName); err == nil {
						m.nlHandle.LinkSetUp(link)
					}
				}
				state.Failures = 0
			} else {
				state.Failures++
				state.LastFailure = time.Now()
				if state.Up && state.Failures >= state.MaxRetries {
					slog.Warn("tunnel keepalive failed, marking down",
						"tunnel", tunnelName, "remote", state.RemoteAddr,
						"failures", state.Failures)
					state.Up = false
					// Bring tunnel down
					if link, err := m.nlHandle.LinkByName(tunnelName); err == nil {
						m.nlHandle.LinkSetDown(link)
					}
				}
			}
			state.mu.Unlock()
		}
	}
}

// probeICMP sends a single ICMP echo request and returns true if the host responds.
func probeICMP(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}

	network := "ip4:icmp"
	if ip.To4() == nil {
		network = "ip6:ipv6-icmp"
	}

	conn, err := net.DialTimeout(network, addr, 3*time.Second)
	if err != nil {
		// Fallback: use UDP dial as a reachability check when raw socket
		// is not available (no CAP_NET_RAW). A successful UDP dial only
		// means the route exists, but for keepalive purposes this is
		// close enough. ping utility would be better but adds exec overhead.
		conn2, err2 := net.DialTimeout("udp", net.JoinHostPort(addr, "1"), 3*time.Second)
		if err2 != nil {
			return false
		}
		conn2.Close()
		return true
	}
	conn.Close()
	return true
}

// GetKeepaliveState returns the keepalive state for a tunnel, or nil
// if no keepalive is configured.
//
// #848: ifaceMu protects the keepalives map against concurrent
// startKeepalive / stopAllKeepalives mutations from ApplyTunnels /
// ClearTunnels. The returned *KeepaliveState pointer is safe to
// dereference outside the lock — Go GC keeps the value alive even
// if a subsequent stopAllKeepalives removes it from the map.
func (m *Manager) GetKeepaliveState(tunnelName string) *KeepaliveState {
	m.ifaceMu.Lock()
	defer m.ifaceMu.Unlock()
	runner, ok := m.keepalives[tunnelName]
	if !ok {
		return nil
	}
	return runner.state
}

// ClearTunnels removes all previously created tunnel interfaces.
func (m *Manager) ClearTunnels() error {
	m.ifaceMu.Lock()
	defer m.ifaceMu.Unlock()
	return m.clearTunnelsLocked()
}

// clearTunnelsLocked is the lock-free body of ClearTunnels. Caller
// must hold ifaceMu. Used internally by ApplyTunnels which already
// holds the lock.
func (m *Manager) clearTunnelsLocked() error {
	m.stopAllKeepalives()
	for _, name := range m.tunnels {
		link, err := m.nlHandle.LinkByName(name)
		if err != nil {
			continue // already gone
		}
		if err := m.nlHandle.LinkDel(link); err != nil {
			slog.Warn("failed to delete tunnel", "name", name, "err", err)
		} else {
			slog.Info("tunnel removed", "name", name)
		}
	}
	m.tunnels = nil
	return nil
}

// ApplyXfrmi creates XFRM virtual interfaces for IPsec VPN tunnels.
// Each VPN with a BindInterface (e.g. "st0.0") gets a unit-specific xfrmi
// device and a stable XFRM interface ID derived from the st/unit pair.
func (m *Manager) ApplyXfrmi(vpns map[string]*config.IPsecVPN) error {
	m.ifaceMu.Lock()
	defer m.ifaceMu.Unlock()
	if err := m.clearXfrmiLocked(); err != nil {
		slog.Warn("failed to clear previous xfrmi interfaces", "err", err)
	}

	for _, vpn := range vpns {
		if vpn.BindInterface == "" {
			continue
		}

		ifName, ifID := config.XFRMIfNameAndID(vpn.BindInterface)
		if ifName == "" || ifID == 0 {
			slog.Warn("invalid bind-interface name",
				"vpn", vpn.Name, "bind-interface", vpn.BindInterface)
			continue
		}

		// Check if already exists
		if _, err := m.nlHandle.LinkByName(ifName); err == nil {
			link, _ := m.nlHandle.LinkByName(ifName)
			m.nlHandle.LinkSetUp(link)
			slog.Debug("xfrmi already exists", "name", ifName, "if_id", ifID)
			// Track if not already tracked
			found := false
			for _, x := range m.xfrmis {
				if x == ifName {
					found = true
					break
				}
			}
			if !found {
				m.xfrmis = append(m.xfrmis, ifName)
			}
			continue
		}

		xfrmi := &netlink.Xfrmi{
			LinkAttrs: netlink.LinkAttrs{
				Name: ifName,
			},
			Ifid: ifID,
		}

		if err := m.nlHandle.LinkAdd(xfrmi); err != nil {
			slog.Warn("failed to create xfrmi",
				"name", ifName, "if_id", ifID, "err", err)
			continue
		}

		link, err := m.nlHandle.LinkByName(ifName)
		if err != nil {
			slog.Warn("failed to find xfrmi after creation",
				"name", ifName, "err", err)
			continue
		}

		if err := m.nlHandle.LinkSetUp(link); err != nil {
			slog.Warn("failed to bring up xfrmi",
				"name", ifName, "err", err)
		}

		slog.Info("xfrmi created", "name", ifName, "if_id", ifID, "vpn", vpn.Name)
		m.xfrmis = append(m.xfrmis, ifName)
	}

	return nil
}

// ClearXfrmi removes all previously created xfrmi interfaces.
func (m *Manager) ClearXfrmi() error {
	m.ifaceMu.Lock()
	defer m.ifaceMu.Unlock()
	return m.clearXfrmiLocked()
}

// clearXfrmiLocked is the lock-free body of ClearXfrmi. Caller must
// hold ifaceMu. Used internally by ApplyXfrmi.
func (m *Manager) clearXfrmiLocked() error {
	for _, name := range m.xfrmis {
		link, err := m.nlHandle.LinkByName(name)
		if err != nil {
			continue // already gone
		}
		if err := m.nlHandle.LinkDel(link); err != nil {
			slog.Warn("failed to delete xfrmi", "name", name, "err", err)
		} else {
			slog.Info("xfrmi removed", "name", name)
		}
	}
	m.xfrmis = nil
	return nil
}

// TunnelStatus holds the status of a tunnel interface.
type TunnelStatus struct {
	Name          string
	Source        string
	Destination   string
	State         string // "up" or "down"
	Addresses     []string
	KeepaliveUp   *bool  // nil if no keepalive configured
	KeepaliveInfo string // human-readable keepalive status
}

// GetTunnelStatus returns the status of managed tunnel interfaces.
func (m *Manager) GetTunnelStatus() ([]TunnelStatus, error) {
	// #848: snapshot tunnel names under ifaceMu, then iterate
	// without the lock so a long netlink probe can't block applyConfig.
	m.ifaceMu.Lock()
	names := append([]string(nil), m.tunnels...)
	m.ifaceMu.Unlock()

	var result []TunnelStatus
	for _, name := range names {
		ts := TunnelStatus{Name: name, State: "down"}

		link, err := m.nlHandle.LinkByName(name)
		if err != nil {
			ts.State = "not found"
			result = append(result, ts)
			continue
		}

		if link.Attrs().Flags&net.FlagUp != 0 {
			ts.State = "up"
		}

		switch tun := link.(type) {
		case *netlink.Gretun:
			ts.Source = tun.Local.String()
			ts.Destination = tun.Remote.String()
		case *netlink.Iptun:
			ts.Source = tun.Local.String()
			ts.Destination = tun.Remote.String()
		case *netlink.Ip6tnl:
			ts.Source = tun.Local.String()
			ts.Destination = tun.Remote.String()
		}

		addrs, err := m.nlHandle.AddrList(link, netlink.FAMILY_ALL)
		if err == nil {
			for _, a := range addrs {
				ts.Addresses = append(ts.Addresses, a.IPNet.String())
			}
		}

		// Add keepalive info
		if ks := m.GetKeepaliveState(name); ks != nil {
			ks.mu.Lock()
			up := ks.Up
			ts.KeepaliveUp = &up
			if up {
				ts.KeepaliveInfo = fmt.Sprintf("up (interval %ds, %d retries)",
					ks.Interval, ks.MaxRetries)
			} else {
				ts.KeepaliveInfo = fmt.Sprintf("down (%d consecutive failures)",
					ks.Failures)
			}
			ks.mu.Unlock()
		}

		result = append(result, ts)
	}
	return result, nil
}

// RouteEntry represents a kernel routing table entry.
type RouteEntry struct {
	Destination string
	NextHop     string
	Interface   string
	Protocol    string
	Preference  int
}

// GetRoutes reads the main kernel routing table.
func (m *Manager) GetRoutes() ([]RouteEntry, error) {
	var entries []RouteEntry

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := m.nlHandle.RouteList(nil, family)
		if err != nil {
			continue
		}
		for _, r := range routes {
			entries = append(entries, routeToEntry(m, r, family))
		}
	}

	return entries, nil
}

// protoTag returns a single-letter Junos-style route protocol marker.
func protoTag(proto string) string {
	switch proto {
	case "static":
		return "S"
	case "connected":
		return "C"
	case "bgp":
		return "B"
	case "ospf":
		return "O"
	case "isis":
		return "I"
	case "rip":
		return "R"
	case "dhcp":
		return "D"
	default:
		return "?"
	}
}

// FormatRouteTerse formats routes in Junos "show route terse" style.
func FormatRouteTerse(entries []RouteEntry) string {
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Destination < entries[j].Destination
	})

	var buf strings.Builder
	fmt.Fprintf(&buf, "%-3s %-40s %-4s %-20s %s\n", "A/S", "Destination", "P", "Next-hop", "Interface")
	for _, e := range entries {
		tag := protoTag(e.Protocol)
		marker := "* "
		nh := e.NextHop
		if nh == "" {
			nh = ">"
		}
		fmt.Fprintf(&buf, "%-3s %-40s %-4s %-20s %s\n", marker, e.Destination, tag, nh, e.Interface)
	}
	return buf.String()
}

// GetVRFRoutes reads routes from a VRF's routing table by VRF device name.
func (m *Manager) GetVRFRoutes(vrfName string) ([]RouteEntry, error) {
	// VRF devices are created with "vrf-" prefix (see EnsureVRF).
	devName := vrfName
	if !strings.HasPrefix(devName, "vrf-") {
		devName = "vrf-" + devName
	}
	link, err := m.nlHandle.LinkByName(devName)
	if err != nil {
		return nil, fmt.Errorf("VRF %q not found: %w", vrfName, err)
	}
	vrf, ok := link.(*netlink.Vrf)
	if !ok {
		return nil, fmt.Errorf("%q is not a VRF device", vrfName)
	}
	return m.GetRoutesForTable(int(vrf.Table))
}

// GetTableRoutes returns routes for a Junos-style table name (e.g. "inet.0",
// "inet6.0", "dmz-vr.inet.0", "dmz-vr.inet6.0"). It resolves the VRF and
// filters by address family.
func (m *Manager) GetTableRoutes(tableName string) ([]RouteEntry, error) {
	// Determine VRF name and address family from Junos table name.
	vrfName := ""
	isV6 := false
	switch {
	case tableName == "inet.0":
		// main table, IPv4
	case tableName == "inet6.0":
		isV6 = true
	case strings.HasSuffix(tableName, ".inet6.0"):
		vrfName = strings.TrimSuffix(tableName, ".inet6.0")
		isV6 = true
	case strings.HasSuffix(tableName, ".inet.0"):
		vrfName = strings.TrimSuffix(tableName, ".inet.0")
	default:
		// Treat as VRF name directly (backwards compat).
		vrfName = tableName
	}

	var entries []RouteEntry
	var err error
	if vrfName == "" {
		entries, err = m.GetRoutes()
	} else {
		entries, err = m.GetVRFRoutes(vrfName)
	}
	if err != nil {
		return nil, err
	}

	// Filter by address family.
	var filtered []RouteEntry
	for _, e := range entries {
		entryIsV6 := strings.Contains(e.Destination, ":")
		if entryIsV6 == isV6 {
			filtered = append(filtered, e)
		}
	}
	return filtered, nil
}

// TableRoutes groups routes by their routing table name.
type TableRoutes struct {
	Name    string       // "inet.0", "VRF-name.inet.0", etc.
	Entries []RouteEntry // routes in this table
}

// GetAllTableRoutes returns routes from the main table and all configured VRFs.
// IPv4 and IPv6 routes are split into separate inet.0/inet6.0 tables.
func (m *Manager) GetAllTableRoutes(instances []*config.RoutingInstanceConfig) ([]TableRoutes, error) {
	var tables []TableRoutes

	// Main table
	mainEntries, err := m.GetRoutes()
	if err != nil {
		return nil, err
	}
	tables = appendSplitAF(tables, "", mainEntries)

	// Per-VRF tables
	for _, ri := range instances {
		if ri.TableID == 0 {
			continue
		}
		entries, err := m.GetRoutesForTable(ri.TableID)
		if err != nil {
			continue
		}
		tables = appendSplitAF(tables, ri.Name, entries)
	}
	return tables, nil
}

// appendSplitAF splits routes into inet.0 and inet6.0 tables and appends them.
func appendSplitAF(tables []TableRoutes, prefix string, entries []RouteEntry) []TableRoutes {
	var v4, v6 []RouteEntry
	for _, e := range entries {
		if strings.Contains(e.Destination, ":") {
			v6 = append(v6, e)
		} else {
			v4 = append(v4, e)
		}
	}
	inetName := "inet.0"
	inet6Name := "inet6.0"
	if prefix != "" {
		inetName = prefix + "." + inetName
		inet6Name = prefix + "." + inet6Name
	}
	if len(v4) > 0 {
		tables = append(tables, TableRoutes{Name: inetName, Entries: v4})
	}
	if len(v6) > 0 {
		tables = append(tables, TableRoutes{Name: inet6Name, Entries: v6})
	}
	return tables
}

// FormatRouteDestination formats matching routes across all tables in Junos style.
// The destination is an IP address (or CIDR prefix). For each table that has a
// matching route, it prints a Junos-style header and route entries.
// The modifier controls matching behavior:
//   - "" (empty): default LPM — show routes whose prefix contains the destination
//   - "exact": only show routes matching the exact prefix (network + mask)
//   - "longer": show routes with a strictly more-specific prefix (longer mask)
//   - "orlonger": show routes with equal or more-specific prefix (equal or longer mask)
func FormatRouteDestination(allTables []TableRoutes, destination, modifier string) string {
	// Parse the destination for matching.
	destIP := net.ParseIP(destination)
	var destNet *net.IPNet
	if strings.Contains(destination, "/") {
		_, destNet, _ = net.ParseCIDR(destination)
	} else if destIP != nil {
		if destIP.To4() != nil {
			destNet = &net.IPNet{IP: destIP, Mask: net.CIDRMask(32, 32)}
		} else {
			destNet = &net.IPNet{IP: destIP, Mask: net.CIDRMask(128, 128)}
		}
	}
	if destNet == nil {
		return fmt.Sprintf("invalid destination: %s\n", destination)
	}
	destOnes, destBits := destNet.Mask.Size()

	var buf strings.Builder
	for _, table := range allTables {
		var matches []RouteEntry
		for _, e := range table.Entries {
			_, routeNet, err := net.ParseCIDR(e.Destination)
			if err != nil {
				continue
			}
			routeOnes, _ := routeNet.Mask.Size()

			switch modifier {
			case "exact":
				// Route must match the exact prefix (network + mask length).
				if routeOnes == destOnes && destNet.IP.Equal(routeNet.IP) {
					matches = append(matches, e)
				}
			case "longer":
				// Route must be strictly more-specific (contained within dest, longer mask).
				if routeOnes > destOnes && destNet.Contains(routeNet.IP) {
					matches = append(matches, e)
				}
			case "orlonger":
				// Route must be equal or more-specific (contained within dest, equal or longer mask).
				if routeOnes >= destOnes && destNet.Contains(routeNet.IP) {
					matches = append(matches, e)
				}
			default:
				// Default LPM behavior: show routes whose prefix contains the
				// destination. For a CIDR input, match routes that contain the
				// requested network (route prefix contains dest IP AND route mask
				// is equal or shorter).
				if destBits > 0 && routeOnes <= destOnes && routeNet.Contains(destNet.IP) {
					matches = append(matches, e)
				}
			}
		}
		if len(matches) == 0 {
			continue
		}

		// Sort by prefix length (longest first), then by preference.
		sort.Slice(matches, func(i, j int) bool {
			_, ni, _ := net.ParseCIDR(matches[i].Destination)
			_, nj, _ := net.ParseCIDR(matches[j].Destination)
			oi, _ := ni.Mask.Size()
			oj, _ := nj.Mask.Size()
			if oi != oj {
				return oi > oj
			}
			return matches[i].Preference < matches[j].Preference
		})

		formatTableJunos(&buf, table.Name, len(table.Entries), matches)
	}

	if buf.Len() == 0 {
		return fmt.Sprintf("no routes matching %s\n", destination)
	}
	return buf.String()
}

// FormatRouteSummary formats a Junos-style route summary across all tables.
// Output matches Junos: right-aligned protocol names, right-aligned counts,
// separate inet.0/inet6.0 sections per table, plus Highwater Mark section.
func FormatRouteSummary(allTables []TableRoutes, routerID string) string {
	var buf strings.Builder
	if routerID != "" {
		fmt.Fprintf(&buf, "Router ID: %s\n", routerID)
	}

	totalRoutes := 0
	totalFIB := 0
	for _, table := range allTables {
		if len(table.Entries) == 0 {
			continue
		}
		byProto := make(map[string]int)
		for _, e := range table.Entries {
			byProto[junosProtoName(e.Protocol)]++
		}
		fmt.Fprintf(&buf, "\n%s: %d destinations, %d routes (%d active, 0 holddown, 0 hidden)\n",
			table.Name, len(table.Entries), len(table.Entries), len(table.Entries))
		formatSummaryProtos(&buf, byProto)
		totalRoutes += len(table.Entries)
		totalFIB += len(table.Entries)
	}

	// Highwater Mark section — since we don't track historical peaks,
	// report current counts as the highwater mark.
	if totalRoutes > 0 {
		buf.WriteString("\nHighwater Mark:\n")
		fmt.Fprintf(&buf, "  %d routes, %d FIB (currently active)\n", totalRoutes, totalFIB)
	}

	return buf.String()
}

// formatSummaryProtos writes sorted protocol summary lines in Junos format.
func formatSummaryProtos(buf *strings.Builder, byProto map[string]int) {
	protos := make([]string, 0, len(byProto))
	for p := range byProto {
		protos = append(protos, p)
	}
	sort.Strings(protos)
	for _, p := range protos {
		fmt.Fprintf(buf, "%21s%7d routes,%7d active\n", p+":", byProto[p], byProto[p])
	}
}

// FormatAllRoutes formats all routes across all tables in Junos style.
func FormatAllRoutes(allTables []TableRoutes) string {
	var buf strings.Builder
	for _, table := range allTables {
		if len(table.Entries) == 0 {
			continue
		}
		// Sort: by destination prefix, then preference.
		sorted := make([]RouteEntry, len(table.Entries))
		copy(sorted, table.Entries)
		sort.Slice(sorted, func(i, j int) bool {
			if sorted[i].Destination != sorted[j].Destination {
				return sorted[i].Destination < sorted[j].Destination
			}
			return sorted[i].Preference < sorted[j].Preference
		})
		formatTableJunos(&buf, table.Name, len(table.Entries), sorted)
	}
	if buf.Len() == 0 {
		return "no routes\n"
	}
	return buf.String()
}

// formatTableJunos writes a Junos-style routing table section.
func formatTableJunos(buf *strings.Builder, tableName string, totalDests int, entries []RouteEntry) {
	fmt.Fprintf(buf, "\n%s: %d destinations, %d routes (%d active, 0 holddown, 0 hidden)\n",
		tableName, totalDests, totalDests, totalDests)
	buf.WriteString("+ = Active Route, - = Last Active, * = Both\n\n")

	for _, e := range entries {
		proto := junosProtoName(e.Protocol)
		dest := e.Destination
		// Pad short destinations, let long ones flow naturally.
		if len(dest) < 19 {
			dest = fmt.Sprintf("%-19s", dest)
		}
		fmt.Fprintf(buf, "%s *[%s/%d]\n", dest, proto, e.Preference)
		if e.NextHop != "" && e.NextHop != "direct" {
			fmt.Fprintf(buf, "                    >  to %s via %s\n", e.NextHop, e.Interface)
		} else if e.Interface != "" {
			fmt.Fprintf(buf, "                    >  via %s\n", e.Interface)
		}
	}
}

// junosProtoName maps protocol names to Junos-style names.
func junosProtoName(proto string) string {
	switch proto {
	case "static":
		return "Static"
	case "connected":
		return "Direct"
	case "bgp":
		return "BGP"
	case "ospf":
		return "OSPF"
	case "isis":
		return "IS-IS"
	case "rip":
		return "RIP"
	case "dhcp":
		return "Access-internal"
	case "redirect":
		return "Redirect"
	default:
		return proto
	}
}

func rtProtoName(p netlink.RouteProtocol) string {
	pi := int(p)
	switch pi {
	case unix.RTPROT_REDIRECT:
		return "redirect"
	case unix.RTPROT_KERNEL:
		return "connected"
	case unix.RTPROT_BOOT:
		return "dhcp"
	case unix.RTPROT_STATIC:
		return "static"
	case 16: // RTPROT_DHCP
		return "dhcp"
	case 11:
		return "ospf"
	case 12:
		return "isis"
	case 186:
		return "bgp"
	case 188:
		return "ospf"
	case 189:
		return "rip"
	case 196:
		return "static" // RTPROT_ZEBRA — FRR staticd-installed routes
	default:
		return strconv.Itoa(pi)
	}
}

// nextTableRulePriority is the base priority for next-table ip rules.
// Lower values = higher priority. We use 100-199 range for next-table rules.
const nextTableRulePriority = 100

// ribGroupRulePriority is the base priority for rib-group ip rules.
// Must be AFTER the main table (32766) so VRF routes supplement rather
// than override main table routing. We use 33000-33099 range.
const ribGroupRulePriority = 33000

// ApplyNextTableRules creates Linux policy routing rules (ip rule) for
// static routes with next-table directives. This implements inter-VRF
// route leaking: "route X/Y next-table Instance.inet.0" means traffic
// to X/Y should be looked up in Instance's routing table.
func (m *Manager) ApplyNextTableRules(routes []*config.StaticRoute, instances []*config.RoutingInstanceConfig) error {
	// Build instance name → table ID map
	tableIDs := make(map[string]int)
	for _, inst := range instances {
		tableIDs[inst.Name] = inst.TableID
	}

	// Clean up old next-table rules (priority range 100-199)
	if err := m.clearNextTableRules(); err != nil {
		slog.Warn("failed to clear old next-table rules", "err", err)
	}

	prio := nextTableRulePriority
	for _, sr := range routes {
		if sr.NextTable == "" {
			continue
		}
		tableID, ok := tableIDs[sr.NextTable]
		if !ok {
			slog.Warn("next-table references unknown routing instance",
				"destination", sr.Destination, "instance", sr.NextTable)
			continue
		}

		_, dst, err := net.ParseCIDR(sr.Destination)
		if err != nil {
			slog.Warn("invalid next-table destination", "destination", sr.Destination, "err", err)
			continue
		}

		family := unix.AF_INET
		if dst.IP.To4() == nil {
			family = unix.AF_INET6
		}

		rule := netlink.NewRule()
		rule.Dst = dst
		rule.Table = tableID
		rule.Priority = prio
		rule.Family = family

		if err := m.nlHandle.RuleAdd(rule); err != nil {
			slog.Warn("failed to add next-table rule",
				"destination", sr.Destination, "instance", sr.NextTable,
				"table", tableID, "err", err)
			continue
		}
		slog.Info("next-table rule added",
			"destination", sr.Destination, "instance", sr.NextTable, "table", tableID)
		prio++
	}
	return nil
}

// clearNextTableRules removes all ip rules in the next-table priority range.
func (m *Manager) clearNextTableRules() error {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := m.nlHandle.RuleList(family)
		if err != nil {
			continue
		}
		for _, r := range rules {
			if r.Priority >= nextTableRulePriority && r.Priority < nextTableRulePriority+100 {
				if err := m.nlHandle.RuleDel(&r); err != nil {
					slog.Debug("failed to delete stale next-table rule",
						"priority", r.Priority, "err", err)
				}
			}
		}
	}
	return nil
}

// ApplyRibGroupRules creates Linux policy routing rules (ip rule) for
// rib-group route leaking. When a routing instance has interface-routes
// with a rib-group reference, the instance's routes are leaked to other
// tables listed in the rib-group's import-rib list.
//
// Both IPv4 (InterfaceRoutesRibGroup) and IPv6 (InterfaceRoutesRibGroupV6)
// rib-groups are handled. For each source table that needs leaking, both
// IPv4 and IPv6 ip rules are created.
//
// For example, if dmz-vr (table 101) has interface-routes rib-group "dmz-leak",
// and dmz-leak has import-rib [ dmz-vr.inet.0 inet.0 ], then an ip rule is
// created to make table 101 visible to main table lookups:
//
//	ip rule add from all lookup 101 pref 33000
func (m *Manager) ApplyRibGroupRules(ribGroups map[string]*config.RibGroup, instances []*config.RoutingInstanceConfig) error {
	// Clean up old rib-group rules
	if err := m.clearRibGroupRules(); err != nil {
		slog.Warn("failed to clear old rib-group rules", "err", err)
	}

	if len(ribGroups) == 0 || len(instances) == 0 {
		return nil
	}

	// Build instance name → table ID map
	tableIDs := make(map[string]int)
	for _, inst := range instances {
		tableIDs[inst.Name] = inst.TableID
	}

	// Track which source tables we've already added rules for
	// (avoid duplicate rules if multiple rib-groups reference the same table)
	leakedTables := make(map[int]bool)

	prio := ribGroupRulePriority
	for _, inst := range instances {
		// Collect all rib-group names referenced by this instance (inet + inet6)
		rgNames := []string{inst.InterfaceRoutesRibGroup, inst.InterfaceRoutesRibGroupV6}

		sourceTable := inst.TableID
		needsLeak := false
		for _, rgName := range rgNames {
			if rgName == "" {
				continue
			}
			rg, ok := ribGroups[rgName]
			if !ok {
				slog.Warn("interface-routes references unknown rib-group",
					"instance", inst.Name, "rib-group", rgName)
				continue
			}
			for _, ribName := range rg.ImportRibs {
				targetTable := resolveRibTable(ribName, tableIDs)
				if targetTable != sourceTable {
					needsLeak = true
					break
				}
			}
			if needsLeak {
				break
			}
		}
		if !needsLeak {
			continue
		}

		if leakedTables[sourceTable] {
			continue
		}
		leakedTables[sourceTable] = true

		// Add IPv4 rule
		rule := netlink.NewRule()
		rule.Table = sourceTable
		rule.Priority = prio
		rule.Family = unix.AF_INET

		if err := m.nlHandle.RuleAdd(rule); err != nil {
			slog.Warn("failed to add rib-group IPv4 rule",
				"instance", inst.Name, "table", sourceTable, "err", err)
		} else {
			slog.Info("rib-group rule added",
				"instance", inst.Name, "table", sourceTable,
				"family", "inet", "pref", prio)
		}
		prio++

		// Add IPv6 rule
		rule6 := netlink.NewRule()
		rule6.Table = sourceTable
		rule6.Priority = prio
		rule6.Family = unix.AF_INET6

		if err := m.nlHandle.RuleAdd(rule6); err != nil {
			slog.Warn("failed to add rib-group IPv6 rule",
				"instance", inst.Name, "table", sourceTable, "err", err)
		} else {
			slog.Info("rib-group rule added",
				"instance", inst.Name, "table", sourceTable,
				"family", "inet6", "pref", prio)
		}
		prio++
	}
	return nil
}

// clearRibGroupRules removes all ip rules in the rib-group priority range.
// Also cleans up legacy rules from the old 200-299 range.
func (m *Manager) clearRibGroupRules() error {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := m.nlHandle.RuleList(family)
		if err != nil {
			continue
		}
		for _, r := range rules {
			inCurrent := r.Priority >= ribGroupRulePriority && r.Priority < ribGroupRulePriority+100
			inLegacy := r.Priority >= 200 && r.Priority < 300
			if inCurrent || inLegacy {
				if err := m.nlHandle.RuleDel(&r); err != nil {
					slog.Debug("failed to delete stale rib-group rule",
						"priority", r.Priority, "err", err)
				}
			}
		}
	}
	return nil
}

// pbrRulePriority is the base priority for policy-based routing ip rules.
// BEFORE the main table (32766) so the kernel also honors PBR for XDP_PASS'd
// packets (e.g. SNAT'd traffic destined for a VRF/GRE tunnel).
// We use 31000-31999 range.
const pbrRulePriority = 31000

// PBRRule describes a single policy-based routing rule derived from a
// firewall filter term with a routing-instance action.
type PBRRule struct {
	Family   int    // unix.AF_INET or unix.AF_INET6
	TOS      uint8  // TOS byte (DSCP << 2), 0 = no TOS match
	Src      string // source CIDR, "" = any
	Dst      string // destination CIDR, "" = any
	TableID  int    // target routing table
	Instance string // routing instance name (for logging)
}

// ApplyPBRRules creates Linux policy routing rules (ip rule) for firewall
// filter terms that use a routing-instance action. This implements
// policy-based routing: traffic matching DSCP/source/destination criteria
// is routed via the specified VRF's routing table.
func (m *Manager) ApplyPBRRules(rules []PBRRule) error {
	// Clean up old PBR rules first
	if err := m.clearPBRRules(); err != nil {
		slog.Warn("failed to clear old PBR rules", "err", err)
	}

	if len(rules) == 0 {
		return nil
	}

	prio := pbrRulePriority
	for _, pbr := range rules {
		rule := netlink.NewRule()
		rule.Table = pbr.TableID
		rule.Priority = prio
		rule.Family = pbr.Family

		if pbr.TOS != 0 {
			rule.Tos = uint(pbr.TOS)
		}
		if pbr.Src != "" {
			_, src, err := net.ParseCIDR(pbr.Src)
			if err != nil {
				slog.Warn("invalid PBR source", "src", pbr.Src, "err", err)
				continue
			}
			rule.Src = src
		}
		if pbr.Dst != "" {
			_, dst, err := net.ParseCIDR(pbr.Dst)
			if err != nil {
				slog.Warn("invalid PBR destination", "dst", pbr.Dst, "err", err)
				continue
			}
			rule.Dst = dst
		}

		if err := m.nlHandle.RuleAdd(rule); err != nil {
			slog.Warn("failed to add PBR rule",
				"instance", pbr.Instance, "tos", pbr.TOS,
				"src", pbr.Src, "dst", pbr.Dst,
				"table", pbr.TableID, "err", err)
			continue
		}
		slog.Info("PBR rule added",
			"instance", pbr.Instance, "tos", pbr.TOS,
			"src", pbr.Src, "dst", pbr.Dst, "table", pbr.TableID)
		prio++
		if prio >= pbrRulePriority+1000 {
			slog.Warn("PBR rule limit reached")
			break
		}
	}
	return nil
}

// clearPBRRules removes all ip rules in the PBR priority range.
func (m *Manager) clearPBRRules() error {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := m.nlHandle.RuleList(family)
		if err != nil {
			continue
		}
		for _, r := range rules {
			if r.Priority >= pbrRulePriority && r.Priority < pbrRulePriority+1000 {
				if err := m.nlHandle.RuleDel(&r); err != nil {
					slog.Debug("failed to delete stale PBR rule",
						"priority", r.Priority, "err", err)
				}
			}
		}
	}
	return nil
}

// BuildPBRRules extracts policy-based routing rules from firewall filter
// configuration. Each filter term with a routing-instance action produces
// one or more PBR rules depending on the match criteria.
func BuildPBRRules(fw *config.FirewallConfig, instances []*config.RoutingInstanceConfig) []PBRRule {
	if fw == nil {
		return nil
	}

	// Build instance name → table ID map
	tableIDs := make(map[string]int)
	for _, inst := range instances {
		tableIDs[inst.Name] = inst.TableID
	}

	var rules []PBRRule
	// Process inet filters
	for _, filter := range fw.FiltersInet {
		rules = append(rules, buildPBRFromFilter(filter, unix.AF_INET, tableIDs)...)
	}
	// Process inet6 filters
	for _, filter := range fw.FiltersInet6 {
		rules = append(rules, buildPBRFromFilter(filter, unix.AF_INET6, tableIDs)...)
	}
	return rules
}

// buildPBRFromFilter extracts PBR rules from a single firewall filter.
func buildPBRFromFilter(filter *config.FirewallFilter, family int, tableIDs map[string]int) []PBRRule {
	var rules []PBRRule
	for _, term := range filter.Terms {
		if term.RoutingInstance == "" {
			continue
		}
		tableID, ok := tableIDs[term.RoutingInstance]
		if !ok {
			slog.Warn("PBR: routing-instance not found",
				"filter", filter.Name, "term", term.Name,
				"instance", term.RoutingInstance)
			continue
		}

		// Determine TOS byte from DSCP value
		var tos uint8
		if term.DSCP != "" {
			tos = dscpToTOS(term.DSCP)
		}

		// If the term has source/dest addresses, create a rule per address.
		// If it has neither addresses nor DSCP, we can't express it as ip rule.
		srcs := term.SourceAddresses
		dsts := term.DestAddresses
		if len(srcs) == 0 {
			srcs = []string{""}
		}
		if len(dsts) == 0 {
			dsts = []string{""}
		}

		// Check if we have anything ip rule can match on
		hasCriteria := tos != 0 || term.SourceAddresses != nil || term.DestAddresses != nil
		if !hasCriteria {
			slog.Warn("PBR: filter term has routing-instance but no ip-rule-compatible criteria (dscp, source-address, destination-address)",
				"filter", filter.Name, "term", term.Name)
			continue
		}

		for _, src := range srcs {
			for _, dst := range dsts {
				rules = append(rules, PBRRule{
					Family:   family,
					TOS:      tos,
					Src:      src,
					Dst:      dst,
					TableID:  tableID,
					Instance: term.RoutingInstance,
				})
			}
		}
	}
	return rules
}

// dscpToTOS converts a DSCP name or numeric value to a TOS byte.
// TOS byte = DSCP value << 2 (DSCP occupies the upper 6 bits of the TOS byte).
func dscpToTOS(dscp string) uint8 {
	// DSCP name → numeric value mapping (same values as dataplane.DSCPValues)
	dscpValues := map[string]uint8{
		"ef":   46,
		"af11": 10, "af12": 12, "af13": 14,
		"af21": 18, "af22": 20, "af23": 22,
		"af31": 26, "af32": 28, "af33": 30,
		"af41": 34, "af42": 36, "af43": 38,
		"cs0": 0, "cs1": 8, "cs2": 16, "cs3": 24,
		"cs4": 32, "cs5": 40, "cs6": 48, "cs7": 56,
		"be": 0,
	}

	name := strings.ToLower(dscp)
	if val, ok := dscpValues[name]; ok {
		return val << 2
	}
	if v, err := strconv.Atoi(dscp); err == nil && v >= 0 && v <= 63 {
		return uint8(v) << 2
	}
	return 0
}

// "<instance>.inet.0" or "<instance>.inet6.0" maps to the instance's table.
func resolveRibTable(ribName string, tableIDs map[string]int) int {
	if ribName == "inet.0" || ribName == "inet6.0" {
		return 254 // main table
	}
	// Parse "instance-name.inet.0" or "instance-name.inet6.0"
	if idx := strings.Index(ribName, ".inet"); idx > 0 {
		instanceName := ribName[:idx]
		if tableID, ok := tableIDs[instanceName]; ok {
			return tableID
		}
	}
	return 0
}

// ApplyBonds creates Linux bond devices for interfaces with fabric-options
// member-interfaces configured. Uses the bond mode from InterfaceConfig.BondMode
// (active-backup for fabric bonds, 802.3ad for ae interfaces).
func (m *Manager) ApplyBonds(interfaces []*config.InterfaceConfig) error {
	m.ifaceMu.Lock()
	defer m.ifaceMu.Unlock()
	if err := m.clearBondsLocked(); err != nil {
		slog.Warn("failed to clear previous bonds", "err", err)
	}

	for _, ifc := range interfaces {
		if len(ifc.FabricMembers) == 0 {
			continue
		}
		// vSRX fabric-options mode: single local member resolved via .link
		// rename — no bond needed.
		if ifc.LocalFabricMember != "" {
			continue
		}
		bondName := ifc.Name

		// Check if bond already exists
		if existing, err := m.nlHandle.LinkByName(bondName); err == nil {
			// Already exists — ensure it's up and skip creation
			m.nlHandle.LinkSetUp(existing)
			m.bonds = append(m.bonds, bondName)
			slog.Debug("bond already exists", "name", bondName)
			continue
		}

		bond := netlink.NewLinkBond(netlink.LinkAttrs{Name: bondName})
		switch ifc.BondMode {
		case "active-backup":
			bond.Mode = netlink.BOND_MODE_ACTIVE_BACKUP
		default:
			bond.Mode = netlink.BOND_MODE_802_3AD
		}
		if ifc.MTU > 0 {
			bond.LinkAttrs.MTU = ifc.MTU
		}
		if err := m.nlHandle.LinkAdd(bond); err != nil {
			slog.Warn("failed to create bond", "name", bondName, "err", err)
			continue
		}

		// Enslave member interfaces
		bondLink, err := m.nlHandle.LinkByName(bondName)
		if err != nil {
			slog.Warn("failed to find created bond", "name", bondName, "err", err)
			continue
		}
		for _, member := range ifc.FabricMembers {
			linuxName := config.LinuxIfName(member)
			memberLink, err := m.nlHandle.LinkByName(linuxName)
			if err != nil {
				slog.Warn("bond member not found",
					"bond", bondName, "member", member, "linux", linuxName, "err", err)
				continue
			}
			// Member must be down before enslaving
			m.nlHandle.LinkSetDown(memberLink)
			if err := m.nlHandle.LinkSetMaster(memberLink, bondLink); err != nil {
				slog.Warn("failed to enslave member",
					"bond", bondName, "member", member, "err", err)
				continue
			}
			m.nlHandle.LinkSetUp(memberLink)
			slog.Info("bond member added", "bond", bondName, "member", member)
		}

		if err := m.nlHandle.LinkSetUp(bondLink); err != nil {
			slog.Warn("failed to bring up bond", "name", bondName, "err", err)
		}
		m.bonds = append(m.bonds, bondName)
		modeStr := "802.3ad"
		if ifc.BondMode == "active-backup" {
			modeStr = "active-backup"
		}
		slog.Info("bond created", "name", bondName,
			"mode", modeStr, "members", ifc.FabricMembers)
	}
	return nil
}

// ClearBonds removes all previously created bond devices.
func (m *Manager) ClearBonds() error {
	m.ifaceMu.Lock()
	defer m.ifaceMu.Unlock()
	return m.clearBondsLocked()
}

// clearBondsLocked is the lock-free body of ClearBonds. Caller must
// hold ifaceMu. Used internally by ApplyBonds.
func (m *Manager) clearBondsLocked() error {
	for _, name := range m.bonds {
		link, err := m.nlHandle.LinkByName(name)
		if err != nil {
			continue // already gone
		}
		if err := m.nlHandle.LinkDel(link); err != nil {
			slog.Warn("failed to delete bond", "name", name, "err", err)
		} else {
			slog.Info("bond removed", "name", name)
		}
	}
	m.bonds = nil
	return nil
}

// ApplyRethInterfaces is a no-op. RETH bonds are no longer created;
// VRRP runs directly on physical member interfaces.
func (m *Manager) ApplyRethInterfaces(interfaces map[string]*config.InterfaceConfig) error {
	return nil
}

// ClearRethInterfaces removes all RETH bond devices from the system.
// It scans for any existing reth* bond devices (including stale ones from
// previous binary versions) and deletes them.
func (m *Manager) ClearRethInterfaces() error {
	// Scan all links for reth* bond devices left from previous deploys.
	links, err := m.nlHandle.LinkList()
	if err != nil {
		return fmt.Errorf("listing links: %w", err)
	}
	for _, link := range links {
		name := link.Attrs().Name
		if !strings.HasPrefix(name, "reth") {
			continue
		}
		if _, ok := link.(*netlink.Bond); !ok {
			continue // not a bond device
		}
		if err := m.nlHandle.LinkDel(link); err != nil {
			slog.Warn("failed to delete RETH bond", "name", name, "err", err)
		} else {
			slog.Info("RETH bond removed", "name", name)
		}
	}
	return nil
}

// RethNames returns the names of currently managed RETH interfaces.
// Returns empty since RETH bonds are no longer created.
func (m *Manager) RethNames() []string {
	return nil
}

// ApplyInterfaceMonitors checks link state for monitored interfaces in each
// redundancy group and stores the results for display.
func (m *Manager) ApplyInterfaceMonitors(groups []*config.RedundancyGroup) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.monitorStatus = make(map[int][]InterfaceMonitorStatus)
	for _, rg := range groups {
		var statuses []InterfaceMonitorStatus
		for _, mon := range rg.InterfaceMonitors {
			// Translate Junos name (ge-0/0/0) to Linux name (ge-0-0-0).
			linuxName := config.LinuxIfName(mon.Interface)
			link, err := m.nlHandle.LinkByName(linuxName)
			if err != nil {
				// Interface doesn't exist — belongs to peer node. Skip.
				continue
			}
			up := link.Attrs().OperState == netlink.OperUp ||
				link.Attrs().Flags&net.FlagUp != 0
			statuses = append(statuses, InterfaceMonitorStatus{
				Interface: mon.Interface,
				Weight:    mon.Weight,
				Up:        up,
			})
			if !up {
				slog.Warn("interface monitor: link down",
					"redundancy_group", rg.ID,
					"interface", mon.Interface,
					"weight", mon.Weight)
			}
		}
		if len(statuses) > 0 {
			m.monitorStatus[rg.ID] = statuses
		}
	}
}

// InterfaceMonitorStatuses returns the current monitor state for all
// redundancy groups. Returns nil if no monitors are configured.
func (m *Manager) InterfaceMonitorStatuses() map[int][]InterfaceMonitorStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.monitorStatus) == 0 {
		return nil
	}
	// Return a copy
	result := make(map[int][]InterfaceMonitorStatus, len(m.monitorStatus))
	for k, v := range m.monitorStatus {
		cp := make([]InterfaceMonitorStatus, len(v))
		copy(cp, v)
		result[k] = cp
	}
	return result
}
