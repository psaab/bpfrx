// Package routing manages static routes, GRE/IPIP tunnels, VRFs, XFRM
// interfaces, policy-based / rib-group / next-table route leaking, bonds,
// RETH cleanup, and interface-monitor status via netlink.
//
// The package is organised as a thin façade (*Manager) over a set of
// unexported per-domain managers, each owning its own sub-state and lock
// and depending on a narrow netlink-facing ops interface (see #1698):
//
//   - vrfManager       (vrf.go)        — VRF lifecycle + interface binding
//   - routeReader      (routes.go)     — kernel routing-table reads
//   - tunnelManager    (tunnel.go)     — GRE/IPIP tunnels + keepalive
//   - xfrmManager      (xfrm.go)       — XFRM/IPsec interface lifecycle
//   - nextTableManager,
//     ribGroupManager,
//     pbrManager       (rules.go)      — policy-routing ip-rule reconcilers
//   - probePinManager  (probe_pin.go)  — RPM probe next-hop pin reconciler (#1827)
//   - bondManager      (bond.go)       — bond device lifecycle
//   - rethManager      (reth.go)       — stale RETH bond cleanup
//   - monitorManager   (monitor.go)    — interface-monitor HA signal
//
// Manager is the sole owner of the *netlink.Handle; the domain managers
// borrow it (or a narrow interface over it) and never close it. Every
// public method below is a delegation to the owning domain, preserving
// the historical API surface byte-for-byte.
package routing

import (
	"fmt"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// Manager is a façade over the routing domain managers. It owns the
// shared netlink handle and delegates each public method to the domain
// that owns the corresponding state.
type Manager struct {
	nlHandle *netlink.Handle // sole owner; closed exactly once in Close()

	vrf      *vrfManager
	routes   *routeReader
	tunnel   *tunnelManager
	xfrm     *xfrmManager
	nextTbl  *nextTableManager
	ribGroup *ribGroupManager
	pbr      *pbrManager
	probePin *probePinManager
	bond     *bondManager
	reth     *rethManager
	monitor  *monitorManager
}

// New creates a new routing Manager and its domain managers.
func New() (*Manager, error) {
	h, err := netlink.NewHandle()
	if err != nil {
		return nil, fmt.Errorf("netlink handle: %w", err)
	}
	m := &Manager{nlHandle: h}
	m.vrf = &vrfManager{ops: h}
	m.routes = &routeReader{ops: h}
	// tunnel depends on vrf for BindInterfaceToVRF (no lock-ordering
	// cycle: BindInterfaceToVRF takes no lock); vrf is constructed first.
	m.tunnel = &tunnelManager{ops: h, vrfBinder: m.vrf, keepalives: make(map[string]*keepaliveRunner)}
	m.xfrm = &xfrmManager{ops: h}
	m.nextTbl = &nextTableManager{ops: h}
	m.ribGroup = &ribGroupManager{ops: h}
	m.pbr = &pbrManager{ops: h}
	m.probePin = &probePinManager{ops: h}
	m.bond = &bondManager{ops: h}
	m.reth = &rethManager{ops: h} // Clear is live (LinkList/LinkDel)
	m.monitor = &monitorManager{ops: h, monitorStatus: make(map[int][]InterfaceMonitorStatus)}
	return m, nil
}

// Close releases the netlink handle and stops all keepalive probes.
//
// Close is not safe to call concurrently with the public apply/read
// methods (the same single-threaded-shutdown contract that held before
// the domain split; there is no daemon caller of Close today). It drains
// keepalive goroutines via tunnel.stopAll() BEFORE closing the handle so
// no in-flight keepalive tick can use-after-close the handle (#848).
func (m *Manager) Close() error {
	m.tunnel.stopAll()
	if m.nlHandle != nil {
		m.nlHandle.Close()
	}
	return nil
}

// --- VRF domain ---

// CreateVRF creates a Linux VRF device and assigns it a routing table.
// Prefer ReconcileVRFs for multi-VRF config apply; CreateVRF is retained
// for callers that need single-VRF semantics.
func (m *Manager) CreateVRF(name string, tableID int) error {
	return m.vrf.Create(name, tableID)
}

// IsManagedVRF reports whether the given logical VRF name is currently
// in the manager's tracked set.
func (m *Manager) IsManagedVRF(name string) bool { return m.vrf.IsManaged(name) }

// ReconcileVRFs brings the manager's owned-VRF set to match desired.
// See vrfManager.Reconcile for the full ownership contract.
func (m *Manager) ReconcileVRFs(desired []VRFSpec) error { return m.vrf.Reconcile(desired) }

// BindInterfaceToVRF binds a network interface to a VRF device.
func (m *Manager) BindInterfaceToVRF(ifaceName, instanceName string) error {
	return m.vrf.BindInterfaceToVRF(ifaceName, instanceName)
}

// --- Route reads ---

// GetRoutesForTable reads routes from a specific kernel routing table.
func (m *Manager) GetRoutesForTable(tableID int) ([]RouteEntry, error) {
	return m.routes.GetRoutesForTable(tableID)
}

// GetRoutes reads the main kernel routing table.
func (m *Manager) GetRoutes() ([]RouteEntry, error) { return m.routes.GetRoutes() }

// GetVRFRoutes reads routes from a VRF's routing table by VRF device name.
func (m *Manager) GetVRFRoutes(vrfName string) ([]RouteEntry, error) {
	return m.routes.GetVRFRoutes(vrfName)
}

// GetTableRoutes returns routes for a Junos-style table name.
func (m *Manager) GetTableRoutes(tableName string) ([]RouteEntry, error) {
	return m.routes.GetTableRoutes(tableName)
}

// GetAllTableRoutes returns routes from the main table and all configured VRFs.
func (m *Manager) GetAllTableRoutes(instances []*config.RoutingInstanceConfig) ([]TableRoutes, error) {
	return m.routes.GetAllTableRoutes(instances)
}

// --- Tunnel domain ---

// ApplyTunnels creates GRE tunnel interfaces, brings them up, and assigns
// addresses. Previous tunnels are removed first. Starts keepalive probes
// for tunnels that have keepalive configured.
func (m *Manager) ApplyTunnels(tunnels []*config.TunnelConfig) error {
	return m.tunnel.Apply(tunnels)
}

// ClearTunnels removes all previously created tunnel interfaces.
func (m *Manager) ClearTunnels() error { return m.tunnel.Clear() }

// GetTunnelStatus returns the status of managed tunnel interfaces.
func (m *Manager) GetTunnelStatus() ([]TunnelStatus, error) { return m.tunnel.GetStatus() }

// GetKeepaliveState returns the keepalive state for a tunnel, or nil if
// no keepalive is configured.
func (m *Manager) GetKeepaliveState(tunnelName string) *KeepaliveState {
	return m.tunnel.GetKeepaliveState(tunnelName)
}

// --- XFRM domain ---

// ApplyXfrmi creates XFRM virtual interfaces for IPsec VPN tunnels.
func (m *Manager) ApplyXfrmi(vpns map[string]*config.IPsecVPN) error { return m.xfrm.Apply(vpns) }

// ClearXfrmi removes all previously created xfrmi interfaces.
func (m *Manager) ClearXfrmi() error { return m.xfrm.Clear() }

// --- Rule domains (next-table / rib-group / PBR) ---

// ApplyNextTableRules creates ip rules implementing next-table inter-VRF
// route leaking.
func (m *Manager) ApplyNextTableRules(routes []*config.StaticRoute, instances []*config.RoutingInstanceConfig) error {
	return m.nextTbl.Apply(routes, instances)
}

// ApplyRibGroupRules creates ip rules implementing rib-group route leaking.
func (m *Manager) ApplyRibGroupRules(ribGroups map[string]*config.RibGroup, instances []*config.RoutingInstanceConfig) error {
	return m.ribGroup.Apply(ribGroups, instances)
}

// ApplyPBRRules creates ip rules implementing policy-based routing.
func (m *Manager) ApplyPBRRules(rules []PBRRule) error { return m.pbr.Apply(rules) }

// --- RPM probe pin domain (#1827) ---

// ApplyProbePins clears the probe-pin band and programs one fwmark rule
// plus one pinned host route per RPM next-hop pin. It returns the
// per-test install failures keyed by ProbePin.TestKey (empty/nil = all
// installed); callers must thread the result into pkg/rpm so tests
// with unbacked pins hold state instead of probing the default path
// (#1895).
func (m *Manager) ApplyProbePins(pins []ProbePin) map[string]error { return m.probePin.Apply(pins) }

// ClearProbePins removes all probe pin rules and flushes the reserved
// probe tables. Run at daemon startup so a crashed daemon never leaks
// stale pins.
func (m *Manager) ClearProbePins() error { return m.probePin.clear() }

// --- Bond domain ---

// ApplyBonds creates Linux bond devices for fabric-options member-interfaces.
func (m *Manager) ApplyBonds(interfaces []*config.InterfaceConfig) error {
	return m.bond.Apply(interfaces)
}

// ClearBonds removes all previously created bond devices.
func (m *Manager) ClearBonds() error { return m.bond.Clear() }

// --- RETH cleanup ---

// ApplyRethInterfaces is a no-op (RETH bonds are no longer created).
func (m *Manager) ApplyRethInterfaces(interfaces map[string]*config.InterfaceConfig) error {
	return m.reth.Apply(interfaces)
}

// ClearRethInterfaces removes all RETH bond devices from the system.
func (m *Manager) ClearRethInterfaces() error { return m.reth.Clear() }

// RethNames returns the names of currently managed RETH interfaces.
func (m *Manager) RethNames() []string { return m.reth.Names() }

// --- Interface-monitor HA signal ---

// ApplyInterfaceMonitors checks link state for monitored interfaces in
// each redundancy group and stores the results for display.
func (m *Manager) ApplyInterfaceMonitors(groups []*config.RedundancyGroup) {
	m.monitor.Apply(groups)
}

// InterfaceMonitorStatuses returns the current monitor state for all
// redundancy groups. Returns nil if no monitors are configured.
func (m *Manager) InterfaceMonitorStatuses() map[int][]InterfaceMonitorStatus {
	return m.monitor.Statuses()
}
