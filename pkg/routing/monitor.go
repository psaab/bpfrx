package routing

import (
	"log/slog"
	"net"
	"sync"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// InterfaceMonitorStatus tracks the link state of a monitored interface.
type InterfaceMonitorStatus struct {
	Interface string
	Weight    int
	Up        bool // true if link is operationally up
	// ConfiguredWeight / Clamped carry the #6589 clamp signal to the display.
	// Weight is what the election APPLIES; these say whether that differs from
	// what the operator wrote. Zero values mean "not clamped", so a producer
	// that does not set them renders exactly as before.
	ConfiguredWeight int
	Clamped          bool
}

// monitorManager owns interface-monitor link-state tracking for
// redundancy groups. This is the only live HA signal in the routing
// package: ApplyInterfaceMonitors results feed cluster weight via
// InterfaceMonitorStatuses. The mu field replaces the former shared
// Manager.mu.
type monitorManager struct {
	ops linkOps

	mu            sync.Mutex
	monitorStatus map[int][]InterfaceMonitorStatus // redundancy-group ID -> monitor states
}

// Apply checks link state for monitored interfaces in each redundancy
// group and stores the results for display.
func (mm *monitorManager) Apply(groups []*config.RedundancyGroup) {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	mm.monitorStatus = make(map[int][]InterfaceMonitorStatus)
	for _, rg := range groups {
		var statuses []InterfaceMonitorStatus
		for _, mon := range rg.InterfaceMonitors {
			// #6549: bound the configured weight to the [0,255] heartbeat
			// weight domain. These statuses are not display-only — the daemon
			// config-apply tail feeds them straight into
			// cluster.Manager.SetMonitorWeight as election debt
			// (daemon_apply_tail.go), so the raw value would install
			// out-of-range debt; and `show chassis cluster interfaces` renders
			// them, so a raw value would report a weight the election does not
			// use. The strict commit path rejects an out-of-range weight; the
			// tolerant load / peer-sync path only warns (#1960 no-brick), so
			// one can still reach here. Deliberately not logged: the cluster
			// manager's reconcileMonitorDebtsLocked already reports this
			// weight once per config apply, against the config that carried
			// it. (Because this clamp runs first, the SetMonitorWeight
			// chokepoint sees an already-bounded value and stays silent — its
			// warning fires only for a producer that skipped its own clamp.)
			weight, weightClamped := config.ClampInterfaceMonitorWeight(mon.Weight)

			// Translate Junos name (ge-0/0/0) to Linux name (ge-0-0-0).
			linuxName := config.LinuxIfName(mon.Interface)
			link, err := mm.ops.LinkByName(linuxName)
			if err != nil {
				// Interface doesn't exist — belongs to peer node. Skip.
				continue
			}
			up := linkAttrsUp(link.Attrs())
			statuses = append(statuses, InterfaceMonitorStatus{
				Interface: mon.Interface,
				Weight:    weight,
				Up:        up,
				// #6589: carry the clamp signal to the display. This is the
				// LIVE path both `show chassis cluster interfaces` renderers
				// take; annotating only the config-only fallback would leave
				// the common case silent.
				ConfiguredWeight: mon.Weight,
				Clamped:          weightClamped,
			})
			if !up {
				slog.Warn("interface monitor: link down",
					"redundancy_group", rg.ID,
					"interface", mon.Interface,
					"weight", weight)
			}
		}
		if len(statuses) > 0 {
			mm.monitorStatus[rg.ID] = statuses
		}
	}
}

// linkAttrsUp reports whether a monitored interface is operationally up.
//
// Interface-monitoring exists to detect carrier loss (cable pulled / peer
// link down) and demote the redundancy group so HA failover fires. The
// administrative IFF_UP flag (net.FlagUp) stays set whenever the interface
// is admin-up — and xpfd admin-ups ALL managed interfaces — so it must NOT
// be used to decide carrier health: a carrier-down link keeps IFF_UP set
// while OperState transitions to OperDown/OperLowerLayerDown. Decide from
// the operational state (IFLA_OPERSTATE):
//   - OperUp                 -> up.
//   - OperUnknown            -> fall back to the admin flag (common on
//     virtual devices that report no carrier state).
//   - OperDown / lower-layer-down / anything else -> down.
//
// This mirrors pkg/vrrp.linkAttrsUp, the canonical link-state read used by
// VRRP track-interface detection (#2070).
func linkAttrsUp(attrs *netlink.LinkAttrs) bool {
	switch attrs.OperState {
	case netlink.OperUp:
		return true
	case netlink.OperUnknown:
		return attrs.Flags&net.FlagUp != 0
	default:
		return false
	}
}

// Statuses returns the current monitor state for all redundancy groups.
// Returns nil if no monitors are configured.
func (mm *monitorManager) Statuses() map[int][]InterfaceMonitorStatus {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	if len(mm.monitorStatus) == 0 {
		return nil
	}
	// Return a copy
	result := make(map[int][]InterfaceMonitorStatus, len(mm.monitorStatus))
	for k, v := range mm.monitorStatus {
		cp := make([]InterfaceMonitorStatus, len(v))
		copy(cp, v)
		result[k] = cp
	}
	return result
}
