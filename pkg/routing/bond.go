package routing

import (
	"log/slog"
	"sync"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// bondManager owns Linux bond device lifecycle for interfaces with
// fabric-options member-interfaces. The mu field replaces the bonds
// slice of the former shared Manager.ifaceMu.
type bondManager struct {
	ops linkOps

	mu    sync.Mutex
	bonds []string // currently created bond interface names
}

// Apply creates Linux bond devices for interfaces with fabric-options
// member-interfaces configured. Uses the bond mode from
// InterfaceConfig.BondMode (active-backup for fabric bonds, 802.3ad for
// ae interfaces).
func (b *bondManager) Apply(interfaces []*config.InterfaceConfig) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.clearLocked(); err != nil {
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
		if existing, err := b.ops.LinkByName(bondName); err == nil {
			// Already exists — ensure it's up and skip creation
			b.ops.LinkSetUp(existing)
			b.bonds = append(b.bonds, bondName)
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
		if err := b.ops.LinkAdd(bond); err != nil {
			slog.Warn("failed to create bond", "name", bondName, "err", err)
			continue
		}

		// Enslave member interfaces
		bondLink, err := b.ops.LinkByName(bondName)
		if err != nil {
			slog.Warn("failed to find created bond", "name", bondName, "err", err)
			continue
		}
		for _, member := range ifc.FabricMembers {
			linuxName := config.LinuxIfName(member)
			memberLink, err := b.ops.LinkByName(linuxName)
			if err != nil {
				slog.Warn("bond member not found",
					"bond", bondName, "member", member, "linux", linuxName, "err", err)
				continue
			}
			// Member must be down before enslaving
			b.ops.LinkSetDown(memberLink)
			if err := b.ops.LinkSetMaster(memberLink, bondLink); err != nil {
				slog.Warn("failed to enslave member",
					"bond", bondName, "member", member, "err", err)
				continue
			}
			b.ops.LinkSetUp(memberLink)
			slog.Info("bond member added", "bond", bondName, "member", member)
		}

		if err := b.ops.LinkSetUp(bondLink); err != nil {
			slog.Warn("failed to bring up bond", "name", bondName, "err", err)
		}
		b.bonds = append(b.bonds, bondName)
		modeStr := "802.3ad"
		if ifc.BondMode == "active-backup" {
			modeStr = "active-backup"
		}
		slog.Info("bond created", "name", bondName,
			"mode", modeStr, "members", ifc.FabricMembers)
	}
	return nil
}

// Clear removes all previously created bond devices.
func (b *bondManager) Clear() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.clearLocked()
}

// clearLocked is the lock-free body of Clear. Caller must hold mu.
// Used internally by Apply.
func (b *bondManager) clearLocked() error {
	for _, name := range b.bonds {
		link, err := b.ops.LinkByName(name)
		if err != nil {
			continue // already gone
		}
		if err := b.ops.LinkDel(link); err != nil {
			slog.Warn("failed to delete bond", "name", name, "err", err)
		} else {
			slog.Info("bond removed", "name", name)
		}
	}
	b.bonds = nil
	return nil
}
