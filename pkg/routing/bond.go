package routing

import (
	"errors"
	"fmt"
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
//
// Link-creation/enslavement/bring-up failures (LinkAdd, LinkSetMaster,
// LinkSetUp) are accumulated with errors.Join and returned instead of
// silently swallowed (#4823): before this fix, every one of these
// netlink failures was logged and skipped, and Apply ALWAYS returned
// nil — so a commit whose fabric/ae bond could not be realized in the
// kernel still reported success, with no way for the commit pipeline
// to detect the incomplete topology. LinkSetDown (best-effort pre-
// enslave step) and a not-yet-present member link (LinkByName on a
// FabricMembers entry — routine during interface enumeration ordering,
// not itself a link-creation failure) are unchanged: still log-only,
// since failing the WHOLE bond over one not-yet-enumerated member
// would be worse than the partial-enslavement it already tolerates.
func (b *bondManager) Apply(interfaces []*config.InterfaceConfig) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.clearLocked(); err != nil {
		slog.Warn("failed to clear previous bonds", "err", err)
	}

	var errs []error
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
			if err := b.ops.LinkSetUp(existing); err != nil {
				slog.Warn("failed to bring up existing bond", "name", bondName, "err", err)
				errs = append(errs, fmt.Errorf("bond %s: bring up existing: %w", bondName, err))
			}
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
			errs = append(errs, fmt.Errorf("bond %s: create: %w", bondName, err))
			continue
		}

		// Enslave member interfaces
		bondLink, err := b.ops.LinkByName(bondName)
		if err != nil {
			slog.Warn("failed to find created bond", "name", bondName, "err", err)
			errs = append(errs, fmt.Errorf("bond %s: find after create: %w", bondName, err))
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
				errs = append(errs, fmt.Errorf("bond %s: enslave member %s: %w", bondName, member, err))
				continue
			}
			b.ops.LinkSetUp(memberLink)
			slog.Info("bond member added", "bond", bondName, "member", member)
		}

		if err := b.ops.LinkSetUp(bondLink); err != nil {
			slog.Warn("failed to bring up bond", "name", bondName, "err", err)
			errs = append(errs, fmt.Errorf("bond %s: bring up: %w", bondName, err))
		}
		b.bonds = append(b.bonds, bondName)
		modeStr := "802.3ad"
		if ifc.BondMode == "active-backup" {
			modeStr = "active-backup"
		}
		slog.Info("bond created", "name", bondName,
			"mode", modeStr, "members", ifc.FabricMembers)
	}
	return errors.Join(errs...)
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
	var errs []error
	var retained []string
	for _, name := range b.bonds {
		link, err := b.ops.LinkByName(name)
		if err != nil {
			continue // already gone
		}
		if err := b.ops.LinkDel(link); err != nil {
			// #4901: a failed LinkDel leaves the bond (and its enslaved members)
			// in the kernel. Retain the name so the next reconcile retries the
			// delete, and surface the error instead of returning a clean-teardown
			// nil that loses ownership of the orphaned bond.
			slog.Warn("failed to delete bond", "name", name, "err", err)
			errs = append(errs, fmt.Errorf("delete bond %s: %w", name, err))
			retained = append(retained, name)
		} else {
			slog.Info("bond removed", "name", name)
		}
	}
	b.bonds = retained
	return errors.Join(errs...)
}
