package routing

import (
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// bondManager owns Linux bond device lifecycle for interfaces with
// fabric-options member-interfaces. The mu field replaces the bonds
// slice of the former shared Manager.ifaceMu.
type bondManager struct {
	ops linkOps

	mu sync.Mutex
	// bonds tracks the currently created bond devices by name, each mapped
	// to the signature (mode, MTU, resolved member set) it was realized
	// with. The signature lets Apply detect an UNCHANGED bond and leave it
	// untouched instead of tearing it down and rebuilding it on every
	// commit (#5119).
	bonds map[string]bondSig
}

// bondSig captures the parts of a fabric/ae bond's desired config that
// determine its kernel realization: the bond mode, the interface-level
// MTU, and the resolved (Linux-named) member set. Two bonds with an
// identical signature realize the same kernel device, so an unchanged
// signature means the bond must NOT be LinkDel'd and rebuilt on an
// unrelated commit — doing so re-enslaves members and forces LACP to
// re-converge, flapping the LAG (#5119). bondSig is a comparable struct
// (the member set is pre-sorted and joined into a single string) so a
// plain == is the whole diff.
type bondSig struct {
	mode    string // normalized: "active-backup" or "802.3ad"
	mtu     int    // interface-level MTU (0 = kernel default, not set)
	members string // sorted, comma-joined resolved Linux member names
}

// bondSigOf derives the signature of the bond an interface config would
// realize. The mode is normalized the same way Apply programs it (any
// non-"active-backup" mode is 802.3ad), and members are resolved to their
// Linux names and sorted so member-order or Junos-vs-Linux spelling never
// registers as a spurious change.
func bondSigOf(ifc *config.InterfaceConfig) bondSig {
	mode := "802.3ad"
	if ifc.BondMode == "active-backup" {
		mode = "active-backup"
	}
	members := make([]string, 0, len(ifc.FabricMembers))
	for _, m := range ifc.FabricMembers {
		members = append(members, config.LinuxIfName(m))
	}
	sort.Strings(members)
	return bondSig{
		mode:    mode,
		mtu:     ifc.MTU,
		members: strings.Join(members, ","),
	}
}

// Apply reconciles the Linux bond devices for interfaces with
// fabric-options member-interfaces against the currently tracked set.
// The bond mode comes from InterfaceConfig.BondMode (active-backup for
// fabric bonds, 802.3ad for ae interfaces).
//
// Apply is invoked on EVERY config commit, not only when the bond/fabric
// config changes (daemon_apply.go always calls ApplyBonds so bonds for
// deleted fabric interfaces are torn down). It therefore reconciles the
// desired bond set differentially rather than clearing and rebuilding —
// the fix for #5119, mirroring the #2546 XFRM reconcile:
//
//   - KEEP a bond untouched when it is still desired with an identical
//     signature (mode, MTU, member set) — no LinkDel/LinkAdd/LinkSetMaster,
//     so an unrelated policy-only commit no longer flaps the LAG (LinkDel→
//     LinkAdd→re-enslave→LACP re-converge). This was the non-idempotent
//     anti-pattern #2546 fixed for XFRM but not bonds.
//   - CREATE a bond that is newly desired (also adopts a kernel bond that
//     outlived in-memory tracking, e.g. across a daemon restart).
//   - RECREATE (delete+create) a bond whose signature changed — a genuine
//     config change (member added/removed, mode or MTU changed). The bond
//     mode and enslavement cannot be changed in place while members are
//     attached, so a signature change is a delete+rebuild.
//   - DELETE a bond that is no longer desired (its fabric interface was
//     removed).
//
// A no-op commit (identical desired bond set) issues zero LinkDel, zero
// LinkAdd, and zero LinkSetMaster calls.
//
// Link-creation/enslavement/bring-up failures (LinkAdd, LinkSetMaster,
// LinkSetUp) are accumulated with errors.Join and returned instead of
// silently swallowed (#4823): before that fix, every one of these netlink
// failures was logged and skipped, and Apply ALWAYS returned nil — so a
// commit whose fabric/ae bond could not be realized in the kernel still
// reported success. LinkSetDown (best-effort pre-enslave step) and a
// not-yet-present member link (LinkByName on a FabricMembers entry —
// routine during interface enumeration ordering) remain log-only.
func (b *bondManager) Apply(interfaces []*config.InterfaceConfig) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.bonds == nil {
		b.bonds = map[string]bondSig{}
	}

	// Build the desired name -> signature set. Skip interfaces with no
	// fabric members and vSRX single-local-member fabric-options mode
	// (LocalFabricMember resolved via .link rename — no bond device).
	desired := make(map[string]bondSig, len(interfaces))
	order := make([]string, 0, len(interfaces))
	ifcByName := make(map[string]*config.InterfaceConfig, len(interfaces))
	for _, ifc := range interfaces {
		if len(ifc.FabricMembers) == 0 || ifc.LocalFabricMember != "" {
			continue
		}
		if _, dup := desired[ifc.Name]; dup {
			continue
		}
		desired[ifc.Name] = bondSigOf(ifc)
		order = append(order, ifc.Name)
		ifcByName[ifc.Name] = ifc
	}

	var errs []error

	// Delete pass: remove bonds that are no longer desired OR whose
	// signature changed. A KEPT bond (still desired, identical signature)
	// is left untouched — no destructive link op — so an unrelated commit
	// does not flap the LAG (#5119). #4901: a failed LinkDel retains
	// tracking so the next reconcile retries; a changed bond whose delete
	// failed keeps its OLD signature, so it is NOT recreated this cycle
	// (its stale kernel device is still present) and the next reconcile
	// retries the delete first.
	for name, trackedSig := range b.bonds {
		if wantSig, want := desired[name]; want && wantSig == trackedSig {
			continue // unchanged — keep
		}
		if err := b.deleteLocked(name); err != nil {
			errs = append(errs, err)
		}
	}

	// Create/reconcile pass: build bonds that are newly desired or were
	// just deleted because their signature changed.
	for _, name := range order {
		sig := desired[name]
		if trackedSig, kept := b.bonds[name]; kept {
			// Survived the delete pass. Either:
			//   - unchanged (signature matched) — bring it up idempotently
			//     (a no-op on an already-up bond, matching the XFRM keep
			//     path); zero LinkDel/LinkAdd/LinkSetMaster, so no flap.
			//   - OR a changed bond whose LinkDel failed above (OLD sig
			//     retained). Skip recreation this cycle to avoid an EEXIST
			//     LinkAdd; the next reconcile retries the delete first.
			if trackedSig == sig {
				if link, err := b.ops.LinkByName(name); err == nil {
					if err := b.ops.LinkSetUp(link); err != nil {
						slog.Warn("failed to bring up existing bond", "name", name, "err", err)
						errs = append(errs, fmt.Errorf("bond %s: bring up existing: %w", name, err))
					}
				}
			}
			continue
		}
		if err := b.createLocked(name, ifcByName[name], sig); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// createLocked realizes a single desired bond in the kernel: it adopts an
// already-present kernel device of that name without tearing it down (one
// that outlived in-memory tracking across a daemon restart, or whose prior
// LinkDel failed), or else creates the bond, enslaves its members, and
// brings everything up. On success the bond is tracked under sig. Netlink
// failures are aggregated and returned (#4823) rather than swallowed; a
// LinkAdd / find-after-create failure leaves the bond UNTRACKED so the
// next reconcile retries. Caller must hold mu.
func (b *bondManager) createLocked(name string, ifc *config.InterfaceConfig, sig bondSig) error {
	// Adopt an existing kernel device without a destructive rebuild. Kernel
	// bond internals (mode/members) are not re-read here — this matches the
	// pre-#5119 adopt behavior; the common no-op commit path never reaches
	// createLocked because an unchanged bond is kept in the delete pass.
	if existing, err := b.ops.LinkByName(name); err == nil {
		b.bonds[name] = sig
		slog.Debug("bond already exists", "name", name)
		if err := b.ops.LinkSetUp(existing); err != nil {
			slog.Warn("failed to bring up existing bond", "name", name, "err", err)
			return fmt.Errorf("bond %s: bring up existing: %w", name, err)
		}
		return nil
	}

	bond := netlink.NewLinkBond(netlink.LinkAttrs{Name: name})
	if sig.mode == "active-backup" {
		bond.Mode = netlink.BOND_MODE_ACTIVE_BACKUP
	} else {
		bond.Mode = netlink.BOND_MODE_802_3AD
	}
	if ifc.MTU > 0 {
		bond.LinkAttrs.MTU = ifc.MTU
	}
	if err := b.ops.LinkAdd(bond); err != nil {
		slog.Warn("failed to create bond", "name", name, "err", err)
		return fmt.Errorf("bond %s: create: %w", name, err)
	}

	// Enslave member interfaces.
	bondLink, err := b.ops.LinkByName(name)
	if err != nil {
		slog.Warn("failed to find created bond", "name", name, "err", err)
		return fmt.Errorf("bond %s: find after create: %w", name, err)
	}

	var errs []error
	for _, member := range ifc.FabricMembers {
		linuxName := config.LinuxIfName(member)
		memberLink, err := b.ops.LinkByName(linuxName)
		if err != nil {
			slog.Warn("bond member not found",
				"bond", name, "member", member, "linux", linuxName, "err", err)
			continue
		}
		// Member must be down before enslaving.
		b.ops.LinkSetDown(memberLink)
		if err := b.ops.LinkSetMaster(memberLink, bondLink); err != nil {
			slog.Warn("failed to enslave member",
				"bond", name, "member", member, "err", err)
			errs = append(errs, fmt.Errorf("bond %s: enslave member %s: %w", name, member, err))
			continue
		}
		b.ops.LinkSetUp(memberLink)
		slog.Info("bond member added", "bond", name, "member", member)
	}

	if err := b.ops.LinkSetUp(bondLink); err != nil {
		slog.Warn("failed to bring up bond", "name", name, "err", err)
		errs = append(errs, fmt.Errorf("bond %s: bring up: %w", name, err))
	}
	b.bonds[name] = sig
	slog.Info("bond created", "name", name, "mode", sig.mode, "members", ifc.FabricMembers)
	return errors.Join(errs...)
}

// Clear removes all previously created bond devices.
func (b *bondManager) Clear() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.clearLocked()
}

// clearLocked deletes every tracked bond. Caller must hold mu. Used by
// Clear (shutdown / full teardown). Apply no longer calls this — it
// reconciles differentially instead (#5119).
func (b *bondManager) clearLocked() error {
	var errs []error
	for name := range b.bonds {
		if err := b.deleteLocked(name); err != nil {
			errs = append(errs, err)
		}
	}
	// #4901: deleteLocked drops each successfully-removed name and RETAINS
	// the ones whose LinkDel failed so the next reconcile retries — do NOT
	// blanket-nil the map here, which would forget an orphaned bond and lose
	// ownership while reporting a clean teardown. Only clear once every
	// device is actually gone.
	if len(b.bonds) == 0 {
		b.bonds = nil
	}
	return errors.Join(errs...)
}

// deleteLocked removes a single tracked bond by name and drops it from
// tracking. Caller must hold mu. A link already gone from the kernel is
// treated as success (the entry is still untracked). It returns a non-nil
// error when the netlink LinkDel fails, in which case the name is RETAINED
// in tracking (#4901) so the next reconcile retries instead of orphaning
// the bond (and its enslaved members).
func (b *bondManager) deleteLocked(name string) error {
	link, err := b.ops.LinkByName(name)
	if err != nil {
		delete(b.bonds, name)
		return nil // already gone
	}
	if err := b.ops.LinkDel(link); err != nil {
		slog.Warn("failed to delete bond", "name", name, "err", err)
		return fmt.Errorf("delete bond %s: %w", name, err)
	}
	slog.Info("bond removed", "name", name)
	delete(b.bonds, name)
	return nil
}
