package daemon

import (
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// rg_ownership_8297.go carries a THREE-state ownership answer for consumers
// whose safe fail direction is "act" rather than "stay silent".
//
// #8342 is the reason this exists. #8314 gated proxy-ARP on
// `isRethMasterState` -> `AllVRRPMaster()` -> `allMasterLocked()`, which
// returns FALSE when the RG has no known VRRP instances:
//
//	if len(s.vrrpInstances) == 0 { return false }
//
// For the DHCP relay that predicate was written for, "nothing known -> do not
// relay" avoids a duplicate and failing closed is right. For proxy-ARP it is an
// OUTAGE: the entry is not installed, nobody answers for the address, and every
// NAT pool / DNAT / static-NAT external address on that segment goes dark. The
// revert measured exactly that — `fw0=0 fw1=0`, empty on both nodes.
//
// **A predicate's fail DIRECTION belongs to its consumer, not to its name.**
// That sentence is #8342's, and this file is what it asks for: the two-state
// bool cannot express the difference between "we are not the owner" and "we do
// not know who is", and proxy-ARP must treat those oppositely.
//
// Proxy ARP for NAT is a shipped, High-priority feature (`docs/feature-gaps.md`)
// — "Required when SNAT pool, DNAT, or static-NAT external addresses are on same
// L2 segment" — so silence is never the safe default for it. Answering twice is
// a defect (#8297); answering zero times is a bigger one.

// rgOwnership is a three-state answer to "does this node own redundancy-group
// N?", kept distinct from a bool so a caller cannot silently collapse the
// unknown case into either verdict.
type rgOwnership int

const (
	// rgOwnershipUnknown: no VRRP instance state is known for the RG, so this
	// node cannot say whether it owns it. Consumers whose silence is an outage
	// must ACT on this, not suppress.
	rgOwnershipUnknown rgOwnership = iota
	// rgOwnershipOwner: every VRRP instance for the RG is MASTER here.
	rgOwnershipOwner
	// rgOwnershipNotOwner: instances ARE known and this node is not master of
	// all of them. The only state in which suppressing is justified, because it
	// is the only one that affirmatively names another node as owner.
	rgOwnershipNotOwner
)

// Ownership reports the three-state ownership of the RG this state machine
// tracks.
//
// The `len(vrrpInstances) == 0` case is the whole point: `AllVRRPMaster` folds
// it into false, and this does not.
func (s *rgStateMachine) Ownership() rgOwnership {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.vrrpInstances) == 0 {
		return rgOwnershipUnknown
	}
	for _, isMaster := range s.vrrpInstances {
		if !isMaster {
			return rgOwnershipNotOwner
		}
	}
	return rgOwnershipOwner
}

// rgOwnershipFor is the daemon-level accessor, mirroring isRethMasterState's
// shape so the two sit side by side and the difference is visible at the call
// site rather than buried in a helper.
func (d *Daemon) rgOwnershipFor(rgID int) rgOwnership {
	return d.getOrCreateRGState(rgID).Ownership()
}

// proxyARPSuppressedForRG reports whether this node must NOT answer proxy-ARP
// for an address on an interface belonging to rgID.
//
// Suppress ONLY on an affirmative not-owner. Unknown answers, which is the
// #8342 fail direction, and rgID <= 0 (an interface in no redundancy group)
// answers because there is no ownership question to ask.
func (d *Daemon) proxyARPSuppressedForRG(rgID int) bool {
	if rgID <= 0 {
		return false
	}
	return d.rgOwnershipFor(rgID) == rgOwnershipNotOwner
}

// proxyARPRedundancyGroupFor resolves the redundancy group of the interface a
// `proxy-arp` entry names, or 0 when it belongs to none.
//
// The entry names a Junos ref such as `reth0.80`; the redundancy group lives on
// the BASE interface (`reth0`, `redundant-ether-options redundancy-group 1`), so
// the unit suffix is trimmed before the lookup. A ref that resolves to no
// configured interface returns 0 — answer — for the same reason the unknown
// ownership state does.
func proxyARPRedundancyGroupFor(cfg *config.Config, ifaceRef string) int {
	if cfg == nil {
		return 0
	}
	base := ifaceRef
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	ifc, ok := cfg.Interfaces.Interfaces[base]
	if !ok || ifc == nil {
		return 0
	}
	if ifc.RedundancyGroup > 0 {
		return ifc.RedundancyGroup
	}
	// A physical member names its reth parent; the group lives there.
	if ifc.RedundantParent != "" {
		if parent, ok := cfg.Interfaces.Interfaces[ifc.RedundantParent]; ok && parent != nil {
			return parent.RedundancyGroup
		}
	}
	return 0
}

// proxyARPEntrySuppressed is the wiring the #8297 fix turns on: it is what
// makes the standby stop answering. Kept as one named predicate so the gate is
// bindable by a test rather than living inline in the reconcile loop.
func (d *Daemon) proxyARPEntrySuppressed(cfg *config.Config, ifaceRef string) bool {
	return d.proxyARPSuppressedForRG(proxyARPRedundancyGroupFor(cfg, ifaceRef))
}
