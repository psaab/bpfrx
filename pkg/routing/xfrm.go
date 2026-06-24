package routing

import (
	"log/slog"
	"sync"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// xfrmManager owns XFRM virtual interface (xfrmi) lifecycle for IPsec
// VPN tunnels. The mu field replaces the xfrmis slice of the former
// shared Manager.ifaceMu.
type xfrmManager struct {
	ops linkOps

	mu sync.Mutex
	// xfrmis tracks the currently created xfrmi interfaces by name, each
	// mapped to the XFRM interface id (Ifid) it was created with. The id
	// is recorded so Apply can detect a params change (same name, but the
	// VPN now derives a different if_id) and recreate only that one
	// interface — the Ifid is set at link creation and is not mutable in
	// place, so a change requires delete+create.
	xfrmis map[string]uint32
}

// Apply reconciles the XFRM virtual interfaces for IPsec VPN tunnels
// against the currently tracked set. Each VPN with a BindInterface
// (e.g. "st0.0") gets a unit-specific xfrmi device and a stable XFRM
// interface ID derived from the st/unit pair.
//
// Apply is invoked on EVERY config commit, not only when IPsec changes
// (daemon_apply.go always calls ApplyXfrmi so xfrmi devices for deleted
// VPNs are torn down). It therefore reconciles differentially rather
// than clearing and rebuilding:
//
//   - KEEP an existing xfrmi untouched if it is still desired with the
//     same if_id (no LinkDel/LinkAdd). This is the fix for #2546: an
//     unrelated commit no longer tears down and rebuilds every IPsec
//     interface, so active tunnel traffic and routing bound to the
//     interfaces are not disrupted.
//   - CREATE an xfrmi that is newly desired.
//   - RECREATE (delete+create) an xfrmi whose name is unchanged but
//     whose desired if_id differs — the kernel does not allow changing
//     Ifid in place.
//   - DELETE an xfrmi that is no longer desired (its VPN was removed).
//
// A no-op commit (identical VPN set) issues zero LinkDel and zero
// LinkAdd calls.
func (x *xfrmManager) Apply(vpns map[string]*config.IPsecVPN) error {
	x.mu.Lock()
	defer x.mu.Unlock()

	if x.xfrmis == nil {
		x.xfrmis = map[string]uint32{}
	}

	// Build the desired name -> if_id set from the VPN config.
	desired := make(map[string]uint32, len(vpns))
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
		desired[ifName] = ifID
	}

	// Delete xfrmis no longer desired, plus those whose if_id changed
	// (they are recreated below from the desired set).
	for name, trackedID := range x.xfrmis {
		wantID, want := desired[name]
		if want && wantID == trackedID {
			continue // still desired, unchanged — leave it untouched
		}
		x.deleteLocked(name)
	}

	// Reconcile each desired xfrmi against the kernel. After the delete
	// pass above, a name survives in x.xfrmis only if it matched the
	// desired if_id, so a tracked+desired interface is unchanged and must
	// not be recreated.
	for ifName, ifID := range desired {
		_, tracked := x.xfrmis[ifName]

		// Single LinkByName lookup. Reuse the link object from this lookup
		// for LinkSetUp: calling LinkByName a second time and ignoring its
		// error risked passing a nil link to LinkSetUp on a transient
		// second-lookup failure, which panics inside netlink's LinkSetUp
		// (link.Attrs() on a nil interface). This is the now-reachable
		// "already exists, reuse" path (#1706, #2546) — taken when the
		// interface is unchanged (commit no-op) or survived a daemon
		// restart that lost in-memory tracking but not the kernel link.
		if link, err := x.ops.LinkByName(ifName); err == nil {
			// Verify the adopted kernel link's ACTUAL if_id matches the
			// desired one before re-tracking it. A kernel xfrmi with the
			// same NAME but a stale Ifid (e.g. a daemon restart after the
			// VPN's derived if_id changed, or a leftover from an aborted
			// recreate) must NOT be silently adopted — Ifid is immutable in
			// place, so a mismatch requires delete+recreate. On match (or a
			// non-xfrmi link of that name, which should not happen) keep the
			// existing adopt behavior.
			if xi, ok := link.(*netlink.Xfrmi); ok && xi.Ifid != ifID {
				slog.Info("xfrmi has stale if_id, recreating",
					"name", ifName, "have", xi.Ifid, "want", ifID)
				x.deleteLocked(ifName)
				// Fall through to the LinkAdd create path below.
			} else {
				if upErr := x.ops.LinkSetUp(link); upErr != nil {
					slog.Warn("failed to bring up existing xfrmi",
						"name", ifName, "err", upErr)
				}
				if tracked {
					slog.Debug("xfrmi unchanged, reused", "name", ifName, "if_id", ifID)
				} else {
					slog.Info("xfrmi adopted", "name", ifName, "if_id", ifID)
				}
				x.xfrmis[ifName] = ifID
				continue
			}
		}

		xfrmi := &netlink.Xfrmi{
			LinkAttrs: netlink.LinkAttrs{
				Name: ifName,
			},
			Ifid: ifID,
		}

		if err := x.ops.LinkAdd(xfrmi); err != nil {
			slog.Warn("failed to create xfrmi",
				"name", ifName, "if_id", ifID, "err", err)
			continue
		}

		link, err := x.ops.LinkByName(ifName)
		if err != nil {
			slog.Warn("failed to find xfrmi after creation",
				"name", ifName, "err", err)
			continue
		}

		if err := x.ops.LinkSetUp(link); err != nil {
			slog.Warn("failed to bring up xfrmi",
				"name", ifName, "err", err)
		}

		slog.Info("xfrmi created", "name", ifName, "if_id", ifID)
		x.xfrmis[ifName] = ifID
	}

	return nil
}

// Clear removes all previously created xfrmi interfaces.
func (x *xfrmManager) Clear() error {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.clearLocked()
}

// clearLocked deletes every tracked xfrmi. Caller must hold mu. Used by
// Clear (shutdown / full teardown). Apply no longer calls this — it
// reconciles differentially instead (#2546).
func (x *xfrmManager) clearLocked() error {
	for name := range x.xfrmis {
		x.deleteLocked(name)
	}
	x.xfrmis = nil
	return nil
}

// deleteLocked removes a single tracked xfrmi by name and drops it from
// tracking. Caller must hold mu. A link already gone from the kernel is
// treated as success (the entry is still untracked).
func (x *xfrmManager) deleteLocked(name string) {
	link, err := x.ops.LinkByName(name)
	if err != nil {
		delete(x.xfrmis, name)
		return // already gone
	}
	if err := x.ops.LinkDel(link); err != nil {
		slog.Warn("failed to delete xfrmi", "name", name, "err", err)
	} else {
		slog.Info("xfrmi removed", "name", name)
	}
	delete(x.xfrmis, name)
}
