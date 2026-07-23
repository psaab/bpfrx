package routing

import (
	"errors"
	"fmt"
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
//
// Fail-closed error contract (#5310). Apply used to log every create /
// find-after-create / bring-up / delete failure and return nil
// UNCONDITIONALLY, so a route-based IPsec VPN whose xfrmi could not be
// realized in the kernel (e.g. LinkAdd failed) reported a SUCCESSFUL
// commit while the interface — and the routes bound to it — carried no
// traffic. Apply now accumulates the GENUINE netlink failures with
// errors.Join and returns them (mirroring the #4823 bond create path and
// the #4901 clearLocked teardown path) so daemon_apply.go can fail the
// commit closed. The tolerated idempotent conditions are NOT errors: an
// xfrmi that already exists is adopted via the LinkByName path below
// (re-tracked + brought up = success, never a LinkAdd), and an
// already-gone delete returns nil from deleteLocked (#4901). Only a real
// failure (LinkAdd/LinkSetUp/find-after-create/LinkDel failed for a real
// reason) becomes a returned error.
func (x *xfrmManager) Apply(vpns map[string]*config.IPsecVPN) error {
	x.mu.Lock()
	defer x.mu.Unlock()

	// errs accumulates GENUINE reconcile failures (create/find/up/delete)
	// so the commit fails closed (#5310). Tolerated idempotent conditions
	// (adopt an existing link, delete an already-gone link) never append.
	var errs []error

	if x.xfrmis == nil {
		x.xfrmis = map[string]uint32{}
	}

	// Build the desired name -> if_id set from the VPN config.
	//
	// The XFRM interface id MUST be unique per distinct xfrmi device:
	// the kernel keys SA<->xfrmi binding on if_id, so two devices that
	// share an if_id make the SAs route to whichever device the kernel
	// matched first — leaking traffic between VPNs that are supposed to
	// be isolated (#2909). config.XFRMIfNameAndID can derive a colliding
	// id for distinct bind-interfaces: a bare "st0" and an explicit
	// "st0.0" both yield if_id 1 (unit defaults to 0 when no ".N" suffix
	// is present) under DIFFERENT device names ("st0" vs "st0.0"). Detect
	// such a collision here and refuse to create either colliding device
	// — better to leave both tunnels' xfrmi absent (fail-closed, no
	// transit) than to create two devices that silently cross-leak.
	//
	// The proper long-term fix is a commit-time rejection of an ambiguous
	// secure-tunnel bind-interface in the config compiler / pkg/ipsec
	// (tracked separately); this routing guard is the last line of
	// defense so a config that slips through never programs colliding
	// kernel state.
	desired := make(map[string]uint32, len(vpns))
	idToName := make(map[uint32]string, len(vpns))
	collidingIDs := make(map[uint32]struct{})
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
		if prev, dup := idToName[ifID]; dup && prev != ifName {
			// A different device name already claimed this if_id. Mark
			// the id as colliding; both names are dropped below.
			collidingIDs[ifID] = struct{}{}
			slog.Error("xfrmi if_id collision: distinct bind-interfaces "+
				"derive the same XFRM if_id; refusing to create either "+
				"(cross-VPN leak / EEXIST risk)",
				"if_id", ifID, "name_a", prev, "name_b", ifName,
				"vpn", vpn.Name)
			continue
		}
		idToName[ifID] = ifName
		desired[ifName] = ifID
	}
	// Drop every device whose if_id collided. The first claimant was
	// recorded in desired before the collision was seen, so remove it too
	// — neither colliding device may be programmed.
	for id := range collidingIDs {
		if name, ok := idToName[id]; ok {
			delete(desired, name)
		}
	}

	// Delete xfrmis no longer desired, plus those whose if_id changed
	// (they are recreated below from the desired set).
	for name, trackedID := range x.xfrmis {
		wantID, want := desired[name]
		if want && wantID == trackedID {
			continue // still desired, unchanged — leave it untouched
		}
		// Differential reconcile: a failed LinkDel now retains tracking (#4901)
		// so the next Apply retries; the recreate below still runs for a desired
		// name whose if_id changed. #5310: surface a genuine LinkDel failure
		// (deleteLocked returns nil for an already-gone link — that stays a
		// tolerated no-op).
		if err := x.deleteLocked(name); err != nil {
			errs = append(errs, err)
		}
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
		link, err := x.ops.LinkByName(ifName)
		if err != nil && !isLinkNotFound(err) {
			// #5461: a transient/lookup error (EBUSY, EINVAL, netlink
			// transport) is NOT proof the xfrmi is absent. Falling through to
			// the LinkAdd create path on a device that actually EXISTS would
			// hit EEXIST and fail the commit closed with a misleading error,
			// leaving the interface desired-but-untracked. Retain ownership
			// (a tracked name is already in x.xfrmis and is deliberately left
			// untouched here), surface the real lookup error so the commit
			// fails closed on the genuine cause, and let the next reconcile
			// retry. Mirrors reconcileVRFs' transient-lookup retention
			// (vrf.go). Only a genuine not-found falls through to create.
			slog.Warn("xfrmi lookup failed; not creating, retaining for retry",
				"name", ifName, "if_id", ifID, "tracked", tracked, "err", err)
			errs = append(errs, fmt.Errorf("lookup xfrmi %s: %w", ifName, err))
			continue
		}
		if err == nil {
			// Verify the adopted kernel link is an xfrm interface whose ACTUAL
			// if_id matches the desired one before re-tracking it. Two cases
			// must NOT be silently adopted:
			//
			//   - A kernel xfrmi with the same NAME but a stale Ifid (e.g. a
			//     daemon restart after the VPN's derived if_id changed, or a
			//     leftover from an aborted recreate). Ifid is immutable in place,
			//     so a mismatch requires delete+recreate.
			//   - A link wearing the xfrmi's name that is NOT an xfrm interface
			//     at all (a foreign/leftover dummy/veth/etc). Adopting it would
			//     track the name as satisfied while NO xfrm interface carries
			//     if_id, so the route-based VPN bound to it silently blackholes
			//     (#5523 C179-104). The type guard previously gated only the
			//     stale-if_id recreate branch, so a non-xfrmi link fell through
			//     to the adopt path.
			//
			// Both cases reclaim the name via delete+recreate; only a matching
			// xfrmi is adopted.
			xi, isXfrmi := link.(*netlink.Xfrmi)
			if !isXfrmi || xi.Ifid != ifID {
				if isXfrmi {
					slog.Info("xfrmi has stale if_id, recreating",
						"name", ifName, "have", xi.Ifid, "want", ifID)
				} else {
					slog.Info("link with xfrmi name is not an xfrm interface, recreating",
						"name", ifName, "type", link.Type(), "want_if_id", ifID)
				}
				// #5310: if the delete fails the kernel link is still present
				// (wrong if_id, or wrong type), so a LinkAdd below would EEXIST —
				// skip the recreate this cycle (mirroring the #5119 bond
				// changed-signature path) and surface the delete failure so the
				// commit fails closed; the next reconcile retries the delete.
				if err := x.deleteLocked(ifName); err != nil {
					errs = append(errs, err)
					continue
				}
				// Fall through to the LinkAdd create path below.
			} else {
				if upErr := x.ops.LinkSetUp(link); upErr != nil {
					slog.Warn("failed to bring up existing xfrmi",
						"name", ifName, "err", upErr)
					// A genuine bring-up failure on an adopted link is surfaced
					// (#5310), but the link exists and we own it, so it stays
					// tracked and the next reconcile re-attempts bring-up.
					errs = append(errs, fmt.Errorf("bring up existing xfrmi %s: %w", ifName, upErr))
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
			// #5310: a genuine create failure leaves the interface UNTRACKED
			// (the next reconcile retries) and fails the commit closed — a
			// route-based VPN bound to an xfrmi that never made it into the
			// kernel must not report a successful commit.
			errs = append(errs, fmt.Errorf("create xfrmi %s (if_id %d): %w", ifName, ifID, err))
			continue
		}

		link, err = x.ops.LinkByName(ifName)
		if err != nil {
			slog.Warn("failed to find xfrmi after creation",
				"name", ifName, "err", err)
			errs = append(errs, fmt.Errorf("find xfrmi %s after creation: %w", ifName, err))
			continue
		}

		if err := x.ops.LinkSetUp(link); err != nil {
			slog.Warn("failed to bring up xfrmi",
				"name", ifName, "err", err)
			// The link was created and is tracked below; surface the bring-up
			// failure (#5310) so the commit fails closed and the next reconcile
			// re-attempts the LinkSetUp.
			errs = append(errs, fmt.Errorf("bring up xfrmi %s: %w", ifName, err))
		}

		slog.Info("xfrmi created", "name", ifName, "if_id", ifID)
		x.xfrmis[ifName] = ifID
	}

	return errors.Join(errs...)
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
	var errs []error
	for name := range x.xfrmis {
		if err := x.deleteLocked(name); err != nil {
			errs = append(errs, err)
		}
	}
	// #4901: deleteLocked drops each successfully-removed name and RETAINS the
	// ones whose LinkDel failed so the next reconcile retries — do NOT
	// blanket-nil the map here (the old behavior), which would forget an
	// orphaned xfrmi and lose ownership while reporting a clean teardown. Only
	// clear the map once every device is actually gone.
	if len(x.xfrmis) == 0 {
		x.xfrmis = nil
	}
	return errors.Join(errs...)
}

// deleteLocked removes a single tracked xfrmi by name and drops it from
// tracking. Caller must hold mu. A link genuinely gone from the kernel is
// treated as success (the entry is dropped from tracking). It returns a non-nil
// error when the netlink LinkDel fails, in which case the name is RETAINED in
// tracking (#4901) so the next reconcile retries instead of orphaning the link.
//
// #5495: only a GENUINE not-found (link-not-found errno) may drop tracking +
// report gone. The former code took the "already gone" branch on ANY LinkByName
// error — a transient/lookup failure (EBUSY, timeout, netlink transport) was
// conflated with genuine absence, so it deleted tracking and returned nil-gone
// while the xfrmi was still live in the kernel. A later Apply then had no
// removed-desired entry to drive cleanup, silently ORPHANING the interface (and
// leaving stale routing/security state) while reporting convergence. On a
// transient error we now RETAIN the entry and surface the error so the caller
// aggregates it (fail-closed) and the next reconcile retries. Mirrors
// reconcileVRFs' transient-lookup retention (vrf.go).
func (x *xfrmManager) deleteLocked(name string) error {
	link, err := x.ops.LinkByName(name)
	if err != nil {
		if isLinkNotFound(err) {
			delete(x.xfrmis, name)
			return nil // genuinely gone
		}
		slog.Warn("xfrmi lookup failed during delete; retaining tracking for retry",
			"name", name, "err", err)
		return fmt.Errorf("lookup xfrmi %s for delete: %w", name, err)
	}
	if err := x.ops.LinkDel(link); err != nil {
		// #4901: a failed LinkDel leaves the xfrmi in the kernel. Retain
		// tracking (do NOT delete from x.xfrmis) and surface the error so the
		// caller can aggregate it and the next reconcile retries.
		slog.Warn("failed to delete xfrmi", "name", name, "err", err)
		return fmt.Errorf("delete xfrmi %s: %w", name, err)
	}
	slog.Info("xfrmi removed", "name", name)
	delete(x.xfrmis, name)
	return nil
}
