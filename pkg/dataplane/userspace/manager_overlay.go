package userspace

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// routeOverlaySnapshot returns a copy of the cached ip-monitoring
// route overlay.
func (m *Manager) routeOverlaySnapshot() []config.RouteOverlayEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return cloneRouteOverlay(m.routeOverlay)
}

func cloneRouteOverlay(overlay []config.RouteOverlayEntry) []config.RouteOverlayEntry {
	if overlay == nil {
		return nil
	}
	out := make([]config.RouteOverlayEntry, len(overlay))
	copy(out, overlay)
	return out
}

// SetRouteOverlay caches the ip-monitoring effective-route overlay for
// the next full snapshot build WITHOUT publishing. The daemon calls
// this at the top of applyConfigLocked (holding applySem) so an
// operator commit while a policy is FAILED rebuilds routes with the
// active overlay instead of wiping the injected route (#1827, AGY
// r2-2).
func (m *Manager) SetRouteOverlay(overlay []config.RouteOverlayEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routeOverlay = cloneRouteOverlay(overlay)
}

// feedSnapshotOverlay returns a deep copy of the cached dynamic-address
// feed-prefix overlay (#2049). Read under m.mu, mirroring
// routeOverlaySnapshot, so the full snapshot build sees a stable view.
func (m *Manager) feedSnapshotOverlay() map[string][]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return cloneFeedOverlay(m.feedOverlay)
}

func cloneFeedOverlay(overlay map[string][]string) map[string][]string {
	if overlay == nil {
		return nil
	}
	out := make(map[string][]string, len(overlay))
	for name, prefixes := range overlay {
		cp := make([]string, len(prefixes))
		copy(cp, prefixes)
		out[name] = cp
	}
	return out
}

// SetFeedSnapshots caches the dynamic-address feed-prefix overlay for the
// next full snapshot build WITHOUT publishing (#2049). The daemon calls this
// at the top of applyConfigLocked (holding applySem) with the live feed
// snapshots joined to the address-name bindings, so an operator commit OR a
// feed onUpdate rebuilds the address book with the current feed prefixes.
// Mirrors SetRouteOverlay. The overlay is deep-copied so the caller may reuse
// or mutate its map afterwards.
func (m *Manager) SetFeedSnapshots(overlay map[string][]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.feedOverlay = cloneFeedOverlay(overlay)
}

// PublishRouteOverlaySnapshot republishes the userspace snapshot with
// the routes section rebuilt under the given ip-monitoring overlay
// (#1827 PR-1b §4.3, modeled on the policy-scheduler partial republish
// above). It must NOT call Compile (which detaches links / restarts
// the helper): it clones lastSnapshot, refreshes Routes via
// buildRouteSnapshots with the overlay, bumps the generation, and
// reuses the apply_snapshot hash/publish bookkeeping. An overlay whose
// snapshot content is identical to the last published one is skipped
// (duplicate-publish skip) and reported as success.
//
// Ordering contract (AGY r2-1): the caller (the daemon's routes-only
// actuator) must call BumpFIBGeneration ONLY after this returns
// published=true with a nil error — bumping before the helper has the
// new routes would re-resolve flows against the OLD routes and the
// later snapshot would not re-invalidate them; bumping after a
// duplicate-skip would churn established-flow route caches for
// nothing (Codex PR #1843 MED).
//
// schedulerState refreshes the policy snapshots in the same publish
// when non-nil; nil keeps the manager's current scheduler view.
func (m *Manager) PublishRouteOverlaySnapshot(cfg *config.Config, overlay []config.RouteOverlayEntry, schedulerState map[string]bool) (published bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// #3760: do NOT advance the cached desired overlay before the publish
	// is known not to have failed. buildRouteSnapshots below builds
	// against this local copy; m.routeOverlay is committed only on a
	// non-error return (deferred commit). A failed apply_snapshot
	// therefore leaves m.routeOverlay at the last-applied baseline, so
	// the next actuator sweep rebuilds the same new routes, sees a hash
	// mismatch against the still-old lastSnapshotHash, and re-publishes
	// (#3757 dirty-retry contract). Mirrors the mutate-after-success
	// pattern (#3766/#3742/#3757): the cache never records an overlay the
	// dataplane never accepted. The nil-error early returns below
	// (no published snapshot yet, helper not running) still commit the
	// overlay so the next full apply carries it; the duplicate-skip
	// return commits a content-equivalent overlay.
	desiredOverlay := cloneRouteOverlay(overlay)
	defer func() {
		if err == nil {
			m.routeOverlay = desiredOverlay
		}
	}()

	if schedulerState != nil {
		m.policySchedulerActive = copyPolicySchedulerActiveState(schedulerState)
	}

	if cfg == nil {
		if m.lastSnapshot == nil {
			return false, nil
		}
		cfg = m.lastSnapshot.Config
	}
	if cfg == nil || m.lastSnapshot == nil {
		// No published snapshot yet: the overlay is cached (deferred
		// commit) and the next full apply will carry it.
		return false, nil
	}
	if m.proc == nil || m.proc.Process == nil {
		return false, nil
	}

	if err := m.ensureRequiredSnapshotProtocolLocked(cfg); err != nil {
		if disarmErr := m.disarmSnapshotProtocolFailureLocked(err); disarmErr != nil {
			slog.Warn("userspace: failed to disarm helper after refusing overlay publish",
				"protocol_err", err, "err", disarmErr)
		}
		return false, fmt.Errorf("refusing route overlay publish to incompatible helper: %w", err)
	}

	next := *m.lastSnapshot
	nextGeneration := m.generation + 1
	next.Generation = nextGeneration
	next.FIBGeneration = m.readFIBGeneration()
	next.GeneratedAt = time.Now().UTC()
	next.Config = cfg
	// #3772 (M9): a transient ip-rule enumeration failure aborts the
	// overlay publish (fail-closed). The deferred commit above leaves
	// m.routeOverlay at the last-applied baseline on a non-nil err, so the
	// next actuator sweep rebuilds and re-publishes (#3757 dirty-retry).
	next.Routes, err = buildRouteSnapshots(cfg, next.Interfaces, desiredOverlay)
	if err != nil {
		return false, fmt.Errorf("build route overlay snapshot: %w", err)
	}

	// Duplicate-publish skip: identical content (e.g. the actuator ran
	// twice for the same overlay) does not need a control-socket
	// round-trip. The content hash excludes Generation/FIBGeneration.
	if h, ok := snapshotContentHash(&next); ok && h == m.lastSnapshotHash {
		slog.Debug("userspace: route overlay publish skipped (content unchanged)")
		return false, nil
	}

	publishSnap := next
	publishSnap.Neighbors = filterPublishableNeighbors(next.Neighbors)
	var status ProcessStatus
	// #2124: disarm before publishing an unsupported-config snapshot.
	if err := m.disarmBeforeUnsupportedPublishLocked(&next); err != nil {
		return false, err
	}
	if err := m.requestLocked(ControlRequest{Type: "apply_snapshot", Snapshot: &publishSnap}, &status); err != nil {
		return false, fmt.Errorf("publish route overlay snapshot: %w", err)
	}
	m.logWgEndpointSetTransitionLocked(&publishSnap, "route-overlay")
	m.generation = nextGeneration
	m.lastSnapshot = &next
	m.rebuildNeighborIndex()
	m.rebuildMonitoredIfindexes()
	m.publishedSnapshot = next.Generation
	m.publishedPlanKey = snapshotBindingPlanKey(&next)
	// #2079: full apply_snapshot succeeded — record the applied snapshot.
	m.markAppliedSnapshotLocked()
	if h, ok := snapshotContentHash(&next); ok {
		m.lastSnapshotHash = h
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		slog.Warn("userspace: failed to sync helper status after route overlay publish", "err", err)
	}
	slog.Info("userspace: route overlay snapshot published",
		"generation", next.Generation, "overlay_routes", len(desiredOverlay))
	return true, nil
}
