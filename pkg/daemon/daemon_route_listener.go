package daemon

import (
	"context"
	"log/slog"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/coalesce"
	"github.com/psaab/xpf/pkg/routing"
)

// #7437: drive a helper-FIB refresh from kernel route events.
//
// THE GAP THIS CLOSES. #7409's ImportLearnedRoutes makes the helper FIB agree
// with the kernel FIB, but the snapshot was only republished on an operator
// commit or an ip-monitoring actuation. A route the kernel learned in between
// stayed absent from the helper FIB, so traffic for it resolved NoRoute and
// took the unadjudicated reinject #7409 exists to stop — forwarded by the
// kernel with no zone policy, session, NAT or screen. The window is bounded by
// "time to the next commit", which on a quiet box with a flapping BGP peer is
// unbounded in practice.
//
// IT MUST NOT PUSH PER EVENT, and that constraint shapes everything here.
// Every publish is a full snapshot replace over a control socket whose
// deadline scales with payload size, and CLAUDE.md's rule is explicit that a
// new caller above 1/s starves session installs during bulk sync. Under BGP
// churn a per-event push is a control-plane brownout, and the failure mode is
// not a visible error. So events only ever MARK; the bounded actuation is
// pkg/coalesce's, whose rate bound is asserted there against an injected clock.
//
// STALE-ABSENT IS THE EXPOSURE. A route the kernel withdrew but the helper
// still holds is self-healing — the helper forwards, gets MissingNeighbor, and
// reinjects, and that arm enforces zone policy (#4024). Both cases mark
// identically here rather than being distinguished, precisely so handling the
// benign one cannot complicate the one that matters.
//
// NOT ADDRESSED HERE: the per-publish snapshot SIZE. This changes how often
// a full snapshot replace happens, not how big one is, and a box holding a
// full BGP table would push hundreds of thousands of entries every time.
// That ceiling needs a measurement nobody has taken and is tracked as #8355;
// the listener's correctness does not depend on its value.

// routeRefreshDebounce / routeRefreshThrottle mirror pkg/ipmon's values, which
// are the in-tree precedent for coalescing an expensive republish rather than
// an independent choice.
const (
	routeRefreshDebounce = coalesce.DefaultDebounce
	routeRefreshThrottle = coalesce.DefaultThrottle
)

// routeEventWarrantsRefresh reports whether a kernel route event should mark
// the helper FIB dirty.
//
// The imported-table set is NOT re-derived here: it comes from
// routing.LearnedRouteTableIDs, the same function buildRouteSnapshots feeds to
// the importer. A second copy of "which tables do we import" is a rule that
// can disagree with the importer, and a listener that marks for a table the
// importer ignores burns publishes for nothing while one that skips a table
// the importer reads leaves exactly the window this issue is about.
func routeEventWarrantsRefresh(tableID int, importedTableIDs []int) bool {
	for _, id := range importedTableIDs {
		if id == tableID {
			return true
		}
	}
	return false
}

// routeListener subscribes to kernel route events and marks the coalescer.
//
// Subscription lifetime and resubscribe-on-error follow
// daemon_neighbor_listener.go, which is the working sibling for this shape.
func (d *Daemon) routeListener(ctx context.Context, loop *coalesce.Loop) {
	loop.SetTimings(routeRefreshDebounce, routeRefreshThrottle)
	d.routeListenerLoop.Store(loop)
	loop.Start()
	defer loop.Stop()

	for {
		if ctx.Err() != nil {
			return
		}
		if err := d.runOneRouteSubscription(ctx, loop); err != nil {
			slog.Warn("route listener: subscription ended; resubscribing", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// runOneRouteSubscription owns ONE RouteSubscribe lifetime.
func (d *Daemon) runOneRouteSubscription(ctx context.Context, loop *coalesce.Loop) error {
	updates := make(chan netlink.RouteUpdate, 256)
	done := make(chan struct{})
	defer close(done)

	if err := netlink.RouteSubscribeWithOptions(updates, done, netlink.RouteSubscribeOptions{
		ListExisting: false,
		ErrorCallback: func(err error) {
			slog.Debug("route listener: netlink error", "err", err)
		},
	}); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case upd, ok := <-updates:
			if !ok {
				return nil
			}
			if !routeEventWarrantsRefresh(upd.Route.Table, d.importedRouteTableIDs()) {
				continue
			}
			// MARK only. The publish is the coalescer's decision, never this
			// goroutine's — see the per-event note above.
			d.routeListenerMarks.Add(1)
			loop.Mark()
		}
	}
}

// importedRouteTableIDs returns the tables the learned-route importer reads,
// derived from the active config through the importer's own helper.
func (d *Daemon) importedRouteTableIDs() []int {
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return routing.LearnedRouteTableIDs(nil)
	}
	instance := make([]int, 0, len(cfg.RoutingInstances))
	for _, inst := range cfg.RoutingInstances {
		if inst != nil {
			instance = append(instance, inst.TableID)
		}
	}
	return routing.LearnedRouteTableIDs(instance)
}

// actuateLearnedRouteRefresh republishes the routes-only snapshot so the
// helper FIB picks up routes the kernel has learned since the last publish.
//
// It deliberately does NOT touch FRR and does NOT change the ip-monitoring
// overlay: the overlay is passed through as the ipmon engine currently holds
// it, so this is a pure re-read of the kernel FIB. That is why it is safe to
// run on a route event — the only thing that changes is the learned-route set
// buildRouteSnapshots imports (#7409), and a redundant republish is idempotent.
//
// Returns whether it CONVERGED, in pkg/coalesce's contract: false keeps the
// state dirty and the loop retries on the next throttle-paced sweep rather
// than losing the event.
func (d *Daemon) actuateLearnedRouteRefresh(ctx context.Context) bool {
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return false
	}
	defer d.applySem.Release(1)

	cfg := d.store.ActiveConfig()
	if cfg == nil {
		// Nothing committed yet: nothing to republish, and the first commit
		// will publish anyway. Converged.
		return true
	}
	pub, ok := d.dataplane().(routeOverlayPublisher)
	if !ok {
		// Helperless build: FRR is the only routing consumer. Converged.
		return true
	}
	var schedulerState map[string]bool
	if sched := d.scheduler.Load(); sched != nil {
		schedulerState = sched.ActiveState()
	}
	// Bounded by the coalescer's throttle (one per 3 s at worst), so this is
	// a state-transition log rather than a per-event one — CLAUDE.md's rule is
	// about the latter. It is also the only operator-visible signal that the
	// listener is doing anything: nothing else exposes the helper's
	// learned-route set.
	slog.Debug("route listener: republishing routes-only snapshot after kernel route change")
	if _, err := pub.PublishRouteOverlaySnapshot(cfg, d.ipmonActiveOverlay(), schedulerState); err != nil {
		slog.Warn("route listener: routes-only republish failed — staying dirty for retry",
			"err", err)
		return false
	}
	return true
}

// RouteListenerMarks and RouteListenerRepublishes surface the #7437 pair for
// the xpf_route_listener_* metrics. Reported together because either alone is
// unreadable: republishes without marks cannot distinguish "no route churn"
// from "the listener is dead", and marks without republishes cannot show the
// coalescing that keeps the control socket safe.
func (d *Daemon) RouteListenerMarks() uint64 { return d.routeListenerMarks.Load() }

func (d *Daemon) RouteListenerRepublishes() uint64 {
	if l := d.routeListenerLoop.Load(); l != nil {
		return l.Actuations()
	}
	return 0
}
