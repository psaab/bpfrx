// daemon_ipmon.go — services ip-monitoring wiring (#1827 PR-1b).
//
// The single decision point is the ipmon engine's effective-route
// overlay; this file owns the two consumers' plumbing:
//
//  1. assembleFRRConfig — the SOLE frr.FullConfig constructor, shared
//     by the full apply path (applyConfigLocked step 3) and the
//     routes-only actuator, so the two paths cannot drift and an
//     unrelated operator commit can never wipe an active failover
//     route (AGY r2-2).
//  2. actuateRouteOverlay — the routes-only actuator: under the SAME
//     apply semaphore as operator commits it re-renders FRR, publishes
//     the dataplane snapshot via PublishRouteOverlaySnapshot, and ONLY
//     after a successful publish bumps the FIB generation (ordering is
//     load-bearing, AGY r2-1: bumping first would re-resolve flows
//     against the OLD routes and the later snapshot would not
//     re-invalidate them — traffic would stay pinned to the dead
//     uplink). It touches NOTHING else: no networkd, no ipsec, no RPM
//     re-apply, no cluster/heartbeat paths.
package daemon

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/ipmon"
	"github.com/psaab/xpf/pkg/rpm"
)

// routeOverlaySetter caches the overlay for full snapshot builds.
type routeOverlaySetter interface {
	SetRouteOverlay([]config.RouteOverlayEntry)
}

// routeOverlayPublisher is the routes-only partial republish surface
// of the userspace dataplane manager (#1827 Codex r2-2).
type routeOverlayPublisher interface {
	// PublishRouteOverlaySnapshot returns whether a snapshot was
	// actually published; duplicate-skips return false so the caller
	// does not bump the FIB generation for a no-op (Codex PR #1843
	// MED).
	PublishRouteOverlaySnapshot(cfg *config.Config, overlay []config.RouteOverlayEntry, schedulerState map[string]bool) (bool, error)
	// BumpFIBGeneration reports whether the helper-side invalidation
	// was confirmed (#1844 plan §4.3, Codex r2-1): a non-nil error
	// feeds the actuator's pendingFIBBump retry — without it, a
	// publish-success/bump-failure ordering followed by a duplicate
	// (hash-skipped) actuation would strand cached flow routes on the
	// pre-failover paths forever.
	BumpFIBGeneration() (uint32, error)
}

// ipmonActiveOverlay returns the engine's current effective-route
// overlay (nil when the engine is absent or publication is gated off).
func (d *Daemon) ipmonActiveOverlay() []config.RouteOverlayEntry {
	if d.ipmon == nil {
		return nil
	}
	return d.ipmon.ActiveOverlay()
}

// commitOverlayForConfig returns the overlay that may ride an
// operator commit's OWN publish: the engine's active overlay filtered
// against the INCOMING config (Codex PR #1843 HIGH-1). The full apply
// caches the overlay before reconcileIPMon installs the new policy
// set, so entries whose policy was removed or whose preferred-route
// spec was edited must be dropped here — otherwise the commit would
// republish the stale overlay to FRR and the snapshot until the
// delayed actuator caught up. Unrelated commits (policy spec
// unchanged) keep the active overlay intact (AGY r2-2).
func (d *Daemon) commitOverlayForConfig(cfg *config.Config) []config.RouteOverlayEntry {
	if cfg == nil {
		return nil
	}
	return ipmon.FilterOverlayForConfig(d.ipmonActiveOverlay(), cfg.Services.IPMonitoring)
}

// assembleFRRConfig builds the complete frr.FullConfig for the given
// compiled config plus the ip-monitoring overlay. It is the sole
// constructor for BOTH the full apply path and the routes-only
// actuator (the complete contract: static routes, generate-routes,
// DHCP routes, policy export, backup-router, interface hints, RethMap,
// IPv6 next-hop interfaces, ClusterMode, per-VRF instances, and the
// overlay's PreferredRoutes).
func (d *Daemon) assembleFRRConfig(cfg *config.Config, overlay []config.RouteOverlayEntry) *frr.FullConfig {
	// Collect interface bandwidths and point-to-point flags for FRR.
	ifaceBandwidths := make(map[string]uint64)
	ifaceP2P := make(map[string]bool)
	for name, ifc := range cfg.Interfaces.Interfaces {
		linuxName := config.LinuxIfName(name)
		if ifc.Bandwidth > 0 {
			ifaceBandwidths[linuxName] = ifc.Bandwidth
		}
		for _, unit := range ifc.Units {
			if unit.PointToPoint {
				ifaceP2P[linuxName] = true
			}
		}
	}

	fc := &frr.FullConfig{
		OSPF:                  cfg.Protocols.OSPF,
		OSPFv3:                cfg.Protocols.OSPFv3,
		BGP:                   cfg.Protocols.BGP,
		RIP:                   cfg.Protocols.RIP,
		ISIS:                  cfg.Protocols.ISIS,
		StaticRoutes:          cfg.RoutingOptions.StaticRoutes,
		Inet6StaticRoutes:     cfg.RoutingOptions.Inet6StaticRoutes,
		GenerateRoutes:        cfg.RoutingOptions.GenerateRoutes,
		DHCPRoutes:            d.collectDHCPRoutes(),
		PolicyOptions:         &cfg.PolicyOptions,
		ForwardingTableExport: cfg.RoutingOptions.ForwardingTableExport,
		BackupRouter:          cfg.System.BackupRouter,
		BackupRouterDst:       cfg.System.BackupRouterDst,
		InterfaceBandwidths:   ifaceBandwidths,
		InterfacePointToPoint: ifaceP2P,
		RethMap:               cfg.RethToPhysical(),
		IPv6NextHopInterfaces: inferIPv6StaticNextHopInterfaces(cfg),
		ClusterMode:           d.cluster != nil,
		PreferredRoutes:       overlay,
	}
	for _, ri := range cfg.RoutingInstances {
		vrfName := "vrf-" + ri.Name
		tableID := 0
		if ri.InstanceType == "forwarding" {
			// Forwarding instances have no VRF device; their statics
			// render into the instance's dedicated kernel table so the
			// kernel agrees with the FBF/PBR ip rules AND the userspace
			// dataplane's `<ri>.inet.0` snapshot table (#1827 PR-2
			// divergence fix — previously these leaked into the default
			// table).
			vrfName = ""
			tableID = ri.TableID
		}
		fc.Instances = append(fc.Instances, frr.InstanceConfig{
			Name:              ri.Name,
			VRFName:           vrfName,
			TableID:           tableID,
			OSPF:              ri.OSPF,
			OSPFv3:            ri.OSPFv3,
			BGP:               ri.BGP,
			RIP:               ri.RIP,
			ISIS:              ri.ISIS,
			StaticRoutes:      ri.StaticRoutes,
			Inet6StaticRoutes: ri.Inet6StaticRoutes,
		})
	}
	return fc
}

// applyFRRConfig applies an assembled FullConfig and handles the
// shared post-ApplyFull consistent-hash sysctl. Both the full apply
// path and the actuator go through here.
func (d *Daemon) applyFRRConfig(fc *frr.FullConfig) {
	if d.frr == nil {
		return
	}
	// Warn-and-continue on FRR reload problems: an FRR hiccup must not
	// fail an otherwise-valid commit. Degraded (#1880) means the config
	// WAS applied additively and the manager's retry loop owns
	// convergence of stale-config removal; the gauge
	// xpf_frr_reload_degraded is 1 until it converges.
	if err := d.frr.ApplyFull(fc); err != nil {
		if errors.Is(err, frr.ErrFRRReloadDegraded) {
			slog.Warn("FRR reload degraded: additive vtysh -f applied; stale-config removal deferred to the in-manager retry", "err", err)
		} else {
			slog.Warn("failed to apply FRR config", "err", err)
		}
	}

	// Set L4 ECMP hash when consistent-hash is configured.
	if fc.ConsistentHash {
		setFibMultipathHashPolicy()
	}
}

// setFibMultipathHashPolicy enables L4 (5-tuple) ECMP hashing by writing
// net.ipv4.fib_multipath_hash_policy=1 when it is not already set.
// BestEffortKernelKnob procfs write — rename(2) is impossible on procfs, so
// it stays a direct os.WriteFile. Extracted from applyFRRConfig (#1916
// §2.D) so the enclosing function is never allowlisted in the fsatomic
// canary; this single-purpose helper is.
func setFibMultipathHashPolicy() {
	path := "/proc/sys/net/ipv4/fib_multipath_hash_policy"
	current, _ := os.ReadFile(path)
	if strings.TrimSpace(string(current)) != "1" {
		if err := os.WriteFile(path, []byte("1\n"), 0644); err != nil {
			slog.Warn("failed to set fib_multipath_hash_policy", "err", err)
		} else {
			slog.Info("enabled L4 ECMP hashing (consistent-hash)")
		}
	}
}

// actuateRouteOverlay is the routes-only actuator (#1827 plan §4.3,
// Path D-routes-only). Invoked from the ipmon engine's single run-loop
// goroutine after debounce + throttle; the engine guarantees at most
// one invocation in flight. It snapshots the overlay at run time
// (last-writer-wins under flap storms).
func (d *Daemon) actuateRouteOverlay() {
	_ = d.applySem.Acquire(context.Background(), 1)
	defer d.applySem.Release(1)

	if d.store == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	d.actuateRouteOverlayLocked(cfg)
}

// actuateRouteOverlayLocked is the actuator body; MUST be called with
// d.applySem held. Split out so the publish-before-bump ordering is
// directly testable.
func (d *Daemon) actuateRouteOverlayLocked(cfg *config.Config) {
	overlay := d.ipmonActiveOverlay()

	// 1. Re-render FRR through the shared constructor.
	d.applyFRRConfig(d.assembleFRRConfig(cfg, overlay))

	// 2. Publish the dataplane snapshot (routes-only partial republish,
	// no Compile, no helper restart).
	pub, ok := d.dp.(routeOverlayPublisher)
	if !ok {
		return
	}
	var schedulerState map[string]bool
	if d.scheduler != nil {
		schedulerState = d.scheduler.ActiveState()
	}
	published, err := pub.PublishRouteOverlaySnapshot(cfg, overlay, schedulerState)
	if err != nil {
		// pendingFIBBump deliberately unchanged: a pending retry from
		// an earlier bump failure stays pending across a failed
		// publish.
		slog.Warn("ip-monitoring: route overlay snapshot publish failed — NOT bumping FIB generation",
			"err", err)
		return
	}
	if !published && !d.pendingFIBBump {
		// Duplicate-skip (content unchanged) or helperless caching:
		// the dataplane routes did not move and the previous bump was
		// confirmed, so do not churn established-flow route caches
		// with a FIB-generation bump (Codex PR #1843 MED).
		return
	}

	// 3. Only after a REAL apply_snapshot success (or with an
	// unconfirmed bump pending from an earlier actuation, #1844 Codex
	// r2-1): invalidate cached flow routes so established flows
	// re-resolve onto the new routes. pendingFIBBump is mutated only
	// here, under d.applySem — no extra locking.
	if _, err := pub.BumpFIBGeneration(); err != nil {
		d.pendingFIBBump = true
		slog.Warn("ip-monitoring: FIB generation bump unconfirmed — will retry on next actuation",
			"err", err)
		return
	}
	d.pendingFIBBump = false
	if !published {
		slog.Info("ip-monitoring: retried FIB generation bump after earlier failure")
		return
	}
	slog.Info("ip-monitoring route overlay actuated", "overlay_routes", len(overlay))
}

// reconcileIPMon applies the committed ip-monitoring policy set to the
// engine (preserving FAIL state across unrelated commits) and seeds it
// with the current probe results. Runs as a late applyConfigLocked
// step, after reconcileRPM has the probe set running.
func (d *Daemon) reconcileIPMon(cfg *config.Config) {
	if d.ipmon == nil || cfg == nil {
		return
	}
	var results []*rpm.ProbeResult
	if d.rpm != nil {
		results = d.rpm.Results()
	}
	d.ipmon.Apply(cfg.Services.IPMonitoring, results)
}

// ipmonPublishAllowed implements §4.4 primary-only overlay
// publication: standalone nodes always publish; cluster nodes publish
// only while primary for the data RG.
func (d *Daemon) ipmonPublishAllowed(cfg *config.Config) bool {
	if d.cluster == nil || cfg == nil || cfg.Chassis.Cluster == nil {
		return true
	}
	return d.cluster.IsLocalPrimary(lowestDataRG(cfg))
}

// reconcileIPMonGating re-evaluates HA gating after an RG transition:
// the probe set (gated probes run only on the primary) and the overlay
// publication gate. On takeover the engine re-seeds from the freshly
// restarted probes' results (all unknown ⇒ baseline first), and the
// overlay follows the first fresh failure transitions — the plan's
// baseline-then-fast-probe takeover semantics.
func (d *Daemon) reconcileIPMonGating() {
	if d.store == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	// Hash-gated: only re-applies when the gating filter actually
	// changed the effective probe set.
	changed := d.reconcileRPM(cfg)
	if d.ipmon == nil {
		return
	}
	if changed {
		// Probe set changed (gated probes started/stopped): re-seed
		// the engine from the fresh results so stale FAIL state from
		// the pre-transition probe set cannot inject routes.
		d.reconcileIPMon(cfg)
	}
	d.ipmon.SetPublishEnabled(d.ipmonPublishAllowed(cfg))
}
