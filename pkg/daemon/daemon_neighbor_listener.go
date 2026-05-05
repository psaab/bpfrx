// Package daemon: neighbor listener + force-probe (issue #1197).
//
// This file implements the event-driven kernel-as-authority
// neighbor reconciliation that replaces the buggy periodic
// preinstall mechanism.
//
// Design (per docs/pr/1197-neighbor-snapshot/plan.md v7):
//
//   1. neighborListener subscribes to RTM_NEWNEIGH/DELNEIGH netlink
//      events; on relevant changes (MAC change, eviction, transition
//      to unusable) triggers Manager.RegenerateNeighborSnapshot()
//      via a 100ms debouncer.
//
//   2. forceProbeNeighbors periodically (15s tick) sends ARP/NS
//      probes for all monitored neighbors INCLUDING those in
//      NUD_STALE/PROBE/DELAY (unlike resolveNeighbors which skips
//      them). Probe replies update kernel ARP → RTM_NEWNEIGH fires
//      → listener regenerates snapshot.
//
//   3. On RG takeover (VRRP MASTER), forceProbeNeighbors is called
//      to re-validate stale entries on the new active.
//
// Trust model: kernel ARP/NDP is authoritative; xpfd listens and
// proactively probes. xpfd no longer pushes neighbor entries into
// the kernel table.
package daemon

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"os"
	"sort"
	"strconv"
	"syscall"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/vishvananda/netlink"
)

// usableNUD is the set of NUD states userspace-dp treats as
// usable for forwarding. MUST mirror the Rust accept rules at
// userspace-dp/src/server/handlers.rs:165 and
// userspace-dp/src/afxdp/forwarding/mod.rs:45.
//
// NUD_NONE (state==0) is INTENTIONALLY excluded — Rust treats
// "none" as usable but state-0 entries have no learned MAC info,
// so we filter them out at publish time
// (see neighborSnapshotPublishable in pkg/dataplane/userspace).
const usableNUD = netlink.NUD_REACHABLE | netlink.NUD_STALE |
	netlink.NUD_DELAY | netlink.NUD_PROBE |
	netlink.NUD_PERMANENT | netlink.NUD_NOARP

// neighborProbeMaxTargetsDefault caps the per-tick force-probe
// target count by default. Override via env
// BPFRX_NEIGHBOR_PROBE_MAX_TARGETS for sites with very large
// address-books. Read once via getNeighborProbeMaxTargets.
const neighborProbeMaxTargetsDefault = 256

// getNeighborProbeMaxTargets returns the per-tick probe-target
// cap, honoring BPFRX_NEIGHBOR_PROBE_MAX_TARGETS env override.
// Invalid / non-positive values fall back to the default.
func getNeighborProbeMaxTargets() int {
	if v := os.Getenv("BPFRX_NEIGHBOR_PROBE_MAX_TARGETS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return neighborProbeMaxTargetsDefault
}

// neighborSnapshotProvider is the dataplane Manager interface
// used by the listener to query/regenerate snapshot state.
type neighborSnapshotProvider interface {
	RegenerateNeighborSnapshot()
	LookupSnapshotNeighbor(ifindex int, ip net.IP) *userspace.NeighborSnapshot
	SnapshotHasIfindex(ifindex int) bool
	IsMonitoredIfindex(ifindex int) bool
}

// neighborListener runs the netlink RTM_NEWNEIGH/DELNEIGH event
// loop. Triggers Manager.RegenerateNeighborSnapshot() when a
// monitored neighbor's forwarding-effective state changes.
//
// Resubscribe loop: kernel multicast can lose events under load;
// runOneSubscription owns one subscription lifetime and returns
// when the subscription closes; the outer loop re-establishes.
//
// Safety net: a 60s ticker triggers full reconciliation
// regardless of events, in case multicast lost the relevant
// notification.
func (d *Daemon) neighborListener(ctx context.Context) {
	regenDebounce := make(chan struct{}, 1)
	debounceMs := 100 * time.Millisecond
	go d.regenDebouncer(ctx, regenDebounce, debounceMs)

	safetyTick := time.NewTicker(60 * time.Second)
	defer safetyTick.Stop()

	for {
		if !d.runOneSubscription(ctx, regenDebounce, safetyTick) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// runOneSubscription owns ONE NeighSubscribe lifetime. Returns
// true on subscription close (caller should retry); false on
// ctx cancellation (caller should exit).
//
// Lifetime guarantee: done is closed exactly once, regardless
// of whether subscribe succeeded, ctx was cancelled, or the
// updates channel was closed. No double-close.
func (d *Daemon) runOneSubscription(
	ctx context.Context,
	regenDebounce chan struct{},
	safetyTick *time.Ticker,
) bool {
	updates := make(chan netlink.NeighUpdate, 1024)
	done := make(chan struct{})
	opts := netlink.NeighSubscribeOptions{
		ListExisting:      true,
		ReceiveBufferSize: 1 << 20, // 1 MB
		ErrorCallback: func(err error) {
			slog.Warn("neighbor listener netlink error", "err", err)
		},
	}
	if err := netlink.NeighSubscribeWithOptions(updates, done, opts); err != nil {
		slog.Warn("neighbor listener subscribe failed", "err", err)
		// NeighSubscribeWithOptions can start its done goroutine
		// before a ListExisting dump request fails; close done
		// explicitly to avoid leaking the goroutine.
		close(done)
		return true
	}
	defer close(done)

	for {
		select {
		case <-ctx.Done():
			return false
		case <-safetyTick.C:
			d.triggerRegen(regenDebounce)
		case u, ok := <-updates:
			if !ok {
				return true // subscription closed; resubscribe
			}
			if !d.isMonitoredNeighbor(u.LinkIndex) {
				continue
			}
			if d.shouldTriggerRegen(u) {
				d.triggerRegen(regenDebounce)
			}
		}
	}
}

// regenDebouncer coalesces regen requests so a burst of events
// (e.g., GARP storm during failover) produces one snapshot
// regeneration. Uses a same-goroutine timer-channel pattern to
// avoid races with time.AfterFunc callbacks.
func (d *Daemon) regenDebouncer(
	ctx context.Context,
	ch chan struct{},
	delay time.Duration,
) {
	var timer *time.Timer
	var timerC <-chan time.Time

	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case <-ch:
			if timer == nil {
				timer = time.NewTimer(delay)
				timerC = timer.C
			} else {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(delay)
				timerC = timer.C
			}
		case <-timerC:
			provider := d.neighborProvider()
			if provider != nil {
				provider.RegenerateNeighborSnapshot()
			}
			timerC = nil
		}
	}
}

// triggerRegen sends a non-blocking signal to the debouncer. If
// a request is already pending, drops this one (the debounced
// regen will see the latest kernel state regardless).
func (d *Daemon) triggerRegen(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// isMonitoredNeighbor returns true if linkIndex belongs to an
// interface enumerated by buildNeighborSnapshots, OR if the
// current snapshot already contains entries for that ifindex
// (snapshot-key fallback for runtime ifindex drift — delete
// events on disappeared links must still be processed).
//
// Codex code-review #2: previously called
// userspace.MonitoredInterfaceLinkIndexes(cfg) on every event,
// which makes O(N) netlink LinkByName calls per N configured
// interfaces. Now reads the cached set from the manager;
// rebuilt only on snapshot publish.
func (d *Daemon) isMonitoredNeighbor(linkIndex int) bool {
	provider := d.neighborProvider()
	if provider == nil {
		return false
	}
	if provider.IsMonitoredIfindex(linkIndex) {
		return true
	}
	if provider.SnapshotHasIfindex(linkIndex) {
		return true
	}
	return false
}

// shouldTriggerRegen filters forwarding-irrelevant churn. Returns
// true when the snapshot should be regenerated; false on harmless
// aging transitions (REACHABLE↔STALE↔DELAY↔PROBE on same MAC).
func (d *Daemon) shouldTriggerRegen(u netlink.NeighUpdate) bool {
	switch u.Type {
	case syscall.RTM_DELNEIGH:
		// Kernel evicted the entry; snapshot must drop it
		// immediately so userspace-dp doesn't keep forwarding
		// to a removed neighbor.
		return true
	case syscall.RTM_NEWNEIGH:
		hasMAC := u.HardwareAddr != nil && len(u.HardwareAddr) > 0
		// Composite-state safety: a state with both REACHABLE and
		// FAILED bits set must NOT be classified as usable. Define
		// usable as: at least one usableNUD bit AND no failed/
		// incomplete bit.
		usable := u.State&usableNUD != 0 &&
			u.State&(netlink.NUD_FAILED|netlink.NUD_INCOMPLETE) == 0
		// "unusable" covers state==0/NONE/FAILED/INCOMPLETE OR
		// composite states that include FAILED/INCOMPLETE.
		unusable := !usable

		provider := d.neighborProvider()
		var existing *userspace.NeighborSnapshot
		if provider != nil {
			existing = provider.LookupSnapshotNeighbor(u.LinkIndex, u.IP)
		}
		if existing == nil {
			// New entry: trigger only if it's publishable.
			return hasMAC && usable
		}
		// MAC change → always trigger (the bug-class case).
		if hasMAC {
			existingMAC, err := net.ParseMAC(existing.MAC)
			if err != nil || !bytes.Equal(existingMAC, u.HardwareAddr) {
				return true
			}
		}
		// Transition to unusable → snapshot must drop entry.
		// Includes NUD_FAILED, NUD_INCOMPLETE, NUD_NONE (state==0).
		if unusable {
			return true
		}
		// Same MAC, still usable: harmless aging churn; skip.
		return false
	}
	return false
}

// neighborProvider returns the dataplane manager's neighbor
// snapshot interface, or nil if the dataplane doesn't expose
// the methods (defensive: tests / non-userspace dataplanes).
func (d *Daemon) neighborProvider() neighborSnapshotProvider {
	if d.dp == nil {
		return nil
	}
	if p, ok := d.dp.(neighborSnapshotProvider); ok {
		return p
	}
	return nil
}

// probeTarget is one entry in the force-probe target list.
type probeTarget struct {
	ip         net.IP
	linkIndex  int
	state      uint16 // current kernel NUD state (bitmask)
	criticality int   // higher = probe earlier within tier
}

// probeTier classifies a target's current state for tiered
// probing: tier1 (most likely to need re-validation) → tier3.
//
// Tier 1: states at risk of stale forwarding
//         (STALE, PROBE, DELAY, FAILED, INCOMPLETE, NONE/missing)
// Tier 2: REACHABLE + critical (next-hop, fabric peer)
// Tier 3: everything else (REACHABLE + non-critical)
func probeTier(state uint16, critical bool) int {
	stale := uint16(netlink.NUD_STALE | netlink.NUD_PROBE |
		netlink.NUD_DELAY | netlink.NUD_FAILED |
		netlink.NUD_INCOMPLETE)
	if state == 0 || state&stale != 0 {
		return 1
	}
	if state&netlink.NUD_REACHABLE != 0 && critical {
		return 2
	}
	return 3
}

// forceProbeNeighbors sends ARP/IPv6 NS probes for all monitored
// neighbor targets, REGARDLESS of NUD state. Distinct from
// resolveNeighborsInner which skips REACHABLE/STALE/PERMANENT —
// that semantics is right for activation priming, but wrong for
// steady-state staleness reconciliation (#1197).
//
// Targets are tier-prioritized (stale-risk first, then critical
// next-hops, then rest) and capped at neighborProbeMaxTargets to
// avoid ARP/NS storms on large address-books.
func (d *Daemon) forceProbeNeighbors(cfg *config.Config) {
	if cfg == nil {
		return
	}
	targets := d.collectMonitoredNeighbors(cfg)
	if len(targets) == 0 {
		return
	}
	cap := getNeighborProbeMaxTargets()
	if len(targets) > cap {
		slog.Warn("neighbor probe truncated",
			"total", len(targets),
			"cap", cap)
		targets = targets[:cap]
	}
	slog.Info("force-probe neighbors", "count", len(targets))
	for _, t := range targets {
		link, err := netlink.LinkByIndex(t.linkIndex)
		if err != nil {
			continue
		}
		ifName := link.Attrs().Name
		go func(ip net.IP, iface string) {
			if ip.To4() == nil {
				if err := cluster.SendNDSolicitationFromInterface(iface, ip); err != nil {
					slog.Debug("force-probe: IPv6 NS failed",
						"iface", iface, "ip", ip, "err", err)
				}
			}
			sendICMPProbe(iface, ip)
		}(t.ip, ifName)
	}
}

// collectMonitoredNeighbors returns the deduped union of all
// targets we want to keep ARP/NDP-warm:
//   1. Snapshot keys (entries we've published to userspace-dp)
//   2. Configured next-hops, NAT destinations, address-book hosts
//      (the resolveNeighborsInner target set)
//   3. Fabric peer IPs
//
// Returned in PRIORITY ORDER (tier1 → tier2 → tier3) where
// tiering is annotated by current kernel NUD state per target.
func (d *Daemon) collectMonitoredNeighbors(cfg *config.Config) []probeTarget {
	type key struct {
		linkIndex int
		ip        string
	}
	seen := make(map[key]bool)
	var targets []probeTarget

	// Helper: NUD state lookup via NeighList per (ifindex, family).
	stateCache := make(map[int]map[string]uint16) // ifindex → ip → state
	getState := func(ifindex int, ip net.IP) uint16 {
		family := netlink.FAMILY_V4
		if ip.To4() == nil {
			family = netlink.FAMILY_V6
		}
		cacheKey := ifindex*2 + family
		if m, ok := stateCache[cacheKey]; ok {
			return m[ip.String()]
		}
		neighs, err := netlink.NeighList(ifindex, family)
		m := make(map[string]uint16)
		if err == nil {
			for _, n := range neighs {
				if n.IP != nil {
					m[n.IP.String()] = uint16(n.State)
				}
			}
		}
		stateCache[cacheKey] = m
		return m[ip.String()]
	}

	addTarget := func(ip net.IP, linkIndex int, critical bool) {
		if ip == nil || linkIndex <= 0 {
			return
		}
		k := key{linkIndex, ip.String()}
		if seen[k] {
			return
		}
		seen[k] = true
		st := getState(linkIndex, ip)
		crit := 0
		if critical {
			crit = 1
		}
		targets = append(targets, probeTarget{
			ip:          ip,
			linkIndex:   linkIndex,
			state:       st,
			criticality: crit,
		})
	}

	// Source 1: snapshot keys
	if provider := d.neighborProvider(); provider != nil {
		// Reach into the manager to enumerate all snapshot entries.
		// We use SnapshotNeighbors() (already exists for fabric work).
		type snapshotEnumerator interface {
			SnapshotNeighbors() []struct {
				Ifindex int
				IP      net.IP
				MAC     net.HardwareAddr
				Family  int
			}
		}
		if e, ok := d.dp.(snapshotEnumerator); ok {
			for _, sn := range e.SnapshotNeighbors() {
				addTarget(sn.IP, sn.Ifindex, false)
			}
		}
	}

	// Source 2: configured next-hops + DHCP gateways + backup
	// router + DNAT pool addresses + static NAT translated
	// addresses + address-book host entries.
	//
	// Codex code-review #1: previously omitted; cold-start path
	// (no snapshot yet) had empty target set so force-probe
	// did nothing. Now uses the shared helper that
	// resolveNeighborsInner also draws from.
	for _, t := range d.collectNeighborProbeTargets(cfg) {
		addTarget(t.neighborIP, t.linkIndex, true)
	}

	// Source 3: fabric peers (probed via fabric overlay link).
	d.fabricMu.RLock()
	fabricPeerIP := d.fabricPeerIP
	fabricPeerIP1 := d.fabricPeerIP1
	fabricOverlay := d.fabricOverlay
	fabricOverlay1 := d.fabricOverlay1
	d.fabricMu.RUnlock()
	if fabricPeerIP != nil && fabricOverlay != "" {
		if link, err := netlink.LinkByName(fabricOverlay); err == nil {
			addTarget(fabricPeerIP, link.Attrs().Index, true)
		}
	}
	if fabricPeerIP1 != nil && fabricOverlay1 != "" {
		if link, err := netlink.LinkByName(fabricOverlay1); err == nil {
			addTarget(fabricPeerIP1, link.Attrs().Index, true)
		}
	}

	// Sort into tier order. Within tier, higher criticality first.
	sort.SliceStable(targets, func(i, j int) bool {
		ti := probeTier(targets[i].state, targets[i].criticality > 0)
		tj := probeTier(targets[j].state, targets[j].criticality > 0)
		if ti != tj {
			return ti < tj
		}
		return targets[i].criticality > targets[j].criticality
	})
	return targets
}

// (collectResolveTargets was sketched here but removed: the
// existing resolveNeighborsInner already covers configured
// next-hops at activation, and snapshot keys cover the
// steady-state set. Re-derivation here would just drift.)
