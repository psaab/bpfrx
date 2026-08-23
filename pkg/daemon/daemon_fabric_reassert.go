package daemon

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// fabricIPVLANReassertInterval paces the fabric-overlay retry owner (#6791).
//
// 30s matches proxyARPReassertLoop and raDeadSenderReassertLoop. The fabric
// overlay carries cluster heartbeat and session sync, so a faster cadence is
// tempting — but the cluster's own 2s reconcile already re-drives a great deal,
// and the gap this loop exists to close is a boot-time netlink failure that
// otherwise persists until an operator commits. Minutes of exposure become
// seconds; a tighter tick would buy little and cost a netlink read per fab
// device per tick forever.
var fabricIPVLANReassertInterval = 30 * time.Second

// fabricEnsureFn is the overlay-creation entry point, overridable in tests so
// the retry owner can be observed without a real IPVLAN. Package-level rather
// than a Daemon field because ensureFabricIPVLAN is a package function and the
// apply path calls it directly; routing BOTH through one seam is what makes the
// re-drive assertable.
var fabricEnsureFn = ensureFabricIPVLAN

// fabricIPVLANRetryDelay spaces applyFabricIPVLAN's in-line retries. A var so a
// test can drive the retries-exhausted path without five real seconds of sleep;
// production keeps 1s.
var fabricIPVLANRetryDelay = time.Second

// fabricIPVLANReassertLoop is the persistent recovery owner the fabric overlay
// did not have (#6791).
//
// applyFabricIPVLAN retries five times at 1s and then gives up. Standalone and
// cluster nodes alike apply the fabric overlay ONLY from a config apply, so a
// netlink failure that outlasts those five seconds — a parent NIC still being
// renamed after a power cycle is the motivating case — left fab0/fab1 absent
// until an operator happened to commit. The node then had no cluster heartbeat
// and no session-sync transport, having reported (before this change) a
// successful commit.
//
// It is also the only owner that can cover the DEFERRED overlays: when the
// userspace dataplane is active, creation is postponed to the OnXSKBound
// callback, which runs after the apply has returned, so its failure cannot
// reach the commit result at all.
//
// Always-on and mode-agnostic, mirroring the two sibling loops: it re-reads the
// active config each tick rather than capturing one at start, so a fabric
// interface added or removed by a later commit is picked up without a restart.
func (d *Daemon) fabricIPVLANReassertLoop(ctx context.Context) {
	t := time.NewTicker(fabricIPVLANReassertInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.reassertFabricIPVLANOnce(ctx)
		}
	}
}

// missingFabricOverlays returns the configured fabric overlays that are absent
// or down, as (parent, name, addrs) triples ready for ensureFabricIPVLAN.
//
// This is the CHEAP gate. On a healthy node it is one netlink name lookup per
// configured fab device — at most two — and returns nothing, so the loop costs
// effectively nothing when everything is up. It deliberately does NOT verify
// the parent index, MTU or addresses: those are ensureFabricIPVLAN's job and
// re-running it for a cosmetic drift would restart a working overlay every
// tick. The gate answers only "is there a usable fab device at all".
func (d *Daemon) missingFabricOverlays(cfg *config.Config) []deferredIPVLAN {
	var out []deferredIPVLAN
	config.RangeInterfaces(cfg, func(ifName string, ifCfg *config.InterfaceConfig) {
		if ifCfg.LocalFabricMember == "" || !strings.HasPrefix(ifName, "fab") {
			return
		}
		fabLinux := config.LinuxIfName(ifName)
		link, err := d.fabricLinkByName(fabLinux)
		if err == nil && link != nil && link.Attrs() != nil &&
			link.Attrs().Flags&net.FlagUp != 0 {
			return // present and administratively up — nothing to do
		}
		var addrs []string
		if unit, ok := config.LookupUnit(ifCfg, 0); ok {
			addrs = unit.Addresses
		}
		out = append(out, deferredIPVLAN{
			parent: config.LinuxIfName(ifCfg.LocalFabricMember),
			name:   fabLinux,
			addrs:  addrs,
		})
	})
	return out
}

// reassertFabricIPVLANOnce re-creates one round of missing fabric overlays.
//
// It takes applySem BEFORE reading ActiveConfig, for the reason #4001 gave the
// proxy-ARP loop: reading the config outside the semaphore lets a tick capture a
// PRE-commit snapshot and re-assert state a concurrent commit has just removed —
// here, re-creating a fab device for a fabric interface the operator had just
// deleted, which the commit's own stale-overlay sweep had torn down moments
// before.
//
// The gate is re-run INSIDE the semaphore. The pre-check outside it is only an
// optimisation to avoid queueing behind a commit for nothing; a commit that
// lands in between may already have created the overlay, and re-running
// ensureFabricIPVLAN then would be a gratuitous rebuild of a working device.
func (d *Daemon) reassertFabricIPVLANOnce(ctx context.Context) {
	if d.store == nil {
		return
	}
	if cfg := d.store.ActiveConfig(); cfg == nil || len(d.missingFabricOverlays(cfg)) == 0 {
		return // cheap path: nothing configured, or everything already up
	}
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return // ctx cancelled (daemon shutdown) — do not reconcile.
	}
	defer d.applySem.Release(1)

	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	for _, ov := range d.missingFabricOverlays(cfg) {
		slog.Warn("fabric IPVLAN missing — re-asserting",
			"parent", ov.parent, "name", ov.name)
		if err := fabricEnsureFn(ov.parent, ov.name, ov.addrs); err != nil {
			slog.Error("fabric IPVLAN re-assert failed; will retry",
				"parent", ov.parent, "name", ov.name, "err", err)
			continue
		}
		slog.Info("fabric IPVLAN re-asserted", "parent", ov.parent, "name", ov.name)
	}
}
