package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcpserver"
)

// daemon_dhcp_lease_sync.go: the #2239 HA DHCP-server lease-sync push/seed
// orchestration (PATH C). It re-instantiates the IPsec-SA-sync precedent
// (syncIPsecSAPeriodic + reinitiateIPsecSAs) for Kea leases:
//
//   - syncDHCPLeasesPeriodic — the RG-MASTER push loop. A slow heartbeat tick
//     (lease-sync re-push of the full set, so a freshly-restarted standby is
//     never empty) PLUS a fast change-detect tick (an on-grant push: it reads
//     the active set and pushes ONLY when it differs from the last push,
//     bounding the duplicate-allocation window far tighter than the heartbeat
//     interval — Q1). Gated on DHCPLeaseSync + the same node-level MASTER gate
//     the DDNS loop uses (dhcpLeaseSyncGateOpen).
//   - seedDHCPLeasesFromPeer — the takeover seed. After this node becomes
//     MASTER and Kea is (re)started, the held peer lease set is re-anchored to
//     the local clock and written into Kea via lease{4,6}-add (Q3 backstop).
//     The pre-Kea-start memfile pre-seed (which FULLY closes the dup-alloc
//     window) is done by preSeedDHCPLeaseMemfile before the Kea ApplyAsync.
//
// CONTROL-SOCKET RULE (CLAUDE.md): this loop talks to KEA's own unix socket and
// the CLUSTER sync channel only — NEVER the userspace-helper control socket. It
// cannot starve session installs. The push is coalesced (change-detect) and the
// heartbeat is slow, keeping the cluster channel budget well under the
// per-second session sweep.

const (
	// dhcpLeaseSyncHeartbeat is the full-set re-push cadence. It keeps a
	// restarted standby from staying empty (Q7) and bounds steady-state
	// staleness. Matches the IPsec SA 30s parity; far above any control-socket
	// throttle (which it does not touch).
	dhcpLeaseSyncHeartbeat = 30 * time.Second
	// dhcpLeaseSyncChangePoll is the fast change-detect cadence (the on-grant
	// push, Q1). It reads the active lease set and pushes ONLY on a change, so
	// a new grant reaches the standby within this interval, shrinking the
	// duplicate-allocation window from the heartbeat interval to ~2s. A no-op
	// poll is a cheap socket read; an idle DHCP server pushes nothing.
	dhcpLeaseSyncChangePoll = 2 * time.Second
	// dhcpLeaseReadTimeout bounds one lease read pass.
	dhcpLeaseReadTimeout = 5 * time.Second
	// dhcpLeaseSeedSocketWait bounds the post-start control-socket-ready wait
	// before seeding on takeover.
	dhcpLeaseSeedSocketWait = 10 * time.Second
)

// dhcpLeaseSyncEnabled reports whether #2239 lease sync is configured for this
// commit: a cluster with the `dhcp-lease-synchronization` knob set. Standalone
// (no cluster) is always false. Used to gate the Kea control-socket/hook
// emission AND the push loop. The cfg argument carries the just-committed
// config's cluster knob (the daemon's clusterConfig() reads the ACTIVE config,
// which during commitAndApply may lag the candidate being applied).
func (d *Daemon) dhcpLeaseSyncEnabled(cfg *config.Config) bool {
	if d.cluster == nil || cfg == nil || cfg.Chassis.Cluster == nil {
		return false
	}
	return cfg.Chassis.Cluster.DHCPLeaseSync
}

// dhcpLeaseSyncGateOpen reports whether this node should PUSH leases now: the
// node-level MASTER gate, identical in shape to ddnsWriterGateOpen. SOUND
// without per-lease RG attribution for the same reason: the Kea config each
// node serves is MASTER-FILTERED (filterDHCPConfigForMasterRGs), so this node's
// lease set is ONLY its own MASTER-RG leases and the two nodes' sets are
// disjoint by RG ownership. Standalone is never a pusher (the loop never runs).
func (d *Daemon) dhcpLeaseSyncGateOpen() bool {
	if d.cluster == nil {
		return false
	}
	for _, isMaster := range d.snapshotRethMasterState() {
		if isMaster {
			return true
		}
	}
	return false
}

// runDHCPLeaseSyncLoop is the supervised lease-sync push loop. It runs for the
// daemon lifetime (joined via wg) and exits on ctx cancellation. It is started
// only in cluster mode with the knob enabled (see daemon_ha_sync.go).
func (d *Daemon) runDHCPLeaseSyncLoop(ctx context.Context) {
	if d.dhcpServer == nil || d.sessionSync == nil {
		return
	}
	heartbeat := time.NewTicker(dhcpLeaseSyncHeartbeat)
	defer heartbeat.Stop()
	change := time.NewTicker(dhcpLeaseSyncChangePoll)
	defer change.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeat.C:
			// Heartbeat: full re-push regardless of change (defeats the
			// change-detect fingerprint) so a reconnected/restarted standby
			// is refreshed even if the set is unchanged.
			d.dispatchDHCPLeasePush(ctx, true)
		case <-change.C:
			d.dispatchDHCPLeasePush(ctx, false)
		case <-d.dhcpLeaseSyncNowCh:
			// Nudge: commit or MASTER takeover or peer-connected → push now.
			d.dispatchDHCPLeasePush(ctx, true)
		}
	}
}

// dispatchDHCPLeasePush runs one push pass in a guarded goroutine
// (skip-if-in-flight), mirroring runGuardedDDNSReconcile, so a slow Kea socket
// read can never wedge the loop. force=true bypasses the change-detect (full
// re-push); force=false pushes only when the set changed since the last push.
func (d *Daemon) dispatchDHCPLeasePush(ctx context.Context, force bool) {
	if !d.dhcpLeaseSyncInFlight.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer d.dhcpLeaseSyncInFlight.Store(false)
		d.pushDHCPLeasesOnce(ctx, force)
	}()
}

// pushDHCPLeasesOnce reads this node's active lease set and replicates it to the
// peer, per family. Fail-open: a read/send error is logged + counted (Errors)
// and never blocks serving. Only the RG-MASTER pushes (the gate).
func (d *Daemon) pushDHCPLeasesOnce(ctx context.Context, force bool) {
	cc := d.clusterConfig()
	if cc == nil || !cc.DHCPLeaseSync {
		return
	}
	if !d.dhcpLeaseSyncGateOpen() {
		return // BACKUP for all RGs: hold the peer's set, push nothing.
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, dhcpLeaseReadTimeout)
	defer cancel()
	now := time.Now()

	want4 := cfg.System.DHCPServer.DHCPLocalServer != nil
	want6 := cfg.System.DHCPServer.DHCPv6LocalServer != nil

	if want4 {
		leases, err := d.dhcpServer.GetSyncLeases4(rctx, now)
		if err != nil {
			slog.Debug("cluster: DHCP v4 lease read failed (retrying)", "err", err)
		} else {
			d.maybePushFamily(4, leases, force)
		}
	}
	if want6 {
		leases, err := d.dhcpServer.GetSyncLeases6(rctx, now)
		if err != nil {
			slog.Debug("cluster: DHCP v6 lease read failed (retrying)", "err", err)
		} else {
			d.maybePushFamily(6, leases, force)
		}
	}
}

// maybePushFamily pushes the family's lease set when force=true or the set
// changed since the last push (change-detect fingerprint). The fingerprint
// ignores the per-lease Remaining countdown (it ticks every second and would
// defeat change-detect); only identity/address/lifetime changes trigger an
// on-grant push, while the heartbeat (force=true) carries refreshed Remaining.
func (d *Daemon) maybePushFamily(family int, leases []dhcpserver.SyncLease, force bool) {
	fp := dhcpLeaseSetFingerprint(leases)
	d.dhcpLeaseLastSentMu.Lock()
	prev := d.dhcpLeaseLastSent4
	if family == 6 {
		prev = d.dhcpLeaseLastSent6
	}
	changed := fp != prev
	if force || changed {
		if family == 6 {
			d.dhcpLeaseLastSent6 = fp
		} else {
			d.dhcpLeaseLastSent4 = fp
		}
	}
	d.dhcpLeaseLastSentMu.Unlock()
	if !force && !changed {
		return
	}
	d.sessionSync.QueueDHCPLeases(family, leases)
}

// dhcpLeaseSetFingerprint computes a stable, order-independent fingerprint of a
// lease set for change detection. It deliberately EXCLUDES Remaining so the
// per-second countdown does not look like a change; an on-grant/renewal (which
// changes ValidLife or the membership) does change it.
func dhcpLeaseSetFingerprint(leases []dhcpserver.SyncLease) string {
	if len(leases) == 0 {
		return ""
	}
	keys := make([]string, 0, len(leases))
	for _, l := range leases {
		keys = append(keys, fmt.Sprintf("%s#%d#%s", l.IdentityKey(), l.ValidLife, l.Hostname))
	}
	sort.Strings(keys)
	return strings.Join(keys, "|")
}

// nudgeDHCPLeaseSync requests an immediate full-set lease push (config commit,
// MASTER takeover, peer reconnect). Non-blocking depth-1 send, coalescing a
// burst. Safe before the loop starts.
func (d *Daemon) nudgeDHCPLeaseSync() {
	if d.dhcpLeaseSyncNowCh == nil {
		return
	}
	select {
	case d.dhcpLeaseSyncNowCh <- struct{}{}:
	default:
	}
}

// preSeedDHCPLeaseMemfile writes the held peer leases into the Kea memfile
// CSV(s) BEFORE Kea is (re)started on takeover (#2239 Q3, the dup-alloc-window
// closer per SMR NIT-1). Pre-seeding the memfile means the just-started Kea
// loads the in-use bindings into its lease manager at boot, so it can NEVER
// answer a DISCOVER with an in-use address even in the brief window before the
// post-start lease-add seed runs. Best-effort + fail-open: a write failure is
// logged; the post-start lease-add (seedDHCPLeasesFromPeer) is the backstop.
//
// Called from the MASTER-takeover path BEFORE dhcpServer.ApplyAsync(start).
func (d *Daemon) preSeedDHCPLeaseMemfile() {
	if d.sessionSync == nil || d.dhcpServer == nil {
		return
	}
	cc := d.clusterConfig()
	if cc == nil || !cc.DHCPLeaseSync {
		return
	}
	now := time.Now()
	if leases := d.sessionSync.PeerDHCPLeases4(); len(leases) > 0 {
		if err := d.dhcpServer.PreSeedMemfile4(leases, now); err != nil {
			slog.Warn("cluster: DHCP v4 lease memfile pre-seed failed (post-start lease-add is backstop)", "err", err)
		} else {
			slog.Info("cluster: DHCP v4 leases pre-seeded into memfile before Kea start", "count", len(leases))
		}
	}
	if leases := d.sessionSync.PeerDHCPLeases6(); len(leases) > 0 {
		if err := d.dhcpServer.PreSeedMemfile6(leases, now); err != nil {
			slog.Warn("cluster: DHCP v6 lease memfile pre-seed failed (post-start lease-add is backstop)", "err", err)
		} else {
			slog.Info("cluster: DHCP v6 leases pre-seeded into memfile before Kea start", "count", len(leases))
		}
	}
}

// seedDHCPLeasesFromPeer seeds the just-started Kea with the held peer leases
// via lease{4,6}-add over the control socket (the reinitiateIPsecSAs
// precedent). Runs ASYNC post-takeover (a goroutine, like reinitiateIPsecSAs)
// so it never blocks the VRRP/takeover critical path. It waits a bounded time
// for the control socket to come up, then re-anchors each lease's Remaining to
// the local clock at seed (clock-skew immunity) and writes it. Idempotent: a
// lease already present (from the memfile pre-seed or this node's own persisted
// state) degrades to lease-update. Fail-open throughout.
func (d *Daemon) seedDHCPLeasesFromPeer(ctx context.Context) {
	if d.sessionSync == nil || d.dhcpServer == nil {
		return
	}
	cc := d.clusterConfig()
	if cc == nil || !cc.DHCPLeaseSync {
		return
	}
	leases4 := d.sessionSync.PeerDHCPLeases4()
	leases6 := d.sessionSync.PeerDHCPLeases6()
	if len(leases4) == 0 && len(leases6) == 0 {
		return
	}
	now := time.Now()
	cfg := d.store.ActiveConfig()
	want4 := cfg != nil && cfg.System.DHCPServer.DHCPLocalServer != nil && len(leases4) > 0
	want6 := cfg != nil && cfg.System.DHCPServer.DHCPv6LocalServer != nil && len(leases6) > 0

	if want4 {
		if d.dhcpServer.WaitControlSocket4(ctx, dhcpLeaseSeedSocketWait) {
			n, err := d.dhcpServer.SeedSyncLeases4(ctx, leases4, now)
			d.sessionSync.RecordDHCPLeasesSeeded(n)
			if err != nil {
				slog.Warn("cluster: DHCP v4 lease seed had errors (fail-open)", "seeded", n, "err", err)
			} else {
				slog.Info("cluster: DHCP v4 leases seeded into Kea on takeover", "count", n)
			}
		} else {
			slog.Warn("cluster: DHCP v4 control socket not ready; relying on memfile pre-seed")
		}
	}
	if want6 {
		if d.dhcpServer.WaitControlSocket6(ctx, dhcpLeaseSeedSocketWait) {
			n, err := d.dhcpServer.SeedSyncLeases6(ctx, leases6, now)
			d.sessionSync.RecordDHCPLeasesSeeded(n)
			if err != nil {
				slog.Warn("cluster: DHCP v6 lease seed had errors (fail-open)", "seeded", n, "err", err)
			} else {
				slog.Info("cluster: DHCP v6 leases seeded into Kea on takeover", "count", n)
			}
		} else {
			slog.Warn("cluster: DHCP v6 control socket not ready; relying on memfile pre-seed")
		}
	}
}
