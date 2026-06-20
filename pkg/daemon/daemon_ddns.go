package daemon

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/dhcpserver"
)

// daemon_ddns.go: the DHCP dynamic-DNS reconcile loop + node-level HA gate
// (#1387 increment 2, docs/research/1387-inc2-ddns-backend/plan.md §4.2/§4.3).
//
// The loop is an always-on guarded background goroutine modeled on the
// neighbor periodic loop (runGuardedNeighborPhase / neighborPeriodicLoop):
// it ticks on a slow cadence AND is nudged for an immediate pass on config
// commit and on VRRP MASTER takeover. Every pass runs in a guarded
// goroutine (skip-if-in-flight) so a hung DNS server can never wedge the
// loop or starve the nudge channel; a per-pass context timeout bounds the
// network calls.
//
// CRITICAL (CLAUDE.md control-socket rule): this loop does FILE I/O (the Kea
// memfile CSVs) + DNS network only. It NEVER touches the userspace-helper
// control socket, so it cannot starve session installs or status polls.

const (
	// ddnsReconcileInterval is the periodic poll cadence. DNS records are
	// not latency-critical; this is far above the 1/s control-socket
	// throttle (which it does not touch) and well under any lease time. A
	// new mid-interval lease shows up in DNS within one tick; config/MASTER
	// changes are immediate via the nudge channel.
	ddnsReconcileInterval = 30 * time.Second
	// ddnsReconcileTimeout bounds one whole reconcile pass (all DNS
	// UPDATEs for the current lease set). The backend's own per-exchange
	// timeout is shorter; this is the outer ceiling so a misbehaving
	// server can only delay one pass, never the loop.
	ddnsReconcileTimeout = 60 * time.Second
)

// ddnsNodeIDSeed reads the cluster node-id file for the DDNS owner
// watermark seed. The seed is a node-stable HINT only (never the
// delete-matching key, Inc-1 ddns.go ownerWatermark), so a missing file
// (standalone mode) yields an empty seed, which is harmless.
func ddnsNodeIDSeed() string {
	data, err := os.ReadFile(nodeIDFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// runDDNSReconcileLoop is the supervised DDNS reconcile loop. It runs for
// the daemon's lifetime (joined via wg) and exits on ctx cancellation.
func (d *Daemon) runDDNSReconcileLoop(ctx context.Context) {
	if d.ddns == nil {
		return
	}
	// Immediate first pass so a daemon restart re-publishes / withdraws
	// without waiting a full tick (the store + current leases drive it).
	d.runGuardedDDNSReconcile(ctx)

	ticker := time.NewTicker(ddnsReconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.runDDNSReconcileTick(ctx)
		case <-d.ddnsReconcileNowCh:
			// Nudge: commit or MASTER takeover. Run an immediate pass.
			d.runDDNSReconcileTick(ctx)
		}
	}
}

// runDDNSReconcileTick is the for-select tick callback, split out so a unit
// test can drive it directly with a synthetic config + injected updater and
// assert convergence. It is O(1) on the loop goroutine — the actual work
// dispatches into a guarded goroutine.
func (d *Daemon) runDDNSReconcileTick(ctx context.Context) {
	d.runGuardedDDNSReconcile(ctx)
}

// runGuardedDDNSReconcile dispatches one reconcile pass into a guarded
// goroutine (skip-if-in-flight), mirroring runGuardedNeighborPhase. A pass
// still running when the next tick/nudge fires is skipped rather than
// overlapped, so a wedged DNS server leaks at most one goroutine and the
// loop keeps servicing ctx + the nudge channel.
func (d *Daemon) runGuardedDDNSReconcile(ctx context.Context) {
	if d.ddns == nil {
		return
	}
	if !d.ddnsReconcileInFlight.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer d.ddnsReconcileInFlight.Store(false)
		d.reconcileDDNSOnce(ctx)
	}()
}

// reconcileDDNSOnce runs one DDNS reconcile pass under the node-level HA
// gate (plan §4.3). It is the single decision point for "should this node
// publish DDNS right now": the gate is OPEN when this node is MASTER for
// >=1 RG (cluster mode) or always (standalone). When the gate is CLOSED
// (BACKUP for all RGs) the node STOPS writing — it does NOT withdraw valid
// records (the peer MASTER owns them and keeps them fresh; deletion is
// lease-state / config-removal driven only, never local-ownership-loss
// driven, plan risk R3).
func (d *Daemon) reconcileDDNSOnce(ctx context.Context) {
	if d.ddns == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	if !d.ddnsWriterGateOpen() {
		// BACKUP for all RGs: stop emitting. No withdraw (plan R3).
		slog.Debug("ddns: skipping reconcile — node is not MASTER for any RG")
		return
	}
	rctx, cancel := context.WithTimeout(ctx, ddnsReconcileTimeout)
	defer cancel()
	if err := d.ddns.Reconcile(rctx, &cfg.System.DHCPServer); err != nil {
		// Fail-open for DHCP (plan risk R9): a DNS failure is logged +
		// counted (by the manager) and retried next cycle; it NEVER
		// propagates to the Kea apply path or to commit.
		slog.Warn("ddns: reconcile pass had errors (retrying next cycle)", "err", err)
	}
}

// ddnsWriterGateOpen reports whether this node should publish DDNS now
// (plan §4.3, node-level gate). SOUND without per-lease RG attribution
// because the Kea config each node serves is rendered MASTER-FILTERED
// (filterDHCPConfigForMasterRGs), so this node's memfile already contains
// ONLY its own MASTER-RG leases — reading the whole memfile cannot see a
// peer-owned lease, and the two nodes' input sets are disjoint by RG
// ownership. The gate reads snapshotRethMasterState ONLY (the SAME source
// the Kea manager uses), never any per-lease subnet_id (which is
// map-order-assigned and per-render unstable, plan §6 fork 2).
//
//   - Standalone (no cluster): always the writer — the gate is open.
//   - Cluster: open IFF this node is MASTER for at least one RG.
func (d *Daemon) ddnsWriterGateOpen() bool {
	if d.cluster == nil {
		return true
	}
	for _, isMaster := range d.snapshotRethMasterState() {
		if isMaster {
			return true
		}
	}
	return false
}

// nudgeDDNSReconcile requests an immediate DDNS reconcile pass (config
// commit or VRRP MASTER takeover). Non-blocking depth-1 send: coalesces a
// burst into one pending wakeup. Safe to call before the loop starts (the
// buffered send is simply consumed by the loop's first select).
//
// Async-takeover ordering note (plan §4.3 / M-r2-2): on a MASTER takeover
// the Kea reconcile is enqueued ASYNC (dhcpServer.ApplyAsync), so this
// nudge may run BEFORE Kea has repopulated this node's memfile. That is
// BENIGN: the reconcile is store-driven and add-only-from-current-leases —
// a too-early pass simply sees fewer/no leases and can only ADD on the next
// cycle once Kea has repopulated; it never deletes a record on the strength
// of a not-yet-written lease (a delete requires the record to be in this
// node's own ownership store). No ordering barrier is required.
func (d *Daemon) nudgeDDNSReconcile() {
	if d.ddnsReconcileNowCh == nil {
		return
	}
	select {
	case d.ddnsReconcileNowCh <- struct{}{}:
	default:
	}
}

// DDNSStats returns the current DHCP dynamic-DNS counter snapshot for the
// API collector / show command, or nil when the manager is not constructed
// (NoDataplane). The api.Server reads this via an injected function so it
// does not import the daemon's manager type directly.
func (d *Daemon) DDNSStats() *dhcpserver.DDNSStats {
	if d.ddns == nil {
		return nil
	}
	st := d.ddns.Stats()
	return &st
}

// OwnedDDNSRecords returns a human-readable summary of the DDNS records this
// node currently owns, for `show system services dhcp-server dynamic-dns
// detail`. Empty when the manager is absent.
func (d *Daemon) OwnedDDNSRecords() []dhcpserver.DDNSOwnedRecordView {
	if d.ddns == nil {
		return nil
	}
	return d.ddns.OwnedRecordViews()
}
