package daemon

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func (d *Daemon) stopSyncReadyTimer() {
	d.syncReadyTimerMu.Lock()
	defer d.syncReadyTimerMu.Unlock()
	d.syncReadyTimerGen.Add(1)
	if d.syncReadyTimer != nil {
		d.syncReadyTimer.Stop()
		d.syncReadyTimer = nil
	}
}

func (d *Daemon) armSyncReadyTimer() {
	if d.cluster == nil || d.syncReadyTimeout <= 0 {
		return
	}
	timerGen := d.syncReadyTimerGen.Add(1)
	d.syncReadyTimerMu.Lock()
	defer d.syncReadyTimerMu.Unlock()
	if d.syncReadyTimer != nil {
		d.syncReadyTimer.Stop()
	}
	timeout := d.syncReadyTimeout
	d.syncReadyTimer = time.AfterFunc(timeout, func() {
		if d.syncReadyTimerGen.Load() != timerGen || !d.syncPeerConnected.Load() {
			return
		}
		if d.cluster != nil && !d.cluster.IsSyncReady() {
			slog.Info("cluster: sync readiness timeout, releasing hold")
			d.cluster.SetSyncReady(true)
		}
	})
}

func (d *Daemon) onSessionSyncPeerConnected() {
	d.syncPeerConnected.Store(true)
	// #5863: a fresh connection is a new epoch. The config-sync reconciler
	// keys its "already pushed" marker on this epoch, so bumping it here forces
	// a re-push to the reconnected peer even if the prior connection had
	// already been satisfied.
	d.syncPeerConnEpoch.Add(1)
	d.hbSuppressStart.Store(0) // fresh connection → reset suppression cap

	// Determine whether this is a true cold start or a routine reconnect.
	// A cold start means no bulk sync has ever completed during this
	// daemon's lifetime — the peer (or we) genuinely started from scratch.
	// On a routine reconnect after a brief network blip, the sessions are
	// already synced; preserve the primed state and sync readiness (#466).
	ss := d.getSessionSync()
	coldStart := ss == nil || !ss.BulkEverCompleted()

	if coldStart {
		d.syncBulkPrimed.Store(false)
		d.syncPeerBulkPrimed.Store(false)
	}

	gen := d.syncPrimeRetryGen.Add(1)
	slog.Info("cluster: session sync peer connected",
		"retry_gen", gen,
		"cold_start", coldStart,
		"bulk_primed", d.syncBulkPrimed.Load(),
		"peer_bulk_primed", d.syncPeerBulkPrimed.Load(),
		"cluster_sync_ready", d.cluster != nil && d.cluster.IsSyncReady())

	if coldStart {
		if d.cluster != nil {
			d.cluster.SetSyncReady(false)
		}
		d.armSyncReadyTimer()
		d.startSessionSyncPrimeRetry(gen)
	}
}

func (d *Daemon) onSessionSyncBulkReceived() {
	d.syncBulkPrimed.Store(true)
	slog.Info("cluster: session sync bulk received",
		"retry_gen", d.syncPrimeRetryGen.Load())
	d.stopSyncReadyTimer()
	if d.vrrpMgr != nil {
		d.vrrpMgr.ReleaseSyncHold()
	}
	if d.cluster != nil {
		d.cluster.SetSyncReady(true)
	}
}

func (d *Daemon) onSessionSyncBulkAckReceived() {
	d.syncPeerBulkPrimed.Store(true)
	slog.Info("cluster: session sync bulk ack received",
		"retry_gen", d.syncPrimeRetryGen.Load())
}

func (d *Daemon) onSessionSyncPeerDisconnected() {
	d.syncPeerConnected.Store(false)
	gen := d.syncPrimeRetryGen.Add(1)

	// On disconnect after a completed bulk exchange, preserve primed state
	// and sync readiness. The sessions are still in the BPF maps — a
	// subsequent reconnect will resume incremental sync without needing a
	// full bulk transfer (#466).
	ss := d.getSessionSync()
	wasEverPrimed := ss != nil && ss.BulkEverCompleted()
	if !wasEverPrimed {
		d.syncBulkPrimed.Store(false)
		d.syncPeerBulkPrimed.Store(false)
	}

	slog.Info("cluster: session sync peer disconnected",
		"retry_gen", gen,
		"was_ever_primed", wasEverPrimed,
		"bulk_primed", d.syncBulkPrimed.Load(),
		"peer_bulk_primed", d.syncPeerBulkPrimed.Load(),
		"cluster_sync_ready", d.cluster != nil && d.cluster.IsSyncReady())
	d.stopSyncReadyTimer()

	if !wasEverPrimed {
		if d.cluster != nil {
			d.cluster.SetSyncReady(false)
		}
	}
}

func (d *Daemon) shouldSuppressPeerHeartbeatTimeout() (bool, string) {
	ss := d.getSessionSync()
	if ss == nil || !ss.IsConnected() {
		d.hbSuppressStart.Store(0) // reset when sync disconnected
		return false, ""
	}
	const maxPeerSyncSilence = 2 * time.Second
	age, ok := ss.LastPeerReceiveAge()
	if !ok || age > maxPeerSyncSilence {
		d.hbSuppressStart.Store(0) // reset when sync goes quiet
		return false, ""
	}

	// Cap total suppression duration. During graceful shutdown the peer
	// may send a bulk sync that keeps LastPeerReceiveAge() fresh for tens
	// of seconds while heartbeats have already stopped. After 5s of
	// continuous suppression, stop suppressing so the heartbeat timeout
	// can fire and trigger failover.
	//
	// The window is measured in CLOCK_MONOTONIC nanos (#1792): with
	// wall-clock UnixNano a backward step left suppression stuck on
	// (blocking failover for the step duration) and a forward step cut
	// it short.
	const maxSuppressDuration = 5 * time.Second
	now := cluster.MonotonicNanos()
	start := d.hbSuppressStart.Load()
	if start == 0 {
		d.hbSuppressStart.Store(now)
		start = now
	}
	if hbSuppressCapExceeded(start, now, maxSuppressDuration) {
		return false, ""
	}

	return true, fmt.Sprintf("session sync connected with recent peer traffic age=%s", age.Truncate(10*time.Millisecond))
}

// hbSuppressCapExceeded reports whether continuous heartbeat-timeout
// suppression that began at startMono has lasted longer than cap by nowMono.
// Both timestamps are CLOCK_MONOTONIC nanos (cluster.MonotonicNanos), so the
// cap is immune to wall-clock steps (#1792). Split out so tests can inject
// timestamps and exercise step scenarios directly.
func hbSuppressCapExceeded(startMono, nowMono int64, capDur time.Duration) bool {
	return time.Duration(nowMono-startMono) > capDur
}

func syncPrimeProgressObserved(current, baseline cluster.SyncStatsSnapshot) bool {
	return current.SessionsReceived > baseline.SessionsReceived ||
		current.SessionsInstalled > baseline.SessionsInstalled ||
		current.DeletesReceived > baseline.DeletesReceived
}

func (d *Daemon) startSessionSyncPrimeRetry(gen uint64) {
	ss := d.getSessionSync()
	if ss == nil || d.dataplane() == nil {
		return
	}
	go func() {
		intervals := []time.Duration{10 * time.Second, 20 * time.Second, 30 * time.Second, 30 * time.Second, 30 * time.Second, 30 * time.Second}
		const retryWhileAckPendingAfter = 35 * time.Second
		maxAttempts := len(intervals)
		baseline := ss.Stats()
		slog.Info("cluster: starting session sync bulk-prime retry loop",
			"retry_gen", gen,
			"max_attempts", maxAttempts,
			"intervals", intervals)
		for attempt := 1; attempt <= maxAttempts; attempt++ {
			if wait := intervals[attempt-1]; wait > 0 {
				time.Sleep(wait)
			}
			if d.syncPrimeRetryGen.Load() != gen {
				slog.Info("cluster: stopping session sync bulk-prime retry loop",
					"retry_gen", gen,
					"attempt", attempt,
					"reason", "generation advanced")
				return
			}
			if d.syncPeerBulkPrimed.Load() {
				slog.Info("cluster: stopping session sync bulk-prime retry loop",
					"retry_gen", gen,
					"attempt", attempt,
					"reason", "peer bulk ack received")
				return
			}
			if cur := d.getSessionSync(); cur != ss || !ss.IsConnected() {
				reason := "session sync replaced"
				if cur == ss && !ss.IsConnected() {
					reason = "session sync disconnected"
				}
				slog.Info("cluster: stopping session sync bulk-prime retry loop",
					"retry_gen", gen,
					"attempt", attempt,
					"reason", reason)
				return
			}
			if pendingEpoch, pendingAge, ok := ss.PendingBulkAck(); ok && pendingAge < retryWhileAckPendingAfter {
				slog.Info("cluster: deferring session sync bulk-prime retry",
					"retry_gen", gen,
					"attempt", attempt,
					"reason", "outbound bulk still awaiting ack",
					"pending_epoch", pendingEpoch,
					"pending_age", pendingAge.Round(10*time.Millisecond),
					"retry_after", retryWhileAckPendingAfter)
				continue
			}
			current := ss.Stats()
			if syncPrimeProgressObserved(current, baseline) {
				slog.Info("cluster: deferring session sync bulk-prime retry",
					"retry_gen", gen,
					"attempt", attempt,
					"reason", "peer sync progress observed",
					"sessions_received", current.SessionsReceived,
					"sessions_installed", current.SessionsInstalled,
					"deletes_received", current.DeletesReceived,
					"baseline_sessions_received", baseline.SessionsReceived,
					"baseline_sessions_installed", baseline.SessionsInstalled,
					"baseline_deletes_received", baseline.DeletesReceived)
				baseline = current
				continue
			}
			slog.Info("cluster: retrying session sync bulk prime",
				"retry_gen", gen,
				"attempt", attempt,
				"connected", ss.IsConnected(),
				"sessions_received", current.SessionsReceived,
				"sessions_installed", current.SessionsInstalled,
				"deletes_received", current.DeletesReceived,
				"baseline_sessions_received", baseline.SessionsReceived,
				"baseline_sessions_installed", baseline.SessionsInstalled,
				"baseline_deletes_received", baseline.DeletesReceived)
			if err := d.bulkSyncViaEventStreamOrFallback(ss); err != nil {
				slog.Warn("cluster: session sync bulk prime retry failed",
					"retry_gen", gen,
					"attempt", attempt,
					"err", err)
				continue
			}
			if d.syncPeerBulkPrimed.Load() {
				slog.Info("cluster: session sync bulk prime retry loop observed bulk ack",
					"retry_gen", gen,
					"attempt", attempt)
				return
			}
		}
		slog.Warn("cluster: session sync bulk-prime retry loop exhausted",
			"retry_gen", gen,
			"attempts", maxAttempts)
	}()
}

// bulkSyncViaEventStreamOrFallback attempts to export all sessions via the
// event stream (fast path — sessions flow through the existing event stream
// callback into QueueSessionV4/V6). Falls back to the old BulkSync path
// (iterating BPF maps from Go) when the event stream isn't available.
func (d *Daemon) bulkSyncViaEventStreamOrFallback(ss *cluster.SessionSync) error {
	// userspaceEventStreamExporter is a local probe satisfied by
	// *dataplane/userspace.LegacyDataPlaneAdapter via
	// ExportAllSessionsViaEventStream (legacy_dataplane.go:422).
	// Type-assertion target is the published dataplane directly — the
	// legacyDP() round-trip retired in #1519 added no method-set coverage.
	// #2114: ONE snapshot feeds the nil-check, the assertion, and the %T
	// log below (plan §5.3 rules 3/9).
	rt := d.dataplane()
	if rt != nil {
		if exporter, ok := rt.(userspaceEventStreamExporter); ok {
			slog.Info("cluster: using event stream export for bulk sync")
			if err := exporter.ExportAllSessionsViaEventStream(); err != nil {
				slog.Warn("cluster: event stream bulk export failed, falling back to BulkSync", "err", err)
			} else {
				slog.Info("cluster: exported sessions via event stream for bulk sync")
				return nil
			}
		}
	}
	slog.Info("cluster: event stream export not available, falling back to BulkSync",
		"dp_type", fmt.Sprintf("%T", rt))
	if ss == nil {
		return fmt.Errorf("session sync not initialized")
	}
	return ss.BulkSync()
}

// rg0ConfigSyncAuthority is the SINGLE, transport-independent rule for whether
// this node should push its committed config to the cluster peer (#5054): the
// node must be the RG0 (config-ownership group) PRIMARY of a configured cluster.
// It depends only on cluster/RG0 state — never on which management transport
// (gRPC, REST, or the local interactive shell) delivered the commit — so every
// operator commit path resolves the peer-sync decision identically and the two
// nodes cannot diverge by transport.
//
// A nil manager (a standalone, non-cluster node) is never an authority, so a
// standalone node never attempts a peer push. Kept as a small pure function so
// the decision is unit-testable in isolation and is reused by BOTH the operator
// commit entry points (commitAndApplyOperator / commitConfirmedAndApplyOperator)
// and the actual push site (syncConfigToPeer below), so the attempt-time and
// push-time gates cannot drift.
func rg0ConfigSyncAuthority(cl *cluster.Manager) bool {
	return cl != nil && cl.IsLocalPrimary(0)
}

// syncConfigToPeer sends the active config to the cluster peer if this node is
// the RG0 config-sync authority and config sync is enabled.
func (d *Daemon) syncConfigToPeer() {
	if d.getSessionSync() == nil {
		return
	}
	// Only sync if this node is the RG0 (config ownership group) primary — the
	// same rule the operator commit entry points use to decide whether to
	// attempt a push (#5054).
	if !rg0ConfigSyncAuthority(d.cluster) {
		return
	}
	d.pushConfigToPeer()
}

// pushConfigToPeer sends the active config to the cluster peer unconditionally
// (does not check primary/secondary status). Used both by normal commit sync
// and by the peer-reconnect path where the stable node pushes its config
// regardless of whether it was preempted.
func (d *Daemon) pushConfigToPeer() {
	ss := d.getSessionSync()
	if ss == nil {
		return
	}
	// Check if config sync is enabled.
	cfg := d.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil || !cfg.Chassis.Cluster.ConfigSync {
		return
	}
	// Get the active config tree as text.
	configText := d.store.ShowActive()
	if configText == "" {
		return
	}
	ss.QueueConfig(configText)
	// #5863: record the reconcile marker so the level-triggered reconciler
	// treats this generation as already pushed on the current connection
	// epoch and does not redundantly re-push it. Only mark when a peer
	// connection is actually up — QueueConfig no-ops with no active conn, and
	// a later (re)connect bumps the epoch so the reconciler pushes fresh.
	if d.syncPeerConnected.Load() {
		d.markConfigSyncPushed(configText)
	}
}

// configGenerationHash reduces the active config text to a compact generation
// token (#5863). The reconciler pushes at most once per (peer-connection-epoch
// × generation); a new commit changes the text and therefore the generation,
// so a config change while a peer stays connected re-pushes exactly once.
func configGenerationHash(configText string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(configText))
	return h.Sum64()
}

// configSyncStableAfter is the uptime a node must have before it is trusted to
// push its on-disk config to a peer (#5863). A freshly booted node must not
// overwrite the peer with stale config before it has settled; the default
// mirrors the historical 30s connect-edge gate. Overridable for tests.
func (d *Daemon) configSyncStableAfter() time.Duration {
	if d.configSyncStable > 0 {
		return d.configSyncStable
	}
	return 30 * time.Second
}

// markConfigSyncPushed records that configText's generation has been pushed to
// the peer on the current connection epoch (#5863). Any push path (commit sync
// or the reconciler) records through here so the marker always reflects the
// latest generation pushed on the live connection, and a redundant reconcile is
// a no-op.
func (d *Daemon) markConfigSyncPushed(configText string) {
	gen := configGenerationHash(configText)
	epoch := d.syncPeerConnEpoch.Load()
	d.configSyncMu.Lock()
	d.configSyncHasPushed = true
	d.configSyncPushedEpoch = epoch
	d.configSyncPushedGen = gen
	d.configSyncMu.Unlock()
}

// reconcileConfigSyncToPeer is the level-triggered config-sync reconciler
// (#5863). It re-evaluates the desired invariant — "if I am the RG0 config
// authority AND stable (uptime ≥ stability threshold) AND a peer is connected
// AND config sync is enabled AND I have not already pushed my current config
// generation on this peer's current connection, then push it (once)" — and
// pushes ONLY when desired-vs-actual diverges.
//
// It replaces the old edge-triggered OnPeerConnected-only push, which evaluated
// the primary/stability gates solely at connect time: a later RG0 promotion or
// the crossing of the stability threshold never re-pushed, so a peer that
// connected while this node was secondary (or freshly booted) could stay
// INDEFINITELY divergent until an unrelated commit/reconnect. The reconciler is
// invoked on every input change (peer (re)connect, RG0 promotion, stability
// timer, and a low-frequency safety-net tick).
//
// Control-socket safety (CLAUDE.md): the config push is heavy and the userspace
// control socket is shared. The (epoch × generation) marker guarantees AT MOST
// ONE push per connection per config generation — once satisfied every further
// call is a cheap no-op (state gates + one hash, no QueueConfig), so a
// safety-net tick or a burst of triggers cannot storm the socket or starve
// session installs during bulk sync. It stays RG0-primary-gated exactly like
// the old connect edge, so a reconnecting SECONDARY never overwrites the
// authoritative primary's config (#2239/#4385).
func (d *Daemon) reconcileConfigSyncToPeer(reason string) {
	ss := d.getSessionSync()
	if ss == nil && d.configSyncPushForTest == nil {
		return
	}
	// Desired-state gates, re-read fresh on every call (persistent state, not
	// a captured edge).
	if !d.syncPeerConnected.Load() {
		slog.Debug("cluster: config-sync reconcile skip (no peer connection)", "reason", reason)
		return
	}
	if !rg0ConfigSyncAuthority(d.cluster) {
		slog.Debug("cluster: config-sync reconcile skip (not RG0 primary)", "reason", reason)
		return
	}
	if time.Since(d.startTime) < d.configSyncStableAfter() {
		slog.Debug("cluster: config-sync reconcile skip (uptime below stability threshold)", "reason", reason)
		return
	}
	if d.store == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil || !cfg.Chassis.Cluster.ConfigSync {
		slog.Debug("cluster: config-sync reconcile skip (config sync disabled)", "reason", reason)
		return
	}
	configText := d.store.ShowActive()
	if configText == "" {
		return
	}
	gen := configGenerationHash(configText)
	epoch := d.syncPeerConnEpoch.Load()

	// Check-and-claim the (epoch × generation) marker under one lock so two
	// concurrent triggers (e.g. a promotion racing the safety-net tick) push
	// at most once. Claim the marker BEFORE the push: a failed/dropped send
	// disconnects, and the next (re)connect bumps the epoch so the reconciler
	// re-pushes on the fresh connection.
	d.configSyncMu.Lock()
	if d.configSyncHasPushed && d.configSyncPushedEpoch == epoch && d.configSyncPushedGen == gen {
		d.configSyncMu.Unlock()
		slog.Debug("cluster: config-sync reconcile no-op (already pushed for epoch/generation)",
			"reason", reason, "epoch", epoch, "generation", gen)
		return
	}
	d.configSyncHasPushed = true
	d.configSyncPushedEpoch = epoch
	d.configSyncPushedGen = gen
	d.configSyncMu.Unlock()

	slog.Info("cluster: config-sync reconcile pushing config to peer",
		"reason", reason, "epoch", epoch, "generation", gen, "size", len(configText))
	if d.configSyncPushForTest != nil {
		d.configSyncPushForTest()
		return
	}
	ss.QueueConfig(configText)
}

// configSyncReconcileLoop is the low-frequency level-triggered safety net for
// config sync (#5863). It wakes at the stability threshold (so a node that was
// too young to push at connect time reconciles the moment it crosses the
// threshold) and thereafter on a coarse periodic tick that recovers any dropped
// promotion/connect edge. Every wake is a no-op once the (epoch × generation)
// marker is satisfied, so it never adds sustained control-socket traffic.
func (d *Daemon) configSyncReconcileLoop(ctx context.Context) {
	const periodic = 30 * time.Second
	for {
		// Wake at the stability threshold while still too young to push, else
		// on the coarse periodic tick.
		delay := periodic
		if until := d.configSyncStableAfter() - time.Since(d.startTime); until > 0 {
			delay = until
		}
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
			d.reconcileConfigSyncToPeer("reconcile-loop")
		}
	}
}

// errConfigSyncRejectedPrimary is returned by handleConfigSync when this node
// believes it is the RG0 primary (config authority) and therefore refuses the
// peer's config. It is NOT an apply failure per se, but the config was not
// applied, so the caller (configApplyLoop) must NOT advance the config
// high-water mark — the transient dual-active window must heal via the peer's
// re-push once this node settles into secondary (M-2/#4151).
var errConfigSyncRejectedPrimary = errors.New("config sync rejected: this node is RG0 primary")

// handleConfigSync processes a config received from the cluster peer.
// Config sync is unidirectional: primary → secondary only. If this node
// is the RG0 primary (config authority), incoming config is rejected to
// prevent a reconnecting secondary from overwriting the authoritative config.
//
// It returns nil ONLY when the config was actually applied (or already matches
// the active config); a non-nil error means the apply did not take effect. The
// config high-water mark advances ONLY on a nil return (M-2/#4151), so a
// rejection or a compile/promote failure leaves the standby eligible for the
// primary's re-push instead of being silently stranded on the prior config.
func (d *Daemon) handleConfigSync(configText string) error {
	if d.cluster != nil && d.cluster.IsLocalPrimary(0) {
		slog.Warn("cluster: rejecting config sync (this node is RG0 primary)")
		return errConfigSyncRejectedPrimary
	}
	if d.store != nil {
		activeText := strings.TrimSpace(d.store.ShowActive())
		incomingText := strings.TrimSpace(configText)
		// #4957: the shortcut requires BOTH that the incoming config is the active
		// tree AND that the active tree actually completed its apply. SyncApply
		// promotes s.active BEFORE applyConfigLocked and (per the #1799
		// degrade-not-fail doctrine) does NOT roll it back on a non-fatal apply
		// failure, so active-text equality alone would treat a promoted-but-
		// UNAPPLIED config as converged: the primary's same-generation re-push
		// would take this fast path, return nil, and advance the config high-water
		// past a config whose dataplane never converged (a stale/disarmed standby
		// that reports the generation applied — visible at failover). Gating on
		// ActiveApplied() lets a re-push of a config whose prior apply failed fall
		// through to syncAndApply and RE-ATTEMPT the apply instead.
		if activeText == incomingText && d.store.ActiveApplied() {
			slog.Info("cluster: skipping config sync apply (config already matches active and is applied)",
				"size", len(configText))
			// Already converged to this config — a nil return lets the
			// high-water advance so a duplicate re-push is correctly skipped.
			return nil
		}
	}
	slog.Info("cluster: accepting config sync from peer", "size", len(configText))

	// #846: route through syncAndApply so the peer's
	// SyncApply(active promotion) + applyConfig run atomically
	// under d.applySem. Without this, a local commitAndApply could
	// interleave between the two and briefly leave store and kernel
	// disagreeing.
	if _, err := d.syncAndApply(context.Background(), configText, nil); err != nil {
		slog.Error("cluster: config sync apply failed", "err", err)
		return err
	}
	// #4957/#6296: on full success syncAndApply itself stamps the applied marker
	// — from a digest captured for the config it applied, while still holding
	// applySem — so a duplicate re-push takes the converged shortcut above, and a
	// config that only PROMOTED active but failed to apply does NOT (keeping the
	// high-water pinned until a retry lands). The stamp moved INTO syncAndApply
	// (from a post-applySem-release MarkActiveApplied here) so a concurrent
	// secondary-side promoter mutating s.active in the release window can no
	// longer make the marker key the wrong, unapplied active digest (#6296).
	slog.Info("cluster: config sync applied successfully")
	return nil
}

// getSessionSync returns the currently-published cluster session-sync object
// under clusterCommsMu (#4958). It is nil when cluster comms are stopped or
// still constructing. Every reader outside the constructor MUST go through this
// accessor rather than touching d.sessionSync directly: the field is published
// asynchronously by the startClusterComms constructor goroutine and nilled by
// stopClusterComms, so a bare field read races the write (and a bare
// `d.sessionSync != nil && d.sessionSync.X()` can nil-deref if stop nils
// between the two loads). Callers capture the returned pointer once and operate
// on it — the lock is never held across a call into SessionSync.
func (d *Daemon) getSessionSync() *cluster.SessionSync {
	d.clusterCommsMu.Lock()
	ss := d.sessionSync
	d.clusterCommsMu.Unlock()
	return ss
}

// getClusterCommsCtx returns the live cluster-comms sub-context under
// clusterCommsMu (#4958). Nil when comms are stopped. Comms-scoped loops that
// (re)launch from the apply path (e.g. the DHCP lease-sync loop) read it here
// so a concurrent stopClusterComms nilling the field does not race them.
func (d *Daemon) getClusterCommsCtx() context.Context {
	d.clusterCommsMu.Lock()
	ctx := d.clusterCommsCtx
	d.clusterCommsMu.Unlock()
	return ctx
}

// snapshotFabricRefreshChans returns the current fabric refresh channels under
// clusterCommsMu (#4958). The populateFabricFwd loops receive their channel by
// value at launch; only the sender (triggerFabricRefresh) reads the live fields,
// so this snapshot is the single synchronized read point.
func (d *Daemon) snapshotFabricRefreshChans() (chan struct{}, chan struct{}) {
	d.clusterCommsMu.Lock()
	ch0, ch1 := d.fabricRefreshCh, d.fabricRefreshCh1
	d.clusterCommsMu.Unlock()
	return ch0, ch1
}

// beginClusterCommsEpoch opens a new cluster-comms epoch (#4958): it bumps
// clusterCommsGen, installs a fresh independently-cancellable sub-context, and
// returns the context plus the epoch generation the constructor goroutine must
// present at publish time. Bumping the counter here means a constructor from a
// prior epoch (still resolving addresses) is already superseded before this
// call returns, so its later publish is dropped.
func (d *Daemon) beginClusterCommsEpoch(parent context.Context) (context.Context, uint64) {
	commsCtx, commsCancel := context.WithCancel(parent)
	d.clusterCommsMu.Lock()
	d.clusterCommsGen++
	gen := d.clusterCommsGen
	d.clusterCommsCancel = commsCancel
	d.clusterCommsCtx = commsCtx
	d.clusterCommsMu.Unlock()
	return commsCtx, gen
}

// publishSessionSyncIfCurrent installs ss as the live session-sync object iff
// gen still matches the current cluster-comms epoch (#4958). It returns false —
// dropping the publish — when a restart (stopClusterComms / a newer
// startClusterComms) has advanced the generation since this constructor started,
// so a late constructor from a superseded epoch never overwrites the newer
// epoch's session/endpoints (the stale-overwrite failure) and never resurrects a
// session that stop is tearing down (the nil-deref failure). The generation
// check and the store happen under the same lock so they cannot interleave with
// a concurrent stop.
func (d *Daemon) publishSessionSyncIfCurrent(gen uint64, ss *cluster.SessionSync) bool {
	d.clusterCommsMu.Lock()
	defer d.clusterCommsMu.Unlock()
	if gen != d.clusterCommsGen {
		slog.Debug("cluster: dropping stale session-sync publish (comms epoch superseded)",
			"publish_gen", gen, "current_gen", d.clusterCommsGen)
		return false
	}
	d.sessionSync = ss
	return true
}

// publishFabricRefreshChansIfCurrent installs the fabric refresh channels iff
// gen still matches the current epoch (#4958), mirroring
// publishSessionSyncIfCurrent so a superseded constructor does not replace a
// newer epoch's channels.
func (d *Daemon) publishFabricRefreshChansIfCurrent(gen uint64, ch0, ch1 chan struct{}) bool {
	d.clusterCommsMu.Lock()
	defer d.clusterCommsMu.Unlock()
	if gen != d.clusterCommsGen {
		slog.Debug("cluster: dropping stale fabric-refresh channel publish (comms epoch superseded)",
			"publish_gen", gen, "current_gen", d.clusterCommsGen)
		return false
	}
	d.fabricRefreshCh = ch0
	d.fabricRefreshCh1 = ch1
	return true
}

// watchClusterEvents monitors cluster state transitions and toggles
// config store read-only mode based on primary/secondary state.
// startClusterComms starts heartbeat and session sync after VRFs are created.
// Called after applyConfig so that control/fabric interfaces are already in
// the management VRF (if configured).
func (d *Daemon) startClusterComms(ctx context.Context) {
	cfg := d.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return
	}
	cc := cfg.Chassis.Cluster

	// Create an independently-cancellable sub-context so cluster comms can
	// be restarted on config change (#87) without cancelling the daemon ctx.
	// beginClusterCommsEpoch bumps the epoch generation under clusterCommsMu so
	// a constructor goroutine from a superseded epoch (still resolving its sync
	// address) drops its publish instead of clobbering this epoch's state
	// (#4958).
	commsCtx, commsGen := d.beginClusterCommsEpoch(ctx)
	d.setActiveTransportIfCurrent(commsGen, clusterTransportFromConfig(cfg))

	// Determine VRF device if control/fabric interfaces are in mgmt VRF.
	// Check mgmtVRFInterfaces first, then fall back to probing the control
	// interface directly (handles config-only mode where applyConfig may
	// have run but mgmtVRFInterfaces is empty due to VRF creation failure).
	vrfDevice := ""
	if len(d.mgmtVRFIfaceSet()) > 0 {
		vrfDevice = "vrf-mgmt"
	} else if cc.ControlInterface != "" {
		// Control/fabric interfaces (em*, fab*) are always placed in
		// vrf-mgmt by the compiler. Check if the VRF device exists.
		if _, err := net.InterfaceByName("vrf-mgmt"); err == nil {
			vrfDevice = "vrf-mgmt"
		}
	}

	// Start BPF watchdog heartbeat: write monotonic timestamp to ha_watchdog
	// map every 500ms for each configured RG. If the daemon is SIGKILL'd,
	// the timestamp goes stale and BPF stops forwarding within 2s.
	//
	// #3917: gate on the published dataplane only (not the startup RG
	// count) and re-read the
	// CURRENT redundancy-group set each tick. Comms are only restarted on a
	// transport-field change, so binding cc.RedundancyGroups here would
	// starve a day-2 RG (added by a later commit) of watchdog heartbeats ->
	// its watchdog goes stale -> the dataplane stops forwarding for it.
	// This mirrors the live-config read the fence path now uses.
	if d.dataplane() != nil {
		go func() {
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-commsCtx.Done():
					return
				case <-ticker.C:
					// #2114: ONE load per tick, shared across the RG loop
					// (plan §5.3 rule 1) — never per-RG, never a lifetime
					// capture.
					rt := d.dataplane()
					if rt == nil {
						continue
					}
					rgs := d.currentRedundancyGroups()
					if len(rgs) == 0 {
						continue
					}
					var ts unix.Timespec
					_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
					now := uint64(ts.Sec)
					for _, rg := range rgs {
						if err := rt.HA().SetHAWatchdog(commsCtx, rg.ID, now); err != nil {
							slog.Warn("ha watchdog write failed", "rg", rg.ID, "err", err)
						}
					}
				}
			}
		}()
		slog.Info("HA watchdog heartbeat started", "rgs", len(cc.RedundancyGroups))
	}

	// In VRRP mode, make strict VIP ownership the runtime default so
	// rg_active follows VIP/MAC ownership rather than cluster-primary
	// intent. Direct/no-reth-vrrp mode and private-rg-election mode
	// still use cluster state because there are no VRRP instances to
	// gate on.
	d.syncRGStrictVIPOwnershipMode(cc)

	// Start heartbeat if control-interface and peer-address are configured.
	// Retry on bind failure: the control interface address and VRF device
	// may not be ready during daemon startup (networkd race).
	if cc.ControlInterface != "" && cc.PeerAddress != "" {
		go d.startHeartbeatWithRetry(commsCtx, cc.ControlInterface, cc.PeerAddress, vrfDevice)
	}

	// Start session/config sync on the control link (same interface as
	// heartbeat, port 4785). Consolidates all control-plane traffic onto
	// the dedicated control path. Falls back to fabric if no control
	// interface is configured (legacy compatibility).
	syncIface := cc.ControlInterface
	syncPeerAddr := cc.PeerAddress
	syncTransport := "control-link"
	if syncIface == "" || syncPeerAddr == "" {
		syncIface = cc.FabricInterface
		syncPeerAddr = cc.FabricPeerAddress
		syncTransport = "fabric"
	}
	if syncIface != "" && syncPeerAddr != "" {
		// Track the constructor goroutine so stopClusterComms can join it
		// before tearing the epoch down (#4958): a cancelled constructor must
		// finish (or drop its publish) before stop nils the shared state.
		d.clusterCommsWG.Add(1)
		go func() {
			defer d.clusterCommsWG.Done()
			var syncIP string
			for i := 0; i < 30; i++ {
				syncIP = resolveClusterInterfaceAddr(syncIface, syncPeerAddr, "")
				if syncIP != "" {
					break
				}
				if i == 0 {
					slog.Info("cluster: sync interface has no usable address yet, waiting",
						"interface", syncIface, "transport", syncTransport)
				}
				select {
				case <-commsCtx.Done():
					return
				case <-time.After(2 * time.Second):
				}
			}
			if syncIP == "" {
				slog.Error("cluster: sync interface address not available after retries",
					"interface", syncIface)
				return
			}

			syncLocal := net.JoinHostPort(syncIP, "4785")
			syncPeer := net.JoinHostPort(syncPeerAddr, "4785")
			slog.Info("cluster: session sync transport", "mode", syncTransport,
				"local", syncLocal, "peer", syncPeer)

			// Resolve secondary fabric (fab1) for dual transport failover.
			// Only applicable when using fabric transport (not control-link).
			var syncLocal1, syncPeer1 string
			if syncTransport == "fabric" && cc.Fabric1Interface != "" && cc.Fabric1PeerAddress != "" {
				var fab1IP string
				for i := 0; i < 15; i++ {
					fab1IP = resolveClusterInterfaceAddr(cc.Fabric1Interface, cc.Fabric1PeerAddress, "")
					if fab1IP != "" {
						break
					}
					if i == 0 {
						slog.Info("cluster: fabric1 interface has no usable address yet, waiting",
							"interface", cc.Fabric1Interface)
					}
					select {
					case <-commsCtx.Done():
						return
					case <-time.After(2 * time.Second):
					}
				}
				if fab1IP != "" {
					syncLocal1 = net.JoinHostPort(fab1IP, "4785")
					syncPeer1 = net.JoinHostPort(cc.Fabric1PeerAddress, "4785")
					slog.Info("cluster: dual fabric transport configured",
						"fab0_local", syncLocal, "fab1_local", syncLocal1)
				} else {
					slog.Warn("cluster: fabric1 address not available, using single fabric only",
						"interface", cc.Fabric1Interface)
				}
			}

			// Build the session-sync object in a LOCAL variable and publish it
			// only if this constructor still owns the current comms epoch
			// (#4958). Everything below wires callbacks and cluster references
			// against this local `ss` — never re-reading d.sessionSync — so a
			// concurrent stopClusterComms that nils the field cannot turn a
			// re-dereference into a nil-deref panic, and a superseded epoch's
			// late publish is dropped rather than clobbering the live epoch.
			var ss *cluster.SessionSync
			if syncLocal1 != "" {
				ss = cluster.NewDualSessionSync(syncLocal, syncPeer, syncLocal1, syncPeer1, nil)
			} else {
				ss = cluster.NewSessionSync(syncLocal, syncPeer, nil)
			}
			if !d.publishSessionSyncIfCurrent(commsGen, ss) {
				// A restart superseded this epoch while we were resolving the
				// sync address; abort before wiring cluster state or binding.
				return
			}
			// #4107 F23: authenticate the session-sync stream with the same
			// control-link PSK the heartbeat + fabric-gRPC use (#4357). The
			// cluster Manager supplies both the key and the heartbeat
			// downgrade-guard signal (HeartbeatPeerAuthSeen). With no key
			// configured the stream stays legacy unauthenticated (dual-accept).
			ss.SetAuthProvider(d.cluster)

			d.cluster.SetSyncTransport(syncTransport)

			// Store sync peer addresses for gRPC peer dialing (session queries etc).
			d.syncPeerAddr = syncPeerAddr
			if syncLocal1 != "" {
				d.syncPeerAddr1 = cc.Fabric1PeerAddress
			}

			// Start gRPC fabric listener(s) so peer can proxy monitor requests.
			// d.grpcSrv is set after startClusterComms returns, so we poll briefly.
			// Uses the sync interface address (fabric or control-link).
			// When dual-fabric is configured, listen on both fabric IPs.
			go func() {
				for i := 0; i < 30; i++ {
					if d.grpcSrv != nil {
						grpcAddr := fmt.Sprintf("%s:50051", syncIP)
						if syncLocal1 != "" {
							// Extract fab1 local IP (syncLocal1 is "ip:4785").
							fab1Host, _, _ := net.SplitHostPort(syncLocal1)
							grpcAddr1 := fmt.Sprintf("%s:50051", fab1Host)
							go d.grpcSrv.RunFabricListener(commsCtx, grpcAddr1, vrfDevice)
							slog.Info("gRPC dual fabric listeners", "fab0", grpcAddr, "fab1", grpcAddr1)
						}
						d.grpcSrv.RunFabricListener(commsCtx, grpcAddr, vrfDevice)
						return
					}
					time.Sleep(time.Second)
				}
			}()

			// Wire sync stats into cluster manager for CLI display.
			d.cluster.SetSyncStats(ss)

			// Wire config sync callback: when secondary receives config from primary.
			ss.OnConfigReceived = func(configText string) error {
				d.cluster.RecordEvent(cluster.EventConfigSync, -1, fmt.Sprintf("Config received (%d bytes)", len(configText)))
				return d.handleConfigSync(configText)
			}

			// #6387: surface a persistent config-sync APPLY failure as a
			// node-global CF monitor-failure / degraded health. configApplyLoop
			// fires this on the time-based stale-duration edge (raise) and on
			// the first post-failure success (clear); the cluster manager stores
			// it as a diagnostic-only annotation. This never gates failover —
			// manual failover stays gated solely by ConfigStale(); crash
			// takeover stays ungated.
			ss.OnConfigApplyHealth = func(failing bool, reason string) {
				d.cluster.SetConfigSyncHealth(failing, reason)
			}

			// Wire peer connected callback: reconcile config to the returning
			// peer. #5863: the push is level-triggered, not a one-shot connect
			// edge — reconcileConfigSyncToPeer re-evaluates the RG0-authority +
			// stability + config-generation invariant and pushes at most once
			// per connection/generation. A node that is secondary or too young
			// at connect time correctly skips here, and a LATER promotion or
			// stability crossing re-pushes via the promotion hook / reconcile
			// loop, instead of leaving the peer indefinitely divergent.
			ss.OnPeerConnected = func() {
				d.cluster.RecordEvent(cluster.EventFabric, -1, "Peer connected")
				d.onSessionSyncPeerConnected()
				// #2239 Q7: a peer that just (re)connected (e.g. a restarted
				// standby) has an empty in-memory peerDHCPLeases set. Nudge a
				// full lease re-push so it is not briefly empty until the next
				// heartbeat tick. The nudge is RG-MASTER gated inside the push
				// loop (this node pushes only its own owned set), so it is safe
				// regardless of RG0 config authority — done before the
				// RG0-only config-push gating below.
				if cc := d.clusterConfig(); cc != nil && cc.DHCPLeaseSync {
					d.nudgeDHCPLeaseSync()
				}
				// #4385: a peer that just (re)connected may have missed the
				// one-shot empty IPsec SA advertisement during the gap, or (a
				// same-process standby) retained a stale peer set across the
				// blip. Nudge a forced re-advertise of the current set (empty or
				// not) so it converges — gated on primary + IPsecSASync inside
				// advertiseIPsecSAOnce, so it is safe regardless of this branch.
				if cc := d.clusterConfig(); cc != nil && cc.IPsecSASync {
					d.nudgeIPsecSASync()
				}
				d.reconcileConfigSyncToPeer("peer-connect")
			}

			ss.OnBulkSyncReceived = func() {
				d.cluster.RecordEvent(cluster.EventColdSync, -1, "Bulk sync completed")
				slog.Info("cluster: session sync complete, releasing VRRP hold")
				d.onSessionSyncBulkReceived()
			}

			ss.OnBulkSyncAckReceived = func() {
				d.cluster.RecordEvent(cluster.EventColdSync, -1, "Bulk sync acknowledged by peer")
				d.onSessionSyncBulkAckReceived()
			}

			ss.OnForwardSessionInstalled = func() {
				d.scheduleStandbyNeighborRefresh()
			}

			// #5085: do NOT wire the event-stream export as the cold-prime
			// bulk override. That path delivered sessions as async, LOSSY
			// event-stream incrementals (QueueSessionV4/V6 -> non-blocking
			// sendCh) and then sent an EMPTY BulkStart/BulkEnd, so the receiver
			// recorded zero session keys and skipped authoritative stale
			// reconciliation — a stale peer-owned session the standby held
			// survived cold-prime. Cold-prime now uses the lossless BulkSync
			// direct-write window (doBulkSync), which delimits a COMPLETE
			// authoritative snapshot the receiver reconciles against.
			//
			// #6031: that window is now framed from TABLE TRUTH, not from the
			// BPF `sessions`/`sessions_v6` conntrack maps BulkSync walks. Under
			// the userspace dataplane those maps are a best-effort DISPLAY
			// mirror — the helper's transit forward install never publishes a
			// conntrack row — so the walk cannot see the transit sessions that
			// dominate a forwarding node. Combined with #5085's authoritative
			// reconcile (absent from the window => DELETED), framing cold prime
			// from the mirror DELETED the standby's live peer-owned transit
			// sessions. BulkSnapshotSource supplies the owner-RG-filtered live
			// set from the helper's SessionTable via ExportOwnerRGSessions
			// instead, and doBulkSync fails CLOSED if it errors rather than
			// falling back to the destructive mirror walk.
			ss.BulkSnapshotSource = d.userspaceBulkSnapshot

			ss.OnPeerDisconnected = func() {
				d.cluster.RecordEvent(cluster.EventFabric, -1, "Peer disconnected (all fabrics)")
				d.onSessionSyncPeerDisconnected()
			}

			// Wire remote failover: when the peer requests us to transfer an RG
			// out of primary and explicitly acknowledge the result.
			// Guard: only honor the request if we are actually primary for
			// this RG. Stale/delayed sync messages can arrive after we've
			// already transitioned to secondary — blindly calling
			// ManualFailover would cause dual-resign (both nodes secondary)
			// and a 30-second traffic blackhole.
			ss.OnRemoteFailover = func(rgID int, reqID uint64) error {
				if !d.cluster.IsLocalPrimary(rgID) {
					return fmt.Errorf("%w: redundancy group %d", cluster.ErrRemoteFailoverRejected, rgID)
				}
				slog.Info("cluster: remote failover request from peer", "rg", rgID, "req_id", reqID)
				// #5640: arm the fence-completion barrier BEFORE ManualFailover
				// enqueues the async demotion event, so watchClusterEvents
				// cannot actuate-and-forget before WaitFailoverApplied observes
				// it. The applied-ack (sync layer) then waits on this barrier.
				barrier := d.armFailoverActuation(rgID, reqID)
				if err := d.cluster.ManualFailover(rgID); err != nil {
					d.disarmFailoverActuation(rgID, reqID, barrier)
					slog.Warn("cluster: remote failover failed", "rg", rgID, "err", err)
					return err
				}
				// #5079: bind an auto-restore lease to this request. If the
				// requester aborts after this ACK (or crashes / loses the fabric)
				// and never sends a commit, electRG restores us when the lease
				// expires so a failed coordinated failover cannot strand us
				// secondary. The matching commit clears the lease.
				d.cluster.ArmRemoteTransferOutLease([]int{rgID}, reqID)
				return nil
			}
			ss.OnRemoteFailoverBatch = func(rgIDs []int, reqID uint64) error {
				for _, rgID := range rgIDs {
					if !d.cluster.IsLocalPrimary(rgID) {
						return fmt.Errorf("%w: redundancy group %d", cluster.ErrRemoteFailoverRejected, rgID)
					}
				}
				slog.Info("cluster: remote batch failover request from peer", "rgs", rgIDs, "req_id", reqID)
				// #5640: arm every member's fence barrier before the batch
				// demotion enqueues its per-RG events.
				barriers := make(map[int]*failoverActuation, len(rgIDs))
				for _, rgID := range rgIDs {
					barriers[rgID] = d.armFailoverActuation(rgID, reqID)
				}
				if err := d.cluster.ManualFailoverBatch(rgIDs); err != nil {
					for _, rgID := range rgIDs {
						d.disarmFailoverActuation(rgID, reqID, barriers[rgID])
					}
					slog.Warn("cluster: remote batch failover failed", "rgs", rgIDs, "err", err)
					return err
				}
				// #5079: bind auto-restore leases to this request across the set.
				d.cluster.ArmRemoteTransferOutLease(rgIDs, reqID)
				return nil
			}
			ss.OnRemoteFailoverCommit = func(rgID int, reqID uint64) error {
				if err := d.cluster.FinalizePeerTransferOut(rgID); err != nil {
					return err
				}
				// #5079: the transfer committed — drop the auto-restore lease so
				// it can never fire on a legitimately completed handoff.
				d.cluster.ClearRemoteTransferOutLease(rgID, reqID)
				return nil
			}
			ss.OnRemoteFailoverCommitBatch = func(rgIDs []int, reqID uint64) error {
				if err := d.cluster.FinalizePeerTransferOutBatch(rgIDs); err != nil {
					return err
				}
				for _, rgID := range rgIDs {
					d.cluster.ClearRemoteTransferOutLease(rgID, reqID)
				}
				return nil
			}
			// #5640: gate the transfer-out applied-ack on the local demotion
			// actually being actuated (VRRP resigned / rg_active cleared),
			// closing the two-owner window where the peer promoted off an ack
			// sent before this node had resigned.
			ss.WaitFailoverApplied = d.waitFailoverActuated
			ss.WaitFailoverAppliedBatch = d.waitFailoverActuatedBatch

			// Wire peer failover sender so cluster Manager can send remote
			// failover requests via the fabric sync connection.
			d.cluster.SetPeerFailoverFunc(ss.SendFailover)
			d.cluster.SetPeerFailoverCommitFunc(ss.SendFailoverCommit)
			d.cluster.SetPeerFailoverBatchFunc(ss.SendFailoverBatch)
			d.cluster.SetPeerFailoverCommitBatchFunc(ss.SendFailoverCommitBatch)
			d.cluster.SetPreManualFailoverHook(d.prepareUserspaceManualFailover)
			d.cluster.SetLocalTransferCommitReadyHook(d.waitLocalFailoverCommitReady)
			// #5079: size the owner-side transfer-out lease above the requester's
			// worst-case post-ACK commit latency — the local commit-ready settle
			// window (localFailoverCommitTimeout) plus the commit round-trip — so
			// a legitimate slow commit never trips it. The cluster floors it. The
			// upstream 20s failover-ACK cap (failoverAckTimeout, sync.go) bounds
			// the actuation-barrier contribution: if the owner takes longer than
			// 20s to ack, the requester times out and sends NO commit, so a large
			// failoverActuateTimeout cannot delay a real commit past this lease.
			d.cluster.SetRemoteTransferOutLeaseDuration(2*d.localFailoverCommitTimeout + 20*time.Second)
			d.cluster.SetTransferReadinessFunc(d.userspaceTransferReadiness)
			d.cluster.SetPeerTimeoutGuard(d.shouldSuppressPeerHeartbeatTimeout)
			// #1792: while our heartbeat sockets restart (VRF rebind),
			// keep the peer's suppression guard fed with fresh sync
			// traffic so a >500ms restart does not fire a false
			// peer-timeout/fence on the peer. Bounded by the peer's
			// 5s continuous-suppression cap.
			d.cluster.SetHeartbeatRestartNotifyFunc(ss.SendLivenessKeepalive)

			// Wire peer fencing: on heartbeat timeout, cluster sends
			// fence via sync; on receive, disable all local RGs.
			d.cluster.SetPeerFenceFunc(ss.SendFence)
			ss.OnFenceReceived = func() {
				slog.Warn("cluster: fence received from peer")
				// #3917: fence the CURRENT redundancy-group set, not the
				// `cfg` snapshot captured in this closure at
				// startClusterComms time. Comms are only restarted on a
				// transport-field change (clusterTransportKey), so a
				// redundancy-group added by a day-2 commit is absent from
				// the startup snapshot. Fencing off the snapshot would
				// leave that RG active on this node while the peer also
				// becomes active for it -> split-brain dual-active. The
				// dp==nil (config-only) and nil-cluster guards live in
				// fenceAllRedundancyGroups.
				d.fenceAllRedundancyGroups(commsCtx)
			}

			ss.SetVRFDevice(vrfDevice)
			// r6-F4: the wiring resolves the provider from the #2114
			// cell per poll, so it never installs callbacks on a backend
			// the daemon has since disowned. wiredStream is the instance
			// the callbacks landed on; the fallback loop re-installs if a
			// rollback + corrected re-arm replaces it.
			var wiredStream *dpuserspace.EventStream
			if _, ok := d.dataplane().(userspaceEventStreamProvider); ok {
				// userspaceEventStreamProvider is a local probe;
				// userspace LegacyDataPlaneAdapter satisfies it via
				// EventStream (legacy_dataplane.go:414). Type-
				// assertion target is the published dataplane directly —
				// the legacyDP() round-trip retired in #1519 added no
				// method-set coverage.
				wireCtx, cancel := context.WithTimeout(commsCtx, 5*time.Second)
				wiredStream = d.wireUserspaceEventStreamCallbacks(wireCtx)
				cancel()
				if wiredStream == nil {
					slog.Warn("userspace: event stream callbacks not ready before session sync start; falling back to polling until stream wires")
				}
			}

			// Retry sync start: the VRF device and address binding may not
			// be ready during daemon startup (networkd race).
			for i := 0; i < 30; i++ {
				// #82: wire the runtime and the ownership predicates BEFORE
				// Start opens the listeners and dialers, not after it returns.
				//
				// Start spawns the accept/connect goroutines, and the first
				// connection they establish runs the authoritative cold-prime
				// bulk inside handleNewConnection. Wiring afterwards left a
				// window in which that bulk ran against a nil session store:
				// BulkSync returns "session store not ready" before it writes a
				// byte, so no disconnect follows and — before the sweep
				// re-drive added alongside this — nothing re-drove the owed
				// prime for the life of that connection. It also made
				// SetRuntime an unsynchronized write to fields the goroutines
				// Start had already spawned were reading. Assigning before the
				// goroutines exist gives the writes a happens-before edge and
				// removes the race outright.
				//
				// ONE snapshot of the published dataplane per iteration feeds
				// both this wiring and the post-Start sweep launch, so a
				// setDataplane(nil) landing mid-retry cannot be seen as non-nil
				// by one site and nil by the other (#2114 / #6743 rule).
				rt := d.dataplane()
				if rt != nil {
					ss.SetRuntime(rt)
					ss.IsPrimaryFn = func() bool {
						return d.cluster != nil && d.cluster.IsLocalPrimary(0)
					}
					ss.IsPrimaryForRGFn = func(rgID int) bool {
						return d.cluster != nil && d.cluster.IsLocalPrimary(rgID)
					}
				}
				if err := ss.Start(commsCtx); err != nil {
					if i < 5 {
						slog.Info("cluster: sync bind not ready, retrying",
							"err", err, "attempt", i+1)
					} else {
						slog.Warn("failed to start session sync, retrying",
							"err", err, "attempt", i+1)
					}
					select {
					case <-commsCtx.Done():
						return
					case <-time.After(2 * time.Second):
					}
					continue
				}
				slog.Info("cluster session sync started",
					"local", syncLocal, "peer", syncPeer, "vrf", vrfDevice)

				// Start the sweep and the event-stream drain now that the
				// listeners are up. The runtime itself was wired above, before
				// Start (#82). All of it must happen here (not in Run) because
				// the session-sync object `ss` is created asynchronously in
				// this goroutine. The published dataplane is a
				// dataplane.RuntimeDataPlane; both the legacy *Manager and the
				// userspace LegacyDataPlaneAdapter implement
				// Sessions()/Telemetry() so they satisfy the cluster package's
				// narrow clusterRuntime contract directly (#1518).
				if rt != nil {
					ss.StartSyncSweep(commsCtx)
					if wiredStream != nil {
						go d.eventStreamFallbackLoop(commsCtx, wiredStream)
					} else {
						go d.runUserspaceEventStream(commsCtx)
					}
				}

				break
			}

			// Start periodic IPsec SA sync if enabled.
			if cc.IPsecSASync && d.ipsec != nil {
				go d.syncIPsecSAPeriodic(commsCtx)
			}

			// #5863: start the level-triggered config-sync reconcile loop.
			// It is the low-frequency safety net that (a) fires the moment the
			// node crosses the stability threshold and (b) recovers any dropped
			// promotion/connect edge. Started unconditionally (config-sync may
			// be enabled by a later commit without a comms restart); it is a
			// cheap no-op on any node that is not the RG0 config authority or
			// whose current generation is already pushed.
			go d.configSyncReconcileLoop(commsCtx)

			// #2239: start the DHCP-server lease-sync push loop if enabled.
			// The loop is gated on the RG-MASTER node-level gate internally;
			// on the BACKUP it pushes nothing and the standby holds the peer
			// set via OnDHCPLeasesReceived. Routed through the idempotent
			// starter (#4647) so a later `dhcp-lease-synchronization` knob
			// toggle from the apply path shares this same launch/stop path
			// (and cannot double-launch).
			d.ensureDHCPLeaseSyncLoop(cc.DHCPLeaseSync)

			// Initialize per-fabric refresh channels for event-driven
			// updates (#124). Each fabric owns its own channel so a
			// single netlink-triggered refresh wakes both the fab0 and
			// fab1 loops rather than only whichever won a shared-channel
			// receive (#4038). #4958: build them locally, hand each loop its
			// OWN channel by value, and publish the shared fields only if this
			// epoch is still current — so a superseded constructor neither
			// replaces a newer epoch's channels nor lets its loops receive on
			// a stale field. The loops read the value they were launched with,
			// never d.fabricRefreshCh, so the sender-side field swap on restart
			// cannot race them.
			fabRefreshCh := make(chan struct{}, 1)
			fabRefreshCh1 := make(chan struct{}, 1)
			if !d.publishFabricRefreshChansIfCurrent(commsGen, fabRefreshCh, fabRefreshCh1) {
				return
			}

			// Populate fabric_fwd BPF map for cross-chassis redirect,
			// then periodically refresh to correct neighbor drift.
			// Resolve to physical parent (ge-0-0-0) — BPF runs on
			// the parent, not the IPVLAN overlay. Neighbor resolution
			// uses the overlay (fab0/fab1) where the sync IP lives (#129).
			fabParent := d.resolveFabricParent(cc.FabricInterface)
			fabOverlay := config.LinuxIfName(cc.FabricInterface)
			if fabOverlay == fabParent {
				fabOverlay = "" // no overlay — legacy mode
			}
			go d.populateFabricFwd(commsCtx, fabParent, fabOverlay, cc.FabricPeerAddress, fabRefreshCh)

			// Populate secondary fabric_fwd entry (key=1) if fab1 configured.
			if cc.Fabric1Interface != "" && cc.Fabric1PeerAddress != "" {
				fab1Parent := d.resolveFabricParent(cc.Fabric1Interface)
				fab1Overlay := config.LinuxIfName(cc.Fabric1Interface)
				if fab1Overlay == fab1Parent {
					fab1Overlay = "" // no overlay
				}
				go d.populateFabricFwd1(commsCtx, fab1Parent, fab1Overlay, cc.Fabric1PeerAddress, fabRefreshCh1)
			}

			// Monitor fabric link/neighbor state via netlink (#124).
			go d.monitorFabricState(commsCtx)
		}()
	}
}

// currentRedundancyGroups returns the redundancy-groups from the CURRENT
// active configuration (d.store.ActiveConfig()) rather than a snapshot
// captured earlier. #3917: long-lived HA goroutines wired in
// startClusterComms (peer-fence handling, watchdog heartbeat) must read
// live config at every event/tick. startClusterComms is only restarted on a
// transport-field change (clusterTransportKey), so a redundancy-group added
// by a day-2 commit never reaches a closure that captured the startup `cfg`.
// Returns nil when there is no store, no compiled config, or the config is
// not in cluster mode — every caller must tolerate an empty slice.
func (d *Daemon) currentRedundancyGroups() []*config.RedundancyGroup {
	if d.store == nil {
		return nil
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	return cfg.Chassis.Cluster.RedundancyGroups
}

// fenceAllRedundancyGroups disables rg_active for every redundancy-group in
// the CURRENT active config. It is the peer-fence handler: when a fence
// message arrives the local node must relinquish ALL redundancy-groups so
// the peer can own them without a dual-active split-brain. #3917: reading
// the live config here (via currentRedundancyGroups) ensures day-2 RGs are
// fenced too. Safe when the dataplane is nil (config-only mode) or the
// config has no cluster/RGs.
func (d *Daemon) fenceAllRedundancyGroups(ctx context.Context) {
	// Guard the published dataplane: the daemon can run in config-only mode
	// (no published dataplane)
	// when the runtime dataplane factory rejects the configured backend —
	// for example, a stale "system dataplane-type dpdk" config triggers
	// dataplane.ErrDPDKBackendRetired and daemon_run.go falls back to no
	// dataplane. Without this guard a peer fence would panic on a nil pointer
	// dereference. The same applies to any future Start() failure that
	// leaves the dataplane unpublished.
	rt := d.dataplane()
	if rt == nil {
		slog.Warn("cluster: fence received but dataplane is nil; skipping RG deactivation",
			"mode", "config-only",
			"action", "skip_rg_deactivation",
			"remediation", "set system dataplane-type userspace and restart xpfd",
		)
		return
	}
	rgs := d.currentRedundancyGroups()
	slog.Warn("cluster: fence: disabling all RGs", "rg_count", len(rgs))
	for _, rg := range rgs {
		if err := rt.HA().SetRGActive(ctx, rg.ID, false); err != nil {
			slog.Warn("cluster: fence: failed to disable rg_active",
				"rg", rg.ID, "err", err)
		}
	}
}

// startHeartbeatWithRetry resolves the control-link local address and starts
// the cluster heartbeat, retrying on a not-ready bind (the control interface
// address and VRF device may not be ready during daemon startup — a networkd
// race). It runs in its own goroutine, owned by the comms sub-context.
//
// It exits immediately when ctx is cancelled (#4033): stopClusterComms cancels
// the comms context before installing new comms, so without this the old retry
// goroutine would survive the teardown and keep looping — up to 30 * 2s = 60s
// — and could call StartHeartbeat AFTER stopClusterComms, installing a
// heartbeat into a torn-down comms lifecycle and racing the replacement
// goroutine. Every iteration (and every retry sleep) observes ctx so a comms
// restart leaves exactly one retry goroutine and one heartbeat.
func (d *Daemon) startHeartbeatWithRetry(ctx context.Context, controlIface, peerAddr, vrfDevice string) {
	for i := 0; i < 30; i++ {
		if ctx.Err() != nil {
			slog.Info("cluster: heartbeat start aborted, comms context cancelled")
			return
		}
		localIP := resolveClusterInterfaceAddr(controlIface, peerAddr, "")
		if localIP == "" {
			if i == 0 {
				slog.Info("cluster: control interface has no usable address yet, waiting",
					"interface", controlIface)
			}
			if !sleepCtx(ctx, 2*time.Second) {
				return
			}
			continue
		}
		if err := d.cluster.StartHeartbeat(localIP, peerAddr, vrfDevice); err != nil {
			if i < 5 {
				slog.Info("cluster: heartbeat bind not ready, retrying",
					"err", err, "attempt", i+1)
			} else {
				slog.Warn("failed to start cluster heartbeat, retrying",
					"err", err, "attempt", i+1)
			}
			if !sleepCtx(ctx, 2*time.Second) {
				return
			}
			continue
		}
		return
	}
	slog.Error("cluster heartbeat failed after retries")
}

// sleepCtx blocks for d or until ctx is cancelled, whichever comes first. It
// returns true if the full duration elapsed and false if ctx was cancelled —
// a false result tells a retry loop to stop rather than continue.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// stopClusterComms tears down heartbeat and session sync so they can be
// restarted with new transport settings (#87). Cancels the comms sub-context
// (which stops retry loops, fabric_fwd refresh, IPsec SA sync, sync sweep)
// and explicitly stops heartbeat + session sync listeners/connections.
//
// #4958: the teardown is epoch-safe. Under clusterCommsMu it first bumps
// clusterCommsGen — superseding any in-flight startClusterComms constructor so
// that constructor's publish is dropped (publishSessionSyncIfCurrent) — and
// captures/clears the cancel handle and comms context. It then cancels the
// context and JOINS the constructor goroutine (clusterCommsWG.Wait) so a
// cancelled-but-still-running constructor finishes (or drops) before the shared
// session-sync/fabric state is nilled. Only after the join does it clear
// sessionSync and the fabric refresh channels and Stop() the session sync. The
// join runs OUTSIDE the lock (the constructor's publish path also takes the
// lock), so there is no deadlock.
func (d *Daemon) stopClusterComms() {
	d.clusterCommsMu.Lock()
	d.clusterCommsGen++
	cancel := d.clusterCommsCancel
	d.clusterCommsCancel = nil
	d.clusterCommsCtx = nil
	d.clusterCommsMu.Unlock()

	if cancel != nil {
		cancel()
	}
	// Join the constructor goroutine before nilling shared state so its
	// publish (if it still owned the just-superseded epoch it will drop; if it
	// published before the generation bump it finishes wiring) cannot race the
	// teardown below.
	d.clusterCommsWG.Wait()

	// #4647: the lease-sync loop is scoped to the comms context just
	// cancelled, so it is already stopping; clear the cancel handle so the
	// next comms session's connect-time launch starts a fresh loop.
	d.resetDHCPLeaseSyncLoop()
	if d.cluster != nil {
		d.cluster.StopHeartbeat()
	}

	d.clusterCommsMu.Lock()
	ss := d.sessionSync
	d.sessionSync = nil
	d.fabricRefreshCh = nil
	d.fabricRefreshCh1 = nil
	d.clusterCommsMu.Unlock()

	if ss != nil {
		d.stopSyncReadyTimer()
		ss.Stop()
	}
}

// clusterTransportKey extracts the four cluster transport fields that
// determine heartbeat and session sync endpoints. Used to detect config
// changes that require restarting cluster comms.
type clusterTransportKey struct {
	ControlInterface   string
	PeerAddress        string
	FabricInterface    string
	FabricPeerAddress  string
	Fabric1Interface   string
	Fabric1PeerAddress string
}

func clusterTransportFromConfig(cfg *config.Config) clusterTransportKey {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return clusterTransportKey{}
	}
	cc := cfg.Chassis.Cluster
	return clusterTransportKey{
		ControlInterface:   cc.ControlInterface,
		PeerAddress:        cc.PeerAddress,
		FabricInterface:    cc.FabricInterface,
		FabricPeerAddress:  cc.FabricPeerAddress,
		Fabric1Interface:   cc.Fabric1Interface,
		Fabric1PeerAddress: cc.Fabric1PeerAddress,
	}
}

// setActiveTransport publishes the transport key of the comms epoch that
// startClusterComms is bringing up, and activeTransport reads it back — both
// under clusterCommsMu (#6290).
//
// The lock is required, not decorative. The field is written by
// startClusterComms, which runs on the boot path (daemon_run.go) holding
// NEITHER applySem NOR this mutex, and read by applyTailReconciles step 20,
// which runs under applySem. A semaphore only excludes participants that take
// it, so applySem orders the readers against each other and not against the
// boot writer.
//
// The boot ordering does not close the gap either. The boot applyConfig
// (daemon_run_bringup.go) starts the DHCP clients via reconcileDHCPClients
// (daemon_apply_routing.go) with onDHCPAddressChange already wired
// (daemon_run_bringup.go), and that callback re-enters applyConfig — hence
// step 20 — on its own goroutine. Those goroutines are created BEFORE the boot
// startClusterComms write, so goroutine creation orders them the wrong way and
// establishes no happens-before from the write to their reads. A lease
// arriving in that window is an unsynchronized concurrent read/write of a
// six-string struct: a real Go data race, not a theoretical one. The same
// hazard on mgmtVRFInterfaces (#5113, see daemon.go) has the mirror shape —
// written under applySem, read by the same callback without it — and was fixed
// the same way.
//
// activeTransport also returns ONE snapshot, so step 20's comparison and the
// eight fields it logs all describe a single epoch rather than up to six
// separate reads that a concurrent restart could interleave.
//
// setActiveTransportIfCurrent is epoch-gated rather than a bare locked store,
// mirroring publishSessionSyncIfCurrent. The same window that makes the race
// reachable also admits two concurrent startClusterComms calls (the boot one
// and a DHCP-callback-driven restart from step 20). Both would bump the epoch
// and both would publish; with an ungated store the LOSER of that ordering can
// land last, leaving the transport key describing a superseded epoch while
// clusterCommsGen names the live one. Step 20 would then compare the next
// commit against the wrong baseline and either skip a needed comms restart or
// perform a spurious one. Gating on gen makes a superseded publish drop
// instead, exactly as the #4958 fields do.
func (d *Daemon) setActiveTransportIfCurrent(gen uint64, k clusterTransportKey) bool {
	d.clusterCommsMu.Lock()
	defer d.clusterCommsMu.Unlock()
	if gen != d.clusterCommsGen {
		slog.Debug("cluster: dropping stale transport publish (comms epoch superseded)",
			"publish_gen", gen, "current_gen", d.clusterCommsGen)
		return false
	}
	d.activeClusterTransport = k
	return true
}

func (d *Daemon) activeTransport() clusterTransportKey {
	d.clusterCommsMu.Lock()
	defer d.clusterCommsMu.Unlock()
	return d.activeClusterTransport
}
