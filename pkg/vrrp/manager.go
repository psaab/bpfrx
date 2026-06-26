package vrrp

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"github.com/vishvananda/netlink"
)

// instanceKey identifies a unique VRRP instance.
type instanceKey struct {
	iface   string
	groupID int
}

// Manager manages all VRRP instances.
type Manager struct {
	mu             sync.RWMutex
	instances      map[instanceKey]*vrrpInstance
	eventCh        chan VRRPEvent
	closeEventOnce sync.Once // guards closing eventCh
	cancel         context.CancelFunc
	syncHold       bool        // suppress preemption until session sync completes
	syncHoldTimer  *time.Timer // safety timeout to release hold
	syncHoldReason string      // "bulk-sync-complete" or "timeout-degraded"
	onEventDrop    func()      // called when an event is dropped (full channel)

	// Interface tracking (#1814): ONE singleton link-watcher goroutine
	// feeds trackDown into instances whose cfg.TrackInterface matches.
	watcherRunning  bool          // guarded by mu — singleton latch
	watcherStarts   int           // guarded by mu — observability/test seam
	watcherStop     chan struct{} // closed by Stop()
	watcherStopOnce sync.Once

	// Injectable link-state seams (unit tests must not require real
	// netlink). Production defaults are set in NewManager.
	linkState      func(name string) (bool, error)
	subscribeLinks func(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error

	// linkNames is the link-watcher's ifindex -> current-name cache (#2944).
	// The kernel emits a runtime rename as a SINGLE RTM_NEWLINK carrying the
	// SAME ifindex with the NEW name and NO RTM_DELLINK for the old name, so
	// name-only matching would leave an instance tracking the old name stuck at
	// its last (typically up) state forever. Keying on the stable ifindex lets
	// the watcher notice that an ifindex's name CHANGED and re-evaluate the old
	// (now-vanished) name so the tracking instance demotes. Guarded by mu;
	// owned by the singleton link-watcher goroutine and reset per run.
	linkNames map[int]string

	// Source-address watcher (#2528): ONE singleton goroutine subscribing to
	// netlink ADDRESS updates so an instance's cached advert source
	// (localIP/localIPv6) is re-resolved when the interface's address changes
	// — closes the stale-source split-brain window opened by the RETH MAC
	// reprogram cycle. Distinct latch from the link-watcher; both share
	// m.watcherStop for cancellation. subscribeAddrs defaults to
	// netlink.AddrSubscribe and is injectable so unit tests need no real
	// netlink.
	addrWatcherRunning bool // guarded by mu — singleton latch
	addrWatcherStarts  int  // guarded by mu — observability/test seam
	subscribeAddrs     func(ch chan<- netlink.AddrUpdate, done <-chan struct{}) error

	// desiredIfaces is the set of interface NAMES from the most recent
	// UpdateInstances desired set (#2788). It lets the addr-watcher recognise
	// an address event for a CONFIGURED interface that has no instance yet —
	// the late-appearing-interface case: a member/VLAN/RETH netdev that did
	// not exist (or was unresolvable) at the UpdateInstances that last ran, so
	// resolveIface failed and no instance was built and added to m.instances.
	// Such an interface is absent from BOTH addrwatch match loops (cached
	// ifindex and name-drift), so its first address event would be dropped and
	// the instance would wait up to ~2s for the periodic reconcile to retry
	// the build. Recording the desired names lets us schedule an immediate
	// reconcile on that first event instead. Guarded by mu.
	desiredIfaces map[string]struct{}

	// resolveLinkName maps a kernel ifindex to its current link NAME. The
	// addr-watcher (#2707) calls it ONLY on a cached-ifindex miss — when an
	// address event arrives for an ifindex no instance is bound to. A
	// VLAN/GRE/WireGuard link that is deleted+recreated (config change, driver
	// restart, link-cycle recovery) gets a NEW ifindex, so the cached
	// vi.iface.Index no longer matches and every subsequent address event on
	// the recreated link would be ignored until the ~2s reconcile noticed the
	// drift. Resolving the event ifindex back to a name lets us re-match the
	// instance by its STABLE configured name and trigger an immediate
	// reconcile. Defaults to a netlink.LinkByIndex wrapper; injectable so unit
	// tests need no real netlink.
	resolveLinkName func(ifindex int) (string, error)

	// Injectable instance-lifecycle seams (#2156). Unit tests must not
	// require real raw sockets or a live run() goroutine to exercise the
	// build-before-teardown ordering in UpdateInstances. Production
	// defaults are set in NewManager:
	//   resolveIface       -> net.InterfaceByName
	//   openInstanceSocket -> vi.openSocket()   (the "proof" step)
	//   runInstance        -> `go vi.run()`     (the "commit" step)
	//   stopInstance       -> vi.stop()
	resolveIface       func(name string) (*net.Interface, error)
	openInstanceSocket func(vi *vrrpInstance) error
	runInstance        func(vi *vrrpInstance)
	stopInstance       func(vi *vrrpInstance)
}

// SetOnEventDrop registers a callback invoked when a VRRP event is dropped
// due to a full channel. The daemon uses this to schedule an immediate
// reconciliation pass.
func (m *Manager) SetOnEventDrop(fn func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onEventDrop = fn
}

// NewManager creates a new VRRP manager.
func NewManager() *Manager {
	return &Manager{
		instances:          make(map[instanceKey]*vrrpInstance),
		eventCh:            make(chan VRRPEvent, 256),
		watcherStop:        make(chan struct{}),
		linkNames:          make(map[int]string),
		linkState:          netlinkLinkState,
		subscribeLinks:     netlinkLinkSubscribe,
		subscribeAddrs:     netlink.AddrSubscribe,
		resolveLinkName:    netlinkLinkName,
		resolveIface:       net.InterfaceByName,
		openInstanceSocket: func(vi *vrrpInstance) error { return vi.openSocket() },
		runInstance:        func(vi *vrrpInstance) { go vi.run() },
		stopInstance:       func(vi *vrrpInstance) { vi.stop() },
	}
}

// Start initializes the manager (no shared socket — each instance has its own).
//
// Start is reuse-safe: a Manager that was previously Stop()ped can be
// Start()ed again. Stop() closes the run-scoped channels (watcherStop,
// eventCh) and cancels the context; Start() re-allocates those channels,
// resets the sync.Once guards, and clears the singleton watcher latches so
// the next UpdateInstances cleanly re-spawns the link/addr watchers
// (#2625). Without this re-init a Stop->Start cycle would: hand callers a
// closed eventCh (send-on-closed panic), make every freshly-spawned
// watcher observe the already-closed watcherStop and exit immediately, and
// leave watcherRunning/addrWatcherRunning latched true so ensure*Locked
// never re-spawns. Production creates the Manager once and only Stop()s at
// shutdown, so this is a latent-lifecycle fix; the unit tests are the
// safety net (the cluster failover gate exercises the single-run path).
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	m.resetRunStateLocked()
	_, m.cancel = context.WithCancel(ctx)
	m.mu.Unlock()
	slog.Info("vrrp: manager started")
	return nil
}

// resetRunStateLocked re-initializes the per-run channels, once-guards, and
// singleton watcher latches so the Manager is safe to Start() after a Stop().
// Caller MUST hold m.mu. It is also invoked implicitly from NewManager's
// equivalent field initialization — the values here mirror NewManager's
// run-scoped defaults so a fresh-construct and a reuse-after-Stop converge on
// the same state. It deliberately does NOT touch instances, seams
// (linkState/subscribe*/resolve*/run/stop/open), or the onEventDrop callback:
// those are construction-time or caller-owned, not run-scoped.
func (m *Manager) resetRunStateLocked() {
	m.watcherStop = make(chan struct{})
	m.watcherStopOnce = sync.Once{}
	m.eventCh = make(chan VRRPEvent, 256)
	m.closeEventOnce = sync.Once{}
	m.watcherRunning = false
	m.addrWatcherRunning = false
	// Drop the previous run's ifindex->name cache (#2944): a re-subscribe
	// re-seeds it from current kernel state (ListExisting), so a stale mapping
	// from before the Stop() must not survive into the new run.
	m.linkNames = make(map[int]string)
}

// Stop stops all instances, removes VIPs, and cancels the context.
func (m *Manager) Stop() {
	m.mu.Lock()
	if m.syncHoldTimer != nil {
		m.syncHoldTimer.Stop()
	}
	instances := make(map[instanceKey]*vrrpInstance, len(m.instances))
	for k, v := range m.instances {
		instances[k] = v
	}
	m.instances = make(map[instanceKey]*vrrpInstance)
	// Capture a CONSISTENT once/channel pair (and the channel) under the lock
	// so the close below operates on a matched generation. This keeps the
	// realistic sequential reuse correct: Stop() closes generation N's
	// channels, then a later Start() re-allocates generation N+1's via
	// resetRunStateLocked (also under m.mu).
	//
	// It does NOT make a concurrent Stop()+Start() race-free: the once-guard
	// Do() and the channel reads run AFTER the lock is released (they must —
	// vi.stop() below blocks on each run() goroutine exiting and cannot hold
	// m.mu, and the close has to follow the instance teardown ordering). A
	// hypothetical concurrent Start() resetting watcherStopOnce / re-allocating
	// the channels could still interleave. That is not reachable today: the
	// Manager is not designed for concurrent Stop/Start — its sole caller (the
	// daemon) does Start-once at init and Stop-once at shutdown, never
	// concurrently (#2625). No locking machinery is added for the unreachable
	// case; the capture is only to keep the pair self-consistent.
	watcherStop := m.watcherStop
	watcherStopOnce := &m.watcherStopOnce
	eventCh := m.eventCh
	closeEventOnce := &m.closeEventOnce
	cancel := m.cancel
	m.mu.Unlock()

	// Stop all instances (removes VIPs, sends priority-0, closes per-instance
	// socket) BEFORE closing eventCh: the stopCh shutdown arm in run() does not
	// emitEvent, but stopping instances first keeps the channel-close strictly
	// after all senders are quiesced regardless.
	for _, vi := range instances {
		vi.stop()
	}

	// Stop the singleton link/addr watchers (done-channel cancellation; the
	// netlink subscriptions observe the same channel). Both watchers pinned
	// this exact channel at spawn time, so closing it cancels precisely this
	// run generation's goroutines; a later Start() re-allocates a fresh one.
	watcherStopOnce.Do(func() { close(watcherStop) })

	// Close events channel so watchers (e.g. daemon's watchVRRPEvents) unblock.
	closeEventOnce.Do(func() { close(eventCh) })

	if cancel != nil {
		cancel()
	}
	slog.Info("vrrp: manager stopped")
}

// SetSyncHold enables sync hold mode — all VRRP instances start with
// preempt=false regardless of config, suppressing preemption until session
// sync completes. A safety timeout releases the hold if sync never arrives.
func (m *Manager) SetSyncHold(timeout time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if m.syncHoldTimer != nil {
		m.syncHoldTimer.Stop()
		m.syncHoldTimer = nil
	}
	wasHeld := m.syncHold
	m.syncHold = true
	m.syncHoldReason = ""
	if !wasHeld {
		for _, vi := range m.instances {
			vi.suppressPreempt()
		}
	}
	m.syncHoldTimer = time.AfterFunc(timeout, func() {
		slog.Warn("vrrp: sync-hold timeout: bulk sync did not complete within timeout, releasing in degraded mode",
			"timeout", timeout)
		m.releaseSyncHoldWithReason("timeout-degraded")
	})
	slog.Info("vrrp: sync hold active, preemption disabled", "timeout", timeout)
}

// ReleaseSyncHold restores configured preempt values on all instances,
// allowing normal VRRP preemption to proceed. Records reason as
// "bulk-sync-complete" (the normal path).
func (m *Manager) ReleaseSyncHold() {
	m.releaseSyncHoldWithReason("bulk-sync-complete")
}

// releaseSyncHoldWithReason is the internal release path that records why
// the sync hold was released.
func (m *Manager) releaseSyncHoldWithReason(reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.syncHold {
		return
	}
	m.syncHold = false
	m.syncHoldReason = reason
	if m.syncHoldTimer != nil {
		m.syncHoldTimer.Stop()
		m.syncHoldTimer = nil
	}
	for _, vi := range m.instances {
		vi.restorePreempt()
		vi.triggerPreemptNow()
	}
	slog.Info("vrrp: sync hold released, preemption enabled", "reason", reason)
}

// InSyncHold returns true if the manager is in sync-hold state (startup,
// waiting for session sync before allowing preemption).
func (m *Manager) InSyncHold() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.syncHold
}

// SyncHoldReason returns why the sync hold was released: "bulk-sync-complete"
// for normal operation, "timeout-degraded" if the safety timeout fired before
// bulk sync arrived, or "" if sync hold was never set or is still active.
func (m *Manager) SyncHoldReason() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.syncHoldReason
}

// Events returns the event channel for state change notifications.
func (m *Manager) Events() <-chan VRRPEvent {
	return m.eventCh
}

// UpdateInstances diffs the current instances against the desired set and
// adds/removes/updates as needed.
func (m *Manager) UpdateInstances(desired []*Instance) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Build desired map. Also record the set of desired interface NAMES so the
	// addr-watcher can recognise an address event for a configured interface
	// that has no instance built yet (#2788, late-appearing interface).
	desiredMap := make(map[instanceKey]*Instance, len(desired))
	desiredIfaces := make(map[string]struct{}, len(desired))
	for _, inst := range desired {
		key := instanceKey{iface: inst.Interface, groupID: inst.GroupID}
		desiredMap[key] = inst
		desiredIfaces[inst.Interface] = struct{}{}
		// Lazily start the singleton link watcher once any instance
		// tracks an interface (#1814). Idempotent under m.mu — repeat
		// UpdateInstances churn never spawns a second goroutine.
		if inst.TrackInterface != "" {
			m.ensureLinkWatcherLocked()
		}
		// Lazily start the singleton address watcher once ANY instance
		// exists (#2528). Every VRRP interface needs its advert source
		// re-resolved when its address changes — not just tracked ones — so
		// this is ungated. Idempotent under m.mu.
		m.ensureAddrWatcherLocked()
	}
	// Publish the desired-name set for the addr-watcher (#2788). Replaced
	// wholesale every reconcile so a removed interface stops being treated as
	// late-appearing.
	m.desiredIfaces = desiredIfaces

	// Remove instances no longer desired.
	for key, vi := range m.instances {
		if _, ok := desiredMap[key]; !ok {
			slog.Info("vrrp: removing instance", "key", vi.key())
			vi.stop()
			delete(m.instances, key)
		}
	}

	// Add or update instances.
	for key, inst := range desiredMap {
		existing, ok := m.instances[key]
		if ok {
			// #2294: detect ifindex drift on an otherwise-unchanged
			// instance. The per-instance AF_PACKET / raw / IPv6 sockets are
			// bound to the member interface's kernel ifindex at openSocket()
			// time. If the netdev is deleted+recreated or renamed
			// (carrier/VLAN flap that fully removes and re-adds the link) its
			// ifindex changes while the xpf config stays byte-identical, so
			// the no-change and in-place (priority-only) branches below would
			// leave the instance bound to the STALE ifindex — its sockets can
			// no longer send/receive VRRP adverts and the RG goes permanently
			// silent (split-brain / blackhole) until an operator re-commit or
			// daemon restart. When the live ifindex differs from the bound
			// one we force the build-before-teardown restart path below (a
			// fresh socket is mandatory; a config-only in-place update cannot
			// rebind).
			//
			// The probe is a cheap, TOLERANT name->ifindex resolve: a resolve
			// FAILURE is treated as "no drift" so a transient netlink hiccup
			// never blocks a time-critical priority/preempt in-place update
			// (failover priority, sync-hold release) — those paths
			// historically never touched netlink, and the build block below
			// already owns the resolve-failure-keeps-old-instance recovery.
			// Detection is idempotent: an unchanged ifindex returns false and
			// the normal no-change / in-place path runs with no churn. This
			// runs every ~2s reconcile tick (daemon reconcileVRRPInstances),
			// so it neither allocates nor restarts on a steady config.
			ifindexChanged := false
			if probe, perr := m.resolveIface(inst.Interface); perr == nil && probe.Index != existing.iface.Index {
				ifindexChanged = true
			}

			// Check if config changed (and the live ifindex is unchanged).
			if !ifindexChanged &&
				existing.cfg.Priority == inst.Priority &&
				existing.cfg.Preempt == inst.Preempt &&
				existing.cfg.PreemptHoldTime == inst.PreemptHoldTime &&
				existing.cfg.TrackInterface == inst.TrackInterface &&
				existing.cfg.TrackPriorityCost == inst.TrackPriorityCost &&
				vipsEqual(existing.cfg.VirtualAddresses, inst.VirtualAddresses) {
				continue // No change.
			}
			// If only priority/preempt/tracking changed (and the ifindex is
			// unchanged), update in-place without stopping. Restarting would
			// cause a 3s master-down gap where the node falsely becomes
			// MASTER before hearing the peer. An ifindex change is NOT
			// in-place-updatable — it requires a fresh socket — so it skips
			// this arm and falls through to the build-before-teardown path.
			if !ifindexChanged && vipsEqual(existing.cfg.VirtualAddresses, inst.VirtualAddresses) {
				slog.Info("vrrp: priority update", "key", existing.key(),
					"old_pri", existing.cfg.Priority, "new_pri", inst.Priority)
				trackIfaceChanged := existing.cfg.TrackInterface != inst.TrackInterface
				instCfg := *inst
				if m.syncHold {
					instCfg.Preempt = false
				}
				existing.updateConfig(instCfg)
				if m.syncHold {
					existing.setDesiredPreempt(inst.Preempt)
				}
				if trackIfaceChanged {
					m.seedTrackState(existing, inst.TrackInterface)
				}
				continue
			}
			// VIPs changed OR the ifindex drifted — the instance must be
			// restarted (changing the VIP set or rebinding to a new ifindex
			// requires re-opening sockets and re-running the state machine).
			// BUILD THE REPLACEMENT BEFORE TEARING DOWN the old one (#2156):
			// a transient member-link failure (carrier flap, mid-rename by
			// networkd) used to delete the working instance and then
			// `continue` on InterfaceByName/openSocket error, orphaning the
			// RG out of VRRP election until an operator re-commit. Falls
			// through to the shared build block below; the old instance is
			// only stopped+replaced on a fully-built replacement. The restart
			// preserves the configured priority/preempt/tracking (it rebuilds
			// from the same desired `inst`) and re-applies sync-hold
			// suppression below, so an ifindex rebind cannot spuriously
			// preempt or break the sync hold. RG role in the cluster state
			// machine is driven separately (heartbeat / debounced priority),
			// not reset here.
			if ifindexChanged {
				slog.Info("vrrp: restarting instance (ifindex changed)",
					"key", existing.key(), "old_ifindex", existing.iface.Index)
			} else {
				slog.Info("vrrp: restarting instance", "key", existing.key(),
					"old_pri", existing.cfg.Priority, "new_pri", inst.Priority)
			}
		}

		// Build the (possibly replacement) instance. On ANY build failure we
		// leave m.instances untouched: an existing instance keeps advertising
		// its old VIP set (strictly better than dropping out of election), and
		// a brand-new key is simply not created yet. The 2s reconcile re-drive
		// (daemon reconcileVRRPInstances) and the two existing UpdateInstances
		// callers retry until the interface returns. No placeholder state is
		// added, so RGVRRPReady and the other map readers stay truthful. This
		// resolve is the authoritative one bound into the new instance; the
		// #2294 drift probe above is only a cheap detector.
		iface, err := m.resolveIface(inst.Interface)
		if err != nil {
			slog.Warn("vrrp: interface not found, keeping existing instance",
				"interface", inst.Interface, "have_existing", ok, "err", err)
			continue
		}

		instCfg := *inst
		if m.syncHold {
			instCfg.Preempt = false
		}
		vi := newInstance(instCfg, iface, m.eventCh, m.onEventDrop)
		// Store the real configured preempt value for when sync hold releases.
		vi.desiredPreempt = inst.Preempt

		// Seed tracked-link state before the state machine starts so the
		// first advert already carries the effective priority (#1814).
		if inst.TrackInterface != "" {
			m.seedTrackState(vi, inst.TrackInterface)
		}

		// PROOF step: open the per-instance socket. This is the operation
		// that fails on a transient member-link problem. On failure the new
		// instance is discarded WITHOUT touching m.instances — the old one
		// (if any) keeps running and advertising its old VIPs
		// (build-before-teardown). run() has NOT been started, so there is
		// no goroutine to stop and no fd leak (openSocket closes its own
		// conn on error).
		if err := m.openInstanceSocket(vi); err != nil {
			slog.Warn("vrrp: failed to open socket, keeping existing instance",
				"interface", inst.Interface, "have_existing", ok, "err", err)
			continue
		}

		// COMMIT step: the replacement is proven buildable. Only now tear
		// down the old instance, then swap in and start the new one. stop()
		// blocks on the old run() goroutine exiting before the new run()
		// owns the key, so the two state machines never run concurrently
		// for the same key (no double-run).
		if ok {
			m.stopInstance(existing)
		}
		m.instances[key] = vi
		m.runInstance(vi)
	}

	return nil
}

// ResignRG forces all VRRP instances for the given redundancy group
// to resign by sending priority-0 adverts and transitioning to BACKUP.
// Also immediately sets the instance priority to 0 to prevent
// re-election before the debounced priority update fires.
// Used when cluster state transitions from Primary to Secondary
// (manual failover, weight drop, etc.) in non-preempt mode.
func (m *Manager) ResignRG(rgID int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	vrid := 100 + rgID
	for _, vi := range m.instances {
		if vi.cfg.GroupID == vrid {
			// Set priority to 0 BEFORE triggering resign. Without this,
			// the masterDown timer (~97ms) can fire before the debounced
			// priority update (500ms), causing the instance to re-elect
			// at the old high priority and knock the peer back to BACKUP.
			vi.mu.Lock()
			vi.cfg.Priority = 0
			vi.mu.Unlock()
			vi.triggerResign()
		}
	}
}

// UpdateRGPriority immediately sets the VRRP priority for all instances
// belonging to the given redundancy group. Used to restore priority
// after ResignRG set it to 0 — e.g. when a cluster event transitions
// the RG back to Primary before the debounced VRRP update fires.
func (m *Manager) UpdateRGPriority(rgID int, priority int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	vrid := 100 + rgID
	for _, vi := range m.instances {
		if vi.cfg.GroupID == vrid {
			vi.mu.Lock()
			old := vi.cfg.Priority
			vi.cfg.Priority = priority
			vi.mu.Unlock()
			if old != priority {
				slog.Info("vrrp: immediate priority update",
					"key", vi.key(), "old_pri", old, "new_pri", priority)
			}
		}
	}
}

// ForceRGMaster forces all VRRP instances for the given redundancy group
// to become MASTER, even with preempt=false. Used when the cluster state
// machine has determined this node is primary for the RG but VRRP hasn't
// transitioned (e.g. after failover reset with preempt=false).
// Uses a one-shot forcePreemptOnce flag instead of modifying cfg.Preempt,
// so the configured preempt value is never leaked.
func (m *Manager) ForceRGMaster(rgID int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	vrid := 100 + rgID
	for _, vi := range m.instances {
		if vi.cfg.GroupID == vrid && vi.getState() != StateMaster {
			slog.Info("vrrp: forcing MASTER (cluster authoritative)",
				"key", vi.key())
			vi.mu.Lock()
			vi.forcePreemptOnce = true
			vi.mu.Unlock()
			vi.triggerPreemptNow()
		}
	}
}

// ReconcileVIPs re-adds VIPs on any MASTER instances. Call this after
// operations that may remove addresses (e.g. programRethMAC link down/up).
func (m *Manager) ReconcileVIPs() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, vi := range m.instances {
		if vi.getState() == StateMaster {
			vi.addVIPs()
			// Bump garpEpoch so the epoch-dedup in sendGARP() doesn't
			// block this send. ReconcileVIPs is called after programRethMAC
			// (link DOWN/UP) which changes the MAC — GARP is critical here.
			vi.garpEpoch.Add(1)
			if !vi.suppressGARP.Load() {
				// force=true: bypass the 500ms time dampener. The epoch bump
				// above defeats the epoch-dedup, but the dampener would STILL
				// suppress this burst if any routine GARP was emitted in the
				// prior 500ms — leaving peers with a stale ARP entry for the
				// just-changed RETH virtual MAC until it ages out (#2081).
				vi.sendGARP(true)
			}
		}
	}
}

// SetGARPSuppression enables or disables GARP/NA suppression for all VRRP
// instances belonging to the given redundancy group. Used by strict-vip-ownership
// mode to prevent duplicate GARP/NA during failover windows.
func (m *Manager) SetGARPSuppression(rgID int, suppress bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	vrid := 100 + rgID
	for _, vi := range m.instances {
		if vi.cfg.GroupID == vrid {
			// Swap (not Store) so we can detect the true->false EDGE.
			// Lifting suppression on an instance that is ALREADY MASTER
			// (common in active-active strict-vip negotiation where the
			// secondary briefly won the election before this node was
			// promoted to RG primary) does NOT trigger any VRRP state
			// transition, so becomeMaster's GARP/NA burst never fires —
			// the VIP stays silent and traffic blackholes until the
			// periodic timer eventually announces it. Fire a forced burst
			// on the unsuppress edge to refresh neighbor MAC bindings
			// immediately (#2940).
			old := vi.suppressGARP.Swap(suppress)
			slog.Info("vrrp: GARP suppression updated",
				"key", vi.key(), "rgID", rgID, "suppress", suppress)
			if old && !suppress && vi.getState() == StateMaster {
				// force=true bypasses ONLY the 500ms time dampener so a
				// routine GARP within the prior 500ms cannot swallow this
				// announce; the per-epoch dedup still applies, so an
				// idempotent re-unsuppress (or an epoch already announced)
				// does not re-emit. Async, matching becomeMaster, so the
				// cluster event handler is never blocked. sendGARP emits
				// both IPv4 GARP and IPv6 NA in one burst.
				slog.Info("vrrp: forcing GARP/NA on unsuppress while MASTER",
					"key", vi.key(), "rgID", rgID)
				go vi.sendGARP(true)
			}
		}
	}
}

// RGVRRPReady returns whether at least one VRRP instance exists and is
// running for the given redundancy group. The RG ID is mapped to VRID
// as 100 + rgID (the standard RETH VRID convention).
// hasRETH indicates whether the RG has any RETH interfaces configured.
// Returns (true, nil) if ready, (false, reasons) if not.
func (m *Manager) RGVRRPReady(rgID int, hasRETH bool) (bool, []string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	vrid := 100 + rgID
	for _, vi := range m.instances {
		if vi.cfg.GroupID == vrid {
			return true, nil // instance exists for this RG
		}
	}

	// No instance for this RG. If the RG has no RETH interfaces
	// (e.g. RG 0 is control-plane only), it has no VRRP requirement.
	if !hasRETH {
		return true, nil
	}

	// RG has RETH interfaces but no VRRP instance yet — not ready.
	return false, []string{fmt.Sprintf("vrrp: no instance for RG %d (VRID %d)", rgID, vrid)}
}

// States returns the current state of all instances.
// Key format: "VI_<iface>_<group>" → "MASTER", "BACKUP", "INIT".
func (m *Manager) States() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	states := make(map[string]string, len(m.instances))
	for _, vi := range m.instances {
		states[vi.key()] = vi.getState().String()
	}
	return states
}

// InstanceStates returns structured per-instance state. Each entry contains
// the interface name, group ID, and current VRRP state. Used by the
// reconciliation loop to verify that rg_active and blackhole routes match
// actual VRRP state.
func (m *Manager) InstanceStates() []VRRPEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]VRRPEvent, 0, len(m.instances))
	for _, vi := range m.instances {
		out = append(out, VRRPEvent{
			Interface: vi.cfg.Interface,
			GroupID:   vi.cfg.GroupID,
			State:     vi.getState(),
		})
	}
	return out
}

// RXDropStats returns per-instance RX drop and received counts.
// Key format: "VI_<iface>_<group>".
func (m *Manager) RXDropStats() map[string]uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[string]uint64, len(m.instances)*2)
	for _, vi := range m.instances {
		k := vi.key()
		stats[k+"/drops"] = vi.rxDrops.Load()
		stats[k+"/received"] = vi.rxReceived.Load()
	}
	return stats
}

// Status returns a formatted multi-line status string.
func (m *Manager) Status() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.instances) == 0 {
		return "VRRP: no instances configured\n"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("VRRP: %d instance(s) running\n\n", len(m.instances)))

	// Sort keys for deterministic output.
	keys := make([]instanceKey, 0, len(m.instances))
	for k := range m.instances {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].iface != keys[j].iface {
			return keys[i].iface < keys[j].iface
		}
		return keys[i].groupID < keys[j].groupID
	})

	for _, key := range keys {
		vi := m.instances[key]
		state := vi.getState()
		sb.WriteString(fmt.Sprintf("  %s: state=%s, priority=%d, preempt=%t, interval=%dms\n",
			vi.key(), state, vi.cfg.Priority, vi.cfg.Preempt, vi.cfg.AdvertiseInterval))
		for _, vip := range vi.cfg.VirtualAddresses {
			sb.WriteString(fmt.Sprintf("    VIP: %s\n", vip))
		}
	}

	return sb.String()
}

// bindSocketToDevice applies SO_BINDTODEVICE to fd, pinning it to ifName. It
// is a package var so tests can intercept the call and assert whether the
// per-interface raw-socket setup binds to the device (it must on a plain
// interface, must NOT on a VLAN sub-interface) without needing CAP_NET_RAW or
// a real socket fd. Both the IPv4 (openPerInterfaceSocket) and IPv6
// (openIPv6Socket) paths route through this seam so the VLAN-skip decision is
// observable and stays symmetric across families (#2786).
var bindSocketToDevice = func(fd int, ifName string) error {
	return unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifName)
}

// maybeBindToDevice applies SO_BINDTODEVICE to fd ONLY when ifName is a plain
// (non-VLAN) interface. On a VLAN sub-interface it is a no-op: generic-XDP
// VLAN tag handling makes the kernel's interface association unpredictable, so
// pinning the socket to the sub-interface index can drop VRRP multicast. Both
// the IPv4 (openPerInterfaceSocket) and IPv6 (openIPv6Socket) raw-socket paths
// MUST route their device bind through this single decision so the two
// families behave identically on a VLAN RETH member — an asymmetry here lets
// one family miss peer adverts and split-brain (#2786).
func maybeBindToDevice(fd int, ifName string, isVLAN bool) error {
	if isVLAN {
		return nil
	}
	return bindSocketToDevice(fd, ifName)
}

// openPerInterfaceSocket creates a raw IP socket (proto 112) and joins the
// VRRP multicast group (224.0.0.18) on the given interface.
// For non-VLAN interfaces, SO_BINDTODEVICE is used for isolation.
// For VLAN sub-interfaces, SO_BINDTODEVICE is skipped because generic XDP
// VLAN handling makes the kernel's interface association unpredictable —
// the packet may be delivered on the parent or sub-interface depending on
// when VLAN stripping occurs. The VRID filter in receiver() provides demuxing.
func openPerInterfaceSocket(ifName string, iface *net.Interface, isVLAN bool) (*ipv4.RawConn, net.PacketConn, error) {
	// Open raw socket for VRRP (protocol 112).
	conn, err := net.ListenPacket("ip4:112", "0.0.0.0")
	if err != nil {
		return nil, nil, fmt.Errorf("listen ip4:112: %w", err)
	}

	// For plain (non-VLAN) interfaces, bind to the interface via SyscallConn
	// (avoids File() which sets blocking mode and removes the fd from Go's
	// poller). maybeBindToDevice skips the bind on VLAN sub-interfaces.
	if !isVLAN {
		sc, err := conn.(*net.IPConn).SyscallConn()
		if err != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("syscall conn: %w", err)
		}
		var bindErr error
		if err := sc.Control(func(fd uintptr) {
			bindErr = maybeBindToDevice(int(fd), ifName, isVLAN)
		}); err != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("control: %w", err)
		}
		if bindErr != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("SO_BINDTODEVICE %s: %w", ifName, bindErr)
		}
	}

	rawConn, err := ipv4.NewRawConn(conn)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("raw conn: %w", err)
	}

	// Join VRRP multicast group on this interface.
	group := net.IPv4(224, 0, 0, 18)
	if err := rawConn.JoinGroup(iface, &net.IPAddr{IP: group}); err != nil {
		slog.Debug("vrrp: join multicast failed", "interface", ifName, "err", err)
	}

	return rawConn, conn, nil
}

// afPacketSocket is the socket(2) entry point used by openAfPacketReceiver.
// It is a package var so tests can intercept the call and assert the type
// flags (notably SOCK_CLOEXEC) without needing CAP_NET_RAW.
var afPacketSocket = unix.Socket

// openAfPacketReceiver opens an AF_PACKET SOCK_RAW socket bound to the
// given interface for receiving VRRP packets. This is used on VLAN sub-
// interfaces where raw IP sockets don't reliably receive multicast.
// SOCK_RAW keeps the Ethernet header — the cBPF VLAN filter and the Go
// parser both expect data starting at the L2 header.
func openAfPacketReceiver(ifIndex int) (int, error) {
	// Use ETH_P_ALL (same as tcpdump) — VLAN sub-interface + multicast
	// delivery is unreliable with ETH_P_IP protocol filtering.
	proto := htons(unix.ETH_P_ALL)
	// SOCK_CLOEXEC is OR'd into the type so the raw packet-capture fd is set
	// close-on-exec ATOMICALLY at creation. A raw unix.Socket does NOT get
	// CLOEXEC by default (unlike Go net sockets), so without this the fd would
	// be inherited by every child the daemon execs (frr-reload.py, swanctl,
	// dhcp helpers) — an fd leak and a security boundary issue (a child could
	// read raw VRRP frames off the capture socket). The atomic OR-into-type
	// avoids the fork race of a separate post-creation fcntl(FD_CLOEXEC).
	fd, err := afPacketSocket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(proto))
	if err != nil {
		return -1, fmt.Errorf("af_packet socket: %w", err)
	}

	// Bind to specific interface.
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: proto,
		Ifindex:  ifIndex,
	}); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("bind af_packet to ifindex %d: %w", ifIndex, err)
	}

	// Receive timeout so the receiver goroutine can check stopCh.
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("set rcvtimeo: %w", err)
	}

	// Promiscuous mode is required to receive multicast frames from
	// remote peers on VLAN sub-interfaces. Without it, only locally-
	// generated multicast (IP-layer loopback) is delivered. This matches
	// tcpdump's behavior, which also sets PACKET_MR_PROMISC.
	mreq := &unix.PacketMreq{
		Ifindex: int32(ifIndex),
		Type:    unix.PACKET_MR_PROMISC,
	}
	if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, mreq); err != nil {
		slog.Debug("vrrp: failed to set promisc", "err", err)
	}

	// BPF filter: accept VRRP for IPv4, IPv6, and 802.1Q-tagged variants.
	// SOCK_RAW includes the Ethernet header. Protocol/next-header offsets:
	//   IPv4 untagged:  ethertype 0x0800 @12, proto @23 (14+9)
	//   IPv6 untagged:  ethertype 0x86DD @12, next-hdr @20 (14+6)
	//   IPv4 802.1Q:    ethertype 0x8100 @12, real 0x0800 @16, proto @27 (18+9)
	//   IPv6 802.1Q:    ethertype 0x8100 @12, real 0x86DD @16, next-hdr @24 (18+6)
	//
	// IPv4 matches base proto == 112 (the IPv4 arm already re-validates IHL +
	// TTL in Go, so it tolerates IPv4 options). IPv6 must additionally admit
	// VRRP adverts that carry one or more IPv6 extension headers (#2155): the
	// base Next-Header of such a frame is the FIRST ext-header's type, not 112.
	// A fixed-offset cBPF cannot walk an ext-header chain, so the IPv6 arm
	// instead matches the base Next-Header against the small set
	//   {112 VRRP, 0 Hop-by-Hop, 43 Routing, 60 Dest-Opts}
	// (approach A2). Any conformant VRRP advert — bare or chained — starts with
	// one of these, while ordinary IPv6 TCP/UDP/ICMPv6/ND stays kernel-dropped
	// on a data-bearing RETH VLAN (e.g. reth0.80). Fragment (44) and AH (51)
	// are deliberately NOT admitted: VRRP adverts are never legitimately
	// fragmented (the receiver does no reassembly) and never AH-wrapped (VRRP
	// has its own authentication, not IPsec-AH), so those frames stay
	// kernel-dropped here rather than waking the RX goroutine only for the Go
	// walker to drop them. The authoritative ext-header walk + proto-112 +
	// hop-limit-255 + VRID validation happens in Go (parseAfPacketIPv6); the
	// cBPF is only an in-kernel volume reducer.
	//
	// Jump offsets (Jt/Jf) are relative to the NEXT instruction.
	filter := []unix.SockFilter{
		{Code: 0x28, K: 12},                    //  0: ldh [12] — ethertype
		{Code: 0x15, Jt: 7, Jf: 0, K: 0x0800},  //  1: jeq 0x0800 → 9 (check_ipv4)
		{Code: 0x15, Jt: 14, Jf: 0, K: 0x86DD}, //  2: jeq 0x86DD → 17 (check_ipv6)
		{Code: 0x15, Jt: 1, Jf: 0, K: 0x8100},  //  3: jeq 0x8100 → 5 (check_vlan); else reject
		{Code: 0x06, K: 0},                     //  4: ret reject
		// check_vlan:
		{Code: 0x28, K: 16},                    //  5: ldh [16] — real ethertype
		{Code: 0x15, Jt: 6, Jf: 0, K: 0x0800},  //  6: jeq 0x0800 → 13 (check_ipv4_vlan)
		{Code: 0x15, Jt: 16, Jf: 0, K: 0x86DD}, //  7: jeq 0x86DD → 24 (check_ipv6_vlan)
		{Code: 0x06, K: 0},                     //  8: ret reject
		// check_ipv4: proto at 14+9=23
		{Code: 0x30, K: 23},                //  9: ldb [23]
		{Code: 0x15, Jt: 0, Jf: 1, K: 112}, // 10: jeq 112 → accept; else reject
		{Code: 0x06, K: 0xFFFFFFFF},        // 11: ret accept
		{Code: 0x06, K: 0},                 // 12: ret reject
		// check_ipv4_vlan: proto at 18+9=27
		{Code: 0x30, K: 27},                // 13: ldb [27]
		{Code: 0x15, Jt: 0, Jf: 1, K: 112}, // 14: jeq 112 → accept; else reject
		{Code: 0x06, K: 0xFFFFFFFF},        // 15: ret accept
		{Code: 0x06, K: 0},                 // 16: ret reject
		// check_ipv6: base next-header at 14+6=20. Accept the VRRP/ext-header
		// set {112,0,43,60}; anything else (incl. Fragment 44, AH 51) is
		// non-VRRP → reject in-kernel.
		{Code: 0x30, K: 20},                // 17: ldb [20]
		{Code: 0x15, Jt: 4, Jf: 0, K: 112}, // 18: jeq 112  → 23 accept
		{Code: 0x15, Jt: 3, Jf: 0, K: 0},   // 19: jeq 0    → 23 accept (Hop-by-Hop)
		{Code: 0x15, Jt: 2, Jf: 0, K: 43},  // 20: jeq 43   → 23 accept (Routing)
		{Code: 0x15, Jt: 1, Jf: 0, K: 60},  // 21: jeq 60   → 23 accept (Dest-Opts)
		{Code: 0x06, K: 0},                 // 22: ret reject
		{Code: 0x06, K: 0xFFFFFFFF},        // 23: ret accept
		// check_ipv6_vlan: base next-header at 18+6=24. Same accept set.
		{Code: 0x30, K: 24},                // 24: ldb [24]
		{Code: 0x15, Jt: 4, Jf: 0, K: 112}, // 25: jeq 112  → 30 accept
		{Code: 0x15, Jt: 3, Jf: 0, K: 0},   // 26: jeq 0    → 30 accept (Hop-by-Hop)
		{Code: 0x15, Jt: 2, Jf: 0, K: 43},  // 27: jeq 43   → 30 accept (Routing)
		{Code: 0x15, Jt: 1, Jf: 0, K: 60},  // 28: jeq 60   → 30 accept (Dest-Opts)
		{Code: 0x06, K: 0},                 // 29: ret reject
		{Code: 0x06, K: 0xFFFFFFFF},        // 30: ret accept
	}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("attach bpf filter: %w", err)
	}

	return fd, nil
}

// openIPv6Socket creates a raw IPv6 socket (IPPROTO_VRRP = 112) bound to
// the given interface for sending VRRPv3 IPv6 advertisements.
// Returns the PacketConn and the raw fd for setsockopt operations.
//
// SO_BINDTODEVICE is applied identically to the IPv4 path
// (openPerInterfaceSocket): used on plain interfaces for isolation, but
// SKIPPED on VLAN sub-interfaces. Generic-XDP VLAN tag handling makes the
// kernel's interface association unpredictable — pinning the socket to the
// VLAN sub-interface index can drop incoming/locally-looped multicast when
// the tag is stripped/modified before delivery. Before #2786 the IPv6 path
// bound unconditionally while IPv4 skipped, so the two families saw VRRP
// traffic differently on a VLAN RETH member (e.g. reth0.50/reth0.80): the
// IPv6 instance could miss peer adverts entirely and both nodes would hold
// MASTER → split-brain / dual-MASTER. IPv6 multicast egress is still steered
// by IPV6_MULTICAST_IF below, which does not depend on SO_BINDTODEVICE.
func openIPv6Socket(ifName string, iface *net.Interface, isVLAN bool) (net.PacketConn, int, error) {
	conn, err := net.ListenPacket("ip6:112", "::")
	if err != nil {
		return nil, -1, fmt.Errorf("listen ip6:112: %w", err)
	}

	sc, err := conn.(*net.IPConn).SyscallConn()
	if err != nil {
		conn.Close()
		return nil, -1, fmt.Errorf("syscall conn: %w", err)
	}

	var fd int
	var bindErr error
	if err := sc.Control(func(rawfd uintptr) {
		fd = int(rawfd)
		// Bind to interface — skip on VLAN sub-interfaces (matches the IPv4
		// path; see openPerInterfaceSocket and the doc comment above).
		bindErr = maybeBindToDevice(fd, ifName, isVLAN)
		if bindErr != nil {
			return
		}
		// Set hop limit to 255 (RFC 5798 requirement).
		bindErr = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_HOPS, 255)
		if bindErr != nil {
			return
		}
		bindErr = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, 255)
		if bindErr != nil {
			return
		}
		// Set multicast interface.
		bindErr = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_IF, iface.Index)
	}); err != nil {
		conn.Close()
		return nil, -1, fmt.Errorf("control: %w", err)
	}
	if bindErr != nil {
		conn.Close()
		return nil, -1, fmt.Errorf("ipv6 socket setup on %s: %w", ifName, bindErr)
	}

	// Join VRRP IPv6 multicast group (ff02::12).
	mreq := &unix.IPv6Mreq{
		Interface: uint32(iface.Index),
	}
	copy(mreq.Multiaddr[:], net.ParseIP("ff02::12").To16())
	if err := sc.Control(func(rawfd uintptr) {
		// Ignore error — may fail if group already joined.
		_ = unix.SetsockoptIPv6Mreq(int(rawfd), unix.IPPROTO_IPV6, unix.IPV6_JOIN_GROUP, mreq)
	}); err != nil {
		slog.Debug("vrrp: ipv6 join multicast failed", "interface", ifName, "err", err)
	}

	return conn, fd, nil
}

// htons converts a uint16 from host to network byte order.
func htons(v uint16) uint16 {
	b := [2]byte{}
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

// vipsEqual compares two VIP slices for equality.
func vipsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
