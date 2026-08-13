package userspace

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/cilium/ebpf"
)

// ctrlMapUpdater is the subset of *ebpf.Map used to flip the ctrl.enabled
// gate. *ebpf.Map satisfies it directly; tests substitute a fake to inject
// Lookup/Update/readback faults without a privileged BPF map (#5486).
type ctrlMapUpdater interface {
	Lookup(key, valueOut interface{}) error
	Update(key, value interface{}, flags ebpf.MapUpdateFlags) error
}

// ctrlMapForDisableLocked returns the ctrl-map accessor used to disable ctrl.
// Production returns the real bpfShim userspace_ctrl map; a test hook can
// override it. Returns nil (a true nil interface, never a typed nil) when the
// shim map is not loaded.
func (m *Manager) ctrlMapForDisableLocked() ctrlMapUpdater {
	if m.disableCtrlMapHook != nil {
		return m.disableCtrlMapHook
	}
	if cm := m.bpfShim.Map(mapNameUserspaceCtrl); cm != nil {
		return cm
	}
	return nil
}

// disableUserspaceCtrlLocked sets ctrl.enabled=0 in the BPF map so the XDP
// shim stops redirecting packets to XSK. This MUST be called before the
// helper exits (or workers/UMEM are torn down) to prevent packets being sent
// to dead socket fds.
//
// It returns an error instead of silently swallowing failures (#5486): a
// stale enabled=1 row with READY bindings keeps the shim redirecting to
// soon-dead XSK fds until heartbeat expiry, so a caller preparing teardown
// MUST learn the gate was not established and fail closed (clear bindings).
func (m *Manager) disableUserspaceCtrlLocked() error {
	ctrlMap := m.ctrlMapForDisableLocked()
	if ctrlMap == nil {
		return fmt.Errorf("userspace: cannot disable ctrl: %s map not loaded", mapNameUserspaceCtrl)
	}
	return disableUserspaceCtrl(ctrlMap)
}

// disableUserspaceCtrl writes ctrl.enabled=0 and verifies the gate took.
//
// On a Lookup failure it does NOT bail out leaving enabled=1: it writes a
// zeroed (Enabled=0) fail-closed row anyway, then returns the read error. The
// Update result is checked (not discarded) and the row is read back to confirm
// Enabled==0 — a silent no-op here would strand transit redirecting to
// soon-dead XSK fds after worker/UMEM teardown.
func disableUserspaceCtrl(ctrlMap ctrlMapUpdater) error {
	zero := uint32(0)
	var ctrl userspaceCtrlValue
	lookupErr := ctrlMap.Lookup(zero, &ctrl)
	if lookupErr != nil {
		// Prior ctrl unreadable — still establish the fail-closed gate with
		// a zeroed ctrl row rather than leaving a stale enabled=1.
		ctrl = userspaceCtrlValue{}
	}
	ctrl.Enabled = 0
	if err := ctrlMap.Update(zero, ctrl, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("userspace: disable ctrl update failed: %w", err)
	}
	// Read back to confirm the disable actually took. A silent write no-op
	// would leave enabled=1 and keep transit redirecting after teardown.
	var verify userspaceCtrlValue
	if err := ctrlMap.Lookup(zero, &verify); err != nil {
		return fmt.Errorf("userspace: disable ctrl readback failed: %w", err)
	}
	if verify.Enabled != 0 {
		return fmt.Errorf("userspace: disable ctrl readback shows enabled=%d, want 0", verify.Enabled)
	}
	if lookupErr != nil {
		slog.Warn("userspace: disabled ctrl via fail-closed fallback (prior ctrl unreadable)", "err", lookupErr)
		return fmt.Errorf("userspace: disable ctrl lookup failed (fail-closed fallback written): %w", lookupErr)
	}
	slog.Info("userspace: disabled ctrl (helper stopping)")
	return nil
}

// disableCtrlBeforeTeardownLocked disables ctrl ahead of stopping workers or
// cycling the link. Teardown cannot abort — the helper is stopping — so if the
// disable cannot be verified, the fail-closed gate is not trustworthy: this
// forcibly clears ALL binding rows (nothing READY for the shim to redirect)
// before the caller proceeds to worker/UMEM teardown, logs the failure, and
// returns the error for callers that surface it (#5486).
func (m *Manager) disableCtrlBeforeTeardownLocked() error {
	if err := m.disableUserspaceCtrlLocked(); err != nil {
		slog.Error("userspace: ctrl disable before teardown failed; clearing all bindings fail-closed", "err", err)
		m.clearAllBindingRowsLocked()
		return err
	}
	return nil
}

// reEnableUserspaceCtrlLocked sets ctrl.enabled=1 in the BPF map.
// Used to rollback a ctrl disable when the subsequent operation fails.
func (m *Manager) reEnableUserspaceCtrlLocked() {
	ctrlMap := m.bpfShim.Map(mapNameUserspaceCtrl)
	if ctrlMap == nil {
		return
	}
	zero := uint32(0)
	var ctrl userspaceCtrlValue
	if err := ctrlMap.Lookup(zero, &ctrl); err != nil {
		return
	}
	ctrl.Enabled = 1
	_ = ctrlMap.Update(zero, ctrl, ebpf.UpdateAny)
	slog.Info("userspace: re-enabled ctrl (rollback)")
}

// DisableAndStopHelper disables ctrl. This prevents the XDP shim from
// redirecting new packets to XSK. Must be called BEFORE any operation that
// invalidates UMEM (e.g. link DOWN on mlx5 zero-copy). Worker threads keep
// running but see no new packets since ctrl=0 stops XSK redirects.
//
// Deprecated: use PrepareLinkCycle which also stops the Rust workers.
func (m *Manager) DisableAndStopHelper() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil || m.proc.Process == nil {
		return
	}
	// Teardown path: the wrapper logs and clears bindings fail-closed if the
	// disable cannot be verified; there is no error channel to surface it on.
	_ = m.disableCtrlBeforeTeardownLocked()
}

// linkCycleLeaseTTL bounds the gap between two consecutive TOUCHES of a
// link-cycle lease — the acquire in PrepareLinkCycle, and each RenewLinkCycle
// the daemon's per-member loop issues after it. It is deliberately NOT a bound
// on the whole cycle, and that distinction is the point.
//
// A TTL that had to cover the whole cycle would be a function of the RETH count,
// and there is no constant that bounds that: the config permits 1..128 RETHs
// (pkg/config/schema_chassis.go, reth-count), step 2.6 walks them serially
// (pkg/daemon/daemon_apply_dataplane.go), and only a member that actually cycles
// re-arms the lease on its own — so the exposure is the tail of members visited
// AFTER the last cycling one, and that traversal is a Go map range, i.e. the
// same input passes or fails between runs. Picking a bigger constant would be
// the same defect with a bigger number.
//
// So the daemon renews instead — once per member, in programRethMemberMAC — and
// the TTL now has to cover the interval between two consecutive members. The
// dominant term there is the per-member `ethtool -K <if> rxvlan off`, whose HARD
// ceiling is 20s, not 15: externalCommandTimeout is 15s and
// runCommandStdinTimeout adds a 5s WaitDelay on top of it
// (pkg/daemon/exec_timeout.go). Everything else in an iteration is netlink or a
// single control-socket round-trip. 60s is 3x that ceiling and, because it is
// per-member, it holds for ANY member count rather than for the deployed N=2
// only. The last renewal is on the final member; between it and NotifyLinkCycle
// sit that member's ethtool, step 2.6b's VIP/link-local reconcile (netlink) and
// NotifyLinkCycle's own 1s NIC settle — still inside the TTL.
//
// The TTL remains what it always was: a backstop, not the mechanism. The lease
// is normally ended by NotifyLinkCycle, which every path that takes one reaches
// (the cycle completes and step 2.6b2 rebinds; or the cycle aborts and
// programRethMACWithWorkerJoin rolls back with the same call). The backstop
// covers the one case that does not — a caller that dies between the two — and a
// lease that never ended would suppress the 1 Hz reconcile FOREVER, which is a
// worse failure than the race it exists to close.
//
// Overrunning is bounded and loud rather than silent: linkCycleInFlight logs a
// Warn under the CAS when it clears an expired lease, and the state it degrades
// to is master's — the pre-#6871 behaviour where the tick was never suppressed
// at all. An overrun loses the added protection for the tail of that cycle; it
// does not introduce a new failure mode.
const linkCycleLeaseTTL = 60 * time.Second

// linkCycleLeaseEpoch is the process-lifetime reference the lease deadline is
// measured from. It is captured once and never reassigned, so
// time.Since(linkCycleLeaseEpoch) reads Go's MONOTONIC clock (a time.Time
// carrying a monotonic reading subtracts monotonically) and is immune to
// wall-clock steps.
//
// #6871 (round 6): the deadline was previously stored as
// time.Now().Add(TTL).UnixNano() and compared against another UnixNano — both of
// which STRIP the monotonic reading and leave a pure wall-clock comparison. A
// step is not hypothetical on this appliance: it runs chrony, and a first sync
// after boot can move the wall clock by minutes. A forward correction larger
// than the TTL expires a one-second-old lease and re-opens the worker-restart
// race the lease exists to close; a backward one strands the lease until the
// clock catches up.
var linkCycleLeaseEpoch = time.Now()

// linkCycleLeaseElapsed reports monotonic time since linkCycleLeaseEpoch. It is
// indirected so a test can prove the TTL backstop actually expires a stranded
// lease without sleeping one out. Production never reassigns it. Mirrors
// linkCycleRebindSleep below.
var linkCycleLeaseElapsed = func() time.Duration { return time.Since(linkCycleLeaseEpoch) }

// linkCycleLeaseDeadline is the value stored in linkCycleLeaseUntil for a lease
// taken or renewed now. It is monotonic nanoseconds since linkCycleLeaseEpoch,
// and is never 0 (elapsed is non-negative and the TTL is positive), so the 0
// sentinel that means "no lease" stays unambiguous.
func linkCycleLeaseDeadline() int64 {
	return int64(linkCycleLeaseElapsed() + linkCycleLeaseTTL)
}

// acquireLinkCycleLease opens the #6871 lease. Callers hold m.mu, but the lease
// deliberately does not depend on it — it is read by the status loop from
// outside m.mu's protection of the window it covers.
func (m *Manager) acquireLinkCycleLease() {
	m.linkCycleLeaseUntil.Store(linkCycleLeaseDeadline())
}

// RenewLinkCycle pushes a lease that is ALREADY held out by another full TTL. It
// is what makes the TTL a per-member bound instead of a whole-cycle guess: the
// daemon calls it once per member of step 2.6's rethToPhys loop (from
// programRethMemberMAC), so the deadline tracks the sequence's actual progress
// rather than a wall-clock estimate of its total length (#6871 round 6).
//
// It NEVER creates a lease. A renewal that could open one would let any caller
// suppress the 1 Hz reconcile with no cycle in flight and nothing obliged to
// release it — the daemon's loop runs on every RETH apply, the vast majority of
// which never cycle a link at all. The load/CAS pair is what keeps that true
// against a concurrent release: linkCycleInFlight below is checked first (which
// also self-heals an already-expired deadline), and the CAS then fails rather
// than resurrecting a lease NotifyLinkCycle released in between.
//
// Renewing an unexpired lease that is already further out than the new deadline
// is a no-op, so the ordering of renew against a fresh acquire does not matter.
func (m *Manager) RenewLinkCycle() {
	if !m.linkCycleInFlight() {
		return
	}
	want := linkCycleLeaseDeadline()
	for {
		until := m.linkCycleLeaseUntil.Load()
		if until == 0 || until >= want {
			return
		}
		if m.linkCycleLeaseUntil.CompareAndSwap(until, want) {
			return
		}
	}
}

// releaseLinkCycleLease ends the lease. Idempotent — the release site runs
// unconditionally at the top of NotifyLinkCycle's critical section, so a second
// call (or a call with no lease held) is a no-op.
func (m *Manager) releaseLinkCycleLease() {
	m.linkCycleLeaseUntil.Store(0)
}

// linkCycleInFlight reports whether a RETH MAC link cycle currently owns the
// dataplane. It self-heals a stranded lease past linkCycleLeaseTTL: the CAS
// clears the deadline so the wedge cannot recur every tick, and the tick that
// observes the expiry resumes reconciling immediately.
func (m *Manager) linkCycleInFlight() bool {
	until := m.linkCycleLeaseUntil.Load()
	if until == 0 {
		return false
	}
	if int64(linkCycleLeaseElapsed()) >= until {
		if m.linkCycleLeaseUntil.CompareAndSwap(until, 0) {
			slog.Warn("userspace: link-cycle lease expired without a rebind; resuming reconcile",
				"ttl", linkCycleLeaseTTL)
		}
		return false
	}
	return true
}

// PrepareLinkCycle must be called BEFORE any link DOWN/UP cycle (e.g. RETH
// MAC programming). It:
//  1. Disables ctrl so the XDP shim stops redirecting to XSK
//  2. Leaves the userspace shim attached with transit fail-closed
//  3. Sends "stop_workers" to the Rust helper, which joins all worker
//     threads — no thread touches UMEM after this returns
//  4. Takes the #6871 link-cycle lease, which holds that join across the
//     window where m.mu is NOT held (see below). The daemon renews it once per
//     RETH member (RenewLinkCycle), so the lease tracks the loop's progress
//     rather than a wall-clock guess at its total length.
//
// The caller then performs the link DOWN/UP. Afterwards, NotifyLinkCycle
// sends "rebind" to recreate workers with fresh AF_XDP sockets.
//
// #6871: the join alone is a MOMENT, not a barrier. This function releases m.mu
// on return, and the daemon does not reach setDown until several netlink calls
// later — so every other holder of m.mu runs in between. The 1 Hz status tick
// alone restarts the workers four different ways in that window:
//
//   - syncSnapshotLocked's plan-key branch stopLocked()s and respawns the whole
//     HELPER PROCESS (process_status.go);
//   - retryDeferredWorkerArmLocked republishes with DeferWorkers=false to settle
//     a #5134 debt (manager_worker_arm_5134.go);
//   - maybeAutoRebindBusyBindingsLocked sends "rebind" directly — the exact
//     inverse of the stop_workers just issued (maps_sync.go);
//   - applyHelperStatusLocked re-enables ctrl, pointing the shim at XSK sockets
//     whose queues the cycle is about to destroy (maps_sync.go).
//
// stop_workers keeps registered bindings and forwarding_armed, so the helper's
// same-plan predicate sees runnable-but-not-live bindings and restarts workers
// on any of those. The lease makes the tick skip its whole body while a cycle
// owns the dataplane, and gates the ctrl re-enable at its source so the
// non-tick callers of applyHelperStatusLocked (UpdateRGActive, driven by VRRP
// events and by reconcileRGStateLoop's 2s pass, which is NOT serialized on the
// daemon's applySem) cannot re-enable it either.
//
// The operator worker-affecting verbs are the sixth producer and are gated at
// their own entry points rather than here — see errLinkCycleInFlight in
// manager_status.go for why the gate cannot live in requestLocked.
//
// The SEVENTH is the daemon's own 500ms HA watchdog heartbeat, and it is the one
// that shows why enumerating callers is not enough: UpdateHAWatchdog runs on its
// own goroutine with no applySem, and its first/change/backstop branch ends in
// syncDesiredForwardingStateLocked, which sends the same worker-respawning
// set_forwarding_state the operator verbs do. That gate lives at the emitter
// (manager_ha.go) rather than at UpdateHAWatchdog, so it also covers the tick's
// and the compile path's calls — see the comment there for why the watchdog's
// update_ha_state half is deliberately NOT suppressed (#6871 round 6).
func (m *Manager) PrepareLinkCycle() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil || m.proc.Process == nil {
		// No helper running: there are no workers to join, so a link cycle
		// cannot race one. This is a genuine success, not a swallowed
		// failure. No lease either — there is nothing for it to protect, and
		// taking one would suppress the reconcile for no reason.
		return nil
	}
	// Take the lease BEFORE the first mutation of dataplane state. The window
	// that needs covering opens at the ctrl disable, not at the successful
	// join: disableCtrlBeforeTeardownLocked can clear every binding row
	// fail-closed and then stop_workers can still fail, and a tick landing in
	// THAT state would repopulate the rows it just cleared.
	m.acquireLinkCycleLease()
	// Disable ctrl BEFORE stopping workers. If the disable cannot be
	// verified the wrapper clears all bindings fail-closed so the shim has
	// no READY slot to redirect to while the workers are being joined.
	//
	// #5103: the ctrl-disable error is CAPTURED rather than acted on here (see
	// the scope note at the return — it is deliberately NOT folded into this
	// function's error). Above all it must NOT short-circuit the worker join
	// below — the join is the half that makes UMEM safe to unmap, and skipping
	// it on a ctrl-disable failure would leave workers running through the very
	// link cycle this function exists to protect. The wrapper has already
	// cleared all binding rows fail-closed, so the shim has nothing READY to
	// redirect into while the join proceeds.
	ctrlErr := m.disableCtrlBeforeTeardownLocked()
	// Tell the Rust helper to stop all workers. This joins worker
	// threads so they stop touching UMEM before the NIC unmaps pages
	// during link DOWN.
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "stop_workers"}, &status); err != nil {
		// #5103: previously a Warn + bare return, which the void signature
		// made invisible. A failed join means worker threads may still be
		// touching UMEM, so the link MUST NOT be cycled.
		slog.Error("userspace: stop_workers before link cycle failed; link cycle must not proceed",
			"err", err)
		return fmt.Errorf("userspace: stop_workers before link cycle: %w", err)
	}
	slog.Info("userspace: workers stopped before link cycle",
		"bindings", len(status.Bindings))
	// SCOPE of the error contract, deliberately narrow: it reports whether the
	// WORKER JOIN succeeded, and nothing else. ctrlErr is logged (loudly, by
	// disableCtrlBeforeTeardownLocked) and its own failure path has already
	// cleared every binding row fail-closed, so the shim has nothing READY to
	// redirect into — but it is NOT folded into the return.
	//
	// Propagating it was tried and is wrong: "userspace_ctrl map not loaded" is
	// a legitimate state (no shim attached), and in that state there is no
	// redirect path for the gate to protect. Failing there would block RETH MAC
	// programming on a healthy deployment — an over-rejection in place of the
	// under-rejection this change exists to fix. The caller's decision hinges
	// on whether threads can still touch UMEM, which is exactly the join.
	_ = ctrlErr
	return nil
}

var linkCycleRebindSleep = time.Sleep

// NotifyLinkCycle tells the userspace helper to rebind all AF_XDP sockets.
// In mlx5 (and other drivers), a link DOWN/UP cycle destroys the kernel-side
// XSK receive queue.  The sockets remain open but no longer receive packets.
// This is called after programRethMAC which takes RETH interfaces DOWN/UP.
//
// PrepareLinkCycle should have been called BEFORE the link cycle to stop
// workers (so they don't access UMEM during link DOWN). This method
// waits 1s for NIC reinitialization then sends "rebind" to recreate
// workers with fresh AF_XDP sockets.
//
// The 1s delay lets the mlx5 NIC fully reinitialize its UMR (User
// Memory Region) subsystem after link reactivation. Without this, the
// NIC's UMR WQE queue overflows when all XSK sockets are recreated
// simultaneously (rx_xsk_congst_umr), causing UMEM pages to not be mapped
// and packets to be silently dropped despite successful XDP_REDIRECT.
//
// #6871: it returns an error, for the same reason PrepareLinkCycle does, and
// with the same deliberately narrow scope — it reports whether the REBIND
// landed, and nothing else (see the scope note at the status apply). This is the
// designated inverse of "stop_workers" and the daemon uses it BOTH to complete a
// cycle and to unwind an aborted one, but a failed rebind used to be a slog.Warn
// and a bare return on a void function, so a clean cycle whose rebind failed left
// every worker stopped WHILE THE COMMIT REPORTED SUCCESS: a silent total
// dataplane outage on that node. The error return is what makes the daemon's
// "this path owns its own rollback" claim true rather than attempted;
// programRethMACWithWorkerJoin folds it into the same errRethPrepareLinkCycle
// class as a failed join, and step 2.6b2 folds it into the commit error.
//
// It also ends the link-cycle lease, unconditionally, at the top of its critical
// section — see the release site for why that is both the earliest and the
// latest correct point.
func (m *Manager) NotifyLinkCycle() error {
	// Let the NIC fully tear down XSK zero-copy contexts before recreating
	// sockets. mlx5 releases zero-copy queue resources asynchronously after
	// socket close — binding a new socket to the same queue before teardown
	// completes returns EBUSY. 1s gives the driver ample time.
	//
	// The lease is still held across this sleep. That is the point: m.mu is NOT
	// held here, so without it the tick would have a full second of open season
	// on a helper whose workers are joined and whose sockets are dead.
	linkCycleRebindSleep(1 * time.Second)

	m.mu.Lock()
	defer m.mu.Unlock()
	// End the lease here, FIRST, and unconditionally.
	//
	// Earliest correct point: from this line on we hold m.mu for the rest of the
	// function, so no other producer can interleave anyway — the lease exists
	// only to cover the window where m.mu is NOT held, and that window just
	// closed. Releasing here (rather than at the end) also keeps the ctrl gate in
	// applyHelperStatusLocked out of the way of our own post-rebind status apply,
	// so a completed cycle re-enables ctrl on this call instead of costing an
	// extra tick of fail-closed transit.
	//
	// Latest correct point: it precedes every `return` below, including the
	// no-helper early return and the rebind failure. A release placed after any
	// of those would strand the lease on exactly the paths where forwarding is
	// already down, turning a recoverable outage into a frozen reconcile loop
	// until the TTL backstop fired.
	m.releaseLinkCycleLease()
	if m.proc == nil || m.proc.Process == nil {
		return nil
	}
	// Ensure ctrl is disabled (PrepareLinkCycle should have done this,
	// but guard against callers that skip it). The subsequent rebind
	// re-establishes ctrl; a fail-closed binding clear here is safe because
	// applyHelperStatusLocked below repopulates the binding rows.
	_ = m.disableCtrlBeforeTeardownLocked()
	// Reset the ctrl enable gate so the fill-ring bootstrap delay
	// restarts from scratch after rebind.  Without this, ctrl stays
	// enabled while the new bindings aren't ready — packets redirected
	// to dead XSK sockets are silently dropped (cold-start blackout).
	//
	// Preserve ctrlEnableAt across rebinds: the hard timeout should
	// count from the FIRST prewarm, not restart on every link cycle.
	// Otherwise repeated rebinds (e.g. RETH MAC programming) keep
	// pushing the hard timeout forward and ctrl never enables.
	m.neighborsPrewarmed = false
	// Reset liveness state so the XSK probe runs fresh after rebind.
	// The old probe result is stale — the link cycle destroyed the
	// previous XSK sockets and the new ones need re-validation.
	m.xskLivenessProven = false
	m.xskLivenessFailed = false
	m.xskProbeStart = time.Time{}
	m.lastXSKRX = 0

	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "rebind"}, &status); err != nil {
		// #6871: was a Warn and a bare return. The workers are joined and ctrl
		// is off at this point, so a rebind that does not land leaves this node
		// forwarding nothing — and the void signature made that indistinguishable
		// from a successful rebind to the one caller that reports the commit.
		slog.Error("userspace: rebind after link cycle failed; workers stay stopped",
			"err", err)
		return fmt.Errorf("userspace: rebind after link cycle: %w", err)
	}
	// SCOPE of the error contract, deliberately narrow and mirroring
	// PrepareLinkCycle's: this function reports whether the REBIND landed, and
	// nothing else. The status apply is logged but NOT folded in.
	//
	// Folding it was tried and is wrong for the same reason PrepareLinkCycle
	// does not fold its ctrl-disable error: applyHelperStatusLocked fails with
	// "userspace_ctrl map not loaded" whenever no shim is attached, which is a
	// legitimate state, and in that state there is no redirect path for the
	// binding rows to matter to. Returning there would fail a commit on a
	// healthy deployment — an over-rejection in place of the under-rejection
	// this change exists to fix. The caller's decision hinges on one thing:
	// whether the workers stop_workers joined are running again, which is
	// exactly the rebind.
	if err := m.applyHelperStatusLocked(&status); err != nil {
		slog.Warn("userspace: helper status apply after link-cycle rebind failed", "err", err)
	}
	// #2079 r11: the deferred apply (DeferWorkers) skipped the appliedSnapshot
	// capture because the helper had not reconciled its forwarding state. The
	// rebind above reconciles the bindings (and swaps the coordinator
	// forwarding state to the applied generation), so NOW record the applied
	// snapshot — its config + generation are coherent with the NAT pool
	// counters the helper will report. m.deferWorkers is cleared by the daemon
	// before NotifyLinkCycle, so markAppliedSnapshotLocked's defer-skip does
	// not suppress this capture.
	m.markAppliedSnapshotLocked()
	ready := 0
	for _, b := range status.Bindings {
		if b.Ready {
			ready++
		}
	}
	slog.Info("userspace: AF_XDP rebind initiated after link cycle",
		"forwarding_armed", status.ForwardingArmed,
		"bindings", len(status.Bindings),
		"ready", ready)
	// Re-bootstrap NAPI queues after rebind. The link DOWN/UP cycle
	// destroyed the XSK channels; the rebind created new sockets but
	// the fill ring WQEs haven't been posted to the NIC yet. Broadcast
	// pings generate hardware RX events that trigger NAPI, which posts
	// fill ring WQEs so zero-copy XSK can receive packets.
	m.bootstrapNAPIQueuesAsyncLocked("link-cycle")
	return nil
}
