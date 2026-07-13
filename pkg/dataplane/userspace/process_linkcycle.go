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

// PrepareLinkCycle must be called BEFORE any link DOWN/UP cycle (e.g. RETH
// MAC programming). It:
//  1. Disables ctrl so the XDP shim stops redirecting to XSK
//  2. Leaves the userspace shim attached with transit fail-closed
//  3. Sends "stop_workers" to the Rust helper, which joins all worker
//     threads — no thread touches UMEM after this returns
//
// The caller then performs the link DOWN/UP. Afterwards, NotifyLinkCycle
// sends "rebind" to recreate workers with fresh AF_XDP sockets.
func (m *Manager) PrepareLinkCycle() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil || m.proc.Process == nil {
		return
	}
	// Disable ctrl BEFORE stopping workers. If the disable cannot be
	// verified the wrapper clears all bindings fail-closed so the shim has
	// no READY slot to redirect to while the workers are being joined.
	_ = m.disableCtrlBeforeTeardownLocked()
	// Tell the Rust helper to stop all workers. This joins worker
	// threads so they stop touching UMEM before the NIC unmaps pages
	// during link DOWN.
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "stop_workers"}, &status); err != nil {
		slog.Warn("userspace: stop_workers before link cycle failed", "err", err)
		return
	}
	slog.Info("userspace: workers stopped before link cycle",
		"bindings", len(status.Bindings))
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
func (m *Manager) NotifyLinkCycle() {
	// Let the NIC fully tear down XSK zero-copy contexts before recreating
	// sockets. mlx5 releases zero-copy queue resources asynchronously after
	// socket close — binding a new socket to the same queue before teardown
	// completes returns EBUSY. 1s gives the driver ample time.
	linkCycleRebindSleep(1 * time.Second)

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil || m.proc.Process == nil {
		return
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
		slog.Warn("userspace: rebind after link cycle failed", "err", err)
		return
	}
	_ = m.applyHelperStatusLocked(&status)
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
}
