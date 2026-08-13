package userspace

import (
	"errors"
	"fmt"
	"strings"
)

func (m *Manager) recordHelperStatusLocked(status *ProcessStatus) {
	status.DataplaneMode = m.mode.String()
	status.ConfiguredMode = m.configuredMode.String()
	status.EntryPrograms = m.entryProgramsLocked()
	status.DegradedPathCounters = m.readDegradedPathStatsLocked()
	// #3261: stamp the manager-owned snapshot-reject diagnostic onto the status
	// the helper round-trip cannot carry (the helper has no PolicyContentRejected
	// field and strips it on decode). This keeps the rejected-snapshot state
	// observable in `show`/metrics even though the helper reports the
	// previous-good capabilities.
	status.LastSnapshotRejectReasons = append([]string(nil), m.lastSnapshotRejectReasons...)
	// #3719: stamp the manager-owned zone-id-collision diagnostic (the helper
	// cannot carry it — the colliding zone was dropped before the wire) so the
	// degraded zone-isolation state is observable in `show`/metrics.
	status.ZoneIDCollisions = append([]string(nil), m.lastZoneIDCollisions...)
	if m.eventStream != nil {
		es := m.eventStream.Status()
		status.EventStream = &es
	}
	m.lastStatus = *status
}

func (m *Manager) Status() (ProcessStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.proc == nil {
		if m.lastStatus.PID != 0 {
			return m.lastStatus, nil
		}
		return ProcessStatus{}, errors.New("userspace dataplane helper not running")
	}

	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "status"}, &status); err != nil {
		if m.lastStatus.PID != 0 {
			return m.lastStatus, err
		}
		return ProcessStatus{}, err
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		return status, err
	}
	return status, nil
}

// CachedStatus returns the most recent ProcessStatus captured by a
// control-socket round-trip (primarily the 1 Hz statusLoop, which
// refreshes m.lastStatus every second via applyHelperStatusLocked),
// WITHOUT issuing a new control-socket request. The bool is false
// when no status has been captured yet (helper not started or never
// polled), in which case the caller should hold its previous values.
//
// This exists so low-priority periodic consumers -- specifically the
// fwdstatus CPU sampler -- can read worker telemetry off the shared
// status poll instead of issuing their own redundant 1 Hz "status"
// request, which would double the control-socket status rate and
// starve session installs during bulk sync (#3970; CLAUDE.md
// "Control socket contention"). Unlike Status(), this MUST NOT touch
// the control socket.
func (m *Manager) CachedStatus() (ProcessStatus, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastStatus.PID == 0 {
		return ProcessStatus{}, false
	}
	return m.lastStatus, true
}

// errLinkCycleInFlight refuses an operator worker-affecting verb while a RETH
// MAC link cycle owns the dataplane (#6871).
//
// The three verbs below — `request chassis cluster data-plane userspace
// forwarding|queue|binding ...` via the CLI (cli_request_chassis.go) and via
// gRPC SystemAction (server_diag_system_action.go) — are the SIXTH producer of
// the worker-respawn class, and the only one reachable from outside the daemon.
// Each ends in a helper handler that calls reconcile_status_bindings
// (handlers/forwarding.rs unconditionally on a set_forwarding_state;
// handlers/binding.rs and handlers/queue.rs when registration_changed), which
// reaches afxdp.reconcile and SPAWNS WORKER THREADS. Neither call site is
// serialized on the daemon's applySem — there is no applySem use anywhere in
// pkg/cli or pkg/grpcapi — so an operator or an automation can issue one in the
// window PrepareLinkCycle opens: the workers are joined, and the daemon has not
// reached setDown yet (up to externalCommandTimeout of `ethtool` per RETH
// member). Respawned workers then meet a NIC unmapping its UMEM pages, which is
// the use-after-unmap #5103 exists to prevent.
//
// The ctrl gate in applyHelperStatusLocked does NOT cover this. It correctly
// holds ctrl.Enabled=0, but the spawn happens INSIDE the helper, before the
// response this manager applies — so the gate cannot un-spawn what the request
// already started.
//
// Scoped at the verbs rather than centrally in requestLocked deliberately:
// requestLocked is also the transport for the link cycle's OWN "stop_workers",
// which PrepareLinkCycle sends AFTER it takes the lease, so a central gate would
// have to exempt exactly the requests that take and release the lease — an
// exemption list that is silently wrong the first time a request type is added.
//
// Both directions are refused, not only the arming one. A disarm/deregister does
// not spawn, but it still drives afxdp.reconcile's teardown arm across AF_XDP
// socket state that PrepareLinkCycle has just quiesced, and whether a given
// (registered, armed) pair reconciles at all is a per-verb helper-side detail
// (binding.rs and queue.rs reconcile only on registration_changed, forwarding.rs
// always). Excluding the whole window is simpler than tracking that. Nothing
// internal is blocked by the broader scope: unlike the #5648 protocol gate
// below — which is scoped to armed==true precisely because the daemon's own
// disarm paths must never be refused — these three verbs have NO caller inside
// the daemon. They are operator-interactive, and the cycle is seconds long.
var errLinkCycleInFlight = errors.New(
	"userspace: a RETH MAC link cycle is in flight (workers are joined and the " +
		"NIC is cycling); retry once the cycle completes")

func (m *Manager) SetForwardingArmed(armed bool) (ProcessStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.proc == nil {
		return ProcessStatus{}, errors.New("userspace dataplane helper not running")
	}
	if m.linkCycleInFlight() {
		return m.lastStatus, errLinkCycleInFlight
	}
	if armed && !m.lastStatus.Capabilities.ForwardingSupported {
		if len(m.lastStatus.Capabilities.UnsupportedReasons) == 0 {
			return m.lastStatus, errors.New("userspace live forwarding is not supported for the current configuration")
		}
		return m.lastStatus, fmt.Errorf(
			"userspace live forwarding is not supported: %s",
			strings.Join(m.lastStatus.Capabilities.UnsupportedReasons, "; "),
		)
	}
	// #5648 (M43b): fail closed on a required-generation protocol mismatch.
	// The compile/publish paths (Compile, syncSnapshotLocked,
	// UpdatePolicyScheduleState) disarm the helper when its accepted config
	// snapshot protocol version is too old to honor a config that REQUIRES a
	// newer one (policy schedulers, persistent source NAT) —
	// ensureRequiredSnapshotProtocolLocked / disarmSnapshotProtocolFailureLocked.
	// An explicit arm request (operator `request`/gRPC, cli_request_chassis.go /
	// server_diag_system_action.go) must honor the SAME gate: arming here
	// without re-checking it would re-arm the STALE accepted image and forward
	// on a config the helper cannot represent — the fail-OPEN this closes.
	//
	// The gate is scoped, not a blanket refuse: ensureRequiredSnapshotProtocolLocked
	// is a no-op unless the last-applied config requires the protocol, and it
	// re-polls the helper first so a helper that has since upgraded (accepted a
	// current image) still arms normally. Only armed==true is gated — the
	// disarm paths (shutdown, disarmSnapshotProtocolFailureLocked) must never be
	// blocked, and this mirrors the ForwardingSupported guard above.
	if armed && m.lastSnapshot != nil && m.lastSnapshot.Config != nil {
		if err := m.ensureRequiredSnapshotProtocolLocked(m.lastSnapshot.Config); err != nil {
			return m.lastStatus, err
		}
	}
	var status ProcessStatus
	req := ControlRequest{
		Type: "set_forwarding_state",
		Forwarding: &ForwardingControlRequest{
			Armed: armed,
		},
	}
	if err := m.requestLocked(req, &status); err != nil {
		return ProcessStatus{}, err
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		return status, err
	}
	return status, nil
}

func (m *Manager) SetQueueState(queueID uint32, registered, armed bool) (ProcessStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.proc == nil {
		return ProcessStatus{}, errors.New("userspace dataplane helper not running")
	}
	if m.linkCycleInFlight() {
		return m.lastStatus, errLinkCycleInFlight
	}
	var status ProcessStatus
	req := ControlRequest{
		Type: "set_queue_state",
		Queue: &QueueControlRequest{
			QueueID:    queueID,
			Registered: registered,
			Armed:      armed,
		},
	}
	if err := m.requestLocked(req, &status); err != nil {
		return ProcessStatus{}, err
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		return status, err
	}
	return status, nil
}

func (m *Manager) SetBindingState(slot uint32, registered, armed bool) (ProcessStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.proc == nil {
		return ProcessStatus{}, errors.New("userspace dataplane helper not running")
	}
	if m.linkCycleInFlight() {
		return m.lastStatus, errLinkCycleInFlight
	}
	var status ProcessStatus
	req := ControlRequest{
		Type: "set_binding_state",
		Binding: &BindingControlRequest{
			Slot:       slot,
			Registered: registered,
			Armed:      armed,
		},
	}
	if err := m.requestLocked(req, &status); err != nil {
		return ProcessStatus{}, err
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		return status, err
	}
	return status, nil
}

func (m *Manager) InjectPacket(req InjectPacketRequest) (ProcessStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.proc == nil {
		return ProcessStatus{}, errors.New("userspace dataplane helper not running")
	}
	if err := validateInjectPacketRequestForHelper(req, m.lastStatus); err != nil {
		return ProcessStatus{}, err
	}
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "inject_packet", Packet: &req}, &status); err != nil {
		return ProcessStatus{}, err
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		return status, err
	}
	return status, nil
}

func (m *Manager) DrainSessionDeltas(max uint32) ([]SessionDeltaInfo, ProcessStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.proc == nil {
		return nil, ProcessStatus{}, errors.New("userspace dataplane helper not running")
	}
	resp, err := m.requestDetailedLocked(ControlRequest{
		Type: "drain_session_deltas",
		SessionDeltas: &SessionDeltaDrainRequest{
			Max: max,
		},
	})
	if err != nil {
		return nil, ProcessStatus{}, err
	}
	var status ProcessStatus
	if resp.Status != nil {
		status = *resp.Status
		if err := m.applyHelperStatusLocked(&status); err != nil {
			return resp.SessionDeltas, status, err
		}
	}
	return resp.SessionDeltas, status, nil
}

func (m *Manager) ExportOwnerRGSessions(rgIDs []int, max uint32) ([]SessionDeltaInfo, ProcessStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.proc == nil {
		return nil, ProcessStatus{}, errors.New("userspace dataplane helper not running")
	}
	resp, err := m.requestDetailedLocked(ControlRequest{
		Type: "export_owner_rg_sessions",
		SessionExport: &SessionExportRequest{
			OwnerRGs: rgIDs,
			Max:      max,
		},
	})
	if err != nil {
		return nil, ProcessStatus{}, err
	}
	var status ProcessStatus
	if resp.Status != nil {
		status = *resp.Status
		if err := m.applyHelperStatusLocked(&status); err != nil {
			return resp.SessionDeltas, status, err
		}
	}
	return resp.SessionDeltas, status, nil
}
