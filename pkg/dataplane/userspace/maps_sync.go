package userspace

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	xpfnft "github.com/psaab/xpf/pkg/nftables"
	"github.com/vishvananda/netlink"
)

type userspaceCtrlValue struct {
	Enabled         uint32
	MetadataVersion uint32
	Workers         uint32
	QueueCount      uint32
	Flags           uint32
	// WgListenPort (#1432 S2a) occupies the former Pad slot before the
	// u64 ConfigGeneration (the ABI alignment pad the Rust shim's
	// UserspaceCtrl also exposes as wg_listen_port). Low 16 bits carry
	// the WG listen port; 0 means no WG tunnel is configured (the shim's
	// per-CPU "wg_rx" gate). The shim steers local-destination UDP on
	// this port to the kernel.
	WgListenPort       uint32
	ConfigGeneration   uint64
	FIBGeneration      uint32
	HeartbeatTimeoutMS uint32
}

const userspaceMetadataVersion = 4
const userspaceCtrlFlagCPUMap = 1
const userspaceCtrlFlagTrace = 2
const userspaceCtrlFlagNativeGRE = 4
const userspaceCtrlFlagStrict = 8

// userspaceCtrlFlagWgRx (#1432 S2a) is set iff at least one WireGuard
// tunnel is configured. The shim gates its per-packet WG steering branch
// on this single bit so non-WG traffic never even loads wg_listen_port.
const userspaceCtrlFlagWgRx = 16
const bindingQueuesPerIface = 16 // must match BINDING_QUEUES_PER_IFACE in BPF

const userspaceBindingReady = 1

// deadWorkerIDSet builds the set of worker IDs whose worker_loop has
// panicked, from the helper's per-worker runtime status. On panic the
// supervisor (coordinator/supervisor.rs) sets runtime_atomics.dead which
// surfaces as WorkerRuntimeStatus.Dead (#925). Dead is set-only until
// daemon restart, so it never spuriously fires for a live worker.
func deadWorkerIDSet(runtime []WorkerRuntimeStatus) map[uint32]bool {
	if len(runtime) == 0 {
		return nil
	}
	var dead map[uint32]bool
	for _, w := range runtime {
		if w.Dead {
			if dead == nil {
				dead = make(map[uint32]bool, len(runtime))
			}
			dead[w.WorkerID] = true
		}
	}
	return dead
}

// bindingForwardingLive reports whether a binding is safe to mark READY
// (userspaceBindingReady) in the XDP userspace_bindings array.
//
// #1666: the gate keeps the historical (Registered && Armed)
// admission AND adds the helper-derived binding.Ready — which is
// (registered && bound && xsk_registered && heartbeat_fresh), computed in
// userspace-dp coordinator/refresh_bindings.rs — ANDed with the binding's
// worker not being Dead.
//
// Registered && Armed must stay in the predicate: the Rust Ready
// derivation does NOT include Armed (armed = armed_req && registered is a
// separate control-plane flag), so a Ready-but-disarmed binding must not
// forward. The Ready + !Dead legs are what newly withhold/clear READY for
// a worker that crashed or never finished XSK registration (the
// crash-blind blackhole).
//
// All of Ready's sub-conditions are flipped true by worker bringup alone
// (socket create -> set_bound, XSKMAP register -> set_xsk_registered,
// per-poll-tick heartbeat), independent of inbound traffic, so this gate
// cannot deadlock a legitimately-live binding (see
// docs/pr/1666-ready-gate/plan.md §4).
func bindingForwardingLive(b BindingStatus, deadWorkers map[uint32]bool) bool {
	return b.Registered && b.Armed && b.Ready && !deadWorkers[b.WorkerID]
}

type userspaceBindingKey struct {
	Ifindex uint32
	QueueID uint32
}

type userspaceBindingValue struct {
	Slot  uint32
	Flags uint32
}

type userspaceLocalV6Key struct {
	Addr [16]byte
}

type userspaceLocalAddressEntry struct {
	v4    bool
	v4Key uint32
	v6Key userspaceLocalV6Key
}

func (m *Manager) programBootstrapMapsLocked(snapshot *ConfigSnapshot, cfg config.UserspaceConfig) error {
	ctrlMap := m.bpfShim.Map(mapNameUserspaceCtrl)
	if ctrlMap == nil {
		return errors.New("userspace_ctrl map not loaded")
	}
	bindingsMap := m.bpfShim.Map(mapNameUserspaceBindings)
	if bindingsMap == nil {
		return errors.New("userspace_bindings map not loaded")
	}
	heartbeatMap := m.bpfShim.Map(mapNameUserspaceHeartbeat)
	if heartbeatMap == nil {
		return errors.New("userspace_heartbeat map not loaded")
	}

	// Populate userspace_cpumap so the XDP shim can use cpumap redirect
	// for IP packets that must reach the kernel on zero-copy AF_XDP paths.
	cpumapReady := m.setupUserspaceCPUMapLocked()

	zero := uint32(0)
	var ctrlFlags uint32
	if cpumapReady {
		ctrlFlags |= userspaceCtrlFlagCPUMap
	}
	if snapshotHasNativeGRE(snapshot) {
		ctrlFlags |= userspaceCtrlFlagNativeGRE
	}
	wgPort := snapshotWgListenPort(snapshot)
	if wgPort != 0 {
		ctrlFlags |= userspaceCtrlFlagWgRx
	}
	// Clamp the worker count before it feeds the ctrl fields and the
	// heartbeat zero-init loop below (#4572). deriveUserspaceConfig
	// already coerces workers<=0 -> 1 (capabilities.go), so the negative
	// case is defended one layer up; this restores the line-154/179
	// consistency with the QueueCount clamp on the next line and keeps the
	// low bound local to the map programmer. The genuinely dangerous input
	// is a large POSITIVE workers: the schema leaf is min-only
	// (ValidateIntegerMin(1)) and deriveUserspaceConfig does not cap the
	// upper side, so e.g. `workers 999999999` reaches the loop below and
	// uint32(999999999)*32 wraps to ~1.9B iterations that hang the apply
	// for hours — bounded by effectiveWorkers' map-capacity clamp.
	//
	// #5718 fold F3: ONE derivation feeds every representation of this
	// quantity. cfg.Workers used to be consumed TWICE under different rules —
	// `maxInt(cfg.Workers, 1)` cast to uint32 for ctrl.Workers/ctrl.QueueCount,
	// and the RAW cfg.Workers passed to heartbeatZeroSlots below — so the two
	// descriptions of "how many workers this dataplane has" could drift, and
	// after the A6-b01-C1 narrowing fix they demonstrably DID: `workers
	// 4294967296` clamps to the full heartbeat map for the zero-init loop
	// while `uint32(maxInt(...))` narrows to 0 for the ctrl fields, telling the
	// shim there are ZERO workers and ZERO queues. planUserspaceWorkers returns
	// both numbers from a single clamp, so no call site can pair a clamped
	// count with a raw one. cfg.Workers is read exactly once, here — a property
	// worker_count_single_source_5718_test.go asserts on this function's AST.
	plan := planUserspaceWorkers(cfg.Workers, heartbeatMap.MaxEntries())
	ctrl := userspaceCtrlValue{
		Enabled:            0,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            plan.Workers,
		QueueCount:         plan.Workers,
		Flags:              ctrlFlags,
		WgListenPort:       wgPort,
		ConfigGeneration:   0,
		FIBGeneration:      0,
		HeartbeatTimeoutMS: 30000,
	}
	if err := ctrlMap.Update(zero, ctrl, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update userspace_ctrl: %w", err)
	}

	// Bindings map is now an Array — zero previously-set indices.
	m.clearAllBindingRowsLocked()
	// Heartbeat map is now an Array — zero used slots instead of deleting.
	// Slots with value 0 appear as stale (bpf_ktime_get_ns() >> 0) so the
	// XDP shim correctly refuses to redirect until userspace begins updating.
	{
		var zeroHB uint64
		// The bound comes from the SAME derivation the ctrl fields above were
		// built from (#5718 fold F3): heartbeatZeroSlots clamps the worker
		// count low to 1 and high to the Array's real capacity, so neither a
		// negative nor an absurd cfg.Workers can make this loop wrap uint32 or
		// index past the map (#4572). Re-deriving it here from the raw
		// cfg.Workers is what let the two descriptions diverge.
		//
		// #5718 fold r3: read plan.HeartbeatSlots INLINE in the loop condition
		// rather than through a local. An intermediate `slots := ...` leaves a
		// decoy an AST guard can be satisfied by while the loop counts against
		// something else entirely — `slot < plan.Workers` zeroes one entry per
		// WORKER instead of per SLOT: 1 of 32 at the default worker count
		// (capabilities.go seeds Workers: 1), and 6 of 192 on the six-worker
		// loss cluster. Every un-zeroed slot keeps whatever stale value it
		// held. The bound the loop actually uses is the only thing worth
		// pinning, so it is the only thing written.
		for slot := uint32(0); slot < plan.HeartbeatSlots; slot++ {
			_ = heartbeatMap.Update(slot, zeroHB, ebpf.UpdateAny)
		}
	}
	return m.syncUserspaceClassifierMapsLocked(snapshot)
}

// setupUserspaceCPUMapLocked populates the userspace_cpumap BPF map with one
// entry per online CPU. This enables the XDP shim to use cpumap redirect
// instead of relying on driver-specific XDP_PASS recycling behavior for IP
// packets delivered to the kernel from zero-copy AF_XDP paths.
func (m *Manager) setupUserspaceCPUMapLocked() bool {
	cpuMap := m.bpfShim.Map(mapNameUserspaceCPUMap)
	if cpuMap == nil {
		slog.Warn("userspace_cpumap not found, zero-copy cpumap redirect disabled")
		return false
	}

	numCPUs := runtime.NumCPU()
	if numCPUs > 256 {
		numCPUs = 256
	}

	// cpumap value: struct { __u32 qsize; int bpf_prog_fd; }
	// With prog_fd=0, no cpumap program is attached — packets go to kernel.
	// TODO: attach xdp_cpumap_prog for eBPF embedded ICMP NAT reversal.
	for cpu := 0; cpu < numCPUs; cpu++ {
		val := make([]byte, 8)
		binary.NativeEndian.PutUint32(val[0:4], 2048) // qsize
		binary.NativeEndian.PutUint32(val[4:8], 0)    // no attached program
		if err := cpuMap.Update(uint32(cpu), val, ebpf.UpdateAny); err != nil {
			slog.Warn("userspace_cpumap update failed", "cpu", cpu, "err", err)
			return false
		}
	}

	slog.Info("userspace cpumap enabled for zero-copy AF_XDP", "cpus", numCPUs)
	return true
}

func (m *Manager) failClosedUserspaceCtrlLocked(ctrlMap *ebpf.Map, ctrl userspaceCtrlValue, cause error) error {
	if ctrl.Enabled != 1 {
		return cause
	}
	disabled := ctrl
	disabled.Enabled = 0
	zero := uint32(0)
	if err := ctrlMap.Update(zero, disabled, ebpf.UpdateAny); err != nil {
		return errors.Join(cause, fmt.Errorf("fail closed userspace_ctrl after publication error: %w", err))
	}
	if m.ctrlWasEnabled {
		m.ctrlDisabledAt = m.bpfKtimeNs()
	}
	m.ctrlWasEnabled = false
	return cause
}

func (m *Manager) syncUserspaceClassifierMapsLocked(snapshot *ConfigSnapshot) error {
	if err := m.syncIngressIfaceMapLocked(snapshot); err != nil {
		return err
	}
	if err := m.syncLocalAddressMapsLocked(snapshot); err != nil {
		return err
	}
	return m.syncInterfaceNATAddressMapsLocked(snapshot)
}

type userspaceCtrlLookupHook func(*ebpf.Map, uint32, *userspaceCtrlValue) error

func (m *Manager) lookupUserspaceCtrlForFailClosed(ctrlMap *ebpf.Map, key uint32, ctrl *userspaceCtrlValue) error {
	if m.lookupUserspaceCtrlForFailClosedHook != nil {
		return m.lookupUserspaceCtrlForFailClosedHook(ctrlMap, key, ctrl)
	}
	return ctrlMap.Lookup(key, ctrl)
}

func (m *Manager) syncUserspaceClassifierMapsFailClosedLocked(snapshot *ConfigSnapshot) error {
	if err := m.syncUserspaceClassifierMapsLocked(snapshot); err != nil {
		return m.failClosedUserspaceCtrlMapLocked(snapshot, err)
	}
	return nil
}

// failClosedUserspaceCtrlMapLocked drives the userspace_ctrl shim to the
// fail-closed state (Enabled=0) so the XDP shim stops redirecting transit to
// XSK and only passes proven local/control traffic to the kernel. It is the
// shared fail-closed action for any error that leaves the ingress/local/
// interface-NAT classifier BPF maps mutated to a plan the running Rust snapshot
// has NOT accepted: a classifier-map write failure
// (syncUserspaceClassifierMapsFailClosedLocked) OR a rejected apply_snapshot
// after an in-place same-plan refresh (#4959). cause is returned, wrapped with
// any secondary lookup/update error. When the ctrl row is unreadable the blind
// path reconstructs a disabled row from the snapshot; a genuinely-absent row
// (fresh boot, never enabled) is already fail-closed and returns cause
// unchanged.
func (m *Manager) failClosedUserspaceCtrlMapLocked(snapshot *ConfigSnapshot, cause error) error {
	ctrlMap := m.bpfShim.Map(mapNameUserspaceCtrl)
	if ctrlMap == nil {
		return cause
	}
	var ctrl userspaceCtrlValue
	zero := uint32(0)
	if lookupErr := m.lookupUserspaceCtrlForFailClosed(ctrlMap, zero, &ctrl); lookupErr != nil {
		if errors.Is(lookupErr, ebpf.ErrKeyNotExist) {
			return cause
		}
		return m.blindFailClosedUserspaceCtrlLocked(ctrlMap, snapshot, cause, lookupErr)
	}
	return m.failClosedUserspaceCtrlLocked(ctrlMap, ctrl, cause)
}

func (m *Manager) blindFailClosedUserspaceCtrlLocked(
	ctrlMap *ebpf.Map,
	snapshot *ConfigSnapshot,
	cause error,
	lookupErr error,
) error {
	disabled := userspaceCtrlValue{
		Enabled:            0,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            1,
		QueueCount:         1,
		HeartbeatTimeoutMS: 30000,
	}
	if snapshot != nil {
		workers := maxInt(snapshot.Userspace.Workers, 1)
		disabled.Workers = uint32(workers)
		disabled.QueueCount = uint32(workers)
		disabled.ConfigGeneration = snapshot.Generation
		disabled.FIBGeneration = snapshot.FIBGeneration
		disabled.WgListenPort = snapshotWgListenPort(snapshot)
		if disabled.WgListenPort != 0 {
			disabled.Flags |= userspaceCtrlFlagWgRx
		}
		if snapshotHasNativeGRE(snapshot) {
			disabled.Flags |= userspaceCtrlFlagNativeGRE
		}
	}
	if m.configuredMode == ModeUserspaceStrict {
		disabled.Flags |= userspaceCtrlFlagStrict
	}
	if cpuMap := m.bpfShim.Map(mapNameUserspaceCPUMap); cpuMap != nil {
		disabled.Flags |= userspaceCtrlFlagCPUMap
	}

	zero := uint32(0)
	if err := ctrlMap.Update(zero, disabled, ebpf.UpdateAny); err != nil {
		return errors.Join(
			cause,
			fmt.Errorf("lookup userspace_ctrl for classifier-map fail-closed: %w", lookupErr),
			fmt.Errorf("blind fail closed userspace_ctrl after lookup failure: %w", err),
		)
	}
	if m.ctrlWasEnabled {
		m.ctrlDisabledAt = m.bpfKtimeNs()
	}
	m.ctrlWasEnabled = false
	return errors.Join(
		cause,
		fmt.Errorf("lookup userspace_ctrl for classifier-map fail-closed: %w", lookupErr),
	)
}

func (m *Manager) applyHelperStatusLocked(status *ProcessStatus) error {
	ctrlMap := m.bpfShim.Map(mapNameUserspaceCtrl)
	if ctrlMap == nil {
		return errors.New("userspace_ctrl map not loaded")
	}
	bindingsMap := m.bpfShim.Map(mapNameUserspaceBindings)
	if bindingsMap == nil {
		return errors.New("userspace_bindings map not loaded")
	}

	var newBindingIndices []uint32
	newBindingIndexSet := make(map[uint32]struct{})

	// Preserve cpumap flag if cpumap is populated.
	var ctrlFlags uint32
	if cpuMap := m.bpfShim.Map(mapNameUserspaceCPUMap); cpuMap != nil {
		ctrlFlags |= userspaceCtrlFlagCPUMap
	}
	if snapshotHasNativeGRE(m.lastSnapshot) {
		ctrlFlags |= userspaceCtrlFlagNativeGRE
	}
	wgPort := snapshotWgListenPort(m.lastSnapshot)
	if wgPort != 0 {
		ctrlFlags |= userspaceCtrlFlagWgRx
	}

	zero := uint32(0)
	ctrl := userspaceCtrlValue{
		Enabled:            0,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            uint32(maxInt(status.Workers, 1)),
		QueueCount:         uint32(queueCountFromBindings(status.Bindings)),
		Flags:              ctrlFlags,
		WgListenPort:       wgPort,
		ConfigGeneration:   status.LastSnapshotGeneration,
		FIBGeneration:      status.LastFIBGeneration,
		HeartbeatTimeoutMS: 30000,
	}
	if status.Enabled && m.rgTransitionInFlight.Load() {
		// One or more RG transitions are in progress and the helper hasn't
		// acked the HA state update yet. Keep ctrl disabled until
		// syncHAStateLocked succeeds to avoid re-enabling ctrl during the
		// handoff (#279, #284).
		ctrl.Enabled = 0
	} else if status.Enabled {
		// Delay ctrl enable until AFTER VIPs are configured in HA mode.
		// The VRRP election + VIP add takes ~10-14s after restart.
		// If we enable ctrl before VIPs, the XSK path gets packets but
		// can't SNAT (no source address) -> all transit dropped. While
		// ctrl is disabled, only proven local/control traffic reaches the
		// kernel; transit remains fail-closed.
		//
		// Also delay by 3s for fill ring bootstrap: mlx5 zero-copy
		// needs NAPI to post fill ring WQEs, and NAPI only runs on
		// hardware RX events.  Background traffic (VRRP, ARP) during
		// the delay generates these events.
		if !m.neighborsPrewarmed {
			m.neighborsPrewarmed = true
			// Hard timeout fallback — ctrl enables after this even if
			// readiness checks haven't passed. Prevents infinite stall
			// if a readiness condition can never be met.
			//
			// Only set ctrlEnableAt on the FIRST prewarm so that
			// subsequent rebind cycles (which reset neighborsPrewarmed)
			// don't push the hard timeout forward indefinitely.
			if m.ctrlEnableAt.IsZero() {
				delay := 3 * time.Second
				if m.clusterHA {
					delay = 15 * time.Second
				}
				m.ctrlEnableAt = time.Now().Add(delay)
				slog.Info("userspace: delaying ctrl enable for readiness",
					"hard_timeout", delay, "cluster_ha", m.clusterHA)
			}
			m.bootstrapNAPIQueuesAsyncLocked("startup-prewarm")
			m.proactiveNeighborResolveLocked()
		}
		// Check readiness gates BEFORE refreshing neighbors (which
		// bumps the generation). The status reports the generation
		// from the previous refresh cycle.
		//
		// The helper can only prove RX liveness after ctrl enables the
		// shim and the userspace_bindings map exposes the binding slots.
		// Requiring Bound here deadlocks startup: ctrl stays off, the shim
		// keeps passing packets away from XSK, and Bound never flips true.
		probeBindingsReady := len(status.Bindings) > 0
		allBindingsBound := len(status.Bindings) > 0
		for _, b := range status.Bindings {
			if b.Ifindex <= 0 {
				continue
			}
			if !b.Registered || !b.Armed {
				probeBindingsReady = false
			}
			if b.Registered && !b.Bound {
				allBindingsBound = false
			}
		}
		// Fire OnXSKBound callback once when all bindings are bound.
		// This lets the daemon create fabric IPVLAN overlays after XSK
		// has bound in zerocopy mode on the parent interface.
		if allBindingsBound && !m.xskBoundNotified && m.OnXSKBound != nil {
			m.xskBoundNotified = true
			go m.OnXSKBound()
		}

		neighborSyncReady := status.NeighborGeneration > 0

		// XSK receive liveness: once bindings and neighbor state are ready,
		// arm ctrl and explicitly probe the userspace shim. A working XSK
		// path must show RX progress while ctrl=1 and the shim is active.
		// Otherwise keep ctrl disabled: local/control packets may still
		// reach the kernel, but transit fails closed in both modes.
		var currentRX uint64
		for _, b := range status.Bindings {
			currentRX += b.RXPackets
		}
		xskReceiveLive := currentRX > m.lastXSKRX
		m.lastXSKRX = currentRX
		slog.Debug("userspace: ctrl gate check",
			"probeBindingsReady", probeBindingsReady,
			"allBindingsBound", allBindingsBound,
			"neighborSyncReady", neighborSyncReady,
			"xskReceiveLive", xskReceiveLive,
			"currentRX", currentRX,
			"lastXSKRX", m.lastXSKRX,
			"neighborsPrewarmed", m.neighborsPrewarmed,
			"xskLivenessFailed", m.xskLivenessFailed,
			"xdpEntryProg", m.bpfShim.XDPEntryProgram())
		if m.xskLivenessFailed {
			// XSK proven broken: ctrl stays disabled. The shim only passes
			// proven local/control packets and drops transit.
			ctrl.Enabled = 0
		} else if probeBindingsReady && neighborSyncReady {
			ctrl.Enabled = 1
			if m.xskLivenessProven {
				if !m.bpfShim.UsingUserspaceXDPShimEntryProgram() {
					if err := m.bpfShim.SwapToUserspaceXDPShimEntryProgram(); err != nil {
						slog.Warn("userspace: failed to restore XDP shim after liveness success", "err", err)
					}
				}
			} else if xskReceiveLive {
				m.xskLivenessProven = true
				m.xskProbeStart = time.Time{}
				if !m.bpfShim.UsingUserspaceXDPShimEntryProgram() {
					if err := m.bpfShim.SwapToUserspaceXDPShimEntryProgram(); err != nil {
						slog.Warn("userspace: failed to swap XDP shim after XSK RX became live", "err", err)
					}
				}
				slog.Info("userspace: XSK liveness proven")
			} else {
				if !m.bpfShim.UsingUserspaceXDPShimEntryProgram() {
					if err := m.bpfShim.SwapToUserspaceXDPShimEntryProgram(); err != nil {
						slog.Warn("userspace: failed to activate XDP shim for XSK liveness probe", "err", err)
					}
				}
				if m.xskProbeStart.IsZero() {
					m.xskProbeStart = time.Now()
					slog.Info("userspace: starting XSK liveness probe")
				} else if time.Now().After(m.xskProbeStart.Add(10 * time.Second)) {
					if m.shouldAutoProveIdleStandbyXSKLocked(currentRX, allBindingsBound) {
						m.xskLivenessProven = true
						m.xskProbeStart = time.Time{}
						if !m.bpfShim.UsingUserspaceXDPShimEntryProgram() {
							if err := m.bpfShim.SwapToUserspaceXDPShimEntryProgram(); err != nil {
								slog.Warn("userspace: failed to restore XDP shim after idle standby liveness success", "err", err)
							}
						}
						slog.Info("userspace: XSK liveness proven on idle standby")
						goto ctrlReady
					} else if m.shouldExtendXSKLivenessIdleLocked(currentRX, allBindingsBound) {
						m.xskProbeStart = time.Now()
						slog.Info("userspace: extending XSK liveness probe while idle")
						goto ctrlReady
					}
					m.xskLivenessFailed = true
					m.xskProbeStart = time.Time{}
					ctrl.Enabled = 0
					if m.configuredMode == ModeUserspaceStrict {
						// Strict mode: keep the shim attached with ctrl=0
						// so packets hit the fail-closed ctrl-disabled path.
						// Log at error level because this degraded state
						// needs operator attention.
						slog.Error("userspace: XSK liveness probe failed in strict mode; dataplane degraded fail-closed")
					} else {
						slog.Warn("userspace: XSK liveness probe failed; keeping shim disabled with transit fail-closed")
						if !m.bpfShim.UsingUserspaceXDPShimEntryProgram() {
							if err := m.bpfShim.SwapToUserspaceXDPShimEntryProgram(); err != nil {
								slog.Warn("userspace: failed to restore XDP shim after XSK liveness failure", "err", err)
							}
						}
					}
				}
			}
		} else if !m.ctrlEnableAt.IsZero() && time.Now().After(m.ctrlEnableAt.Add(60*time.Second)) {
			// Hard timeout fallback: allow ctrl even if readiness has not been
			// fully proven yet. The XSK liveness probe still decides whether
			// the userspace shim starts redirecting or stays fail-closed
			// for transit.
			ctrl.Enabled = 1
		} else {
			ctrl.Enabled = 0
		}
	}
ctrlReady:
	// Flush stale BPF session entries when ctrl transitions from
	// disabled to enabled. Older legacy-fallback windows could create
	// PASS_TO_KERNEL entries in the userspace session map. These poison
	// the XDP shim after ctrl enables: it sees the stale entry and
	// bypasses XSK instead of redirecting to the userspace helper.
	//
	// Also flush BPF conntrack sessions left by earlier legacy-fallback
	// windows. These sessions interfere with the userspace pipeline via
	// TC egress: when the Rust helper sends packets via XSK TX, TC egress
	// finds the stale BPF conntrack entries and may apply conflicting NAT
	// or update session state incorrectly. The userspace helper's own
	// session table (Rust SessionTable + shared_sessions) holds the
	// authoritative synced sessions, so BPF conntrack must be empty when
	// ctrl re-enables.
	// Only flush stale BPF sessions on the very first ctrl enable after
	// daemon startup. Snapshot generation is not a reliable proxy for
	// "startup" on long-lived HA nodes because a steady appliance can stay
	// at generation 1 indefinitely; later ctrl re-enables during RG moves
	// would then retrigger the startup flush and destroy synced sessions.
	if ctrl.Enabled == 1 && !m.ctrlWasEnabled && !m.initialCtrlCleanupDone {
		if usMap := m.bpfShim.Map(mapNameUserspaceSessions); usMap != nil {
			var key, nextKey []byte
			key = make([]byte, usMap.KeySize())
			nextKey = make([]byte, usMap.KeySize())
			deleted := 0
			for {
				if err := usMap.NextKey(key, nextKey); err != nil {
					break
				}
				copy(key, nextKey)
				_ = usMap.Delete(key)
				deleted++
			}
			if deleted > 0 {
				slog.Info("userspace: flushed stale BPF session entries on initial ctrl enable",
					"deleted", deleted)
			}
		}
		// Flush BPF conntrack sessions left by an earlier fallback
		// transition window. Only delete
		// sessions whose Created timestamp is AFTER ctrlDisabledAt —
		// synced sessions from the cluster peer have earlier timestamps
		// and must survive for HA failover continuity.
		//
		// Why this is needed (issue #334): a previous legacy fallback
		// can leave conntrack entries in the BPF sessions map. When
		// ctrl re-enables, TC egress finds these stale BPF entries and
		// may apply conflicting NAT or update session state incorrectly;
		// the userspace helper's own session table (Rust SessionTable +
		// shared_sessions) is authoritative.
		//
		// session_value layout: State[1]+Flags[1]+TCPState[1]+
		// IsReverse[1]+AppTimeout[4]+SessionID[8]+Created[8].
		// Created is at byte offset 16. The value is seconds since
		// boot (bpf_ktime_get_coarse_ns / 1e9). ctrlDisabledAt is
		// nanoseconds, so convert to seconds for comparison.
		cutoffSec := m.ctrlDisabledAt / 1_000_000_000
		for _, mapName := range []string{"sessions", "sessions_v6"} {
			if ctMap := m.bpfShim.Map(mapName); ctMap != nil {
				keySize := ctMap.KeySize()
				valSize := ctMap.ValueSize()
				var key, nextKey []byte
				key = make([]byte, keySize)
				nextKey = make([]byte, keySize)
				val := make([]byte, valSize)
				deleted, kept := 0, 0
				for {
					if err := ctMap.NextKey(key, nextKey); err != nil {
						break
					}
					copy(key, nextKey)
					// Read session value to check Created timestamp.
					// Created is at byte offset 16:
					//   State(1) + Flags(1) + TCPState(1) + IsReverse(1)
					//   + AppTimeout(4) + SessionID(8) = 16
					if cutoffSec > 0 {
						if err := ctMap.Lookup(key, val); err == nil && len(val) >= 24 {
							created := binary.NativeEndian.Uint64(val[16:24])
							if created > 0 && created <= cutoffSec {
								kept++
								continue // synced session — keep it
							}
						}
					}
					_ = ctMap.Delete(key)
					deleted++
				}
				if deleted > 0 || kept > 0 {
					slog.Info("userspace: flushed stale BPF conntrack on ctrl enable",
						"map", mapName, "deleted", deleted, "kept_synced", kept,
						"cutoff_sec", cutoffSec)
				}
			}
		}
		m.initialCtrlCleanupDone = true
	}

	// Compute active runtime mode from ctrl state and liveness.
	switch {
	case ctrl.Enabled == 0 || m.xskLivenessFailed:
		// Degraded userspace mode keeps the shim attached. Compat still only
		// permits local/control kernel delivery; it is not eBPF-only transit.
		if m.configuredMode == ModeUserspaceStrict {
			m.mode = ModeUserspaceStrict
		} else {
			m.mode = ModeUserspaceCompat
		}
	case m.xskLivenessProven && m.configuredMode == ModeUserspaceStrict:
		m.mode = ModeUserspaceStrict
	case m.xskLivenessProven:
		m.mode = ModeUserspaceCompat
	default:
		// ctrl enabled but liveness not yet proven — still probing.
		m.mode = ModeUserspaceCompat
	}
	// Set strict flag in ctrl so the XDP shim reports strict degraded drops
	// separately while keeping transit fail-closed in both modes.
	if m.configuredMode == ModeUserspaceStrict {
		ctrl.Flags |= userspaceCtrlFlagStrict
	}

	if ctrl.Enabled == 0 {
		if err := ctrlMap.Update(zero, ctrl, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("disable userspace_ctrl from helper status: %w", err)
		}
		if m.ctrlWasEnabled {
			m.ctrlDisabledAt = m.bpfKtimeNs()
		}
		m.ctrlWasEnabled = false
	}

	deadWorkers := deadWorkerIDSet(status.WorkerRuntime)
	for _, binding := range status.Bindings {
		if binding.Ifindex <= 0 {
			continue
		}
		flags := uint32(0)
		if bindingForwardingLive(binding, deadWorkers) {
			// #1666: mark forwarding-ready only when the helper derives
			// the binding Ready (registered && bound && xsk_registered &&
			// heartbeat_fresh) and the worker has not panicked. The prior
			// (Registered && Armed) predicate let the XDP shim steer
			// transit to a slot whose worker had crashed or never finished
			// XSK registration (crash-blind blackhole). Ready's
			// sub-conditions are all set by worker bringup independent of
			// RX, so this does not deadlock startup (plan §4).
			flags = userspaceBindingReady
		}
		// Queue-dimension bound guard (#4894): a queue-id at or above the
		// fixed stride makes idx = ifindex*stride + queue land on
		// (ifindex+1)*stride + (queue-stride) — aliasing a slot that
		// belongs to the ADJACENT ifindex. The dense-cap guard below
		// cannot catch this (the aliased index is in range), so bound the
		// queue dimension explicitly and fail closed rather than steer an
		// interface's packets into another interface's XSK. Never
		// clamp/modulo the queue-id: that would still steer to a wrong
		// slot.
		if binding.QueueID >= bindingQueuesPerIface {
			return m.failClosedUserspaceCtrlLocked(ctrlMap, ctrl, fmt.Errorf(
				"update userspace_bindings: queue-id=%d >= stride=%d would alias the adjacent ifindex queue-0 slot (ifindex=%d) — cap the helper queue count or raise BINDING_QUEUES_PER_IFACE in userspace-xdp/src/binding_index.rs (mirrored in pkg/dataplane/constants.go) (#4894)",
				binding.QueueID, uint32(bindingQueuesPerIface), binding.Ifindex,
			))
		}
		idx := uint32(binding.Ifindex)*bindingQueuesPerIface + binding.QueueID
		// Call-site cap guard (#814): the aya Array is sized to
		// dataplane.BindingArrayMaxEntries = MaxInterfaces *
		// BindingQueuesPerIface. An ifindex above MaxInterfaces would
		// overflow the flat index; fail with a legible error instead
		// of relying on the kernel's "argument list too long" E2BIG.
		if idx >= dataplane.BindingArrayMaxEntries {
			return m.failClosedUserspaceCtrlLocked(ctrlMap, ctrl, fmt.Errorf(
				"update userspace_bindings: idx=%d exceeds cap=%d (ifindex=%d queue=%d; raise MAX_INTERFACES in bpf/headers/xpf_common.h)",
				idx, dataplane.BindingArrayMaxEntries, binding.Ifindex, binding.QueueID,
			))
		}
		val := userspaceBindingValue{
			Slot:  binding.Slot,
			Flags: flags,
		}
		if err := bindingsMap.Update(idx, val, ebpf.UpdateAny); err != nil {
			return m.failClosedUserspaceCtrlLocked(ctrlMap, ctrl, fmt.Errorf("update userspace_bindings idx=%d (if=%d q=%d): %w", idx, binding.Ifindex, binding.QueueID, err))
		}
		if _, seen := newBindingIndexSet[idx]; !seen {
			newBindingIndexSet[idx] = struct{}{}
			newBindingIndices = append(newBindingIndices, idx)
		}
	}
	for childIfindex, parentIfindex := range buildUserspaceIngressBindingAliases(m.lastSnapshot) {
		for _, binding := range status.Bindings {
			if binding.Ifindex != int(parentIfindex) {
				continue
			}
			flags := uint32(0)
			if bindingForwardingLive(binding, deadWorkers) {
				// #1666: unify the VLAN-alias child with the primary gate.
				flags = userspaceBindingReady
			}
			// Queue-dimension bound guard (#4894): see primary apply above.
			// The alias child uses its own ifindex, but the queue-id comes
			// from the parent's binding, so bound it here too.
			if binding.QueueID >= bindingQueuesPerIface {
				return m.failClosedUserspaceCtrlLocked(ctrlMap, ctrl, fmt.Errorf(
					"update aliased userspace_bindings: queue-id=%d >= stride=%d would alias the adjacent ifindex queue-0 slot (child=%d parent=%d) — cap the helper queue count or raise BINDING_QUEUES_PER_IFACE in userspace-xdp/src/binding_index.rs (mirrored in pkg/dataplane/constants.go) (#4894)",
					binding.QueueID, uint32(bindingQueuesPerIface), childIfindex, parentIfindex,
				))
			}
			idx := childIfindex*bindingQueuesPerIface + binding.QueueID
			// Call-site cap guard (#814): see primary apply above.
			// VLAN-alias children use their own ifindex here, so the
			// child (not the parent) is the overflow risk.
			if idx >= dataplane.BindingArrayMaxEntries {
				return m.failClosedUserspaceCtrlLocked(ctrlMap, ctrl, fmt.Errorf(
					"update aliased userspace_bindings: idx=%d exceeds cap=%d (child=%d parent=%d queue=%d; raise MAX_INTERFACES in bpf/headers/xpf_common.h)",
					idx, dataplane.BindingArrayMaxEntries, childIfindex, parentIfindex, binding.QueueID,
				))
			}
			val := userspaceBindingValue{
				Slot:  binding.Slot,
				Flags: flags,
			}
			if err := bindingsMap.Update(idx, val, ebpf.UpdateAny); err != nil {
				return m.failClosedUserspaceCtrlLocked(ctrlMap, ctrl, fmt.Errorf(
					"update aliased userspace_bindings idx=%d (if=%d parent=%d q=%d): %w",
					idx,
					childIfindex,
					parentIfindex,
					binding.QueueID,
					err,
				))
			}
			if _, seen := newBindingIndexSet[idx]; !seen {
				newBindingIndexSet[idx] = struct{}{}
				newBindingIndices = append(newBindingIndices, idx)
			}
		}
	}
	m.lastBindingIndices = m.clearStaleBindingRowsLocked(bindingsMap, newBindingIndices, newBindingIndexSet)
	if err := m.syncIngressIfaceMapLocked(m.lastSnapshot); err != nil {
		return m.failClosedUserspaceCtrlLocked(ctrlMap, ctrl, err)
	}
	if err := m.syncLocalAddressMapsLocked(m.lastSnapshot); err != nil {
		return m.failClosedUserspaceCtrlLocked(ctrlMap, ctrl, err)
	}
	if err := m.syncInterfaceNATAddressMapsLocked(m.lastSnapshot); err != nil {
		return m.failClosedUserspaceCtrlLocked(ctrlMap, ctrl, err)
	}
	// Sync userspace-forwarded packet counters into BPF counter maps so
	// that ReadGlobalCounter/ReadZoneCounters/etc. return complete values
	// even for packets that bypassed the BPF pipeline (#332).
	m.syncBPFCountersLocked(status)

	if ctrl.Enabled == 1 {
		if err := ctrlMap.Update(zero, ctrl, ebpf.UpdateAny); err != nil {
			return m.failClosedUserspaceCtrlLocked(ctrlMap, ctrl, fmt.Errorf("enable userspace_ctrl from helper status: %w", err))
		}
		m.ctrlWasEnabled = true
	}

	m.recordHelperStatusLocked(status)
	return nil
}

// clearStaleBindingRowsLocked zeroes userspace_bindings rows that were live on
// the previous status pass (recorded in m.lastBindingIndices) but are absent
// from the current pass (newBindingIndexSet). It returns the retry inventory
// to store back into m.lastBindingIndices.
//
// A row whose zeroing Update FAILS is RETAINED in the returned inventory so a
// later status pass re-attempts the clear (#5697, codex-review-182 M20). The
// clear loop only rescans indices recorded in m.lastBindingIndices, so if a
// failed clear dropped the row from the inventory it would never be
// rediscovered — the stale row would persist in the BPF map indefinitely and
// the XDP shim would keep steering transit to a slot no longer backed by a
// live worker. A successful clear removes the row from the inventory (it is
// not in newBindingIndexSet, so it is not carried forward).
func (m *Manager) clearStaleBindingRowsLocked(bindingsMap *ebpf.Map, newBindingIndices []uint32, newBindingIndexSet map[uint32]struct{}) []uint32 {
	var zeroBinding userspaceBindingValue
	for _, idx := range m.lastBindingIndices {
		if _, keep := newBindingIndexSet[idx]; keep {
			continue
		}
		if err := bindingsMap.Update(idx, zeroBinding, ebpf.UpdateAny); err != nil {
			slog.Warn("userspace: failed to clear stale binding entry; retaining in retry inventory",
				"idx", idx, "err", err)
			if _, seen := newBindingIndexSet[idx]; !seen {
				newBindingIndexSet[idx] = struct{}{}
				newBindingIndices = append(newBindingIndices, idx)
			}
			continue
		}
	}
	return newBindingIndices
}

// clearAllBindingRowsLocked zeroes every userspace_bindings row recorded in
// m.lastBindingIndices and forgets the inventory. It is the fail-closed
// teardown primitive (#5486): when ctrl-disable cannot be verified before
// worker/UMEM teardown, this leaves the XDP shim with no READY slot to
// redirect to, so no packet can reach a soon-dead XSK fd. It mirrors the
// bootstrap zero-all used by the initial map program. Best-effort: a per-row
// Update failure on the teardown path is not fatal (the helper is stopping),
// but the inventory is always niled so a fresh apply re-establishes rows.
func (m *Manager) clearAllBindingRowsLocked() {
	bindingsMap := m.bpfShim.Map(mapNameUserspaceBindings)
	if bindingsMap == nil {
		m.lastBindingIndices = nil
		return
	}
	var zeroBinding userspaceBindingValue
	for _, idx := range m.lastBindingIndices {
		_ = bindingsMap.Update(idx, zeroBinding, ebpf.UpdateAny)
	}
	m.lastBindingIndices = nil
}

// userspaceCounterSnapshot holds cumulative counter totals from the helper,
// used to compute deltas between status polls.

// degradedPathReasonNames maps BPF array index to a human-readable name.
// Must stay in sync with USERSPACE_FALLBACK_REASON_* in userspace-xdp/src/lib.rs.
var degradedPathReasonNames = [16]string{
	0:  "ctrl_disabled",
	1:  "parse_fail",
	2:  "binding_missing",
	3:  "binding_not_ready",
	4:  "heartbeat_missing",
	5:  "heartbeat_stale",
	6:  "icmp",
	7:  "early_filter",
	8:  "adjust_meta",
	9:  "meta_bounds",
	10: "redirect_err",
	11: "interface_nat_no_session",
	12: "no_session",
	13: "strict_drop",
	14: "pass_to_kernel",
	15: "transit_drop",
}

// readDegradedPathStatsLocked reads retained-shim degraded-path counters and
// returns a map of reason name -> cumulative count. Entries with zero count are
// omitted.
//
// The pinned BPF map name remains userspace_fallback_stats as an internal
// mixed-version compatibility exception. Operator-facing Go status, JSON, and
// docs must use degraded-path terminology instead.
func (m *Manager) readDegradedPathStatsLocked() map[string]uint64 {
	statsMap := m.bpfShim.Map(mapNameUserspaceShimDegradedStats)
	if statsMap == nil {
		return nil
	}
	result := make(map[string]uint64)
	for i := uint32(0); i < uint32(len(degradedPathReasonNames)); i++ {
		// #4113 (F13): userspace_fallback_stats is a PER-CPU array. A per-CPU
		// map lookup returns one value per possible CPU, which we sum to get
		// the cumulative count for this reason. Reading into a single uint64
		// would fail (per-CPU maps require a slice destination).
		var perCPU []uint64
		if err := statsMap.Lookup(i, &perCPU); err != nil {
			continue
		}
		var val uint64
		for _, v := range perCPU {
			val += v
		}
		if val == 0 {
			continue
		}
		name := degradedPathReasonNames[i]
		if name == "" {
			name = fmt.Sprintf("reason_%d", i)
		}
		result[name] = val
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// entryProgramsLocked returns a map of ifindex -> attached XDP program name
// by inspecting the bpfShim dataplane manager's link state.
// Note: VLAN sub-interfaces are skipped during userspace-shim swaps and may
// retain the parent's program; they are excluded from this map.
func (m *Manager) entryProgramsLocked() map[int]string {
	links := m.bpfShim.XDPLinks()
	if len(links) == 0 {
		return nil
	}
	progName := m.bpfShim.XDPEntryProgram()
	result := make(map[int]string, len(links))
	for ifindex := range links {
		if m.bpfShim.VlanSubInterfaces[ifindex] {
			continue // VLAN sub-interfaces use parent's XDP program
		}
		result[ifindex] = progName
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func (m *Manager) syncIngressIfaceMapLocked(snapshot *ConfigSnapshot) error {
	ifaceMap := m.bpfShim.Map(mapNameUserspaceIngressIfaces)
	if ifaceMap == nil {
		return errors.New("userspace_ingress_ifaces map not loaded")
	}

	newIngress := buildUserspaceIngressIfindexes(snapshot)
	newIngressSet := make(map[uint32]struct{}, len(newIngress))
	for _, ifindex := range newIngress {
		newIngressSet[ifindex] = struct{}{}
		if err := ifaceMap.Update(ifindex, uint8(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update userspace_ingress_ifaces %d: %w", ifindex, err)
		}
	}
	// HashMap: Delete removes the entry. ErrKeyNotExist is expected
	// across daemon restarts (idempotent). Any other failure must be
	// fatal — a stale entry the dataplane still treats as ingress
	// would silently redirect traffic for an interface removed from
	// the config.
	for _, k := range m.lastIngressIfaces {
		if _, keep := newIngressSet[k]; keep {
			continue
		}
		if err := ifaceMap.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete userspace_ingress_ifaces %d: %w", k, err)
		}
	}
	m.lastIngressIfaces = newIngress
	return nil
}

func (m *Manager) syncLocalAddressMapsLocked(snapshot *ConfigSnapshot) error {
	localV4Map := m.bpfShim.Map(mapNameUserspaceLocalV4)
	if localV4Map == nil {
		return errors.New("userspace_local_v4 map not loaded")
	}
	localV6Map := m.bpfShim.Map(mapNameUserspaceLocalV6)
	if localV6Map == nil {
		return errors.New("userspace_local_v6 map not loaded")
	}

	desiredV4, desiredV6, enumComplete := m.buildDesiredLocalAddressSets(snapshot)
	for key := range desiredV4 {
		if err := localV4Map.Update(key, uint8(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update userspace_local_v4 %08x: %w", key, err)
		}
	}
	for key := range desiredV6 {
		if err := localV6Map.Update(key, uint8(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update userspace_local_v6 %+v: %w", key, err)
		}
	}

	// A transient netlink AddrList failure (or an interrupted/ENOBUFS
	// partial dump) yields a NON-AUTHORITATIVE desired set that may be
	// missing kernel-owned VIP addresses (VRRP VIPs, secondary locals).
	// Pruning against that partial set would delete live VRRP VIP / local
	// keys from userspace_local_v4/v6 and blackhole packets destined to
	// the VIP / SSH / BGP / IKE local endpoints (#3924). Treat the
	// incomplete enumeration as non-authoritative: the adds above already
	// landed (adding is always safe — it only ever widens the local set),
	// but SKIP the stale-key prune this cycle and warn. The next reconcile
	// with a complete enumeration removes any genuinely stale keys.
	if !enumComplete {
		slog.Warn("userspace local-address sync: netlink AddrList enumeration incomplete; " +
			"skipping stale-key prune to avoid removing VRRP VIP/local keys from " +
			"userspace_local_v4/v6 (will reconcile on the next complete enumeration)")
		return nil
	}

	var (
		localV4Key uint32
		localV4Val uint8
	)
	localV4Iter := localV4Map.Iterate()
	var staleLocalV4Keys []uint32
	for localV4Iter.Next(&localV4Key, &localV4Val) {
		if _, keep := desiredV4[localV4Key]; keep {
			continue
		}
		staleLocalV4Keys = append(staleLocalV4Keys, localV4Key)
	}
	if err := localV4Iter.Err(); err != nil {
		return fmt.Errorf("iterate userspace_local_v4: %w", err)
	}
	for _, key := range staleLocalV4Keys {
		if err := localV4Map.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete userspace_local_v4 %08x: %w", key, err)
		}
	}

	var (
		localV6Key userspaceLocalV6Key
		localV6Val uint8
	)
	localV6Iter := localV6Map.Iterate()
	var staleLocalV6Keys []userspaceLocalV6Key
	for localV6Iter.Next(&localV6Key, &localV6Val) {
		if _, keep := desiredV6[localV6Key]; keep {
			continue
		}
		staleLocalV6Keys = append(staleLocalV6Keys, localV6Key)
	}
	if err := localV6Iter.Err(); err != nil {
		return fmt.Errorf("iterate userspace_local_v6: %w", err)
	}
	for _, key := range staleLocalV6Keys {
		if err := localV6Map.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete userspace_local_v6 %+v: %w", key, err)
		}
	}
	return nil
}

// addrListHook mirrors netlink.AddrList so tests can inject a transient
// enumeration failure through the Manager (#3924).
type addrListHook func(link netlink.Link, family int) ([]netlink.Addr, error)

// addrListForLocalSync enumerates addresses for the local-address map
// reconcile, dispatching to the test hook when one is installed and to
// netlink.AddrList otherwise.
func (m *Manager) addrListForLocalSync(link netlink.Link, family int) ([]netlink.Addr, error) {
	if m.addrListForLocalSyncHook != nil {
		return m.addrListForLocalSyncHook(link, family)
	}
	return netlink.AddrList(link, family)
}

// buildDesiredLocalAddressSets returns the desired userspace_local_v4/v6
// key sets and reports whether the kernel-address enumeration was
// COMPLETE. enumComplete is false when any netlink AddrList family dump
// failed — in that case the returned sets are non-authoritative (they may
// be missing kernel-owned VIP addresses), so the caller MUST NOT prune
// existing map keys against them (#3924). Config-derived entries are
// always present regardless of enumeration outcome.
func (m *Manager) buildDesiredLocalAddressSets(snapshot *ConfigSnapshot) (desiredV4 map[uint32]struct{}, desiredV6 map[userspaceLocalV6Key]struct{}, enumComplete bool) {
	desiredV4 = make(map[uint32]struct{})
	desiredV6 = make(map[userspaceLocalV6Key]struct{})
	for _, entry := range buildLocalAddressEntries(snapshot) {
		if entry.v4 {
			desiredV4[entry.v4Key] = struct{}{}
			continue
		}
		desiredV6[entry.v6Key] = struct{}{}
	}
	// Also add kernel addresses (VIPs added by VRRP) that aren't in the
	// config snapshot. Without this, the XDP shim doesn't recognize VIP
	// destinations as local and redirects them to XSK instead of the kernel.
	// Use AddrList(nil, ...) to enumerate ALL addresses on the system.
	//
	// A failed family dump means the enumeration is INCOMPLETE: record it
	// via enumComplete so the caller skips the destructive prune. We still
	// accumulate whatever the surviving family dump returned (adding is
	// safe — only pruning against a partial set is dangerous).
	enumComplete = true
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		addrs, err := m.addrListForLocalSync(nil, family)
		if err != nil {
			enumComplete = false
			continue
		}
		for _, addr := range addrs {
			ip := addr.IP
			if ip == nil {
				continue
			}
			if v4 := ip.To4(); v4 != nil && family == netlink.FAMILY_V4 {
				key := binary.BigEndian.Uint32(v4)
				desiredV4[key] = struct{}{}
			} else if v6 := ip.To16(); v6 != nil && family == netlink.FAMILY_V6 {
				var key [16]byte
				copy(key[:], v6)
				desiredV6[userspaceLocalV6Key{Addr: key}] = struct{}{}
			}
		}
	}
	return desiredV4, desiredV6, enumComplete
}

func (m *Manager) syncInterfaceNATAddressMapsLocked(snapshot *ConfigSnapshot) error {
	natV4Map := m.bpfShim.Map(mapNameUserspaceInterfaceNATv4)
	if natV4Map == nil {
		return errors.New("userspace_interface_nat_v4 map not loaded")
	}
	natV6Map := m.bpfShim.Map(mapNameUserspaceInterfaceNATv6)
	if natV6Map == nil {
		return errors.New("userspace_interface_nat_v6 map not loaded")
	}

	desiredV4, desiredV6, rstV4, rstV6 := buildDesiredInterfaceNATAddressSets(snapshot)
	for key := range desiredV4 {
		if err := natV4Map.Update(key, uint8(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update userspace_interface_nat_v4 %08x: %w", key, err)
		}
	}
	for key := range desiredV6 {
		if err := natV6Map.Update(key, uint8(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update userspace_interface_nat_v6 %+v: %w", key, err)
		}
	}

	var (
		natV4Key uint32
		natV4Val uint8
	)
	natV4Iter := natV4Map.Iterate()
	var staleNatV4Keys []uint32
	for natV4Iter.Next(&natV4Key, &natV4Val) {
		if _, keep := desiredV4[natV4Key]; keep {
			continue
		}
		staleNatV4Keys = append(staleNatV4Keys, natV4Key)
	}
	if err := natV4Iter.Err(); err != nil {
		return fmt.Errorf("iterate userspace_interface_nat_v4: %w", err)
	}
	for _, key := range staleNatV4Keys {
		if err := natV4Map.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete userspace_interface_nat_v4 %08x: %w", key, err)
		}
	}

	var (
		natV6Key userspaceLocalV6Key
		natV6Val uint8
	)
	natV6Iter := natV6Map.Iterate()
	var staleNatV6Keys []userspaceLocalV6Key
	for natV6Iter.Next(&natV6Key, &natV6Val) {
		if _, keep := desiredV6[natV6Key]; keep {
			continue
		}
		staleNatV6Keys = append(staleNatV6Keys, natV6Key)
	}
	if err := natV6Iter.Err(); err != nil {
		return fmt.Errorf("iterate userspace_interface_nat_v6: %w", err)
	}
	for _, key := range staleNatV6Keys {
		if err := natV6Map.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete userspace_interface_nat_v6 %+v: %w", key, err)
		}
	}

	slices.SortFunc(rstV4, netip.Addr.Compare)
	slices.SortFunc(rstV6, netip.Addr.Compare)
	// Install RST suppression rules. Retry immediately on address changes,
	// and periodically retry unchanged failed installs so a transient
	// startup failure does not leave the node permanently unprotected.
	now := time.Now()
	if shouldAttemptRSTSuppression(
		now,
		rstV4,
		rstV6,
		m.lastRSTv4,
		m.lastRSTv6,
		m.lastRSTAttempt,
		m.lastRSTInstallOK,
	) {
		if err := xpfnft.InstallRSTSuppression(rstV4, rstV6); err != nil {
			slog.Warn("userspace: RST suppression unavailable (nftables error, non-fatal)", "err", err)
			m.lastRSTInstallOK = false
		} else {
			m.lastRSTInstallOK = true
		}
		m.lastRSTAttempt = now
		m.lastRSTv4 = slices.Clone(rstV4)
		m.lastRSTv6 = slices.Clone(rstV6)
	}
	return nil
}

func buildDesiredInterfaceNATAddressSets(snapshot *ConfigSnapshot) (map[uint32]struct{}, map[userspaceLocalV6Key]struct{}, []netip.Addr, []netip.Addr) {
	entries := buildInterfaceNATAddressEntries(snapshot)
	v4Count := 0
	for _, entry := range entries {
		if entry.v4 {
			v4Count++
		}
	}
	v6Count := len(entries) - v4Count
	desiredV4 := make(map[uint32]struct{})
	desiredV6 := make(map[userspaceLocalV6Key]struct{})
	rstV4 := make([]netip.Addr, 0, v4Count)
	rstV6 := make([]netip.Addr, 0, v6Count)
	for _, entry := range entries {
		if entry.v4 {
			desiredV4[entry.v4Key] = struct{}{}
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], entry.v4Key)
			rstV4 = append(rstV4, netip.AddrFrom4(b))
			continue
		}
		desiredV6[entry.v6Key] = struct{}{}
		rstV6 = append(rstV6, netip.AddrFrom16(entry.v6Key.Addr))
	}
	return desiredV4, desiredV6, rstV4, rstV6
}

// verifyBindingsMapLocked reads the BPF userspace_bindings map and compares
// each entry against the helper's last reported binding status. If the helper
// reports a binding as Registered+Armed (meaning the XSK socket exists and the
// queue is armed for redirect) but the BPF map entry is all zeros (no slot,
// no flags), the BPF map is stale — the XDP shim has nothing to redirect to
// and all transit traffic silently drops.
//
// This can happen after a peer crash+reconnect when Compile() calls
// programBootstrapMapsLocked() which zeros the bindings map, and then either:
//   - applyHelperStatusLocked didn't run (error path)
//   - another Compile() ran concurrently and re-zeroed the map
//   - the bpfShim eBPF compile recreated the map from a fresh pin
//
// When a mismatch is detected, this method rewrites the BPF map entries from
// the helper's reported state — the same logic as applyHelperStatusLocked but
// targeted to only the stale entries. This is cheaper than a full rebind.
//
// Returns true if any stale entries were repaired.
func (m *Manager) verifyBindingsMapLocked() bool {
	if m.proc == nil || m.proc.Process == nil {
		return false
	}
	// Only check when ctrl is enabled and bindings should be active.
	// During startup (ctrl=0), the map is expected to be empty.
	if !m.ctrlWasEnabled {
		return false
	}
	bindings := m.lastStatus.Bindings
	if len(bindings) == 0 {
		return false
	}
	bindingsMap := m.bpfShim.Map(mapNameUserspaceBindings)
	if bindingsMap == nil {
		return false
	}

	deadWorkers := deadWorkerIDSet(m.lastStatus.WorkerRuntime)
	repaired := 0
	for _, binding := range bindings {
		if binding.Ifindex <= 0 {
			continue
		}
		// #1666: only repair (re-assert READY for) slots whose worker is
		// actually forwarding-live. Repairing on (Registered && Armed)
		// would let the watchdog fight the crash-clear by rewriting
		// READY=1 for a dead worker.
		if !bindingForwardingLive(binding, deadWorkers) {
			continue
		}
		// Queue-dimension bound guard (#4894): repair-only, log-and-skip
		// (never unwind). A queue-id at/above the stride would alias the
		// adjacent ifindex queue-0 slot; the dense-cap guard below cannot
		// catch that, so skip the binding instead of repairing a wrong slot.
		if binding.QueueID >= bindingQueuesPerIface {
			slog.Warn("userspace: bindings watchdog: queue-id at/above stride would alias adjacent ifindex queue-0 slot, skipping (#4894)",
				"ifindex", binding.Ifindex, "queue", binding.QueueID,
				"stride", uint32(bindingQueuesPerIface))
			continue
		}
		idx := uint32(binding.Ifindex)*bindingQueuesPerIface + binding.QueueID
		// Call-site cap guard (#814): the watchdog is repair-only and
		// must not unwind. Log and skip if the ifindex would overflow
		// the BindingArrayMaxEntries dense cap.
		if idx >= dataplane.BindingArrayMaxEntries {
			slog.Warn("userspace: bindings watchdog: ifindex exceeds BindingArrayMaxEntries cap, skipping",
				"ifindex", binding.Ifindex, "queue", binding.QueueID,
				"idx", idx, "cap", dataplane.BindingArrayMaxEntries)
			continue
		}
		var val userspaceBindingValue
		if err := bindingsMap.Lookup(idx, &val); err != nil {
			slog.Debug("userspace: bindings watchdog lookup failed",
				"ifindex", binding.Ifindex, "queue", binding.QueueID, "err", err)
			continue
		}
		if val.Flags != 0 || val.Slot != 0 {
			// BPF map entry is populated — no mismatch.
			continue
		}
		// BPF map entry is all zeros but the helper says the queue is
		// forwarding-live (Registered && Armed && Ready && !Dead, gated
		// above). Rewrite the entry.
		flags := uint32(userspaceBindingReady)
		newVal := userspaceBindingValue{
			Slot:  binding.Slot,
			Flags: flags,
		}
		if err := bindingsMap.Update(idx, newVal, ebpf.UpdateAny); err != nil {
			slog.Warn("userspace: bindings watchdog failed to repair entry",
				"ifindex", binding.Ifindex, "queue", binding.QueueID,
				"slot", binding.Slot, "err", err)
			continue
		}
		repaired++
	}

	// Also repair aliased bindings (VLAN children inheriting parent's XSK).
	if m.lastSnapshot != nil {
		for childIfindex, parentIfindex := range buildUserspaceIngressBindingAliases(m.lastSnapshot) {
			for _, binding := range bindings {
				if binding.Ifindex != int(parentIfindex) {
					continue
				}
				// #1666: same forwarding-live gate as the primary repair.
				if !bindingForwardingLive(binding, deadWorkers) {
					continue
				}
				// Queue-dimension bound guard (#4894): repair-only,
				// log-and-skip. Same aliasing risk as the primary watchdog
				// path; the queue-id comes from the parent binding.
				if binding.QueueID >= bindingQueuesPerIface {
					slog.Warn("userspace: bindings watchdog alias: queue-id at/above stride would alias adjacent ifindex queue-0 slot, skipping (#4894)",
						"child", childIfindex, "parent", parentIfindex,
						"queue", binding.QueueID, "stride", uint32(bindingQueuesPerIface))
					continue
				}
				idx := childIfindex*bindingQueuesPerIface + binding.QueueID
				// Call-site cap guard (#814): repair-only, log-and-skip
				// instead of unwinding. VLAN child ifindex is the
				// overflow risk here.
				if idx >= dataplane.BindingArrayMaxEntries {
					slog.Warn("userspace: bindings watchdog alias: ifindex exceeds BindingArrayMaxEntries cap, skipping",
						"child", childIfindex, "parent", parentIfindex,
						"queue", binding.QueueID,
						"idx", idx, "cap", dataplane.BindingArrayMaxEntries)
					continue
				}
				var val userspaceBindingValue
				if err := bindingsMap.Lookup(idx, &val); err != nil {
					slog.Debug("userspace: bindings watchdog alias lookup failed",
						"child", childIfindex, "parent", parentIfindex, "queue", binding.QueueID, "err", err)
					continue
				}
				if val.Flags != 0 || val.Slot != 0 {
					continue
				}
				newVal := userspaceBindingValue{
					Slot:  binding.Slot,
					Flags: userspaceBindingReady,
				}
				if err := bindingsMap.Update(idx, newVal, ebpf.UpdateAny); err != nil {
					slog.Warn("userspace: bindings watchdog failed to repair alias entry",
						"child", childIfindex, "parent", parentIfindex,
						"queue", binding.QueueID, "slot", binding.Slot, "err", err)
					continue
				}
				repaired++
			}
		}
	}

	if repaired > 0 {
		slog.Warn("userspace: bindings watchdog repaired stale BPF map entries",
			"repaired", repaired, "total_bindings", len(bindings))
	}
	return repaired > 0
}

func (m *Manager) hasBusyBindingsWedgeLocked(repaired bool) bool {
	if m.proc == nil || m.proc.Process == nil {
		return false
	}
	if !m.lastStatus.ForwardingArmed || m.deferWorkers {
		return false
	}
	if m.xskLivenessProven || m.xskLivenessFailed {
		return false
	}
	bindings := m.lastStatus.Bindings
	if len(bindings) == 0 {
		return false
	}
	registeredArmed := 0
	bound := 0
	ready := 0
	busyErr := false
	for _, binding := range bindings {
		if binding.Ifindex <= 0 {
			continue
		}
		if binding.Registered && binding.Armed {
			registeredArmed++
		}
		if binding.Bound {
			bound++
		}
		if binding.Ready {
			ready++
		}
		if strings.Contains(strings.ToLower(binding.LastError), "resource busy") {
			busyErr = true
		}
	}
	return registeredArmed > 0 && bound == 0 && ready == 0 && (busyErr || repaired)
}

func (m *Manager) shouldAutoRebindBusyBindingsLocked(now time.Time, repaired bool) bool {
	if !m.hasBusyBindingsWedgeLocked(repaired) {
		m.bindingsBusySince = time.Time{}
		return false
	}
	if m.bindingsBusySince.IsZero() {
		m.bindingsBusySince = now
		return false
	}
	if now.Sub(m.bindingsBusySince) < 5*time.Second {
		return false
	}
	if !m.lastBindingsAutoRebind.IsZero() && now.Sub(m.lastBindingsAutoRebind) < 15*time.Second {
		return false
	}
	m.lastBindingsAutoRebind = now
	return true
}

func (m *Manager) maybeAutoRebindBusyBindingsLocked(now time.Time, repaired bool) {
	if !m.shouldAutoRebindBusyBindingsLocked(now, repaired) {
		return
	}
	var status ProcessStatus
	m.neighborsPrewarmed = false
	m.xskLivenessProven = false
	m.xskLivenessFailed = false
	m.xskProbeStart = time.Time{}
	m.lastXSKRX = 0
	if err := m.requestLocked(ControlRequest{Type: "rebind"}, &status); err != nil {
		slog.Warn("userspace: auto-rebind for stuck XSK bindings failed", "err", err)
		return
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		slog.Warn("userspace: auto-rebind status sync failed", "err", err)
	}
	slog.Warn("userspace: auto-rebind initiated for stuck XSK bindings",
		"bindings", len(status.Bindings),
		"forwarding_armed", status.ForwardingArmed)
	m.bootstrapNAPIQueuesAsyncLocked("busy-xsk-wedge")
}

func buildLocalAddressEntries(snapshot *ConfigSnapshot) []userspaceLocalAddressEntry {
	if snapshot == nil {
		return nil
	}
	excludedV4, excludedV6 := buildNATTranslatedLocalAddressExclusions(snapshot)
	seenV4 := make(map[uint32]bool)
	seenV6 := make(map[[16]byte]bool)
	out := make([]userspaceLocalAddressEntry, 0)
	for _, iface := range snapshot.Interfaces {
		for _, addr := range iface.Addresses {
			ip, _, err := net.ParseCIDR(addr.Address)
			if err != nil || ip == nil {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				key := binary.BigEndian.Uint32(v4)
				if excludedV4[key] || seenV4[key] {
					continue
				}
				seenV4[key] = true
				out = append(out, userspaceLocalAddressEntry{v4: true, v4Key: key})
				continue
			}
			v6 := ip.To16()
			if v6 == nil {
				continue
			}
			var key [16]byte
			copy(key[:], v6)
			if excludedV6[key] || seenV6[key] {
				continue
			}
			seenV6[key] = true
			out = append(out, userspaceLocalAddressEntry{v4: false, v6Key: userspaceLocalV6Key{Addr: key}})
		}
	}
	return out
}

func buildInterfaceNATAddressEntries(snapshot *ConfigSnapshot) []userspaceLocalAddressEntry {
	if snapshot == nil {
		return nil
	}
	excludedV4, excludedV6 := buildNATTranslatedLocalAddressExclusions(snapshot)
	seenV4 := make(map[uint32]bool)
	seenV6 := make(map[[16]byte]bool)
	out := make([]userspaceLocalAddressEntry, 0)
	for key := range excludedV4 {
		if seenV4[key] {
			continue
		}
		seenV4[key] = true
		out = append(out, userspaceLocalAddressEntry{v4: true, v4Key: key})
	}
	for key := range excludedV6 {
		if seenV6[key] {
			continue
		}
		seenV6[key] = true
		out = append(out, userspaceLocalAddressEntry{v6Key: userspaceLocalV6Key{Addr: key}})
	}
	return out
}

func buildUserspaceIngressIfindexes(snapshot *ConfigSnapshot) []uint32 {
	if snapshot == nil {
		return nil
	}
	seen := make(map[uint32]bool)
	out := make([]uint32, 0)
	for _, iface := range snapshot.Interfaces {
		if iface.Zone == "" || userspaceSkipsIngressInterface(iface) {
			continue
		}
		if iface.ParentIfindex > 0 {
			if iface.Ifindex > 0 && !iface.LogicalOnly {
				key := uint32(iface.Ifindex)
				if !seen[key] {
					seen[key] = true
					out = append(out, key)
				}
			}
			key := uint32(iface.ParentIfindex)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, key)
			continue
		}
		if iface.Ifindex <= 0 {
			continue
		}
		key := uint32(iface.Ifindex)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	for _, fab := range snapshot.Fabrics {
		if fab.ParentIfindex <= 0 {
			continue
		}
		key := uint32(fab.ParentIfindex)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func snapshotBindingPlanKey(snapshot *ConfigSnapshot) string {
	if snapshot == nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "workers=%d;ring=%d;", snapshot.Userspace.Workers, snapshot.Userspace.RingEntries)
	for _, iface := range snapshot.Interfaces {
		if iface.Zone == "" || userspaceSkipsIngressInterface(iface) {
			continue
		}
		fmt.Fprintf(
			&b,
			"iface=%s/%s/%d/%d/%d/%t/%t;",
			iface.Name,
			iface.LinuxName,
			iface.Ifindex,
			iface.ParentIfindex,
			iface.RXQueues,
			iface.LogicalOnly,
			iface.Tunnel,
		)
	}
	for _, fab := range snapshot.Fabrics {
		fmt.Fprintf(
			&b,
			"fabric=%s/%s/%d/%d;",
			fab.Name,
			fab.ParentLinuxName,
			fab.ParentIfindex,
			fab.RXQueues,
		)
	}
	return b.String()
}

func buildUserspaceIngressBindingAliases(snapshot *ConfigSnapshot) map[uint32]uint32 {
	if snapshot == nil {
		return nil
	}
	out := make(map[uint32]uint32)
	for _, iface := range snapshot.Interfaces {
		if iface.Zone == "" || userspaceSkipsIngressInterface(iface) {
			continue
		}
		if iface.Ifindex <= 0 || iface.ParentIfindex <= 0 || iface.Ifindex == iface.ParentIfindex || iface.LogicalOnly {
			continue
		}
		out[uint32(iface.Ifindex)] = uint32(iface.ParentIfindex)
	}
	return out
}

func snapshotHasNativeGRE(snapshot *ConfigSnapshot) bool {
	if snapshot == nil {
		return false
	}
	for _, endpoint := range snapshot.TunnelEndpoints {
		if endpoint.ID == 0 {
			continue
		}
		switch endpoint.Mode {
		case "", "gre", "ip6gre":
			return true
		}
	}
	return false
}

// snapshotWgListenPort returns the WireGuard listen port for the shim
// ctrl block (#1432 S2a). S2a supports a single WG tunnel, so the first
// configured mode=="wireguard" endpoint's listen port wins. 0 means no
// WG tunnel (the shim's per-CPU wg_rx gate stays off). The shim packs
// this into the low 16 bits of UserspaceCtrl.wg_listen_port and steers
// local-destination UDP on this port to the kernel.
func snapshotWgListenPort(snapshot *ConfigSnapshot) uint32 {
	if snapshot == nil {
		return 0
	}
	for _, endpoint := range snapshot.TunnelEndpoints {
		if endpoint.ID == 0 || endpoint.Mode != "wireguard" {
			continue
		}
		if endpoint.WgListenPort != 0 {
			return uint32(endpoint.WgListenPort)
		}
	}
	return 0
}

func buildNATTranslatedLocalAddressExclusions(snapshot *ConfigSnapshot) (map[uint32]bool, map[[16]byte]bool) {
	excludedV4 := make(map[uint32]bool)
	excludedV6 := make(map[[16]byte]bool)
	if snapshot == nil || len(snapshot.SourceNAT) == 0 || len(snapshot.Interfaces) == 0 {
		return excludedV4, excludedV6
	}
	toZones := make(map[string]bool)
	for _, nat := range snapshot.SourceNAT {
		if !nat.InterfaceMode || nat.Off || nat.ToZone == "" {
			continue
		}
		toZones[nat.ToZone] = true
	}
	if len(toZones) == 0 {
		return excludedV4, excludedV6
	}
	for _, iface := range snapshot.Interfaces {
		if iface.Zone == "" || !toZones[iface.Zone] {
			continue
		}
		if ip := pickInterfaceSnapshotV4(iface); ip != nil {
			excludedV4[binary.BigEndian.Uint32(ip.To4())] = true
		}
		if ip := pickInterfaceSnapshotV6(iface); ip != nil {
			var key [16]byte
			copy(key[:], ip.To16())
			excludedV6[key] = true
		}
	}
	return excludedV4, excludedV6
}

func pickInterfaceSnapshotV4(iface InterfaceSnapshot) net.IP {
	var fallback net.IP
	for _, addr := range iface.Addresses {
		if addr.Family != "inet" {
			continue
		}
		ip, _, err := net.ParseCIDR(addr.Address)
		if err != nil || ip == nil {
			continue
		}
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		if fallback == nil {
			fallback = append(net.IP(nil), v4...)
		}
		if !v4.IsLinkLocalUnicast() {
			return append(net.IP(nil), v4...)
		}
	}
	return fallback
}

func pickInterfaceSnapshotV6(iface InterfaceSnapshot) net.IP {
	var fallback net.IP
	for _, addr := range iface.Addresses {
		if addr.Family != "inet6" {
			continue
		}
		ip, _, err := net.ParseCIDR(addr.Address)
		if err != nil || ip == nil {
			continue
		}
		v6 := ip.To16()
		if v6 == nil || ip.To4() != nil {
			continue
		}
		if fallback == nil {
			fallback = append(net.IP(nil), v6...)
		}
		if !v6.IsLinkLocalUnicast() {
			return append(net.IP(nil), v6...)
		}
	}
	return fallback
}

// heartbeatSlotsPerWorker is the number of userspace_heartbeat Array
// slots reserved per dataplane worker (2 directions x up to 16 queues).
// programBootstrapMapsLocked zero-inits workers*heartbeatSlotsPerWorker
// slots on every apply.
const heartbeatSlotsPerWorker = 2 * 16

// heartbeatZeroSlots returns how many leading userspace_heartbeat Array
// slots programBootstrapMapsLocked must zero-init for a configured worker
// count. It clamps the worker count into [1, mapCap/heartbeatSlotsPerWorker]
// so the returned slot count can never wrap uint32 or exceed the fixed-size
// Array, regardless of what cfg.Workers carries.
//
// The low clamp mirrors the QueueCount / disabled-ctrl coercions
// (workers<=0 -> 1). The negative-workers case is already defended by
// deriveUserspaceConfig (capabilities.go), so the load-bearing guard is
// the HIGH clamp: `workers` is a min-only schema leaf (ValidateIntegerMin(1))
// with no upper bound in deriveUserspaceConfig, so a large positive value
// (e.g. 999999999) reaches this function and a raw
// uint32(workers)*heartbeatSlotsPerWorker wraps uint32 to ~1.9B loop
// iterations that hang the apply for hours (#4572). Clamping the worker
// count to mapCap/heartbeatSlotsPerWorker before the multiply keeps the
// returned slot count <= mapCap and never wraps.
// #5718 A6-b01-C1: BOTH clamps run in int space, BEFORE the uint32 cast.
// Casting first (the pre-#5718 shape, `w := uint32(maxInt(workers, 1))`) let a
// worker count above the uint32 range narrow into the clamp's blind spot and
// defeat the very bounds this function exists to enforce: `workers` is an int
// from a min-only schema leaf, so `1<<32` narrows to 0 — under maxW, so the
// high clamp passes it through — and the function returns 0 slots, zeroing
// NOTHING and leaving stale heartbeat entries live for every worker. `1<<32+5`
// narrows to 5 and silently zeroes 5 workers' slots no matter how large maxW
// is. Clamping in int space keeps the low clamp (>=1) and the high clamp
// (<=maxW) both binding for every int input, and the cast then happens on a
// value already proven to be within [1, maxW].
func heartbeatZeroSlots(workers int, mapCap uint32) uint32 {
	slots := uint32(effectiveWorkers(workers, mapCap)) * heartbeatSlotsPerWorker
	if slots > mapCap {
		// Degenerate: an Array too small to hold even one worker's slots
		// (mapCap < heartbeatSlotsPerWorker). effectiveWorkers keeps its floor
		// of 1 because "zero workers" is not a thing to report to the shim;
		// the loop bound still may not leave the Array.
		slots = mapCap
	}
	return slots
}

// userspaceWorkerPlan carries every representation of the bootstrap's worker
// count, produced by one derivation (#5718 fold F3). Returning them together
// is the contract: a caller cannot pair a clamped count with a raw one,
// because there is only one clamp and both fields come out of it.
type userspaceWorkerPlan struct {
	// Workers is the count reported to the shim in userspaceCtrlValue's
	// Workers AND QueueCount fields.
	Workers uint32
	// HeartbeatSlots is how many leading userspace_heartbeat Array slots the
	// zero-init loop must write — Workers * heartbeatSlotsPerWorker, capped at
	// the Array's capacity.
	HeartbeatSlots uint32
}

// planUserspaceWorkers clamps the configured worker count ONCE and derives
// every representation of it from that single value. See userspaceWorkerPlan.
func planUserspaceWorkers(workers int, heartbeatMapCap uint32) userspaceWorkerPlan {
	w := effectiveWorkers(workers, heartbeatMapCap)
	return userspaceWorkerPlan{
		Workers:        uint32(w),
		HeartbeatSlots: heartbeatZeroSlots(w, heartbeatMapCap),
	}
}

// effectiveWorkers is the single source of truth for "how many workers this
// dataplane has" (#5718 fold F3). Every representation of that quantity —
// userspaceCtrlValue.Workers, userspaceCtrlValue.QueueCount, and the heartbeat
// zero-init loop bound — derives from this one value, so they cannot describe
// the same number differently.
//
// The clamp runs entirely in INT space, before any uint32 cast, for the
// A6-b01-C1 reason: cfg.Workers is an int from a min-only schema leaf
// (ValidateIntegerMin(1)) with no upper bound in deriveUserspaceConfig, so a
// cast-first implementation lets a worker count above the uint32 range narrow
// into the clamp's blind spot — `1<<32` becomes 0 and `1<<32+5` becomes 5,
// both of which look like legal counts and sail through every bound. That is
// how the two representations diverged after A6-b01-C1: the zero-init loop got
// the clamped value while ctrl.Workers/ctrl.QueueCount got the narrowed one.
//
// maxW is how many workers the fixed-size userspace_heartbeat Array can carry
// slots for (4096 / 32 = 128 today), which is also the honest ceiling for the
// ctrl fields: a worker with no zero-initialised heartbeat slot has none to
// keep fresh, and the shim refuses to redirect on a stale slot. The floor
// stays 1 even when the Array cannot hold a single worker's slots;
// heartbeatZeroSlots caps the resulting SLOT count at mapCap for that
// degenerate case instead of reporting zero workers.
func effectiveWorkers(workers int, heartbeatMapCap uint32) int {
	w := maxInt(workers, 1)
	if maxW := int(heartbeatMapCap / heartbeatSlotsPerWorker); maxW >= 1 && w > maxW {
		w = maxW
	}
	return w
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func queueCountFromBindings(bindings []BindingStatus) int {
	maxQueueID := -1
	for _, binding := range bindings {
		if !binding.Registered || binding.Ifindex <= 0 {
			continue
		}
		if int(binding.QueueID) > maxQueueID {
			maxQueueID = int(binding.QueueID)
		}
	}
	if maxQueueID < 0 {
		return 1
	}
	return maxQueueID + 1
}
