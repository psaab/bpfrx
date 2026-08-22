package userspace

import (
	"context"
	"os/exec"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"net/netip"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
)

var _ dataplane.ConfigSink = (*Manager)(nil)
var _ dataplane.RuntimeDataPlane = (*Manager)(nil)

// DataplaneMode describes which packet-processing pipeline is active.
type DataplaneMode int

const (
	ModeEBPFOnly        DataplaneMode = iota // Fallback-only, no userspace forwarding
	ModeUserspaceCompat                      // Userspace preferred, degraded transit fails closed
	ModeUserspaceStrict                      // Strict userspace only, no transit fallback
)

const userspaceXDPEntryProg = "xdp_userspace_prog"

func (m DataplaneMode) String() string {
	switch m {
	case ModeEBPFOnly:
		return "ebpf_only"
	case ModeUserspaceCompat:
		return "userspace_compat"
	case ModeUserspaceStrict:
		return "userspace_strict"
	default:
		return "unknown"
	}
}

func init() {
	// RegisterRuntimeBackend retains the userspace runtime as a
	// compatibility / test seam for callers that go through the legacy
	// dataplane.NewRuntimeDataPlane(...) factory (and for the existing
	// canaries that exercise the registry round-trip). Daemon startup
	// prefers userspace.Boot() directly via the pkg/daemon helper, so
	// this registry entry is no longer the canonical boot path.
	// Removing it is out of scope for #1520; #1474 already permits its
	// presence as the test / compatibility seam.
	dataplane.RegisterRuntimeBackend(dataplane.TypeUserspace, func() dataplane.RuntimeDataPlane {
		return Boot()
	})
}

// Boot constructs the userspace AF_XDP runtime and returns it as a
// dataplane.RuntimeDataPlane wrapped in the legacy-compatible adapter.
//
// Daemon startup prefers Boot() over dataplane.NewRuntimeDataPlane(
// TypeUserspace) for the default and explicit userspace selections.
// The runtime backend registry entry for TypeUserspace (see init()
// above) is retained as a compatibility / test seam — it remains
// reachable via dataplane.NewRuntimeDataPlane(TypeUserspace) but is
// no longer the canonical daemon boot path.
//
// The explicit "dataplane-type ebpf" rollback does NOT use the
// userspace registry entry at all; it goes through the
// dataplane.NewRuntimeDataPlane → TypeEBPF switch which constructs
// a bare *dataplane.Manager (legacy) via the legacy program loader.
//
// The returned value still implements dataplane.DataPlane via the
// adapter, so daemon.legacyDP() can keep handing a compatibility handle
// to the remaining CLI, gRPC, and cluster session-sync call sites until
// #1451 finishes the surface shrink. When #1521 / #1473 need to thread
// additional construction configuration in, they should add a typed
// options argument here. No empty options struct is added pre-emptively
// (YAGNI).
func Boot() dataplane.RuntimeDataPlane {
	return NewLegacyDataPlaneAdapter(New())
}

type Manager struct {
	bpfShim *dataplane.Manager

	mu        sync.Mutex
	sessionMu sync.Mutex // separate lock for session sync requests (Phase 3)
	proc      *exec.Cmd
	// procSup is the supervisor record for the CURRENTLY spawned helper
	// generation: the single goroutine that owns cmd.Wait() for it, plus the
	// channel that goroutine closes when the child is reaped (#5838).
	//
	// INVARIANT: procSup is non-nil exactly while proc is non-nil, and each
	// spawn allocates a strictly greater procGen. Every asynchronous callback
	// that can outlive a generation (the waiter itself, and the restart timer)
	// re-checks its captured generation against procGen under m.mu before
	// mutating anything, so a stale notification from generation N can never
	// clear or restart generation N+1.
	procSup *helperGeneration
	// procGen counts helper PROCESS generations. Distinct from `generation`,
	// which counts CONFIG snapshots: one config can outlive many helper
	// processes across a crash-restart, and one helper can serve many configs.
	procGen uint64
	// helperCrash records the last UNEXPECTED helper exit for the operator and
	// drives the restart backoff. Zero value means "no crash on record".
	helperCrash helperCrashState
	// restartTimerFn overrides how a crash restart is armed. Production leaves
	// it nil (time.AfterFunc); a test injects a synchronous or recording timer.
	// Per-Manager, not a package var — see scheduleRestartTimer.
	restartTimerFn func(time.Duration, func())
	cfg            config.UserspaceConfig
	clusterHA      bool
	generation     uint64
	// neighborReplaceGen is a dedicated monotonic counter for the #6034
	// manager-neighbor replace-generation envelope. Every authoritative
	// update_neighbors replace (RegenerateNeighborSnapshot, BumpFIBGeneration)
	// allocates the next value and stamps it on the ControlRequest so the
	// helper can fence a stale/reordered replace and ACK the applied
	// generation. Distinct from `generation` (the config-snapshot counter):
	// this only advances on a neighbor push and is never reused, so a retry
	// always carries a strictly higher generation. Guarded by m.mu (both
	// senders hold it across the send).
	neighborReplaceGen uint64
	syncCancel         context.CancelFunc
	lastStatus         ProcessStatus
	// helperStatusObserved records that a helper status has been decoded at
	// least once in this Manager's life — i.e. that lastStatus describes a
	// helper we actually heard from rather than a zero value (#6691 round 10).
	//
	// It exists because a required-protocol gate must arm on an OBSERVED
	// too-old version and never on the ABSENCE of one, and
	// lastStatus.ConfigSnapshotProtocolVersion == 0 cannot tell those apart: it
	// is equally "no helper has ever answered" and "a helper answered without
	// the field". Both are < ProtocolVersion, and only the second is an
	// incompatibility. Guarded by m.mu, like lastStatus itself.
	helperStatusObserved bool
	lastSnapshot         *ConfigSnapshot
	lastApply            *dataplane.ApplyResult
	// lastSnapshotRejectReasons holds the #3261 diagnostic: the reasons the
	// most recently built snapshot carries unrepresentable policy content that
	// the helper integrity preflight rejects (previous-good retained, or
	// fresh-boot default-deny — never fail-open). Set under m.mu at every full
	// snapshot build, surfaced via ProcessStatus.LastSnapshotRejectReasons and
	// the xpf_userspace_policy_content_rejected gauge so the Go/Rust skew
	// (ForwardingSupported=true while the helper rejected the snapshot) is
	// observable. nil/empty means the last build was fully representable.
	lastSnapshotRejectReasons []string
	// lastZoneIDCollisions holds the #3719 diagnostic: the zones the most
	// recent snapshot build QUARANTINED because their StableZoneID collided
	// with an earlier-sorting zone. Set under m.mu at every full snapshot
	// build, surfaced via ProcessStatus.ZoneIDCollisions and the
	// xpf_userspace_zone_id_collision gauge. nil/empty means no active
	// collision.
	lastZoneIDCollisions  []string
	policySchedulerActive map[string]bool
	// routeOverlay is the ip-monitoring effective-route overlay
	// (#1827 PR-1b). Cached so the FULL apply path
	// (buildSnapshotWithSchedulerState in ApplyConfig) preserves the
	// overlay across operator commits while a policy is FAILED.
	// Updated by SetRouteOverlay / PublishRouteOverlaySnapshot.
	routeOverlay []config.RouteOverlayEntry
	// feedOverlay is the dynamic-address feed-prefix overlay (#2049):
	// address-name -> union of live feed-backed CIDR strings. Cached so
	// the FULL apply path (buildSnapshotWithSchedulerState in ApplyConfig)
	// merges the current feed prefixes into the address book the helper
	// enforces. Set by SetFeedSnapshots (daemon, from feeds.Manager) under
	// m.mu, mirroring routeOverlay. A feed onUpdate re-runs applyConfig
	// against the SAME *config.Config; the overlay is what makes the
	// rebuilt snapshot's AddressBooks (and thus the content hash) shift on
	// a feed change so the duplicate-publish gate lets the refresh through.
	feedOverlay map[string][]string
	haGroups    map[int]HAGroupStatus
	// haWatchdogMapWrite writes the kernel-visible watchdog timestamp into the
	// BPF shim's ha_watchdog map. It runs on EVERY heartbeat tick (the BPF ~2s
	// stale window relies on this fast map write, so it is never throttled).
	// Indirected through a field so tests can drive the IPC-throttle path in
	// UpdateHAWatchdog without a loaded BPF map. Defaults to
	// bpfShim.UpdateHAWatchdog (set in New()); nil-safe at the call site.
	haWatchdogMapWrite func(rgID int, timestamp uint64) error
	// haWatchdogIPCSynced tracks, per RG, the watchdog timestamp and Active
	// state last published to the helper via the update_ha_state socket IPC.
	// It throttles that IPC (see UpdateHAWatchdog): the shim map write above
	// happens every tick, but the JSON socket round-trip fires only on an
	// Active-state change (failover/failback — instant) or a periodic backstop
	// comfortably under the helper's ~10s stale-lease window. Guarded by m.mu.
	haWatchdogIPCSynced map[int]haWatchdogIPCSyncState
	// fabricSnapshotBuilder resolves the fabric snapshots (with live peer/local
	// MACs from kernel neighbor + link state) that SyncFabricState pushes to the
	// helper. Indirected through a field so tests can inject a deterministic
	// resolved MAC without real netlink neighbor state, mirroring
	// haWatchdogMapWrite. nil-safe at the call site: it defaults to
	// buildFabricSnapshots when unset (so bare &Manager{} literals still work).
	fabricSnapshotBuilder func(*config.Config) []FabricSnapshot
	lastIngressIfaces     []uint32
	lastRSTv4             []netip.Addr
	lastRSTv6             []netip.Addr
	lastRSTAttempt        time.Time
	lastRSTInstallOK      bool
	lastSnapshotHash      [32]byte // content hash of last published snapshot (excludes volatile fields)
	// #1866 D3: canonical summary of the WG endpoint set in the last
	// successfully published snapshot, for publish-boundary transition
	// logging (logWgEndpointSetTransitionLocked).
	lastPublishedWgEndpoints string
	// #1197: O(1) neighbor lookup index for the listener hot path.
	// Keyed by (ifindex, ip-string). Rebuilt whenever lastSnapshot.Neighbors
	// is replaced. Read under m.mu (existing snapshot lock).
	neighborIndex map[neighborIndexKey]*NeighborSnapshot
	// #1197: ifindex set for listener filter; rebuilt on config commit.
	monitoredIfindexes      map[int]struct{}
	lastBindingIndices      []uint32
	neighborsPrewarmed      bool
	ctrlEnableAt            time.Time
	ctrlWasEnabled          bool
	initialCtrlCleanupDone  bool
	ctrlDisabledAt          uint64    // monotonic ktime_ns when ctrl was last disabled
	lastDemotionTime        time.Time // wall clock when last RG demotion occurred
	xskLivenessFailed       bool
	xskLivenessProven       bool
	xskProbeStart           time.Time
	lastXSKRX               uint64
	lastNAPIBootstrap       time.Time
	lastStandbyNeighResolve time.Time
	bindingsBusySince       time.Time
	lastBindingsAutoRebind  time.Time
	publishedSnapshot       uint64
	publishedPlanKey        string
	// appliedSnapshot is the config + generation the helper has
	// ACTUALLY applied via a successful full apply_snapshot — the
	// generation the helper echoes back as
	// status.LastSnapshotGeneration (userspace-dp snapshot.rs sets
	// last_snapshot_generation only on a full apply). It is captured
	// ONLY at the apply_snapshot publish/catch-up sites via
	// markAppliedSnapshotLocked, NOT on FIB-bump / neighbor-regen /
	// content-dedup-skip paths (which advance publishedSnapshot or
	// lastSnapshot.Generation without the helper accepting a new
	// snapshot generation). It is the generation-coherent source for
	// the #2079 NAT pool-utilization-alarm monitor: AppliedNATView
	// pairs this Config with the same-generation pool counters.
	appliedSnapshot     appliedSnapshot
	sessionMirrorFailed bool
	sessionMirrorErr    string
	deferWorkers        bool // skip worker spawn until NotifyLinkCycle
	xskBoundNotified    bool // OnXSKBound fired at most once
	// pendingWorkerArm records "generation debt" from a deferred-MAC
	// re-apply that failed to publish (#5134). After a live RETH
	// virtual-MAC change with no link cycle, the first apply publishes a
	// workerless DeferWorkers=true snapshot and the daemon issues a
	// MANDATORY re-apply to arm the workers with the now-correct MAC. If
	// that re-apply's apply_snapshot fails, the manager keeps the
	// workerless snapshot as lastSnapshot/publishedSnapshot and the commit
	// still reports success — a silent forwarding outage. The daemon records
	// the debt here instead of swallowing the error; the status reconcile
	// loop (retryDeferredWorkerArmLocked) then retries the DeferWorkers=false
	// publish every tick until the workers bind, self-healing a transient
	// helper / control-socket error.
	pendingWorkerArm bool

	// pendingHAStateClear records "clear debt" from a standalone (non-cluster)
	// HA-state clear whose idempotent empty update_ha_state RPC failed (#5487).
	// A cluster->standalone reconfig clears the helper's HA groups; if that RPC
	// hits a transient control-socket error the apply returns an error but the
	// helper keeps the stale groups while the manager is clusterHA=false. The
	// status poll's HA sync is gated behind m.clusterHA, so the clear is never
	// retried and owner_rg_id<=0 forwarding candidates stay HAInactive (transit
	// drop). The poll tick retries clearHelperHAStateLocked while this is set,
	// OUTSIDE the clusterHA guard, until the helper reports no groups.
	pendingHAStateClear bool

	// clearHelperHAStateHook, when non-nil, replaces the update_ha_state RPC in
	// clearHelperHAStateLocked so tests can inject a transient clear failure
	// without a control socket (#5487). Production leaves it nil.
	clearHelperHAStateHook func() error

	lookupUserspaceCtrlForFailClosedHook userspaceCtrlLookupHook

	// disableCtrlMapHook, when non-nil, replaces the bpfShim userspace_ctrl
	// map in disableUserspaceCtrlLocked so tests can inject Lookup/Update/
	// readback faults without a privileged BPF map (#5486). Production leaves
	// it nil.
	disableCtrlMapHook ctrlMapUpdater
	// controlRequestHook replaces requestLocked in unit tests that exercise
	// manager state transitions without opening a Unix control socket.
	controlRequestHook func(ControlRequest, *ProcessStatus) error

	// addrListForLocalSyncHook, when non-nil, replaces netlink.AddrList in
	// buildDesiredLocalAddressSets so tests can inject a transient
	// enumeration failure (#3924). Production leaves it nil.
	addrListForLocalSyncHook addrListHook

	mode               DataplaneMode // current active runtime mode
	configuredMode     DataplaneMode // user-configured desired mode (from config)
	lastHASyncTime     time.Time     // throttle HA watchdog sync to avoid control socket contention
	lastRGActivateTime time.Time     // wall clock of last update_ha_state; statusLoop skips HA sync for 2s

	rgTransitionInFlight atomic.Bool // set before syncHAStateLocked, cleared on completion

	// linkCycleLeaseUntil is the #6871 link-cycle lease: the deadline until
	// which an in-flight RETH MAC link DOWN/UP owns the dataplane, or 0 when no
	// cycle is in flight. The unit is MONOTONIC nanoseconds since
	// linkCycleLeaseEpoch, not UnixNano — a wall-clock deadline would let an NTP
	// step expire a live lease or strand a dead one (#6871 round 6). See the lease
	// block in process_linkcycle.go for what it suppresses, why a deadline
	// rather than a bare flag, and why the daemon renews it per RETH member.
	//
	// atomic, and for exactly the reason rgTransitionInFlight above is: the
	// guard has to survive m.mu being RELEASED. PrepareLinkCycle joins the
	// workers and returns, dropping m.mu while the daemon takes the NIC down —
	// and every other holder of m.mu is free to run in that window, including
	// the 1 Hz status tick, which has four independent ways to undo the join
	// before the link comes back up.
	linkCycleLeaseUntil atomic.Int64

	// linkCycleHB owns the #6871 round-8 lease heartbeat: the goroutine that
	// renews a live lease on a FIXED period, so the interval the TTL has to
	// cover is a constant instead of a function of operator-controlled
	// cardinality. See linkCycleLeaseHeartbeat in process_linkcycle.go.
	//
	// Its own mutex, not m.mu: acquire/release run under m.mu in production but
	// not in tests, and the heartbeat goroutine must never need m.mu (it calls
	// RenewLinkCycle, which is pure atomics) or stopping it from under m.mu
	// would deadlock.
	linkCycleHB linkCycleHeartbeat

	// neighborPrewarmInFlight is the #5104 singleflight guard for the async
	// neighbor-resolve prewarm scan spawned by the status loop. The loop kicks
	// a full scan every 1s for the first 60s (then every 10s on HA standby); a
	// scan does route-indexed NeighList dumps and a bounded probe sweep. Under
	// slow netlink or a large RIB a scan can outlast its tick, so this flag
	// coalesces overlapping ticks onto the running scan: CAS false->true before
	// spawning, cleared (via defer) when the scan goroutine returns. Lock-free
	// (like rgTransitionInFlight) because the clear happens off m.mu in the
	// background scan goroutine.
	neighborPrewarmInFlight atomic.Bool
	// neighborPrewarmScan runs one prewarm scan. Indirected through a field so
	// tests can inject a deterministic/blocking scan to exercise the #5104
	// singleflight coalescing without real netlink. nil-safe at the call site:
	// it defaults to proactiveNeighborResolveAsync when unset, so bare
	// &Manager{} literals still work.
	neighborPrewarmScan func(ctx context.Context, cfg *config.Config)

	// Counter delta tracking: previous binding counter totals for computing
	// deltas to write into BPF counter maps (#332).
	prevBindingCounters userspaceCounterSnapshot

	eventStream       *EventStream
	eventStreamCancel context.CancelFunc

	// OnXSKBound is called once when all XSK bindings are bound.
	// Used by the daemon to defer IPVLAN creation until after XSK
	// binds in zerocopy mode on fabric parents.
	OnXSKBound func()

	// #1620: cold-path latency histogram sample mask. Set by the
	// daemon via SetColdPathSampleMask once at startup. Stamped onto
	// every ConfigSnapshot built by buildSnapshotWithSchedulerState.
	// nil pointer ⇒ omit the field from the wire (userspace-dp
	// defaults to 0xff per #1620 plan §4.3).
	coldPathSampleMask *uint64
}

// #1620: set the cold-path sample mask. Called by the daemon at
// startup with the validated CLI flag value (powers-of-two-minus-one
// or 0 with --enable-cold-path-1-in-1-sampling). nil means "no
// operator setting; let userspace-dp use its default 0xff."
func (m *Manager) SetColdPathSampleMask(mask *uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.coldPathSampleMask = mask
}

const rstSuppressionRetryBackoff = 5 * time.Second

func shouldAttemptRSTSuppression(
	now time.Time,
	desiredV4 []netip.Addr,
	desiredV6 []netip.Addr,
	appliedV4 []netip.Addr,
	appliedV6 []netip.Addr,
	lastAttempt time.Time,
	lastInstallOK bool,
) bool {
	if lastAttempt.IsZero() {
		return true
	}
	if !slices.Equal(desiredV4, appliedV4) || !slices.Equal(desiredV6, appliedV6) {
		return true
	}
	if lastInstallOK {
		return false
	}
	return now.Sub(lastAttempt) >= rstSuppressionRetryBackoff
}

func New() *Manager {
	bpfShim := dataplane.New()
	bpfShim.SelectUserspaceXDPShimEntryProgram()
	return &Manager{
		bpfShim:             bpfShim,
		configuredMode:      ModeUserspaceCompat,
		haGroups:            make(map[int]HAGroupStatus),
		haWatchdogMapWrite:  bpfShim.UpdateHAWatchdog,
		haWatchdogIPCSynced: make(map[int]haWatchdogIPCSyncState),
	}
}

func (m *Manager) ApplyConfig(ctx context.Context, cfg *config.Config) (*dataplane.ApplyResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	if _, err := m.Compile(cfg); err != nil {
		return nil, err
	}
	return m.LastApplyResult(), nil
}

func (m *Manager) LastApplyResult() *dataplane.ApplyResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastApply.Clone()
}

func (m *Manager) RuntimeSessionDeltaSource() dpruntime.SessionDeltaSource {
	return runtimeSessionDeltaSource{manager: m}
}

func (m *Manager) Start(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	// #7409: arm the kernel-learned route import for every subsequent
	// snapshot build. This is the ONE production bring-up path for the
	// userspace dataplane (LegacyDataPlaneAdapter.Start delegates here), and
	// the import defaults to DISABLED precisely so that reaching this line is
	// the only way it can switch on — see EnableLearnedRouteImport in
	// routes.go for why a build-host-dependent default would be worse than
	// no feature at all.
	EnableLearnedRouteImport()
	return m.Load()
}

func (m *Manager) Link() dataplane.LinkController {
	return userspaceLinkController{manager: m}
}

func (m *Manager) HA() dataplane.HAController {
	return userspaceHAController{manager: managerHAOps{manager: m}}
}

func (m *Manager) Sessions() dataplane.SessionStore {
	return userspaceSessionStore{
		SessionStore: dataplane.NewDataPlaneSessionStore(NewLegacyDataPlaneAdapter(m)),
		source:       m.RuntimeSessionDeltaSource(),
	}
}

func (m *Manager) SessionDeltas() dpruntime.SessionDeltaSource {
	return m.RuntimeSessionDeltaSource()
}

func (m *Manager) Telemetry() dataplane.Telemetry {
	return dataplane.NewDataPlaneTelemetry(NewLegacyDataPlaneAdapter(m))
}

func (m *Manager) recordApplyResultLocked(result *dataplane.ApplyResult, caps UserspaceCapabilities, generation uint64) {
	if result == nil {
		return
	}
	result.Capabilities = dataplane.Capabilities{
		ForwardingSupported: caps.ForwardingSupported,
		UnsupportedReasons:  append([]string(nil), caps.UnsupportedReasons...),
	}
	result.Generation = generation
	m.lastApply = result.Clone()
}

// EventStream returns the event stream instance, or nil if not available.
func (m *Manager) EventStream() *EventStream {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.eventStream
}

// XSKBoundNotified reports whether the OnXSKBound callback has already fired.
// The daemon uses this to distinguish first applyConfig (defer IPVLAN) from
// subsequent calls (reconcile normally).
func (m *Manager) XSKBoundNotified() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.xskBoundNotified
}

func (m *Manager) SetOnXSKBound(fn func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.OnXSKBound = fn
}

// Mode returns the current active dataplane runtime mode.
func (m *Manager) Mode() DataplaneMode {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mode
}

// SetConfiguredMode sets the user-configured desired dataplane mode.
// The active mode is computed in applyHelperStatusLocked based on runtime
// state and may differ from the configured mode.
func (m *Manager) SetConfiguredMode(mode DataplaneMode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.configuredMode = mode
}

func (m *Manager) SessionSyncSweepProfile() (bool, time.Duration, time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil {
		return false, 0, 0
	}
	if !m.lastStatus.Enabled || !m.lastStatus.ForwardingArmed || !m.lastStatus.Capabilities.ForwardingSupported {
		return false, 0, 0
	}
	// Userspace forwarding already streams authoritative open/close deltas.
	// Keep a periodic refresh for long-lived flows, but avoid the 1s batch walk
	// that was tuned for the eBPF session tables.
	return true, 15 * time.Second, 60 * time.Second
}

func (m *Manager) Load() error {
	return m.bpfShim.LoadUserspaceShim()
}

func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
	return m.bpfShim.Close()
}

func (m *Manager) Teardown() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
	return m.bpfShim.Teardown()
}

// SetDeferWorkers tells the manager to skip worker startup during the next
// Compile(). Workers will be started on the first NotifyLinkCycle() instead.
// Use this when RETH MAC programming will follow Compile() — avoids the
// double-bind that causes EBUSY on mlx5 zero-copy queues.
func (m *Manager) SetDeferWorkers(v bool) {
	m.mu.Lock()
	m.deferWorkers = v
	m.mu.Unlock()
}
