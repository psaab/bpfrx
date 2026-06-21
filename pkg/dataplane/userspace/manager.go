package userspace

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"net/netip"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var _ dataplane.ConfigSink = (*Manager)(nil)
var _ dataplane.RuntimeDataPlane = (*Manager)(nil)

var ErrPolicySchedulerProtocolIncompatible = errors.New("userspace policy scheduler snapshot protocol incompatible")
var ErrPersistentSourceNATProtocolIncompatible = errors.New("userspace persistent source NAT snapshot protocol incompatible")

// requiredProtocolGateSentinels enumerates every "this config cannot be
// committed against the helper's current ConfigSnapshotProtocolVersion"
// sentinel produced by ensureRequiredSnapshotProtocolLocked. ApplyConfig
// disarms the helper (Armed=false, fail-closed) and returns one of these
// when the running helper is too old to honor the committed config. A
// commit that hits any of them MUST abort — i.e. the daemon must surface a
// failed commit to the operator rather than report success against a
// disarmed dataplane (#2138).
//
// The lenient-load doctrine (#1960) is unaffected, because abort changes
// behavior ONLY for daemon callers that surface the apply error to a human:
//   - Boot/restart of an already-persisted config goes through the void
//     applyConfig wrapper, which logs slog.Warn and swallows the error —
//     the node boots through (warn, not brick).
//   - Peer config-sync goes through syncAndApply, which DOES propagate the
//     error, but its caller (handleConfigSync) logs slog.Error and returns;
//     the store is already promoted by SyncApply, so the node stays
//     consistent with the peer (helper disarmed, not bricked).
// Only the operator-facing commit path (commitAndApply /
// commitConfirmedAndApply) returns the abort to the committer.
//
// Every future ensureRequiredSnapshotProtocolLocked gate MUST add its
// sentinel here so the commit-abort policy can never silently omit it
// (the omission this list exists to prevent was exactly #2138: the
// persistent-source-NAT gate disarmed the helper but was missing from the
// daemon's abort set).
var requiredProtocolGateSentinels = []error{
	ErrPolicySchedulerProtocolIncompatible,
	ErrPersistentSourceNATProtocolIncompatible,
}

// IsRequiredProtocolGateError reports whether err is (or wraps) any
// required helper-protocol gate sentinel — the set that must abort a
// commit. The daemon commit policy (compileErrorMustAbortApply) delegates
// to this so the abort set has a single source of truth co-located with
// the sentinels and the ensureRequiredSnapshotProtocolLocked gate that
// emits them.
func IsRequiredProtocolGateError(err error) bool {
	for _, sentinel := range requiredProtocolGateSentinels {
		if errors.Is(err, sentinel) {
			return true
		}
	}
	return false
}

const persistentSourceNATHAUnsupportedReason = "userspace persistent-nat source pool leases are not HA-synchronized"

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

	mu                    sync.Mutex
	sessionMu             sync.Mutex // separate lock for session sync requests (Phase 3)
	proc                  *exec.Cmd
	cfg                   config.UserspaceConfig
	clusterHA             bool
	generation            uint64
	syncCancel            context.CancelFunc
	lastStatus            ProcessStatus
	lastSnapshot          *ConfigSnapshot
	lastApply             *dataplane.ApplyResult
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
	feedOverlay       map[string][]string
	haGroups          map[int]HAGroupStatus
	lastIngressIfaces []uint32
	lastRSTv4         []netip.Addr
	lastRSTv6         []netip.Addr
	lastRSTAttempt    time.Time
	lastRSTInstallOK  bool
	lastSnapshotHash  [32]byte // content hash of last published snapshot (excludes volatile fields)
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

	lookupUserspaceCtrlForFailClosedHook userspaceCtrlLookupHook

	mode               DataplaneMode // current active runtime mode
	configuredMode     DataplaneMode // user-configured desired mode (from config)
	lastHASyncTime     time.Time     // throttle HA watchdog sync to avoid control socket contention
	lastRGActivateTime time.Time     // wall clock of last update_ha_state; statusLoop skips HA sync for 2s

	rgTransitionInFlight atomic.Bool // set before syncHAStateLocked, cleared on completion

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
		bpfShim:        bpfShim,
		configuredMode: ModeUserspaceCompat,
		haGroups:       make(map[int]HAGroupStatus),
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

func copyPolicySchedulerActiveState(activeState map[string]bool) map[string]bool {
	if activeState == nil {
		return nil
	}
	out := make(map[string]bool, len(activeState))
	for name, active := range activeState {
		out[name] = active
	}
	return out
}

func (m *Manager) policySchedulerActiveStateSnapshot() map[string]bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return copyPolicySchedulerActiveState(m.policySchedulerActive)
}

// SetPolicySchedulerActiveState seeds the active-state map used by the next
// full snapshot build. The daemon calls this while holding applySem so config
// commits and scheduler flips cannot publish hybrid policy snapshots.
func (m *Manager) SetPolicySchedulerActiveState(activeState map[string]bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policySchedulerActive = copyPolicySchedulerActiveState(activeState)
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

func (m *Manager) Compile(cfg *config.Config) (*dataplane.CompileResult, error) {
	// Delete XDP link pins BEFORE CompileUserspaceShim() so AttachXDP does
	// a fresh attach. This is critical for zero-copy: fresh attach
	// triggers mlx5 to initialize XSK buffer pool from fill ring.
	// Pinned link reuse (l.Update) only swaps the program without
	// reinitializing XSK RQs, leaving the fill ring unconsumed.
	if linkPinDir := "/sys/fs/bpf/xpf/links"; true {
		entries, _ := os.ReadDir(linkPinDir)
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "xdp_") {
				path := filepath.Join(linkPinDir, e.Name())
				_ = os.Remove(path)
			}
		}
	}
	caps := deriveUserspaceCapabilities(cfg)
	_ = caps // used below for helper config
	// Userspace mode always attaches the retained XDP shim. The shim
	// redirects to XSK when ctrl=1; when ctrl=0 it only passes proven
	// local/control traffic to the kernel and drops transit. Do not swap to
	// xdp_main_prog for unsupported capabilities or failed XSK liveness: the
	// userspace runtime must not require the legacy main XDP pipeline.
	m.bpfShim.SelectUserspaceXDPShimEntryProgram()
	result, err := m.bpfShim.CompileUserspaceShim(cfg)
	if err != nil {
		return nil, err
	}
	ucfg := deriveUserspaceConfig(cfg)
	activeState := m.policySchedulerActiveStateSnapshot()
	// #1827: include the cached ip-monitoring route overlay so a full
	// apply (operator commit) while a policy is FAILED preserves the
	// injected route instead of reverting traffic to the dead uplink.
	snap := buildSnapshotWithSchedulerStateAndNATCounters(cfg, ucfg, m.bumpGeneration(), m.readFIBGeneration(), activeState, m.routeOverlaySnapshot(), m.feedSnapshotOverlay(), result.NATCounterIDs)
	// #1620: stamp the cold-path sample mask onto the snapshot. The
	// daemon called SetColdPathSampleMask once at startup with the
	// validated CLI flag value (or nil for "use default"). A nil
	// pointer here leaves the wire field absent (omitempty), which
	// the Rust receiver unwrap_or-s to 0xff per plan §4.3.
	m.mu.Lock()
	snap.ColdPathSampleMask = m.coldPathSampleMask
	m.mu.Unlock()
	m.syncInterfaceAttachments(result, snap)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.clusterHA = cfg != nil && cfg.Chassis.Cluster != nil
	m.seedHAGroupInventoryLocked(cfg)
	prevPlanKey := snapshotBindingPlanKey(m.lastSnapshot)
	newPlanKey := snapshotBindingPlanKey(snap)
	pendingXSKStartup := m.proc != nil &&
		m.proc.Process != nil &&
		m.publishedSnapshot != 0 &&
		!m.xskLivenessProven &&
		!m.xskLivenessFailed
	samePlanRefresh := m.proc != nil &&
		m.proc.Process != nil &&
		prevPlanKey != "" &&
		prevPlanKey == newPlanKey
	publishedPlanChangedDuringStartup := pendingXSKStartup &&
		m.publishedPlanKey != "" &&
		m.publishedPlanKey != newPlanKey
	if publishedPlanChangedDuringStartup {
		slog.Info(
			"userspace: restarting helper during XSK startup for binding plan change",
			"generation", snap.Generation,
			"fib_generation", snap.FIBGeneration,
		)
		m.stopLocked()
		pendingXSKStartup = false
		samePlanRefresh = false
	}
	// #1197 v4 (Codex code-review v3 #1+#2): rebuild listener
	// caches ONLY after a successful apply_snapshot. Doing it
	// here (before publish) leaves the listener thinking
	// userspace-dp has entries it doesn't if apply_snapshot fails.
	// Moved to the post-success path below (after line 343).
	if pendingXSKStartup {
		if err := m.ensureRequiredSnapshotProtocolLocked(cfg); err != nil {
			if disarmErr := m.disarmSnapshotProtocolFailureLocked(err); disarmErr != nil {
				return result, errors.Join(err, disarmErr)
			}
			return result, err
		}
		if err := m.syncUserspaceClassifierMapsFailClosedLocked(snap); err != nil {
			return result, err
		}
		// #1928 (Codex review Q1): the deferred-publish resume path
		// (syncSnapshotLocked in process.go) never syncs HA state, so a
		// cluster->standalone reconfig that lands during the XSK-startup
		// deferral window would leave stale HA groups in the helper and
		// re-arm the HAInactive transit-drop gate. seedHAGroupInventoryLocked
		// already cleared m.haGroups for the non-cluster case above; clear the
		// helper side here too so the standalone state is consistent
		// regardless of which apply path runs. (Idempotent empty update.)
		if !m.clusterHA {
			if err := m.clearHelperHAStateLocked(); err != nil {
				return result, fmt.Errorf("clear userspace HA state (deferred startup): %w", err)
			}
		}
		m.lastSnapshot = snap
		m.cfg = ucfg
		m.recordApplyResultLocked(dataplane.ApplyResultFromCompileResult(result), caps, snap.Generation)
		slog.Info(
			"userspace: deferring snapshot publish during XSK startup",
			"generation", snap.Generation,
			"fib_generation", snap.FIBGeneration,
			"same_plan", samePlanRefresh,
		)
		return result, nil
	}
	if samePlanRefresh {
		if err := m.syncUserspaceClassifierMapsFailClosedLocked(snap); err != nil {
			return result, err
		}
	} else {
		if err := m.programBootstrapMapsLocked(snap, ucfg); err != nil {
			return result, err
		}
	}
	if err := m.ensureProcessLocked(ucfg); err != nil {
		return result, err
	}
	if err := m.ensureRequiredSnapshotProtocolLocked(cfg); err != nil {
		if disarmErr := m.disarmSnapshotProtocolFailureLocked(err); disarmErr != nil {
			return result, errors.Join(err, disarmErr)
		}
		return result, err
	}
	if m.deferWorkers {
		snap.DeferWorkers = true
	}
	var status ProcessStatus
	if err := m.disarmBeforeUnsupportedPublishLocked(snap.Config); err != nil {
		return result, err
	}
	// #1197 v5 (Codex code-review v4 #2): apply_snapshot must
	// send publishable-only neighbors to match the
	// update_neighbors path. Otherwise Rust's full-snapshot
	// build accepts state="none" entries Go's predicate rejects,
	// and Go can't track removal of those entries via the index.
	publishSnap := *snap
	publishSnap.Neighbors = filterPublishableNeighbors(snap.Neighbors)
	if err := m.requestLocked(ControlRequest{Type: "apply_snapshot", Snapshot: &publishSnap}, &status); err != nil {
		return result, fmt.Errorf("publish userspace snapshot: %w", err)
	}
	m.logWgEndpointSetTransitionLocked(&publishSnap, "apply")
	m.lastSnapshot = snap
	// #1197 v4: apply_snapshot succeeded — userspace-dp has the
	// new neighbors. NOW rebuild listener caches; before this
	// point the index would shadow events for entries the
	// dataplane hadn't accepted.
	m.rebuildNeighborIndex()
	m.rebuildMonitoredIfindexes()
	m.publishedSnapshot = snap.Generation
	m.publishedPlanKey = newPlanKey
	// #2079: this full apply_snapshot succeeded — record the applied
	// (config, generation) for the NAT pool-utilization-alarm monitor.
	m.markAppliedSnapshotLocked()
	if h, ok := snapshotContentHash(snap); ok {
		m.lastSnapshotHash = h
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		return result, fmt.Errorf("sync helper status: %w", err)
	}
	// #1928: HA group state must only be replayed/published for chassis-cluster
	// members. The rg_active map is a fixed-size ARRAY (16 entries, keys 0-15)
	// so it is ALWAYS fully populated — even on a standalone firewall with no
	// redundancy groups, where every entry is inactive. On standalone the old
	// unconditional refreshHAStateFromMapsLocked() therefore fabricated 16
	// inactive HA groups and shipped them to the helper; the helper's per-packet
	// HA gate (enforce_ha_resolution_snapshot) then treats every transit
	// ForwardCandidate as HAInactive (owner_rg_id<=0 && !ha_state.is_empty())
	// and drops it — a total transit forwarding outage on non-cluster nodes. The
	// periodic status poll already guards the refresh with m.clusterHA (see
	// process.go); the startup path must match.
	if m.clusterHA {
		if err := m.refreshHAStateFromMapsLocked(); err != nil {
			return result, fmt.Errorf("replay userspace HA state from maps: %w", err)
		}
		if err := m.syncHAStateLocked(); err != nil {
			return result, fmt.Errorf("publish userspace HA state: %w", err)
		}
	} else if err := m.clearHelperHAStateLocked(); err != nil {
		// Non-cluster node: ensure neither the manager nor the helper retains
		// HA groups. seedHAGroupInventoryLocked already cleared m.haGroups
		// above; this also clears any groups a prior clustered apply pushed to
		// the helper (cluster->standalone live reconfig), which would otherwise
		// keep the HAInactive transit-drop gate armed (Codex review #1928 Q3).
		return result, fmt.Errorf("clear userspace HA state: %w", err)
	}
	if err := m.syncDesiredForwardingStateLocked(); err != nil {
		return result, fmt.Errorf("sync userspace forwarding state: %w", err)
	}
	m.ensureStatusLoopLocked()
	m.cfg = ucfg
	m.recordApplyResultLocked(dataplane.ApplyResultFromCompileResult(result), caps, snap.Generation)
	return result, nil
}

// UpdatePolicyScheduleState republishes the userspace policy snapshot with one
// coherent inactive-bit view. This shadows the embedded eBPF manager method;
// scheduled userspace policies must not update the policy_rules BPF map.
func (m *Manager) UpdatePolicyScheduleState(cfg *config.Config, activeState map[string]bool) {
	activeCopy := copyPolicySchedulerActiveState(activeState)

	m.mu.Lock()
	defer m.mu.Unlock()

	m.policySchedulerActive = activeCopy
	if cfg == nil {
		if m.lastSnapshot == nil {
			return
		}
		cfg = m.lastSnapshot.Config
	}
	if cfg == nil || m.lastSnapshot == nil {
		return
	}
	if m.proc == nil || m.proc.Process == nil {
		return
	}

	if err := m.ensureRequiredSnapshotProtocolLocked(cfg); err != nil {
		if disarmErr := m.disarmSnapshotProtocolFailureLocked(err); disarmErr != nil {
			slog.Warn("userspace: failed to disarm helper after refusing snapshot publish",
				"protocol_err", err, "err", disarmErr)
		}
		slog.Warn("userspace: refusing snapshot publish to incompatible helper", "err", err)
		return
	}
	next := *m.lastSnapshot
	nextGeneration := m.generation + 1
	next.Generation = nextGeneration
	next.FIBGeneration = m.readFIBGeneration()
	next.GeneratedAt = time.Now().UTC()
	next.Config = cfg
	// #2049: thread the cached dynamic-address feed overlay through the
	// scheduler-only republish so a CoS scheduler-state change does not
	// drop feed enforcement until the next full apply. m.mu is already
	// held here, so read m.feedOverlay directly via cloneFeedOverlay
	// rather than feedSnapshotOverlay() (which re-locks m.mu and would
	// deadlock). Matches how the full snapshot build reads the overlay.
	feedOverlay := cloneFeedOverlay(m.feedOverlay)
	next.Policies = buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, activeCopy, feedOverlay)
	// #1606: refresh the address-book table alongside the policies
	// so book IDs cited in the new policies always resolve on the
	// dataplane side.
	books, _ := buildAddressBookTableWithFeeds(cfg, feedOverlay)
	next.AddressBooks = books

	publishSnap := next
	publishSnap.Neighbors = filterPublishableNeighbors(next.Neighbors)
	var status ProcessStatus
	// #2124: disarm before publishing an unsupported-config snapshot (see
	// disarmBeforeUnsupportedPublishLocked). cfg is this snapshot's config.
	if err := m.disarmBeforeUnsupportedPublishLocked(cfg); err != nil {
		slog.Warn("userspace: failed to disarm before unsupported-config policy scheduler publish", "err", err)
		return
	}
	if err := m.requestLocked(ControlRequest{Type: "apply_snapshot", Snapshot: &publishSnap}, &status); err != nil {
		slog.Warn("userspace: failed to publish policy scheduler state", "err", err)
		return
	}
	m.logWgEndpointSetTransitionLocked(&publishSnap, "policy-scheduler")
	m.generation = nextGeneration
	m.lastSnapshot = &next
	m.rebuildNeighborIndex()
	m.rebuildMonitoredIfindexes()
	m.publishedSnapshot = next.Generation
	m.publishedPlanKey = snapshotBindingPlanKey(&next)
	// #2079: full apply_snapshot succeeded — record the applied snapshot.
	m.markAppliedSnapshotLocked()
	if h, ok := snapshotContentHash(&next); ok {
		m.lastSnapshotHash = h
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		slog.Warn("userspace: failed to sync helper status after policy scheduler publish", "err", err)
	}
}

// routeOverlaySnapshot returns a copy of the cached ip-monitoring
// route overlay.
func (m *Manager) routeOverlaySnapshot() []config.RouteOverlayEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return cloneRouteOverlay(m.routeOverlay)
}

func cloneRouteOverlay(overlay []config.RouteOverlayEntry) []config.RouteOverlayEntry {
	if overlay == nil {
		return nil
	}
	out := make([]config.RouteOverlayEntry, len(overlay))
	copy(out, overlay)
	return out
}

// SetRouteOverlay caches the ip-monitoring effective-route overlay for
// the next full snapshot build WITHOUT publishing. The daemon calls
// this at the top of applyConfigLocked (holding applySem) so an
// operator commit while a policy is FAILED rebuilds routes with the
// active overlay instead of wiping the injected route (#1827, AGY
// r2-2).
func (m *Manager) SetRouteOverlay(overlay []config.RouteOverlayEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routeOverlay = cloneRouteOverlay(overlay)
}

// feedSnapshotOverlay returns a deep copy of the cached dynamic-address
// feed-prefix overlay (#2049). Read under m.mu, mirroring
// routeOverlaySnapshot, so the full snapshot build sees a stable view.
func (m *Manager) feedSnapshotOverlay() map[string][]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return cloneFeedOverlay(m.feedOverlay)
}

func cloneFeedOverlay(overlay map[string][]string) map[string][]string {
	if overlay == nil {
		return nil
	}
	out := make(map[string][]string, len(overlay))
	for name, prefixes := range overlay {
		cp := make([]string, len(prefixes))
		copy(cp, prefixes)
		out[name] = cp
	}
	return out
}

// SetFeedSnapshots caches the dynamic-address feed-prefix overlay for the
// next full snapshot build WITHOUT publishing (#2049). The daemon calls this
// at the top of applyConfigLocked (holding applySem) with the live feed
// snapshots joined to the address-name bindings, so an operator commit OR a
// feed onUpdate rebuilds the address book with the current feed prefixes.
// Mirrors SetRouteOverlay. The overlay is deep-copied so the caller may reuse
// or mutate its map afterwards.
func (m *Manager) SetFeedSnapshots(overlay map[string][]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.feedOverlay = cloneFeedOverlay(overlay)
}

// PublishRouteOverlaySnapshot republishes the userspace snapshot with
// the routes section rebuilt under the given ip-monitoring overlay
// (#1827 PR-1b §4.3, modeled on the policy-scheduler partial republish
// above). It must NOT call Compile (which detaches links / restarts
// the helper): it clones lastSnapshot, refreshes Routes via
// buildRouteSnapshots with the overlay, bumps the generation, and
// reuses the apply_snapshot hash/publish bookkeeping. An overlay whose
// snapshot content is identical to the last published one is skipped
// (duplicate-publish skip) and reported as success.
//
// Ordering contract (AGY r2-1): the caller (the daemon's routes-only
// actuator) must call BumpFIBGeneration ONLY after this returns
// published=true with a nil error — bumping before the helper has the
// new routes would re-resolve flows against the OLD routes and the
// later snapshot would not re-invalidate them; bumping after a
// duplicate-skip would churn established-flow route caches for
// nothing (Codex PR #1843 MED).
//
// schedulerState refreshes the policy snapshots in the same publish
// when non-nil; nil keeps the manager's current scheduler view.
func (m *Manager) PublishRouteOverlaySnapshot(cfg *config.Config, overlay []config.RouteOverlayEntry, schedulerState map[string]bool) (published bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.routeOverlay = cloneRouteOverlay(overlay)
	if schedulerState != nil {
		m.policySchedulerActive = copyPolicySchedulerActiveState(schedulerState)
	}

	if cfg == nil {
		if m.lastSnapshot == nil {
			return false, nil
		}
		cfg = m.lastSnapshot.Config
	}
	if cfg == nil || m.lastSnapshot == nil {
		// No published snapshot yet: the overlay is cached and the
		// next full apply will carry it.
		return false, nil
	}
	if m.proc == nil || m.proc.Process == nil {
		return false, nil
	}

	if err := m.ensureRequiredSnapshotProtocolLocked(cfg); err != nil {
		if disarmErr := m.disarmSnapshotProtocolFailureLocked(err); disarmErr != nil {
			slog.Warn("userspace: failed to disarm helper after refusing overlay publish",
				"protocol_err", err, "err", disarmErr)
		}
		return false, fmt.Errorf("refusing route overlay publish to incompatible helper: %w", err)
	}

	next := *m.lastSnapshot
	nextGeneration := m.generation + 1
	next.Generation = nextGeneration
	next.FIBGeneration = m.readFIBGeneration()
	next.GeneratedAt = time.Now().UTC()
	next.Config = cfg
	next.Routes = buildRouteSnapshots(cfg, next.Interfaces, m.routeOverlay)

	// Duplicate-publish skip: identical content (e.g. the actuator ran
	// twice for the same overlay) does not need a control-socket
	// round-trip. The content hash excludes Generation/FIBGeneration.
	if h, ok := snapshotContentHash(&next); ok && h == m.lastSnapshotHash {
		slog.Debug("userspace: route overlay publish skipped (content unchanged)")
		return false, nil
	}

	publishSnap := next
	publishSnap.Neighbors = filterPublishableNeighbors(next.Neighbors)
	var status ProcessStatus
	// #2124: disarm before publishing an unsupported-config snapshot.
	if err := m.disarmBeforeUnsupportedPublishLocked(next.Config); err != nil {
		return false, err
	}
	if err := m.requestLocked(ControlRequest{Type: "apply_snapshot", Snapshot: &publishSnap}, &status); err != nil {
		return false, fmt.Errorf("publish route overlay snapshot: %w", err)
	}
	m.logWgEndpointSetTransitionLocked(&publishSnap, "route-overlay")
	m.generation = nextGeneration
	m.lastSnapshot = &next
	m.rebuildNeighborIndex()
	m.rebuildMonitoredIfindexes()
	m.publishedSnapshot = next.Generation
	m.publishedPlanKey = snapshotBindingPlanKey(&next)
	// #2079: full apply_snapshot succeeded — record the applied snapshot.
	m.markAppliedSnapshotLocked()
	if h, ok := snapshotContentHash(&next); ok {
		m.lastSnapshotHash = h
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		slog.Warn("userspace: failed to sync helper status after route overlay publish", "err", err)
	}
	slog.Info("userspace: route overlay snapshot published",
		"generation", next.Generation, "overlay_routes", len(m.routeOverlay))
	return true, nil
}

func (m *Manager) syncInterfaceAttachments(result *dataplane.CompileResult, snapshot *ConfigSnapshot) {
	if result == nil {
		return
	}
	allowed := make(map[int]bool)
	for _, ifindex := range buildUserspaceIngressIfindexes(snapshot) {
		allowed[int(ifindex)] = true
	}
	for ifindex := range m.bpfShim.XDPLinks() {
		if allowed[ifindex] {
			continue
		}
		if err := m.bpfShim.DetachXDP(ifindex); err != nil {
			slog.Warn("userspace: detach XDP from non-data interface failed", "ifindex", ifindex, "err", err)
		}
	}
	for ifindex := range m.bpfShim.TCLinks() {
		if allowed[ifindex] {
			continue
		}
		if err := m.bpfShim.DetachTC(ifindex); err != nil {
			slog.Warn("userspace: detach TC from non-data interface failed", "ifindex", ifindex, "err", err)
		}
	}
}

func (m *Manager) readFIBGeneration() uint32 {
	fibGenMap := m.bpfShim.Map("fib_gen_map")
	if fibGenMap == nil {
		return 0
	}
	var (
		key uint32
		gen uint32
	)
	if err := fibGenMap.Lookup(key, &gen); err != nil {
		return 0
	}
	return gen
}

func configHasScheduledPolicy(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		for _, pol := range zpp.Policies {
			if pol != nil && pol.SchedulerName != "" {
				return true
			}
		}
	}
	for _, pol := range cfg.Security.GlobalPolicies {
		if pol != nil && pol.SchedulerName != "" {
			return true
		}
	}
	return false
}

func (m *Manager) ensurePolicySchedulerProtocolLocked(cfg *config.Config) error {
	if !configHasScheduledPolicy(cfg) {
		return nil
	}
	if m.lastStatus.ConfigSnapshotProtocolVersion >= ProtocolVersion {
		return nil
	}
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "status"}, &status); err == nil {
		m.recordHelperStatusLocked(&status)
		if status.ConfigSnapshotProtocolVersion >= ProtocolVersion {
			return nil
		}
	}
	return fmt.Errorf(
		"%w: helper config snapshot protocol version %d < required %d for policy scheduler snapshots",
		ErrPolicySchedulerProtocolIncompatible,
		m.lastStatus.ConfigSnapshotProtocolVersion,
		ProtocolVersion,
	)
}

func (m *Manager) ensurePersistentSourceNATProtocolLocked(cfg *config.Config) error {
	if !userspaceConfigUsesPersistentSourceNAT(cfg) {
		return nil
	}
	if m.lastStatus.ConfigSnapshotProtocolVersion >= ProtocolVersion {
		return nil
	}
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "status"}, &status); err == nil {
		m.recordHelperStatusLocked(&status)
		if status.ConfigSnapshotProtocolVersion >= ProtocolVersion {
			return nil
		}
	}
	return fmt.Errorf(
		"%w: helper config snapshot protocol version %d < required %d for persistent source NAT snapshots",
		ErrPersistentSourceNATProtocolIncompatible,
		m.lastStatus.ConfigSnapshotProtocolVersion,
		ProtocolVersion,
	)
}

func (m *Manager) ensureRequiredSnapshotProtocolLocked(cfg *config.Config) error {
	if err := m.ensurePolicySchedulerProtocolLocked(cfg); err != nil {
		return err
	}
	return m.ensurePersistentSourceNATProtocolLocked(cfg)
}

func (m *Manager) recordHelperStatusLocked(status *ProcessStatus) {
	status.DataplaneMode = m.mode.String()
	status.ConfiguredMode = m.configuredMode.String()
	status.EntryPrograms = m.entryProgramsLocked()
	status.DegradedPathCounters = m.readDegradedPathStatsLocked()
	if m.eventStream != nil {
		es := m.eventStream.Status()
		status.EventStream = &es
	}
	m.lastStatus = *status
}

func (m *Manager) disarmSnapshotProtocolFailureLocked(protocolErr error) error {
	if m.proc == nil || m.proc.Process == nil {
		return nil
	}
	req := ControlRequest{
		Type: "set_forwarding_state",
		Forwarding: &ForwardingControlRequest{
			Armed: false,
		},
	}
	var status ProcessStatus
	if err := m.requestLocked(req, &status); err != nil {
		return fmt.Errorf("userspace: disarm helper after snapshot protocol error: %w", err)
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		m.recordHelperStatusLocked(&status)
		return fmt.Errorf("userspace: sync helper status after snapshot protocol fail-closed disarm: %w", err)
	}
	slog.Warn("userspace: disarmed helper after snapshot protocol error", "err", protocolErr)
	return nil
}

// bpfKtimeNs returns the current CLOCK_BOOTTIME in nanoseconds, matching
// the clock used by BPF's bpf_ktime_get_ns() for session Created timestamps.
func (m *Manager) bpfKtimeNs() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts)
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}

func (m *Manager) bumpGeneration() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.generation++
	return m.generation
}

// BumpFIBGeneration updates the BPF FIB generation counter and sends a
// lightweight FIB generation bump to the userspace helper. If kernel neighbors
// changed since the last publish, an incremental neighbor update is sent first.
// This avoids the full buildSnapshot() + apply_snapshot round-trip that was the
// primary source of control socket contention during route convergence.
//
// Error contract (#1844): a non-nil error means the helper-side
// invalidation is NOT confirmed (shim map bump or the
// bump_fib_generation control message failed) — callers with retry
// semantics (the ip-monitoring actuator's pendingFIBBump) must retry.
// The helperless / no-snapshot early returns are SUCCESS (nil): with
// no published snapshot there are no cached flow routes to invalidate,
// and the next full apply carries its own invalidation. A failed
// incremental NEIGHBOR update is deliberately NOT an error — it has
// its own retry semantics (the cached neighbor view is only advanced
// on success, so the next bump re-diffs and re-sends).
func (m *Manager) BumpFIBGeneration() (uint32, error) {
	newGen, shimErr := m.bpfShim.BumpFIBGeneration()

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
		return newGen, nil
	}
	if m.proc == nil || m.proc.Process == nil {
		return newGen, nil
	}

	// Update the cached snapshot's FIB generation without rebuilding.
	m.lastSnapshot.FIBGeneration = newGen
	m.generation++
	m.lastSnapshot.Generation = m.generation

	// #1197 v4 (Codex code-review v3 #1): refresh the monitored
	// ifindex cache UNCONDITIONALLY — link recreation can happen
	// without any neighbor diff (operator unplugs cable, kernel
	// rebinds a VLAN, etc.), and a stale cache silently drops
	// events on the new ifindex until the next config commit.
	m.rebuildMonitoredIfindexes()

	// Check if kernel neighbors changed — if so, push an incremental update.
	// #1197: use forwarding-effective diff so REACHABLE↔STALE aging churn
	// doesn't trigger unnecessary publishes; filter publish payload to
	// publishable-only entries (matches userspace-dp accept rules).
	newNeighbors := buildNeighborSnapshots(m.lastSnapshot.Config)
	if !neighborsEqualForwarding(m.lastSnapshot.Neighbors, newNeighbors) {
		publishable := filterPublishableNeighbors(newNeighbors)
		var status ProcessStatus
		if err := m.requestLocked(ControlRequest{
			Type:            "update_neighbors",
			Neighbors:       publishable,
			NeighborReplace: true,
		}, &status); err != nil {
			slog.Warn("userspace: failed to publish neighbor update", "err", err)
		} else {
			// Only update cached neighbors after successful publish so
			// a transient failure doesn't suppress future retries.
			m.lastSnapshot.Neighbors = newNeighbors
			m.rebuildNeighborIndex() // #1197
		}
	}

	// Send lightweight FIB generation bump — no full snapshot rebuild.
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{
		Type: "bump_fib_generation",
		Snapshot: &ConfigSnapshot{
			FIBGeneration: newGen,
		},
	}, &status); err != nil {
		slog.Warn("userspace: failed to bump FIB generation", "err", err)
		return newGen, fmt.Errorf("bump fib generation: %w", err)
	}
	return newGen, shimErr
}

// neighborIndexKey is the (ifindex, ip-string) key for the
// O(1) neighbor lookup index used by the daemon's listener hot
// path. ip-string is used (not net.IP) so map equality is well-
// defined for both v4 and v6 representations.
type neighborIndexKey struct {
	ifindex int
	ip      string
}

// filterPublishableNeighbors returns only the entries
// userspace-dp will accept (per neighborSnapshotPublishable).
func filterPublishableNeighbors(neighbors []NeighborSnapshot) []NeighborSnapshot {
	out := make([]NeighborSnapshot, 0, len(neighbors))
	for _, n := range neighbors {
		if neighborSnapshotPublishable(n) {
			out = append(out, n)
		}
	}
	return out
}

// rebuildNeighborIndex updates m.neighborIndex from the current
// m.lastSnapshot.Neighbors slice. Caller MUST hold m.mu. Called
// after every assignment to lastSnapshot.Neighbors.
//
// Codex code-review v2 #1: index ONLY publishable entries.
// Indexing raw entries causes a bug: a raw failed→reachable
// transition on the same MAC would return existing.MAC == new.MAC
// from LookupSnapshotNeighbor → shouldTriggerRegen returns false
// → snapshot stays out of date until 60s safety tick. By indexing
// only publishable entries, an unpublishable→publishable
// transition presents as "no existing entry" → trigger fires.
func (m *Manager) rebuildNeighborIndex() {
	if m.lastSnapshot == nil {
		m.neighborIndex = nil
		return
	}
	idx := make(map[neighborIndexKey]*NeighborSnapshot,
		len(m.lastSnapshot.Neighbors))
	for i := range m.lastSnapshot.Neighbors {
		n := &m.lastSnapshot.Neighbors[i]
		if !neighborSnapshotPublishable(*n) {
			continue
		}
		idx[neighborIndexKey{n.Ifindex, n.IP}] = n
	}
	m.neighborIndex = idx
}

// RegenerateNeighborSnapshot rebuilds the in-memory neighbor
// snapshot from current kernel ARP/NDP state and publishes any
// forwarding-relevant changes to userspace-dp.
//
// #1197: this is the event-driven entry point used by the
// daemon's RTM_NEWNEIGH/DELNEIGH listener (and the 60s safety
// reconciliation tick) to keep the userspace-dp neighbor table
// in sync with the kernel without depending on the buggy
// preinstall mechanism.
//
// Forwarding-effective diff (key, MAC, publishable-bit) decides
// whether to publish; raw NUD state (REACHABLE↔STALE) is ignored
// to avoid republish churn.
func (m *Manager) RegenerateNeighborSnapshot() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
		return
	}
	if m.proc == nil || m.proc.Process == nil {
		return
	}
	// #1197 v4 (Codex code-review v3 #1): refresh monitored
	// ifindex cache unconditionally — a regen call may be
	// triggered by the safety tick precisely because a link
	// changed, and the listener filter must reflect that even
	// if neighbor entries didn't diff.
	m.rebuildMonitoredIfindexes()

	newNeighbors := buildNeighborSnapshots(m.lastSnapshot.Config)
	if neighborsEqualForwarding(m.lastSnapshot.Neighbors, newNeighbors) {
		return
	}
	publishable := filterPublishableNeighbors(newNeighbors)
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{
		Type:            "update_neighbors",
		Neighbors:       publishable,
		NeighborReplace: true,
	}, &status); err != nil {
		slog.Warn("userspace: failed to publish neighbor regeneration", "err", err)
		return
	}
	m.lastSnapshot.Neighbors = newNeighbors
	m.rebuildNeighborIndex() // #1197 (after publish success)
	m.generation++
	m.lastSnapshot.Generation = m.generation
	// Copilot review: advance publishedSnapshot + refresh
	// lastSnapshotHash. Otherwise the status loop sees the
	// bumped generation as unpublished and may force a redundant
	// apply_snapshot, AND any churn in filtered-out rows could
	// leak through hash-dedup.
	m.publishedSnapshot = m.lastSnapshot.Generation
	if h, ok := snapshotContentHash(m.lastSnapshot); ok {
		m.lastSnapshotHash = h
	}
}

// LookupSnapshotNeighbor returns a copy of the snapshot's
// current entry for (ifindex, ip), or nil if not present. The
// returned snapshot is a value copy — safe to read after the
// lock is released, and avoids the (currently no-op) mutation
// hazard of returning an internal pointer.
//
// Codex code-review v2 #4: previous version returned a defensive
// pointer via heap copy. Caller (shouldTriggerRegen) only reads
// the MAC immediately while still under m.mu, so a pointer is
// safe. But the API surface is cleaner as a value (caller can
// hold it across other lock-acquiring calls without aliasing
// concerns), so we keep the value-copy semantics — just skip
// the heap-allocated *NeighborSnapshot wrapping.
//
// Index covers ONLY publishable entries (#1 v2 fix), so a hit
// here means userspace-dp has been told about this entry.
func (m *Manager) LookupSnapshotNeighbor(ifindex int, ip net.IP) *NeighborSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.neighborIndex == nil {
		return nil
	}
	entry, ok := m.neighborIndex[neighborIndexKey{ifindex, ip.String()}]
	if !ok {
		return nil
	}
	out := *entry
	return &out
}

// IsMonitoredIfindex returns true if the given link index
// belongs to a configured interface that buildNeighborSnapshots
// would iterate. O(1) hash-map lookup under m.mu.
//
// Codex code-review v2 #2: previous version returned a copy of
// the whole map, which made the listener hot path O(configured-
// interfaces) plus heap churn per event. This direct lookup
// avoids both.
func (m *Manager) IsMonitoredIfindex(ifindex int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.monitoredIfindexes == nil {
		return false
	}
	_, ok := m.monitoredIfindexes[ifindex]
	return ok
}

// rebuildMonitoredIfindexes updates m.monitoredIfindexes from
// the active config. Caller MUST hold m.mu.
//
// Codex code-review v2 #3: previous version was called only on
// full snapshot assignment. Neighbor-only updates (BumpFIBGeneration,
// RegenerateNeighborSnapshot) didn't refresh the cache, so a
// configured link recreated under a new ifindex could have its
// events dropped. Now called from every neighbor-related update
// path that may reflect a new ifindex.
func (m *Manager) rebuildMonitoredIfindexes() {
	if m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
		m.monitoredIfindexes = nil
		return
	}
	m.monitoredIfindexes = MonitoredInterfaceLinkIndexes(m.lastSnapshot.Config)
}

// ForEachSnapshotNeighbor invokes fn for every PUBLISHABLE
// neighbor entry in the current snapshot (i.e., entries
// userspace-dp accepted into its forwarding table).
//
// #1197 (Copilot review): the existing SnapshotNeighbors() walks
// raw lastSnapshot.Neighbors which can include filtered-out
// entries (FAILED/INCOMPLETE/none). For force-probe target
// collection we want only the entries the dataplane is actually
// using, so we walk neighborIndex (publishable-only).
func (m *Manager) ForEachSnapshotNeighbor(fn func(ifindex int, ip net.IP)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, n := range m.neighborIndex {
		ip := net.ParseIP(n.IP)
		if ip == nil {
			continue
		}
		fn(k.ifindex, ip)
	}
}

// SnapshotHasIfindex returns true if the current snapshot
// contains any neighbor entry on the given ifindex. Used by the
// daemon's listener filter as a fallback for runtime ifindex
// drift. O(N) scan over the neighborIndex but the listener
// already pays O(1) for the LookupSnapshotNeighbor; this fallback
// only fires when the config-derived monitored set doesn't
// contain the ifindex (rare, e.g., link disappeared).
func (m *Manager) SnapshotHasIfindex(ifindex int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k := range m.neighborIndex {
		if k.ifindex == ifindex {
			return true
		}
	}
	return false
}

// SnapshotNeighbors returns the neighbor entries from the last published
// snapshot. Used by the daemon to pre-install kernel ARP entries on RG
// activation so failback doesn't drop packets during ARP resolution.
func (m *Manager) SnapshotNeighbors() []struct {
	Ifindex int
	IP      net.IP
	MAC     net.HardwareAddr
	Family  int
} {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastSnapshot == nil {
		return nil
	}
	var result []struct {
		Ifindex int
		IP      net.IP
		MAC     net.HardwareAddr
		Family  int
	}
	for _, n := range m.lastSnapshot.Neighbors {
		if n.Ifindex <= 0 || n.MAC == "" || n.IP == "" {
			continue
		}
		mac, err := net.ParseMAC(n.MAC)
		if err != nil {
			continue
		}
		ip := net.ParseIP(n.IP)
		if ip == nil {
			continue
		}
		family := netlink.FAMILY_V4
		if ip.To4() == nil {
			family = netlink.FAMILY_V6
		}
		result = append(result, struct {
			Ifindex int
			IP      net.IP
			MAC     net.HardwareAddr
			Family  int
		}{
			Ifindex: n.Ifindex,
			IP:      ip,
			MAC:     mac,
			Family:  family,
		})
	}
	return result
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

func (m *Manager) SetForwardingArmed(armed bool) (ProcessStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.proc == nil {
		return ProcessStatus{}, errors.New("userspace dataplane helper not running")
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
