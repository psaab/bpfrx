package userspace

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

var ErrPolicySchedulerProtocolIncompatible = errors.New("userspace policy scheduler snapshot protocol incompatible")

var ErrPersistentSourceNATProtocolIncompatible = errors.New("userspace persistent source NAT snapshot protocol incompatible")

// ErrScopedGlobalZoneSetProtocolIncompatible is the #5488 required-protocol
// gate sentinel: the committed config carries a policy whose scoped-global zone
// context holds MORE THAN ONE zone on a side, and the running helper's accepted
// ConfigSnapshotProtocolVersion predates the v4 contract in which the plural
// match_from_zones/match_to_zones snapshot fields are AUTHORITATIVE.
//
// Such a helper reads only the singular match_from_zone/match_to_zone, which
// carry the FIRST element (config.ScopeSingular), so it NARROWS the rule to one
// zone. For a `deny`/`reject` global that is a fail-OPEN — the zones dropped
// from the scope stop being denied and fall through to lower-precedence rules.
// For a `permit` it is a fail-closed correctness break. The gate is keyed on
// the multi-zone SHAPE rather than the action so it covers both directions.
var ErrScopedGlobalZoneSetProtocolIncompatible = errors.New("userspace scoped-global zone-set snapshot protocol incompatible")

// ErrSecureTunnelProtocolIncompatible is the #5619/#6691 v5 gate. The snapshot
// carries InterfaceSnapshot.SecureTunnel, and the helper's binding admission
// (include_userspace_binding_interface) is AUTHORITATIVE on it: a route-based
// IPsec xfrmi must not become an AF_XDP binding candidate.
//
// #6691 round 8: the flag is set by CONFIG ownership or by the KERNEL link
// kind, so this gate fires for a stale live xfrmi too — the case the operator
// cannot fix by editing the config. Round 9: the gate reads the flag off the
// SNAPSHOT (snapshotHasSecureTunnel) instead of re-deriving it, so it cannot
// disagree with what was built.
//
// A helper that predates the field ignores it and plans the candidate. That is
// not a lost optimisation — the helper's queue count is the GLOBAL MINIMUM
// across candidates (replan_bindings_from_candidates) and an xfrm interface has
// exactly ONE RX queue (numrxqueues 1; a single `rx-0` under
// /sys/class/net/<if>/queues, which is what userspaceRXQueueCount reads and
// ships). So an ignored flag re-plans EVERY physical interface on the box onto
// one queue and one worker: the #3091 single-worker regression, on a config
// this control plane has already decided is safe. Neither the version-equality
// check (same advertised version on both sides before the v5 bump) nor the
// snapshot content hash can see it, because nothing about the bytes is wrong —
// only the reader is.
var ErrSecureTunnelProtocolIncompatible = errors.New("userspace secure-tunnel snapshot protocol incompatible")

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
//     error; its caller (handleConfigSync) logs slog.Error and returns the
//     error to configApplyLoop, which counts ConfigsApplyFailed and leaves the
//     config high-water mark UNADVANCED so the primary's re-push re-converges
//     the standby (M-2/#4151). When SyncApply already promoted the store, the
//     re-push short-circuits on the "already matches active" check and heals
//     the high-water; the node stays consistent with the peer (helper
//     disarmed, not bricked).
//
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
	ErrScopedGlobalZoneSetProtocolIncompatible,
	ErrSecureTunnelProtocolIncompatible,
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

// recordPolicyContentRejectionLocked tracks the #3261 diagnostic for the
// just-built snapshot: the reasons (if any) it carries unrepresentable policy
// content that the helper integrity preflight will reject. It is called at the
// snapshot-build site BEFORE the publish so it is recorded even when the
// publish is rejected (the helper keeps previous-good / default-deny while
// staying armed — never fail-open). A one-shot slog line fires only on a
// transition (per the logging rules — NOT per apply): a Warn when content
// becomes unrepresentable (the operator must see the snapshot is being
// rejected) and an Info when it becomes representable again.
func (m *Manager) recordPolicyContentRejectionLocked(reasons []string) {
	had := len(m.lastSnapshotRejectReasons) > 0
	now := len(reasons) > 0
	m.lastSnapshotRejectReasons = append([]string(nil), reasons...)
	switch {
	case now && !had:
		slog.Warn(
			"userspace: snapshot carries unrepresentable policy content; the helper integrity preflight rejects it and retains the previous-good state (fresh boot: default-deny). Helper stays armed — no kernel fail-open. Edit out the offending application/address and re-commit to restore enforcement.",
			"reasons", reasons,
		)
	case had && !now:
		slog.Info("userspace: policy content is representable again; snapshot will publish normally")
	}
}

// recordZoneIDCollisionsLocked stores the #3719 zone-id-collision diagnostic
// from the last snapshot build and fires a one-shot operator alarm on a
// transition (per the logging rules — NOT per apply). A collision reaches this
// only on the LENIENT path (a tolerant load, an HA sync from an un-upgraded
// peer, or a config a pre-#3075 binary persisted); the strict commit path
// rejects it. The builder already QUARANTINED the later-sorting colliding zone
// (dropped from the wire, its interfaces unzoned, its policies removed), so the
// dataplane is fail-closed and never merges two zones — but zone isolation is
// DEGRADED (the quarantined zone forwards nothing) until an operator renames
// one zone, so this is a loud Error naming both zones.
func (m *Manager) recordZoneIDCollisionsLocked(collisions []ZoneIDCollision) {
	had := len(m.lastZoneIDCollisions) > 0
	msgs := make([]string, 0, len(collisions))
	for _, c := range collisions {
		msgs = append(msgs, c.String())
	}
	now := len(msgs) > 0
	m.lastZoneIDCollisions = msgs
	switch {
	case now && !had:
		slog.Error(
			"userspace: security-zone id collision — two zone names fold to the same StableZoneID; the later-sorting zone is QUARANTINED (dropped from the dataplane, its interfaces unzoned and its traffic denied) so two zones never share an id. Zone isolation is DEGRADED until one zone is renamed and the config re-committed.",
			"collisions", msgs,
		)
	case had && !now:
		slog.Info("userspace: security-zone id collision cleared; all zones install with distinct ids")
	}
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

// PolicySchedulerActiveState returns a copy of the daemon-maintained
// per-scheduler active-state map (scheduler name -> currently active).
// Read-only show surfaces (#3062 CLI/gRPC policy detail) consult it via
// PolicyInactive to render runtime scheduler-driven policy state without
// recomputing wall-clock schedule windows. A nil result means no
// scheduler state has been published yet.
func (m *Manager) PolicySchedulerActiveState() map[string]bool {
	return m.policySchedulerActiveStateSnapshot()
}

// SetPolicySchedulerActiveState seeds the active-state map used by the next
// full snapshot build. The daemon calls this while holding applySem so config
// commits and scheduler flips cannot publish hybrid policy snapshots.
func (m *Manager) SetPolicySchedulerActiveState(activeState map[string]bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policySchedulerActive = copyPolicySchedulerActiveState(activeState)
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
	// #2514: a config-shaped input (e.g. address-book content-ID
	// collision) must reject the apply with an error rather than panic
	// the daemon. buildSnapshot* returns the error up here; ApplyConfig
	// fails closed and the previously published snapshot / dataplane state
	// is retained (m.lastSnapshot is not advanced on the error path).
	snap, err := buildSnapshotWithSchedulerStateAndNATCounters(cfg, ucfg, m.bumpGeneration(), m.readFIBGeneration(), activeState, m.routeOverlaySnapshot(), m.feedSnapshotOverlay(), result.NATCounterIDs)
	if err != nil {
		return nil, fmt.Errorf("userspace: build config snapshot: %w", err)
	}
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
	// #3261: record whether this snapshot carries unrepresentable policy
	// content BEFORE the publish, so the diagnostic is captured even when the
	// helper rejects the snapshot (the publish path returns early on the
	// integrity error, before recordApplyResultLocked). The helper stays armed
	// for this class; the reject retains previous-good (or leaves the fresh-boot
	// default-deny), never fail-open.
	m.recordPolicyContentRejectionLocked(snap.Capabilities.PolicyContentRejected)
	// #3719: record + alarm any StableZoneID collision the builder quarantined
	// (lenient / HA-sync / pre-#3075-persisted path). The colliding zone was
	// already dropped from snap; this surfaces the degraded-isolation state.
	m.recordZoneIDCollisionsLocked(snap.zoneIDCollisions)
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
		if err := m.ensureRequiredSnapshotProtocolLocked(snap); err != nil {
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
			if err := m.clearHelperHAStateWithDebtEnsureRetryLocked(); err != nil {
				// Debt recorded — the status poll retries the clear until it
				// succeeds; still surface the error so the apply fails closed.
				// #5873: this deferred-publish resume path returns without
				// reaching the ensureStatusLoopLocked() call on the normal apply
				// path, so the WithDebtEnsureRetry wrapper starts the loop (the
				// debt's only retry consumer) before this failure propagates —
				// otherwise the failed clear would orphan the debt with no worker
				// to retry it. The pendingXSKStartup precondition guarantees
				// m.proc != nil, so the loop can actually run.
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
	if err := m.ensureRequiredSnapshotProtocolLocked(snap); err != nil {
		return result, m.disarmSnapshotProtocolFailClosedLocked(snap, err, samePlanRefresh)
	}
	if m.deferWorkers {
		snap.DeferWorkers = true
	}
	var status ProcessStatus
	if err := m.disarmBeforeUnsupportedPublishLocked(snap); err != nil {
		return result, err
	}
	// #1197 v5 (Codex code-review v4 #2): apply_snapshot must
	// send publishable-only neighbors to match the
	// update_neighbors path. Otherwise Rust's full-snapshot
	// build accepts state="none" entries Go's predicate rejects,
	// and Go can't track removal of those entries via the index.
	publishSnap := *snap
	publishSnap.Neighbors = filterPublishableNeighbors(snap.Neighbors)
	// #4959: on the samePlanRefresh path the classifier BPF maps were already
	// mutated IN PLACE above (syncUserspaceClassifierMapsFailClosedLocked) with
	// ctrl still enabled; publishSnapshotFailClosedLocked disables ctrl if this
	// publish is rejected so the maps can never run a generation ahead of the
	// applied Rust snapshot (fail-open). The bootstrap path already set
	// ctrl.Enabled=0, so it needs no extra fail-closed.
	if err := m.publishSnapshotFailClosedLocked(&publishSnap, &status, samePlanRefresh); err != nil {
		return result, err
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
	} else if err := m.clearHelperHAStateWithDebtEnsureRetryLocked(); err != nil {
		// Non-cluster node: ensure neither the manager nor the helper retains
		// HA groups. seedHAGroupInventoryLocked already cleared m.haGroups
		// above; this also clears any groups a prior clustered apply pushed to
		// the helper (cluster->standalone live reconfig), which would otherwise
		// keep the HAInactive transit-drop gate armed (Codex review #1928 Q3).
		// On failure a retry debt is recorded (#5487) so the status poll
		// re-attempts the idempotent clear until the helper reports no groups;
		// the error is still surfaced so this apply fails closed.
		// #5873: the recorded debt's ONLY retry consumer is the periodic status
		// loop, which the success path starts below via ensureStatusLoopLocked().
		// On first startup (or any apply with no pre-existing loop) returning
		// here BEFORE that call would orphan the debt — no worker would ever
		// retry the clear, so the stale helper HA groups (and the owner-RG-0
		// transit-drop gate) would persist indefinitely. The WithDebtEnsureRetry
		// wrapper starts the loop (idempotent) before this failure propagates.
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

// publishSnapshotFailClosedLocked sends apply_snapshot to the running helper and
// makes an in-place classifier-map refresh + helper publish one fail-closed
// transaction (#4959).
//
// When mapsMutatedInPlace is true the caller took the samePlanRefresh path: the
// ingress/local/interface-NAT classifier BPF maps were mutated IN PLACE to the
// new plan while the XDP shim's ctrl gate is still enabled. If the helper then
// REJECTS the snapshot (helper-side validation failure, or any transport error)
// it keeps enforcing the previous-good snapshot, so returning the error while
// leaving ctrl enabled would run the shim against classifier maps a generation
// ahead of the applied Rust snapshot — wrong kernel-pass vs XSK-redirect and
// wrong local-vs-interface-NAT ownership, a fail-OPEN security/availability
// mismatch instead of the intended previous-good retention. On that path a
// publish error disables ctrl (failClosedUserspaceCtrlMapLocked) so transit
// drops to the kernel-only fail-closed posture until a subsequent good commit
// re-publishes and re-enables it.
//
// When mapsMutatedInPlace is false the caller took the full bootstrap path,
// which already programmed ctrl.Enabled=0 before this publish, so a publish
// error is already fail-closed and the error is returned unchanged.
func (m *Manager) publishSnapshotFailClosedLocked(publishSnap *ConfigSnapshot, status *ProcessStatus, mapsMutatedInPlace bool) error {
	if err := m.requestLocked(ControlRequest{Type: "apply_snapshot", Snapshot: publishSnap}, status); err != nil {
		publishErr := fmt.Errorf("publish userspace snapshot: %w", err)
		if mapsMutatedInPlace {
			return m.failClosedUserspaceCtrlMapLocked(publishSnap, publishErr)
		}
		return publishErr
	}
	// #6034: apply_snapshot returns the helper's current neighbor-replace
	// generation. Seed from that response before returning to Compile, which
	// exposes m.lastSnapshot (and therefore enables RegenerateNeighborSnapshot)
	// immediately afterward. Waiting for statusLoop's first 1s tick leaves a
	// window where a surviving helper can fence this manager's generation 1.
	if status != nil {
		m.seedNeighborReplaceGenerationLocked(status.ManagerNeighborGeneration)
	}
	return nil
}

// rebuildScheduledPolicySectionsLocked rebuilds the policy + address-book
// sections of a partial (non-Compile) republish under a scheduler active-state
// map and re-applies the StableZoneID zone quarantine's policy scrub so the
// rebuilt next.Policies stays consistent with the inherited, already-reduced
// next.Zones (#6480). It is the SHARED core of the two republish paths that
// rebuild policies without a full Compile — PublishRouteOverlaySnapshot
// (route-overlay) and UpdatePolicyScheduleState (scheduler-only) — so the
// quarantine re-application can never drift between them. It mutates next in
// place and must be called with m.mu held.
//
// activeState is the policy-scheduler active-state map to build the inactive
// bits from (both callers set m.policySchedulerActive to it first, so it equals
// m.policySchedulerActive). #2049: the cached dynamic-address feed overlay is
// threaded through so a scheduler-state flip does not drop feed enforcement
// until the next full apply (m.mu is held, so read m.feedOverlay directly via
// cloneFeedOverlay rather than feedSnapshotOverlay(), which re-locks m.mu). A
// build error is returned wrapped; both callers retain the prior snapshot
// (fail-closed) and surface a retry.
func (m *Manager) rebuildScheduledPolicySectionsLocked(next *ConfigSnapshot, cfg *config.Config, activeState map[string]bool) error {
	// #6480 (config-skew fail-open guard): this helper rebuilds next.Policies
	// from cfg and scrubs them against cfg's StableZoneID quarantine set, but
	// next.Zones / next.Interfaces were inherited verbatim from m.lastSnapshot
	// (the APPLIED config). If cfg's zone generation differs from that applied
	// config, the scrub can drop a policy whose to/from zone is STILL a live
	// member of the inherited next.Zones — shipping a snapshot the Rust
	// UnresolvableZoneReference preflight ACCEPTS yet whose missing rule lets
	// traffic fall through to the inherited default policy (a fail-OPEN a full
	// Compile of cfg would instead render fail-closed by ALSO dropping the
	// quarantined zone and unzoning its interface). The route-overlay caller
	// already refuses this exact skew at its call site (routeOnlyPublishHybrid,
	// #5680); the scheduler-only caller (UpdatePolicyScheduleState) had no prior
	// guard, so enforce it HERE so BOTH partial-republish paths are protected.
	// routeOnlyPublishHybrid is parameterized on the applied config, so it doubles
	// as the general "cfg content-differs from applied" skew predicate. next.Config
	// was already set to cfg by both callers, so compare cfg against the INHERITED
	// snapshot's config (m.lastSnapshot.Config), NEVER next.Config (a cfg==cfg
	// tautology). On divergence retain the prior snapshot; the caller surfaces a
	// retry and the next tick reconverges once cfg's full apply lands
	// (m.lastSnapshot.Config == cfg) — the #3780 retry semantics already handle it.
	if m.lastSnapshot != nil && routeOnlyPublishHybrid(cfg, m.lastSnapshot.Config) {
		return fmt.Errorf("refusing scheduled-policy republish: cfg carries a zone/policy " +
			"generation the inherited dataplane snapshot does not reflect; rebuilding and " +
			"scrubbing against it could drop a live-zone policy and ship a fail-open snapshot (#6480)")
	}
	feedOverlay := cloneFeedOverlay(m.feedOverlay)
	// #2514: an unresolvable address-book content-ID collision must not panic the
	// daemon — surface it as an error so the caller retains the prior snapshot.
	policies, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, activeState, feedOverlay)
	if err != nil {
		return fmt.Errorf("policy snapshot rebuild for scheduler republish: %w", err)
	}
	// #6480: the raw builder re-introduces any policy referencing a
	// StableZoneID-quarantined zone (it has no knowledge of the quarantine),
	// while next.Zones was inherited already reduced by quarantineCollidingZones.
	// Re-establish the same zone-isolation invariant the full build guarantees
	// (builder.go) so no policy references a zone absent from next.Zones —
	// otherwise the Rust UnresolvableZoneReference preflight rejects the WHOLE
	// snapshot, and because the ip-monitoring actuator updates FRR BEFORE this
	// publish (daemon_ipmon.go) the kernel/FRR would sit on the new routes while
	// userspace keeps the old FIB with retries that cannot converge.
	policies = scrubPoliciesForQuarantinedZones(policies, quarantinedZoneNamesForConfig(cfg))
	next.Policies = policies
	// #3261: recompute the (feed-aware) content-rejection diagnostic from the
	// scrubbed rules' sentinels; the copied lastSnapshot value would be stale.
	next.Capabilities.PolicyContentRejected = collectPolicyContentRejections(policies)
	// Keep the operator-facing count equal to what is actually published, exactly
	// as the full build does after quarantine (builder.go): Summary.PolicyCount
	// must equal len(next.Policies).
	next.Summary.PolicyCount = len(policies)
	// #1606: refresh the address-book table alongside the policies so book IDs
	// cited by the rebuilt rules always resolve dataplane-side.
	books, _, err := buildAddressBookTableWithFeeds(cfg, feedOverlay)
	if err != nil {
		return fmt.Errorf("address-book rebuild for scheduler republish: %w", err)
	}
	next.AddressBooks = books
	return nil
}

// UpdatePolicyScheduleState republishes the userspace policy snapshot with one
// coherent inactive-bit view. This shadows the embedded eBPF manager method;
// scheduled userspace policies must not update the policy_rules BPF map.
func (m *Manager) UpdatePolicyScheduleState(cfg *config.Config, activeState map[string]bool) error {
	activeCopy := copyPolicySchedulerActiveState(activeState)

	m.mu.Lock()
	defer m.mu.Unlock()

	m.policySchedulerActive = activeCopy
	if cfg == nil {
		if m.lastSnapshot == nil {
			// #3780: no snapshot ever published — nothing to
			// republish, and no live enforcement to go stale. The
			// next full apply publishes the initial state. Converged.
			return nil
		}
		cfg = m.lastSnapshot.Config
	}
	if cfg == nil || m.lastSnapshot == nil {
		return nil
	}
	if m.proc == nil || m.proc.Process == nil {
		// #3780: the helper is not running, so no snapshot is being
		// enforced — there is no stale permit to converge. The helper
		// restart path re-applies the last snapshot. Converged.
		return nil
	}

	if err := m.ensureRequiredSnapshotProtocolLocked(m.lastSnapshot); err != nil {
		if disarmErr := m.disarmSnapshotProtocolFailureLocked(err); disarmErr != nil {
			slog.Warn("userspace: failed to disarm helper after refusing snapshot publish",
				"protocol_err", err, "err", disarmErr)
		}
		slog.Warn("userspace: refusing snapshot publish to incompatible helper", "err", err)
		// #3780: the intended new inactive-bit view was NOT applied.
		// Report failure so the daemon retries on the next scheduler
		// tick and surfaces the stale-enforcement metric.
		return fmt.Errorf("userspace: refusing snapshot publish to incompatible helper: %w", err)
	}
	next := *m.lastSnapshot
	nextGeneration := m.generation + 1
	next.Generation = nextGeneration
	next.FIBGeneration = m.readFIBGeneration()
	next.GeneratedAt = time.Now().UTC()
	next.Config = cfg
	// #6480: rebuild the schedule-affected policy + address-book sections
	// (threading the cached feed overlay, #2049) and re-apply the StableZoneID
	// zone quarantine's policy scrub via the shared helper, so this scheduler-only
	// republish and the route-overlay republish stay in lockstep and neither ships
	// a policy referencing a quarantined zone absent from the inherited next.Zones.
	if err := m.rebuildScheduledPolicySectionsLocked(&next, cfg, activeCopy); err != nil {
		slog.Warn("userspace: skipping policy-scheduler republish; retaining prior snapshot", "err", err)
		// #3780: the prior snapshot is retained, which for a CLOSING window means
		// the old permit stays live. Report failure so the transition is retried
		// on the next scheduler tick until the rebuild succeeds and converges.
		return fmt.Errorf("userspace: %w", err)
	}

	publishSnap := next
	publishSnap.Neighbors = filterPublishableNeighbors(next.Neighbors)
	var status ProcessStatus
	// #2124: disarm before publishing an unsupported-config snapshot (see
	// disarmBeforeUnsupportedPublishLocked). cfg is this snapshot's config.
	if err := m.disarmBeforeUnsupportedPublishLocked(&publishSnap); err != nil {
		slog.Warn("userspace: failed to disarm before unsupported-config policy scheduler publish", "err", err)
		// #3780: disarm failed and the new snapshot was not published —
		// report failure so the transition retries.
		return fmt.Errorf("userspace: disarm before unsupported-config policy scheduler publish: %w", err)
	}
	if err := m.requestLocked(ControlRequest{Type: "apply_snapshot", Snapshot: &publishSnap}, &status); err != nil {
		slog.Warn("userspace: failed to publish policy scheduler state", "err", err)
		// #3780: THE fail-open path from the issue. apply_snapshot did
		// not land, so the helper keeps the OLD inactive bits — a permit
		// past its window stays live. Report failure so the daemon
		// retries autonomously on the next scheduler tick.
		return fmt.Errorf("userspace: publish policy scheduler snapshot: %w", err)
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
		// #3780: the snapshot DID land (generation bumped, lastSnapshot
		// updated above) — the schedule transition converged. A status
		// re-sync failure is observability only; do NOT force a retry
		// that would churn an identical snapshot.
		slog.Warn("userspace: failed to sync helper status after policy scheduler publish", "err", err)
	}
	return nil
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

// policyScopeIsMultiZone reports whether a policy's scoped-global zone context
// (#4626 M03) holds more than one zone on either side — the exact shape the
// SINGULAR MatchFromZone/MatchToZone snapshot fields cannot represent, because
// config.ScopeSingular stamps only the first element onto them.
//
// A one-element scope is bit-identical in both shapes (singular == the one
// zone), and an unscoped global has both sides empty, so neither can be
// narrowed by a reader that ignores the plural fields. Restricting the
// predicate to len > 1 keeps the #5488 disarm blast radius to exactly the
// misrepresentable population.
//
// A set that CONTAINS the "any" wildcard alongside concrete zones is included
// conservatively: whether the singular field happens to land on "any" depends
// on element order, so the shape — not a coincidence of ordering — decides.
func policyScopeIsMultiZone(pol *config.Policy) bool {
	if pol == nil {
		return false
	}
	return len(pol.Match.FromZones) > 1 || len(pol.Match.ToZones) > 1
}

// configHasMultiZoneScopedPolicy scans every policy the snapshot builder lowers
// through buildOneRuleSnapshot — the global tier AND the zone-pair tier — for a
// multi-zone scope. Only global policies carry a zone scope today (the compiler
// never populates Match.FromZones/ToZones for a zone-pair policy), but the
// emitter stamps MatchFromZone/MatchToZone from the SAME Match fields for every
// rule, so the gate covers the whole emission surface rather than assuming the
// compiler's current tier discipline.
func configHasMultiZoneScopedPolicy(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	for _, pol := range cfg.Security.GlobalPolicies {
		if policyScopeIsMultiZone(pol) {
			return true
		}
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		for _, pol := range zpp.Policies {
			if policyScopeIsMultiZone(pol) {
				return true
			}
		}
	}
	return false
}

// ensureScopedGlobalZoneSetProtocolLocked is the #5488 fail-closed half of the
// v4 protocol bump. The bump itself makes a pre-v4 helper REFUSE the snapshot
// (both apply_snapshot and bump_fib_generation gate on exact version equality),
// which stops it from misreading the scope — but a refused snapshot leaves that
// helper ARMED on its previous-good image, still forwarding, with the newly
// committed deny never installed. This gate closes that window the way the
// project's other required-protocol gates do: the caller
// (ensureRequiredSnapshotProtocolLocked) disarms the helper and the commit
// aborts with an operator-visible reason, instead of reporting success against
// a dataplane running a policy set the helper cannot represent.
func (m *Manager) ensureScopedGlobalZoneSetProtocolLocked(cfg *config.Config) error {
	if !configHasMultiZoneScopedPolicy(cfg) {
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
		"%w: helper config snapshot protocol version %d < required %d for multi-zone scoped global policies "+
			"(an older helper reads only the singular match from-zone/to-zone and would NARROW the scope)",
		ErrScopedGlobalZoneSetProtocolIncompatible,
		m.lastStatus.ConfigSnapshotProtocolVersion,
		ProtocolVersion,
	)
}

// snapshotHasSecureTunnel reports whether this snapshot carries an
// InterfaceSnapshot with SecureTunnel set.
//
// It asks the snapshot builder ITSELF (#6691 round 9), rather than asking the
// same question over the same refs and asserting the two answers agree.
//
// Round 8 hand-mirrored the builder's walk here — config ownership first, then
// a SECOND RTM_GETLINK dump for the kernel half — under a comment claiming the
// gate "cannot arm for a config whose snapshot carries no flagged row or stay
// silent for one that does". A review round measured that claim false, and the
// mechanism was the second dump: with an xfrm device visible to the builder's
// dump and gone by this one, the built snapshot carried SecureTunnel=true on
// `st10` while this function returned FALSE, so the required-protocol gate
// stayed silent for exactly the snapshot it exists to gate. Two samples of a
// changing kernel are two answers; the invariant was never a property of the
// code, only of the timing.
//
// Reading the rows makes it a property of the code: there is ONE classification
// per snapshot, taken by the builder that stamps the flag, so "arms iff the
// snapshot carries a flagged row" is true by construction rather than by two
// samples agreeing. It also costs NOTHING — no dump, no walk, just a scan of
// rows the caller already has. Round 8's cost sentence ("ONE RTM_GETLINK dump,
// taken only after the config half has found nothing … skipped entirely on a
// box with no xfrm devices … never on a poll tick") was wrong three ways: the
// dump was unconditional once the config half found nothing, "skipped on a box
// with no xfrm devices" described the RESULT being empty rather than the dump
// being skipped, and the poll-triggered arm reconciliation (manager_status.go,
// manager_ha.go) does reach this gate.
//
// This does NOT eliminate every re-sample in the package — UserspaceBoundLinuxInterfaces
// still builds its own snapshot from a bare *config.Config, because that is the
// only thing its daemon call sites have. What it eliminates is the sample whose
// disagreement was UNSAFE: a silent gate leaves a pre-v5 helper armed on its
// previous-good image. The allowlist's remaining sample is conservative in its
// own direction (see its degrade-to-nil path) and cannot leave a helper armed.
func snapshotHasSecureTunnel(snap *ConfigSnapshot) bool {
	if snap == nil {
		return false
	}
	for _, iface := range snap.Interfaces {
		if iface.SecureTunnel {
			return true
		}
	}
	return false
}

// ensureSecureTunnelProtocolLocked is the fail-closed half of the #5619/#6691
// v5 bump. The bump makes a pre-v5 helper REFUSE the snapshot outright, which
// stops it from planning a binding for the xfrmi — but a refused snapshot
// leaves that helper ARMED on its previous-good image while the commit reports
// success. This gate closes that window the way the sibling gates do: the
// caller disarms the helper and the commit aborts with an operator-visible
// reason.
//
// Scoped by configHasSecureTunnel, which since #6691 round 8 is the SAME union
// the row flag is — a config-derived xfrmi OR a LIVE xfrm netdev the config no
// longer describes. So the honest statement of the scope is: an operator with
// neither route-based IPsec NOR a leftover xfrm device is never blocked by a
// helper-version mismatch that cannot affect them. The narrower "no route-based
// IPsec" wording this comment used to carry outlived the widening it describes
// and was measurably wrong: with zero VPNs configured, configHasSecureTunnel
// returns false with no live xfrmi and TRUE with a stale live `st10`. The
// arming is right — a stale xfrmi is exactly the case an operator cannot fix by
// editing the config, so a pre-v5 helper must not stay armed for it — and only
// the sentence was the defect.
func (m *Manager) ensureSecureTunnelProtocolLocked(snap *ConfigSnapshot) error {
	if !snapshotHasSecureTunnel(snap) {
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
		"%w: helper config snapshot protocol version %d < required %d for route-based IPsec secure tunnels "+
			"(an older helper ignores the secure_tunnel flag and plans an AF_XDP binding for the xfrmi; its "+
			"single RX queue then becomes the global minimum and collapses every interface to one queue and one worker)",
		ErrSecureTunnelProtocolIncompatible,
		m.lastStatus.ConfigSnapshotProtocolVersion,
		ProtocolVersion,
	)
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

// ensureRequiredSnapshotProtocolLocked takes the SNAPSHOT, not the config
// (#6691 round 9).
//
// Three of the four gates are pure config questions and read snap.Config
// exactly as before. The fourth — the secure-tunnel gate — is not: the flag it
// arms on is stamped by the snapshot builder from a sample of the KERNEL, and
// asking the same question from a config a moment later is asking a different
// kernel. Measured before this round, with an xfrm device visible to the
// builder's dump and gone by the gate's: the built snapshot carried
// SecureTunnel=true on `st10` while the gate returned false, so a pre-v5 helper
// stayed ARMED on its previous-good image for exactly the snapshot the gate
// exists to refuse.
//
// Passing the snapshot makes "arms iff the snapshot carries a flagged row" true
// by construction rather than by two samples agreeing. Every call site already
// had one in scope: the apply paths pass the snapshot they are about to
// publish, and the poll/status/HA paths pass m.lastSnapshot, which is the
// snapshot actually being enforced — a strictly better oracle than re-deriving
// from config on a poll tick.
func (m *Manager) ensureRequiredSnapshotProtocolLocked(snap *ConfigSnapshot) error {
	var cfg *config.Config
	if snap != nil {
		cfg = snap.Config
	}
	if err := m.ensurePolicySchedulerProtocolLocked(cfg); err != nil {
		return err
	}
	if err := m.ensurePersistentSourceNATProtocolLocked(cfg); err != nil {
		return err
	}
	if err := m.ensureScopedGlobalZoneSetProtocolLocked(cfg); err != nil {
		return err
	}
	return m.ensureSecureTunnelProtocolLocked(snap)
}

// disarmSnapshotProtocolFailClosedLocked is the shared fail-closed action for a
// required-protocol gate hit on a publish path (#5488 F7). It disarms the helper
// — the fail-closed contract of requiredProtocolGateSentinels — and, when the
// disarm ITSELF fails, additionally drives the userspace_ctrl shim to Enabled=0
// on the paths whose classifier BPF maps were already mutated IN PLACE.
//
// Why the extra step. A failed disarm leaves the helper ARMED on its
// previous-good Rust snapshot. On a same-plan refresh the ingress/local/
// interface-NAT classifier maps were already rewritten to the NEW plan with
// ctrl still enabled (syncUserspaceClassifierMapsFailClosedLocked), so simply
// returning would leave the XDP shim redirecting transit to XSK against maps a
// generation AHEAD of the snapshot the helper is enforcing. That is precisely
// the "fail-OPEN security/availability mismatch" failClosedUserspaceCtrlMapLocked
// exists to prevent (#4959), and the reason publishSnapshotFailClosedLocked
// takes the same mapsMutatedInPlace flag. Driving ctrl to 0 drops transit to the
// kernel-only fail-closed posture until a later good commit re-publishes.
//
// mapsMutatedInPlace MUST mirror the flag the caller passes to
// publishSnapshotFailClosedLocked, which is the codebase's oracle for "the
// classifier maps are ahead of the applied snapshot": samePlanRefresh in Compile,
// unconditionally true in syncSnapshotLocked (its only producer of an
// unpublished lastSnapshot is Compile's pendingXSKStartup branch, which always
// mutates the maps in place). The bootstrap path already programmed
// ctrl.Enabled=0, so it needs no extra fail-closed.
//
// Every failClosedUserspaceCtrlMapLocked return path PRESERVES cause (returned
// as-is, or wrapped with errors.Join), so the gate sentinel still satisfies
// IsRequiredProtocolGateError and the commit still ABORTS. A fail-closed disarm
// must never be downgraded into a promoted commit (#2138).
func (m *Manager) disarmSnapshotProtocolFailClosedLocked(snapshot *ConfigSnapshot, protocolErr error, mapsMutatedInPlace bool) error {
	disarmErr := m.disarmSnapshotProtocolFailureLocked(protocolErr)
	if disarmErr == nil {
		return protocolErr
	}
	joined := errors.Join(protocolErr, disarmErr)
	if !mapsMutatedInPlace {
		return joined
	}
	return m.failClosedUserspaceCtrlMapLocked(snapshot, joined)
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
