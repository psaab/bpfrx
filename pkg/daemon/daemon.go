// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/conntrack"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/dhcprelay"
	"github.com/psaab/xpf/pkg/dhcpserver"
	"github.com/psaab/xpf/pkg/eventengine"
	"github.com/psaab/xpf/pkg/feeds"
	"github.com/psaab/xpf/pkg/flowexport"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/grpcapi"
	"github.com/psaab/xpf/pkg/ipmon"
	"github.com/psaab/xpf/pkg/ipsec"
	"github.com/psaab/xpf/pkg/lldp"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/psaab/xpf/pkg/natpoolalarm"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/ra"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/psaab/xpf/pkg/rpm"
	"github.com/psaab/xpf/pkg/scheduler"
	"github.com/psaab/xpf/pkg/snmp"
	"github.com/psaab/xpf/pkg/vrrp"
)

// Options configures the daemon.
type Options struct {
	ConfigFile  string
	NoDataplane bool   // set to true to run without a dataplane (config-only mode)
	APIAddr     string // HTTP API listen address (empty = disabled)
	GRPCAddr    string // gRPC API listen address (empty = disabled)
	Version     string // software version string
	// #1620: cold-path latency histogram sample mask. nil pointer ⇒
	// userspace-dp uses default 0xff (1-in-256). Non-nil pointer ⇒
	// the operator explicitly set --cold-path-sample-mask (and, if
	// the value is 0, also --enable-cold-path-1-in-1-sampling). The
	// daemon forwards this verbatim to userspace-dp via the
	// `cold_path_sample_mask` field on ConfigSnapshot.
	ColdPathSampleMask *uint64
}

// nodeIDFile is the path to the cluster node ID file.
// If this file exists and contains a valid integer (0 or 1), the daemon
// runs in cluster mode with ${node} variable expansion. If the file does
// not exist, the daemon runs in standalone mode.
const nodeIDFile = "/etc/xpf/node-id"

// Daemon is the main xpf daemon.
type Daemon struct {
	opts     Options
	store    *configstore.Store
	dp       dataplane.RuntimeDataPlane
	networkd *networkd.Manager
	routing  *routing.Manager
	frr      *frr.Manager
	ipsec    *ipsec.Manager
	ra       *ra.Manager
	dhcp     *dhcp.Manager
	// dnsBootDone gates the #1715 DNS boot policy. It is false during the
	// single boot-time applyConfig (which runs before DHCP clients start,
	// so the lease set is empty) and set true immediately after. While
	// false, an empty DNS merge only repairs a dangling/stub/missing
	// /etc/resolv.conf and never clobbers a pre-existing good file; once
	// true, an empty merge is a declarative "clear DNS" (deleting all
	// `name-server` / expiring the last lease clears the file). Written
	// once after the boot apply and read only under applySem in
	// reconcileDNSLocked.
	dnsBootDone bool
	dhcpServer  *dhcpserver.Manager
	// ddns is the always-on DHCP dynamic-DNS manager (#1387 inc-2). It is
	// constructed UNCONDITIONALLY at daemon start (plan §4.2) — even when
	// DDNS is disabled — so an enabled→disabled commit always has a running
	// loop to withdraw the records it published. The reconcile loop is
	// file-I/O + DNS-network only (no control-socket calls), gated to the
	// HA-active node, and nudged on commit + MASTER transition.
	ddns *dhcpserver.DDNSManager
	// ddnsReconcileNowCh nudges the DDNS reconcile loop for an immediate
	// pass (config commit / VRRP MASTER takeover). Buffered depth 1 +
	// non-blocking send: coalesces a burst into one pending wakeup.
	ddnsReconcileNowCh chan struct{}
	// ddnsReconcileInFlight is the no-freeze guard for the DDNS loop: a
	// reconcile pass runs in a guarded goroutine (mirrors the neighbor
	// loop) so a hung DNS server can never wedge the loop or starve the
	// nudge channel.
	ddnsReconcileInFlight atomic.Bool
	// #2239 HA DHCP-server lease sync (PATH C). The push loop runs on the
	// RG-MASTER, reads the active lease set (Kea control socket → memfile
	// fallback), and replicates it over the cluster sync channel. The standby
	// holds the peer set in SessionSync.peerDHCPLeases{4,6} and seeds Kea on
	// takeover. These mirror the ddnsReconcile* fields above. The loop talks
	// ONLY to Kea's own socket + the cluster channel — never the
	// userspace-helper control socket (CLAUDE.md rule).
	dhcpLeaseSyncNowCh    chan struct{} // nudge: grant/commit/MASTER takeover
	dhcpLeaseSyncInFlight atomic.Bool   // no-freeze skip-if-in-flight guard
	dhcpLeaseLastSentMu   sync.Mutex
	dhcpLeaseLastSent4    string // last-pushed v4 set fingerprint (change-detect)
	dhcpLeaseLastSent6    string // last-pushed v6 set fingerprint (change-detect)
	feeds                 *feeds.Manager
	rpm                   *rpm.Manager
	rpmMu                 sync.Mutex // serializes reconcileRPM callers (#1827)
	activeRPMHash         [32]byte   // config-hash gate for RPM re-apply (#1827)
	// rpmPinsFailed records that the last probe-pin install left at
	// least one pin unprogrammed (#1895): the install is retried
	// (without restarting probes) on hash-gated reconcileRPM calls AND
	// by the slow periodic probePinRetryLoop until it succeeds.
	// Guarded by rpmMu.
	rpmPinsFailed bool
	// rpmPinRetryActive is true while a probePinRetryLoop goroutine is
	// running (#1895 AGY fold — autonomous recovery of boot-time pin
	// failures on a quiet box, no commit required). Guarded by rpmMu.
	rpmPinRetryActive bool
	// rpmEffective/rpmRethMap are the last-applied effective RPM
	// config + RETH map, kept for the periodic pin retry (which has no
	// fresh cfg in hand). Guarded by rpmMu.
	rpmEffective *config.RPMConfig
	rpmRethMap   map[string]string
	// probePinRetryEvery overrides the periodic pin-retry cadence
	// (tests); 0 = probePinRetryInterval.
	probePinRetryEvery time.Duration
	// probePinApply is the test seam for probe-pin programming; nil =
	// d.routing.ApplyProbePins (#1895).
	probePinApply func([]routing.ProbePin) map[string]error
	ipmon         *ipmon.Engine
	// natPoolAlarm is the #2079 NAT source pool-utilization-alarm monitor:
	// a slow (10s) loop over the helper's last-applied NAT pool snapshot
	// that raises/clears `show security alarms` entries with hysteresis and
	// emits one structured RT_NAT syslog line per transition. Nil in
	// NoDataplane mode (no helper to sample).
	//
	// #2114: atomic.Pointer because the monitor is now started/stopped at
	// RUNTIME (bootstrap exit arms it; bootstrap rollback stops+discards
	// it) concurrently with the `show security alarms` render reader
	// (natPoolAlarms, wired into the gRPC/CLI callbacks). All access goes
	// through maybeStartNATPoolAlarm / stopAndDiscardNATPoolAlarm /
	// natPoolAlarms so the pointer is never read or written unsynchronized.
	natPoolAlarm atomic.Pointer[natpoolalarm.Monitor]
	// natPoolAlarmTestTick overrides the monitor's sampler cadence at
	// construction time (#2114 race tests only). Zero in production (default
	// 10s). Read once in maybeStartNATPoolAlarm before Start.
	natPoolAlarmTestTick time.Duration
	// pendingFIBBump records an UNCONFIRMED FIB-generation bump after a
	// successful route-overlay publish (#1844, Codex plan r2-1): the
	// bump_fib_generation control message failed, so the next actuation
	// must retry the bump even when its publish is a duplicate-skip —
	// otherwise cached flow routes stay pinned to pre-failover paths.
	// Mutated only in actuateRouteOverlayLocked under applySem.
	pendingFIBBump bool
	// #2461: one exporter per per-flow-server template group, so a
	// collector receives the template it referenced (was a single exporter
	// using the first map-iteration template for every collector).
	flowExporters  []*flowexport.Exporter
	flowCancel     context.CancelFunc
	flowWg         sync.WaitGroup
	ipfixExporters []*flowexport.IPFIXExporter
	ipfixCancel    context.CancelFunc
	ipfixWg        sync.WaitGroup
	// #2075 flowexport reconcile state. The bundle pointers carry the
	// live (exporter, resolved-config) pair read lock-free by the
	// once-registered session-close callbacks; reconcile swaps them
	// atomically. The per-family hashes gate the reconcile so an
	// unrelated commit never bounces a healthy exporter; the *HashSet
	// bools distinguish "never reconciled" from "reconciled to the
	// nil sentinel". The *ReconMu serialize the reconcile swap against
	// shutdown's stopFlow/IPFIXExporter (both touch the cancel/wg).
	flowBundle                 atomic.Pointer[exporterBundle]
	flowHash                   [32]byte
	flowHashSet                bool
	flowCBOnce                 sync.Once
	flowReconMu                sync.Mutex
	ipfixBundlePtr             atomic.Pointer[ipfixBundle]
	ipfixHash                  [32]byte
	ipfixHashSet               bool
	ipfixCBOnce                sync.Once
	ipfixReconMu               sync.Mutex
	dhcpRelay                  *dhcprelay.Manager
	snmpAgent                  *snmp.Agent
	lldpMgr                    *lldp.Manager
	scheduler                  *scheduler.Scheduler
	schedulerCancel            context.CancelFunc
	policySchedulerConfigHash  [32]byte
	policySchedulerEpoch       atomic.Uint64
	cluster                    *cluster.Manager
	sessionSync                *cluster.SessionSync
	syncBulkPrimed             atomic.Bool
	syncPeerBulkPrimed         atomic.Bool
	syncPeerConnected          atomic.Bool
	lastStandbyNeighborRefresh atomic.Int64
	neighborWarmupInFlight     atomic.Bool
	// #1780 Path A: per-phase supervision of runPeriodicNeighborResolution.
	// Each periodic phase runs in a guarded goroutine so a hung netlink/probe
	// syscall in one phase can never freeze the for-select loop (the observed
	// 17.5h stall). In-flight bools skip a phase while a prior pass is still
	// running (no overlap / netlink-socket leak — a stuck syscall can't be
	// cancelled, so we leak at most one goroutine per phase, never a growing
	// pile). The last-success UnixNano feeds the
	// neighbor_periodic_last_success_age_seconds{phase} gauge so a stalled
	// phase is observable. neighborWarmupInFlight (above) already follows this
	// pattern for warmNeighborCache.
	resolveNeighborsInFlight    atomic.Bool
	forceProbeInFlight          atomic.Bool
	cleanFailedInFlight         atomic.Bool
	resolveLastSuccessNanos     atomic.Int64
	forceProbeLastSuccessNanos  atomic.Int64
	cleanFailedLastSuccessNanos atomic.Int64
	warmLastSuccessNanos        atomic.Int64
	// neighborPeriodicLoopStarted gates the phase-age gauge: it is set
	// once runPeriodicNeighborResolution actually starts (the loop only
	// runs when the dataplane is enabled with active config). Without it,
	// a daemon that never starts the loop would report every phase as a
	// forever-climbing "wedged" age — a false positive (Codex #1781 r1).
	neighborPeriodicLoopStarted atomic.Bool
	hbSuppressStart             atomic.Int64 // CLOCK_MONOTONIC nanos of first heartbeat suppression; 0 = inactive (#1792)
	syncPrimeRetryGen           atomic.Uint64
	syncReadyTimerGen           atomic.Uint64
	syncReadyTimerMu            sync.Mutex
	syncReadyTimer              *time.Timer
	syncReadyTimeout            time.Duration
	slogHandler                 *logging.SyslogSlogHandler
	traceWriter                 *logging.TraceWriter
	eventBuf                    *logging.EventBuffer
	eventReader                 *logging.EventReader
	eventEngine                 *eventengine.Engine
	aggregator                  *logging.SessionAggregator
	aggCancel                   context.CancelFunc
	vrrpMgr                     *vrrp.Manager
	gc                          *conntrack.GC
	startTime                   time.Time // daemon start time; used to suppress stale config sync

	// #846: applySem (capacity 1) serializes applyConfig + the
	// commit→apply pair across all entry points (HTTP/gRPC commits,
	// cluster sync recv, DHCP callbacks, config-poll, dynamic feeds,
	// event engine, in-process CLI commits, CLI auto-rollback).
	// Without this, two concurrent callers can interleave across
	// VRF/tunnel/FRR-reload steps, or one caller's commit can
	// interleave between another's commit and apply, leaving
	// configstore/kernel divergent. Used as a semaphore (not a
	// sync.Mutex) so handlers can Acquire(ctx, 1) and surface a 503
	// to the client when the lock holder is slow, instead of
	// hanging the request indefinitely.
	applySem *semaphore.Weighted
	// applyBodyForTest, when non-nil, replaces applyConfigLocked's
	// body. Test-only seam used by apply_serialize_test.go to
	// exercise the semaphore contract through the real applyConfig
	// / commitAndApply paths without standing up the full dataplane.
	applyBodyForTest func(*config.Config)

	// mgmtVRFInterfaces tracks interfaces bound to the management VRF (vrf-mgmt).
	// Used by collectDHCPRoutes to exclude management routes from FRR.
	mgmtVRFInterfaces map[string]bool

	// rgStates tracks the unified cluster + VRRP state for each
	// redundancy group. Both watchClusterEvents and watchVRRPEvents
	// funnel transitions through rgStateMachine, which determines the
	// desired rg_active value and provides an epoch counter for
	// stale-update detection.
	rgStatesMu sync.RWMutex
	rgStates   map[int]*rgStateMachine

	// blackholeRoutes tracks blackhole routes injected for inactive RG subnets.
	// When an RG goes BACKUP, we inject blackhole routes for its RETH subnets
	// to prevent FIB from routing return traffic via the default route (which
	// would escape via WAN). Instead, bpf_fib_lookup returns BLACKHOLE and
	// the FIB failure handler triggers fabric redirect to the peer.
	blackholeMu     sync.Mutex
	blackholeRoutes map[int][]netlink.Route

	// reconcileNowCh triggers an immediate RG state reconciliation pass.
	// Sent on event channel drops (cluster or VRRP) so recovery does not
	// wait for the 2-second periodic ticker.
	reconcileNowCh chan struct{}

	// Fabric cross-chassis forwarding state for periodic refresh.
	fabricMu         sync.RWMutex
	fabricIface      string // physical parent (XDP attachment point)
	fabricOverlay    string // IPVLAN overlay for neighbor resolution (#129)
	fabricPeerIP     net.IP
	fabricIface1     string        // secondary fabric parent
	fabricOverlay1   string        // secondary fabric overlay (#129)
	fabricPeerIP1    net.IP        // secondary fabric peer IP
	fabricPopulated  bool          // true after first successful fab0 write
	fabric1Populated bool          // true after first successful fab1 write
	fabricRefreshCh  chan struct{} // triggers immediate fabric_fwd refresh
	lastFabricProbe  time.Time     // rate-limit active fab0 neighbor probes
	lastFabricProbe1 time.Time     // rate-limit active fab1 neighbor probes
	lastFabricLog0   time.Time     // rate-limit fab0 refresh failure logs
	lastFabricLog1   time.Time     // rate-limit fab1 refresh failure logs

	// vipWarnedIfaces tracks interfaces that already emitted a
	// "directAddVIPs: interface not found" warning to avoid log spam
	// from the reconcile ticker. Reset on config commit.
	vipWarnedIfaces map[string]bool

	// syncPeerAddr is the primary peer address used for gRPC peer dialing
	// (session queries, config sync). Set to control link or fabric
	// peer depending on sync transport mode.
	syncPeerAddr string
	// syncPeerAddr1 is the secondary fabric peer address (fab1) for
	// gRPC peer dialing failover. Empty if no dual-fabric is configured.
	syncPeerAddr1 string

	// gRPC server reference for starting fabric listener in cluster mode.
	grpcSrv *grpcapi.Server

	// daemonCtx is the parent context from Run(), used to derive
	// independently-cancellable sub-contexts for cluster comms.
	daemonCtx context.Context

	// clusterCommsCancel cancels the sub-context used by startClusterComms
	// goroutines. Set when cluster comms are started, called to restart them
	// on config change (#87).
	clusterCommsCancel context.CancelFunc

	// activeClusterTransport stores the transport config used by the
	// currently running cluster comms. Compared on each applyConfig to
	// detect changes that require a comms restart (#87).
	activeClusterTransport clusterTransportKey

	// startupGoodbyeRA tracks whether the one-shot goodbye RA has been
	// sent for each inactive RG on startup. Prevents stale RA routes
	// from a previous primary run keeping hosts dual-pathing traffic.
	startupGoodbyeRA map[int]bool

	// startupActiveAnnounce tracks whether the one-shot active-side
	// neighbor refresh has been sent for each RG on this daemon run.
	// This covers restart/redeploy of an already-active direct-mode RG,
	// where VIP ownership does not transition and the normal failover
	// GARP/NA path would not fire.
	startupActiveAnnounce map[int]bool
	// directAnnounceSeq cancels and supersedes scheduled direct-mode
	// post-failover re-announcement bursts per RG. A new schedule bumps
	// the sequence; in-flight goroutines exit when their generation is
	// no longer current or the RG is no longer active locally.
	directAnnounceMu       sync.Mutex
	directAnnounceSeq      map[int]uint64
	directAnnounceSchedule []time.Duration
	directSendGARPsFn      func(int)
	// directVIPOwned tracks the last direct-mode ownership state applied
	// for each RG so reconciliation can trigger one-shot side effects
	// (service start/stop, announce bursts) while still reasserting
	// VIP presence/removal idempotently every pass.
	directVIPMu    sync.Mutex
	directVIPOwned map[int]bool
	// localFailoverCommitReady tracks whether this node has already
	// applied the local side of a freshly committed transfer request for
	// each RG. The cluster manager waits on this before telling the peer
	// to finalize demotion, so the old owner does not stand down before
	// the target daemon has processed the promotion edge.
	localFailoverCommitMu      sync.Mutex
	localFailoverCommitReady   map[int]bool
	localFailoverCommitTimeout time.Duration
	// localFailoverCommitDelay adds one short post-ready dwell after the
	// readiness bit flips so the VRRP/direct-ownership side effects that set
	// the bit have a chance to propagate before the peer finalizes demotion.
	localFailoverCommitDelay time.Duration
	// Test hooks for direct-mode VIP ownership reconciliation.
	directAddVIPsFn        func(int) int
	directRemoveVIPsFn     func(int) int
	directAddStableLLFn    func(int)
	directRemoveStableLLFn func(int)

	// linkByNameFn resolves a network interface by name. Defaults to
	// netlink.LinkByName; overridden in tests.
	linkByNameFn func(string) (netlink.Link, error)

	// userspaceSessionIDs allocates synthetic session IDs for sessions
	// learned from the userspace dataplane helper before they enter the
	// existing HA/session-sync transport.
	userspaceSessionIDs atomic.Uint64

	// eventStreamConnected is set when the helper's binary event stream
	// is live. The polling fallback loop uses this to decide its cadence:
	// 5s reconciliation when connected, 100ms fast-poll when disconnected.
	eventStreamConnected atomic.Bool

	// userspaceDeltaSyncMu serializes helper delta draining between the
	// event-stream fallback loop and the background polling loop.
	userspaceDeltaSyncMu sync.Mutex
	// userspaceDemotionPrepUntil suppresses duplicate demotion prep for the
	// same RG during a single failover transition. Manual failover can now
	// stage prep before ownership changes; the later cluster/VRRP edges must
	// not rerun the same barrier sequence immediately afterward.
	userspaceDemotionPrepMu    sync.Mutex
	userspaceDemotionPrepUntil map[int]time.Time

	// Compile health (#758). If dataplane compile fails and never
	// succeeds, the daemon is in a degraded state: config is accepted
	// but the forwarding path may be partial or absent. Track this so
	// /health can surface it and operators aren't left staring at a
	// single pre-existing WARN line with no other signal.
	compileHealthMu         sync.Mutex
	compileFailureCount     uint64 // total failed compiles since daemon start
	compileEverSucceeded    bool   // true once any compile completed cleanly
	compileLastError        string // text of the most recent compile error
	compileLastErrorUnixSec int64  // timestamp of the most recent compile error

	// priorTunables stores the pre-xpfd values of every host-scope
	// tunable xpfd has touched, so that restore-on-disable (B2) can
	// revert to what the operator had before xpfd claimed the host.
	// Populated lazily on first apply. Restored when claim-host-tunables
	// transitions from true → false, or on daemon shutdown. See
	// pkg/daemon/host_tunables.go for capture/restore implementation.
	priorTunablesMu     sync.Mutex
	priorTunables       *priorHostTunables
	priorTunablesActive bool // true once the current config has applied host tunables

	// bootstrapMode is the #1922 explicit bootstrap-mode flag. When set, the
	// daemon runs gRPC/REST/CLI as normal but suppresses ALL interface
	// takeover ACTIONS (rename loop beyond the lifeline path, link cycles,
	// networkd takeover writes beyond the lifeline .network, dataplane arm,
	// FRR managed-section, boot-time applyConfig, VRRP instance creation).
	// Set once at startup from the five-case boot predicate (computeBootClass)
	// and cleared one-way on the first non-empty config apply (local confirmed
	// commit or cluster SyncApply). Read on every commit gate / reconcile, so
	// an atomic avoids a lock on the hot read path. Managers are still
	// constructed unconditionally (C1) so the bootstrap-exit reconcile wires
	// every subsystem.
	bootstrapMode atomic.Bool
}

func (d *Daemon) applyResult() *dataplane.ApplyResult {
	if d == nil {
		return nil
	}
	return dataplane.LastApplyResultOf(d.dp)
}

// CompileHealth is a snapshot of dataplane compile health (#758).
// Consumed by /health to surface a degraded state instead of returning
// OK when the dataplane never compiled successfully.
type CompileHealth struct {
	EverSucceeded    bool
	FailureCount     uint64
	LastError        string
	LastErrorUnixSec int64
}

const standbyNeighborRefreshMinInterval = time.Second

// New creates a new Daemon. It fails when the config store cannot be
// constructed (#1893 — the store is fail-closed on an unusable
// .configdb): a daemon that cannot persist configuration must not
// boot pretending otherwise.
func New(opts Options) (*Daemon, error) {
	if opts.ConfigFile == "" {
		opts.ConfigFile = "/etc/xpf/xpf.conf"
	}

	store, err := configstore.New(opts.ConfigFile)
	if err != nil {
		return nil, fmt.Errorf("config store: %w", err)
	}

	// Stamp the build version into the config-DB compatibility envelope on
	// write (#1917 increment B, plan §6.4 / D1). The envelope's magic header
	// makes a future format bump fail closed on an old reader instead of
	// silently empty-loading.
	store.SetConfigDBWriterVersion(opts.Version)

	// Read cluster node ID from file. If the file exists and contains a
	// valid integer, the daemon runs in cluster mode with ${node} variable
	// expansion in apply-groups. If the file does not exist, standalone mode.
	if data, err := os.ReadFile(nodeIDFile); err == nil {
		s := strings.TrimSpace(string(data))
		var nodeID int
		if _, err := fmt.Sscanf(s, "%d", &nodeID); err == nil {
			store.SetNodeID(nodeID)
			slog.Info("cluster node ID loaded from file", "node", nodeID, "file", nodeIDFile)
		}
	}

	return &Daemon{
		opts:                       opts,
		startTime:                  time.Now(),
		store:                      store,
		rgStates:                   make(map[int]*rgStateMachine),
		blackholeRoutes:            make(map[int][]netlink.Route),
		reconcileNowCh:             make(chan struct{}, 1),
		ddnsReconcileNowCh:         make(chan struct{}, 1),
		dhcpLeaseSyncNowCh:         make(chan struct{}, 1),
		syncReadyTimeout:           5 * time.Second,
		linkByNameFn:               netlink.LinkByName,
		directAnnounceSchedule:     []time.Duration{0, 250 * time.Millisecond, 1 * time.Second, 2 * time.Second, 4 * time.Second, 6 * time.Second},
		directVIPOwned:             make(map[int]bool),
		localFailoverCommitReady:   make(map[int]bool),
		localFailoverCommitTimeout: 3 * time.Second,
		localFailoverCommitDelay:   200 * time.Millisecond,
		userspaceDemotionPrepUntil: make(map[int]time.Time),
		applySem:                   semaphore.NewWeighted(1),
	}, nil
}

// NOTE (#1519, sub-#1451 S4): the (*Daemon).legacyDP() escape hatch
// previously declared here was removed when every daemon-internal
// consumer migrated to a narrow typed probe in runtime_probes.go.
// A regression-guard AST canary in legacy_dataplane_canary_test.go
// keeps the symbol from being reintroduced without explicit review.
