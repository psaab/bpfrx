// Package daemon implements the bpfrx daemon lifecycle.
package daemon

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/psaab/bpfrx/pkg/api"
	"github.com/psaab/bpfrx/pkg/cli"
	"github.com/psaab/bpfrx/pkg/cluster"
	"github.com/psaab/bpfrx/pkg/config"
	"github.com/psaab/bpfrx/pkg/configstore"
	"github.com/psaab/bpfrx/pkg/conntrack"
	"github.com/psaab/bpfrx/pkg/dataplane"
	dpuserspace "github.com/psaab/bpfrx/pkg/dataplane/userspace"
	"github.com/psaab/bpfrx/pkg/dhcp"
	"github.com/psaab/bpfrx/pkg/dhcprelay"
	"github.com/psaab/bpfrx/pkg/dhcpserver"
	"github.com/psaab/bpfrx/pkg/eventengine"
	"github.com/psaab/bpfrx/pkg/feeds"
	"github.com/psaab/bpfrx/pkg/flowexport"
	"github.com/psaab/bpfrx/pkg/frr"
	"github.com/psaab/bpfrx/pkg/grpcapi"
	"github.com/psaab/bpfrx/pkg/ipsec"
	"github.com/psaab/bpfrx/pkg/lldp"
	"github.com/psaab/bpfrx/pkg/logging"
	"github.com/psaab/bpfrx/pkg/networkd"
	"github.com/psaab/bpfrx/pkg/ra"
	"github.com/psaab/bpfrx/pkg/routing"
	"github.com/psaab/bpfrx/pkg/rpm"
	"github.com/psaab/bpfrx/pkg/scheduler"
	"github.com/psaab/bpfrx/pkg/snmp"
	"github.com/psaab/bpfrx/pkg/vrrp"
)

// Options configures the daemon.
type Options struct {
	ConfigFile  string
	NoDataplane bool   // set to true to run without eBPF (config-only mode)
	APIAddr     string // HTTP API listen address (empty = disabled)
	GRPCAddr    string // gRPC API listen address (empty = disabled)
	Version     string // software version string
}

// nodeIDFile is the path to the cluster node ID file.
// If this file exists and contains a valid integer (0 or 1), the daemon
// runs in cluster mode with ${node} variable expansion. If the file does
// not exist, the daemon runs in standalone mode.
const nodeIDFile = "/etc/bpfrx/node-id"

// Daemon is the main bpfrx daemon.
type Daemon struct {
	opts               Options
	store              *configstore.Store
	dp                 dataplane.DataPlane
	networkd           *networkd.Manager
	routing            *routing.Manager
	frr                *frr.Manager
	ipsec              *ipsec.Manager
	ra                 *ra.Manager
	dhcp               *dhcp.Manager
	dhcpServer         *dhcpserver.Manager
	feeds              *feeds.Manager
	rpm                *rpm.Manager
	flowExporter       *flowexport.Exporter
	flowCancel         context.CancelFunc
	flowWg             sync.WaitGroup
	ipfixExporter      *flowexport.IPFIXExporter
	ipfixCancel        context.CancelFunc
	ipfixWg            sync.WaitGroup
	dhcpRelay          *dhcprelay.Manager
	snmpAgent          *snmp.Agent
	lldpMgr            *lldp.Manager
	scheduler          *scheduler.Scheduler
	cluster            *cluster.Manager
	sessionSync        *cluster.SessionSync
	syncBulkPrimed     atomic.Bool
	syncPeerBulkPrimed atomic.Bool
	syncPeerConnected  atomic.Bool
	hbSuppressStart    atomic.Int64 // UnixNano of first heartbeat suppression; 0 = inactive
	syncPrimeRetryGen  atomic.Uint64
	syncReadyTimerGen  atomic.Uint64
	syncReadyTimerMu   sync.Mutex
	syncReadyTimer     *time.Timer
	syncReadyTimeout   time.Duration
	slogHandler        *logging.SyslogSlogHandler
	traceWriter        *logging.TraceWriter
	eventReader        *logging.EventReader
	eventEngine        *eventengine.Engine
	aggregator         *logging.SessionAggregator
	aggCancel          context.CancelFunc
	vrrpMgr            *vrrp.Manager
	gc                 *conntrack.GC
	startTime          time.Time // daemon start time; used to suppress stale config sync

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
	// periodic background sync loop and the RG demotion prepare path.
	// Demotion prepare must drain and barrier its continuity-critical
	// republish deltas itself; otherwise the background loop can consume
	// them first and let demotion proceed without peer ack.
	userspaceDeltaSyncMu sync.Mutex
	// userspaceDemotionPrepDepth pauses background incremental session-sync
	// producers while demotion prep stages continuity-critical republish.
	userspaceDemotionPrepDepth atomic.Int32
	// demotionKernelJournal buffers kernel SESSION_OPEN events that arrive
	// during demotion prep. Instead of dropping them, they are flushed to
	// the peer before the final barrier.
	demotionKernelJournalMu sync.Mutex
	demotionKernelJournalV4 []journaledSessionV4
	demotionKernelJournalV6 []journaledSessionV6
	// userspaceDemotionPrepUntil suppresses duplicate demotion prep for the
	// same RG during a single failover transition. Manual failover can now
	// stage prep before ownership changes; the later cluster/VRRP edges must
	// not rerun the same barrier sequence immediately afterward.
	userspaceDemotionPrepMu    sync.Mutex
	userspaceDemotionPrepUntil map[int]time.Time
}

// New creates a new Daemon.
func New(opts Options) *Daemon {
	if opts.ConfigFile == "" {
		opts.ConfigFile = "/etc/bpfrx/bpfrx.conf"
	}

	store := configstore.New(opts.ConfigFile)

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
		syncReadyTimeout:           5 * time.Second,
		linkByNameFn:               netlink.LinkByName,
		directAnnounceSchedule:     []time.Duration{0, 250 * time.Millisecond, 1 * time.Second, 2 * time.Second, 4 * time.Second, 6 * time.Second},
		userspaceDemotionPrepUntil: make(map[int]time.Time),
	}
}

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
	d.syncBulkPrimed.Store(false)
	d.syncPeerBulkPrimed.Store(false)
	d.syncPeerConnected.Store(true)
	d.hbSuppressStart.Store(0) // fresh connection → reset suppression cap
	gen := d.syncPrimeRetryGen.Add(1)
	slog.Info("cluster: session sync peer connected",
		"retry_gen", gen,
		"cluster_sync_ready", d.cluster != nil && d.cluster.IsSyncReady())
	if d.cluster != nil {
		d.cluster.SetSyncReady(false)
	}
	d.armSyncReadyTimer()
	d.startSessionSyncPrimeRetry(gen)
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
	d.syncBulkPrimed.Store(false)
	d.syncPeerBulkPrimed.Store(false)
	d.syncPeerConnected.Store(false)
	gen := d.syncPrimeRetryGen.Add(1)
	slog.Info("cluster: session sync peer disconnected",
		"retry_gen", gen,
		"cluster_sync_ready", d.cluster != nil && d.cluster.IsSyncReady())
	d.stopSyncReadyTimer()
	if d.cluster != nil {
		d.cluster.SetSyncReady(false)
	}
}

func (d *Daemon) shouldSuppressPeerHeartbeatTimeout() (bool, string) {
	ss := d.sessionSync
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
	const maxSuppressDuration = 5 * time.Second
	now := time.Now().UnixNano()
	start := d.hbSuppressStart.Load()
	if start == 0 {
		d.hbSuppressStart.Store(now)
		start = now
	}
	if time.Duration(now-start) > maxSuppressDuration {
		return false, ""
	}

	return true, fmt.Sprintf("session sync connected with recent peer traffic age=%s", age.Truncate(10*time.Millisecond))
}

func syncPrimeProgressObserved(current, baseline cluster.SyncStatsSnapshot) bool {
	return current.SessionsReceived > baseline.SessionsReceived ||
		current.SessionsInstalled > baseline.SessionsInstalled ||
		current.DeletesReceived > baseline.DeletesReceived
}

func (d *Daemon) startSessionSyncPrimeRetry(gen uint64) {
	ss := d.sessionSync
	if ss == nil || d.dp == nil {
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
			if d.sessionSync != ss || !ss.IsConnected() {
				reason := "session sync replaced"
				if d.sessionSync == ss && !ss.IsConnected() {
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
			if err := ss.BulkSync(); err != nil {
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

func collectAppliedTunnels(cfg *config.Config) []*config.TunnelConfig {
	if cfg == nil {
		return nil
	}
	anchorOnly := cfg.System.DataplaneType == dataplane.TypeUserspace
	var tunnels []*config.TunnelConfig
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		if ifc.Tunnel != nil && ifc.Tunnel.Source != "" {
			tc := *ifc.Tunnel
			tc.AnchorOnly = anchorOnly
			tunnels = append(tunnels, &tc)
		}
		for _, unit := range ifc.Units {
			if unit == nil || unit.Tunnel == nil {
				continue
			}
			tc := *unit.Tunnel
			tc.AnchorOnly = anchorOnly
			tunnels = append(tunnels, &tc)
		}
	}
	return tunnels
}

// Run starts the daemon and blocks until shutdown.
func (d *Daemon) Run(ctx context.Context) error {
	d.daemonCtx = ctx

	// Wrap the default slog handler to support system syslog forwarding.
	// Syslog clients are added later when config is applied.
	d.slogHandler = logging.NewSyslogSlogHandler(slog.Default().Handler())
	slog.SetDefault(slog.New(d.slogHandler))

	slog.Info("starting bpfrx daemon",
		"config", d.opts.ConfigFile,
		"pid", os.Getpid())

	// Load persisted configuration from DB, falling back to text config file
	if err := d.store.Load(); err != nil {
		slog.Warn("failed to load config from db", "err", err)
	}

	// If DB had no active config, bootstrap from the text config file
	if d.store.ActiveConfig() == nil {
		if err := d.bootstrapFromFile(); err != nil {
			slog.Warn("failed to bootstrap config from file", "err", err)
		}
	} else {
		slog.Info("configuration loaded from db")
	}

	// Enumerate PCI NICs and assign vSRX-style names (fxp0, em0, ge-X-0-Y)
	// before any manager creation or BPF load.
	if !d.opts.NoDataplane {
		clusterMode := false
		nodeID := 0
		if cfg := d.store.ActiveConfig(); cfg != nil && cfg.Chassis.Cluster != nil {
			clusterMode = true
			nodeID = cfg.Chassis.Cluster.NodeID
		}
		if err := enumerateAndRenameInterfaces(nodeID, clusterMode); err != nil {
			slog.Warn("interface naming failed", "err", err)
		}
	}

	// Initialize routing, FRR, and IPsec managers
	if !d.opts.NoDataplane {
		rm, err := routing.New()
		if err != nil {
			slog.Warn("failed to create routing manager", "err", err)
		} else {
			d.routing = rm
		}
		d.frr = frr.New()
		d.ipsec = ipsec.New()
		d.ra = ra.New()
		d.networkd = networkd.New()
		d.dhcpServer = dhcpserver.New()
	}

	// Initialize cluster manager if configured (heartbeat/sync started after applyConfig).
	if cfg := d.store.ActiveConfig(); cfg != nil && cfg.Chassis.Cluster != nil {
		cc := cfg.Chassis.Cluster
		d.cluster = cluster.NewManager(cc.NodeID, cc.ClusterID)
		d.cluster.UpdateConfig(cc)
		d.cluster.Start(ctx)
		// Wire event-drop callback: on dropped cluster events, trigger
		// immediate reconciliation so the safety net doesn't wait 2s.
		d.cluster.SetOnEventDrop(d.triggerReconcile)
		slog.Info("cluster manager initialized",
			"node", cc.NodeID, "cluster", cc.ClusterID)

		// Watch cluster events for state transitions (primary/secondary).
		go d.watchClusterEvents(ctx)
	}

	// Enable IP forwarding — required for the firewall to route packets.
	if !d.opts.NoDataplane {
		enableForwarding()
	}

	// Create VRRP manager eagerly — must exist before applyConfig runs.
	d.vrrpMgr = vrrp.NewManager()
	// Wire event-drop callback: on dropped VRRP events, trigger
	// immediate reconciliation.
	d.vrrpMgr.SetOnEventDrop(d.triggerReconcile)
	if err := d.vrrpMgr.Start(context.Background()); err != nil {
		slog.Warn("failed to start VRRP manager", "err", err)
	}
	// On fresh cluster daemon start, suppress VRRP preemption until session
	// bulk sync completes (or timeout) to avoid preempt-before-sync outages.
	// Only applies when VRRP is enabled — otherwise no RETH VRRP instances.
	if cfg := d.store.ActiveConfig(); cfg != nil && cfg.Chassis.Cluster != nil {
		cc := cfg.Chassis.Cluster
		if cc.FabricInterface != "" && cc.FabricPeerAddress != "" && !cc.NoRethVRRP && !cc.PrivateRGElection {
			d.vrrpMgr.SetSyncHold(30 * time.Second)
		}
		// Private-rg-election mode: gate RG promotion on session sync
		// readiness with a 30s timeout fallback (mirrors VRRP sync-hold).
		// Without this, standalone nodes or nodes with permanently-down
		// peers would never become primary.
		if cc.PrivateRGElection && cc.FabricInterface != "" && cc.FabricPeerAddress != "" {
			d.armSyncReadyTimer()
		}
	}

	// Create dataplane backend (unless in config-only mode)
	if !d.opts.NoDataplane {
		dpType := ""
		if cfg := d.store.ActiveConfig(); cfg != nil {
			dpType = cfg.System.DataplaneType
		}
		dp, err := dataplane.NewDataPlane(dpType)
		if err != nil {
			slog.Error("failed to create dataplane", "type", dpType, "err", err)
			return fmt.Errorf("create dataplane: %w", err)
		}
		d.dp = dp
		if err := d.dp.Load(); err != nil {
			slog.Warn("failed to load dataplane programs, running in config-only mode",
				"err", err)
			d.dp = nil
		} else {
			d.dp.SeedNATPortCounters()
			nodeID := 0
			if cfg := d.store.ActiveConfig(); cfg != nil && cfg.Chassis.Cluster != nil {
				nodeID = cfg.Chassis.Cluster.NodeID
			}
			d.dp.SeedSessionIDCounter(nodeID)
		}
		// Apply current config — needed even in config-only mode so that
		// VRFs, interfaces, and routing are configured before cluster comms.
		if cfg := d.store.ActiveConfig(); cfg != nil {
			slog.Info("applying active configuration")
			d.applyConfig(cfg)
		}
	}

	// Remove stale blackhole routes from previous daemon runs before
	// cluster comms start (which may inject new ones).
	if d.cluster != nil {
		d.reconcileBlackholeRoutes()
	}

	// Start cluster heartbeat + sync after applyConfig (needs VRF to exist).
	if d.cluster != nil {
		d.startClusterComms(ctx)
	}

	// Handle signals for clean shutdown.
	// In interactive mode, only SIGTERM triggers shutdown — SIGINT is handled
	// by the CLI for command cancellation (Ctrl-C).
	// In daemon mode, both SIGTERM and SIGINT trigger shutdown.
	var stop context.CancelFunc
	if isInteractive() {
		ctx, stop = signal.NotifyContext(ctx, syscall.SIGTERM)
	} else {
		ctx, stop = signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	}
	defer stop()

	// Create event buffer (shared between event reader and CLI)
	eventBuf := logging.NewEventBuffer(1000)

	// WaitGroup for coordinated shutdown of background goroutines
	var wg sync.WaitGroup

	// NOTE: session sync dp wiring + sweep start moved into startClusterComms
	// goroutine to avoid race: d.sessionSync is created asynchronously.

	// Start background services if dataplane is loaded
	var er *logging.EventReader
	if d.dp != nil {
		// Start FIB sync (DPDK: background route populator; eBPF: no-op)
		d.dp.StartFIBSync(ctx)

		gc := conntrack.NewGC(d.dp, 10*time.Second)
		d.gc = gc

		// When the userspace dataplane is active, skip BPF session map
		// GC entirely — sessions are managed in user-space. Without
		// this, BatchLookup burns ~19% CPU scanning maps not used for
		// forwarding decisions.
		//
		// The helper still mirrors sessions to BPF conntrack for display
		// and periodically refreshes last_seen (~10s) so IterateSessions
		// callers see accurate idle times.  See #333.
		if _, ok := d.dp.(userspaceSessionDeltaDrainer); ok {
			gc.SkipSweep = func() bool { return true }
		}

		// In cluster mode, GC should only expire sessions when this node
		// is primary.  The peer primary ages sessions and syncs deletes.
		if d.cluster != nil {
			gc.IsLocalPrimary = d.cluster.IsLocalPrimaryAny
		}

		// Wire GC delete callbacks for incremental session sync.
		// Deletes are synced if this node is primary for any RG — the peer
		// ignores deletes for sessions it doesn't have.
		gc.OnDeleteV4 = func(key dataplane.SessionKey) {
			// Always sync deletes, even during demotion prep. Dropping
			// deletes leaves stale sessions on the peer indefinitely.
			if d.cluster != nil && d.cluster.IsLocalPrimaryAny() && d.sessionSync != nil {
				d.sessionSync.QueueDeleteV4(key)
			}
		}
		gc.OnDeleteV6 = func(key dataplane.SessionKeyV6) {
			if d.cluster != nil && d.cluster.IsLocalPrimaryAny() && d.sessionSync != nil {
				d.sessionSync.QueueDeleteV6(key)
			}
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			gc.Run(ctx)
		}()

		evSrc, evErr := d.dp.NewEventSource()
		if evErr != nil {
			slog.Warn("failed to create event source", "err", evErr)
		}
		if evSrc != nil {
			er = logging.NewEventReader(evSrc, eventBuf)
			d.eventReader = er
			wg.Add(1)
			go func() {
				defer wg.Done()
				er.Run(ctx)
			}()

			// Wire ring buffer callback for near-real-time session sync.
			if d.sessionSync != nil {
				er.AddCallback(func(rec logging.EventRecord, raw []byte) {
					if rec.Type != "SESSION_OPEN" {
						return
					}
					if d.cluster == nil || !d.cluster.IsLocalPrimaryAny() {
						return
					}
					if !d.sessionSync.IsConnected() {
						return
					}
					if len(raw) < 56 {
						return
					}
					proto := raw[53]
					af := raw[55]
					demotionActive := d.userspaceDemotionPrepActive()

					if af == dataplane.AFInet6 {
						var key dataplane.SessionKeyV6
						copy(key.SrcIP[:], raw[8:24])
						copy(key.DstIP[:], raw[24:40])
						key.SrcPort = binary.BigEndian.Uint16(raw[40:42])
						key.DstPort = binary.BigEndian.Uint16(raw[42:44])
						key.Protocol = proto
						if val, err := d.dp.GetSessionV6(key); err == nil && val.IsReverse == 0 {
							if d.sessionSync.ShouldSyncZone(val.IngressZone) {
								if demotionActive {
									d.journalKernelSessionV6(key, val)
								} else {
									d.sessionSync.QueueSessionV6(key, val)
								}
							}
						}
					} else {
						var key dataplane.SessionKey
						copy(key.SrcIP[:], raw[8:12])
						copy(key.DstIP[:], raw[24:28])
						key.SrcPort = binary.BigEndian.Uint16(raw[40:42])
						key.DstPort = binary.BigEndian.Uint16(raw[42:44])
						key.Protocol = proto
						if val, err := d.dp.GetSessionV4(key); err == nil && val.IsReverse == 0 {
							if d.sessionSync.ShouldSyncZone(val.IngressZone) {
								if demotionActive {
									d.journalKernelSessionV4(key, val)
								} else {
									d.sessionSync.QueueSessionV4(key, val)
								}
							}
						}
					}
				})
			}

			// Set up syslog clients from active config
			if cfg := d.store.ActiveConfig(); cfg != nil {
				d.applySyslogConfig(er, cfg)
			}

			// Start NetFlow exporter if configured
			if cfg := d.store.ActiveConfig(); cfg != nil {
				d.startFlowExporter(ctx, cfg, er)
			}

			// Start IPFIX exporter if configured
			if cfg := d.store.ActiveConfig(); cfg != nil {
				d.startIPFIXExporter(ctx, cfg, er)
			}

			// Set up flow traceoptions if configured
			if cfg := d.store.ActiveConfig(); cfg != nil {
				d.applyFlowTrace(cfg, er)
			}
		}
	}

	// Start DHCP clients for interfaces configured with dhcp/dhcpv6.
	// This must happen after BPF load + config compile so HOST_INBOUND_DHCP
	// flags are active before DHCP packets start flowing.
	if !d.opts.NoDataplane {
		if cfg := d.store.ActiveConfig(); cfg != nil {
			d.startDHCPClients(ctx, cfg)
		}
	}

	// Start dynamic address feeds if configured.
	if cfg := d.store.ActiveConfig(); cfg != nil && len(cfg.Security.DynamicAddress.FeedServers) > 0 {
		d.feeds = feeds.New(func() {
			slog.Info("dynamic-address feed updated, recompiling dataplane")
			if activeCfg := d.store.ActiveConfig(); activeCfg != nil {
				d.applyConfig(activeCfg)
			}
		})
		d.feeds.Apply(ctx, &cfg.Security.DynamicAddress)
	}

	// Start RPM probes if configured.
	if cfg := d.store.ActiveConfig(); cfg != nil && cfg.Services.RPM != nil && len(cfg.Services.RPM.Probes) > 0 {
		d.rpm = rpm.New()
		d.rpm.Apply(ctx, cfg.Services.RPM)
	}

	// Start LLDP if configured.
	if cfg := d.store.ActiveConfig(); cfg != nil && cfg.Protocols.LLDP != nil && !cfg.Protocols.LLDP.Disable && len(cfg.Protocols.LLDP.Interfaces) > 0 {
		d.lldpMgr = lldp.New()
		var lldpIfaces []lldp.LLDPInterface
		for _, iface := range cfg.Protocols.LLDP.Interfaces {
			lldpIfaces = append(lldpIfaces, lldp.LLDPInterface{
				Name:    iface.Name,
				Disable: iface.Disable,
			})
		}
		d.lldpMgr.Apply(ctx, &lldp.LLDPConfig{
			Interfaces:     lldpIfaces,
			Interval:       cfg.Protocols.LLDP.Interval,
			HoldMultiplier: cfg.Protocols.LLDP.HoldMultiplier,
			SystemName:     cfg.System.HostName,
		})
	}

	// Start event-options engine if configured.
	if cfg := d.store.ActiveConfig(); cfg != nil && len(cfg.EventOptions) > 0 {
		d.eventEngine = eventengine.New(d.store, d.applyConfig)
		d.eventEngine.Apply(cfg.EventOptions)
		if d.rpm != nil {
			d.rpm.SetEventCallback(d.eventEngine.HandleEvent)
		}
		slog.Info("event-options engine started", "policies", len(cfg.EventOptions))
	}

	// Start DHCP relay if configured.
	if cfg := d.store.ActiveConfig(); cfg != nil && cfg.ForwardingOptions.DHCPRelay != nil {
		d.dhcpRelay = dhcprelay.NewManager()
		d.dhcpRelay.Apply(ctx, cfg.ForwardingOptions.DHCPRelay)
	}

	// Port mirroring
	if cfg := d.store.ActiveConfig(); cfg != nil && cfg.ForwardingOptions.PortMirroring != nil {
		for name, inst := range cfg.ForwardingOptions.PortMirroring.Instances {
			slog.Info("Port mirroring configured", "instance", name, "input", inst.Input, "output", inst.Output)
		}
	}

	// Start SNMP agent if configured (unless system processes snmp disable).
	if cfg := d.store.ActiveConfig(); cfg != nil && cfg.System.SNMP != nil && (len(cfg.System.SNMP.Communities) > 0 || len(cfg.System.SNMP.V3Users) > 0) && !isProcessDisabled(cfg, "snmpd") {
		d.snmpAgent = snmp.NewAgent(cfg.System.SNMP)
		d.snmpAgent.SetIfDataFn(func() []snmp.IfData {
			links, err := netlink.LinkList()
			if err != nil {
				return nil
			}
			var result []snmp.IfData
			for _, link := range links {
				attrs := link.Attrs()
				if attrs.Name == "lo" {
					continue
				}
				ifType := 6 // ethernetCsmacd
				switch link.Type() {
				case "vrf":
					ifType = 53 // propVirtual
				case "gre", "ip6tnl", "xfrm":
					ifType = 131 // tunnel
				case "veth":
					ifType = 53
				}
				admin := 2 // down
				if attrs.Flags&net.FlagUp != 0 {
					admin = 1
				}
				oper := 2 // down
				if attrs.OperState == netlink.OperUp || attrs.OperState == netlink.OperUnknown {
					oper = 1
				}
				speed := uint32(0)
				if attrs.TxQLen > 0 {
					speed = 1000000000 // default 1Gbps
				}
				var stats *netlink.LinkStatistics
				if attrs.Statistics != nil {
					stats = attrs.Statistics
				}
				entry := snmp.IfData{
					IfIndex:     attrs.Index,
					IfDescr:     attrs.Name,
					IfType:      ifType,
					IfMtu:       attrs.MTU,
					IfSpeed:     speed,
					AdminStatus: admin,
					OperStatus:  oper,
					IfName:      attrs.Name,
					IfHighSpeed: speed / 1_000_000, // bps -> Mbps
				}
				if stats != nil {
					entry.InOctets = uint32(stats.RxBytes)
					entry.OutOctets = uint32(stats.TxBytes)
					entry.HCInOctets = stats.RxBytes
					entry.HCInUcastPkts = stats.RxPackets
					entry.HCOutOctets = stats.TxBytes
					entry.HCOutUcastPkts = stats.TxPackets
					entry.InMulticastPkts = uint32(stats.Multicast)
				}
				result = append(result, entry)
			}
			return result
		})
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.snmpAgent.Start(ctx)
		}()

		// Start link state monitor for SNMP traps.
		if len(cfg.System.SNMP.TrapGroups) > 0 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				d.monitorLinkState(ctx)
			}()
		}
	}

	// Start policy scheduler if configured.
	if cfg := d.store.ActiveConfig(); cfg != nil && len(cfg.Schedulers) > 0 && d.dp != nil {
		d.scheduler = scheduler.New(cfg.Schedulers, func(activeState map[string]bool) {
			slog.Info("scheduler state changed, updating policy rules")
			if activeCfg := d.store.ActiveConfig(); activeCfg != nil {
				d.dp.UpdatePolicyScheduleState(activeCfg, activeState)
			}
		})
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.scheduler.Run(ctx)
		}()
	}

	// Start periodic neighbor resolution to keep ARP entries warm for
	// known forwarding targets (DNAT pools, gateways, address-book hosts).
	// Without this, bpf_fib_lookup returns NO_NEIGH when ARP expires,
	// causing cold-start delays or connection failures for return traffic.
	if !d.opts.NoDataplane {
		if cfg := d.store.ActiveConfig(); cfg != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				d.runPeriodicNeighborResolution(ctx)
			}()
		}
	}

	// Start VRRP event watcher (manager was created earlier, before applyConfig).
	// Uses context.Background() — the watcher must outlive daemon ctx cancel
	// so it can process VRRP BACKUP events during shutdown (rg_active cleanup).
	// The watcher exits when eventCh is closed by vrrpMgr.Stop().
	go d.watchVRRPEvents(context.Background())

	// Start reconciliation loop — periodic safety net that corrects
	// rg_active and blackhole route drift from dropped events.
	if d.cluster != nil {
		go d.reconcileRGStateLoop(ctx)
	}

	// Start HTTP API server if configured.
	if d.opts.APIAddr != "" {
		apiCfg := api.Config{
			Addr:     d.opts.APIAddr,
			Store:    d.store,
			DP:       d.dp,
			EventBuf: eventBuf,
			GC:       d.gc,
			Routing:  d.routing,
			FRR:      d.frr,
			IPsec:    d.ipsec,
			DHCP:     d.dhcp,
			VRRPMgr:  d.vrrpMgr,
			ApplyFn:  d.applyConfig,
		}
		// Resolve interface bindings from web-management config
		if cfg := d.store.ActiveConfig(); cfg != nil && cfg.System.Services != nil &&
			cfg.System.Services.WebManagement != nil {
			wm := cfg.System.Services.WebManagement
			// Bind HTTP to configured interface
			if wm.HTTPInterface != "" {
				bindIP := resolveInterfaceAddr(wm.HTTPInterface, "127.0.0.1")
				apiCfg.Addr = bindIP + ":8080"
				slog.Info("HTTP API bound to interface", "interface", wm.HTTPInterface, "addr", apiCfg.Addr)
			}
			// Enable HTTPS if configured
			if wm.HTTPS {
				httpsBindIP := "127.0.0.1"
				if wm.HTTPSInterface != "" {
					httpsBindIP = resolveInterfaceAddr(wm.HTTPSInterface, "127.0.0.1")
					slog.Info("HTTPS API bound to interface", "interface", wm.HTTPSInterface, "addr", httpsBindIP+":8443")
				}
				apiCfg.TLS = true
				apiCfg.HTTPSAddr = httpsBindIP + ":8443"
			}
			// API authentication
			if wm.APIAuth != nil && (len(wm.APIAuth.Users) > 0 || len(wm.APIAuth.APIKeys) > 0) {
				authCfg := &api.AuthConfig{
					Users:   make(map[string]string),
					APIKeys: make(map[string]bool),
				}
				for _, u := range wm.APIAuth.Users {
					authCfg.Users[u.Username] = u.Password
				}
				for _, k := range wm.APIAuth.APIKeys {
					authCfg.APIKeys[k] = true
				}
				apiCfg.Auth = authCfg
				slog.Info("HTTP API authentication enabled", "users", len(wm.APIAuth.Users), "api_keys", len(wm.APIAuth.APIKeys))
			}
		}
		srv := api.NewServer(apiCfg)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.Run(ctx); err != nil {
				slog.Error("API server error", "err", err)
			}
		}()
		slog.Info("HTTP API server started", "addr", d.opts.APIAddr)
	}

	// Start gRPC API server.
	{
		// Wrap applyConfig to also sync config to cluster peer after commit.
		applyAndSync := func(cfg *config.Config) {
			d.applyConfig(cfg)
			d.syncConfigToPeer()
		}
		grpcSrv := grpcapi.NewServer(d.opts.GRPCAddr, grpcapi.Config{
			Store:      d.store,
			DP:         d.dp,
			EventBuf:   eventBuf,
			GC:         d.gc,
			Routing:    d.routing,
			FRR:        d.frr,
			IPsec:      d.ipsec,
			Cluster:    d.cluster,
			DHCP:       d.dhcp,
			DHCPServer: d.dhcpServer,
			RPMResultsFn: func() []*rpm.ProbeResult {
				if d.rpm != nil {
					return d.rpm.Results()
				}
				return nil
			},
			FeedsFn: func() map[string]feeds.FeedInfo {
				if d.feeds != nil {
					return d.feeds.AllFeeds()
				}
				return nil
			},
			LLDPNeighborsFn: func() []*lldp.Neighbor {
				if d.lldpMgr != nil {
					return d.lldpMgr.Neighbors()
				}
				return nil
			},
			ApplyFn: applyAndSync,
			VRRPMgr: d.vrrpMgr,
			RAMgr:   d.ra,
			Version: d.opts.Version,
			FabricPeerAddrFn: func() []string {
				var addrs []string
				if d.syncPeerAddr != "" {
					addrs = append(addrs, d.syncPeerAddr)
				} else {
					d.fabricMu.RLock()
					if d.fabricPeerIP != nil {
						addrs = append(addrs, d.fabricPeerIP.String())
					}
					d.fabricMu.RUnlock()
				}
				if d.syncPeerAddr1 != "" {
					addrs = append(addrs, d.syncPeerAddr1)
				} else {
					d.fabricMu.RLock()
					if d.fabricPeerIP1 != nil {
						addrs = append(addrs, d.fabricPeerIP1.String())
					}
					d.fabricMu.RUnlock()
				}
				return addrs
			},
			FabricVRFDevice: func() string {
				if c := d.store.ActiveConfig(); c != nil && c.Chassis.Cluster != nil {
					cc := c.Chassis.Cluster
					if cc.ControlInterface != "" || cc.FabricInterface != "" {
						return "vrf-mgmt"
					}
				}
				return ""
			}(),
		})
		d.grpcSrv = grpcSrv
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := grpcSrv.Run(ctx); err != nil {
				slog.Error("gRPC server error", "err", err)
			}
		}()
		slog.Info("gRPC API server started", "addr", d.opts.GRPCAddr)
	}

	// Start interactive CLI or block in daemon mode
	var runErr error
	if isInteractive() {
		shell := cli.New(d.store, d.dp, eventBuf, er, d.routing, d.frr, d.ipsec, d.dhcp, d.dhcpRelay, d.cluster)
		shell.SetVersion(d.opts.Version)
		shell.SetRPMResultsFn(func() []*rpm.ProbeResult {
			if d.rpm != nil {
				return d.rpm.Results()
			}
			return nil
		})
		shell.SetFeedsFn(func() map[string]feeds.FeedInfo {
			if d.feeds != nil {
				return d.feeds.AllFeeds()
			}
			return nil
		})
		shell.SetLLDPNeighborsFn(func() []*lldp.Neighbor {
			if d.lldpMgr != nil {
				return d.lldpMgr.Neighbors()
			}
			return nil
		})
		shell.SetVRRPManager(d.vrrpMgr)
		shell.SetFabricPeer(func() []string {
			var addrs []string
			if d.syncPeerAddr != "" {
				addrs = append(addrs, d.syncPeerAddr)
			} else {
				d.fabricMu.RLock()
				if d.fabricPeerIP != nil {
					addrs = append(addrs, d.fabricPeerIP.String())
				}
				d.fabricMu.RUnlock()
			}
			if d.syncPeerAddr1 != "" {
				addrs = append(addrs, d.syncPeerAddr1)
			} else {
				d.fabricMu.RLock()
				if d.fabricPeerIP1 != nil {
					addrs = append(addrs, d.fabricPeerIP1.String())
				}
				d.fabricMu.RUnlock()
			}
			return addrs
		}, func() string {
			if c := d.store.ActiveConfig(); c != nil && c.Chassis.Cluster != nil {
				cc := c.Chassis.Cluster
				if cc.ControlInterface != "" || cc.FabricInterface != "" {
					return "vrf-mgmt"
				}
			}
			return ""
		}())

		// Set RBAC login class from config (default to super-user if user not found)
		if cfg := d.store.ActiveConfig(); cfg != nil && cfg.System.Login != nil {
			osUser := os.Getenv("USER")
			found := false
			for _, u := range cfg.System.Login.Users {
				if u.Name == osUser {
					shell.SetUserClass(u.Class)
					found = true
					break
				}
			}
			if !found {
				shell.SetUserClass("super-user")
			}
		}

		// Run CLI in a goroutine so we can still handle signals
		errCh := make(chan error, 1)
		go func() {
			errCh <- shell.Run()
		}()

		select {
		case err := <-errCh:
			if err != nil {
				runErr = fmt.Errorf("CLI: %w", err)
			}
		case <-ctx.Done():
			slog.Info("signal received, shutting down")
		}
	} else {
		slog.Info("daemon mode (non-interactive), waiting for signals")
		<-ctx.Done()
		slog.Info("signal received, shutting down")
	}

	// Cancel context to stop background goroutines, then wait for them.
	stop()
	wg.Wait()

	// Clean up flow exporters.
	d.stopFlowExporter()
	d.stopIPFIXExporter()

	// Clean up dynamic address feeds.
	if d.feeds != nil {
		d.feeds.StopAll()
	}

	// Clean up RPM probes.
	if d.rpm != nil {
		d.rpm.StopAll()
	}

	// Clean up LLDP.
	if d.lldpMgr != nil {
		d.lldpMgr.Stop()
	}

	// Determine shutdown mode early so we can clear rg_active BEFORE
	// stopping subsystems (VRRP, sync) that may hang.
	cfg := d.store.ActiveConfig()
	haMode := cfg != nil && cfg.Chassis.Cluster != nil
	hitless := !haMode // standalone = hitless by default
	if haMode && cfg.Chassis.Cluster.HitlessRestart {
		hitless = true // operator explicitly opted in
	}

	// In HA fail-closed mode, clear rg_active and watchdog immediately so
	// BPF stops forwarding traffic even if subsequent cleanup steps hang.
	if !hitless && d.dp != nil && cfg.Chassis.Cluster != nil {
		slog.Info("HA shutdown: clearing rg_active for all RGs")
		for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
			if err := d.dp.UpdateRGActive(rg.ID, false); err != nil {
				slog.Warn("failed to clear rg_active on shutdown", "rg", rg.ID, "err", err)
			}
			if err := d.dp.UpdateHAWatchdog(rg.ID, 0); err != nil {
				slog.Warn("failed to clear ha_watchdog on shutdown", "rg", rg.ID, "err", err)
			}
		}
	}

	// Withdraw RA senders (sends goodbye RAs with lifetime=0) before VRRP
	// stop so hosts immediately stop using this node as a default router.
	if d.ra != nil {
		if err := d.ra.Withdraw(); err != nil {
			slog.Warn("shutdown: failed to withdraw RA senders", "err", err)
		}
	}

	// Direct-mode: remove VIPs before VRRP stop (VRRP won't manage them).
	if d.isNoRethVRRP() && cfg.Chassis.Cluster != nil {
		for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
			d.directRemoveVIPs(rg.ID)
		}
	}

	// Stop VRRP manager (removes VIPs, sends priority-0).
	if d.vrrpMgr != nil {
		d.vrrpMgr.Stop()
	}

	// Stop cluster monitor (heartbeats) immediately after VRRP priority-0.
	// This ensures the peer's heartbeat timeout starts promptly instead of
	// being delayed by the 5s sync Stop timeout below.
	if d.cluster != nil {
		d.cluster.Stop()
	}

	// Stop session sync (5s timeout to avoid blocking teardown).
	if d.sessionSync != nil {
		d.stopSyncReadyTimer()
		d.sessionSync.Stop()
	}

	if d.dp != nil {
		logFinalStats(d.dp)
		if hitless {
			// Hitless: close Go handles only — BPF programs keep running.
			slog.Info("hitless shutdown: preserving BPF state")
			d.dp.Close()
		} else {
			// Fail-closed: tear down all pinned BPF state.
			slog.Info("HA shutdown: tearing down BPF state")
			d.dp.Teardown()
		}
	}

	slog.Info("shutdown complete")
	return runErr
}

// isInteractive returns true if stdin is a real terminal (not /dev/null or a pipe).
// enableForwarding enables IPv4 and IPv6 forwarding via sysctl
// and disables RA acceptance on all interfaces.
// A firewall must forward packets between interfaces; without this,
// the kernel drops all transit traffic. A firewall must not accept
// RAs — it uses its own configured routes exclusively.
func enableForwarding() {
	sysctls := map[string]string{
		"/proc/sys/net/ipv4/ip_forward":             "1",
		"/proc/sys/net/ipv6/conf/all/forwarding":    "1",
		"/proc/sys/net/ipv6/conf/all/accept_ra":     "0",
		"/proc/sys/net/ipv6/conf/default/accept_ra": "0",
		// l3mdev_accept: allow accepting TCP/UDP connections on management VRF
		// interfaces from sockets not bound to the VRF (needed for SSH).
		"/proc/sys/net/ipv4/tcp_l3mdev_accept": "1",
		"/proc/sys/net/ipv4/udp_l3mdev_accept": "1",
		// accept_local: allow packets with a source IP that is local to the
		// machine on a different interface. Required when XDP SNAT rewrites
		// src to a tunnel endpoint IP and XDP_PASS to kernel for routing —
		// kernel would otherwise reject the packet as a martian.
		"/proc/sys/net/ipv4/conf/all/accept_local": "1",
	}
	for path, val := range sysctls {
		if err := os.WriteFile(path, []byte(val), 0644); err != nil {
			slog.Warn("failed to set sysctl", "path", path, "err", err)
		}
	}
	slog.Info("IP forwarding enabled, RA acceptance disabled")
}

// fixRethLinkFile rewrites the .link file for a RETH member to use
// OriginalName= (the kernel name) instead of MACAddress= for matching.
// This ensures the .link works on reboot when the MAC reverts to physical.
func fixRethLinkFile(ifName, kernelName string) {
	path := fmt.Sprintf("/etc/systemd/network/10-bpfrx-%s.link", ifName)
	content := fmt.Sprintf("# Managed by bpfrxd — do not edit\n[Match]\nOriginalName=%s\n\n[Link]\nName=%s\n", kernelName, ifName)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		slog.Warn("failed to fix RETH .link file", "path", path, "err", err)
	}
}

// ensureRethLinkOriginalName checks that a RETH member's .link file uses
// OriginalName= (PCI kernel name) instead of MACAddress=. If the file still
// uses MACAddress=, it derives the kernel name and rewrites the file. This
// handles bootstrap .link files that were created before the daemon ran.
func ensureRethLinkOriginalName(ifName string) {
	path := fmt.Sprintf("/etc/systemd/network/10-bpfrx-%s.link", ifName)
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	content := string(data)
	if !strings.Contains(content, "MACAddress=") {
		return // already uses OriginalName= or other match
	}
	// Derive kernel name from altnames or sysfs
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return
	}
	var kernelName string
	for _, alt := range link.Attrs().AltNames {
		if strings.HasPrefix(alt, "enp") || strings.HasPrefix(alt, "eno") ||
			strings.HasPrefix(alt, "ens") || strings.HasPrefix(alt, "eth") {
			kernelName = alt
			break
		}
	}
	if kernelName == "" {
		kernelName = deriveKernelName(ifName)
	}
	if kernelName == "" {
		return
	}
	slog.Info("fixing RETH .link file to use OriginalName",
		"iface", ifName, "kernelName", kernelName)
	fixRethLinkFile(ifName, kernelName)
}

// deriveKernelName returns the predictable kernel name (e.g. enp8s0) for an
// interface by examining its sysfs device path. Handles both PCI-direct
// devices (device → 0000:09:00.0) and virtio-over-PCI (device → virtioN,
// parent → 0000:08:00.0).
func deriveKernelName(ifName string) string {
	devPath, err := filepath.EvalSymlinks(fmt.Sprintf("/sys/class/net/%s/device", ifName))
	if err != nil {
		return ""
	}
	pciAddr := pciAddrFromPath(devPath)
	if pciAddr == "" {
		// Virtio: device is virtioN, parent directory is the PCI device
		parent := filepath.Dir(devPath)
		pciAddr = pciAddrFromPath(parent)
	}
	if pciAddr == "" {
		return ""
	}
	return pciAddrToEnp(pciAddr)
}

// pciAddrFromPath extracts a PCI address (domain:bus:slot.fn) from a sysfs
// path basename. Returns "" if the basename is not a PCI address.
func pciAddrFromPath(path string) string {
	base := filepath.Base(path)
	// PCI addresses look like "0000:08:00.0"
	parts := strings.SplitN(base, ":", 3)
	if len(parts) != 3 {
		return ""
	}
	// Validate slot.fn exists
	if !strings.Contains(parts[2], ".") {
		return ""
	}
	return base
}

// pciAddrToEnp converts a PCI address like "0000:08:00.0" to a predictable
// network name like "enp8s0".
func pciAddrToEnp(pciAddr string) string {
	parts := strings.SplitN(pciAddr, ":", 3)
	if len(parts) != 3 {
		return ""
	}
	bus, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return ""
	}
	sf := strings.SplitN(parts[2], ".", 2)
	if len(sf) != 2 {
		return ""
	}
	slot, err := strconv.ParseUint(sf[0], 16, 16)
	if err != nil {
		return ""
	}
	fn, err := strconv.ParseUint(sf[1], 16, 8)
	if err != nil {
		return ""
	}
	if fn > 0 {
		return fmt.Sprintf("enp%ds%df%d", bus, slot, fn)
	}
	return fmt.Sprintf("enp%ds%d", bus, slot)
}

// renameRethMember finds an interface by its RETH virtual MAC and renames it
// to the expected config name. Returns the old kernel name if renamed, or "".
// The interface must be DOWN for the rename to succeed.
func renameRethMember(targetName string, expectedMAC net.HardwareAddr) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if !bytes.Equal(iface.HardwareAddr, expectedMAC) || iface.Name == targetName {
			continue
		}
		link, err := netlink.LinkByIndex(iface.Index)
		if err != nil {
			return ""
		}
		// Ensure interface is DOWN for rename.
		netlink.LinkSetDown(link)
		if err := netlink.LinkSetName(link, targetName); err != nil {
			slog.Warn("failed to rename RETH member",
				"from", iface.Name, "to", targetName, "err", err)
			return ""
		}
		return iface.Name
	}
	return ""
}

// programRethMAC sets a deterministic virtual MAC on a RETH member interface.
// Skips if the interface already has the correct MAC.
// The interface must be brought DOWN to change its MAC, then back UP.
func programRethMAC(ifName string, mac net.HardwareAddr) (linkCycled bool, err error) {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return false, fmt.Errorf("interface %s: %w", ifName, err)
	}
	current := link.Attrs().HardwareAddr
	if bytes.Equal(current, mac) {
		return false, nil
	}
	slog.Info("setting RETH virtual MAC", "iface", ifName, "mac", mac)
	// Try setting MAC while link is UP (avoids link DOWN/UP cycle).
	// mlx5 zero-copy AF_XDP sockets break on link cycle — the driver
	// doesn't reinitialize XSK WQEs after link UP. If the driver
	// supports IFF_LIVE_ADDR_CHANGE, this succeeds without any cycle.
	if err := netlink.LinkSetHardwareAddr(link, mac); err == nil {
		slog.Info("RETH MAC set without link cycle", "iface", ifName)
		return false, nil
	}
	// Fallback: bring link down, set MAC, bring back up.
	slog.Info("RETH MAC requires link cycle (driver does not support live change)",
		"iface", ifName)
	if err := netlink.LinkSetDown(link); err != nil {
		return false, fmt.Errorf("link down %s: %w", ifName, err)
	}
	if err := netlink.LinkSetHardwareAddr(link, mac); err != nil {
		netlink.LinkSetUp(link) // best-effort restore
		return false, fmt.Errorf("set mac %s: %w", ifName, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return true, fmt.Errorf("link up %s: %w", ifName, err)
	}
	return true, nil
}

// clearDadFailed removes any dadfailed link-local IPv6 addresses and re-adds
// them with IFA_F_NODAD so they become usable. This handles the case where the
// virtual MAC was already set but accept_dad wasn't disabled at that time.
func clearDadFailed(ifName string) {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return
	}
	for _, addr := range addrs {
		if !addr.IP.IsLinkLocalUnicast() {
			continue
		}
		if addr.Flags&unix.IFA_F_DADFAILED == 0 {
			continue
		}
		// Remove the dadfailed address and re-add with NODAD.
		netlink.AddrDel(link, &addr)
		addr.Flags = unix.IFA_F_NODAD
		if err := netlink.AddrAdd(link, &addr); err != nil {
			slog.Warn("failed to re-add link-local with NODAD", "iface", ifName, "err", err)
		} else {
			slog.Info("cleared dadfailed link-local", "iface", ifName, "addr", addr.IP)
		}
	}
}

// removeAutoLinkLocal removes the kernel auto-generated link-local IPv6 address
// from a RETH member interface. With addr_gen_mode=1 set, no new link-local will
// be created on link-up, but a stale one may remain from before the sysctl change.
func removeAutoLinkLocal(ifName string) {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return
	}
	for _, addr := range addrs {
		if addr.IP.IsLinkLocalUnicast() {
			// Preserve stable router link-locals managed by addStableRethLinkLocal.
			if cluster.IsStableRethLinkLocal(addr.IP) {
				continue
			}
			if err := netlink.AddrDel(link, &addr); err == nil {
				slog.Info("removed auto link-local from RETH member", "iface", ifName, "addr", addr.IP)
			}
		}
	}
}

// ensureRethLinkLocal adds a link-local IPv6 address to a RETH member
// interface (or its VLAN sub-interface) if one is missing. RETH interfaces
// have addr_gen_mode=1 to suppress MLDv2 noise, but the kernel needs a
// link-local source address for NDP Neighbor Solicitations when forwarding
// IPv6 traffic to on-link destinations. Without this, bpf_fib_lookup returns
// NO_NEIGH and the kernel can never resolve the neighbor.
//
// Computes EUI-64 link-local from the interface MAC and adds it with NODAD.
func ensureRethLinkLocal(ifName string) {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return
	}
	mac := link.Attrs().HardwareAddr
	if len(mac) != 6 {
		return
	}
	// Check if link-local already exists.
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return
	}
	for _, a := range addrs {
		if a.IP.IsLinkLocalUnicast() {
			return // already have one
		}
	}

	// Compute EUI-64 link-local from MAC.
	ll := net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0,
		mac[0] ^ 0x02, mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5]}
	addr := &netlink.Addr{
		IPNet: &net.IPNet{IP: ll, Mask: net.CIDRMask(64, 128)},
		Flags: unix.IFA_F_NODAD,
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		slog.Warn("failed to add link-local to RETH interface",
			"iface", ifName, "addr", ll, "err", err)
	} else {
		slog.Info("added link-local for NDP on RETH interface",
			"iface", ifName, "addr", ll)
	}
}

// rethUnitHasConfiguredLinkLocal checks whether the RETH config has an
// explicitly configured link-local IPv6 address (fe80::/10) on the given unit.
func rethUnitHasConfiguredLinkLocal(rethCfg *config.InterfaceConfig, unitNum int) bool {
	unit, ok := rethCfg.Units[unitNum]
	if !ok {
		return false
	}
	for _, addr := range unit.Addresses {
		ip, _, err := net.ParseCIDR(addr)
		if err != nil {
			continue
		}
		if ip.IsLinkLocalUnicast() && ip.To4() == nil {
			return true
		}
	}
	return false
}

// rethUnitHasIPv6 checks whether the RETH config has IPv6 addresses on the
// given unit number (VLAN ID). Unit 0 is the native/untagged interface.
func rethUnitHasIPv6(rethCfg *config.InterfaceConfig, unitNum int) bool {
	unit, ok := rethCfg.Units[unitNum]
	if !ok {
		return false
	}
	for _, addr := range unit.Addresses {
		if strings.Contains(addr, ":") {
			return true
		}
	}
	return unit.DHCPv6
}

func isInteractive() bool {
	_, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS)
	return err == nil
}

// resolveInterfaceAddr returns the first IPv4 address on the named interface.
// If the interface is not found or has no IPv4 addresses, it returns fallback.
func resolveInterfaceAddr(ifname, fallback string) string {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		slog.Warn("web-management interface not found, using fallback", "interface", ifname, "fallback", fallback)
		return fallback
	}
	addrs, err := iface.Addrs()
	if err != nil || len(addrs) == 0 {
		slog.Warn("web-management interface has no addresses, using fallback", "interface", ifname, "fallback", fallback)
		return fallback
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ip4 := ipNet.IP.To4(); ip4 != nil {
			return ip4.String()
		}
	}
	// No IPv4, try IPv6
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ipNet.IP.To4() == nil {
			return ipNet.IP.String()
		}
	}
	slog.Warn("web-management interface has no usable addresses, using fallback", "interface", ifname, "fallback", fallback)
	return fallback
}

// applyConfig applies a compiled config in the correct order:
// 0. Create VRF devices and bind interfaces (routing instances)
// bootstrapFromFile reads the text Junos config file and imports it as the
// initial active configuration. This is called on first start when the DB
// has no active config yet.
func (d *Daemon) bootstrapFromFile() error {
	data, err := os.ReadFile(d.opts.ConfigFile)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}

	// Import into the store: enter config mode, load, commit.
	// Commit() handles compilation (including ${node} variable expansion
	// when nodeID is set on the store for cluster mode).
	if err := d.store.EnterConfigure(); err != nil {
		return fmt.Errorf("enter configure: %w", err)
	}
	if err := d.store.LoadOverride(string(data)); err != nil {
		d.store.ExitConfigure()
		return fmt.Errorf("load override: %w", err)
	}
	if _, err := d.store.Commit(); err != nil {
		d.store.ExitConfigure()
		return fmt.Errorf("commit: %w", err)
	}
	d.store.ExitConfigure()
	slog.Info("configuration bootstrapped from file", "file", d.opts.ConfigFile)
	return nil
}

// 1. Create tunnels (so interfaces exist for zone binding)
// 2. Compile eBPF (attaches XDP/TC to interfaces including tunnels)
// 3. Install static routes (global + per-instance)
// 4. Apply FRR config (OSPF/BGP, global + per-VRF)
// 5. Apply IPsec config (strongSwan)
func (d *Daemon) applyConfig(cfg *config.Config) {
	// Reset VIP warning suppression so new config gets fresh warnings.
	d.vipWarnedIfaces = nil

	// Log config validation warnings
	for _, w := range cfg.Warnings {
		slog.Warn("config validation", "warning", w)
	}

	// 0. Create VRF devices for routing instances (skip forwarding type)
	if d.routing != nil && len(cfg.RoutingInstances) > 0 {
		if err := d.routing.ClearVRFs(); err != nil {
			slog.Warn("failed to clear previous VRFs", "err", err)
		}
		for _, ri := range cfg.RoutingInstances {
			if ri.InstanceType == "forwarding" {
				slog.Info("forwarding instance, skipping VRF creation",
					"instance", ri.Name)
				continue
			}
			if err := d.routing.CreateVRF(ri.Name, ri.TableID); err != nil {
				slog.Warn("failed to create VRF",
					"instance", ri.Name, "table", ri.TableID, "err", err)
				continue
			}
			for _, ifaceName := range ri.Interfaces {
				// Convert Junos name (gr-0/0/0.0) to Linux name (gr-0-0-0).
				// Strip ".0" unit suffix — unit 0 is the base interface.
				linuxName := config.LinuxIfName(ifaceName)
				if strings.HasSuffix(linuxName, ".0") {
					linuxName = strings.TrimSuffix(linuxName, ".0")
				}
				if err := d.routing.BindInterfaceToVRF(linuxName, ri.Name); err != nil {
					slog.Warn("failed to bind interface to VRF",
						"interface", ifaceName, "linux", linuxName,
						"instance", ri.Name, "err", err)
				}
			}
		}
	}

	// 0.5. Create management VRF for fxp* interfaces.
	// Management/control interfaces (fxp0, fxp1, fab0) are placed in a separate
	// routing instance so their DHCP/static routes don't pollute the data-plane
	// routing table. This mirrors Junos __juniper_private1/2__ instances.
	d.mgmtVRFInterfaces = nil
	if d.routing != nil {
		mgmtIfaces := make(map[string]bool)
		for name := range cfg.Interfaces.Interfaces {
			if strings.HasPrefix(name, "fxp") || strings.HasPrefix(name, "fab") || strings.HasPrefix(name, "em") {
				mgmtIfaces[config.LinuxIfName(name)] = true
			}
		}
		if len(mgmtIfaces) > 0 {
			const mgmtVRFName = "mgmt"
			const mgmtTableID = 999
			if err := d.routing.CreateVRF(mgmtVRFName, mgmtTableID); err != nil {
				slog.Warn("failed to create management VRF", "err", err)
			} else {
				d.mgmtVRFInterfaces = mgmtIfaces
				for ifName := range mgmtIfaces {
					if err := d.routing.BindInterfaceToVRF(ifName, mgmtVRFName); err != nil {
						slog.Warn("failed to bind interface to management VRF",
							"interface", ifName, "err", err)
					}
				}
			}
		}
	}

	// 0.6. Program default routes in the management VRF for DHCP leases.
	d.applyMgmtVRFRoutes()

	// 1. Create tunnel interfaces (interface-level + per-unit tunnels)
	if d.routing != nil {
		if err := d.routing.ApplyTunnels(collectAppliedTunnels(cfg)); err != nil {
			slog.Warn("failed to apply tunnels", "err", err)
		}
	}

	// 1.5. Create xfrmi interfaces for IPsec VPN tunnels.
	// Must happen before BPF compilation so compileZones() can discover
	// the xfrmi interfaces and map them to security zones.
	// Always call ApplyXfrmi so stale xfrmi devices are removed when VPNs
	// are deleted from config.
	if d.routing != nil {
		if err := d.routing.ApplyXfrmi(cfg.Security.IPsec.VPNs); err != nil {
			slog.Warn("failed to apply xfrmi interfaces", "err", err)
		}
	}

	// 1.7. Create bond (LAG) interfaces for fabric-options member-interfaces.
	// Always call ApplyBonds (even with empty list) so stale bonds from
	// previous configs get cleaned up via ClearBonds().
	if d.routing != nil {
		var bondIfaces []*config.InterfaceConfig
		for _, ifc := range cfg.Interfaces.Interfaces {
			if len(ifc.FabricMembers) > 0 {
				bondIfaces = append(bondIfaces, ifc)
			}
		}
		if err := d.routing.ApplyBonds(bondIfaces); err != nil {
			slog.Warn("failed to apply bonds", "err", err)
		}
	}

	// 1.8. Clean up legacy RETH bond devices from previous binary versions.
	// VRRP now runs directly on physical member interfaces — no bonds needed.
	if d.routing != nil {
		d.routing.ClearRethInterfaces()
	}

	// 1.9. Create IPVLAN interfaces for fabric members (fab0, fab1).
	// The physical member (ge-0-0-0) keeps its name; fab0 is IPVLAN L2
	// on top for IP addressing. BPF attaches to the parent.
	// Track which overlays are configured so stale ones can be cleaned up (#128).
	//
	// When the userspace dataplane is active, DEFER IPVLAN creation until
	// after XSK binds complete. The kernel checks for upper devices (like
	// IPVLAN) at XSK bind time — if an IPVLAN exists, zerocopy bind fails
	// and falls back to copy mode (~3 Gbps). Deferring lets the fabric
	// parent bind XSK in zerocopy first, then the IPVLAN is added for
	// sync/heartbeat addressing.
	activeFabricOverlays := make(map[string]bool)
	type deferredIPVLAN struct {
		parent string
		name   string
		addrs  []string
	}
	var deferredOverlays []deferredIPVLAN
	_, isUserspaceDP := d.dp.(*dpuserspace.Manager)
	for ifName, ifCfg := range cfg.Interfaces.Interfaces {
		if ifCfg.LocalFabricMember == "" || !strings.HasPrefix(ifName, "fab") {
			continue
		}
		parentLinux := config.LinuxIfName(ifCfg.LocalFabricMember)
		fabLinux := config.LinuxIfName(ifName)
		activeFabricOverlays[fabLinux] = true
		var addrs []string
		if unit, ok := ifCfg.Units[0]; ok {
			addrs = unit.Addresses
		}
		// When userspace DP is active, remove any existing IPVLAN and
		// defer recreation until after XSK binds in zerocopy. The kernel
		// checks for upper devices at bind time — IPVLAN blocks zerocopy.
		// On subsequent applyConfig calls (config change), the IPVLAN
		// already exists from the OnXSKBound callback and XSK is already
		// bound, so the xskBoundNotified guard prevents re-deletion.
		if isUserspaceDP {
			if um, ok := d.dp.(*dpuserspace.Manager); ok && !um.XSKBoundNotified() {
				// First applyConfig — remove stale IPVLAN so XSK can zerocopy.
				if link, err := netlink.LinkByName(fabLinux); err == nil {
					netlink.LinkDel(link)
					slog.Info("removed fabric IPVLAN for deferred zerocopy XSK bind",
						"name", fabLinux)
				}
				deferredOverlays = append(deferredOverlays, deferredIPVLAN{
					parent: parentLinux, name: fabLinux, addrs: addrs,
				})
				slog.Info("deferring fabric IPVLAN creation until XSK binds complete",
					"parent", parentLinux, "name", fabLinux)
				// continue // DISABLED: deferred IPVLAN broke forwarding
			}
			// XSK already bound — fall through to reconcile.
		}
		if err := ensureFabricIPVLAN(parentLinux, fabLinux, addrs); err != nil {
			// Fabric overlay is critical for cluster heartbeat and VRRP.
			// Retry up to 5 times with 1s delay — the parent interface
			// might not be ready yet after a power cycle.
			var retryErr error
			for retry := 0; retry < 5; retry++ {
				time.Sleep(time.Second)
				slog.Info("retrying fabric IPVLAN creation",
					"parent", parentLinux, "name", fabLinux, "attempt", retry+2)
				retryErr = ensureFabricIPVLAN(parentLinux, fabLinux, addrs)
				if retryErr == nil {
					break
				}
			}
			if retryErr != nil {
				slog.Error("CRITICAL: fabric IPVLAN creation failed after retries — cluster heartbeat will not work",
					"parent", parentLinux, "name", fabLinux, "err", retryErr)
			}
			continue
		}
	}
	// Register deferred IPVLAN creation callback on the userspace manager.
	if len(deferredOverlays) > 0 {
		if um, ok := d.dp.(*dpuserspace.Manager); ok {
			um.OnXSKBound = func() {
				for _, ov := range deferredOverlays {
					slog.Info("XSK bound — creating deferred fabric IPVLAN",
						"parent", ov.parent, "name", ov.name)
					if err := ensureFabricIPVLAN(ov.parent, ov.name, ov.addrs); err != nil {
						slog.Error("deferred fabric IPVLAN creation failed",
							"parent", ov.parent, "name", ov.name, "err", err)
					}
				}
			}
		}
	}
	// Clean up stale fabric IPVLAN overlays not in current config (#128).
	for _, name := range []string{"fab0", "fab1"} {
		if activeFabricOverlays[name] {
			continue
		}
		if link, err := netlink.LinkByName(name); err == nil {
			if _, ok := link.(*netlink.IPVlan); ok {
				netlink.LinkDel(link)
				slog.Info("removed stale fabric IPVLAN", "name", name)
			}
		}
	}

	// 1.9. Pre-check: will RETH MAC programming require a link cycle?
	// If yes, tell the userspace DP to skip initial worker startup during
	// Compile(). Workers will be started by NotifyLinkCycle() after MAC
	// programming is done. This avoids the double-bind that causes EBUSY
	// on mlx5 zero-copy queues.
	rethMACPending := false
	if d.cluster != nil && cfg.Chassis.Cluster != nil && d.dp != nil {
		cc := cfg.Chassis.Cluster
		for rethName, physName := range cfg.RethToPhysical() {
			rethCfg, ok := cfg.Interfaces.Interfaces[rethName]
			if !ok || rethCfg.RedundancyGroup <= 0 {
				continue
			}
			linuxName := config.LinuxIfName(physName)
			link, err := netlink.LinkByName(linuxName)
			if err != nil {
				continue
			}
			mac := cluster.RethMAC(cc.ClusterID, rethCfg.RedundancyGroup, cc.NodeID)
			if !bytes.Equal(link.Attrs().HardwareAddr, mac) {
				rethMACPending = true
				break
			}
		}
		if rethMACPending {
			type deferSetter interface{ SetDeferWorkers(bool) }
			if ds, ok := d.dp.(deferSetter); ok {
				ds.SetDeferWorkers(true)
			}
		}
	}

	// 2. Compile eBPF dataplane
	var compileResult *dataplane.CompileResult
	if d.dp != nil {
		var err error
		if compileResult, err = d.dp.Compile(cfg); err != nil {
			slog.Warn("failed to compile dataplane", "err", err)
		}
	}

	// Clear defer flag after Compile so subsequent recompiles (where MAC
	// is already set) don't skip workers.
	if rethMACPending {
		type deferSetter interface{ SetDeferWorkers(bool) }
		if ds, ok := d.dp.(deferSetter); ok {
			ds.SetDeferWorkers(false)
		}
	}

	// 2.1. Wire aggressive session aging config to GC.
	if d.gc != nil {
		d.gc.SetAgingConfig(
			cfg.Security.Flow.AgingEarlyAgeout,
			cfg.Security.Flow.AgingHighWatermark,
			cfg.Security.Flow.AgingLowWatermark,
		)

		// Enable per-IP session counting if any screen profile has session limits.
		sessionLimitEnabled := false
		for _, sp := range cfg.Security.Screen {
			if sp.LimitSession.SourceIPBased > 0 || sp.LimitSession.DestinationIPBased > 0 {
				sessionLimitEnabled = true
				break
			}
		}
		d.gc.SetSessionLimitEnabled(sessionLimitEnabled)
	}

	// 2.2. Build zone→RG map for per-RG session sync.
	if d.sessionSync != nil && compileResult != nil {
		d.sessionSync.SetZoneRGMap(buildZoneRGMap(cfg, compileResult.ZoneIDs))
	}

	// 2.5. Write systemd-networkd config for managed interfaces
	if d.networkd != nil && compileResult != nil && len(compileResult.ManagedInterfaces) > 0 {
		if err := d.networkd.Apply(compileResult.ManagedInterfaces); err != nil {
			slog.Warn("failed to apply networkd config", "err", err)
		}
	}

	// 2.6. Program deterministic virtual MACs on RETH member interfaces.
	// Each node gets a per-node MAC (02:bf:72:CC:RR:NN) to avoid FDB conflicts
	// when both nodes' members are on the same L2 domain. VRRP + gratuitous NA
	// handle failover; RA goodbye packets handle IPv6 default gateway transitions.
	// Must run AFTER networkd.Apply() so .link renames are applied first.
	needLinkCycleRecovery := false
	if d.cluster != nil && cfg.Chassis.Cluster != nil {
		cc := cfg.Chassis.Cluster
		rethToPhys := cfg.RethToPhysical()

		// PrepareLinkCycle is called on-demand after programRethMAC reports
		// an actual link DOWN/UP cycle. Most drivers (mlx5, virtio) support
		// IFF_LIVE_ADDR_CHANGE so no cycle is needed and workers keep running.

		for rethName, physName := range rethToPhys {
			rethCfg, ok := cfg.Interfaces.Interfaces[rethName]
			if !ok || rethCfg.RedundancyGroup <= 0 {
				continue
			}
			linuxName := config.LinuxIfName(physName)
			// If the interface doesn't exist under its config name,
			// find it by RETH virtual MAC and rename it.
			if _, err := netlink.LinkByName(linuxName); err != nil {
				mac := cluster.RethMAC(cc.ClusterID, rethCfg.RedundancyGroup, cc.NodeID)
				if oldName := renameRethMember(linuxName, mac); oldName != "" {
					slog.Info("renamed RETH member interface",
						"from", oldName, "to", linuxName)
					fixRethLinkFile(linuxName, oldName)
				}
			}
			// Ensure the .link file uses OriginalName= (not MACAddress=)
			// for stable matching across reboots. The bootstrap .link
			// files may use MACAddress= which breaks after virtual MAC
			// programming — the interface reboots with physical MAC but
			// the MACAddress= line might reference the wrong one.
			ensureRethLinkOriginalName(linuxName)
			// Disable DAD — virtual MAC may still collide with peer on
			// some deployments; disable to avoid DAD failures.
			dadPath := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/accept_dad", linuxName)
			os.WriteFile(dadPath, []byte("0"), 0644)
			// Suppress auto link-local generation on RETH member interfaces.
			// The virtual MAC triggers a kernel-generated link-local (fe80::...)
			// which causes continuous MLDv2 multicast reports on the L2 segment.
			// VIPs are managed explicitly; auto link-locals are unnecessary.
			addrGenPath := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/addr_gen_mode", linuxName)
			os.WriteFile(addrGenPath, []byte("1"), 0644)
			mac := cluster.RethMAC(cc.ClusterID, rethCfg.RedundancyGroup, cc.NodeID)
			linkCycled, err := programRethMAC(linuxName, mac)
			if err != nil {
				slog.Warn("failed to set RETH MAC", "iface", linuxName, "mac", mac, "err", err)
			}
			if linkCycled && !needLinkCycleRecovery {
				// First link cycle — stop workers NOW (they may have
				// been accessing UMEM during the DOWN/UP). The rebind
				// in NotifyLinkCycle will restart them.
				if d.dp != nil {
					type linkCyclePreparer interface{ PrepareLinkCycle() }
					if preparer, ok := d.dp.(linkCyclePreparer); ok {
						slog.Info("userspace: stopping workers after RETH MAC link cycle")
						preparer.PrepareLinkCycle()
					}
				}
			}
			needLinkCycleRecovery = needLinkCycleRecovery || linkCycled
			clearDadFailed(linuxName)
			removeAutoLinkLocal(linuxName)
			// Re-add link-local if this parent interface has IPv6 on unit 0.
			// NDP Neighbor Solicitation requires a link-local source address.
			if rethUnitHasIPv6(rethCfg, 0) {
				ensureRethLinkLocal(linuxName)
			}

			// Re-disable VLAN RX offload after MAC programming.
			// The iavf VF driver resets ethtool features (including
			// rx-vlan-offload) during the link down/up cycle that
			// programRethMAC requires. Without this, XDP cannot see
			// VLAN tags in the packet data and drops VLAN traffic.
			if out, err := exec.Command("ethtool", "-K", linuxName, "rxvlan", "off").CombinedOutput(); err != nil {
				slog.Warn("failed to re-disable rxvlan after RETH MAC",
					"interface", linuxName, "err", err, "output", strings.TrimSpace(string(out)))
			} else {
				slog.Info("re-disabled VLAN RX offload after RETH MAC", "interface", linuxName)
			}

			// Propagate MAC change to VLAN sub-interfaces.
			// Linux VLAN sub-interfaces don't always inherit the
			// parent's MAC change after link down/up.
			if parentLink, err := netlink.LinkByName(linuxName); err == nil {
				parentIdx := parentLink.Attrs().Index
				links, _ := netlink.LinkList()
				for _, l := range links {
					if l.Attrs().ParentIndex != parentIdx {
						continue
					}
					subName := l.Attrs().Name
					// Suppress auto link-local on VLAN sub-interfaces too.
					subAddrGen := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/addr_gen_mode", subName)
					os.WriteFile(subAddrGen, []byte("1"), 0644)
					if !bytes.Equal(l.Attrs().HardwareAddr, mac) {
						if err := netlink.LinkSetHardwareAddr(l, mac); err != nil {
							slog.Warn("failed to propagate MAC to VLAN sub-interface",
								"iface", subName, "err", err)
						} else {
							slog.Info("propagated RETH MAC to VLAN sub-interface",
								"iface", subName, "mac", mac)
						}
					}
					removeAutoLinkLocal(subName)
					// Re-add link-local if this VLAN sub-interface has IPv6.
					// Extract VLAN ID from sub-interface name (e.g. "ge-7-0-1.100").
					if dotIdx := strings.LastIndex(subName, "."); dotIdx >= 0 {
						if vid, err := strconv.Atoi(subName[dotIdx+1:]); err == nil {
							if rethUnitHasIPv6(rethCfg, vid) {
								ensureRethLinkLocal(subName)
							}
						}
					}
				}
			}
		}
	}

	// 2.6b. Reconcile VRRP VIPs and stable link-locals after RETH MAC
	// programming. Only needed when programRethMAC had to bring the
	// interface DOWN/UP (link cycle), which removes all addresses
	// including VRRP VIPs and stable link-locals.
	if needLinkCycleRecovery && d.isNoRethVRRP() {
		// Direct mode: re-add VIPs + stable link-locals for each RG
		// where we are primary.
		if d.cluster != nil {
			for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
				if d.cluster.IsLocalPrimary(rg.ID) {
					d.directAddVIPs(rg.ID)
					d.addStableRethLinkLocal(rg.ID)
					d.scheduleDirectAnnounce(rg.ID, "link-cycle-recovery")
				}
			}
		}
	} else if needLinkCycleRecovery && d.vrrpMgr != nil {
		d.vrrpMgr.ReconcileVIPs()
		// Re-add stable link-locals for active RGs after MAC bounce.
		if d.cluster != nil && cfg.Chassis.Cluster != nil {
			for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
				s := d.getOrCreateRGState(rg.ID)
				if s.IsActive() {
					d.addStableRethLinkLocal(rg.ID)
				}
			}
		}
	}

	// 2.6b2. Rebind AF_XDP sockets after RETH MAC programming.
	// Only needed when PrepareLinkCycle was called (macChangeNeeded=true
	// or rethMACPending=true). Calling NotifyLinkCycle without a prior
	// PrepareLinkCycle causes a spurious rebind that gets EBUSY on mlx5
	// zero-copy queues because the first bind is still in progress.
	if d.dp != nil && needLinkCycleRecovery {
		// Actual link DOWN/UP occurred — old XSK sockets are dead.
		// Rebind to create fresh sockets on the reinitialized queues.
		d.dp.NotifyLinkCycle()
		if d.ra != nil {
			d.ra.ResendBurst()
		}
	} else if d.dp != nil && rethMACPending && !needLinkCycleRecovery {
		// MAC set live (no link cycle) but workers were deferred.
		// Trigger a re-Compile to start workers with the now-correct MAC.
		// This is cheaper than NotifyLinkCycle (no stop_workers/rebind).
		if _, err := d.dp.Compile(cfg); err != nil {
			slog.Warn("failed to re-compile after deferred MAC", "err", err)
		}
	}

	// NOTE: stable link-local cleanup for secondary RGs is handled by
	// the reconcile loop (reconcileRGState) after election settles,
	// not here — we don't know who's primary during config apply.

	// 2.6c. Reconcile proxy ARP entries for NAT addresses.
	if len(cfg.Security.NAT.ProxyARP) > 0 {
		ifaceMap := make(map[string]int)
		rethToPhys := cfg.RethToPhysical()
		for _, entry := range cfg.Security.NAT.ProxyARP {
			parts := strings.SplitN(entry.Interface, ".", 2)
			baseName := parts[0]
			if phys, ok := rethToPhys[baseName]; ok {
				baseName = phys
			}
			linuxName := config.LinuxIfName(baseName)
			if _, ok := ifaceMap[entry.Interface]; ok {
				continue
			}
			iface, err := net.InterfaceByName(linuxName)
			if err != nil {
				slog.Warn("proxy-arp: interface not found", "iface", entry.Interface, "linux", linuxName, "err", err)
				continue
			}
			ifaceMap[entry.Interface] = iface.Index
		}
		added, err := dataplane.ReconcileProxyARP(cfg, ifaceMap)
		if err != nil {
			slog.Warn("failed to reconcile proxy ARP", "err", err)
		}
		for _, a := range added {
			if a.Iface != "" {
				if err := cluster.SendGratuitousARP(a.Iface, a.IP, 1); err != nil {
					slog.Warn("proxy-arp: GARP failed", "ip", a.IP, "iface", a.Iface, "err", err)
				}
			}
		}
	}

	// 2.7. Re-bind management VRF interfaces after networkd.Apply().
	// networkctl reconfigure strips VRF master bindings because networkd
	// considers the daemon-created vrf-mgmt device "unmanaged" and ignores
	// the VRF= directive. Re-bind here to restore VRF membership.
	if d.routing != nil && d.mgmtVRFInterfaces != nil {
		for ifName := range d.mgmtVRFInterfaces {
			if err := d.routing.BindInterfaceToVRF(ifName, "mgmt"); err != nil {
				slog.Warn("failed to re-bind interface to management VRF",
					"interface", ifName, "err", err)
			}
		}
		// Restart heartbeat after VRF rebind — networkd reconfigure moves
		// the control interface (em0) out of vrf-mgmt temporarily, which
		// invalidates the heartbeat UDP sockets. Without this restart,
		// the recovering node stops receiving peer heartbeats and declares
		// split-brain after the grace period expires.
		if d.cluster != nil {
			d.cluster.RestartHeartbeat()
		}
	}

	// 3. Apply all routes + dynamic protocols via FRR
	if d.frr != nil {
		// Collect interface bandwidths and point-to-point flags for FRR.
		ifaceBandwidths := make(map[string]uint64)
		ifaceP2P := make(map[string]bool)
		for name, ifc := range cfg.Interfaces.Interfaces {
			linuxName := config.LinuxIfName(name)
			if ifc.Bandwidth > 0 {
				ifaceBandwidths[linuxName] = ifc.Bandwidth
			}
			for _, unit := range ifc.Units {
				if unit.PointToPoint {
					ifaceP2P[linuxName] = true
				}
			}
		}

		fc := &frr.FullConfig{
			OSPF:                  cfg.Protocols.OSPF,
			OSPFv3:                cfg.Protocols.OSPFv3,
			BGP:                   cfg.Protocols.BGP,
			RIP:                   cfg.Protocols.RIP,
			ISIS:                  cfg.Protocols.ISIS,
			StaticRoutes:          cfg.RoutingOptions.StaticRoutes,
			Inet6StaticRoutes:     cfg.RoutingOptions.Inet6StaticRoutes,
			GenerateRoutes:        cfg.RoutingOptions.GenerateRoutes,
			DHCPRoutes:            d.collectDHCPRoutes(),
			PolicyOptions:         &cfg.PolicyOptions,
			ForwardingTableExport: cfg.RoutingOptions.ForwardingTableExport,
			BackupRouter:          cfg.System.BackupRouter,
			BackupRouterDst:       cfg.System.BackupRouterDst,
			InterfaceBandwidths:   ifaceBandwidths,
			InterfacePointToPoint: ifaceP2P,
			RethMap:               cfg.RethToPhysical(),
			ClusterMode:           d.cluster != nil,
		}
		for _, ri := range cfg.RoutingInstances {
			vrfName := "vrf-" + ri.Name
			if ri.InstanceType == "forwarding" {
				vrfName = "" // forwarding instances use the default table
			}
			fc.Instances = append(fc.Instances, frr.InstanceConfig{
				VRFName:           vrfName,
				OSPF:              ri.OSPF,
				OSPFv3:            ri.OSPFv3,
				BGP:               ri.BGP,
				RIP:               ri.RIP,
				ISIS:              ri.ISIS,
				StaticRoutes:      ri.StaticRoutes,
				Inet6StaticRoutes: ri.Inet6StaticRoutes,
			})
		}
		if err := d.frr.ApplyFull(fc); err != nil {
			slog.Warn("failed to apply FRR config", "err", err)
		}

		// Set L4 ECMP hash when consistent-hash is configured.
		if fc.ConsistentHash {
			path := "/proc/sys/net/ipv4/fib_multipath_hash_policy"
			current, _ := os.ReadFile(path)
			if strings.TrimSpace(string(current)) != "1" {
				if err := os.WriteFile(path, []byte("1\n"), 0644); err != nil {
					slog.Warn("failed to set fib_multipath_hash_policy", "err", err)
				} else {
					slog.Info("enabled L4 ECMP hashing (consistent-hash)")
				}
			}
		}
	}

	// 3b. Apply next-table policy routing rules (ip rule)
	if d.routing != nil {
		// Collect all static routes from main + per-rib
		allRoutes := append(cfg.RoutingOptions.StaticRoutes, cfg.RoutingOptions.Inet6StaticRoutes...)
		if err := d.routing.ApplyNextTableRules(allRoutes, cfg.RoutingInstances); err != nil {
			slog.Warn("failed to apply next-table rules", "err", err)
		}
	}

	// 3c. Apply rib-group route leaking rules (ip rule)
	if d.routing != nil && len(cfg.RoutingOptions.RibGroups) > 0 {
		if err := d.routing.ApplyRibGroupRules(cfg.RoutingOptions.RibGroups, cfg.RoutingInstances); err != nil {
			slog.Warn("failed to apply rib-group rules", "err", err)
		}
	}

	// 3d. Apply policy-based routing rules (ip rule) for firewall filter routing-instance
	if d.routing != nil {
		pbrRules := routing.BuildPBRRules(&cfg.Firewall, cfg.RoutingInstances)
		if err := d.routing.ApplyPBRRules(pbrRules); err != nil {
			slog.Warn("failed to apply PBR rules", "err", err)
		}
	}

	// 4. Proactive neighbor resolution for all known next-hops/gateways.
	// This ensures bpf_fib_lookup returns SUCCESS (with valid MACs)
	// instead of NO_NEIGH for the first forwarded packet.
	// In cluster mode, skip here — RETH VIPs are not yet installed (VRRP
	// hasn't become MASTER), so RouteGet() for WAN next-hops may fail.
	// resolveNeighbors() is triggered on VRRP MASTER in watchVRRPEvents.
	if cfg.Chassis.Cluster == nil {
		d.resolveNeighbors(cfg)
	}

	// 5. Apply RA config (Router Advertisements)
	// In cluster mode, RA/kea are managed by watchVRRPEvents — only
	// the MASTER runs these services to prevent dual-RA / dual-DHCP.
	// The VRRP event fires shortly after startup and calls applyRethServices().
	isCluster := cfg.Chassis.Cluster != nil
	raConfigs := d.buildRAConfigs(cfg)
	if !isCluster {
		if d.ra != nil && len(raConfigs) > 0 {
			if err := d.ra.Apply(raConfigs); err != nil {
				slog.Warn("failed to apply RA config", "err", err)
			}
		} else if d.ra != nil {
			// No RA configs — clear any previous RA senders.
			if err := d.ra.Clear(); err != nil {
				slog.Warn("failed to clear RA config", "err", err)
			}
		}
	}
	// Cluster startup: goodbye RAs for stale routes are handled by the
	// reconcile loop (reconcileRGState) after VRRP election settles.
	// Each RETH node has a different virtual MAC (hence different
	// link-local), so both nodes appear as separate routers to hosts.
	// Only the primary sends RAs (via applyRethServicesForRG on MASTER);
	// the reconcile loop sends goodbye RAs for inactive RGs.
	//
	// Stable link-local cleanup: handled by reconcile after election.

	// 6. Apply IPsec config
	// Always call Apply so stale swanctl config is removed when VPNs are
	// deleted from config.
	if d.ipsec != nil {
		if err := d.ipsec.Apply(ipsec.PrepareConfig(cfg)); err != nil {
			slog.Warn("failed to apply IPsec config", "err", err)
		}
	}

	// 7. Apply DHCP server config (Kea DHCPv4 + DHCPv6)
	// In cluster mode, deferred to VRRP MASTER transition.
	if !isCluster && d.dhcpServer != nil && (cfg.System.DHCPServer.DHCPLocalServer != nil || cfg.System.DHCPServer.DHCPv6LocalServer != nil) {
		// Resolve RETH interface names for Kea (needs real Linux names)
		resolveDHCPRethInterfaces(&cfg.System.DHCPServer, cfg)
		if err := d.dhcpServer.Apply(&cfg.System.DHCPServer); err != nil {
			slog.Warn("failed to apply DHCP server config", "err", err)
		}
	}

	// 8. Apply VRRP config — merge user VRRP + RETH VRRP instances
	vrrpInstances := vrrp.CollectInstances(cfg)
	if d.cluster != nil {
		localPri := d.cluster.LocalPriorities()
		vrrpInstances = append(vrrpInstances, vrrp.CollectRethInstances(cfg, localPri)...)
	}
	if err := d.vrrpMgr.UpdateInstances(vrrpInstances); err != nil {
		slog.Warn("failed to update VRRP instances", "err", err)
	}

	// 9. Apply system DNS and NTP configuration
	d.applySystemDNS(cfg)
	d.applySystemNTP(cfg)
	d.applyDNSService(cfg)

	// 9.5. Apply system hostname, timezone, and kernel tuning
	d.applyHostname(cfg)
	d.applyTimezone(cfg)
	d.applyKernelTuning(cfg)
	d.applyLo0Filter(cfg)

	// 9.6. Write SSH known hosts file
	d.applySSHKnownHosts(cfg)

	// 10. Apply system syslog forwarding
	d.applySystemSyslog(cfg)

	// 11. Apply system login users (create OS accounts, SSH keys)
	d.applySystemLogin(cfg)

	// 12. Apply SSH service configuration (root-login)
	d.applySSHConfig(cfg)

	// 13. Apply root authentication (encrypted-password + SSH keys)
	d.applyRootAuth(cfg)

	// 14. Apply syslog file destinations (rsyslog configs)
	d.applySyslogFiles(cfg)

	// 14b. Update security log syslog clients + zone name mapping
	if d.eventReader != nil {
		d.applySyslogConfig(d.eventReader, cfg)
	}

	// 15. Archive config to remote sites if transfer-on-commit is enabled
	d.archiveConfig(cfg)

	// 15b. Configure local archival settings for auto-archive on commit
	if cfg.System.Archival != nil {
		dir := cfg.System.Archival.ArchiveDir
		if dir == "" {
			dir = "/var/lib/bpfrx/archive"
		}
		max := cfg.System.Archival.MaxArchives
		if max <= 0 {
			max = 10
		}
		d.store.SetArchiveConfig(dir, max)
	} else {
		d.store.SetArchiveConfig("", 0)
	}

	// 16. Update flow traceoptions (trace file + filters)
	d.updateFlowTrace(cfg)

	// 17. Update event-options policies (RPM-driven failover)
	if d.eventEngine != nil {
		d.eventEngine.Apply(cfg.EventOptions)
	}

	// 18. Update chassis cluster interface monitors
	if d.routing != nil && cfg.Chassis.Cluster != nil &&
		len(cfg.Chassis.Cluster.RedundancyGroups) > 0 {
		d.routing.ApplyInterfaceMonitors(cfg.Chassis.Cluster.RedundancyGroups)
	}

	// 19. Update chassis cluster state machine
	if d.cluster != nil && cfg.Chassis.Cluster != nil {
		d.cluster.UpdateConfig(cfg.Chassis.Cluster)
		// Feed interface monitor statuses into cluster weight calculation
		if d.routing != nil {
			monStatuses := d.routing.InterfaceMonitorStatuses()
			for rgID, statuses := range monStatuses {
				for _, st := range statuses {
					d.cluster.SetMonitorWeight(rgID, st.Interface, !st.Up, st.Weight)
				}
			}
		}

		// RETH GARP is handled by native VRRP (VRRP-backed RETH).
		// No manual GARP registration needed.
	}

	// 20. Detect cluster transport config changes and restart comms (#87).
	// Only restart if comms were previously started (activeClusterTransport
	// is non-zero) and the new config differs.
	if d.cluster != nil && d.daemonCtx != nil {
		newTransport := clusterTransportFromConfig(cfg)
		if d.activeClusterTransport != (clusterTransportKey{}) && newTransport != d.activeClusterTransport {
			slog.Info("cluster: transport config changed, restarting comms",
				"old_control", d.activeClusterTransport.ControlInterface,
				"new_control", newTransport.ControlInterface,
				"old_peer", d.activeClusterTransport.PeerAddress,
				"new_peer", newTransport.PeerAddress,
				"old_fabric", d.activeClusterTransport.FabricInterface,
				"new_fabric", newTransport.FabricInterface,
				"old_fabric_peer", d.activeClusterTransport.FabricPeerAddress,
				"new_fabric_peer", newTransport.FabricPeerAddress)
			d.stopClusterComms()
			d.startClusterComms(d.daemonCtx)
		}
	}
}

// buildRAConfigs merges static RA configs from the Junos config with
// PD-derived prefixes from DHCPv6 prefix delegation.
func (d *Daemon) buildRAConfigs(cfg *config.Config) []*config.RAInterfaceConfig {
	// Start with static RA configs from the configuration.
	raByIface := make(map[string]*config.RAInterfaceConfig)
	var result []*config.RAInterfaceConfig
	for _, ra := range cfg.Protocols.RouterAdvertisement {
		raByIface[ra.Interface] = ra
		result = append(result, ra)
	}

	// If no DHCP manager, return static only.
	if d.dhcp == nil {
		return result
	}

	// Merge PD-derived prefixes from DHCPv6 clients.
	for _, mapping := range d.dhcp.DelegatedPrefixesForRA() {
		subPrefix := dhcp.DeriveSubPrefix(mapping.Prefix, mapping.SubPrefLen)
		if !subPrefix.IsValid() {
			slog.Warn("DHCPv6 PD: invalid sub-prefix derivation",
				"delegated", mapping.Prefix, "sub_len", mapping.SubPrefLen)
			continue
		}

		pfx := &config.RAPrefix{
			Prefix:     subPrefix.String(),
			OnLink:     true,
			Autonomous: true,
		}
		if mapping.ValidLifetime > 0 {
			pfx.ValidLifetime = int(mapping.ValidLifetime.Seconds())
		}
		if mapping.PreferredLifetime > 0 {
			pfx.PreferredLife = int(mapping.PreferredLifetime.Seconds())
		}

		if existing, ok := raByIface[mapping.RAIface]; ok {
			// Append prefix to existing RA interface config.
			existing.Prefixes = append(existing.Prefixes, pfx)
		} else {
			// Create a new RA interface config for this downstream interface.
			ra := &config.RAInterfaceConfig{
				Interface: mapping.RAIface,
				Prefixes:  []*config.RAPrefix{pfx},
			}
			raByIface[mapping.RAIface] = ra
			result = append(result, ra)
		}

		slog.Info("DHCPv6 PD: advertising prefix via RA",
			"prefix", subPrefix, "interface", mapping.RAIface,
			"delegated_from", mapping.Interface)
	}

	// Detect explicitly configured link-local addresses on RA interfaces.
	// If a user configures e.g. fe80::face/64 on a RETH interface, the RA
	// sender should bind to that address instead of auto-selecting one.
	for _, ra := range result {
		if ifc, ok := cfg.Interfaces.Interfaces[ra.Interface]; ok {
			if unit, ok := ifc.Units[0]; ok {
				for _, addr := range unit.Addresses {
					ip, _, err := net.ParseCIDR(addr)
					if err != nil {
						continue
					}
					if ip.IsLinkLocalUnicast() && ip.To4() == nil {
						ra.SourceLinkLocal = ip.String()
						break
					}
				}
			}
		}
	}

	// Resolve RETH interface names for RA senders (needs real Linux names).
	for _, ra := range result {
		ra.Interface = config.LinuxIfName(cfg.ResolveReth(ra.Interface))
	}

	return result
}

// startDHCPClients iterates the config and starts DHCP/DHCPv6 clients
// for interfaces that have family inet { dhcp; } or family inet6 { dhcpv6; }.
func (d *Daemon) startDHCPClients(ctx context.Context, cfg *config.Config) {
	// Check if any interface needs DHCP
	needsDHCP := false
	for _, ifc := range cfg.Interfaces.Interfaces {
		for _, unit := range ifc.Units {
			if unit.DHCP || unit.DHCPv6 {
				needsDHCP = true
				break
			}
		}
	}
	if !needsDHCP {
		return
	}

	// State dir for DUID persistence — same directory as config file
	stateDir := filepath.Dir(d.opts.ConfigFile)

	dm, err := dhcp.New(stateDir, func() {
		// Full recompile is safe: heartbeat sockets survive VRF rebind
		// (RestartHeartbeat), RETH MAC is set live (no XSK rebind), and
		// BPF compile skips reconcile when the binding plan is unchanged.
		if activeCfg := d.store.ActiveConfig(); activeCfg != nil {
			if d.dhcpLeaseChangeRequiresRecompile(activeCfg) {
				slog.Info("DHCP address changed, recompiling dataplane")
				d.applyConfig(activeCfg)
			} else {
				slog.Info("DHCP address changed on management-only interface, refreshing management routes")
				d.applyMgmtVRFRoutes()
			}
		}
	})
	if err != nil {
		slog.Warn("failed to create DHCP manager", "err", err)
		return
	}
	d.dhcp = dm

	for ifName, ifc := range cfg.Interfaces.Interfaces {
		for _, unit := range ifc.Units {
			// Use VLAN sub-interface name when unit has a VLAN ID
			dhcpIface := config.LinuxIfName(ifName)
			if unit.VlanID > 0 {
				dhcpIface = fmt.Sprintf("%s.%d", dhcpIface, unit.VlanID)
			}
			if unit.DHCP {
				if unit.DHCPOptions != nil {
					dm.SetDHCPv4Options(dhcpIface, &dhcp.DHCPv4Options{
						LeaseTime:              unit.DHCPOptions.LeaseTime,
						RetransmissionAttempt:  unit.DHCPOptions.RetransmissionAttempt,
						RetransmissionInterval: unit.DHCPOptions.RetransmissionInterval,
						ForceDiscover:          unit.DHCPOptions.ForceDiscover,
					})
				}
				slog.Info("starting DHCPv4 client", "interface", dhcpIface)
				dm.Start(ctx, dhcpIface, dhcp.AFInet)
			}
			if unit.DHCPv6 {
				// Configure DUID type from dhcpv6-client stanza
				if unit.DHCPv6Client != nil && unit.DHCPv6Client.DUIDType != "" {
					dm.SetDUIDType(dhcpIface, unit.DHCPv6Client.DUIDType)
				} else {
					dm.SetDUIDType(dhcpIface, "duid-ll") // default
				}
				// Configure DHCPv6 PD and other options
				if unit.DHCPv6Client != nil {
					dm.SetDHCPv6Options(dhcpIface, &dhcp.DHCPv6Options{
						Stateless:  unit.DHCPv6Client.ClientType == "stateless",
						UpdateDNS:  slices.Contains(unit.DHCPv6Client.ReqOptions, "dns-server"),
						IATypes:    unit.DHCPv6Client.ClientIATypes,
						PDPrefLen:  unit.DHCPv6Client.PrefixDelegatingPrefixLen,
						PDSubLen:   unit.DHCPv6Client.PrefixDelegatingSubPrefLen,
						ReqOptions: unit.DHCPv6Client.ReqOptions,
						RAIface:    unit.DHCPv6Client.UpdateRAInterface,
					})
				}
				slog.Info("starting DHCPv6 client", "interface", dhcpIface)
				dm.Start(ctx, dhcpIface, dhcp.AFInet6)
			}
		}
	}
}

func (d *Daemon) dhcpLeaseChangeRequiresRecompile(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	// Prefix delegation can affect downstream addressing/RA and still needs
	// a full re-apply.
	if d.dhcp != nil && len(d.dhcp.DelegatedPrefixesForRA()) > 0 {
		return true
	}
	// If management VRF bindings are unavailable, stay conservative.
	if len(d.mgmtVRFInterfaces) == 0 {
		return true
	}
	for ifName, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		for _, unit := range ifc.Units {
			if unit == nil || (!unit.DHCP && !unit.DHCPv6) {
				continue
			}
			dhcpIface := config.LinuxIfName(ifName)
			if unit.VlanID > 0 {
				dhcpIface = fmt.Sprintf("%s.%d", dhcpIface, unit.VlanID)
			}
			if !d.mgmtVRFInterfaces[dhcpIface] {
				return true
			}
		}
	}
	return false
}

// resolveJunosIfName converts a Junos-style interface name to its Linux
// equivalent. It resolves RETH names to their physical members (e.g.
// reth0.50 → ge-0/0/0.50) and converts Junos slashes to dashes (e.g.
// ge-0/0/0 → ge-0-0-0).
func resolveJunosIfName(cfg *config.Config, ifName string) string {
	return config.LinuxIfName(cfg.ResolveReth(ifName))
}

// stripCIDR removes the /prefix from a CIDR string, returning just the IP.
func stripCIDR(s string) string {
	ip, _, err := net.ParseCIDR(s)
	if err != nil {
		return s // not CIDR, return as-is
	}
	return ip.String()
}

// resolveNeighbors proactively triggers ARP/NDP resolution for all known
// next-hops, gateways, NAT destinations, and address-book host entries.
// This ensures bpf_fib_lookup returns SUCCESS (with valid MAC addresses)
// instead of NO_NEIGH for the first packet.
func (d *Daemon) resolveNeighbors(cfg *config.Config) {
	type target struct {
		neighborIP net.IP
		linkIndex  int
	}
	var targets []target
	seen := make(map[string]bool)

	addByLink := func(ip net.IP, linkIndex int) {
		key := fmt.Sprintf("%s@%d", ip, linkIndex)
		if seen[key] {
			return
		}
		seen[key] = true
		targets = append(targets, target{neighborIP: ip, linkIndex: linkIndex})
	}

	// addByIP resolves the outgoing interface via the kernel routing table.
	addByIP := func(ipStr string) {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return
		}
		routes, err := netlink.RouteGet(ip)
		if err != nil || len(routes) == 0 {
			return
		}
		neighborIP := ip
		if gw := routes[0].Gw; gw != nil && !gw.IsUnspecified() {
			neighborIP = gw
		}
		addByLink(neighborIP, routes[0].LinkIndex)
	}

	addByName := func(ipStr, ifName string) {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return
		}
		resolved := resolveJunosIfName(cfg, ifName)
		if resolved != ifName {
			slog.Debug("neighbor warmup: resolved interface name", "from", ifName, "to", resolved)
		}
		link, err := netlink.LinkByName(resolved)
		if err != nil {
			return
		}
		addByLink(ip, link.Attrs().Index)
	}

	// 1. Static route next-hops (resolve interface via FIB if not specified)
	allStaticRoutes := append(cfg.RoutingOptions.StaticRoutes, cfg.RoutingOptions.Inet6StaticRoutes...)
	for _, sr := range allStaticRoutes {
		if sr.Discard {
			continue
		}
		for _, nh := range sr.NextHops {
			if nh.Address == "" {
				continue
			}
			if nh.Interface != "" {
				addByName(nh.Address, nh.Interface)
			} else {
				addByIP(nh.Address)
			}
		}
	}
	for _, ri := range cfg.RoutingInstances {
		for _, sr := range ri.StaticRoutes {
			if sr.Discard {
				continue
			}
			for _, nh := range sr.NextHops {
				if nh.Address == "" {
					continue
				}
				if nh.Interface != "" {
					addByName(nh.Address, nh.Interface)
				} else {
					addByIP(nh.Address)
				}
			}
		}
	}

	// 2. DHCP-learned gateways
	if d.dhcp != nil {
		for _, lease := range d.dhcp.Leases() {
			if lease.Gateway.IsValid() {
				addByName(lease.Gateway.String(), lease.Interface)
			}
		}
	}

	// 3. Backup router next-hop
	if cfg.System.BackupRouter != "" {
		addByIP(cfg.System.BackupRouter)
	}

	// 4. DNAT pool addresses (destinations that will receive forwarded traffic)
	if cfg.Security.NAT.Destination != nil {
		for _, pool := range cfg.Security.NAT.Destination.Pools {
			if pool.Address != "" {
				addByIP(stripCIDR(pool.Address))
			}
		}
	}

	// 5. Static NAT translated addresses (internal hosts receiving forwarded traffic)
	for _, rs := range cfg.Security.NAT.Static {
		for _, rule := range rs.Rules {
			if rule.Then != "" {
				addByIP(stripCIDR(rule.Then))
			}
		}
	}

	// 6. Address-book host entries (known hosts referenced in policies).
	// Only resolve host addresses (/32 for v4, /128 for v6) to avoid
	// flooding entire subnets with ARP requests.
	if cfg.Security.AddressBook != nil {
		for _, addr := range cfg.Security.AddressBook.Addresses {
			ip, ipNet, err := net.ParseCIDR(addr.Value)
			if err != nil {
				continue
			}
			ones, bits := ipNet.Mask.Size()
			if ones == bits {
				addByIP(ip.String())
			}
		}
	}

	// Resolve each target via ping (triggers kernel ARP/NDP resolution)
	resolved := 0
	for _, t := range targets {
		link, err := netlink.LinkByIndex(t.linkIndex)
		if err != nil {
			continue
		}
		ifName := link.Attrs().Name
		family := netlink.FAMILY_V4
		if t.neighborIP.To4() == nil {
			family = netlink.FAMILY_V6
		}
		// Skip if neighbor already exists and is usable
		neighs, _ := netlink.NeighList(t.linkIndex, family)
		skip := false
		for _, n := range neighs {
			if n.IP.Equal(t.neighborIP) && (n.State&(netlink.NUD_REACHABLE|netlink.NUD_STALE|netlink.NUD_PERMANENT)) != 0 {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		resolved++
		// Trigger proactive neighbor discovery.
		// IPv4 continues to use ping so the kernel owns ARP resolution.
		// IPv6 additionally sends an explicit NS before pinging so the
		// failover path also nudges peer neighbor caches directly.
		go func(ip net.IP, iface string) {
			if ip.To4() == nil {
				if err := cluster.SendNDSolicitationFromInterface(iface, ip); err != nil {
					slog.Debug("neighbor warmup: IPv6 NS probe failed",
						"iface", iface, "ip", ip, "err", err)
				}
			}
			sendICMPProbe(iface, ip)
		}(t.neighborIP, ifName)
	}

	if resolved > 0 {
		slog.Info("proactive neighbor resolution", "resolving", resolved, "total_targets", len(targets))
		// Brief pause to allow ARP responses
		time.Sleep(500 * time.Millisecond)
	}
}

// cleanFailedNeighbors deletes NUD_FAILED neighbor entries on all interfaces
// and proactively pings the IP to pre-populate ARP/NDP for fast recovery.
//
// When a host goes down, the kernel marks its ARP/NDP entry as FAILED and
// retains it for ~60 seconds (gc_staletime). During that window, packets
// XDP_PASS'd for NO_NEIGH resolution are silently dropped by the kernel
// because it refuses to re-resolve a FAILED entry. Deleting the entry and
// pinging ensures ARP/NDP is resolved before the next forwarded packet.
func (d *Daemon) cleanFailedNeighbors() int {
	type probe struct {
		ip    net.IP
		iface string
	}
	var probes []probe
	cleaned := 0
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		neighs, err := netlink.NeighList(0, family)
		if err != nil {
			continue
		}
		for i := range neighs {
			if neighs[i].State&netlink.NUD_FAILED != 0 {
				// Capture interface name for probing before delete.
				link, linkErr := netlink.LinkByIndex(neighs[i].LinkIndex)
				if err := netlink.NeighDel(&neighs[i]); err == nil {
					cleaned++
					if linkErr == nil {
						probes = append(probes, probe{
							ip:    neighs[i].IP,
							iface: link.Attrs().Name,
						})
					}
				}
			}
		}
	}
	if cleaned > 0 {
		slog.Debug("cleaned failed neighbor entries", "count", cleaned)
	}
	// Reprobe cleaned neighbors so the kernel's table repopulates before
	// the next forwarded packet. IPv4 keeps the existing ARP probe path.
	// IPv6 now sends an explicit NS instead of waiting for passive later
	// traffic to trigger NDP.
	for _, p := range probes {
		if p.ip.To4() != nil {
			cluster.SendARPProbe(p.iface, p.ip)
		} else {
			if err := cluster.SendNDSolicitationFromInterface(p.iface, p.ip); err != nil {
				slog.Debug("failed-neighbor reprobe: IPv6 NS failed",
					"iface", p.iface, "ip", p.ip, "err", err)
			}
		}
	}
	return cleaned
}

// runPeriodicNeighborResolution manages two periodic tasks:
//   - Every 5 seconds: clean NUD_FAILED neighbor entries so the kernel
//     retries ARP/NDP on the next forwarded packet (fast recovery).
//   - Every 15 seconds: proactively resolve known forwarding targets
//     (gateways, DNAT pools, etc.) to keep ARP/NDP entries warm.
//
// Runs once immediately at start to avoid a blind spot.
// Fetches fresh active config on each tick so config changes take effect.
func (d *Daemon) runPeriodicNeighborResolution(ctx context.Context) {
	// Immediate first run — don't wait for first tick.
	if cfg := d.store.ActiveConfig(); cfg != nil {
		d.resolveNeighbors(cfg)
	}
	d.cleanFailedNeighbors()

	const (
		cleanInterval   = 5 * time.Second
		resolveInterval = 15 * time.Second
	)
	cleanTicker := time.NewTicker(cleanInterval)
	resolveTicker := time.NewTicker(resolveInterval)
	defer cleanTicker.Stop()
	defer resolveTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-cleanTicker.C:
			d.cleanFailedNeighbors()
		case <-resolveTicker.C:
			if cfg := d.store.ActiveConfig(); cfg != nil {
				d.resolveNeighbors(cfg)
			}
		}
	}
}

// collectDHCPRoutes builds FRR DHCPRoute entries from active DHCP leases.
// Interfaces bound to the management VRF are excluded — their routes are
// programmed directly via netlink into the VRF table by applyMgmtVRFRoutes.
func (d *Daemon) collectDHCPRoutes() []frr.DHCPRoute {
	if d.dhcp == nil {
		return nil
	}
	var routes []frr.DHCPRoute
	for _, lease := range d.dhcp.Leases() {
		if !lease.Gateway.IsValid() {
			continue
		}
		if d.mgmtVRFInterfaces[lease.Interface] {
			continue
		}
		dr := frr.DHCPRoute{
			Gateway:   lease.Gateway.String(),
			Interface: lease.Interface,
			IsIPv6:    lease.Family == dhcp.AFInet6,
		}
		routes = append(routes, dr)
	}
	return routes
}

// applyMgmtVRFRoutes programs default routes in the management VRF table
// for DHCP leases on management interfaces (fxp*, fab*). These routes are
// managed via netlink (not FRR) because FRR doesn't own the management VRF.
func (d *Daemon) applyMgmtVRFRoutes() {
	if d.dhcp == nil || len(d.mgmtVRFInterfaces) == 0 {
		return
	}
	const mgmtTableID = 999
	nlh, err := netlink.NewHandle()
	if err != nil {
		slog.Warn("mgmt VRF routes: failed to get netlink handle", "err", err)
		return
	}
	defer nlh.Close()

	for _, lease := range d.dhcp.Leases() {
		if !lease.Gateway.IsValid() || !d.mgmtVRFInterfaces[lease.Interface] {
			continue
		}
		link, err := nlh.LinkByName(lease.Interface)
		if err != nil {
			slog.Warn("mgmt VRF route: interface not found",
				"interface", lease.Interface, "err", err)
			continue
		}
		var dst *net.IPNet
		if lease.Family == dhcp.AFInet6 {
			dst = &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
		} else {
			dst = &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
		}
		gwSlice := lease.Gateway.AsSlice()
		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       dst,
			Gw:        net.IP(gwSlice),
			Table:     mgmtTableID,
		}
		if err := nlh.RouteReplace(route); err != nil {
			slog.Warn("mgmt VRF route: failed to add default route",
				"interface", lease.Interface, "gw", lease.Gateway, "table", mgmtTableID, "err", err)
		} else {
			slog.Info("mgmt VRF default route installed",
				"interface", lease.Interface, "gw", lease.Gateway, "table", mgmtTableID)
		}
	}
}

// logFinalStats reads and logs global counter summary before shutdown.
func logFinalStats(dp dataplane.DataPlane) {
	if !dp.IsLoaded() {
		return
	}
	indices := []struct {
		idx  uint32
		name string
	}{
		{dataplane.GlobalCtrRxPackets, "rx_packets"},
		{dataplane.GlobalCtrTxPackets, "tx_packets"},
		{dataplane.GlobalCtrDrops, "drops"},
		{dataplane.GlobalCtrSessionsNew, "sessions_created"},
		{dataplane.GlobalCtrSessionsClosed, "sessions_closed"},
		{dataplane.GlobalCtrScreenDrops, "screen_drops"},
		{dataplane.GlobalCtrPolicyDeny, "policy_denies"},
	}

	attrs := make([]any, 0, len(indices)*2)
	for _, n := range indices {
		v, err := dp.ReadGlobalCounter(n.idx)
		if err != nil {
			continue
		}
		attrs = append(attrs, n.name, v)
	}

	slog.Info("final statistics", attrs...)
}

// startFlowExporter starts the NetFlow v9 exporter if configured.
func (d *Daemon) startFlowExporter(ctx context.Context, cfg *config.Config, er *logging.EventReader) {
	ec := flowexport.BuildExportConfig(&cfg.Services, &cfg.ForwardingOptions)
	if ec == nil {
		return
	}

	// Build per-zone sampling direction flags using deterministic zone IDs
	// (same sorted assignment as dataplane compiler).
	zoneIDs := buildZoneIDs(cfg)
	ec.SamplingZones = flowexport.BuildSamplingZones(cfg, zoneIDs)

	exp, err := flowexport.NewExporter(*ec)
	if err != nil {
		slog.Warn("failed to create flow exporter", "err", err)
		return
	}

	flowCtx, cancel := context.WithCancel(ctx)
	d.flowExporter = exp
	d.flowCancel = cancel

	// Register callback for session close events
	er.AddCallback(func(rec logging.EventRecord, raw []byte) {
		if rec.Type != "SESSION_CLOSE" {
			return
		}
		// Check sampling direction: skip if zone has no sampling enabled
		if !ec.ShouldExport(rec.InZone, rec.OutZone) {
			return
		}
		sd := flowexport.SessionCloseData{
			SrcPort:  parseSrcPort(rec.SrcAddr),
			DstPort:  parseSrcPort(rec.DstAddr),
			Protocol: parseProtocol(rec.Protocol),
		}
		sd.SrcIP, sd.DstIP, sd.IsIPv6 = parseAddrPair(rec.SrcAddr, rec.DstAddr)
		exp.ExportSessionClose(rec, sd)
	})

	d.flowWg.Add(1)
	go func() {
		defer d.flowWg.Done()
		exp.Run(flowCtx)
	}()

	slog.Info("NetFlow v9 exporter started",
		"collectors", len(ec.Collectors),
		"active_timeout", ec.FlowActiveTimeout,
		"inactive_timeout", ec.FlowInactiveTimeout,
		"sampling_zones", len(ec.SamplingZones),
		"sampling_rate", ec.SamplingRate)
}

// stopFlowExporter stops the running flow exporter.
func (d *Daemon) stopFlowExporter() {
	if d.flowCancel != nil {
		d.flowCancel()
	}
	d.flowWg.Wait()
	if d.flowExporter != nil {
		d.flowExporter.Close()
		d.flowExporter = nil
	}
}

// startIPFIXExporter starts the IPFIX (NetFlow v10) exporter if configured.
func (d *Daemon) startIPFIXExporter(ctx context.Context, cfg *config.Config, er *logging.EventReader) {
	ec := flowexport.BuildIPFIXExportConfig(&cfg.Services, &cfg.ForwardingOptions)
	if ec == nil {
		return
	}

	zoneIDs := buildZoneIDs(cfg)
	ec.SamplingZones = flowexport.BuildSamplingZones(cfg, zoneIDs)

	exp, err := flowexport.NewIPFIXExporter(*ec)
	if err != nil {
		slog.Warn("failed to create IPFIX exporter", "err", err)
		return
	}

	ipfixCtx, cancel := context.WithCancel(ctx)
	d.ipfixExporter = exp
	d.ipfixCancel = cancel

	er.AddCallback(func(rec logging.EventRecord, raw []byte) {
		if rec.Type != "SESSION_CLOSE" {
			return
		}
		if !ec.ShouldExport(rec.InZone, rec.OutZone) {
			return
		}
		sd := flowexport.SessionCloseData{
			SrcPort:  parseSrcPort(rec.SrcAddr),
			DstPort:  parseSrcPort(rec.DstAddr),
			Protocol: parseProtocol(rec.Protocol),
		}
		sd.SrcIP, sd.DstIP, sd.IsIPv6 = parseAddrPair(rec.SrcAddr, rec.DstAddr)
		exp.ExportSessionClose(rec, sd)
	})

	d.ipfixWg.Add(1)
	go func() {
		defer d.ipfixWg.Done()
		exp.Run(ipfixCtx)
	}()

	slog.Info("IPFIX exporter started",
		"collectors", len(ec.Collectors),
		"active_timeout", ec.FlowActiveTimeout,
		"inactive_timeout", ec.FlowInactiveTimeout,
		"sampling_zones", len(ec.SamplingZones),
		"sampling_rate", ec.SamplingRate)
}

// stopIPFIXExporter stops the running IPFIX exporter.
func (d *Daemon) stopIPFIXExporter() {
	if d.ipfixCancel != nil {
		d.ipfixCancel()
	}
	d.ipfixWg.Wait()
	if d.ipfixExporter != nil {
		d.ipfixExporter.Close()
		d.ipfixExporter = nil
	}
}

// buildZoneIDs replicates the deterministic zone ID assignment from the
// dataplane compiler (sorted zone names, 1-based sequential IDs).
func buildZoneIDs(cfg *config.Config) map[string]uint16 {
	names := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		names = append(names, name)
	}
	sort.Strings(names)
	ids := make(map[string]uint16, len(names))
	for i, name := range names {
		ids[name] = uint16(i + 1)
	}
	return ids
}

type userspaceSessionDeltaDrainer interface {
	DrainSessionDeltas(max uint32) ([]dpuserspace.SessionDeltaInfo, dpuserspace.ProcessStatus, error)
}

type userspaceSessionExporter interface {
	ExportOwnerRGSessions(rgIDs []int, max uint32) ([]dpuserspace.SessionDeltaInfo, dpuserspace.ProcessStatus, error)
}

type userspaceEventStreamProvider interface {
	EventStream() *dpuserspace.EventStream
}

func daemonMonotonicSeconds() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)
}

func userspaceSessionTimeout(proto uint8) uint32 {
	switch proto {
	case 6:
		return 300
	case 17:
		return 60
	case 1, 58:
		return 15
	default:
		return 30
	}
}

func userspaceHostToNetwork16(v uint16) uint16 {
	var raw [2]byte
	binary.BigEndian.PutUint16(raw[:], v)
	return binary.NativeEndian.Uint16(raw[:])
}

func userspaceNetworkToHost16(v uint16) uint16 {
	var raw [2]byte
	binary.NativeEndian.PutUint16(raw[:], v)
	return binary.BigEndian.Uint16(raw[:])
}

func userspaceReverseKeyV4(key dataplane.SessionKey, delta dpuserspace.SessionDeltaInfo) dataplane.SessionKey {
	rev := dataplane.SessionKey{
		SrcIP:    key.DstIP,
		DstIP:    key.SrcIP,
		SrcPort:  key.DstPort,
		DstPort:  key.SrcPort,
		Protocol: key.Protocol,
	}
	if ip := net.ParseIP(delta.NATDstIP).To4(); ip != nil {
		copy(rev.SrcIP[:], ip)
	}
	if ip := net.ParseIP(delta.NATSrcIP).To4(); ip != nil {
		copy(rev.DstIP[:], ip)
	}
	if delta.NATDstPort != 0 {
		rev.SrcPort = userspaceHostToNetwork16(delta.NATDstPort)
	}
	if delta.NATSrcPort != 0 {
		rev.DstPort = userspaceHostToNetwork16(delta.NATSrcPort)
	}
	return rev
}

func userspaceForwardWireKeyV4(key dataplane.SessionKey, delta dpuserspace.SessionDeltaInfo) dataplane.SessionKey {
	wire := key
	if ip := net.ParseIP(delta.NATSrcIP).To4(); ip != nil {
		copy(wire.SrcIP[:], ip)
		wire.SrcPort = userspaceHostToNetwork16(effectiveUserspaceNATSrcPort(delta))
	}
	if ip := net.ParseIP(delta.NATDstIP).To4(); ip != nil {
		copy(wire.DstIP[:], ip)
		wire.DstPort = userspaceHostToNetwork16(effectiveUserspaceNATDstPort(delta))
	}
	return wire
}

func effectiveUserspaceNATSrcPort(delta dpuserspace.SessionDeltaInfo) uint16 {
	if delta.NATSrcPort != 0 {
		return delta.NATSrcPort
	}
	if delta.NATSrcIP != "" {
		return delta.SrcPort
	}
	return 0
}

func effectiveUserspaceNATDstPort(delta dpuserspace.SessionDeltaInfo) uint16 {
	if delta.NATDstPort != 0 {
		return delta.NATDstPort
	}
	if delta.NATDstIP != "" {
		return delta.DstPort
	}
	return 0
}

func userspaceReverseKeyV6(key dataplane.SessionKeyV6, delta dpuserspace.SessionDeltaInfo) dataplane.SessionKeyV6 {
	rev := dataplane.SessionKeyV6{
		SrcIP:    key.DstIP,
		DstIP:    key.SrcIP,
		SrcPort:  key.DstPort,
		DstPort:  key.SrcPort,
		Protocol: key.Protocol,
	}
	if ip := net.ParseIP(delta.NATDstIP).To16(); ip != nil {
		copy(rev.SrcIP[:], ip)
	}
	if ip := net.ParseIP(delta.NATSrcIP).To16(); ip != nil {
		copy(rev.DstIP[:], ip)
	}
	if delta.NATDstPort != 0 {
		rev.SrcPort = userspaceHostToNetwork16(delta.NATDstPort)
	}
	if delta.NATSrcPort != 0 {
		rev.DstPort = userspaceHostToNetwork16(delta.NATSrcPort)
	}
	return rev
}

func userspaceParseSyncMAC(raw string) [6]byte {
	var out [6]byte
	if raw == "" {
		return out
	}
	mac, err := net.ParseMAC(raw)
	if err != nil || len(mac) != len(out) {
		return out
	}
	copy(out[:], mac)
	return out
}

func userspaceSessionFromDeltaV4(delta dpuserspace.SessionDeltaInfo, zoneIDs map[string]uint16) (dataplane.SessionKey, dataplane.SessionValue, bool) {
	src := net.ParseIP(delta.SrcIP).To4()
	dst := net.ParseIP(delta.DstIP).To4()
	if src == nil || dst == nil {
		return dataplane.SessionKey{}, dataplane.SessionValue{}, false
	}
	var key dataplane.SessionKey
	copy(key.SrcIP[:], src)
	copy(key.DstIP[:], dst)
	key.SrcPort = userspaceHostToNetwork16(delta.SrcPort)
	key.DstPort = userspaceHostToNetwork16(delta.DstPort)
	key.Protocol = delta.Protocol

	ingressZone := zoneIDs[delta.IngressZone]
	egressZone := zoneIDs[delta.EgressZone]
	if ingressZone == 0 || egressZone == 0 {
		return dataplane.SessionKey{}, dataplane.SessionValue{}, false
	}

	now := daemonMonotonicSeconds()
	val := dataplane.SessionValue{
		State:       4, // SESS_STATE_ESTABLISHED
		SessionID:   uint64(now)<<16 | uint64(delta.Slot&0xffff),
		Created:     now,
		LastSeen:    now,
		Timeout:     userspaceSessionTimeout(delta.Protocol),
		IngressZone: ingressZone,
		EgressZone:  egressZone,
		ReverseKey:  userspaceReverseKeyV4(key, delta),
	}
	if delta.TunnelEndpointID != 0 {
		val.LogFlags |= dataplane.LogFlagUserspaceTunnelEndpoint
		val.FibGen = delta.TunnelEndpointID
	} else if delta.TXIfindex > 0 {
		val.FibIfindex = uint32(delta.TXIfindex)
	} else if delta.EgressIfindex > 0 {
		val.FibIfindex = uint32(delta.EgressIfindex)
	}
	val.FibVlanID = delta.TXVLANID
	val.FibDmac = userspaceParseSyncMAC(delta.NeighborMAC)
	val.FibSmac = userspaceParseSyncMAC(delta.SrcMAC)
	if ip := net.ParseIP(delta.NATSrcIP).To4(); ip != nil {
		val.Flags |= dataplane.SessFlagSNAT
		val.NATSrcIP = binary.NativeEndian.Uint32(ip)
		val.NATSrcPort = userspaceHostToNetwork16(effectiveUserspaceNATSrcPort(delta))
	}
	if ip := net.ParseIP(delta.NATDstIP).To4(); ip != nil {
		val.Flags |= dataplane.SessFlagDNAT
		val.NATDstIP = binary.NativeEndian.Uint32(ip)
		val.NATDstPort = userspaceHostToNetwork16(effectiveUserspaceNATDstPort(delta))
	}
	if delta.FabricIngress {
		val.LogFlags |= dataplane.LogFlagUserspaceFabricIngress
	}
	return key, val, true
}

func userspaceForwardWireAliasFromDeltaV4(delta dpuserspace.SessionDeltaInfo, zoneIDs map[string]uint16) (dataplane.SessionKey, dataplane.SessionValue, bool) {
	key, val, ok := userspaceSessionFromDeltaV4(delta, zoneIDs)
	if !ok {
		return dataplane.SessionKey{}, dataplane.SessionValue{}, false
	}
	wireKey := userspaceForwardWireKeyV4(key, delta)
	if wireKey == key {
		return dataplane.SessionKey{}, dataplane.SessionValue{}, false
	}
	return wireKey, val, true
}

func userspaceSessionFromDeltaV6(delta dpuserspace.SessionDeltaInfo, zoneIDs map[string]uint16) (dataplane.SessionKeyV6, dataplane.SessionValueV6, bool) {
	src := net.ParseIP(delta.SrcIP).To16()
	dst := net.ParseIP(delta.DstIP).To16()
	if src == nil || dst == nil {
		return dataplane.SessionKeyV6{}, dataplane.SessionValueV6{}, false
	}
	var key dataplane.SessionKeyV6
	copy(key.SrcIP[:], src)
	copy(key.DstIP[:], dst)
	key.SrcPort = userspaceHostToNetwork16(delta.SrcPort)
	key.DstPort = userspaceHostToNetwork16(delta.DstPort)
	key.Protocol = delta.Protocol

	ingressZone := zoneIDs[delta.IngressZone]
	egressZone := zoneIDs[delta.EgressZone]
	if ingressZone == 0 || egressZone == 0 {
		return dataplane.SessionKeyV6{}, dataplane.SessionValueV6{}, false
	}

	now := daemonMonotonicSeconds()
	val := dataplane.SessionValueV6{
		State:       4, // SESS_STATE_ESTABLISHED
		SessionID:   uint64(now)<<16 | uint64(delta.Slot&0xffff),
		Created:     now,
		LastSeen:    now,
		Timeout:     userspaceSessionTimeout(delta.Protocol),
		IngressZone: ingressZone,
		EgressZone:  egressZone,
		ReverseKey:  userspaceReverseKeyV6(key, delta),
	}
	if delta.TunnelEndpointID != 0 {
		val.LogFlags |= dataplane.LogFlagUserspaceTunnelEndpoint
		val.FibGen = delta.TunnelEndpointID
	} else if delta.TXIfindex > 0 {
		val.FibIfindex = uint32(delta.TXIfindex)
	} else if delta.EgressIfindex > 0 {
		val.FibIfindex = uint32(delta.EgressIfindex)
	}
	val.FibVlanID = delta.TXVLANID
	val.FibDmac = userspaceParseSyncMAC(delta.NeighborMAC)
	val.FibSmac = userspaceParseSyncMAC(delta.SrcMAC)
	if ip := net.ParseIP(delta.NATSrcIP).To16(); ip != nil {
		val.Flags |= dataplane.SessFlagSNAT
		copy(val.NATSrcIP[:], ip)
		val.NATSrcPort = userspaceHostToNetwork16(effectiveUserspaceNATSrcPort(delta))
	}
	if ip := net.ParseIP(delta.NATDstIP).To16(); ip != nil {
		val.Flags |= dataplane.SessFlagDNAT
		copy(val.NATDstIP[:], ip)
		val.NATDstPort = userspaceHostToNetwork16(effectiveUserspaceNATDstPort(delta))
	}
	if delta.FabricIngress {
		val.LogFlags |= dataplane.LogFlagUserspaceFabricIngress
	}
	return key, val, true
}

func userspaceForwardWireKeyV6(key dataplane.SessionKeyV6, delta dpuserspace.SessionDeltaInfo) dataplane.SessionKeyV6 {
	wire := key
	if ip := net.ParseIP(delta.NATSrcIP).To16(); ip != nil {
		copy(wire.SrcIP[:], ip)
		wire.SrcPort = userspaceHostToNetwork16(effectiveUserspaceNATSrcPort(delta))
	}
	if ip := net.ParseIP(delta.NATDstIP).To16(); ip != nil {
		copy(wire.DstIP[:], ip)
		wire.DstPort = userspaceHostToNetwork16(effectiveUserspaceNATDstPort(delta))
	}
	return wire
}

func userspaceForwardWireAliasFromDeltaV6(delta dpuserspace.SessionDeltaInfo, zoneIDs map[string]uint16) (dataplane.SessionKeyV6, dataplane.SessionValueV6, bool) {
	key, val, ok := userspaceSessionFromDeltaV6(delta, zoneIDs)
	if !ok {
		return dataplane.SessionKeyV6{}, dataplane.SessionValueV6{}, false
	}
	wireKey := userspaceForwardWireKeyV6(key, delta)
	if wireKey == key {
		return dataplane.SessionKeyV6{}, dataplane.SessionValueV6{}, false
	}
	return wireKey, val, true
}

func (d *Daemon) shouldSyncUserspaceDelta(delta dpuserspace.SessionDeltaInfo, ingressZone uint16) bool {
	// Local-delivery sessions are traffic destined TO the firewall itself
	// (management SSH, BGP peering, DHCP, NDP, ICMP echo, etc.).  These are
	// intentionally excluded from HA session sync because:
	//  1. Each cluster node handles its own host-bound traffic independently;
	//     the peer's kernel stack processes its own local-delivery sessions
	//     after failover with no need for synced state.
	//  2. Local-delivery sessions reference node-local ifindexes and addresses
	//     that are meaningless on the peer.
	//  3. The userspace dataplane already sets track_in_userspace=false for
	//     these (afxdp.rs), so they are not in the session sweep; this guard
	//     covers the helper event-stream path.
	// See #315 for discussion.
	if strings.EqualFold(delta.Disposition, "local_delivery") {
		slog.Debug("userspace delta: filtered (local_delivery)", "src", delta.SrcIP, "dst", delta.DstIP)
		return false
	}
	if delta.FabricRedirect && !delta.FabricIngress {
		return d.sessionSync != nil
	}
	if delta.OwnerRGID > 0 && d.sessionSync != nil && d.sessionSync.IsPrimaryForRGFn != nil {
		ok := d.sessionSync.IsPrimaryForRGFn(delta.OwnerRGID)
		if !ok {
			slog.Debug("userspace delta: filtered (not primary for owner RG)", "rg", delta.OwnerRGID, "src", delta.SrcIP, "dst", delta.DstIP)
		}
		return ok
	}
	ok := d.sessionSync != nil && d.sessionSync.ShouldSyncZone(ingressZone)
	if !ok {
		slog.Debug("userspace delta: filtered (zone not synced)", "zone", ingressZone, "src", delta.SrcIP, "dst", delta.DstIP)
	}
	return ok
}

// buildZoneRGMap builds a zone_id→RG mapping by looking up which interfaces
// belong to each zone, then checking those interfaces' RedundancyGroup.
// Zones with RETH interfaces inherit the RETH's RG; non-RETH zones are not
// included (they fall back to global IsPrimaryFn in session sync).
func buildZoneRGMap(cfg *config.Config, zoneIDs map[string]uint16) map[uint16]int {
	result := make(map[uint16]int)
	for zoneName, zone := range cfg.Security.Zones {
		zid, ok := zoneIDs[zoneName]
		if !ok {
			continue
		}
		rgSeen := -1
		for _, ifName := range zone.Interfaces {
			// Strip unit suffix (e.g. "reth0.0" → "reth0") for config lookup.
			baseName := ifName
			if idx := strings.IndexByte(ifName, '.'); idx >= 0 {
				baseName = ifName[:idx]
			}
			if ifc, ok := cfg.Interfaces.Interfaces[baseName]; ok && ifc.RedundancyGroup > 0 {
				if rgSeen >= 0 && rgSeen != ifc.RedundancyGroup {
					slog.Warn("zone spans multiple redundancy groups; "+
						"active/active session sync ownership is ambiguous",
						"zone", zoneName,
						"rg1", rgSeen, "rg2", ifc.RedundancyGroup)
				}
				if rgSeen < 0 {
					result[zid] = ifc.RedundancyGroup
					rgSeen = ifc.RedundancyGroup
				}
			}
		}
	}
	return result
}

// rgHasRETH returns whether the given redundancy group has any RETH interfaces.
func rgHasRETH(cfg *config.Config, rgID int) bool {
	if cfg == nil {
		return false
	}
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc.RedundancyGroup == rgID {
			return true
		}
	}
	return false
}

func (d *Daemon) syncUserspaceSessionDeltas(ctx context.Context) {
	drainer, ok := d.dp.(userspaceSessionDeltaDrainer)
	if !ok || d.cluster == nil || d.sessionSync == nil {
		return
	}

	const (
		fastInterval          = 100 * time.Millisecond // event stream disconnected
		reconcileInterval     = 5 * time.Second        // event stream connected
	)
	ticker := time.NewTicker(fastInterval)
	defer ticker.Stop()
	wasConnected := false

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		// Adjust cadence based on event stream state.
		connected := d.eventStreamConnected.Load()
		if connected != wasConnected {
			wasConnected = connected
			if connected {
				ticker.Reset(reconcileInterval)
			} else {
				ticker.Reset(fastInterval)
			}
		}

		if d.cluster == nil || d.sessionSync == nil {
			return
		}
		if !d.cluster.IsLocalPrimaryAny() || !d.sessionSync.IsConnected() {
			continue
		}
		if d.userspaceDemotionPrepActive() {
			continue
		}

		cfg := d.store.ActiveConfig()
		if cfg == nil {
			continue
		}
		d.userspaceDeltaSyncMu.Lock()
		_, err := d.drainUserspaceSessionDeltasWithConfig(drainer, cfg, 1)
		d.userspaceDeltaSyncMu.Unlock()
		if err != nil {
			slog.Debug("userspace session delta drain failed", "err", err)
		}
	}
}

// runUserspaceEventStream attempts to consume session events from the helper's
// binary event stream. Falls back to the existing polling loop when the stream
// is unavailable or disconnected.
func (d *Daemon) runUserspaceEventStream(ctx context.Context) {
	provider, ok := d.dp.(userspaceEventStreamProvider)
	if !ok || d.cluster == nil || d.sessionSync == nil {
		// Manager doesn't support event stream — fall back to polling.
		d.syncUserspaceSessionDeltas(ctx)
		return
	}

	// Wait for the event stream to become available (helper may not have started yet).
	var es *dpuserspace.EventStream
	for {
		es = provider.EventStream()
		if es != nil {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}

	// Wire callbacks.
	es.SetOnEvent(func(eventType uint8, seq uint64, delta dpuserspace.SessionDeltaInfo) {
		d.handleEventStreamDelta(eventType, delta)
	})
	es.SetOnFullResync(func() {
		d.handleEventStreamFullResync()
	})

	slog.Info("userspace: event stream consumer started, polling is primary until stream connects")

	// Monitor connection. When the stream is connected, events arrive via
	// callback and polling drops to 5s reconciliation. When disconnected,
	// polling resumes at 100ms.
	d.eventStreamFallbackLoop(ctx, provider)
}

// handleEventStreamDelta processes a single session event from the event stream.
func (d *Daemon) handleEventStreamDelta(eventType uint8, delta dpuserspace.SessionDeltaInfo) {
	if d.cluster == nil || d.sessionSync == nil {
		slog.Debug("userspace delta: dropped (no cluster/sync)", "type", eventType)
		return
	}
	if !d.cluster.IsLocalPrimaryAny() {
		slog.Debug("userspace delta: dropped (not primary for any RG)", "type", eventType)
		return
	}
	if !d.sessionSync.IsConnected() {
		slog.Debug("userspace delta: dropped (sync not connected)", "type", eventType)
		return
	}
	if d.userspaceDemotionPrepActive() {
		slog.Debug("userspace delta: dropped (demotion prep active)", "type", eventType)
		return
	}

	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	zoneIDs := buildZoneIDs(cfg)

	// Map binary event type to the string event expected by queueUserspaceSessionDeltas.
	switch eventType {
	case dpuserspace.EventTypeSessionOpen, dpuserspace.EventTypeSessionUpdate:
		delta.Event = "open"
	case dpuserspace.EventTypeSessionClose:
		delta.Event = "close"
	}

	d.queueUserspaceSessionDeltas(zoneIDs, []dpuserspace.SessionDeltaInfo{delta})
}

// handleEventStreamFullResync handles a FullResync frame from the helper.
// This means the helper's replay buffer was trimmed past our last ack; we need
// a one-shot bulk export to catch up.
func (d *Daemon) handleEventStreamFullResync() {
	slog.Warn("userspace event stream: full resync requested, triggering bulk export")
	exporter, ok := d.dp.(userspaceSessionExporter)
	if !ok {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	// Export sessions for all RGs we're primary for.
	var rgIDs []int
	if d.cluster != nil {
		for rgID := 0; rgID < 16; rgID++ {
			if d.cluster.IsLocalPrimary(rgID) {
				rgIDs = append(rgIDs, rgID)
			}
		}
	}
	if len(rgIDs) == 0 {
		return
	}
	if _, err := d.exportUserspaceOwnerRGSessionsWithConfig(exporter, cfg, rgIDs); err != nil {
		slog.Warn("userspace event stream: full resync export failed", "err", err)
	}
}

// eventStreamFallbackLoop monitors the event stream connection and falls back
// to polling via DrainSessionDeltas when the stream is disconnected.
// When the event stream is live, polling slows to 5s reconciliation;
// when disconnected, it runs at 100ms to compensate for the lost stream.
func (d *Daemon) eventStreamFallbackLoop(ctx context.Context, provider userspaceEventStreamProvider) {
	drainer, hasDrainer := d.dp.(userspaceSessionDeltaDrainer)

	const (
		fastInterval      = 100 * time.Millisecond // event stream disconnected
		reconcileInterval = 5 * time.Second         // event stream connected
	)
	ticker := time.NewTicker(fastInterval)
	defer ticker.Stop()
	wasConnected := false

	defer d.eventStreamConnected.Store(false)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		es := provider.EventStream()
		connected := es != nil && es.IsConnected()

		// Track transitions and adjust cadence.
		if connected != wasConnected {
			wasConnected = connected
			d.eventStreamConnected.Store(connected)
			if connected {
				ticker.Reset(reconcileInterval)
				slog.Info("userspace: event stream connected, polling reduced to reconciliation (5s)")
			} else {
				ticker.Reset(fastInterval)
				slog.Info("userspace: event stream disconnected, polling resumed at 100ms")
			}
		}

		if connected {
			// Stream is live — run reconciliation drain to catch any
			// missed events, but at the slow 5s cadence.
			if !hasDrainer {
				continue
			}
			if d.cluster == nil || d.sessionSync == nil {
				return
			}
			if !d.cluster.IsLocalPrimaryAny() || !d.sessionSync.IsConnected() {
				continue
			}
			if d.userspaceDemotionPrepActive() {
				continue
			}
			cfg := d.store.ActiveConfig()
			if cfg == nil {
				continue
			}
			d.userspaceDeltaSyncMu.Lock()
			n, _ := d.drainUserspaceSessionDeltasWithConfig(drainer, cfg, 1)
			d.userspaceDeltaSyncMu.Unlock()
			if n > 0 {
				slog.Info("userspace: reconciliation drain caught missed deltas", "count", n)
			}
			continue
		}

		// Stream disconnected — fall back to fast polling.
		if !hasDrainer {
			continue
		}
		if d.cluster == nil || d.sessionSync == nil {
			return
		}
		if !d.cluster.IsLocalPrimaryAny() || !d.sessionSync.IsConnected() {
			continue
		}
		if d.userspaceDemotionPrepActive() {
			continue
		}
		cfg := d.store.ActiveConfig()
		if cfg == nil {
			continue
		}
		d.userspaceDeltaSyncMu.Lock()
		_, _ = d.drainUserspaceSessionDeltasWithConfig(drainer, cfg, 1)
		d.userspaceDeltaSyncMu.Unlock()
	}
}

type journaledSessionV4 struct {
	Key dataplane.SessionKey
	Val dataplane.SessionValue
}
type journaledSessionV6 struct {
	Key dataplane.SessionKeyV6
	Val dataplane.SessionValueV6
}

func (d *Daemon) userspaceDemotionPrepActive() bool {
	return d.userspaceDemotionPrepDepth.Load() > 0
}

// journalKernelSessionV4 buffers a kernel session event during demotion prep.
func (d *Daemon) journalKernelSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) {
	d.demotionKernelJournalMu.Lock()
	d.demotionKernelJournalV4 = append(d.demotionKernelJournalV4, journaledSessionV4{key, val})
	d.demotionKernelJournalMu.Unlock()
}

func (d *Daemon) journalKernelSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) {
	d.demotionKernelJournalMu.Lock()
	d.demotionKernelJournalV6 = append(d.demotionKernelJournalV6, journaledSessionV6{key, val})
	d.demotionKernelJournalMu.Unlock()
}


func (d *Daemon) queueUserspaceSessionDeltas(
	zoneIDs map[string]uint16,
	deltas []dpuserspace.SessionDeltaInfo,
) int {
	if d.sessionSync == nil {
		return 0
	}
	queued := 0
	for _, delta := range deltas {
		switch strings.ToLower(delta.Event) {
		case "open":
			switch delta.AddrFamily {
			case dataplane.AFInet:
				key, val, ok := userspaceSessionFromDeltaV4(delta, zoneIDs)
				if !ok {
					slog.Debug("userspace delta: V4 conversion failed", "src", delta.SrcIP, "dst", delta.DstIP, "disposition", delta.Disposition)
					continue
				}
				if !d.shouldSyncUserspaceDelta(delta, val.IngressZone) {
					continue
				}
				d.sessionSync.QueueSessionV4(key, val)
				slog.Debug("userspace delta: queued V4", "src", delta.SrcIP, "dst", delta.DstIP, "ownerRG", delta.OwnerRGID)
				queued++
				if delta.FabricRedirect && !delta.FabricIngress {
					if wireKey, wireVal, ok := userspaceForwardWireAliasFromDeltaV4(delta, zoneIDs); ok {
						d.sessionSync.QueueSessionV4(wireKey, wireVal)
						queued++
					}
				}
			case dataplane.AFInet6:
				key, val, ok := userspaceSessionFromDeltaV6(delta, zoneIDs)
				if !ok || !d.shouldSyncUserspaceDelta(delta, val.IngressZone) {
					continue
				}
				d.sessionSync.QueueSessionV6(key, val)
				queued++
				if delta.FabricRedirect && !delta.FabricIngress {
					if wireKey, wireVal, ok := userspaceForwardWireAliasFromDeltaV6(delta, zoneIDs); ok {
						d.sessionSync.QueueSessionV6(wireKey, wireVal)
						queued++
					}
				}
			}
		case "close":
			switch delta.AddrFamily {
			case dataplane.AFInet:
				key, val, ok := userspaceSessionFromDeltaV4(delta, zoneIDs)
				if ok && d.shouldSyncUserspaceDelta(delta, val.IngressZone) {
					d.sessionSync.QueueDeleteV4(key)
					queued++
					if delta.FabricRedirect && !delta.FabricIngress {
						wireKey := userspaceForwardWireKeyV4(key, delta)
						if wireKey != key {
							d.sessionSync.QueueDeleteV4(wireKey)
							queued++
						}
					}
				}
			case dataplane.AFInet6:
				key, val, ok := userspaceSessionFromDeltaV6(delta, zoneIDs)
				if ok && d.shouldSyncUserspaceDelta(delta, val.IngressZone) {
					d.sessionSync.QueueDeleteV6(key)
					queued++
					if delta.FabricRedirect && !delta.FabricIngress {
						wireKey := userspaceForwardWireKeyV6(key, delta)
						if wireKey != key {
							d.sessionSync.QueueDeleteV6(wireKey)
							queued++
						}
					}
				}
			}
		}
	}
	return queued
}

func (d *Daemon) drainUserspaceSessionDeltasWithConfig(
	drainer userspaceSessionDeltaDrainer,
	cfg *config.Config,
	maxBatches int,
) (int, error) {
	if drainer == nil || cfg == nil || maxBatches <= 0 {
		return 0, nil
	}
	zoneIDs := buildZoneIDs(cfg)
	total := 0
	for batch := 0; batch < maxBatches; batch++ {
		deltas, _, err := drainer.DrainSessionDeltas(256)
		if err != nil {
			return total, err
		}
		if len(deltas) == 0 {
			break
		}
		total += d.queueUserspaceSessionDeltas(zoneIDs, deltas)
		if len(deltas) < 256 {
			break
		}
	}
	return total, nil
}

func (d *Daemon) exportUserspaceOwnerRGSessionsWithConfig(
	exporter userspaceSessionExporter,
	cfg *config.Config,
	rgIDs []int,
) (int, error) {
	if exporter == nil || cfg == nil || len(rgIDs) == 0 {
		return 0, nil
	}
	deltas, _, err := exporter.ExportOwnerRGSessions(rgIDs, 0)
	if err != nil {
		return 0, err
	}
	return d.queueUserspaceSessionDeltas(buildZoneIDs(cfg), deltas), nil
}

func (d *Daemon) tryPrepareUserspaceRGDemotion(rgID int) {
	if err := d.prepareUserspaceRGDemotionWithTimeout(rgID, 5*time.Second); err != nil {
		slog.Warn("userspace: prepare rg demotion failed", "rg", rgID, "err", err)
	}
}

func (d *Daemon) acquireUserspaceRGDemotionPrep(rgID int, hold time.Duration) bool {
	d.userspaceDemotionPrepMu.Lock()
	defer d.userspaceDemotionPrepMu.Unlock()
	now := time.Now()
	if until, ok := d.userspaceDemotionPrepUntil[rgID]; ok && now.Before(until) {
		return false
	}
	if hold < 10*time.Second {
		hold = 10 * time.Second
	}
	d.userspaceDemotionPrepUntil[rgID] = now.Add(hold)
	return true
}

// releaseUserspaceRGDemotionPrep clears the suppression window so retries
// (e.g. manual failover admission) can re-attempt demotion prep immediately.
func (d *Daemon) releaseUserspaceRGDemotionPrep(rgID int) {
	d.userspaceDemotionPrepMu.Lock()
	defer d.userspaceDemotionPrepMu.Unlock()
	delete(d.userspaceDemotionPrepUntil, rgID)
}

func (d *Daemon) prepareUserspaceRGDemotion(rgID int) error {
	return d.prepareUserspaceRGDemotionWithTimeout(rgID, 30*time.Second)
}

func wrapUserspaceManualFailoverPrepareError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, "previous demotion barrier still pending") ||
		strings.Contains(msg, "session sync not ready before demotion") ||
		strings.Contains(msg, "session sync peer not quiescent before demotion") ||
		strings.Contains(msg, "demotion peer barrier failed") {
		return &cluster.RetryablePreFailoverError{Err: err}
	}
	return err
}

func (d *Daemon) prepareUserspaceManualFailover(rgID int) error {
	return wrapUserspaceManualFailoverPrepareError(
		d.prepareUserspaceRGDemotionWithTimeout(rgID, 15*time.Second),
	)
}

func (d *Daemon) prepareUserspaceRGDemotionWithTimeout(rgID int, barrierTimeout time.Duration) error {
	if !d.acquireUserspaceRGDemotionPrep(rgID, barrierTimeout) {
		slog.Info("userspace: skipping duplicate rg demotion prepare", "rg", rgID)
		return nil
	}
	success := false
	defer func() {
		if !success {
			d.releaseUserspaceRGDemotionPrep(rgID)
		}
	}()
	if d.sessionSync == nil || !d.sessionSync.IsConnected() {
		success = true
		return nil
	}

	// Verify the peer is caught up by sending a barrier. Incremental sync
	// delivers deltas in real-time, so one barrier ack proves the peer has
	// every session we've sent — no quiescence loop, pause/resume, or
	// event-stream drain needed.
	if !d.syncPeerBulkPrimed.Load() {
		slog.Info("cluster: bulk sync not acked yet, verifying peer readiness via barrier",
			"rg", rgID)
		if err := d.sessionSync.WaitForPeerBarrier(5 * time.Second); err != nil {
			return fmt.Errorf("session sync not ready before demotion: peer not responding to barrier: %w", err)
		}
		slog.Info("cluster: peer barrier succeeded without bulk ack — proceeding with demotion", "rg", rgID)
	}

	// Drain any in-flight barrier from a previous demotion attempt.
	pendingBarrierTimeout := barrierTimeout / 2
	if pendingBarrierTimeout > 10*time.Second {
		pendingBarrierTimeout = 10 * time.Second
	}
	if pendingBarrierTimeout < 2*time.Second {
		pendingBarrierTimeout = 2 * time.Second
	}
	if err := d.sessionSync.WaitForPeerBarriersDrained(pendingBarrierTimeout); err != nil {
		return fmt.Errorf("previous demotion barrier still pending: %w", err)
	}

	// Single barrier — peer ack means it has processed all queued deltas.
	// The actual demotion happens atomically in UpdateRGActive(false).
	if err := d.sessionSync.WaitForPeerBarrier(barrierTimeout); err != nil {
		return fmt.Errorf("demotion peer barrier failed: %w", err)
	}
	success = true
	slog.Info("userspace: prepared rg demotion", "rg", rgID)
	return nil
}

// parseAddrPair parses "ip:port" or "[ip]:port" into net.IPs and IPv6 flag.
func parseAddrPair(src, dst string) (srcIP, dstIP net.IP, isV6 bool) {
	srcIP = parseHost(src)
	dstIP = parseHost(dst)
	isV6 = srcIP != nil && srcIP.To4() == nil
	return
}

func parseHost(addr string) net.IP {
	// Handle "[ipv6]:port" format
	if len(addr) > 0 && addr[0] == '[' {
		end := 0
		for i, c := range addr {
			if c == ']' {
				end = i
				break
			}
		}
		if end > 1 {
			return net.ParseIP(addr[1:end])
		}
	}
	// Handle "ipv4:port" format
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return net.ParseIP(addr[:i])
		}
	}
	return net.ParseIP(addr)
}

func parseSrcPort(addr string) uint16 {
	// Find last colon
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			var port uint16
			for _, c := range addr[i+1:] {
				if c >= '0' && c <= '9' {
					port = port*10 + uint16(c-'0')
				}
			}
			return port
		}
	}
	return 0
}

func parseProtocol(proto string) uint8 {
	switch proto {
	case "TCP":
		return 6
	case "UDP":
		return 17
	case "ICMP":
		return 1
	case "ICMPv6":
		return 58
	}
	return 0
}

// applySyslogConfig constructs syslog clients or local log writers from the
// config and applies them to the event reader. When mode is "event", events
// are written to a local file; when "stream" (default), events are forwarded
// to remote syslog servers. Also updates zone name resolution for structured logging.
func (d *Daemon) applySyslogConfig(er *logging.EventReader, cfg *config.Config) {
	if er == nil {
		return
	}
	// Update zone name map for structured syslog formatting
	zoneNames := make(map[uint16]string)
	zoneIDs := buildZoneIDs(cfg)
	for name, id := range zoneIDs {
		zoneNames[id] = name
	}
	er.SetZoneNames(zoneNames)

	// Wire policy names and app names for structured logging
	if d.dp != nil {
		if cr := d.dp.LastCompileResult(); cr != nil {
			er.SetPolicyNames(cr.PolicyNames)
			if cr.AppNames != nil {
				er.SetAppNames(cr.AppNames)
			}
		}
	}

	// Wire interface names (ifindex -> name) from config
	ifNames := make(map[uint32]string)
	for name, iface := range cfg.Interfaces.Interfaces {
		ifName := name
		if iface != nil && iface.Name != "" {
			ifName = iface.Name
		}
		if link, err := netlink.LinkByName(ifName); err == nil {
			ifNames[uint32(link.Attrs().Index)] = ifName
		}
	}
	er.SetIfNames(ifNames)

	// Event mode: write to local file instead of remote syslog
	if cfg.Security.Log.Mode == "event" {
		er.SetSyslogClients(nil) // clear any remote clients
		lw, err := logging.NewLocalLogWriter(logging.LocalLogConfig{})
		if err != nil {
			slog.Warn("failed to create local log writer", "err", err)
		} else {
			if cfg.Security.Log.Format != "" {
				lw.Format = cfg.Security.Log.Format
			}
			er.ReplaceLocalWriters([]*logging.LocalLogWriter{lw})
			slog.Info("security log event mode: writing to /var/log/bpfrx/security.log",
				"format", cfg.Security.Log.Format)
		}
		d.applyAggregator(er, cfg)
		return
	}

	// Stream mode (default): clear local writers, set up remote syslog
	er.ReplaceLocalWriters(nil)

	if len(cfg.Security.Log.Streams) == 0 {
		d.applyAggregator(er, cfg)
		return
	}
	// Resolve global source-interface to IP (fallback for streams without source-address).
	// Prefer PrimaryAddress from config if set on the source interface unit.
	var globalSourceAddr string
	if cfg.Security.Log.SourceInterface != "" {
		globalSourceAddr = resolveSourceAddr(cfg, cfg.Security.Log.SourceInterface)
	}

	var clients []*logging.SyslogClient
	for name, stream := range cfg.Security.Log.Streams {
		srcAddr := stream.SourceAddress
		if srcAddr == "" {
			srcAddr = globalSourceAddr
		}
		protocol := stream.Transport.Protocol
		if protocol == "" {
			protocol = "udp"
		}
		client, err := logging.NewSyslogClientTransport(stream.Host, stream.Port, srcAddr, protocol, nil)
		if err != nil {
			slog.Warn("failed to create syslog client",
				"stream", name, "host", stream.Host, "protocol", protocol, "err", err)
			continue
		}
		if stream.Severity != "" {
			client.MinSeverity = logging.ParseSeverity(stream.Severity)
		}
		if stream.Facility != "" {
			client.Facility = logging.ParseFacility(stream.Facility)
		}
		if stream.Category != "" {
			client.Categories = logging.ParseCategory(stream.Category)
		}
		// Per-stream format overrides global log format
		format := stream.Format
		if format == "" {
			format = cfg.Security.Log.Format
		}
		if format != "" {
			client.Format = format
		}
		slog.Info("syslog stream configured",
			"stream", name, "host", stream.Host, "port", stream.Port,
			"protocol", protocol, "severity", stream.Severity,
			"facility", stream.Facility, "format", format,
			"category", stream.Category)
		clients = append(clients, client)
	}
	if len(clients) > 0 {
		er.SetSyslogClients(clients)
	}
	d.applyAggregator(er, cfg)
}

// resolveSourceAddr returns the source IP for syslog from the given interface.
// It prefers PrimaryAddress from config (stripped to bare IP); falls back to
// the first IPv4 address on the kernel interface.
func resolveSourceAddr(cfg *config.Config, srcIface string) string {
	// Parse "iface.unit" — e.g. "reth1.100" → base="reth1", unit=100
	base, unitStr, hasUnit := strings.Cut(srcIface, ".")
	unitNum := 0
	if hasUnit {
		if n, err := strconv.Atoi(unitStr); err == nil {
			unitNum = n
		}
	}
	if ifc, ok := cfg.Interfaces.Interfaces[base]; ok {
		if unit, ok := ifc.Units[unitNum]; ok && unit.PrimaryAddress != "" {
			// PrimaryAddress is CIDR — strip the prefix length
			if ip, _, err := net.ParseCIDR(unit.PrimaryAddress); err == nil {
				return ip.String()
			}
		}
	}
	// Fallback: first IPv4 from kernel
	if iface, err := net.InterfaceByName(srcIface); err == nil {
		if addrs, err := iface.Addrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
					return ipn.IP.String()
				}
			}
		}
	}
	return ""
}

// applyAggregator starts or stops the session aggregation reporter.
func (d *Daemon) applyAggregator(er *logging.EventReader, cfg *config.Config) {
	// Stop existing aggregator
	if d.aggCancel != nil {
		d.aggCancel()
		d.aggCancel = nil
	}
	d.aggregator = nil

	if !cfg.Security.Log.Report {
		return
	}

	agg := logging.NewSessionAggregator(0, 0) // defaults: 5min, top-10

	// Wire aggregator log output to the first available syslog client or local writer
	agg.SetLogFunc(func(severity int, msg string) {
		er.ForwardLogMsg(severity, msg)
	})

	er.AddCallback(agg.HandleEvent)

	ctx, cancel := context.WithCancel(context.Background())
	d.aggCancel = cancel
	d.aggregator = agg
	go agg.Run(ctx)
	slog.Info("session aggregation reporting enabled (5 min interval)")
}

// applySystemDNS writes /etc/resolv.conf from system { name-server } config.
// applyHostname sets the system hostname from system { host-name } config.
func (d *Daemon) applyHostname(cfg *config.Config) {
	if cfg.System.HostName == "" {
		return
	}

	current, _ := os.Hostname()
	if current == cfg.System.HostName {
		return
	}

	if err := syscall.Sethostname([]byte(cfg.System.HostName)); err != nil {
		slog.Warn("failed to set hostname", "err", err)
		return
	}

	// Persist to /etc/hostname
	if err := os.WriteFile("/etc/hostname", []byte(cfg.System.HostName+"\n"), 0644); err != nil {
		slog.Warn("failed to write /etc/hostname", "err", err)
	}
	slog.Info("hostname set", "hostname", cfg.System.HostName)
}

// isProcessDisabled checks if a Junos process name is in the disabled list.
func isProcessDisabled(cfg *config.Config, name string) bool {
	for _, p := range cfg.System.DisabledProcesses {
		if p == name {
			return true
		}
	}
	return false
}

func (d *Daemon) applySystemDNS(cfg *config.Config) {
	const dropinDir = "/etc/systemd/resolved.conf.d"
	const dropinPath = dropinDir + "/bpfrx.conf"

	if len(cfg.System.NameServers) == 0 && cfg.System.DomainName == "" && len(cfg.System.DomainSearch) == 0 {
		// Remove drop-in if no DNS config and file exists.
		if _, err := os.Stat(dropinPath); err == nil {
			os.Remove(dropinPath)
			restartResolved()
		}
		return
	}

	var b strings.Builder
	b.WriteString("# Generated by bpfrxd — do not edit\n[Resolve]\n")
	if len(cfg.System.NameServers) > 0 {
		fmt.Fprintf(&b, "DNS=%s\n", strings.Join(cfg.System.NameServers, " "))
	}
	if cfg.System.DomainName != "" {
		fmt.Fprintf(&b, "Domains=%s\n", cfg.System.DomainName)
	} else if len(cfg.System.DomainSearch) > 0 {
		fmt.Fprintf(&b, "Domains=%s\n", strings.Join(cfg.System.DomainSearch, " "))
	}

	current, _ := os.ReadFile(dropinPath)
	if string(current) == b.String() {
		return // no change
	}

	os.MkdirAll(dropinDir, 0755)
	if err := os.WriteFile(dropinPath, []byte(b.String()), 0644); err != nil {
		slog.Warn("failed to write resolved drop-in", "path", dropinPath, "err", err)
		return
	}
	slog.Info("DNS config applied via resolved", "domain", cfg.System.DomainName,
		"search", cfg.System.DomainSearch, "servers", cfg.System.NameServers)
	restartResolved()
}

func restartResolved() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "systemctl", "restart", "systemd-resolved").CombinedOutput(); err != nil {
		slog.Warn("failed to restart systemd-resolved", "err", err, "output", string(out))
	}
}

const (
	chronySourcesPath   = "/etc/chrony/sources.d/bpfrx.sources"
	chronyThresholdPath = "/etc/chrony/conf.d/bpfrx-threshold.conf"
)

func renderChronySources(servers []string) string {
	var b strings.Builder
	for _, server := range servers {
		// Use "pool" for hostnames and "server" for literal IPs.
		directive := "pool"
		if net.ParseIP(server) != nil {
			directive = "server"
		}
		fmt.Fprintf(&b, "%s %s iburst\n", directive, server)
	}
	return b.String()
}

func renderChronyThreshold(threshold int, action string) string {
	if threshold <= 0 || action == "" {
		return ""
	}

	// Only "accept" and "reject" are valid actions. Log and ignore anything else.
	if action != "accept" && action != "reject" {
		slog.Warn("unsupported NTP threshold action, ignoring", "action", action)
		return ""
	}

	// Junos NTP threshold is configured in seconds; chrony directives use
	// seconds as well. "accept" logs offsets beyond the threshold while
	// allowing correction, and "reject" additionally refuses large changes
	// after the initial update.
	var b strings.Builder
	fmt.Fprintf(&b, "logchange %d\n", threshold)
	if action == "reject" {
		fmt.Fprintf(&b, "maxchange %d 1 -1\n", threshold)
	}
	return b.String()
}

func reconcileManagedFile(path, content string) (bool, error) {
	current, err := os.ReadFile(path)
	if err == nil && string(current) == content {
		return false, nil
	}
	if err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("read %s: %w", path, err)
	}

	if content == "" {
		removeErr := os.Remove(path)
		if removeErr != nil && !os.IsNotExist(removeErr) {
			return false, fmt.Errorf("remove %s: %w", path, removeErr)
		}
		return removeErr == nil, nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return false, fmt.Errorf("create dir for %s: %w", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return false, fmt.Errorf("write %s: %w", path, err)
	}
	return true, nil
}

func reloadChronyRuntime(sourcesChanged, thresholdChanged bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if sourcesChanged {
		if out, err := exec.CommandContext(ctx, "chronyc", "reload", "sources").CombinedOutput(); err != nil {
			slog.Warn("failed to reload chrony sources", "err", err, "output", string(out))
		}
	}

	if !thresholdChanged {
		return
	}

	commands := [][]string{
		{"systemctl", "reload", "chrony"},
		{"systemctl", "reload", "chronyd"},
		{"systemctl", "restart", "chrony"},
		{"systemctl", "restart", "chronyd"},
	}
	for _, cmd := range commands {
		if out, err := exec.CommandContext(ctx, cmd[0], cmd[1:]...).CombinedOutput(); err == nil {
			return
		} else {
			slog.Debug("chrony config reload attempt failed", "cmd", strings.Join(cmd, " "), "err", err, "output", string(out))
		}
	}
	slog.Warn("failed to reload chrony threshold config; change will apply on next chronyd restart")
}

// applySystemNTP configures chrony from system { ntp } config.
// Writes per-server source lines to /etc/chrony/sources.d/bpfrx.sources and
// optional threshold directives to /etc/chrony/conf.d/bpfrx-threshold.conf.
func (d *Daemon) applySystemNTP(cfg *config.Config) {
	if isProcessDisabled(cfg, "ntp") {
		sourcesChanged, err := reconcileManagedFile(chronySourcesPath, "")
		if err != nil {
			slog.Warn("failed to remove chrony sources", "err", err)
		}
		thresholdChanged, err := reconcileManagedFile(chronyThresholdPath, "")
		if err != nil {
			slog.Warn("failed to remove chrony threshold config", "err", err)
		}
		if sourcesChanged || thresholdChanged {
			reloadChronyRuntime(sourcesChanged, thresholdChanged)
			slog.Info("NTP disabled; chrony managed configuration removed")
		}
		return
	}

	sourcesChanged, err := reconcileManagedFile(chronySourcesPath, renderChronySources(cfg.System.NTPServers))
	if err != nil {
		slog.Warn("failed to reconcile chrony sources", "err", err)
		return
	}
	thresholdChanged, err := reconcileManagedFile(chronyThresholdPath, renderChronyThreshold(cfg.System.NTPThreshold, cfg.System.NTPThresholdAction))
	if err != nil {
		slog.Warn("failed to reconcile chrony threshold config", "err", err)
		return
	}
	if !sourcesChanged && !thresholdChanged {
		return
	}

	reloadChronyRuntime(sourcesChanged, thresholdChanged)
	slog.Info("NTP config applied via chrony",
		"servers", cfg.System.NTPServers,
		"threshold", cfg.System.NTPThreshold,
		"action", cfg.System.NTPThresholdAction)
}

// applyDNSService manages systemd-resolved based on system { services { dns } }.
func (d *Daemon) applyDNSService(cfg *config.Config) {
	if cfg.System.Services == nil {
		return
	}
	if cfg.System.Services.DNSEnabled {
		exec.Command("systemctl", "enable", "--now", "systemd-resolved").Run()
	} else {
		exec.Command("systemctl", "disable", "--now", "systemd-resolved").Run()
	}
}

// applyKernelTuning sets kernel sysctl parameters from config.
// Handles system { no-redirects } and system { internet-options }.
func (d *Daemon) applyKernelTuning(cfg *config.Config) {
	// Disable ICMP redirects (send + accept) on all interfaces
	// system { no-redirects; }
	if cfg.System.NoRedirects {
		sysctls := []string{
			"/proc/sys/net/ipv4/conf/all/send_redirects",
			"/proc/sys/net/ipv4/conf/all/accept_redirects",
			"/proc/sys/net/ipv6/conf/all/accept_redirects",
		}
		for _, path := range sysctls {
			current, _ := os.ReadFile(path)
			if strings.TrimSpace(string(current)) != "0" {
				if err := os.WriteFile(path, []byte("0\n"), 0644); err != nil {
					slog.Warn("failed to set sysctl", "path", path, "err", err)
				}
			}
		}
	}

	// system { internet-options { no-ipv6-reject-zero-hop-limit; } }
	// Normally Linux drops IPv6 packets with hop-limit=0 and sends ICMPv6
	// time exceeded. This sysctl raises the ratelimit to effectively
	// accept them without generating errors (Junos compatibility).
	if cfg.System.InternetOptions != nil && cfg.System.InternetOptions.NoIPv6RejectZeroHopLimit {
		path := "/proc/sys/net/ipv6/icmp/ratelimit"
		current, _ := os.ReadFile(path)
		if strings.TrimSpace(string(current)) != "0" {
			if err := os.WriteFile(path, []byte("0\n"), 0644); err != nil {
				slog.Warn("failed to set sysctl", "path", path, "err", err)
			}
		}
	}

	// Enable IP forwarding (required for firewall operation)
	for _, path := range []string{
		"/proc/sys/net/ipv4/ip_forward",
		"/proc/sys/net/ipv6/conf/all/forwarding",
	} {
		current, _ := os.ReadFile(path)
		if strings.TrimSpace(string(current)) != "1" {
			if err := os.WriteFile(path, []byte("1\n"), 0644); err != nil {
				slog.Warn("failed to enable forwarding", "path", path, "err", err)
			}
		}
	}
}

// applyLo0Filter applies loopback filter rules for host-bound traffic.
// Implements "interfaces lo0 unit 0 family inet filter input <name>" by
// generating nftables rules from the named firewall filter.
func (d *Daemon) applyLo0Filter(cfg *config.Config) {
	filterV4 := cfg.System.Lo0FilterInputV4
	filterV6 := cfg.System.Lo0FilterInputV6
	if filterV4 == "" && filterV6 == "" {
		// No lo0 filter configured — clean up any stale nftables rules
		_ = exec.Command("nft", "delete", "table", "inet", "bpfrx_lo0").Run()
		return
	}

	var rules []string
	rules = append(rules, "table inet bpfrx_lo0 {")
	rules = append(rules, "  chain input {")
	rules = append(rules, "    type filter hook input priority 0; policy accept;")

	prefixLists := cfg.PolicyOptions.PrefixLists
	if filterV4 != "" {
		if f, ok := cfg.Firewall.FiltersInet[filterV4]; ok {
			for _, term := range f.Terms {
				r := nftRuleFromTerm(term, "ip", prefixLists)
				if r != "" {
					rules = append(rules, "    "+r)
				}
			}
		}
	}
	if filterV6 != "" {
		if f, ok := cfg.Firewall.FiltersInet6[filterV6]; ok {
			for _, term := range f.Terms {
				r := nftRuleFromTerm(term, "ip6", prefixLists)
				if r != "" {
					rules = append(rules, "    "+r)
				}
			}
		}
	}
	rules = append(rules, "  }")
	rules = append(rules, "}")

	nftConf := strings.Join(rules, "\n") + "\n"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader("flush ruleset inet bpfrx_lo0\n" + nftConf)
	if out, err := cmd.CombinedOutput(); err != nil {
		slog.Warn("failed to apply lo0 filter", "err", err, "output", string(out))
	} else {
		slog.Info("lo0 filter applied", "v4", filterV4, "v6", filterV6)
	}
}

// nftRuleFromTerm converts a firewall filter term to an nftables rule string.
// prefixLists is used to expand source-prefix-list and destination-prefix-list references.
func nftRuleFromTerm(term *config.FirewallFilterTerm, family string, prefixLists map[string]*config.PrefixList) string {
	var parts []string

	// Collect all source CIDRs (direct addresses + expanded prefix-lists)
	var srcCIDRs []string
	srcCIDRs = append(srcCIDRs, term.SourceAddresses...)
	var srcNegate bool
	for _, pl := range term.SourcePrefixLists {
		if resolved, ok := prefixLists[pl.Name]; ok {
			srcCIDRs = append(srcCIDRs, resolved.Prefixes...)
		}
		if pl.Except {
			srcNegate = true
		}
	}
	if len(srcCIDRs) > 0 {
		op := " saddr "
		if srcNegate {
			op = " saddr != "
		}
		if len(srcCIDRs) == 1 {
			parts = append(parts, family+op+srcCIDRs[0])
		} else {
			parts = append(parts, family+op+"{ "+strings.Join(srcCIDRs, ", ")+" }")
		}
	}

	// Collect all destination CIDRs
	var dstCIDRs []string
	dstCIDRs = append(dstCIDRs, term.DestAddresses...)
	var dstNegate bool
	for _, pl := range term.DestPrefixLists {
		if resolved, ok := prefixLists[pl.Name]; ok {
			dstCIDRs = append(dstCIDRs, resolved.Prefixes...)
		}
		if pl.Except {
			dstNegate = true
		}
	}
	if len(dstCIDRs) > 0 {
		op := " daddr "
		if dstNegate {
			op = " daddr != "
		}
		if len(dstCIDRs) == 1 {
			parts = append(parts, family+op+dstCIDRs[0])
		} else {
			parts = append(parts, family+op+"{ "+strings.Join(dstCIDRs, ", ")+" }")
		}
	}

	// Protocol matching
	if term.Protocol != "" {
		parts = append(parts, "meta l4proto "+term.Protocol)
	}

	// Source port matching
	if len(term.SourcePorts) == 1 {
		parts = append(parts, "th sport "+term.SourcePorts[0])
	} else if len(term.SourcePorts) > 1 {
		parts = append(parts, "th sport { "+strings.Join(term.SourcePorts, ", ")+" }")
	}

	// Destination port matching
	if len(term.DestinationPorts) == 1 {
		parts = append(parts, "th dport "+term.DestinationPorts[0])
	} else if len(term.DestinationPorts) > 1 {
		parts = append(parts, "th dport { "+strings.Join(term.DestinationPorts, ", ")+" }")
	}

	// DSCP / traffic-class matching
	if term.DSCP != "" {
		dscp := nftDSCPValue(term.DSCP)
		if family == "ip6" {
			parts = append(parts, "ip6 dscp "+dscp)
		} else {
			parts = append(parts, "ip dscp "+dscp)
		}
	}

	// ICMP type/code matching
	if term.ICMPType >= 0 {
		icmpFamily := "icmp"
		if family == "ip6" {
			icmpFamily = "icmpv6"
		}
		parts = append(parts, fmt.Sprintf("%s type %d", icmpFamily, term.ICMPType))
		if term.ICMPCode >= 0 {
			parts = append(parts, fmt.Sprintf("%s code %d", icmpFamily, term.ICMPCode))
		}
	}

	// TCP flags matching
	if len(term.TCPFlags) > 0 {
		parts = append(parts, "tcp flags "+strings.Join(term.TCPFlags, ","))
	}

	// IP fragment matching
	if term.IsFragment {
		parts = append(parts, "ip frag-off & 0x1fff != 0")
	}

	// Action: discard → drop (silent), reject → reject (ICMP unreachable), accept → accept
	action := "accept"
	switch term.Action {
	case "discard":
		action = "drop"
	case "reject":
		action = "reject"
	case "accept", "":
		action = "accept"
	}

	if len(parts) == 0 {
		return action
	}
	return strings.Join(parts, " ") + " " + action
}

// nftDSCPValue converts a Junos DSCP name to the nftables symbolic name.
// nftables accepts: cs0-cs7, af11-af43, ef, or numeric values.
func nftDSCPValue(name string) string {
	// Junos and nftables use the same naming for standard DSCP values.
	// Just pass through — nftables accepts ef, af11, af12, af13, af21,
	// af22, af23, af31, af32, af33, af41, af42, af43, cs0-cs7.
	return name
}

// applySSHKnownHosts writes /etc/ssh/ssh_known_hosts from
// security { ssh-known-hosts { host ... } } config.
func (d *Daemon) applySSHKnownHosts(cfg *config.Config) {
	const path = "/etc/ssh/ssh_known_hosts"
	if len(cfg.Security.SSHKnownHosts) == 0 {
		return
	}

	var buf strings.Builder
	buf.WriteString("# Managed by bpfrxd — do not edit\n")
	// Sort hosts for deterministic output
	var hosts []string
	for h := range cfg.Security.SSHKnownHosts {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		for _, key := range cfg.Security.SSHKnownHosts[host] {
			// Map Junos key type names to OpenSSH types
			sshType := key.Type
			switch sshType {
			case "ssh-rsa-key":
				sshType = "ssh-rsa"
			case "ecdsa-sha2-nistp256-key":
				sshType = "ecdsa-sha2-nistp256"
			case "ssh-ed25519-key":
				sshType = "ssh-ed25519"
			case "ecdsa-sha2-nistp384-key":
				sshType = "ecdsa-sha2-nistp384"
			case "ecdsa-sha2-nistp521-key":
				sshType = "ecdsa-sha2-nistp521"
			}
			fmt.Fprintf(&buf, "%s %s %s\n", host, sshType, key.Key)
		}
	}

	content := buf.String()
	current, _ := os.ReadFile(path)
	if string(current) == content {
		return
	}

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		slog.Warn("failed to write ssh known hosts", "err", err)
		return
	}
	slog.Info("SSH known hosts written", "hosts", len(cfg.Security.SSHKnownHosts))
}

// applyTimezone sets the system timezone from system { time-zone } config.
func (d *Daemon) applyTimezone(cfg *config.Config) {
	if cfg.System.TimeZone == "" {
		return
	}

	// Check current timezone
	current, _ := os.Readlink("/etc/localtime")
	target := "/usr/share/zoneinfo/" + cfg.System.TimeZone
	if current == target {
		return
	}

	// Verify timezone file exists
	if _, err := os.Stat(target); err != nil {
		slog.Warn("invalid timezone", "timezone", cfg.System.TimeZone, "err", err)
		return
	}

	// Set timezone via symlink
	os.Remove("/etc/localtime")
	if err := os.Symlink(target, "/etc/localtime"); err != nil {
		slog.Warn("failed to set timezone", "err", err)
		return
	}

	// Also write /etc/timezone for tools that read it
	os.WriteFile("/etc/timezone", []byte(cfg.System.TimeZone+"\n"), 0644)
	slog.Info("timezone set", "timezone", cfg.System.TimeZone)
}

// applySystemSyslog configures system-level syslog forwarding from
// system { syslog { host ... } } config. This forwards daemon log
// messages (Go slog) to remote syslog servers.
func (d *Daemon) applySystemSyslog(cfg *config.Config) {
	if d.slogHandler == nil {
		return
	}

	if cfg.System.Syslog == nil || len(cfg.System.Syslog.Hosts) == 0 {
		d.slogHandler.SetClients(nil)
		return
	}

	var clients []*logging.SyslogClient
	for _, host := range cfg.System.Syslog.Hosts {
		port := 514
		c, err := logging.NewSyslogClient(host.Address, port)
		if err != nil {
			slog.Warn("failed to create system syslog client",
				"host", host.Address, "err", err)
			continue
		}

		// Apply facility from first facility entry, default to daemon
		c.Facility = logging.FacilityDaemon
		if len(host.Facilities) > 0 {
			c.Facility = logging.ParseFacility(host.Facilities[0].Facility)
			// Apply severity filter from the most restrictive facility entry
			for _, f := range host.Facilities {
				if sev := logging.ParseSeverity(f.Severity); sev > 0 {
					if c.MinSeverity == 0 || sev < c.MinSeverity {
						c.MinSeverity = sev
					}
				}
			}
		}

		clients = append(clients, c)
		slog.Info("system syslog forwarding configured",
			"host", host.Address, "facility", c.Facility)
	}

	d.slogHandler.SetClients(clients)
}

// applySyslogFiles writes rsyslog drop-in configs for system { syslog { file ... } }
// destinations. Each file entry generates a rule that directs matching
// facility/severity messages to /var/log/<name>.
func (d *Daemon) applySyslogFiles(cfg *config.Config) {
	confDir := "/etc/rsyslog.d"
	prefix := "10-bpfrx-"

	// Collect desired configs
	desired := make(map[string]string) // filename -> content
	if cfg.System.Syslog != nil {
		for _, f := range cfg.System.Syslog.Files {
			if f.Name == "" {
				continue
			}
			// Map Junos facility/severity to rsyslog selector
			facility := f.Facility
			if facility == "" || facility == "any" {
				facility = "*"
			}
			// Junos "change-log" maps to local6; rsyslog doesn't know the name
			if facility == "change-log" {
				facility = "local6"
			}
			severity := f.Severity
			if severity == "" || severity == "any" {
				severity = "*"
			}
			// Junos severity names map directly to rsyslog (info, warning, error, etc.)
			selector := fmt.Sprintf("%s.%s", facility, severity)
			logPath := fmt.Sprintf("/var/log/%s", f.Name)

			content := fmt.Sprintf("# Managed by bpfrx — do not edit\n%s\t%s\n", selector, logPath)
			confFile := prefix + f.Name + ".conf"
			desired[confFile] = content
		}
		// Syslog user destinations: forward to logged-in users via rsyslog omusrmsg
		for _, u := range cfg.System.Syslog.Users {
			if u.User == "" {
				continue
			}
			facility := u.Facility
			if facility == "" || facility == "any" {
				facility = "*"
			}
			if facility == "change-log" {
				facility = "local6"
			}
			severity := u.Severity
			if severity == "" || severity == "any" {
				severity = "*"
			}
			selector := fmt.Sprintf("%s.%s", facility, severity)
			target := u.User // "*" means all logged-in users
			content := fmt.Sprintf("# Managed by bpfrx — do not edit\n%s\t:omusrmsg:%s\n", selector, target)
			confFile := prefix + "user-" + target + ".conf"
			desired[confFile] = content
		}
	}

	// Read existing bpfrx-managed files
	entries, _ := os.ReadDir(confDir)
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		if _, keep := desired[e.Name()]; !keep {
			// Remove stale config
			os.Remove(filepath.Join(confDir, e.Name()))
		}
	}

	// Write desired configs
	changed := false
	for name, content := range desired {
		path := filepath.Join(confDir, name)
		current, _ := os.ReadFile(path)
		if string(current) != content {
			if err := os.WriteFile(path, []byte(content), 0644); err != nil {
				slog.Warn("failed to write rsyslog config", "file", name, "err", err)
				continue
			}
			changed = true
		}
	}

	if changed {
		exec.Command("systemctl", "restart", "rsyslog").Run()
		slog.Info("rsyslog file configs applied", "files", len(desired))
	}
}

// applySystemLogin creates OS user accounts and SSH authorized_keys from
// system { login { user ... } } configuration.
func (d *Daemon) applySystemLogin(cfg *config.Config) {
	if cfg.System.Login == nil || len(cfg.System.Login.Users) == 0 {
		return
	}

	for _, user := range cfg.System.Login.Users {
		if user.Name == "" || user.Name == "root" {
			continue // never create/modify root via config
		}

		// Check if user already exists
		_, err := exec.Command("id", user.Name).CombinedOutput()
		if err != nil {
			// User doesn't exist — create it
			args := []string{"-m", "-s", "/bin/bash"}
			if user.UID > 0 {
				args = append(args, "-u", fmt.Sprintf("%d", user.UID))
			}
			args = append(args, user.Name)
			if out, err := exec.Command("useradd", args...).CombinedOutput(); err != nil {
				slog.Warn("failed to create user",
					"user", user.Name, "err", err, "output", string(out))
				continue
			}
			slog.Info("created system user", "user", user.Name, "uid", user.UID)
		}

		// Grant sudo for super-user class
		if user.Class == "super-user" {
			sudoFile := fmt.Sprintf("/etc/sudoers.d/bpfrx-%s", user.Name)
			sudoLine := fmt.Sprintf("%s ALL=(ALL) NOPASSWD: ALL\n", user.Name)
			current, _ := os.ReadFile(sudoFile)
			if string(current) != sudoLine {
				if err := os.WriteFile(sudoFile, []byte(sudoLine), 0440); err != nil {
					slog.Warn("failed to write sudoers file",
						"user", user.Name, "err", err)
				}
			}
		}

		// Set SSH authorized keys
		if len(user.SSHKeys) > 0 {
			homeDir := fmt.Sprintf("/home/%s", user.Name)
			sshDir := homeDir + "/.ssh"
			os.MkdirAll(sshDir, 0700)

			keysContent := strings.Join(user.SSHKeys, "\n") + "\n"
			keysFile := sshDir + "/authorized_keys"
			current, _ := os.ReadFile(keysFile)
			if string(current) != keysContent {
				if err := os.WriteFile(keysFile, []byte(keysContent), 0600); err != nil {
					slog.Warn("failed to write authorized_keys",
						"user", user.Name, "err", err)
					continue
				}
				// Fix ownership
				exec.Command("chown", "-R", user.Name+":"+user.Name, sshDir).Run()
				slog.Info("SSH keys updated", "user", user.Name, "keys", len(user.SSHKeys))
			}
		}
	}
}

// applySSHConfig configures sshd from system { services { ssh { ... } } }.
// Uses a drop-in config file to avoid modifying the main sshd_config.
func (d *Daemon) applySSHConfig(cfg *config.Config) {
	if cfg.System.Services == nil || cfg.System.Services.SSH == nil {
		return
	}

	ssh := cfg.System.Services.SSH
	if ssh.RootLogin == "" {
		return
	}

	// Map Junos values to sshd_config PermitRootLogin values
	var permitRoot string
	switch ssh.RootLogin {
	case "allow":
		permitRoot = "yes"
	case "deny":
		permitRoot = "no"
	case "deny-password":
		permitRoot = "prohibit-password"
	default:
		return
	}

	confPath := "/etc/ssh/sshd_config.d/bpfrx.conf"
	content := fmt.Sprintf("# Managed by bpfrx — do not edit\nPermitRootLogin %s\n", permitRoot)

	current, _ := os.ReadFile(confPath)
	if string(current) == content {
		return // no change
	}

	os.MkdirAll("/etc/ssh/sshd_config.d", 0755)
	if err := os.WriteFile(confPath, []byte(content), 0644); err != nil {
		slog.Warn("failed to write sshd config", "err", err)
		return
	}

	// Reload sshd to pick up changes
	exec.Command("systemctl", "reload", "sshd").Run()
	slog.Info("SSH config applied", "permit_root_login", permitRoot)
}

// applyRootAuth applies root-authentication config: encrypted-password and SSH keys.
func (d *Daemon) applyRootAuth(cfg *config.Config) {
	ra := cfg.System.RootAuthentication
	if ra == nil {
		return
	}

	// Set root password from encrypted-password (crypt(3) hash)
	if ra.EncryptedPassword != "" {
		// Use chpasswd -e to set pre-hashed password
		cmd := exec.Command("chpasswd", "-e")
		cmd.Stdin = strings.NewReader("root:" + ra.EncryptedPassword + "\n")
		if out, err := cmd.CombinedOutput(); err != nil {
			slog.Warn("failed to set root password", "err", err, "output", string(out))
		} else {
			slog.Info("root encrypted-password applied")
		}
	}

	// Write SSH authorized_keys for root
	if len(ra.SSHKeys) > 0 {
		sshDir := "/root/.ssh"
		os.MkdirAll(sshDir, 0700)
		keysContent := strings.Join(ra.SSHKeys, "\n") + "\n"
		keysFile := sshDir + "/authorized_keys"
		current, _ := os.ReadFile(keysFile)
		if string(current) != keysContent {
			if err := os.WriteFile(keysFile, []byte(keysContent), 0600); err != nil {
				slog.Warn("failed to write root authorized_keys", "err", err)
			} else {
				slog.Info("root SSH keys applied", "keys", len(ra.SSHKeys))
			}
		}
	}
}

// archiveConfig transfers the active config to remote archive sites
// when system { archival { configuration { transfer-on-commit; } } } is set.
func (d *Daemon) archiveConfig(cfg *config.Config) {
	if cfg.System.Archival == nil || !cfg.System.Archival.TransferOnCommit {
		return
	}
	if len(cfg.System.Archival.ArchiveSites) == 0 {
		return
	}

	configFile := d.opts.ConfigFile
	for _, site := range cfg.System.Archival.ArchiveSites {
		go func(dest string) {
			slog.Info("archiving config", "destination", dest)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			out, err := exec.CommandContext(ctx, "scp",
				"-o", "StrictHostKeyChecking=no",
				"-o", "BatchMode=yes",
				configFile, dest,
			).CombinedOutput()
			if err != nil {
				slog.Warn("config archival failed",
					"destination", dest, "err", err, "output", string(out))
			} else {
				slog.Info("config archived successfully", "destination", dest)
			}
		}(site)
	}
}

// applyFlowTrace sets up the initial flow trace writer from config.
func (d *Daemon) applyFlowTrace(cfg *config.Config, er *logging.EventReader) {
	if cfg.Security.Flow.Traceoptions == nil || cfg.Security.Flow.Traceoptions.File == "" {
		return
	}

	tw, err := logging.NewTraceWriter(cfg.Security.Flow.Traceoptions)
	if err != nil {
		slog.Warn("failed to create trace writer", "err", err)
		return
	}
	d.traceWriter = tw
	er.AddCallback(tw.HandleEvent)
	slog.Info("flow traceoptions enabled",
		"file", cfg.Security.Flow.Traceoptions.File,
		"filters", len(cfg.Security.Flow.Traceoptions.PacketFilters))
}

// updateFlowTrace updates the trace writer when config changes.
func (d *Daemon) updateFlowTrace(cfg *config.Config) {
	if d.traceWriter != nil {
		d.traceWriter.Close()
		d.traceWriter = nil
	}

	if d.eventReader == nil {
		return
	}

	if cfg.Security.Flow.Traceoptions == nil || cfg.Security.Flow.Traceoptions.File == "" {
		return
	}

	tw, err := logging.NewTraceWriter(cfg.Security.Flow.Traceoptions)
	if err != nil {
		slog.Warn("failed to create trace writer", "err", err)
		return
	}
	d.traceWriter = tw
	d.eventReader.AddCallback(tw.HandleEvent)
	slog.Info("flow traceoptions updated",
		"file", cfg.Security.Flow.Traceoptions.File,
		"filters", len(cfg.Security.Flow.Traceoptions.PacketFilters))
}

// monitorLinkState subscribes to netlink link updates and sends SNMP traps
// on interface state changes (link up / link down).
func (d *Daemon) monitorLinkState(ctx context.Context) {
	updates := make(chan netlink.LinkUpdate, 64)
	done := make(chan struct{})
	if err := netlink.LinkSubscribe(updates, done); err != nil {
		slog.Warn("SNMP link monitor: failed to subscribe", "err", err)
		return
	}
	slog.Info("SNMP link state monitor started")

	// Track previous oper state per ifindex to avoid duplicate traps.
	prevOper := make(map[int]bool) // true = up

	// Seed with current state.
	links, err := netlink.LinkList()
	if err == nil {
		for _, l := range links {
			attrs := l.Attrs()
			prevOper[attrs.Index] = (attrs.OperState == netlink.OperUp)
		}
	}

	for {
		select {
		case <-ctx.Done():
			close(done)
			return
		case update, ok := <-updates:
			if !ok {
				return
			}
			attrs := update.Attrs()
			if attrs.Name == "lo" {
				continue
			}

			nowUp := (attrs.OperState == netlink.OperUp)
			wasUp, known := prevOper[attrs.Index]
			if known && wasUp == nowUp {
				continue // no change
			}
			prevOper[attrs.Index] = nowUp

			if d.snmpAgent == nil {
				continue
			}

			if nowUp {
				d.snmpAgent.NotifyLinkUp(attrs.Index, attrs.Name)
			} else {
				d.snmpAgent.NotifyLinkDown(attrs.Index, attrs.Name)
			}
		}
	}
}

// syncConfigToPeer sends the active config to the cluster peer if this node
// is primary and config sync is enabled.
func (d *Daemon) syncConfigToPeer() {
	if d.cluster == nil || d.sessionSync == nil {
		return
	}
	// Only sync if this node is primary for RG0 (config ownership group).
	if !d.cluster.IsLocalPrimary(0) {
		return
	}
	d.pushConfigToPeer()
}

// pushConfigToPeer sends the active config to the cluster peer unconditionally
// (does not check primary/secondary status). Used both by normal commit sync
// and by the peer-reconnect path where the stable node pushes its config
// regardless of whether it was preempted.
func (d *Daemon) pushConfigToPeer() {
	if d.sessionSync == nil {
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
	d.sessionSync.QueueConfig(configText)
}

// handleConfigSync processes a config received from the cluster peer.
// Config sync is unidirectional: primary → secondary only. If this node
// is the RG0 primary (config authority), incoming config is rejected to
// prevent a reconnecting secondary from overwriting the authoritative config.
func (d *Daemon) handleConfigSync(configText string) {
	if d.cluster != nil && d.cluster.IsLocalPrimary(0) {
		slog.Warn("cluster: rejecting config sync (this node is RG0 primary)")
		return
	}
	slog.Info("cluster: accepting config sync from peer", "size", len(configText))

	compiled, err := d.store.SyncApply(configText, nil)
	if err != nil {
		slog.Error("cluster: config sync apply failed", "err", err)
		return
	}

	// Apply the compiled config to the dataplane.
	if compiled != nil {
		d.applyConfig(compiled)
	}
	slog.Info("cluster: config sync applied successfully")
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
	commsCtx, commsCancel := context.WithCancel(ctx)
	d.clusterCommsCancel = commsCancel
	d.activeClusterTransport = clusterTransportFromConfig(cfg)

	// Determine VRF device if control/fabric interfaces are in mgmt VRF.
	// Check mgmtVRFInterfaces first, then fall back to probing the control
	// interface directly (handles config-only mode where applyConfig may
	// have run but mgmtVRFInterfaces is empty due to VRF creation failure).
	vrfDevice := ""
	if len(d.mgmtVRFInterfaces) > 0 {
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
	if d.dp != nil && len(cc.RedundancyGroups) > 0 {
		go func() {
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-commsCtx.Done():
					return
				case <-ticker.C:
					var ts unix.Timespec
					_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
					now := uint64(ts.Sec)
					for _, rg := range cc.RedundancyGroups {
						if err := d.dp.UpdateHAWatchdog(rg.ID, now); err != nil {
							slog.Warn("ha watchdog write failed", "rg", rg.ID, "err", err)
						}
					}
				}
			}
		}()
		slog.Info("HA watchdog heartbeat started", "rgs", len(cc.RedundancyGroups))
	}

	// Propagate strict-vip-ownership mode to RG state machines.
	for _, rg := range cc.RedundancyGroups {
		if rg.StrictVIPOwnership {
			s := d.getOrCreateRGState(rg.ID)
			s.SetStrictVIPOwnership(true)
			slog.Info("cluster: strict-vip-ownership enabled for RG",
				"rg", rg.ID)
		}
	}

	// Start heartbeat if control-interface and peer-address are configured.
	// Retry on bind failure: the control interface address and VRF device
	// may not be ready during daemon startup (networkd race).
	if cc.ControlInterface != "" && cc.PeerAddress != "" {
		go func() {
			for i := 0; i < 30; i++ {
				localIP := resolveInterfaceAddr(cc.ControlInterface, "")
				if localIP == "" {
					if i == 0 {
						slog.Info("cluster: control interface has no IPv4 address yet, waiting",
							"interface", cc.ControlInterface)
					}
					time.Sleep(2 * time.Second)
					continue
				}
				if err := d.cluster.StartHeartbeat(localIP, cc.PeerAddress, vrfDevice); err != nil {
					if i < 5 {
						slog.Info("cluster: heartbeat bind not ready, retrying",
							"err", err, "attempt", i+1)
					} else {
						slog.Warn("failed to start cluster heartbeat, retrying",
							"err", err, "attempt", i+1)
					}
					time.Sleep(2 * time.Second)
					continue
				}
				return
			}
			slog.Error("cluster heartbeat failed after retries")
		}()
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
		go func() {
			var syncIP string
			for i := 0; i < 30; i++ {
				syncIP = resolveInterfaceAddr(syncIface, "")
				if syncIP != "" {
					break
				}
				if i == 0 {
					slog.Info("cluster: sync interface has no IPv4 address yet, waiting",
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

			syncLocal := fmt.Sprintf("%s:4785", syncIP)
			syncPeer := fmt.Sprintf("%s:4785", syncPeerAddr)
			slog.Info("cluster: session sync transport", "mode", syncTransport,
				"local", syncLocal, "peer", syncPeer)

			// Resolve secondary fabric (fab1) for dual transport failover.
			// Only applicable when using fabric transport (not control-link).
			var syncLocal1, syncPeer1 string
			if syncTransport == "fabric" && cc.Fabric1Interface != "" && cc.Fabric1PeerAddress != "" {
				var fab1IP string
				for i := 0; i < 15; i++ {
					fab1IP = resolveInterfaceAddr(cc.Fabric1Interface, "")
					if fab1IP != "" {
						break
					}
					if i == 0 {
						slog.Info("cluster: fabric1 interface has no IPv4 address yet, waiting",
							"interface", cc.Fabric1Interface)
					}
					select {
					case <-commsCtx.Done():
						return
					case <-time.After(2 * time.Second):
					}
				}
				if fab1IP != "" {
					syncLocal1 = fmt.Sprintf("%s:4785", fab1IP)
					syncPeer1 = fmt.Sprintf("%s:4785", cc.Fabric1PeerAddress)
					slog.Info("cluster: dual fabric transport configured",
						"fab0_local", syncLocal, "fab1_local", syncLocal1)
				} else {
					slog.Warn("cluster: fabric1 address not available, using single fabric only",
						"interface", cc.Fabric1Interface)
				}
			}

			if syncLocal1 != "" {
				d.sessionSync = cluster.NewDualSessionSync(syncLocal, syncPeer, syncLocal1, syncPeer1, nil)
			} else {
				d.sessionSync = cluster.NewSessionSync(syncLocal, syncPeer, nil)
			}

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
			d.cluster.SetSyncStats(d.sessionSync)

			// Wire config sync callback: when secondary receives config from primary.
			d.sessionSync.OnConfigReceived = func(configText string) {
				d.cluster.RecordEvent(cluster.EventConfigSync, -1, fmt.Sprintf("Config received (%d bytes)", len(configText)))
				d.handleConfigSync(configText)
			}

			// Wire peer connected callback: push config to returning peer.
			// Only push if this node is RG0 primary (config authority) and
			// has been running >30s (stable node). A freshly started node
			// must NOT push stale config from disk.
			d.sessionSync.OnPeerConnected = func() {
				d.cluster.RecordEvent(cluster.EventFabric, -1, "Peer connected")
				d.onSessionSyncPeerConnected()
				if d.cluster == nil || !d.cluster.IsLocalPrimary(0) {
					slog.Info("cluster: skipping config push (not RG0 primary)")
					return
				}
				if time.Since(d.startTime) < 30*time.Second {
					slog.Info("cluster: skipping config push (daemon just started)")
					return
				}
				slog.Info("cluster: pushing config to reconnected peer")
				d.pushConfigToPeer()
			}

			d.sessionSync.OnBulkSyncReceived = func() {
				d.cluster.RecordEvent(cluster.EventColdSync, -1, "Bulk sync completed")
				slog.Info("cluster: session sync complete, releasing VRRP hold")
				d.onSessionSyncBulkReceived()
			}

			d.sessionSync.OnBulkSyncAckReceived = func() {
				d.cluster.RecordEvent(cluster.EventColdSync, -1, "Bulk sync acknowledged by peer")
				d.onSessionSyncBulkAckReceived()
			}

			d.sessionSync.OnPeerDisconnected = func() {
				d.cluster.RecordEvent(cluster.EventFabric, -1, "Peer disconnected (all fabrics)")
				d.onSessionSyncPeerDisconnected()
			}

			// Wire remote failover: when peer requests us to give up primary.
			// Guard: only honor the request if we are actually primary for
			// this RG. Stale/delayed sync messages can arrive after we've
			// already transitioned to secondary — blindly calling
			// ManualFailover would cause dual-resign (both nodes secondary)
			// and a 30-second traffic blackhole.
			d.sessionSync.OnRemoteFailover = func(rgID int) {
				if !d.cluster.IsLocalPrimary(rgID) {
					slog.Warn("cluster: ignoring remote failover request (not primary)",
						"rg", rgID)
					return
				}
				slog.Info("cluster: remote failover request from peer", "rg", rgID)
				if err := d.cluster.ManualFailover(rgID); err != nil {
					slog.Warn("cluster: remote failover failed", "rg", rgID, "err", err)
				}
			}

			// Wire peer failover sender so cluster Manager can send remote
			// failover requests via the fabric sync connection.
			d.cluster.SetPeerFailoverFunc(d.sessionSync.SendFailover)
			d.cluster.SetPreManualFailoverHook(d.prepareUserspaceManualFailover)
			d.cluster.SetPeerTimeoutGuard(d.shouldSuppressPeerHeartbeatTimeout)

			// Wire peer fencing: on heartbeat timeout, cluster sends
			// fence via sync; on receive, disable all local RGs.
			d.cluster.SetPeerFenceFunc(d.sessionSync.SendFence)
			d.sessionSync.OnFenceReceived = func() {
				slog.Warn("cluster: fence received from peer, disabling all RGs")
				if cfg.Chassis.Cluster != nil {
					for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
						if err := d.dp.UpdateRGActive(rg.ID, false); err != nil {
							slog.Warn("cluster: fence: failed to disable rg_active",
								"rg", rg.ID, "err", err)
						}
					}
				}
			}

			d.sessionSync.SetVRFDevice(vrfDevice)
			// Retry sync start: the VRF device and address binding may not
			// be ready during daemon startup (networkd race).
			for i := 0; i < 30; i++ {
				if err := d.sessionSync.Start(commsCtx); err != nil {
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

				// Wire dataplane into session sync and start the sweep.
				// Must happen here (not in Run) because d.sessionSync is
				// created asynchronously in this goroutine.
				if d.dp != nil {
					d.sessionSync.SetDataPlane(d.dp)
					d.sessionSync.IsPrimaryFn = func() bool {
						return d.cluster != nil && d.cluster.IsLocalPrimary(0)
					}
					d.sessionSync.IsPrimaryForRGFn = func(rgID int) bool {
						return d.cluster != nil && d.cluster.IsLocalPrimary(rgID)
					}
					d.sessionSync.StartSyncSweep(commsCtx)
					go d.runUserspaceEventStream(commsCtx)
				}

				break
			}

			// Start periodic IPsec SA sync if enabled.
			if cc.IPsecSASync && d.ipsec != nil {
				go d.syncIPsecSAPeriodic(commsCtx)
			}

			// Initialize fabric refresh channel for event-driven updates (#124).
			d.fabricRefreshCh = make(chan struct{}, 1)

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
			go d.populateFabricFwd(commsCtx, fabParent, fabOverlay, cc.FabricPeerAddress)

			// Populate secondary fabric_fwd entry (key=1) if fab1 configured.
			if cc.Fabric1Interface != "" && cc.Fabric1PeerAddress != "" {
				fab1Parent := d.resolveFabricParent(cc.Fabric1Interface)
				fab1Overlay := config.LinuxIfName(cc.Fabric1Interface)
				if fab1Overlay == fab1Parent {
					fab1Overlay = "" // no overlay
				}
				go d.populateFabricFwd1(commsCtx, fab1Parent, fab1Overlay, cc.Fabric1PeerAddress)
			}

			// Monitor fabric link/neighbor state via netlink (#124).
			go d.monitorFabricState(commsCtx)
		}()
	}
}

// stopClusterComms tears down heartbeat and session sync so they can be
// restarted with new transport settings (#87). Cancels the comms sub-context
// (which stops retry loops, fabric_fwd refresh, IPsec SA sync, sync sweep)
// and explicitly stops heartbeat + session sync listeners/connections.
func (d *Daemon) stopClusterComms() {
	if d.clusterCommsCancel != nil {
		d.clusterCommsCancel()
		d.clusterCommsCancel = nil
	}
	if d.cluster != nil {
		d.cluster.StopHeartbeat()
	}
	if d.sessionSync != nil {
		d.stopSyncReadyTimer()
		d.sessionSync.Stop()
		d.sessionSync = nil
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

// ensureFabricIPVLAN creates an IPVLAN L2 interface on top of parent for
// fabric IP addressing. The parent keeps its ge-X-0-Y name (XDP/TC attaches
// there); the IPVLAN carries the fabric IP used for session sync.
// Idempotent: skips creation if the IPVLAN already exists on the correct parent.
func ensureFabricIPVLAN(parent, name string, addrs []string) error {
	parentLink, err := netlink.LinkByName(parent)
	if err != nil {
		return fmt.Errorf("parent %s: %w", parent, err)
	}

	// Ensure parent is UP — IPVLAN inherits carrier from parent.
	netlink.LinkSetUp(parentLink)

	// Set jumbo MTU on parent for fabric throughput — IPVLAN inherits
	// parent MTU as upper bound, so parent must be set first.
	if parentLink.Attrs().MTU < 9000 {
		if err := netlink.LinkSetMTU(parentLink, 9000); err != nil {
			slog.Warn("fabric: failed to set parent MTU 9000",
				"parent", parent, "err", err)
		}
	}

	// Check if IPVLAN already exists on correct parent.
	if existing, err := netlink.LinkByName(name); err == nil {
		if existing.Attrs().ParentIndex == parentLink.Attrs().Index {
			// Already correct — reconcile addresses, MTU, and ensure UP (#127).
			if existing.Attrs().MTU < 9000 {
				netlink.LinkSetMTU(existing, 9000)
			}
			reconcileIPVLANAddrs(existing, name, addrs)
			netlink.LinkSetUp(existing)
			return nil
		}
		// Wrong parent — remove and recreate.
		netlink.LinkDel(existing)
	}

	ipvlan := &netlink.IPVlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        name,
			ParentIndex: parentLink.Attrs().Index,
		},
		Mode: netlink.IPVLAN_MODE_L2,
	}
	if err := netlink.LinkAdd(ipvlan); err != nil {
		return fmt.Errorf("create IPVLAN %s on %s: %w", name, parent, err)
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("find created IPVLAN %s: %w", name, err)
	}

	// Set jumbo MTU on IPVLAN overlay (must not exceed parent MTU).
	if err := netlink.LinkSetMTU(link, 9000); err != nil {
		slog.Warn("fabric IPVLAN: failed to set MTU 9000",
			"name", name, "err", err)
	}

	// Add configured addresses.
	for _, addrStr := range addrs {
		addr, err := netlink.ParseAddr(addrStr)
		if err != nil {
			slog.Warn("fabric IPVLAN: invalid address", "addr", addrStr, "err", err)
			continue
		}
		if err := netlink.AddrReplace(link, addr); err != nil {
			slog.Warn("fabric IPVLAN: failed to add address",
				"name", name, "addr", addrStr, "err", err)
		}
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring up %s: %w", name, err)
	}
	slog.Info("created fabric IPVLAN", "name", name, "parent", parent,
		"addrs", addrs)
	return nil
}

// reconcileIPVLANAddrs adds missing addresses and removes stale ones from an
// existing IPVLAN interface (#127). Called when ensureFabricIPVLAN finds the
// overlay already exists on the correct parent.
func reconcileIPVLANAddrs(link netlink.Link, name string, desired []string) {
	// Build set of desired addresses (normalized to CIDR strings).
	want := make(map[string]*netlink.Addr, len(desired))
	for _, addrStr := range desired {
		addr, err := netlink.ParseAddr(addrStr)
		if err != nil {
			slog.Warn("fabric IPVLAN: invalid address in config", "addr", addrStr, "err", err)
			continue
		}
		want[addr.IPNet.String()] = addr
	}

	// Get current addresses.
	existing, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		slog.Warn("fabric IPVLAN: failed to list addresses", "name", name, "err", err)
		return
	}

	// Remove stale addresses not in desired set.
	have := make(map[string]bool, len(existing))
	for _, a := range existing {
		key := a.IPNet.String()
		have[key] = true
		if _, ok := want[key]; !ok {
			if err := netlink.AddrDel(link, &a); err != nil {
				slog.Warn("fabric IPVLAN: failed to remove stale address",
					"name", name, "addr", key, "err", err)
			} else {
				slog.Info("fabric IPVLAN: removed stale address",
					"name", name, "addr", key)
			}
		}
	}

	// Add missing addresses.
	for key, addr := range want {
		if !have[key] {
			if err := netlink.AddrReplace(link, addr); err != nil {
				slog.Warn("fabric IPVLAN: failed to add address",
					"name", name, "addr", key, "err", err)
			} else {
				slog.Info("fabric IPVLAN: added missing address",
					"name", name, "addr", key)
			}
		}
	}
}

// CleanupFabricIPVLANs removes all fabric IPVLAN interfaces (fab0, fab1).
func CleanupFabricIPVLANs() {
	for _, name := range []string{"fab0", "fab1"} {
		if link, err := netlink.LinkByName(name); err == nil {
			if _, ok := link.(*netlink.IPVlan); ok {
				netlink.LinkDel(link)
				slog.Info("removed fabric IPVLAN", "name", name)
			}
		}
	}
}

// resolveFabricParent returns the Linux name of the physical parent interface
// for a fabric interface (e.g. fab0 → ge-0-0-0). Falls back to fabName if
// no LocalFabricMember is configured (legacy mode).
func (d *Daemon) resolveFabricParent(fabName string) string {
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return fabName
	}
	if ifCfg, ok := cfg.Interfaces.Interfaces[fabName]; ok && ifCfg.LocalFabricMember != "" {
		return config.LinuxIfName(ifCfg.LocalFabricMember)
	}
	return fabName
}

// populateFabricFwd resolves the fabric interface MACs and populates the
// fabric_fwd BPF map for cross-chassis packet redirect during failback.
// fabIface is the physical parent (XDP attachment point); overlay is the
// IPVLAN child where the sync IP lives (neighbor resolution target, #129).
// If overlay is empty, fabIface is used for both (legacy/no-IPVLAN mode).
// Attempts immediately on startup with fast 500ms retries (10 attempts),
// then falls back to 30s periodic refresh.
func (d *Daemon) populateFabricFwd(ctx context.Context, fabIface, overlay, peerAddr string) {
	peerIP := net.ParseIP(peerAddr)
	if peerIP == nil {
		slog.Warn("cluster: invalid fabric peer address", "addr", peerAddr)
		return
	}
	if overlay == "" {
		overlay = fabIface
	}

	// Store fabric config for RefreshFabricFwd.
	d.fabricMu.Lock()
	d.fabricIface = fabIface
	d.fabricOverlay = overlay
	d.fabricPeerIP = peerIP
	d.fabricMu.Unlock()

	// Fast initial population: attempt immediately, then 500ms retries.
	for i := 0; i < 10; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(500 * time.Millisecond):
			}
		}

		// Actively probe for neighbor entry on the overlay (#129).
		d.probeFabricNeighbor(ctx, overlay, peerIP)

		if d.refreshFabricFwd(fabIface, overlay, peerIP, i == 0) {
			break
		}
		if i == 9 {
			slog.Warn("cluster: fabric_fwd not populated after fast retries, continuing with periodic refresh")
		}
	}

	// Periodic refresh every 30s as safety net, plus event-driven
	// refresh via fabricRefreshCh from netlink monitor (#124).
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.refreshFabricFwd(fabIface, overlay, peerIP, false)
		case <-d.fabricRefreshCh:
			d.refreshFabricFwd(fabIface, overlay, peerIP, false)
		}
	}
}

// probeFabricNeighbor triggers ARP/NDP resolution for the fabric peer
// if no neighbor entry exists. Uses ping (not arping) because arping's
// PF_PACKET raw sockets don't populate the kernel ARP table with XDP attached.
func (d *Daemon) probeFabricNeighbor(ctx context.Context, fabIface string, peerIP net.IP) {
	link, err := netlink.LinkByName(fabIface)
	if err != nil {
		return
	}

	neighFamily := netlink.FAMILY_V4
	if peerIP.To4() == nil {
		neighFamily = netlink.FAMILY_V6
	}
	neighs, _ := netlink.NeighList(link.Attrs().Index, neighFamily)
	for _, n := range neighs {
		if n.IP.Equal(peerIP) && len(n.HardwareAddr) == 6 &&
			(n.State&(netlink.NUD_REACHABLE|netlink.NUD_STALE|netlink.NUD_PERMANENT|netlink.NUD_DELAY|netlink.NUD_PROBE)) != 0 {
			return // Entry exists, no probe needed.
		}
	}

	// No neighbor entry — trigger ARP/NDP resolution via raw ICMP probe.
	sendICMPProbe(fabIface, peerIP)

	// Also probe on the parent interface if this is an IPVLAN overlay.
	// After crash recovery, the IPVLAN overlay may not respond to ARP
	// (stale MAC, vrf-mgmt routing isolation). The parent (ge-X-0-0)
	// is a real NIC on the same L2 segment — ARP on it is more reliable.
	// Additionally, send IPv6 ff02::1 multicast on the parent to populate
	// the NDP table with the peer's MAC as a fallback.
	if parentIdx := link.Attrs().ParentIndex; parentIdx > 0 {
		if parent, err := netlink.LinkByIndex(parentIdx); err == nil {
			parentName := parent.Attrs().Name
			sendICMPProbe(parentName, peerIP)
			sendIPv6MulticastProbe(parentName, parentIdx)
		}
	}
}

// sendICMPProbe sends a single raw ICMP/ICMPv6 echo request bound to
// the given interface. This triggers kernel ARP/NDP resolution without
// shelling out to ping. Non-blocking: sendto MSG_DONTWAIT.
func sendICMPProbe(iface string, target net.IP) {
	if target.To4() != nil {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
		if err != nil {
			return
		}
		defer unix.Close(fd)
		_ = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		// ICMP echo: type=8, code=0, checksum=0xf7ff, id=0, seq=0
		icmp := [8]byte{8, 0, 0xf7, 0xff, 0, 0, 0, 0}
		sa := &unix.SockaddrInet4{}
		copy(sa.Addr[:], target.To4())
		_ = unix.Sendto(fd, icmp[:], unix.MSG_DONTWAIT, sa)
	} else {
		fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_ICMPV6)
		if err != nil {
			return
		}
		defer unix.Close(fd)
		_ = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		// ICMPv6 auto-checksum at offset 2
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_ICMPV6, unix.IPV6_CHECKSUM, 2)
		// ICMPv6 echo: type=128, code=0, checksum=0 (kernel fills), id=0, seq=0
		icmp6 := [8]byte{128, 0, 0, 0, 0, 0, 0, 0}
		sa6 := &unix.SockaddrInet6{}
		copy(sa6.Addr[:], target.To16())
		_ = unix.Sendto(fd, icmp6[:], unix.MSG_DONTWAIT, sa6)
	}
}

// sendIPv6MulticastProbe sends an ICMPv6 echo request to ff02::1 (all-nodes
// multicast) on the given interface. All link-local nodes respond, populating
// the IPv6 neighbor table with their MACs. This provides a reliable fallback
// for discovering the fabric peer's MAC when IPv4 ARP fails (e.g. after
// crash recovery with RETH MAC changes on IPVLAN overlays).
func sendIPv6MulticastProbe(iface string, ifindex int) {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_ICMPV6)
	if err != nil {
		return
	}
	defer unix.Close(fd)
	_ = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_ICMPV6, unix.IPV6_CHECKSUM, 2)
	// ICMPv6 echo request: type=128, code=0, checksum=0 (kernel fills)
	icmp6 := [8]byte{128, 0, 0, 0, 0, 0, 0, 1}
	sa6 := &unix.SockaddrInet6{ZoneId: uint32(ifindex)}
	// ff02::1 — all-nodes link-local multicast
	copy(sa6.Addr[:], net.ParseIP("ff02::1").To16())
	_ = unix.Sendto(fd, icmp6[:], unix.MSG_DONTWAIT, sa6)
}

func (d *Daemon) logFabricRefreshFailure(slot int, msg string, args ...any) {
	d.fabricMu.Lock()
	now := time.Now()
	last := d.lastFabricLog0
	if slot == 1 {
		last = d.lastFabricLog1
	}
	if now.Sub(last) < 2*time.Second {
		d.fabricMu.Unlock()
		return
	}
	if slot == 0 {
		d.lastFabricLog0 = now
	} else {
		d.lastFabricLog1 = now
	}
	d.fabricMu.Unlock()
	slog.Info(msg, args...)
}

// refreshFabricFwd resolves fabric link/neighbor state and updates the
// fabric_fwd BPF map. Returns true on success. Called during initial
// population and periodic drift correction.
// fabIface is the physical parent (for ifindex/MAC); overlay is the IPVLAN
// child where the sync IP lives (for neighbor resolution, #129).
func (d *Daemon) refreshFabricFwd(fabIface, overlay string, peerIP net.IP, logWaiting bool) bool {
	link, err := netlink.LinkByName(fabIface)
	if err != nil {
		d.logFabricRefreshFailure(0, "cluster: fabric refresh failed (link not found)",
			"interface", fabIface, "err", err)
		d.clearFabricFwd0()
		return false
	}
	localMAC := link.Attrs().HardwareAddr
	if len(localMAC) != 6 {
		d.logFabricRefreshFailure(0, "cluster: fabric refresh failed (invalid local mac)",
			"interface", fabIface, "local_mac", localMAC)
		d.clearFabricFwd0()
		return false
	}

	// Check oper-state: non-UP interfaces cannot forward (#122).
	operState := link.Attrs().OperState
	if operState != netlink.OperUp && operState != netlink.OperUnknown {
		d.logFabricRefreshFailure(0, "cluster: fabric refresh failed (link not operational)",
			"interface", fabIface, "oper_state", operState)
		d.clearFabricFwd0()
		return false
	}

	// Increase fabric txqueuelen for generic XDP.
	if link.Attrs().TxQLen < 10000 {
		if err := netlink.LinkSetTxQLen(link, 10000); err != nil {
			slog.Warn("cluster: failed to set fabric txqueuelen",
				"interface", fabIface, "err", err)
		}
	}

	// Resolve peer MAC from ARP/NDP table on the overlay interface (#129).
	// The sync IP lives on the overlay (fab0/fab1), so neighbor entries
	// are associated with the overlay's ifindex, not the parent's.
	neighLink := link
	if overlay != fabIface {
		if ol, err := netlink.LinkByName(overlay); err == nil {
			neighLink = ol
		}
	}
	neighFamily := netlink.FAMILY_V4
	if peerIP.To4() == nil {
		neighFamily = netlink.FAMILY_V6
	}

	validState := netlink.NUD_REACHABLE | netlink.NUD_STALE | netlink.NUD_PERMANENT | netlink.NUD_DELAY | netlink.NUD_PROBE

	neighs, err := netlink.NeighList(neighLink.Attrs().Index, neighFamily)
	if err != nil {
		d.logFabricRefreshFailure(0, "cluster: fabric refresh failed (neighbor list)",
			"overlay", neighLink.Attrs().Name, "peer", peerIP, "err", err)
		d.clearFabricFwd0()
		return false
	}
	var peerMAC net.HardwareAddr
	for _, n := range neighs {
		if n.IP.Equal(peerIP) && len(n.HardwareAddr) == 6 &&
			(n.State&validState) != 0 {
			peerMAC = n.HardwareAddr
			break
		}
	}

	// Fallback: if overlay ARP failed, try the parent interface's neighbor
	// tables (both IPv4 and IPv6). After crash recovery, the IPVLAN overlay
	// may not resolve ARP due to stale MAC or VRF isolation, but the parent
	// (ge-X-0-0) is a real NIC on the same L2 — its ARP/NDP is reliable.
	if peerMAC == nil {
		parentIdx := neighLink.Attrs().ParentIndex
		if parentIdx == 0 {
			parentIdx = link.Attrs().Index // use fabric parent directly
		}
		// Check parent IPv4 neighbors for the peer IP.
		parentNeighs, _ := netlink.NeighList(parentIdx, neighFamily)
		for _, n := range parentNeighs {
			if n.IP.Equal(peerIP) && len(n.HardwareAddr) == 6 &&
				(n.State&validState) != 0 {
				peerMAC = n.HardwareAddr
				slog.Info("cluster: fabric peer MAC resolved via parent ARP",
					"peer_mac", peerMAC, "overlay", overlay)
				break
			}
		}
		// Check parent IPv6 NDP neighbors (populated via ff02::1 probe).
		if peerMAC == nil {
			v6Neighs, _ := netlink.NeighList(parentIdx, netlink.FAMILY_V6)
			for _, n := range v6Neighs {
				if len(n.HardwareAddr) != 6 || (n.State&validState) == 0 {
					continue
				}
				if !n.IP.IsLinkLocalUnicast() {
					continue
				}
				if bytes.Equal(n.HardwareAddr, localMAC) {
					continue
				}
				peerMAC = n.HardwareAddr
				slog.Info("cluster: fabric peer MAC resolved via parent IPv6 NDP",
					"peer_mac", peerMAC, "peer_ll", n.IP, "overlay", overlay)
				break
			}
		}
	}

	if peerMAC == nil {
		if logWaiting {
			slog.Info("cluster: waiting for fabric peer neighbor entry",
				"peer", peerIP, "overlay", overlay)
		} else {
			d.logFabricRefreshFailure(0, "cluster: fabric refresh failed (missing peer neighbor)",
				"peer", peerIP, "overlay", overlay)
		}
		d.clearFabricFwd0()
		return false
	}

	// Use parent's ifindex for redirect — XDP runs on the parent.
	info := dataplane.FabricFwdInfo{
		Ifindex: uint32(link.Attrs().Index),
	}
	copy(info.PeerMAC[:], peerMAC)
	copy(info.LocalMAC[:], localMAC)

	// Find a non-VRF interface for zone-decoded FIB lookups.
	// Prefer the fabric interface itself (known UP, non-VRF).
	// Fall back to loopback (ifindex 1): always present, always
	// UP, never a VRF member — deterministic across reboots.
	info.FIBIfindex = uint32(link.Attrs().Index)
	if link.Attrs().MasterIndex != 0 {
		// Fabric link is a VRF member — use loopback for
		// main-table FIB lookups (avoids l3mdev interference).
		info.FIBIfindex = 1
	}

	if d.dp == nil {
		d.logFabricRefreshFailure(0, "cluster: fabric refresh failed (dataplane not ready)")
		return false
	}
	if err := d.dp.UpdateFabricFwd(info); err != nil {
		slog.Warn("cluster: failed to update fabric_fwd map", "err", err)
		return false
	}

	d.fabricMu.Lock()
	d.fabricPopulated = true
	d.fabricMu.Unlock()

	slog.Info("cluster: fabric_fwd updated",
		"interface", fabIface, "ifindex", info.Ifindex,
		"fib_ifindex", info.FIBIfindex,
		"local_mac", localMAC, "peer_mac", peerMAC)

	// Push updated fabric MACs to userspace helper so it can do
	// cross-chassis fabric redirect. The initial snapshot may have
	// been built before the peer MAC was resolved.
	if d.dp != nil {
		d.dp.SyncFabricState()
	}

	return true
}

// clearFabricFwd0 writes a zeroed FabricFwdInfo to key=0 if a valid entry
// was previously written, ensuring the dataplane falls back (#121).
func (d *Daemon) clearFabricFwd0() {
	d.fabricMu.RLock()
	populated := d.fabricPopulated
	d.fabricMu.RUnlock()
	if !populated || d.dp == nil {
		return
	}
	if err := d.dp.UpdateFabricFwd(dataplane.FabricFwdInfo{}); err != nil {
		slog.Warn("cluster: failed to clear fabric_fwd[0]", "err", err)
		return
	}
	d.fabricMu.Lock()
	d.fabricPopulated = false
	d.fabricMu.Unlock()
	slog.Info("cluster: fabric_fwd[0] cleared (path down)")
}

// populateFabricFwd1 resolves the secondary fabric interface MACs and populates
// the fabric_fwd BPF map entry at key=1 for cross-chassis packet redirect.
// Mirrors populateFabricFwd but writes to key=1 via UpdateFabricFwd1.
func (d *Daemon) populateFabricFwd1(ctx context.Context, fabIface, overlay, peerAddr string) {
	peerIP := net.ParseIP(peerAddr)
	if peerIP == nil {
		slog.Warn("cluster: invalid fabric1 peer address", "addr", peerAddr)
		return
	}
	if overlay == "" {
		overlay = fabIface
	}

	// Store fabric1 config for RefreshFabricFwd.
	d.fabricMu.Lock()
	d.fabricIface1 = fabIface
	d.fabricOverlay1 = overlay
	d.fabricPeerIP1 = peerIP
	d.fabricMu.Unlock()

	// Fast initial population: attempt immediately, then 500ms retries.
	for i := 0; i < 10; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(500 * time.Millisecond):
			}
		}

		// Probe on the overlay (#129).
		d.probeFabricNeighbor(ctx, overlay, peerIP)

		if d.refreshFabricFwd1(fabIface, overlay, peerIP, i == 0) {
			break
		}
		if i == 9 {
			slog.Warn("cluster: fabric1_fwd not populated after fast retries, continuing with periodic refresh")
		}
	}

	// Periodic refresh every 30s as safety net, plus event-driven
	// refresh via fabricRefreshCh from netlink monitor (#124).
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.refreshFabricFwd1(fabIface, overlay, peerIP, false)
		case <-d.fabricRefreshCh:
			d.refreshFabricFwd1(fabIface, overlay, peerIP, false)
		}
	}
}

// refreshFabricFwd1 resolves secondary fabric link/neighbor state and updates
// the fabric_fwd BPF map at key=1. Returns true on success.
// fabIface is the physical parent; overlay is the IPVLAN child (#129).
func (d *Daemon) refreshFabricFwd1(fabIface, overlay string, peerIP net.IP, logWaiting bool) bool {
	link, err := netlink.LinkByName(fabIface)
	if err != nil {
		d.logFabricRefreshFailure(1, "cluster: fabric1 refresh failed (link not found)",
			"interface", fabIface, "err", err)
		d.clearFabricFwd1()
		return false
	}
	localMAC := link.Attrs().HardwareAddr
	if len(localMAC) != 6 {
		d.logFabricRefreshFailure(1, "cluster: fabric1 refresh failed (invalid local mac)",
			"interface", fabIface, "local_mac", localMAC)
		d.clearFabricFwd1()
		return false
	}

	// Check oper-state: non-UP interfaces cannot forward (#122).
	operState := link.Attrs().OperState
	if operState != netlink.OperUp && operState != netlink.OperUnknown {
		d.logFabricRefreshFailure(1, "cluster: fabric1 refresh failed (link not operational)",
			"interface", fabIface, "oper_state", operState)
		d.clearFabricFwd1()
		return false
	}

	// Increase fabric txqueuelen for generic XDP.
	if link.Attrs().TxQLen < 10000 {
		if err := netlink.LinkSetTxQLen(link, 10000); err != nil {
			slog.Warn("cluster: failed to set fabric1 txqueuelen",
				"interface", fabIface, "err", err)
		}
	}

	// Resolve peer MAC from overlay interface (#129).
	neighLink := link
	if overlay != fabIface {
		if ol, err := netlink.LinkByName(overlay); err == nil {
			neighLink = ol
		}
	}
	neighFamily := netlink.FAMILY_V4
	if peerIP.To4() == nil {
		neighFamily = netlink.FAMILY_V6
	}
	neighs, err := netlink.NeighList(neighLink.Attrs().Index, neighFamily)
	if err != nil {
		d.logFabricRefreshFailure(1, "cluster: fabric1 refresh failed (neighbor list)",
			"overlay", neighLink.Attrs().Name, "peer", peerIP, "err", err)
		d.clearFabricFwd1()
		return false
	}
	var peerMAC net.HardwareAddr
	for _, n := range neighs {
		if n.IP.Equal(peerIP) && len(n.HardwareAddr) == 6 &&
			(n.State&(netlink.NUD_REACHABLE|netlink.NUD_STALE|netlink.NUD_PERMANENT|netlink.NUD_DELAY|netlink.NUD_PROBE)) != 0 {
			peerMAC = n.HardwareAddr
			break
		}
	}
	if peerMAC == nil {
		if logWaiting {
			slog.Info("cluster: waiting for fabric1 peer neighbor entry",
				"peer", peerIP, "overlay", overlay)
		} else {
			d.logFabricRefreshFailure(1, "cluster: fabric1 refresh failed (missing peer neighbor)",
				"peer", peerIP, "overlay", overlay)
		}
		d.clearFabricFwd1()
		return false
	}

	info := dataplane.FabricFwdInfo{
		Ifindex: uint32(link.Attrs().Index),
	}
	copy(info.PeerMAC[:], peerMAC)
	copy(info.LocalMAC[:], localMAC)

	info.FIBIfindex = uint32(link.Attrs().Index)
	if link.Attrs().MasterIndex != 0 {
		info.FIBIfindex = 1
	}

	if d.dp == nil {
		d.logFabricRefreshFailure(1, "cluster: fabric1 refresh failed (dataplane not ready)")
		return false
	}
	if err := d.dp.UpdateFabricFwd1(info); err != nil {
		slog.Warn("cluster: failed to update fabric1_fwd map", "err", err)
		return false
	}

	d.fabricMu.Lock()
	d.fabric1Populated = true
	d.fabricMu.Unlock()

	slog.Info("cluster: fabric1_fwd updated",
		"interface", fabIface, "ifindex", info.Ifindex,
		"fib_ifindex", info.FIBIfindex,
		"local_mac", localMAC, "peer_mac", peerMAC)
	return true
}

// clearFabricFwd1 writes a zeroed FabricFwdInfo to key=1 if a valid entry
// was previously written, ensuring the dataplane falls back (#121).
func (d *Daemon) clearFabricFwd1() {
	d.fabricMu.RLock()
	populated := d.fabric1Populated
	d.fabricMu.RUnlock()
	if !populated || d.dp == nil {
		return
	}
	if err := d.dp.UpdateFabricFwd1(dataplane.FabricFwdInfo{}); err != nil {
		slog.Warn("cluster: failed to clear fabric_fwd[1]", "err", err)
		return
	}
	d.fabricMu.Lock()
	d.fabric1Populated = false
	d.fabricMu.Unlock()
	slog.Info("cluster: fabric_fwd[1] cleared (path down)")
}

// RefreshFabricFwd triggers an immediate refresh of the fabric_fwd BPF map.
// Call this on link state changes, neighbor changes, or failover transitions.
// Refreshes both fab0 (key=0) and fab1 (key=1) entries.
func (d *Daemon) RefreshFabricFwd() {
	d.fabricMu.RLock()
	fabIface := d.fabricIface
	overlay := d.fabricOverlay
	peerIP := d.fabricPeerIP
	fabIface1 := d.fabricIface1
	overlay1 := d.fabricOverlay1
	peerIP1 := d.fabricPeerIP1
	probeAt0 := d.lastFabricProbe
	probeAt1 := d.lastFabricProbe1
	d.fabricMu.RUnlock()
	if fabIface != "" && peerIP != nil {
		if time.Since(probeAt0) >= 2*time.Second {
			d.fabricMu.Lock()
			if time.Since(d.lastFabricProbe) >= 2*time.Second {
				d.lastFabricProbe = time.Now()
				go d.probeFabricNeighbor(context.Background(), overlayOrParent(overlay, fabIface), peerIP)
			}
			d.fabricMu.Unlock()
		}
		d.refreshFabricFwd(fabIface, overlay, peerIP, false)
	}
	if fabIface1 != "" && peerIP1 != nil {
		if time.Since(probeAt1) >= 2*time.Second {
			d.fabricMu.Lock()
			if time.Since(d.lastFabricProbe1) >= 2*time.Second {
				d.lastFabricProbe1 = time.Now()
				go d.probeFabricNeighbor(context.Background(), overlayOrParent(overlay1, fabIface1), peerIP1)
			}
			d.fabricMu.Unlock()
		}
		d.refreshFabricFwd1(fabIface1, overlay1, peerIP1, false)
	}
}

func overlayOrParent(overlay, parent string) string {
	if overlay != "" {
		return overlay
	}
	return parent
}

// monitorFabricState subscribes to netlink link and neighbor updates and
// triggers immediate fabric_fwd refresh when fabric interfaces or their
// neighbor entries change (#124). The 30s ticker in populateFabricFwd
// remains as a safety net.
func (d *Daemon) monitorFabricState(ctx context.Context) {
	linkUpdates := make(chan netlink.LinkUpdate, 64)
	linkDone := make(chan struct{})
	if err := netlink.LinkSubscribe(linkUpdates, linkDone); err != nil {
		slog.Warn("cluster: failed to subscribe to link updates for fabric monitor", "err", err)
		return
	}

	neighUpdates := make(chan netlink.NeighUpdate, 64)
	neighDone := make(chan struct{})
	if err := netlink.NeighSubscribe(neighUpdates, neighDone); err != nil {
		slog.Warn("cluster: failed to subscribe to neigh updates for fabric monitor", "err", err)
		close(linkDone)
		return
	}

	slog.Info("cluster: fabric state monitor started (link + neighbor)")

	for {
		select {
		case <-ctx.Done():
			close(linkDone)
			close(neighDone)
			return
		case update, ok := <-linkUpdates:
			if !ok {
				return
			}
			name := update.Attrs().Name
			d.fabricMu.RLock()
			isFabric := name == d.fabricIface || name == d.fabricIface1 ||
				name == d.fabricOverlay || name == d.fabricOverlay1
			d.fabricMu.RUnlock()
			if isFabric {
				slog.Debug("cluster: fabric link state change detected",
					"interface", name, "oper_state", update.Attrs().OperState)
				d.triggerFabricRefresh()
			}
		case update, ok := <-neighUpdates:
			if !ok {
				return
			}
			d.fabricMu.RLock()
			isPeer := (d.fabricPeerIP != nil && update.IP.Equal(d.fabricPeerIP)) ||
				(d.fabricPeerIP1 != nil && update.IP.Equal(d.fabricPeerIP1))
			d.fabricMu.RUnlock()
			if isPeer {
				slog.Debug("cluster: fabric peer neighbor change detected",
					"ip", update.IP, "type", update.Type)
				d.triggerFabricRefresh()
			}
		}
	}
}

// triggerFabricRefresh sends a non-blocking signal to the fabric refresh
// channel, waking populateFabricFwd/populateFabricFwd1 loops.
func (d *Daemon) triggerFabricRefresh() {
	select {
	case d.fabricRefreshCh <- struct{}{}:
	default:
		// Already pending — no need to queue another.
	}
}

// getOrCreateRGState returns the rgStateMachine for the given RG, creating
// one if it doesn't exist yet.
func (d *Daemon) getOrCreateRGState(rgID int) *rgStateMachine {
	d.rgStatesMu.RLock()
	s, ok := d.rgStates[rgID]
	d.rgStatesMu.RUnlock()
	if ok {
		return s
	}
	d.rgStatesMu.Lock()
	defer d.rgStatesMu.Unlock()
	// Double-check after upgrading to write lock.
	if s, ok = d.rgStates[rgID]; ok {
		return s
	}
	s = newRGStateMachine()
	d.rgStates[rgID] = s
	return s
}

// isRethMasterState returns true when ALL VRRP instances for rgID are MASTER.
// Returns false if no instances exist for the RG.
func (d *Daemon) isRethMasterState(rgID int) bool {
	return d.getOrCreateRGState(rgID).AllVRRPMaster()
}

// isAnyRethInstanceMaster returns true if ANY VRRP instance for rgID is
// MASTER. Used by the cluster event handler to defer rg_active deactivation
// until all VRRP instances have transitioned to BACKUP.
func (d *Daemon) isAnyRethInstanceMaster(rgID int) bool {
	return d.getOrCreateRGState(rgID).AnyVRRPMaster()
}

// snapshotRethMasterState returns per-RG master state derived from all
// per-instance entries. An RG is MASTER only when ALL its instances are MASTER.
func (d *Daemon) snapshotRethMasterState() map[int]bool {
	d.rgStatesMu.RLock()
	defer d.rgStatesMu.RUnlock()
	out := make(map[int]bool, len(d.rgStates))
	for rgID, s := range d.rgStates {
		out[rgID] = s.IsActive()
	}
	return out
}

func (d *Daemon) watchClusterEvents(ctx context.Context) {
	// Debounce VRRP updates: coalesce rapid cluster events into a single
	// UpdateInstances call. Without this, every heartbeat-driven state change
	// triggers a separate update before priorities settle.
	var vrrpTimer *time.Timer
	defer func() {
		if vrrpTimer != nil {
			vrrpTimer.Stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-d.cluster.Events():
			noRethVRRP := d.isNoRethVRRP()

			// Dual-active winner reaffirm: no state change but send
			// GARPs to refresh upstream ARP/NDP caches after split-brain.
			if ev.DualActiveWin && noRethVRRP {
				d.scheduleDirectAnnounce(ev.GroupID, "dual-active-win")
				continue
			}

			// Immediate VRRP priority + resign on state transitions.
			// ResignRG sets priority=0 to prevent re-election race.
			// On Primary transition, restore priority=200 immediately
			// so the instance can accept the peer's resignation and
			// send adverts at the correct priority.
			if !noRethVRRP {
				if ev.OldState == cluster.StatePrimary &&
					(ev.NewState == cluster.StateSecondary || ev.NewState == cluster.StateSecondaryHold) {
					d.vrrpMgr.ResignRG(ev.GroupID)
				}
				if ev.NewState == cluster.StatePrimary {
					d.vrrpMgr.UpdateRGPriority(ev.GroupID, 200)
					// With preempt=false, VRRP won't self-elect even at
					// higher priority. Force MASTER since cluster state
					// is authoritative (e.g. after failover reset).
					// Only do this for intentional promotions (Secondary →
					// Primary), NOT on initial boot (SecondaryHold → Primary)
					// where VRRP should follow its own election timer.
					if ev.OldState == cluster.StateSecondary {
						d.vrrpMgr.ForceRGMaster(ev.GroupID)
					}
				}
			}

			// Update rg_active through unified state machine.
			//
			// Both cluster and VRRP events funnel through rgStateMachine
			// which determines rg_active = clusterPri || anyVrrpMaster.
			// This prevents the dual-inactive window (both nodes
			// rg_active=false during failover) and eliminates the race
			// between the two independent goroutine writers.
			//
			// Transition ordering safety:
			// - Activation: set rg_active FIRST, then remove blackholes
			// - Deactivation: add blackholes FIRST, then clear rg_active
			isPrimary := ev.NewState == cluster.StatePrimary
			clusterDemotionEdge := ev.OldState == cluster.StatePrimary && !isPrimary
			s := d.getOrCreateRGState(ev.GroupID)
			tr := s.SetCluster(isPrimary)
			if isPrimary {
				// Activation: enable forwarding first.
				// Re-read desired state to guard against a
				// concurrent VRRP goroutine that may have
				// already superseded this transition.
				if tr.Changed && d.dp != nil {
					cur, _ := s.CurrentDesired()
					if err := d.dp.UpdateRGActive(ev.GroupID, cur); err != nil {
						slog.Warn("failed to update rg_active from cluster event",
							"rg", ev.GroupID, "active", cur, "err", err)
					} else {
						s.ApplyIfCurrent(tr)
					}
				}
				// Then remove blackhole routes — FIB lookups must
				// succeed for synced sessions.
				d.removeBlackholeRoutes(ev.GroupID)
				go d.warmNeighborCache()

				// no-reth-vrrp direct mode: add VIPs + send GARPs +
				// start per-RG services on primary transition.
				if noRethVRRP {
					d.directAddVIPs(ev.GroupID)
					d.addStableRethLinkLocal(ev.GroupID)
					d.scheduleDirectAnnounce(ev.GroupID, "cluster-primary")
					d.applyRethServicesForRG(ev.GroupID)
					go func() {
						if cfg := d.store.ActiveConfig(); cfg != nil {
							d.resolveNeighbors(cfg)
						}
					}()
					go d.RefreshFabricFwd()
				}
			} else {
				// Cluster-primary demotion is the continuity-critical edge
				// for stale-owner forwarding. Stage session republish before
				// rg_active waits for VRRP to follow this transition.
				if clusterDemotionEdge && d.dp != nil {
					d.tryPrepareUserspaceRGDemotion(ev.GroupID)
				}
				// Deactivation: blackhole routes first (if transitioning
				// to inactive), then clear rg_active.
				if tr.Changed && !tr.Active {
					d.injectBlackholeRoutes(ev.GroupID)
				}
				if tr.Changed && d.dp != nil {
					cur, _ := s.CurrentDesired()
					if !cur && !clusterDemotionEdge {
						d.tryPrepareUserspaceRGDemotion(ev.GroupID)
					}
					if err := d.dp.UpdateRGActive(ev.GroupID, cur); err != nil {
						slog.Warn("failed to update rg_active from cluster event",
							"rg", ev.GroupID, "active", cur, "err", err)
					} else {
						s.ApplyIfCurrent(tr)
					}
				}

				// no-reth-vrrp direct mode: remove VIPs + stop services
				// on secondary transition.
				if noRethVRRP && tr.Changed && !tr.Active {
					d.cancelDirectAnnounce(ev.GroupID)
					d.directRemoveVIPs(ev.GroupID)
					d.removeStableRethLinkLocal(ev.GroupID)
					d.clearRethServicesForRG(ev.GroupID)
				}
			}
			if d.dp != nil {
				d.dp.BumpFIBGeneration()
			}

			// Strict VIP ownership: suppress GARP on secondary, allow on primary.
			// Not applicable with no-reth-vrrp (no VRRP instances).
			if !noRethVRRP && s.IsStrictVIPOwnership() {
				d.vrrpMgr.SetGARPSuppression(ev.GroupID, !isPrimary)
			}

			// Debounced VRRP priority update — 500ms coalesce window.
			// Skipped in no-reth-vrrp mode (no RETH VRRP instances to update).
			if !noRethVRRP {
				if vrrpTimer != nil {
					vrrpTimer.Stop()
				}
				vrrpTimer = time.AfterFunc(500*time.Millisecond, func() {
					if cfg := d.store.ActiveConfig(); cfg != nil {
						localPri := d.cluster.LocalPriorities()
						var all []*vrrp.Instance
						all = append(all, vrrp.CollectInstances(cfg)...)
						all = append(all, vrrp.CollectRethInstances(cfg, localPri)...)
						if err := d.vrrpMgr.UpdateInstances(all); err != nil {
							slog.Warn("cluster: failed to update VRRP instances", "err", err)
						}
					}
				})
			}

			// RG0-specific: config ownership and IPsec SA re-initiation.
			if ev.GroupID == 0 {
				switch ev.NewState {
				case cluster.StatePrimary:
					slog.Info("cluster: became primary for RG0, enabling config writes")
					d.store.SetClusterReadOnly(false)

					// On failover to primary: re-initiate synced IPsec SAs.
					if cc := d.clusterConfig(); cc != nil && cc.IPsecSASync && d.ipsec != nil && d.sessionSync != nil {
						go d.reinitiateIPsecSAs()
					}

				case cluster.StateSecondary, cluster.StateSecondaryHold:
					slog.Info("cluster: became secondary for RG0, disabling config writes")
					d.store.SetClusterReadOnly(true)
				}
			}
		}
	}
}

// rethVRIDBase is the VRRP GroupID offset for RETH instances.
// RETH instances use GroupID = rethVRIDBase + rgID (set in pkg/vrrp/vrrp.go).
// Standalone VRRP groups use GroupID < rethVRIDBase.
const rethVRIDBase = 100

// isRethVRID returns true if the VRRP GroupID belongs to a RETH instance.
func isRethVRID(vrid int) bool {
	return vrid >= rethVRIDBase
}

// rgIDFromVRID extracts the redundancy group ID from a VRRP group ID.
// VRID = rethVRIDBase + RG ID (set in pkg/vrrp/vrrp.go).
func rgIDFromVRID(vrid int) int {
	return vrid - rethVRIDBase
}

// watchVRRPEvents monitors VRRP state changes and logs transitions.
// On MASTER transition, triggers ARP/ND warmup for synced session
// next-hops so that bpf_fib_lookup finds neighbor entries immediately.
// Also starts/stops RA senders and Kea DHCP server per-RG — in
// active/active mode, a BACKUP event for RG1 must not clear services
// started for RG0.
func (d *Daemon) watchVRRPEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-d.vrrpMgr.Events():
			if !ok {
				return
			}
			// Standalone VRRP instances (GroupID < rethVRIDBase) do not
			// participate in HA redundancy group state. Skip the
			// rg_active/blackhole logic to avoid creating phantom RG entries.
			if !isRethVRID(ev.GroupID) {
				slog.Info("vrrp: standalone state change (non-RETH)",
					"interface", ev.Interface,
					"group", ev.GroupID,
					"state", ev.State.String())
				continue
			}
			rgID := rgIDFromVRID(ev.GroupID)
			slog.Info("vrrp: state change",
				"interface", ev.Interface,
				"group", ev.GroupID,
				"rg", rgID,
				"state", ev.State.String())
			if ev.State == vrrp.StateMaster {
				s := d.getOrCreateRGState(rgID)
				tr := s.SetVRRP(ev.Interface, true)
				if tr.Changed && tr.Active && d.dp != nil {
					// Activation order: set rg_active FIRST, then
					// remove blackhole routes. Re-read desired state
					// to guard against interleaved cluster goroutine.
					// Only activate when ALL VRRP instances in the RG
					// are MASTER — prevents partial ownership (#132).
					cur, _ := s.CurrentDesired()
					if err := d.dp.UpdateRGActive(rgID, cur); err != nil {
						slog.Warn("failed to update rg_active", "rg", rgID, "err", err)
					} else {
						s.ApplyIfCurrent(tr)
					}
					d.dp.BumpFIBGeneration()
					go d.warmNeighborCache()
					go func() {
						// Resolve config-based next-hops (static routes,
						// DHCP gateways) now that RETH VIPs are installed
						// and routes are reachable.
						if cfg := d.store.ActiveConfig(); cfg != nil {
							d.resolveNeighbors(cfg)
						}
					}()
					go d.RefreshFabricFwd()
				}
				// Only remove blackholes and apply services when ALL
				// VRRP instances in the RG are MASTER (#132).
				if tr.Changed && tr.Active {
					d.removeBlackholeRoutes(rgID)
					d.addStableRethLinkLocal(rgID)
					d.applyRethServicesForRG(rgID)
				}
			}
			if ev.State == vrrp.StateBackup {
				s := d.getOrCreateRGState(rgID)
				tr := s.SetVRRP(ev.Interface, false)
				if tr.Changed && !tr.Active {
					// Deactivation order: inject blackhole routes FIRST,
					// then clear rg_active. Re-read desired state to
					// guard against interleaved cluster goroutine.
					d.injectBlackholeRoutes(rgID)
					if d.dp != nil {
						cur, _ := s.CurrentDesired()
						if !cur {
							d.tryPrepareUserspaceRGDemotion(rgID)
						}
						if err := d.dp.UpdateRGActive(rgID, cur); err != nil {
							slog.Warn("failed to update rg_active", "rg", rgID, "err", err)
						} else {
							s.ApplyIfCurrent(tr)
						}
						d.dp.BumpFIBGeneration()
						go d.RefreshFabricFwd()
					}
					d.removeStableRethLinkLocal(rgID)
					d.clearRethServicesForRG(rgID)
				}
			}
		}
	}
}

// reconcileRGStateLoop periodically reads the authoritative cluster and VRRP
// states and reconciles rgStateMachine / rg_active BPF map / blackhole routes /
// VRRP posture / RA+DHCP services.
// This is the safety net for dropped events (non-blocking channel sends).
// Runs every 2s; also wakes immediately on event-drop notifications via
// reconcileNowCh. Skips if cluster or dataplane is nil.
func (d *Daemon) reconcileRGStateLoop(ctx context.Context) {
	// Run immediately on startup to correct stale rg_active from prior run.
	d.reconcileRGState()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.reconcileRGState()
		case <-d.reconcileNowCh:
			d.reconcileRGState()
		}
	}
}

// triggerReconcile requests an immediate RG state reconciliation pass.
// Non-blocking: if a reconcile is already pending, the request is coalesced.
func (d *Daemon) triggerReconcile() {
	select {
	case d.reconcileNowCh <- struct{}{}:
	default:
	}
}

func (d *Daemon) reconcileRGState() {
	if d.cluster == nil || d.vrrpMgr == nil {
		return
	}

	// Read authoritative VRRP instance states.
	vrrpStates := d.vrrpMgr.InstanceStates()

	// Build per-RG VRRP state map: rgID → { iface → isMaster }.
	// Skip standalone (non-RETH) VRRP instances.
	rgVRRP := make(map[int]map[string]bool)
	for _, ev := range vrrpStates {
		if !isRethVRID(ev.GroupID) {
			continue
		}
		rgID := rgIDFromVRID(ev.GroupID)
		if rgVRRP[rgID] == nil {
			rgVRRP[rgID] = make(map[string]bool)
		}
		rgVRRP[rgID][ev.Interface] = (ev.State == vrrp.StateMaster)
	}

	// Collect all known RG IDs from three sources:
	// 1) existing rgStates (event-driven)
	// 2) cluster-configured groups (may exist before VRRP fires)
	// 3) RETH VRRP instances (may exist before cluster events)
	seen := make(map[int]bool)
	d.rgStatesMu.RLock()
	for rgID := range d.rgStates {
		seen[rgID] = true
	}
	d.rgStatesMu.RUnlock()
	for _, gs := range d.cluster.GroupStates() {
		seen[gs.GroupID] = true
	}
	for rgID := range rgVRRP {
		seen[rgID] = true
	}
	rgIDs := make([]int, 0, len(seen))
	for rgID := range seen {
		rgIDs = append(rgIDs, rgID)
	}

	// Evaluate per-RG readiness for the takeover gate.
	noRethVRRP := d.isNoRethVRRP()

	// Check fabric readiness — only relevant when peer is alive.
	fabricReady := true
	if d.cluster.PeerAlive() {
		d.fabricMu.RLock()
		fp := d.fabricPopulated
		d.fabricMu.RUnlock()
		if !fp {
			d.triggerFabricRefresh()
			fabricReady = false
		}
	}

	if mon := d.cluster.Monitor(); mon != nil {
		for _, rgID := range rgIDs {
			ifReady, ifReasons := mon.RGInterfaceReady(rgID)
			var vrrpReady bool
			var vrrpReasons []string
			if noRethVRRP {
				// No RETH VRRP instances — check sync readiness instead.
				// Blocks promotion until bulk session sync completes (or
				// times out), equivalent to VRRP sync-hold in RETH mode.
				vrrpReady = d.cluster.IsSyncReady()
				if !vrrpReady {
					vrrpReasons = append(vrrpReasons, "session sync not ready")
				}
				// Also verify VIP ownership can be established: RETH
				// interfaces must exist and be UP before we allow promotion.
				vipOK, vipReasons := d.checkVIPReadiness(rgID)
				if !vipOK {
					vrrpReady = false
					vrrpReasons = append(vrrpReasons, vipReasons...)
				}
			} else if d.vrrpMgr != nil {
				hasRETH := rgHasRETH(d.store.ActiveConfig(), rgID)
				vrrpReady, vrrpReasons = d.vrrpMgr.RGVRRPReady(rgID, hasRETH)
			} else {
				vrrpReady = true // no VRRP = always ready
			}
			ready := ifReady && vrrpReady && fabricReady
			var reasons []string
			reasons = append(reasons, ifReasons...)
			reasons = append(reasons, vrrpReasons...)
			if !fabricReady {
				reasons = append(reasons, "fabric forwarding path not ready")
			}
			d.cluster.SetRGReady(rgID, ready, reasons)
		}
	}

	for _, rgID := range rgIDs {
		clusterPri := d.cluster.IsLocalPrimary(rgID)
		vrrp := rgVRRP[rgID] // may be nil if no VRRP instances for this RG
		if vrrp == nil {
			vrrp = make(map[string]bool)
		}

		s := d.getOrCreateRGState(rgID)
		tr := s.Reconcile(clusterPri, vrrp)

		// Desired-vs-applied retry: even if the state machine didn't
		// change this pass, a prior UpdateRGActive failure may have
		// left applied != desired. Retry unconditionally.
		needsApply := tr.Changed || s.NeedsApply()
		if needsApply && d.dp != nil {
			if tr.Changed {
				slog.Info("reconcile: correcting rg_active drift",
					"rg", rgID, "active", tr.Active, "epoch", tr.Epoch)
			} else {
				slog.Info("reconcile: retrying rg_active apply",
					"rg", rgID, "active", tr.Active)
			}
			if tr.Active {
				// Activation ordering: set rg_active FIRST, then
				// remove blackholes.
				if err := d.dp.UpdateRGActive(rgID, true); err != nil {
					slog.Warn("reconcile: failed to update rg_active",
						"rg", rgID, "active", true, "err", err)
				} else {
					s.MarkApplied(true)
				}
				d.dp.BumpFIBGeneration()
			} else {
				// Deactivation ordering: blackholes FIRST, then
				// clear rg_active.
				d.injectBlackholeRoutes(rgID)
				d.tryPrepareUserspaceRGDemotion(rgID)
				if err := d.dp.UpdateRGActive(rgID, false); err != nil {
					slog.Warn("reconcile: failed to update rg_active",
						"rg", rgID, "active", false, "err", err)
				} else {
					s.MarkApplied(false)
				}
				d.dp.BumpFIBGeneration()
			}
		}

		// Declarative blackhole route reconciliation: assert the route
		// set that should exist regardless of prior transition results.
		// Active RGs should NOT have blackholes; inactive RGs SHOULD.
		if tr.Active {
			d.removeBlackholeRoutes(rgID)
		} else {
			d.injectBlackholeRoutes(rgID)
		}

		// VRRP posture reconciliation (#86): detect sustained mismatch
		// between cluster state and VRRP state. Only act after 10s+
		// continuous mismatch to avoid fighting transient states (VRRP
		// sync-hold, election timers, hitless restart). Skip entirely
		// during sync-hold when VRRP is intentionally suppressing preempt.
		// Also skip when no-reth-vrrp is active (no RETH VRRP instances).
		//
		// NeedsMaster: only re-send priority update — do NOT call
		// ForceRGMaster here. ForceRGMaster overrides preempt=false,
		// which should only happen from explicit cluster operations
		// (Secondary→Primary in watchClusterEvents). After a reboot
		// the transition is SecondaryHold→Primary, which intentionally
		// skips ForceRGMaster so VRRP respects non-preempt config.
		// The priority update fixes the dropped-event case (#86) while
		// letting VRRP's preempt logic decide whether to transition.
		if d.vrrpMgr != nil && !d.vrrpMgr.InSyncHold() && !noRethVRRP {
			switch s.CheckVRRPPosture(time.Now()) {
			case vrrpPostureNeedsMaster:
				slog.Warn("reconcile: VRRP posture mismatch — cluster=primary but VRRP!=MASTER, re-sending priority",
					"rg", rgID)
				d.vrrpMgr.UpdateRGPriority(rgID, 200)
			case vrrpPostureNeedsResign:
				slog.Warn("reconcile: VRRP posture mismatch — cluster=secondary but VRRP=MASTER, resigning",
					"rg", rgID)
				d.vrrpMgr.ResignRG(rgID)
			}
		}

		// Direct-mode VIP safety net: idempotently add VIPs on active
		// RGs to recover from missed events or transient address removal
		// (e.g. networkd reload). VIP removal only on state change to
		// avoid racing with event-driven directAddVIPs during failover.
		if noRethVRRP {
			if tr.Active {
				if added := d.directAddVIPs(rgID); added > 0 {
					d.scheduleDirectAnnounce(rgID, "reconcile-vip-add")
				}
			} else if tr.Changed {
				d.cancelDirectAnnounce(rgID)
				d.directRemoveVIPs(rgID)
			}
		}

		// Startup active-side announce: after a daemon restart, an RG can
		// remain active without any ownership transition. In direct mode
		// that means no failover event fires to refresh downstream ARP/NDP
		// caches, so LAN hosts can keep a failed gateway entry until they
		// happen to relearn it. Re-announce once per daemon run.
		if noRethVRRP && tr.Active && !d.startupActiveAnnounce[rgID] {
			if d.startupActiveAnnounce == nil {
				d.startupActiveAnnounce = make(map[int]bool)
			}
			d.startupActiveAnnounce[rgID] = true
			d.scheduleDirectAnnounce(rgID, "startup-active")
			go func() {
				if cfg := d.store.ActiveConfig(); cfg != nil {
					d.resolveNeighbors(cfg)
				}
			}()
		}

		// RA/DHCP service reconciliation (#93): safety net for dropped
		// VRRP events that should have started or stopped per-RG services.
		// Services (RA/DHCP) only start/stop on actual state change to
		// avoid thrashing restarts every reconcile tick.
		if tr.Changed {
			if tr.Active {
				d.applyRethServicesForRG(rgID)
			} else {
				d.clearRethServicesForRG(rgID)
			}
		}
		// Stable link-local: ensure correct on EVERY reconcile tick.
		// The kernel preserves NODAD addresses across daemon restarts,
		// so stale addresses can exist without a state transition.
		// Primary: add (idempotent — AddrAdd returns EEXIST if present).
		// Secondary: remove (idempotent — AddrDel returns ENOENT if absent).
		if tr.Active {
			d.addStableRethLinkLocal(rgID)
		} else {
			d.removeStableRethLinkLocal(rgID)
		}

		// Startup goodbye RA: when an RG is inactive on the first
		// reconcile pass (node booted as secondary), send a one-shot
		// goodbye RA (lifetime=0) to clear stale routes from a
		// previous primary run. Each RETH node has a per-node virtual
		// MAC producing a distinct link-local, so hosts see each node
		// as a separate IPv6 router. Without this, hosts ECMP-split
		// traffic to BOTH nodes even though only one is active.
		if !tr.Active && d.ra != nil && !d.startupGoodbyeRA[rgID] {
			if d.startupGoodbyeRA == nil {
				d.startupGoodbyeRA = make(map[int]bool)
			}
			d.startupGoodbyeRA[rgID] = true
			cfg := d.store.ActiveConfig()
			if cfg != nil {
				rgIfaces := rethInterfacesForRG(cfg, rgID)
				rgIfaceSet := make(map[string]bool, len(rgIfaces))
				for _, n := range rgIfaces {
					rgIfaceSet[n] = true
				}
				allRA := d.buildRAConfigs(cfg)
				var rgRA []*config.RAInterfaceConfig
				for _, ra := range allRA {
					if rgIfaceSet[ra.Interface] {
						rgRA = append(rgRA, ra)
					}
				}
				if len(rgRA) > 0 {
					go d.ra.WithdrawOnce(rgRA)
				}
			}
		}
	}
}

// rethInterfacesForRG returns the Linux interface names of RETH interfaces
// belonging to the given redundancy group.
func rethInterfacesForRG(cfg *config.Config, rgID int) []string {
	var names []string
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc.RedundancyGroup == rgID && strings.HasPrefix(name, "reth") {
			// Resolve RETH to physical member for Linux-level operations.
			resolved := config.LinuxIfName(cfg.ResolveReth(name))
			for _, unit := range ifc.Units {
				if unit.VlanID > 0 {
					names = append(names, resolved+"."+fmt.Sprintf("%d", unit.VlanID))
				} else {
					names = append(names, resolved)
				}
			}
		}
	}
	return names
}

// userspaceDataplaneActive returns true when the userspace dataplane is
// running in a mode that handles forwarding (not eBPF-only). Callers use
// this to skip eBPF-specific workarounds (blackhole routes) that the
// userspace pipeline doesn't need.
func (d *Daemon) userspaceDataplaneActive() bool {
	if um, ok := d.dp.(*dpuserspace.Manager); ok {
		return um.Mode() != dpuserspace.ModeEBPFOnly
	}
	return false
}

// injectBlackholeRoutes adds blackhole routes for RETH subnets of the given
// RG. Called on VRRP BACKUP transition — prevents bpf_fib_lookup from routing
// return traffic via the default route (which would escape via WAN). Instead,
// FIB returns BLACKHOLE and the BPF failure handler triggers fabric redirect.
func (d *Daemon) injectBlackholeRoutes(rgID int) {
	if d.userspaceDataplaneActive() {
		return
	}
	d.blackholeMu.Lock()
	defer d.blackholeMu.Unlock()

	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}

	var routes []netlink.Route
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc.RedundancyGroup != rgID || !strings.HasPrefix(name, "reth") {
			continue
		}
		for _, unit := range ifc.Units {
			for _, addr := range unit.Addresses {
				_, ipNet, err := net.ParseCIDR(addr)
				if err != nil {
					slog.Warn("blackhole: failed to parse RETH address",
						"rg", rgID, "iface", name, "addr", addr, "err", err)
					continue
				}
				rt := netlink.Route{
					Dst:      ipNet,
					Type:     unix.RTN_BLACKHOLE,
					Priority: 4242,
				}
				if err := netlink.RouteAdd(&rt); err != nil {
					if errors.Is(err, unix.EEXIST) {
						// Idempotent transition: route already present
						// from a prior BACKUP event. Track it so MASTER
						// cleanup removes it deterministically.
						routes = append(routes, rt)
						slog.Debug("blackhole: route already exists",
							"rg", rgID, "dst", ipNet)
						continue
					}
					slog.Warn("blackhole: failed to add route",
						"rg", rgID, "dst", ipNet, "err", err)
					continue
				}
				routes = append(routes, rt)
				slog.Info("blackhole: injected route for inactive RG",
					"rg", rgID, "dst", ipNet)
			}
		}
	}
	d.blackholeRoutes[rgID] = routes
}

// removeBlackholeRoutes removes blackhole routes previously injected for the
// given RG. Called on VRRP MASTER transition — the connected route returns
// naturally when the VIP is added back.
func (d *Daemon) removeBlackholeRoutes(rgID int) {
	if d.userspaceDataplaneActive() {
		return
	}
	d.blackholeMu.Lock()
	defer d.blackholeMu.Unlock()

	for _, rt := range d.blackholeRoutes[rgID] {
		if err := netlink.RouteDel(&rt); err != nil {
			if errors.Is(err, unix.ESRCH) {
				// Idempotent transition: route already gone.
				slog.Debug("blackhole: route already removed",
					"rg", rgID, "dst", rt.Dst)
				continue
			}
			slog.Warn("blackhole: failed to remove route",
				"rg", rgID, "dst", rt.Dst, "err", err)
		} else {
			slog.Info("blackhole: removed route for active RG",
				"rg", rgID, "dst", rt.Dst)
		}
	}
	delete(d.blackholeRoutes, rgID)
}

// reconcileBlackholeRoutes removes stale blackhole routes left by a previous
// daemon run. The in-memory blackholeRoutes map is lost on restart, so any
// RTN_BLACKHOLE routes with priority 4242 (our sentinel) survive in the kernel.
// Called once at startup before cluster comms start.
func (d *Daemon) reconcileBlackholeRoutes() {
	d.blackholeMu.Lock()
	defer d.blackholeMu.Unlock()

	families := []int{netlink.FAMILY_V4, netlink.FAMILY_V6}
	for _, family := range families {
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{
			Type: unix.RTN_BLACKHOLE,
		}, netlink.RT_FILTER_TYPE)
		if err != nil {
			slog.Warn("blackhole: failed to list routes for reconciliation",
				"family", family, "err", err)
			continue
		}
		for _, rt := range routes {
			if rt.Priority != 4242 {
				continue
			}
			if err := netlink.RouteDel(&rt); err != nil && !errors.Is(err, unix.ESRCH) {
				slog.Warn("blackhole: failed to remove stale route",
					"dst", rt.Dst, "err", err)
			} else {
				slog.Info("blackhole: removed stale route from previous run",
					"dst", rt.Dst)
			}
		}
	}
}

// applyRethServicesForRG starts RA senders and Kea DHCP server only for
// RETH interfaces belonging to the given RG. Called on VRRP MASTER
// transition — these services must only run on the primary to avoid
// dual-router / dual-DHCP issues.
func (d *Daemon) applyRethServicesForRG(rgID int) {
	if d.store == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	rgIfaces := rethInterfacesForRG(cfg, rgID)
	rgIfaceSet := make(map[string]bool, len(rgIfaces))
	for _, n := range rgIfaces {
		rgIfaceSet[n] = true
	}

	if d.ra != nil {
		allRA := d.buildRAConfigs(cfg)
		var rgRA []*config.RAInterfaceConfig
		for _, ra := range allRA {
			if rgIfaceSet[ra.Interface] {
				rgRA = append(rgRA, ra)
			}
		}
		// Collect RA configs from ALL master RGs (not just this one).
		for otherRG, isMaster := range d.snapshotRethMasterState() {
			if !isMaster || otherRG == rgID {
				continue
			}
			otherIfaces := rethInterfacesForRG(cfg, otherRG)
			otherSet := make(map[string]bool, len(otherIfaces))
			for _, n := range otherIfaces {
				otherSet[n] = true
			}
			for _, ra := range allRA {
				if otherSet[ra.Interface] {
					rgRA = append(rgRA, ra)
				}
			}
		}
		if len(rgRA) > 0 {
			if err := d.ra.Apply(rgRA); err != nil {
				slog.Warn("vrrp: failed to apply RA on MASTER", "rg", rgID, "err", err)
			} else {
				slog.Info("vrrp: RA senders started (MASTER)", "rg", rgID)
			}
		}
	}
	if d.dhcpServer != nil && (cfg.System.DHCPServer.DHCPLocalServer != nil || cfg.System.DHCPServer.DHCPv6LocalServer != nil) {
		dhcpCfg := d.filterDHCPConfigForMasterRGs(cfg)
		if dhcpCfg != nil {
			if err := d.dhcpServer.Apply(dhcpCfg); err != nil {
				slog.Warn("vrrp: failed to apply DHCP server on MASTER", "rg", rgID, "err", err)
			} else {
				slog.Info("vrrp: DHCP server started (MASTER)", "rg", rgID)
			}
		}
	}
}

// clearRethServicesForRG withdraws RA senders and stops DHCP server only
// for RETH interfaces belonging to the given RG. Called on VRRP BACKUP
// transition. If other RGs are still MASTER, their services remain active.
func (d *Daemon) clearRethServicesForRG(rgID int) {
	if d.store == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}

	// Check if any other RG is still master — if so, reapply services for
	// those RGs only; otherwise clear everything.
	anyOtherMaster := false
	for otherRG, isMaster := range d.snapshotRethMasterState() {
		if otherRG != rgID && isMaster {
			anyOtherMaster = true
			break
		}
	}

	if d.ra != nil {
		if anyOtherMaster {
			// Withdraw only this RG's interfaces; reapply others.
			rgIfaces := rethInterfacesForRG(cfg, rgID)
			d.ra.WithdrawInterfaces(rgIfaces)
		} else {
			if err := d.ra.Withdraw(); err != nil {
				slog.Warn("vrrp: failed to withdraw RA on BACKUP", "rg", rgID, "err", err)
			} else {
				slog.Info("vrrp: RA withdrawn (BACKUP, goodbye RA sent)", "rg", rgID)
			}
		}
	}
	if d.dhcpServer != nil {
		if anyOtherMaster {
			// Reapply DHCP with only the remaining master RGs' interfaces.
			dhcpCfg := d.filterDHCPConfigForMasterRGs(cfg)
			if dhcpCfg != nil {
				if err := d.dhcpServer.Apply(dhcpCfg); err != nil {
					slog.Warn("vrrp: failed to reapply DHCP after RG BACKUP", "rg", rgID, "err", err)
				}
			} else {
				d.dhcpServer.Clear()
			}
		} else {
			d.dhcpServer.Clear()
			slog.Info("vrrp: DHCP server stopped (BACKUP)", "rg", rgID)
		}
	}
}

// filterDHCPConfigForMasterRGs returns a DHCP config containing only groups
// whose interfaces belong to RGs that are currently MASTER. Returns nil if
// no groups match.
func (d *Daemon) filterDHCPConfigForMasterRGs(cfg *config.Config) *config.DHCPServerConfig {
	// Collect all interfaces belonging to master RGs.
	masterIfaces := make(map[string]bool)
	for rgID, isMaster := range d.snapshotRethMasterState() {
		if !isMaster {
			continue
		}
		for _, n := range rethInterfacesForRG(cfg, rgID) {
			masterIfaces[n] = true
		}
	}

	dhcpCfg := cfg.System.DHCPServer
	resolveDHCPRethInterfaces(&dhcpCfg, cfg)

	filterGroups := func(groups map[string]*config.DHCPServerGroup) map[string]*config.DHCPServerGroup {
		if groups == nil {
			return nil
		}
		result := make(map[string]*config.DHCPServerGroup)
		for name, group := range groups {
			var kept []string
			for _, iface := range group.Interfaces {
				if masterIfaces[iface] {
					kept = append(kept, iface)
				}
			}
			if len(kept) > 0 {
				cp := *group
				cp.Interfaces = kept
				result[name] = &cp
			}
		}
		return result
	}

	var result config.DHCPServerConfig
	if dhcpCfg.DHCPLocalServer != nil {
		filtered := filterGroups(dhcpCfg.DHCPLocalServer.Groups)
		if len(filtered) > 0 {
			result.DHCPLocalServer = &config.DHCPLocalServerConfig{Groups: filtered}
		}
	}
	if dhcpCfg.DHCPv6LocalServer != nil {
		filtered := filterGroups(dhcpCfg.DHCPv6LocalServer.Groups)
		if len(filtered) > 0 {
			result.DHCPv6LocalServer = &config.DHCPLocalServerConfig{Groups: filtered}
		}
	}
	if result.DHCPLocalServer == nil && result.DHCPv6LocalServer == nil {
		return nil
	}
	return &result
}

// applyRethServices starts RA senders and Kea DHCP server. Called on VRRP
// MASTER transition — these services bind to RETH member interfaces
// and must only run on the primary node to avoid dual-RA / dual-DHCP.
// Deprecated: use applyRethServicesForRG for per-RG management.
func (d *Daemon) applyRethServices() {
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	if d.ra != nil {
		raConfigs := d.buildRAConfigs(cfg)
		if len(raConfigs) > 0 {
			if err := d.ra.Apply(raConfigs); err != nil {
				slog.Warn("vrrp: failed to apply RA on MASTER", "err", err)
			} else {
				slog.Info("vrrp: RA senders started (MASTER)")
			}
		}
	}
	if d.dhcpServer != nil && (cfg.System.DHCPServer.DHCPLocalServer != nil || cfg.System.DHCPServer.DHCPv6LocalServer != nil) {
		dhcpCfg := cfg.System.DHCPServer
		resolveDHCPRethInterfaces(&dhcpCfg, cfg)
		if err := d.dhcpServer.Apply(&dhcpCfg); err != nil {
			slog.Warn("vrrp: failed to apply DHCP server on MASTER", "err", err)
		} else {
			slog.Info("vrrp: DHCP server started (MASTER)")
		}
	}
}

// clearRethServices sends goodbye RAs (lifetime=0) and stops Kea DHCP
// server. Called on VRRP BACKUP transition to prevent the secondary from
// advertising RAs or serving DHCP leases. The goodbye RA tells hosts to
// immediately remove this router as a default gateway.
// Deprecated: use clearRethServicesForRG for per-RG management.
func (d *Daemon) clearRethServices() {
	if d.ra != nil {
		if err := d.ra.Withdraw(); err != nil {
			slog.Warn("vrrp: failed to withdraw RA on BACKUP", "err", err)
		} else {
			slog.Info("vrrp: RA withdrawn (BACKUP, goodbye RA sent)")
		}
	}
	if d.dhcpServer != nil {
		d.dhcpServer.Clear()
		slog.Info("vrrp: DHCP server stopped (BACKUP)")
	}
}

// warmNeighborCache iterates synced sessions and sends ARP requests /
// ICMPv6 Neighbor Solicitations for unique destination IPs. This
// pre-populates the kernel neighbor cache so that bpf_fib_lookup
// returns SUCCESS (not NO_NEIGH) for the first packet after failover.
func (d *Daemon) warmNeighborCache() {
	if d.dp == nil {
		return
	}

	seen := make(map[[4]byte]bool)
	seenV6 := make(map[[16]byte]bool)

	// Iterate IPv4 sessions: collect unique dst IPs (forward entries
	// need ARP for the next-hop toward the destination) and unique src IPs
	// (return entries need ARP for the on-link client).
	_ = d.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if !seen[key.DstIP] {
			seen[key.DstIP] = true
		}
		if !seen[key.SrcIP] {
			seen[key.SrcIP] = true
		}
		return true
	})

	// Iterate IPv6 sessions.
	_ = d.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if !seenV6[key.DstIP] {
			seenV6[key.DstIP] = true
		}
		if !seenV6[key.SrcIP] {
			seenV6[key.SrcIP] = true
		}
		return true
	})

	// Resolve IPv4 neighbors by sending a UDP packet to trigger kernel ARP.
	// UDP connect() alone does NOT trigger ARP — only the route lookup is
	// performed. We must send at least one byte so the kernel actually
	// calls neigh_resolve_output() → arp_solicit().
	count := 0
	for ip4 := range seen {
		addr := netip.AddrFrom4(ip4)
		if !addr.IsGlobalUnicast() || addr.IsPrivate() && addr.IsLoopback() {
			continue
		}
		conn, err := net.DialTimeout("udp4", netip.AddrPortFrom(addr, 1).String(), 50*time.Millisecond)
		if err == nil {
			conn.Write([]byte{0}) // triggers ARP resolution
			conn.Close()
			count++
		}
	}

	// Resolve IPv6 neighbors.
	countV6 := 0
	for ip6 := range seenV6 {
		addr := netip.AddrFrom16(ip6)
		if !addr.IsGlobalUnicast() {
			continue
		}
		conn, err := net.DialTimeout("udp6", netip.AddrPortFrom(addr, 1).String(), 50*time.Millisecond)
		if err == nil {
			conn.Write([]byte{0}) // triggers NDP resolution
			conn.Close()
			countV6++
		}
	}

	if count > 0 || countV6 > 0 {
		slog.Info("cluster: neighbor cache warmup complete",
			"ipv4_hosts", count, "ipv6_hosts", countV6)
		// Brief pause to allow ARP/NDP responses before traffic arrives.
		time.Sleep(200 * time.Millisecond)
	}
}

// clusterConfig returns the current cluster config or nil.
func (d *Daemon) clusterConfig() *config.ClusterConfig {
	if d.store == nil {
		return nil
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	return cfg.Chassis.Cluster
}

// checkVIPReadiness verifies that RETH interfaces for the given RG exist and
// are operationally UP, so that VIPs can actually be added. Used in
// private-rg-election mode where there are no VRRP instances to gate readiness.
func (d *Daemon) checkVIPReadiness(rgID int) (bool, []string) {
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return true, nil // no config = nothing to check
	}
	linkByName := d.linkByNameFn
	if linkByName == nil {
		linkByName = netlink.LinkByName
	}
	return checkVIPReadinessForConfig(cfg, rgID, linkByName)
}

// checkVIPReadinessForConfig verifies that RETH interfaces for the given RG
// exist and are operationally UP. Pure function for testability.
func checkVIPReadinessForConfig(cfg *config.Config, rgID int, linkByName func(string) (netlink.Link, error)) (bool, []string) {
	vipMap := vrrp.RethVIPsForRG(cfg, rgID)
	if len(vipMap) == 0 {
		return true, nil // no VIPs for this RG
	}
	var reasons []string
	for ifName := range vipMap {
		link, err := linkByName(ifName)
		if err != nil {
			reasons = append(reasons, fmt.Sprintf("vip interface %s not found", ifName))
			continue
		}
		up := link.Attrs().OperState == netlink.OperUp ||
			link.Attrs().Flags&net.FlagUp != 0
		if !up {
			reasons = append(reasons, fmt.Sprintf("vip interface %s down", ifName))
		}
	}
	return len(reasons) == 0, reasons
}

// isNoRethVRRP returns true when no-reth-vrrp is explicitly configured,
// meaning the daemon directly manages VIPs/GARPs without VRRP instances.
// Default (no flag) uses VRRP for RETH failover.
func (d *Daemon) isNoRethVRRP() bool {
	cc := d.clusterConfig()
	return cc != nil && (cc.NoRethVRRP || cc.PrivateRGElection)
}

// directAddVIPs adds VIPs for RETH interfaces in the given RG using netlink.
// IPv6 addresses are added with IFA_F_NODAD to avoid DAD delays.
// Idempotent — skips addresses that already exist. Returns the number of
// addresses actually added (non-EEXIST).
func (d *Daemon) directAddVIPs(rgID int) int {
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return 0
	}
	var added int
	vipMap := vrrp.RethVIPsForRG(cfg, rgID)
	for ifName, addrs := range vipMap {
		link, err := netlink.LinkByName(ifName)
		if err != nil {
			if d.vipWarnedIfaces == nil {
				d.vipWarnedIfaces = make(map[string]bool)
			}
			if !d.vipWarnedIfaces[ifName] {
				slog.Warn("directAddVIPs: interface not found", "iface", ifName, "err", err)
				d.vipWarnedIfaces[ifName] = true
			}
			continue
		}
		// Interface exists now — clear any previous warning suppression
		delete(d.vipWarnedIfaces, ifName)
		for _, cidr := range addrs {
			addr, err := netlink.ParseAddr(cidr)
			if err != nil {
				slog.Warn("directAddVIPs: bad address", "addr", cidr, "err", err)
				continue
			}
			if addr.IP.To4() == nil {
				addr.Flags = unix.IFA_F_NODAD
			}
			if err := netlink.AddrAdd(link, addr); err != nil {
				if !errors.Is(err, syscall.EEXIST) {
					slog.Warn("directAddVIPs: failed to add", "iface", ifName, "addr", cidr, "err", err)
				}
			} else {
				slog.Info("directAddVIPs: added VIP", "iface", ifName, "addr", cidr)
				added++
			}
		}
	}
	return added
}

// directRemoveVIPs removes VIPs for RETH interfaces in the given RG.
// Ignores "not found" errors for idempotency.
func (d *Daemon) directRemoveVIPs(rgID int) {
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	vipMap := vrrp.RethVIPsForRG(cfg, rgID)
	for ifName, addrs := range vipMap {
		link, err := netlink.LinkByName(ifName)
		if err != nil {
			continue // interface may not exist yet
		}
		for _, cidr := range addrs {
			addr, err := netlink.ParseAddr(cidr)
			if err != nil {
				continue
			}
			if err := netlink.AddrDel(link, addr); err != nil {
				if !errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ESRCH) && !errors.Is(err, syscall.EADDRNOTAVAIL) {
					slog.Warn("directRemoveVIPs: failed to remove", "iface", ifName, "addr", cidr, "err", err)
				}
			} else {
				slog.Info("directRemoveVIPs: removed VIP", "iface", ifName, "addr", cidr)
			}
		}
	}
}

// addStableRethLinkLocal adds the stable router link-local address to all
// RETH interfaces for the given RG. This address is shared across cluster
// nodes (no nodeID component) so hosts see the same IPv6 router identity
// regardless of which node is primary. Managed like a VIP: only present
// on the MASTER node.
func (d *Daemon) addStableRethLinkLocal(rgID int) {
	if d.store == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return
	}
	clusterID := cfg.Chassis.Cluster.ClusterID
	stableLL := cluster.StableRethLinkLocal(clusterID, rgID)
	rethToPhys := cfg.RethToPhysical()

	for ifName, ifc := range cfg.Interfaces.Interfaces {
		if ifc.RedundancyGroup != rgID {
			continue
		}
		if !strings.HasPrefix(ifName, "reth") {
			continue
		}
		// Skip interfaces with an explicitly configured link-local address —
		// the user's configured LL replaces the auto-generated stable LL.
		if rethUnitHasConfiguredLinkLocal(ifc, 0) {
			slog.Debug("skipping stable LL (explicit LL configured)", "iface", ifName)
			continue
		}
		physName := ifc.Name
		if phys, ok := rethToPhys[ifc.Name]; ok {
			physName = phys
		}
		linuxName := config.LinuxIfName(physName)
		addStableLLToInterface(linuxName, stableLL)
		for unitNum := range ifc.Units {
			if unitNum > 0 && rethUnitHasIPv6(ifc, unitNum) {
				unit := ifc.Units[unitNum]
				subIface := linuxName
				if unit.VlanID > 0 {
					subIface = fmt.Sprintf("%s.%d", linuxName, unit.VlanID)
				}
				addStableLLToInterface(subIface, stableLL)
			}
		}
	}
}

func addStableLLToInterface(ifName string, ll net.IP) {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return
	}
	addr := &netlink.Addr{
		IPNet: &net.IPNet{IP: ll, Mask: net.CIDRMask(128, 128)},
		Flags: unix.IFA_F_NODAD,
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		if !errors.Is(err, syscall.EEXIST) {
			slog.Warn("failed to add stable link-local", "iface", ifName, "addr", ll, "err", err)
		}
	} else {
		slog.Info("added stable router link-local", "iface", ifName, "addr", ll)
	}
}

// removeStableRethLinkLocal removes the stable router link-local address
// from all RETH interfaces for the given RG. Called on BACKUP transition.
func (d *Daemon) removeStableRethLinkLocal(rgID int) {
	if d.store == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return
	}
	clusterID := cfg.Chassis.Cluster.ClusterID
	stableLL := cluster.StableRethLinkLocal(clusterID, rgID)
	rethToPhys := cfg.RethToPhysical()

	for ifName, ifc := range cfg.Interfaces.Interfaces {
		if ifc.RedundancyGroup != rgID {
			continue
		}
		if !strings.HasPrefix(ifName, "reth") {
			continue
		}
		physName := ifc.Name
		if phys, ok := rethToPhys[ifc.Name]; ok {
			physName = phys
		}
		linuxName := config.LinuxIfName(physName)
		removeStableLLFromInterface(linuxName, stableLL)
		for unitNum := range ifc.Units {
			if unitNum > 0 {
				unit := ifc.Units[unitNum]
				subIface := linuxName
				if unit.VlanID > 0 {
					subIface = fmt.Sprintf("%s.%d", linuxName, unit.VlanID)
				}
				removeStableLLFromInterface(subIface, stableLL)
			}
		}
	}
}

func removeStableLLFromInterface(ifName string, ll net.IP) {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return
	}
	addr := &netlink.Addr{
		IPNet: &net.IPNet{IP: ll, Mask: net.CIDRMask(128, 128)},
	}
	if err := netlink.AddrDel(link, addr); err != nil {
		if !errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ESRCH) && !errors.Is(err, syscall.EADDRNOTAVAIL) {
			slog.Warn("failed to remove stable link-local", "iface", ifName, "addr", ll, "err", err)
		}
	} else {
		slog.Info("removed stable router link-local", "iface", ifName, "addr", ll)
	}
}

func (d *Daemon) directAnnounceActive(rgID int, seq uint64) bool {
	d.directAnnounceMu.Lock()
	current := d.directAnnounceSeq[rgID]
	d.directAnnounceMu.Unlock()
	if current != seq {
		return false
	}
	d.rgStatesMu.RLock()
	s := d.rgStates[rgID]
	d.rgStatesMu.RUnlock()
	return s != nil && s.IsActive()
}

func (d *Daemon) cancelDirectAnnounce(rgID int) {
	d.directAnnounceMu.Lock()
	defer d.directAnnounceMu.Unlock()
	if d.directAnnounceSeq == nil {
		d.directAnnounceSeq = make(map[int]uint64)
	}
	d.directAnnounceSeq[rgID]++
}

func (d *Daemon) scheduleDirectAnnounce(rgID int, reason string) {
	d.directAnnounceMu.Lock()
	if d.directAnnounceSeq == nil {
		d.directAnnounceSeq = make(map[int]uint64)
	}
	d.directAnnounceSeq[rgID]++
	seq := d.directAnnounceSeq[rgID]
	schedule := append([]time.Duration(nil), d.directAnnounceSchedule...)
	sendFn := d.directSendGARPsFn
	d.directAnnounceMu.Unlock()
	if len(schedule) == 0 {
		schedule = []time.Duration{0}
	}
	if sendFn == nil {
		sendFn = d.directSendGARPs
	}
	slog.Info("direct-mode re-announce scheduled", "rg", rgID, "reason", reason, "bursts", len(schedule))
	go func() {
		start := time.Now()
		for idx, at := range schedule {
			if wait := time.Until(start.Add(at)); wait > 0 {
				timer := time.NewTimer(wait)
				<-timer.C
			}
			if !d.directAnnounceActive(rgID, seq) {
				return
			}
			sendFn(rgID)
			slog.Info("direct-mode re-announce sent", "rg", rgID, "reason", reason, "burst", idx+1, "total", len(schedule))
		}
	}()
}

// directSendGARPs sends gratuitous ARP/IPv6 NA bursts for all VIPs in the
// given RG. Reads per-RG GratuitousARPCount (default 3).
func (d *Daemon) directSendGARPs(rgID int) {
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	// Read per-RG GARP count.
	garpCount := 3
	if cc := cfg.Chassis.Cluster; cc != nil {
		for _, rg := range cc.RedundancyGroups {
			if rg.ID == rgID && rg.GratuitousARPCount > 0 {
				garpCount = rg.GratuitousARPCount
			}
		}
	}

	vipMap := vrrp.RethVIPsForRG(cfg, rgID)
	for ifName, addrs := range vipMap {
		for _, cidr := range addrs {
			ip, _, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			if ip.To4() != nil {
				if err := cluster.SendGratuitousARPBurst(ifName, ip, garpCount); err != nil {
					slog.Warn("directSendGARPs: GARP failed", "iface", ifName, "ip", ip, "err", err)
				}
				// Send ARP probe to gateway (.1) to update upstream ARP caches.
				_, ipNet, _ := net.ParseCIDR(cidr)
				if ipNet != nil {
					gw := make(net.IP, len(ipNet.IP))
					copy(gw, ipNet.IP)
					gw[len(gw)-1] = 1
					if err := cluster.SendARPProbe(ifName, gw); err != nil {
						slog.Warn("directSendGARPs: ARP probe failed", "iface", ifName, "gw", gw, "err", err)
					}
				}
			} else {
				if err := cluster.SendGratuitousIPv6Burst(ifName, ip, garpCount); err != nil {
					slog.Warn("directSendGARPs: IPv6 NA failed", "iface", ifName, "ip", ip, "err", err)
				}
			}
		}
	}

	// Send NA burst for router link-local so hosts update neighbor cache for
	// the router identity (not just VIPs). Uses the explicitly configured
	// link-local if present, otherwise the auto-generated stable LL.
	// Send on base interface AND all VLAN sub-interfaces (separate L2 domains).
	if cfg.Chassis.Cluster != nil {
		stableLL := cluster.StableRethLinkLocal(cfg.Chassis.Cluster.ClusterID, rgID)
		rethToPhys := cfg.RethToPhysical()
		seen := make(map[string]bool)
		for ifName, ifc := range cfg.Interfaces.Interfaces {
			if ifc.RedundancyGroup != rgID || !strings.HasPrefix(ifName, "reth") {
				continue
			}
			// Use configured link-local if present, otherwise stable LL.
			routerLL := stableLL
			if unit, ok := ifc.Units[0]; ok {
				for _, addr := range unit.Addresses {
					ip, _, err := net.ParseCIDR(addr)
					if err == nil && ip.IsLinkLocalUnicast() && ip.To4() == nil {
						routerLL = ip
						break
					}
				}
			}
			physName := ifc.Name
			if phys, ok := rethToPhys[ifc.Name]; ok {
				physName = phys
			}
			linuxName := config.LinuxIfName(physName)
			// Send on base interface.
			if !seen[linuxName] {
				seen[linuxName] = true
				if err := cluster.SendGratuitousIPv6Burst(linuxName, routerLL, garpCount); err != nil {
					slog.Warn("directSendGARPs: router link-local NA failed",
						"iface", linuxName, "ip", routerLL, "err", err)
				}
			}
			// Send on each VLAN sub-interface.
			for _, unit := range ifc.Units {
				if unit.VlanID > 0 {
					subIface := fmt.Sprintf("%s.%d", linuxName, unit.VlanID)
					if !seen[subIface] {
						seen[subIface] = true
						if err := cluster.SendGratuitousIPv6Burst(subIface, routerLL, garpCount); err != nil {
							slog.Warn("directSendGARPs: router link-local NA failed",
								"iface", subIface, "ip", routerLL, "err", err)
						}
					}
				}
			}
		}
	}
}

// syncIPsecSAPeriodic runs on the primary node, periodically syncing active IPsec
// connection names to the secondary via the session sync channel.
func (d *Daemon) syncIPsecSAPeriodic(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if d.cluster == nil || !d.cluster.IsLocalPrimary(0) {
				continue
			}
			cc := d.clusterConfig()
			if cc == nil || !cc.IPsecSASync {
				continue
			}
			names, err := d.ipsec.ActiveConnectionNames()
			if err != nil {
				slog.Debug("cluster: failed to get IPsec connection names", "err", err)
				continue
			}
			if len(names) > 0 && d.sessionSync != nil {
				d.sessionSync.QueueIPsecSA(names)
			}
		}
	}
}

// reinitiateIPsecSAs re-initiates all IPsec connections that were synced from the
// previous primary. Called when this node becomes primary after failover.
func (d *Daemon) reinitiateIPsecSAs() {
	names := d.sessionSync.PeerIPsecSAs()
	if len(names) == 0 {
		return
	}
	slog.Info("cluster: re-initiating IPsec SAs after failover", "count", len(names))
	for _, name := range names {
		if err := d.ipsec.InitiateConnection(name); err != nil {
			slog.Warn("cluster: failed to initiate IPsec SA", "name", name, "err", err)
		} else {
			slog.Info("cluster: IPsec SA initiated", "name", name)
		}
	}
}

// resolveDHCPRethInterfaces translates RETH interface names in DHCP server
// groups to their physical member Linux names (Kea needs real device names).
func resolveDHCPRethInterfaces(dhcpCfg *config.DHCPServerConfig, cfg *config.Config) {
	resolve := func(groups map[string]*config.DHCPServerGroup) {
		for _, group := range groups {
			for i, iface := range group.Interfaces {
				group.Interfaces[i] = config.LinuxIfName(cfg.ResolveReth(iface))
			}
		}
	}
	if dhcpCfg.DHCPLocalServer != nil {
		resolve(dhcpCfg.DHCPLocalServer.Groups)
	}
	if dhcpCfg.DHCPv6LocalServer != nil {
		resolve(dhcpCfg.DHCPv6LocalServer.Groups)
	}
}
