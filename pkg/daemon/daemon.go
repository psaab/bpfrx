// Package daemon implements the bpfrx daemon lifecycle.
package daemon

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
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
	opts                       Options
	store                      *configstore.Store
	dp                         dataplane.DataPlane
	networkd                   *networkd.Manager
	routing                    *routing.Manager
	frr                        *frr.Manager
	ipsec                      *ipsec.Manager
	ra                         *ra.Manager
	dhcp                       *dhcp.Manager
	dhcpServer                 *dhcpserver.Manager
	feeds                      *feeds.Manager
	rpm                        *rpm.Manager
	flowExporter               *flowexport.Exporter
	flowCancel                 context.CancelFunc
	flowWg                     sync.WaitGroup
	ipfixExporter              *flowexport.IPFIXExporter
	ipfixCancel                context.CancelFunc
	ipfixWg                    sync.WaitGroup
	dhcpRelay                  *dhcprelay.Manager
	snmpAgent                  *snmp.Agent
	lldpMgr                    *lldp.Manager
	scheduler                  *scheduler.Scheduler
	cluster                    *cluster.Manager
	sessionSync                *cluster.SessionSync
	syncBulkPrimed             atomic.Bool
	syncPeerBulkPrimed         atomic.Bool
	syncPeerConnected          atomic.Bool
	lastStandbyNeighborRefresh atomic.Int64
	neighborWarmupInFlight     atomic.Bool
	hbSuppressStart            atomic.Int64 // UnixNano of first heartbeat suppression; 0 = inactive
	syncPrimeRetryGen          atomic.Uint64
	syncReadyTimerGen          atomic.Uint64
	syncReadyTimerMu           sync.Mutex
	syncReadyTimer             *time.Timer
	syncReadyTimeout           time.Duration
	slogHandler                *logging.SyslogSlogHandler
	traceWriter                *logging.TraceWriter
	eventReader                *logging.EventReader
	eventEngine                *eventengine.Engine
	aggregator                 *logging.SessionAggregator
	aggCancel                  context.CancelFunc
	vrrpMgr                    *vrrp.Manager
	gc                         *conntrack.GC
	startTime                  time.Time // daemon start time; used to suppress stale config sync

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
}

const standbyNeighborRefreshMinInterval = time.Second

func (d *Daemon) shouldScheduleStandbyNeighborRefresh(now time.Time) bool {
	elapsed := now.Sub(d.startTime).Nanoseconds()
	last := d.lastStandbyNeighborRefresh.Load()
	if last != 0 && elapsed >= last && elapsed-last < int64(standbyNeighborRefreshMinInterval) {
		return false
	}
	return d.lastStandbyNeighborRefresh.CompareAndSwap(last, elapsed)
}

func (d *Daemon) scheduleStandbyNeighborRefresh() {
	if d.cluster == nil || d.dp == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	if !d.shouldScheduleStandbyNeighborRefresh(time.Now()) {
		return
	}
	go func(cfg *config.Config) {
		d.resolveNeighborsInner(cfg, false)
		d.maintainClusterNeighborReadiness()
	}(cfg)
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
		directVIPOwned:             make(map[int]bool),
		userspaceDemotionPrepUntil: make(map[int]time.Time),
	}
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
			// Always sync deletes. Dropping deletes leaves stale sessions
			// on the peer indefinitely.
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
					if af == dataplane.AFInet6 {
						var key dataplane.SessionKeyV6
						copy(key.SrcIP[:], raw[8:24])
						copy(key.DstIP[:], raw[24:40])
						key.SrcPort = binary.BigEndian.Uint16(raw[40:42])
						key.DstPort = binary.BigEndian.Uint16(raw[42:44])
						key.Protocol = proto
						if val, err := d.dp.GetSessionV6(key); err == nil && val.IsReverse == 0 {
							if d.sessionSync.ShouldSyncZone(val.IngressZone) {
								d.sessionSync.QueueSessionV6(key, val)
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
								d.sessionSync.QueueSessionV4(key, val)
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

func inferIPv6StaticNextHopInterfaces(cfg *config.Config) map[string]string {
	type connectedPrefix struct {
		net    *net.IPNet
		ifName string
		bits   int
	}

	var connected []connectedPrefix
	for ifName, ifc := range cfg.Interfaces.Interfaces {
		base := config.LinuxIfName(ifName)
		for unitNum, unit := range ifc.Units {
			logical := base
			if unitNum != 0 {
				logical = fmt.Sprintf("%s.%d", base, unitNum)
			}
			for _, addr := range unit.Addresses {
				ip, ipNet, err := net.ParseCIDR(addr)
				if err != nil || ip == nil || ip.To4() != nil {
					continue
				}
				bits, _ := ipNet.Mask.Size()
				connected = append(connected, connectedPrefix{
					net:    ipNet,
					ifName: logical,
					bits:   bits,
				})
			}
		}
	}

	resolve := func(addr string) string {
		ip := net.ParseIP(addr)
		if ip == nil || ip.To4() != nil {
			return ""
		}
		bestIf := ""
		bestBits := -1
		for _, candidate := range connected {
			if candidate.net.Contains(ip) && candidate.bits > bestBits {
				bestIf = candidate.ifName
				bestBits = candidate.bits
			}
		}
		return bestIf
	}

	resolved := make(map[string]string)
	addRoutes := func(routes []*config.StaticRoute) {
		for _, sr := range routes {
			for _, nh := range sr.NextHops {
				if nh.Interface != "" || nh.Address == "" || !strings.Contains(nh.Address, ":") {
					continue
				}
				if ifName := resolve(nh.Address); ifName != "" {
					resolved[nh.Address] = ifName
				}
			}
		}
	}

	addRoutes(cfg.RoutingOptions.StaticRoutes)
	addRoutes(cfg.RoutingOptions.Inet6StaticRoutes)
	for _, ri := range cfg.RoutingInstances {
		addRoutes(ri.StaticRoutes)
		addRoutes(ri.Inet6StaticRoutes)
	}
	return resolved
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

func parseLiteralIP(addr string) net.IP {
	if addr == "" {
		return nil
	}
	if ip := net.ParseIP(addr); ip != nil {
		return ip
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

func selectClusterBindAddr(addrs []net.Addr, peerAddr, fallback string) string {
	var ipv4Candidates []string
	var globalIPv6Candidates []string
	peerIP := parseLiteralIP(peerAddr)
	peerWantsIPv4 := peerIP != nil && peerIP.To4() != nil
	peerWantsIPv6 := peerIP != nil && peerIP.To4() == nil

	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ip4 := ipNet.IP.To4(); ip4 != nil {
			ipv4Candidates = append(ipv4Candidates, ip4.String())
			continue
		}
		// Cluster control/fabric transports do not support binding to bare
		// link-local IPv6 addresses because the resulting listen address lacks
		// an interface zone. Treat them as unusable so startup waits for the
		// configured control/fabric address family instead of racing on fe80::.
		if ipNet.IP.IsLinkLocalUnicast() {
			continue
		}
		globalIPv6Candidates = append(globalIPv6Candidates, ipNet.IP.String())
	}

	switch {
	case peerWantsIPv4:
		if len(ipv4Candidates) > 0 {
			return ipv4Candidates[0]
		}
	case peerWantsIPv6:
		if len(globalIPv6Candidates) > 0 {
			return globalIPv6Candidates[0]
		}
	default:
		if len(ipv4Candidates) > 0 {
			return ipv4Candidates[0]
		}
		if len(globalIPv6Candidates) > 0 {
			return globalIPv6Candidates[0]
		}
	}

	return fallback
}

// resolveClusterInterfaceAddr returns a usable control/fabric bind address for
// the named interface. It prefers the same address family as the configured
// peer and skips unscoped link-local IPv6 addresses.
func resolveClusterInterfaceAddr(ifname, peerAddr, fallback string) string {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		slog.Warn("cluster interface not found, using fallback", "interface", ifname, "fallback", fallback)
		return fallback
	}
	addrs, err := iface.Addrs()
	if err != nil || len(addrs) == 0 {
		slog.Warn("cluster interface has no addresses, using fallback", "interface", ifname, "fallback", fallback)
		return fallback
	}
	addr := selectClusterBindAddr(addrs, peerAddr, fallback)
	if addr == "" {
		slog.Info("cluster interface has no usable bind address yet", "interface", ifname, "peer", peerAddr)
	}
	return addr
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
			IPv6NextHopInterfaces: inferIPv6StaticNextHopInterfaces(cfg),
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

// preinstallSnapshotNeighbors refreshes the kernel ARP/NDP table from two
// sources: (1) iterates each configured interface's kernel NeighList and
// re-installs valid entries as NUD_REACHABLE via netlink.NeighSet, and
// (2) installs snapshot-learned neighbors from the dataplane provider
// (populated by buildNeighborSnapshots during Compile and synced from the
// active node). The periodic neighbor-maintenance loop calls this to keep
// the standby's neighbor table hot so failover does not depend on
// activation-time priming.
func (d *Daemon) preinstallSnapshotNeighbors() {
	type neighborInstaller interface {
		LastPublishedNeighbors() []struct {
			Ifindex int
			Family  string
			IP      string
			MAC     string
		}
	}
	// Read neighbors from the snapshot via the dataplane manager.
	// Fall back to kernel NeighList if the snapshot isn't available.
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	var installed int
	// Iterate ALL interfaces and install any neighbor we know about.
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		for _, unit := range ifc.Units {
			if unit == nil {
				continue
			}
			linuxName := config.LinuxIfName(name)
			if unit.Number != 0 {
				linuxName = fmt.Sprintf("%s.%d", linuxName, unit.Number)
			}
			link, err := netlink.LinkByName(linuxName)
			if err != nil || link == nil {
				continue
			}
			for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
				neighs, err := netlink.NeighList(link.Attrs().Index, family)
				if err != nil {
					continue
				}
				for _, neigh := range neighs {
					if neigh.HardwareAddr == nil || len(neigh.HardwareAddr) == 0 {
						continue
					}
					if neigh.State == netlink.NUD_FAILED || neigh.State == netlink.NUD_NOARP {
						continue
					}
					entry := netlink.Neigh{
						LinkIndex:    link.Attrs().Index,
						Family:       family,
						State:        netlink.NUD_REACHABLE,
						IP:           neigh.IP,
						HardwareAddr: neigh.HardwareAddr,
					}
					if err := netlink.NeighSet(&entry); err == nil {
						installed++
					}
				}
			}
		}
	}
	// Also install static route next-hop neighbors that may not be in the
	// kernel table yet (expired while another node owned the RG). Use the
	// config's known gateway addresses with their MACs from the snapshot.
	if d.dp != nil {
		type snapshotNeighborProvider interface {
			SnapshotNeighbors() []struct {
				Ifindex int
				IP      net.IP
				MAC     net.HardwareAddr
				Family  int
			}
		}
		if provider, ok := d.dp.(snapshotNeighborProvider); ok {
			for _, sn := range provider.SnapshotNeighbors() {
				entry := netlink.Neigh{
					LinkIndex:    sn.Ifindex,
					Family:       sn.Family,
					State:        netlink.NUD_REACHABLE,
					IP:           sn.IP,
					HardwareAddr: sn.MAC,
				}
				if err := netlink.NeighSet(&entry); err == nil {
					installed++
				}
			}
		}
	}
	if installed > 0 {
		slog.Info("preinstalled kernel neighbor entries from snapshot", "count", installed)
	}
}

// resolveNeighbors proactively triggers ARP/NDP resolution for all known
// next-hops, gateways, NAT destinations, and address-book host entries.
// This ensures bpf_fib_lookup returns SUCCESS (with valid MAC addresses)
// instead of NO_NEIGH for the first packet.
//
// Runtime: the synchronous portion collects targets via netlink RouteGet +
// NeighList (~1-2ms each), then fires ICMP/NS probes as goroutines. For a
// typical config with 2-5 next-hops, the blocking phase completes in <10ms.
// The 500ms sleep at the end waits for ARP replies; callers that cannot
// afford the sleep should invoke this from a goroutine.
func (d *Daemon) resolveNeighbors(cfg *config.Config) {
	d.resolveNeighborsInner(cfg, true)
}

func (d *Daemon) resolveNeighborsInner(cfg *config.Config, waitForReplies bool) {
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

	// addByIPOrConfig first tries the kernel FIB (addByIP). If the kernel
	// has no route (e.g. standby node where FRR hasn't installed the route),
	// fall back to finding the outgoing interface from the config by matching
	// the next-hop IP against configured interface subnets. This keeps ARP
	// warm on standby nodes so failback doesn't lose packets to ARP delay.
	addByIPOrConfig := func(ipStr string) {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return
		}
		// Try kernel FIB first — this is the fast/common path on active nodes.
		routes, err := netlink.RouteGet(ip)
		if err == nil && len(routes) > 0 {
			neighborIP := ip
			if gw := routes[0].Gw; gw != nil && !gw.IsUnspecified() {
				neighborIP = gw
			}
			addByLink(neighborIP, routes[0].LinkIndex)
			return
		}
		// Kernel has no route — find the interface from config by subnet match.
		for _, ifc := range cfg.Interfaces.Interfaces {
			for _, unit := range ifc.Units {
				for _, addrStr := range unit.Addresses {
					_, ipNet, err := net.ParseCIDR(addrStr)
					if err != nil {
						continue
					}
					if ipNet.Contains(ip) {
						linuxName := resolveJunosIfName(cfg, ifc.Name)
						link, err := netlink.LinkByName(linuxName)
						if err != nil {
							continue
						}
						slog.Debug("neighbor warmup: resolved next-hop via config subnet",
							"nexthop", ipStr, "iface", linuxName, "subnet", addrStr)
						addByLink(ip, link.Attrs().Index)
						return
					}
				}
			}
		}
	}

	// 1. Static route next-hops (resolve interface via FIB if not specified).
	// Uses addByIPOrConfig so standby nodes without the kernel route still
	// resolve next-hops via config subnet matching (keeps ARP cache warm).
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
				addByIPOrConfig(nh.Address)
			}
		}
	}
	for _, ri := range cfg.RoutingInstances {
		for _, sr := range append(ri.StaticRoutes, ri.Inet6StaticRoutes...) {
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
					addByIPOrConfig(nh.Address)
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
		if waitForReplies {
			// Brief pause to allow ARP responses
			time.Sleep(500 * time.Millisecond)
		}
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

// runPeriodicNeighborResolution manages periodic neighbor upkeep:
//   - Every 5 seconds: clean NUD_FAILED neighbor entries so the kernel
//     retries ARP/NDP on the next forwarded packet (fast recovery).
//   - Every 15 seconds: proactively resolve known forwarding targets
//     (gateways, DNAT pools, etc.) to keep ARP/NDP entries warm.
//   - In cluster mode: continuously refresh snapshot-learned neighbors and
//     session-derived neighbor cache entries so standby forwarding stays ready
//     without activation-time warmup.
//
// Runs once immediately at start to avoid a blind spot.
// Fetches fresh active config on each tick so config changes take effect.
func (d *Daemon) runPeriodicNeighborResolution(ctx context.Context) {
	// Immediate first run — don't wait for first tick.
	if cfg := d.store.ActiveConfig(); cfg != nil {
		d.resolveNeighbors(cfg)
		d.maintainClusterNeighborReadiness()
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
				d.maintainClusterNeighborReadiness()
			}
		}
	}
}

// maintainClusterNeighborReadiness runs every 15 seconds (via the resolve
// ticker in runPeriodicNeighborResolution) when HA is active. It refreshes
// kernel neighbor entries and spawns warmNeighborCache which iterates the
// full session table and sends one UDP probe per unique src/dst IP. The
// session walk can be large; an atomic guard prevents overlapping runs if
// a single pass exceeds one tick interval.
func (d *Daemon) maintainClusterNeighborReadiness() {
	if d.cluster == nil {
		return
	}
	d.preinstallSnapshotNeighbors()
	if !d.neighborWarmupInFlight.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer d.neighborWarmupInFlight.Store(false)
		d.warmNeighborCache()
	}()
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
