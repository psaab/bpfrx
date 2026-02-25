// Package daemon implements the bpfrx daemon lifecycle.
package daemon

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
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
	opts          Options
	store         *configstore.Store
	dp            dataplane.DataPlane
	networkd      *networkd.Manager
	routing       *routing.Manager
	frr           *frr.Manager
	ipsec         *ipsec.Manager
	ra            *ra.Manager
	dhcp          *dhcp.Manager
	dhcpServer    *dhcpserver.Manager
	feeds         *feeds.Manager
	rpm           *rpm.Manager
	flowExporter  *flowexport.Exporter
	flowCancel    context.CancelFunc
	flowWg        sync.WaitGroup
	ipfixExporter *flowexport.IPFIXExporter
	ipfixCancel   context.CancelFunc
	ipfixWg       sync.WaitGroup
	dhcpRelay     *dhcprelay.Manager
	snmpAgent     *snmp.Agent
	lldpMgr       *lldp.Manager
	scheduler     *scheduler.Scheduler
	cluster       *cluster.Manager
	sessionSync   *cluster.SessionSync
	slogHandler   *logging.SyslogSlogHandler
	traceWriter   *logging.TraceWriter
	eventReader   *logging.EventReader
	eventEngine   *eventengine.Engine
	aggregator    *logging.SessionAggregator
	aggCancel     context.CancelFunc
	vrrpMgr       *vrrp.Manager
	gc            *conntrack.GC
	startTime     time.Time // daemon start time; used to suppress stale config sync

	// mgmtVRFInterfaces tracks interfaces bound to the management VRF (vrf-mgmt).
	// Used by collectDHCPRoutes to exclude management routes from FRR.
	mgmtVRFInterfaces map[string]bool

	// rethMasterState tracks per-RG VRRP master state. In active/active HA,
	// a node can be MASTER for one RG and BACKUP for another simultaneously.
	rethMasterState map[int]bool
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
		opts:      opts,
		startTime: time.Now(),
		store:     store,
	}
}

// Run starts the daemon and blocks until shutdown.
func (d *Daemon) Run(ctx context.Context) error {
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
	if err := d.vrrpMgr.Start(context.Background()); err != nil {
		slog.Warn("failed to start VRRP manager", "err", err)
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
			// Apply current config using ordered flow
			if cfg := d.store.ActiveConfig(); cfg != nil {
				slog.Info("applying active configuration")
				d.applyConfig(cfg)
			}
		}
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

		// Wire GC delete callbacks for incremental session sync.
		// Deletes are synced if this node is primary for any RG — the peer
		// ignores deletes for sessions it doesn't have.
		gc.OnDeleteV4 = func(key dataplane.SessionKey) {
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
				d.runPeriodicNeighborResolution(ctx, cfg)
			}()
		}
	}

	// Start VRRP event watcher (manager was created earlier, before applyConfig).
	go d.watchVRRPEvents(context.Background())

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
		})
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

	// Stop VRRP manager (removes VIPs, sends priority-0).
	if d.vrrpMgr != nil {
		d.vrrpMgr.Stop()
	}

	// Stop session sync.
	if d.sessionSync != nil {
		d.sessionSync.Stop()
	}

	// Stop cluster monitor.
	if d.cluster != nil {
		d.cluster.Stop()
	}

	// For hitless restarts, preserve all control-plane state so the next
	// daemon inherits working routes, DHCP leases, VRFs, and tunnels.
	// BPF programs keep running via pinned links; leaving FRR routes and
	// interface addresses intact means zero forwarding disruption.
	//
	// Only close Go file handles — pinned BPF maps/links survive in-kernel.
	// Full teardown (DHCP release, route removal, VRF cleanup) is done
	// by "bpfrxd cleanup".
	if d.dp != nil {
		logFinalStats(d.dp)
		d.dp.Close()
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
func programRethMAC(ifName string, mac net.HardwareAddr) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("interface %s: %w", ifName, err)
	}
	current := link.Attrs().HardwareAddr
	if bytes.Equal(current, mac) {
		return nil
	}
	slog.Info("setting RETH virtual MAC", "iface", ifName, "mac", mac)
	// Must bring link down to change MAC (EAGAIN if UP).
	if err := netlink.LinkSetDown(link); err != nil {
		return fmt.Errorf("link down %s: %w", ifName, err)
	}
	if err := netlink.LinkSetHardwareAddr(link, mac); err != nil {
		netlink.LinkSetUp(link) // best-effort restore
		return fmt.Errorf("set mac %s: %w", ifName, err)
	}
	return netlink.LinkSetUp(link)
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
				if err := d.routing.BindInterfaceToVRF(ifaceName, ri.Name); err != nil {
					slog.Warn("failed to bind interface to VRF",
						"interface", ifaceName, "instance", ri.Name, "err", err)
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
			if strings.HasPrefix(name, "fxp") || strings.HasPrefix(name, "fab") {
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

	// 1. Create tunnel interfaces
	if d.routing != nil {
		var tunnels []*config.TunnelConfig
		for _, ifc := range cfg.Interfaces.Interfaces {
			if ifc.Tunnel != nil {
				tunnels = append(tunnels, ifc.Tunnel)
			}
		}
		if len(tunnels) > 0 {
			if err := d.routing.ApplyTunnels(tunnels); err != nil {
				slog.Warn("failed to apply tunnels", "err", err)
			}
		}
	}

	// 1.5. Create xfrmi interfaces for IPsec VPN tunnels.
	// Must happen before BPF compilation so compileZones() can discover
	// the xfrmi interfaces and map them to security zones.
	if d.routing != nil && len(cfg.Security.IPsec.VPNs) > 0 {
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

	// 2. Compile eBPF dataplane
	var compileResult *dataplane.CompileResult
	if d.dp != nil {
		var err error
		if compileResult, err = d.dp.Compile(cfg); err != nil {
			slog.Warn("failed to compile dataplane", "err", err)
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
	if d.cluster != nil && cfg.Chassis.Cluster != nil {
		cc := cfg.Chassis.Cluster
		rethToPhys := cfg.RethToPhysical()
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
			mac := cluster.RethMAC(cc.ClusterID, rethCfg.RedundancyGroup, cc.NodeID)
			if err := programRethMAC(linuxName, mac); err != nil {
				slog.Warn("failed to set RETH MAC", "iface", linuxName, "mac", mac, "err", err)
			}
			clearDadFailed(linuxName)

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
					if !bytes.Equal(l.Attrs().HardwareAddr, mac) {
						if err := netlink.LinkSetHardwareAddr(l, mac); err != nil {
							slog.Warn("failed to propagate MAC to VLAN sub-interface",
								"iface", l.Attrs().Name, "err", err)
						} else {
							slog.Info("propagated RETH MAC to VLAN sub-interface",
								"iface", l.Attrs().Name, "mac", mac)
						}
					}
				}
			}
		}
	}

	// 2.6b. Reconcile VRRP VIPs after RETH MAC programming.
	// programRethMAC brings the interface DOWN/UP which removes all
	// addresses including VRRP VIPs. Re-add them on MASTER instances.
	if d.vrrpMgr != nil {
		d.vrrpMgr.ReconcileVIPs()
	}

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
		}
		for _, ri := range cfg.RoutingInstances {
			vrfName := "vrf-" + ri.Name
			if ri.InstanceType == "forwarding" {
				vrfName = "" // forwarding instances use the default table
			}
			fc.Instances = append(fc.Instances, frr.InstanceConfig{
				VRFName:      vrfName,
				OSPF:         ri.OSPF,
				OSPFv3:       ri.OSPFv3,
				BGP:          ri.BGP,
				RIP:          ri.RIP,
				ISIS:         ri.ISIS,
				StaticRoutes: ri.StaticRoutes,
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
	d.resolveNeighbors(cfg)

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

	// 6. Apply IPsec config
	if d.ipsec != nil && len(cfg.Security.IPsec.VPNs) > 0 {
		if err := d.ipsec.Apply(&cfg.Security.IPsec); err != nil {
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
		slog.Info("DHCP address changed, recompiling dataplane")
		if activeCfg := d.store.ActiveConfig(); activeCfg != nil {
			d.applyConfig(activeCfg)
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
				if unit.DHCPv6Client != nil && (len(unit.DHCPv6Client.ClientIATypes) > 0 || len(unit.DHCPv6Client.ReqOptions) > 0) {
					dm.SetDHCPv6Options(dhcpIface, &dhcp.DHCPv6Options{
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
		ip        net.IP
		linkIndex int
	}
	var targets []target
	seen := make(map[string]bool)

	addByLink := func(ip net.IP, linkIndex int) {
		key := fmt.Sprintf("%s@%d", ip, linkIndex)
		if seen[key] {
			return
		}
		seen[key] = true
		targets = append(targets, target{ip: ip, linkIndex: linkIndex})
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
		addByLink(ip, routes[0].LinkIndex)
	}

	addByName := func(ipStr, ifName string) {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return
		}
		link, err := netlink.LinkByName(ifName)
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
		if t.ip.To4() == nil {
			family = netlink.FAMILY_V6
		}
		// Skip if neighbor already exists and is usable
		neighs, _ := netlink.NeighList(t.linkIndex, family)
		skip := false
		for _, n := range neighs {
			if n.IP.Equal(t.ip) && (n.State&(netlink.NUD_REACHABLE|netlink.NUD_STALE|netlink.NUD_PERMANENT)) != 0 {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		resolved++
		// Use ping to trigger kernel ARP/NDP resolution.
		// arping uses PF_PACKET raw sockets which don't populate the kernel
		// ARP table when XDP is attached. ping triggers the kernel's own
		// neighbor resolution before sending, which works with XDP.
		go func(ip net.IP, iface string) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if ip.To4() != nil {
				exec.CommandContext(ctx, "ping", "-c1", "-W1", "-I", iface, ip.String()).Run()
			} else {
				exec.CommandContext(ctx, "ping", "-6", "-c1", "-W1", "-I", iface, ip.String()).Run()
			}
		}(t.ip, ifName)
	}

	if resolved > 0 {
		slog.Info("proactive neighbor resolution", "resolving", resolved, "total_targets", len(targets))
		// Brief pause to allow ARP responses
		time.Sleep(500 * time.Millisecond)
	}
}

// runPeriodicNeighborResolution re-runs neighbor resolution every 15 seconds
// to keep ARP/NDP entries warm for known forwarding targets.
func (d *Daemon) runPeriodicNeighborResolution(ctx context.Context, cfg *config.Config) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.resolveNeighbors(cfg)
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
		for _, ifName := range zone.Interfaces {
			// Strip unit suffix (e.g. "reth0.0" → "reth0") for config lookup.
			baseName := ifName
			if idx := strings.IndexByte(ifName, '.'); idx >= 0 {
				baseName = ifName[:idx]
			}
			if ifc, ok := cfg.Interfaces.Interfaces[baseName]; ok && ifc.RedundancyGroup > 0 {
				result[zid] = ifc.RedundancyGroup
				break // one RETH per zone is enough to determine the RG
			}
		}
	}
	return result
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
			er.ReplaceLocalWriters([]*logging.LocalLogWriter{lw})
			slog.Info("security log event mode: writing to /var/log/bpfrx/security.log")
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
	if len(cfg.System.NameServers) == 0 && cfg.System.DomainName == "" && len(cfg.System.DomainSearch) == 0 {
		return
	}

	var b strings.Builder
	b.WriteString("# Generated by bpfrxd from system config\n")
	if cfg.System.DomainName != "" {
		fmt.Fprintf(&b, "domain %s\n", cfg.System.DomainName)
	}
	if len(cfg.System.DomainSearch) > 0 {
		fmt.Fprintf(&b, "search %s\n", strings.Join(cfg.System.DomainSearch, " "))
	}
	for _, ns := range cfg.System.NameServers {
		fmt.Fprintf(&b, "nameserver %s\n", ns)
	}

	current, _ := os.ReadFile("/etc/resolv.conf")
	if string(current) == b.String() {
		return // no change
	}

	if err := os.WriteFile("/etc/resolv.conf", []byte(b.String()), 0644); err != nil {
		slog.Warn("failed to write /etc/resolv.conf", "err", err)
		return
	}
	slog.Info("DNS config applied", "domain", cfg.System.DomainName,
		"search", cfg.System.DomainSearch, "servers", cfg.System.NameServers)
}

// applySystemNTP configures chrony from system { ntp } config.
// Writes per-server source lines to /etc/chrony/sources.d/bpfrx.sources
// and reloads chrony to pick up changes.
func (d *Daemon) applySystemNTP(cfg *config.Config) {
	if len(cfg.System.NTPServers) == 0 || isProcessDisabled(cfg, "ntp") {
		return
	}

	var b strings.Builder
	for _, server := range cfg.System.NTPServers {
		// Use "pool" directive for hostnames (multiple IPs), "server" for explicit IPs
		directive := "pool"
		if net.ParseIP(server) != nil {
			directive = "server"
		}
		fmt.Fprintf(&b, "%s %s iburst\n", directive, server)
	}
	content := b.String()
	confPath := "/etc/chrony/sources.d/bpfrx.sources"

	current, _ := os.ReadFile(confPath)
	if string(current) == content {
		return // no change
	}

	os.MkdirAll("/etc/chrony/sources.d", 0755)
	if err := os.WriteFile(confPath, []byte(content), 0644); err != nil {
		slog.Warn("failed to write chrony sources", "err", err)
		return
	}

	// Reload chrony to pick up new sources
	exec.Command("chronyc", "reload", "sources").Run()
	slog.Info("NTP config applied via chrony", "servers", cfg.System.NTPServers)
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

// handleConfigSync processes a config received from the cluster primary.
// It preserves the local chassis cluster settings (node ID, peer addresses)
// and applies the rest of the config.
func (d *Daemon) handleConfigSync(configText string) {
	slog.Info("cluster: applying synced config from primary")

	// Get local chassis cluster settings before overwrite.
	localCfg := d.store.ActiveConfig()
	var localChassisNode *config.Node
	if localCfg != nil {
		localTree := d.store.ActiveTree()
		if localTree != nil {
			localChassisNode = localTree.FindChild("chassis")
		}
	}

	compiled, err := d.store.SyncApply(configText, func(tree *config.ConfigTree) {
		// Preserve local chassis cluster settings.
		if localChassisNode != nil {
			// Replace the received chassis node with local one.
			for i, child := range tree.Children {
				if len(child.Keys) > 0 && child.Keys[0] == "chassis" {
					tree.Children[i] = localChassisNode
					return
				}
			}
			// No chassis node in received config — add local one.
			tree.Children = append(tree.Children, localChassisNode)
		}
	})
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

	// Determine VRF device if control/fabric interfaces are in mgmt VRF.
	vrfDevice := ""
	if len(d.mgmtVRFInterfaces) > 0 {
		vrfDevice = "vrf-mgmt"
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

	// Start session/config sync on fabric interface.
	// Retry: fabric interface address and VRF may not be ready at startup.
	if cc.FabricInterface != "" && cc.FabricPeerAddress != "" {
		go func() {
			var fabIP string
			for i := 0; i < 30; i++ {
				fabIP = resolveInterfaceAddr(cc.FabricInterface, "")
				if fabIP != "" {
					break
				}
				if i == 0 {
					slog.Info("cluster: fabric interface has no IPv4 address yet, waiting",
						"interface", cc.FabricInterface)
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(2 * time.Second):
				}
			}
			if fabIP == "" {
				slog.Error("cluster: fabric interface address not available after retries",
					"interface", cc.FabricInterface)
				return
			}

			syncLocal := fmt.Sprintf("%s:4785", fabIP)
			syncPeer := fmt.Sprintf("%s:4785", cc.FabricPeerAddress)
			d.sessionSync = cluster.NewSessionSync(syncLocal, syncPeer, nil)

			// Wire sync stats into cluster manager for CLI display.
			d.cluster.SetSyncStats(d.sessionSync)

			// Wire config sync callback: when secondary receives config from primary.
			d.sessionSync.OnConfigReceived = func(configText string) {
				d.cluster.RecordEvent(cluster.EventConfigSync, -1, fmt.Sprintf("Config received (%d bytes)", len(configText)))
				d.handleConfigSync(configText)
			}

			// Wire peer connected callback: push config to returning peer.
			// Only push if this node has been running >30s (stable node).
			// A freshly started node must NOT push stale config from disk.
			// Uses pushConfigToPeer (not syncConfigToPeer) to bypass the
			// primary check — the stable node may have been preempted by
			// the time the TCP sync connection is established.
			d.sessionSync.OnPeerConnected = func() {
				d.cluster.RecordEvent(cluster.EventFabric, -1, "Peer connected")
				if time.Since(d.startTime) < 30*time.Second {
					slog.Info("cluster: skipping config push (daemon just started)")
					return
				}
				slog.Info("cluster: pushing config to reconnected peer")
				d.pushConfigToPeer()
			}

			// Enable VRRP sync hold on fresh daemon start: suppress preemption
			// until bulk session sync completes from the peer. This prevents
			// the returning high-priority node from preempting before it has
			// session state, which would break all existing connections.
			if time.Since(d.startTime) < 30*time.Second {
				d.vrrpMgr.SetSyncHold(10 * time.Second)
			}

			d.sessionSync.OnBulkSyncReceived = func() {
				d.cluster.RecordEvent(cluster.EventColdSync, -1, "Bulk sync completed")
				slog.Info("cluster: session sync complete, releasing VRRP hold")
				d.vrrpMgr.ReleaseSyncHold()
			}

			d.sessionSync.SetVRFDevice(vrfDevice)
			// Retry sync start: the VRF device and address binding may not
			// be ready during daemon startup (networkd race).
			for i := 0; i < 30; i++ {
				if err := d.sessionSync.Start(ctx); err != nil {
					if i < 5 {
						slog.Info("cluster: sync bind not ready, retrying",
							"err", err, "attempt", i+1)
					} else {
						slog.Warn("failed to start session sync, retrying",
							"err", err, "attempt", i+1)
					}
					select {
					case <-ctx.Done():
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
					d.sessionSync.StartSyncSweep(ctx)
				}

				break
			}

			// Start periodic IPsec SA sync if enabled.
			if cc.IPsecSASync && d.ipsec != nil {
				go d.syncIPsecSAPeriodic(ctx)
			}

			// Populate fabric_fwd BPF map for cross-chassis redirect.
			// Retry: the peer ARP entry may not exist yet (heartbeat
			// hasn't exchanged packets). Once populated, the BPF
			// program can redirect packets to the peer during VRRP
			// failback asymmetric routing windows.
			go d.populateFabricFwd(ctx, cc.FabricInterface, cc.FabricPeerAddress)
		}()
	}
}

// populateFabricFwd resolves the fabric interface MACs and populates the
// fabric_fwd BPF map for cross-chassis packet redirect during failback.
func (d *Daemon) populateFabricFwd(ctx context.Context, fabIface, peerAddr string) {
	peerIP := net.ParseIP(peerAddr)
	if peerIP == nil {
		slog.Warn("cluster: invalid fabric peer address", "addr", peerAddr)
		return
	}

	for i := 0; i < 30; i++ {
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}

		link, err := netlink.LinkByName(fabIface)
		if err != nil {
			slog.Debug("cluster: fabric link not found, retrying",
				"interface", fabIface, "err", err)
			continue
		}
		localMAC := link.Attrs().HardwareAddr
		if len(localMAC) != 6 {
			continue
		}

		// Resolve peer MAC from ARP/NDP table.
		neighs, err := netlink.NeighList(link.Attrs().Index, netlink.FAMILY_V4)
		if err != nil {
			slog.Debug("cluster: neigh list failed", "err", err)
			continue
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
			if i == 0 {
				slog.Info("cluster: waiting for fabric peer ARP entry",
					"peer", peerAddr)
			}
			continue
		}

		info := dataplane.FabricFwdInfo{
			Ifindex: uint32(link.Attrs().Index),
		}
		copy(info.PeerMAC[:], peerMAC)
		copy(info.LocalMAC[:], localMAC)

		if err := d.dp.UpdateFabricFwd(info); err != nil {
			slog.Warn("cluster: failed to update fabric_fwd map", "err", err)
			continue
		}
		slog.Info("cluster: fabric cross-chassis redirect enabled",
			"interface", fabIface, "ifindex", info.Ifindex,
			"local_mac", localMAC, "peer_mac", peerMAC)
		return
	}
	slog.Warn("cluster: fabric_fwd map population failed after retries")
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
			// Debounced VRRP priority update — 500ms coalesce window.
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

// rgIDFromVRID extracts the redundancy group ID from a VRRP group ID.
// VRID = 100 + RG ID (set in pkg/vrrp/vrrp.go).
func rgIDFromVRID(vrid int) int {
	return vrid - 100
}

// watchVRRPEvents monitors VRRP state changes and logs transitions.
// On MASTER transition, triggers ARP/ND warmup for synced session
// next-hops so that bpf_fib_lookup finds neighbor entries immediately.
// Also starts/stops RA senders and Kea DHCP server per-RG — in
// active/active mode, a BACKUP event for RG1 must not clear services
// started for RG0.
func (d *Daemon) watchVRRPEvents(ctx context.Context) {
	if d.rethMasterState == nil {
		d.rethMasterState = make(map[int]bool)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-d.vrrpMgr.Events():
			if !ok {
				return
			}
			rgID := rgIDFromVRID(ev.GroupID)
			slog.Info("vrrp: state change",
				"interface", ev.Interface,
				"group", ev.GroupID,
				"rg", rgID,
				"state", ev.State.String())
			if ev.State == vrrp.StateMaster {
				d.rethMasterState[rgID] = true
				if d.dp != nil {
					go d.warmNeighborCache()
				}
				d.applyRethServicesForRG(rgID)
			}
			if ev.State == vrrp.StateBackup {
				d.rethMasterState[rgID] = false
				d.clearRethServicesForRG(rgID)
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

// applyRethServicesForRG starts RA senders and Kea DHCP server only for
// RETH interfaces belonging to the given RG. Called on VRRP MASTER
// transition — these services must only run on the primary to avoid
// dual-router / dual-DHCP issues.
func (d *Daemon) applyRethServicesForRG(rgID int) {
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
		for otherRG, isMaster := range d.rethMasterState {
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
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}

	// Check if any other RG is still master — if so, reapply services for
	// those RGs only; otherwise clear everything.
	anyOtherMaster := false
	for otherRG, isMaster := range d.rethMasterState {
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
	for rgID, isMaster := range d.rethMasterState {
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

	// Resolve IPv4 neighbors by sending a UDP connect (triggers kernel ARP).
	count := 0
	for ip4 := range seen {
		addr := netip.AddrFrom4(ip4)
		if !addr.IsGlobalUnicast() || addr.IsPrivate() && addr.IsLoopback() {
			continue
		}
		// net.Dial triggers kernel routing + ARP resolution.
		conn, err := net.DialTimeout("udp4", netip.AddrPortFrom(addr, 1).String(), 50*time.Millisecond)
		if err == nil {
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
			conn.Close()
			countV6++
		}
	}

	if count > 0 || countV6 > 0 {
		slog.Info("vrrp: neighbor cache warmup complete",
			"ipv4_hosts", count, "ipv6_hosts", countV6)
	}
}

// clusterConfig returns the current cluster config or nil.
func (d *Daemon) clusterConfig() *config.ClusterConfig {
	cfg := d.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	return cfg.Chassis.Cluster
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
