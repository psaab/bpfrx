// Package daemon implements the bpfrx daemon lifecycle.
package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/psaab/bpfrx/pkg/api"
	"github.com/psaab/bpfrx/pkg/cli"
	"github.com/psaab/bpfrx/pkg/config"
	"github.com/psaab/bpfrx/pkg/configstore"
	"github.com/psaab/bpfrx/pkg/eventengine"
	"github.com/psaab/bpfrx/pkg/conntrack"
	"github.com/psaab/bpfrx/pkg/dataplane"
	"github.com/psaab/bpfrx/pkg/dhcp"
	"github.com/psaab/bpfrx/pkg/dhcprelay"
	"github.com/psaab/bpfrx/pkg/dhcpserver"
	"github.com/psaab/bpfrx/pkg/feeds"
	"github.com/psaab/bpfrx/pkg/flowexport"
	"github.com/psaab/bpfrx/pkg/frr"
	"github.com/psaab/bpfrx/pkg/grpcapi"
	"github.com/psaab/bpfrx/pkg/ipsec"
	"github.com/psaab/bpfrx/pkg/logging"
	"github.com/psaab/bpfrx/pkg/networkd"
	"github.com/psaab/bpfrx/pkg/radvd"
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

// Daemon is the main bpfrx daemon.
type Daemon struct {
	opts         Options
	store        *configstore.Store
	dp           dataplane.DataPlane
	networkd     *networkd.Manager
	routing      *routing.Manager
	frr          *frr.Manager
	ipsec        *ipsec.Manager
	radvd        *radvd.Manager
	dhcp         *dhcp.Manager
	dhcpServer   *dhcpserver.Manager
	feeds        *feeds.Manager
	rpm          *rpm.Manager
	flowExporter *flowexport.Exporter
	flowCancel   context.CancelFunc
	flowWg       sync.WaitGroup
	dhcpRelay    *dhcprelay.Manager
	snmpAgent    *snmp.Agent
	scheduler    *scheduler.Scheduler
	slogHandler  *logging.SyslogSlogHandler
	traceWriter   *logging.TraceWriter
	eventReader   *logging.EventReader
	eventEngine   *eventengine.Engine
}

// New creates a new Daemon.
func New(opts Options) *Daemon {
	if opts.ConfigFile == "" {
		opts.ConfigFile = "/etc/bpfrx/bpfrx.conf"
	}

	return &Daemon{
		opts:  opts,
		store: configstore.New(opts.ConfigFile),
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
		d.radvd = radvd.New()
		d.networkd = networkd.New()
		d.dhcpServer = dhcpserver.New()
	}

	// Enable IP forwarding — required for the firewall to route packets.
	if !d.opts.NoDataplane {
		enableForwarding()
	}

	// Load eBPF programs (unless in config-only mode)
	if !d.opts.NoDataplane {
		d.dp = dataplane.New()
		if err := d.dp.Load(); err != nil {
			slog.Warn("failed to load eBPF programs, running in config-only mode",
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

	// Handle signals for clean shutdown
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// Create event buffer (shared between event reader and CLI)
	eventBuf := logging.NewEventBuffer(1000)

	// WaitGroup for coordinated shutdown of background goroutines
	var wg sync.WaitGroup

	// Start background services if dataplane is loaded
	var er *logging.EventReader
	var gc *conntrack.GC
	if d.dp != nil {
		gc = conntrack.NewGC(d.dp, 10*time.Second)
		wg.Add(1)
		go func() {
			defer wg.Done()
			gc.Run(ctx)
		}()

		eventsMap := d.dp.Map("events")
		if eventsMap != nil {
			er = logging.NewEventReader(eventsMap, eventBuf)
			d.eventReader = er
			wg.Add(1)
			go func() {
				defer wg.Done()
				er.Run(ctx)
			}()

			// Set up syslog clients from active config
			if cfg := d.store.ActiveConfig(); cfg != nil {
				applySyslogConfig(er, cfg)
			}

			// Start NetFlow exporter if configured
			if cfg := d.store.ActiveConfig(); cfg != nil {
				d.startFlowExporter(ctx, cfg, er)
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

	// Start SNMP agent if configured (unless system processes snmp disable).
	if cfg := d.store.ActiveConfig(); cfg != nil && cfg.System.SNMP != nil && len(cfg.System.SNMP.Communities) > 0 && !isProcessDisabled(cfg, "snmpd") {
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
				}
				if stats != nil {
					entry.InOctets = uint32(stats.RxBytes)
					entry.OutOctets = uint32(stats.TxBytes)
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

	// Start HTTP API server if configured.
	if d.opts.APIAddr != "" {
		apiCfg := api.Config{
			Addr:     d.opts.APIAddr,
			Store:    d.store,
			DP:       d.dp,
			EventBuf: eventBuf,
			GC:       gc,
			Routing:  d.routing,
			FRR:      d.frr,
			IPsec:    d.ipsec,
			DHCP:     d.dhcp,
			ApplyFn:  d.applyConfig,
		}
		// Enable HTTPS if web-management https is configured
		if cfg := d.store.ActiveConfig(); cfg != nil && cfg.System.Services != nil &&
			cfg.System.Services.WebManagement != nil && cfg.System.Services.WebManagement.HTTPS {
			apiCfg.TLS = true
			apiCfg.HTTPSAddr = "127.0.0.1:8443"
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
		grpcSrv := grpcapi.NewServer(d.opts.GRPCAddr, grpcapi.Config{
			Store:    d.store,
			DP:       d.dp,
			EventBuf: eventBuf,
			GC:       gc,
			Routing:  d.routing,
			FRR:      d.frr,
			IPsec:    d.ipsec,
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
			ApplyFn: d.applyConfig,
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
		shell := cli.New(d.store, d.dp, eventBuf, er, d.routing, d.frr, d.ipsec, d.dhcp, d.dhcpRelay)
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

	// Clean up flow exporter.
	d.stopFlowExporter()

	// Clean up dynamic address feeds.
	if d.feeds != nil {
		d.feeds.StopAll()
	}

	// Clean up RPM probes.
	if d.rpm != nil {
		d.rpm.StopAll()
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
	}
	for path, val := range sysctls {
		if err := os.WriteFile(path, []byte(val), 0644); err != nil {
			slog.Warn("failed to set sysctl", "path", path, "err", err)
		}
	}
	slog.Info("IP forwarding enabled, RA acceptance disabled")
}

func isInteractive() bool {
	_, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS)
	return err == nil
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

	parser := config.NewParser(string(data))
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		return fmt.Errorf("parse config file: %v", errs[0])
	}

	compiled, err := config.CompileConfig(tree)
	if err != nil {
		return fmt.Errorf("compile config: %w", err)
	}

	// Import into the store: enter config mode, load, commit
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

	_ = compiled // store.Commit() recompiles; ActiveConfig() will return it
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

	// 2. Compile eBPF dataplane
	var compileResult *dataplane.CompileResult
	if d.dp != nil {
		var err error
		if compileResult, err = d.dp.Compile(cfg); err != nil {
			slog.Warn("failed to compile dataplane", "err", err)
		}
	}

	// 2.5. Write systemd-networkd config for managed interfaces
	if d.networkd != nil && compileResult != nil && len(compileResult.ManagedInterfaces) > 0 {
		if err := d.networkd.Apply(compileResult.ManagedInterfaces); err != nil {
			slog.Warn("failed to apply networkd config", "err", err)
		}
	}

	// 3. Apply all routes + dynamic protocols via FRR
	if d.frr != nil {
		fc := &frr.FullConfig{
			OSPF:                  cfg.Protocols.OSPF,
			BGP:                   cfg.Protocols.BGP,
			RIP:                   cfg.Protocols.RIP,
			ISIS:                  cfg.Protocols.ISIS,
			StaticRoutes:          cfg.RoutingOptions.StaticRoutes,
			Inet6StaticRoutes:     cfg.RoutingOptions.Inet6StaticRoutes,
			DHCPRoutes:            d.collectDHCPRoutes(),
			PolicyOptions:         &cfg.PolicyOptions,
			ForwardingTableExport: cfg.RoutingOptions.ForwardingTableExport,
			BackupRouter:          cfg.System.BackupRouter,
			BackupRouterDst:       cfg.System.BackupRouterDst,
		}
		for _, ri := range cfg.RoutingInstances {
			vrfName := "vrf-" + ri.Name
			if ri.InstanceType == "forwarding" {
				vrfName = "" // forwarding instances use the default table
			}
			fc.Instances = append(fc.Instances, frr.InstanceConfig{
				VRFName:      vrfName,
				OSPF:         ri.OSPF,
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

	// 5. Apply radvd config (Router Advertisements)
	if d.radvd != nil && len(cfg.Protocols.RouterAdvertisement) > 0 {
		if err := d.radvd.Apply(cfg.Protocols.RouterAdvertisement); err != nil {
			slog.Warn("failed to apply radvd config", "err", err)
		}
	}

	// 6. Apply IPsec config
	if d.ipsec != nil && len(cfg.Security.IPsec.VPNs) > 0 {
		if err := d.ipsec.Apply(&cfg.Security.IPsec); err != nil {
			slog.Warn("failed to apply IPsec config", "err", err)
		}
	}

	// 7. Apply DHCP server config (Kea DHCPv4 + DHCPv6)
	if d.dhcpServer != nil && (cfg.System.DHCPServer.DHCPLocalServer != nil || cfg.System.DHCPServer.DHCPv6LocalServer != nil) {
		if err := d.dhcpServer.Apply(&cfg.System.DHCPServer); err != nil {
			slog.Warn("failed to apply DHCP server config", "err", err)
		}
	}

	// 8. Apply VRRP config (keepalived)
	instances := vrrp.CollectInstances(cfg)
	if len(instances) > 0 {
		if err := vrrp.Apply(instances); err != nil {
			slog.Warn("failed to apply VRRP config", "err", err)
		}
	}

	// 9. Apply system DNS and NTP configuration
	d.applySystemDNS(cfg)
	d.applySystemNTP(cfg)

	// 9.5. Apply system hostname, timezone, and kernel tuning
	d.applyHostname(cfg)
	d.applyTimezone(cfg)
	d.applyKernelTuning(cfg)

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

	// 15. Archive config to remote sites if transfer-on-commit is enabled
	d.archiveConfig(cfg)

	// 16. Update flow traceoptions (trace file + filters)
	d.updateFlowTrace(cfg)

	// 17. Update event-options policies (RPM-driven failover)
	if d.eventEngine != nil {
		d.eventEngine.Apply(cfg.EventOptions)
	}
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
			dhcpIface := ifName
			if unit.VlanID > 0 {
				dhcpIface = fmt.Sprintf("%s.%d", ifName, unit.VlanID)
			}
			if unit.DHCP {
				if unit.DHCPOptions != nil {
					dm.SetDHCPv4Options(dhcpIface, &dhcp.DHCPv4Options{
						LeaseTime:              unit.DHCPOptions.LeaseTime,
						RetransmissionAttempt:   unit.DHCPOptions.RetransmissionAttempt,
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
func (d *Daemon) collectDHCPRoutes() []frr.DHCPRoute {
	if d.dhcp == nil {
		return nil
	}
	var routes []frr.DHCPRoute
	for _, lease := range d.dhcp.Leases() {
		if !lease.Gateway.IsValid() {
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

// logFinalStats reads and logs global counter summary before shutdown.
func logFinalStats(dp dataplane.DataPlane) {
	if !dp.IsLoaded() {
		return
	}
	ctrMap := dp.Map("global_counters")
	if ctrMap == nil {
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
		var perCPU []uint64
		if err := ctrMap.Lookup(n.idx, &perCPU); err != nil {
			continue
		}
		var total uint64
		for _, v := range perCPU {
			total += v
		}
		attrs = append(attrs, n.name, total)
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
		"sampling_zones", len(ec.SamplingZones))
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

// applySyslogConfig constructs syslog clients from the config and applies them
// to the event reader.
func applySyslogConfig(er *logging.EventReader, cfg *config.Config) {
	if er == nil || len(cfg.Security.Log.Streams) == 0 {
		return
	}
	// Resolve global source-interface to IP (fallback for streams without source-address)
	var globalSourceAddr string
	if cfg.Security.Log.SourceInterface != "" {
		if iface, err := net.InterfaceByName(cfg.Security.Log.SourceInterface); err == nil {
			if addrs, err := iface.Addrs(); err == nil {
				for _, a := range addrs {
					if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
						globalSourceAddr = ipn.IP.String()
						break
					}
				}
			}
		}
	}

	var clients []*logging.SyslogClient
	for name, stream := range cfg.Security.Log.Streams {
		srcAddr := stream.SourceAddress
		if srcAddr == "" {
			srcAddr = globalSourceAddr
		}
		client, err := logging.NewSyslogClientWithSource(stream.Host, stream.Port, srcAddr)
		if err != nil {
			slog.Warn("failed to create syslog client",
				"stream", name, "host", stream.Host, "err", err)
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
			"severity", stream.Severity, "facility", stream.Facility,
			"format", format, "category", stream.Category)
		clients = append(clients, client)
	}
	if len(clients) > 0 {
		er.SetSyslogClients(clients)
	}
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

// applySystemNTP configures systemd-timesyncd from system { ntp } config.
func (d *Daemon) applySystemNTP(cfg *config.Config) {
	if len(cfg.System.NTPServers) == 0 || isProcessDisabled(cfg, "ntp") {
		return
	}

	var b strings.Builder
	fmt.Fprintf(&b, "[Time]\nNTP=%s\n", strings.Join(cfg.System.NTPServers, " "))
	// Junos ntp boot-server threshold maps to timesyncd RootDistanceMaxUSec
	if cfg.System.NTPThreshold > 0 {
		fmt.Fprintf(&b, "RootDistanceMaxUSec=%dms\n", cfg.System.NTPThreshold)
	}
	content := b.String()
	confPath := "/etc/systemd/timesyncd.conf.d/bpfrx.conf"

	current, _ := os.ReadFile(confPath)
	if string(current) == content {
		return // no change
	}

	os.MkdirAll("/etc/systemd/timesyncd.conf.d", 0755)
	if err := os.WriteFile(confPath, []byte(content), 0644); err != nil {
		slog.Warn("failed to write timesyncd config", "err", err)
		return
	}

	// Restart timesyncd to pick up new servers
	exec.Command("systemctl", "restart", "systemd-timesyncd").Run()
	slog.Info("NTP config applied", "servers", cfg.System.NTPServers)
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
