// Package daemon implements the bpfrx daemon lifecycle.
package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/psviderski/bpfrx/pkg/cli"
	"github.com/psviderski/bpfrx/pkg/config"
	"github.com/psviderski/bpfrx/pkg/configstore"
	"github.com/psviderski/bpfrx/pkg/conntrack"
	"github.com/psviderski/bpfrx/pkg/dataplane"
	"github.com/psviderski/bpfrx/pkg/frr"
	"github.com/psviderski/bpfrx/pkg/ipsec"
	"github.com/psviderski/bpfrx/pkg/logging"
	"github.com/psviderski/bpfrx/pkg/routing"
)

// Options configures the daemon.
type Options struct {
	ConfigFile  string
	NoDataplane bool // set to true to run without eBPF (config-only mode)
}

// Daemon is the main bpfrx daemon.
type Daemon struct {
	opts    Options
	store   *configstore.Store
	dp      *dataplane.Manager
	routing *routing.Manager
	frr     *frr.Manager
	ipsec   *ipsec.Manager
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
	slog.Info("starting bpfrx daemon",
		"config", d.opts.ConfigFile,
		"pid", os.Getpid())

	// Load persisted configuration
	if err := d.store.Load(); err != nil {
		slog.Warn("failed to load config, starting with empty config",
			"err", err)
	} else {
		slog.Info("configuration loaded", "file", d.opts.ConfigFile)
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
	if d.dp != nil {
		gc := conntrack.NewGC(d.dp, 10*time.Second)
		wg.Add(1)
		go func() {
			defer wg.Done()
			gc.Run(ctx)
		}()

		eventsMap := d.dp.Map("events")
		if eventsMap != nil {
			er = logging.NewEventReader(eventsMap, eventBuf)
			wg.Add(1)
			go func() {
				defer wg.Done()
				er.Run(ctx)
			}()

			// Set up syslog clients from active config
			if cfg := d.store.ActiveConfig(); cfg != nil {
				applySyslogConfig(er, cfg)
			}
		}
	}

	// Start CLI shell
	shell := cli.New(d.store, d.dp, eventBuf, er, d.routing, d.frr, d.ipsec)

	// Run CLI in a goroutine so we can still handle signals
	errCh := make(chan error, 1)
	go func() {
		errCh <- shell.Run()
	}()

	var runErr error
	select {
	case err := <-errCh:
		if err != nil {
			runErr = fmt.Errorf("CLI: %w", err)
		}
	case <-ctx.Done():
		slog.Info("signal received, shutting down")
	}

	// Cancel context to stop background goroutines, then wait for them.
	stop()
	wg.Wait()

	// Clean up routing subsystems.
	if d.ipsec != nil {
		d.ipsec.Clear()
	}
	if d.frr != nil {
		d.frr.Clear()
	}
	if d.routing != nil {
		d.routing.ClearTunnels()
		d.routing.ClearStaticRoutes()
		d.routing.Close()
	}

	// Log final stats before closing dataplane.
	if d.dp != nil {
		logFinalStats(d.dp)
		d.dp.Close()
	}

	slog.Info("shutdown complete")
	return runErr
}

// applyConfig applies a compiled config in the correct order:
// 1. Create tunnels (so interfaces exist for zone binding)
// 2. Compile eBPF (attaches XDP/TC to interfaces including tunnels)
// 3. Install static routes
// 4. Apply FRR config (OSPF/BGP)
// 5. Apply IPsec config (strongSwan)
func (d *Daemon) applyConfig(cfg *config.Config) {
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

	// 2. Compile eBPF dataplane
	if d.dp != nil {
		if _, err := d.dp.Compile(cfg); err != nil {
			slog.Warn("failed to compile dataplane", "err", err)
		}
	}

	// 3. Install static routes
	if d.routing != nil && len(cfg.RoutingOptions.StaticRoutes) > 0 {
		if err := d.routing.ApplyStaticRoutes(cfg.RoutingOptions.StaticRoutes); err != nil {
			slog.Warn("failed to apply static routes", "err", err)
		}
	}

	// 4. Apply FRR config
	if d.frr != nil && (cfg.Protocols.OSPF != nil || cfg.Protocols.BGP != nil) {
		if err := d.frr.Apply(cfg.Protocols.OSPF, cfg.Protocols.BGP); err != nil {
			slog.Warn("failed to apply FRR config", "err", err)
		}
	}

	// 5. Apply IPsec config
	if d.ipsec != nil && len(cfg.Security.IPsec.VPNs) > 0 {
		if err := d.ipsec.Apply(&cfg.Security.IPsec); err != nil {
			slog.Warn("failed to apply IPsec config", "err", err)
		}
	}
}

// logFinalStats reads and logs global counter summary before shutdown.
func logFinalStats(dp *dataplane.Manager) {
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

// applySyslogConfig constructs syslog clients from the config and applies them
// to the event reader.
func applySyslogConfig(er *logging.EventReader, cfg *config.Config) {
	if er == nil || len(cfg.Security.Log.Streams) == 0 {
		return
	}
	var clients []*logging.SyslogClient
	for name, stream := range cfg.Security.Log.Streams {
		client, err := logging.NewSyslogClient(stream.Host, stream.Port)
		if err != nil {
			slog.Warn("failed to create syslog client",
				"stream", name, "host", stream.Host, "err", err)
			continue
		}
		slog.Info("syslog stream configured",
			"stream", name, "host", stream.Host, "port", stream.Port)
		clients = append(clients, client)
	}
	if len(clients) > 0 {
		er.SetSyslogClients(clients)
	}
}
