// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/psaab/xpf/pkg/cli"
	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/ddns"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/dhcprelay"
	"github.com/psaab/xpf/pkg/dhcpserver"
	"github.com/psaab/xpf/pkg/feeds"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/fwdstatus"
	"github.com/psaab/xpf/pkg/ipmon"
	"github.com/psaab/xpf/pkg/ipsec"
	"github.com/psaab/xpf/pkg/lldp"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/ra"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/psaab/xpf/pkg/rpm"
	"github.com/psaab/xpf/pkg/vrrp"
)

// buildRuntimeDataPlane selects the userspace-native Boot() path for the
// default and explicit userspace selections, and falls through to
// dataplane.NewRuntimeDataPlane for every other type. After #1476
// (legacy eBPF retirement) and #1527 (DPDK Phase 2), the only
// operator-facing cases on the fall-through branch are the two
// retirement-error sentinels: explicit "dataplane-type ebpf" →
// ErrEBPFBackendRetired, and "dataplane-type dpdk" →
// ErrDPDKBackendRetired. Unknown/custom types and any future
// registry-backed types also flow through the same default branch
// and surface the legacy factory's error (including "unknown
// dataplane type") verbatim.
//
// Keeping the legacy branch routed through the dataplane factory
// preserves both retirement sentinel handlings unchanged AND
// preserves the existing AST canary in
// pkg/dataplane/retirement_boundary_canary_test.go
// (TestDaemonRuntimeEntryPointUsesRuntimeDataPlane) that requires
// daemon_run.go to reference dataplane.NewRuntimeDataPlane.
//
// This helper MUST stay in daemon_run.go for the canary above. Do not
// split into a separate file in pkg/daemon/ without updating the canary.
//
// #1520 (sub-#1451 S5): userspace daemon construction no longer detours
// through the runtime backend registry. The registry entry is retained
// as a compatibility / test seam (see pkg/dataplane/userspace/manager.go
// init()).
func buildRuntimeDataPlane(dpType string) (dataplane.RuntimeDataPlane, error) {
	switch dataplane.EffectiveType(dpType) {
	case dataplane.TypeUserspace:
		return dpuserspace.Boot(), nil
	default:
		return dataplane.NewRuntimeDataPlane(dpType)
	}
}

// Run starts the daemon and blocks until shutdown.
func (d *Daemon) Run(ctx context.Context) error {
	// d.daemonCtx is the RAW parent (production: context.Background) for the
	// long-lived background goroutines and the dataplane/cluster runtimes. The
	// shutdown sequence tears those down EXPLICITLY and needs them LIVE during
	// teardown (logFinalStats via dp.Telemetry, the HA rg_active clear via
	// dp.HA()), so it is deliberately kept SEPARATE from — and never replaced by
	// — the shutdown-signal context below (#5807).
	d.daemonCtx = ctx

	// #5807: capture the shutdown signals BEFORE the mutating startup phases
	// (config load / interface naming / manager init / dataplane setup). A
	// SIGTERM — or a daemon-mode SIGINT — that arrives DURING startup then
	// cancels this context instead of the process taking its default action
	// (immediate kill, no deferred cleanup): runStartupOrAbort below aborts the
	// remaining phases and runs the ordered teardown for whatever was already
	// initialized, so a signal mid-startup no longer strands partially-applied
	// links / routes / FRR / IPsec / DHCP / HA / dataplane state with none of
	// the fencing steady-state shutdown performs. The signal set matches the
	// pre-#5807 late install: interactive mode catches only SIGTERM (the CLI
	// keeps SIGINT for Ctrl-C command cancellation), daemon mode catches both.
	// `ctx` is reassigned to this signal context and carries through every later
	// phase, the apply-cancel context, and the main wait exactly as the old
	// PHASE 4 install did.
	ctx, stop := startupSignalContext(ctx)
	defer stop()

	// #5308: guarantee the two daemonCtx-bound background loops (policy
	// scheduler + RPM probe-pin retry) are cancelled + joined even when Run
	// returns WITHOUT reaching runShutdownSequence — an early-error return
	// (config load / manager init / dataplane setup) or an embedded library
	// caller whose ctx cancels. On the normal path runShutdownSequence has
	// already stopped both (idempotent / nil-safe), so these defers are no-ops
	// there; they only do real work on the return paths that skip it. Both loops
	// may be started during initManagers' boot apply below, so registering the
	// defers here covers every subsequent return.
	defer d.stopPinRetryLoop()
	defer d.stopPolicySchedulerLoop()
	d.startPolicySchedulerLoopLocked()

	// WaitGroup for coordinated shutdown of background goroutines. Declared here
	// (before the mutating phases) so the #5807 startup-abort path can hand it to
	// runShutdownSequence; no goroutine is added until PHASE 5, so an early-abort
	// wg.Wait() is a no-op.
	var wg sync.WaitGroup

	// Wrap the default slog handler to support system syslog forwarding.
	// Syslog clients are added later when config is applied.
	d.slogHandler = logging.NewSyslogSlogHandler(slog.Default().Handler())
	slog.SetDefault(slog.New(d.slogHandler))

	slog.Info("starting xpf daemon",
		"config", d.opts.ConfigFile,
		"pid", os.Getpid())

	// Register the daemon-owned commit-confirmed timeout rollback executor
	// (#1922 Item 1a). Wiring it here — at daemon init, before any commit can
	// be issued — covers ALL commit-confirmed paths (gRPC/REST/remote-cli
	// service mode as well as the interactive in-process CLI), not just the
	// interactive shell. The executor acquires d.applySem then runs store
	// promotion + dataplane re-apply atomically; see executeConfirmedRollback.
	d.store.SetRollbackExecutor(d.executeConfirmedRollback)

	// Register the #1922 Item 4 protected-set resolver so the dataplane
	// reconcile (compileZones unmanaged strip) never brings down the
	// management lifeline / fxp0, even on an empty/absent/rolled-back
	// config. The resolver lives in the reconcile path (config-independent);
	// it reads the persisted PCI-keyed lifeline record + the (optional)
	// `system management-interface` leaf. Set even in NoDataplane mode is
	// harmless (the compiler is not exercised there).
	dataplane.SetProtectedInterfaceResolver(d.resolveProtectedInterfaces)

	// ===== PHASES 1-4: mutating startup, cancellable via the signal ctx (#5807) =====
	// Each phase mutates real host / manager / dataplane state. runStartupOrAbort
	// checks the shutdown-signal context BEFORE each phase, so a SIGTERM (or
	// daemon-mode SIGINT) that arrives partway through skips the remaining phases
	// and runs the ordered teardown for whatever was already initialized (every
	// runShutdownSequence step nil-guards its manager, so a partial init tears
	// down cleanly) — then Run returns the non-nil abort error rather than
	// proceeding into steady state. A PLAIN phase error keeps the historical
	// path: return the error and let the deferred loop stops (#5308) run.
	var configCompileFailed bool
	phases := []startupPhase{
		{"config-load-bootstrap", func(context.Context) error {
			var e error
			configCompileFailed, e = d.loadAndBootstrapConfig()
			return e
		}},
		{"interface-naming", func(context.Context) error {
			d.setupInterfaceNaming()
			return nil
		}},
		{"manager-init", func(context.Context) error {
			return d.initManagers(configCompileFailed)
		}},
		{"dataplane-setup", func(context.Context) error {
			return d.setupDataplaneAndInitialConfig()
		}},
	}
	if err := d.runStartupOrAbort(ctx, phases, func(abortErr error) error {
		return d.runShutdownSequence(&wg, stop, abortErr)
	}); err != nil {
		return err
	}

	// #2926: dedicated apply-abort context. A child of the signal context
	// captured at the top of Run, so a real daemon stop (SIGTERM, plus SIGINT in
	// daemon mode)
	// cancels an in-flight commit/remediation apply at its next coarse
	// boundary (applyConfigLocked C1/C2/C3) instead of blocking termination
	// behind netlink + an FRR reload + a Rust control-socket sync. It is kept
	// SEPARATE from d.daemonCtx: d.daemonCtx stays the (production-uncancelled,
	// context.Background) parent of the long-lived background goroutines —
	// flow-export/IPFIX relays, RPM probe-pin retry, the policy scheduler,
	// cluster comms, and the dp.Start dataplane runtime — which the shutdown
	// sequence below tears down EXPLICITLY and which the orderly teardown
	// (logFinalStats through dp.Telemetry, the HA rg_active clear through
	// dp.HA()) still needs live. applyCancelCtx() returns this context; only
	// the commit/sync/confirmed-commit applies route through it. The boot /
	// DHCP / feed applies and executeConfirmedRollback still pass
	// context.Background() unconditionally so they always run to completion.
	d.applyCancelContext, d.applyCancel = context.WithCancel(ctx)
	defer d.applyCancel()

	// Create event buffer (shared between event reader and CLI)
	eventBuf := logging.NewEventBuffer(1000)
	d.eventBuf = eventBuf

	// (wg is declared at the top of Run so the #5807 startup-abort path can pass
	// it to runShutdownSequence.)

	// NOTE: session sync dp wiring + sweep start moved into startClusterComms
	// goroutine to avoid race: d.sessionSync is created asynchronously.

	// ===== PHASE 5: Background-service starts + HTTP/gRPC API =====
	// Start background services if dataplane is loaded
	var er *logging.EventReader
	if d.dp != nil {
		// StartFIBSync is a no-op on every in-tree backend: eBPF
		// resolves FIB queries via bpf_fib_lookup in-kernel and the
		// userspace AF_XDP runtime wraps that no-op through the
		// legacy adapter.  Call site retained for backends that
		// need a userspace route populator (DPDK had one; retired
		// in #1527 / #1525).
		// fibSyncStarter is a no-op on both in-tree backends
		// (kernel bpf_fib_lookup handles FIB resolution); the probe
		// is retained for forward compatibility (a future backend
		// may need a userspace route populator).
		if starter, ok := d.dp.(fibSyncStarter); ok {
			starter.StartFIBSync(ctx)
		}

		gc := d.newConntrackGC(10 * time.Second)
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
			if ss := d.getSessionSync(); d.cluster != nil && d.cluster.IsLocalPrimaryAny() && ss != nil {
				ss.QueueDeleteV4(key)
			}
		}
		gc.OnDeleteV6 = func(key dataplane.SessionKeyV6) {
			if ss := d.getSessionSync(); d.cluster != nil && d.cluster.IsLocalPrimaryAny() && ss != nil {
				ss.QueueDeleteV6(key)
			}
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			gc.Run(ctx)
		}()

		evSrc, evErr := d.dp.Telemetry().NewEventSource()
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
			if d.getSessionSync() != nil {
				er.AddCallback(func(rec logging.EventRecord, raw []byte) {
					if rec.Type != "SESSION_OPEN" {
						return
					}
					if d.cluster == nil || !d.cluster.IsLocalPrimaryAny() {
						return
					}
					// Snapshot the session-sync object once per event (#4958)
					// so the connection check and both queue calls operate on
					// the same instance a concurrent comms restart cannot nil
					// between reads.
					ss := d.getSessionSync()
					if ss == nil || !ss.IsConnected() {
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
						if val, err := d.dp.Sessions().GetV6(key); err == nil && val.IsReverse == 0 {
							if ss.ShouldSyncZone(val.IngressZone) {
								ss.QueueSessionV6(key, val)
							}
						}
					} else {
						var key dataplane.SessionKey
						copy(key.SrcIP[:], raw[8:12])
						copy(key.DstIP[:], raw[24:28])
						key.SrcPort = binary.BigEndian.Uint16(raw[40:42])
						key.DstPort = binary.BigEndian.Uint16(raw[42:44])
						key.Protocol = proto
						if val, err := d.dp.Sessions().GetV4(key); err == nil && val.IsReverse == 0 {
							if ss.ShouldSyncZone(val.IngressZone) {
								ss.QueueSessionV4(key, val)
							}
						}
					}
				})
			}

			// Set up syslog clients from active config
			if cfg := d.store.ActiveConfig(); cfg != nil {
				d.applySyslogConfig(er, cfg)
			}

			// Start NetFlow v9 + IPFIX exporters if configured (#2075).
			// This post-EventReader block is load-bearing: the earlier
			// boot applyConfig ran before d.eventReader existed, so the
			// apply-path reconcileFlowExporters no-op'd. This call is
			// what first starts the exporters at boot; later commits go
			// through the apply path.
			if cfg := d.store.ActiveConfig(); cfg != nil {
				d.reconcileFlowExporters(cfg)
			}

			// Set up flow traceoptions if configured
			if cfg := d.store.ActiveConfig(); cfg != nil {
				d.applyFlowTrace(cfg, er)
			}
		}
		if er == nil {
			if _, ok := d.dp.(userspaceEventStreamProvider); ok {
				er = logging.NewEventReader(nil, eventBuf)
				d.eventReader = er
				if cfg := d.store.ActiveConfig(); cfg != nil {
					d.applySyslogConfig(er, cfg)
					d.reconcileFlowExporters(cfg)
					d.applyFlowTrace(cfg, er)
				}
			}
		}

		if _, ok := d.dp.(userspaceEventStreamProvider); ok && d.cluster == nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				d.runUserspaceEventStream(ctx)
			}()
		}

		// #2079: start the NAT source pool-utilization-alarm monitor HERE —
		// after d.dp and d.eventReader are both fully assigned above — so the
		// monitor goroutine's sampler (reads d.dp) and emitter (reads
		// d.eventReader) never race with their initialization. Slow (10s) loop
		// over the helper's last-applied NAT pool snapshot; raises/clears
		// `show security alarms` entries with hysteresis and emits one
		// structured RT_NAT syslog line per transition. (The whole block is
		// gated on a non-NoDataplane dataplane being present.)
		//
		// #2114: route through maybeStartNATPoolAlarm, which gates on
		// !inBootstrap() in addition to a constructed dataplane. In bootstrap
		// mode the dataplane object exists (d.dp != nil) but is not armed, and
		// the bootstrap-exit path may write d.dp = nil on an arm failure;
		// launching the sampler here would race that write. The monitor is
		// instead started in runBootstrapExitStartup once the dataplane is
		// armed. On a normal (non-bootstrap) boot the gate passes and the
		// monitor starts here exactly as before.
		d.maybeStartNATPoolAlarm()
	}

	// Start cluster heartbeat + sync after event fanout is initialized.
	// This avoids an HA startup race where runUserspaceEventStream wires a
	// decode-only fallback callback before d.eventReader exists.
	if d.cluster != nil {
		d.startClusterComms(ctx)
	}

	// Reconcile DHCP clients for interfaces configured with dhcp/dhcpv6.
	// The startup applyConfig above already reconciled them (#1793), so
	// this is normally a no-op; it is kept as a safety net to preserve
	// the documented ordering guarantee: clients run only after BPF load
	// + config compile, so HOST_INBOUND_DHCP flags are active before
	// DHCP packets start flowing.
	if !d.opts.NoDataplane {
		if cfg := d.store.ActiveConfig(); cfg != nil {
			d.reconcileDHCPClients(cfg)
		}
	}

	// Construct the dynamic-address feed manager UNCONDITIONALLY (#5036) — even
	// when no feed servers are configured at boot — and reconcile it against
	// the active config. Before this the manager was built only if boot-time
	// feed servers existed and Apply was never re-invoked, so a feed server
	// added (or removed/edited) on a later commit was silently ignored until
	// restart: a deny policy bound to the new feed armed with zero prefixes
	// (fail-open). ensureFeedManager makes d.feeds non-nil so the day-2
	// reconcile path (reconcileFeeds, wired into applyConfigLocked) can start
	// the producers; reconcileFeeds here does the initial hash-gated Apply for
	// a config that already declares feed servers.
	if cfg := d.store.ActiveConfig(); cfg != nil {
		d.ensureFeedManager()
		d.reconcileFeeds(cfg)
	}

	// RPM probes are started by the hash-gated reconcileRPM step inside
	// the startup applyConfig above (#1827); this safety net covers the
	// no-dataplane path where the startup apply may have run before
	// d.daemonCtx-dependent wiring settled.
	if cfg := d.store.ActiveConfig(); cfg != nil {
		d.reconcileRPM(cfg)
	}

	// Start LLDP if configured. The Manager is always created here (not gated
	// on a non-nil/enabled LLDP config), mirroring d.dhcpRelay above: the
	// d.lldpMgr pointer is then written exactly once, at boot, so the lock-free
	// reads on the gRPC / CLI `show lldp neighbors` handler goroutines never
	// race a day-2 commit (#2372 finding 3 — a lazy day-2 reassignment would be
	// a data race on the pointer). reconcileLLDP is the single source of truth
	// for LLDP start/stop/reconfigure: it runs here at boot and again on every
	// day-2 commit from applyConfigLocked, so a config change to `protocols
	// lldp` takes effect without a daemon restart, and it only ever calls
	// Apply()/Stop() on this already-constructed manager.
	d.lldpMgr = lldp.New()
	if cfg := d.store.ActiveConfig(); cfg != nil {
		d.reconcileLLDP(cfg)
	}

	// Event-options engine safety net. The engine was already constructed and
	// its RPM callback registered earlier (initEventEngine, before probes
	// started, #3755), and the boot applyConfig reconciled the policy set via
	// applyConfigLocked step 17. This mirrors the reconcileRPM/reconcileLLDP
	// boot safety nets above: it covers the bootstrap-mode path where the boot
	// applyConfig was suppressed, so a bootstrap-exit still loads any policies.
	// reconcileEventOptions is idempotent (Apply reconciles state), so a repeat
	// on the normal path is harmless (#3752).
	if cfg := d.store.ActiveConfig(); cfg != nil {
		d.reconcileEventOptions(cfg)
	}

	// Start DHCP relay. The Manager is always created (not gated on a
	// non-nil relay config) so the apply pipeline (reconcileDHCPRelay,
	// #2348) can start a relay added on a day-2 commit and stop one
	// removed — Apply diffs desired-vs-running and a nil config stops all
	// relays. The relay goroutines bind to d.daemonCtx (== ctx here) so
	// they outlive each apply call and are torn down only at daemon stop.
	d.dhcpRelay = dhcprelay.NewManager()
	// #2456: gate the upstream relay-forward on this node's VRRP/cluster MASTER
	// state for the relay interface's redundancy group. On a shared client
	// segment both the master and the backup receive the client broadcast;
	// without this gate BOTH relay it upstream (duplicate relayed requests with
	// different per-node giaddrs). The gate is read per packet, so a backup that
	// becomes master starts relaying immediately. Standalone / non-RG-owned
	// interfaces always relay (the gate returns true).
	d.dhcpRelay.SetMasterGate(d.relayMasterGateOpen)
	if cfg := d.store.ActiveConfig(); cfg != nil {
		d.dhcpRelay.Apply(ctx, cfg.ForwardingOptions.DHCPRelay)
	}

	// Port mirroring
	if cfg := d.store.ActiveConfig(); cfg != nil && cfg.ForwardingOptions.PortMirroring != nil {
		for name, inst := range cfg.ForwardingOptions.PortMirroring.Instances {
			slog.Info("Port mirroring configured", "instance", name, "input", inst.Input, "output", inst.Output)
		}
	}

	// Start the SNMP agent if configured (#3967). This is the FIRST start; it
	// runs regardless of config-only / bootstrap mode (unlike the boot
	// applyConfig, which is gated on !NoDataplane and suppressed in bootstrap)
	// so the agent serves even in degraded modes, matching pre-#3967 behavior.
	// The agent + link-state monitor are bound to a lifetime context derived
	// from d.daemonCtx (via startSNMPLocked) and torn down explicitly at
	// shutdown (teardownSNMP), NOT on this run WaitGroup. Setting snmpBootReady
	// hands day-2 lifecycle changes over to reconcileSNMP (applyConfigLocked):
	// an earlier boot apply left the start gated on snmpBootReady==false so the
	// boot apply and this block never double-start.
	d.snmpReconMu.Lock()
	if cfg := d.store.ActiveConfig(); snmpEnabled(cfg) {
		// Record the running-config hash only if the listener actually bound.
		// A discarded bind failure would otherwise leave SNMP down while state
		// says "applied", so a later identical commit no-ops forever (#5110);
		// leaving the hash unrecorded lets the next commit retry the bind.
		if err := d.startSNMPLocked(cfg); err != nil {
			slog.Error("SNMP agent failed to start at boot; a later commit will retry", "err", err)
		} else {
			d.snmpHash, d.snmpHashSet = snmpConfigHash(cfg), true
		}
	}
	d.snmpBootReady = true
	d.snmpReconMu.Unlock()

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
			// #1197: kernel-as-authority neighbor listener.
			// Subscribes to RTM_NEWNEIGH/DELNEIGH and triggers
			// snapshot regen on forwarding-relevant changes.
			wg.Add(1)
			go func() {
				defer wg.Done()
				d.neighborListener(ctx)
			}()
		}
		// #2197 item 2: always-on proxy-ARP/NDP re-assert. Started
		// unconditionally (independent of ActiveConfig at start, which it
		// re-reads each tick) so a non-commit link cycle that re-defaults
		// the per-interface proxy_arp/proxy_ndp sysctl self-heals within
		// proxyARPReassertInterval. The reconcile is a no-op when no
		// proxy-arp entries are configured, so the loop is cheap on configs
		// that do not use proxy-arp. It covers BOTH standalone and cluster
		// modes (reconcileRGStateLoop is cluster-only; monitorLinkState is
		// SNMP-gated).
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.proxyARPReassertLoop(ctx)
		}()
	}

	// #1387 inc-2: start the always-on DHCP dynamic-DNS reconcile loop. It
	// is constructed UNCONDITIONALLY (idle when disabled) so an
	// enabled→disabled commit can still withdraw published records; the loop
	// is file-I/O + DNS only (no control-socket contention) and is gated to
	// the HA-active node (MASTER for >=1 RG; always-open standalone).
	if !d.opts.NoDataplane && d.ddns != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.runDDNSReconcileLoop(ctx)
		}()
	}

	// #2691 P2: start the always-on Surface A (router/interface-address) DDNS
	// reconcile loop. Same lifecycle + control-socket-free + per-RG-gated
	// discipline as the lease loop above; it reads netlink + the DHCP client
	// lease set and publishes the firewall's own addresses.
	if !d.opts.NoDataplane && d.surfaceA.mgr != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.runSurfaceADDNSReconcileLoop(ctx)
		}()
	}

	// Start VRRP event watcher (manager was created earlier, before applyConfig).
	// Uses context.Background() — the watcher must outlive daemon ctx cancel
	// so it can process VRRP BACKUP events during shutdown (rg_active cleanup).
	// The watcher exits when eventCh is closed by vrrpMgr.Stop().
	go d.watchVRRPEvents(context.Background())

	// Start reconciliation loop — periodic safety net that corrects
	// rg_active and blackhole route drift from dropped events.
	if d.cluster != nil {
		d.startReconcileRGStateLoop(ctx, &wg)
	}

	// Start HTTP API server if configured.
	if d.opts.APIAddr != "" {
		d.startHTTPServer(ctx, &wg, eventBuf)
	}

	// #881: forwarding-daemon CPU sampler (5s/1m/5m windows for
	// `show chassis forwarding`).  Shared between the gRPC server
	// and the local CLI; both paths call Snapshot() at query time.
	// Started here so the ring is populated before the first CLI.
	fwdSampler := fwdstatus.NewSampler(d.forwardingStatusDataplane(), fwdstatus.OSProcReader{})
	fwdSampler.Start(ctx)

	// Start gRPC API server.
	d.startGRPCServer(ctx, &wg, eventBuf, fwdSampler)

	// ===== PHASE 6: Main block / wait (interactive CLI or daemon-mode signal wait) =====
	// Start interactive CLI or block in daemon mode
	var runErr error
	if isInteractive() {
		// d.dp asserted against the local cliDataPlane probe
		// (runtime_probes.go) — structurally identical to pkg/cli's
		// package-private cliRuntime (pkg/cli/runtime.go, #1517).
		// Go duck-types the assignment to cli.New's dp parameter at
		// this site; signature drift surfaces as a compile error.
		var cliDP cliDataPlane
		if d.dp != nil {
			if probe, ok := d.dp.(cliDataPlane); ok {
				cliDP = probe
			}
		}
		shell := cli.New(d.store, cliDP, eventBuf, er, d.routing, d.frr, d.ipsec, d.dhcp, d.dhcpRelay, d.cluster)
		shell.SetVersion(d.opts.Version)
		shell.SetForwardingSampler(fwdSampler)
		// #797 H2 / #846: route in-process CLI commits through the
		// daemon's atomic commit+apply so they serialize against
		// HTTP/gRPC/event-engine commits under d.applySem.
		// applyConfigFn stays wired for non-commit paths (rollback,
		// confirm) that still need the full reconcile.
		shell.SetApplyConfigFn(d.applyConfig)
		// #5054: in-process CLI commits sync to the peer on the SAME
		// RG0-ownership policy as gRPC/REST — peer convergence is
		// transport-independent, decided in commitAndApplyOperator, not
		// by which API committed. Wiring lives in the shellCommitFn /
		// shellCommitConfirmedFn seams so it is fail-on-revert covered
		// (#5961, configsync_transport_5054_test.go).
		shell.SetCommitFns(d.shellCommitFn(), d.shellCommitConfirmedFn())
		// #5871: route the in-process `request system zeroize` through the
		// daemon's coordinated factory-reset transaction — the SAME function wired
		// into the gRPC server as grpcapi.Config.ZeroizeFn. factoryReset takes
		// d.applySem (draining any in-flight apply) and enters the terminal reset
		// generation BEFORE the wipe, so a console zeroize can no longer erase
		// state out-of-band while a concurrent commit / HA-sync / reconcile
		// re-creates the just-erased .configdb SSOT or re-renders the wiped secrets.
		shell.SetFactoryResetFn(d.factoryReset)
		shell.SetRPMResultsFn(func() []*rpm.ProbeResult {
			if d.rpm != nil {
				return d.rpm.Results()
			}
			return nil
		})
		shell.SetIPMonStatusFn(func() []ipmon.PolicyStatus {
			if d.ipmon != nil {
				return d.ipmon.Status()
			}
			return nil
		})
		// #2079: active NAT pool-utilization alarms for `show security alarms`.
		shell.SetNATPoolAlarmsFn(d.natPoolAlarms)
		shell.SetFeedsFn(func() map[string]feeds.FeedInfo {
			if d.feeds != nil {
				return d.feeds.AllFeeds()
			}
			return nil
		})
		// #3105: live feed-prefix overlay so the in-process CLI's
		// `show security match-policies` / `test policy` simulators resolve
		// feed-backed address-names to their live CIDRs, matching the REST/gRPC
		// simulators (same FeedOverlayFn) and what the AF_XDP helper enforces.
		// Reads daemon-local state (feedSnapshotsForConfig -> the feed
		// manager's in-memory snapshots) — no control-socket call.
		shell.SetFeedOverlayFn(func() map[string][]string {
			return d.feedSnapshotsForConfig(d.store.ActiveConfig())
		})
		shell.SetLLDPNeighborsFn(func() []*lldp.Neighbor {
			if d.lldpMgr != nil {
				return d.lldpMgr.Neighbors()
			}
			return nil
		})
		// #1387 inc-2: DHCP dynamic-DNS status hooks for the in-process CLI.
		shell.SetDDNSStatsFn(d.DDNSStats)
		shell.SetDDNSOwnedRecordsFn(d.OwnedDDNSRecords)
		shell.SetSurfaceADDNSStatsFn(d.SurfaceAStats)
		shell.SetSurfaceADDNSStatusFn(d.SurfaceAStatus)
		shell.SetSurfaceADDNSForceFn(d.ForceDDNSUpdate)
		shell.SetFlowCollectorHealthFn(d.FlowCollectorHealth)
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

	// ===== PHASE 7: Shutdown sequence (extracted to runShutdownSequence, #4662) =====
	return d.runShutdownSequence(&wg, stop, runErr)
}

// startupSignalContext returns a child of parent that is cancelled when the
// daemon receives a shutdown signal, captured at the TOP of Run so a signal
// during the mutating startup phases aborts startup instead of the process
// default-terminating (#5807). The signal set is mode-dependent and matches the
// historical late install: interactive mode catches only SIGTERM so the CLI
// keeps SIGINT for Ctrl-C command cancellation; daemon (non-interactive) mode
// catches SIGTERM and SIGINT. Extracted as a named seam so a test can assert the
// returned context is a cancellable child (not context.Background, whose Done()
// is nil) without delivering a real OS signal.
func startupSignalContext(parent context.Context) (context.Context, context.CancelFunc) {
	if isInteractive() {
		return signal.NotifyContext(parent, syscall.SIGTERM)
	}
	return signal.NotifyContext(parent, syscall.SIGTERM, syscall.SIGINT)
}

// startupPhase is one ordered, MUTATING startup step run under the
// shutdown-signal context (#5807). name is used only for the abort log/error.
type startupPhase struct {
	name string
	run  func(context.Context) error
}

// runStartupPhases executes the mutating startup phases in order, checking the
// shutdown-signal context for cancellation BEFORE each phase and once more after
// the last (#5807). A SIGTERM / daemon-SIGINT that arrives mid-startup therefore
// stops the sequence at the next phase boundary — the remaining phases do NOT
// run and their mutations never happen — and the wrapped context error is
// returned. A phase's own error is returned as-is (unwrapped). It returns nil
// only when every phase ran and the context was never cancelled.
//
// Cancellation is observed BETWEEN phases (a phase already in flight runs to
// completion): the mutating phases use context.Background()-equivalent
// long-lived wiring internally, so this coarse, boundary-level cancellation is
// the abort granularity — matched to the coarse boot mutations it guards.
func (d *Daemon) runStartupPhases(ctx context.Context, phases []startupPhase) error {
	for _, p := range phases {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("startup aborted by shutdown signal before phase %q: %w", p.name, err)
		}
		if err := p.run(ctx); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("startup aborted by shutdown signal after the final phase: %w", err)
	}
	return nil
}

// runStartupOrAbort runs the mutating startup phases (runStartupPhases) and,
// when a shutdown signal cancelled startup mid-way, runs the ordered teardown
// for whatever was initialized before returning the non-nil abort error (#5807).
// teardown is injected (Run passes runShutdownSequence) so the abort→cleanup
// wiring is unit-testable without executing the real subsystem teardown.
//
// A PLAIN phase error (ctx NOT cancelled) is returned WITHOUT running teardown:
// that preserves the pre-#5807 early-error path, where Run's deferred
// stopPolicySchedulerLoop / stopPinRetryLoop (#5308) are the intended cleanup
// and running the full ordered teardown was deliberately not done. The
// distinguishing test is ctx.Err() (was the SIGNAL context cancelled), never the
// returned error's identity, so a phase error that merely wraps a context error
// is not mistaken for a signal abort.
func (d *Daemon) runStartupOrAbort(ctx context.Context, phases []startupPhase, teardown func(error) error) error {
	err := d.runStartupPhases(ctx, phases)
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		slog.Warn("xpf daemon: shutdown signal during startup — running teardown for the "+
			"initialized subset before exit (partial-init safe)", "err", err)
		return teardown(err)
	}
	return err
}

// startReconcileRGStateLoop launches the RG-state reconcile safety-net loop and
// registers it on the run WaitGroup so runShutdownSequence's wg.Wait() JOINS it
// BEFORE the HA ownership-relinquish steps (rg_active clear, RA withdraw,
// direct-mode VIP removal, VRRP Stop). #5681 / M23: as a bare goroutine the loop
// was never joined — stop() cancelled its ctx, but a tick already past the
// ctx.Done() select (or blocked mid-pass on a control-socket update) could
// complete AFTER wg.Wait() during ownership cleanup and re-assert mastership
// (re-enable forwarding / re-add VIPs), opening a transient dual-master /
// blackhole window on planned shutdown or failover. Quiescing it early removes
// no needed shutdown behavior: the VRRP BACKUP transition during shutdown is
// driven by watchVRRPEvents (deliberately on context.Background()), not this
// safety-net loop. Mirrors the sibling reconcile loops (DDNS/proxy-ARP/Surface
// A) that were already wg-registered.
func (d *Daemon) startReconcileRGStateLoop(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.reconcileRGStateLoop(ctx)
	}()
}

// initManagers eagerly constructs the daemon's subsystem managers (routing,
// FRR, IPsec, RPM, ip-monitoring, event-options engine, DHCP, cluster, and
// VRRP), storing each on d.*, BEFORE the first applyConfig and the dataplane
// backend build that follow in Run(). Extracted verbatim from Run()'s PHASE 3
// (#4662 Increment 4); the creation order is load-bearing (e.g. the
// event-options engine registers an RPM callback and must exist before the
// first applyConfig reconciles RPM). configCompileFailed is the #1960
// fail-closed flag threaded from PHASE 1 (read-only here, at
// clearFRRForFailClosedBoot). Returns a non-nil error only on a fatal DHCP
// manager-create failure (the sole early return in the original block), which
// Run propagates unchanged.
// initManagers constructs the routing/FRR/IPsec/RPM/ipmon/event-engine/DHCP/
// cluster/VRRP managers and runs the first applyConfig. Its long-lived runtimes
// (cluster monitor, cluster-event watcher, kernel self-recovery) bind to
// d.daemonCtx — the RAW, signal-uncancelled daemon-lifetime parent — NOT the
// startup-signal context, because the shutdown sequence tears them down
// EXPLICITLY and needs them live during teardown; a startup signal aborts at the
// phase boundary (runStartupPhases), it must not kill these runtimes underneath
// the teardown (#5807).
func (d *Daemon) initManagers(configCompileFailed bool) error {
	// Initialize routing, FRR, and IPsec managers
	if !d.opts.NoDataplane {
		rm, err := routing.New()
		if err != nil {
			slog.Warn("failed to create routing manager", "err", err)
		} else {
			d.routing = rm
			// #1827: flush the reserved probe-pin band (ip rules 50-99 +
			// tables 7000-7049) before anything else runs, so a crashed
			// daemon never leaks stale probe pins across restarts.
			if err := d.routing.ClearProbePins(); err != nil {
				slog.Warn("failed to clear stale probe pins", "err", err)
			}
		}
		d.frr = frr.New()
		// #1993: on a compile-failure boot with NO preserved XDP attachments,
		// the last-good frr.conf managed section is still on disk and FRR (an
		// independent service) will form peerings + re-advertise prefixes for
		// routes this unarmed node cannot forward — a transit blackhole. Clear
		// ONLY the managed section, right after the manager exists and BEFORE
		// the run loop settles, so peers fail over to the HA partner. The
		// predicate PRESERVES the managed section on a hitless restart only when
		// the helper control socket reports forwarding is genuinely live
		// (enabled+armed); pinned XDP links are merely a cheap pre-filter, NOT
		// proof of live forwarding (a graceful stop leaves the pins but disarms
		// forwarding). Freeze-in-last-known-good for management (#1960) is
		// preserved: no .network/.link removal, no link-cycle.
		d.clearFRRForFailClosedBoot(configCompileFailed)
		d.ipsec = ipsec.New()
		d.ra = ra.New()
		d.networkd = networkd.New()
		// #1956 AGY r3 CRITICAL: exempt the #1922 management protected set
		// from networkd.Apply's stale-file sweep so the lifeline's rename +
		// addressing survive a commit that leaves it out of the config.
		d.networkd.SetProtectedResolver(d.resolveProtectedInterfaces)
		d.dhcpServer = dhcpserver.New()
		// #1387 inc-2: construct the DHCP dynamic-DNS manager UNCONDITIONALLY
		// (plan §4.2) — even when DDNS is disabled — so the always-on
		// reconcile loop can withdraw records on an enabled→disabled commit.
		// The nodeID is a node-stable watermark HINT only (never the
		// delete-matching key, Inc-1 ddns.go), so an empty seed in standalone
		// mode is harmless. The live rfc2136 backend is resolved per-Reconcile
		// from the current policy.
		d.ddns = dhcpserver.NewProductionDDNSManager(ddnsNodeIDSeed())
		// #2691 P2: the always-on Surface A manager (router/interface-address
		// publish). Constructed unconditionally for the same reason as the lease
		// manager — a binding removal must have a running loop to withdraw.
		d.surfaceA.mgr = ddns.NewSurfaceAManager()
		// #5748: cross-wire the two DDNS ownership surfaces so each teardown guard
		// can see a wire RR the OTHER surface co-owns and suppress a DELETE that
		// would clobber it (the cross-surface arm of the #5709 co-ownership guard).
		// Each accessor is a LOCK-FREE snapshot read (an atomic.Pointer load in the
		// peer, never taking the peer's mutex), so a teardown holding its own
		// manager's mu can consult the peer with no lock-order cycle / deadlock.
		d.ddns.SetSurfaceACoownerSource(d.surfaceA.mgr.WireRRClaims)
		d.surfaceA.mgr.SetLeaseCoownerSource(d.ddns.WireRRClaims)
	}

	// Create the RPM manager eagerly so the pointer is stable for the
	// CLI/gRPC results closures and so applyConfig's hash-gated
	// reconcileRPM (#1827) can start probes from the very first apply.
	d.rpm = rpm.New()

	// Create the ip-monitoring engine (#1827 PR-1b) before the first
	// applyConfig so reconcileIPMon can install committed policies.
	// The engine drives the routes-only actuator through its own
	// debounce/throttle loop; the RPM transition hook is its sensor.
	d.ipmon = ipmon.New(d.actuateRouteOverlay)
	d.rpm.SetTransitionCallback(d.ipmon.HandleTransition)

	// Construct the event-options engine and register its RPM event callback
	// HERE — BEFORE the first applyConfig runs reconcileRPM and starts the
	// probe goroutines (#3755). runProbeLoop runs its FIRST cycle immediately,
	// so a ping_probe_failed / ping_test_failed / ping_test_completed emitted by
	// that first cycle would be dropped (fireEvent is a no-op while onEvent is
	// nil) if the callback were installed later — a boot-time failover edge the
	// automation exists to handle, lost for long test-interval values. Wiring
	// the callback before probes start closes that gap; rpm additionally buffers
	// any event fired before a callback exists and replays it on registration,
	// as a belt against a future reorder. Idempotent (write-once pointer).
	d.initEventEngine()

	// Create the DHCP manager eagerly, beside the ipmon engine (#1844
	// plan §4.3, AGY r2-1/r2-2): d.dhcp is write-once at boot and
	// read-only thereafter — the engine's run-loop goroutine (via the
	// next-hop resolver) and the CLI/gRPC handlers read the pointer
	// bare, so the previous lazy-create-under-applySem was a Go data
	// race (and the first apply would have built the overlay against a
	// nil resolver target). A dhcp.New failure is FATAL: it means
	// netlink.NewHandle failed, and the daemon cannot manage interfaces
	// without netlink anyway — a silent nil d.dhcp would strand the
	// process DHCP-less for its lifetime with no retry path (SMR plan
	// r3). The gateway-change hook nil-guards d.ipmon so construction
	// order can never regress silently.
	if !d.opts.NoDataplane {
		// State dir for DUID persistence — same directory as config file.
		dm, err := dhcp.New(filepath.Dir(d.opts.ConfigFile), d.onDHCPAddressChange, func() {
			if e := d.ipmon; e != nil {
				e.NotifyNextHopChange()
			}
		})
		if err != nil {
			return fmt.Errorf("create DHCP manager: %w", err)
		}
		d.dhcp = dm
	}

	// Resolver injection MUST precede Start(): the run-loop goroutine
	// reads the resolver field without further synchronization, and the
	// goroutine-creation happens-before edge also publishes d.dhcp.
	d.ipmon.SetNextHopResolver(d.resolveDHCPNextHop)
	d.ipmon.Start()

	// Initialize cluster manager if configured (heartbeat/sync started after applyConfig).
	if cfg := d.store.ActiveConfig(); cfg != nil && cfg.Chassis.Cluster != nil {
		cc := cfg.Chassis.Cluster
		d.cluster = cluster.NewManager(cc.NodeID, cc.ClusterID)
		d.cluster.SetSoftwareVersion(d.opts.Version)

		// #1930 INC-2: if THIS boot is a kernel-candidate trial (the kernel
		// journal is ARMED), set the unconditional election hold BEFORE the
		// FIRST election so the candidate can never win it (even isolated) until
		// the promotion gate verifies the dataplane. UpdateConfig() ITSELF runs
		// an election (single-node path when no peer is up yet, which is exactly
		// the candidate-boot case), so the hold MUST precede UpdateConfig — not
		// merely Start() — or the node is already StatePrimary by the time the
		// hold is set and Start()'s heartbeat/VRRP would advertise primary and
		// preempt the healthy peer. ManualFailover is in-memory (lost across the
		// reboot) and peerAlive is still false here, so the unconditional hold —
		// not ForceSecondary — is what keeps an unverified candidate from
		// blackholing traffic (r2 AGY Critical). No-op on an ordinary boot.
		d.holdSecondaryIfKernelCandidateArmed()

		d.cluster.UpdateConfig(cc)
		d.cluster.Start(d.daemonCtx)
		// Wire event-drop callback: on dropped cluster events, trigger
		// immediate reconciliation so the safety net doesn't wait 2s.
		d.cluster.SetOnEventDrop(d.triggerReconcile)
		// Wire dual-active reaffirm-drop callback (#4867): if the
		// "winner stays" event is dropped on a full channel, the generic
		// reconcile above does NOT re-announce for a steady VIP owner, so
		// re-drive the direct-mode GARP/NA refresh directly. Runs off the
		// election goroutine (cluster m.mu held during the callback) — spawn
		// so the announce I/O never blocks election under that lock.
		d.cluster.SetOnDualActiveWinDrop(func(rgID int) {
			go func() {
				if d.isNoRethVRRP() {
					d.scheduleDirectAnnounce(rgID, "dual-active-win-drop")
				}
			}()
		})
		slog.Info("cluster manager initialized",
			"node", cc.NodeID, "cluster", cc.ClusterID)

		// Watch cluster events for state transitions (primary/secondary).
		go d.watchClusterEvents(d.daemonCtx)

		// #1930 INC-2: bounded local self-recovery for the LANE-1 HA kernel
		// channel — auto-rejoin if an external kernel-roll orchestrator crashed
		// while this node was drained+rebooting (no-op unless orphaned-drained).
		d.startKernelSelfRecovery(d.daemonCtx)
	}

	// Enable IP forwarding — required for the firewall to route packets.
	// #1922: suppressed in bootstrap mode (a takeover host tunable; the
	// bootstrap-exit reconcile enables it on the first confirmed commit).
	if !d.opts.NoDataplane && !d.inBootstrap() {
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
	return nil
}

// loadAndBootstrapConfig loads the persisted configuration (DB, falling back to
// the text config file), enforces the #1917 fatal-on-parse floor, runs
// bootstrapFromFile when required, and derives the boot class + node-id state.
// Extracted verbatim from Run()'s PHASE 1 (#4662 Increment 5). Returns the
// #1960 configCompileFailed fail-closed flag (threaded onward to initManagers)
// and a non-nil error only for the fatal 'DB present but unreadable' floor,
// which Run propagates unchanged (fail closed, never a blind bootstrap).
func (d *Daemon) loadAndBootstrapConfig() (bool, error) {
	// Load persisted configuration from DB, falling back to text config file.
	//
	// Fatal-on-parse floor (#1917 increment B, plan §6.4 / D1): a PRESENT
	// but unreadable active.json (JSON parse error, decrypt failure, or a
	// config compatibility envelope this build cannot read because it was
	// written by a NEWER xpf) must FAIL CLOSED — return the error from Run
	// instead of warning-and-proceeding to a blind bootstrapFromFile() that
	// would OVERWRITE the unreadable DB and silently wipe the operator's
	// config. This is the structural guard that makes a future config-format
	// change safe to roll out: an old reader refuses a too-new DB rather than
	// empty-loading it. A compile error (handled leniently inside Load) or an
	// absent DB (start-fresh) is NOT this case and still degrades gracefully.
	//
	// mgmt-never-stranded (#1922): on the appliance the day-0 + protected-set
	// lifeline keeps mgmt reachable through a fail-closed boot; #1922 hardens
	// the foreign/non-appliance host case (noted in the PR; not implemented
	// here).
	// configCompileFailed records the #1960 fail-closed case: a PRESENT,
	// previously-committed active.json read+parsed fine but no longer
	// compiles. It must NOT fall back to bootstrapFromFile() (which would
	// blind-import the text config file over a broken-but-present committed
	// DB — the same silently-wrong takeover this issue closes) and it forces
	// bootstrap mode below regardless of computeBootClass's other inputs.
	configCompileFailed := false
	switch loadErr := d.store.Load(); classifyLoadError(loadErr) {
	case loadFatalUnreadable:
		// Point recovery at the actual unreadable artifact — the config
		// DB under .configdb/, NOT the text config file (Copilot).
		dbPath := filepath.Join(filepath.Dir(d.opts.ConfigFile), ".configdb", "active.json")
		return false, fmt.Errorf("config DB is present but unreadable; refusing to "+
			"start and overwrite it (fail closed). Inspect/repair %s (the on-disk "+
			"config DB, NOT the text config file) or roll the xpf binary forward "+
			"to a build that can read it: %w",
			dbPath, loadErr)
	case loadCompileFailed:
		// #1960 fail-closed: a previously-committed config no longer
		// compiles. Store.Load set everCommitted=true but left compiled
		// nil, so without this the boot predicate would resolve to NORMAL
		// (ActiveConfig()==nil + everCommitted) and run the positional
		// claim-all interface rename — exactly the safety hole this fixes.
		// Surface it LOUDLY (Error, not the ignored Warn) and route into
		// the #1922 bootstrap/lifeline safe state below.
		configCompileFailed = true
		dbPath := filepath.Join(filepath.Dir(d.opts.ConfigFile), ".configdb", "active.json")
		slog.Error("active config DB is present but no longer compiles; refusing interface "+
			"takeover and entering BOOTSTRAP/lifeline safe state (management preserved, NO "+
			"positional claim-all). Fix the config from the CLI/gRPC and 'commit confirmed', "+
			"or repair/remove the on-disk config DB",
			"db_path", dbPath, "err", loadErr)
	case loadOtherError:
		slog.Warn("failed to load config from db", "err", loadErr)
	case loadOK:
		// nil error: absent DB (start-fresh) or a valid loaded config.
	}

	// If DB had no active config, bootstrap from the text config file.
	//
	// #1960: but NOT when a present committed config failed to compile —
	// importing the text xpf.conf there would silently swap in a different
	// config and then take over interfaces, defeating the fail-closed intent.
	if shouldBootstrapFromFile(d.store.ActiveConfig() != nil, configCompileFailed) {
		if err := d.bootstrapFromFile(); err != nil {
			// #4186 (H-17): a missing text config file is the EXPECTED
			// factory/fresh-boot state, not a failure — log it at Info, not
			// Warn, so operators triaging a real day-0 failure aren't taught
			// to ignore a benign line. Keep Warn for a REAL failure (file
			// present but unreadable/unparseable/uncommittable, incl. the
			// #4183 device-map strand rejection).
			// #4184 (H-11): record the outcome so a failed import is visible
			// on /health + an event, not just here in journald.
			if errors.Is(err, os.ErrNotExist) {
				slog.Info("no text config present to bootstrap from (factory/fresh boot)",
					"file", d.opts.ConfigFile)
				d.recordBootstrapImport(bootstrapImportNoConfig, "")
			} else {
				slog.Warn("failed to bootstrap config from file", "err", err)
				d.recordBootstrapImport(bootstrapImportFailed, err.Error())
			}
		} else {
			d.recordBootstrapImport(bootstrapImportOK, "")
		}
	} else if d.store.ActiveConfig() != nil {
		slog.Info("configuration loaded from db")
		d.recordBootstrapImport(bootstrapImportLoadedDB, "")
	} else {
		// No DB config and bootstrap-from-file suppressed (e.g. a present
		// committed config that failed to compile, #1960). Record no-config
		// so /health reflects that no active config is installed.
		d.recordBootstrapImport(bootstrapImportNoConfig, "")
	}

	// #1922 Item 2: the five-case boot predicate, computed ONCE here after
	// Load + bootstrapFromFile have resolved. Case 4 (corrupt/too-new DB)
	// already exited fatally above (#1917 D1). The remaining cases select
	// bootstrap vs normal. Bootstrap mode suppresses interface/dataplane
	// TAKEOVER actions (but not the management control surfaces or manager
	// construction — C1). Every existing deployment resolves NOT-bootstrap
	// (case 2/3, or case 5 committed-empty) → zero behavior change.
	//
	// #1960: configCompileFailed forces bootstrap here — a previously-committed
	// config that no longer compiles must fail closed (no positional claim-all)
	// regardless of the other inputs, including the HA-node guard.
	nodeIDPresent := hasNodeIDFile()
	bootClass := computeBootClass(d.store.ActiveConfig() != nil, d.store.EverCommitted(), nodeIDPresent, configCompileFailed)
	if bootClass == bootClassBootstrap {
		d.bootstrapMode.Store(true)
		detail := "management control plane (gRPC/REST/CLI) runs normally, but interface " +
			"rename/takeover, dataplane arm, and FRR/VRRP takeover are SUPPRESSED until the " +
			"first 'commit confirmed' (+ confirm) or cluster config sync. This keeps a " +
			"foreign/non-appliance host reachable on its existing management NIC."
		if configCompileFailed {
			// #1960: distinct cause — not "no config", but "committed config no
			// longer compiles". The Error log above already named the DB path.
			slog.Warn("xpf daemon entering BOOTSTRAP mode: committed configuration no longer compiles",
				"detail", detail)
		} else {
			slog.Warn("xpf daemon entering BOOTSTRAP mode: no committed configuration found",
				"detail", detail)
		}
	} else if nodeIDPresent && d.store.ActiveConfig() == nil {
		// HA-node guard (C2/C8): node-id present but NEITHER a DB nor an
		// importable xpf.conf. Resolved to NOT-bootstrap so takeover is not
		// silently suppressed on a normal deploy, but HA availability is NOT
		// promised — this is an operator misconfiguration. Log loudly.
		//
		// #4179: the nil active config carries no cluster stanza, so the boot
		// naming below runs in STANDALONE mode (clusterMode=false → fxp0 +
		// ge-0-0-X, no em0 / FPC). Arm the one-shot re-naming flag so the first
		// non-empty config that arrives (a cluster SyncApply from the primary,
		// or a local commit) re-runs startup naming with the config's real
		// cluster identity. Naming reconciles on config arrival — no daemon
		// restart is required.
		d.emptyHANamingPending.Store(true)
		slog.Error("xpf HA node has /etc/xpf/node-id but no committed config and no importable "+
			"xpf.conf; proceeding with EMPTY config takeover (NOT bootstrap mode) using STANDALONE "+
			"interface names. HA availability is NOT promised until the cluster config is pushed and "+
			"committed; interface naming will reconcile to the node's cluster names (em0, ge-<fpc>-0-X) "+
			"automatically when that config arrives (no restart required)",
			"node_id_file", nodeIDFile)
	}
	return configCompileFailed, nil
}

// setupInterfaceNaming enumerates and renames the PCI NICs to vSRX-style names
// (fxp0, em0, ge-X-0-Y), sets up the bootstrap lifeline, and applies the #801
// step-0 host tunables — all before any manager creation or dataplane load.
// Extracted verbatim from Run()'s PHASE 2 (#4662 Increment 6); a self-contained
// block with no crossing output, no early return, and no ordering change.
func (d *Daemon) setupInterfaceNaming() {
	// Enumerate PCI NICs and assign vSRX-style names (fxp0, em0, ge-X-0-Y)
	// before any manager creation or BPF load.
	if !d.opts.NoDataplane {
		clusterMode := false
		nodeID := 0
		userspaceWorkers := 0
		// D3 (#797): default enabled. Operators opt out via
		// `set system dataplane rss-indirection disable`.
		rssEnabled := true
		var rssAllowed []string
		// #801 Phase-B Step-0 tunables: host-scope governor + netdev
		// budget; per-iface mlx5 coalescence. Host-scope knobs are
		// GATED by `claim-host-tunables true` (B1). Per-iface knobs
		// (rx-usecs/tx-usecs) follow the D3 allowlist and are applied
		// whenever coalescence is configured.
		var (
			governor          string
			netdevBudget      int
			coalesceEnable    bool
			coalesceRX        int
			coalesceTX        int
			userspaceDP       bool
			coalesceExplicit  bool
			claimHostTunables bool
		)
		if cfg := d.store.ActiveConfig(); cfg != nil {
			if cfg.Chassis.Cluster != nil {
				clusterMode = true
				nodeID = cfg.Chassis.Cluster.NodeID
			}
			// D3 (#785): pass userspace-dp worker count so linksetup can
			// reshape mlx5 RSS indirection before any AF_XDP bind. Zero
			// when userspace dataplane is not in use — applyRSSIndirection
			// treats that as a no-op.
			if dataplane.EffectiveType(cfg.System.DataplaneType) == dataplane.TypeUserspace &&
				cfg.System.UserspaceDataplane != nil {
				userspaceDP = true
				userspaceWorkers = cfg.System.UserspaceDataplane.Workers
				if cfg.System.UserspaceDataplane.RSSIndirectionDisabled {
					rssEnabled = false
				}
				// Codex H1: scope D3 to only interfaces that
				// userspace-dp actually binds AF_XDP sockets on.
				rssAllowed = dpuserspace.UserspaceBoundLinuxInterfaces(cfg)
				// #801 knobs.
				claimHostTunables = cfg.System.UserspaceDataplane.ClaimHostTunables
				governor = cfg.System.UserspaceDataplane.CPUGovernor
				netdevBudget = cfg.System.UserspaceDataplane.NetdevBudget
				coalesceExplicit = cfg.System.UserspaceDataplane.CoalescenceAdaptiveExplicit
				// coalesceEnable stays false by default — the Step-0
				// finding is "adaptive=on causes pp99 latency jitter",
				// so default-off is what the issue asks for. An
				// explicit `adaptive enable` inverts this.
				if coalesceExplicit &&
					!cfg.System.UserspaceDataplane.CoalescenceAdaptiveDisabled {
					coalesceEnable = true
				}
				coalesceRX = cfg.System.UserspaceDataplane.CoalescenceRXUsecs
				coalesceTX = cfg.System.UserspaceDataplane.CoalescenceTXUsecs
			}
		}
		if d.inBootstrap() {
			// #1922 Item 2/3: bootstrap mode suppresses the full rename loop
			// and host tunables. Instead, the lifeline-gated path identifies
			// the management NIC by its default route, records its PCI
			// identity, and (only if it would become fxp0) renames JUST that
			// NIC + snapshots its addressing into the bootstrap .network so
			// the operator stays reachable. No other NIC is touched.
			d.setupBootstrapLifeline()
		} else {
			// #1956: device-map mode (opt-in) renames ONLY mapped NICs by
			// stable identity and leaves the rest alone. Positional mode
			// (no device-map) is bit-identical to pre-#1956.
			if err := applyStartupNamingPolicy(d.store.ActiveConfig(), nodeID, clusterMode,
				userspaceWorkers, rssEnabled, rssAllowed, d.resolveProtectedInterfaces()); err != nil {
				// Log stays generic: helper already selected device-map vs
				// positional; callers care only that startup naming failed.
				slog.Warn("interface naming failed", "err", err)
			}
			// #801: host tunables + coalescence. Runs after the interface
			// rename but still before the dataplane is loaded — matches
			// the D3 "before any AF_XDP bind" invariant. Best-effort: any
			// failure logs and continues.
			//
			// B1 opt-in gate: host-scope knobs (governor + netdev_budget +
			// adaptive-rx/tx flip) only apply when `claim-host-tunables
			// true` is set. This keeps xpfd from stepping on shared hosts
			// silently. D3 and per-iface rx-usecs/tx-usecs continue to run
			// as before — both are interface-scoped.
			d.applyStep0Tunables(userspaceDP, claimHostTunables, governor, netdevBudget,
				coalesceExplicit, coalesceEnable, coalesceRX, coalesceTX, rssAllowed)
		}
	}
}

// setupDataplaneAndInitialConfig builds the runtime dataplane backend (unless
// config-only), seeds the NAT/session-id counters, runs the FIRST applyConfig
// (configures VRFs/interfaces/routing before cluster comms), flips the #1715
// dnsBootDone flag under applySem, and clears stale blackhole routes. Extracted
// verbatim from Run()'s PHASE 3 tail (#4662 Increment 7) — the ordering-
// sensitive dataplane-arming path. The resolver injection in initManagers
// (called before this) precedes the dataplane Start here, and the dataplane is
// loaded before the first applyConfig; order is preserved by calling this in
// the same Run() slot right after initManagers. Returns a non-nil error only
// on a fatal dataplane-create failure (the block's sole early return), which
// Run propagates unchanged.
// setupDataplaneAndInitialConfig loads the dataplane and runs the boot config
// apply. The dataplane runtime (dp.Start) binds to d.daemonCtx — the RAW,
// signal-uncancelled daemon-lifetime parent (mirroring the bootstrap-exit
// dp.Start below) — NOT the startup-signal context: the shutdown sequence needs
// the runtime live for logFinalStats (dp.Telemetry) and the HA rg_active clear
// (dp.HA) during teardown, so a startup signal aborts at the phase boundary
// rather than tearing the runtime out from under the teardown (#5807).
func (d *Daemon) setupDataplaneAndInitialConfig() error {
	// Create dataplane backend (unless in config-only mode)
	if !d.opts.NoDataplane {
		dpType := ""
		if cfg := d.store.ActiveConfig(); cfg != nil {
			dpType = cfg.System.DataplaneType
		}
		dp, err := buildRuntimeDataPlane(dpType)
		if errors.Is(err, dataplane.ErrDPDKBackendRetired) {
			// #1527 Phase 2 of the DPDK retirement (umbrella
			// #1525): the runtime DPDK backend is gone, but a
			// node may still have "set system dataplane-type
			// dpdk" persisted in the active config from before
			// Chain A (#1526) blocked the commit. Treat this
			// the same way as a Start() failure: log a warning
			// and fall through to config-only mode so the
			// daemon stays up and the operator can fix the
			// config from the CLI / gRPC. The hard fatal-at-
			// startup branch is reserved for genuinely unknown
			// dataplane types (the default branch below).
			//
			// Note: Store.Load() now also rewrites persisted
			// `dataplane-type dpdk` to empty before compile, so
			// the typical path through buildRuntimeDataPlane
			// resolves to userspace and never reaches this
			// branch. The branch stays as defence-in-depth for
			// callers (config sync, REST/gRPC candidate apply)
			// that bypass Store.Load() and pass the retired
			// type through explicitly.
			slog.Warn("the DPDK dataplane backend has been retired; running in config-only mode until config is updated",
				"type", dpType,
				"err", err,
				"remediation", "set system dataplane-type userspace",
			)
			d.dp = nil
		} else if errors.Is(err, dataplane.ErrEBPFBackendRetired) {
			// #1476: mechanical source removal of the legacy
			// eBPF dataplane. Behaviour mirrors the DPDK arm
			// above. Store.Load() / Store.SyncApply() both
			// rewrite persisted `dataplane-type ebpf` to
			// empty before compile, so the typical path
			// never reaches this branch — but a candidate
			// apply through REST/gRPC that explicitly passes
			// the retired type will, and the daemon must stay
			// up so the operator can correct the candidate.
			slog.Warn("the legacy eBPF dataplane backend has been retired; running in config-only mode until config is updated",
				"type", dpType,
				"err", err,
				"remediation", "set system dataplane-type userspace",
			)
			d.dp = nil
		} else if err != nil {
			slog.Error("failed to create dataplane", "type", dpType, "err", err)
			return fmt.Errorf("create dataplane: %w", err)
		} else {
			d.dp = dp
		}
		// #1620: stamp the cold-path sample mask onto the userspace
		// Manager so the next buildSnapshot includes it. Mask
		// validation already happened in cmd/xpfd/main.go (two-flag
		// scheme, pow-of-2-1, reject u64::MAX). nil pointer ⇒ no
		// operator setting, userspace-dp defaults to 0xff.
		if d.dp != nil && d.opts.ColdPathSampleMask != nil {
			if adapter, ok := d.dp.(interface{ Manager() *dpuserspace.Manager }); ok {
				if mgr := adapter.Manager(); mgr != nil {
					mgr.SetColdPathSampleMask(d.opts.ColdPathSampleMask)
				}
			}
		}
		// #1922 Item 2: in bootstrap mode, do NOT arm the dataplane
		// (AF_XDP attach) and do NOT run the boot-time applyConfig
		// (interface/FRR/routing takeover). The backend object stays
		// constructed (d.dp != nil) so the bootstrap-exit reconcile can
		// arm it on the first confirmed commit (C1: construct always, arm
		// only when not bootstrap). The control plane (gRPC/REST/CLI) is
		// started later regardless.
		if d.inBootstrap() {
			slog.Info("bootstrap mode: dataplane arm and boot-time config apply suppressed")
		} else {
			if d.dp != nil {
				if err := d.dp.Start(d.daemonCtx); err != nil {
					slog.Warn("failed to start dataplane, running in config-only mode",
						"err", err)
					d.dp = nil
				} else {
					// natSeeder is satisfied by both *dataplane.Manager
					// (legacy eBPF — SeedNATPortCounters in maps_nat.go,
					// SeedSessionIDCounter in maps_session.go) and the userspace
					// *LegacyDataPlaneAdapter (via embedded bpfShim). The
					// seed methods are no-ops on the userspace fast path
					// but harmless to invoke. The legacyDP() round-trip is
					// no longer required (#1519).
					if seeder, ok := d.dp.(natSeeder); ok {
						seeder.SeedNATPortCounters()
						nodeID := 0
						if cfg := d.store.ActiveConfig(); cfg != nil && cfg.Chassis.Cluster != nil {
							nodeID = cfg.Chassis.Cluster.NodeID
						}
						seeder.SeedSessionIDCounter(nodeID)
					}
				}
			}
			// Apply current config — needed even in config-only mode so that
			// VRFs, interfaces, and routing are configured before cluster comms.
			if cfg := d.store.ActiveConfig(); cfg != nil {
				slog.Info("applying active configuration")
				d.applyConfig(cfg)
			}
		}
	}
	// #1715: the boot-time DNS reconcile (inside the apply above) ran
	// before DHCP clients start, so its empty-merge policy was
	// repair-only. From here on, an empty DNS merge means "clear DNS".
	// Set under applySem so reconcileDNSLocked (which reads it) never
	// races: applyConfig has released the lock by now, and every later
	// reader re-acquires it.
	_ = d.applySem.Acquire(context.Background(), 1)
	d.dnsBootDone = true
	d.applySem.Release(1)

	// Remove stale blackhole routes from previous daemon runs before
	// cluster comms start (which may inject new ones).
	if d.cluster != nil {
		d.reconcileBlackholeRoutes()
	}
	return nil
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

// namingParamsFromConfig derives the startup-naming inputs from a config: the
// cluster node ID and mode (from the chassis cluster stanza) and the
// userspace-dp RSS-indirection knobs. Shared by the boot naming site, the
// bootstrap-exit takeover, and the #4179 config-arrival re-naming so all three
// derive naming identically from the SAME config.
func namingParamsFromConfig(cfg *config.Config) (nodeID int, clusterMode bool, userspaceWorkers int, rssEnabled bool, rssAllowed []string) {
	rssEnabled = true
	if cfg == nil {
		return
	}
	if cfg.Chassis.Cluster != nil {
		clusterMode = true
		nodeID = cfg.Chassis.Cluster.NodeID
	}
	if dataplane.EffectiveType(cfg.System.DataplaneType) == dataplane.TypeUserspace &&
		cfg.System.UserspaceDataplane != nil {
		userspaceWorkers = cfg.System.UserspaceDataplane.Workers
		if cfg.System.UserspaceDataplane.RSSIndirectionDisabled {
			rssEnabled = false
		}
		rssAllowed = dpuserspace.UserspaceBoundLinuxInterfaces(cfg)
	}
	return
}

// applyStartupNamingForConfig runs the startup naming policy (positional or
// device-map) for a given config, deriving the naming inputs from that config.
// It is the shared naming action used by the bootstrap-exit takeover and the
// #4179 config-arrival re-naming. It does NOT arm the dataplane or enable
// forwarding — those are the caller's concern (the config-arrival path is NOT
// bootstrap, so the dataplane was already armed at boot).
func (d *Daemon) applyStartupNamingForConfig(cfg *config.Config) error {
	if d.opts.NoDataplane {
		return nil
	}
	nodeID, clusterMode, userspaceWorkers, rssEnabled, rssAllowed := namingParamsFromConfig(cfg)
	return applyStartupNamingPolicy(cfg, nodeID, clusterMode, userspaceWorkers,
		rssEnabled, rssAllowed, d.resolveProtectedInterfaces())
}

// maybeReapplyConfigArrivalNaming re-runs startup naming exactly once, when a
// config-less HA node (emptyHANamingPending, set on the #4179 HA-guard
// EMPTY-takeover boot) receives its FIRST non-empty config. That boot named the
// NICs with STANDALONE names because the nil active config carried no cluster
// stanza; the arriving config finally supplies the node's cluster identity, so
// the NICs must be renamed to em0 + ge-<fpc>-0-X (the names the config
// references) instead of stranding on standalone names until a restart.
//
// It mirrors the bootstrap-exit re-naming but WITHOUT re-arming the dataplane
// (this node is NOT in bootstrap mode — the dataplane was armed at boot). The
// caller places it BEFORE the reconcile so the config is wired onto the
// correctly-named links. The config-less node forwards no real traffic yet
// (empty config at boot), so the mid-apply rename is safe. Returns true if
// naming was re-run AND succeeded (the one-shot flag was consumed). An empty
// config does NOT consume the flag — naming waits for the real cluster config.
//
// The flag is consumed only on SUCCESS: if applyStartupNamingForConfig errors
// (a transient NIC enumeration / netlink failure), the flag STAYS SET so the
// next config apply retries. Otherwise a single transient error would strand
// the config-less HA node on standalone names forever. The retry is bounded to
// once per config apply (a commit / SyncApply, not a hot loop); a persistently
// failing enumeration re-attempts on each commit, which is acceptable and
// logged. Both call sites run under d.applySem, so applies are serialized and
// the success path cannot double-run.
func (d *Daemon) maybeReapplyConfigArrivalNaming(cfg *config.Config) bool {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return false
	}
	if !d.emptyHANamingPending.Load() {
		return false
	}
	_, clusterMode, _, _, _ := namingParamsFromConfig(cfg)
	slog.Info("config-arrival interface naming: a config-less HA node received its first "+
		"non-empty config; re-running startup naming with the config's cluster identity",
		"cluster_mode", clusterMode)
	if err := d.applyStartupNamingForConfig(cfg); err != nil {
		// Leave the flag SET so the next config apply retries — a transient
		// enumeration/netlink error must not permanently strand this node on
		// standalone names.
		slog.Warn("config-arrival interface naming failed; will retry on the next config apply",
			"err", err)
		return false
	}
	// Consume the one-shot flag only now that naming succeeded.
	d.emptyHANamingPending.Store(false)
	return true
}

// runBootstrapExitStartup performs the one-time startup TAKEOVER steps that
// bootstrap mode suppressed at boot — interface rename, IP forwarding, and
// dataplane arm — when the daemon leaves bootstrap on its first non-empty
// config apply (#1922 Item 2). It runs under d.applySem (the apply caller
// holds it) and strictly BEFORE the reconcile that wires the config onto
// these subsystems. It mirrors the boot block in Run; bootstrap exit is
// one-way, so this runs at most once.
func (d *Daemon) runBootstrapExitStartup(cfg *config.Config) {
	if d.opts.NoDataplane {
		return
	}

	nodeID, _, _, _, _ := namingParamsFromConfig(cfg)

	// Full rename loop — the lifeline-gated path only renamed fxp0 (or
	// nothing). Now claim the NICs per the active naming policy.
	//
	// #1956 R-4: bootstrap-exit (the FIRST real commit) is exactly when a
	// device-map first appears, so this site must branch too — otherwise
	// day-0 bare metal claims every NIC positionally before the map ever
	// applies.
	if err := d.applyStartupNamingForConfig(cfg); err != nil {
		slog.Warn("bootstrap exit: interface naming failed", "err", err)
	}

	// Enable IP forwarding (suppressed in bootstrap).
	enableForwarding()

	// Arm the dataplane (AF_XDP attach) — the backend object was
	// constructed at boot (C1) but never started in bootstrap mode.
	if d.dp != nil {
		if err := d.dp.Start(d.daemonCtx); err != nil {
			slog.Warn("bootstrap exit: failed to start dataplane, running in config-only mode",
				"err", err)
			d.dp = nil
		} else {
			if seeder, ok := d.dp.(natSeeder); ok {
				seeder.SeedNATPortCounters()
				seeder.SeedSessionIDCounter(nodeID)
			}
			// #2114: start the NAT pool-alarm monitor now that the dataplane
			// is armed and d.dp is stable. It was suppressed at boot in
			// bootstrap mode; exitBootstrapMode already flipped
			// bootstrapMode=false in applyConfigLocked before calling this,
			// so maybeStartNATPoolAlarm's !inBootstrap() gate passes. Runs
			// under the apply caller's d.applySem, so the monitor's first
			// sampler read cannot overlap a concurrent d.dp write. Idempotent.
			d.maybeStartNATPoolAlarm()
		}
	}
	slog.Info("bootstrap exit: startup takeover complete; applying first config")
}
