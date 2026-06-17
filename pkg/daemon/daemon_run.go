// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/api"
	"github.com/psaab/xpf/pkg/cli"
	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/dhcprelay"
	"github.com/psaab/xpf/pkg/dhcpserver"
	"github.com/psaab/xpf/pkg/eventengine"
	"github.com/psaab/xpf/pkg/feeds"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/fwdstatus"
	"github.com/psaab/xpf/pkg/grpcapi"
	"github.com/psaab/xpf/pkg/ipmon"
	"github.com/psaab/xpf/pkg/ipsec"
	"github.com/psaab/xpf/pkg/lldp"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/ra"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/psaab/xpf/pkg/rpm"
	"github.com/psaab/xpf/pkg/snmp"
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

// riMemberLinuxName converts a routing-instance `interface` list entry
// (Junos name, e.g. "gr-0/0/0.0") to the Linux interface name the
// daemon_apply step-0a bind loop targets. SHARED between step 0a and
// the RIListMember scan in collectAppliedTunnels (#1884): the tunnel
// manager's unbind-veto/observation logic must mirror exactly what 0a
// binds — both callers MUST pass a tunMap built from the SAME cfg via
// cfg.TunnelNameMap().
//
// Tunnel refs resolve through tunMap (#1904): TunnelNameMap returns
// the compiler-assigned TunnelConfig.Name verbatim — the same field
// ApplyTunnels uses to create the kernel device — so a unit>0 member
// like gr-0/0/0.1 binds the real per-unit "uN" device gr-0-0-0u1
// (pkg/config/compiler_interfaces.go) and cannot diverge from the
// device-naming scheme by construction. Non-tunnel refs keep the
// literal pre-#1904 transform (LinuxIfName + unit-0 collapse)
// byte-identically; widening to the full cfg.ResolveKernelIfName
// (reth → physical member, st0.N verbatim, irb → bridge) would
// silently activate binds 0a has never performed and needs its own
// ratification.
func riMemberLinuxName(tunMap map[string]string, ifaceName string) string {
	if name, ok := tunMap[ifaceName]; ok && name != "" {
		return name
	}
	// Convert Junos name (gr-0/0/0.0) to Linux name (gr-0-0-0).
	// Strip ".0" unit suffix — unit 0 is the base interface.
	linuxName := config.LinuxIfName(ifaceName)
	if strings.HasSuffix(linuxName, ".0") {
		linuxName = strings.TrimSuffix(linuxName, ".0")
	}
	return linuxName
}

func collectAppliedTunnels(cfg *config.Config) []*config.TunnelConfig {
	if cfg == nil {
		return nil
	}
	anchorOnly := dataplane.EffectiveType(cfg.System.DataplaneType) == dataplane.TypeUserspace
	// Linux interface name -> routing-instance whose `interface` list
	// names it, mirroring the step-0a bind loop (forwarding instances
	// skipped; shared normalization; later entries overwrite, matching
	// 0a's last-bind-wins iteration). Feeds TunnelConfig.RIListMember.
	riListMember := map[string]string{}
	tunMap := cfg.TunnelNameMap()
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.InstanceType == "forwarding" {
			continue
		}
		for _, ifaceName := range ri.Interfaces {
			riListMember[riMemberLinuxName(tunMap, ifaceName)] = ri.Name
		}
	}
	var tunnels []*config.TunnelConfig
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		// WireGuard tunnels carry no GRE-style local `source` (the peer
		// lives in WgEndpoint; the local side is just a listen port), so
		// the Source!="" gate that screens half-configured GRE/IPIP
		// stanzas must not drop them. Found live in #1736 S2b: without
		// this, `interfaces wgN tunnel mode wireguard` compiled and fed
		// the dataplane snapshot, but applyWireguardTunLocked never ran,
		// so the persistent wgN TUN was never created and the Rust
		// control thread's open_tun failed. The dataplane side already
		// special-cases the missing source
		// (pkg/dataplane/userspace/tunnels.go); this is the routing-side
		// twin.
		if ifc.Tunnel != nil && (ifc.Tunnel.Source != "" || ifc.Tunnel.Mode == "wireguard") {
			tc := *ifc.Tunnel
			tc.AnchorOnly = anchorOnly
			tc.MTU = ifc.MTU
			tc.RIListMember = riListMember[tc.Name]
			tunnels = append(tunnels, &tc)
		}
		for _, unit := range ifc.Units {
			if unit == nil || unit.Tunnel == nil {
				continue
			}
			tc := *unit.Tunnel
			tc.AnchorOnly = anchorOnly
			// Unit-level MTU overrides interface-level, mirroring the
			// compiler_iface precedence (#1884).
			tc.MTU = ifc.MTU
			if unit.MTU > 0 {
				tc.MTU = unit.MTU
			}
			tc.RIListMember = riListMember[tc.Name]
			tunnels = append(tunnels, &tc)
		}
	}
	return tunnels
}

// Run starts the daemon and blocks until shutdown.
func (d *Daemon) Run(ctx context.Context) error {
	d.daemonCtx = ctx
	d.startPolicySchedulerLoopLocked()

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
	if err := d.store.Load(); err != nil {
		if errors.Is(err, configstore.ErrConfigDBUnreadable) {
			// Point recovery at the actual unreadable artifact — the config
			// DB under .configdb/, NOT the text config file (Copilot).
			dbPath := filepath.Join(filepath.Dir(d.opts.ConfigFile), ".configdb", "active.json")
			return fmt.Errorf("config DB is present but unreadable; refusing to "+
				"start and overwrite it (fail closed). Inspect/repair %s (the on-disk "+
				"config DB, NOT the text config file) or roll the xpf binary forward "+
				"to a build that can read it: %w",
				dbPath, err)
		}
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

	// #1922 Item 2: the five-case boot predicate, computed ONCE here after
	// Load + bootstrapFromFile have resolved. Case 4 (corrupt/too-new DB)
	// already exited fatally above (#1917 D1). The remaining cases select
	// bootstrap vs normal. Bootstrap mode suppresses interface/dataplane
	// TAKEOVER actions (but not the management control surfaces or manager
	// construction — C1). Every existing deployment resolves NOT-bootstrap
	// (case 2/3, or case 5 committed-empty) → zero behavior change.
	nodeIDPresent := hasNodeIDFile()
	bootClass := computeBootClass(d.store.ActiveConfig() != nil, d.store.EverCommitted(), nodeIDPresent)
	if bootClass == bootClassBootstrap {
		d.bootstrapMode.Store(true)
		slog.Warn("xpf daemon entering BOOTSTRAP mode: no committed configuration found",
			"detail", "management control plane (gRPC/REST/CLI) runs normally, but interface "+
				"rename/takeover, dataplane arm, and FRR/VRRP takeover are SUPPRESSED until the "+
				"first 'commit confirmed' (+ confirm) or cluster config sync. This keeps a "+
				"foreign/non-appliance host reachable on its existing management NIC.")
	} else if nodeIDPresent && d.store.ActiveConfig() == nil {
		// HA-node guard (C2/C8): node-id present but NEITHER a DB nor an
		// importable xpf.conf. Resolved to NOT-bootstrap so takeover is not
		// silently suppressed on a normal deploy, but HA availability is NOT
		// promised — this is an operator misconfiguration. Log loudly.
		slog.Error("xpf HA node has /etc/xpf/node-id but no committed config and no importable "+
			"xpf.conf; proceeding with EMPTY config takeover (NOT bootstrap mode). HA availability "+
			"is NOT promised in this state — push the cluster config and commit",
			"node_id_file", nodeIDFile)
	}

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
			if err := enumerateAndRenameInterfaces(nodeID, clusterMode, userspaceWorkers, rssEnabled, rssAllowed); err != nil {
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
		d.ipsec = ipsec.New()
		d.ra = ra.New()
		d.networkd = networkd.New()
		d.dhcpServer = dhcpserver.New()
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
		d.cluster.UpdateConfig(cc)
		d.cluster.Start(ctx)
		// Wire event-drop callback: on dropped cluster events, trigger
		// immediate reconciliation so the safety net doesn't wait 2s.
		d.cluster.SetOnEventDrop(d.triggerReconcile)
		slog.Info("cluster manager initialized",
			"node", cc.NodeID, "cluster", cc.ClusterID)

		// Watch cluster events for state transitions (primary/secondary).
		go d.watchClusterEvents(ctx)

		// #1930 INC-2: bounded local self-recovery for the LANE-1 HA kernel
		// channel — auto-rejoin if an external kernel-roll orchestrator crashed
		// while this node was drained+rebooting (no-op unless orphaned-drained).
		d.startKernelSelfRecovery(ctx)
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
				if err := d.dp.Start(ctx); err != nil {
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
	d.eventBuf = eventBuf

	// WaitGroup for coordinated shutdown of background goroutines
	var wg sync.WaitGroup

	// NOTE: session sync dp wiring + sweep start moved into startClusterComms
	// goroutine to avoid race: d.sessionSync is created asynchronously.

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
						if val, err := d.dp.Sessions().GetV6(key); err == nil && val.IsReverse == 0 {
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
						if val, err := d.dp.Sessions().GetV4(key); err == nil && val.IsReverse == 0 {
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
		if er == nil {
			if _, ok := d.dp.(userspaceEventStreamProvider); ok {
				er = logging.NewEventReader(nil, eventBuf)
				d.eventReader = er
				if cfg := d.store.ActiveConfig(); cfg != nil {
					d.applySyslogConfig(er, cfg)
					d.startFlowExporter(ctx, cfg, er)
					d.startIPFIXExporter(ctx, cfg, er)
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

	// RPM probes are started by the hash-gated reconcileRPM step inside
	// the startup applyConfig above (#1827); this safety net covers the
	// no-dataplane path where the startup apply may have run before
	// d.daemonCtx-dependent wiring settled.
	if cfg := d.store.ActiveConfig(); cfg != nil {
		d.reconcileRPM(cfg)
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
		// #846: route through commitAndApply so the engine's commit
		// serializes with HTTP/gRPC commits under d.applySem.
		// Event-options changes don't sync to peer (the engine fires
		// independently on each node based on local RPM events).
		d.eventEngine = eventengine.New(d.store, func(ctx context.Context, comment string) (*config.Config, error) {
			return d.commitAndApply(ctx, comment, false)
		})
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
		// d.dp asserted against the local apiDataPlane probe
		// (runtime_probes.go) — structurally identical to pkg/api's
		// package-private apiRuntimeDataPlane. Go duck-types the
		// assignment to api.Config.DP at this site; signature drift
		// surfaces as a compile error here.
		var apiDP apiDataPlane
		if d.dp != nil {
			if probe, ok := d.dp.(apiDataPlane); ok {
				apiDP = probe
			}
		}
		apiCfg := api.Config{
			Addr:     d.opts.APIAddr,
			Store:    d.store,
			DP:       apiDP,
			EventBuf: eventBuf,
			GC:       d.gc,
			Routing:  d.routing,
			FRR:      d.frr,
			IPsec:    d.ipsec,
			DHCP:     d.dhcp,
			VRRPMgr:  d.vrrpMgr,
			// HTTP commits don't sync to peer (preserves prior
			// behavior; see #846 for follow-up).
			CommitFn: func(ctx context.Context, comment string) (*config.Config, error) {
				return d.commitAndApply(ctx, comment, false)
			},
			CommitConfirmedFn: func(ctx context.Context, minutes int) (*config.Config, error) {
				return d.commitConfirmedAndApply(ctx, minutes, false)
			},
			// #758: surface compile state so /health returns 503
			// when the dataplane has never compiled successfully.
			CompileHealthFn: func() api.CompileHealthSnapshot {
				h := d.CompileHealthSnapshot()
				return api.CompileHealthSnapshot{
					EverSucceeded:    h.EverSucceeded,
					FailureCount:     h.FailureCount,
					LastError:        h.LastError,
					LastErrorUnixSec: h.LastErrorUnixSec,
				}
			},
			// #1780 Path A: expose the per-phase age of the Go periodic
			// neighbor-maintenance loop so a wedged guarded goroutine
			// (stuck netlink/probe syscall) is observable as a climbing
			// gauge before it manifests as the cold-connect hang.
			NeighborPhaseAgeFn: d.NeighborPeriodicPhaseAges,
			// #1880: 1 while the last applied FRR reload fell back to
			// the additive vtysh -f path (stale-config removal deferred
			// to the in-manager retry loop).
			FRRReloadDegradedFn: func() bool {
				if d.frr == nil {
					return false
				}
				return d.frr.ReloadDegraded()
			},
			// #1827: ip-monitoring policy state for the xpf_ipmon_*
			// metric family.
			IPMonStatusFn: func() []ipmon.PolicyStatus {
				if d.ipmon != nil {
					return d.ipmon.Status()
				}
				return nil
			},
			// #1895: currently-failed RPM probe-pin installs (tests
			// holding state on ErrProbeSetup instead of probing the
			// default path).
			RPMPinFailedFn: func() float64 {
				if d.rpm != nil {
					return float64(d.rpm.PinInstallFailureCount())
				}
				return 0
			},
			// #1799: surface configstore persist-degraded state so
			// /health returns 503 (and xpf_daemon_config_persist_degraded
			// reads 1) while the running active config is not durable on
			// disk (failed HA sync / auto-rollback persist, retry pending).
			ConfigPersistDegradedFn: d.store.ConfigPersistDegraded,
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

	// #881: forwarding-daemon CPU sampler (5s/1m/5m windows for
	// `show chassis forwarding`).  Shared between the gRPC server
	// and the local CLI; both paths call Snapshot() at query time.
	// Started here so the ring is populated before the first CLI.
	fwdSampler := fwdstatus.NewSampler(d.forwardingStatusDataplane(), fwdstatus.OSProcReader{})
	fwdSampler.Start(ctx)

	// Start gRPC API server.
	{
		// d.dp asserted against the local grpcDataPlane probe
		// (runtime_probes.go) — structurally identical to
		// pkg/grpcapi's package-private grpcRuntime
		// (pkg/grpcapi/runtime.go, #1516/#1554). Go duck-types the
		// assignment to grpcapi.Config.DP at this site; signature
		// drift surfaces as a compile error here.
		var grpcDP grpcDataPlane
		if d.dp != nil {
			if probe, ok := d.dp.(grpcDataPlane); ok {
				grpcDP = probe
			}
		}
		grpcSrv := grpcapi.NewServer(d.opts.GRPCAddr, grpcapi.Config{
			Store:      d.store,
			DP:         grpcDP,
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
			IPMonStatusFn: func() []ipmon.PolicyStatus {
				if d.ipmon != nil {
					return d.ipmon.Status()
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
			// gRPC commits sync to cluster peer atomically inside
			// the apply lock so the peer can never observe an apply
			// that hasn't yet been propagated.
			CommitFn: func(ctx context.Context, comment string) (*config.Config, error) {
				return d.commitAndApply(ctx, comment, true)
			},
			CommitConfirmedFn: func(ctx context.Context, minutes int) (*config.Config, error) {
				return d.commitConfirmedAndApply(ctx, minutes, true)
			},
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
			FwdSampler: fwdSampler,
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
		shell.SetCommitFns(
			func(ctx context.Context, comment string) (*config.Config, error) {
				// In-process CLI commits don't sync to peer (the
				// CLI is local; preserves prior per-transport
				// behavior, same as HTTP).
				return d.commitAndApply(ctx, comment, false)
			},
			func(ctx context.Context, minutes int) (*config.Config, error) {
				return d.commitConfirmedAndApply(ctx, minutes, false)
			},
		)
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

	// Stop the ip-monitoring engine (after RPM so no transitions
	// arrive during teardown).
	if d.ipmon != nil {
		d.ipmon.Stop()
	}

	// Stop the FRR manager (after ipmon, whose actuator is an FRR
	// writer): cancels the degraded-retry goroutine and kills any
	// in-flight frr-reload.py process group (#1880).
	if d.frr != nil {
		d.frr.Stop()
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
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
			err := runHAShutdownUpdate(shutdownCtx, func(ctx context.Context) error {
				return d.dp.HA().SetRGActive(ctx, rg.ID, false)
			})
			if err != nil {
				slog.Warn("failed to clear rg_active on shutdown", "rg", rg.ID, "err", err)
			}
			err = runHAShutdownUpdate(shutdownCtx, func(ctx context.Context) error {
				return d.dp.HA().SetHAWatchdog(ctx, rg.ID, 0)
			})
			if err != nil {
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
		// logFinalStats now reads through the runtime Telemetry
		// domain (#1519); the dataplaneReadyProbe gate keeps the
		// "no-op when dp not loaded" contract intact for both
		// backends.
		if ready, ok := d.dp.(dataplaneReadyProbe); ok {
			logFinalStats(ready, d.dp.Telemetry())
		}
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

	// #801 B2: restore any host-scope tunables xpfd claimed to their
	// pre-xpfd values. No-op if `claim-host-tunables` was never set.
	// Runs on every shutdown (hitless + fail-closed) so stopping xpfd
	// leaves the host as xpfd found it.
	d.restoreStep0TunablesOnShutdown()

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

	clusterMode := false
	nodeID := 0
	userspaceWorkers := 0
	rssEnabled := true
	var rssAllowed []string
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

	// Full rename loop — the lifeline-gated path only renamed fxp0 (or
	// nothing). Now claim every NIC per the vSRX naming scheme.
	if err := enumerateAndRenameInterfaces(nodeID, clusterMode, userspaceWorkers, rssEnabled, rssAllowed); err != nil {
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
		} else if seeder, ok := d.dp.(natSeeder); ok {
			seeder.SeedNATPortCounters()
			seeder.SeedSessionIDCounter(nodeID)
		}
	}
	slog.Info("bootstrap exit: startup takeover complete; applying first config")
}

func inferIPv6StaticNextHopInterfaces(cfg *config.Config) map[string]map[string]string {
	type connectedPrefix struct {
		net    *net.IPNet
		ifName string
		bits   int
	}

	var connected []connectedPrefix
	connectedByLogical := make(map[string][]connectedPrefix)
	ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for ifName := range cfg.Interfaces.Interfaces {
		ifNames = append(ifNames, ifName)
	}
	sort.Strings(ifNames)
	for _, ifName := range ifNames {
		ifc := cfg.Interfaces.Interfaces[ifName]
		base := config.LinuxIfName(ifName)
		unitNums := make([]int, 0, len(ifc.Units))
		for unitNum := range ifc.Units {
			unitNums = append(unitNums, unitNum)
		}
		sort.Ints(unitNums)
		for _, unitNum := range unitNums {
			unit := ifc.Units[unitNum]
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
				prefix := connectedPrefix{
					net:    ipNet,
					ifName: logical,
					bits:   bits,
				}
				connected = append(connected, prefix)
				connectedByLogical[logical] = append(connectedByLogical[logical], prefix)
			}
		}
	}

	resolve := func(candidates []connectedPrefix, addr string) string {
		ip := net.ParseIP(addr)
		if ip == nil || ip.To4() != nil {
			return ""
		}
		bestIf := ""
		bestBits := -1
		for _, candidate := range candidates {
			if !candidate.net.Contains(ip) {
				continue
			}
			if candidate.bits > bestBits || (candidate.bits == bestBits && (bestIf == "" || candidate.ifName < bestIf)) {
				bestIf = candidate.ifName
				bestBits = candidate.bits
			}
		}
		return bestIf
	}

	collectPrefixesForInterface := func(ifName string) []connectedPrefix {
		normalized := config.LinuxIfName(ifName)
		var prefixes []connectedPrefix
		if entries, ok := connectedByLogical[normalized]; ok {
			prefixes = append(prefixes, entries...)
		}
		if !strings.Contains(normalized, ".") {
			prefixNames := make([]string, 0, len(connectedByLogical))
			for logical := range connectedByLogical {
				if strings.HasPrefix(logical, normalized+".") {
					prefixNames = append(prefixNames, logical)
				}
			}
			sort.Strings(prefixNames)
			for _, logical := range prefixNames {
				prefixes = append(prefixes, connectedByLogical[logical]...)
			}
		}
		return prefixes
	}

	resolved := make(map[string]map[string]string)
	connectedByVRF := map[string][]connectedPrefix{
		"": append([]connectedPrefix(nil), connected...),
	}
	setResolved := func(vrfName, nextHop, ifName string) {
		if ifName == "" {
			return
		}
		vrfMap, ok := resolved[vrfName]
		if !ok {
			vrfMap = make(map[string]string)
			resolved[vrfName] = vrfMap
		}
		if existing, ok := vrfMap[nextHop]; !ok || ifName < existing {
			vrfMap[nextHop] = ifName
		}
	}
	addRoutes := func(vrfName string, routes []*config.StaticRoute) {
		candidates := connectedByVRF[vrfName]
		for _, sr := range routes {
			for _, nh := range sr.NextHops {
				if nh.Interface != "" || nh.Address == "" || !strings.Contains(nh.Address, ":") {
					continue
				}
				setResolved(vrfName, nh.Address, resolve(candidates, nh.Address))
			}
		}
	}

	claimedByVRF := make(map[string]struct{})
	for _, ri := range cfg.RoutingInstances {
		vrfName := "vrf-" + ri.Name
		if ri.InstanceType == "forwarding" {
			vrfName = ""
		}
		for _, ifName := range ri.Interfaces {
			prefixes := collectPrefixesForInterface(ifName)
			if len(prefixes) == 0 {
				continue
			}
			connectedByVRF[vrfName] = append(connectedByVRF[vrfName], prefixes...)
			if vrfName != "" {
				normalized := config.LinuxIfName(ifName)
				claimedByVRF[normalized] = struct{}{}
			}
		}
	}
	if len(claimedByVRF) > 0 {
		filtered := connectedByVRF[""][:0]
		for _, prefix := range connectedByVRF[""] {
			base := prefix.ifName
			if idx := strings.IndexByte(base, '.'); idx >= 0 {
				base = base[:idx]
			}
			if _, claimed := claimedByVRF[prefix.ifName]; claimed {
				continue
			}
			if _, claimed := claimedByVRF[base]; claimed {
				continue
			}
			filtered = append(filtered, prefix)
		}
		connectedByVRF[""] = filtered
	}

	addRoutes("", cfg.RoutingOptions.StaticRoutes)
	addRoutes("", cfg.RoutingOptions.Inet6StaticRoutes)
	for _, ri := range cfg.RoutingInstances {
		vrfName := "vrf-" + ri.Name
		if ri.InstanceType == "forwarding" {
			vrfName = ""
		}
		addRoutes(vrfName, ri.StaticRoutes)
		addRoutes(vrfName, ri.Inet6StaticRoutes)
	}
	return resolved
}

func runHAShutdownUpdate(ctx context.Context, update func(context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() {
		done <- update(ctx)
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
