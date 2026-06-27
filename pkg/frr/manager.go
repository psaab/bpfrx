// Package frr generates FRR configuration and queries routing state via vtysh.
//
// The package is split across sibling files:
//   - manager.go:        Manager lifecycle + top-level types + ApplyFull
//     orchestration + writeManagedSection + reload.
//   - config_render.go:  Non-protocol config rendering (interface settings,
//     static routes, generate-routes, DHCP defaults,
//     backup-router, cluster-mode defaults, ECMP).
//   - policy_render.go:  Protocols + policy rendering (OSPF/OSPFv3/BGP/RIP/
//     ISIS, policy-options, redistribute, BFD profile
//     dedup).
//   - vtysh.go:          frrExecutor interface + realExecutor + thin raw
//     Get* shells.
//   - status_parse.go:   Parsed Get* methods + their public types +
//     parseRouteJSON / FormatRouteDetail.
package frr

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
)

const (
	// DefaultFRRConf is the main FRR config file.
	DefaultFRRConf = "/etc/frr/frr.conf"

	markerBegin = "! BEGIN BPFRX MANAGED CONFIG - do not edit this section"
	markerEnd   = "! END BPFRX MANAGED CONFIG"

	// reloadTimeout bounds EACH reload shell-out independently: the
	// primary `frr-reload.py --reload` gets its own 15s context and the
	// `vtysh -f` fallback, when taken, gets a FRESH 15s context (a
	// timed-out primary must not hand the fallback a dead context).
	// Worst case on the apply path is therefore 30s plus up to two 5s
	// WaitDelay teardown windows (≤40s). reload() runs on the apply path
	// only — the daemon's shutdown sequence never reloads FRR (#1880
	// measurement: the deploy-window reload came from `xpfd cleanup`,
	// not the unit stop), so xpfd.service's TimeoutStopSec=20 is not in
	// tension with this bound.
	reloadTimeout = 15 * time.Second

	// degradedRetrySlowDelay is the steady-state cadence of the
	// degraded-retry loop once the initial backoff rungs are exhausted
	// (and the immediate cadence when frr-pythontools is missing, where
	// fast retries cannot succeed until the package is installed).
	degradedRetrySlowDelay = 5 * time.Minute
)

// degradedRetryDelays are the initial backoff rungs of the
// degraded-retry loop (#1880); after these, degradedRetrySlowDelay
// applies forever (until convergence, supersession, or Stop).
var degradedRetryDelays = []time.Duration{
	15 * time.Second,
	30 * time.Second,
	60 * time.Second,
}

// ErrFRRReloadDegraded marks a reload that converged only via the
// ADDITIVE `vtysh -f` fallback: every desired line was (re)applied but
// stale config removal did not happen (the full frr-reload.py diff
// failed). The manager's degraded-retry loop keeps re-running the
// primary until a full diff converges; callers branch with errors.Is
// to distinguish degraded from hard failure. (#1880)
var ErrFRRReloadDegraded = errors.New("frr reload degraded: additive vtysh -f fallback applied, stale-config removal deferred")

// Manager handles FRR config generation and state queries.
type Manager struct {
	frrConf string
	// exec drives every vtysh / frr-reload.py shell-out. Initialized in
	// New(). Tests inject a fake. A nil exec is tolerated via the
	// executor() accessor — see executor() below.
	exec frrExecutor

	// reloadMu is the single-writer serialization point for FRR config
	// (#1880): it covers the FULL write+reload critical section in
	// ApplyFull/Clear (managed-section write, confGen bump, reload) AND
	// every degraded-retry reload. confGen increments under reloadMu on
	// every managed-section write; the retry captures it before the
	// primary reload and refuses to clear the degraded state if it
	// changed (a structural impossibility while the exec stays under
	// reloadMu — kept as a fail-safe invariant against refactors that
	// move the exec outside the lock).
	reloadMu sync.Mutex
	confGen  uint64

	// degraded is 1 while the last APPLIED reload fell back to the
	// additive vtysh -f path and the retry loop has not yet converged a
	// full diff. Exported via ReloadDegraded() for the
	// xpf_frr_reload_degraded Prometheus gauge.
	degraded atomic.Bool

	// retryMu guards the degraded-retry episode fields below. Lock
	// order: reloadMu → retryMu (retryMu is a leaf).
	retryMu      sync.Mutex
	retryEnabled bool
	retryCtx     context.Context
	retryCancel  context.CancelFunc
	retryDone    chan struct{}
	retryWG      sync.WaitGroup

	// retryDelays/retrySlow allow tests to compress the backoff; nil/0
	// means the production degradedRetryDelays/degradedRetrySlowDelay.
	retryDelays []time.Duration
	retrySlow   time.Duration

	// pytoolsWarnOnce gates the frr-pythontools-missing warning to one
	// emission per manager lifetime (sync.Once — no extra lock
	// traffic; AGY code-r1 f3).
	pytoolsWarnOnce sync.Once

	// mgrCtx is the manager lifetime: parent of every reload exec
	// context and every retry episode, so Stop() kills in-flight
	// frr-reload.py process groups and terminates the retry goroutine.
	mgrCtx    context.Context
	mgrCancel context.CancelFunc
}

// New creates a new FRR manager with the degraded-retry loop enabled
// (the daemon configuration). One-shot consumers (`xpfd cleanup`) must
// call DisableDegradedRetry; everyone constructing via New should
// arrange for Stop() at teardown.
func New() *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		frrConf:      DefaultFRRConf,
		exec:         realExecutor{},
		retryEnabled: true,
		mgrCtx:       ctx,
		mgrCancel:    cancel,
	}
}

// DisableDegradedRetry marks this manager as one-shot: a degraded
// reload outcome is reported to the caller but never schedules the
// background retry loop. Used by `xpfd cleanup`, whose process exits
// immediately after Clear(); its bounded-convergence story is the
// deploy flow itself (the new daemon's first ApplyFull full-diffs any
// residue). (#1880)
func (m *Manager) DisableDegradedRetry() {
	m.retryMu.Lock()
	m.retryEnabled = false
	m.retryMu.Unlock()
}

// ReloadDegraded reports whether the last applied FRR reload is still
// in the degraded (additive-fallback) state. Backs the
// xpf_frr_reload_degraded Prometheus gauge (0/1, no labels).
func (m *Manager) ReloadDegraded() bool {
	return m.degraded.Load()
}

// Stop cancels the manager lifetime context — killing any in-flight
// frr-reload.py process group via its derived exec context — and waits
// for the degraded-retry goroutine to exit. Wired into the daemon
// shutdown sequence; safe to call multiple times and on managers that
// never went degraded.
func (m *Manager) Stop() {
	// Disable BEFORE waiting (Codex code-r1 M1): an in-flight commit
	// reaching its degraded handling after Stop() starts must not
	// retryWG.Add a new episode behind the Wait (WaitGroup Add/Wait
	// misuse + a leaked goroutine). retryEnabled is read and Add(1)
	// happens under the same retryMu, so any ensure either completed
	// its Add before this disable or observes it and spawns nothing.
	m.retryMu.Lock()
	m.retryEnabled = false
	m.retryMu.Unlock()
	if m.mgrCancel != nil {
		m.mgrCancel()
	}
	m.retryWG.Wait()
}

// lifetimeCtx returns the manager lifetime context, tolerating
// zero-value Managers (same contract as executor()).
func (m *Manager) lifetimeCtx() context.Context {
	if m.mgrCtx != nil {
		return m.mgrCtx
	}
	return context.Background()
}

// executor returns m.exec if set, or a default realExecutor otherwise.
// This preserves the contract that `var m frr.Manager; m.ExecVtysh(...)`
// (a zero-value Manager) does not panic — useful for same-package tests
// and historical callers that constructed a literal Manager.
func (m *Manager) executor() frrExecutor {
	if m.exec == nil {
		return realExecutor{}
	}
	return m.exec
}

// InstanceConfig pairs routing config with a VRF name for per-instance generation.
//
// Two rendering modes (#1827 PR-2):
//   - VRFName != "": a `virtual-router` instance backed by a kernel VRF
//     device — statics render with a trailing `vrf <name>`.
//   - VRFName == "" with TableID > 0: an `instance-type forwarding`
//     instance — no VRF device exists; statics render with a trailing
//     `table <id>` so the kernel table matches the FBF/PBR `ip rule`
//     target and the userspace dataplane's `<ri>.inet.0` snapshot table
//     (the FRR-vs-dataplane divergence fixed in #1827 PR-2).
type InstanceConfig struct {
	// Name is the routing-instance name (without the "vrf-" prefix),
	// used by renderPreferredRoutes to resolve an overlay entry's
	// target instance. May be empty on legacy callers; lookup misses
	// fall back to the historical "vrf-<name>" rendering.
	Name string
	// VRFName is the kernel VRF device name ("vrf-<name>"), or "" for
	// forwarding instances (and, historically, the master table).
	VRFName string
	// TableID is the instance's kernel routing table; only consumed
	// when VRFName == "" (forwarding instances).
	TableID           int
	OSPF              *config.OSPFConfig
	OSPFv3            *config.OSPFv3Config
	BGP               *config.BGPConfig
	RIP               *config.RIPConfig
	ISIS              *config.ISISConfig
	StaticRoutes      []*config.StaticRoute
	Inet6StaticRoutes []*config.StaticRoute
}

// DHCPRoute represents a default route learned via DHCP.
type DHCPRoute struct {
	Gateway   string // "10.0.2.1" or "fe80::1"
	Interface string // needed for IPv6 link-local gateways
	IsIPv6    bool
}

// FullConfig holds the complete routing config for a single FRR apply.
type FullConfig struct {
	OSPF              *config.OSPFConfig
	OSPFv3            *config.OSPFv3Config
	BGP               *config.BGPConfig
	RIP               *config.RIPConfig
	ISIS              *config.ISISConfig
	StaticRoutes      []*config.StaticRoute
	Inet6StaticRoutes []*config.StaticRoute // rib inet6.0 static routes
	GenerateRoutes    []*config.GenerateRoute
	DHCPRoutes        []DHCPRoute
	Instances         []InstanceConfig
	PolicyOptions     *config.PolicyOptionsConfig

	// ForwardingTableExport is the export policy for the forwarding table (ECMP).
	ForwardingTableExport string

	// BackupRouter is the fallback default gateway (system backup-router).
	// Installed with admin distance 250 so it's only used when all other defaults fail.
	BackupRouter    string // next-hop IP (e.g. "192.168.50.1")
	BackupRouterDst string // destination prefix (e.g. "192.168.0.0/16"), default "0.0.0.0/0"

	// InterfaceBandwidths maps interface names to bandwidth in bits per second.
	// FRR emits "bandwidth <kbps>" in interface blocks (used by OSPF auto-cost).
	InterfaceBandwidths map[string]uint64

	// InterfacePointToPoint maps interface names to point-to-point flag.
	// When true and no explicit OSPF network-type is set, emits "ip ospf network point-to-point".
	InterfacePointToPoint map[string]bool

	// RethMap maps reth name → physical member name (e.g. "reth0" → "ge-0-0-1").
	// Used to translate RETH interface names in static routes to kernel names.
	RethMap map[string]string

	// IPv6NextHopInterfaces maps VRF name -> IPv6 next-hop -> interface for
	// global and per-instance static routes that omit an explicit interface.
	// Values may still be logical interface names (for example, "reth0.50");
	// any later translation to kernel/physical names is handled separately via
	// RethMap. The global table uses the empty-string VRF key.
	IPv6NextHopInterfaces map[string]map[string]string

	// ConsistentHash is set when the forwarding-table export policy uses
	// "load-balance consistent-hash". The daemon should set
	// net.ipv4.fib_multipath_hash_policy=1 for L4 ECMP hashing.
	//
	// NOTE: ApplyFull mutates this field as a side effect of resolveECMP().
	// See resolveECMP() in config_render.go.
	ConsistentHash bool

	// ClusterMode adds a blackhole default route with high admin distance
	// (250) as a safety net for active/active per-RG failover.  When the
	// WAN VIP moves to the peer, FRR withdraws the real default route
	// (next-hop unreachable).  The blackhole default makes bpf_fib_lookup
	// return BPF_FIB_LKUP_RET_BLACKHOLE instead of NOT_FWDED, triggering
	// zone-encoded fabric redirect for new connections.  The real default
	// route (AD 5 or 200) always takes priority when present.
	ClusterMode bool

	// PreferredRoutes is the ip-monitoring effective-route overlay
	// (#1827 PR-1b): winner-resolved injected routes rendered as
	// DISTANCE-1 statics (Static/1 — beats static AD 5 and DHCP AD
	// 200; that is what makes them "preferred"). Runtime state from
	// pkg/ipmon, supplied by the daemon's assembleFRRConfig for BOTH
	// the full apply path and the routes-only actuator, so an
	// unrelated operator commit can never wipe an active failover
	// route.
	PreferredRoutes []config.RouteOverlayEntry
}

// NOTE (#1827, AGY review on PR #1843 F1): the legacy Apply(ospf, bgp)
// and ApplyWithInstances(...) convenience constructors were DELETED
// here. They built a partial FullConfig inline, bypassing the daemon's
// assembleFRRConfig — the sole production FullConfig constructor — so
// any caller reaching them would have wiped an active ip-monitoring
// failover overlay (PreferredRoutes) from the managed section. They
// had zero callers (production or test) at removal time. New callers
// must go through the daemon's assembleFRRConfig; pkg/daemon's
// TestFRRFullConfigConstructedOnlyByAssembler guard enforces this.

// ApplyFull generates the complete FRR config including static routes,
// DHCP-learned defaults, per-VRF routes, and dynamic protocols, then
// reloads FRR.
//
// Emission order (preserved as a contract — many FRR parsers depend on
// it; in particular, interface bandwidth must precede OSPF so auto-cost
// picks it up):
//
//  1. global static routes
//  2. generate-routes (blackhole)
//  3. inet6 static routes
//  4. DHCP-learned defaults (admin distance 200)
//  5. backup-router (admin distance 250)
//  6. cluster-mode blackhole defaults (admin distance 250)
//  7. ip-monitoring preferred routes (admin distance 1, #1827)
//  8. per-VRF static routes
//  9. policy-options (prefix-lists, route-maps, communities)
//  10. interface settings (bandwidth, point-to-point)
//  11. global dynamic protocols (OSPF/OSPFv3/BGP/RIP/ISIS)
//  12. per-VRF dynamic protocols
func (m *Manager) ApplyFull(fc *FullConfig) error {
	if fc == nil {
		return m.Clear()
	}

	hasContent := fc.OSPF != nil || fc.OSPFv3 != nil || fc.BGP != nil || fc.RIP != nil || fc.ISIS != nil ||
		len(fc.StaticRoutes) > 0 || len(fc.Inet6StaticRoutes) > 0 || len(fc.GenerateRoutes) > 0 || len(fc.DHCPRoutes) > 0 || fc.BackupRouter != "" || fc.ClusterMode ||
		len(fc.PreferredRoutes) > 0
	for _, inst := range fc.Instances {
		if inst.OSPF != nil || inst.OSPFv3 != nil || inst.BGP != nil || inst.RIP != nil || inst.ISIS != nil || len(inst.StaticRoutes) > 0 || len(inst.Inet6StaticRoutes) > 0 {
			hasContent = true
			break
		}
	}
	if !hasContent {
		return m.Clear()
	}

	return m.commitManagedSection(m.buildManagedSection(fc))
}

// buildManagedSection renders the full xpf-managed frr.conf section for fc
// WITHOUT writing or reloading. It is the pure assembly half of ApplyFull,
// split out so the consolidated single-`bfd`-block invariant (#2550) and
// other whole-section properties can be asserted in unit tests via the
// real assemble path rather than a hand-rebuilt string. resolveECMP's
// fc.ConsistentHash side effect still happens here (ApplyFull's only
// caller invokes it before commit).
func (m *Manager) buildManagedSection(fc *FullConfig) string {
	var b strings.Builder
	b.WriteString("! xpf managed config - do not edit\n")
	b.WriteString("!\n")

	// 1. Global static routes
	if len(fc.StaticRoutes) > 0 {
		for _, sr := range fc.StaticRoutes {
			b.WriteString(m.generateStaticRoute(sr, "", fc.RethMap, fc.IPv6NextHopInterfaces))
		}
		b.WriteString("!\n")
	}

	// 2. Generate (aggregate) routes — rendered as blackhole static routes
	renderGenerateRoutes(&b, fc)

	// 3. IPv6 RIB static routes (rib inet6.0)
	if len(fc.Inet6StaticRoutes) > 0 {
		for _, sr := range fc.Inet6StaticRoutes {
			b.WriteString(m.generateStaticRoute(sr, "", fc.RethMap, fc.IPv6NextHopInterfaces))
		}
		b.WriteString("!\n")
	}

	// 4. DHCP-learned default routes (admin distance 200).
	renderDHCPDefaults(&b, fc)

	// 5. Backup router: fallback default gateway with admin distance 250
	renderBackupRouter(&b, fc)

	// 6. Cluster mode: blackhole default route as fallback for fabric redirect.
	renderClusterModeDefaults(&b, fc)

	// 7. ip-monitoring preferred routes (admin distance 1, #1827).
	m.renderPreferredRoutes(&b, fc)

	// 8. Per-VRF static routes. Forwarding instances (VRFName == "",
	// TableID > 0) render into their dedicated kernel table instead of
	// the default one (#1827 PR-2 divergence fix).
	for _, inst := range fc.Instances {
		if len(inst.StaticRoutes) > 0 || len(inst.Inet6StaticRoutes) > 0 {
			for _, sr := range inst.StaticRoutes {
				b.WriteString(m.generateStaticRouteInTable(sr, inst.VRFName, inst.TableID, fc.RethMap, fc.IPv6NextHopInterfaces))
			}
			for _, sr := range inst.Inet6StaticRoutes {
				b.WriteString(m.generateStaticRouteInTable(sr, inst.VRFName, inst.TableID, fc.RethMap, fc.IPv6NextHopInterfaces))
			}
			b.WriteString("!\n")
		}
	}

	// 9. Policy options: prefix-lists and route-maps. Collect the set of
	// policy-statements applied as a BGP route-map in/out (default instance
	// + every VRF) so a BGP policy with no explicit default action renders a
	// terminating `permit` (Junos BGP default-accept) rather than FRR's
	// implicit deny — preventing a non-matching-route blackhole (#2998).
	if fc.PolicyOptions != nil {
		bgpAcceptDefault := make(map[string]bool)
		collectBGPRouteMapPolicies(fc.BGP, fc.PolicyOptions, bgpAcceptDefault)
		for _, inst := range fc.Instances {
			collectBGPRouteMapPolicies(inst.BGP, fc.PolicyOptions, bgpAcceptDefault)
		}
		b.WriteString(m.generatePolicyOptions(fc.PolicyOptions, bgpAcceptDefault))
	}

	// Resolve forwarding-table export policy for ECMP. Sets fc.ConsistentHash
	// as a side effect when the policy uses "load-balance consistent-hash".
	ecmpMaxPaths := resolveECMP(fc)

	// 10. Interface-level settings (bandwidth, point-to-point)
	b.WriteString(m.generateInterfaceSettings(fc))

	// BFD profiles/peers are accumulated across the default instance AND
	// every VRF into ONE section, then emitted as a single top-level `bfd`
	// block after all instances render (#2550). FRR's bfdd is a single
	// global daemon, so one consolidated block replaces the per-instance
	// blocks that previously produced redundant / repeated profile defs.
	bfdSec := newBFDSection()

	// 11. Global dynamic protocols
	if fc.OSPF != nil || fc.OSPFv3 != nil || fc.BGP != nil || fc.RIP != nil || fc.ISIS != nil {
		b.WriteString(m.generateProtocols(fc.OSPF, fc.OSPFv3, fc.BGP, fc.RIP, fc.ISIS, "", ecmpMaxPaths, fc.PolicyOptions, bfdSec))
	}

	// 12. Per-VRF dynamic protocols
	for _, inst := range fc.Instances {
		if inst.OSPF != nil || inst.OSPFv3 != nil || inst.BGP != nil || inst.RIP != nil || inst.ISIS != nil {
			b.WriteString(m.generateProtocols(inst.OSPF, inst.OSPFv3, inst.BGP, inst.RIP, inst.ISIS, inst.VRFName, ecmpMaxPaths, fc.PolicyOptions, bfdSec))
		}
	}

	// 13. Single consolidated top-level BFD block (profiles + peers),
	// emitted exactly once outside any router/instance scope.
	b.WriteString(bfdSec.render())

	return b.String()
}

// commitManagedSection is the single write+reload critical section
// (#1880). It signal-cancels any pending degraded-retry episode FIRST
// (an in-flight retry's frr-reload.py process group dies within one
// WaitDelay window, so the apply waits at most ~5s behind it), then
// holds reloadMu across the managed-section write, the confGen bump,
// and the reload — preserving single-writer semantics against the
// retry goroutine.
//
// Return contract: nil = full diff convergence; ErrFRRReloadDegraded
// (errors.Is) = additive fallback applied, retry scheduled when
// enabled; other errors = nothing converged.
func (m *Manager) commitManagedSection(section string) error {
	m.signalRetryCancel()
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	// Re-arm guard (Codex code-r1 H1, runs BEFORE the unlock above by
	// LIFO order): the pre-cancel assumed this commit supersedes the
	// degraded state, but a failed write (early return below) or a
	// hard reload failure leaves degraded=true with the old episode
	// already cancelled — without this, stale-config removal would
	// never retry until the next commit or restart. ensureRetryLocked
	// is idempotent against the episode the degraded outcome itself
	// may have just scheduled.
	defer func() {
		if m.degraded.Load() {
			m.ensureRetryLocked(false)
		}
	}()

	if err := m.writeManagedSection(section); err != nil {
		return err
	}
	m.confGen++
	slog.Info("FRR config written", "path", m.frrConf, "generation", m.confGen)

	err := m.reloadLocked()
	m.noteReloadOutcomeLocked(err)
	if err != nil && !errors.Is(err, ErrFRRReloadDegraded) {
		slog.Warn("FRR reload failed", "err", err)
	}
	return err
}

// Clear removes the xpf managed section from frr.conf and reloads FRR.
// Unlike the historical version it PROPAGATES the reload outcome
// (including ErrFRRReloadDegraded) instead of discarding it — `xpfd
// cleanup` logs it loudly while still exiting 0 (#1880).
func (m *Manager) Clear() error {
	return m.commitManagedSection("")
}

// writeManagedSection replaces the xpf-managed section in frr.conf.
// If section is empty, the managed block is removed entirely.
func (m *Manager) writeManagedSection(section string) error {
	existing, err := os.ReadFile(m.frrConf)
	if err != nil {
		if os.IsNotExist(err) {
			existing = []byte("log syslog informational\n")
		} else {
			return fmt.Errorf("read frr.conf: %w", err)
		}
	}

	// Strip existing managed section.
	//
	// A correct file has a begin marker followed by an end marker. But a
	// prior torn write (os.WriteFile is not atomic — a crash or disk-full
	// mid-write can truncate after the begin marker) can leave an orphaned
	// markerBegin with no markerEnd. If we only stripped on the both-found
	// case, the orphan would survive: we would append a second managed block,
	// leaving two begin markers. The next write's strings.Index(markerEnd)
	// then matches the new block's end while content[:start] cuts from the
	// orphaned begin — deleting everything between them, which may include
	// unrelated FRR config the operator appended. So we treat a begin with no
	// end as a corrupt tail and discard it to EOF.
	//
	// The end-marker search is anchored AFTER the begin marker (#2908). A
	// stale end-marker positioned *before* the begin marker (an operator
	// hand-edit, an interleaved partial copy, or external tooling) must not
	// be matched: an unanchored strings.Index(content, markerEnd) would
	// return end < start, and the strip content[:start] + content[end:] would
	// then DUPLICATE the text between end and start while leaving the live
	// begin marker in place — corrupting the file with two begin markers and
	// breaking FRR reload. Anchoring the search keeps the end >= start
	// invariant, so the slice can never duplicate. (This is distinct from the
	// #1646 orphaned-begin case handled by the else branch below.)
	content := string(existing)
	if start := strings.Index(content, markerBegin); start >= 0 {
		// Search for the end marker strictly after the begin marker, then map
		// the relative index back to an absolute offset.
		searchFrom := start + len(markerBegin)
		if rel := strings.Index(content[searchFrom:], markerEnd); rel >= 0 {
			end := searchFrom + rel + len(markerEnd)
			// Also consume the trailing newline
			if end < len(content) && content[end] == '\n' {
				end++
			}
			content = content[:start] + content[end:]
		} else {
			// Orphaned begin marker (torn write): discard from the begin
			// marker to EOF. Whatever followed an unterminated managed block
			// is xpf-generated partial config that must not be preserved, and
			// keeping the orphan begin would cause the next write to over-cut.
			content = content[:start]
		}
	}

	// Append new managed section
	if section != "" {
		content = strings.TrimRight(content, "\n") + "\n"
		content += markerBegin + "\n"
		content += section
		content += markerEnd + "\n"
	}

	// Write atomically: a temp file in the same directory followed by rename,
	// so a crash or disk-full can never leave frr.conf half-written (which is
	// what creates the orphaned-begin-marker state handled above in the first
	// place). rename(2) within a filesystem is atomic.
	if err := atomicWriteFile(m.frrConf, []byte(content), 0644); err != nil {
		return fmt.Errorf("write frr.conf: %w", err)
	}
	return nil
}

// atomicWriteFile durably replaces path via pkg/fsatomic (#1894,
// DurableState class: frr.conf carries operator content outside the
// managed section, so losing it to a power cut is data loss — and a
// half-written file is what creates the orphaned-begin-marker state
// handled in writeManagedSection).
//
// The two options reproduce this function's pre-#1894 semantics
// verbatim (they were lifted from here, see pkg/fsatomic):
//   - WithPreserveExisting: an existing target's mode/ownership is
//     reapplied on the temp fd (fchmod/fchown before rename, no
//     path race; chown only when the owner differs, failure surfaced),
//     falling back to perm for a new file.
//   - WithResolveSymlinks: a symlinked frr.conf is resolved and
//     replaced at its target, preserving the operator's symlink.
//
// On top of the previous behavior the durable writer adds the
// parent-directory fsync that was missing here, making the rename
// itself crash-safe.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	return fsatomic.WriteFileDurable(path, data, perm,
		fsatomic.WithPreserveExisting(), fsatomic.WithResolveSymlinks())
}

// reloadLocked reloads FRR. Caller must hold reloadMu.
//
// Primary: a DIRECT bounded `frr-reload.py --reload` — never
// `systemctl reload frr`. On FRR 10.6 the unit's ExecReload restarts
// watchfrr (the Type=forking MainPID), so every systemd-mediated
// reload cancels its own job, parks frr.service in stop-sigterm for 2
// minutes, and ends with systemd SIGKILLing all FRR daemons. That
// poison window was queueing harness reboots behind the 2-minute
// timer (#1880) and meant the systemctl branch had been 100%-failing —
// every reload silently ran the additive fallback, breaking
// stale-config removal on commit.
//
// Fallback: `vtysh -f` under a FRESH 15s context (never the primary's
// possibly-dead one). The fallback is additive-convergent — desired
// lines are (re)applied, only stale removals can be missed — which the
// degraded-retry loop then converges. Fallback success returns
// ErrFRRReloadDegraded (wrapping the primary cause, so errors.Is can
// still see exec.ErrNotFound / fs ENOENT for the pythontools-missing
// classification).
func (m *Manager) reloadLocked() error {
	pctx, pcancel := context.WithTimeout(m.lifetimeCtx(), reloadTimeout)
	perr := m.executor().FrrReloadPy(pctx, m.frrConf)
	pcancel()
	if perr == nil {
		slog.Info("FRR reloaded via frr-reload.py (full diff)")
		return nil
	}
	if isFrrReloadPyMissing(perr) {
		m.warnPytoolsOnce(perr)
	} else {
		slog.Warn("frr-reload.py reload failed; falling back to additive vtysh -f", "err", perr)
	}

	fctx, fcancel := context.WithTimeout(m.lifetimeCtx(), reloadTimeout)
	defer fcancel()
	output, err := m.executor().VtyshLoad(fctx, m.frrConf)
	if err != nil {
		return fmt.Errorf("vtysh reload: %w: %s", err, string(output))
	}
	slog.Warn("FRR config loaded via additive vtysh -f (degraded: stale-config removal deferred to retry)")
	return fmt.Errorf("%w: %w", ErrFRRReloadDegraded, perr)
}

// isFrrReloadPyMissing classifies a primary-reload error as
// "frr-reload.py is not installed" (frr-pythontools absent).
// exec.CommandContext with an absolute path surfaces fs ENOENT;
// exec.ErrNotFound covers the LookPath shape for completeness.
func isFrrReloadPyMissing(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, exec.ErrNotFound)
}

// warnPytoolsOnce logs the frr-pythontools-missing warning once per
// manager lifetime (the degraded retry would otherwise repeat it every
// 5 minutes forever).
func (m *Manager) warnPytoolsOnce(err error) {
	m.pytoolsWarnOnce.Do(func() {
		slog.Warn("frr-pythontools not installed — FRR reload degraded to additive vtysh -f until it is",
			"script", frrReloadScript, "err", err)
	})
}

// noteReloadOutcomeLocked updates the degraded state machine after a
// reload. Caller must hold reloadMu.
//
//   - nil: full diff converged — clear the gauge and signal-cancel any
//     pending retry episode (AGY r3 f2: a woken redundant retry must
//     exit without exec'ing, so its own transient failure can never
//     spuriously re-set the gauge).
//   - ErrFRRReloadDegraded: set the gauge and ensure a retry episode
//     (when enabled). A pythontools-missing cause starts the retry at
//     the slow cadence directly.
//   - other errors: nothing was applied at all; the gauge keeps
//     reflecting the last APPLIED reload and the error propagates to
//     the caller (warn-and-continue at commit, loud log at cleanup).
func (m *Manager) noteReloadOutcomeLocked(err error) {
	switch {
	case err == nil:
		m.degraded.Store(false)
		m.signalRetryCancel()
	case errors.Is(err, ErrFRRReloadDegraded):
		m.degraded.Store(true)
		m.ensureRetryLocked(isFrrReloadPyMissing(err))
	}
}

// signalRetryCancel cancels the current retry episode WITHOUT waiting
// for the goroutine to exit (it may be blocked on reloadMu, which the
// caller can hold — waiting here would deadlock). The cancelled
// goroutine self-cleans its episode fields and is reaped by retryWG at
// Stop(). Idempotent.
func (m *Manager) signalRetryCancel() {
	m.retryMu.Lock()
	cancel := m.retryCancel
	m.retryMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// ensureRetryLocked spawns the single-flight degraded-retry episode if
// none is live. Caller must hold reloadMu (lock order reloadMu →
// retryMu). slowStart skips the fast backoff rungs (pythontools
// missing — fast retries cannot succeed).
func (m *Manager) ensureRetryLocked(slowStart bool) {
	m.retryMu.Lock()
	defer m.retryMu.Unlock()
	if !m.retryEnabled {
		return
	}
	// No manager lifetime context (zero-value / legacy literal
	// Managers) means no Stop() can ever cancel or reap an episode —
	// never spawn one (AGY code-r1 f2). Only New() managers, which own
	// mgrCtx/mgrCancel, run the background retry.
	if m.mgrCtx == nil {
		return
	}
	// A live (non-cancelled) episode already covers us. A
	// cancelled-but-draining episode does not — spawn a fresh one; the
	// drainer's self-clean is identity-guarded so it cannot clobber the
	// new episode's fields.
	if m.retryDone != nil && m.retryCtx != nil && m.retryCtx.Err() == nil {
		return
	}
	ctx, cancel := context.WithCancel(m.lifetimeCtx())
	done := make(chan struct{})
	m.retryCtx, m.retryCancel, m.retryDone = ctx, cancel, done
	start := 0
	if slowStart {
		start = len(m.retryDelaysOrDefault())
	}
	m.retryWG.Add(1)
	go func() {
		defer m.retryWG.Done()
		m.degradedRetryLoop(ctx, done, start)
	}()
}

func (m *Manager) retryDelaysOrDefault() []time.Duration {
	if m.retryDelays != nil {
		return m.retryDelays
	}
	return degradedRetryDelays
}

func (m *Manager) retrySlowOrDefault() time.Duration {
	if m.retrySlow > 0 {
		return m.retrySlow
	}
	return degradedRetrySlowDelay
}

// degradedRetryLoop re-runs the PRIMARY reload (no nested fallback)
// until a full diff converges, the episode is superseded/cancelled, or
// the manager stops. frr.conf on disk is the SSOT: every attempt
// reloads the file as it stands, so a newer ApplyFull/Clear supersedes
// automatically.
func (m *Manager) degradedRetryLoop(ctx context.Context, myDone chan struct{}, attempt int) {
	defer close(myDone)
	defer m.clearEpisodeIfMine(myDone)
	delays := m.retryDelaysOrDefault()
	for {
		var d time.Duration
		if attempt < len(delays) {
			d = delays[attempt]
		} else {
			d = m.retrySlowOrDefault()
		}
		timer := time.NewTimer(d)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		stop, notFound := m.retryReloadOnce(ctx)
		if stop {
			return
		}
		if notFound {
			attempt = len(delays) // jump to the slow cadence
		} else {
			attempt++
		}
	}
}

// retryReloadOnce performs one degraded-retry attempt under reloadMu.
// Returns stop=true when the episode is finished (converged, cancelled,
// or superseded by an apply that already cleared the degraded state).
func (m *Manager) retryReloadOnce(ctx context.Context) (stop, notFound bool) {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	// Both checks run INSIDE the critical section: a commit that
	// cancelled/converged while we were waiting for reloadMu must win
	// (no TOCTOU between gauge state and exec).
	if ctx.Err() != nil {
		return true, false
	}
	if !m.degraded.Load() {
		return true, false
	}
	gen := m.confGen
	rctx, rcancel := context.WithTimeout(ctx, reloadTimeout)
	defer rcancel()
	if err := m.executor().FrrReloadPy(rctx, m.frrConf); err != nil {
		nf := isFrrReloadPyMissing(err)
		if nf {
			m.warnPytoolsOnce(err)
		} else {
			slog.Warn("FRR degraded-retry reload failed", "err", err)
		}
		return false, nf
	}
	if m.confGen != gen {
		// Invariant assertion (#1880 plan r4): confGen cannot change
		// while reloadMu is held — writes bump it under the same mutex.
		// Kept so a refactor that moves the exec outside the lock fails
		// SAFE: a stale success must never clear the degraded state.
		slog.Warn("FRR degraded-retry succeeded against a stale generation; retrying",
			"have", gen, "latest", m.confGen)
		return false, false
	}
	m.degraded.Store(false)
	slog.Info("FRR reload converged after degraded fallback", "generation", gen)
	return true, false
}

// clearEpisodeIfMine nils the episode fields iff they still belong to
// this goroutine (identity via the done channel) — a drainer from a
// superseded episode must not clobber its successor's fields.
func (m *Manager) clearEpisodeIfMine(myDone chan struct{}) {
	m.retryMu.Lock()
	defer m.retryMu.Unlock()
	if m.retryDone == myDone {
		if m.retryCancel != nil {
			m.retryCancel() // release the ctx's resources
		}
		m.retryCtx, m.retryCancel, m.retryDone = nil, nil, nil
	}
}
