package userspace

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"net/netip"

	"github.com/psaab/bpfrx/pkg/config"
	"github.com/psaab/bpfrx/pkg/dataplane"
	bpfrxnft "github.com/psaab/bpfrx/pkg/nftables"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var _ dataplane.DataPlane = (*Manager)(nil)

// DataplaneMode describes which packet-processing pipeline is active.
type DataplaneMode int

const (
	ModeEBPFOnly        DataplaneMode = iota // Pure eBPF pipeline, no userspace
	ModeUserspaceCompat                      // Userspace preferred, eBPF/kernel fallback allowed
	ModeUserspaceStrict                      // Strict userspace only, no transit fallback
)

func (m DataplaneMode) String() string {
	switch m {
	case ModeEBPFOnly:
		return "ebpf_only"
	case ModeUserspaceCompat:
		return "userspace_compat"
	case ModeUserspaceStrict:
		return "userspace_strict"
	default:
		return "unknown"
	}
}

func init() {
	dataplane.RegisterBackend(dataplane.TypeUserspace, func() dataplane.DataPlane {
		return New()
	})
}

type Manager struct {
	dataplane.DataPlane
	inner *dataplane.Manager

	mu                 sync.Mutex
	sessionMu          sync.Mutex // separate lock for session sync requests (Phase 3)
	proc               *exec.Cmd
	cfg                config.UserspaceConfig
	clusterHA          bool
	generation         uint64
	syncCancel         context.CancelFunc
	lastStatus         ProcessStatus
	lastSnapshot       *ConfigSnapshot
	haGroups           map[int]HAGroupStatus
	lastIngressIfaces  []uint32
	lastRSTv4          []netip.Addr
	lastRSTv6          []netip.Addr
	lastSnapshotHash   [32]byte // content hash of last published snapshot (excludes volatile fields)
	lastBindingIndices []uint32
	neighborsPrewarmed bool
	ctrlEnableAt       time.Time
	ctrlWasEnabled     bool
	ctrlDisabledAt     uint64    // monotonic ktime_ns when ctrl was last disabled
	lastDemotionTime   time.Time // wall clock when last RG demotion occurred
	xskLivenessFailed  bool
	xskLivenessProven  bool
	xskProbeStart      time.Time
	lastXSKRX          uint64
	lastNAPIBootstrap  time.Time
	publishedSnapshot  uint64
	publishedPlanKey   string
	deferWorkers       bool // skip worker spawn until NotifyLinkCycle
	xskBoundNotified   bool // OnXSKBound fired at most once

	mode               DataplaneMode // current active runtime mode
	configuredMode     DataplaneMode // user-configured desired mode (from config)
	lastHASyncTime     time.Time     // throttle HA watchdog sync to avoid control socket contention
	lastRGActivateTime time.Time     // wall clock of last update_ha_state; statusLoop skips HA sync for 2s

	rgTransitionInFlight atomic.Bool // set before syncHAStateLocked, cleared on completion

	// Counter delta tracking: previous binding counter totals for computing
	// deltas to write into BPF counter maps (#332).
	prevBindingCounters userspaceCounterSnapshot

	eventStream       *EventStream
	eventStreamCancel context.CancelFunc

	// OnXSKBound is called once when all XSK bindings are bound.
	// Used by the daemon to defer IPVLAN creation until after XSK
	// binds in zerocopy mode on fabric parents.
	OnXSKBound func()
}

func New() *Manager {
	inner := dataplane.New()
	inner.XDPEntryProg = "xdp_main_prog"
	return &Manager{
		DataPlane:      inner,
		inner:          inner,
		configuredMode: ModeUserspaceCompat,
		haGroups:       make(map[int]HAGroupStatus),
	}
}

// EventStream returns the event stream instance, or nil if not available.
func (m *Manager) EventStream() *EventStream {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.eventStream
}

// XSKBoundNotified reports whether the OnXSKBound callback has already fired.
// The daemon uses this to distinguish first applyConfig (defer IPVLAN) from
// subsequent calls (reconcile normally).
func (m *Manager) XSKBoundNotified() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.xskBoundNotified
}

// Mode returns the current active dataplane runtime mode.
func (m *Manager) Mode() DataplaneMode {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mode
}

// SetConfiguredMode sets the user-configured desired dataplane mode.
// The active mode is computed in applyHelperStatusLocked based on runtime
// state and may differ from the configured mode.
func (m *Manager) SetConfiguredMode(mode DataplaneMode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.configuredMode = mode
}

func (m *Manager) SessionSyncSweepProfile() (bool, time.Duration, time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil {
		return false, 0, 0
	}
	if !m.lastStatus.Enabled || !m.lastStatus.ForwardingArmed || !m.lastStatus.Capabilities.ForwardingSupported {
		return false, 0, 0
	}
	// Userspace forwarding already streams authoritative open/close deltas.
	// Keep a periodic refresh for long-lived flows, but avoid the 1s batch walk
	// that was tuned for the eBPF session tables.
	return true, 15 * time.Second, 60 * time.Second
}

func (m *Manager) Load() error {
	return m.inner.Load()
}

func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
	return m.inner.Close()
}

func (m *Manager) Teardown() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
	return m.inner.Teardown()
}

// SetDeferWorkers tells the manager to skip worker startup during the next
// Compile(). Workers will be started on the first NotifyLinkCycle() instead.
// Use this when RETH MAC programming will follow Compile() — avoids the
// double-bind that causes EBUSY on mlx5 zero-copy queues.
func (m *Manager) SetDeferWorkers(v bool) {
	m.mu.Lock()
	m.deferWorkers = v
	m.mu.Unlock()
}

func (m *Manager) Compile(cfg *config.Config) (*dataplane.CompileResult, error) {
	// Delete XDP link pins BEFORE inner.Compile() so AttachXDP does
	// a fresh attach. This is critical for zero-copy: fresh attach
	// triggers mlx5 to initialize XSK buffer pool from fill ring.
	// Pinned link reuse (l.Update) only swaps the program without
	// reinitializing XSK RQs, leaving the fill ring unconsumed.
	if linkPinDir := "/sys/fs/bpf/bpfrx/links"; true {
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
	// Use the shim when forwarding is supported. The shim redirects to
	// XSK when ctrl=1; when ctrl=0 it falls through to XDP_PASS which
	// delivers to the kernel at the same throughput as xdp_main_prog.
	// XSK socket creation is deferred by the arm delay (45s) to avoid
	// segfaults from __xsk_setup_xdp_prog during link cycles.
	if m.xskLivenessFailed {
		m.inner.XDPEntryProg = "xdp_main_prog"
	} else if caps.ForwardingSupported {
		m.inner.XDPEntryProg = "xdp_userspace_prog"
	} else {
		m.inner.XDPEntryProg = "xdp_main_prog"
	}
	result, err := m.inner.Compile(cfg)
	if err != nil {
		return nil, err
	}
	ucfg := deriveUserspaceConfig(cfg)
	snap := buildSnapshot(cfg, ucfg, m.bumpGeneration(), m.readFIBGeneration())
	m.syncInterfaceAttachments(result, snap)

	m.mu.Lock()
	defer m.mu.Unlock()
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
	m.lastSnapshot = snap
	if pendingXSKStartup {
		if err := m.syncIngressIfaceMapLocked(snap); err != nil {
			return result, err
		}
		if err := m.syncLocalAddressMapsLocked(snap); err != nil {
			return result, err
		}
		if err := m.syncInterfaceNATAddressMapsLocked(snap); err != nil {
			return result, err
		}
		m.cfg = ucfg
		slog.Info(
			"userspace: deferring snapshot publish during XSK startup",
			"generation", snap.Generation,
			"fib_generation", snap.FIBGeneration,
			"same_plan", samePlanRefresh,
		)
		return result, nil
	}
	if samePlanRefresh {
		if err := m.syncIngressIfaceMapLocked(snap); err != nil {
			return result, err
		}
		if err := m.syncLocalAddressMapsLocked(snap); err != nil {
			return result, err
		}
		if err := m.syncInterfaceNATAddressMapsLocked(snap); err != nil {
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
	if m.deferWorkers {
		snap.DeferWorkers = true
	}
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "apply_snapshot", Snapshot: snap}, &status); err != nil {
		return result, fmt.Errorf("publish userspace snapshot: %w", err)
	}
	m.publishedSnapshot = snap.Generation
	m.publishedPlanKey = newPlanKey
	if h, ok := snapshotContentHash(snap); ok {
		m.lastSnapshotHash = h
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		return result, fmt.Errorf("sync helper status: %w", err)
	}
	if err := m.refreshHAStateFromMapsLocked(); err != nil {
		return result, fmt.Errorf("replay userspace HA state from maps: %w", err)
	}
	if err := m.syncHAStateLocked(); err != nil {
		return result, fmt.Errorf("publish userspace HA state: %w", err)
	}
	if err := m.syncDesiredForwardingStateLocked(); err != nil {
		return result, fmt.Errorf("sync userspace forwarding state: %w", err)
	}
	m.ensureStatusLoopLocked()
	m.cfg = ucfg
	return result, nil
}

func (m *Manager) syncInterfaceAttachments(result *dataplane.CompileResult, snapshot *ConfigSnapshot) {
	if result == nil {
		return
	}
	allowed := make(map[int]bool)
	for _, ifindex := range buildUserspaceIngressIfindexes(snapshot) {
		allowed[int(ifindex)] = true
	}
	for ifindex := range m.inner.XDPLinks() {
		if allowed[ifindex] {
			continue
		}
		if err := m.inner.DetachXDP(ifindex); err != nil {
			slog.Warn("userspace: detach XDP from non-data interface failed", "ifindex", ifindex, "err", err)
		}
	}
	for ifindex := range m.inner.TCLinks() {
		if allowed[ifindex] {
			continue
		}
		if err := m.inner.DetachTC(ifindex); err != nil {
			slog.Warn("userspace: detach TC from non-data interface failed", "ifindex", ifindex, "err", err)
		}
	}
}

// bpfKtimeNs returns the current CLOCK_BOOTTIME in nanoseconds, matching
// the clock used by BPF's bpf_ktime_get_ns() for session Created timestamps.
func (m *Manager) bpfKtimeNs() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts)
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}

func (m *Manager) bumpGeneration() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.generation++
	return m.generation
}

// BumpFIBGeneration updates the BPF FIB generation counter and sends a
// lightweight FIB generation bump to the userspace helper. If kernel neighbors
// changed since the last publish, an incremental neighbor update is sent first.
// This avoids the full buildSnapshot() + apply_snapshot round-trip that was the
// primary source of control socket contention during route convergence.
func (m *Manager) BumpFIBGeneration() uint32 {
	newGen := m.inner.BumpFIBGeneration()

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
		return newGen
	}
	if m.proc == nil || m.proc.Process == nil {
		return newGen
	}

	// Update the cached snapshot's FIB generation without rebuilding.
	m.lastSnapshot.FIBGeneration = newGen
	m.generation++
	m.lastSnapshot.Generation = m.generation

	// Check if kernel neighbors changed — if so, push an incremental update.
	newNeighbors := buildNeighborSnapshots(m.lastSnapshot.Config)
	if !neighborsEqual(m.lastSnapshot.Neighbors, newNeighbors) {
		var status ProcessStatus
		if err := m.requestLocked(ControlRequest{
			Type:            "update_neighbors",
			Neighbors:       newNeighbors,
			NeighborReplace: true,
		}, &status); err != nil {
			slog.Warn("userspace: failed to publish neighbor update", "err", err)
		} else {
			// Only update cached neighbors after successful publish so
			// a transient failure doesn't suppress future retries.
			m.lastSnapshot.Neighbors = newNeighbors
		}
	}

	// Send lightweight FIB generation bump — no full snapshot rebuild.
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{
		Type: "bump_fib_generation",
		Snapshot: &ConfigSnapshot{
			FIBGeneration: newGen,
		},
	}, &status); err != nil {
		slog.Warn("userspace: failed to bump FIB generation", "err", err)
	}
	return newGen
}

func deriveUserspaceConfig(cfg *config.Config) config.UserspaceConfig {
	out := config.UserspaceConfig{
		Workers:       1,
		RingEntries:   1024,
		ControlSocket: filepath.Join(os.TempDir(), "bpfrx-userspace-dp", "control.sock"),
		StateFile:     filepath.Join(os.TempDir(), "bpfrx-userspace-dp", "state.json"),
	}
	if cfg != nil && cfg.System.UserspaceDataplane != nil {
		out = *cfg.System.UserspaceDataplane
	}
	if out.Workers <= 0 {
		out.Workers = 1
	}
	if out.RingEntries <= 0 {
		out.RingEntries = 1024
	}
	if out.ControlSocket == "" {
		out.ControlSocket = filepath.Join(os.TempDir(), "bpfrx-userspace-dp", "control.sock")
	}
	if out.StateFile == "" {
		out.StateFile = filepath.Join(filepath.Dir(out.ControlSocket), "state.json")
	}
	if out.EventSocket == "" {
		out.EventSocket = filepath.Join(filepath.Dir(out.ControlSocket), "userspace-dp-events.sock")
	}
	return out
}

func deriveUserspaceCapabilities(cfg *config.Config) UserspaceCapabilities {
	caps := UserspaceCapabilities{ForwardingSupported: true}
	if cfg == nil {
		return caps
	}
	addReason := func(reason string) {
		caps.ForwardingSupported = false
		caps.UnsupportedReasons = append(caps.UnsupportedReasons, reason)
	}
	if !userspaceSupportsSecurityPolicies(cfg) {
		addReason("full security policy semantics are not implemented in the userspace dataplane")
	}
	// Pool-mode source NAT is now implemented in the userspace dataplane
	// (PortAllocator with round-robin address + port allocation).
	// NAT64 is supported — NATv6v4 config (no-v6-frag-header option) is fine
	// Session timeouts (TCP/UDP/ICMP) are supported — only gate on unsupported flow features
	// TCP MSS clamping is supported in the userspace dataplane
	// GRE acceleration (key extraction into session ports) is supported
	if !userspaceSupportsScreenProfiles(cfg) {
		addReason("screen features requiring SYN cookies are not implemented in the userspace dataplane")
	}
	// Firewall filters and policers are now supported in the userspace dataplane.
	// Three-color policers remain unsupported.
	if len(cfg.Firewall.ThreeColorPolicers) > 0 {
		addReason("three-color policers are not implemented in the userspace dataplane")
	}
	// IPsec: kernel XFRM handles ESP encryption/decryption; the userspace
	// dataplane passes ESP/IKE traffic to the kernel via the slow-path.
	// GRE transit is now modeled as native userspace tunnel endpoints on the
	// physical NIC path. Kernel tunnel interfaces remain only for host/control
	// plane compatibility during migration.
	if cfg.ForwardingOptions.PortMirroring != nil {
		addReason("port mirroring is not implemented in the userspace dataplane")
	}
	// Flow export (NetFlow v9) is now supported in the userspace dataplane.
	return caps
}

func userspaceSupportsSecurityPolicies(cfg *config.Config) bool {
	if cfg == nil {
		return true
	}
	for _, pol := range cfg.Security.GlobalPolicies {
		if pol == nil {
			continue
		}
		// SchedulerName and Count are informational — not forwarding-critical.
		// Schedulers define time windows (not DSCP), and counters are advisory.
		if !userspacePolicyAddressesSupported(cfg, pol.Match.SourceAddresses) ||
			!userspacePolicyAddressesSupported(cfg, pol.Match.DestinationAddresses) ||
			!userspacePolicyApplicationsSupported(cfg, pol.Match.Applications) {
			return false
		}
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		for _, pol := range zpp.Policies {
			if pol == nil {
				continue
			}
			if !userspacePolicyAddressesSupported(cfg, pol.Match.SourceAddresses) ||
				!userspacePolicyAddressesSupported(cfg, pol.Match.DestinationAddresses) ||
				!userspacePolicyApplicationsSupported(cfg, pol.Match.Applications) {
				return false
			}
		}
	}
	return true
}

func userspacePolicyAddressesSupported(cfg *config.Config, addrs []string) bool {
	_, ok := expandUserspacePolicyAddresses(cfg, addrs)
	return ok
}

func expandUserspacePolicyAddresses(cfg *config.Config, addrs []string) ([]string, bool) {
	if len(addrs) == 0 {
		return nil, true
	}
	expanded := make([]string, 0, len(addrs))
	seen := make(map[string]struct{}, len(addrs))
	addUnique := func(value string) {
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		expanded = append(expanded, value)
	}
	for _, addr := range addrs {
		switch {
		case addr == "" || addr == "any":
			addUnique("any")
		case isUserspaceLiteralAddress(addr):
			addUnique(normalizeUserspaceLiteralAddress(addr))
		default:
			values, ok := resolveUserspaceAddressBookEntry(cfg, addr)
			if !ok || len(values) == 0 {
				return nil, false
			}
			for _, value := range values {
				if value == "" {
					return nil, false
				}
				if !isUserspaceLiteralAddress(value) {
					return nil, false
				}
				addUnique(normalizeUserspaceLiteralAddress(value))
			}
		}
	}
	sort.Strings(expanded)
	return expanded, true
}

func isUserspaceLiteralAddress(value string) bool {
	if value == "" || value == "any" {
		return true
	}
	if _, _, err := net.ParseCIDR(value); err == nil {
		return true
	}
	return net.ParseIP(value) != nil
}

func normalizeUserspaceLiteralAddress(value string) string {
	if value == "" || value == "any" {
		return value
	}
	if _, ipNet, err := net.ParseCIDR(value); err == nil && ipNet != nil {
		return ipNet.String()
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	return value
}

func resolveUserspaceAddressBookEntry(cfg *config.Config, name string) ([]string, bool) {
	if cfg == nil || cfg.Security.AddressBook == nil || name == "" {
		return nil, false
	}
	addressBook := cfg.Security.AddressBook
	seenSets := make(map[string]bool)
	expanded := make([]string, 0, 4)
	var resolve func(string) bool
	resolve = func(ref string) bool {
		if ref == "" {
			return false
		}
		if addr := addressBook.Addresses[ref]; addr != nil {
			if addr.Value == "" {
				return false
			}
			expanded = append(expanded, addr.Value)
			return true
		}
		set := addressBook.AddressSets[ref]
		if set == nil {
			return false
		}
		if seenSets[ref] {
			return true
		}
		seenSets[ref] = true
		resolvedAny := false
		for _, member := range set.Addresses {
			if !resolve(member) {
				return false
			}
			resolvedAny = true
		}
		for _, member := range set.AddressSets {
			if !resolve(member) {
				return false
			}
			resolvedAny = true
		}
		return resolvedAny
	}
	if !resolve(name) {
		return nil, false
	}
	sort.Strings(expanded)
	expanded = slices.Compact(expanded)
	return expanded, true
}

func userspacePolicyApplicationsSupported(cfg *config.Config, apps []string) bool {
	_, ok := expandUserspacePolicyApplications(cfg, apps)
	return ok
}

func expandUserspacePolicyApplications(cfg *config.Config, apps []string) ([]PolicyApplicationSnapshot, bool) {
	if len(apps) == 0 {
		return nil, true
	}
	expanded := make([]PolicyApplicationSnapshot, 0, len(apps))
	seen := make(map[string]struct{}, len(apps))
	for _, appName := range apps {
		if appName == "" || appName == "any" {
			return nil, true
		}
		resolved, ok := resolveUserspaceApplicationNames(cfg, appName)
		if !ok || len(resolved) == 0 {
			return nil, false
		}
		for _, resolvedName := range resolved {
			app, ok := config.ResolveApplication(resolvedName, cfg.Applications.Applications)
			if !ok || app == nil {
				return nil, false
			}
			proto := normalizeUserspaceApplicationProtocol(app.Protocol)
			if proto == "" {
				return nil, false
			}
			snap := PolicyApplicationSnapshot{
				Name:            resolvedName,
				Protocol:        proto,
				SourcePort:      app.SourcePort,
				DestinationPort: app.DestinationPort,
			}
			key := strings.Join([]string{snap.Name, snap.Protocol, snap.SourcePort, snap.DestinationPort}, "\x00")
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			expanded = append(expanded, snap)
		}
	}
	sort.Slice(expanded, func(i, j int) bool {
		if expanded[i].Name != expanded[j].Name {
			return expanded[i].Name < expanded[j].Name
		}
		if expanded[i].Protocol != expanded[j].Protocol {
			return expanded[i].Protocol < expanded[j].Protocol
		}
		if expanded[i].SourcePort != expanded[j].SourcePort {
			return expanded[i].SourcePort < expanded[j].SourcePort
		}
		return expanded[i].DestinationPort < expanded[j].DestinationPort
	})
	return expanded, true
}

func resolveUserspaceApplicationNames(cfg *config.Config, name string) ([]string, bool) {
	if cfg == nil || name == "" {
		return nil, false
	}
	if _, ok := config.ResolveApplication(name, cfg.Applications.Applications); ok {
		return []string{name}, true
	}
	if _, ok := config.ResolveApplicationSet(name, cfg.Applications.ApplicationSets); ok {
		expanded, err := config.ExpandApplicationSet(name, &cfg.Applications)
		if err != nil || len(expanded) == 0 {
			return nil, false
		}
		sort.Strings(expanded)
		return slices.Compact(expanded), true
	}
	return nil, false
}

func normalizeUserspaceApplicationProtocol(proto string) string {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "icmp6":
		return "icmpv6"
	default:
		return strings.ToLower(strings.TrimSpace(proto))
	}
}

func userspaceSupportsSourceNAT(ruleSets []*config.NATRuleSet) bool {
	for _, rs := range ruleSets {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			if rule.Then.Interface || rule.Then.Off {
				continue
			}
			return false
		}
	}
	return true
}

func buildSnapshot(cfg *config.Config, ucfg config.UserspaceConfig, generation uint64, fibGeneration uint32) *ConfigSnapshot {
	if cfg == nil {
		return &ConfigSnapshot{
			Version:       ProtocolVersion,
			Generation:    generation,
			FIBGeneration: 0,
			GeneratedAt:   time.Now().UTC(),
			Capabilities:  deriveUserspaceCapabilities(nil),
			MapPins:       userspaceMapPins(),
			Userspace:     ucfg,
		}
	}
	policyCount := len(cfg.Security.Policies)
	interfaces := buildInterfaceSnapshots(cfg)
	return &ConfigSnapshot{
		Version:         ProtocolVersion,
		Generation:      generation,
		FIBGeneration:   fibGeneration,
		GeneratedAt:     time.Now().UTC(),
		Capabilities:    deriveUserspaceCapabilities(cfg),
		MapPins:         userspaceMapPins(),
		Userspace:       ucfg,
		Zones:           buildZoneSnapshots(cfg),
		Interfaces:      interfaces,
		Fabrics:         buildFabricSnapshots(cfg),
		TunnelEndpoints: buildTunnelEndpointSnapshots(cfg, interfaces),
		Neighbors:       buildNeighborSnapshots(cfg),
		Routes:          buildRouteSnapshots(cfg, interfaces),
		Flow:            buildFlowSnapshot(cfg),
		DefaultPolicy:   policyActionString(cfg.Security.DefaultPolicy),
		Policies:        buildPolicySnapshots(cfg),
		SourceNAT:       buildSourceNATSnapshots(cfg),
		StaticNAT:       buildStaticNATSnapshots(cfg),
		DestinationNAT:  buildDestinationNATSnapshots(cfg),
		NAT64:           buildNAT64Snapshots(cfg),
		Nptv6:           buildNptv6Snapshots(cfg),
		Screens:         buildScreenSnapshots(cfg),
		Filters:         buildFirewallFilterSnapshots(cfg),
		Policers:        buildPolicerSnapshots(cfg),
		FlowExport:      buildFlowExportSnapshot(cfg),
		Config:          cfg,
		Summary: SnapshotSummary{
			HostName:       cfg.System.HostName,
			DataplaneType:  cfg.System.DataplaneType,
			InterfaceCount: len(cfg.Interfaces.Interfaces),
			ZoneCount:      len(cfg.Security.Zones),
			PolicyCount:    policyCount,
			SchedulerCount: len(cfg.Schedulers),
			HAEnabled:      cfg.Chassis.Cluster != nil,
		},
	}
}

// snapshotContentHash computes a SHA-256 hash over the stable content of a
// snapshot, excluding volatile fields (Generation, FIBGeneration, GeneratedAt)
// that change on every build even when the forwarding-relevant content is
// identical. Used to skip redundant control-socket publishes.
func snapshotContentHash(snap *ConfigSnapshot) ([32]byte, bool) {
	// Create a shallow copy with volatile fields zeroed, then JSON-encode.
	// This is cheaper than a custom hasher and reuses the existing JSON tags.
	tmp := *snap
	tmp.Generation = 0
	tmp.FIBGeneration = 0
	tmp.GeneratedAt = time.Time{}
	tmp.Config = nil // exclude raw config from content hash to avoid churn from non-forwarding metadata
	data, err := json.Marshal(&tmp)
	if err != nil {
		slog.Warn("snapshotContentHash: marshal failed, skipping dedup", "err", err)
		return [32]byte{}, false
	}
	return sha256.Sum256(data), true
}

// neighborsEqual returns true if two neighbor snapshot slices have identical content.
func neighborsEqual(a, b []NeighborSnapshot) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func buildZoneSnapshots(cfg *config.Config) []ZoneSnapshot {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return nil
	}
	names := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]ZoneSnapshot, 0, len(names))
	for i, name := range names {
		out = append(out, ZoneSnapshot{
			Name: name,
			ID:   uint16(i + 1),
		})
	}
	return out
}

func buildFabricSnapshots(cfg *config.Config) []FabricSnapshot {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	cc := cfg.Chassis.Cluster
	type fabricInput struct {
		name string
		peer string
	}
	inputs := []fabricInput{
		{name: cc.FabricInterface, peer: cc.FabricPeerAddress},
		{name: cc.Fabric1Interface, peer: cc.Fabric1PeerAddress},
	}
	var out []FabricSnapshot
	seen := make(map[string]struct{}, len(inputs))
	for _, in := range inputs {
		if in.name == "" {
			continue
		}
		if _, ok := seen[in.name]; ok {
			continue
		}
		seen[in.name] = struct{}{}
		ifCfg := cfg.Interfaces.Interfaces[in.name]
		if ifCfg == nil {
			continue
		}
		parentName := ifCfg.LocalFabricMember
		parentLinux := config.LinuxIfName(parentName)
		parentIfindex, _, parentMAC, _ := buildLinkSnapshot(parentLinux)
		overlayLinux := config.LinuxIfName(in.name)
		overlayIfindex, _, _, _ := buildLinkSnapshot(overlayLinux)
		rxQueues := 0
		if parentLinux != "" {
			rxQueues = userspaceRXQueueCount(parentLinux)
		}
		peerMAC := buildFabricPeerMAC(overlayIfindex, parentIfindex, in.peer)
		out = append(out, FabricSnapshot{
			Name:            in.name,
			ParentInterface: parentName,
			ParentLinuxName: parentLinux,
			ParentIfindex:   parentIfindex,
			OverlayLinux:    overlayLinux,
			OverlayIfindex:  overlayIfindex,
			RXQueues:        rxQueues,
			PeerAddress:     in.peer,
			LocalMAC:        parentMAC,
			PeerMAC:         peerMAC,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

func buildFabricPeerMAC(overlayIfindex, parentIfindex int, peer string) string {
	ip := net.ParseIP(peer)
	if ip == nil {
		return ""
	}
	family := netlink.FAMILY_V4
	if ip.To4() == nil {
		family = netlink.FAMILY_V6
	}
	for _, ifindex := range []int{overlayIfindex, parentIfindex} {
		if ifindex <= 0 {
			continue
		}
		neighs, err := netlink.NeighList(ifindex, family)
		if err != nil {
			continue
		}
		for _, neigh := range neighs {
			if neigh.IP == nil || !neigh.IP.Equal(ip) || neigh.HardwareAddr == nil {
				continue
			}
			return neigh.HardwareAddr.String()
		}
	}
	return ""
}

func userspaceMapPins() UserspaceMapPins {
	return UserspaceMapPins{
		Ctrl:        dataplane.UserspaceCtrlPinPath(),
		Bindings:    dataplane.UserspaceBindingsPinPath(),
		Heartbeat:   dataplane.UserspaceHeartbeatPinPath(),
		XSK:         dataplane.UserspaceXSKMapPinPath(),
		LocalV4:     dataplane.UserspaceLocalV4PinPath(),
		LocalV6:     dataplane.UserspaceLocalV6PinPath(),
		Sessions:    dataplane.UserspaceSessionsPinPath(),
		ConntrackV4: dataplane.ConntrackV4PinPath(),
		ConntrackV6: dataplane.ConntrackV6PinPath(),
		DnatTable:   dataplane.UserspaceDnatTablePinPath(),
		DnatTableV6: dataplane.UserspaceDnatTableV6PinPath(),
		Trace:       dataplane.UserspaceTracePinPath(),
	}
}

func (m *Manager) readFIBGeneration() uint32 {
	fibGenMap := m.inner.Map("fib_gen_map")
	if fibGenMap == nil {
		return 0
	}
	var (
		key uint32
		gen uint32
	)
	if err := fibGenMap.Lookup(key, &gen); err != nil {
		return 0
	}
	return gen
}

func buildInterfaceSnapshots(cfg *config.Config) []InterfaceSnapshot {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return nil
	}
	zoneByInterface := buildInterfaceZoneMap(cfg)
	// Build RETH RG lookup: physical member → RETH's RedundancyGroup.
	// Physical members have RedundantParent set but RedundancyGroup=0;
	// the RG is on the RETH. Without this, flow cache HA checks on
	// RETH member egress interfaces return owner_rg=0 and bypass
	// HA active/inactive validation, causing stale forwarding after failover.
	rethRG := make(map[string]int)
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc != nil && ifc.RedundantParent != "" {
			if reth := cfg.Interfaces.Interfaces[ifc.RedundantParent]; reth != nil && reth.RedundancyGroup > 0 {
				rethRG[ifc.Name] = reth.RedundancyGroup
			}
		}
	}
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]InterfaceSnapshot, 0, len(names))
	for _, name := range names {
		iface := cfg.Interfaces.Interfaces[name]
		if iface == nil {
			continue
		}
		linuxName := snapshotLinuxName(cfg, name, iface, nil)
		ifindex, mtu, hardwareAddr, addresses := buildLinkSnapshot(linuxName)
		// Use the interface's own RG, or inherit from RETH parent.
		rg := iface.RedundancyGroup
		if rg <= 0 {
			rg = rethRG[name]
		}
		out = append(out, InterfaceSnapshot{
			Name:            name,
			Zone:            zoneByInterface[name],
			LinuxName:       linuxName,
			ParentLinuxName: "",
			Ifindex:         ifindex,
			ParentIfindex:   0,
			RXQueues:        userspaceRXQueueCount(linuxName),
			VLANID:          0,
			LocalFabric:     iface.LocalFabricMember,
			RedundancyGroup: rg,
			UnitCount:       len(iface.Units),
			Tunnel:          iface.Tunnel != nil,
			MTU:             mtu,
			HardwareAddr:    hardwareAddr,
			Addresses:       addresses,
		})
		if len(iface.Units) == 0 {
			continue
		}
		unitNums := make([]int, 0, len(iface.Units))
		for unitNum := range iface.Units {
			unitNums = append(unitNums, unitNum)
		}
		sort.Ints(unitNums)
		for _, unitNum := range unitNums {
			unit := iface.Units[unitNum]
			if unit == nil {
				continue
			}
			unitName := fmt.Sprintf("%s.%d", name, unitNum)
			parentLinux := snapshotLinuxName(cfg, name, iface, nil)
			parentIfindex, _, _, _ := buildLinkSnapshot(parentLinux)
			linuxUnit := snapshotLinuxName(cfg, name, iface, unit)
			ifindex, mtu, hardwareAddr, addresses := buildLinkSnapshot(linuxUnit)
			addresses = mergeInterfaceAddressSnapshots(addresses, buildConfiguredAddressSnapshots(unit.Addresses))
			out = append(out, InterfaceSnapshot{
				Name:            unitName,
				Zone:            zoneByInterface[unitName],
				LinuxName:       linuxUnit,
				ParentLinuxName: parentLinux,
				Ifindex:         ifindex,
				ParentIfindex:   parentIfindex,
				RXQueues:        userspaceRXQueueCount(linuxUnit),
				VLANID:          unit.VlanID,
				LocalFabric:     iface.LocalFabricMember,
				RedundancyGroup: rg, // inherit resolved RG (RETH parent or own)
				UnitCount:       0,
				Tunnel:          iface.Tunnel != nil || unit.Tunnel != nil,
				MTU:             mtu,
				HardwareAddr:    hardwareAddr,
				Addresses:       addresses,
				FilterInputV4:   unit.FilterInputV4,
				FilterInputV6:   unit.FilterInputV6,
			})
		}
	}
	return out
}

func buildTunnelEndpointSnapshots(cfg *config.Config, interfaces []InterfaceSnapshot) []TunnelEndpointSnapshot {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return nil
	}
	ifaceByName := make(map[string]InterfaceSnapshot, len(interfaces))
	rgByAddress := make(map[string]int)
	for _, iface := range interfaces {
		if iface.Name == "" || iface.Ifindex <= 0 {
			continue
		}
		ifaceByName[iface.Name] = iface
		if iface.RedundancyGroup <= 0 {
			continue
		}
		for _, addr := range iface.Addresses {
			ip, _, err := net.ParseCIDR(addr.Address)
			if err != nil || ip == nil {
				continue
			}
			rgByAddress[ip.String()] = iface.RedundancyGroup
		}
	}
	if len(ifaceByName) == 0 {
		return nil
	}
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]TunnelEndpointSnapshot, 0)
	var nextID uint16 = 1
	addEndpoint := func(ifName string, tunnel *config.TunnelConfig) {
		if tunnel == nil || tunnel.Source == "" || tunnel.Destination == "" || nextID == 0 {
			return
		}
		iface, ok := ifaceByName[ifName]
		if !ok {
			return
		}
		outerFamily := "inet"
		transportTable := "inet.0"
		if dst := net.ParseIP(tunnel.Destination); dst != nil && dst.To4() == nil {
			outerFamily = "inet6"
			transportTable = "inet6.0"
		} else if src := net.ParseIP(tunnel.Source); src != nil && src.To4() == nil {
			outerFamily = "inet6"
			transportTable = "inet6.0"
		}
		if tunnel.RoutingInstance != "" {
			if outerFamily == "inet6" {
				transportTable = tunnel.RoutingInstance + ".inet6.0"
			} else {
				transportTable = tunnel.RoutingInstance + ".inet.0"
			}
		}
		redundancyGroup := iface.RedundancyGroup
		if redundancyGroup <= 0 {
			if src := net.ParseIP(tunnel.Source); src != nil {
				redundancyGroup = rgByAddress[src.String()]
			}
		}
		out = append(out, TunnelEndpointSnapshot{
			ID:              nextID,
			Interface:       ifName,
			LinuxName:       iface.LinuxName,
			Ifindex:         iface.Ifindex,
			Zone:            iface.Zone,
			RedundancyGroup: redundancyGroup,
			MTU:             iface.MTU,
			Mode:            tunnel.Mode,
			OuterFamily:     outerFamily,
			Source:          tunnel.Source,
			Destination:     tunnel.Destination,
			Key:             tunnel.Key,
			TTL:             tunnel.TTL,
			TransportTable:  transportTable,
		})
		nextID++
	}
	for _, name := range names {
		iface := cfg.Interfaces.Interfaces[name]
		if iface == nil {
			continue
		}
		if iface.Tunnel != nil {
			if len(iface.Units) == 0 {
				addEndpoint(name, iface.Tunnel)
				continue
			}
			unitNums := make([]int, 0, len(iface.Units))
			for unitNum := range iface.Units {
				unitNums = append(unitNums, unitNum)
			}
			sort.Ints(unitNums)
			for _, unitNum := range unitNums {
				addEndpoint(fmt.Sprintf("%s.%d", name, unitNum), iface.Tunnel)
			}
			continue
		}
		if len(iface.Units) == 0 {
			continue
		}
		unitNums := make([]int, 0, len(iface.Units))
		for unitNum := range iface.Units {
			unitNums = append(unitNums, unitNum)
		}
		sort.Ints(unitNums)
		for _, unitNum := range unitNums {
			unit := iface.Units[unitNum]
			if unit == nil || unit.Tunnel == nil {
				continue
			}
			addEndpoint(fmt.Sprintf("%s.%d", name, unitNum), unit.Tunnel)
		}
	}
	return out
}

func buildInterfaceZoneMap(cfg *config.Config) map[string]string {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return nil
	}
	out := make(map[string]string, len(cfg.Security.Zones))
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	sort.Strings(zoneNames)
	for _, zoneName := range zoneNames {
		zone := cfg.Security.Zones[zoneName]
		if zone == nil {
			continue
		}
		for _, iface := range zone.Interfaces {
			if iface == "" {
				continue
			}
			if _, exists := out[iface]; !exists {
				out[iface] = zoneName
			}
			if base, unit, ok := strings.Cut(iface, "."); ok && base != "" {
				if _, exists := out[base]; !exists {
					out[base] = zoneName
				}
				if unit != "" {
					continue
				}
			}
			if ifCfg := cfg.Interfaces.Interfaces[iface]; ifCfg != nil {
				for unitNum := range ifCfg.Units {
					unitName := fmt.Sprintf("%s.%d", iface, unitNum)
					if _, exists := out[unitName]; !exists {
						out[unitName] = zoneName
					}
				}
			}
		}
	}
	return out
}

func snapshotLinuxName(cfg *config.Config, ifName string, iface *config.InterfaceConfig, unit *config.InterfaceUnit) string {
	if iface == nil {
		return config.LinuxIfName(ifName)
	}
	if unit != nil {
		if tunnelNames := cfg.TunnelNameMap(); len(tunnelNames) > 0 {
			ref := fmt.Sprintf("%s.%d", ifName, unit.Number)
			if linuxName, ok := tunnelNames[ref]; ok && linuxName != "" {
				return linuxName
			}
		}
		if unit.VlanID > 0 {
			return fmt.Sprintf("%s.%d", config.LinuxIfName(cfg.ResolveReth(ifName)), unit.VlanID)
		}
		if strings.HasPrefix(ifName, "reth") {
			if unit.Number == 0 {
				return config.LinuxIfName(cfg.ResolveReth(ifName))
			}
			return config.LinuxIfName(cfg.ResolveReth(fmt.Sprintf("%s.%d", ifName, unit.Number)))
		}
		if unit.Number == 0 {
			return config.LinuxIfName(ifName)
		}
		return config.LinuxIfName(fmt.Sprintf("%s.%d", ifName, unit.Number))
	}
	if strings.HasPrefix(ifName, "reth") {
		return config.LinuxIfName(cfg.ResolveReth(ifName))
	}
	return config.LinuxIfName(ifName)
}

func buildLinkSnapshot(linuxName string) (ifindex int, mtu int, hardwareAddr string, addresses []InterfaceAddressSnapshot) {
	if linuxName == "" {
		return 0, 0, "", nil
	}
	if link, err := net.InterfaceByName(linuxName); err == nil {
		ifindex = link.Index
	}
	if link, err := netlink.LinkByName(linuxName); err == nil && link != nil {
		mtu = link.Attrs().MTU
		if hw := link.Attrs().HardwareAddr; len(hw) > 0 {
			hardwareAddr = hw.String()
		}
		addresses = buildInterfaceAddressSnapshots(link)
	}
	return ifindex, mtu, hardwareAddr, addresses
}

func buildConfiguredAddressSnapshots(addrs []string) []InterfaceAddressSnapshot {
	if len(addrs) == 0 {
		return nil
	}
	out := make([]InterfaceAddressSnapshot, 0, len(addrs))
	for _, cidr := range addrs {
		ip, netw, err := net.ParseCIDR(cidr)
		if err != nil || netw == nil {
			continue
		}
		netw.IP = ip
		family := "inet"
		if ip.To4() == nil {
			family = "inet6"
		}
		out = append(out, InterfaceAddressSnapshot{
			Family:  family,
			Address: netw.String(),
			Scope:   int(netlink.SCOPE_UNIVERSE),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].Address < out[j].Address
	})
	return out
}

func mergeInterfaceAddressSnapshots(live []InterfaceAddressSnapshot, configured []InterfaceAddressSnapshot) []InterfaceAddressSnapshot {
	if len(live) == 0 {
		return configured
	}
	if len(configured) == 0 {
		return live
	}
	seen := make(map[string]bool, len(live)+len(configured))
	out := make([]InterfaceAddressSnapshot, 0, len(live)+len(configured))
	for _, addr := range live {
		key := addr.Family + "/" + addr.Address
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, addr)
	}
	for _, addr := range configured {
		key := addr.Family + "/" + addr.Address
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, addr)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].Address < out[j].Address
	})
	return out
}

func buildInterfaceAddressSnapshots(link netlink.Link) []InterfaceAddressSnapshot {
	if link == nil {
		return nil
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil || len(addrs) == 0 {
		return nil
	}
	out := make([]InterfaceAddressSnapshot, 0, len(addrs))
	for _, addr := range addrs {
		if addr.IPNet == nil {
			continue
		}
		family := "inet"
		if addr.IPNet.IP.To4() == nil {
			family = "inet6"
		}
		out = append(out, InterfaceAddressSnapshot{
			Family:  family,
			Address: addr.IPNet.String(),
			Scope:   addr.Scope,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].Address < out[j].Address
	})
	return out
}

func userspaceRXQueueCount(linuxName string) int {
	if linuxName == "" {
		return 0
	}
	entries, err := os.ReadDir(filepath.Join("/sys/class/net", linuxName, "queues"))
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if name := entry.Name(); len(name) > 3 && name[:3] == "rx-" {
			count++
		}
	}
	return count
}

func buildRouteSnapshots(cfg *config.Config, interfaces []InterfaceSnapshot) []RouteSnapshot {
	if cfg == nil {
		return nil
	}
	out := make([]RouteSnapshot, 0)
	seen := make(map[string]struct{})
	addSnapshot := func(snap RouteSnapshot) {
		key := snap.Table + "|" + snap.Family + "|" + snap.Destination + "|" + strings.Join(snap.NextHops, ",") + "|" + snap.NextTable
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, snap)
	}
	addRoutes := func(table, family string, routes []*config.StaticRoute) {
		for _, route := range routes {
			if route == nil {
				continue
			}
			tableName, familyName := normalizeRouteSnapshotFamily(table, family, route.Destination)
			snap := RouteSnapshot{
				Table:       tableName,
				Family:      familyName,
				Destination: route.Destination,
				Discard:     route.Discard,
				NextTable:   route.NextTable,
			}
			for _, nh := range route.NextHops {
				switch {
				case nh.Address != "" && nh.Interface != "":
					snap.NextHops = append(snap.NextHops, nh.Address+"@"+nh.Interface)
				case nh.Address != "":
					snap.NextHops = append(snap.NextHops, nh.Address)
				case nh.Interface != "":
					snap.NextHops = append(snap.NextHops, "@"+nh.Interface)
				}
			}
			addSnapshot(snap)
		}
	}
	interfaceTablesV4, interfaceTablesV6 := buildInterfaceRouteTables(cfg)
	addConnectedRoutes := func(family, table string, prefixes []string) {
		for _, prefix := range prefixes {
			snap := RouteSnapshot{
				Table:       table,
				Family:      family,
				Destination: prefix,
			}
			addSnapshot(snap)
		}
	}
	addRoutes("inet.0", "inet", cfg.RoutingOptions.StaticRoutes)
	addRoutes("inet6.0", "inet6", cfg.RoutingOptions.Inet6StaticRoutes)

	if len(cfg.RoutingInstances) > 0 {
		insts := make([]*config.RoutingInstanceConfig, 0, len(cfg.RoutingInstances))
		for _, ri := range cfg.RoutingInstances {
			if ri != nil {
				insts = append(insts, ri)
			}
		}
		sort.Slice(insts, func(i, j int) bool { return insts[i].Name < insts[j].Name })
		for _, ri := range insts {
			addRoutes(ri.Name+".inet.0", "inet", ri.StaticRoutes)
			addRoutes(ri.Name+".inet6.0", "inet6", ri.Inet6StaticRoutes)
		}
	}
	for _, iface := range interfaces {
		if iface.Name == "" {
			continue
		}
		v4Table := interfaceTablesV4[iface.Name]
		if v4Table == "" {
			v4Table = "inet.0"
		}
		v6Table := interfaceTablesV6[iface.Name]
		if v6Table == "" {
			v6Table = "inet6.0"
		}
		v4Prefixes, v6Prefixes := connectedPrefixesForInterface(iface)
		addConnectedRoutes("inet", v4Table, v4Prefixes)
		addConnectedRoutes("inet6", v6Table, v6Prefixes)
	}

	// Add synthetic routes for ip rule entries that implement inter-VRF
	// route leaking (rib-groups, next-table). These rules send traffic
	// matching a destination prefix to a different routing table.
	// Without these, the userspace FIB can't cross-reference VRF tables.
	tableIDToName := make(map[int]string)
	for _, inst := range cfg.RoutingInstances {
		if inst != nil && inst.TableID > 0 {
			tableIDToName[inst.TableID] = inst.Name + ".inet.0"
		}
	}
	for _, family := range []int{syscall.AF_INET, syscall.AF_INET6} {
		rules, err := netlink.RuleList(family)
		if err != nil {
			continue
		}
		for _, rule := range rules {
			if rule.Dst == nil || rule.Table <= 0 {
				continue
			}
			tableName, ok := tableIDToName[rule.Table]
			if !ok {
				continue
			}
			familyStr := "inet"
			mainTable := "inet.0"
			if family == syscall.AF_INET6 {
				familyStr = "inet6"
				mainTable = "inet6.0"
			}
			addSnapshot(RouteSnapshot{
				Table:       mainTable,
				Family:      familyStr,
				Destination: rule.Dst.String(),
				NextTable:   tableName,
			})
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Table != out[j].Table {
			return out[i].Table < out[j].Table
		}
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].Destination < out[j].Destination
	})
	return out
}

func buildInterfaceRouteTables(cfg *config.Config) (map[string]string, map[string]string) {
	v4 := make(map[string]string)
	v6 := make(map[string]string)
	if cfg == nil {
		return v4, v6
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.Name == "" {
			continue
		}
		for _, ifname := range ri.Interfaces {
			if ifname == "" {
				continue
			}
			v4[ifname] = ri.Name + ".inet.0"
			v6[ifname] = ri.Name + ".inet6.0"
		}
	}
	return v4, v6
}

func connectedPrefixesForInterface(iface InterfaceSnapshot) ([]string, []string) {
	var v4 []string
	var v6 []string
	for _, addr := range iface.Addresses {
		if addr.Scope != 0 && addr.Scope != int(netlink.SCOPE_UNIVERSE) {
			continue
		}
		ip, network, err := net.ParseCIDR(addr.Address)
		if err != nil || network == nil {
			continue
		}
		ones, bits := network.Mask.Size()
		if ones <= 0 || ones == bits {
			continue
		}
		network.IP = ip.Mask(network.Mask)
		prefix := network.String()
		switch addr.Family {
		case "inet":
			v4 = append(v4, prefix)
		case "inet6":
			if ip.IsLinkLocalUnicast() {
				continue
			}
			v6 = append(v6, prefix)
		}
	}
	slices.Sort(v4)
	slices.Sort(v6)
	return slices.Compact(v4), slices.Compact(v6)
}

func normalizeRouteSnapshotFamily(table, family, destination string) (string, string) {
	isIPv6 := strings.Contains(destination, ":")
	if isIPv6 {
		family = "inet6"
		switch {
		case table == "inet.0":
			table = "inet6.0"
		case strings.HasSuffix(table, ".inet.0"):
			table = strings.TrimSuffix(table, ".inet.0") + ".inet6.0"
		}
		return table, family
	}
	family = "inet"
	switch {
	case table == "inet6.0":
		table = "inet.0"
	case strings.HasSuffix(table, ".inet6.0"):
		table = strings.TrimSuffix(table, ".inet6.0") + ".inet.0"
	}
	return table, family
}

func buildSourceNATSnapshots(cfg *config.Config) []SourceNATRuleSnapshot {
	if cfg == nil || len(cfg.Security.NAT.Source) == 0 {
		return nil
	}
	out := make([]SourceNATRuleSnapshot, 0)
	for _, rs := range cfg.Security.NAT.Source {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			sourceAddrs := append([]string(nil), rule.Match.SourceAddresses...)
			if len(sourceAddrs) == 0 && rule.Match.SourceAddress != "" {
				sourceAddrs = append(sourceAddrs, rule.Match.SourceAddress)
			}
			destAddrs := append([]string(nil), rule.Match.DestinationAddresses...)
			if len(destAddrs) == 0 && rule.Match.DestinationAddress != "" {
				destAddrs = append(destAddrs, rule.Match.DestinationAddress)
			}
			out = append(out, SourceNATRuleSnapshot{
				Name:                 rule.Name,
				FromZone:             rs.FromZone,
				ToZone:               rs.ToZone,
				SourceAddresses:      sourceAddrs,
				DestinationAddresses: destAddrs,
				InterfaceMode:        rule.Then.Interface,
				Off:                  rule.Then.Off,
				PoolName:             rule.Then.PoolName,
			})
		}
	}
	return out
}

func buildStaticNATSnapshots(cfg *config.Config) []StaticNATRuleSnapshot {
	if cfg == nil || len(cfg.Security.NAT.Static) == 0 {
		return nil
	}
	out := make([]StaticNATRuleSnapshot, 0)
	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || rule.IsNPTv6 {
				continue
			}
			out = append(out, StaticNATRuleSnapshot{
				Name:       rule.Name,
				FromZone:   rs.FromZone,
				ExternalIP: rule.Match,
				InternalIP: rule.Then,
			})
		}
	}
	return out
}

// appPortsFromSpec parses a port specification like "80", "1024-65535" into a
// list of port numbers. Mirrors the logic in pkg/dataplane/compiler.go.
func appPortsFromSpec(spec string) []int {
	if spec == "" {
		return nil
	}
	if strings.Contains(spec, "-") {
		parts := strings.SplitN(spec, "-", 2)
		lo, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			return nil
		}
		hi, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			return nil
		}
		if hi > lo {
			var ports []int
			for p := lo; p <= hi; p++ {
				ports = append(ports, int(p))
			}
			return ports
		}
		return []int{int(lo)}
	}
	p, err := strconv.ParseUint(spec, 10, 16)
	if err != nil {
		return nil
	}
	return []int{int(p)}
}

func buildDestinationNATSnapshots(cfg *config.Config) []DestinationNATRuleSnapshot {
	if cfg == nil || cfg.Security.NAT.Destination == nil || len(cfg.Security.NAT.Destination.RuleSets) == 0 {
		return nil
	}
	var out []DestinationNATRuleSnapshot
	for _, rs := range cfg.Security.NAT.Destination.RuleSets {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || rule.Then.PoolName == "" {
				continue
			}
			pool, ok := cfg.Security.NAT.Destination.Pools[rule.Then.PoolName]
			if !ok || pool == nil || pool.Address == "" {
				continue
			}
			if rule.Match.DestinationAddress == "" {
				continue
			}

			// Resolve application match to protocol+ports if specified.
			type appTerm struct {
				proto string
				ports []int
			}
			var appTerms []appTerm

			if rule.Match.Application != "" {
				userApps := cfg.Applications.Applications
				app, found := config.ResolveApplication(rule.Match.Application, userApps)
				if found {
					appTerms = append(appTerms, appTerm{proto: app.Protocol, ports: appPortsFromSpec(app.DestinationPort)})
				} else if _, isSet := cfg.Applications.ApplicationSets[rule.Match.Application]; isSet {
					expanded, err := config.ExpandApplicationSet(rule.Match.Application, &cfg.Applications)
					if err == nil {
						for _, termName := range expanded {
							tApp, ok := config.ResolveApplication(termName, userApps)
							if !ok {
								continue
							}
							appTerms = append(appTerms, appTerm{proto: tApp.Protocol, ports: appPortsFromSpec(tApp.DestinationPort)})
						}
					}
				}
			}

			// If no application terms resolved, use explicit match values
			if len(appTerms) == 0 {
				appTerms = []appTerm{{proto: rule.Match.Protocol, ports: rule.Match.DestinationPorts}}
			}

			for _, term := range appTerms {
				var dstPorts []uint16
				if len(term.ports) > 0 {
					for _, p := range term.ports {
						dstPorts = append(dstPorts, uint16(p))
					}
				} else if rule.Match.DestinationPort != 0 {
					dstPorts = []uint16{uint16(rule.Match.DestinationPort)}
				} else {
					dstPorts = []uint16{0}
				}

				for _, dstPort := range dstPorts {
					poolPort := dstPort
					if pool.Port != 0 {
						poolPort = uint16(pool.Port)
					}

					// Determine protocol string for the snapshot.
					proto := term.proto
					if proto == "" && dstPort != 0 {
						proto = "tcp" // default for port-based DNAT
					}

					// Strip the destination address CIDR suffix for the snapshot
					// (DNAT matches exact host IPs).
					dstAddr := rule.Match.DestinationAddress
					if idx := strings.IndexByte(dstAddr, '/'); idx != -1 {
						dstAddr = dstAddr[:idx]
					}
					poolAddr := pool.Address
					if idx := strings.IndexByte(poolAddr, '/'); idx != -1 {
						poolAddr = poolAddr[:idx]
					}

					out = append(out, DestinationNATRuleSnapshot{
						Name:               rule.Name,
						FromZone:           rs.FromZone,
						DestinationAddress: dstAddr,
						DestinationPort:    dstPort,
						Protocol:           proto,
						PoolAddress:        poolAddr,
						PoolPort:           poolPort,
					})
				}
			}
		}
	}
	return out
}

func buildNAT64Snapshots(cfg *config.Config) []NAT64RuleSnapshot {
	if cfg == nil || len(cfg.Security.NAT.NAT64) == 0 {
		return nil
	}
	out := make([]NAT64RuleSnapshot, 0, len(cfg.Security.NAT.NAT64))
	for _, rs := range cfg.Security.NAT.NAT64 {
		if rs == nil || rs.Prefix == "" {
			continue
		}
		var poolAddresses []string
		if rs.SourcePool != "" {
			if pool, ok := cfg.Security.NAT.SourcePools[rs.SourcePool]; ok && pool != nil {
				if pool.Address != "" {
					poolAddresses = append(poolAddresses, pool.Address)
				}
				poolAddresses = append(poolAddresses, pool.Addresses...)
			}
		}
		out = append(out, NAT64RuleSnapshot{
			Name:          rs.Name,
			Prefix:        rs.Prefix,
			PoolAddresses: poolAddresses,
		})
	}
	return out
}

func buildNptv6Snapshots(cfg *config.Config) []Nptv6RuleSnapshot {
	if cfg == nil || len(cfg.Security.NAT.Static) == 0 {
		return nil
	}
	var out []Nptv6RuleSnapshot
	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || !rule.IsNPTv6 {
				continue
			}
			out = append(out, Nptv6RuleSnapshot{
				Name:           rule.Name,
				FromZone:       rs.FromZone,
				ExternalPrefix: rule.Match,
				InternalPrefix: rule.Then,
			})
		}
	}
	return out
}

// hasNonNptv6StaticNAT returns true if the config has any static NAT rules
// that are NOT NPTv6. NPTv6 rules are supported by the userspace dataplane.
func hasNonNptv6StaticNAT(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule != nil && !rule.IsNPTv6 {
				return true
			}
		}
	}
	return false
}

func buildScreenSnapshots(cfg *config.Config) []ScreenProfileSnapshot {
	if cfg == nil || len(cfg.Security.Screen) == 0 || len(cfg.Security.Zones) == 0 {
		return nil
	}
	var out []ScreenProfileSnapshot
	for _, zone := range cfg.Security.Zones {
		if zone == nil || zone.ScreenProfile == "" {
			continue
		}
		sp := cfg.Security.Screen[zone.ScreenProfile]
		if sp == nil {
			continue
		}
		snap := ScreenProfileSnapshot{
			Zone:        zone.Name,
			Land:        sp.TCP.Land,
			SynFin:      sp.TCP.SynFin,
			NoFlag:      sp.TCP.NoFlag,
			FinNoAck:    sp.TCP.FinNoAck,
			WinNuke:     sp.TCP.WinNuke,
			PingDeath:   sp.ICMP.PingDeath,
			Teardrop:    sp.IP.TearDrop,
			SourceRoute: sp.IP.SourceRouteOption,
		}
		if sp.ICMP.FloodThreshold > 0 {
			snap.ICMPFloodThreshold = uint32(sp.ICMP.FloodThreshold)
		}
		if sp.UDP.FloodThreshold > 0 {
			snap.UDPFloodThreshold = uint32(sp.UDP.FloodThreshold)
		}
		if sp.TCP.SynFlood != nil && sp.TCP.SynFlood.AttackThreshold > 0 {
			snap.SYNFloodThreshold = uint32(sp.TCP.SynFlood.AttackThreshold)
		}
		if sp.LimitSession.SourceIPBased > 0 {
			snap.SessionLimitSrc = uint32(sp.LimitSession.SourceIPBased)
		}
		if sp.LimitSession.DestinationIPBased > 0 {
			snap.SessionLimitDst = uint32(sp.LimitSession.DestinationIPBased)
		}
		if sp.TCP.PortScanThreshold > 0 {
			snap.PortScanThreshold = uint32(sp.TCP.PortScanThreshold)
		}
		if sp.IP.IPSweepThreshold > 0 {
			snap.IPSweepThreshold = uint32(sp.IP.IPSweepThreshold)
		}
		// Only include profiles that have at least one check enabled
		if snap.Land || snap.SynFin || snap.NoFlag || snap.FinNoAck ||
			snap.WinNuke || snap.PingDeath || snap.Teardrop ||
			snap.SourceRoute ||
			snap.ICMPFloodThreshold > 0 || snap.UDPFloodThreshold > 0 ||
			snap.SYNFloodThreshold > 0 ||
			snap.SessionLimitSrc > 0 || snap.SessionLimitDst > 0 ||
			snap.PortScanThreshold > 0 || snap.IPSweepThreshold > 0 {
			out = append(out, snap)
		}
	}
	return out
}

// userspaceSupportsScreenProfiles returns true if the configured screen
// profiles only use checks that the userspace dataplane implements.
// SYN cookies require eBPF-specific facilities and are not supported.
// Port scan detection, IP sweep detection, and per-IP session limiting
// are now implemented in the userspace dataplane.
func userspaceSupportsScreenProfiles(cfg *config.Config) bool {
	if cfg == nil || len(cfg.Security.Screen) == 0 {
		return true
	}
	if cfg.Security.Flow.SynFloodProtectionMode == "syn-cookie" {
		return false
	}
	return true
}

func buildFlowSnapshot(cfg *config.Config) FlowSnapshot {
	snap := FlowSnapshot{
		AllowDNSReply:      cfg.Security.Flow.AllowDNSReply,
		AllowEmbeddedICMP:  cfg.Security.Flow.AllowEmbeddedICMP,
		TCPMSSIPsecVPN:     cfg.Security.Flow.TCPMSSIPsecVPN,
		TCPMSSGreIn:        cfg.Security.Flow.TCPMSSGreIn,
		TCPMSSGreOut:       cfg.Security.Flow.TCPMSSGreOut,
		UDPSessionTimeout:  cfg.Security.Flow.UDPSessionTimeout,
		ICMPSessionTimeout: cfg.Security.Flow.ICMPSessionTimeout,
		GREAcceleration:    cfg.Security.Flow.GREPerformanceAcceleration,
		Lo0FilterInputV4:   cfg.System.Lo0FilterInputV4,
		Lo0FilterInputV6:   cfg.System.Lo0FilterInputV6,
	}
	if cfg.Security.Flow.TCPSession != nil {
		snap.TCPSessionTimeout = cfg.Security.Flow.TCPSession.EstablishedTimeout
	}
	return snap
}

func buildFlowExportSnapshot(cfg *config.Config) *FlowExportSnapshot {
	if cfg == nil || cfg.Services.FlowMonitoring == nil {
		return nil
	}
	fm := cfg.Services.FlowMonitoring
	if fm.Version9 == nil || len(fm.Version9.Templates) == 0 {
		return nil
	}
	// Find sampling config for flow server
	if cfg.ForwardingOptions.Sampling == nil {
		return nil
	}
	for _, inst := range cfg.ForwardingOptions.Sampling.Instances {
		if inst == nil {
			continue
		}
		rate := inst.InputRate
		if rate <= 0 {
			rate = 1
		}
		families := []*config.SamplingFamily{inst.FamilyInet, inst.FamilyInet6}
		for _, fam := range families {
			if fam == nil {
				continue
			}
			for _, server := range fam.FlowServers {
				if server == nil || server.Address == "" || server.Port == 0 {
					continue
				}
				snap := &FlowExportSnapshot{
					CollectorAddress: server.Address,
					CollectorPort:    server.Port,
					SamplingRate:     rate,
				}
				// Use template config if the server references one
				if server.Version9Template != "" && fm.Version9.Templates != nil {
					if tmpl, ok := fm.Version9.Templates[server.Version9Template]; ok {
						snap.ActiveTimeout = tmpl.FlowActiveTimeout
						snap.InactiveTimeout = tmpl.FlowInactiveTimeout
					}
				}
				return snap
			}
		}
	}
	return nil
}

func buildFirewallFilterSnapshots(cfg *config.Config) []FirewallFilterSnapshot {
	if cfg == nil {
		return nil
	}
	var out []FirewallFilterSnapshot
	// inet filters
	inetNames := make([]string, 0, len(cfg.Firewall.FiltersInet))
	for name := range cfg.Firewall.FiltersInet {
		inetNames = append(inetNames, name)
	}
	sort.Strings(inetNames)
	for _, name := range inetNames {
		filter := cfg.Firewall.FiltersInet[name]
		if filter == nil {
			continue
		}
		snap := FirewallFilterSnapshot{
			Name:   name,
			Family: "inet",
			Terms:  buildFilterTermSnapshots(filter, cfg),
		}
		out = append(out, snap)
	}
	// inet6 filters
	inet6Names := make([]string, 0, len(cfg.Firewall.FiltersInet6))
	for name := range cfg.Firewall.FiltersInet6 {
		inet6Names = append(inet6Names, name)
	}
	sort.Strings(inet6Names)
	for _, name := range inet6Names {
		filter := cfg.Firewall.FiltersInet6[name]
		if filter == nil {
			continue
		}
		snap := FirewallFilterSnapshot{
			Name:   name,
			Family: "inet6",
			Terms:  buildFilterTermSnapshots(filter, cfg),
		}
		out = append(out, snap)
	}
	return out
}

func buildFilterTermSnapshots(filter *config.FirewallFilter, cfg *config.Config) []FirewallTermSnapshot {
	if filter == nil || len(filter.Terms) == 0 {
		return nil
	}
	terms := make([]FirewallTermSnapshot, 0, len(filter.Terms))
	for _, term := range filter.Terms {
		if term == nil {
			continue
		}
		snap := FirewallTermSnapshot{
			Name:            term.Name,
			Action:          term.Action,
			Count:           term.Count,
			Log:             term.Log,
			PolicerName:     term.Policer,
			RoutingInstance: term.RoutingInstance,
			ForwardingClass: term.ForwardingClass,
		}
		// Source addresses (CIDRs)
		snap.SourceAddresses = append(snap.SourceAddresses, term.SourceAddresses...)
		// Destination addresses (CIDRs)
		snap.DestAddresses = append(snap.DestAddresses, term.DestAddresses...)
		// Protocols
		if term.Protocol != "" {
			snap.Protocols = []string{term.Protocol}
		}
		// Source ports
		snap.SourcePorts = append(snap.SourcePorts, term.SourcePorts...)
		// Destination ports
		snap.DestPorts = append(snap.DestPorts, term.DestinationPorts...)
		// DSCP
		if term.DSCP != "" {
			if val, ok := dataplane.DSCPValues[strings.ToLower(term.DSCP)]; ok {
				snap.DSCPValues = []uint8{val}
			} else if v, err := strconv.Atoi(term.DSCP); err == nil && v >= 0 && v <= 63 {
				snap.DSCPValues = []uint8{uint8(v)}
			}
		}
		// DSCP rewrite
		if term.DSCPRewrite != "" {
			if val, ok := dataplane.DSCPValues[strings.ToLower(term.DSCPRewrite)]; ok {
				snap.DSCPRewrite = val
			} else if v, err := strconv.Atoi(term.DSCPRewrite); err == nil && v >= 0 && v <= 63 {
				snap.DSCPRewrite = uint8(v)
			}
		}
		terms = append(terms, snap)
	}
	return terms
}

func buildPolicerSnapshots(cfg *config.Config) []PolicerSnapshot {
	if cfg == nil || len(cfg.Firewall.Policers) == 0 {
		return nil
	}
	names := make([]string, 0, len(cfg.Firewall.Policers))
	for name := range cfg.Firewall.Policers {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]PolicerSnapshot, 0, len(names))
	for _, name := range names {
		pol := cfg.Firewall.Policers[name]
		if pol == nil {
			continue
		}
		snap := PolicerSnapshot{
			Name:         name,
			BandwidthBps: pol.BandwidthLimit,
			BurstBytes:   pol.BurstSizeLimit,
		}
		if pol.ThenAction == "discard" {
			snap.DiscardExcess = true
		}
		out = append(out, snap)
	}
	return out
}

func buildPolicySnapshots(cfg *config.Config) []PolicyRuleSnapshot {
	if cfg == nil || (len(cfg.Security.Policies) == 0 && len(cfg.Security.GlobalPolicies) == 0) {
		return nil
	}
	out := make([]PolicyRuleSnapshot, 0)
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		for _, pol := range zpp.Policies {
			if pol == nil {
				continue
			}
			sourceAddresses, ok := expandUserspacePolicyAddresses(cfg, pol.Match.SourceAddresses)
			if !ok {
				sourceAddresses = append([]string(nil), pol.Match.SourceAddresses...)
			}
			destinationAddresses, ok := expandUserspacePolicyAddresses(cfg, pol.Match.DestinationAddresses)
			if !ok {
				destinationAddresses = append([]string(nil), pol.Match.DestinationAddresses...)
			}
			applicationTerms, ok := expandUserspacePolicyApplications(cfg, pol.Match.Applications)
			if !ok {
				applicationTerms = nil
			}
			out = append(out, PolicyRuleSnapshot{
				Name:                 pol.Name,
				FromZone:             zpp.FromZone,
				ToZone:               zpp.ToZone,
				SourceAddresses:      sourceAddresses,
				DestinationAddresses: destinationAddresses,
				Applications:         append([]string(nil), pol.Match.Applications...),
				ApplicationTerms:     applicationTerms,
				Action:               policyActionString(pol.Action),
			})
		}
	}
	// Global policies match traffic regardless of zone pair.
	for _, pol := range cfg.Security.GlobalPolicies {
		if pol == nil {
			continue
		}
		sourceAddresses, ok := expandUserspacePolicyAddresses(cfg, pol.Match.SourceAddresses)
		if !ok {
			sourceAddresses = append([]string(nil), pol.Match.SourceAddresses...)
		}
		destinationAddresses, ok := expandUserspacePolicyAddresses(cfg, pol.Match.DestinationAddresses)
		if !ok {
			destinationAddresses = append([]string(nil), pol.Match.DestinationAddresses...)
		}
		applicationTerms, ok := expandUserspacePolicyApplications(cfg, pol.Match.Applications)
		if !ok {
			applicationTerms = nil
		}
		out = append(out, PolicyRuleSnapshot{
			Name:                 pol.Name,
			FromZone:             "junos-global",
			ToZone:               "junos-global",
			SourceAddresses:      sourceAddresses,
			DestinationAddresses: destinationAddresses,
			Applications:         append([]string(nil), pol.Match.Applications...),
			ApplicationTerms:     applicationTerms,
			Action:               policyActionString(pol.Action),
		})
	}
	return out
}

func policyActionString(action config.PolicyAction) string {
	switch action {
	case config.PolicyPermit:
		return "permit"
	case config.PolicyReject:
		return "reject"
	default:
		return "deny"
	}
}

func buildNeighborSnapshots(cfg *config.Config) []NeighborSnapshot {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]NeighborSnapshot, 0)
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		iface := cfg.Interfaces.Interfaces[name]
		if iface == nil {
			continue
		}
		linuxNames := []string{snapshotLinuxName(cfg, name, iface, nil)}
		if len(iface.Units) > 0 {
			unitNums := make([]int, 0, len(iface.Units))
			for unitNum := range iface.Units {
				unitNums = append(unitNums, unitNum)
			}
			sort.Ints(unitNums)
			for _, unitNum := range unitNums {
				unit := iface.Units[unitNum]
				if unit == nil {
					continue
				}
				linuxNames = append(linuxNames, snapshotLinuxName(cfg, name, iface, unit))
			}
		}
		for _, linuxName := range linuxNames {
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
					if neigh.IP == nil {
						continue
					}
					key := fmt.Sprintf("%d/%s", link.Attrs().Index, neigh.IP.String())
					if seen[key] {
						continue
					}
					seen[key] = true
					fam := "inet"
					if family == netlink.FAMILY_V6 {
						fam = "inet6"
					}
					mac := ""
					if neigh.HardwareAddr != nil {
						mac = neigh.HardwareAddr.String()
					}
					out = append(out, NeighborSnapshot{
						Interface: linuxName,
						Ifindex:   link.Attrs().Index,
						Family:    fam,
						IP:        neigh.IP.String(),
						MAC:       mac,
						State:     neighborStateString(neigh.State),
						Router:    neigh.Flags&netlink.NTF_ROUTER != 0,
						LinkLocal: neigh.IP.IsLinkLocalUnicast(),
					})
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Interface != out[j].Interface {
			return out[i].Interface < out[j].Interface
		}
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].IP < out[j].IP
	})
	return out
}

func neighborStateString(state int) string {
	parts := make([]string, 0, 4)
	if state&netlink.NUD_PERMANENT != 0 {
		parts = append(parts, "permanent")
	}
	if state&netlink.NUD_REACHABLE != 0 {
		parts = append(parts, "reachable")
	}
	if state&netlink.NUD_STALE != 0 {
		parts = append(parts, "stale")
	}
	if state&netlink.NUD_DELAY != 0 {
		parts = append(parts, "delay")
	}
	if state&netlink.NUD_PROBE != 0 {
		parts = append(parts, "probe")
	}
	if state&netlink.NUD_FAILED != 0 {
		parts = append(parts, "failed")
	}
	if state&netlink.NUD_NOARP != 0 {
		parts = append(parts, "noarp")
	}
	if state&netlink.NUD_INCOMPLETE != 0 {
		parts = append(parts, "incomplete")
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, "|")
}

func (m *Manager) ensureProcessLocked(cfg config.UserspaceConfig) error {
	tuneSocketBuffers()
	if m.proc != nil && m.proc.Process != nil && configEqual(m.cfg, cfg) {
		if err := m.requestLocked(ControlRequest{Type: "ping"}, nil); err == nil {
			return nil
		}
		slog.Warn("userspace dataplane helper unhealthy, restarting")
		m.stopLocked()
	}
	if m.proc != nil {
		m.stopLocked()
	}
	m.lastStatus = ProcessStatus{}
	binary, err := findBinary(cfg.Binary)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.ControlSocket), 0755); err != nil {
		return fmt.Errorf("mkdir control socket dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.StateFile), 0755); err != nil {
		return fmt.Errorf("mkdir state dir: %w", err)
	}
	_ = os.Remove(cfg.ControlSocket)
	// Start the event stream listener before spawning the helper so it
	// can connect immediately.
	evtPath := cfg.EventSocket
	if evtPath == "" {
		evtPath = filepath.Join(filepath.Dir(cfg.ControlSocket), "userspace-dp-events.sock")
	}
	_ = os.Remove(evtPath)
	es := NewEventStream(evtPath)
	esCtx, esCancel := context.WithCancel(context.Background())
	es.Start(esCtx)
	m.eventStream = es
	m.eventStreamCancel = esCancel
	// Clear stale XSKMAP entries from previous helper instance.
	// Old entries point to dead socket fds; new helper will repopulate.
	if xskMap := m.inner.Map("userspace_xsk_map"); xskMap != nil {
		for i := uint32(0); i < 4096; i++ {
			_ = xskMap.Delete(i)
		}
		slog.Debug("userspace: cleared stale XSKMAP entries")
	}
	pollMode := cfg.PollMode
	if pollMode == "" {
		pollMode = "busy-poll"
	}
	cmd := exec.Command(binary,
		"--control-socket", cfg.ControlSocket,
		"--state-file", cfg.StateFile,
		"--workers", fmt.Sprintf("%d", cfg.Workers),
		"--ring-entries", fmt.Sprintf("%d", cfg.RingEntries),
		"--poll-mode", pollMode,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start userspace dataplane helper: %w", err)
	}
	m.cfg = cfg
	m.proc = cmd
	// Bootstrap XSK fill ring on all queues: send broadcast pings
	// 3 seconds after helper start. During this window, ctrl is disabled
	// so the XDP shim falls back to eBPF. The broadcast pings generate
	// hardware RX events on multiple queues, triggering NAPI which
	// consumes fill ring entries and posts WQEs for zero-copy.
	go func() {
		time.Sleep(3 * time.Second)
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.proc == nil {
			return
		}
		m.bootstrapNAPIQueuesAsyncLocked("startup")
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(cfg.ControlSocket); err == nil {
			if err := m.requestLocked(ControlRequest{Type: "ping"}, nil); err == nil {
				slog.Info("userspace dataplane helper started", "pid", cmd.Process.Pid, "socket", cfg.ControlSocket)
				return nil
			}
		}
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	m.stopLocked()
	return fmt.Errorf("userspace dataplane helper did not become ready at %s", cfg.ControlSocket)
}

// tuneSocketBuffers raises the kernel socket buffer limits so AF_XDP copy-mode
// sockets can receive at line rate.  The default rmem_default (212992 = 208KB)
// is far too small — copy-mode XSK pushes each packet through the socket
// receive buffer and silently drops when it fills, causing throughput to stall
// after an initial burst.
func tuneSocketBuffers() {
	const desired = 67108864 // 64 MB
	paths := []string{
		"/proc/sys/net/core/rmem_default",
		"/proc/sys/net/core/rmem_max",
		"/proc/sys/net/core/wmem_default",
		"/proc/sys/net/core/wmem_max",
	}
	for _, path := range paths {
		cur, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var curVal int
		if _, err := fmt.Sscanf(strings.TrimSpace(string(cur)), "%d", &curVal); err != nil {
			continue
		}
		if curVal >= desired {
			continue
		}
		val := fmt.Sprintf("%d", desired)
		if err := os.WriteFile(path, []byte(val), 0644); err != nil {
			slog.Warn("failed to tune socket buffer", "path", path, "err", err)
		} else {
			slog.Info("tuned socket buffer for AF_XDP", "path", path, "from", curVal, "to", desired)
		}
	}
}

func findBinary(explicit string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err == nil {
			return explicit, nil
		}
		return "", fmt.Errorf("userspace dataplane binary not found: %s", explicit)
	}
	candidates := []string{
		"./bpfrx-userspace-dp",
		filepath.Join("userspace-dp", "target", "release", "bpfrx-userspace-dp"),
		filepath.Join(filepath.Dir(os.Args[0]), "bpfrx-userspace-dp"),
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	if p, err := exec.LookPath("bpfrx-userspace-dp"); err == nil {
		return p, nil
	}
	return "", errors.New("userspace dataplane helper binary not found; build ./cmd/bpfrx-userspace-dp or configure system dataplane binary")
}

func (m *Manager) requestDetailedLocked(req ControlRequest) (ControlResponse, error) {
	if m.cfg.ControlSocket == "" {
		return ControlResponse{}, errors.New("userspace dataplane control socket not configured")
	}
	conn, err := net.DialTimeout("unix", m.cfg.ControlSocket, 2*time.Second)
	if err != nil {
		return ControlResponse{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := json.NewEncoder(conn).Encode(&req); err != nil {
		return ControlResponse{}, err
	}
	var resp ControlResponse
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		return ControlResponse{}, err
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "unknown helper error"
		}
		return ControlResponse{}, errors.New(resp.Error)
	}
	return resp, nil
}

// sessionSocketPath returns the path to the dedicated session sync socket.
func (m *Manager) sessionSocketPath() string {
	if m.cfg.ControlSocket == "" {
		return ""
	}
	dir := filepath.Dir(m.cfg.ControlSocket)
	return filepath.Join(dir, "userspace-dp-sessions.sock")
}

// requestSessionSync sends a session sync request via the dedicated session
// socket, using sessionMu instead of mu. This ensures session installs from
// HA sync never block behind snapshot publishes on the main control socket.
func (m *Manager) requestSessionSync(req ControlRequest) error {
	sockPath := m.sessionSocketPath()
	if sockPath == "" {
		return errors.New("session socket not configured")
	}
	m.sessionMu.Lock()
	defer m.sessionMu.Unlock()
	conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := json.NewEncoder(conn).Encode(&req); err != nil {
		return err
	}
	var resp ControlResponse
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		return err
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "unknown helper error"
		}
		return errors.New(resp.Error)
	}
	return nil
}

func (m *Manager) syncSnapshotLocked() error {
	if m.proc == nil || m.proc.Process == nil || m.lastSnapshot == nil {
		return nil
	}
	planKey := snapshotBindingPlanKey(m.lastSnapshot)
	if m.publishedSnapshot >= m.lastSnapshot.Generation {
		return nil
	}
	if m.lastStatus.LastSnapshotGeneration >= m.lastSnapshot.Generation {
		m.publishedSnapshot = m.lastStatus.LastSnapshotGeneration
		return nil
	}
	// Publish the initial snapshot immediately so the helper can plan its
	// bindings. After that, defer newer snapshots until the first XSK
	// liveness outcome is known. HA startup can emit several snapshots in
	// quick succession as VIPs and routes converge; pushing every one of
	// them forces back-to-back full AF_XDP reconciles and self-collides.
	//
	// EXCEPTION: allow same-plan refreshes (FIB-only updates) through even
	// during XSK startup. These don't trigger XSK rebinding — they only
	// update routes and neighbors. Blocking them creates a deadlock: XSK
	// liveness needs RX traffic, but transit traffic needs FIB data that
	// hasn't been published yet.
	if m.publishedSnapshot != 0 && !m.xskLivenessProven && !m.xskLivenessFailed {
		samePlan := m.publishedPlanKey != "" && m.publishedPlanKey == planKey
		if !samePlan {
			return nil
		}
		slog.Info("userspace: publishing deferred same-plan snapshot during XSK startup",
			"generation", m.lastSnapshot.Generation,
			"fib_generation", m.lastSnapshot.FIBGeneration,
			"published", m.publishedSnapshot)
	}
	if m.publishedSnapshot != 0 && m.publishedPlanKey != "" && m.publishedPlanKey != planKey {
		slog.Info(
			"userspace: restarting helper for binding plan change",
			"generation", m.lastSnapshot.Generation,
			"fib_generation", m.lastSnapshot.FIBGeneration,
		)
		cfg := m.cfg
		m.stopLocked()
		if err := m.ensureProcessLocked(cfg); err != nil {
			return fmt.Errorf("restart userspace helper for binding plan change: %w", err)
		}
	}
	// Content-hash dedup: skip the control socket publish if the snapshot's
	// forwarding-relevant content hasn't changed since the last publish.
	// This eliminates redundant publishes during route convergence where
	// BumpFIBGeneration fires repeatedly but routes/neighbors are unchanged.
	hash, hashOK := snapshotContentHash(m.lastSnapshot)
	if hashOK && hash == m.lastSnapshotHash && m.publishedSnapshot != 0 {
		// Still update the published generation so subsequent checks pass.
		m.publishedSnapshot = m.lastSnapshot.Generation
		return nil
	}
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "apply_snapshot", Snapshot: m.lastSnapshot}, &status); err != nil {
		return fmt.Errorf("publish userspace snapshot: %w", err)
	}
	m.publishedSnapshot = m.lastSnapshot.Generation
	m.publishedPlanKey = planKey
	if hashOK {
		m.lastSnapshotHash = hash
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		return fmt.Errorf("sync helper status: %w", err)
	}
	return nil
}

func (m *Manager) requestLocked(req ControlRequest, status *ProcessStatus) error {
	resp, err := m.requestDetailedLocked(req)
	if err != nil {
		return err
	}
	if status != nil && resp.Status != nil {
		*status = *resp.Status
	}
	return nil
}

type userspaceCtrlValue struct {
	Enabled            uint32
	MetadataVersion    uint32
	Workers            uint32
	QueueCount         uint32
	Flags              uint32
	Pad                uint32
	ConfigGeneration   uint64
	FIBGeneration      uint32
	HeartbeatTimeoutMS uint32
}

const userspaceMetadataVersion = 4
const userspaceCtrlFlagCPUMap = 1
const userspaceCtrlFlagTrace = 2
const userspaceCtrlFlagNativeGRE = 4
const userspaceCtrlFlagStrict = 8
const bindingQueuesPerIface = 16 // must match BINDING_QUEUES_PER_IFACE in BPF

func (m *Manager) programBootstrapMapsLocked(snapshot *ConfigSnapshot, cfg config.UserspaceConfig) error {
	ctrlMap := m.inner.Map("userspace_ctrl")
	if ctrlMap == nil {
		return errors.New("userspace_ctrl map not loaded")
	}
	bindingsMap := m.inner.Map("userspace_bindings")
	if bindingsMap == nil {
		return errors.New("userspace_bindings map not loaded")
	}
	heartbeatMap := m.inner.Map("userspace_heartbeat")
	if heartbeatMap == nil {
		return errors.New("userspace_heartbeat map not loaded")
	}
	fallbackMap := m.inner.Map("userspace_fallback_progs")
	if fallbackMap == nil {
		return errors.New("userspace_fallback_progs map not loaded")
	}
	fallbackProg := m.inner.Program("xdp_main_prog")
	if fallbackProg == nil {
		return errors.New("xdp_main_prog not loaded")
	}

	// Populate userspace_cpumap so the XDP shim can use cpumap redirect
	// instead of XDP_PASS (required for zero-copy AF_XDP).
	cpumapReady := m.setupUserspaceCPUMapLocked()

	zero := uint32(0)
	var ctrlFlags uint32
	if cpumapReady {
		ctrlFlags |= userspaceCtrlFlagCPUMap
	}
	if snapshotHasNativeGRE(snapshot) {
		ctrlFlags |= userspaceCtrlFlagNativeGRE
	}
	ctrl := userspaceCtrlValue{
		Enabled:            0,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            uint32(cfg.Workers),
		QueueCount:         uint32(maxInt(cfg.Workers, 1)),
		Flags:              ctrlFlags,
		ConfigGeneration:   0,
		FIBGeneration:      0,
		HeartbeatTimeoutMS: 30000,
	}
	if err := ctrlMap.Update(zero, ctrl, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update userspace_ctrl: %w", err)
	}
	fallbackFD := uint32(fallbackProg.FD())
	if err := fallbackMap.Update(zero, fallbackFD, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update userspace_fallback_progs: %w", err)
	}

	// Bindings map is now an Array — zero previously-set indices.
	{
		var zeroBinding userspaceBindingValue
		for _, idx := range m.lastBindingIndices {
			_ = bindingsMap.Update(idx, zeroBinding, ebpf.UpdateAny)
		}
		m.lastBindingIndices = nil
	}
	// Heartbeat map is now an Array — zero used slots instead of deleting.
	// Slots with value 0 appear as stale (bpf_ktime_get_ns() >> 0) so the
	// XDP shim correctly refuses to redirect until userspace begins updating.
	{
		var zeroHB uint64
		for slot := uint32(0); slot < uint32(cfg.Workers)*2*16; slot++ {
			_ = heartbeatMap.Update(slot, zeroHB, ebpf.UpdateAny)
		}
	}
	if err := m.syncIngressIfaceMapLocked(snapshot); err != nil {
		return err
	}
	if err := m.syncLocalAddressMapsLocked(snapshot); err != nil {
		return err
	}
	return m.syncInterfaceNATAddressMapsLocked(snapshot)
}

// setupUserspaceCPUMapLocked populates the userspace_cpumap BPF map with one
// entry per online CPU. This enables the XDP shim to use cpumap redirect
// instead of XDP_PASS, which is required for zero-copy AF_XDP (XDP_PASS in
// zero-copy mode permanently leaks UMEM frames).
func (m *Manager) setupUserspaceCPUMapLocked() bool {
	cpuMap := m.inner.Map("userspace_cpumap")
	if cpuMap == nil {
		slog.Warn("userspace_cpumap not found, zero-copy cpumap redirect disabled")
		return false
	}

	numCPUs := runtime.NumCPU()
	if numCPUs > 256 {
		numCPUs = 256
	}

	// cpumap value: struct { __u32 qsize; int bpf_prog_fd; }
	// cpumap value: struct { __u32 qsize; int bpf_prog_fd; }
	// With prog_fd=0, no cpumap program is attached — packets go to kernel.
	// TODO: attach xdp_cpumap_prog for eBPF embedded ICMP NAT reversal.
	for cpu := 0; cpu < numCPUs; cpu++ {
		val := make([]byte, 8)
		binary.NativeEndian.PutUint32(val[0:4], 2048) // qsize
		binary.NativeEndian.PutUint32(val[4:8], 0)    // no attached program
		if err := cpuMap.Update(uint32(cpu), val, ebpf.UpdateAny); err != nil {
			slog.Warn("userspace_cpumap update failed", "cpu", cpu, "err", err)
			return false
		}
	}

	slog.Info("userspace cpumap enabled for zero-copy AF_XDP", "cpus", numCPUs)
	return true
}

func (m *Manager) applyHelperStatusLocked(status *ProcessStatus) error {
	ctrlMap := m.inner.Map("userspace_ctrl")
	if ctrlMap == nil {
		return errors.New("userspace_ctrl map not loaded")
	}
	bindingsMap := m.inner.Map("userspace_bindings")
	if bindingsMap == nil {
		return errors.New("userspace_bindings map not loaded")
	}

	var newBindingIndices []uint32
	newBindingIndexSet := make(map[uint32]struct{})

	// Preserve cpumap flag if cpumap is populated.
	var ctrlFlags uint32
	if cpuMap := m.inner.Map("userspace_cpumap"); cpuMap != nil {
		ctrlFlags |= userspaceCtrlFlagCPUMap
	}
	if snapshotHasNativeGRE(m.lastSnapshot) {
		ctrlFlags |= userspaceCtrlFlagNativeGRE
	}

	zero := uint32(0)
	ctrl := userspaceCtrlValue{
		Enabled:            0,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            uint32(maxInt(status.Workers, 1)),
		QueueCount:         uint32(queueCountFromBindings(status.Bindings)),
		Flags:              ctrlFlags,
		ConfigGeneration:   status.LastSnapshotGeneration,
		FIBGeneration:      status.LastFIBGeneration,
		HeartbeatTimeoutMS: 30000,
	}
	if status.Enabled && m.rgTransitionInFlight.Load() {
		// One or more RG transitions are in progress and the helper hasn't
		// acked the HA state update yet. Keep ctrl disabled until
		// syncHAStateLocked succeeds to avoid re-enabling ctrl during the
		// handoff (#279, #284).
		ctrl.Enabled = 0
	} else if status.Enabled {
		// Delay ctrl enable until AFTER VIPs are configured in HA mode.
		// The VRRP election + VIP add takes ~10-14s after restart.
		// If we enable ctrl before VIPs, the XSK path gets packets but
		// can't SNAT (no source address) → all transit dropped.  The
		// eBPF pipeline (XDP_PASS fallback) handles traffic correctly
		// during this window since the kernel has the same FIB state.
		//
		// Also delay by 3s for fill ring bootstrap: mlx5 zero-copy
		// needs NAPI to post fill ring WQEs, and NAPI only runs on
		// hardware RX events.  Background traffic (VRRP, ARP) during
		// the delay generates these events.
		if !m.neighborsPrewarmed {
			m.neighborsPrewarmed = true
			// Hard timeout fallback — ctrl enables after this even if
			// readiness checks haven't passed. Prevents infinite stall
			// if a readiness condition can never be met.
			//
			// Only set ctrlEnableAt on the FIRST prewarm so that
			// subsequent rebind cycles (which reset neighborsPrewarmed)
			// don't push the hard timeout forward indefinitely.
			if m.ctrlEnableAt.IsZero() {
				delay := 3 * time.Second
				if m.clusterHA {
					delay = 15 * time.Second
				}
				m.ctrlEnableAt = time.Now().Add(delay)
				slog.Info("userspace: delaying ctrl enable for readiness",
					"hard_timeout", delay, "cluster_ha", m.clusterHA)
			}
			m.bootstrapNAPIQueuesAsyncLocked("startup-prewarm")
			m.proactiveNeighborResolveLocked()
		}
		// Check readiness gates BEFORE refreshing neighbors (which
		// bumps the generation). The status reports the generation
		// from the previous refresh cycle.
		//
		// The helper can only prove RX liveness after ctrl enables the
		// shim and the userspace_bindings map exposes the binding slots.
		// Requiring Bound here deadlocks startup: ctrl stays off, the shim
		// keeps passing packets away from XSK, and Bound never flips true.
		probeBindingsReady := len(status.Bindings) > 0
		allBindingsBound := len(status.Bindings) > 0
		for _, b := range status.Bindings {
			if b.Ifindex <= 0 {
				continue
			}
			if !b.Registered || !b.Armed {
				probeBindingsReady = false
			}
			if b.Registered && !b.Bound {
				allBindingsBound = false
			}
		}
		// Fire OnXSKBound callback once when all bindings are bound.
		// This lets the daemon create fabric IPVLAN overlays after XSK
		// has bound in zerocopy mode on the parent interface.
		if allBindingsBound && !m.xskBoundNotified && m.OnXSKBound != nil {
			m.xskBoundNotified = true
			go m.OnXSKBound()
		}

		neighborSyncReady := status.NeighborGeneration > 0

		// XSK receive liveness: once bindings and neighbor state are ready,
		// arm ctrl and explicitly probe the userspace shim. A working XSK
		// path must show RX progress while ctrl=1 and the shim is active.
		// Otherwise swap back to the eBPF pipeline instead of assuming
		// the userspace AF_XDP path is healthy.
		var currentRX uint64
		for _, b := range status.Bindings {
			currentRX += b.RXPackets
		}
		xskReceiveLive := currentRX > m.lastXSKRX
		m.lastXSKRX = currentRX
		slog.Debug("userspace: ctrl gate check",
			"probeBindingsReady", probeBindingsReady,
			"allBindingsBound", allBindingsBound,
			"neighborSyncReady", neighborSyncReady,
			"xskReceiveLive", xskReceiveLive,
			"currentRX", currentRX,
			"lastXSKRX", m.lastXSKRX,
			"neighborsPrewarmed", m.neighborsPrewarmed,
			"xskLivenessFailed", m.xskLivenessFailed,
			"xdpEntryProg", m.inner.XDPEntryProg)
		if m.xskLivenessFailed {
			// XSK proven broken — ctrl disabled.
			// In compat mode, the entry program was already swapped to
			// xdp_main_prog (eBPF pipeline). In strict mode the shim
			// stays attached so packets drop rather than silently
			// falling through to eBPF.
			ctrl.Enabled = 0
		} else if probeBindingsReady && neighborSyncReady {
			ctrl.Enabled = 1
			if m.xskLivenessProven {
				if m.inner.XDPEntryProg != "xdp_userspace_prog" {
					if err := m.inner.SwapXDPEntryProg("xdp_userspace_prog"); err != nil {
						slog.Warn("userspace: failed to restore XDP shim after liveness success", "err", err)
					}
				}
			} else if xskReceiveLive {
				m.xskLivenessProven = true
				m.xskProbeStart = time.Time{}
				if m.inner.XDPEntryProg != "xdp_userspace_prog" {
					if err := m.inner.SwapXDPEntryProg("xdp_userspace_prog"); err != nil {
						slog.Warn("userspace: failed to swap XDP shim after XSK RX became live", "err", err)
					}
				}
				slog.Info("userspace: XSK liveness proven")
			} else {
				if m.inner.XDPEntryProg != "xdp_userspace_prog" {
					if err := m.inner.SwapXDPEntryProg("xdp_userspace_prog"); err != nil {
						slog.Warn("userspace: failed to activate XDP shim for XSK liveness probe", "err", err)
					}
				}
				if m.xskProbeStart.IsZero() {
					m.xskProbeStart = time.Now()
					slog.Info("userspace: starting XSK liveness probe")
				} else if time.Now().After(m.xskProbeStart.Add(10 * time.Second)) {
					if m.shouldExtendXSKLivenessIdleLocked(currentRX, allBindingsBound) {
						m.xskProbeStart = time.Now()
						slog.Info("userspace: extending XSK liveness probe while idle")
						goto ctrlReady
					}
					m.xskLivenessFailed = true
					m.xskProbeStart = time.Time{}
					ctrl.Enabled = 0
					if m.configuredMode == ModeUserspaceStrict {
						// Strict mode: do NOT swap to xdp_main_prog.
						// Keep the shim attached with ctrl=0 so packets
						// hit the shim's ctrl-disabled fallback path and
						// get counted, but never silently enter the eBPF
						// pipeline. Log at error level — this is a
						// degraded state that needs operator attention.
						slog.Error("userspace: XSK liveness probe failed in strict mode — dataplane degraded, no eBPF fallback")
					} else {
						slog.Warn("userspace: XSK liveness probe failed, falling back to eBPF pipeline")
						if err := m.inner.SwapXDPEntryProg("xdp_main_prog"); err != nil {
							slog.Warn("userspace: failed to swap to eBPF pipeline after XSK liveness failure", "err", err)
						}
					}
				}
			}
		} else if !m.ctrlEnableAt.IsZero() && time.Now().After(m.ctrlEnableAt.Add(60*time.Second)) {
			// Hard timeout fallback: allow ctrl even if readiness has not been
			// fully proven yet. The XSK liveness probe still decides whether
			// the userspace shim stays active or we fall back to xdp_main.
			ctrl.Enabled = 1
		} else {
			ctrl.Enabled = 0
		}
	}
ctrlReady:
	// Flush stale BPF session entries when ctrl transitions from
	// disabled to enabled. During ctrl-disabled, the eBPF pipeline
	// creates PASS_TO_KERNEL entries in the userspace session map.
	// These poison the XDP shim after ctrl enables — it sees the stale
	// entry and bypasses XSK, routing packets to the eBPF pipeline
	// instead of the userspace helper.
	//
	// Also flush BPF conntrack sessions created by the eBPF pipeline
	// during the ctrl-disabled window. These sessions interfere with
	// the userspace pipeline via TC egress: when the Rust helper sends
	// packets via XSK TX, TC egress finds the stale BPF conntrack
	// entries and may apply conflicting NAT or update session state
	// incorrectly. The userspace helper's own session table (Rust
	// SessionTable + shared_sessions) holds the authoritative synced
	// sessions — BPF conntrack must be empty when ctrl re-enables.
	if ctrl.Enabled == 1 && !m.ctrlWasEnabled {
		if usMap := m.inner.Map("userspace_sessions"); usMap != nil {
			var key, nextKey []byte
			key = make([]byte, usMap.KeySize())
			nextKey = make([]byte, usMap.KeySize())
			deleted := 0
			for {
				if err := usMap.NextKey(key, nextKey); err != nil {
					break
				}
				copy(key, nextKey)
				_ = usMap.Delete(key)
				deleted++
			}
			if deleted > 0 {
				slog.Info("userspace: flushed stale BPF session entries on ctrl enable",
					"deleted", deleted)
			}
		}
		// Flush BPF conntrack sessions created by the eBPF pipeline
		// during the ctrl-disabled transition window. Only delete
		// sessions whose Created timestamp is AFTER ctrlDisabledAt —
		// synced sessions from the cluster peer have earlier timestamps
		// and must survive for HA failover continuity.
		//
		// Why this is needed (issue #334): when ctrl=0 (startup, XSK
		// liveness probe, link cycle), the eBPF pipeline creates
		// conntrack entries in the BPF sessions map. When ctrl
		// re-enables, TC egress finds these stale BPF entries and
		// may apply conflicting NAT or update session state
		// incorrectly — the userspace helper's own session table
		// (Rust SessionTable + shared_sessions) is authoritative.
		//
		// session_value layout: State[1]+Flags[1]+TCPState[1]+
		// IsReverse[1]+AppTimeout[4]+SessionID[8]+Created[8].
		// Created is at byte offset 16. The value is seconds since
		// boot (bpf_ktime_get_coarse_ns / 1e9). ctrlDisabledAt is
		// nanoseconds, so convert to seconds for comparison.
		cutoffSec := m.ctrlDisabledAt / 1_000_000_000
		for _, mapName := range []string{"sessions", "sessions_v6"} {
			if ctMap := m.inner.Map(mapName); ctMap != nil {
				keySize := ctMap.KeySize()
				valSize := ctMap.ValueSize()
				var key, nextKey []byte
				key = make([]byte, keySize)
				nextKey = make([]byte, keySize)
				val := make([]byte, valSize)
				deleted, kept := 0, 0
				for {
					if err := ctMap.NextKey(key, nextKey); err != nil {
						break
					}
					copy(key, nextKey)
					// Read session value to check Created timestamp.
					// Created is at byte offset 16:
					//   State(1) + Flags(1) + TCPState(1) + IsReverse(1)
					//   + AppTimeout(4) + SessionID(8) = 16
					if cutoffSec > 0 {
						if err := ctMap.Lookup(key, val); err == nil && len(val) >= 24 {
							created := binary.NativeEndian.Uint64(val[16:24])
							if created > 0 && created <= cutoffSec {
								kept++
								continue // synced session — keep it
							}
						}
					}
					_ = ctMap.Delete(key)
					deleted++
				}
				if deleted > 0 || kept > 0 {
					slog.Info("userspace: flushed stale BPF conntrack on ctrl enable",
						"map", mapName, "deleted", deleted, "kept_synced", kept,
						"cutoff_sec", cutoffSec)
				}
			}
		}
	}
	if ctrl.Enabled == 0 && m.ctrlWasEnabled {
		m.ctrlDisabledAt = m.bpfKtimeNs()
	}
	m.ctrlWasEnabled = ctrl.Enabled == 1

	// Compute active runtime mode from ctrl state and liveness.
	switch {
	case ctrl.Enabled == 0 || m.xskLivenessFailed:
		// In strict mode, a degraded userspace path still implies the strict
		// shim is attached and fail-closed, not eBPF-only forwarding.
		if m.configuredMode == ModeUserspaceStrict {
			m.mode = ModeUserspaceStrict
		} else {
			m.mode = ModeEBPFOnly
		}
	case m.xskLivenessProven && m.configuredMode == ModeUserspaceStrict:
		m.mode = ModeUserspaceStrict
	case m.xskLivenessProven:
		m.mode = ModeUserspaceCompat
	default:
		// ctrl enabled but liveness not yet proven — still probing.
		m.mode = ModeUserspaceCompat
	}
	// Set strict flag in ctrl so the XDP shim knows not to fall back.
	if m.configuredMode == ModeUserspaceStrict {
		ctrl.Flags |= userspaceCtrlFlagStrict
	}

	if err := ctrlMap.Update(zero, ctrl, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update userspace_ctrl from helper status: %w", err)
	}

	for _, binding := range status.Bindings {
		if binding.Ifindex <= 0 {
			continue
		}
		flags := uint32(0)
		if binding.Registered && binding.Armed {
			// Mark ready once registered + armed. Don't wait for Bound:
			// the Bound flag is set asynchronously by worker threads
			// after XSK socket creation. Waiting creates a chicken-and-egg
			// where the XDP shim drops packets (flags=0) preventing the
			// XSK socket from ever receiving (so Bound never becomes true).
			flags = userspaceBindingReady
		}
		idx := uint32(binding.Ifindex)*bindingQueuesPerIface + binding.QueueID
		val := userspaceBindingValue{
			Slot:  binding.Slot,
			Flags: flags,
		}
		if err := bindingsMap.Update(idx, val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update userspace_bindings idx=%d (if=%d q=%d): %w", idx, binding.Ifindex, binding.QueueID, err)
		}
		if _, seen := newBindingIndexSet[idx]; !seen {
			newBindingIndexSet[idx] = struct{}{}
			newBindingIndices = append(newBindingIndices, idx)
		}
	}
	for childIfindex, parentIfindex := range buildUserspaceIngressBindingAliases(m.lastSnapshot) {
		for _, binding := range status.Bindings {
			if binding.Ifindex != int(parentIfindex) {
				continue
			}
			flags := uint32(0)
			if binding.Registered && binding.Armed && binding.Bound {
				flags = userspaceBindingReady
			}
			idx := childIfindex*bindingQueuesPerIface + binding.QueueID
			val := userspaceBindingValue{
				Slot:  binding.Slot,
				Flags: flags,
			}
			if err := bindingsMap.Update(idx, val, ebpf.UpdateAny); err != nil {
				return fmt.Errorf(
					"update aliased userspace_bindings idx=%d (if=%d parent=%d q=%d): %w",
					idx,
					childIfindex,
					parentIfindex,
					binding.QueueID,
					err,
				)
			}
			if _, seen := newBindingIndexSet[idx]; !seen {
				newBindingIndexSet[idx] = struct{}{}
				newBindingIndices = append(newBindingIndices, idx)
			}
		}
	}
	{
		var zeroBinding userspaceBindingValue
		for _, idx := range m.lastBindingIndices {
			if _, keep := newBindingIndexSet[idx]; keep {
				continue
			}
			_ = bindingsMap.Update(idx, zeroBinding, ebpf.UpdateAny)
		}
		m.lastBindingIndices = newBindingIndices
	}
	if err := m.syncIngressIfaceMapLocked(m.lastSnapshot); err != nil {
		return err
	}
	if err := m.syncLocalAddressMapsLocked(m.lastSnapshot); err != nil {
		return err
	}
	if err := m.syncInterfaceNATAddressMapsLocked(m.lastSnapshot); err != nil {
		return err
	}
	// Sync userspace-forwarded packet counters into BPF counter maps so
	// that ReadGlobalCounter/ReadZoneCounters/etc. return complete values
	// even for packets that bypassed the BPF pipeline (#332).
	m.syncBPFCountersLocked(status)

	// Populate runtime mode and observability fields in status.
	status.DataplaneMode = m.mode.String()
	status.ConfiguredMode = m.configuredMode.String()
	status.EntryPrograms = m.entryProgramsLocked()
	status.FallbackCounters = m.readFallbackStatsLocked()

	m.lastStatus = *status
	return nil
}

// userspaceCounterSnapshot holds cumulative counter totals from the helper,
// used to compute deltas between status polls.

// fallbackReasonNames maps BPF array index to a human-readable name.
// Must stay in sync with USERSPACE_FALLBACK_REASON_* in userspace-xdp/src/lib.rs.
var fallbackReasonNames = [16]string{
	0:  "ctrl_disabled",
	1:  "parse_fail",
	2:  "binding_missing",
	3:  "binding_not_ready",
	4:  "heartbeat_missing",
	5:  "heartbeat_stale",
	6:  "icmp",
	7:  "early_filter",
	8:  "adjust_meta",
	9:  "meta_bounds",
	10: "redirect_err",
	11: "interface_nat_no_session",
	12: "no_session",
	13: "strict_drop",
	14: "pass_to_kernel",
}

// readFallbackStatsLocked reads the userspace_fallback_stats BPF array map
// and returns a map of reason name -> cumulative count. Entries with zero
// count are omitted.
func (m *Manager) readFallbackStatsLocked() map[string]uint64 {
	statsMap := m.inner.Map("userspace_fallback_stats")
	if statsMap == nil {
		return nil
	}
	result := make(map[string]uint64)
	for i := uint32(0); i < uint32(len(fallbackReasonNames)); i++ {
		var val uint64
		if err := statsMap.Lookup(i, &val); err != nil {
			continue
		}
		if val == 0 {
			continue
		}
		name := fallbackReasonNames[i]
		if name == "" {
			name = fmt.Sprintf("reason_%d", i)
		}
		result[name] = val
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// entryProgramsLocked returns a map of ifindex -> attached XDP program name
// by inspecting the inner dataplane manager's link state.
// Note: VLAN sub-interfaces are skipped during SwapXDPEntryProg and may
// retain the parent's program; they are excluded from this map.
func (m *Manager) entryProgramsLocked() map[int]string {
	links := m.inner.XDPLinks()
	if len(links) == 0 {
		return nil
	}
	progName := m.inner.XDPEntryProg
	result := make(map[int]string, len(links))
	for ifindex := range links {
		if m.inner.VlanSubInterfaces[ifindex] {
			continue // VLAN sub-interfaces use parent's XDP program
		}
		result[ifindex] = progName
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func (m *Manager) syncIngressIfaceMapLocked(snapshot *ConfigSnapshot) error {
	ifaceMap := m.inner.Map("userspace_ingress_ifaces")
	if ifaceMap == nil {
		return errors.New("userspace_ingress_ifaces map not loaded")
	}

	newIngress := buildUserspaceIngressIfindexes(snapshot)
	newIngressSet := make(map[uint32]struct{}, len(newIngress))
	for _, ifindex := range newIngress {
		newIngressSet[ifindex] = struct{}{}
		if err := ifaceMap.Update(ifindex, uint8(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update userspace_ingress_ifaces %d: %w", ifindex, err)
		}
	}
	for _, k := range m.lastIngressIfaces {
		if _, keep := newIngressSet[k]; keep {
			continue
		}
		_ = ifaceMap.Update(k, uint8(0), ebpf.UpdateAny)
	}
	m.lastIngressIfaces = newIngress
	return nil
}

func (m *Manager) syncLocalAddressMapsLocked(snapshot *ConfigSnapshot) error {
	localV4Map := m.inner.Map("userspace_local_v4")
	if localV4Map == nil {
		return errors.New("userspace_local_v4 map not loaded")
	}
	localV6Map := m.inner.Map("userspace_local_v6")
	if localV6Map == nil {
		return errors.New("userspace_local_v6 map not loaded")
	}

	var (
		localV4Key uint32
		localV4Val uint8
	)
	localV4Iter := localV4Map.Iterate()
	var localV4Keys []uint32
	for localV4Iter.Next(&localV4Key, &localV4Val) {
		localV4Keys = append(localV4Keys, localV4Key)
	}
	for _, key := range localV4Keys {
		if err := localV4Map.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete userspace_local_v4 %08x: %w", key, err)
		}
	}

	var (
		localV6Key userspaceLocalV6Key
		localV6Val uint8
	)
	localV6Iter := localV6Map.Iterate()
	var localV6Keys []userspaceLocalV6Key
	for localV6Iter.Next(&localV6Key, &localV6Val) {
		localV6Keys = append(localV6Keys, localV6Key)
	}
	for _, key := range localV6Keys {
		if err := localV6Map.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete userspace_local_v6 %+v: %w", key, err)
		}
	}

	for _, entry := range buildLocalAddressEntries(snapshot) {
		if entry.v4 {
			if err := localV4Map.Update(entry.v4Key, uint8(1), ebpf.UpdateAny); err != nil {
				return fmt.Errorf("update userspace_local_v4 %08x: %w", entry.v4Key, err)
			}
			continue
		}
		if err := localV6Map.Update(entry.v6Key, uint8(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update userspace_local_v6 %+v: %w", entry.v6Key, err)
		}
	}
	// Also add kernel addresses (VIPs added by VRRP) that aren't in the
	// config snapshot. Without this, the XDP shim doesn't recognize VIP
	// destinations as local and redirects them to XSK instead of the kernel.
	// Use AddrList(nil, ...) to enumerate ALL addresses on the system.
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		addrs, err := netlink.AddrList(nil, family)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip := addr.IP
			if ip == nil {
				continue
			}
			if v4 := ip.To4(); v4 != nil && family == netlink.FAMILY_V4 {
				key := binary.BigEndian.Uint32(v4)
				_ = localV4Map.Update(key, uint8(1), ebpf.UpdateAny)
			} else if v6 := ip.To16(); v6 != nil && family == netlink.FAMILY_V6 {
				var key [16]byte
				copy(key[:], v6)
				_ = localV6Map.Update(userspaceLocalV6Key{Addr: key}, uint8(1), ebpf.UpdateAny)
			}
		}
	}
	return nil
}

func (m *Manager) syncInterfaceNATAddressMapsLocked(snapshot *ConfigSnapshot) error {
	natV4Map := m.inner.Map("userspace_interface_nat_v4")
	if natV4Map == nil {
		return errors.New("userspace_interface_nat_v4 map not loaded")
	}
	natV6Map := m.inner.Map("userspace_interface_nat_v6")
	if natV6Map == nil {
		return errors.New("userspace_interface_nat_v6 map not loaded")
	}

	var (
		natV4Key uint32
		natV4Val uint8
	)
	natV4Iter := natV4Map.Iterate()
	var natV4Keys []uint32
	for natV4Iter.Next(&natV4Key, &natV4Val) {
		natV4Keys = append(natV4Keys, natV4Key)
	}
	for _, key := range natV4Keys {
		if err := natV4Map.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete userspace_interface_nat_v4 %08x: %w", key, err)
		}
	}

	var (
		natV6Key userspaceLocalV6Key
		natV6Val uint8
	)
	natV6Iter := natV6Map.Iterate()
	var natV6Keys []userspaceLocalV6Key
	for natV6Iter.Next(&natV6Key, &natV6Val) {
		natV6Keys = append(natV6Keys, natV6Key)
	}
	for _, key := range natV6Keys {
		if err := natV6Map.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete userspace_interface_nat_v6 %+v: %w", key, err)
		}
	}

	var rstV4 []netip.Addr
	var rstV6 []netip.Addr
	for _, entry := range buildInterfaceNATAddressEntries(snapshot) {
		if entry.v4 {
			if err := natV4Map.Update(entry.v4Key, uint8(1), ebpf.UpdateAny); err != nil {
				return fmt.Errorf("update userspace_interface_nat_v4 %08x: %w", entry.v4Key, err)
			}
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], entry.v4Key)
			rstV4 = append(rstV4, netip.AddrFrom4(b))
			continue
		}
		if err := natV6Map.Update(entry.v6Key, uint8(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update userspace_interface_nat_v6 %+v: %w", entry.v6Key, err)
		}
		rstV6 = append(rstV6, netip.AddrFrom16(entry.v6Key.Addr))
	}
	slices.SortFunc(rstV4, netip.Addr.Compare)
	slices.SortFunc(rstV6, netip.Addr.Compare)
	// Install RST suppression rules. Skip if addresses haven't changed
	// (dedup) to avoid hammering a broken nftables subsystem on every
	// compile cycle. On first call (lastRSTv4 nil) always try.
	if m.lastRSTv4 == nil || !slices.Equal(rstV4, m.lastRSTv4) || !slices.Equal(rstV6, m.lastRSTv6) {
		if err := bpfrxnft.InstallRSTSuppression(rstV4, rstV6); err != nil {
			// Log once, don't retry until addresses change.
			if m.lastRSTv4 == nil {
				slog.Warn("userspace: RST suppression unavailable (nftables error, non-fatal)", "err", err)
			}
		}
		m.lastRSTv4 = rstV4
		m.lastRSTv6 = rstV6
	}
	return nil
}

// SnapshotNeighbors returns the neighbor entries from the last published
// snapshot. Used by the daemon to pre-install kernel ARP entries on RG
// activation so failback doesn't drop packets during ARP resolution.
func (m *Manager) SnapshotNeighbors() []struct {
	Ifindex int
	IP      net.IP
	MAC     net.HardwareAddr
	Family  int
} {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastSnapshot == nil {
		return nil
	}
	var result []struct {
		Ifindex int
		IP      net.IP
		MAC     net.HardwareAddr
		Family  int
	}
	for _, n := range m.lastSnapshot.Neighbors {
		if n.Ifindex <= 0 || n.MAC == "" || n.IP == "" {
			continue
		}
		mac, err := net.ParseMAC(n.MAC)
		if err != nil {
			continue
		}
		ip := net.ParseIP(n.IP)
		if ip == nil {
			continue
		}
		family := netlink.FAMILY_V4
		if ip.To4() == nil {
			family = netlink.FAMILY_V6
		}
		result = append(result, struct {
			Ifindex int
			IP      net.IP
			MAC     net.HardwareAddr
			Family  int
		}{
			Ifindex: n.Ifindex,
			IP:      ip,
			MAC:     mac,
			Family:  family,
		})
	}
	return result
}

func (m *Manager) Status() (ProcessStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.proc == nil {
		if m.lastStatus.PID != 0 {
			return m.lastStatus, nil
		}
		return ProcessStatus{}, errors.New("userspace dataplane helper not running")
	}

	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "status"}, &status); err != nil {
		if m.lastStatus.PID != 0 {
			return m.lastStatus, err
		}
		return ProcessStatus{}, err
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		return status, err
	}
	return status, nil
}

func (m *Manager) SetForwardingArmed(armed bool) (ProcessStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.proc == nil {
		return ProcessStatus{}, errors.New("userspace dataplane helper not running")
	}
	if armed && !m.lastStatus.Capabilities.ForwardingSupported {
		if len(m.lastStatus.Capabilities.UnsupportedReasons) == 0 {
			return m.lastStatus, errors.New("userspace live forwarding is not supported for the current configuration")
		}
		return m.lastStatus, fmt.Errorf(
			"userspace live forwarding is not supported: %s",
			strings.Join(m.lastStatus.Capabilities.UnsupportedReasons, "; "),
		)
	}
	var status ProcessStatus
	req := ControlRequest{
		Type: "set_forwarding_state",
		Forwarding: &ForwardingControlRequest{
			Armed: armed,
		},
	}
	if err := m.requestLocked(req, &status); err != nil {
		return ProcessStatus{}, err
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		return status, err
	}
	return status, nil
}

func (m *Manager) SetQueueState(queueID uint32, registered, armed bool) (ProcessStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.proc == nil {
		return ProcessStatus{}, errors.New("userspace dataplane helper not running")
	}
	var status ProcessStatus
	req := ControlRequest{
		Type: "set_queue_state",
		Queue: &QueueControlRequest{
			QueueID:    queueID,
			Registered: registered,
			Armed:      armed,
		},
	}
	if err := m.requestLocked(req, &status); err != nil {
		return ProcessStatus{}, err
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		return status, err
	}
	return status, nil
}

func (m *Manager) SetBindingState(slot uint32, registered, armed bool) (ProcessStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.proc == nil {
		return ProcessStatus{}, errors.New("userspace dataplane helper not running")
	}
	var status ProcessStatus
	req := ControlRequest{
		Type: "set_binding_state",
		Binding: &BindingControlRequest{
			Slot:       slot,
			Registered: registered,
			Armed:      armed,
		},
	}
	if err := m.requestLocked(req, &status); err != nil {
		return ProcessStatus{}, err
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		return status, err
	}
	return status, nil
}

func (m *Manager) InjectPacket(req InjectPacketRequest) (ProcessStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.proc == nil {
		return ProcessStatus{}, errors.New("userspace dataplane helper not running")
	}
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "inject_packet", Packet: &req}, &status); err != nil {
		return ProcessStatus{}, err
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		return status, err
	}
	return status, nil
}

func (m *Manager) DrainSessionDeltas(max uint32) ([]SessionDeltaInfo, ProcessStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.proc == nil {
		return nil, ProcessStatus{}, errors.New("userspace dataplane helper not running")
	}
	resp, err := m.requestDetailedLocked(ControlRequest{
		Type: "drain_session_deltas",
		SessionDeltas: &SessionDeltaDrainRequest{
			Max: max,
		},
	})
	if err != nil {
		return nil, ProcessStatus{}, err
	}
	var status ProcessStatus
	if resp.Status != nil {
		status = *resp.Status
		if err := m.applyHelperStatusLocked(&status); err != nil {
			return resp.SessionDeltas, status, err
		}
	}
	return resp.SessionDeltas, status, nil
}

func (m *Manager) ExportOwnerRGSessions(rgIDs []int, max uint32) ([]SessionDeltaInfo, ProcessStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.proc == nil {
		return nil, ProcessStatus{}, errors.New("userspace dataplane helper not running")
	}
	resp, err := m.requestDetailedLocked(ControlRequest{
		Type: "export_owner_rg_sessions",
		SessionExport: &SessionExportRequest{
			OwnerRGs: rgIDs,
			Max:      max,
		},
	})
	if err != nil {
		return nil, ProcessStatus{}, err
	}
	var status ProcessStatus
	if resp.Status != nil {
		status = *resp.Status
		if err := m.applyHelperStatusLocked(&status); err != nil {
			return resp.SessionDeltas, status, err
		}
	}
	return resp.SessionDeltas, status, nil
}

const userspaceBindingReady = 1

type userspaceBindingKey struct {
	Ifindex uint32
	QueueID uint32
}

type userspaceBindingValue struct {
	Slot  uint32
	Flags uint32
}

// verifyBindingsMapLocked reads the BPF userspace_bindings map and compares
// each entry against the helper's last reported binding status. If the helper
// reports a binding as Registered+Armed (meaning the XSK socket exists and the
// queue is armed for redirect) but the BPF map entry is all zeros (no slot,
// no flags), the BPF map is stale — the XDP shim has nothing to redirect to
// and all transit traffic silently drops.
//
// This can happen after a peer crash+reconnect when Compile() calls
// programBootstrapMapsLocked() which zeros the bindings map, and then either:
//   - applyHelperStatusLocked didn't run (error path)
//   - another Compile() ran concurrently and re-zeroed the map
//   - the inner eBPF compile recreated the map from a fresh pin
//
// When a mismatch is detected, this method rewrites the BPF map entries from
// the helper's reported state — the same logic as applyHelperStatusLocked but
// targeted to only the stale entries. This is cheaper than a full rebind.
//
// Returns true if any stale entries were repaired.
func (m *Manager) verifyBindingsMapLocked() bool {
	if m.proc == nil || m.proc.Process == nil {
		return false
	}
	// Only check when ctrl is enabled and bindings should be active.
	// During startup (ctrl=0), the map is expected to be empty.
	if !m.ctrlWasEnabled {
		return false
	}
	bindings := m.lastStatus.Bindings
	if len(bindings) == 0 {
		return false
	}
	bindingsMap := m.inner.Map("userspace_bindings")
	if bindingsMap == nil {
		return false
	}

	repaired := 0
	for _, binding := range bindings {
		if binding.Ifindex <= 0 {
			continue
		}
		if !binding.Registered || !binding.Armed {
			continue
		}
		idx := uint32(binding.Ifindex)*bindingQueuesPerIface + binding.QueueID
		var val userspaceBindingValue
		if err := bindingsMap.Lookup(idx, &val); err != nil {
			slog.Debug("userspace: bindings watchdog lookup failed",
				"ifindex", binding.Ifindex, "queue", binding.QueueID, "err", err)
			continue
		}
		if val.Flags != 0 || val.Slot != 0 {
			// BPF map entry is populated — no mismatch.
			continue
		}
		// BPF map entry is all zeros but the helper says the queue is
		// registered and armed. Rewrite the entry.
		flags := uint32(userspaceBindingReady)
		newVal := userspaceBindingValue{
			Slot:  binding.Slot,
			Flags: flags,
		}
		if err := bindingsMap.Update(idx, newVal, ebpf.UpdateAny); err != nil {
			slog.Warn("userspace: bindings watchdog failed to repair entry",
				"ifindex", binding.Ifindex, "queue", binding.QueueID,
				"slot", binding.Slot, "err", err)
			continue
		}
		repaired++
	}

	// Also repair aliased bindings (VLAN children inheriting parent's XSK).
	if m.lastSnapshot != nil {
		for childIfindex, parentIfindex := range buildUserspaceIngressBindingAliases(m.lastSnapshot) {
			for _, binding := range bindings {
				if binding.Ifindex != int(parentIfindex) {
					continue
				}
				if !binding.Registered || !binding.Armed || !binding.Bound {
					continue
				}
				idx := childIfindex*bindingQueuesPerIface + binding.QueueID
				var val userspaceBindingValue
				if err := bindingsMap.Lookup(idx, &val); err != nil {
					slog.Debug("userspace: bindings watchdog alias lookup failed",
						"child", childIfindex, "parent", parentIfindex, "queue", binding.QueueID, "err", err)
					continue
				}
				if val.Flags != 0 || val.Slot != 0 {
					continue
				}
				newVal := userspaceBindingValue{
					Slot:  binding.Slot,
					Flags: userspaceBindingReady,
				}
				if err := bindingsMap.Update(idx, newVal, ebpf.UpdateAny); err != nil {
					slog.Warn("userspace: bindings watchdog failed to repair alias entry",
						"child", childIfindex, "parent", parentIfindex,
						"queue", binding.QueueID, "slot", binding.Slot, "err", err)
					continue
				}
				repaired++
			}
		}
	}

	if repaired > 0 {
		slog.Warn("userspace: bindings watchdog repaired stale BPF map entries",
			"repaired", repaired, "total_bindings", len(bindings))
	}
	return repaired > 0
}

type userspaceLocalV6Key struct {
	Addr [16]byte
}

type userspaceLocalAddressEntry struct {
	v4    bool
	v4Key uint32
	v6Key userspaceLocalV6Key
}

func buildLocalAddressEntries(snapshot *ConfigSnapshot) []userspaceLocalAddressEntry {
	if snapshot == nil {
		return nil
	}
	excludedV4, excludedV6 := buildNATTranslatedLocalAddressExclusions(snapshot)
	seenV4 := make(map[uint32]bool)
	seenV6 := make(map[[16]byte]bool)
	out := make([]userspaceLocalAddressEntry, 0)
	for _, iface := range snapshot.Interfaces {
		for _, addr := range iface.Addresses {
			ip, _, err := net.ParseCIDR(addr.Address)
			if err != nil || ip == nil {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				key := binary.BigEndian.Uint32(v4)
				if excludedV4[key] {
					continue
				}
				if seenV4[key] {
					continue
				}
				seenV4[key] = true
				out = append(out, userspaceLocalAddressEntry{v4: true, v4Key: key})
				continue
			}
			var key [16]byte
			copy(key[:], ip.To16())
			if excludedV6[key] {
				continue
			}
			if seenV6[key] {
				continue
			}
			seenV6[key] = true
			out = append(out, userspaceLocalAddressEntry{v6Key: userspaceLocalV6Key{Addr: key}})
		}
	}
	return out
}

func buildInterfaceNATAddressEntries(snapshot *ConfigSnapshot) []userspaceLocalAddressEntry {
	if snapshot == nil {
		return nil
	}
	excludedV4, excludedV6 := buildNATTranslatedLocalAddressExclusions(snapshot)
	seenV4 := make(map[uint32]bool)
	seenV6 := make(map[[16]byte]bool)
	out := make([]userspaceLocalAddressEntry, 0)
	for key := range excludedV4 {
		if seenV4[key] {
			continue
		}
		seenV4[key] = true
		out = append(out, userspaceLocalAddressEntry{v4: true, v4Key: key})
	}
	for key := range excludedV6 {
		if seenV6[key] {
			continue
		}
		seenV6[key] = true
		out = append(out, userspaceLocalAddressEntry{v6Key: userspaceLocalV6Key{Addr: key}})
	}
	return out
}

func buildUserspaceIngressIfindexes(snapshot *ConfigSnapshot) []uint32 {
	if snapshot == nil {
		return nil
	}
	seen := make(map[uint32]bool)
	out := make([]uint32, 0)
	for _, iface := range snapshot.Interfaces {
		if iface.Zone == "" || userspaceSkipsIngressInterface(iface) {
			continue
		}
		if iface.ParentIfindex > 0 {
			if iface.Ifindex > 0 {
				key := uint32(iface.Ifindex)
				if !seen[key] {
					seen[key] = true
					out = append(out, key)
				}
			}
			key := uint32(iface.ParentIfindex)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, key)
			continue
		}
		if iface.Ifindex <= 0 {
			continue
		}
		key := uint32(iface.Ifindex)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	// Include fabric parent interfaces so the XDP shim is attached and
	// XSK bind() succeeds.  This enables both fabric-redirect TX and
	// fabric ingress RX in the userspace dataplane.
	for _, fab := range snapshot.Fabrics {
		if fab.ParentIfindex <= 0 {
			continue
		}
		key := uint32(fab.ParentIfindex)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func snapshotBindingPlanKey(snapshot *ConfigSnapshot) string {
	if snapshot == nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "workers=%d;ring=%d;", snapshot.Userspace.Workers, snapshot.Userspace.RingEntries)
	for _, iface := range snapshot.Interfaces {
		if iface.Zone == "" || userspaceSkipsIngressInterface(iface) {
			continue
		}
		fmt.Fprintf(
			&b,
			"iface=%s/%s/%d/%d/%d/%t;",
			iface.Name,
			iface.LinuxName,
			iface.Ifindex,
			iface.ParentIfindex,
			iface.RXQueues,
			iface.Tunnel,
		)
	}
	for _, fab := range snapshot.Fabrics {
		fmt.Fprintf(
			&b,
			"fabric=%s/%s/%d/%d;",
			fab.Name,
			fab.ParentLinuxName,
			fab.ParentIfindex,
			fab.RXQueues,
		)
	}
	return b.String()
}

func buildUserspaceIngressBindingAliases(snapshot *ConfigSnapshot) map[uint32]uint32 {
	if snapshot == nil {
		return nil
	}
	out := make(map[uint32]uint32)
	for _, iface := range snapshot.Interfaces {
		if iface.Zone == "" || userspaceSkipsIngressInterface(iface) {
			continue
		}
		if iface.Ifindex <= 0 || iface.ParentIfindex <= 0 {
			continue
		}
		out[uint32(iface.Ifindex)] = uint32(iface.ParentIfindex)
	}
	return out
}

func userspaceSkipsIngressInterface(iface InterfaceSnapshot) bool {
	if iface.Tunnel {
		return true
	}
	name := iface.Name
	base := name
	if idx := strings.IndexByte(base, '.'); idx >= 0 {
		base = base[:idx]
	}
	switch {
	case strings.HasPrefix(base, "fxp"):
		return true
	case strings.HasPrefix(base, "em"):
		return true
	case strings.HasPrefix(base, "fab"):
		return true
	case base == "lo0":
		return true
	}
	switch iface.Zone {
	case "mgmt", "control":
		return true
	}
	if iface.LocalFabric != "" {
		return true
	}
	return false
}

func snapshotHasNativeGRE(snapshot *ConfigSnapshot) bool {
	if snapshot == nil {
		return false
	}
	for _, endpoint := range snapshot.TunnelEndpoints {
		if endpoint.ID == 0 {
			continue
		}
		switch endpoint.Mode {
		case "", "gre", "ip6gre":
			return true
		}
	}
	return false
}

func buildNATTranslatedLocalAddressExclusions(snapshot *ConfigSnapshot) (map[uint32]bool, map[[16]byte]bool) {
	excludedV4 := make(map[uint32]bool)
	excludedV6 := make(map[[16]byte]bool)
	if snapshot == nil || len(snapshot.SourceNAT) == 0 || len(snapshot.Interfaces) == 0 {
		return excludedV4, excludedV6
	}
	toZones := make(map[string]bool)
	for _, rule := range snapshot.SourceNAT {
		if !rule.InterfaceMode || rule.Off || rule.ToZone == "" {
			continue
		}
		toZones[rule.ToZone] = true
	}
	if len(toZones) == 0 {
		return excludedV4, excludedV6
	}
	for _, iface := range snapshot.Interfaces {
		if iface.Zone == "" || !toZones[iface.Zone] {
			continue
		}
		if ip := pickInterfaceSnapshotV4(iface); ip != nil {
			excludedV4[binary.BigEndian.Uint32(ip.To4())] = true
		}
		if ip := pickInterfaceSnapshotV6(iface); ip != nil {
			var key [16]byte
			copy(key[:], ip.To16())
			excludedV6[key] = true
		}
	}
	return excludedV4, excludedV6
}

func pickInterfaceSnapshotV4(iface InterfaceSnapshot) net.IP {
	var fallback net.IP
	for _, addr := range iface.Addresses {
		if addr.Family != "inet" {
			continue
		}
		ip, _, err := net.ParseCIDR(addr.Address)
		if err != nil || ip == nil {
			continue
		}
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		if fallback == nil {
			fallback = append(net.IP(nil), v4...)
		}
		if !v4.IsLinkLocalUnicast() {
			return append(net.IP(nil), v4...)
		}
	}
	return fallback
}

func pickInterfaceSnapshotV6(iface InterfaceSnapshot) net.IP {
	var fallback net.IP
	for _, addr := range iface.Addresses {
		if addr.Family != "inet6" {
			continue
		}
		ip, _, err := net.ParseCIDR(addr.Address)
		if err != nil || ip == nil {
			continue
		}
		v6 := ip.To16()
		if v6 == nil {
			continue
		}
		if fallback == nil {
			fallback = append(net.IP(nil), v6...)
		}
		if !v6.IsLinkLocalUnicast() {
			return append(net.IP(nil), v6...)
		}
	}
	return fallback
}

func (m *Manager) ensureStatusLoopLocked() {
	if m.syncCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.syncCancel = cancel
	go m.statusLoop(ctx)
}

func (m *Manager) statusLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	startTime := time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.mu.Lock()
			if m.proc == nil {
				m.mu.Unlock()
				return
			}
			prevActiveSig := activeHAGroupSignature(m.haGroups)
			var status ProcessStatus
			if err := m.requestLocked(ControlRequest{Type: "status"}, &status); err == nil {
				if err := m.applyHelperStatusLocked(&status); err != nil {
					slog.Warn("userspace dataplane status sync failed", "err", err)
				} else {
					// Bindings watchdog (#473): verify the BPF map matches
					// the helper's reported state. Only run after a successful
					// status update — stale m.lastStatus could cause incorrect
					// repairs.
					m.verifyBindingsMapLocked()
				}
				if m.lastSnapshot != nil && m.publishedSnapshot < m.lastSnapshot.Generation {
					if err := m.syncSnapshotLocked(); err != nil {
						slog.Warn("userspace dataplane snapshot sync failed", "err", err)
					}
				}
				helperActiveSig := activeHAGroupSignatureSlice(status.HAGroups)
				if m.clusterHA {
					_ = m.refreshHAStateFromMapsLocked()
				}
				newActiveSig := activeHAGroupSignature(m.haGroups)
				if m.clusterHA && newActiveSig != "" && time.Since(m.lastRGActivateTime) >= 2*time.Second {
					// Only sync watchdog updates to the helper from the poll.
					// Do NOT sync active/inactive transitions here — that's
					// handled by UpdateRGActive which must be the sole source
					// of demotion/activation deltas. If the poll syncs first,
					// the helper sees no delta and skips FlushFlowCaches.
					// Skip entirely for 2s after UpdateRGActive to avoid
					// control socket contention during post-transition work.
					if helperActiveSig != newActiveSig || newActiveSig != prevActiveSig {
						// Sync watchdog timestamps only (HA state update
						// without active/inactive change detection).
						// Throttle to every 5s to avoid control socket
						// contention with session installs during bulk sync.
						if time.Since(m.lastHASyncTime) >= 5*time.Second {
							if err := m.syncHAWatchdogOnlyLocked(); err != nil {
								slog.Warn("userspace dataplane HA watchdog sync failed", "err", err)
							}
							m.lastHASyncTime = time.Now()
						}
					}
					// Do not bootstrap NAPI queues or kick neighbor repair on
					// HA ownership changes. By the time UpdateRGActive runs, the
					// standby must already be forwarding-ready; otherwise
					// TakeoverReady() should have blocked the handoff earlier.
				}
				if err := m.syncDesiredForwardingStateLocked(); err != nil {
					slog.Warn("userspace dataplane forwarding sync failed", "err", err)
				}
			} else {
				slog.Warn("userspace dataplane status poll failed", "err", err)
			}
			// Keep the targeted kernel prewarm during initial startup, but
			// let the helper own neighbor-table sync via its own dump+subscribe
			// netlink path instead of pushing periodic manager snapshots.
			if time.Since(startTime) < 60*time.Second && m.lastSnapshot != nil && m.lastSnapshot.Config != nil {
				m.proactiveNeighborResolveAsyncLocked()
			}
			m.mu.Unlock()
		}
	}
}

func (m *Manager) bootstrapNAPIQueuesAsyncLocked(reason string) {
	now := time.Now()
	if !m.lastNAPIBootstrap.IsZero() && now.Sub(m.lastNAPIBootstrap) < 2*time.Second {
		return
	}
	m.lastNAPIBootstrap = now
	go func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.proc == nil || m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
			return
		}
		slog.Info("userspace: bootstrapping NAPI queues", "reason", reason)
		m.bootstrapNAPIQueuesLocked()
	}()
}

func (m *Manager) stopLocked() {
	if m.eventStreamCancel != nil {
		m.eventStreamCancel()
		m.eventStreamCancel = nil
	}
	if m.eventStream != nil {
		m.eventStream.Close()
		m.eventStream = nil
	}
	if m.syncCancel != nil {
		m.syncCancel()
		m.syncCancel = nil
	}
	if m.proc == nil {
		m.lastStatus = ProcessStatus{}
		return
	}
	// Disable userspace forwarding BEFORE stopping the helper.
	// Without this, the XDP shim continues redirecting to XSK after
	// the helper exits, sending packets to dead socket fds. Setting
	// ctrl.enabled=0 makes the shim fall back to the eBPF pipeline.
	m.disableUserspaceCtrlLocked()
	_ = m.requestLocked(ControlRequest{Type: "shutdown"}, nil)
	done := make(chan struct{})
	go func(cmd *exec.Cmd) {
		_ = cmd.Wait()
		close(done)
	}(m.proc)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		if m.proc.Process != nil {
			_ = m.proc.Process.Signal(syscall.SIGTERM)
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			if m.proc.Process != nil {
				_ = m.proc.Process.Kill()
			}
			<-done
		}
	}
	m.proc = nil
	m.lastStatus = ProcessStatus{}
	m.neighborsPrewarmed = false
	m.ctrlEnableAt = time.Time{}
	m.xskLivenessProven = false
	m.xskLivenessFailed = false
	m.xskProbeStart = time.Time{}
	m.lastXSKRX = 0
	m.lastNAPIBootstrap = time.Time{}
	m.publishedSnapshot = 0
	m.publishedPlanKey = ""
}

// bootstrapNAPIQueuesLocked sends UDP probe packets to each managed
// interface to trigger hardware RX events on all NIC queues. This is
// needed for mlx5 zero-copy: the driver only consumes XSK fill ring
// entries during NAPI poll, and NAPI only runs when there are HW RX
// events. Without at least one packet per queue, the fill ring stays
// unconsumed and XDP_REDIRECT silently drops packets.
//
// The probes are sent while ctrl is disabled, so the XDP shim falls
// back to the eBPF pipeline which handles them normally (XDP_PASS).
func (m *Manager) bootstrapNAPIQueuesLocked() {
	if m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
		return
	}
	// Send ARP requests on each managed interface to generate hardware RX
	// events from ARP replies. This triggers mlx5 NAPI which processes
	// the XSK fill ring and posts WQEs for zero-copy packet reception.
	// Without at least one HW RX event per queue, the fill ring entries
	// added after socket bind are never consumed by the driver's pool.
	for _, linuxName := range userspaceBootstrapProbeInterfaces(m.lastSnapshot.Config) {
		// Send many parallel pings to hit all RSS queues. Each ping
		// process gets a different ICMP echo ID from the kernel, causing
		// RSS to distribute replies across different NIC queues. This
		// triggers NAPI on each queue, which posts fill ring WQEs for
		// zero-copy XSK packet reception.
		link, err := netlink.LinkByName(linuxName)
		if err != nil || link == nil {
			continue
		}
		// Find a target: gateway or any neighbor
		var target string
		routes, _ := netlink.RouteList(link, netlink.FAMILY_V4)
		for _, r := range routes {
			if r.Gw != nil && r.Gw.To4() != nil {
				target = r.Gw.String()
				break
			}
		}
		if target == "" {
			neighs, _ := netlink.NeighList(link.Attrs().Index, netlink.FAMILY_V4)
			for _, n := range neighs {
				if n.IP != nil && n.IP.To4() != nil && n.HardwareAddr != nil &&
					n.State != netlink.NUD_FAILED {
					target = n.IP.String()
					break
				}
			}
		}
		if target == "" {
			continue
		}
		// Send multiple ICMP probes with different ICMP echo IDs to
		// trigger NAPI on ALL NIC queues. mlx5 RSS distributes replies
		// across queues based on hash(src, dst, proto, id). Sending
		// ~2× the queue count with varying IDs makes it very likely
		// that every queue sees at least one hardware RX event, which
		// posts XSK fill ring WQEs for zero-copy packet reception.
		targetIP := net.ParseIP(target)
		if targetIP != nil {
			// ICMP RSS hashes on (src, dst, proto) only — varying
			// ICMP ID doesn't change the target queue. Use UDP probes
			// with varying ports: mlx5 RSS hashes (src, dst, sport,
			// dport) for UDP, distributing across all queues.
			// Send 30 probes across port range 40000-40029.
			for i := 0; i < 30; i++ {
				sendUDPProbeForNAPI(linuxName, targetIP, uint16(40000+i))
				if i%6 == 5 {
					time.Sleep(time.Millisecond)
				}
			}
			// Also send one ICMP probe for neighbor resolution.
			sendICMPProbeFromManager(linuxName, targetIP)
		}
	}
}

// proactiveNeighborResolveLocked reads the kernel neighbor table and
// pings any STALE/FAILED entries to force re-resolution. Also pings
// the default gateway on each managed interface. This ensures the
// helper has fresh neighbor entries when ctrl is enabled.
func (m *Manager) proactiveNeighborResolveLocked() {
	if m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
		return
	}
	// Collect all managed interface names
	seen := make(map[string]bool)
	var ifaces []string
	for ifName, ifc := range m.lastSnapshot.Config.Interfaces.Interfaces {
		base := config.LinuxIfName(ifName)
		if !seen[base] {
			seen[base] = true
			ifaces = append(ifaces, base)
		}
		for _, unit := range ifc.Units {
			if unit.VlanID > 0 {
				vlanName := fmt.Sprintf("%s.%d", base, unit.VlanID)
				if !seen[vlanName] {
					seen[vlanName] = true
					ifaces = append(ifaces, vlanName)
				}
			}
		}
	}
	// For each interface, read neighbors and ping any that need resolution
	var resolved int
	for _, ifName := range ifaces {
		link, err := netlink.LinkByName(ifName)
		if err != nil || link == nil {
			continue
		}
		for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
			neighs, err := netlink.NeighList(link.Attrs().Index, family)
			if err != nil {
				continue
			}
			for _, n := range neighs {
				if n.IP == nil || n.IP.IsLinkLocalUnicast() {
					continue
				}
				// Trigger ARP/NDP resolution for STALE/FAILED/absent entries.
				if n.HardwareAddr == nil || len(n.HardwareAddr) == 0 ||
					n.State == netlink.NUD_STALE || n.State == netlink.NUD_DELAY ||
					n.State == netlink.NUD_PROBE || n.State == netlink.NUD_FAILED {
					sendICMPProbeFromManager(ifName, n.IP)
					resolved++
				}
			}
		}
	}
	// Also resolve route next-hops that aren't in the neighbor table yet.
	// After VRRP election, the kernel may not have ARP for destinations
	// like .200 that were previously known but got purged on restart.
	routes, _ := netlink.RouteList(nil, netlink.FAMILY_ALL)
	for _, r := range routes {
		if r.Gw == nil || r.Gw.IsLinkLocalUnicast() {
			continue
		}
		link, err := netlink.LinkByIndex(r.LinkIndex)
		if err != nil || link == nil {
			continue
		}
		ifName := link.Attrs().Name
		if !seen[ifName] {
			continue // only managed interfaces
		}
		// Check if this gateway is already in neighbor table
		existing, _ := netlink.NeighList(r.LinkIndex, netlink.FAMILY_ALL)
		found := false
		for _, n := range existing {
			if n.IP.Equal(r.Gw) && n.HardwareAddr != nil && len(n.HardwareAddr) > 0 &&
				n.State != netlink.NUD_FAILED {
				found = true
				break
			}
		}
		if !found {
			sendICMPProbeFromManager(ifName, r.Gw)
			resolved++
		}
	}
	if resolved > 0 {
		slog.Info("userspace: proactive neighbor resolution",
			"resolved", resolved, "interfaces", len(ifaces))
	}
}

// sendICMPProbeFromManager sends a single raw ICMP/ICMPv6 echo request
// bound to the given interface. Triggers kernel ARP/NDP resolution
// without shelling out to ping. Non-blocking.
func sendICMPProbeFromManager(iface string, target net.IP) {
	sendICMPProbeWithID(iface, target, 0)
}

// sendICMPProbeWithID sends a single ICMP echo request with a specific echo
// ID. Varying the ID causes RSS to distribute replies across different NIC
// queues, triggering NAPI on each queue for zero-copy fill ring processing.
func sendICMPProbeWithID(iface string, target net.IP, id uint16) {
	if target.To4() != nil {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
		if err != nil {
			return
		}
		defer unix.Close(fd)
		_ = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		// ICMP Echo: type=8, code=0, checksum(auto), id, seq=1
		icmp := [8]byte{8, 0, 0, 0, byte(id >> 8), byte(id), 0, 1}
		// Compute checksum
		var sum uint32
		for i := 0; i < 8; i += 2 {
			sum += uint32(icmp[i])<<8 | uint32(icmp[i+1])
		}
		sum = (sum >> 16) + (sum & 0xffff)
		sum += sum >> 16
		cs := uint16(^sum)
		icmp[2] = byte(cs >> 8)
		icmp[3] = byte(cs)
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
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_ICMPV6, unix.IPV6_CHECKSUM, 2)
		// ICMPv6 Echo: type=128, code=0, checksum(kernel), id, seq=1
		icmp6 := [8]byte{128, 0, 0, 0, byte(id >> 8), byte(id), 0, 1}
		sa6 := &unix.SockaddrInet6{}
		copy(sa6.Addr[:], target.To16())
		_ = unix.Sendto(fd, icmp6[:], unix.MSG_DONTWAIT, sa6)
	}
}

// sendUDPProbeForNAPI sends a single UDP packet to the target on the given
// port. The packet is sent via a raw UDP socket bound to the interface.
// The destination is unlikely to respond, but the important thing is that
// the REPLY (ICMP port unreachable) or even the outgoing packet's DMA
// completion triggers NAPI on the NIC queue determined by RSS hash of
// (src_ip, dst_ip, src_port, dst_port). Different ports → different queues.
func sendUDPProbeForNAPI(iface string, target net.IP, port uint16) {
	if target.To4() != nil {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
		if err != nil {
			return
		}
		defer unix.Close(fd)
		_ = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		sa := &unix.SockaddrInet4{Port: int(port)}
		copy(sa.Addr[:], target.To4())
		_ = unix.Sendto(fd, []byte("napi"), unix.MSG_DONTWAIT, sa)
	} else {
		fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
		if err != nil {
			return
		}
		defer unix.Close(fd)
		_ = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		sa6 := &unix.SockaddrInet6{Port: int(port)}
		copy(sa6.Addr[:], target.To16())
		_ = unix.Sendto(fd, []byte("napi"), unix.MSG_DONTWAIT, sa6)
	}
}

// proactiveNeighborResolveAsyncLocked is the non-blocking version that
// fires probes in background goroutines. Used by the status loop.
func (m *Manager) proactiveNeighborResolveAsyncLocked() {
	if m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
		return
	}
	seen := make(map[string]bool)
	targetSet := make(map[string]struct{})
	var targets []struct{ iface, ip string }
	for ifName, ifc := range m.lastSnapshot.Config.Interfaces.Interfaces {
		base := config.LinuxIfName(ifName)
		seen[base] = true // include base interface for route-GW probing
		for _, unit := range ifc.Units {
			linuxName := base
			if unit.VlanID > 0 {
				linuxName = fmt.Sprintf("%s.%d", base, unit.VlanID)
			}
			seen[linuxName] = true
			link, err := netlink.LinkByName(linuxName)
			if err != nil || link == nil {
				continue
			}
			for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
				neighs, err := netlink.NeighList(link.Attrs().Index, family)
				if err != nil {
					continue
				}
				for _, n := range neighs {
					if n.IP == nil || n.IP.IsLinkLocalUnicast() {
						continue
					}
					if n.HardwareAddr == nil || len(n.HardwareAddr) == 0 ||
						n.State == netlink.NUD_STALE || n.State == netlink.NUD_FAILED {
						key := linuxName + "|" + n.IP.String()
						if _, ok := targetSet[key]; ok {
							continue
						}
						targetSet[key] = struct{}{}
						targets = append(targets, struct{ iface, ip string }{linuxName, n.IP.String()})
					}
				}
			}
		}
	}
	routes, _ := netlink.RouteList(nil, netlink.FAMILY_ALL)
	for _, r := range routes {
		if r.Gw == nil || r.Gw.IsLinkLocalUnicast() {
			continue
		}
		link, err := netlink.LinkByIndex(r.LinkIndex)
		if err != nil || link == nil {
			continue
		}
		ifName := link.Attrs().Name
		if !seen[ifName] {
			continue
		}
		existing, _ := netlink.NeighList(r.LinkIndex, netlink.FAMILY_ALL)
		found := false
		for _, n := range existing {
			if n.IP.Equal(r.Gw) && n.HardwareAddr != nil && len(n.HardwareAddr) > 0 &&
				n.State != netlink.NUD_FAILED {
				found = true
				break
			}
		}
		if found {
			continue
		}
		key := ifName + "|" + r.Gw.String()
		if _, ok := targetSet[key]; ok {
			continue
		}
		targetSet[key] = struct{}{}
		targets = append(targets, struct{ iface, ip string }{ifName, r.Gw.String()})
	}
	for _, t := range targets {
		go func(iface, ip string) {
			targetIP := net.ParseIP(ip)
			if targetIP != nil {
				sendICMPProbeFromManager(iface, targetIP)
			}
		}(t.iface, t.ip)
	}
}

// disableUserspaceCtrlLocked sets ctrl.enabled=0 in the BPF map so the XDP
// shim stops redirecting packets to XSK. This MUST be called before the
// helper exits to prevent packets being sent to dead socket fds.
func (m *Manager) disableUserspaceCtrlLocked() {
	ctrlMap := m.inner.Map("userspace_ctrl")
	if ctrlMap == nil {
		return
	}
	zero := uint32(0)
	// Read current ctrl, set enabled=0, write back.
	var ctrl userspaceCtrlValue
	if err := ctrlMap.Lookup(zero, &ctrl); err != nil {
		return
	}
	ctrl.Enabled = 0
	_ = ctrlMap.Update(zero, ctrl, ebpf.UpdateAny)
	slog.Info("userspace: disabled ctrl (helper stopping)")
}

// reEnableUserspaceCtrlLocked sets ctrl.enabled=1 in the BPF map.
// Used to rollback a ctrl disable when the subsequent operation fails.
func (m *Manager) reEnableUserspaceCtrlLocked() {
	ctrlMap := m.inner.Map("userspace_ctrl")
	if ctrlMap == nil {
		return
	}
	zero := uint32(0)
	var ctrl userspaceCtrlValue
	if err := ctrlMap.Lookup(zero, &ctrl); err != nil {
		return
	}
	ctrl.Enabled = 1
	_ = ctrlMap.Update(zero, ctrl, ebpf.UpdateAny)
	slog.Info("userspace: re-enabled ctrl (rollback)")
}

// DisableAndStopHelper disables ctrl and swaps to the eBPF pipeline entry
// program. This prevents the XDP shim from redirecting new packets to XSK.
// Must be called BEFORE any operation that invalidates UMEM (e.g. link
// DOWN on mlx5 zero-copy). Worker threads keep running but see no new
// packets since ctrl=0 stops XSK redirects.
//
// Deprecated: use PrepareLinkCycle which also stops the Rust workers.
func (m *Manager) DisableAndStopHelper() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil || m.proc.Process == nil {
		return
	}
	m.disableUserspaceCtrlLocked()
	// Swap to eBPF pipeline so packets go through xdp_main_prog
	// even if the XDP shim was previously attached.
	if m.inner.XDPEntryProg != "xdp_main_prog" {
		_ = m.inner.SwapXDPEntryProg("xdp_main_prog")
	}
}

// PrepareLinkCycle must be called BEFORE any link DOWN/UP cycle (e.g. RETH
// MAC programming). It:
//  1. Disables ctrl so the XDP shim stops redirecting to XSK
//  2. Swaps to xdp_main_prog (eBPF pipeline)
//  3. Sends "stop_workers" to the Rust helper, which joins all worker
//     threads — no thread touches UMEM after this returns
//
// The caller then performs the link DOWN/UP. Afterwards, NotifyLinkCycle
// sends "rebind" to recreate workers with fresh AF_XDP sockets.
func (m *Manager) PrepareLinkCycle() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil || m.proc.Process == nil {
		return
	}
	m.disableUserspaceCtrlLocked()
	if m.inner.XDPEntryProg != "xdp_main_prog" {
		_ = m.inner.SwapXDPEntryProg("xdp_main_prog")
	}
	// Tell the Rust helper to stop all workers. This joins worker
	// threads so they stop touching UMEM before the NIC unmaps pages
	// during link DOWN.
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "stop_workers"}, &status); err != nil {
		slog.Warn("userspace: stop_workers before link cycle failed", "err", err)
		return
	}
	slog.Info("userspace: workers stopped before link cycle",
		"bindings", len(status.Bindings))
}

func configEqual(a, b config.UserspaceConfig) bool {
	return a.Binary == b.Binary &&
		a.ControlSocket == b.ControlSocket &&
		a.EventSocket == b.EventSocket &&
		a.StateFile == b.StateFile &&
		a.Workers == b.Workers &&
		a.RingEntries == b.RingEntries
}

func (m *Manager) StartFIBSync(ctx context.Context) {
	m.inner.StartFIBSync(ctx)
}

// NotifyLinkCycle tells the userspace helper to rebind all AF_XDP sockets.
// In mlx5 (and other drivers), a link DOWN/UP cycle destroys the kernel-side
// XSK receive queue.  The sockets remain open but no longer receive packets.
// This is called after programRethMAC which takes RETH interfaces DOWN/UP.
//
// PrepareLinkCycle should have been called BEFORE the link cycle to stop
// workers (so they don't access UMEM during link DOWN). This method
// waits 200ms for NIC reinitialization then sends "rebind" to recreate
// workers with fresh AF_XDP sockets.
//
// The 200ms delay lets the mlx5 NIC fully reinitialize its UMR (User
// Memory Region) subsystem after link reactivation. Without this, the
// NIC's UMR WQE queue overflows when all XSK sockets are recreated
// simultaneously (rx_xsk_congst_umr), causing UMEM pages to not be mapped
// and packets to be silently dropped despite successful XDP_REDIRECT.
func (m *Manager) NotifyLinkCycle() {
	// Let the NIC fully tear down XSK zero-copy contexts before recreating
	// sockets. mlx5 releases zero-copy queue resources asynchronously after
	// socket close — binding a new socket to the same queue before teardown
	// completes returns EBUSY. 1s gives the driver ample time.
	time.Sleep(1 * time.Second)

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil || m.proc.Process == nil {
		return
	}
	// Ensure ctrl is disabled (PrepareLinkCycle should have done this,
	// but guard against callers that skip it).
	m.disableUserspaceCtrlLocked()
	if m.inner.XDPEntryProg != "xdp_main_prog" {
		_ = m.inner.SwapXDPEntryProg("xdp_main_prog")
	}
	// Reset the ctrl enable gate so the fill-ring bootstrap delay
	// restarts from scratch after rebind.  Without this, ctrl stays
	// enabled while the new bindings aren't ready — packets redirected
	// to dead XSK sockets are silently dropped (cold-start blackout).
	//
	// Preserve ctrlEnableAt across rebinds: the hard timeout should
	// count from the FIRST prewarm, not restart on every link cycle.
	// Otherwise repeated rebinds (e.g. RETH MAC programming) keep
	// pushing the hard timeout forward and ctrl never enables.
	m.neighborsPrewarmed = false
	// Reset liveness state so the XSK probe runs fresh after rebind.
	// The old probe result is stale — the link cycle destroyed the
	// previous XSK sockets and the new ones need re-validation.
	m.xskLivenessProven = false
	m.xskLivenessFailed = false
	m.xskProbeStart = time.Time{}
	m.lastXSKRX = 0

	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "rebind"}, &status); err != nil {
		slog.Warn("userspace: rebind after link cycle failed", "err", err)
		return
	}
	_ = m.applyHelperStatusLocked(&status)
	ready := 0
	for _, b := range status.Bindings {
		if b.Ready {
			ready++
		}
	}
	slog.Info("userspace: AF_XDP rebind initiated after link cycle",
		"forwarding_armed", status.ForwardingArmed,
		"bindings", len(status.Bindings),
		"ready", ready)
	// Re-bootstrap NAPI queues after rebind. The link DOWN/UP cycle
	// destroyed the XSK channels; the rebind created new sockets but
	// the fill ring WQEs haven't been posted to the NIC yet. Broadcast
	// pings generate hardware RX events that trigger NAPI, which posts
	// fill ring WQEs so zero-copy XSK can receive packets.
	m.bootstrapNAPIQueuesAsyncLocked("link-cycle")
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func queueCountFromBindings(bindings []BindingStatus) int {
	maxQueueID := -1
	for _, binding := range bindings {
		if !binding.Registered || binding.Ifindex <= 0 {
			continue
		}
		if int(binding.QueueID) > maxQueueID {
			maxQueueID = int(binding.QueueID)
		}
	}
	if maxQueueID < 0 {
		return 1
	}
	return maxQueueID + 1
}
