package userspace

import (
	"bufio"
	"context"
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
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/psaab/bpfrx/pkg/config"
	"github.com/psaab/bpfrx/pkg/dataplane"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var _ dataplane.DataPlane = (*Manager)(nil)

func init() {
	dataplane.RegisterBackend(dataplane.TypeUserspace, func() dataplane.DataPlane {
		return New()
	})
}

type Manager struct {
	dataplane.DataPlane
	inner *dataplane.Manager

	mu                 sync.Mutex
	proc               *exec.Cmd
	cfg                config.UserspaceConfig
	clusterHA          bool
	generation         uint64
	syncCancel         context.CancelFunc
	lastStatus         ProcessStatus
	lastSnapshot       *ConfigSnapshot
	haGroups           map[int]HAGroupStatus
	lastIngressIfaces  []uint32
	lastBindingIndices []uint32
	neighborsPrewarmed  bool
	ctrlEnableAt        time.Time
	ctrlWasEnabled      bool
	xskLivenessFailed   bool
	xskLivenessProven   bool
	xskProbeStart       time.Time
	lastXSKRX           uint64
	neighborGeneration  uint64
}

func New() *Manager {
	inner := dataplane.New()
	inner.XDPEntryProg = "xdp_main_prog"
	return &Manager{
		DataPlane: inner,
		inner:     inner,
		haGroups:  make(map[int]HAGroupStatus),
	}
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
	m.lastSnapshot = snap
	if err := m.programBootstrapMapsLocked(snap, ucfg); err != nil {
		return result, err
	}
	if err := m.ensureProcessLocked(ucfg); err != nil {
		return result, err
	}
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "apply_snapshot", Snapshot: snap}, &status); err != nil {
		return result, fmt.Errorf("publish userspace snapshot: %w", err)
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
	// Immediately push kernel neighbors so the helper can forward
	// without waiting for the first 5-second status loop tick.
	m.refreshNeighborSnapshotLocked()
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

func (m *Manager) bumpGeneration() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.generation++
	return m.generation
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
		Ctrl:      dataplane.UserspaceCtrlPinPath(),
		Bindings:  dataplane.UserspaceBindingsPinPath(),
		Heartbeat: dataplane.UserspaceHeartbeatPinPath(),
		XSK:       dataplane.UserspaceXSKMapPinPath(),
		LocalV4:   dataplane.UserspaceLocalV4PinPath(),
		LocalV6:   dataplane.UserspaceLocalV6PinPath(),
		Sessions:    dataplane.UserspaceSessionsPinPath(),
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
			RedundancyGroup: iface.RedundancyGroup,
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
				RedundancyGroup: iface.RedundancyGroup,
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
		m.bootstrapNAPIQueuesLocked()
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

func (m *Manager) syncHAStateLocked() error {
	if m.proc == nil || m.proc.Process == nil {
		return nil
	}
	if len(m.haGroups) == 0 {
		if err := m.refreshHAStateFromMapsLocked(); err != nil {
			return err
		}
	}
	if len(m.haGroups) == 0 {
		return nil
	}
	groups := make([]HAGroupStatus, 0, len(m.haGroups))
	for _, group := range m.haGroups {
		groups = append(groups, group)
	}
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].RGID < groups[j].RGID
	})
	var status ProcessStatus
	req := ControlRequest{
		Type: "update_ha_state",
		HAState: &HAStateUpdateRequest{
			Groups: groups,
		},
	}
	if err := m.requestLocked(req, &status); err != nil {
		return err
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		return err
	}
	return m.syncDesiredForwardingStateLocked()
}

// SyncFabricState pushes current fabric snapshots (with fresh peer MACs)
// to the Rust helper. Called from the daemon after refreshFabricFwd succeeds
// so the helper has up-to-date fabric MAC info for cross-chassis redirect.
func (m *Manager) SyncFabricState() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil || m.proc.Process == nil || m.lastSnapshot == nil {
		return
	}
	fabrics := buildFabricSnapshots(m.lastSnapshot.Config)
	if len(fabrics) == 0 {
		return
	}
	var status ProcessStatus
	req := ControlRequest{
		Type:    "update_fabrics",
		Fabrics: fabrics,
	}
	if err := m.requestLocked(req, &status); err != nil {
		slog.Debug("userspace: failed to sync fabric state", "err", err)
	}
}

func (m *Manager) refreshHAStateFromMapsLocked() error {
	rgMap := m.inner.Map("rg_active")
	if rgMap == nil {
		return errors.New("rg_active map not loaded")
	}
	wdMap := m.inner.Map("ha_watchdog")
	if wdMap == nil {
		return errors.New("ha_watchdog map not loaded")
	}
	merged, err := mergeHAStateFromMaps(rgMap, wdMap, m.haGroups)
	if err != nil {
		return err
	}
	if len(merged) == 0 {
		return nil
	}
	m.haGroups = merged
	return nil
}

func (m *Manager) seedHAGroupInventoryLocked(cfg *config.Config) {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return
	}
	seeded := make(map[int]HAGroupStatus, len(cfg.Chassis.Cluster.RedundancyGroups)+1)
	if group, ok := m.haGroups[0]; ok {
		group.RGID = 0
		seeded[0] = group
	}
	for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
		if rg == nil || rg.ID < 0 {
			continue
		}
		group := m.haGroups[rg.ID]
		group.RGID = rg.ID
		seeded[rg.ID] = group
	}
	m.haGroups = seeded
}

func mergeHAStateFromMaps(rgMap, wdMap *ebpf.Map, existing map[int]HAGroupStatus) (map[int]HAGroupStatus, error) {
	seen := make(map[int]HAGroupStatus, len(existing))
	for rgID, group := range existing {
		seen[rgID] = group
	}

	var (
		rgKey uint32
		rgVal uint8
	)
	rgIter := rgMap.Iterate()
	for rgIter.Next(&rgKey, &rgVal) {
		group := seen[int(rgKey)]
		group.RGID = int(rgKey)
		group.Active = rgVal != 0
		seen[int(rgKey)] = group
	}
	if err := rgIter.Err(); err != nil {
		return nil, fmt.Errorf("iterate rg_active: %w", err)
	}

	var (
		wdKey uint32
		wdVal uint64
	)
	wdIter := wdMap.Iterate()
	for wdIter.Next(&wdKey, &wdVal) {
		group := seen[int(wdKey)]
		group.RGID = int(wdKey)
		group.WatchdogTimestamp = wdVal
		seen[int(wdKey)] = group
	}
	if err := wdIter.Err(); err != nil {
		return nil, fmt.Errorf("iterate ha_watchdog: %w", err)
	}
	return seen, nil
}

func (m *Manager) desiredForwardingArmedLocked() bool {
	if !m.lastStatus.Capabilities.ForwardingSupported {
		return false
	}
	// Don't arm during the settle window: xsk_socket__create_shared calls
	// __xsk_setup_xdp_prog which segfaults if a link cycle is in progress.
	// 45s covers MAC programming + VRRP elections + networkd. The probe
	// starts at 60s, so bindings are armed 15s before the probe fires.
	if !m.ctrlEnableAt.IsZero() && time.Now().Before(m.ctrlEnableAt.Add(45*time.Second)) {
		return false
	}
	if !m.clusterHA {
		return true
	}
	if m.configHasDataRGLocked() {
		// Keep the helper armed on standby HA nodes so stale-MAC traffic can
		// stay in the userspace fabric redirect path during ownership moves.
		// Per-packet HA resolution still decides whether traffic is forwarded
		// locally or redirected to the active peer.
		return true
	}
	for _, group := range m.haGroups {
		if group.Active {
			return true
		}
	}
	return false
}

func (m *Manager) configHasDataRGLocked() bool {
	if m.lastSnapshot == nil || m.lastSnapshot.Config == nil || m.lastSnapshot.Config.Chassis.Cluster == nil {
		return false
	}
	for _, rg := range m.lastSnapshot.Config.Chassis.Cluster.RedundancyGroups {
		if rg != nil && rg.ID > 0 {
			return true
		}
	}
	return false
}

func (m *Manager) syncDesiredForwardingStateLocked() error {
	if m.proc == nil || m.proc.Process == nil {
		return nil
	}
	desired := m.desiredForwardingArmedLocked()
	if m.lastStatus.ForwardingArmed == desired {
		return nil
	}
	if m.clusterHA {
		slog.Info(
			"userspace: forwarding arm state change",
			"desired", desired,
			"current", m.lastStatus.ForwardingArmed,
			"config_has_data_rg", m.configHasDataRGLocked(),
			"ha_group_count", len(m.haGroups),
		)
	}
	var status ProcessStatus
	req := ControlRequest{
		Type: "set_forwarding_state",
		Forwarding: &ForwardingControlRequest{
			Armed: desired,
		},
	}
	if err := m.requestLocked(req, &status); err != nil {
		return err
	}
	return m.applyHelperStatusLocked(&status)
}

func (m *Manager) UpdateRGActive(rgID int, active bool) error {
	if err := m.inner.UpdateRGActive(rgID, active); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	group := m.haGroups[rgID]
	group.RGID = rgID
	group.Active = active
	m.haGroups[rgID] = group
	return m.syncHAStateLocked()
}

func (m *Manager) UpdateHAWatchdog(rgID int, timestamp uint64) error {
	if err := m.inner.UpdateHAWatchdog(rgID, timestamp); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	group := m.haGroups[rgID]
	group.RGID = rgID
	group.WatchdogTimestamp = timestamp
	m.haGroups[rgID] = group
	return m.syncHAStateLocked()
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
	if status.Enabled {
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
			go m.bootstrapNAPIQueuesLocked()
			m.proactiveNeighborResolveLocked()
		}
		// Check readiness gates BEFORE refreshing neighbors (which
		// bumps the generation). The status reports the generation
		// from the previous refresh cycle.
		allBindingsReady := true
		for _, b := range status.Bindings {
			if b.Ifindex > 0 && b.Registered && !b.Bound {
				allBindingsReady = false
				break
			}
		}
		neighborGenOK := m.neighborGeneration == 0 ||
			status.NeighborGeneration >= m.neighborGeneration

		// Now refresh neighbors for the next cycle.
		m.refreshNeighborSnapshotLocked()

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
		slog.Warn("userspace: ctrl gate check",
			"allBindingsReady", allBindingsReady,
			"neighborGenOK", neighborGenOK,
			"xskReceiveLive", xskReceiveLive,
			"currentRX", currentRX,
			"lastXSKRX", m.lastXSKRX,
			"neighborsPrewarmed", m.neighborsPrewarmed,
			"xskLivenessFailed", m.xskLivenessFailed,
			"xdpEntryProg", m.inner.XDPEntryProg)
		if m.xskLivenessFailed {
			// XSK proven broken — stay on eBPF pipeline, ctrl disabled.
			ctrl.Enabled = 0
		} else if allBindingsReady && neighborGenOK {
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
					m.xskLivenessFailed = true
					m.xskProbeStart = time.Time{}
					ctrl.Enabled = 0
					slog.Warn("userspace: XSK liveness probe failed, falling back to eBPF pipeline")
					if err := m.inner.SwapXDPEntryProg("xdp_main_prog"); err != nil {
						slog.Warn("userspace: failed to swap to eBPF pipeline after XSK liveness failure", "err", err)
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
	// Flush stale BPF session entries when ctrl transitions from
	// disabled to enabled. During ctrl-disabled, the eBPF pipeline
	// creates PASS_TO_KERNEL entries in the userspace session map.
	// These poison the XDP shim after ctrl enables — it sees the stale
	// entry and bypasses XSK, routing packets to the eBPF pipeline
	// instead of the userspace helper.
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
				if deleted > 100000 {
					break
				}
			}
			if deleted > 0 {
				slog.Info("userspace: flushed stale BPF session entries on ctrl enable",
					"deleted", deleted)
			}
		}
	}
	m.ctrlWasEnabled = ctrl.Enabled == 1
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
	m.lastStatus = *status
	return nil
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

	for _, entry := range buildInterfaceNATAddressEntries(snapshot) {
		if entry.v4 {
			if err := natV4Map.Update(entry.v4Key, uint8(1), ebpf.UpdateAny); err != nil {
				return fmt.Errorf("update userspace_interface_nat_v4 %08x: %w", entry.v4Key, err)
			}
			continue
		}
		if err := natV6Map.Update(entry.v6Key, uint8(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update userspace_interface_nat_v6 %+v: %w", entry.v6Key, err)
		}
	}
	return nil
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

func (m *Manager) SetSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) error {
	if err := m.inner.SetSessionV4(key, val); err != nil {
		return err
	}
	if !shouldMirrorUserspaceSession(val.IsReverse) {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_ = m.syncSessionV4Locked("upsert", key, &val)
	return nil
}

func (m *Manager) SetClusterSyncedSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) error {
	installVal := val
	installVal.FibIfindex = 0
	installVal.FibVlanID = 0
	installVal.FibDmac = [6]byte{}
	installVal.FibSmac = [6]byte{}
	installVal.FibGen = 0
	if err := m.inner.SetSessionV4(key, installVal); err != nil {
		return err
	}
	if !shouldMirrorUserspaceSession(val.IsReverse) {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_ = m.syncSessionV4Locked("upsert", key, &val)
	return nil
}

func (m *Manager) SetSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) error {
	if err := m.inner.SetSessionV6(key, val); err != nil {
		return err
	}
	if !shouldMirrorUserspaceSession(val.IsReverse) {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_ = m.syncSessionV6Locked("upsert", key, &val)
	return nil
}

func (m *Manager) SetClusterSyncedSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) error {
	installVal := val
	installVal.FibIfindex = 0
	installVal.FibVlanID = 0
	installVal.FibDmac = [6]byte{}
	installVal.FibSmac = [6]byte{}
	installVal.FibGen = 0
	if err := m.inner.SetSessionV6(key, installVal); err != nil {
		return err
	}
	if !shouldMirrorUserspaceSession(val.IsReverse) {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_ = m.syncSessionV6Locked("upsert", key, &val)
	return nil
}

func shouldMirrorUserspaceSession(isReverse uint8) bool {
	return isReverse == 0
}

func (m *Manager) DeleteSession(key dataplane.SessionKey) error {
	if err := m.inner.DeleteSession(key); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_ = m.syncSessionV4Locked("delete", key, nil)
	return nil
}

func (m *Manager) DeleteSessionV6(key dataplane.SessionKeyV6) error {
	if err := m.inner.DeleteSessionV6(key); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_ = m.syncSessionV6Locked("delete", key, nil)
	return nil
}

func (m *Manager) syncSessionV4Locked(op string, key dataplane.SessionKey, val *dataplane.SessionValue) error {
	if m.proc == nil {
		return nil
	}
	req := m.buildSessionSyncRequestV4(op, key, val)
	return m.syncSessionRequestLocked(req)
}

func (m *Manager) buildSessionSyncRequestV4(op string, key dataplane.SessionKey, val *dataplane.SessionValue) SessionSyncRequest {
	req := SessionSyncRequest{
		Operation:  op,
		AddrFamily: dataplane.AFInet,
		Protocol:   key.Protocol,
		SrcIP:      net.IP(key.SrcIP[:]).String(),
		DstIP:      net.IP(key.DstIP[:]).String(),
		SrcPort:    networkUint16ToHost(key.SrcPort),
		DstPort:    networkUint16ToHost(key.DstPort),
	}
	if val != nil {
		req.IngressZone = m.zoneNameByID(val.IngressZone)
		req.EgressZone = m.zoneNameByID(val.EgressZone)
		req.EgressIfindex, req.TXIfindex, req.OwnerRGID = m.sessionSyncEgressLocked(int(val.FibIfindex), val.FibVlanID)
		req.TunnelEndpointID = m.sessionSyncTunnelEndpointIDLocked(req.EgressIfindex)
		if val.LogFlags&dataplane.LogFlagUserspaceTunnelEndpoint != 0 && val.FibGen != 0 {
			req.TunnelEndpointID = val.FibGen
		}
		if req.TunnelEndpointID != 0 {
			if endpoint, ok := m.sessionSyncTunnelEndpointLocked(req.TunnelEndpointID); ok {
				req.EgressIfindex = endpoint.Ifindex
				req.OwnerRGID = endpoint.RedundancyGroup
			} else {
				req.EgressIfindex = 0
				req.OwnerRGID = 0
			}
			req.TXIfindex = 0
			req.TXVLANID = 0
			req.NeighborMAC = ""
			req.SrcMAC = ""
		} else {
			req.TXVLANID = val.FibVlanID
			req.NeighborMAC = macString(val.FibDmac[:])
			req.SrcMAC = macString(val.FibSmac[:])
		}
		req.NATSrcIP = ipString(nativeUint32ToIP(val.NATSrcIP))
		req.NATDstIP = ipString(nativeUint32ToIP(val.NATDstIP))
		req.NATSrcPort = networkUint16ToHost(val.NATSrcPort)
		req.NATDstPort = networkUint16ToHost(val.NATDstPort)
		req.FabricIngress = val.LogFlags&dataplane.LogFlagUserspaceFabricIngress != 0
		req.IsReverse = val.IsReverse != 0
		if val.Flags&dataplane.SessFlagSNAT == 0 {
			req.NATSrcIP = ""
			req.NATSrcPort = 0
		}
		if val.Flags&dataplane.SessFlagDNAT == 0 {
			req.NATDstIP = ""
			req.NATDstPort = 0
		}
	}
	return req
}

func (m *Manager) syncSessionV6Locked(op string, key dataplane.SessionKeyV6, val *dataplane.SessionValueV6) error {
	if m.proc == nil {
		return nil
	}
	req := m.buildSessionSyncRequestV6(op, key, val)
	return m.syncSessionRequestLocked(req)
}

func (m *Manager) buildSessionSyncRequestV6(op string, key dataplane.SessionKeyV6, val *dataplane.SessionValueV6) SessionSyncRequest {
	req := SessionSyncRequest{
		Operation:  op,
		AddrFamily: dataplane.AFInet6,
		Protocol:   key.Protocol,
		SrcIP:      net.IP(key.SrcIP[:]).String(),
		DstIP:      net.IP(key.DstIP[:]).String(),
		SrcPort:    networkUint16ToHost(key.SrcPort),
		DstPort:    networkUint16ToHost(key.DstPort),
	}
	if val != nil {
		req.IngressZone = m.zoneNameByID(val.IngressZone)
		req.EgressZone = m.zoneNameByID(val.EgressZone)
		req.EgressIfindex, req.TXIfindex, req.OwnerRGID = m.sessionSyncEgressLocked(int(val.FibIfindex), val.FibVlanID)
		req.TunnelEndpointID = m.sessionSyncTunnelEndpointIDLocked(req.EgressIfindex)
		if val.LogFlags&dataplane.LogFlagUserspaceTunnelEndpoint != 0 && val.FibGen != 0 {
			req.TunnelEndpointID = val.FibGen
		}
		if req.TunnelEndpointID != 0 {
			if endpoint, ok := m.sessionSyncTunnelEndpointLocked(req.TunnelEndpointID); ok {
				req.EgressIfindex = endpoint.Ifindex
				req.OwnerRGID = endpoint.RedundancyGroup
			} else {
				req.EgressIfindex = 0
				req.OwnerRGID = 0
			}
			req.TXIfindex = 0
			req.TXVLANID = 0
			req.NeighborMAC = ""
			req.SrcMAC = ""
		} else {
			req.TXVLANID = val.FibVlanID
			req.NeighborMAC = macString(val.FibDmac[:])
			req.SrcMAC = macString(val.FibSmac[:])
		}
		req.NATSrcIP = ipString(net.IP(val.NATSrcIP[:]))
		req.NATDstIP = ipString(net.IP(val.NATDstIP[:]))
		req.NATSrcPort = networkUint16ToHost(val.NATSrcPort)
		req.NATDstPort = networkUint16ToHost(val.NATDstPort)
		req.FabricIngress = val.LogFlags&dataplane.LogFlagUserspaceFabricIngress != 0
		req.IsReverse = val.IsReverse != 0
		if val.Flags&dataplane.SessFlagSNAT == 0 {
			req.NATSrcIP = ""
			req.NATSrcPort = 0
		}
		if val.Flags&dataplane.SessFlagDNAT == 0 {
			req.NATDstIP = ""
			req.NATDstPort = 0
		}
	}
	return req
}

func (m *Manager) sessionSyncTunnelEndpointIDLocked(egressIfindex int) uint16 {
	snapshot := m.lastSnapshot
	if snapshot == nil || egressIfindex <= 0 {
		return 0
	}
	for _, endpoint := range snapshot.TunnelEndpoints {
		if endpoint.Ifindex == egressIfindex {
			return endpoint.ID
		}
	}
	return 0
}

func (m *Manager) sessionSyncTunnelEndpointLocked(id uint16) (TunnelEndpointSnapshot, bool) {
	snapshot := m.lastSnapshot
	if snapshot == nil || id == 0 {
		return TunnelEndpointSnapshot{}, false
	}
	for _, endpoint := range snapshot.TunnelEndpoints {
		if endpoint.ID == id {
			return endpoint, true
		}
	}
	return TunnelEndpointSnapshot{}, false
}

func (m *Manager) syncSessionRequestLocked(req SessionSyncRequest) error {
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{
		Type:        "sync_session",
		SessionSync: &req,
	}, &status); err != nil {
		slog.Warn("userspace session sync mirror failed", "operation", req.Operation, "err", err)
		return err
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		slog.Warn("userspace session sync status apply failed", "operation", req.Operation, "err", err)
		return err
	}
	return nil
}

func (m *Manager) zoneNameByID(zoneID uint16) string {
	if zoneID == 0 {
		return ""
	}
	if cr := m.inner.LastCompileResult(); cr != nil {
		for name, id := range cr.ZoneIDs {
			if id == zoneID {
				return name
			}
		}
	}
	return ""
}

func nativeUint32ToIP(v uint32) net.IP {
	if v == 0 {
		return nil
	}
	var raw [4]byte
	binary.NativeEndian.PutUint32(raw[:], v)
	return net.IPv4(raw[0], raw[1], raw[2], raw[3]).To4()
}

func networkUint16ToHost(v uint16) uint16 {
	var raw [2]byte
	binary.NativeEndian.PutUint16(raw[:], v)
	return binary.BigEndian.Uint16(raw[:])
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil && v4.Equal(net.IPv4zero) {
		return ""
	}
	if v6 := ip.To16(); v6 != nil && v6.Equal(net.IPv6zero) {
		return ""
	}
	return ip.String()
}

func macString(raw []byte) string {
	if len(raw) < 6 {
		return ""
	}
	allZero := true
	for i := 0; i < 6; i++ {
		if raw[i] != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return ""
	}
	return net.HardwareAddr(raw[:6]).String()
}

func (m *Manager) sessionSyncEgressLocked(fibIfindex int, fibVlanID uint16) (egressIfindex, txIfindex, ownerRGID int) {
	snapshot := m.lastSnapshot
	if snapshot == nil || fibIfindex <= 0 {
		return fibIfindex, fibIfindex, 0
	}
	if iface, ok := findUserspaceEgressInterfaceSnapshot(snapshot, fibIfindex, fibVlanID); ok {
		egress := iface.Ifindex
		if egress <= 0 {
			egress = fibIfindex
		}
		tx := iface.ParentIfindex
		if tx <= 0 {
			tx = egress
		}
		return egress, tx, iface.RedundancyGroup
	}
	return fibIfindex, fibIfindex, 0
}

func findUserspaceEgressInterfaceSnapshot(snapshot *ConfigSnapshot, fibIfindex int, fibVlanID uint16) (InterfaceSnapshot, bool) {
	if snapshot == nil {
		return InterfaceSnapshot{}, false
	}
	if fibVlanID != 0 {
		for _, iface := range snapshot.Interfaces {
			if iface.ParentIfindex == fibIfindex && iface.VLANID == int(fibVlanID) {
				return iface, true
			}
		}
	}
	for _, iface := range snapshot.Interfaces {
		if iface.Ifindex == fibIfindex {
			return iface, true
		}
	}
	for _, iface := range snapshot.Interfaces {
		if iface.ParentIfindex == fibIfindex {
			return iface, true
		}
	}
	return InterfaceSnapshot{}, false
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
	var neighborTick int
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
			var status ProcessStatus
			if err := m.requestLocked(ControlRequest{Type: "status"}, &status); err == nil {
				if err := m.applyHelperStatusLocked(&status); err != nil {
					slog.Warn("userspace dataplane status sync failed", "err", err)
				}
				if m.clusterHA && len(m.haGroups) == 0 {
					_ = m.refreshHAStateFromMapsLocked()
				}
				if err := m.syncDesiredForwardingStateLocked(); err != nil {
					slog.Warn("userspace dataplane forwarding sync failed", "err", err)
				}
			} else {
				slog.Warn("userspace dataplane status poll failed", "err", err)
			}
			// Refresh kernel neighbors. During the first 60 seconds
			// after startup, refresh every tick (1s) and proactively
			// resolve stale entries. This covers the VRRP election
			// window (30-40s) plus neighbor resolution time.
			neighborTick++
			neighborInterval := 5
			sinceStart := time.Since(startTime)
			if sinceStart < 60*time.Second {
				neighborInterval = 1
			}
			if neighborTick >= neighborInterval && m.lastSnapshot != nil && m.lastSnapshot.Config != nil {
				neighborTick = 0
				// During startup, also proactively resolve stale/failed
				// neighbors so the helper has fresh entries as soon as
				// VIPs are assigned.
				if sinceStart < 60*time.Second {
					m.proactiveNeighborResolveAsyncLocked()
				}
				m.refreshNeighborSnapshotLocked()
			}
			m.mu.Unlock()
		}
	}
}

func (m *Manager) refreshNeighborSnapshotLocked() {
	if m.proc == nil || m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
		return
	}
	neighbors := buildNeighborSnapshots(m.lastSnapshot.Config)
	if len(neighbors) == 0 {
		return
	}
	// Bump generation and push neighbor update to the helper.
	// Use additive mode (replace=false) so learned neighbors from
	// the netlink monitor and packet path are preserved. The manager's
	// entries are authoritative and override any learned entry for the
	// same (ifindex, ip) key, but learned entries for hosts not in the
	// manager snapshot (e.g. 172.16.80.200) survive.
	m.neighborGeneration++
	m.lastSnapshot.Neighbors = neighbors
	var status ProcessStatus
	req := ControlRequest{
		Type:               "update_neighbors",
		Neighbors:          neighbors,
		NeighborGeneration: m.neighborGeneration,
		NeighborReplace:    false,
	}
	if err := m.requestLocked(req, &status); err != nil {
		slog.Warn("userspace neighbor refresh failed", "err", err)
	}
}

func (m *Manager) stopLocked() {
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
	seen := make(map[string]bool)
	for ifName, ifc := range m.lastSnapshot.Config.Interfaces.Interfaces {
		for _, unit := range ifc.Units {
			base := config.LinuxIfName(ifName)
			linuxName := base
			if unit.VlanID > 0 {
				linuxName = fmt.Sprintf("%s.%d", base, unit.VlanID)
			}
			if seen[linuxName] {
				continue
			}
			seen[linuxName] = true
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
	var targets []struct{ iface, ip string }
	for ifName, ifc := range m.lastSnapshot.Config.Interfaces.Interfaces {
		for _, unit := range ifc.Units {
			base := config.LinuxIfName(ifName)
			linuxName := base
			if unit.VlanID > 0 {
				linuxName = fmt.Sprintf("%s.%d", base, unit.VlanID)
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
				for _, n := range neighs {
					if n.IP == nil || n.IP.IsLinkLocalUnicast() {
						continue
					}
					if n.HardwareAddr == nil || len(n.HardwareAddr) == 0 ||
						n.State == netlink.NUD_STALE || n.State == netlink.NUD_FAILED {
						targets = append(targets, struct{ iface, ip string }{linuxName, n.IP.String()})
					}
				}
			}
		}
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
	// Let the NIC reinitialize after link UP before recreating XSK sockets.
	time.Sleep(200 * time.Millisecond)

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
	go m.bootstrapNAPIQueuesLocked()
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
