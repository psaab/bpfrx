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
}

func New() *Manager {
	inner := dataplane.New()
	inner.XDPEntryProg = "xdp_userspace_prog"
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
	caps := deriveUserspaceCapabilities(cfg)
	if caps.ForwardingSupported {
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
	// Tunnel interfaces (GRE, ip6gre, XFRM) are handled by the eBPF
	// pipeline which prepends/strips the pseudo-Ethernet header. The
	// userspace worker detects ESP/IKE and routes to slow-path for XFRM.
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
		Version:       ProtocolVersion,
		Generation:    generation,
		FIBGeneration: fibGeneration,
		GeneratedAt:   time.Now().UTC(),
		Capabilities:  deriveUserspaceCapabilities(cfg),
		MapPins:       userspaceMapPins(),
		Userspace:     ucfg,
		Zones:         buildZoneSnapshots(cfg),
		Interfaces:    interfaces,
		Fabrics:       buildFabricSnapshots(cfg),
		Neighbors:     buildNeighborSnapshots(cfg),
		Routes:        buildRouteSnapshots(cfg, interfaces),
		Flow: buildFlowSnapshot(cfg),
		DefaultPolicy: policyActionString(cfg.Security.DefaultPolicy),
		Policies:      buildPolicySnapshots(cfg),
		SourceNAT:      buildSourceNATSnapshots(cfg),
		StaticNAT:      buildStaticNATSnapshots(cfg),
		DestinationNAT: buildDestinationNATSnapshots(cfg),
		NAT64:          buildNAT64Snapshots(cfg),
		Nptv6:          buildNptv6Snapshots(cfg),
		Screens:        buildScreenSnapshots(cfg),
		Filters:        buildFirewallFilterSnapshots(cfg),
		Policers:       buildPolicerSnapshots(cfg),
		FlowExport:     buildFlowExportSnapshot(cfg),
		Config:        cfg,
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
		parentIfindex, _, _, _ := buildLinkSnapshot(parentLinux)
		overlayLinux := config.LinuxIfName(in.name)
		overlayIfindex, _, _, _ := buildLinkSnapshot(overlayLinux)
		rxQueues := 0
		if parentLinux != "" {
			rxQueues = userspaceRXQueueCount(parentLinux)
		}
		out = append(out, FabricSnapshot{
			Name:            in.name,
			ParentInterface: parentName,
			ParentLinuxName: parentLinux,
			ParentIfindex:   parentIfindex,
			OverlayLinux:    overlayLinux,
			OverlayIfindex:  overlayIfindex,
			RXQueues:        rxQueues,
			PeerAddress:     in.peer,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

func userspaceMapPins() UserspaceMapPins {
	return UserspaceMapPins{
		Ctrl:      dataplane.UserspaceCtrlPinPath(),
		Bindings:  dataplane.UserspaceBindingsPinPath(),
		Heartbeat: dataplane.UserspaceHeartbeatPinPath(),
		XSK:       dataplane.UserspaceXSKMapPinPath(),
		LocalV4:   dataplane.UserspaceLocalV4PinPath(),
		LocalV6:   dataplane.UserspaceLocalV6PinPath(),
		Sessions:  dataplane.UserspaceSessionsPinPath(),
		Trace:     dataplane.UserspaceTracePinPath(),
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
				Table:     mainTable,
				Family:    familyStr,
				Destination: rule.Dst.String(),
				NextTable: tableName,
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
			NoFlag:   sp.TCP.NoFlag,
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
	cmd := exec.Command(binary,
		"--control-socket", cfg.ControlSocket,
		"--state-file", cfg.StateFile,
		"--workers", fmt.Sprintf("%d", cfg.Workers),
		"--ring-entries", fmt.Sprintf("%d", cfg.RingEntries),
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start userspace dataplane helper: %w", err)
	}
	m.cfg = cfg
	m.proc = cmd
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
	if !m.clusterHA {
		return true
	}
	if len(m.haGroups) == 0 {
		return false
	}
	hasDataRG := false
	for rgID, group := range m.haGroups {
		if rgID <= 0 {
			continue
		}
		hasDataRG = true
		if group.Active {
			return true
		}
	}
	if !hasDataRG {
		for _, group := range m.haGroups {
			if group.Active {
				return true
			}
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
	ctrl := userspaceCtrlValue{
		Enabled:            0,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            uint32(cfg.Workers),
		QueueCount:         uint32(maxInt(cfg.Workers, 1)),
		Flags:              ctrlFlags,
		ConfigGeneration:   0,
		FIBGeneration:      0,
		HeartbeatTimeoutMS: 5000,
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

	// Bindings map is now an Array — zero previously-set indices.
	{
		var zeroBinding userspaceBindingValue
		for _, idx := range m.lastBindingIndices {
			_ = bindingsMap.Update(idx, zeroBinding, ebpf.UpdateAny)
		}
		m.lastBindingIndices = nil
	}

	// Preserve cpumap flag if cpumap is populated.
	var ctrlFlags uint32
	if cpuMap := m.inner.Map("userspace_cpumap"); cpuMap != nil {
		ctrlFlags |= userspaceCtrlFlagCPUMap
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
		HeartbeatTimeoutMS: 5000,
	}
	if status.Enabled {
		ctrl.Enabled = 1
	}
	if err := ctrlMap.Update(zero, ctrl, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update userspace_ctrl from helper status: %w", err)
	}

	for _, binding := range status.Bindings {
		if binding.Ifindex <= 0 {
			continue
		}
		flags := uint32(0)
		if binding.Registered && binding.Armed && binding.Ready {
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
		m.lastBindingIndices = append(m.lastBindingIndices, idx)
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

	// Map is now an Array[1024] — zero previous entries, set new ones to 1.
	for _, k := range m.lastIngressIfaces {
		_ = ifaceMap.Update(k, uint8(0), ebpf.UpdateAny)
	}
	m.lastIngressIfaces = nil
	for _, ifindex := range buildUserspaceIngressIfindexes(snapshot) {
		if err := ifaceMap.Update(ifindex, uint8(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update userspace_ingress_ifaces %d: %w", ifindex, err)
		}
		m.lastIngressIfaces = append(m.lastIngressIfaces, ifindex)
	}
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
	m.mu.Lock()
	defer m.mu.Unlock()
	_ = m.syncSessionV4Locked("upsert", key, &val)
	return nil
}

func (m *Manager) SetSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) error {
	if err := m.inner.SetSessionV6(key, val); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_ = m.syncSessionV6Locked("upsert", key, &val)
	return nil
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
	req := SessionSyncRequest{
		Operation:  op,
		AddrFamily: dataplane.AFInet,
		Protocol:   key.Protocol,
		SrcIP:      net.IP(key.SrcIP[:]).String(),
		DstIP:      net.IP(key.DstIP[:]).String(),
		SrcPort:    key.SrcPort,
		DstPort:    key.DstPort,
	}
	if val != nil {
		req.IngressZone = m.zoneNameByID(val.IngressZone)
		req.EgressZone = m.zoneNameByID(val.EgressZone)
		req.EgressIfindex, req.TXIfindex, req.OwnerRGID = m.sessionSyncEgressLocked(int(val.FibIfindex), val.FibVlanID)
		req.TXVLANID = val.FibVlanID
		req.NeighborMAC = macString(val.FibDmac[:])
		req.SrcMAC = macString(val.FibSmac[:])
		req.NATSrcIP = ipString(nativeUint32ToIP(val.NATSrcIP))
		req.NATDstIP = ipString(nativeUint32ToIP(val.NATDstIP))
		req.NATSrcPort = val.NATSrcPort
		req.NATDstPort = val.NATDstPort
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
	return m.syncSessionRequestLocked(req)
}

func (m *Manager) syncSessionV6Locked(op string, key dataplane.SessionKeyV6, val *dataplane.SessionValueV6) error {
	if m.proc == nil {
		return nil
	}
	req := SessionSyncRequest{
		Operation:  op,
		AddrFamily: dataplane.AFInet6,
		Protocol:   key.Protocol,
		SrcIP:      net.IP(key.SrcIP[:]).String(),
		DstIP:      net.IP(key.DstIP[:]).String(),
		SrcPort:    key.SrcPort,
		DstPort:    key.DstPort,
	}
	if val != nil {
		req.IngressZone = m.zoneNameByID(val.IngressZone)
		req.EgressZone = m.zoneNameByID(val.EgressZone)
		req.EgressIfindex, req.TXIfindex, req.OwnerRGID = m.sessionSyncEgressLocked(int(val.FibIfindex), val.FibVlanID)
		req.TXVLANID = val.FibVlanID
		req.NeighborMAC = macString(val.FibDmac[:])
		req.SrcMAC = macString(val.FibSmac[:])
		req.NATSrcIP = ipString(net.IP(val.NATSrcIP[:]))
		req.NATDstIP = ipString(net.IP(val.NATDstIP[:]))
		req.NATSrcPort = val.NATSrcPort
		req.NATDstPort = val.NATDstPort
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
	return m.syncSessionRequestLocked(req)
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

func userspaceSkipsIngressInterface(iface InterfaceSnapshot) bool {
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
			m.mu.Unlock()
		}
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
func (m *Manager) NotifyLinkCycle() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil || m.proc.Process == nil {
		return
	}
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
