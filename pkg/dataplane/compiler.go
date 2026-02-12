package dataplane

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/psaab/bpfrx/pkg/config"
	"github.com/vishvananda/netlink"
)

// CompileResult holds the result of a config compilation for reference.
type CompileResult struct {
	ZoneIDs    map[string]uint16 // zone name -> zone ID
	ScreenIDs  map[string]uint16 // screen profile name -> profile ID (1-based)
	AddrIDs    map[string]uint32 // address name -> address ID
	AppIDs     map[string]uint32 // application name -> app ID
	PoolIDs    map[string]uint8  // NAT pool name -> pool ID (0-based)
	PolicySets int               // number of policy sets created

	nextAddrID       uint32            // next available address ID (after address book)
	implicitSets     map[string]uint32 // cache of implicit set key -> set ID
	nextNATCounterID uint16            // next available NAT rule counter ID (1-based, 0 = no counter)
	NATCounterIDs    map[string]uint16 // "rulesetName/ruleName" -> counter ID

	// pendingXDP/TC collect interface indexes for deferred program attachment.
	// Attachment happens AFTER all compilation phases so that link.Update()
	// atomically switches to programs with fully-populated maps.
	pendingXDP []int
	pendingTC  []int
}

// Compile translates a typed Config into eBPF map entries.
func (m *Manager) Compile(cfg *config.Config) (*CompileResult, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil config")
	}
	if !m.loaded {
		return nil, fmt.Errorf("eBPF programs not loaded")
	}

	result := &CompileResult{
		ZoneIDs:          make(map[string]uint16),
		ScreenIDs:        make(map[string]uint16),
		AddrIDs:          make(map[string]uint32),
		AppIDs:           make(map[string]uint32),
		PoolIDs:          make(map[string]uint8),
		implicitSets:     make(map[string]uint32),
		nextNATCounterID: 1, // 0 = no counter
		NATCounterIDs:    make(map[string]uint16),
	}

	// Phase 1: Assign zone IDs (1-based; 0 = unassigned)
	zoneID := uint16(1)
	for name := range cfg.Security.Zones {
		result.ZoneIDs[name] = zoneID
		zoneID++
	}

	// Phase 1.5: Assign screen profile IDs (1-based; 0 = no profile)
	screenID := uint16(1)
	for name := range cfg.Security.Screen {
		result.ScreenIDs[name] = screenID
		screenID++
	}

	// Phase 2: Compile zones
	if err := m.compileZones(cfg, result); err != nil {
		return nil, fmt.Errorf("compile zones: %w", err)
	}

	// Phase 3: Compile address book
	if err := m.compileAddressBook(cfg, result); err != nil {
		return nil, fmt.Errorf("compile address book: %w", err)
	}

	// Phase 4: Compile applications
	if err := m.compileApplications(cfg, result); err != nil {
		return nil, fmt.Errorf("compile applications: %w", err)
	}

	// Phase 5: Compile policies
	if err := m.compilePolicies(cfg, result); err != nil {
		return nil, fmt.Errorf("compile policies: %w", err)
	}

	// Phase 6: Compile NAT
	if err := m.compileNAT(cfg, result); err != nil {
		return nil, fmt.Errorf("compile nat: %w", err)
	}

	// Phase 6.5: Compile static NAT
	if err := m.compileStaticNAT(cfg, result); err != nil {
		return nil, fmt.Errorf("compile static nat: %w", err)
	}

	// Phase 6.6: Compile NAT64 prefixes
	if err := m.compileNAT64(cfg, result); err != nil {
		return nil, fmt.Errorf("compile nat64: %w", err)
	}

	// Phase 7: Compile screen profiles
	if err := m.compileScreenProfiles(cfg, result); err != nil {
		return nil, fmt.Errorf("compile screen profiles: %w", err)
	}

	// Phase 8: Compile default policy
	if err := m.compileDefaultPolicy(cfg); err != nil {
		return nil, fmt.Errorf("compile default policy: %w", err)
	}

	// Phase 9: Compile flow timeouts
	if err := m.compileFlowTimeouts(cfg); err != nil {
		return nil, fmt.Errorf("compile flow timeouts: %w", err)
	}

	// Phase 9b: Compile flow config (TCP MSS clamp, etc.)
	if err := m.compileFlowConfig(cfg); err != nil {
		return nil, fmt.Errorf("compile flow config: %w", err)
	}

	// Phase 10: Compile firewall filters
	if err := m.compileFirewallFilters(cfg, result); err != nil {
		return nil, fmt.Errorf("compile firewall filters: %w", err)
	}

	// All maps are now fully populated. Attach XDP/TC programs last so that
	// link.Update() atomically switches to programs with complete config.
	// This eliminates the brief window where new programs run with empty
	// policy/NAT maps — critical for hitless restarts.
	for _, ifidx := range result.pendingTC {
		if err := m.AttachTC(ifidx); err != nil {
			if !strings.Contains(err.Error(), "already attached") {
				return nil, fmt.Errorf("attach TC to ifindex %d: %w", ifidx, err)
			}
		}
	}

	if len(result.pendingXDP) > 0 {
		rcMap := m.maps["redirect_capable"]

		// Try native XDP on all interfaces first. If any interface lacks
		// native support, ALL must use generic mode because bpf_redirect_map
		// from native XDP cannot target non-ndo_xdp_xmit interfaces.
		needGeneric := false
		for _, ifidx := range result.pendingXDP {
			if err := m.AttachXDP(ifidx, false); err != nil {
				if strings.Contains(err.Error(), "already attached") {
					continue
				}
				slog.Info("native XDP not supported, falling back ALL to generic",
					"ifindex", ifidx, "err", err)
				needGeneric = true
				break
			}
		}

		if needGeneric {
			// Detach any native links we just created, then attach all as generic.
			for _, ifidx := range result.pendingXDP {
				m.DetachXDP(ifidx)
			}
			for _, ifidx := range result.pendingXDP {
				if err := m.AttachXDP(ifidx, true); err != nil {
					if !strings.Contains(err.Error(), "already attached") {
						return nil, fmt.Errorf("attach XDP generic to ifindex %d: %w", ifidx, err)
					}
				}
			}
		}

		// All interfaces use the same mode — redirect works between all of them.
		if rcMap != nil {
			for _, ifidx := range result.pendingXDP {
				rcMap.Update(uint32(ifidx), uint8(1), ebpf.UpdateAny)
			}
		}
	}

	slog.Info("config compiled to dataplane",
		"zones", len(result.ZoneIDs),
		"addresses", len(result.AddrIDs),
		"applications", len(result.AppIDs),
		"policy_sets", result.PolicySets)

	m.lastCompile = result
	return result, nil
}

// resolveInterfaceRef parses an interface reference like "enp6s0" or "enp6s0.100"
// and returns the physical interface name, unit number, and VLAN ID from config.
func resolveInterfaceRef(ref string, cfg *config.Config) (physName string, unitNum int, vlanID int) {
	parts := strings.SplitN(ref, ".", 2)
	physName = parts[0]
	if len(parts) == 2 {
		unitNum, _ = strconv.Atoi(parts[1])
	}

	// Look up VLAN ID from interface config
	if ifCfg, ok := cfg.Interfaces.Interfaces[physName]; ok {
		if unit, ok := ifCfg.Units[unitNum]; ok {
			vlanID = unit.VlanID
		}
	}
	return
}

// ensureVLANSubInterface creates a Linux VLAN sub-interface if it doesn't exist.
// Returns the sub-interface's ifindex.
func ensureVLANSubInterface(parentName string, vlanID int) (int, error) {
	parent, err := netlink.LinkByName(parentName)
	if err != nil {
		return 0, fmt.Errorf("parent interface %s: %w", parentName, err)
	}

	subName := fmt.Sprintf("%s.%d", parentName, vlanID)

	// Check if sub-interface already exists
	existing, err := netlink.LinkByName(subName)
	if err == nil {
		// Already exists, ensure it's up
		if existing.Attrs().OperState != netlink.OperUp {
			netlink.LinkSetUp(existing)
		}
		return existing.Attrs().Index, nil
	}

	// Create VLAN sub-interface
	vlan := &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        subName,
			ParentIndex: parent.Attrs().Index,
		},
		VlanId: vlanID,
	}
	if err := netlink.LinkAdd(vlan); err != nil {
		return 0, fmt.Errorf("create VLAN sub-interface %s: %w", subName, err)
	}

	// Bring it up
	link, err := netlink.LinkByName(subName)
	if err != nil {
		return 0, fmt.Errorf("find created VLAN sub-interface %s: %w", subName, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return 0, fmt.Errorf("set VLAN sub-interface %s up: %w", subName, err)
	}

	slog.Info("created VLAN sub-interface",
		"name", subName, "parent", parentName, "vlan_id", vlanID,
		"ifindex", link.Attrs().Index)

	return link.Attrs().Index, nil
}

// assignInterfaceAddresses assigns configured addresses to a physical interface via netlink.
func assignInterfaceAddresses(ifaceName string, addresses []string) {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		slog.Warn("cannot find interface for address assignment",
			"name", ifaceName, "err", err)
		return
	}
	for _, addrStr := range addresses {
		addr, err := netlink.ParseAddr(addrStr)
		if err != nil {
			slog.Warn("invalid address for interface",
				"addr", addrStr, "name", ifaceName, "err", err)
			continue
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			// EEXIST is fine
			if !strings.Contains(err.Error(), "exists") {
				slog.Warn("failed to add address to interface",
					"addr", addrStr, "name", ifaceName, "err", err)
			}
		}
	}
}

// assignSubInterfaceAddresses assigns configured addresses to a VLAN sub-interface via netlink.
func assignSubInterfaceAddresses(subName string, addresses []string) {
	link, err := netlink.LinkByName(subName)
	if err != nil {
		slog.Warn("cannot find sub-interface for address assignment",
			"name", subName, "err", err)
		return
	}
	for _, addrStr := range addresses {
		addr, err := netlink.ParseAddr(addrStr)
		if err != nil {
			slog.Warn("invalid address for sub-interface",
				"addr", addrStr, "name", subName, "err", err)
			continue
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			// EEXIST is fine
			if !strings.Contains(err.Error(), "exists") {
				slog.Warn("failed to add address to sub-interface",
					"addr", addrStr, "name", subName, "err", err)
			}
		}
	}
}

func (m *Manager) compileZones(cfg *config.Config, result *CompileResult) error {
	// Clear previous zone and VLAN mappings for recompile
	if err := m.ClearIfaceZoneMap(); err != nil {
		slog.Warn("failed to clear iface_zone_map", "err", err)
	}
	if err := m.ClearVlanIfaceMap(); err != nil {
		slog.Warn("failed to clear vlan_iface_map", "err", err)
	}

	// Track which physical interfaces we've already attached to
	attached := make(map[int]bool)
	// Collect physical ifindexes for deferred XDP attachment
	var xdpIfindexes []int

	for name, zone := range cfg.Security.Zones {
		zid := result.ZoneIDs[name]

		// Write zone_config
		zc := ZoneConfig{
			ZoneID: zid,
		}

		// Look up screen profile ID for this zone
		if zone.ScreenProfile != "" {
			if sid, ok := result.ScreenIDs[zone.ScreenProfile]; ok {
				zc.ScreenProfileID = sid
				slog.Info("zone screen profile assigned",
					"zone", name, "screen", zone.ScreenProfile, "id", sid)
			} else {
				return fmt.Errorf("screen profile %q not found for zone %q",
					zone.ScreenProfile, name)
			}
		}

		// Compile host-inbound-traffic flags
		if zone.HostInboundTraffic != nil {
			var flags uint32
			for _, svc := range zone.HostInboundTraffic.SystemServices {
				if f, ok := HostInboundServiceFlags[svc]; ok {
					flags |= f
				} else {
					slog.Warn("unknown host-inbound system-service",
						"service", svc, "zone", name)
				}
			}
			for _, proto := range zone.HostInboundTraffic.Protocols {
				if f, ok := HostInboundProtocolFlags[proto]; ok {
					flags |= f
				} else {
					slog.Warn("unknown host-inbound protocol",
						"protocol", proto, "zone", name)
				}
			}
			zc.HostInbound = flags
			slog.Info("host-inbound-traffic compiled",
				"zone", name, "flags", fmt.Sprintf("0x%x", flags))
		}

		if err := m.SetZoneConfig(zid, zc); err != nil {
			return fmt.Errorf("set zone config %s: %w", name, err)
		}

		// Map interfaces to zone
		for _, ifaceRef := range zone.Interfaces {
			physName, unitNum, vlanID := resolveInterfaceRef(ifaceRef, cfg)

			// Get the physical interface
			physIface, err := net.InterfaceByName(physName)
			if err != nil {
				slog.Warn("interface not found, skipping",
					"interface", physName, "zone", name, "err", err)
				continue
			}

			if vlanID > 0 {
				// VLAN sub-interface: create it, populate vlan_iface_map
				subIfindex, err := ensureVLANSubInterface(physName, vlanID)
				if err != nil {
					slog.Warn("VLAN sub-interface failed, skipping",
						"parent", physName, "vlan_id", vlanID, "zone", name, "err", err)
					continue
				}

				if err := m.SetVlanIfaceInfo(subIfindex, physIface.Index, uint16(vlanID)); err != nil {
					return fmt.Errorf("set vlan_iface_info %s.%d: %w",
						physName, vlanID, err)
				}

				// Assign addresses from unit config to sub-interface
				if ifCfg, ok := cfg.Interfaces.Interfaces[physName]; ok {
					if unit, ok := ifCfg.Units[unitNum]; ok && len(unit.Addresses) > 0 {
						subName := fmt.Sprintf("%s.%d", physName, vlanID)
						assignSubInterfaceAddresses(subName, unit.Addresses)
					}
				}

				slog.Info("VLAN sub-interface configured",
					"parent", physName, "vlan_id", vlanID,
					"sub_ifindex", subIfindex, "zone", name)
			}

			// Set zone mapping using composite key {physIfindex, vlanID}
			if err := m.SetZone(physIface.Index, uint16(vlanID), zid); err != nil {
				return fmt.Errorf("set zone for %s vlan %d (ifindex %d): %w",
					physName, vlanID, physIface.Index, err)
			}

			// Add physical interface to tx_ports and attach TC (once per phys iface).
			// XDP attachment is deferred to after the loop so we can ensure
			// all interfaces use the same XDP mode (native vs generic).
			if !attached[physIface.Index] {
				if err := m.AddTxPort(physIface.Index); err != nil {
					return fmt.Errorf("add tx port %s: %w", physName, err)
				}

				// Disable VLAN RX offload so XDP sees VLAN tags in packet data
				// (otherwise NIC strips them into skb->vlan_tci which XDP can't read)
				if out, err := exec.Command("ethtool", "-K", physName, "rxvlan", "off").CombinedOutput(); err != nil {
					slog.Warn("failed to disable rxvlan offload (VLAN parsing may fail)",
						"interface", physName, "err", err, "output", strings.TrimSpace(string(out)))
				} else {
					slog.Info("disabled VLAN RX offload for XDP", "interface", physName)
				}

				// Bring the interface UP so XDP can process traffic
				if nl, err := netlink.LinkByIndex(physIface.Index); err == nil {
					if err := netlink.LinkSetUp(nl); err != nil {
						slog.Warn("failed to bring interface up",
							"name", physName, "err", err)
					}
				}

				// Defer actual XDP/TC attachment to after all compile phases
				// so link.Update() switches to programs with fully-populated maps.
				xdpIfindexes = append(xdpIfindexes, physIface.Index)
				result.pendingTC = append(result.pendingTC, physIface.Index)
				attached[physIface.Index] = true
			}

			// Assign addresses from config for non-VLAN interfaces
			if vlanID == 0 {
				if ifCfg, ok := cfg.Interfaces.Interfaces[physName]; ok {
					if unit, ok := ifCfg.Units[unitNum]; ok && len(unit.Addresses) > 0 {
						assignInterfaceAddresses(physName, unit.Addresses)
					}
				}
			}

			slog.Info("zone interface configured",
				"zone", name, "interface", ifaceRef,
				"phys_ifindex", physIface.Index, "vlan_id", vlanID,
				"zone_id", zid)
		}
	}

	// Store pending XDP ifindexes for deferred attachment after all compile phases.
	result.pendingXDP = xdpIfindexes

	return nil
}

func (m *Manager) compileAddressBook(cfg *config.Config, result *CompileResult) error {
	ab := cfg.Security.AddressBook
	if ab == nil {
		result.nextAddrID = 1 // start from 1 for implicit entries
		return nil
	}

	// Assign address IDs (1-based; 0 = "any")
	addrID := uint32(1)

	// Process individual addresses
	for name, addr := range ab.Addresses {
		result.AddrIDs[name] = addrID

		cidr := addr.Value
		// Ensure CIDR notation
		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr = cidr + "/128" // IPv6
			} else {
				cidr = cidr + "/32" // IPv4
			}
		}

		if err := m.SetAddressBookEntry(cidr, addrID); err != nil {
			return fmt.Errorf("set address %s (%s): %w", name, cidr, err)
		}

		// Write self-membership: (addrID, addrID) -> 1
		if err := m.SetAddressMembership(addrID, addrID); err != nil {
			return fmt.Errorf("set self-membership for %s: %w", name, err)
		}

		slog.Debug("address compiled", "name", name, "cidr", cidr, "id", addrID)
		addrID++
	}

	// Process address sets (with nested set expansion)
	for setName := range ab.AddressSets {
		setID := addrID
		result.AddrIDs[setName] = setID
		addrID++

		// Recursively expand nested sets to flat address list
		allAddresses, err := config.ExpandAddressSet(setName, ab)
		if err != nil {
			return fmt.Errorf("address set %q: %w", setName, err)
		}

		// Write membership entries for each resolved address
		for _, memberName := range allAddresses {
			memberID, ok := result.AddrIDs[memberName]
			if !ok {
				return fmt.Errorf("address set %q: member %q not found",
					setName, memberName)
			}
			if err := m.SetAddressMembership(memberID, setID); err != nil {
				return fmt.Errorf("set membership %s in %s: %w",
					memberName, setName, err)
			}
		}

		slog.Debug("address set compiled", "name", setName, "id", setID,
			"members", len(allAddresses))
	}

	result.nextAddrID = addrID
	return nil
}

func (m *Manager) compileApplications(cfg *config.Config, result *CompileResult) error {
	if err := m.ClearApplications(); err != nil {
		slog.Warn("failed to clear applications map", "err", err)
	}

	appID := uint32(1)
	userApps := cfg.Applications.Applications

	// Collect all referenced application names from policies,
	// expanding application-sets to individual apps.
	referenced := make(map[string]bool)
	for _, zpp := range cfg.Security.Policies {
		for _, pol := range zpp.Policies {
			for _, appName := range pol.Match.Applications {
				if appName == "any" {
					continue
				}
				// Check if it's an application-set
				if _, isSet := cfg.Applications.ApplicationSets[appName]; isSet {
					expanded, err := config.ExpandApplicationSet(appName, &cfg.Applications)
					if err != nil {
						return fmt.Errorf("expand application-set %q: %w", appName, err)
					}
					for _, a := range expanded {
						referenced[a] = true
					}
				} else {
					referenced[appName] = true
				}
			}
		}
	}

	for appName := range referenced {
		app, found := config.ResolveApplication(appName, userApps)
		if !found {
			return fmt.Errorf("application %q not found", appName)
		}

		proto := protocolNumber(app.Protocol)
		if proto == 0 && app.Protocol != "icmp" {
			slog.Warn("unknown protocol for application",
				"name", appName, "protocol", app.Protocol)
			continue
		}

		result.AppIDs[appName] = appID

		// Parse destination port (may be a range like "8080-8090")
		ports, err := parsePorts(app.DestinationPort)
		if err != nil {
			slog.Warn("bad port for application",
				"name", appName, "port", app.DestinationPort, "err", err)
			continue
		}

		for _, port := range ports {
			if err := m.SetApplication(proto, port, appID); err != nil {
				return fmt.Errorf("set application %s port %d: %w",
					appName, port, err)
			}
		}

		slog.Debug("application compiled", "name", appName, "id", appID,
			"proto", proto, "ports", ports)
		appID++
	}

	return nil
}

// resolveAddrList resolves a list of address names to a single address ID.
// If the list has one entry, returns that entry's ID directly.
// If the list has multiple entries, creates an implicit address-set containing
// all referenced addresses and returns the set's ID.
func (m *Manager) resolveAddrList(names []string, result *CompileResult) (uint32, error) {
	if len(names) == 0 {
		return 0, nil
	}

	// Filter out "any" entries
	var filtered []string
	for _, n := range names {
		if n != "any" {
			filtered = append(filtered, n)
		}
	}
	if len(filtered) == 0 {
		return 0, nil // all "any"
	}

	// Single address: return its ID directly
	if len(filtered) == 1 {
		id, ok := result.AddrIDs[filtered[0]]
		if !ok {
			return 0, fmt.Errorf("address %q not found", filtered[0])
		}
		return id, nil
	}

	// Multiple addresses: build implicit address-set
	sorted := make([]string, len(filtered))
	copy(sorted, filtered)
	sort.Strings(sorted)
	cacheKey := strings.Join(sorted, ",")

	if setID, ok := result.implicitSets[cacheKey]; ok {
		return setID, nil
	}

	setID := result.nextAddrID
	result.nextAddrID++

	for _, name := range sorted {
		memberID, ok := result.AddrIDs[name]
		if !ok {
			return 0, fmt.Errorf("address %q not found", name)
		}
		if err := m.SetAddressMembership(memberID, setID); err != nil {
			return 0, fmt.Errorf("set implicit membership %s in set %d: %w", name, setID, err)
		}
	}

	result.implicitSets[cacheKey] = setID
	slog.Debug("implicit address-set created", "id", setID, "members", sorted)
	return setID, nil
}

// resolveSNATMatchAddr resolves a SNAT match CIDR to an address ID.
// If the CIDR already exists as an address-book entry, reuses that ID.
// Otherwise, creates an implicit address-book entry with a synthetic name.
// Returns 0 (any) if the CIDR is empty.
func (m *Manager) resolveSNATMatchAddr(cidr string, result *CompileResult) (uint32, error) {
	if cidr == "" {
		return 0, nil
	}

	// Normalize CIDR
	if !strings.Contains(cidr, "/") {
		if strings.Contains(cidr, ":") {
			cidr += "/128"
		} else {
			cidr += "/32"
		}
	}

	// Create implicit address-book entry (LPM trie handles deduplication)
	synthName := "_snat_match_" + cidr
	if id, ok := result.AddrIDs[synthName]; ok {
		return id, nil
	}

	addrID := result.nextAddrID
	result.nextAddrID++
	result.AddrIDs[synthName] = addrID

	if err := m.SetAddressBookEntry(cidr, addrID); err != nil {
		return 0, fmt.Errorf("set implicit address %s: %w", cidr, err)
	}
	if err := m.SetAddressMembership(addrID, addrID); err != nil {
		return 0, fmt.Errorf("set self-membership for implicit %s: %w", cidr, err)
	}

	slog.Debug("implicit SNAT match address created", "cidr", cidr, "id", addrID)
	return addrID, nil
}

func (m *Manager) compilePolicies(cfg *config.Config, result *CompileResult) error {
	if err := m.ClearZonePairPolicies(); err != nil {
		slog.Warn("failed to clear zone pair policies", "err", err)
	}

	policySetID := uint32(0)

	for _, zpp := range cfg.Security.Policies {
		fromZone, ok := result.ZoneIDs[zpp.FromZone]
		if !ok {
			return fmt.Errorf("policy from-zone %q not found", zpp.FromZone)
		}
		toZone, ok := result.ZoneIDs[zpp.ToZone]
		if !ok {
			return fmt.Errorf("policy to-zone %q not found", zpp.ToZone)
		}

		// Expand rules: each config rule with N applications becomes N BPF rules.
		// Collect expanded rules first to know the total count.
		type expandedRule struct {
			pol    *config.Policy
			appID  uint32
		}
		var expanded []expandedRule

		for _, pol := range zpp.Policies {
			// Resolve application list, expanding application-sets
			var appIDs []uint32
			hasAny := false
			for _, appName := range pol.Match.Applications {
				if appName == "any" {
					hasAny = true
					break
				}
			}
			if hasAny || len(pol.Match.Applications) == 0 {
				appIDs = []uint32{0} // single rule with app_id=0 (any)
			} else {
				seen := make(map[uint32]bool)
				for _, appName := range pol.Match.Applications {
					// Expand application-sets
					if _, isSet := cfg.Applications.ApplicationSets[appName]; isSet {
						expanded, err := config.ExpandApplicationSet(appName, &cfg.Applications)
						if err != nil {
							return fmt.Errorf("policy %s expand app-set %q: %w", pol.Name, appName, err)
						}
						for _, a := range expanded {
							if id, ok := result.AppIDs[a]; ok && !seen[id] {
								seen[id] = true
								appIDs = append(appIDs, id)
							}
						}
					} else if id, ok := result.AppIDs[appName]; ok && !seen[id] {
						seen[id] = true
						appIDs = append(appIDs, id)
					}
				}
				if len(appIDs) == 0 {
					appIDs = []uint32{0}
				}
			}

			for _, aid := range appIDs {
				expanded = append(expanded, expandedRule{pol: pol, appID: aid})
			}
		}

		ps := PolicySet{
			PolicySetID:   policySetID,
			NumRules:      uint16(len(expanded)),
			DefaultAction: ActionDeny,
		}
		if err := m.SetZonePairPolicy(fromZone, toZone, ps); err != nil {
			return fmt.Errorf("set zone pair policy %s->%s: %w",
				zpp.FromZone, zpp.ToZone, err)
		}

		for i, er := range expanded {
			pol := er.pol
			rule := PolicyRule{
				RuleID:      uint32(policySetID*MaxRulesPerPolicy + uint32(i)),
				PolicySetID: policySetID,
				Sequence:    uint16(i),
				AppID:       er.appID,
				Active:      1, // default active; scheduler may toggle to 0
			}

			// Map action
			switch pol.Action {
			case config.PolicyPermit:
				rule.Action = ActionPermit
			case config.PolicyDeny:
				rule.Action = ActionDeny
			case config.PolicyReject:
				rule.Action = ActionReject
			}

			// Logging
			if pol.Log != nil {
				if pol.Log.SessionInit {
					rule.Log |= LogFlagSessionInit
				}
				if pol.Log.SessionClose {
					rule.Log |= LogFlagSessionClose
				}
			}

			// Source address (supports multiple via implicit address-set)
			srcID, err := m.resolveAddrList(pol.Match.SourceAddresses, result)
			if err != nil {
				return fmt.Errorf("policy %s source address: %w", pol.Name, err)
			}
			rule.SrcAddrID = srcID

			// Destination address (supports multiple via implicit address-set)
			dstID, err := m.resolveAddrList(pol.Match.DestinationAddresses, result)
			if err != nil {
				return fmt.Errorf("policy %s destination address: %w", pol.Name, err)
			}
			rule.DstAddrID = dstID

			if err := m.SetPolicyRule(policySetID, uint32(i), rule); err != nil {
				return fmt.Errorf("set policy rule %s[%d]: %w",
					pol.Name, i, err)
			}

			slog.Debug("policy rule compiled",
				"from", zpp.FromZone, "to", zpp.ToZone,
				"policy", pol.Name, "action", rule.Action,
				"index", i, "app_id", er.appID)
		}

		result.PolicySets++
		policySetID++
	}

	return nil
}

func (m *Manager) compileNAT(cfg *config.Config, result *CompileResult) error {
	// Clear previous NAT entries (v4 + v6)
	if err := m.ClearSNATRules(); err != nil {
		slog.Warn("failed to clear snat_rules", "err", err)
	}
	if err := m.ClearSNATRulesV6(); err != nil {
		slog.Warn("failed to clear snat_rules_v6", "err", err)
	}
	if err := m.ClearDNATStatic(); err != nil {
		slog.Warn("failed to clear static dnat entries", "err", err)
	}
	if err := m.ClearDNATStaticV6(); err != nil {
		slog.Warn("failed to clear static dnat_v6 entries", "err", err)
	}
	if err := m.ClearNATPoolConfigs(); err != nil {
		slog.Warn("failed to clear nat_pool_configs", "err", err)
	}
	if err := m.ClearNATPoolIPs(); err != nil {
		slog.Warn("failed to clear nat_pool_ips", "err", err)
	}

	natCfg := &cfg.Security.NAT

	// Source NAT: allocate pool IDs and compile pools + rules
	poolID := uint8(0)

	// Track per-zone-pair v4/v6 rule indices for multiple SNAT rules
	type zonePairIdx struct{ from, to uint16 }
	v4RuleIdx := make(map[zonePairIdx]uint16)
	v6RuleIdx := make(map[zonePairIdx]uint16)

	for _, rs := range natCfg.Source {
		fromZone, ok := result.ZoneIDs[rs.FromZone]
		if !ok {
			return fmt.Errorf("source NAT from-zone %q not found", rs.FromZone)
		}
		toZone, ok := result.ZoneIDs[rs.ToZone]
		if !ok {
			return fmt.Errorf("source NAT to-zone %q not found", rs.ToZone)
		}

		for _, rule := range rs.Rules {
			if !rule.Then.Interface && rule.Then.PoolName == "" {
				slog.Warn("SNAT rule has no action",
					"rule", rule.Name, "rule-set", rs.Name)
				continue
			}

			var curPoolID uint8
			var poolCfg NATPoolConfig
			var v4IPs []net.IP
			var v6IPs []net.IP

			if rule.Then.Interface {
				// Interface mode: create implicit pool from egress interface IP(s)
				toZoneCfg, ok := cfg.Security.Zones[rs.ToZone]
				if !ok || len(toZoneCfg.Interfaces) == 0 {
					slog.Warn("to-zone has no interfaces",
						"zone", rs.ToZone, "rule-set", rs.Name)
					continue
				}
				ifaceName := toZoneCfg.Interfaces[0]

				snatIP, err := getInterfaceIP(ifaceName)
				if err != nil {
					slog.Warn("cannot get interface IPv4 for SNAT",
						"interface", ifaceName, "err", err)
				} else {
					v4IPs = append(v4IPs, snatIP)
				}

				snatIPv6, err := getInterfaceIPv6(ifaceName)
				if err != nil {
					slog.Debug("no IPv6 address for SNAT",
						"interface", ifaceName, "err", err)
				} else {
					v6IPs = append(v6IPs, snatIPv6)
				}

				if len(v4IPs) == 0 && len(v6IPs) == 0 {
					slog.Warn("no IP addresses for interface SNAT",
						"interface", ifaceName)
					continue
				}

				poolCfg.PortLow = 1024
				poolCfg.PortHigh = 65535
				curPoolID = poolID
				poolID++
			} else {
				// Pool mode: look up named pool
				pool, ok := natCfg.SourcePools[rule.Then.PoolName]
				if !ok {
					return fmt.Errorf("source NAT pool %q not found (rule %q)",
						rule.Then.PoolName, rule.Name)
				}

				// Check if pool already has an ID assigned
				if existingID, exists := result.PoolIDs[pool.Name]; exists {
					curPoolID = existingID
				} else {
					curPoolID = poolID
					result.PoolIDs[pool.Name] = curPoolID
					poolID++
				}

				// Parse pool addresses
				for _, addr := range pool.Addresses {
					cidr := addr
					if !strings.Contains(cidr, "/") {
						if strings.Contains(cidr, ":") {
							cidr += "/128"
						} else {
							cidr += "/32"
						}
					}
					ip, _, err := net.ParseCIDR(cidr)
					if err != nil {
						slog.Warn("invalid pool address", "addr", addr, "err", err)
						continue
					}
					if ip.To4() != nil {
						v4IPs = append(v4IPs, ip.To4())
					} else {
						v6IPs = append(v6IPs, ip)
					}
				}

				poolCfg.PortLow = uint16(pool.PortLow)
				poolCfg.PortHigh = uint16(pool.PortHigh)
				if poolCfg.PortLow == 0 {
					poolCfg.PortLow = 1024
				}
				if poolCfg.PortHigh == 0 {
					poolCfg.PortHigh = 65535
				}
			}

			// Write pool IPs to maps
			poolCfg.NumIPs = uint16(len(v4IPs))
			poolCfg.NumIPsV6 = uint16(len(v6IPs))

			for i, ip := range v4IPs {
				if i >= int(MaxNATPoolIPsPerPool) {
					break
				}
				if err := m.SetNATPoolIPV4(uint32(curPoolID), uint32(i), ipToUint32BE(ip)); err != nil {
					return fmt.Errorf("set pool ip v4 %d/%d: %w", curPoolID, i, err)
				}
			}
			for i, ip := range v6IPs {
				if i >= int(MaxNATPoolIPsPerPool) {
					break
				}
				if err := m.SetNATPoolIPV6(uint32(curPoolID), uint32(i), ipTo16Bytes(ip)); err != nil {
					return fmt.Errorf("set pool ip v6 %d/%d: %w", curPoolID, i, err)
				}
			}

			if err := m.SetNATPoolConfig(uint32(curPoolID), poolCfg); err != nil {
				return fmt.Errorf("set pool config %d: %w", curPoolID, err)
			}

			// Resolve SNAT match criteria to address IDs
			srcAddrID, err := m.resolveSNATMatchAddr(rule.Match.SourceAddress, result)
			if err != nil {
				return fmt.Errorf("snat rule %s/%s source match: %w",
					rs.Name, rule.Name, err)
			}
			dstAddrID, err := m.resolveSNATMatchAddr(rule.Match.DestinationAddress, result)
			if err != nil {
				return fmt.Errorf("snat rule %s/%s dest match: %w",
					rs.Name, rule.Name, err)
			}

			zp := zonePairIdx{fromZone, toZone}

			// Assign NAT rule counter ID
			ruleKey := rs.Name + "/" + rule.Name
			counterID := result.nextNATCounterID
			result.NATCounterIDs[ruleKey] = counterID
			result.nextNATCounterID++

			// Write SNAT rule (v4)
			if len(v4IPs) > 0 {
				val := SNATValue{
					Mode:      curPoolID,
					SrcAddrID: srcAddrID,
					DstAddrID: dstAddrID,
					CounterID: counterID,
				}
				ri := v4RuleIdx[zp]
				if err := m.SetSNATRule(fromZone, toZone, ri, val); err != nil {
					return fmt.Errorf("set snat rule %s/%s: %w",
						rs.Name, rule.Name, err)
				}
				v4RuleIdx[zp] = ri + 1
				slog.Info("source NAT rule compiled",
					"rule-set", rs.Name, "rule", rule.Name,
					"from", rs.FromZone, "to", rs.ToZone,
					"pool_id", curPoolID, "rule_idx", ri,
					"counter_id", counterID,
					"src_addr_id", srcAddrID, "dst_addr_id", dstAddrID,
					"v4_ips", len(v4IPs),
					"ports", fmt.Sprintf("%d-%d", poolCfg.PortLow, poolCfg.PortHigh))
			}

			// Write SNAT rule (v6)
			if len(v6IPs) > 0 {
				val := SNATValueV6{
					Mode:      curPoolID,
					SrcAddrID: srcAddrID,
					DstAddrID: dstAddrID,
					CounterID: counterID,
				}
				ri := v6RuleIdx[zp]
				if err := m.SetSNATRuleV6(fromZone, toZone, ri, val); err != nil {
					return fmt.Errorf("set snat_v6 rule %s/%s: %w",
						rs.Name, rule.Name, err)
				}
				v6RuleIdx[zp] = ri + 1
				slog.Info("source NAT v6 rule compiled",
					"rule-set", rs.Name, "rule", rule.Name,
					"from", rs.FromZone, "to", rs.ToZone,
					"pool_id", curPoolID, "rule_idx", ri,
					"counter_id", counterID,
					"src_addr_id", srcAddrID, "dst_addr_id", dstAddrID,
					"v6_ips", len(v6IPs))
			}
		}
	}

	// Destination NAT
	if natCfg.Destination != nil {
		for _, rs := range natCfg.Destination.RuleSets {
			for _, rule := range rs.Rules {
				if rule.Then.PoolName == "" {
					continue
				}

				pool, ok := natCfg.Destination.Pools[rule.Then.PoolName]
				if !ok {
					return fmt.Errorf("DNAT pool %q not found (rule %q)",
						rule.Then.PoolName, rule.Name)
				}

				// Parse match destination address
				if rule.Match.DestinationAddress == "" {
					slog.Warn("DNAT rule has no match destination-address",
						"rule", rule.Name)
					continue
				}

				matchIP, _, err := net.ParseCIDR(rule.Match.DestinationAddress)
				if err != nil {
					// Try as plain IP
					matchIP = net.ParseIP(rule.Match.DestinationAddress)
					if matchIP == nil {
						slog.Warn("invalid DNAT match address",
							"addr", rule.Match.DestinationAddress)
						continue
					}
				}

				// Parse pool address
				poolIP, _, err := net.ParseCIDR(pool.Address)
				if err != nil {
					poolIP = net.ParseIP(pool.Address)
					if poolIP == nil {
						slog.Warn("invalid DNAT pool address",
							"addr", pool.Address)
						continue
					}
				}

				// Determine port (use pool port if set, else match port)
				dstPort := uint16(rule.Match.DestinationPort)
				poolPort := dstPort
				if pool.Port != 0 {
					poolPort = uint16(pool.Port)
				}

				// Determine protocol(s) to insert DNAT entries for.
				// If protocol is explicitly set, use it.
				// If protocol not set but port is set, default to TCP(6).
				// If neither protocol nor port set, create entries for both TCP(6) and UDP(17)
				// with port=0 (wildcard port, matched via BPF fallback lookup).
				var protos []uint8
				if rule.Match.Protocol != "" {
					protos = []uint8{protocolNumber(rule.Match.Protocol)}
				} else if dstPort != 0 {
					protos = []uint8{6} // TCP default for port-based DNAT
				} else {
					protos = []uint8{6, 17} // both TCP and UDP for port-less DNAT
				}

				for _, proto := range protos {
					// Route to v4 or v6 DNAT table based on match IP
					if matchIP.To4() != nil {
						dk := DNATKey{
							Protocol: proto,
							DstIP:    ipToUint32BE(matchIP),
							DstPort:  htons(dstPort),
						}
						dv := DNATValue{
							NewDstIP:   ipToUint32BE(poolIP),
							NewDstPort: htons(poolPort),
							Flags:      DNATFlagStatic,
						}
						if err := m.SetDNATEntry(dk, dv); err != nil {
							return fmt.Errorf("set dnat entry %s/%s proto %d: %w",
								rs.Name, rule.Name, proto, err)
						}
					} else {
						dk := DNATKeyV6{
							Protocol: proto,
							DstIP:    ipTo16Bytes(matchIP),
							DstPort:  htons(dstPort),
						}
						dv := DNATValueV6{
							NewDstIP:   ipTo16Bytes(poolIP),
							NewDstPort: htons(poolPort),
							Flags:      DNATFlagStatic,
						}
						if err := m.SetDNATEntryV6(dk, dv); err != nil {
							return fmt.Errorf("set dnat_v6 entry %s/%s proto %d: %w",
								rs.Name, rule.Name, proto, err)
						}
					}

					slog.Info("destination NAT rule compiled",
						"rule-set", rs.Name, "rule", rule.Name,
						"match_ip", matchIP, "match_port", dstPort,
						"proto", proto,
						"pool", pool.Name, "pool_ip", poolIP,
						"pool_port", poolPort)
				}
			}
		}
	}

	return nil
}

func (m *Manager) compileStaticNAT(cfg *config.Config, result *CompileResult) error {
	if err := m.ClearStaticNATEntries(); err != nil {
		slog.Warn("failed to clear static_nat entries", "err", err)
	}

	count := 0
	for _, rs := range cfg.Security.NAT.Static {
		for _, rule := range rs.Rules {
			if rule.Match == "" || rule.Then == "" {
				slog.Warn("static NAT rule missing match or then",
					"rule-set", rs.Name, "rule", rule.Name)
				continue
			}

			// Parse external (match) address
			matchCIDR := rule.Match
			if !strings.Contains(matchCIDR, "/") {
				if strings.Contains(matchCIDR, ":") {
					matchCIDR += "/128"
				} else {
					matchCIDR += "/32"
				}
			}
			extIP, _, err := net.ParseCIDR(matchCIDR)
			if err != nil {
				slog.Warn("invalid static NAT match address",
					"addr", rule.Match, "err", err)
				continue
			}

			// Parse internal (then) address
			thenCIDR := rule.Then
			if !strings.Contains(thenCIDR, "/") {
				if strings.Contains(thenCIDR, ":") {
					thenCIDR += "/128"
				} else {
					thenCIDR += "/32"
				}
			}
			intIP, _, err := net.ParseCIDR(thenCIDR)
			if err != nil {
				slog.Warn("invalid static NAT then address",
					"addr", rule.Then, "err", err)
				continue
			}

			// Insert DNAT entry (external -> internal) and SNAT entry (internal -> external)
			if extIP.To4() != nil && intIP.To4() != nil {
				extU32 := ipToUint32BE(extIP)
				intU32 := ipToUint32BE(intIP)

				if err := m.SetStaticNATEntryV4(extU32, StaticNATDNAT, intU32); err != nil {
					return fmt.Errorf("set static nat dnat v4 %s: %w", rule.Name, err)
				}
				if err := m.SetStaticNATEntryV4(intU32, StaticNATSNAT, extU32); err != nil {
					return fmt.Errorf("set static nat snat v4 %s: %w", rule.Name, err)
				}
			} else {
				extBytes := ipTo16Bytes(extIP)
				intBytes := ipTo16Bytes(intIP)

				if err := m.SetStaticNATEntryV6(extBytes, StaticNATDNAT, intBytes); err != nil {
					return fmt.Errorf("set static nat dnat v6 %s: %w", rule.Name, err)
				}
				if err := m.SetStaticNATEntryV6(intBytes, StaticNATSNAT, extBytes); err != nil {
					return fmt.Errorf("set static nat snat v6 %s: %w", rule.Name, err)
				}
			}

			count++
			slog.Info("static NAT rule compiled",
				"rule-set", rs.Name, "rule", rule.Name,
				"external", rule.Match, "internal", rule.Then)
		}
	}

	if count > 0 {
		slog.Info("static NAT compilation complete", "entries", count)
	}
	return nil
}

func (m *Manager) compileNAT64(cfg *config.Config, result *CompileResult) error {
	if err := m.ClearNAT64Configs(); err != nil {
		slog.Warn("failed to clear nat64_configs", "err", err)
	}

	ruleSets := cfg.Security.NAT.NAT64
	if len(ruleSets) == 0 {
		return nil
	}

	count := uint32(0)
	for _, rs := range ruleSets {
		if count >= 4 { // MAX_NAT64_PREFIXES
			slog.Warn("max NAT64 prefixes exceeded, skipping", "rule-set", rs.Name)
			break
		}

		// Parse the /96 prefix (e.g. "64:ff9b::/96")
		ip, ipNet, err := net.ParseCIDR(rs.Prefix)
		if err != nil {
			return fmt.Errorf("NAT64 rule-set %q: invalid prefix %q: %w", rs.Name, rs.Prefix, err)
		}
		ones, _ := ipNet.Mask.Size()
		if ones != 96 {
			return fmt.Errorf("NAT64 rule-set %q: prefix must be /96, got /%d", rs.Name, ones)
		}

		// Extract first 96 bits as 3 x uint32.
		// BPF stores these as __be32 (raw network bytes). cilium/ebpf serializes
		// Go uint32 using native endian, so use NativeEndian.Uint32 on the raw
		// IP bytes to preserve the byte pattern (same as ipToUint32BE).
		ip16 := ip.To16()
		if ip16 == nil {
			return fmt.Errorf("NAT64 rule-set %q: prefix is not IPv6", rs.Name)
		}
		var prefix [3]uint32
		prefix[0] = binary.NativeEndian.Uint32(ip16[0:4])
		prefix[1] = binary.NativeEndian.Uint32(ip16[4:8])
		prefix[2] = binary.NativeEndian.Uint32(ip16[8:12])

		// Look up the source pool ID
		poolID, ok := result.PoolIDs[rs.SourcePool]
		if !ok {
			return fmt.Errorf("NAT64 rule-set %q: source pool %q not found (must be defined in source NAT)", rs.Name, rs.SourcePool)
		}

		nat64Cfg := NAT64Config{
			Prefix:     prefix,
			SNATPoolID: poolID,
		}
		if err := m.SetNAT64Config(count, nat64Cfg); err != nil {
			return fmt.Errorf("NAT64 rule-set %q: set config: %w", rs.Name, err)
		}

		slog.Info("compiled NAT64 prefix",
			"rule-set", rs.Name, "prefix", rs.Prefix,
			"pool", rs.SourcePool, "pool_id", poolID)
		count++
	}

	if err := m.SetNAT64Count(count); err != nil {
		return fmt.Errorf("set NAT64 count: %w", err)
	}

	slog.Info("NAT64 compilation complete", "prefixes", count)
	return nil
}

func (m *Manager) compileScreenProfiles(cfg *config.Config, result *CompileResult) error {
	if err := m.ClearScreenConfigs(); err != nil {
		slog.Warn("failed to clear screen_configs", "err", err)
	}

	for name, profile := range cfg.Security.Screen {
		sid, ok := result.ScreenIDs[name]
		if !ok {
			continue
		}

		var flags uint32
		var sc ScreenConfig

		// TCP flags
		if profile.TCP.Land {
			flags |= ScreenLandAttack
		}
		if profile.TCP.SynFin {
			flags |= ScreenTCPSynFin
		}
		if profile.TCP.NoFlag {
			flags |= ScreenTCPNoFlag
		}
		if profile.TCP.FinNoAck {
			flags |= ScreenTCPFinNoAck
		}
		if profile.TCP.WinNuke {
			flags |= ScreenWinNuke
		}
		if profile.TCP.SynFrag {
			flags |= ScreenSynFrag
		}
		if profile.TCP.SynFlood != nil && profile.TCP.SynFlood.AttackThreshold > 0 {
			flags |= ScreenSynFlood
			sc.SynFloodThresh = uint32(profile.TCP.SynFlood.AttackThreshold)
		}

		// ICMP flags
		if profile.ICMP.PingDeath {
			flags |= ScreenPingOfDeath
		}
		if profile.ICMP.FloodThreshold > 0 {
			flags |= ScreenICMPFlood
			sc.ICMPFloodThresh = uint32(profile.ICMP.FloodThreshold)
		}

		// IP flags
		if profile.IP.SourceRouteOption {
			flags |= ScreenIPSourceRoute
		}

		// UDP flags
		if profile.UDP.FloodThreshold > 0 {
			flags |= ScreenUDPFlood
			sc.UDPFloodThresh = uint32(profile.UDP.FloodThreshold)
		}

		sc.Flags = flags

		if err := m.SetScreenConfig(uint32(sid), sc); err != nil {
			return fmt.Errorf("set screen config %s (id=%d): %w", name, sid, err)
		}

		slog.Info("screen profile compiled",
			"name", name, "id", sid,
			"flags", fmt.Sprintf("0x%x", flags),
			"syn_thresh", sc.SynFloodThresh,
			"icmp_thresh", sc.ICMPFloodThresh,
			"udp_thresh", sc.UDPFloodThresh)
	}

	return nil
}

func (m *Manager) compileDefaultPolicy(cfg *config.Config) error {
	action := uint8(ActionDeny) // default deny
	if cfg.Security.DefaultPolicy == config.PolicyPermit {
		action = ActionPermit
	}
	if err := m.SetDefaultPolicy(action); err != nil {
		return fmt.Errorf("set default policy: %w", err)
	}
	if action == ActionPermit {
		slog.Info("default policy compiled", "action", "permit-all")
	} else {
		slog.Info("default policy compiled", "action", "deny-all")
	}
	return nil
}

func (m *Manager) compileFlowTimeouts(cfg *config.Config) error {
	flow := &cfg.Security.Flow

	// Write all timeout slots; 0 means "use BPF default".
	timeouts := [FlowTimeoutMax]uint32{}

	if flow.TCPSession != nil {
		timeouts[FlowTimeoutTCPEstablished] = uint32(flow.TCPSession.EstablishedTimeout)
		timeouts[FlowTimeoutTCPInitial] = uint32(flow.TCPSession.InitialTimeout)
		timeouts[FlowTimeoutTCPClosing] = uint32(flow.TCPSession.ClosingTimeout)
		timeouts[FlowTimeoutTCPTimeWait] = uint32(flow.TCPSession.TimeWaitTimeout)
	}
	timeouts[FlowTimeoutUDP] = uint32(flow.UDPSessionTimeout)
	timeouts[FlowTimeoutICMP] = uint32(flow.ICMPSessionTimeout)

	for idx := uint32(0); idx < FlowTimeoutMax; idx++ {
		if err := m.SetFlowTimeout(idx, timeouts[idx]); err != nil {
			return fmt.Errorf("set flow timeout %d: %w", idx, err)
		}
	}

	// Log only if any non-default value was set.
	for _, v := range timeouts {
		if v > 0 {
			slog.Info("flow timeouts compiled",
				"tcp_established", timeouts[FlowTimeoutTCPEstablished],
				"tcp_initial", timeouts[FlowTimeoutTCPInitial],
				"tcp_closing", timeouts[FlowTimeoutTCPClosing],
				"tcp_time_wait", timeouts[FlowTimeoutTCPTimeWait],
				"udp", timeouts[FlowTimeoutUDP],
				"icmp", timeouts[FlowTimeoutICMP])
			break
		}
	}

	return nil
}

func (m *Manager) compileFlowConfig(cfg *config.Config) error {
	flow := &cfg.Security.Flow
	fc := FlowConfigValue{
		TCPMSSIPsec: uint16(flow.TCPMSSIPsecVPN),
		TCPMSSGre:   uint16(flow.TCPMSSGre),
	}
	if flow.AllowDNSReply {
		fc.AllowDNSReply = 1
	}
	if flow.AllowEmbeddedICMP {
		fc.AllowEmbeddedICMP = 1
	}

	if err := m.SetFlowConfig(fc); err != nil {
		return err
	}

	if fc.TCPMSSIPsec > 0 || fc.TCPMSSGre > 0 {
		slog.Info("flow config compiled",
			"tcp_mss_ipsec", fc.TCPMSSIPsec,
			"tcp_mss_gre", fc.TCPMSSGre,
			"allow_dns_reply", fc.AllowDNSReply,
			"allow_embedded_icmp", fc.AllowEmbeddedICMP)
	}

	return nil
}

// getInterfaceIP returns the first IPv4 address of a network interface.
func getInterfaceIP(ifaceName string) (net.IP, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", ifaceName, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("interface %s addrs: %w", ifaceName, err)
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipNet.IP.To4()
		if ip4 != nil {
			return ip4, nil
		}
	}
	return nil, fmt.Errorf("no IPv4 address on interface %s", ifaceName)
}

// getInterfaceIPv6 returns the first global unicast IPv6 address of a network interface.
func getInterfaceIPv6(ifaceName string) (net.IP, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", ifaceName, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("interface %s addrs: %w", ifaceName, err)
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipNet.IP.To4() != nil {
			continue // skip IPv4
		}
		if ipNet.IP.IsGlobalUnicast() {
			return ipNet.IP, nil
		}
	}
	return nil, fmt.Errorf("no global unicast IPv6 address on interface %s", ifaceName)
}

// protocolNumber converts a protocol name to its IANA number.
func protocolNumber(name string) uint8 {
	switch strings.ToLower(name) {
	case "tcp":
		return 6
	case "udp":
		return 17
	case "icmp":
		return 1
	case "icmpv6", "icmp6":
		return 58
	default:
		return 0
	}
}

// parsePorts parses a port specification like "80", "8080-8090", or "".
// Returns a list of individual ports. For ranges, returns all ports in range.
func parsePorts(spec string) ([]uint16, error) {
	if spec == "" {
		return []uint16{0}, nil
	}

	if strings.Contains(spec, "-") {
		parts := strings.SplitN(spec, "-", 2)
		low, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			return nil, err
		}
		high, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			return nil, err
		}
		var ports []uint16
		for p := low; p <= high; p++ {
			ports = append(ports, uint16(p))
		}
		return ports, nil
	}

	port, err := strconv.ParseUint(spec, 10, 16)
	if err != nil {
		return nil, err
	}
	return []uint16{uint16(port)}, nil
}

// compileFirewallFilters compiles firewall filter config into BPF maps.
// It creates filter_rules, filter_configs, and iface_filter_map entries.
func (m *Manager) compileFirewallFilters(cfg *config.Config, result *CompileResult) error {
	// Clear previous filter maps
	if err := m.ClearIfaceFilterMap(); err != nil {
		slog.Warn("failed to clear iface_filter_map", "err", err)
	}
	if err := m.ClearFilterConfigs(); err != nil {
		slog.Warn("failed to clear filter_configs", "err", err)
	}

	// Build routing instance name -> table ID map
	riTableIDs := make(map[string]uint32)
	for _, ri := range cfg.RoutingInstances {
		riTableIDs[ri.Name] = uint32(ri.TableID)
	}

	filterID := uint32(0)
	ruleIdx := uint32(0)
	filterIDs := make(map[string]uint32) // "inet:name" or "inet6:name" -> filter_id

	// Compile inet filters
	for name, filter := range cfg.Firewall.FiltersInet {
		if filterID >= MaxFilterConfigs || ruleIdx >= MaxFilterRules {
			slog.Warn("firewall filter limit reached", "filter", name)
			break
		}
		startIdx := ruleIdx
		for _, term := range filter.Terms {
			rules := expandFilterTerm(term, AFInet, riTableIDs)
			for _, rule := range rules {
				if ruleIdx >= MaxFilterRules {
					slog.Warn("filter rule limit reached", "filter", name, "term", term.Name)
					break
				}
				if err := m.SetFilterRule(ruleIdx, rule); err != nil {
					return fmt.Errorf("set filter rule %d: %w", ruleIdx, err)
				}
				ruleIdx++
			}
		}
		numRules := ruleIdx - startIdx
		if err := m.SetFilterConfig(filterID, FilterConfig{
			NumRules:  numRules,
			RuleStart: startIdx,
		}); err != nil {
			return fmt.Errorf("set filter config %s: %w", name, err)
		}
		filterIDs["inet:"+name] = filterID
		slog.Info("compiled firewall filter",
			"name", name, "family", "inet", "terms", len(filter.Terms),
			"rules", numRules, "filter_id", filterID)
		filterID++
	}

	// Compile inet6 filters
	for name, filter := range cfg.Firewall.FiltersInet6 {
		if filterID >= MaxFilterConfigs || ruleIdx >= MaxFilterRules {
			slog.Warn("firewall filter limit reached", "filter", name)
			break
		}
		startIdx := ruleIdx
		for _, term := range filter.Terms {
			rules := expandFilterTerm(term, AFInet6, riTableIDs)
			for _, rule := range rules {
				if ruleIdx >= MaxFilterRules {
					slog.Warn("filter rule limit reached", "filter", name, "term", term.Name)
					break
				}
				if err := m.SetFilterRule(ruleIdx, rule); err != nil {
					return fmt.Errorf("set filter rule %d: %w", ruleIdx, err)
				}
				ruleIdx++
			}
		}
		numRules := ruleIdx - startIdx
		if err := m.SetFilterConfig(filterID, FilterConfig{
			NumRules:  numRules,
			RuleStart: startIdx,
		}); err != nil {
			return fmt.Errorf("set filter config %s: %w", name, err)
		}
		filterIDs["inet6:"+name] = filterID
		slog.Info("compiled firewall filter",
			"name", name, "family", "inet6", "terms", len(filter.Terms),
			"rules", numRules, "filter_id", filterID)
		filterID++
	}

	// Map interfaces to their assigned filters
	for _, ifCfg := range cfg.Interfaces.Interfaces {
		for _, unit := range ifCfg.Units {
			if unit.FilterInputV4 == "" && unit.FilterInputV6 == "" {
				continue
			}

			physName := ifCfg.Name
			vlanID := uint16(unit.VlanID)

			// Resolve ifindex
			iface, err := net.InterfaceByName(physName)
			if err != nil {
				slog.Warn("interface not found for filter assignment",
					"interface", physName, "err", err)
				continue
			}

			ifindex := uint32(iface.Index)
			// If VLAN sub-interface, use the sub-interface ifindex
			if vlanID > 0 {
				subName := fmt.Sprintf("%s.%d", physName, vlanID)
				subIface, err := net.InterfaceByName(subName)
				if err != nil {
					slog.Warn("VLAN sub-interface not found for filter",
						"name", subName, "err", err)
					continue
				}
				ifindex = uint32(subIface.Index)
				// Physical ifindex is used in iface_filter_key since
				// xdp_main uses ctx->ingress_ifindex (parent phys NIC)
				ifindex = uint32(iface.Index)
			}

			if unit.FilterInputV4 != "" {
				fid, ok := filterIDs["inet:"+unit.FilterInputV4]
				if !ok {
					slog.Warn("filter not found for interface",
						"filter", unit.FilterInputV4, "interface", physName)
				} else {
					key := IfaceFilterKey{
						Ifindex: ifindex,
						VlanID:  vlanID,
						Family:  AFInet,
					}
					if err := m.SetIfaceFilter(key, fid); err != nil {
						return fmt.Errorf("set iface filter %s inet: %w", physName, err)
					}
					slog.Info("assigned filter to interface",
						"interface", physName, "vlan", vlanID,
						"family", "inet", "filter", unit.FilterInputV4)
				}
			}

			if unit.FilterInputV6 != "" {
				fid, ok := filterIDs["inet6:"+unit.FilterInputV6]
				if !ok {
					slog.Warn("filter not found for interface",
						"filter", unit.FilterInputV6, "interface", physName)
				} else {
					key := IfaceFilterKey{
						Ifindex: ifindex,
						VlanID:  vlanID,
						Family:  AFInet6,
					}
					if err := m.SetIfaceFilter(key, fid); err != nil {
						return fmt.Errorf("set iface filter %s inet6: %w", physName, err)
					}
					slog.Info("assigned filter to interface",
						"interface", physName, "vlan", vlanID,
						"family", "inet6", "filter", unit.FilterInputV6)
				}
			}
		}
	}

	return nil
}

// expandFilterTerm expands a single filter term into one or more BPF filter rules.
// Terms with multiple source/destination addresses generate the cross product of rules.
func expandFilterTerm(term *config.FirewallFilterTerm, family uint8, riTableIDs map[string]uint32) []FilterRule {
	// Base rule with common fields
	base := FilterRule{
		Family: family,
	}

	// Set action
	if term.RoutingInstance != "" {
		base.Action = FilterActionRoute
		if tableID, ok := riTableIDs[term.RoutingInstance]; ok {
			base.RoutingTable = tableID
		} else {
			slog.Warn("routing-instance not found for filter term",
				"term", term.Name, "instance", term.RoutingInstance)
			base.Action = FilterActionAccept
		}
	} else {
		switch term.Action {
		case "discard":
			base.Action = FilterActionDiscard
		case "reject":
			base.Action = FilterActionReject
		default:
			base.Action = FilterActionAccept
		}
	}

	// DSCP match
	if term.DSCP != "" {
		base.MatchFlags |= FilterMatchDSCP
		if val, ok := DSCPValues[strings.ToLower(term.DSCP)]; ok {
			base.DSCP = val
		} else if v, err := strconv.Atoi(term.DSCP); err == nil {
			base.DSCP = uint8(v)
		}
	}

	// Protocol match
	if term.Protocol != "" {
		base.MatchFlags |= FilterMatchProtocol
		switch strings.ToLower(term.Protocol) {
		case "tcp":
			base.Protocol = 6
		case "udp":
			base.Protocol = 17
		case "icmp":
			base.Protocol = 1
		case "icmpv6":
			base.Protocol = 58
		default:
			if v, err := strconv.Atoi(term.Protocol); err == nil {
				base.Protocol = uint8(v)
			}
		}
	}

	// ICMP type/code
	if term.ICMPType >= 0 {
		base.MatchFlags |= FilterMatchICMPType
		base.ICMPType = uint8(term.ICMPType)
	}
	if term.ICMPCode >= 0 {
		base.MatchFlags |= FilterMatchICMPCode
		base.ICMPCode = uint8(term.ICMPCode)
	}

	// Destination port (first port only for now)
	if len(term.DestinationPorts) > 0 {
		base.MatchFlags |= FilterMatchDstPort
		portStr := term.DestinationPorts[0]
		// Resolve well-known port names
		portNum := resolvePortName(portStr)
		base.DstPort = htons(portNum)
	}

	// Expand source/destination address combinations
	srcAddrs := term.SourceAddresses
	dstAddrs := term.DestAddresses
	if len(srcAddrs) == 0 {
		srcAddrs = []string{""} // "any"
	}
	if len(dstAddrs) == 0 {
		dstAddrs = []string{""} // "any"
	}

	var rules []FilterRule
	for _, src := range srcAddrs {
		for _, dst := range dstAddrs {
			rule := base
			if src != "" {
				rule.MatchFlags |= FilterMatchSrcAddr
				setFilterAddr(&rule.SrcAddr, &rule.SrcMask, src, family)
			}
			if dst != "" {
				rule.MatchFlags |= FilterMatchDstAddr
				setFilterAddr(&rule.DstAddr, &rule.DstMask, dst, family)
			}
			rules = append(rules, rule)
		}
	}

	return rules
}

// setFilterAddr parses a CIDR string and populates addr/mask byte arrays.
func setFilterAddr(addr, mask *[16]byte, cidr string, family uint8) {
	// Strip "except" suffix (prefix-list negation — not supported yet, treat as positive match)
	cidr = strings.TrimSuffix(cidr, " except")
	cidr = strings.TrimSuffix(cidr, ";")

	// If no prefix length, assume /32 (v4) or /128 (v6)
	if !strings.Contains(cidr, "/") {
		if family == AFInet {
			cidr += "/32"
		} else {
			cidr += "/128"
		}
	}

	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		slog.Warn("invalid CIDR in filter term", "cidr", cidr, "err", err)
		return
	}

	if family == AFInet {
		ip4 := ip.To4()
		if ip4 == nil {
			return
		}
		copy(addr[:4], ip4)
		copy(mask[:4], ipNet.Mask)
	} else {
		ip16 := ip.To16()
		if ip16 == nil {
			return
		}
		copy(addr[:], ip16)
		copy(mask[:], ipNet.Mask)
	}
}

// resolvePortName maps well-known port names to numbers.
func resolvePortName(name string) uint16 {
	switch strings.ToLower(name) {
	case "ssh":
		return 22
	case "http":
		return 80
	case "https":
		return 443
	case "dns":
		return 53
	case "ftp":
		return 21
	case "smtp":
		return 25
	case "snmp":
		return 161
	case "bgp":
		return 179
	case "ntp":
		return 123
	case "telnet":
		return 23
	default:
		if v, err := strconv.ParseUint(name, 10, 16); err == nil {
			return uint16(v)
		}
		return 0
	}
}
