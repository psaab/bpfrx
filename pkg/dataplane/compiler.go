package dataplane

import (
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/psviderski/bpfrx/pkg/config"
)

// CompileResult holds the result of a config compilation for reference.
type CompileResult struct {
	ZoneIDs    map[string]uint16 // zone name -> zone ID
	AddrIDs    map[string]uint32 // address name -> address ID
	AppIDs     map[string]uint32 // application name -> app ID
	PolicySets int               // number of policy sets created
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
		ZoneIDs: make(map[string]uint16),
		AddrIDs: make(map[string]uint32),
		AppIDs:  make(map[string]uint32),
	}

	// Phase 1: Assign zone IDs (1-based; 0 = unassigned)
	zoneID := uint16(1)
	for name := range cfg.Security.Zones {
		result.ZoneIDs[name] = zoneID
		zoneID++
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

	slog.Info("config compiled to dataplane",
		"zones", len(result.ZoneIDs),
		"addresses", len(result.AddrIDs),
		"applications", len(result.AppIDs),
		"policy_sets", result.PolicySets)

	return result, nil
}

func (m *Manager) compileZones(cfg *config.Config, result *CompileResult) error {
	for name, zone := range cfg.Security.Zones {
		zid := result.ZoneIDs[name]

		// Write zone_config
		zc := ZoneConfig{
			ZoneID: zid,
		}
		if err := m.SetZoneConfig(zid, zc); err != nil {
			return fmt.Errorf("set zone config %s: %w", name, err)
		}

		// Map interfaces to zone
		for _, ifaceName := range zone.Interfaces {
			iface, err := net.InterfaceByName(ifaceName)
			if err != nil {
				slog.Warn("interface not found, skipping",
					"interface", ifaceName, "zone", name, "err", err)
				continue
			}

			if err := m.SetZone(iface.Index, zid); err != nil {
				return fmt.Errorf("set zone for %s (ifindex %d): %w",
					ifaceName, iface.Index, err)
			}

			if err := m.AddTxPort(iface.Index); err != nil {
				return fmt.Errorf("add tx port %s: %w", ifaceName, err)
			}

			if err := m.AttachXDP(iface.Index); err != nil {
				// May already be attached from a previous compile
				if !strings.Contains(err.Error(), "already attached") {
					return fmt.Errorf("attach XDP to %s: %w", ifaceName, err)
				}
			}

			slog.Info("zone interface configured",
				"zone", name, "interface", ifaceName,
				"ifindex", iface.Index, "zone_id", zid)
		}
	}
	return nil
}

func (m *Manager) compileAddressBook(cfg *config.Config, result *CompileResult) error {
	ab := cfg.Security.AddressBook
	if ab == nil {
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
			cidr = cidr + "/32"
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

	// Process address sets
	for setName, addrSet := range ab.AddressSets {
		setID := addrID
		result.AddrIDs[setName] = setID
		addrID++

		// Write membership entries for each member
		for _, memberName := range addrSet.Addresses {
			memberID, ok := result.AddrIDs[memberName]
			if !ok {
				slog.Warn("address set member not found",
					"set", setName, "member", memberName)
				continue
			}
			if err := m.SetAddressMembership(memberID, setID); err != nil {
				return fmt.Errorf("set membership %s in %s: %w",
					memberName, setName, err)
			}
		}

		slog.Debug("address set compiled", "name", setName, "id", setID,
			"members", len(addrSet.Addresses))
	}

	return nil
}

func (m *Manager) compileApplications(cfg *config.Config, result *CompileResult) error {
	if err := m.ClearApplications(); err != nil {
		slog.Warn("failed to clear applications map", "err", err)
	}

	appID := uint32(1)
	userApps := cfg.Applications.Applications

	// Collect all referenced application names from policies
	referenced := make(map[string]bool)
	for _, zpp := range cfg.Security.Policies {
		for _, pol := range zpp.Policies {
			for _, appName := range pol.Match.Applications {
				if appName != "any" {
					referenced[appName] = true
				}
			}
		}
	}

	for appName := range referenced {
		app, found := config.ResolveApplication(appName, userApps)
		if !found {
			slog.Warn("application not found", "name", appName)
			continue
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

func (m *Manager) compilePolicies(cfg *config.Config, result *CompileResult) error {
	if err := m.ClearZonePairPolicies(); err != nil {
		slog.Warn("failed to clear zone pair policies", "err", err)
	}

	policySetID := uint32(0)

	for _, zpp := range cfg.Security.Policies {
		fromZone, ok := result.ZoneIDs[zpp.FromZone]
		if !ok {
			slog.Warn("from-zone not found", "zone", zpp.FromZone)
			continue
		}
		toZone, ok := result.ZoneIDs[zpp.ToZone]
		if !ok {
			slog.Warn("to-zone not found", "zone", zpp.ToZone)
			continue
		}

		ps := PolicySet{
			PolicySetID:   policySetID,
			NumRules:      uint16(len(zpp.Policies)),
			DefaultAction: ActionDeny,
		}
		if err := m.SetZonePairPolicy(fromZone, toZone, ps); err != nil {
			return fmt.Errorf("set zone pair policy %s->%s: %w",
				zpp.FromZone, zpp.ToZone, err)
		}

		for i, pol := range zpp.Policies {
			rule := PolicyRule{
				RuleID:      uint32(policySetID*MaxRulesPerPolicy + uint32(i)),
				PolicySetID: policySetID,
				Sequence:    uint16(i),
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
			if pol.Log != nil && (pol.Log.SessionInit || pol.Log.SessionClose) {
				rule.Log = 1
			}

			// Source address
			if len(pol.Match.SourceAddresses) > 0 {
				addrName := pol.Match.SourceAddresses[0]
				if addrName != "any" {
					if id, ok := result.AddrIDs[addrName]; ok {
						rule.SrcAddrID = id
					}
				}
			}

			// Destination address
			if len(pol.Match.DestinationAddresses) > 0 {
				addrName := pol.Match.DestinationAddresses[0]
				if addrName != "any" {
					if id, ok := result.AddrIDs[addrName]; ok {
						rule.DstAddrID = id
					}
				}
			}

			// Application
			if len(pol.Match.Applications) > 0 {
				appName := pol.Match.Applications[0]
				if appName != "any" {
					if id, ok := result.AppIDs[appName]; ok {
						rule.AppID = id
					}
				}
			}

			if err := m.SetPolicyRule(policySetID, uint32(i), rule); err != nil {
				return fmt.Errorf("set policy rule %s[%d]: %w",
					pol.Name, i, err)
			}

			slog.Debug("policy rule compiled",
				"from", zpp.FromZone, "to", zpp.ToZone,
				"policy", pol.Name, "action", rule.Action,
				"index", i)
		}

		result.PolicySets++
		policySetID++
	}

	return nil
}

func (m *Manager) compileNAT(cfg *config.Config, result *CompileResult) error {
	// Clear previous NAT entries
	if err := m.ClearSNATRules(); err != nil {
		slog.Warn("failed to clear snat_rules", "err", err)
	}
	if err := m.ClearDNATStatic(); err != nil {
		slog.Warn("failed to clear static dnat entries", "err", err)
	}

	natCfg := &cfg.Security.NAT

	// Source NAT
	for _, rs := range natCfg.Source {
		fromZone, ok := result.ZoneIDs[rs.FromZone]
		if !ok {
			slog.Warn("source NAT from-zone not found", "zone", rs.FromZone)
			continue
		}
		toZone, ok := result.ZoneIDs[rs.ToZone]
		if !ok {
			slog.Warn("source NAT to-zone not found", "zone", rs.ToZone)
			continue
		}

		for _, rule := range rs.Rules {
			if !rule.Then.Interface {
				slog.Warn("only interface mode SNAT supported",
					"rule", rule.Name, "rule-set", rs.Name)
				continue
			}

			// Find the to-zone's interface and get its primary IPv4 address
			toZoneCfg, ok := cfg.Security.Zones[rs.ToZone]
			if !ok || len(toZoneCfg.Interfaces) == 0 {
				slog.Warn("to-zone has no interfaces",
					"zone", rs.ToZone, "rule-set", rs.Name)
				continue
			}

			ifaceName := toZoneCfg.Interfaces[0]
			snatIP, err := getInterfaceIP(ifaceName)
			if err != nil {
				slog.Warn("cannot get interface IP for SNAT",
					"interface", ifaceName, "err", err)
				continue
			}

			val := SNATValue{
				SNATIP: ipToUint32BE(snatIP),
				Mode:   0, // interface mode
			}
			if err := m.SetSNATRule(fromZone, toZone, val); err != nil {
				return fmt.Errorf("set snat rule %s/%s: %w",
					rs.Name, rule.Name, err)
			}

			slog.Info("source NAT rule compiled",
				"rule-set", rs.Name, "rule", rule.Name,
				"from", rs.FromZone, "to", rs.ToZone,
				"snat_ip", snatIP)
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
					slog.Warn("DNAT pool not found",
						"pool", rule.Then.PoolName,
						"rule", rule.Name)
					continue
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

				// Determine protocol (default TCP if port specified)
				proto := uint8(0) // any
				if dstPort != 0 {
					proto = 6 // TCP default for port-based DNAT
				}

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
					return fmt.Errorf("set dnat entry %s/%s: %w",
						rs.Name, rule.Name, err)
				}

				slog.Info("destination NAT rule compiled",
					"rule-set", rs.Name, "rule", rule.Name,
					"match_ip", matchIP, "match_port", dstPort,
					"pool", pool.Name, "pool_ip", poolIP,
					"pool_port", poolPort)
			}
		}
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

// protocolNumber converts a protocol name to its IANA number.
func protocolNumber(name string) uint8 {
	switch strings.ToLower(name) {
	case "tcp":
		return 6
	case "udp":
		return 17
	case "icmp":
		return 1
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
