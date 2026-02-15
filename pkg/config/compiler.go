package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// CompileConfig converts a parsed ConfigTree AST into a typed Config struct.
func CompileConfig(tree *ConfigTree) (*Config, error) {
	// Expand groups before compilation — resolve all apply-groups references.
	if err := tree.ExpandGroups(); err != nil {
		return nil, fmt.Errorf("apply-groups: %w", err)
	}

	cfg := &Config{
		Security: SecurityConfig{
			Zones:  make(map[string]*ZoneConfig),
			Screen: make(map[string]*ScreenProfile),
		},
		Interfaces: InterfacesConfig{
			Interfaces: make(map[string]*InterfaceConfig),
		},
		Applications: ApplicationsConfig{
			Applications:    make(map[string]*Application),
			ApplicationSets: make(map[string]*ApplicationSet),
		},
	}

	for _, node := range tree.Children {
		switch node.Name() {
		case "security":
			if err := compileSecurity(node, &cfg.Security); err != nil {
				return nil, fmt.Errorf("security: %w", err)
			}
		case "interfaces":
			if err := compileInterfaces(node, &cfg.Interfaces); err != nil {
				return nil, fmt.Errorf("interfaces: %w", err)
			}
		case "applications":
			if err := compileApplications(node, &cfg.Applications); err != nil {
				return nil, fmt.Errorf("applications: %w", err)
			}
		case "routing-options":
			if err := compileRoutingOptions(node, &cfg.RoutingOptions); err != nil {
				return nil, fmt.Errorf("routing-options: %w", err)
			}
		case "protocols":
			if err := compileProtocols(node, &cfg.Protocols); err != nil {
				return nil, fmt.Errorf("protocols: %w", err)
			}
		case "routing-instances":
			if err := compileRoutingInstances(node, cfg); err != nil {
				return nil, fmt.Errorf("routing-instances: %w", err)
			}
		case "firewall":
			if err := compileFirewall(node, &cfg.Firewall); err != nil {
				return nil, fmt.Errorf("firewall: %w", err)
			}
		case "services":
			if err := compileServices(node, &cfg.Services); err != nil {
				return nil, fmt.Errorf("services: %w", err)
			}
		case "forwarding-options":
			if err := compileForwardingOptions(node, &cfg.ForwardingOptions); err != nil {
				return nil, fmt.Errorf("forwarding-options: %w", err)
			}
		case "system":
			if err := compileSystem(node, &cfg.System); err != nil {
				return nil, fmt.Errorf("system: %w", err)
			}
		case "schedulers":
			if err := compileSchedulers(node, cfg); err != nil {
				return nil, fmt.Errorf("schedulers: %w", err)
			}
		case "policy-options":
			if err := compilePolicyOptions(node, &cfg.PolicyOptions); err != nil {
				return nil, fmt.Errorf("policy-options: %w", err)
			}
		case "chassis":
			if err := compileChassis(node, &cfg.Chassis); err != nil {
				return nil, fmt.Errorf("chassis: %w", err)
			}
		case "event-options":
			if err := compileEventOptions(node, &cfg.EventOptions); err != nil {
				return nil, fmt.Errorf("event-options: %w", err)
			}
		case "snmp":
			// Top-level snmp stanza (same format as system { snmp { ... } })
			if err := compileSNMP(node, &cfg.System); err != nil {
				return nil, fmt.Errorf("snmp: %w", err)
			}
		}
	}

	// Extract lo0 filter input from parsed interfaces into SystemConfig.
	if lo0 := cfg.Interfaces.Interfaces["lo0"]; lo0 != nil {
		if u0 := lo0.Units[0]; u0 != nil {
			cfg.System.Lo0FilterInputV4 = u0.FilterInputV4
			cfg.System.Lo0FilterInputV6 = u0.FilterInputV6
		}
	}

	if warnings := ValidateConfig(cfg); len(warnings) > 0 {
		for _, w := range warnings {
			cfg.Warnings = append(cfg.Warnings, w)
		}
	}

	return cfg, nil
}

// ValidateConfig performs cross-reference validation on a compiled config.
// Returns a list of warnings (non-fatal) for references that don't resolve.
func ValidateConfig(cfg *Config) []string {
	var warnings []string

	// Collect valid zone names
	zones := make(map[string]bool)
	for name := range cfg.Security.Zones {
		zones[name] = true
	}

	// Collect valid address-book entries
	addrs := make(map[string]bool)
	if ab := cfg.Security.AddressBook; ab != nil {
		for name := range ab.Addresses {
			addrs[name] = true
		}
		for name := range ab.AddressSets {
			addrs[name] = true
		}
	}

	// Collect valid applications
	apps := make(map[string]bool)
	for name := range cfg.Applications.Applications {
		apps[name] = true
	}
	for name := range cfg.Applications.ApplicationSets {
		apps[name] = true
	}
	// Built-in Junos application names
	builtins := []string{"any", "junos-http", "junos-https", "junos-ssh", "junos-telnet",
		"junos-dns-udp", "junos-dns-tcp", "junos-ping", "junos-icmp-all",
		"junos-bgp", "junos-ospf", "junos-ntp", "junos-dhcp-relay",
		"junos-ftp", "junos-smtp", "junos-icmp6-all", "junos-ike",
		"junos-ipsec-nat-t", "junos-dhcp-client", "junos-dhcp-server",
		"junos-snmp", "junos-syslog", "junos-traceroute", "junos-radius"}
	for _, b := range builtins {
		apps[b] = true
	}

	// Validate application port specs and protocols
	for name, app := range cfg.Applications.Applications {
		if err := validatePortSpec(app.DestinationPort); err != nil {
			warnings = append(warnings, fmt.Sprintf("application %s: destination-port: %v", name, err))
		}
		if err := validatePortSpec(app.SourcePort); err != nil {
			warnings = append(warnings, fmt.Sprintf("application %s: source-port: %v", name, err))
		}
		if app.Protocol != "" {
			if err := validateProtocol(app.Protocol); err != nil {
				warnings = append(warnings, fmt.Sprintf("application %s: %v", name, err))
			}
		}
	}

	// Validate policies
	for _, zpp := range cfg.Security.Policies {
		if zpp.FromZone != "any" && !zones[zpp.FromZone] {
			warnings = append(warnings, fmt.Sprintf(
				"policy from-zone %q: zone not defined", zpp.FromZone))
		}
		if zpp.ToZone != "any" && !zones[zpp.ToZone] {
			warnings = append(warnings, fmt.Sprintf(
				"policy to-zone %q: zone not defined", zpp.ToZone))
		}
		for _, p := range zpp.Policies {
			for _, addr := range p.Match.SourceAddresses {
				if addr != "any" && !addrs[addr] {
					warnings = append(warnings, fmt.Sprintf(
						"policy %q: source-address %q not in address-book", p.Name, addr))
				}
			}
			for _, addr := range p.Match.DestinationAddresses {
				if addr != "any" && !addrs[addr] {
					warnings = append(warnings, fmt.Sprintf(
						"policy %q: destination-address %q not in address-book", p.Name, addr))
				}
			}
			for _, app := range p.Match.Applications {
				if !apps[app] {
					warnings = append(warnings, fmt.Sprintf(
						"policy %q: application %q not defined", p.Name, app))
				}
			}
		}
	}

	// Validate NAT zone references
	for _, rs := range cfg.Security.NAT.Source {
		if rs.FromZone != "" && !zones[rs.FromZone] {
			warnings = append(warnings, fmt.Sprintf(
				"source-nat ruleset %q: from-zone %q not defined", rs.Name, rs.FromZone))
		}
		if rs.ToZone != "" && !zones[rs.ToZone] {
			warnings = append(warnings, fmt.Sprintf(
				"source-nat ruleset %q: to-zone %q not defined", rs.Name, rs.ToZone))
		}
	}

	// Validate screen references in zones
	for name, zone := range cfg.Security.Zones {
		if zone.ScreenProfile != "" {
			if _, ok := cfg.Security.Screen[zone.ScreenProfile]; !ok {
				warnings = append(warnings, fmt.Sprintf(
					"zone %q: screen profile %q not defined", name, zone.ScreenProfile))
			}
		}
	}

	// Validate address-book entries have valid CIDR or IP formats
	if ab := cfg.Security.AddressBook; ab != nil {
		for name, entry := range ab.Addresses {
			if entry.Value != "" {
				if _, _, err := net.ParseCIDR(entry.Value); err != nil {
					if net.ParseIP(entry.Value) == nil {
						warnings = append(warnings, fmt.Sprintf(
							"address-book %q: invalid address %q", name, entry.Value))
					}
				}
			}
		}
		// Validate address-set members reference valid entries
		for setName, as := range ab.AddressSets {
			for _, m := range as.Addresses {
				if !addrs[m] {
					warnings = append(warnings, fmt.Sprintf(
						"address-set %q: member %q not in address-book", setName, m))
				}
			}
			for _, m := range as.AddressSets {
				if !addrs[m] {
					warnings = append(warnings, fmt.Sprintf(
						"address-set %q: nested set %q not in address-book", setName, m))
				}
			}
		}
	}

	// Validate static route destinations are valid CIDR
	for _, sr := range cfg.RoutingOptions.StaticRoutes {
		if sr.Destination != "" {
			if _, _, err := net.ParseCIDR(sr.Destination); err != nil {
				warnings = append(warnings, fmt.Sprintf(
					"static route: invalid destination %q", sr.Destination))
			}
		}
	}

	// Validate DNAT pool references
	if dnat := cfg.Security.NAT.Destination; dnat != nil {
		for _, rs := range dnat.RuleSets {
			for _, rule := range rs.Rules {
				if rule.Then.PoolName != "" {
					if _, ok := dnat.Pools[rule.Then.PoolName]; !ok {
						warnings = append(warnings, fmt.Sprintf(
							"destination-nat %q rule %q: pool %q not defined",
							rs.Name, rule.Name, rule.Then.PoolName))
					}
				}
			}
		}
	}

	// Validate SNAT pool references
	for _, rs := range cfg.Security.NAT.Source {
		for _, rule := range rs.Rules {
			if rule.Then.PoolName != "" {
				if _, ok := cfg.Security.NAT.SourcePools[rule.Then.PoolName]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"source-nat %q rule %q: pool %q not defined",
						rs.Name, rule.Name, rule.Then.PoolName))
				}
			}
		}
	}

	// Validate zone interface references
	configuredIfaces := make(map[string]bool)
	for name := range cfg.Interfaces.Interfaces {
		configuredIfaces[name] = true
	}
	for zoneName, zone := range cfg.Security.Zones {
		for _, ifName := range zone.Interfaces {
			// Strip unit suffix (e.g. "trust0.0" -> "trust0")
			base := ifName
			if idx := strings.Index(ifName, "."); idx > 0 {
				base = ifName[:idx]
			}
			if !configuredIfaces[base] {
				warnings = append(warnings, fmt.Sprintf(
					"zone %q: interface %q not in interfaces config", zoneName, ifName))
			}
		}
	}

	// Validate scheduler references in policies
	for _, zpp := range cfg.Security.Policies {
		for _, p := range zpp.Policies {
			if p.SchedulerName != "" {
				if _, ok := cfg.Schedulers[p.SchedulerName]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"policy %q: scheduler %q not defined", p.Name, p.SchedulerName))
				}
			}
		}
	}

	// Validate routing-instance interface references
	for _, ri := range cfg.RoutingInstances {
		for _, ifName := range ri.Interfaces {
			base := ifName
			if idx := strings.Index(ifName, "."); idx > 0 {
				base = ifName[:idx]
			}
			if !configuredIfaces[base] {
				warnings = append(warnings, fmt.Sprintf(
					"routing-instance %q: interface %q not in interfaces config",
					ri.Name, ifName))
			}
		}
	}

	// Validate firewall filter references on interfaces
	for ifName, ifc := range cfg.Interfaces.Interfaces {
		for unitNum, unit := range ifc.Units {
			if unit.FilterInputV4 != "" {
				if _, ok := cfg.Firewall.FiltersInet[unit.FilterInputV4]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"interface %s unit %d: filter input %q not defined",
						ifName, unitNum, unit.FilterInputV4))
				}
			}
			if unit.FilterInputV6 != "" {
				if _, ok := cfg.Firewall.FiltersInet6[unit.FilterInputV6]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"interface %s unit %d: filter input-v6 %q not defined",
						ifName, unitNum, unit.FilterInputV6))
				}
			}
			if unit.FilterOutputV4 != "" {
				if _, ok := cfg.Firewall.FiltersInet[unit.FilterOutputV4]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"interface %s unit %d: filter output %q not defined",
						ifName, unitNum, unit.FilterOutputV4))
				}
			}
			if unit.FilterOutputV6 != "" {
				if _, ok := cfg.Firewall.FiltersInet6[unit.FilterOutputV6]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"interface %s unit %d: filter output-v6 %q not defined",
						ifName, unitNum, unit.FilterOutputV6))
				}
			}
		}
	}

	return warnings
}

func compileSecurity(node *Node, sec *SecurityConfig) error {
	for _, child := range node.Children {
		switch child.Name() {
		case "zones":
			if err := compileZones(child, sec); err != nil {
				return fmt.Errorf("zones: %w", err)
			}
		case "policies":
			if err := compilePolicies(child, sec); err != nil {
				return fmt.Errorf("policies: %w", err)
			}
		case "screen":
			if err := compileScreen(child, sec); err != nil {
				return fmt.Errorf("screen: %w", err)
			}
		case "nat":
			if err := compileNAT(child, sec); err != nil {
				return fmt.Errorf("nat: %w", err)
			}
		case "address-book":
			if err := compileAddressBook(child, sec); err != nil {
				return fmt.Errorf("address-book: %w", err)
			}
		case "log":
			if err := compileLog(child, sec); err != nil {
				return fmt.Errorf("log: %w", err)
			}
		case "flow":
			if err := compileFlow(child, sec); err != nil {
				return fmt.Errorf("flow: %w", err)
			}
		case "ike":
			if err := compileIKE(child, sec); err != nil {
				return fmt.Errorf("ike: %w", err)
			}
		case "ipsec":
			if err := compileIPsec(child, sec); err != nil {
				return fmt.Errorf("ipsec: %w", err)
			}
		case "dynamic-address":
			if err := compileDynamicAddress(child, sec); err != nil {
				return fmt.Errorf("dynamic-address: %w", err)
			}
		case "alg":
			if err := compileALG(child, sec); err != nil {
				return fmt.Errorf("alg: %w", err)
			}
		case "ssh-known-hosts":
			sec.SSHKnownHosts = make(map[string][]SSHKnownHostKey)
			for _, hostInst := range namedInstances(child.FindChildren("host")) {
				var keys []SSHKnownHostKey
				for _, kp := range hostInst.node.Children {
					name := kp.Name()
					if v := nodeVal(kp); v != "" {
						keys = append(keys, SSHKnownHostKey{Type: name, Key: v})
					}
				}
				sec.SSHKnownHosts[hostInst.name] = keys
			}
		case "policy-stats":
			if sw := child.FindChild("system-wide"); sw != nil {
				sec.PolicyStatsEnabled = nodeVal(sw) == "enable"
			}
		case "pre-id-default-policy":
			sec.PreIDDefaultPolicy = &PreIDDefaultPolicy{}
			if thenNode := child.FindChild("then"); thenNode != nil {
				if logNode := thenNode.FindChild("log"); logNode != nil {
					if logNode.FindChild("session-init") != nil {
						sec.PreIDDefaultPolicy.LogSessionInit = true
					}
					if logNode.FindChild("session-close") != nil {
						sec.PreIDDefaultPolicy.LogSessionClose = true
					}
				}
			}
		}
	}
	return nil
}

func compileZones(node *Node, sec *SecurityConfig) error {
	for _, inst := range namedInstances(node.FindChildren("security-zone")) {
		zone := &ZoneConfig{Name: inst.name}

		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "interfaces":
				for _, iface := range prop.Children {
					zone.Interfaces = append(zone.Interfaces, iface.Name())
				}
			case "screen":
				zone.ScreenProfile = nodeVal(prop)
			case "host-inbound-traffic":
				zone.HostInboundTraffic = &HostInboundTraffic{}
				for _, hit := range prop.Children {
					switch hit.Name() {
					case "system-services":
						for _, svc := range hit.Children {
							zone.HostInboundTraffic.SystemServices = append(
								zone.HostInboundTraffic.SystemServices, svc.Name())
						}
					case "protocols":
						for _, proto := range hit.Children {
							zone.HostInboundTraffic.Protocols = append(
								zone.HostInboundTraffic.Protocols, proto.Name())
						}
					}
				}
			case "tcp-rst":
				zone.TCPRst = true
			case "description":
				zone.Description = nodeVal(prop)
			}
		}

		sec.Zones[inst.name] = zone
	}
	return nil
}

func compilePolicies(node *Node, sec *SecurityConfig) error {
	for _, child := range node.Children {
		if child.Name() == "default-policy" {
			var policyStr string
			if len(child.Keys) >= 2 {
				// Flat form: default-policy deny-all;
				policyStr = child.Keys[1]
			} else if len(child.Children) > 0 {
				// Hierarchical form: default-policy { deny-all; }
				policyStr = child.Children[0].Name()
			}
			switch policyStr {
			case "permit-all":
				sec.DefaultPolicy = PolicyPermit
			case "deny-all":
				sec.DefaultPolicy = PolicyDeny
			}
			continue
		}
		// "global { policy ... }" - global policies applied to all zone pairs
		if child.Name() == "global" {
			for _, polInst := range namedInstances(child.FindChildren("policy")) {
				pol := compilePolicy(polInst)
				sec.GlobalPolicies = append(sec.GlobalPolicies, pol)
			}
			continue
		}
		// "from-zone trust to-zone untrust { ... }"
		if child.Name() == "from-zone" {
			type zonePair struct {
				from, to   string
				policyNode *Node
			}
			var pairs []zonePair

			if len(child.Keys) >= 4 {
				// Hierarchical: Keys=["from-zone", "trust", "to-zone", "untrust"]
				pairs = append(pairs, zonePair{child.Keys[1], child.Keys[3], child})
			} else {
				// Flat set: from-zone → <name> → to-zone → <name> → policy ...
				for _, fzSub := range child.Children {
					tzNode := fzSub.FindChild("to-zone")
					if tzNode == nil {
						continue
					}
					for _, tzSub := range tzNode.Children {
						pairs = append(pairs, zonePair{fzSub.Name(), tzSub.Name(), tzSub})
					}
				}
			}

			for _, zp := range pairs {
				zpp := &ZonePairPolicies{
					FromZone: zp.from,
					ToZone:   zp.to,
				}

				for _, polInst := range namedInstances(zp.policyNode.FindChildren("policy")) {
					zpp.Policies = append(zpp.Policies, compilePolicy(polInst))
				}

				sec.Policies = append(sec.Policies, zpp)
			}
		}
	}
	return nil
}

// compilePolicy extracts a Policy from a named policy instance.
func compilePolicy(polInst struct {
	name string
	node *Node
}) *Policy {
	pol := &Policy{Name: polInst.name}

	matchNode := polInst.node.FindChild("match")
	if matchNode != nil {
		for _, m := range matchNode.Children {
			switch m.Name() {
			case "source-address":
				if len(m.Keys) >= 2 {
					pol.Match.SourceAddresses = append(pol.Match.SourceAddresses, m.Keys[1:]...)
				} else {
					for _, c := range m.Children {
						pol.Match.SourceAddresses = append(pol.Match.SourceAddresses, c.Name())
					}
				}
			case "destination-address":
				if len(m.Keys) >= 2 {
					pol.Match.DestinationAddresses = append(pol.Match.DestinationAddresses, m.Keys[1:]...)
				} else {
					for _, c := range m.Children {
						pol.Match.DestinationAddresses = append(pol.Match.DestinationAddresses, c.Name())
					}
				}
			case "application":
				if len(m.Keys) >= 2 {
					pol.Match.Applications = append(pol.Match.Applications, m.Keys[1:]...)
				} else {
					for _, c := range m.Children {
						pol.Match.Applications = append(pol.Match.Applications, c.Name())
					}
				}
			}
		}
	}

	thenNode := polInst.node.FindChild("then")
	if thenNode != nil {
		for _, t := range thenNode.Children {
			switch t.Name() {
			case "permit":
				pol.Action = PolicyPermit
			case "deny":
				pol.Action = PolicyDeny
			case "reject":
				pol.Action = PolicyReject
			case "log":
				pol.Log = &PolicyLog{}
				for _, logOpt := range t.Children {
					switch logOpt.Name() {
					case "session-init":
						pol.Log.SessionInit = true
					case "session-close":
						pol.Log.SessionClose = true
					}
				}
			case "count":
				pol.Count = true
			}
		}
	}

	if descNode := polInst.node.FindChild("description"); descNode != nil {
		pol.Description = nodeVal(descNode)
	}
	if snNode := polInst.node.FindChild("scheduler-name"); snNode != nil {
		pol.SchedulerName = nodeVal(snNode)
	}

	return pol
}

func compileScreen(node *Node, sec *SecurityConfig) error {
	for _, inst := range namedInstances(node.FindChildren("ids-option")) {
		profile := &ScreenProfile{Name: inst.name}

		icmpNode := inst.node.FindChild("icmp")
		if icmpNode != nil {
			for _, opt := range icmpNode.Children {
				switch opt.Name() {
				case "ping-death":
					profile.ICMP.PingDeath = true
				case "flood":
					if len(opt.Keys) >= 3 {
						if v, err := strconv.Atoi(opt.Keys[2]); err == nil {
							profile.ICMP.FloodThreshold = v
						}
					} else if v := nodeVal(opt); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							profile.ICMP.FloodThreshold = n
						}
					}
				}
			}
		}

		ipNode := inst.node.FindChild("ip")
		if ipNode != nil {
			for _, opt := range ipNode.Children {
				switch opt.Name() {
				case "source-route-option":
					profile.IP.SourceRouteOption = true
				case "tear-drop":
					profile.IP.TearDrop = true
				case "ip-sweep":
					for _, swOpt := range opt.Children {
						if swOpt.Name() == "threshold" {
							val := nodeVal(swOpt)
							if val == "" && len(swOpt.Keys) >= 2 {
								val = swOpt.Keys[1]
							}
							if n, err := strconv.Atoi(val); err == nil {
								profile.IP.IPSweepThreshold = n
							}
						}
					}
				}
			}
		}

		tcpNode := inst.node.FindChild("tcp")
		if tcpNode != nil {
			for _, opt := range tcpNode.Children {
				switch opt.Name() {
				case "land":
					profile.TCP.Land = true
				case "winnuke":
					profile.TCP.WinNuke = true
				case "syn-frag":
					profile.TCP.SynFrag = true
				case "syn-fin":
					profile.TCP.SynFin = true
				case "no-flag":
					profile.TCP.NoFlag = true
				case "fin-no-ack":
					profile.TCP.FinNoAck = true
				case "syn-flood":
					sf := &SynFloodConfig{}
					for _, sfOpt := range opt.Children {
						val := nodeVal(sfOpt)
						if val == "" && len(sfOpt.Keys) >= 2 {
							val = sfOpt.Keys[1]
						}
						if val != "" {
							n, _ := strconv.Atoi(val)
							switch sfOpt.Name() {
							case "alarm-threshold":
								sf.AlarmThreshold = n
							case "attack-threshold":
								sf.AttackThreshold = n
							case "source-threshold":
								sf.SourceThreshold = n
							case "destination-threshold":
								sf.DestinationThreshold = n
							case "timeout":
								sf.Timeout = n
							}
						}
					}
					profile.TCP.SynFlood = sf
				case "port-scan":
					for _, psOpt := range opt.Children {
						if psOpt.Name() == "threshold" {
							val := nodeVal(psOpt)
							if val == "" && len(psOpt.Keys) >= 2 {
								val = psOpt.Keys[1]
							}
							if n, err := strconv.Atoi(val); err == nil {
								profile.TCP.PortScanThreshold = n
							}
						}
					}
				}
			}
		}

		udpNode := inst.node.FindChild("udp")
		if udpNode != nil {
			for _, opt := range udpNode.Children {
				switch opt.Name() {
				case "flood":
					if len(opt.Keys) >= 3 {
						if v, err := strconv.Atoi(opt.Keys[2]); err == nil {
							profile.UDP.FloodThreshold = v
						}
					} else if v := nodeVal(opt); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							profile.UDP.FloodThreshold = n
						}
					}
				}
			}
		}

		sec.Screen[profile.Name] = profile
	}
	return nil
}

func compileAddressBook(node *Node, sec *SecurityConfig) error {
	globalNode := node.FindChild("global")
	if globalNode == nil {
		return nil
	}

	ab := &AddressBook{
		Addresses:   make(map[string]*Address),
		AddressSets: make(map[string]*AddressSet),
	}

	for _, child := range globalNode.Children {
		switch child.Name() {
		case "address":
			if len(child.Keys) >= 3 {
				addr := &Address{
					Name:  child.Keys[1],
					Value: child.Keys[2],
				}
				ab.Addresses[addr.Name] = addr
			}
		case "address-set":
			if len(child.Keys) >= 2 {
				as := &AddressSet{Name: child.Keys[1]}
				for _, member := range child.Children {
					switch member.Name() {
					case "address":
						if len(member.Keys) >= 2 {
							as.Addresses = append(as.Addresses, member.Keys[1])
						}
					case "address-set":
						if len(member.Keys) >= 2 {
							as.AddressSets = append(as.AddressSets, member.Keys[1])
						}
					}
				}
				ab.AddressSets[as.Name] = as
			}
		}
	}

	sec.AddressBook = ab
	return nil
}

func compileInterfaces(node *Node, ifaces *InterfacesConfig) error {
	for _, child := range node.Children {
		if child.IsLeaf {
			continue
		}
		ifName := child.Name()
		ifc := &InterfaceConfig{
			Name:  ifName,
			Units: make(map[int]*InterfaceUnit),
		}

		// Check for description
		if descNode := child.FindChild("description"); descNode != nil {
			ifc.Description = nodeVal(descNode)
		}

		// Interface-level MTU
		if mtuNode := child.FindChild("mtu"); mtuNode != nil {
			if v := nodeVal(mtuNode); v != "" {
				if n, err := strconv.Atoi(v); err == nil {
					ifc.MTU = n
				}
			}
		}

		// Speed and duplex (ether-options or gigether-options)
		if speedNode := child.FindChild("speed"); speedNode != nil {
			ifc.Speed = nodeVal(speedNode)
		}
		if duplexNode := child.FindChild("duplex"); duplexNode != nil {
			ifc.Duplex = nodeVal(duplexNode)
		}
		if child.FindChild("disable") != nil {
			ifc.Disable = true
		}

		// Check for vlan-tagging flag
		if child.FindChild("vlan-tagging") != nil {
			ifc.VlanTagging = true
		}

		// Check for gigether-options redundant-parent
		if goNode := child.FindChild("gigether-options"); goNode != nil {
			if rpNode := goNode.FindChild("redundant-parent"); rpNode != nil {
				ifc.RedundantParent = nodeVal(rpNode)
			}
		}

		// Check for redundant-ether-options redundancy-group
		if reoNode := child.FindChild("redundant-ether-options"); reoNode != nil {
			if rgNode := reoNode.FindChild("redundancy-group"); rgNode != nil {
				if v, err := strconv.Atoi(nodeVal(rgNode)); err == nil {
					ifc.RedundancyGroup = v
				}
			}
		}

		// Check for fabric-options member-interfaces
		if foNode := child.FindChild("fabric-options"); foNode != nil {
			if miNode := foNode.FindChild("member-interfaces"); miNode != nil {
				for _, m := range miNode.Children {
					ifc.FabricMembers = append(ifc.FabricMembers, m.Name())
				}
			}
		}

		// Check for tunnel configuration
		tunnelNode := child.FindChild("tunnel")
		if tunnelNode != nil {
			// Default mode based on interface name prefix: ip-X/X/X → ipip, gr-X/X/X → gre
			defaultMode := "gre"
			if strings.HasPrefix(ifName, "ip-") {
				defaultMode = "ipip"
			}
			tc := &TunnelConfig{
				Name: ifName,
				Mode: defaultMode,
			}
			for _, prop := range tunnelNode.Children {
				switch prop.Name() {
				case "source":
					if len(prop.Keys) >= 2 {
						tc.Source = prop.Keys[1]
					}
				case "destination":
					if len(prop.Keys) >= 2 {
						tc.Destination = prop.Keys[1]
					}
				case "mode":
					if len(prop.Keys) >= 2 {
						tc.Mode = prop.Keys[1]
					}
				case "key":
					if len(prop.Keys) >= 2 {
						if v, err := strconv.Atoi(prop.Keys[1]); err == nil {
							tc.Key = uint32(v)
						}
					}
				case "ttl":
					if len(prop.Keys) >= 2 {
						if v, err := strconv.Atoi(prop.Keys[1]); err == nil {
							tc.TTL = v
						}
					}
				case "keepalive":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							tc.Keepalive = n
						}
					}
				case "keepalive-retry":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							tc.KeepaliveRetry = n
						}
					}
				case "routing-instance":
					// routing-instance { destination <name>; }
					if destNode := prop.FindChild("destination"); destNode != nil {
						tc.RoutingInstance = nodeVal(destNode)
					} else if v := nodeVal(prop); v != "" {
						tc.RoutingInstance = v
					}
				}
			}
			ifc.Tunnel = tc
		}

		for _, unitInst := range namedInstances(child.FindChildren("unit")) {
			unitNum, err := strconv.Atoi(unitInst.name)
			if err != nil {
				continue
			}
			unit := &InterfaceUnit{Number: unitNum}

			// Parse description on unit
			if descNode := unitInst.node.FindChild("description"); descNode != nil {
				unit.Description = nodeVal(descNode)
			}

			// Parse point-to-point flag
			if unitInst.node.FindChild("point-to-point") != nil {
				unit.PointToPoint = true
			}

			// Parse tunnel config at unit level (gr-0/0/0 unit N { tunnel { ... } })
			if tunnelNode := unitInst.node.FindChild("tunnel"); tunnelNode != nil {
				tc := ifc.Tunnel
				if tc == nil {
					defaultMode := "gre"
					if strings.HasPrefix(ifName, "ip-") {
						defaultMode = "ipip"
					}
					tc = &TunnelConfig{Name: ifName, Mode: defaultMode}
					ifc.Tunnel = tc
				}
				for _, prop := range tunnelNode.Children {
					switch prop.Name() {
					case "source":
						if v := nodeVal(prop); v != "" {
							tc.Source = v
						}
					case "destination":
						if v := nodeVal(prop); v != "" {
							tc.Destination = v
						}
					case "routing-instance":
						if destNode := prop.FindChild("destination"); destNode != nil {
							tc.RoutingInstance = nodeVal(destNode)
						} else if v := nodeVal(prop); v != "" {
							tc.RoutingInstance = v
						}
					}
				}
			}

			// Parse vlan-id on unit
			if vlanNode := unitInst.node.FindChild("vlan-id"); vlanNode != nil {
				if v := nodeVal(vlanNode); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						unit.VlanID = n
					}
				}
			}

			// Handle two AST shapes:
			// - set commands:  family { inet { address ...; dhcp; } }
			//   Keys=["family"], child Keys=["inet"] with grandchildren
			// - hierarchical:  family inet { address ...; dhcp; }
			//   Keys=["family","inet"], children are address/dhcp directly
			for _, familyNode := range unitInst.node.FindChildren("family") {
				var afNodes []*Node
				if len(familyNode.Keys) >= 2 {
					afNodes = append(afNodes, familyNode)
				} else {
					afNodes = append(afNodes, familyNode.Children...)
				}
				for _, afNode := range afNodes {
					afName := afNode.Keys[0]
					if len(afNode.Keys) >= 2 {
						afName = afNode.Keys[1]
					}
					switch afName {
					case "inet":
						for _, addrInst := range namedInstances(afNode.FindChildren("address")) {
							unit.Addresses = append(unit.Addresses, addrInst.name)
							// Check for primary/preferred flags
							if addrInst.node.FindChild("primary") != nil {
								unit.PrimaryAddress = addrInst.name
							}
							if addrInst.node.FindChild("preferred") != nil {
								unit.PreferredAddress = addrInst.name
							}
							// Parse VRRP groups under address
							for _, vrrpInst := range namedInstances(addrInst.node.FindChildren("vrrp-group")) {
								groupID, err := strconv.Atoi(vrrpInst.name)
								if err != nil {
									continue
								}
								vg := &VRRPGroup{
									ID:       groupID,
									Priority: 100, // default
								}
								for _, prop := range vrrpInst.node.Children {
									switch prop.Name() {
									case "virtual-address":
										if v := nodeVal(prop); v != "" {
											vg.VirtualAddresses = append(vg.VirtualAddresses, v)
										}
									case "priority":
										if v := nodeVal(prop); v != "" {
											vg.Priority, _ = strconv.Atoi(v)
										}
									case "preempt":
										vg.Preempt = true
									case "accept-data":
										vg.AcceptData = true
									case "advertise-interval":
										if v := nodeVal(prop); v != "" {
											vg.AdvertiseInterval, _ = strconv.Atoi(v)
										}
									case "authentication-type":
										vg.AuthType = nodeVal(prop)
									case "authentication-key":
										vg.AuthKey = nodeVal(prop)
									case "track-interface":
										vg.TrackInterface = nodeVal(prop)
									case "track-priority-cost":
										if v := nodeVal(prop); v != "" {
											vg.TrackPriorityDelta, _ = strconv.Atoi(v)
										}
									}
								}
								if unit.VRRPGroups == nil {
									unit.VRRPGroups = make(map[string]*VRRPGroup)
								}
								key := fmt.Sprintf("%s_grp%d", addrInst.name, groupID)
								unit.VRRPGroups[key] = vg
							}
						}
						if dhcpNode := afNode.FindChild("dhcp"); dhcpNode != nil {
							unit.DHCP = true
							if len(dhcpNode.Children) > 0 {
								opts := &DHCPInetOptions{}
								for _, prop := range dhcpNode.Children {
									switch prop.Name() {
									case "lease-time":
										if v := nodeVal(prop); v != "" {
											opts.LeaseTime, _ = strconv.Atoi(v)
										}
									case "retransmission-attempt":
										if v := nodeVal(prop); v != "" {
											opts.RetransmissionAttempt, _ = strconv.Atoi(v)
										}
									case "retransmission-interval":
										if v := nodeVal(prop); v != "" {
											opts.RetransmissionInterval, _ = strconv.Atoi(v)
										}
									case "force-discover":
										opts.ForceDiscover = true
									}
								}
								unit.DHCPOptions = opts
							}
						}
						if mtuNode := afNode.FindChild("mtu"); mtuNode != nil {
							if v := nodeVal(mtuNode); v != "" {
								if n, err := strconv.Atoi(v); err == nil {
									unit.MTU = n
								}
							}
						}
						if sampNode := afNode.FindChild("sampling"); sampNode != nil {
							if sampNode.FindChild("input") != nil {
								unit.SamplingInput = true
							}
							if sampNode.FindChild("output") != nil {
								unit.SamplingOutput = true
							}
						}
						if filterNode := afNode.FindChild("filter"); filterNode != nil {
							if inputNode := filterNode.FindChild("input"); inputNode != nil {
								unit.FilterInputV4 = nodeVal(inputNode)
							}
							if outputNode := filterNode.FindChild("output"); outputNode != nil {
								unit.FilterOutputV4 = nodeVal(outputNode)
							}
						}
					case "inet6":
						for _, addrInst := range namedInstances(afNode.FindChildren("address")) {
							unit.Addresses = append(unit.Addresses, addrInst.name)
							if addrInst.node.FindChild("primary") != nil && unit.PrimaryAddress == "" {
								unit.PrimaryAddress = addrInst.name
							}
							if addrInst.node.FindChild("preferred") != nil && unit.PreferredAddress == "" {
								unit.PreferredAddress = addrInst.name
							}
						}
						if afNode.FindChild("dhcpv6") != nil {
							unit.DHCPv6 = true
						}
						if afNode.FindChild("dad-disable") != nil {
							unit.DADDisable = true
						}
						if mtuNode := afNode.FindChild("mtu"); mtuNode != nil {
							if v := nodeVal(mtuNode); v != "" {
								if n, err := strconv.Atoi(v); err == nil {
									if n < unit.MTU || unit.MTU == 0 {
										unit.MTU = n
									}
								}
							}
						}
						if sampNode := afNode.FindChild("sampling"); sampNode != nil {
							if sampNode.FindChild("input") != nil {
								unit.SamplingInput = true
							}
							if sampNode.FindChild("output") != nil {
								unit.SamplingOutput = true
							}
						}
						if filterNode := afNode.FindChild("filter"); filterNode != nil {
							if inputNode := filterNode.FindChild("input"); inputNode != nil {
								unit.FilterInputV6 = nodeVal(inputNode)
							}
							if outputNode := filterNode.FindChild("output"); outputNode != nil {
								unit.FilterOutputV6 = nodeVal(outputNode)
							}
						}
						if dcNode := afNode.FindChild("dhcpv6-client"); dcNode != nil {
							unit.DHCPv6 = true
							dc := &DHCPv6ClientConfig{}
							for _, prop := range dcNode.Children {
								switch prop.Name() {
								case "client-identifier":
									if dtNode := prop.FindChild("duid-type"); dtNode != nil {
										dc.DUIDType = nodeVal(dtNode)
									} else if nodeVal(prop) == "duid-type" && len(prop.Keys) >= 3 {
										// Inline: client-identifier duid-type duid-ll;
										dc.DUIDType = prop.Keys[2]
									}
								case "client-type":
									dc.ClientType = nodeVal(prop)
								case "client-ia-type":
									if v := nodeVal(prop); v != "" {
										dc.ClientIATypes = append(dc.ClientIATypes, v)
									}
								case "prefix-delegating":
									if plNode := prop.FindChild("preferred-prefix-length"); plNode != nil {
										if v := nodeVal(plNode); v != "" {
											dc.PrefixDelegatingPrefixLen, _ = strconv.Atoi(v)
										}
									}
									if slNode := prop.FindChild("sub-prefix-length"); slNode != nil {
										if v := nodeVal(slNode); v != "" {
											dc.PrefixDelegatingSubPrefLen, _ = strconv.Atoi(v)
										}
									}
								case "req-option":
									if v := nodeVal(prop); v != "" {
										dc.ReqOptions = append(dc.ReqOptions, v)
									}
								case "update-router-advertisement":
									if ifNode := prop.FindChild("interface"); ifNode != nil {
										dc.UpdateRAInterface = nodeVal(ifNode)
									}
								}
							}
							unit.DHCPv6Client = dc
						}
					}
				}
			}

			ifc.Units[unitNum] = unit

			// Collect tunnel addresses from unit config
			if ifc.Tunnel != nil {
				ifc.Tunnel.Addresses = append(ifc.Tunnel.Addresses, unit.Addresses...)
			}
		}

		ifaces.Interfaces[ifName] = ifc
	}
	return nil
}

func compileNAT(node *Node, sec *SecurityConfig) error {
	// Initialize SourcePools map
	if sec.NAT.SourcePools == nil {
		sec.NAT.SourcePools = make(map[string]*NATPool)
	}

	srcNode := node.FindChild("source")
	if srcNode != nil {
		if err := compileNATSource(srcNode, sec); err != nil {
			return fmt.Errorf("source: %w", err)
		}
	}

	dstNode := node.FindChild("destination")
	if dstNode != nil {
		if err := compileNATDestination(dstNode, sec); err != nil {
			return fmt.Errorf("destination: %w", err)
		}
	}

	staticNode := node.FindChild("static")
	if staticNode != nil {
		if err := compileNATStatic(staticNode, sec); err != nil {
			return fmt.Errorf("static: %w", err)
		}
	}

	nat64Node := node.FindChild("nat64")
	if nat64Node != nil {
		if err := compileNAT64(nat64Node, sec); err != nil {
			return fmt.Errorf("nat64: %w", err)
		}
	}

	// natv6v4 { no-v6-frag-header; }
	v6v4Node := node.FindChild("natv6v4")
	if v6v4Node != nil {
		sec.NAT.NATv6v4 = &NATv6v4Config{}
		if v6v4Node.FindChild("no-v6-frag-header") != nil {
			sec.NAT.NATv6v4.NoV6FragHeader = true
		}
	}

	return nil
}

func compileNAT64(node *Node, sec *SecurityConfig) error {
	for _, inst := range namedInstances(node.FindChildren("rule-set")) {
		rs := &NAT64RuleSet{Name: inst.name}

		for _, child := range inst.node.Children {
			switch child.Name() {
			case "prefix":
				rs.Prefix = nodeVal(child)
			case "source-pool":
				rs.SourcePool = nodeVal(child)
			}
		}

		sec.NAT.NAT64 = append(sec.NAT.NAT64, rs)
	}
	return nil
}

// parseZoneList extracts zone names from a from/to node.
// Handles multiple AST shapes:
//   - Hierarchical bracket list: Keys=["from","zone","A","B","C"] → ["A","B","C"]
//   - SetPath single: child zone node with value → ["A"]
//   - SetPath multiple: multiple zone children → ["A","B"]
//   - SetPath bracket-expanded: zone child with orphan leaf children → ["A","B"]
func parseZoneList(node *Node) []string {
	// Hierarchical: all zone names inline in Keys
	if len(node.Keys) >= 3 && node.Keys[1] == "zone" {
		return node.Keys[2:]
	}
	// SetPath: iterate all "zone" children (multiple set commands create siblings)
	var zones []string
	for _, child := range node.Children {
		if child.Name() == "zone" {
			if v := nodeVal(child); v != "" {
				zones = append(zones, v)
			}
			// Also collect orphan leaf children (bracket-expanded extra zone names)
			for _, grandchild := range child.Children {
				if grandchild.IsLeaf && len(grandchild.Keys) >= 1 {
					zones = append(zones, grandchild.Keys[0])
				}
			}
		}
	}
	return zones
}

func compileNATSource(node *Node, sec *SecurityConfig) error {
	// Global flags
	if node.FindChild("address-persistent") != nil {
		sec.NAT.AddressPersistent = true
	}

	// Parse source NAT pools
	for _, inst := range namedInstances(node.FindChildren("pool")) {
		pool := &NATPool{Name: inst.name}

		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "address":
				if v := nodeVal(prop); v != "" {
					pool.Addresses = append(pool.Addresses, v)
				}
			case "port":
				// "port range low N high M" or "port N"
				if len(prop.Keys) >= 6 && prop.Keys[1] == "range" &&
					prop.Keys[2] == "low" && prop.Keys[4] == "high" {
					if v, err := strconv.Atoi(prop.Keys[3]); err == nil {
						pool.PortLow = v
					}
					if v, err := strconv.Atoi(prop.Keys[5]); err == nil {
						pool.PortHigh = v
					}
				} else if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						pool.PortLow = n
						pool.PortHigh = n
					}
				}
			case "persistent-nat":
				pnat := &PersistentNATConfig{InactivityTimeout: 300}
				for _, pnProp := range prop.Children {
					switch pnProp.Name() {
					case "permit":
						if v := nodeVal(pnProp); v == "any-remote-host" {
							pnat.PermitAnyRemoteHost = true
						}
					case "inactivity-timeout":
						if v := nodeVal(pnProp); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								pnat.InactivityTimeout = n
							}
						}
					}
				}
				pool.PersistentNAT = pnat
			}
		}
		if pool.PortLow == 0 {
			pool.PortLow = 1024
		}
		if pool.PortHigh == 0 {
			pool.PortHigh = 65535
		}
		sec.NAT.SourcePools[pool.Name] = pool
	}

	// Parse source NAT rule-sets
	for _, rsInst := range namedInstances(node.FindChildren("rule-set")) {
		// Parse from/to zones (bracket lists produce multiple keys)
		var fromZones, toZones []string
		for _, child := range rsInst.node.Children {
			if child.Name() == "from" {
				fromZones = append(fromZones, parseZoneList(child)...)
			}
			if child.Name() == "to" {
				toZones = append(toZones, parseZoneList(child)...)
			}
		}
		if len(fromZones) == 0 {
			fromZones = []string{""}
		}
		if len(toZones) == 0 {
			toZones = []string{""}
		}

		// Parse rules (shared across all zone-pair expansions)
		var rules []*NATRule
		for _, ruleInst := range namedInstances(rsInst.node.FindChildren("rule")) {
			rule := &NATRule{Name: ruleInst.name}

			matchNode := ruleInst.node.FindChild("match")
			if matchNode != nil {
				for _, m := range matchNode.Children {
					switch m.Name() {
					case "source-address":
						// Support bracket lists: source-address [ addr1 addr2 ... ]
						if len(m.Keys) >= 2 {
							rule.Match.SourceAddresses = append(rule.Match.SourceAddresses, m.Keys[1:]...)
						} else if len(m.Children) > 0 {
							for _, child := range m.Children {
								rule.Match.SourceAddresses = append(rule.Match.SourceAddresses, child.Name())
							}
						}
						if len(rule.Match.SourceAddresses) > 0 {
							rule.Match.SourceAddress = rule.Match.SourceAddresses[0]
						}
					case "destination-address":
						// Support bracket lists: destination-address [ addr1 addr2 ... ]
						if len(m.Keys) >= 2 {
							rule.Match.DestinationAddresses = append(rule.Match.DestinationAddresses, m.Keys[1:]...)
						} else if len(m.Children) > 0 {
							for _, child := range m.Children {
								rule.Match.DestinationAddresses = append(rule.Match.DestinationAddresses, child.Name())
							}
						}
						if len(rule.Match.DestinationAddresses) > 0 {
							rule.Match.DestinationAddress = rule.Match.DestinationAddresses[0]
						} else {
							rule.Match.DestinationAddress = nodeVal(m)
						}
					case "destination-port":
						if len(m.Children) > 0 {
							for _, child := range m.Children {
								if n, err := strconv.Atoi(child.Name()); err == nil {
									rule.Match.DestinationPorts = append(rule.Match.DestinationPorts, n)
									if rule.Match.DestinationPort == 0 {
										rule.Match.DestinationPort = n
									}
								}
							}
						} else if v := nodeVal(m); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								rule.Match.DestinationPort = n
								rule.Match.DestinationPorts = append(rule.Match.DestinationPorts, n)
							}
						}
					case "application":
						rule.Match.Application = nodeVal(m)
					}
				}
			}

			thenNode := ruleInst.node.FindChild("then")
			if thenNode != nil {
				for _, t := range thenNode.Children {
					if t.Name() == "source-nat" {
						if len(t.Keys) >= 2 {
							switch t.Keys[1] {
							case "interface":
								rule.Then.Type = NATSource
								rule.Then.Interface = true
							case "off":
								rule.Then.Type = NATSource
								rule.Then.Off = true
							case "pool":
								rule.Then.Type = NATSource
								if len(t.Keys) >= 3 {
									rule.Then.PoolName = t.Keys[2]
								}
							}
						} else if t.FindChild("interface") != nil {
							rule.Then.Type = NATSource
							rule.Then.Interface = true
						} else if t.FindChild("off") != nil {
							rule.Then.Type = NATSource
							rule.Then.Off = true
						} else if poolNode := t.FindChild("pool"); poolNode != nil {
							rule.Then.Type = NATSource
							rule.Then.PoolName = nodeVal(poolNode)
						}
					}
				}
			}

			rules = append(rules, rule)
		}

		// Expand Cartesian product of from-zones × to-zones
		for _, fz := range fromZones {
			for _, tz := range toZones {
				rs := &NATRuleSet{
					Name:     rsInst.name,
					FromZone: fz,
					ToZone:   tz,
					Rules:    rules,
				}
				sec.NAT.Source = append(sec.NAT.Source, rs)
			}
		}
	}
	return nil
}

func compileNATDestination(node *Node, sec *SecurityConfig) error {
	if sec.NAT.Destination == nil {
		sec.NAT.Destination = &DestinationNATConfig{
			Pools: make(map[string]*NATPool),
		}
	}

	// Parse pools
	for _, inst := range namedInstances(node.FindChildren("pool")) {
		pool := &NATPool{Name: inst.name}

		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "address":
				pool.Address = nodeVal(prop)
			case "port":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						pool.Port = n
					}
				}
			}
		}

		sec.NAT.Destination.Pools[pool.Name] = pool
	}

	// Parse rule-sets
	for _, rsInst := range namedInstances(node.FindChildren("rule-set")) {
		// Parse from/to zones (bracket lists produce multiple keys)
		var fromZones, toZones []string
		for _, child := range rsInst.node.Children {
			if child.Name() == "from" {
				fromZones = append(fromZones, parseZoneList(child)...)
			}
			if child.Name() == "to" {
				toZones = append(toZones, parseZoneList(child)...)
			}
		}
		if len(fromZones) == 0 {
			fromZones = []string{""}
		}
		if len(toZones) == 0 {
			toZones = []string{""}
		}

		var rules []*NATRule
		for _, ruleInst := range namedInstances(rsInst.node.FindChildren("rule")) {
			rule := &NATRule{Name: ruleInst.name}

			matchNode := ruleInst.node.FindChild("match")
			if matchNode != nil {
				for _, m := range matchNode.Children {
					switch m.Name() {
					case "destination-address":
						// Support bracket lists: destination-address [ addr1 addr2 ... ]
						if len(m.Keys) >= 2 {
							rule.Match.DestinationAddresses = append(rule.Match.DestinationAddresses, m.Keys[1:]...)
						} else if len(m.Children) > 0 {
							for _, child := range m.Children {
								rule.Match.DestinationAddresses = append(rule.Match.DestinationAddresses, child.Name())
							}
						}
						if len(rule.Match.DestinationAddresses) > 0 {
							rule.Match.DestinationAddress = rule.Match.DestinationAddresses[0]
						} else {
							rule.Match.DestinationAddress = nodeVal(m)
						}
					case "destination-port":
						rule.Match.DestinationPorts = append(rule.Match.DestinationPorts, parseDNATPortList(m)...)
						if rule.Match.DestinationPort == 0 && len(rule.Match.DestinationPorts) > 0 {
							rule.Match.DestinationPort = rule.Match.DestinationPorts[0]
						}
					case "source-address":
						// Support bracket lists: source-address [ addr1 addr2 ... ]
						if len(m.Keys) >= 2 {
							rule.Match.SourceAddresses = append(rule.Match.SourceAddresses, m.Keys[1:]...)
						} else if len(m.Children) > 0 {
							for _, child := range m.Children {
								rule.Match.SourceAddresses = append(rule.Match.SourceAddresses, child.Name())
							}
						}
						if len(rule.Match.SourceAddresses) > 0 {
							rule.Match.SourceAddress = rule.Match.SourceAddresses[0]
						}
					case "source-address-name":
						rule.Match.SourceAddressName = nodeVal(m)
					case "protocol":
						rule.Match.Protocol = nodeVal(m)
					case "application":
						rule.Match.Application = nodeVal(m)
					}
				}
			}

			thenNode := ruleInst.node.FindChild("then")
			if thenNode != nil {
				for _, t := range thenNode.Children {
					if t.Name() == "destination-nat" {
						if len(t.Keys) >= 3 && t.Keys[1] == "pool" {
							rule.Then.Type = NATDestination
							rule.Then.PoolName = t.Keys[2]
						} else if poolNode := t.FindChild("pool"); poolNode != nil {
							rule.Then.Type = NATDestination
							rule.Then.PoolName = nodeVal(poolNode)
						}
					}
				}
			}

			rules = append(rules, rule)
		}

		// Expand Cartesian product of from-zones × to-zones
		for _, fz := range fromZones {
			for _, tz := range toZones {
				rs := &NATRuleSet{
					Name:     rsInst.name,
					FromZone: fz,
					ToZone:   tz,
					Rules:    rules,
				}
				sec.NAT.Destination.RuleSets = append(sec.NAT.Destination.RuleSets, rs)
			}
		}
	}
	return nil
}

// parseDNATPortList extracts destination ports from a destination-port node.
// Handles single port, multiple ports as children, and port ranges ("20000 to 30000").
// AST shapes handled:
//   - Hierarchical multi-port: destination-port { 80; 443; 20000 to 30000; }
//   - Single port leaf: destination-port 8080;
//   - Set syntax range: destination-port 20000 { to 30000; } (args=1 consumes low, "to N" is child)
func parseDNATPortList(m *Node) []int {
	var ports []int
	if len(m.Children) > 0 {
		// Check for set-syntax port range: Keys=["destination-port","20000"] + child "to 30000"
		if len(m.Keys) >= 2 {
			if low, err := strconv.Atoi(m.Keys[1]); err == nil {
				// Look for "to" child indicating a range
				toChild := m.FindChild("to")
				if toChild != nil {
					if high, err2 := strconv.Atoi(nodeVal(toChild)); err2 == nil && high >= low {
						for p := low; p <= high; p++ {
							ports = append(ports, p)
						}
						return ports
					}
				}
				// No range — just a port with non-range children (shouldn't happen, but be safe)
				ports = append(ports, low)
			}
		}
		// Multiple ports/ranges as children: destination-port { 80; 443; 20000 to 30000; }
		for i := 0; i < len(m.Children); i++ {
			child := m.Children[i]
			low, err := strconv.Atoi(child.Name())
			if err != nil {
				continue
			}
			// Hierarchical range: "20000 to 30000" → leaf Keys=["20000", "to", "30000"]
			if len(child.Keys) >= 3 && child.Keys[1] == "to" {
				if high, err2 := strconv.Atoi(child.Keys[2]); err2 == nil && high >= low {
					for p := low; p <= high; p++ {
						ports = append(ports, p)
					}
					continue
				}
			}
			// Sibling-node range: child[i]="20000", child[i+1]="to", child[i+2]="30000"
			if i+2 < len(m.Children) && m.Children[i+1].Name() == "to" {
				if high, err2 := strconv.Atoi(m.Children[i+2].Name()); err2 == nil && high >= low {
					for p := low; p <= high; p++ {
						ports = append(ports, p)
					}
					i += 2
					continue
				}
			}
			ports = append(ports, low)
		}
	} else if v := nodeVal(m); v != "" {
		// Single port: destination-port 8080;
		if n, err := strconv.Atoi(v); err == nil {
			ports = append(ports, n)
		}
	}
	return ports
}

func compileNATStatic(node *Node, sec *SecurityConfig) error {
	for _, rsInst := range namedInstances(node.FindChildren("rule-set")) {
		// Parse from zones (bracket lists produce multiple keys)
		var fromZones []string
		for _, child := range rsInst.node.Children {
			if child.Name() == "from" {
				fromZones = append(fromZones, parseZoneList(child)...)
			}
		}
		if len(fromZones) == 0 {
			fromZones = []string{""}
		}

		// Parse rules (shared across all zone expansions)
		var rules []*StaticNATRule
		for _, ruleInst := range namedInstances(rsInst.node.FindChildren("rule")) {
			rule := &StaticNATRule{Name: ruleInst.name}

			matchNode := ruleInst.node.FindChild("match")
			if matchNode != nil {
				for _, m := range matchNode.Children {
					switch m.Name() {
					case "destination-address":
						rule.Match = nodeVal(m)
					case "source-address":
						rule.SourceAddress = nodeVal(m)
					}
				}
			}

			thenNode := ruleInst.node.FindChild("then")
			if thenNode != nil {
				for _, t := range thenNode.Children {
					if t.Name() == "static-nat" {
						if len(t.Keys) >= 3 && t.Keys[1] == "prefix" {
							rule.Then = t.Keys[2]
						} else if pn := t.FindChild("prefix"); pn != nil {
							rule.Then = nodeVal(pn)
						} else if t.FindChild("inet") != nil || (len(t.Keys) >= 2 && t.Keys[1] == "inet") {
							// static-nat { inet; } — NAT64 translation
							rule.Then = "inet"
						}
					}
				}
			}

			rules = append(rules, rule)
		}

		// Expand for each from-zone
		for _, fz := range fromZones {
			rs := &StaticNATRuleSet{
				Name:     rsInst.name,
				FromZone: fz,
				Rules:    rules,
			}
			sec.NAT.Static = append(sec.NAT.Static, rs)
		}
	}
	return nil
}

// parseMSSValue extracts MSS value from either "node { mss VALUE; }" or "node VALUE;" syntax.
func parseMSSValue(node *Node) int {
	// Hierarchical: ipsec-vpn { mss 1360; } or gre-in { mss 1360; }
	mssChild := node.FindChild("mss")
	if mssChild != nil && len(mssChild.Keys) >= 2 {
		if v, err := strconv.Atoi(mssChild.Keys[1]); err == nil {
			return v
		}
	}
	// Flat: ipsec-vpn 1360; (set syntax)
	if len(node.Keys) >= 2 {
		if v, err := strconv.Atoi(node.Keys[1]); err == nil {
			return v
		}
	}
	return 0
}

func compileLog(node *Node, sec *SecurityConfig) error {
	if sec.Log.Streams == nil {
		sec.Log.Streams = make(map[string]*SyslogStream)
	}

	// Top-level log settings
	if modeNode := node.FindChild("mode"); modeNode != nil {
		sec.Log.Mode = nodeVal(modeNode)
	}
	if fmtNode := node.FindChild("format"); fmtNode != nil {
		sec.Log.Format = nodeVal(fmtNode)
	}
	if srcNode := node.FindChild("source-interface"); srcNode != nil {
		sec.Log.SourceInterface = nodeVal(srcNode)
	}

	for _, inst := range namedInstances(node.FindChildren("stream")) {
		stream := &SyslogStream{
			Name: inst.name,
			Port: 514, // default
		}
		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "host":
				// Flat: host 192.168.99.3;
				if v := nodeVal(prop); v != "" {
					stream.Host = v
				}
				// Nested: host { 192.168.99.3; port 9006; }
				for _, hc := range prop.Children {
					switch hc.Name() {
					case "port":
						if v := nodeVal(hc); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								stream.Port = n
							}
						}
					default:
						// IP address as a bare child node
						if stream.Host == "" && len(hc.Keys) >= 1 {
							stream.Host = hc.Keys[0]
						}
					}
				}
			case "port":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						stream.Port = n
					}
				}
			case "severity":
				stream.Severity = nodeVal(prop)
			case "facility":
				stream.Facility = nodeVal(prop)
			case "format":
				stream.Format = nodeVal(prop)
			case "category":
				stream.Category = nodeVal(prop)
			case "source-address":
				stream.SourceAddress = nodeVal(prop)
			}
		}
		if stream.Host != "" {
			sec.Log.Streams[stream.Name] = stream
		}
	}
	return nil
}

func compileFlow(node *Node, sec *SecurityConfig) error {
	tcpNode := node.FindChild("tcp-session")
	if tcpNode != nil {
		sec.Flow.TCPSession = &TCPSessionConfig{}
		for _, opt := range tcpNode.Children {
			if len(opt.Keys) < 2 {
				continue
			}
			val, err := strconv.Atoi(opt.Keys[1])
			if err != nil {
				continue
			}
			switch opt.Name() {
			case "established-timeout":
				sec.Flow.TCPSession.EstablishedTimeout = val
			case "initial-timeout":
				sec.Flow.TCPSession.InitialTimeout = val
			case "closing-timeout":
				sec.Flow.TCPSession.ClosingTimeout = val
			case "time-wait-timeout":
				sec.Flow.TCPSession.TimeWaitTimeout = val
			}
		}
	}

	udpNode := node.FindChild("udp-session")
	if udpNode != nil {
		for _, opt := range udpNode.Children {
			if opt.Name() == "timeout" && len(opt.Keys) >= 2 {
				if v, err := strconv.Atoi(opt.Keys[1]); err == nil {
					sec.Flow.UDPSessionTimeout = v
				}
			}
		}
	}

	icmpNode := node.FindChild("icmp-session")
	if icmpNode != nil {
		for _, opt := range icmpNode.Children {
			if opt.Name() == "timeout" && len(opt.Keys) >= 2 {
				if v, err := strconv.Atoi(opt.Keys[1]); err == nil {
					sec.Flow.ICMPSessionTimeout = v
				}
			}
		}
	}

	// TCP MSS clamping
	mssNode := node.FindChild("tcp-mss")
	if mssNode != nil {
		for _, opt := range mssNode.Children {
			switch opt.Name() {
			case "ipsec-vpn":
				if v := parseMSSValue(opt); v > 0 {
					sec.Flow.TCPMSSIPsecVPN = v
				}
			case "gre-in":
				if v := parseMSSValue(opt); v > 0 {
					sec.Flow.TCPMSSGreIn = v
				}
			case "gre-out":
				if v := parseMSSValue(opt); v > 0 {
					sec.Flow.TCPMSSGreOut = v
				}
			case "all-tcp":
				if v := parseMSSValue(opt); v > 0 {
					sec.Flow.TCPMSSIPsecVPN = v
					sec.Flow.TCPMSSGreIn = v
					sec.Flow.TCPMSSGreOut = v
				}
			}
		}
	}

	// allow-dns-reply
	if node.FindChild("allow-dns-reply") != nil {
		sec.Flow.AllowDNSReply = true
	}

	// allow-embedded-icmp
	if node.FindChild("allow-embedded-icmp") != nil {
		sec.Flow.AllowEmbeddedICMP = true
	}

	// gre-performance-acceleration
	if node.FindChild("gre-performance-acceleration") != nil {
		sec.Flow.GREPerformanceAcceleration = true
	}

	// power-mode-disable
	if node.FindChild("power-mode-disable") != nil {
		sec.Flow.PowerModeDisable = true
	}

	// traceoptions
	if toNode := node.FindChild("traceoptions"); toNode != nil {
		to := &FlowTraceoptions{}
		if fileNode := toNode.FindChild("file"); fileNode != nil {
			to.File = nodeVal(fileNode)
			for i := 2; i < len(fileNode.Keys)-1; i++ {
				switch fileNode.Keys[i] {
				case "size":
					if n, err := strconv.Atoi(fileNode.Keys[i+1]); err == nil {
						to.FileSize = n
					}
				case "files":
					if n, err := strconv.Atoi(fileNode.Keys[i+1]); err == nil {
						to.FileCount = n
					}
				}
			}
			// Also check children for hierarchical syntax
			if sNode := fileNode.FindChild("size"); sNode != nil {
				if v := nodeVal(sNode); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						to.FileSize = n
					}
				}
			}
			if fNode := fileNode.FindChild("files"); fNode != nil {
				if v := nodeVal(fNode); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						to.FileCount = n
					}
				}
			}
		}
		for _, flagNode := range toNode.FindChildren("flag") {
			if v := nodeVal(flagNode); v != "" {
				to.Flags = append(to.Flags, v)
			}
		}
		for _, pfInst := range namedInstances(toNode.FindChildren("packet-filter")) {
			pf := &TracePacketFilter{Name: pfInst.name}
			if spNode := pfInst.node.FindChild("source-prefix"); spNode != nil {
				pf.SourcePrefix = nodeVal(spNode)
			}
			if dpNode := pfInst.node.FindChild("destination-prefix"); dpNode != nil {
				pf.DestinationPrefix = nodeVal(dpNode)
			}
			to.PacketFilters = append(to.PacketFilters, pf)
		}
		sec.Flow.Traceoptions = to
	}

	return nil
}

func compileALG(node *Node, sec *SecurityConfig) error {
	if dnsNode := node.FindChild("dns"); dnsNode != nil {
		if dnsNode.FindChild("disable") != nil {
			sec.ALG.DNSDisable = true
		}
	}
	if ftpNode := node.FindChild("ftp"); ftpNode != nil {
		if ftpNode.FindChild("disable") != nil {
			sec.ALG.FTPDisable = true
		}
	}
	if sipNode := node.FindChild("sip"); sipNode != nil {
		if sipNode.FindChild("disable") != nil {
			sec.ALG.SIPDisable = true
		}
	}
	if tftpNode := node.FindChild("tftp"); tftpNode != nil {
		if tftpNode.FindChild("disable") != nil {
			sec.ALG.TFTPDisable = true
		}
	}
	return nil
}

func compileApplications(node *Node, apps *ApplicationsConfig) error {
	for _, inst := range namedInstances(node.FindChildren("application")) {
		appName := inst.name
		app := &Application{Name: appName}

		var terms []*Application
		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "protocol":
				app.Protocol = nodeVal(prop)
			case "destination-port":
				app.DestinationPort = nodeVal(prop)
			case "source-port":
				app.SourcePort = nodeVal(prop)
			case "inactivity-timeout":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						app.InactivityTimeout = n
					}
				}
			case "alg":
				app.ALG = nodeVal(prop)
			case "description":
				app.Description = nodeVal(prop)
			case "term":
				// Inline term: "term <name> [alg <a>] protocol <p> [source-port <sp>]
				//               [destination-port <dp>] [inactivity-timeout <t>];"
				if len(prop.Keys) < 2 {
					continue
				}
				// Hierarchical: all values in prop.Keys (inline statement)
				// Flat set: values split across prop.Keys and prop.Children
				allKeys := prop.Keys[1:]
				for _, c := range prop.Children {
					allKeys = append(allKeys, c.Keys...)
				}
				termApp := parseApplicationTerm(appName, allKeys)
				if termApp != nil {
					terms = append(terms, termApp)
				}
			}
		}

		if len(terms) > 0 {
			implicitSet := &ApplicationSet{Name: appName}
			for _, t := range terms {
				t.Description = app.Description
				apps.Applications[t.Name] = t
				implicitSet.Applications = append(implicitSet.Applications, t.Name)
			}
			apps.ApplicationSets[appName] = implicitSet
		} else {
			apps.Applications[appName] = app
		}
	}

	for _, inst := range namedInstances(node.FindChildren("application-set")) {
		as := &ApplicationSet{Name: inst.name}

		for _, member := range inst.node.Children {
			if member.Name() == "application" {
				v := nodeVal(member)
				if v != "" {
					as.Applications = append(as.Applications, v)
				}
			}
		}

		apps.ApplicationSets[as.Name] = as
	}

	return nil
}

// parseApplicationTerm parses an inline term like:
// "term-name [alg ssh] protocol tcp [source-port 22] [destination-port 22] [inactivity-timeout 86400]"
// and returns a named Application.
func parseApplicationTerm(parentName string, keys []string) *Application {
	if len(keys) == 0 {
		return nil
	}
	termName := keys[0]
	app := &Application{
		Name: parentName + "-" + termName,
	}
	for i := 1; i < len(keys); i++ {
		switch keys[i] {
		case "protocol":
			if i+1 < len(keys) {
				i++
				app.Protocol = keys[i]
			}
		case "destination-port":
			if i+1 < len(keys) {
				i++
				app.DestinationPort = keys[i]
			}
		case "source-port":
			if i+1 < len(keys) {
				i++
				app.SourcePort = keys[i]
			}
		case "inactivity-timeout":
			if i+1 < len(keys) {
				i++
				if v, err := strconv.Atoi(keys[i]); err == nil {
					app.InactivityTimeout = v
				}
			}
		case "alg":
			if i+1 < len(keys) {
				i++
				app.ALG = keys[i]
			}
		}
	}
	return app
}

// validatePortSpec checks that a port specification is valid.
// Valid formats: "80", "8080-8090", named ports like "http".
func validatePortSpec(spec string) error {
	if spec == "" {
		return nil
	}
	namedPorts := map[string]bool{
		"http": true, "https": true, "ssh": true, "telnet": true,
		"ftp": true, "ftp-data": true, "smtp": true, "dns": true,
		"pop3": true, "imap": true, "snmp": true, "ntp": true,
		"bgp": true, "ldap": true, "syslog": true,
	}
	if namedPorts[strings.ToLower(spec)] {
		return nil
	}
	if strings.Contains(spec, "-") {
		parts := strings.SplitN(spec, "-", 2)
		lo, err1 := strconv.Atoi(parts[0])
		hi, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil {
			return fmt.Errorf("invalid port range %q: non-numeric", spec)
		}
		if lo < 1 || lo > 65535 {
			return fmt.Errorf("invalid port %d: must be 1-65535", lo)
		}
		if hi < 1 || hi > 65535 {
			return fmt.Errorf("invalid port %d: must be 1-65535", hi)
		}
		if lo > hi {
			return fmt.Errorf("invalid port range %q: start > end", spec)
		}
		return nil
	}
	port, err := strconv.Atoi(spec)
	if err != nil {
		return fmt.Errorf("invalid port %q: not a number or known service", spec)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port %d: must be 1-65535", port)
	}
	return nil
}

// validateProtocol checks that a protocol specification is valid.
func validateProtocol(proto string) error {
	validProtos := map[string]bool{
		"tcp": true, "udp": true, "icmp": true, "icmp6": true,
		"ospf": true, "gre": true, "ipip": true, "ah": true, "esp": true,
	}
	if validProtos[strings.ToLower(proto)] {
		return nil
	}
	n, err := strconv.Atoi(proto)
	if err != nil {
		return fmt.Errorf("invalid protocol %q", proto)
	}
	if n < 0 || n > 255 {
		return fmt.Errorf("invalid protocol number %d: must be 0-255", n)
	}
	return nil
}

func compileRoutingOptions(node *Node, ro *RoutingOptionsConfig) error {
	// Parse autonomous-system
	if asNode := node.FindChild("autonomous-system"); asNode != nil {
		if v := nodeVal(asNode); v != "" {
			if n, err := strconv.ParseUint(v, 10, 32); err == nil {
				ro.AutonomousSystem = uint32(n)
			}
		}
	}

	// Parse forwarding-table { export <policy>; }
	if ftNode := node.FindChild("forwarding-table"); ftNode != nil {
		if expNode := ftNode.FindChild("export"); expNode != nil {
			ro.ForwardingTableExport = nodeVal(expNode)
		}
	}

	// Parse rib inet6.0 { static { route ... } }
	for _, ribNode := range node.FindChildren("rib") {
		ribName := nodeVal(ribNode)
		if ribName == "inet6.0" {
			if ribStatic := ribNode.FindChild("static"); ribStatic != nil {
				ro.Inet6StaticRoutes = compileStaticRoutes(ribStatic, ro.Inet6StaticRoutes)
			}
		}
	}

	staticNode := node.FindChild("static")
	if staticNode != nil {
		ro.StaticRoutes = compileStaticRoutes(staticNode, ro.StaticRoutes)
	}

	// Parse rib-groups
	if rgNode := node.FindChild("rib-groups"); rgNode != nil {
		if ro.RibGroups == nil {
			ro.RibGroups = make(map[string]*RibGroup)
		}
		for _, inst := range namedInstances(rgNode.FindChildren("")) {
			rg := &RibGroup{Name: inst.name}
			if irNode := inst.node.FindChild("import-rib"); irNode != nil {
				// import-rib [ rib1 rib2 ... ] or import-rib rib1;
				for i := 1; i < len(irNode.Keys); i++ {
					if irNode.Keys[i] == "[" || irNode.Keys[i] == "]" {
						continue
					}
					rg.ImportRibs = append(rg.ImportRibs, irNode.Keys[i])
				}
				for _, child := range irNode.Children {
					rg.ImportRibs = append(rg.ImportRibs, child.Name())
				}
			}
			ro.RibGroups[rg.Name] = rg
		}
		// Also handle direct children (non-named instances)
		for _, child := range rgNode.Children {
			name := child.Name()
			if _, exists := ro.RibGroups[name]; exists {
				continue
			}
			rg := &RibGroup{Name: name}
			if irNode := child.FindChild("import-rib"); irNode != nil {
				for i := 1; i < len(irNode.Keys); i++ {
					if irNode.Keys[i] == "[" || irNode.Keys[i] == "]" {
						continue
					}
					rg.ImportRibs = append(rg.ImportRibs, irNode.Keys[i])
				}
				for _, child := range irNode.Children {
					rg.ImportRibs = append(rg.ImportRibs, child.Name())
				}
			}
			ro.RibGroups[rg.Name] = rg
		}
	}

	// Parse generate routes (aggregate routes)
	if genNode := node.FindChild("generate"); genNode != nil {
		for _, routeNode := range genNode.FindChildren("route") {
			prefix := nodeVal(routeNode)
			if prefix == "" {
				continue
			}
			gr := &GenerateRoute{Prefix: prefix}
			if policyNode := routeNode.FindChild("policy"); policyNode != nil {
				gr.Policy = nodeVal(policyNode)
			}
			if routeNode.FindChild("discard") != nil {
				gr.Discard = true
			}
			// Also handle inline keys: "route X/Y discard" or "route X/Y policy Z"
			for i := 2; i < len(routeNode.Keys); i++ {
				switch routeNode.Keys[i] {
				case "discard":
					gr.Discard = true
				case "policy":
					if i+1 < len(routeNode.Keys) {
						gr.Policy = routeNode.Keys[i+1]
						i++
					}
				}
			}
			ro.GenerateRoutes = append(ro.GenerateRoutes, gr)
		}
	}

	// Parse global interface-routes { rib-group { inet X; inet6 Y; } }
	if irNode := node.FindChild("interface-routes"); irNode != nil {
		if rgNode := irNode.FindChild("rib-group"); rgNode != nil {
			for _, rgChild := range rgNode.Children {
				switch rgChild.Name() {
				case "inet":
					ro.InterfaceRoutesRibGroup = nodeVal(rgChild)
				case "inet6":
					ro.InterfaceRoutesRibGroupV6 = nodeVal(rgChild)
				}
			}
			// Also handle inline: "rib-group inet NAME" or "rib-group inet6 NAME"
			for i := 1; i < len(rgNode.Keys)-1; i++ {
				switch rgNode.Keys[i] {
				case "inet":
					ro.InterfaceRoutesRibGroup = rgNode.Keys[i+1]
				case "inet6":
					ro.InterfaceRoutesRibGroupV6 = rgNode.Keys[i+1]
				}
			}
		}
	}

	return nil
}

// compileStaticRoutes parses static route entries from a "static" node,
// appending to and returning the updated slice.
func compileStaticRoutes(staticNode *Node, existing []*StaticRoute) []*StaticRoute {
	// Track destination→index so flat "set" duplicates merge into one route.
	destIdx := make(map[string]int)
	for i, sr := range existing {
		destIdx[sr.Destination] = i
	}

	for _, routeInst := range namedInstances(staticNode.FindChildren("route")) {
		route := &StaticRoute{
			Destination: routeInst.name,
			Preference:  5, // default
		}

		// Handle inline keys: "route ::/0 next-hop 2001:db8::1" has all in Keys
		if len(routeInst.node.Children) == 0 && len(routeInst.node.Keys) > 2 {
			for i := 2; i < len(routeInst.node.Keys); i++ {
				switch routeInst.node.Keys[i] {
				case "next-hop":
					if i+1 < len(routeInst.node.Keys) {
						i++
						route.NextHops = append(route.NextHops, NextHopEntry{Address: routeInst.node.Keys[i]})
					}
				case "next-table":
					if i+1 < len(routeInst.node.Keys) {
						i++
						route.NextTable = parseNextTableInstance(routeInst.node.Keys[i])
					}
				case "discard":
					route.Discard = true
				case "preference":
					if i+1 < len(routeInst.node.Keys) {
						i++
						if n, err := strconv.Atoi(routeInst.node.Keys[i]); err == nil {
							route.Preference = n
						}
					}
				}
			}
		}

		// Handle children (hierarchical syntax)
		for _, prop := range routeInst.node.Children {
			switch prop.Name() {
			case "next-hop":
				nh := NextHopEntry{}
				nh.Address = nodeVal(prop)
				// Check children for interface (needed for IPv6 link-local next-hops)
				for _, child := range prop.Children {
					if child.Name() == "interface" {
						nh.Interface = nodeVal(child)
					}
				}
				route.NextHops = append(route.NextHops, nh)
			case "discard":
				route.Discard = true
			case "preference":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						route.Preference = n
					}
				}
			case "qualified-next-hop":
				nh := NextHopEntry{}
				nh.Address = nodeVal(prop)
				// Check for "interface <name>" among remaining keys
				for j := 2; j < len(prop.Keys)-1; j++ {
					if prop.Keys[j] == "interface" {
						nh.Interface = prop.Keys[j+1]
					}
				}
				// Also check children for flat set syntax
				if ifNode := prop.FindChild("interface"); ifNode != nil {
					nh.Interface = nodeVal(ifNode)
				}
				route.NextHops = append(route.NextHops, nh)
			case "next-table":
				if v := nodeVal(prop); v != "" {
					route.NextTable = parseNextTableInstance(v)
				}
			}
		}

		// Merge routes with the same destination (flat "set" syntax creates duplicates).
		if idx, exists := destIdx[route.Destination]; exists {
			existingRoute := existing[idx]
			existingRoute.NextHops = append(existingRoute.NextHops, route.NextHops...)
			if route.Discard {
				existingRoute.Discard = true
			}
			if route.Preference != 5 {
				existingRoute.Preference = route.Preference
			}
			if route.NextTable != "" {
				existingRoute.NextTable = route.NextTable
			}
		} else {
			destIdx[route.Destination] = len(existing)
			existing = append(existing, route)
		}
	}
	return existing
}

// parseNextTableInstance extracts the routing instance name from a Junos
// next-table value like "Comcast-GigabitPro.inet.0" → "Comcast-GigabitPro".
func parseNextTableInstance(table string) string {
	// Strip .inet.0 or .inet6.0 suffix to get the routing instance name
	if idx := strings.Index(table, ".inet"); idx > 0 {
		return table[:idx]
	}
	return table
}

func compileRouterAdvertisement(node *Node, proto *ProtocolsConfig) error {
	for _, inst := range namedInstances(node.FindChildren("interface")) {
		ra := &RAInterfaceConfig{
			Interface: inst.name,
		}

		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "managed-configuration":
				ra.ManagedConfig = true
			case "other-stateful-configuration":
				ra.OtherStateful = true
			case "default-lifetime":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						ra.DefaultLifetime = n
					}
				}
			case "max-advertisement-interval":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						ra.MaxAdvInterval = n
					}
				}
			case "min-advertisement-interval":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						ra.MinAdvInterval = n
					}
				}
			case "link-mtu":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						ra.LinkMTU = n
					}
				}
			case "dns-server-address":
				if len(prop.Keys) >= 2 {
					ra.DNSServers = append(ra.DNSServers, nodeVal(prop))
				}
			case "preference":
				ra.Preference = nodeVal(prop)
			case "nat64prefix", "nat-prefix":
				ra.NAT64Prefix = nodeVal(prop)
				// Check for lifetime sub-property
				if ltNode := prop.FindChild("lifetime"); ltNode != nil {
					if v := nodeVal(ltNode); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							ra.NAT64PrefixLife = n
						}
					}
				}
			case "prefix":
				pfxName := nodeVal(prop)
				if pfxName != "" {
					pfx := &RAPrefix{
						Prefix:     pfxName,
						OnLink:     true, // defaults
						Autonomous: true,
					}
					// For flat set, prefix children may be under the named child
					pfxChildren := prop.Children
					if len(prop.Keys) < 2 && len(prop.Children) > 0 {
						pfxChildren = prop.Children[0].Children
					}
					for _, child := range pfxChildren {
						switch child.Name() {
						case "on-link":
							pfx.OnLink = true
						case "autonomous":
							pfx.Autonomous = true
						case "no-onlink":
							pfx.OnLink = false
						case "no-autonomous":
							pfx.Autonomous = false
						case "valid-lifetime":
							if v := nodeVal(child); v != "" {
								if n, err := strconv.Atoi(v); err == nil {
									pfx.ValidLifetime = n
								}
							}
						case "preferred-lifetime":
							if v := nodeVal(child); v != "" {
								if n, err := strconv.Atoi(v); err == nil {
									pfx.PreferredLife = n
								}
							}
						}
					}
					ra.Prefixes = append(ra.Prefixes, pfx)
				}
			}
		}

		proto.RouterAdvertisement = append(proto.RouterAdvertisement, ra)
	}
	return nil
}

func compileProtocols(node *Node, proto *ProtocolsConfig) error {
	raNode := node.FindChild("router-advertisement")
	if raNode != nil {
		if err := compileRouterAdvertisement(raNode, proto); err != nil {
			return fmt.Errorf("router-advertisement: %w", err)
		}
	}

	lldpNode := node.FindChild("lldp")
	if lldpNode != nil {
		proto.LLDP = &LLDPConfig{}
		for _, child := range lldpNode.Children {
			switch child.Name() {
			case "interface":
				if v := nodeVal(child); v != "" {
					iface := LLDPInterface{Name: v}
					if child.FindChild("disable") != nil {
						iface.Disable = true
					}
					proto.LLDP.Interfaces = append(proto.LLDP.Interfaces, iface)
				}
			case "transmit-interval":
				if v := nodeVal(child); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						proto.LLDP.Interval = n
					}
				}
			case "hold-multiplier":
				if v := nodeVal(child); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						proto.LLDP.HoldMultiplier = n
					}
				}
			case "disable":
				proto.LLDP.Disable = true
			}
		}
	}

	ospfNode := node.FindChild("ospf")
	if ospfNode != nil {
		proto.OSPF = &OSPFConfig{}

		// Router ID, passive-default, and export policies at the ospf level
		for _, child := range ospfNode.Children {
			switch child.Name() {
			case "router-id":
				if len(child.Keys) >= 2 {
					proto.OSPF.RouterID = child.Keys[1]
				}
			case "reference-bandwidth":
				if v := nodeVal(child); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						proto.OSPF.ReferenceBandwidth = n
					}
				}
			case "passive":
				proto.OSPF.PassiveDefault = true
			case "export":
				if len(child.Keys) >= 2 {
					proto.OSPF.Export = append(proto.OSPF.Export, child.Keys[1])
				}
			}
		}

		for _, areaInst := range namedInstances(ospfNode.FindChildren("area")) {
			area := &OSPFArea{ID: areaInst.name}

			for _, ifInst := range namedInstances(areaInst.node.FindChildren("interface")) {
				iface := &OSPFInterface{Name: ifInst.name}
				for _, prop := range ifInst.node.Children {
					switch prop.Name() {
					case "passive":
						iface.Passive = true
					case "no-passive":
						iface.NoPassive = true
					case "interface-type":
						iface.NetworkType = nodeVal(prop)
					case "cost":
						if v := nodeVal(prop); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								iface.Cost = n
							}
						}
					case "authentication":
						for _, authChild := range prop.Children {
							switch authChild.Name() {
							case "md5":
								iface.AuthType = "md5"
								if v := nodeVal(authChild); v != "" {
									if n, err := strconv.Atoi(v); err == nil {
										iface.AuthKeyID = n
									}
								}
								for _, kc := range authChild.Children {
									if kc.Name() == "key" {
										iface.AuthKey = nodeVal(kc)
									}
								}
							case "simple-password":
								iface.AuthType = "simple"
								iface.AuthKey = nodeVal(authChild)
							}
						}
					case "bfd-liveness-detection":
						iface.BFD = true
					}
				}
				area.Interfaces = append(area.Interfaces, iface)
			}

			// Parse area-type (stub/nssa)
			if atNode := areaInst.node.FindChild("area-type"); atNode != nil {
				for _, atChild := range atNode.Children {
					switch atChild.Name() {
					case "stub":
						area.AreaType = "stub"
						if atChild.FindChild("no-summaries") != nil {
							area.NoSummary = true
						}
					case "nssa":
						area.AreaType = "nssa"
						if atChild.FindChild("no-summaries") != nil {
							area.NoSummary = true
						}
					}
				}
			}

			// Parse virtual-link entries
			for _, vlInst := range namedInstances(areaInst.node.FindChildren("virtual-link")) {
				vl := &OSPFVirtualLink{
					NeighborID:  vlInst.name,
					TransitArea: area.ID,
				}
				// Allow explicit transit-area override
				if taNode := vlInst.node.FindChild("transit-area"); taNode != nil {
					if v := nodeVal(taNode); v != "" {
						vl.TransitArea = v
					}
				}
				area.VirtualLinks = append(area.VirtualLinks, vl)
			}

			proto.OSPF.Areas = append(proto.OSPF.Areas, area)
		}
	}

	bgpNode := node.FindChild("bgp")
	if bgpNode != nil {
		proto.BGP = &BGPConfig{}

		for _, child := range bgpNode.Children {
			switch child.Name() {
			case "local-as":
				if len(child.Keys) >= 2 {
					if v, err := strconv.Atoi(child.Keys[1]); err == nil {
						proto.BGP.LocalAS = uint32(v)
					}
				}
			case "router-id":
				if len(child.Keys) >= 2 {
					proto.BGP.RouterID = child.Keys[1]
				}
			case "cluster-id":
				if len(child.Keys) >= 2 {
					proto.BGP.ClusterID = child.Keys[1]
				}
			case "graceful-restart":
				proto.BGP.GracefulRestart = true
			case "log-updown":
				proto.BGP.LogNeighborChanges = true
			case "multipath":
				proto.BGP.Multipath = 64 // default to 64 when enabled
				for _, mc := range child.Children {
					if mc.Name() == "multiple-as" {
						proto.BGP.MultipathMultipleAS = true
					}
				}
			case "damping":
				proto.BGP.Dampening = true
				for _, dc := range child.Children {
					if v := nodeVal(dc); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							switch dc.Name() {
							case "half-life":
								proto.BGP.DampeningHalfLife = n
							case "reuse":
								proto.BGP.DampeningReuse = n
							case "suppress":
								proto.BGP.DampeningSuppress = n
							case "max-suppress":
								proto.BGP.DampeningMaxSuppress = n
							}
						}
					}
				}
				// Handle inline keys (flat set syntax)
				for i := 1; i < len(child.Keys)-1; i += 2 {
					if n, err := strconv.Atoi(child.Keys[i+1]); err == nil {
						switch child.Keys[i] {
						case "half-life":
							proto.BGP.DampeningHalfLife = n
						case "reuse":
							proto.BGP.DampeningReuse = n
						case "suppress":
							proto.BGP.DampeningSuppress = n
						case "max-suppress":
							proto.BGP.DampeningMaxSuppress = n
						}
					}
				}
			case "export":
				if len(child.Keys) >= 2 {
					proto.BGP.Export = append(proto.BGP.Export, child.Keys[1])
				}
			}
		}

		for _, groupInst := range namedInstances(bgpNode.FindChildren("group")) {
			var peerAS uint32
			var groupDesc string
			var groupMultihop int
			var groupExport []string
			var familyInet, familyInet6 bool
			var groupPrefixLimitInet, groupPrefixLimitInet6 int
			var groupAuthKey string
			var groupBFD bool
			var groupBFDInterval int
			var groupDefaultOriginate bool
			var groupAllowASIn int
			var groupRemovePrivateAS bool
			for _, child := range groupInst.node.Children {
				switch child.Name() {
				case "peer-as":
					if v := nodeVal(child); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							peerAS = uint32(n)
						}
					}
				case "description":
					groupDesc = nodeVal(child)
				case "multihop":
					if v := nodeVal(child); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							groupMultihop = n
						}
					}
				case "export":
					if v := nodeVal(child); v != "" {
						groupExport = append(groupExport, v)
					} else if len(child.Keys) >= 2 {
						groupExport = append(groupExport, child.Keys[1:]...)
					}
				case "family":
					// Hierarchical: family { inet { unicast; } inet6 { unicast; } }
					// Flat (via schema): family node with children inet/inet6
					if len(child.Keys) >= 2 {
						switch child.Keys[1] {
						case "inet":
							familyInet = true
						case "inet6":
							familyInet6 = true
						}
					} else {
						for _, fc := range child.Children {
							switch fc.Name() {
							case "inet":
								familyInet = true
								groupPrefixLimitInet = parsePrefixLimit(fc)
							case "inet6":
								familyInet6 = true
								groupPrefixLimitInet6 = parsePrefixLimit(fc)
							}
						}
					}
				case "default-originate":
					groupDefaultOriginate = true
				case "loops":
					if v := nodeVal(child); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							groupAllowASIn = n
						}
					}
				case "remove-private":
					groupRemovePrivateAS = true
				case "authentication-key":
					groupAuthKey = nodeVal(child)
				case "bfd-liveness-detection":
					groupBFD = true
					for _, bc := range child.Children {
						if bc.Name() == "minimum-interval" {
							if v := nodeVal(bc); v != "" {
								if n, err := strconv.Atoi(v); err == nil {
									groupBFDInterval = n
								}
							}
						}
					}
				case "neighbor":
					nAddr := nodeVal(child)
					if nAddr != "" {
						neighbor := &BGPNeighbor{
							Address:          nAddr,
							PeerAS:           peerAS,
							Description:      groupDesc,
							MultihopTTL:      groupMultihop,
							Export:           groupExport,
							FamilyInet:       familyInet,
							FamilyInet6:      familyInet6,
							GroupName:        groupInst.name,
							AuthPassword:     groupAuthKey,
							BFD:              groupBFD,
							BFDInterval:      groupBFDInterval,
							DefaultOriginate: groupDefaultOriginate,
							AllowASIn:        groupAllowASIn,
							RemovePrivateAS:  groupRemovePrivateAS,
							PrefixLimitInet:  groupPrefixLimitInet,
							PrefixLimitInet6: groupPrefixLimitInet6,
						}
						// Per-neighbor overrides
						for _, prop := range child.Children {
							switch prop.Name() {
							case "description":
								neighbor.Description = nodeVal(prop)
							case "multihop":
								if v := nodeVal(prop); v != "" {
									if n, err := strconv.Atoi(v); err == nil {
										neighbor.MultihopTTL = n
									}
								}
							case "peer-as":
								if v := nodeVal(prop); v != "" {
									if n, err := strconv.Atoi(v); err == nil {
										neighbor.PeerAS = uint32(n)
									}
								}
							case "authentication-key":
								neighbor.AuthPassword = nodeVal(prop)
							case "route-reflector-client":
								neighbor.RouteReflectorClient = true
							case "default-originate":
								neighbor.DefaultOriginate = true
							case "bfd-liveness-detection":
								neighbor.BFD = true
								for _, bc := range prop.Children {
									if bc.Name() == "minimum-interval" {
										if v := nodeVal(bc); v != "" {
											if n, err := strconv.Atoi(v); err == nil {
												neighbor.BFDInterval = n
											}
										}
									}
								}
							case "loops":
								if v := nodeVal(prop); v != "" {
									if n, err := strconv.Atoi(v); err == nil {
										neighbor.AllowASIn = n
									}
								}
							case "remove-private":
								neighbor.RemovePrivateAS = true
							case "family":
								for _, fc := range prop.Children {
									switch fc.Name() {
									case "inet":
										neighbor.FamilyInet = true
										if pl := parsePrefixLimit(fc); pl > 0 {
											neighbor.PrefixLimitInet = pl
										}
									case "inet6":
										neighbor.FamilyInet6 = true
										if pl := parsePrefixLimit(fc); pl > 0 {
											neighbor.PrefixLimitInet6 = pl
										}
									}
								}
							}
						}
						proto.BGP.Neighbors = append(proto.BGP.Neighbors, neighbor)
					}
				}
			}
		}
	}


	ospf3Node := node.FindChild("ospf3")
	if ospf3Node != nil {
		proto.OSPFv3 = &OSPFv3Config{}

		for _, child := range ospf3Node.Children {
			switch child.Name() {
			case "router-id":
				if len(child.Keys) >= 2 {
					proto.OSPFv3.RouterID = child.Keys[1]
				}
			case "export":
				if len(child.Keys) >= 2 {
					proto.OSPFv3.Export = append(proto.OSPFv3.Export, child.Keys[1])
				}
			}
		}

		for _, areaInst := range namedInstances(ospf3Node.FindChildren("area")) {
			area := &OSPFv3Area{ID: areaInst.name}

			for _, ifInst := range namedInstances(areaInst.node.FindChildren("interface")) {
				iface := &OSPFv3Interface{Name: ifInst.name}
				for _, prop := range ifInst.node.Children {
					switch prop.Name() {
					case "passive":
						iface.Passive = true
					case "cost":
						if v := nodeVal(prop); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								iface.Cost = n
							}
						}
					}
				}
				area.Interfaces = append(area.Interfaces, iface)
			}

			proto.OSPFv3.Areas = append(proto.OSPFv3.Areas, area)
		}
	}

	ripNode := node.FindChild("rip")
	if ripNode != nil {
		proto.RIP = &RIPConfig{}
		for _, child := range ripNode.Children {
			switch child.Name() {
			case "group":
				for _, gc := range child.Children {
					switch gc.Name() {
					case "neighbor":
						if len(gc.Keys) >= 2 {
							proto.RIP.Interfaces = append(proto.RIP.Interfaces, gc.Keys[1])
						}
					case "export":
						if len(gc.Keys) >= 2 {
							proto.RIP.Redistribute = append(proto.RIP.Redistribute, gc.Keys[1])
						}
					}
				}
			case "neighbor":
				if len(child.Keys) >= 2 {
					proto.RIP.Interfaces = append(proto.RIP.Interfaces, child.Keys[1])
				}
			case "passive-interface":
				if len(child.Keys) >= 2 {
					proto.RIP.Passive = append(proto.RIP.Passive, child.Keys[1])
				}
			case "redistribute":
				if len(child.Keys) >= 2 {
					proto.RIP.Redistribute = append(proto.RIP.Redistribute, child.Keys[1])
				}
			case "authentication-key":
				if v := nodeVal(child); v != "" {
					proto.RIP.AuthKey = v
				}
			case "authentication-type":
				if v := nodeVal(child); v != "" {
					proto.RIP.AuthType = v
				}
			}
		}
	}

	isisNode := node.FindChild("isis")
	if isisNode != nil {
		proto.ISIS = &ISISConfig{Level: "level-2"}
		for _, child := range isisNode.Children {
			switch child.Name() {
			case "net":
				if len(child.Keys) >= 2 {
					proto.ISIS.NET = child.Keys[1]
				}
			case "level":
				if len(child.Keys) >= 2 {
					proto.ISIS.Level = child.Keys[1]
				}
			case "is-type":
				if len(child.Keys) >= 2 {
					proto.ISIS.Level = child.Keys[1]
				}
			case "export":
				if len(child.Keys) >= 2 {
					proto.ISIS.Export = append(proto.ISIS.Export, child.Keys[1])
				}
			case "authentication-key":
				if v := nodeVal(child); v != "" {
					proto.ISIS.AuthKey = v
				}
			case "authentication-type":
				if v := nodeVal(child); v != "" {
					proto.ISIS.AuthType = v
				}
			case "wide-metrics-only":
				proto.ISIS.WideMetricsOnly = true
			case "overload":
				proto.ISIS.Overload = true
			case "interface":
				if len(child.Keys) >= 2 {
					iface := &ISISInterface{Name: child.Keys[1]}
					for _, prop := range child.Children {
						switch prop.Name() {
						case "level":
							if len(prop.Keys) >= 2 {
								iface.Level = prop.Keys[1]
							}
						case "passive":
							iface.Passive = true
						case "metric":
							if len(prop.Keys) >= 2 {
								if v, err := strconv.Atoi(prop.Keys[1]); err == nil {
									iface.Metric = v
								}
							}
						case "authentication-key":
							iface.AuthKey = nodeVal(prop)
						case "authentication-type":
							iface.AuthType = nodeVal(prop)
						}
					}
					// Check keys for "level N" and "passive" shorthand
					for _, k := range child.Keys[2:] {
						switch k {
						case "passive":
							iface.Passive = true
						case "level":
							// next key is the level value, handled above
						}
					}
					proto.ISIS.Interfaces = append(proto.ISIS.Interfaces, iface)
				}
			}
		}
	}
	return nil
}

// namedInstances handles the dual AST shape for named config objects.
// Hierarchical: Node Keys: ["type", "name"], Children are properties.
// Flat set:     Node Keys: ["type"], Children are named instance nodes.
// Returns (name, propertyNode) pairs for each instance.
func namedInstances(nodes []*Node) []struct {
	name string
	node *Node
} {
	var result []struct {
		name string
		node *Node
	}
	for _, child := range nodes {
		if len(child.Keys) >= 2 {
			result = append(result, struct {
				name string
				node *Node
			}{child.Keys[1], child})
		} else {
			for _, sub := range child.Children {
				result = append(result, struct {
					name string
					node *Node
				}{sub.Name(), sub})
			}
		}
	}
	return result
}

// nodeVal returns the value for a property node, handling both AST shapes.
// Hierarchical: Keys: ["prop", "value"] → returns "value"
// Flat set:     Keys: ["prop"], Children: [Node{Keys:["value"]}] → returns "value"
// parsePrefixLimit extracts the maximum prefix count from a family inet/inet6 node.
// Walks: inet -> unicast -> prefix-limit -> maximum -> value
func parsePrefixLimit(famNode *Node) int {
	unicast := famNode.FindChild("unicast")
	if unicast == nil {
		return 0
	}
	pl := unicast.FindChild("prefix-limit")
	if pl == nil {
		return 0
	}
	mx := pl.FindChild("maximum")
	if mx == nil {
		return 0
	}
	if v := nodeVal(mx); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return 0
}

func nodeVal(n *Node) string {
	if len(n.Keys) >= 2 {
		return n.Keys[1]
	}
	if len(n.Children) > 0 {
		return n.Children[0].Name()
	}
	return ""
}

func compileIKE(node *Node, sec *SecurityConfig) error {
	if sec.IPsec.IKEProposals == nil {
		sec.IPsec.IKEProposals = make(map[string]*IKEProposal)
	}
	if sec.IPsec.IKEPolicies == nil {
		sec.IPsec.IKEPolicies = make(map[string]*IKEPolicy)
	}
	if sec.IPsec.Gateways == nil {
		sec.IPsec.Gateways = make(map[string]*IPsecGateway)
	}

	// IKE proposals (Phase 1 crypto)
	for _, inst := range namedInstances(node.FindChildren("proposal")) {
		prop := &IKEProposal{Name: inst.name}
		for _, p := range inst.node.Children {
			v := nodeVal(p)
			switch p.Name() {
			case "authentication-method":
				prop.AuthMethod = v
			case "encryption-algorithm":
				prop.EncryptionAlg = v
			case "authentication-algorithm":
				prop.AuthAlg = v
			case "dh-group":
				// Handle "group2" or "2" format
				g := strings.TrimPrefix(v, "group")
				if n, err := strconv.Atoi(g); err == nil {
					prop.DHGroup = n
				}
			case "lifetime-seconds":
				if n, err := strconv.Atoi(v); err == nil {
					prop.LifetimeSeconds = n
				}
			}
		}
		sec.IPsec.IKEProposals[prop.Name] = prop
	}

	// IKE policies (Phase 1 mode + PSK + proposal ref)
	for _, inst := range namedInstances(node.FindChildren("policy")) {
		pol := &IKEPolicy{Name: inst.name}
		for _, p := range inst.node.Children {
			v := nodeVal(p)
			switch p.Name() {
			case "mode":
				pol.Mode = v
			case "proposals":
				pol.Proposals = v
			case "pre-shared-key":
				// "pre-shared-key ascii-text VALUE" or children
				if len(p.Keys) >= 3 {
					pol.PSK = p.Keys[2]
				} else {
					for _, c := range p.Children {
						if c.Name() == "ascii-text" {
							pol.PSK = nodeVal(c)
						}
					}
				}
			}
		}
		sec.IPsec.IKEPolicies[pol.Name] = pol
	}

	// IKE gateways
	for _, inst := range namedInstances(node.FindChildren("gateway")) {
		gw := sec.IPsec.Gateways[inst.name]
		if gw == nil {
			gw = &IPsecGateway{Name: inst.name}
		}
		for _, p := range inst.node.Children {
			v := nodeVal(p)
			switch p.Name() {
			case "address":
				if v != "" {
					gw.Address = v
				}
			case "local-address":
				if v != "" {
					gw.LocalAddress = v
				}
			case "ike-policy":
				if v != "" {
					gw.IKEPolicy = v
				}
			case "external-interface":
				if v != "" {
					gw.ExternalIface = v
				}
			case "version":
				if v != "" {
					gw.Version = v
				}
			case "no-nat-traversal":
				gw.NoNATTraversal = true
				gw.NATTraversal = "disable"
			case "nat-traversal":
				if v != "" {
					gw.NATTraversal = v
				}
				if v == "disable" {
					gw.NoNATTraversal = true
				}
			case "dead-peer-detection":
				if v != "" {
					gw.DeadPeerDetect = v
				} else {
					gw.DeadPeerDetect = "always-send"
				}
			case "local-identity":
				if len(p.Keys) >= 3 {
					gw.LocalIDType = p.Keys[1]
					gw.LocalIDValue = p.Keys[2]
				} else if len(p.Children) > 0 {
					for _, c := range p.Children {
						gw.LocalIDType = c.Name()
						gw.LocalIDValue = nodeVal(c)
					}
				}
			case "remote-identity":
				if len(p.Keys) >= 3 {
					gw.RemoteIDType = p.Keys[1]
					gw.RemoteIDValue = p.Keys[2]
				} else if len(p.Children) > 0 {
					for _, c := range p.Children {
						gw.RemoteIDType = c.Name()
						gw.RemoteIDValue = nodeVal(c)
					}
				}
			case "dynamic":
				// "dynamic hostname FQDN" or children
				if len(p.Keys) >= 3 && p.Keys[1] == "hostname" {
					gw.DynamicHostname = p.Keys[2]
				} else {
					for _, c := range p.Children {
						if c.Name() == "hostname" && len(c.Keys) >= 2 {
							gw.DynamicHostname = c.Keys[1]
						}
					}
				}
			}
		}
		sec.IPsec.Gateways[gw.Name] = gw
	}

	return nil
}

func compileIPsec(node *Node, sec *SecurityConfig) error {
	if sec.IPsec.Proposals == nil {
		sec.IPsec.Proposals = make(map[string]*IPsecProposal)
	}
	if sec.IPsec.Policies == nil {
		sec.IPsec.Policies = make(map[string]*IPsecPolicyDef)
	}
	if sec.IPsec.VPNs == nil {
		sec.IPsec.VPNs = make(map[string]*IPsecVPN)
	}

	// IPsec proposals (Phase 2 crypto)
	for _, inst := range namedInstances(node.FindChildren("proposal")) {
		prop := &IPsecProposal{Name: inst.name}
		for _, p := range inst.node.Children {
			v := nodeVal(p)
			switch p.Name() {
			case "protocol":
				prop.Protocol = v
			case "encryption-algorithm":
				prop.EncryptionAlg = v
			case "authentication-algorithm":
				prop.AuthAlg = v
			case "dh-group":
				if n, err := strconv.Atoi(v); err == nil {
					prop.DHGroup = n
				}
			case "lifetime-seconds":
				if n, err := strconv.Atoi(v); err == nil {
					prop.LifetimeSeconds = n
				}
			}
		}
		sec.IPsec.Proposals[prop.Name] = prop
	}

	// IPsec policies (PFS + proposal reference)
	for _, inst := range namedInstances(node.FindChildren("policy")) {
		pol := &IPsecPolicyDef{Name: inst.name}
		for _, p := range inst.node.Children {
			v := nodeVal(p)
			switch p.Name() {
			case "proposals":
				pol.Proposals = v
			case "perfect-forward-secrecy":
				for _, c := range p.Children {
					if c.Name() == "keys" {
						g := strings.TrimPrefix(nodeVal(c), "group")
						if n, err := strconv.Atoi(g); err == nil {
							pol.PFSGroup = n
						}
					}
				}
			}
		}
		sec.IPsec.Policies[pol.Name] = pol
	}

	// Gateways (may appear under ipsec or ike)
	if sec.IPsec.Gateways == nil {
		sec.IPsec.Gateways = make(map[string]*IPsecGateway)
	}
	for _, inst := range namedInstances(node.FindChildren("gateway")) {
		gw := sec.IPsec.Gateways[inst.name]
		if gw == nil {
			gw = &IPsecGateway{Name: inst.name}
		}
		for _, p := range inst.node.Children {
			v := nodeVal(p)
			switch p.Name() {
			case "address":
				if v != "" {
					gw.Address = v
				}
			case "local-address":
				if v != "" {
					gw.LocalAddress = v
				}
			case "ike-policy":
				if v != "" {
					gw.IKEPolicy = v
				}
			case "external-interface":
				if v != "" {
					gw.ExternalIface = v
				}
			case "version":
				if v != "" {
					gw.Version = v
				}
			case "no-nat-traversal":
				gw.NoNATTraversal = true
				gw.NATTraversal = "disable"
			case "nat-traversal":
				if v != "" {
					gw.NATTraversal = v
				}
				if v == "disable" {
					gw.NoNATTraversal = true
				}
			case "dead-peer-detection":
				if v != "" {
					gw.DeadPeerDetect = v
				} else {
					gw.DeadPeerDetect = "always-send"
				}
			case "local-identity":
				if len(p.Keys) >= 3 {
					gw.LocalIDType = p.Keys[1]
					gw.LocalIDValue = p.Keys[2]
				} else if len(p.Children) > 0 {
					for _, c := range p.Children {
						gw.LocalIDType = c.Name()
						gw.LocalIDValue = nodeVal(c)
					}
				}
			case "remote-identity":
				if len(p.Keys) >= 3 {
					gw.RemoteIDType = p.Keys[1]
					gw.RemoteIDValue = p.Keys[2]
				} else if len(p.Children) > 0 {
					for _, c := range p.Children {
						gw.RemoteIDType = c.Name()
						gw.RemoteIDValue = nodeVal(c)
					}
				}
			case "dynamic":
				if len(p.Keys) >= 3 && p.Keys[1] == "hostname" {
					gw.DynamicHostname = p.Keys[2]
				} else {
					for _, c := range p.Children {
						if c.Name() == "hostname" {
							gw.DynamicHostname = nodeVal(c)
						}
					}
				}
			}
		}
		sec.IPsec.Gateways[gw.Name] = gw
	}

	// VPN tunnels
	for _, inst := range namedInstances(node.FindChildren("vpn")) {
		vpn := &IPsecVPN{Name: inst.name}
		for _, p := range inst.node.Children {
			v := nodeVal(p)
			switch p.Name() {
			case "bind-interface":
				vpn.BindInterface = v
			case "df-bit":
				vpn.DFBit = v
			case "establish-tunnels":
				vpn.EstablishTunnels = v
			case "ike":
				// Nested ike { gateway X; ipsec-policy Y; }
				for _, c := range p.Children {
					cv := nodeVal(c)
					switch c.Name() {
					case "gateway":
						vpn.Gateway = cv
					case "ipsec-policy":
						vpn.IPsecPolicy = cv
					}
				}
			case "gateway":
				vpn.Gateway = v
			case "ipsec-policy":
				vpn.IPsecPolicy = v
			case "local-identity":
				vpn.LocalID = v
			case "remote-identity":
				vpn.RemoteID = v
			case "pre-shared-key":
				vpn.PSK = v
			case "local-address":
				vpn.LocalAddr = v
			}
		}
		sec.IPsec.VPNs[vpn.Name] = vpn
	}

	return nil
}

func compileRoutingInstances(node *Node, cfg *Config) error {
	// Auto-assign VRF table IDs starting from 100
	tableID := 100

	for _, child := range node.Children {
		if child.IsLeaf || len(child.Keys) == 0 {
			continue
		}
		instanceName := child.Keys[0]
		ri := &RoutingInstanceConfig{
			Name:    instanceName,
			TableID: tableID,
		}
		tableID++

		for _, prop := range child.Children {
			switch prop.Name() {
			case "description":
				ri.Description = nodeVal(prop)
			case "instance-type":
				ri.InstanceType = nodeVal(prop)
			case "interface":
				if v := nodeVal(prop); v != "" {
					ri.Interfaces = append(ri.Interfaces, v)
				}
			case "routing-options":
				var ro RoutingOptionsConfig
				if err := compileRoutingOptions(prop, &ro); err != nil {
					return fmt.Errorf("instance %s routing-options: %w", instanceName, err)
				}
				ri.StaticRoutes = ro.StaticRoutes
				// Parse interface-routes rib-group
				if irNode := prop.FindChild("interface-routes"); irNode != nil {
					if rgNode := irNode.FindChild("rib-group"); rgNode != nil {
						for _, rgChild := range rgNode.Children {
							switch rgChild.Name() {
							case "inet":
								ri.InterfaceRoutesRibGroup = nodeVal(rgChild)
							case "inet6":
								ri.InterfaceRoutesRibGroupV6 = nodeVal(rgChild)
							}
						}
						// Also handle inline: "rib-group inet NAME"
						for i := 1; i < len(rgNode.Keys)-1; i++ {
							switch rgNode.Keys[i] {
							case "inet":
								ri.InterfaceRoutesRibGroup = rgNode.Keys[i+1]
							case "inet6":
								ri.InterfaceRoutesRibGroupV6 = rgNode.Keys[i+1]
							}
						}
					}
				}
			case "protocols":
				var proto ProtocolsConfig
				if err := compileProtocols(prop, &proto); err != nil {
					return fmt.Errorf("instance %s protocols: %w", instanceName, err)
				}
				ri.OSPF = proto.OSPF
				ri.OSPFv3 = proto.OSPFv3
				ri.BGP = proto.BGP
				ri.RIP = proto.RIP
				ri.ISIS = proto.ISIS
			}
		}

		cfg.RoutingInstances = append(cfg.RoutingInstances, ri)
	}
	return nil
}

func compileFirewall(node *Node, fw *FirewallConfig) error {
	if fw.FiltersInet == nil {
		fw.FiltersInet = make(map[string]*FirewallFilter)
	}
	if fw.FiltersInet6 == nil {
		fw.FiltersInet6 = make(map[string]*FirewallFilter)
	}

	for _, familyNode := range node.FindChildren("family") {
		var afNodes []*Node
		var afName string

		if len(familyNode.Keys) >= 2 {
			// Hierarchical: family inet { ... }
			afName = familyNode.Keys[1]
			afNodes = []*Node{familyNode}
		} else {
			// Set-command shape: family { inet { ... } inet6 { ... } }
			for _, child := range familyNode.Children {
				afNodes = append(afNodes, child)
			}
		}

		for _, afNode := range afNodes {
			af := afName
			if af == "" {
				af = afNode.Keys[0]
				if len(afNode.Keys) >= 2 {
					af = afNode.Keys[1]
				}
			}

			dest := fw.FiltersInet
			if af == "inet6" {
				dest = fw.FiltersInet6
			}

			for _, filterInst := range namedInstances(afNode.FindChildren("filter")) {
				filter := &FirewallFilter{Name: filterInst.name}

				for _, termInst := range namedInstances(filterInst.node.FindChildren("term")) {
					term := &FirewallFilterTerm{
						Name:     termInst.name,
						ICMPType: -1,
						ICMPCode: -1,
					}

					fromNode := termInst.node.FindChild("from")
					if fromNode != nil {
						compileFilterFrom(fromNode, term)
					}

					thenNode := termInst.node.FindChild("then")
					if thenNode != nil {
						compileFilterThen(thenNode, term)
					}

					filter.Terms = append(filter.Terms, term)
				}

				dest[filter.Name] = filter
			}
		}
	}
	return nil
}

func compileFilterFrom(node *Node, term *FirewallFilterTerm) {
	for _, child := range node.Children {
		switch child.Name() {
		case "dscp", "traffic-class":
			if v := nodeVal(child); v != "" {
				term.DSCP = v
			}
		case "protocol":
			if v := nodeVal(child); v != "" {
				term.Protocol = v
			}
		case "source-address":
			// Can be a leaf with value or a block with address entries
			if len(child.Keys) >= 2 {
				term.SourceAddresses = append(term.SourceAddresses, child.Keys[1])
			}
			for _, addrNode := range child.Children {
				if len(addrNode.Keys) >= 1 {
					term.SourceAddresses = append(term.SourceAddresses, addrNode.Keys[0])
				}
			}
		case "destination-address":
			if len(child.Keys) >= 2 {
				term.DestAddresses = append(term.DestAddresses, child.Keys[1])
			}
			for _, addrNode := range child.Children {
				if len(addrNode.Keys) >= 1 {
					term.DestAddresses = append(term.DestAddresses, addrNode.Keys[0])
				}
			}
		case "destination-port":
			if len(child.Keys) >= 2 {
				// Can be a single port or bracket list
				for _, k := range child.Keys[1:] {
					term.DestinationPorts = append(term.DestinationPorts, k)
				}
			}
			// Flat set syntax: port value as child node
			for _, portNode := range child.Children {
				if len(portNode.Keys) >= 1 {
					term.DestinationPorts = append(term.DestinationPorts, portNode.Keys[0])
				}
			}
		case "source-prefix-list":
			// Block form: source-prefix-list { mgmt-hosts except; }
			for _, plNode := range child.Children {
				ref := PrefixListRef{Name: plNode.Keys[0]}
				if len(plNode.Keys) >= 2 && plNode.Keys[1] == "except" {
					ref.Except = true
				}
				term.SourcePrefixLists = append(term.SourcePrefixLists, ref)
			}
		case "destination-prefix-list":
			for _, plNode := range child.Children {
				ref := PrefixListRef{Name: plNode.Keys[0]}
				if len(plNode.Keys) >= 2 && plNode.Keys[1] == "except" {
					ref.Except = true
				}
				term.DestPrefixLists = append(term.DestPrefixLists, ref)
			}
		case "source-port":
			if len(child.Keys) >= 2 {
				for _, k := range child.Keys[1:] {
					term.SourcePorts = append(term.SourcePorts, k)
				}
			}
			for _, portNode := range child.Children {
				if len(portNode.Keys) >= 1 {
					term.SourcePorts = append(term.SourcePorts, portNode.Keys[0])
				}
			}
		case "icmp-type":
			v := nodeVal(child)
			if v != "" {
				if n, err := strconv.Atoi(v); err == nil {
					term.ICMPType = n
				}
			}
		case "icmp-code":
			v := nodeVal(child)
			if v != "" {
				if n, err := strconv.Atoi(v); err == nil {
					term.ICMPCode = n
				}
			}
		case "tcp-flags":
			// Can be bracket list or single value: tcp-flags "syn ack" or [ syn ack ]
			if len(child.Keys) >= 2 {
				for _, k := range child.Keys[1:] {
					term.TCPFlags = append(term.TCPFlags, k)
				}
			}
			for _, flagNode := range child.Children {
				if len(flagNode.Keys) >= 1 {
					term.TCPFlags = append(term.TCPFlags, flagNode.Keys[0])
				}
			}
		case "is-fragment":
			term.IsFragment = true
		}
	}
}

func compileFilterThen(node *Node, term *FirewallFilterTerm) {
	// Handle leaf form: "then discard;" or "then accept;" produces
	// Keys=["then", "discard"] with IsLeaf=true and no children.
	if node.IsLeaf && len(node.Keys) >= 2 {
		for _, k := range node.Keys[1:] {
			switch k {
			case "accept":
				term.Action = "accept"
			case "reject":
				term.Action = "reject"
			case "discard":
				term.Action = "discard"
			case "log":
				term.Log = true
			case "syslog":
				term.Log = true
			}
		}
		return
	}

	for _, child := range node.Children {
		switch child.Name() {
		case "accept":
			term.Action = "accept"
		case "reject":
			term.Action = "reject"
		case "discard":
			term.Action = "discard"
		case "log":
			term.Log = true
		case "syslog":
			term.Log = true
		case "routing-instance":
			if len(child.Keys) >= 2 {
				term.RoutingInstance = child.Keys[1]
			}
		case "count":
			if len(child.Keys) >= 2 {
				term.Count = child.Keys[1]
			}
		case "forwarding-class":
			if len(child.Keys) >= 2 {
				term.ForwardingClass = child.Keys[1]
			}
		case "loss-priority":
			if len(child.Keys) >= 2 {
				term.LossPriority = child.Keys[1]
			}
		case "dscp", "traffic-class":
			term.DSCPRewrite = nodeVal(child)
		}
	}
}

func compileSystem(node *Node, sys *SystemConfig) error {
	for _, child := range node.Children {
		switch child.Name() {
		case "host-name":
			if len(child.Keys) >= 2 {
				sys.HostName = child.Keys[1]
			}
		case "dataplane-type":
			if len(child.Keys) >= 2 {
				sys.DataplaneType = child.Keys[1]
			}
		case "domain-name":
			if len(child.Keys) >= 2 {
				sys.DomainName = child.Keys[1]
			}
		case "domain-search":
			// Block: domain-search { dom1; dom2; } or leaf: domain-search dom
			if len(child.Keys) >= 2 {
				sys.DomainSearch = append(sys.DomainSearch, child.Keys[1])
			}
			for _, d := range child.Children {
				if len(d.Keys) >= 1 {
					sys.DomainSearch = append(sys.DomainSearch, d.Keys[0])
				}
			}
		case "time-zone":
			if len(child.Keys) >= 2 {
				sys.TimeZone = child.Keys[1]
			}
		case "no-redirects":
			sys.NoRedirects = true
		case "name-server":
			// Block: name-server { IP1; IP2; } or leaf: name-server IP
			if len(child.Keys) >= 2 {
				sys.NameServers = append(sys.NameServers, child.Keys[1])
			}
			for _, ns := range child.Children {
				if len(ns.Keys) >= 1 {
					sys.NameServers = append(sys.NameServers, ns.Keys[0])
				}
			}
		case "ntp":
			for _, ntpChild := range child.FindChildren("server") {
				if len(ntpChild.Keys) >= 2 {
					sys.NTPServers = append(sys.NTPServers, ntpChild.Keys[1])
				}
			}
			if thNode := child.FindChild("threshold"); thNode != nil {
				if v := nodeVal(thNode); v != "" {
					sys.NTPThreshold, _ = strconv.Atoi(v)
				}
				// Check for inline: threshold 400 action accept;
				for i := 2; i < len(thNode.Keys)-1; i++ {
					if thNode.Keys[i] == "action" {
						sys.NTPThresholdAction = thNode.Keys[i+1]
					}
				}
				// Check for hierarchical: action { accept; }
				if actNode := thNode.FindChild("action"); actNode != nil {
					sys.NTPThresholdAction = nodeVal(actNode)
				}
			}
		case "login":
			sys.Login = &LoginConfig{}
			for _, userInst := range namedInstances(child.FindChildren("user")) {
				user := &LoginUser{Name: userInst.name}
				for _, prop := range userInst.node.Children {
					switch prop.Name() {
					case "uid":
						if v := nodeVal(prop); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								user.UID = n
							}
						}
					case "class":
						user.Class = nodeVal(prop)
					case "authentication":
						for _, authChild := range prop.Children {
							switch authChild.Name() {
							case "ssh-ed25519", "ssh-rsa", "ssh-dsa":
								if v := nodeVal(authChild); v != "" {
									user.SSHKeys = append(user.SSHKeys, v)
								}
							}
						}
					}
				}
				sys.Login.Users = append(sys.Login.Users, user)
			}
		case "backup-router":
			if len(child.Keys) >= 2 {
				sys.BackupRouter = child.Keys[1]
			}
			// destination keyword: backup-router 192.168.50.1 destination 192.168.0.0/16
			for i, k := range child.Keys {
				if k == "destination" && i+1 < len(child.Keys) {
					sys.BackupRouterDst = child.Keys[i+1]
				}
			}
			// Also check children for hierarchical format
			if dstNode := child.FindChild("destination"); dstNode != nil && len(dstNode.Keys) >= 2 {
				sys.BackupRouterDst = dstNode.Keys[1]
			}
		case "root-authentication":
			sys.RootAuthentication = &RootAuthConfig{}
			for _, prop := range child.Children {
				switch prop.Name() {
				case "encrypted-password":
					sys.RootAuthentication.EncryptedPassword = nodeVal(prop)
				case "ssh-ed25519", "ssh-rsa", "ssh-dsa":
					if v := nodeVal(prop); v != "" {
						sys.RootAuthentication.SSHKeys = append(sys.RootAuthentication.SSHKeys, v)
					}
				}
			}
		case "archival":
			sys.Archival = &ArchivalConfig{
				ArchiveDir:  "/var/lib/bpfrx/archive",
				MaxArchives: 10,
			}
			if cfgNode := child.FindChild("configuration"); cfgNode != nil {
				if cfgNode.FindChild("transfer-on-commit") != nil {
					sys.Archival.TransferOnCommit = true
				}
				if tiNode := cfgNode.FindChild("transfer-interval"); tiNode != nil {
					if v := nodeVal(tiNode); v != "" {
						sys.Archival.TransferInterval, _ = strconv.Atoi(v)
					}
				}
				for _, asNode := range cfgNode.FindChildren("archive-sites") {
					if asNode.IsLeaf && len(asNode.Keys) >= 2 {
						// Flat set syntax: archive-sites <url>;
						sys.Archival.ArchiveSites = append(sys.Archival.ArchiveSites, asNode.Keys[1])
					}
					for _, site := range asNode.Children {
						if len(site.Keys) >= 1 {
							sys.Archival.ArchiveSites = append(sys.Archival.ArchiveSites, site.Keys[0])
						}
					}
				}
			}
		case "master-password":
			if prfNode := child.FindChild("pseudorandom-function"); prfNode != nil {
				sys.MasterPassword = nodeVal(prfNode)
			}
		case "license":
			if auNode := child.FindChild("autoupdate"); auNode != nil {
				if urlNode := auNode.FindChild("url"); urlNode != nil {
					sys.LicenseAutoUpdate = nodeVal(urlNode)
				}
			}
		case "processes":
			for _, proc := range child.Children {
				if proc.FindChild("disable") != nil || nodeVal(proc) == "disable" {
					sys.DisabledProcesses = append(sys.DisabledProcesses, proc.Name())
				}
			}
		case "internet-options":
			sys.InternetOptions = &InternetOptionsConfig{}
			if child.FindChild("no-ipv6-reject-zero-hop-limit") != nil {
				sys.InternetOptions.NoIPv6RejectZeroHopLimit = true
			}
		case "dataplane":
			sys.DPDKDataplane = &DPDKConfig{}
			if err := compileDPDKDataplane(child, sys.DPDKDataplane); err != nil {
				return err
			}
		case "syslog":
			sys.Syslog = &SystemSyslogConfig{}
			for _, slInst := range namedInstances(child.FindChildren("host")) {
				host := &SyslogHostConfig{Address: slInst.name}
				for _, prop := range slInst.node.Children {
					switch prop.Name() {
					case "allow-duplicates":
						host.AllowDuplicates = true
					default:
						if len(prop.Keys) >= 2 {
							host.Facilities = append(host.Facilities, SyslogFacility{
								Facility: prop.Keys[0],
								Severity: prop.Keys[1],
							})
						}
					}
				}
				sys.Syslog.Hosts = append(sys.Syslog.Hosts, host)
			}
			for _, fileInst := range namedInstances(child.FindChildren("file")) {
				file := &SyslogFileConfig{Name: fileInst.name}
				for _, prop := range fileInst.node.Children {
					if len(prop.Keys) >= 2 {
						file.Facility = prop.Keys[0]
						file.Severity = prop.Keys[1]
					}
				}
				sys.Syslog.Files = append(sys.Syslog.Files, file)
			}
			// Parse user destinations: user * { any emergency; }
			for _, userInst := range namedInstances(child.FindChildren("user")) {
				user := &SyslogUserConfig{User: userInst.name}
				for _, prop := range userInst.node.Children {
					if len(prop.Keys) >= 2 {
						user.Facility = prop.Keys[0]
						user.Severity = prop.Keys[1]
					}
				}
				sys.Syslog.Users = append(sys.Syslog.Users, user)
			}
		}
	}

	svcNode := node.FindChild("services")
	if svcNode != nil {
		dhcpNode := svcNode.FindChild("dhcp-local-server")
		if dhcpNode != nil {
			if err := compileDHCPLocalServer(dhcpNode, &sys.DHCPServer, false); err != nil {
				return err
			}
		}
		dhcp6Node := svcNode.FindChild("dhcpv6-local-server")
		if dhcp6Node != nil {
			if err := compileDHCPLocalServer(dhcp6Node, &sys.DHCPServer, true); err != nil {
				return err
			}
		}
		// SSH service
		if sshNode := svcNode.FindChild("ssh"); sshNode != nil {
			if sys.Services == nil {
				sys.Services = &SystemServicesConfig{}
			}
			sys.Services.SSH = &SSHServiceConfig{}
			if rl := sshNode.FindChild("root-login"); rl != nil && len(rl.Keys) >= 2 {
				sys.Services.SSH.RootLogin = rl.Keys[1]
			}
		}
		// DNS service
		if svcNode.FindChild("dns") != nil {
			if sys.Services == nil {
				sys.Services = &SystemServicesConfig{}
			}
			sys.Services.DNSEnabled = true
		}
		// Web management
		if wmNode := svcNode.FindChild("web-management"); wmNode != nil {
			if sys.Services == nil {
				sys.Services = &SystemServicesConfig{}
			}
			sys.Services.WebManagement = &WebManagementConfig{}
			if httpNode := wmNode.FindChild("http"); httpNode != nil {
				sys.Services.WebManagement.HTTP = true
				if ifNode := httpNode.FindChild("interface"); ifNode != nil {
					sys.Services.WebManagement.HTTPInterface = nodeVal(ifNode)
				}
			}
			if httpsNode := wmNode.FindChild("https"); httpsNode != nil {
				sys.Services.WebManagement.HTTPS = true
				if httpsNode.FindChild("system-generated-certificate") != nil {
					sys.Services.WebManagement.SystemGeneratedCert = true
				}
				if ifNode := httpsNode.FindChild("interface"); ifNode != nil {
					sys.Services.WebManagement.HTTPSInterface = nodeVal(ifNode)
				}
			}
			if authNode := wmNode.FindChild("api-auth"); authNode != nil {
				auth := &APIAuthConfig{}
				for _, inst := range namedInstances(authNode.FindChildren("user")) {
					if pwNode := inst.node.FindChild("password"); pwNode != nil {
						auth.Users = append(auth.Users, &APIAuthUser{
							Username: inst.name,
							Password: nodeVal(pwNode),
						})
					}
				}
				for _, ch := range authNode.FindChildren("api-key") {
					auth.APIKeys = append(auth.APIKeys, nodeVal(ch))
				}
				sys.Services.WebManagement.APIAuth = auth
			}
		}
	}

	snmpNode := node.FindChild("snmp")
	if snmpNode != nil {
		if err := compileSNMP(snmpNode, sys); err != nil {
			return err
		}
	}

	return nil
}

func compileDPDKDataplane(node *Node, cfg *DPDKConfig) error {
	for _, child := range node.Children {
		switch child.Name() {
		case "cores":
			if v := nodeVal(child); v != "" {
				cfg.Cores = v
			}
		case "memory":
			if v := nodeVal(child); v != "" {
				cfg.Memory, _ = strconv.Atoi(v)
			}
		case "socket-mem":
			if v := nodeVal(child); v != "" {
				cfg.SocketMem = v
			}
		case "rx-mode":
			// rx-mode can be a simple value ("polling") or a block ("adaptive { ... }")
			if v := nodeVal(child); v != "" {
				cfg.RXMode = v
			}
			if cfg.RXMode == "adaptive" {
				cfg.AdaptiveConfig = &DPDKAdaptiveConfig{}
				for _, ac := range child.Children {
					switch ac.Name() {
					case "idle-threshold":
						if v := nodeVal(ac); v != "" {
							cfg.AdaptiveConfig.IdleThreshold, _ = strconv.Atoi(v)
						}
					case "resume-threshold":
						if v := nodeVal(ac); v != "" {
							cfg.AdaptiveConfig.ResumeThreshold, _ = strconv.Atoi(v)
						}
					case "sleep-timeout":
						if v := nodeVal(ac); v != "" {
							cfg.AdaptiveConfig.SleepTimeout, _ = strconv.Atoi(v)
						}
					}
				}
			}
		case "ports":
			for _, portChild := range child.Children {
				port := DPDKPort{PCIAddress: portChild.Name()}
				for _, prop := range portChild.Children {
					switch prop.Name() {
					case "interface":
						port.Interface = nodeVal(prop)
					case "rx-mode":
						port.RXMode = nodeVal(prop)
					case "cores":
						port.Cores = nodeVal(prop)
					}
				}
				cfg.Ports = append(cfg.Ports, port)
			}
		}
	}
	return nil
}

func compileDHCPLocalServer(node *Node, dhcp *DHCPServerConfig, isV6 bool) error {
	lsc := &DHCPLocalServerConfig{
		Groups: make(map[string]*DHCPServerGroup),
	}
	if isV6 {
		dhcp.DHCPv6LocalServer = lsc
	} else {
		dhcp.DHCPLocalServer = lsc
	}

	for _, groupInst := range namedInstances(node.FindChildren("group")) {
		group := &DHCPServerGroup{Name: groupInst.name}

		for _, prop := range groupInst.node.Children {
			switch prop.Name() {
			case "interface":
				if v := nodeVal(prop); v != "" {
					group.Interfaces = append(group.Interfaces, v)
				}
			case "pool":
				poolName := nodeVal(prop)
				if poolName != "" {
					pool := &DHCPPool{Name: poolName}
					poolChildren := prop.Children
					if len(prop.Keys) < 2 && len(prop.Children) > 0 {
						poolChildren = prop.Children[0].Children
					}
					for _, pp := range poolChildren {
						switch pp.Name() {
						case "address-range":
							if len(pp.Keys) >= 5 && pp.Keys[1] == "low" && pp.Keys[3] == "high" {
								pool.RangeLow = pp.Keys[2]
								pool.RangeHigh = pp.Keys[4]
							}
						case "subnet":
							pool.Subnet = nodeVal(pp)
						case "router":
							pool.Router = nodeVal(pp)
						case "dns-server":
							if v := nodeVal(pp); v != "" {
								pool.DNSServers = append(pool.DNSServers, v)
							}
						case "lease-time":
							if v := nodeVal(pp); v != "" {
								if n, err := strconv.Atoi(v); err == nil {
									pool.LeaseTime = n
								}
							}
						case "domain-name":
							pool.Domain = nodeVal(pp)
						}
					}
					group.Pools = append(group.Pools, pool)
				}
			}
		}

		lsc.Groups[group.Name] = group
	}
	return nil
}

func compileDynamicAddress(node *Node, sec *SecurityConfig) error {
	if sec.DynamicAddress.FeedServers == nil {
		sec.DynamicAddress.FeedServers = make(map[string]*FeedServer)
	}

	for _, inst := range namedInstances(node.FindChildren("feed-server")) {
		fs := &FeedServer{Name: inst.name}

		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "url":
				fs.URL = nodeVal(prop)
			case "update-interval":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						fs.UpdateInterval = n
					}
				}
			case "hold-interval":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						fs.HoldInterval = n
					}
				}
			case "feed-name":
				fs.FeedName = nodeVal(prop)
			}
		}

		sec.DynamicAddress.FeedServers[fs.Name] = fs
	}
	return nil
}

func compileServices(node *Node, svc *ServicesConfig) error {
	if fmNode := node.FindChild("flow-monitoring"); fmNode != nil {
		if err := compileFlowMonitoring(fmNode, svc); err != nil {
			return err
		}
	}
	if rpmNode := node.FindChild("rpm"); rpmNode != nil {
		if err := compileRPM(rpmNode, svc); err != nil {
			return err
		}
	}
	if node.FindChild("application-identification") != nil {
		svc.ApplicationIdentification = true
	}
	return nil
}

func compileRPM(node *Node, svc *ServicesConfig) error {
	rpmCfg := &RPMConfig{Probes: make(map[string]*RPMProbe)}

	for _, probeInst := range namedInstances(node.FindChildren("probe")) {
		probe := &RPMProbe{
			Name:  probeInst.name,
			Tests: make(map[string]*RPMTest),
		}

		for _, testInst := range namedInstances(probeInst.node.FindChildren("test")) {
			test := &RPMTest{Name: testInst.name}

			for _, prop := range testInst.node.Children {
				switch prop.Name() {
				case "probe-type":
					test.ProbeType = nodeVal(prop)
				case "target":
					test.Target = nodeVal(prop)
				case "source-address":
					test.SourceAddress = nodeVal(prop)
				case "routing-instance":
					test.RoutingInstance = nodeVal(prop)
				case "probe-interval":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							test.ProbeInterval = n
						}
					}
				case "probe-count":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							test.ProbeCount = n
						}
					}
				case "test-interval":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							test.TestInterval = n
						}
					}
				case "thresholds":
					for _, th := range prop.Children {
						if th.Name() == "successive-loss" {
							if v := nodeVal(th); v != "" {
								if n, err := strconv.Atoi(v); err == nil {
									test.ThresholdSuccessive = n
								}
							}
						}
					}
				case "destination-port":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							test.DestPort = n
						}
					}
				}
			}

			probe.Tests[test.Name] = test
		}

		rpmCfg.Probes[probe.Name] = probe
	}

	svc.RPM = rpmCfg
	return nil
}

func compileFlowMonitoring(node *Node, svc *ServicesConfig) error {
	fm := &FlowMonitoringConfig{}

	if v9Node := node.FindChild("version9"); v9Node != nil {
		v9cfg := &NetFlowV9Config{
			Templates: make(map[string]*NetFlowV9Template),
		}
		for _, tmplInst := range namedInstances(v9Node.FindChildren("template")) {
			tmpl := &NetFlowV9Template{Name: tmplInst.name}
			for _, prop := range tmplInst.node.Children {
				switch prop.Name() {
				case "flow-active-timeout":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							tmpl.FlowActiveTimeout = n
						}
					}
				case "flow-inactive-timeout":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							tmpl.FlowInactiveTimeout = n
						}
					}
				case "template-refresh-rate":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							tmpl.TemplateRefreshRate = n
						}
					}
					if secNode := prop.FindChild("seconds"); secNode != nil {
						if v := nodeVal(secNode); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								tmpl.TemplateRefreshRate = n
							}
						}
					}
				}
			}
			v9cfg.Templates[tmpl.Name] = tmpl
		}
		fm.Version9 = v9cfg
	}

	if ipfixNode := node.FindChild("version-ipfix"); ipfixNode != nil {
		ipfixCfg := &NetFlowIPFIXConfig{
			Templates: make(map[string]*NetFlowIPFIXTemplate),
		}
		for _, tmplInst := range namedInstances(ipfixNode.FindChildren("template")) {
			tmpl := &NetFlowIPFIXTemplate{Name: tmplInst.name}
			for _, prop := range tmplInst.node.Children {
				switch prop.Name() {
				case "flow-active-timeout":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							tmpl.FlowActiveTimeout = n
						}
					}
				case "flow-inactive-timeout":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							tmpl.FlowInactiveTimeout = n
						}
					}
				case "template-refresh-rate":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							tmpl.TemplateRefreshRate = n
						}
					}
					if secNode := prop.FindChild("seconds"); secNode != nil {
						if v := nodeVal(secNode); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								tmpl.TemplateRefreshRate = n
							}
						}
					}
				case "ipv4-template", "ipv6-template":
					for _, child := range prop.Children {
						if child.Name() == "export-extension" {
							if v := nodeVal(child); v != "" {
								tmpl.ExportExtensions = append(tmpl.ExportExtensions, v)
							}
						}
					}
				}
			}
			ipfixCfg.Templates[tmpl.Name] = tmpl
		}
		fm.VersionIPFIX = ipfixCfg
	}

	svc.FlowMonitoring = fm
	return nil
}

func compileForwardingOptions(node *Node, fo *ForwardingOptionsConfig) error {
	sampNode := node.FindChild("sampling")
	if sampNode != nil {
		if err := compileSampling(sampNode, fo); err != nil {
			return err
		}
	}

	relayNode := node.FindChild("dhcp-relay")
	if relayNode != nil {
		if err := compileDHCPRelay(relayNode, fo); err != nil {
			return err
		}
	}

	// Parse family { inet6 { mode <flow-based|packet-based> } }
	if famNode := node.FindChild("family"); famNode != nil {
		if inet6Node := famNode.FindChild("inet6"); inet6Node != nil {
			if modeNode := inet6Node.FindChild("mode"); modeNode != nil {
				fo.FamilyInet6Mode = nodeVal(modeNode)
			}
		}
	}

	if pmNode := node.FindChild("port-mirroring"); pmNode != nil {
		if err := compilePortMirroring(pmNode, fo); err != nil {
			return err
		}
	}

	return nil
}

func compilePortMirroring(node *Node, fo *ForwardingOptionsConfig) error {
	pm := &PortMirroringConfig{
		Instances: make(map[string]*PortMirrorInstance),
	}

	for _, inst := range namedInstances(node.FindChildren("instance")) {
		mi := &PortMirrorInstance{Name: inst.name}

		if inputNode := inst.node.FindChild("input"); inputNode != nil {
			if rateNode := inputNode.FindChild("rate"); rateNode != nil {
				if v := nodeVal(rateNode); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						mi.InputRate = n
					}
				}
			}
			if ingressNode := inputNode.FindChild("ingress"); ingressNode != nil {
				for _, child := range ingressNode.Children {
					if child.Name() == "interface" {
						if v := nodeVal(child); v != "" {
							mi.Input = append(mi.Input, v)
						}
					}
				}
			}
		}

		if outputNode := inst.node.FindChild("output"); outputNode != nil {
			if ifNode := outputNode.FindChild("interface"); ifNode != nil {
				mi.Output = nodeVal(ifNode)
			}
		}

		pm.Instances[mi.Name] = mi
	}

	fo.PortMirroring = pm
	return nil
}

func compileSampling(node *Node, fo *ForwardingOptionsConfig) error {
	sc := &SamplingConfig{
		Instances: make(map[string]*SamplingInstance),
	}

	for _, sampInst := range namedInstances(node.FindChildren("instance")) {
		inst := &SamplingInstance{Name: sampInst.name}

		inputNode := sampInst.node.FindChild("input")
		if inputNode != nil {
			for _, prop := range inputNode.Children {
				if prop.Name() == "rate" {
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							inst.InputRate = n
						}
					}
				}
			}
		}

		for _, familyNode := range sampInst.node.FindChildren("family") {
			var afNodes []*Node
			if len(familyNode.Keys) >= 2 {
				afNodes = append(afNodes, familyNode)
			} else {
				afNodes = append(afNodes, familyNode.Children...)
			}
			for _, afNode := range afNodes {
				afName := afNode.Keys[0]
				if len(afNode.Keys) >= 2 {
					afName = afNode.Keys[1]
				}

				sf := compileSamplingFamily(afNode)
				switch afName {
				case "inet":
					inst.FamilyInet = sf
				case "inet6":
					inst.FamilyInet6 = sf
				}
			}
		}

		sc.Instances[inst.Name] = inst
	}

	fo.Sampling = sc
	return nil
}

func compileSamplingFamily(node *Node) *SamplingFamily {
	sf := &SamplingFamily{}

	outputNode := node.FindChild("output")
	if outputNode == nil {
		return sf
	}

	for _, child := range outputNode.Children {
		switch child.Name() {
		case "flow-server":
			fsAddr := nodeVal(child)
			if fsAddr != "" {
				fs := &FlowServer{Address: fsAddr}
				fsChildren := child.Children
				if len(child.Keys) < 2 && len(child.Children) > 0 {
					fsChildren = child.Children[0].Children
				}
				for _, prop := range fsChildren {
					switch prop.Name() {
					case "port":
						if v := nodeVal(prop); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								fs.Port = n
							}
						}
					case "version9-template":
						fs.Version9Template = nodeVal(prop)
					case "version9":
						// Hierarchical: version9 { template { <name>; } }
						if tmplNode := prop.FindChild("template"); tmplNode != nil {
							// Template name is either nodeVal or first child's name
							if v := nodeVal(tmplNode); v != "" {
								fs.Version9Template = v
							} else if len(tmplNode.Children) > 0 {
								fs.Version9Template = tmplNode.Children[0].Name()
							}
						}
					case "source-address":
						sf.SourceAddress = nodeVal(prop)
					}
				}
				sf.FlowServers = append(sf.FlowServers, fs)
			}
		case "inline-jflow":
			sf.InlineJflow = true
			if saNode := child.FindChild("source-address"); saNode != nil {
				sf.InlineJflowSourceAddress = nodeVal(saNode)
			}
			// Also handle inline keys: "inline-jflow source-address X"
			for i := 1; i < len(child.Keys)-1; i++ {
				if child.Keys[i] == "source-address" {
					sf.InlineJflowSourceAddress = child.Keys[i+1]
				}
			}
		}
	}

	return sf
}

func compileDHCPRelay(node *Node, fo *ForwardingOptionsConfig) error {
	relay := &DHCPRelayConfig{
		ServerGroups: make(map[string]*DHCPRelayServerGroup),
		Groups:       make(map[string]*DHCPRelayGroup),
	}

	for _, sgInst := range namedInstances(node.FindChildren("server-group")) {
		sg := &DHCPRelayServerGroup{Name: sgInst.name}
		for _, child := range sgInst.node.Children {
			if len(child.Keys) >= 1 {
				sg.Servers = append(sg.Servers, child.Keys[0])
			}
		}
		relay.ServerGroups[sg.Name] = sg
	}

	for _, gInst := range namedInstances(node.FindChildren("group")) {
		g := &DHCPRelayGroup{Name: gInst.name}
		for _, prop := range gInst.node.Children {
			switch prop.Name() {
			case "interface":
				if v := nodeVal(prop); v != "" {
					g.Interfaces = append(g.Interfaces, v)
				}
			case "active-server-group":
				g.ActiveServerGroup = nodeVal(prop)
			}
		}
		relay.Groups[g.Name] = g
	}

	fo.DHCPRelay = relay
	return nil
}

func compileSNMP(node *Node, sys *SystemConfig) error {
	snmp := &SNMPConfig{
		Communities: make(map[string]*SNMPCommunity),
		TrapGroups:  make(map[string]*SNMPTrapGroup),
		V3Users:     make(map[string]*SNMPv3User),
	}

	for _, child := range node.Children {
		switch child.Name() {
		case "location":
			snmp.Location = nodeVal(child)
		case "contact":
			snmp.Contact = nodeVal(child)
		case "description":
			snmp.Description = nodeVal(child)
		case "community":
			commName := nodeVal(child)
			if commName != "" {
				comm := &SNMPCommunity{Name: commName}
				commChildren := child.Children
				if len(child.Keys) < 2 && len(child.Children) > 0 {
					commChildren = child.Children[0].Children
				}
				for _, prop := range commChildren {
					if prop.Name() == "authorization" {
						comm.Authorization = nodeVal(prop)
					}
				}
				// Flat form: community public authorization read-only
				for i := 2; i < len(child.Keys)-1; i++ {
					if child.Keys[i] == "authorization" {
						comm.Authorization = child.Keys[i+1]
					}
				}
				if comm.Authorization == "" {
					comm.Authorization = "read-only"
				}
				snmp.Communities[comm.Name] = comm
			}
		case "trap-group":
			tgName := nodeVal(child)
			if tgName != "" {
				tg := &SNMPTrapGroup{Name: tgName}
				tgChildren := child.Children
				if len(child.Keys) < 2 && len(child.Children) > 0 {
					tgChildren = child.Children[0].Children
				}
				for _, prop := range tgChildren {
					if prop.Name() == "targets" {
						if v := nodeVal(prop); v != "" {
							tg.Targets = append(tg.Targets, v)
						}
					}
				}
				snmp.TrapGroups[tg.Name] = tg
			}
		case "v3":
			compileSNMPv3(child, snmp)
		}
	}

	sys.SNMP = snmp
	return nil
}

// compileSNMPv3 parses the v3 { usm { local-engine { user <name> { ... } } } } hierarchy.
func compileSNMPv3(node *Node, snmp *SNMPConfig) {
	// Flat form: Keys = ["v3", "usm", "local-engine", "user", "<name>", "authentication-sha", "authentication-password", "<pass>"]
	// Index:       0      1         2              3       4                5                         6                       7
	if len(node.Keys) >= 8 && node.Keys[1] == "usm" && node.Keys[2] == "local-engine" && node.Keys[3] == "user" {
		userName := node.Keys[4]
		user := snmp.V3Users[userName]
		if user == nil {
			user = &SNMPv3User{Name: userName}
		}
		parseSNMPv3UserKeys(node.Keys[5:], user)
		snmp.V3Users[userName] = user
		return
	}

	// Hierarchical form: v3 -> usm -> local-engine -> user <name> { ... }
	usmNode := node.FindChild("usm")
	if usmNode == nil {
		return
	}
	engineNode := usmNode.FindChild("local-engine")
	if engineNode == nil {
		return
	}
	for _, child := range engineNode.Children {
		if child.Name() != "user" {
			continue
		}
		userName := nodeVal(child)
		if userName == "" {
			continue
		}
		user := snmp.V3Users[userName]
		if user == nil {
			user = &SNMPv3User{Name: userName}
		}
		userChildren := child.Children
		if len(child.Keys) < 2 && len(child.Children) > 0 {
			userChildren = child.Children[0].Children
		}
		for _, prop := range userChildren {
			switch prop.Name() {
			case "authentication-md5":
				user.AuthProtocol = "md5"
				if pw := prop.FindChild("authentication-password"); pw != nil {
					user.AuthPassword = nodeVal(pw)
				}
			case "authentication-sha":
				user.AuthProtocol = "sha"
				if pw := prop.FindChild("authentication-password"); pw != nil {
					user.AuthPassword = nodeVal(pw)
				}
			case "authentication-sha256":
				user.AuthProtocol = "sha256"
				if pw := prop.FindChild("authentication-password"); pw != nil {
					user.AuthPassword = nodeVal(pw)
				}
			case "privacy-des":
				user.PrivProtocol = "des"
				if pw := prop.FindChild("privacy-password"); pw != nil {
					user.PrivPassword = nodeVal(pw)
				}
			case "privacy-aes128":
				user.PrivProtocol = "aes128"
				if pw := prop.FindChild("privacy-password"); pw != nil {
					user.PrivPassword = nodeVal(pw)
				}
			}
		}
		snmp.V3Users[userName] = user
	}
}

// parseSNMPv3UserKeys parses flat-form keys after the user name.
// Keys like: ["authentication-sha256", "authentication-password", "adminpass"]
func parseSNMPv3UserKeys(keys []string, user *SNMPv3User) {
	if len(keys) == 0 {
		return
	}
	switch keys[0] {
	case "authentication-md5":
		user.AuthProtocol = "md5"
		if len(keys) >= 3 && keys[1] == "authentication-password" {
			user.AuthPassword = keys[2]
		}
	case "authentication-sha":
		user.AuthProtocol = "sha"
		if len(keys) >= 3 && keys[1] == "authentication-password" {
			user.AuthPassword = keys[2]
		}
	case "authentication-sha256":
		user.AuthProtocol = "sha256"
		if len(keys) >= 3 && keys[1] == "authentication-password" {
			user.AuthPassword = keys[2]
		}
	case "privacy-des":
		user.PrivProtocol = "des"
		if len(keys) >= 3 && keys[1] == "privacy-password" {
			user.PrivPassword = keys[2]
		}
	case "privacy-aes128":
		user.PrivProtocol = "aes128"
		if len(keys) >= 3 && keys[1] == "privacy-password" {
			user.PrivPassword = keys[2]
		}
	}
}

func compileSchedulers(node *Node, cfg *Config) error {
	if cfg.Schedulers == nil {
		cfg.Schedulers = make(map[string]*SchedulerConfig)
	}

	for _, inst := range namedInstances(node.FindChildren("scheduler")) {
		sched := &SchedulerConfig{Name: inst.name}

		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "start-time":
				sched.StartTime = nodeVal(prop)
			case "stop-time":
				sched.StopTime = nodeVal(prop)
			case "start-date":
				sched.StartDate = nodeVal(prop)
			case "stop-date":
				sched.StopDate = nodeVal(prop)
			case "daily":
				sched.Daily = true
			}
		}

		cfg.Schedulers[inst.name] = sched
	}
	return nil
}

func compilePolicyOptions(node *Node, po *PolicyOptionsConfig) error {
	if po.PrefixLists == nil {
		po.PrefixLists = make(map[string]*PrefixList)
	}
	if po.Communities == nil {
		po.Communities = make(map[string]*CommunityDef)
	}
	if po.PolicyStatements == nil {
		po.PolicyStatements = make(map[string]*PolicyStatement)
	}

	// Parse prefix-lists
	for _, inst := range namedInstances(node.FindChildren("prefix-list")) {
		pl := &PrefixList{Name: inst.name}
		for _, entry := range inst.node.Children {
			if len(entry.Keys) > 0 {
				pl.Prefixes = append(pl.Prefixes, entry.Keys[0])
			}
		}
		po.PrefixLists[pl.Name] = pl
	}

	// Parse community definitions
	for _, inst := range namedInstances(node.FindChildren("community")) {
		cd := po.Communities[inst.name]
		if cd == nil {
			cd = &CommunityDef{Name: inst.name}
			po.Communities[inst.name] = cd
		}
		for _, entry := range inst.node.Children {
			if entry.Name() == "members" {
				if v := nodeVal(entry); v != "" {
					cd.Members = append(cd.Members, v)
				}
			}
		}
		// Handle flat set syntax: keys like ["members", "65000:100"]
		if len(inst.node.Keys) > 1 && inst.node.Keys[0] == "members" {
			cd.Members = append(cd.Members, inst.node.Keys[1])
		}
	}

	// Parse AS-path definitions
	if po.ASPaths == nil {
		po.ASPaths = make(map[string]*ASPathDef)
	}
	for _, child := range node.FindChildren("as-path") {
		if len(child.Keys) >= 3 {
			// Hierarchical: Keys=["as-path", "NAME", "REGEX"]
			po.ASPaths[child.Keys[1]] = &ASPathDef{
				Name:  child.Keys[1],
				Regex: child.Keys[2],
			}
		} else if len(child.Keys) >= 2 {
			// Flat set syntax may produce: Keys=["as-path","NAME"] with children
			name := child.Keys[1]
			ap := &ASPathDef{Name: name}
			// Look for path child (regex value)
			for _, entry := range child.Children {
				if len(entry.Keys) > 0 {
					ap.Regex = entry.Keys[0]
				}
			}
			po.ASPaths[name] = ap
		}
	}

	// Parse policy-statements
	for _, inst := range namedInstances(node.FindChildren("policy-statement")) {
		ps := &PolicyStatement{Name: inst.name}
		termsByName := make(map[string]*PolicyTerm)

		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "term":
				if len(prop.Keys) < 2 {
					continue
				}
				termName := prop.Keys[1]

				// Find or create term (flat set syntax may create multiple
				// nodes for the same term name)
				term, exists := termsByName[termName]
				if !exists {
					term = &PolicyTerm{Name: termName}
					termsByName[termName] = term
					ps.Terms = append(ps.Terms, term)
				}

				// Handle both hierarchical children and flat inline keys.
				// Flat: Keys=["term","t1","from","protocol","direct"] with no children
				// Hierarchical: Keys=["term","t1"] with from/then children
				if len(prop.Children) > 0 {
					// Hierarchical form
					parsePolicyTermChildren(term, prop.Children)
				} else if len(prop.Keys) > 2 {
					// Flat form: remaining keys after term name are key-value pairs
					parsePolicyTermInlineKeys(term, prop.Keys[2:])
				}
			case "then":
				// Default action at the policy level
				for _, ac := range prop.Children {
					switch ac.Name() {
					case "accept":
						ps.DefaultAction = "accept"
					case "reject":
						ps.DefaultAction = "reject"
					}
				}
				if len(prop.Keys) >= 2 {
					ps.DefaultAction = prop.Keys[1]
				}
			}
		}

		po.PolicyStatements[ps.Name] = ps
	}

	return nil
}

// parsePolicyTermChildren handles hierarchical form of policy term
// where "from" and "then" are child nodes.
func parsePolicyTermChildren(term *PolicyTerm, children []*Node) {
	for _, tc := range children {
		switch tc.Name() {
		case "from":
			for _, fc := range tc.Children {
				switch fc.Name() {
				case "protocol":
					if len(fc.Keys) >= 2 {
						term.FromProtocol = fc.Keys[1]
					}
				case "prefix-list":
					if v := nodeVal(fc); v != "" {
						term.PrefixList = v
					}
				case "route-filter":
					if len(fc.Keys) >= 3 {
						rf := &RouteFilter{
							Prefix:    fc.Keys[1],
							MatchType: fc.Keys[2],
						}
						term.RouteFilters = append(term.RouteFilters, rf)
					}
				case "community":
					if v := nodeVal(fc); v != "" {
						term.FromCommunity = v
					}
				case "as-path":
					if v := nodeVal(fc); v != "" {
						term.FromASPath = v
					}
				}
			}
		case "then":
			for _, ac := range tc.Children {
				switch ac.Name() {
				case "accept":
					term.Action = "accept"
				case "reject":
					term.Action = "reject"
				case "next-hop":
					term.NextHop = nodeVal(ac)
				case "load-balance":
					term.LoadBalance = nodeVal(ac)
				case "local-preference":
					if v := nodeVal(ac); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							term.LocalPreference = n
						}
					}
				case "metric":
					if v := nodeVal(ac); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							term.Metric = n
						}
					}
				case "metric-type":
					if v := nodeVal(ac); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							term.MetricType = n
						}
					}
				case "community":
					term.Community = nodeVal(ac)
				case "origin":
					term.Origin = nodeVal(ac)
				}
			}
			if len(tc.Keys) >= 2 {
				term.Action = tc.Keys[1]
			}
		}
	}
}

// parsePolicyTermInlineKeys handles flat set syntax where remaining keys
// after the term name are inline key-value pairs like:
// "from", "protocol", "direct" or "from", "route-filter", "10.0.0.0/8", "exact"
// or "then", "accept"
func parsePolicyTermInlineKeys(term *PolicyTerm, keys []string) {
	inFrom := false
	for i := 0; i < len(keys); i++ {
		switch keys[i] {
		case "from":
			inFrom = true
			continue
		case "then":
			inFrom = false
			if i+1 < len(keys) {
				i++
				term.Action = keys[i]
			}
		case "protocol":
			if i+1 < len(keys) {
				i++
				term.FromProtocol = keys[i]
			}
		case "prefix-list":
			if i+1 < len(keys) {
				i++
				term.PrefixList = keys[i]
			}
		case "route-filter":
			if i+2 < len(keys) {
				rf := &RouteFilter{
					Prefix:    keys[i+1],
					MatchType: keys[i+2],
				}
				term.RouteFilters = append(term.RouteFilters, rf)
				i += 2
			}
		case "next-hop":
			if i+1 < len(keys) {
				i++
				term.NextHop = keys[i]
			}
		case "load-balance":
			if i+1 < len(keys) {
				i++
				term.LoadBalance = keys[i]
			}
		case "local-preference":
			if i+1 < len(keys) {
				i++
				if n, err := strconv.Atoi(keys[i]); err == nil {
					term.LocalPreference = n
				}
			}
		case "metric":
			if i+1 < len(keys) {
				i++
				if n, err := strconv.Atoi(keys[i]); err == nil {
					term.Metric = n
				}
			}
		case "metric-type":
			if i+1 < len(keys) {
				i++
				if n, err := strconv.Atoi(keys[i]); err == nil {
					term.MetricType = n
				}
			}
		case "community":
			if i+1 < len(keys) {
				i++
				if inFrom {
					term.FromCommunity = keys[i]
				} else {
					term.Community = keys[i]
				}
			}
		case "as-path":
			if i+1 < len(keys) {
				i++
				term.FromASPath = keys[i]
			}
		case "origin":
			if i+1 < len(keys) {
				i++
				term.Origin = keys[i]
			}
		case "accept":
			term.Action = "accept"
		case "reject":
			term.Action = "reject"
		}
	}
}

func compileChassis(node *Node, ch *ChassisConfig) error {
	clusterNode := node.FindChild("cluster")
	if clusterNode == nil {
		return nil
	}

	ch.Cluster = &ClusterConfig{}

	if n := clusterNode.FindChild("cluster-id"); n != nil {
		if v := nodeVal(n); v != "" {
			if id, err := strconv.Atoi(v); err == nil {
				ch.Cluster.ClusterID = id
			}
		}
	}
	if n := clusterNode.FindChild("node"); n != nil {
		if v := nodeVal(n); v != "" {
			if id, err := strconv.Atoi(v); err == nil {
				ch.Cluster.NodeID = id
			}
		}
	}
	if rcNode := clusterNode.FindChild("reth-count"); rcNode != nil {
		if v := nodeVal(rcNode); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				ch.Cluster.RethCount = n
			}
		}
	}
	if n := clusterNode.FindChild("heartbeat-interval"); n != nil {
		if v := nodeVal(n); v != "" {
			if ms, err := strconv.Atoi(v); err == nil {
				ch.Cluster.HeartbeatInterval = ms
			}
		}
	}
	if n := clusterNode.FindChild("heartbeat-threshold"); n != nil {
		if v := nodeVal(n); v != "" {
			if cnt, err := strconv.Atoi(v); err == nil {
				ch.Cluster.HeartbeatThreshold = cnt
			}
		}
	}
	if clusterNode.FindChild("control-link-recovery") != nil {
		ch.Cluster.ControlLinkRecovery = true
	}
	if n := clusterNode.FindChild("control-interface"); n != nil {
		if v := nodeVal(n); v != "" {
			ch.Cluster.ControlInterface = v
		}
	}
	if n := clusterNode.FindChild("peer-address"); n != nil {
		if v := nodeVal(n); v != "" {
			ch.Cluster.PeerAddress = v
		}
	}
	if n := clusterNode.FindChild("fabric-interface"); n != nil {
		if v := nodeVal(n); v != "" {
			ch.Cluster.FabricInterface = v
		}
	}
	if n := clusterNode.FindChild("fabric-peer-address"); n != nil {
		if v := nodeVal(n); v != "" {
			ch.Cluster.FabricPeerAddress = v
		}
	}
	if clusterNode.FindChild("configuration-synchronize") != nil {
		ch.Cluster.ConfigSync = true
	}

	for _, rgInst := range namedInstances(clusterNode.FindChildren("redundancy-group")) {
		rgID := 0
		if n, err := strconv.Atoi(rgInst.name); err == nil {
			rgID = n
		}

		rg := &RedundancyGroup{
			ID:             rgID,
			NodePriorities: make(map[int]int),
		}

		for _, child := range rgInst.node.Children {
			switch child.Name() {
			case "node":
				// node <id> priority <value>
				nodeID := 0
				if v := nodeVal(child); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						nodeID = n
					}
				}
				// Look for "priority" in inline keys or children
				for i := 2; i < len(child.Keys)-1; i++ {
					if child.Keys[i] == "priority" {
						if n, err := strconv.Atoi(child.Keys[i+1]); err == nil {
							rg.NodePriorities[nodeID] = n
						}
					}
				}
				if priNode := child.FindChild("priority"); priNode != nil {
					if v := nodeVal(priNode); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							rg.NodePriorities[nodeID] = n
						}
					}
				}
			case "gratuitous-arp-count":
				if v := nodeVal(child); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						rg.GratuitousARPCount = n
					}
				}
			case "preempt":
				rg.Preempt = true
			case "interface-monitor":
				for _, ifChild := range child.Children {
					im := &InterfaceMonitor{
						Interface: ifChild.Name(),
					}
					// weight is typically inline: "ge-0/0/0 weight 255"
					for i := 1; i < len(ifChild.Keys)-1; i++ {
						if ifChild.Keys[i] == "weight" {
							if n, err := strconv.Atoi(ifChild.Keys[i+1]); err == nil {
								im.Weight = n
							}
						}
					}
					if wNode := ifChild.FindChild("weight"); wNode != nil {
						if v := nodeVal(wNode); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								im.Weight = n
							}
						}
					}
					rg.InterfaceMonitors = append(rg.InterfaceMonitors, im)
				}
			case "ip-monitoring":
				ipm := &IPMonitoring{}
				if gwNode := child.FindChild("global-weight"); gwNode != nil {
					if v := nodeVal(gwNode); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							ipm.GlobalWeight = n
						}
					}
				}
				if gtNode := child.FindChild("global-threshold"); gtNode != nil {
					if v := nodeVal(gtNode); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							ipm.GlobalThreshold = n
						}
					}
				}
				if familyNode := child.FindChild("family"); familyNode != nil {
					if inetNode := familyNode.FindChild("inet"); inetNode != nil {
						for _, addrChild := range inetNode.Children {
							target := &IPMonitorTarget{
								Address: addrChild.Name(),
							}
							// weight inline: "10.0.1.1 weight 100"
							for i := 1; i < len(addrChild.Keys)-1; i++ {
								if addrChild.Keys[i] == "weight" {
									if n, err := strconv.Atoi(addrChild.Keys[i+1]); err == nil {
										target.Weight = n
									}
								}
							}
							if wNode := addrChild.FindChild("weight"); wNode != nil {
								if v := nodeVal(wNode); v != "" {
									if n, err := strconv.Atoi(v); err == nil {
										target.Weight = n
									}
								}
							}
							ipm.Targets = append(ipm.Targets, target)
						}
					}
				}
				rg.IPMonitoring = ipm
			}
		}

		ch.Cluster.RedundancyGroups = append(ch.Cluster.RedundancyGroups, rg)
	}

	return nil
}

func compileEventOptions(node *Node, policies *[]*EventPolicy) error {
	for _, pInst := range namedInstances(node.FindChildren("policy")) {
		ep := &EventPolicy{
			Name: pInst.name,
		}

		for _, child := range pInst.node.Children {
			switch child.Name() {
			case "events":
				// Hierarchical: events [ evt1 evt2 ]; → Keys = ["events", "evt1", "evt2"]
				// Hierarchical: events evt1;          → Keys = ["events", "evt1"]
				// Brackets are stripped by the lexer, so just take Keys[1:]
				for i := 1; i < len(child.Keys); i++ {
					ep.Events = append(ep.Events, child.Keys[i])
				}
				// Flat set format: children are individual event name nodes
				for _, evtChild := range child.Children {
					ep.Events = append(ep.Events, evtChild.Name())
				}
			case "within":
				w := &EventWithin{}
				if v := nodeVal(child); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						w.Seconds = n
					}
				}
				if trigNode := child.FindChild("trigger"); trigNode != nil {
					// trigger on N or trigger until N
					for i := 1; i < len(trigNode.Keys)-1; i++ {
						switch trigNode.Keys[i] {
						case "on":
							if n, err := strconv.Atoi(trigNode.Keys[i+1]); err == nil {
								w.TriggerOn = n
							}
						case "until":
							if n, err := strconv.Atoi(trigNode.Keys[i+1]); err == nil {
								w.TriggerUntil = n
							}
						}
					}
					// Also check children
					if onNode := trigNode.FindChild("on"); onNode != nil {
						if v := nodeVal(onNode); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								w.TriggerOn = n
							}
						}
					}
					if untilNode := trigNode.FindChild("until"); untilNode != nil {
						if v := nodeVal(untilNode); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								w.TriggerUntil = n
							}
						}
					}
				}
				ep.WithinClauses = append(ep.WithinClauses, w)
			case "attributes-match":
				// Each child is a match line like "ping_test_failed.test-owner matches Comcast"
				for _, amChild := range child.Children {
					// Reconstruct the match expression from keys
					ep.AttributesMatch = append(ep.AttributesMatch, strings.Join(amChild.Keys, " "))
				}
			case "then":
				if ccNode := child.FindChild("change-configuration"); ccNode != nil {
					if cmdsNode := ccNode.FindChild("commands"); cmdsNode != nil {
						for _, cmdChild := range cmdsNode.Children {
							ep.ThenCommands = append(ep.ThenCommands, cmdChild.Name())
						}
					}
				}
			}
		}

		*policies = append(*policies, ep)
	}
	return nil
}
