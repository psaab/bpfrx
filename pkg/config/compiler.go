package config

import (
	"fmt"
	"strconv"
)

// CompileConfig converts a parsed ConfigTree AST into a typed Config struct.
func CompileConfig(tree *ConfigTree) (*Config, error) {
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
		}
	}

	return cfg, nil
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
		case "ipsec":
			if err := compileIPsec(child, sec); err != nil {
				return fmt.Errorf("ipsec: %w", err)
			}
		}
	}
	return nil
}

func compileZones(node *Node, sec *SecurityConfig) error {
	for _, child := range node.FindChildren("security-zone") {
		if len(child.Keys) < 2 {
			return fmt.Errorf("security-zone missing name at line %d", child.Line)
		}
		zoneName := child.Keys[1]
		zone := &ZoneConfig{Name: zoneName}

		for _, prop := range child.Children {
			switch prop.Name() {
			case "interfaces":
				for _, iface := range prop.Children {
					zone.Interfaces = append(zone.Interfaces, iface.Name())
				}
			case "screen":
				// "screen untrust-screen;" or "screen ids-option name;"
				if len(prop.Keys) >= 2 {
					zone.ScreenProfile = prop.Keys[1]
				}
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
			}
		}

		sec.Zones[zoneName] = zone
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
		// "from-zone trust to-zone untrust { ... }"
		if child.Name() == "from-zone" && len(child.Keys) >= 4 {
			fromZone := child.Keys[1]
			toZone := child.Keys[3] // "to-zone" is at index 2
			zpp := &ZonePairPolicies{
				FromZone: fromZone,
				ToZone:   toZone,
			}

			for _, policyNode := range child.FindChildren("policy") {
				if len(policyNode.Keys) < 2 {
					continue
				}
				pol := &Policy{Name: policyNode.Keys[1]}

				matchNode := policyNode.FindChild("match")
				if matchNode != nil {
					for _, m := range matchNode.Children {
						switch m.Name() {
						case "source-address":
							if len(m.Keys) >= 2 {
								pol.Match.SourceAddresses = append(pol.Match.SourceAddresses, m.Keys[1])
							}
						case "destination-address":
							if len(m.Keys) >= 2 {
								pol.Match.DestinationAddresses = append(pol.Match.DestinationAddresses, m.Keys[1])
							}
						case "application":
							if len(m.Keys) >= 2 {
								pol.Match.Applications = append(pol.Match.Applications, m.Keys[1])
							}
						}
					}
				}

				thenNode := policyNode.FindChild("then")
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

				zpp.Policies = append(zpp.Policies, pol)
			}

			sec.Policies = append(sec.Policies, zpp)
		}
	}
	return nil
}

func compileScreen(node *Node, sec *SecurityConfig) error {
	for _, child := range node.FindChildren("ids-option") {
		if len(child.Keys) < 2 {
			continue
		}
		profile := &ScreenProfile{Name: child.Keys[1]}

		icmpNode := child.FindChild("icmp")
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
					}
				}
			}
		}

		ipNode := child.FindChild("ip")
		if ipNode != nil {
			for _, opt := range ipNode.Children {
				switch opt.Name() {
				case "source-route-option":
					profile.IP.SourceRouteOption = true
				case "tear-drop":
					profile.IP.TearDrop = true
				}
			}
		}

		tcpNode := child.FindChild("tcp")
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
						if len(sfOpt.Keys) >= 2 {
							val, _ := strconv.Atoi(sfOpt.Keys[1])
							switch sfOpt.Name() {
							case "alarm-threshold":
								sf.AlarmThreshold = val
							case "attack-threshold":
								sf.AttackThreshold = val
							case "source-threshold":
								sf.SourceThreshold = val
							case "timeout":
								sf.Timeout = val
							}
						}
					}
					profile.TCP.SynFlood = sf
				}
			}
		}

		udpNode := child.FindChild("udp")
		if udpNode != nil {
			for _, opt := range udpNode.Children {
				switch opt.Name() {
				case "flood":
					if len(opt.Keys) >= 3 {
						if v, err := strconv.Atoi(opt.Keys[2]); err == nil {
							profile.UDP.FloodThreshold = v
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
					if member.Name() == "address" && len(member.Keys) >= 2 {
						as.Addresses = append(as.Addresses, member.Keys[1])
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

		// Check for vlan-tagging flag
		if child.FindChild("vlan-tagging") != nil {
			ifc.VlanTagging = true
		}

		// Check for tunnel configuration
		tunnelNode := child.FindChild("tunnel")
		if tunnelNode != nil {
			tc := &TunnelConfig{
				Name: ifName,
				Mode: "gre", // default
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
				}
			}
			ifc.Tunnel = tc
		}

		for _, unitNode := range child.FindChildren("unit") {
			if len(unitNode.Keys) < 2 {
				continue
			}
			unitNum, err := strconv.Atoi(unitNode.Keys[1])
			if err != nil {
				continue
			}
			unit := &InterfaceUnit{Number: unitNum}

			// Parse vlan-id on unit
			vlanNode := unitNode.FindChild("vlan-id")
			if vlanNode != nil && len(vlanNode.Keys) >= 2 {
				if v, err := strconv.Atoi(vlanNode.Keys[1]); err == nil {
					unit.VlanID = v
				}
			}

			// Handle two AST shapes:
			// - set commands:  family { inet { address ...; dhcp; } }
			//   Keys=["family"], child Keys=["inet"] with grandchildren
			// - hierarchical:  family inet { address ...; dhcp; }
			//   Keys=["family","inet"], children are address/dhcp directly
			for _, familyNode := range unitNode.FindChildren("family") {
				var afNodes []*Node
				if len(familyNode.Keys) >= 2 {
					// Hierarchical: Keys=["family","inet"] — node itself is the AF
					afNodes = append(afNodes, familyNode)
				} else {
					// Set-command: Keys=["family"], children are inet/inet6
					afNodes = append(afNodes, familyNode.Children...)
				}
				for _, afNode := range afNodes {
					afName := afNode.Keys[0]
					if len(afNode.Keys) >= 2 {
						afName = afNode.Keys[1]
					}
					switch afName {
					case "inet":
						for _, addrNode := range afNode.FindChildren("address") {
							if len(addrNode.Keys) >= 2 {
								unit.Addresses = append(unit.Addresses, addrNode.Keys[1])
							}
						}
						if afNode.FindChild("dhcp") != nil {
							unit.DHCP = true
						}
					case "inet6":
						for _, addrNode := range afNode.FindChildren("address") {
							if len(addrNode.Keys) >= 2 {
								unit.Addresses = append(unit.Addresses, addrNode.Keys[1])
							}
						}
						if afNode.FindChild("dhcpv6") != nil {
							unit.DHCPv6 = true
						}
						if dcNode := afNode.FindChild("dhcpv6-client"); dcNode != nil {
							unit.DHCPv6 = true
							unit.DHCPv6Client = &DHCPv6ClientConfig{}
							if ciNode := dcNode.FindChild("client-identifier"); ciNode != nil {
								if dtNode := ciNode.FindChild("duid-type"); dtNode != nil && len(dtNode.Keys) >= 2 {
									unit.DHCPv6Client.DUIDType = dtNode.Keys[1]
								}
							}
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

	return nil
}

func compileNATSource(node *Node, sec *SecurityConfig) error {
	// Parse source NAT pools
	for _, poolNode := range node.FindChildren("pool") {
		if len(poolNode.Keys) < 2 {
			continue
		}
		pool := &NATPool{Name: poolNode.Keys[1]}

		for _, prop := range poolNode.Children {
			switch prop.Name() {
			case "address":
				if len(prop.Keys) >= 2 {
					pool.Addresses = append(pool.Addresses, prop.Keys[1])
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
				} else if len(prop.Keys) >= 2 {
					if v, err := strconv.Atoi(prop.Keys[1]); err == nil {
						pool.PortLow = v
						pool.PortHigh = v
					}
				}
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
	for _, rsNode := range node.FindChildren("rule-set") {
		if len(rsNode.Keys) < 2 {
			continue
		}
		rs := &NATRuleSet{Name: rsNode.Keys[1]}

		// Parse from/to zone
		for _, child := range rsNode.Children {
			if child.Name() == "from" && len(child.Keys) >= 3 && child.Keys[1] == "zone" {
				rs.FromZone = child.Keys[2]
			}
			if child.Name() == "to" && len(child.Keys) >= 3 && child.Keys[1] == "zone" {
				rs.ToZone = child.Keys[2]
			}
		}

		// Parse rules
		for _, ruleNode := range rsNode.FindChildren("rule") {
			if len(ruleNode.Keys) < 2 {
				continue
			}
			rule := &NATRule{Name: ruleNode.Keys[1]}

			matchNode := ruleNode.FindChild("match")
			if matchNode != nil {
				for _, m := range matchNode.Children {
					switch m.Name() {
					case "source-address":
						if len(m.Keys) >= 2 {
							rule.Match.SourceAddress = m.Keys[1]
						}
					case "destination-address":
						if len(m.Keys) >= 2 {
							rule.Match.DestinationAddress = m.Keys[1]
						}
					case "destination-port":
						if len(m.Keys) >= 2 {
							if v, err := strconv.Atoi(m.Keys[1]); err == nil {
								rule.Match.DestinationPort = v
							}
						}
					}
				}
			}

			thenNode := ruleNode.FindChild("then")
			if thenNode != nil {
				for _, t := range thenNode.Children {
					if t.Name() == "source-nat" {
						if len(t.Keys) >= 2 {
							// Flat form: source-nat interface; / source-nat pool <name>;
							if t.Keys[1] == "interface" {
								rule.Then.Type = NATSource
								rule.Then.Interface = true
							} else if t.Keys[1] == "pool" && len(t.Keys) >= 3 {
								rule.Then.Type = NATSource
								rule.Then.PoolName = t.Keys[2]
							}
						} else if t.FindChild("interface") != nil {
							// Hierarchical form: source-nat { interface; }
							rule.Then.Type = NATSource
							rule.Then.Interface = true
						} else if poolNode := t.FindChild("pool"); poolNode != nil && len(poolNode.Keys) >= 2 {
							// Hierarchical form: source-nat { pool <name>; }
							rule.Then.Type = NATSource
							rule.Then.PoolName = poolNode.Keys[1]
						}
					}
				}
			}

			rs.Rules = append(rs.Rules, rule)
		}

		sec.NAT.Source = append(sec.NAT.Source, rs)
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
	for _, poolNode := range node.FindChildren("pool") {
		if len(poolNode.Keys) < 2 {
			continue
		}
		pool := &NATPool{Name: poolNode.Keys[1]}

		for _, prop := range poolNode.Children {
			switch prop.Name() {
			case "address":
				if len(prop.Keys) >= 2 {
					pool.Address = prop.Keys[1]
				}
			case "port":
				if len(prop.Keys) >= 2 {
					if v, err := strconv.Atoi(prop.Keys[1]); err == nil {
						pool.Port = v
					}
				}
			}
		}

		sec.NAT.Destination.Pools[pool.Name] = pool
	}

	// Parse rule-sets
	for _, rsNode := range node.FindChildren("rule-set") {
		if len(rsNode.Keys) < 2 {
			continue
		}
		rs := &NATRuleSet{Name: rsNode.Keys[1]}

		for _, child := range rsNode.Children {
			if child.Name() == "from" && len(child.Keys) >= 3 && child.Keys[1] == "zone" {
				rs.FromZone = child.Keys[2]
			}
			if child.Name() == "to" && len(child.Keys) >= 3 && child.Keys[1] == "zone" {
				rs.ToZone = child.Keys[2]
			}
		}

		for _, ruleNode := range rsNode.FindChildren("rule") {
			if len(ruleNode.Keys) < 2 {
				continue
			}
			rule := &NATRule{Name: ruleNode.Keys[1]}

			matchNode := ruleNode.FindChild("match")
			if matchNode != nil {
				for _, m := range matchNode.Children {
					switch m.Name() {
					case "destination-address":
						if len(m.Keys) >= 2 {
							rule.Match.DestinationAddress = m.Keys[1]
						}
					case "destination-port":
						if len(m.Keys) >= 2 {
							if v, err := strconv.Atoi(m.Keys[1]); err == nil {
								rule.Match.DestinationPort = v
							}
						}
					case "source-address":
						if len(m.Keys) >= 2 {
							rule.Match.SourceAddress = m.Keys[1]
						}
					case "protocol":
						if len(m.Keys) >= 2 {
							rule.Match.Protocol = m.Keys[1]
						}
					}
				}
			}

			thenNode := ruleNode.FindChild("then")
			if thenNode != nil {
				for _, t := range thenNode.Children {
					if t.Name() == "destination-nat" {
						if len(t.Keys) >= 3 && t.Keys[1] == "pool" {
							rule.Then.Type = NATDestination
							rule.Then.PoolName = t.Keys[2]
						} else if poolNode := t.FindChild("pool"); poolNode != nil && len(poolNode.Keys) >= 2 {
							// Hierarchical form: destination-nat { pool <name>; }
							rule.Then.Type = NATDestination
							rule.Then.PoolName = poolNode.Keys[1]
						}
					}
				}
			}

			rs.Rules = append(rs.Rules, rule)
		}

		sec.NAT.Destination.RuleSets = append(sec.NAT.Destination.RuleSets, rs)
	}
	return nil
}

func compileNATStatic(node *Node, sec *SecurityConfig) error {
	for _, rsNode := range node.FindChildren("rule-set") {
		if len(rsNode.Keys) < 2 {
			continue
		}
		rs := &StaticNATRuleSet{Name: rsNode.Keys[1]}

		// Parse from zone
		for _, child := range rsNode.Children {
			if child.Name() == "from" && len(child.Keys) >= 3 && child.Keys[1] == "zone" {
				rs.FromZone = child.Keys[2]
			}
		}

		// Parse rules
		for _, ruleNode := range rsNode.FindChildren("rule") {
			if len(ruleNode.Keys) < 2 {
				continue
			}
			rule := &StaticNATRule{Name: ruleNode.Keys[1]}

			matchNode := ruleNode.FindChild("match")
			if matchNode != nil {
				for _, m := range matchNode.Children {
					if m.Name() == "destination-address" && len(m.Keys) >= 2 {
						rule.Match = m.Keys[1]
					}
				}
			}

			thenNode := ruleNode.FindChild("then")
			if thenNode != nil {
				for _, t := range thenNode.Children {
					if t.Name() == "static-nat" && len(t.Keys) >= 3 && t.Keys[1] == "prefix" {
						rule.Then = t.Keys[2]
					}
				}
			}

			rs.Rules = append(rs.Rules, rule)
		}

		sec.NAT.Static = append(sec.NAT.Static, rs)
	}
	return nil
}

func compileLog(node *Node, sec *SecurityConfig) error {
	if sec.Log.Streams == nil {
		sec.Log.Streams = make(map[string]*SyslogStream)
	}
	for _, streamNode := range node.FindChildren("stream") {
		if len(streamNode.Keys) < 2 {
			continue
		}
		stream := &SyslogStream{
			Name: streamNode.Keys[1],
			Port: 514, // default
		}
		for _, prop := range streamNode.Children {
			switch prop.Name() {
			case "host":
				if len(prop.Keys) >= 2 {
					stream.Host = prop.Keys[1]
				}
			case "port":
				if len(prop.Keys) >= 2 {
					if v, err := strconv.Atoi(prop.Keys[1]); err == nil {
						stream.Port = v
					}
				}
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

	return nil
}

func compileApplications(node *Node, apps *ApplicationsConfig) error {
	for _, child := range node.FindChildren("application") {
		if len(child.Keys) < 2 {
			continue
		}
		app := &Application{Name: child.Keys[1]}

		for _, prop := range child.Children {
			switch prop.Name() {
			case "protocol":
				if len(prop.Keys) >= 2 {
					app.Protocol = prop.Keys[1]
				}
			case "destination-port":
				if len(prop.Keys) >= 2 {
					app.DestinationPort = prop.Keys[1]
				}
			}
		}

		apps.Applications[app.Name] = app
	}

	for _, child := range node.FindChildren("application-set") {
		if len(child.Keys) < 2 {
			continue
		}
		as := &ApplicationSet{Name: child.Keys[1]}

		for _, member := range child.Children {
			if member.Name() == "application" && len(member.Keys) >= 2 {
				as.Applications = append(as.Applications, member.Keys[1])
			}
		}

		apps.ApplicationSets[as.Name] = as
	}

	return nil
}

func compileRoutingOptions(node *Node, ro *RoutingOptionsConfig) error {
	staticNode := node.FindChild("static")
	if staticNode == nil {
		return nil
	}

	for _, routeNode := range staticNode.FindChildren("route") {
		if len(routeNode.Keys) < 2 {
			continue
		}
		route := &StaticRoute{
			Destination: routeNode.Keys[1],
			Preference:  5, // default
		}

		for _, prop := range routeNode.Children {
			switch prop.Name() {
			case "next-hop":
				if len(prop.Keys) >= 2 {
					route.NextHop = prop.Keys[1]
				}
			case "discard":
				route.Discard = true
			case "preference":
				if len(prop.Keys) >= 2 {
					if v, err := strconv.Atoi(prop.Keys[1]); err == nil {
						route.Preference = v
					}
				}
			case "qualified-next-hop":
				if len(prop.Keys) >= 2 {
					route.NextHop = prop.Keys[1]
				}
				// Check for "interface <name>" among remaining keys
				for j := 2; j < len(prop.Keys)-1; j++ {
					if prop.Keys[j] == "interface" {
						route.Interface = prop.Keys[j+1]
					}
				}
			}
		}

		ro.StaticRoutes = append(ro.StaticRoutes, route)
	}
	return nil
}

func compileProtocols(node *Node, proto *ProtocolsConfig) error {
	ospfNode := node.FindChild("ospf")
	if ospfNode != nil {
		proto.OSPF = &OSPFConfig{}

		// Router ID at the ospf level
		for _, child := range ospfNode.Children {
			if child.Name() == "router-id" && len(child.Keys) >= 2 {
				proto.OSPF.RouterID = child.Keys[1]
			}
		}

		for _, areaNode := range ospfNode.FindChildren("area") {
			if len(areaNode.Keys) < 2 {
				continue
			}
			area := &OSPFArea{ID: areaNode.Keys[1]}

			for _, child := range areaNode.Children {
				if child.Name() == "interface" && len(child.Keys) >= 2 {
					iface := &OSPFInterface{Name: child.Keys[1]}
					// Check for "passive" flag in remaining keys
					for _, k := range child.Keys[2:] {
						if k == "passive" {
							iface.Passive = true
						}
					}
					// Check children for cost etc.
					for _, prop := range child.Children {
						switch prop.Name() {
						case "passive":
							iface.Passive = true
						case "cost":
							if len(prop.Keys) >= 2 {
								if v, err := strconv.Atoi(prop.Keys[1]); err == nil {
									iface.Cost = v
								}
							}
						}
					}
					area.Interfaces = append(area.Interfaces, iface)
				}
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
			}
		}

		for _, groupNode := range bgpNode.FindChildren("group") {
			if len(groupNode.Keys) < 2 {
				continue
			}
			var peerAS uint32
			for _, child := range groupNode.Children {
				switch child.Name() {
				case "peer-as":
					if len(child.Keys) >= 2 {
						if v, err := strconv.Atoi(child.Keys[1]); err == nil {
							peerAS = uint32(v)
						}
					}
				case "neighbor":
					if len(child.Keys) >= 2 {
						neighbor := &BGPNeighbor{
							Address: child.Keys[1],
							PeerAS:  peerAS,
						}
						proto.BGP.Neighbors = append(proto.BGP.Neighbors, neighbor)
					}
				}
			}
		}
	}

	return nil
}

func compileIPsec(node *Node, sec *SecurityConfig) error {
	if sec.IPsec.Proposals == nil {
		sec.IPsec.Proposals = make(map[string]*IPsecProposal)
	}
	if sec.IPsec.Gateways == nil {
		sec.IPsec.Gateways = make(map[string]*IPsecGateway)
	}
	if sec.IPsec.VPNs == nil {
		sec.IPsec.VPNs = make(map[string]*IPsecVPN)
	}

	for _, child := range node.FindChildren("proposal") {
		if len(child.Keys) < 2 {
			continue
		}
		prop := &IPsecProposal{Name: child.Keys[1]}

		for _, p := range child.Children {
			switch p.Name() {
			case "protocol":
				if len(p.Keys) >= 2 {
					prop.Protocol = p.Keys[1]
				}
			case "encryption-algorithm":
				if len(p.Keys) >= 2 {
					prop.EncryptionAlg = p.Keys[1]
				}
			case "authentication-algorithm":
				if len(p.Keys) >= 2 {
					prop.AuthAlg = p.Keys[1]
				}
			case "dh-group":
				if len(p.Keys) >= 2 {
					if v, err := strconv.Atoi(p.Keys[1]); err == nil {
						prop.DHGroup = v
					}
				}
			case "lifetime-seconds":
				if len(p.Keys) >= 2 {
					if v, err := strconv.Atoi(p.Keys[1]); err == nil {
						prop.LifetimeSeconds = v
					}
				}
			}
		}

		sec.IPsec.Proposals[prop.Name] = prop
	}

	for _, child := range node.FindChildren("vpn") {
		if len(child.Keys) < 2 {
			continue
		}
		vpn := &IPsecVPN{Name: child.Keys[1]}

		for _, p := range child.Children {
			switch p.Name() {
			case "gateway":
				if len(p.Keys) >= 2 {
					vpn.Gateway = p.Keys[1]
				}
			case "local-address":
				if len(p.Keys) >= 2 {
					vpn.LocalAddr = p.Keys[1]
				}
			case "ipsec-policy":
				if len(p.Keys) >= 2 {
					vpn.IPsecPolicy = p.Keys[1]
				}
			case "local-identity":
				if len(p.Keys) >= 2 {
					vpn.LocalID = p.Keys[1]
				}
			case "remote-identity":
				if len(p.Keys) >= 2 {
					vpn.RemoteID = p.Keys[1]
				}
			case "pre-shared-key":
				if len(p.Keys) >= 2 {
					vpn.PSK = p.Keys[1]
				}
			}
		}

		sec.IPsec.VPNs[vpn.Name] = vpn
	}

	return nil
}
