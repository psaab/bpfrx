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
		case "dynamic-address":
			if err := compileDynamicAddress(child, sec); err != nil {
				return fmt.Errorf("dynamic-address: %w", err)
			}
		case "alg":
			if err := compileALG(child, sec); err != nil {
				return fmt.Errorf("alg: %w", err)
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

				// scheduler-name at the policy level
				if snNode := policyNode.FindChild("scheduler-name"); snNode != nil && len(snNode.Keys) >= 2 {
					pol.SchedulerName = snNode.Keys[1]
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
								// Parse VRRP groups under address
								for _, vrrpNode := range addrNode.FindChildren("vrrp-group") {
									if len(vrrpNode.Keys) < 2 {
										continue
									}
									groupID, err := strconv.Atoi(vrrpNode.Keys[1])
									if err != nil {
										continue
									}
									vg := &VRRPGroup{
										ID:       groupID,
										Priority: 100, // default
									}
									for _, prop := range vrrpNode.Children {
										switch prop.Name() {
										case "virtual-address":
											if len(prop.Keys) >= 2 {
												vg.VirtualAddresses = append(vg.VirtualAddresses, prop.Keys[1])
											}
										case "priority":
											if len(prop.Keys) >= 2 {
												vg.Priority, _ = strconv.Atoi(prop.Keys[1])
											}
										case "preempt":
											vg.Preempt = true
										case "accept-data":
											vg.AcceptData = true
										case "advertise-interval":
											if len(prop.Keys) >= 2 {
												vg.AdvertiseInterval, _ = strconv.Atoi(prop.Keys[1])
											}
										case "authentication-type":
											if len(prop.Keys) >= 2 {
												vg.AuthType = prop.Keys[1]
											}
										case "authentication-key":
											if len(prop.Keys) >= 2 {
												vg.AuthKey = prop.Keys[1]
											}
										case "track-interface":
											if len(prop.Keys) >= 2 {
												vg.TrackInterface = prop.Keys[1]
											}
										case "track-priority-cost":
											if len(prop.Keys) >= 2 {
												vg.TrackPriorityDelta, _ = strconv.Atoi(prop.Keys[1])
											}
										}
									}
									if unit.VRRPGroups == nil {
										unit.VRRPGroups = make(map[string]*VRRPGroup)
									}
									key := fmt.Sprintf("%s_grp%d", addrNode.Keys[1], groupID)
									unit.VRRPGroups[key] = vg
								}
							}
						}
						if afNode.FindChild("dhcp") != nil {
							unit.DHCP = true
						}
						if filterNode := afNode.FindChild("filter"); filterNode != nil {
							if inputNode := filterNode.FindChild("input"); inputNode != nil && len(inputNode.Keys) >= 2 {
								unit.FilterInputV4 = inputNode.Keys[1]
							}
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
						if filterNode := afNode.FindChild("filter"); filterNode != nil {
							if inputNode := filterNode.FindChild("input"); inputNode != nil && len(inputNode.Keys) >= 2 {
								unit.FilterInputV6 = inputNode.Keys[1]
							}
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

	nat64Node := node.FindChild("nat64")
	if nat64Node != nil {
		if err := compileNAT64(nat64Node, sec); err != nil {
			return fmt.Errorf("nat64: %w", err)
		}
	}

	return nil
}

func compileNAT64(node *Node, sec *SecurityConfig) error {
	for _, rsNode := range node.FindChildren("rule-set") {
		if len(rsNode.Keys) < 2 {
			continue
		}
		rs := &NAT64RuleSet{Name: rsNode.Keys[1]}

		for _, child := range rsNode.Children {
			switch child.Name() {
			case "prefix":
				if len(child.Keys) >= 2 {
					rs.Prefix = child.Keys[1]
				}
			case "source-pool":
				if len(child.Keys) >= 2 {
					rs.SourcePool = child.Keys[1]
				}
			}
		}

		sec.NAT.NAT64 = append(sec.NAT.NAT64, rs)
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
			case "persistent-nat":
				pnat := &PersistentNATConfig{InactivityTimeout: 300}
				for _, pnProp := range prop.Children {
					switch pnProp.Name() {
					case "permit":
						if len(pnProp.Keys) >= 2 && pnProp.Keys[1] == "any-remote-host" {
							pnat.PermitAnyRemoteHost = true
						}
					case "inactivity-timeout":
						if len(pnProp.Keys) >= 2 {
							if v, err := strconv.Atoi(pnProp.Keys[1]); err == nil {
								pnat.InactivityTimeout = v
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

	// TCP MSS clamping
	mssNode := node.FindChild("tcp-mss")
	if mssNode != nil {
		for _, opt := range mssNode.Children {
			switch opt.Name() {
			case "ipsec-vpn":
				if len(opt.Keys) >= 2 {
					if v, err := strconv.Atoi(opt.Keys[1]); err == nil {
						sec.Flow.TCPMSSIPsecVPN = v
					}
				}
			case "gre-in", "gre-out":
				if len(opt.Keys) >= 2 {
					if v, err := strconv.Atoi(opt.Keys[1]); err == nil {
						sec.Flow.TCPMSSGre = v
					}
				}
			case "all-tcp":
				// Junos "all-tcp { mss VALUE }" variant
				mssChild := opt.FindChild("mss")
				if mssChild != nil && len(mssChild.Keys) >= 2 {
					if v, err := strconv.Atoi(mssChild.Keys[1]); err == nil {
						sec.Flow.TCPMSSIPsecVPN = v
						sec.Flow.TCPMSSGre = v
					}
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

func compileRouterAdvertisement(node *Node, proto *ProtocolsConfig) error {
	for _, ifNode := range node.FindChildren("interface") {
		if len(ifNode.Keys) < 2 {
			continue
		}
		ra := &RAInterfaceConfig{
			Interface: ifNode.Keys[1],
		}

		for _, prop := range ifNode.Children {
			switch prop.Name() {
			case "managed-configuration":
				ra.ManagedConfig = true
			case "other-stateful-configuration":
				ra.OtherStateful = true
			case "default-lifetime":
				if len(prop.Keys) >= 2 {
					if v, err := strconv.Atoi(prop.Keys[1]); err == nil {
						ra.DefaultLifetime = v
					}
				}
			case "max-advertisement-interval":
				if len(prop.Keys) >= 2 {
					if v, err := strconv.Atoi(prop.Keys[1]); err == nil {
						ra.MaxAdvInterval = v
					}
				}
			case "min-advertisement-interval":
				if len(prop.Keys) >= 2 {
					if v, err := strconv.Atoi(prop.Keys[1]); err == nil {
						ra.MinAdvInterval = v
					}
				}
			case "link-mtu":
				if len(prop.Keys) >= 2 {
					if v, err := strconv.Atoi(prop.Keys[1]); err == nil {
						ra.LinkMTU = v
					}
				}
			case "dns-server-address":
				if len(prop.Keys) >= 2 {
					ra.DNSServers = append(ra.DNSServers, prop.Keys[1])
				}
			case "nat64prefix":
				if len(prop.Keys) >= 2 {
					ra.NAT64Prefix = prop.Keys[1]
				}
			case "prefix":
				if len(prop.Keys) >= 2 {
					pfx := &RAPrefix{
						Prefix:     prop.Keys[1],
						OnLink:     true, // defaults
						Autonomous: true,
					}
					for _, child := range prop.Children {
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
							if len(child.Keys) >= 2 {
								if v, err := strconv.Atoi(child.Keys[1]); err == nil {
									pfx.ValidLifetime = v
								}
							}
						case "preferred-lifetime":
							if len(child.Keys) >= 2 {
								if v, err := strconv.Atoi(child.Keys[1]); err == nil {
									pfx.PreferredLife = v
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
			case "instance-type":
				if len(prop.Keys) >= 2 {
					ri.InstanceType = prop.Keys[1]
				}
			case "interface":
				if len(prop.Keys) >= 2 {
					ri.Interfaces = append(ri.Interfaces, prop.Keys[1])
				}
			case "routing-options":
				var ro RoutingOptionsConfig
				if err := compileRoutingOptions(prop, &ro); err != nil {
					return fmt.Errorf("instance %s routing-options: %w", instanceName, err)
				}
				ri.StaticRoutes = ro.StaticRoutes
			case "protocols":
				var proto ProtocolsConfig
				if err := compileProtocols(prop, &proto); err != nil {
					return fmt.Errorf("instance %s protocols: %w", instanceName, err)
				}
				ri.OSPF = proto.OSPF
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

			for _, filterNode := range afNode.FindChildren("filter") {
				if len(filterNode.Keys) < 2 {
					continue
				}
				filter := &FirewallFilter{Name: filterNode.Keys[1]}

				for _, termNode := range filterNode.FindChildren("term") {
					if len(termNode.Keys) < 2 {
						continue
					}
					term := &FirewallFilterTerm{
						Name:     termNode.Keys[1],
						ICMPType: -1,
						ICMPCode: -1,
					}

					fromNode := termNode.FindChild("from")
					if fromNode != nil {
						compileFilterFrom(fromNode, term)
					}

					thenNode := termNode.FindChild("then")
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
			if len(child.Keys) >= 2 {
				term.DSCP = child.Keys[1]
			}
		case "protocol":
			if len(child.Keys) >= 2 {
				term.Protocol = child.Keys[1]
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
		case "icmp-type":
			if len(child.Keys) >= 2 {
				if v, err := strconv.Atoi(child.Keys[1]); err == nil {
					term.ICMPType = v
				}
			}
		case "icmp-code":
			if len(child.Keys) >= 2 {
				if v, err := strconv.Atoi(child.Keys[1]); err == nil {
					term.ICMPCode = v
				}
			}
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
		}
	}
}

func compileSystem(node *Node, sys *SystemConfig) error {
	svcNode := node.FindChild("services")
	if svcNode != nil {
		dhcpNode := svcNode.FindChild("dhcp-local-server")
		if dhcpNode != nil {
			if err := compileDHCPLocalServer(dhcpNode, &sys.DHCPServer); err != nil {
				return err
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

func compileDHCPLocalServer(node *Node, dhcp *DHCPServerConfig) error {
	dhcp.DHCPLocalServer = &DHCPLocalServerConfig{
		Groups: make(map[string]*DHCPServerGroup),
	}

	for _, groupNode := range node.FindChildren("group") {
		if len(groupNode.Keys) < 2 {
			continue
		}
		group := &DHCPServerGroup{Name: groupNode.Keys[1]}

		for _, prop := range groupNode.Children {
			switch prop.Name() {
			case "interface":
				if len(prop.Keys) >= 2 {
					group.Interfaces = append(group.Interfaces, prop.Keys[1])
				}
			case "pool":
				if len(prop.Keys) >= 2 {
					pool := &DHCPPool{Name: prop.Keys[1]}
					for _, pp := range prop.Children {
						switch pp.Name() {
						case "address-range":
							// address-range low X high Y
							if len(pp.Keys) >= 5 && pp.Keys[1] == "low" && pp.Keys[3] == "high" {
								pool.RangeLow = pp.Keys[2]
								pool.RangeHigh = pp.Keys[4]
							}
						case "subnet":
							if len(pp.Keys) >= 2 {
								pool.Subnet = pp.Keys[1]
							}
						case "router":
							if len(pp.Keys) >= 2 {
								pool.Router = pp.Keys[1]
							}
						case "dns-server":
							if len(pp.Keys) >= 2 {
								pool.DNSServers = append(pool.DNSServers, pp.Keys[1])
							}
						case "lease-time":
							if len(pp.Keys) >= 2 {
								if v, err := strconv.Atoi(pp.Keys[1]); err == nil {
									pool.LeaseTime = v
								}
							}
						case "domain-name":
							if len(pp.Keys) >= 2 {
								pool.Domain = pp.Keys[1]
							}
						}
					}
					group.Pools = append(group.Pools, pool)
				}
			}
		}

		dhcp.DHCPLocalServer.Groups[group.Name] = group
	}
	return nil
}

func compileDynamicAddress(node *Node, sec *SecurityConfig) error {
	if sec.DynamicAddress.FeedServers == nil {
		sec.DynamicAddress.FeedServers = make(map[string]*FeedServer)
	}

	for _, fsNode := range node.FindChildren("feed-server") {
		if len(fsNode.Keys) < 2 {
			continue
		}
		fs := &FeedServer{Name: fsNode.Keys[1]}

		for _, prop := range fsNode.Children {
			switch prop.Name() {
			case "url":
				if len(prop.Keys) >= 2 {
					fs.URL = prop.Keys[1]
				}
			case "update-interval":
				if len(prop.Keys) >= 2 {
					if v, err := strconv.Atoi(prop.Keys[1]); err == nil {
						fs.UpdateInterval = v
					}
				}
			case "hold-interval":
				if len(prop.Keys) >= 2 {
					if v, err := strconv.Atoi(prop.Keys[1]); err == nil {
						fs.HoldInterval = v
					}
				}
			case "feed-name":
				if len(prop.Keys) >= 2 {
					fs.FeedName = prop.Keys[1]
				}
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
	return nil
}

func compileRPM(node *Node, svc *ServicesConfig) error {
	rpmCfg := &RPMConfig{Probes: make(map[string]*RPMProbe)}

	for _, probeNode := range node.FindChildren("probe") {
		if len(probeNode.Keys) < 2 {
			continue
		}
		probe := &RPMProbe{
			Name:  probeNode.Keys[1],
			Tests: make(map[string]*RPMTest),
		}

		for _, testNode := range probeNode.FindChildren("test") {
			if len(testNode.Keys) < 2 {
				continue
			}
			test := &RPMTest{Name: testNode.Keys[1]}

			for _, prop := range testNode.Children {
				switch prop.Name() {
				case "probe-type":
					if len(prop.Keys) >= 2 {
						test.ProbeType = prop.Keys[1]
					}
				case "target":
					if len(prop.Keys) >= 2 {
						test.Target = prop.Keys[1]
					}
				case "source-address":
					if len(prop.Keys) >= 2 {
						test.SourceAddress = prop.Keys[1]
					}
				case "routing-instance":
					if len(prop.Keys) >= 2 {
						test.RoutingInstance = prop.Keys[1]
					}
				case "probe-interval":
					if len(prop.Keys) >= 2 {
						if v, err := strconv.Atoi(prop.Keys[1]); err == nil {
							test.ProbeInterval = v
						}
					}
				case "probe-count":
					if len(prop.Keys) >= 2 {
						if v, err := strconv.Atoi(prop.Keys[1]); err == nil {
							test.ProbeCount = v
						}
					}
				case "test-interval":
					if len(prop.Keys) >= 2 {
						if v, err := strconv.Atoi(prop.Keys[1]); err == nil {
							test.TestInterval = v
						}
					}
				case "thresholds":
					for _, th := range prop.Children {
						if th.Name() == "successive-loss" && len(th.Keys) >= 2 {
							if v, err := strconv.Atoi(th.Keys[1]); err == nil {
								test.ThresholdSuccessive = v
							}
						}
					}
				case "destination-port":
					if len(prop.Keys) >= 2 {
						if v, err := strconv.Atoi(prop.Keys[1]); err == nil {
							test.DestPort = v
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
	v9Node := node.FindChild("version9")
	if v9Node == nil {
		return nil
	}

	v9cfg := &NetFlowV9Config{
		Templates: make(map[string]*NetFlowV9Template),
	}

	for _, tmplNode := range v9Node.FindChildren("template") {
		if len(tmplNode.Keys) < 2 {
			continue
		}
		tmpl := &NetFlowV9Template{Name: tmplNode.Keys[1]}

		for _, prop := range tmplNode.Children {
			switch prop.Name() {
			case "flow-active-timeout":
				if len(prop.Keys) >= 2 {
					if v, err := strconv.Atoi(prop.Keys[1]); err == nil {
						tmpl.FlowActiveTimeout = v
					}
				}
			case "flow-inactive-timeout":
				if len(prop.Keys) >= 2 {
					if v, err := strconv.Atoi(prop.Keys[1]); err == nil {
						tmpl.FlowInactiveTimeout = v
					}
				}
			case "template-refresh-rate":
				// Two forms:
				// "template-refresh-rate 60;" (flat) → prop.Keys = ["template-refresh-rate", "60"]
				// "template-refresh-rate { seconds 60; }" (hierarchical)
				if len(prop.Keys) >= 2 {
					if v, err := strconv.Atoi(prop.Keys[1]); err == nil {
						tmpl.TemplateRefreshRate = v
					}
				}
				if secNode := prop.FindChild("seconds"); secNode != nil && len(secNode.Keys) >= 2 {
					if v, err := strconv.Atoi(secNode.Keys[1]); err == nil {
						tmpl.TemplateRefreshRate = v
					}
				}
			}
		}

		v9cfg.Templates[tmpl.Name] = tmpl
	}

	svc.FlowMonitoring = &FlowMonitoringConfig{Version9: v9cfg}
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

	return nil
}

func compileSampling(node *Node, fo *ForwardingOptionsConfig) error {
	sc := &SamplingConfig{
		Instances: make(map[string]*SamplingInstance),
	}

	for _, instNode := range node.FindChildren("instance") {
		if len(instNode.Keys) < 2 {
			continue
		}
		inst := &SamplingInstance{Name: instNode.Keys[1]}

		inputNode := instNode.FindChild("input")
		if inputNode != nil {
			for _, prop := range inputNode.Children {
				if prop.Name() == "rate" && len(prop.Keys) >= 2 {
					if v, err := strconv.Atoi(prop.Keys[1]); err == nil {
						inst.InputRate = v
					}
				}
			}
		}

		for _, familyNode := range instNode.FindChildren("family") {
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
			if len(child.Keys) >= 2 {
				fs := &FlowServer{Address: child.Keys[1]}
				for _, prop := range child.Children {
					switch prop.Name() {
					case "port":
						if len(prop.Keys) >= 2 {
							if v, err := strconv.Atoi(prop.Keys[1]); err == nil {
								fs.Port = v
							}
						}
					case "version9-template":
						if len(prop.Keys) >= 2 {
							fs.Version9Template = prop.Keys[1]
						}
					case "source-address":
						if len(prop.Keys) >= 2 {
							sf.SourceAddress = prop.Keys[1]
						}
					}
				}
				sf.FlowServers = append(sf.FlowServers, fs)
			}
		case "inline-jflow":
			sf.InlineJflow = true
		}
	}

	return sf
}

func compileDHCPRelay(node *Node, fo *ForwardingOptionsConfig) error {
	relay := &DHCPRelayConfig{
		ServerGroups: make(map[string]*DHCPRelayServerGroup),
		Groups:       make(map[string]*DHCPRelayGroup),
	}

	for _, sgNode := range node.FindChildren("server-group") {
		if len(sgNode.Keys) < 2 {
			continue
		}
		sg := &DHCPRelayServerGroup{Name: sgNode.Keys[1]}
		// Servers can be in remaining keys or children
		for _, k := range sgNode.Keys[2:] {
			sg.Servers = append(sg.Servers, k)
		}
		for _, child := range sgNode.Children {
			if len(child.Keys) >= 1 {
				sg.Servers = append(sg.Servers, child.Keys[0])
			}
		}
		relay.ServerGroups[sg.Name] = sg
	}

	for _, gNode := range node.FindChildren("group") {
		if len(gNode.Keys) < 2 {
			continue
		}
		g := &DHCPRelayGroup{Name: gNode.Keys[1]}
		for _, prop := range gNode.Children {
			switch prop.Name() {
			case "interface":
				if len(prop.Keys) >= 2 {
					g.Interfaces = append(g.Interfaces, prop.Keys[1])
				}
			case "active-server-group":
				if len(prop.Keys) >= 2 {
					g.ActiveServerGroup = prop.Keys[1]
				}
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
	}

	for _, child := range node.Children {
		switch child.Name() {
		case "location":
			if len(child.Keys) >= 2 {
				snmp.Location = child.Keys[1]
			}
		case "contact":
			if len(child.Keys) >= 2 {
				snmp.Contact = child.Keys[1]
			}
		case "description":
			if len(child.Keys) >= 2 {
				snmp.Description = child.Keys[1]
			}
		case "community":
			if len(child.Keys) >= 2 {
				comm := &SNMPCommunity{Name: child.Keys[1]}
				for _, prop := range child.Children {
					if prop.Name() == "authorization" && len(prop.Keys) >= 2 {
						comm.Authorization = prop.Keys[1]
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
			if len(child.Keys) >= 2 {
				tg := &SNMPTrapGroup{Name: child.Keys[1]}
				for _, prop := range child.Children {
					if prop.Name() == "targets" && len(prop.Keys) >= 2 {
						tg.Targets = append(tg.Targets, prop.Keys[1])
					}
				}
				snmp.TrapGroups[tg.Name] = tg
			}
		}
	}

	sys.SNMP = snmp
	return nil
}

func compileSchedulers(node *Node, cfg *Config) error {
	if cfg.Schedulers == nil {
		cfg.Schedulers = make(map[string]*SchedulerConfig)
	}

	for _, schedNode := range node.FindChildren("scheduler") {
		if len(schedNode.Keys) < 2 {
			continue
		}
		sched := &SchedulerConfig{Name: schedNode.Keys[1]}

		for _, prop := range schedNode.Children {
			switch prop.Name() {
			case "start-time":
				if len(prop.Keys) >= 2 {
					sched.StartTime = prop.Keys[1]
				}
			case "stop-time":
				if len(prop.Keys) >= 2 {
					sched.StopTime = prop.Keys[1]
				}
			case "start-date":
				if len(prop.Keys) >= 2 {
					sched.StartDate = prop.Keys[1]
				}
			case "stop-date":
				if len(prop.Keys) >= 2 {
					sched.StopDate = prop.Keys[1]
				}
			case "daily":
				sched.Daily = true
			}
		}

		cfg.Schedulers[sched.Name] = sched
	}
	return nil
}
