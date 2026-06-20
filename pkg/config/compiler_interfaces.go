package config

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// vrrpGroupPropertyKeywords are the property keywords recognized inside
// a vrrp-group block. Used to delimit multi-value runs (virtual-address)
// when properties are packed into a single node's Keys (#1813).
var vrrpGroupPropertyKeywords = map[string]bool{
	"virtual-address":     true,
	"priority":            true,
	"preempt":             true,
	"accept-data":         true,
	"advertise-interval":  true,
	"authentication-type": true,
	"authentication-key":  true,
	"track-interface":     true,
	"track-priority-cost": true,
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

		// Interface bandwidth (bits per second)
		if bwNode := child.FindChild("bandwidth"); bwNode != nil {
			if v := nodeVal(bwNode); v != "" {
				ifc.Bandwidth = parseBandwidthBps(v)
			}
		}

		// Check for vlan-tagging flag
		if child.FindChild("vlan-tagging") != nil {
			ifc.VlanTagging = true
		}

		// Check for flexible-vlan-tagging flag (QinQ)
		if child.FindChild("flexible-vlan-tagging") != nil {
			ifc.FlexibleVlanTagging = true
		}

		// Check for encapsulation
		if encapNode := child.FindChild("encapsulation"); encapNode != nil {
			ifc.Encapsulation = nodeVal(encapNode)
		}

		// Check for gigether-options redundant-parent and 802.3ad LAG member
		if goNode := child.FindChild("gigether-options"); goNode != nil {
			if rpNode := goNode.FindChild("redundant-parent"); rpNode != nil {
				ifc.RedundantParent = nodeVal(rpNode)
			}
			if adNode := goNode.FindChild("802.3ad"); adNode != nil {
				ifc.LAGParent = nodeVal(adNode)
			}
		}

		// Check for aggregated-ether-options (LAG/ae interface)
		if aeoNode := child.FindChild("aggregated-ether-options"); aeoNode != nil {
			opts := &AggregatedEtherOptions{}
			if lacpNode := aeoNode.FindChild("lacp"); lacpNode != nil {
				if lacpNode.FindChild("active") != nil {
					opts.LACPActive = true
				}
				if lacpNode.FindChild("passive") != nil {
					opts.LACPPassive = true
				}
				if periodicNode := lacpNode.FindChild("periodic"); periodicNode != nil {
					opts.LACPPeriodic = nodeVal(periodicNode)
				}
			}
			if lsNode := aeoNode.FindChild("link-speed"); lsNode != nil {
				opts.LinkSpeed = nodeVal(lsNode)
			}
			if mlNode := aeoNode.FindChild("minimum-links"); mlNode != nil {
				if v := nodeVal(mlNode); v != "" {
					opts.MinimumLinks, _ = strconv.Atoi(v)
				}
			}
			ifc.AggregatedEtherOpts = opts
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
			if len(ifc.FabricMembers) > 0 {
				ifc.BondMode = "active-backup"
			}
		}

		// Check for interface-level tunnel configuration
		tunnelNode := child.FindChild("tunnel")
		if tunnelNode != nil {
			// Default mode based on interface name prefix: ip-X/X/X → ipip, gr-X/X/X → gre
			defaultMode := "gre"
			if strings.HasPrefix(ifName, "ip-") {
				defaultMode = "ipip"
			}
			tc := &TunnelConfig{
				Name: LinuxIfName(ifName),
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
				case "wireguard":
					parseTunnelWireguard(tc, prop)
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
				defaultMode := "gre"
				if strings.HasPrefix(ifName, "ip-") {
					defaultMode = "ipip"
				}
				// Per-unit tunnel: each unit with its own tunnel config gets
				// a separate Linux interface. Unit 0 uses the base name,
				// unit N>0 appends "uN".
				linuxName := LinuxIfName(ifName)
				if unitNum > 0 {
					linuxName = linuxName + "u" + strconv.Itoa(unitNum)
				}
				tc := &TunnelConfig{Name: linuxName, Mode: defaultMode}
				// Inherit from interface-level tunnel if present
				if ifc.Tunnel != nil {
					*tc = *ifc.Tunnel
					tc.Name = linuxName
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
					case "mode":
						if v := nodeVal(prop); v != "" {
							tc.Mode = v
						}
					case "key":
						if v := nodeVal(prop); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								tc.Key = uint32(n)
							}
						}
					case "ttl":
						if v := nodeVal(prop); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								tc.TTL = n
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
					case "wireguard":
						parseTunnelWireguard(tc, prop)
					}
				}
				unit.Tunnel = tc
			}

			// Parse vlan-id on unit
			if vlanNode := unitInst.node.FindChild("vlan-id"); vlanNode != nil {
				if v := nodeVal(vlanNode); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						unit.VlanID = n
					}
				}
			}

			// Parse inner-vlan-id on unit (QinQ inner tag)
			if ivNode := unitInst.node.FindChild("inner-vlan-id"); ivNode != nil {
				if v := nodeVal(ivNode); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						unit.InnerVlanID = n
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
							// Parse VRRP groups under address. Handles both AST
							// shapes (#1796): properties as child nodes
							// (hierarchical blocks + schema-structured flat-set)
							// AND properties packed into the instance node's
							// Keys[2:] (legacy flat-set leaves, one leaf per
							// `set ... vrrp-group <id> <prop> <value>` line —
							// merged into one group instead of last-leaf-wins).
							for _, vrrpInst := range namedInstances(addrInst.node.FindChildren("vrrp-group")) {
								groupID, err := strconv.Atoi(vrrpInst.name)
								if err != nil {
									continue
								}
								if unit.VRRPGroups == nil {
									unit.VRRPGroups = make(map[string]*VRRPGroup)
								}
								key := fmt.Sprintf("%s_grp%d", addrInst.name, groupID)
								vg := unit.VRRPGroups[key]
								if vg == nil {
									vg = &VRRPGroup{
										ID:       groupID,
										Priority: 100, // default
									}
									unit.VRRPGroups[key] = vg
								}
								// Keys-encoded properties (flat-set leaf shape):
								// Keys = ["vrrp-group", "<id>", prop, value, ...].
								keys := vrrpInst.node.Keys
								for i := 2; i < len(keys); i++ {
									switch keys[i] {
									case "virtual-address":
										// Multi-value (#1813): consume every
										// following token up to the next
										// recognized property keyword —
										// `vrrp-group 1 virtual-address
										// [ a b ];` packs all addresses
										// inline.
										for i+1 < len(keys) && !vrrpGroupPropertyKeywords[keys[i+1]] {
											i++
											vg.VirtualAddresses = append(vg.VirtualAddresses, keys[i])
										}
									case "priority":
										if i+1 < len(keys) {
											i++
											vg.Priority, _ = strconv.Atoi(keys[i])
										}
									case "preempt":
										vg.Preempt = true
									case "accept-data":
										vg.AcceptData = true
									case "advertise-interval":
										if i+1 < len(keys) {
											i++
											vg.AdvertiseInterval, _ = strconv.Atoi(keys[i])
										}
									case "authentication-type":
										if i+1 < len(keys) {
											i++
											vg.AuthType = keys[i]
										}
									case "authentication-key":
										if i+1 < len(keys) {
											i++
											vg.AuthKey = Secret(keys[i])
										}
									case "track-interface":
										if i+1 < len(keys) {
											i++
											// First-wins (#1814): duplicates in
											// the Keys-packed spelling are
											// rejected/warned by the AST
											// pre-walk; keep the first here so
											// lenient semantics are consistent
											// with the child-node prune.
											if vg.TrackInterface == "" {
												vg.TrackInterface = keys[i]
											}
										}
									case "track-priority-cost":
										if i+1 < len(keys) {
											i++
											vg.TrackPriorityDelta, _ = parseTrackCost(keys[i])
										}
									}
								}
								// Child-node properties (hierarchical blocks and
								// schema-structured flat-set containers).
								// Track-interface values are gathered and applied
								// AFTER the loop so the nested
								// `track-interface <if> { priority-cost <n>; }`
								// form wins over the legacy flat sibling
								// `track-priority-cost <n>` regardless of node
								// order (#1814 — the loop is source-order based).
								var (
									trackIface          string
									trackIfaceSet       bool
									nestedTrackCost     int
									nestedTrackCostSet  bool
									siblingTrackCost    int
									siblingTrackCostSet bool
								)
								for _, prop := range vrrpInst.node.Children {
									switch prop.Name() {
									case "virtual-address":
										// Multi-value spellings (#1813):
										// bracketed `virtual-address [ a b ];`
										// packs all addresses into Keys[1:]
										// (flat-set replay may carry trailing
										// values as children); braced block
										// `virtual-address { a; b; }` holds
										// one child per address. nodeVal kept
										// only the first of each.
										for _, k := range prop.Keys[1:] {
											vg.VirtualAddresses = append(vg.VirtualAddresses, k)
										}
										for _, child := range prop.Children {
											if v := child.Name(); v != "" {
												vg.VirtualAddresses = append(vg.VirtualAddresses, v)
											}
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
										vg.AuthKey = Secret(nodeVal(prop))
									case "track-interface":
										// The interface name lives in Keys[1]
										// (NOT nodeVal — its Children[0]
										// fallback would misread the nested
										// priority-cost child as the name).
										if len(prop.Keys) >= 2 {
											trackIface = prop.Keys[1]
											trackIfaceSet = true
										}
										// Nested form (#1814): standard Junos
										// `track-interface <if> { priority-cost <n>; }`.
										if pc := prop.FindChild("priority-cost"); pc != nil {
											if v := nodeVal(pc); v != "" {
												if n, ok := parseTrackCost(v); ok {
													nestedTrackCost = n
													nestedTrackCostSet = true
												}
											}
										}
									case "track-priority-cost":
										if v := nodeVal(prop); v != "" {
											if n, ok := parseTrackCost(v); ok {
												siblingTrackCost = n
												siblingTrackCostSet = true
											}
										}
									}
								}
								if trackIfaceSet {
									vg.TrackInterface = trackIface
								}
								if siblingTrackCostSet {
									vg.TrackPriorityDelta = siblingTrackCost
								}
								if nestedTrackCostSet {
									// Nested wins over the legacy sibling,
									// independent of node order.
									vg.TrackPriorityDelta = nestedTrackCost
								}
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
			if unit.Tunnel != nil {
				// Per-unit tunnel: addresses belong to this specific tunnel
				unit.Tunnel.Addresses = append(unit.Tunnel.Addresses, unit.Addresses...)
			} else if ifc.Tunnel != nil {
				// Interface-level tunnel: all unit addresses go to shared tunnel
				ifc.Tunnel.Addresses = append(ifc.Tunnel.Addresses, unit.Addresses...)
			}
		}

		ifaces.Interfaces[ifName] = ifc
	}
	return nil
}

// parseTunnelWireguard fills the WireGuard fields on tc from a
// `wireguard { ... }` node under a tunnel stanza (#1432 S2a). The
// minimal generic grammar is:
//
//	tunnel {
//	    mode wireguard;
//	    wireguard {
//	        listen-port 51820;
//	        private-key <64-hex>;
//	        peer {
//	            public-key <64-hex>;
//	            allowed-ips <cidr>;   # repeatable
//	            endpoint <ip:port>;
//	            persistent-keepalive <secs>;
//	        }
//	    }
//	}
//
// This is intentionally narrower than the eventual Junos wireguard
// grammar (S6); it compiles to the TunnelEndpointSnapshot Wg* DTO
// fields without committing to that surface.
func parseTunnelWireguard(tc *TunnelConfig, wgNode *Node) {
	for _, prop := range wgNode.Children {
		switch prop.Name() {
		case "listen-port":
			if v := nodeVal(prop); v != "" {
				if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 65535 {
					tc.WgListenPort = uint16(n)
				}
			}
		case "private-key":
			if v := nodeVal(prop); v != "" {
				tc.WgLocalPrivkeyHex = Secret(v)
			}
		case "peer":
			parseTunnelWireguardPeer(tc, prop)
		}
	}
}

func parseTunnelWireguardPeer(tc *TunnelConfig, peerNode *Node) {
	for _, prop := range peerNode.Children {
		switch prop.Name() {
		case "public-key":
			if v := nodeVal(prop); v != "" {
				tc.WgPeerPubkeyHex = v
			}
		case "allowed-ips":
			if v := nodeVal(prop); v != "" {
				tc.WgAllowedIPs = append(tc.WgAllowedIPs, v)
			}
		case "endpoint":
			if v := nodeVal(prop); v != "" {
				tc.WgEndpoint = v
			}
		case "persistent-keepalive":
			if v := nodeVal(prop); v != "" {
				if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 65535 {
					tc.WgKeepaliveSecs = uint16(n)
				}
			}
		}
	}
}

// selectMSSToken returns the raw MSS token the compiler would actually
// select for a tcp-mss kind node (ipsec-vpn / gre-in / gre-out / all-tcp),
// using the SAME precedence as parseMSSValue: the hierarchical `mss` child's
// Keys[1] FIRST (if present), else the node's own flat Keys[1]. The bool is
// false when neither position carries a token. #1979 Layer B shares this so
// the Tier-3 commit-time validator (validateTCPMSSRanges) can never diverge
// from what the compiler reads — it must range-check the SELECTED value, not
// "both positions" (a mixed shape like `gre-in 70000 { mss 1360; }` compiles
// the child 1360 and discards the flat 70000, so validating both would
// wrongly reject it).
func selectMSSToken(node *Node) (string, bool) {
	// Hierarchical: ipsec-vpn { mss 1360; } or gre-in { mss 1360; }.
	// Prefer the child ONLY when it parses — an unparseable child
	// (e.g. `gre-in 1360 { mss bogus; }`) must fall through to the flat
	// token so the value selected here matches what parseMSSValue/the
	// compiler actually use (the flat 1360), not the discarded child.
	// Returning the unparseable child unconditionally was a precedence
	// regression vs the original parseMSSValue (#1979).
	if mssChild := node.FindChild("mss"); mssChild != nil && len(mssChild.Keys) >= 2 {
		if _, err := strconv.Atoi(mssChild.Keys[1]); err == nil {
			return mssChild.Keys[1], true
		}
	}
	// Flat: ipsec-vpn 1360; (set syntax)
	if len(node.Keys) >= 2 {
		return node.Keys[1], true
	}
	return "", false
}

// parseMSSValue extracts MSS value from either "node { mss VALUE; }" or "node VALUE;" syntax.
func parseMSSValue(node *Node) int {
	tok, ok := selectMSSToken(node)
	if !ok {
		return 0
	}
	if v, err := strconv.Atoi(tok); err == nil {
		return v
	}
	return 0
}

// validateVRRPTrackInterfaceAST walks the (group-expanded) AST and
// enforces the single-track-interface invariant per vrrp-group (#1814).
//
// Strict path (commit / commit-check, lenient=false): more than one
// track-interface statement inside a single vrrp-group is a hard
// compile error — single-interface tracking is what the runtime
// implements, and silently last-winsing the extras would hide it.
//
// Lenient path (load / peer-sync, lenient=true): the extra
// track-interface children are pruned IN PLACE (the tree is already a
// clone — same contract as sanitizeNodesControlChars) so the compiler
// deterministically sees only the FIRST, and a warning is returned.
//
// Shape-only warnings emitted on BOTH paths (the typed config cannot
// distinguish these post-compile):
//   - nested `priority-cost` AND legacy sibling `track-priority-cost`
//     both present (nested wins);
//   - an orphan `priority-cost` child directly under the vrrp-group
//     (only valid nested under track-interface).
func validateVRRPTrackInterfaceAST(nodes []*Node, prefix string, lenient bool) ([]string, error) {
	var warnings []string
	for _, n := range nodes {
		nodePath := joinNodePath(prefix, n.Keys)
		if n.Name() == "vrrp-group" {
			w, err := checkVRRPGroupTrackShape(n, nodePath, lenient)
			warnings = append(warnings, w...)
			if err != nil {
				return nil, err
			}
		}
		w, err := validateVRRPTrackInterfaceAST(n.Children, nodePath, lenient)
		warnings = append(warnings, w...)
		if err != nil {
			return nil, err
		}
	}
	return warnings, nil
}

// parseTrackCost parses a priority-cost value, returning 0 (tracking
// has no effect) for anything outside the schema's 1..254 range — a
// negative cost would RAISE priority on link-down (Codex review on PR
// #1821). The AST pre-walk rejects out-of-range values on strict
// commits and warns on lenient loads; this keeps the lenient compile
// consistent with that warning.
func parseTrackCost(v string) (int, bool) {
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 254 {
		return 0, false
	}
	return n, true
}

// checkVRRPGroupTrackShape applies the #1814 track-interface shape
// checks to a single vrrp-group node. See validateVRRPTrackInterfaceAST.
func checkVRRPGroupTrackShape(vg *Node, nodePath string, lenient bool) ([]string, error) {
	var warnings []string
	// Keys-packed compact spelling (Codex review on PR #1821): a
	// hierarchical leaf like `vrrp-group 1 track-interface ge-0/0/1
	// track-interface ge-0/0/2;` packs duplicates into the node's own
	// Keys, bypassing the child-node count below. Count those too; the
	// compiler's keys walk is first-wins, so lenient semantics match.
	keysPacked := 0
	for _, k := range vg.Keys {
		if k == "track-interface" {
			keysPacked++
		}
	}
	tracks := vg.FindChildren("track-interface")
	if total := keysPacked + len(tracks); total > 1 {
		if !lenient {
			return nil, fmt.Errorf("%s: %d track-interface statements; only one tracked interface is supported per vrrp-group", nodePath, total)
		}
		if keysPacked > 0 {
			// Child-node duplicates are warned by the prune below; the
			// Keys-packed spelling needs its own warning (the compiler
			// keys walk is first-wins).
			warnings = append(warnings, fmt.Sprintf("%s: %d track-interface statements; keeping the first and ignoring the rest (#1814)", nodePath, total))
		}
	}
	if len(tracks) > 1 {
		if !lenient {
			return nil, fmt.Errorf("%s: %d track-interface statements; only one tracked interface is supported per vrrp-group", nodePath, len(tracks))
		}
		// First-wins: prune every track-interface child after the first.
		kept := false
		pruned := vg.Children[:0]
		for _, c := range vg.Children {
			if c.Name() == "track-interface" {
				if kept {
					continue
				}
				kept = true
			}
			pruned = append(pruned, c)
		}
		vg.Children = pruned
		warnings = append(warnings, fmt.Sprintf("%s: %d track-interface statements; keeping the first (%s) and ignoring the rest (#1814)", nodePath, len(tracks), nodeVal(tracks[0])))
		tracks = tracks[:1]
	}
	if len(tracks) == 1 && tracks[0].FindChild("priority-cost") != nil && vg.FindChild("track-priority-cost") != nil {
		warnings = append(warnings, fmt.Sprintf("%s: both nested track-interface priority-cost and legacy track-priority-cost are configured; the nested priority-cost wins", nodePath))
	}
	if vg.FindChild("priority-cost") != nil {
		warnings = append(warnings, fmt.Sprintf("%s: priority-cost is only valid nested under track-interface; this statement has no effect", nodePath))
	}
	// Range-validate every cost spelling (Codex review on PR #1821):
	// the schema advertises <1..254> but nothing enforced it, and a
	// negative cost would RAISE priority on link-down. Strict commit
	// rejects; lenient load warns (the compiler clamp keeps runtime
	// safe either way via getPriority's [1,254] clamp, but a raised
	// priority is a semantic inversion worth refusing).
	costCheck := func(val, spelling string) error {
		n, err := strconv.Atoi(val)
		if err != nil || n < 1 || n > 254 {
			if !lenient {
				return fmt.Errorf("%s: %s %q out of range; must be 1..254", nodePath, spelling, val)
			}
			warnings = append(warnings, fmt.Sprintf("%s: %s %q out of range (1..254); ignoring tracking cost", nodePath, spelling, val))
		}
		return nil
	}
	// Validate EVERY occurrence, not just the first (Codex confirm
	// round on PR #1821): a duplicate invalid child after a valid one
	// must not bypass the strict reject.
	for _, tr := range tracks {
		for _, pc := range tr.FindChildren("priority-cost") {
			if len(pc.Keys) > 1 {
				if err := costCheck(pc.Keys[1], "priority-cost"); err != nil {
					return nil, err
				}
			}
		}
	}
	for _, tpc := range vg.FindChildren("track-priority-cost") {
		if len(tpc.Keys) > 1 {
			if err := costCheck(tpc.Keys[1], "track-priority-cost"); err != nil {
				return nil, err
			}
		}
	}
	for i, k := range vg.Keys {
		if (k == "track-priority-cost" || k == "priority-cost") && i+1 < len(vg.Keys) {
			if err := costCheck(vg.Keys[i+1], k); err != nil {
				return nil, err
			}
		}
	}
	return warnings, nil
}

// vrrpTrackConfigWarnings derives operator-visible interface-tracking
// warnings from the compiled typed config (#1814). Emitted on both the
// strict and lenient paths so a tracking misconfiguration is never a
// silent no-op:
//   - track-interface without any priority-cost (nested or legacy
//     sibling) has no effect;
//   - track-priority-cost without track-interface has no effect;
//   - priority 255 marks the address owner — the runtime ignores
//     tracking there (an owner stepping down while still holding the
//     address invites duplicate-IP conflicts).
//
// Iteration is sorted at every level so warning order is deterministic.
func vrrpTrackConfigWarnings(cfg *Config) []string {
	var warnings []string
	ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		ifNames = append(ifNames, name)
	}
	sort.Strings(ifNames)
	for _, ifName := range ifNames {
		ifc := cfg.Interfaces.Interfaces[ifName]
		unitNums := make([]int, 0, len(ifc.Units))
		for n := range ifc.Units {
			unitNums = append(unitNums, n)
		}
		sort.Ints(unitNums)
		for _, un := range unitNums {
			unit := ifc.Units[un]
			groupKeys := make([]string, 0, len(unit.VRRPGroups))
			for k := range unit.VRRPGroups {
				groupKeys = append(groupKeys, k)
			}
			sort.Strings(groupKeys)
			for _, gk := range groupKeys {
				vg := unit.VRRPGroups[gk]
				loc := fmt.Sprintf("interfaces %s unit %d vrrp-group %d", ifName, un, vg.ID)
				switch {
				case vg.TrackInterface != "" && vg.TrackPriorityDelta == 0:
					warnings = append(warnings, fmt.Sprintf("%s: track-interface %s without priority-cost has no effect", loc, vg.TrackInterface))
				case vg.TrackInterface == "" && vg.TrackPriorityDelta != 0:
					warnings = append(warnings, fmt.Sprintf("%s: track-priority-cost without track-interface has no effect", loc))
				case vg.TrackInterface != "" && vg.Priority == 255:
					warnings = append(warnings, fmt.Sprintf("%s: interface tracking is ignored for the address owner (priority 255)", loc))
				}
			}
		}
	}
	return warnings
}
