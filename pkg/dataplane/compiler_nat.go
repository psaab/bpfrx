package dataplane

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// resolveSNATMatchAddr resolves a SNAT match CIDR to an address ID.
// If the CIDR already exists as an address-book entry, reuses that ID.
// Otherwise, creates an implicit address-book entry with a synthetic name.
// Returns 0 (any) if the CIDR is empty.
func resolveSNATMatchAddr(dp DataPlane, cidr string, result *CompileResult) (uint32, error) {
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

	if err := dp.SetAddressBookEntry(cidr, addrID); err != nil {
		return 0, fmt.Errorf("set implicit address %s: %w", cidr, err)
	}
	if err := dp.SetAddressMembership(addrID, addrID); err != nil {
		return 0, fmt.Errorf("set self-membership for implicit %s: %w", cidr, err)
	}

	slog.Debug("implicit SNAT match address created", "cidr", cidr, "id", addrID)
	return addrID, nil
}

func compileNAT(dp DataPlane, cfg *config.Config, result *CompileResult) error {
	// Track written keys for populate-before-clear.
	writtenSNAT := make(map[SNATKey]bool)
	writtenSNATv6 := make(map[SNATKey]bool)
	writtenDNAT := make(map[DNATKey]bool)
	writtenDNATv6 := make(map[DNATKeyV6]bool)

	// Clear stale persistent NAT pool configs before recompilation
	if pnat := dp.GetPersistentNAT(); pnat != nil {
		pnat.ClearPoolConfigs()
	}

	natCfg := &cfg.Security.NAT

	// Clear stale SNAT egress IP map before repopulating.
	dp.ClearSNATEgressIPs()

	// Source NAT: allocate pool IDs and compile pools + rules
	poolID := uint8(0)

	// Track per-zone-pair v4/v6 rule indices for multiple SNAT rules
	type zonePairIdx struct{ from, to uint16 }
	v4RuleIdx := make(map[zonePairIdx]uint16)
	v6RuleIdx := make(map[zonePairIdx]uint16)

	// Cache compiled pool data to skip redundant parse+write when the same
	// named pool is referenced by multiple SNAT rules.
	type compiledPoolInfo struct {
		hasV4, hasV6 bool
	}
	compiledPools := make(map[string]*compiledPoolInfo)

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
			if !rule.Then.Interface && rule.Then.PoolName == "" && !rule.Then.Off {
				slog.Warn("SNAT rule has no action",
					"rule", rule.Name, "rule-set", rs.Name)
				continue
			}

			// source-nat off: write exemption rule (no pool allocation)
			if rule.Then.Off {
				// Resolve source addresses (supports bracket lists)
				srcAddrs := rule.Match.SourceAddresses
				if len(srcAddrs) == 0 {
					srcAddrs = []string{rule.Match.SourceAddress}
				}

				// Resolve destination addresses (supports bracket lists)
				dstAddrs := rule.Match.DestinationAddresses
				if len(dstAddrs) == 0 {
					dstAddrs = []string{rule.Match.DestinationAddress}
				}

				zp := zonePairIdx{fromZone, toZone}
				ruleKey := rs.Name + "/" + rule.Name
				counterID := result.nextNATCounterID
				if counterID >= MaxNATRuleCounters {
					slog.Warn("NAT rule counter IDs exhausted, reusing counter 0",
						"rule-set", rs.Name, "rule", rule.Name,
						"counter_id", counterID, "max", MaxNATRuleCounters)
					counterID = 0
				}
				result.NATCounterIDs[ruleKey] = counterID
				if counterID != 0 {
					result.nextNATCounterID++
				}

				for _, srcAddr := range srcAddrs {
					srcAddrID, err := resolveSNATMatchAddr(dp, srcAddr, result)
					if err != nil {
						return fmt.Errorf("snat rule %s/%s source match %q: %w",
							rs.Name, rule.Name, srcAddr, err)
					}
					for _, dstAddr := range dstAddrs {
						dstAddrID, err := resolveSNATMatchAddr(dp, dstAddr, result)
						if err != nil {
							return fmt.Errorf("snat rule %s/%s dest match %q: %w",
								rs.Name, rule.Name, dstAddr, err)
						}

						// Write v4 rule
						val := SNATValue{
							Mode:      SNATModeOff,
							SrcAddrID: srcAddrID,
							DstAddrID: dstAddrID,
							CounterID: counterID,
						}
						ri := v4RuleIdx[zp]
						if err := dp.SetSNATRule(fromZone, toZone, ri, val); err != nil {
							return fmt.Errorf("set snat off rule %s/%s: %w",
								rs.Name, rule.Name, err)
						}
						writtenSNAT[SNATKey{FromZone: fromZone, ToZone: toZone, RuleIdx: ri}] = true
						v4RuleIdx[zp] = ri + 1

						// Write v6 rule
						val6 := SNATValueV6{
							Mode:      SNATModeOff,
							SrcAddrID: srcAddrID,
							DstAddrID: dstAddrID,
							CounterID: counterID,
						}
						ri6 := v6RuleIdx[zp]
						if err := dp.SetSNATRuleV6(fromZone, toZone, ri6, val6); err != nil {
							return fmt.Errorf("set snat_v6 off rule %s/%s: %w",
								rs.Name, rule.Name, err)
						}
						writtenSNATv6[SNATKey{FromZone: fromZone, ToZone: toZone, RuleIdx: ri6}] = true
						v6RuleIdx[zp] = ri6 + 1

						slog.Info("source NAT off rule compiled",
							"rule-set", rs.Name, "rule", rule.Name,
							"from", rs.FromZone, "to", rs.ToZone,
							"counter_id", counterID,
							"src_addr_id", srcAddrID, "dst_addr_id", dstAddrID,
							"src_addr", srcAddr, "dst_addr", dstAddr)
					}
				}
				continue
			}

			var curPoolID uint8
			var hasV4, hasV6 bool

			if rule.Then.Interface {
				// Interface mode: populate snat_egress_ips with per-interface IPs
				// so BPF picks the correct IP based on actual egress ifindex+vlan.
				toZoneCfg, ok := cfg.Security.Zones[rs.ToZone]
				if !ok || len(toZoneCfg.Interfaces) == 0 {
					slog.Warn("to-zone has no interfaces",
						"zone", rs.ToZone, "rule-set", rs.Name)
					continue
				}

				var poolCfg NATPoolConfig
				var v4IPs []net.IP
				var v6IPs []net.IP

				for _, ifaceRef := range toZoneCfg.Interfaces {
					physName, cfgName, unitNum, vlanID := resolveInterfaceRef(ifaceRef, cfg)

					physIface, err := result.cachedInterfaceByName(physName)
					if err != nil {
						slog.Debug("interface not found for SNAT egress",
							"interface", physName, "err", err)
						continue
					}

					var unitV4 net.IP
					var unitV6 net.IP

					ifCfg, ifOK := cfg.Interfaces.Interfaces[cfgName]
					if ifOK && ifCfg.RedundancyGroup > 0 {
						// RETH: read addresses from config (VIPs may not be on this node)
						if unit, uOK := ifCfg.Units[unitNum]; uOK {
							for _, addr := range unit.Addresses {
								ip, _, perr := net.ParseCIDR(addr)
								if perr != nil {
									continue
								}
								if ip4 := ip.To4(); ip4 != nil && unitV4 == nil {
									unitV4 = ip4
								} else if ip.IsGlobalUnicast() && unitV6 == nil {
									unitV6 = ip
								}
							}
						}
					} else {
						// Non-RETH: query live interface
						subName := physName
						if vlanID > 0 {
							subName = fmt.Sprintf("%s.%d", physName, vlanID)
						}
						if ip, ierr := getInterfaceIP(subName, result); ierr == nil {
							unitV4 = ip
						}
						if ip, ierr := getInterfaceIPv6(subName, result); ierr == nil {
							unitV6 = ip
						}
					}

					if unitV4 == nil && unitV6 == nil {
						continue
					}

					// Populate snat_egress_ips for this (ifindex, vlan) pair
					ekey := SNATEgressKey{
						Ifindex: uint32(physIface.Index),
						VlanID:  uint16(vlanID),
					}
					var eval SNATEgressValue
					if unitV4 != nil {
						eval.IPv4 = ipToUint32BE(unitV4)
						v4IPs = append(v4IPs, unitV4)
					}
					if unitV6 != nil {
						eval.IPv6 = ipTo16Bytes(unitV6)
						v6IPs = append(v6IPs, unitV6)
					}
					if err := dp.SetSNATEgressIP(ekey, eval); err != nil {
						slog.Warn("failed to set SNAT egress IP",
							"interface", ifaceRef, "err", err)
					} else {
						slog.Info("SNAT egress IP set",
							"interface", ifaceRef, "ifindex", physIface.Index,
							"vlan", vlanID, "v4", unitV4, "v6", unitV6)
					}
				}

				if len(v4IPs) == 0 && len(v6IPs) == 0 {
					slog.Warn("no IP addresses for interface SNAT",
						"zone", rs.ToZone)
					continue
				}

				poolCfg.InterfaceMode = 1
				poolCfg.PortLow = 1024
				poolCfg.PortHigh = 65535
				curPoolID = poolID
				poolID++
				hasV4 = len(v4IPs) > 0
				hasV6 = len(v6IPs) > 0

				// Write pool IPs + config (interface pools are unique per rule)
				poolCfg.NumIPs = uint16(len(v4IPs))
				poolCfg.NumIPsV6 = uint16(len(v6IPs))
				for i, ip := range v4IPs {
					if i >= int(MaxNATPoolIPsPerPool) {
						break
					}
					if err := dp.SetNATPoolIPV4(uint32(curPoolID), uint32(i), ipToUint32BE(ip)); err != nil {
						return fmt.Errorf("set pool ip v4 %d/%d: %w", curPoolID, i, err)
					}
				}
				for i, ip := range v6IPs {
					if i >= int(MaxNATPoolIPsPerPool) {
						break
					}
					if err := dp.SetNATPoolIPV6(uint32(curPoolID), uint32(i), ipTo16Bytes(ip)); err != nil {
						return fmt.Errorf("set pool ip v6 %d/%d: %w", curPoolID, i, err)
					}
				}
				if natCfg.AddressPersistent {
					poolCfg.AddrPersistent = 1
				}
				if err := dp.SetNATPoolConfig(uint32(curPoolID), poolCfg); err != nil {
					return fmt.Errorf("set pool config %d: %w", curPoolID, err)
				}
			} else {
				// Pool mode: look up named pool
				pool, ok := natCfg.SourcePools[rule.Then.PoolName]
				if !ok {
					return fmt.Errorf("source NAT pool %q not found (rule %q)",
						rule.Then.PoolName, rule.Name)
				}

				// Check if pool was already compiled — skip parse+write, reuse cached info.
				if cp, cached := compiledPools[pool.Name]; cached {
					curPoolID = result.PoolIDs[pool.Name]
					hasV4 = cp.hasV4
					hasV6 = cp.hasV6
				} else {
					// First encounter: assign ID, parse addresses, write maps.
					if existingID, exists := result.PoolIDs[pool.Name]; exists {
						curPoolID = existingID
					} else {
						curPoolID = poolID
						result.PoolIDs[pool.Name] = curPoolID
						poolID++
					}

					var poolCfg NATPoolConfig
					var v4IPs []net.IP
					var v6IPs []net.IP

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

					// Compile deterministic NAT fields
					if pool.Deterministic != nil {
						_, hostNet, err := net.ParseCIDR(pool.Deterministic.HostAddress)
						if err == nil {
							ones, bits := hostNet.Mask.Size()
							portRange := int(poolCfg.PortHigh) - int(poolCfg.PortLow) + 1
							poolCfg.BlockSize = uint16(pool.Deterministic.BlockSize)
							poolCfg.BlocksPerIP = uint16(portRange / pool.Deterministic.BlockSize)

							if bits == 128 {
								// IPv6 host — deterministic mode 2
								poolCfg.Deterministic = 2
								poolCfg.HostPrefixLen = uint8(ones)
								// Subscriber count capped by pool capacity
								poolCfg.HostCount = uint32(len(v4IPs)) * uint32(poolCfg.BlocksPerIP)
								ip16 := hostNet.IP.To16()
								for i := 0; i < 4; i++ {
									poolCfg.HostBaseV6[i] = binary.NativeEndian.Uint32(ip16[i*4 : (i+1)*4])
								}
							} else {
								// IPv4 host — deterministic mode 1
								hostCount := uint32(1) << uint(bits-ones)
								poolCfg.Deterministic = 1
								poolCfg.HostBase = ipToUint32BE(hostNet.IP.To4())
								poolCfg.HostCount = hostCount
							}
						}
					}

					// Write pool IPs to maps
					poolCfg.NumIPs = uint16(len(v4IPs))
					poolCfg.NumIPsV6 = uint16(len(v6IPs))
					for i, ip := range v4IPs {
						if i >= int(MaxNATPoolIPsPerPool) {
							break
						}
						if err := dp.SetNATPoolIPV4(uint32(curPoolID), uint32(i), ipToUint32BE(ip)); err != nil {
							return fmt.Errorf("set pool ip v4 %d/%d: %w", curPoolID, i, err)
						}
					}
					for i, ip := range v6IPs {
						if i >= int(MaxNATPoolIPsPerPool) {
							break
						}
						if err := dp.SetNATPoolIPV6(uint32(curPoolID), uint32(i), ipTo16Bytes(ip)); err != nil {
							return fmt.Errorf("set pool ip v6 %d/%d: %w", curPoolID, i, err)
						}
					}

					if natCfg.AddressPersistent {
						poolCfg.AddrPersistent = 1
					}
					if err := dp.SetNATPoolConfig(uint32(curPoolID), poolCfg); err != nil {
						return fmt.Errorf("set pool config %d: %w", curPoolID, err)
					}

					// Register persistent NAT pool config and IPs
					if pool.PersistentNAT != nil {
						pnat := dp.GetPersistentNAT()
						if pnat != nil {
							timeout := time.Duration(pool.PersistentNAT.InactivityTimeout) * time.Second
							if timeout == 0 {
								timeout = 300 * time.Second
							}
							pnat.SetPoolConfig(pool.Name, PersistentNATPoolInfo{
								Timeout:             timeout,
								PermitAnyRemoteHost: pool.PersistentNAT.PermitAnyRemoteHost,
							})
							for _, ip := range v4IPs {
								addr, ok := netip.AddrFromSlice(ip.To4())
								if ok {
									pnat.RegisterNATIP(addr, pool.Name)
								}
							}
							for _, ip := range v6IPs {
								addr, ok := netip.AddrFromSlice(ip.To16())
								if ok {
									pnat.RegisterNATIP(addr, pool.Name)
								}
							}
							slog.Info("persistent NAT pool registered",
								"pool", pool.Name,
								"timeout", timeout,
								"permit_any_remote_host", pool.PersistentNAT.PermitAnyRemoteHost)
						}
					}

					hasV4 = len(v4IPs) > 0
					hasV6 = len(v6IPs) > 0
					compiledPools[pool.Name] = &compiledPoolInfo{hasV4: hasV4, hasV6: hasV6}
				}
			}

			// Resolve SNAT match addresses (supports bracket lists).
			// Creates one BPF rule per (src, dst) address pair (Cartesian product).
			srcAddrs := rule.Match.SourceAddresses
			if len(srcAddrs) == 0 {
				srcAddrs = []string{rule.Match.SourceAddress}
			}
			dstAddrs := rule.Match.DestinationAddresses
			if len(dstAddrs) == 0 {
				dstAddrs = []string{rule.Match.DestinationAddress}
			}

			zp := zonePairIdx{fromZone, toZone}

			// Assign NAT rule counter ID (shared across expanded address pairs)
			ruleKey := rs.Name + "/" + rule.Name
			counterID := result.nextNATCounterID
			if counterID >= MaxNATRuleCounters {
				slog.Warn("NAT rule counter IDs exhausted, reusing counter 0",
					"rule-set", rs.Name, "rule", rule.Name,
					"counter_id", counterID, "max", MaxNATRuleCounters)
				counterID = 0
			}
			result.NATCounterIDs[ruleKey] = counterID
			if counterID != 0 {
				result.nextNATCounterID++
			}

			for _, srcAddr := range srcAddrs {
				srcAddrID, err := resolveSNATMatchAddr(dp, srcAddr, result)
				if err != nil {
					return fmt.Errorf("snat rule %s/%s source match %q: %w",
						rs.Name, rule.Name, srcAddr, err)
				}
				for _, dstAddr := range dstAddrs {
					dstAddrID, err := resolveSNATMatchAddr(dp, dstAddr, result)
					if err != nil {
						return fmt.Errorf("snat rule %s/%s dest match %q: %w",
							rs.Name, rule.Name, dstAddr, err)
					}

					// Write SNAT rule (v4)
					if hasV4 {
						val := SNATValue{
							Mode:      curPoolID,
							SrcAddrID: srcAddrID,
							DstAddrID: dstAddrID,
							CounterID: counterID,
						}
						ri := v4RuleIdx[zp]
						if err := dp.SetSNATRule(fromZone, toZone, ri, val); err != nil {
							return fmt.Errorf("set snat rule %s/%s: %w",
								rs.Name, rule.Name, err)
						}
						writtenSNAT[SNATKey{FromZone: fromZone, ToZone: toZone, RuleIdx: ri}] = true
						v4RuleIdx[zp] = ri + 1
						slog.Info("source NAT rule compiled",
							"rule-set", rs.Name, "rule", rule.Name,
							"from", rs.FromZone, "to", rs.ToZone,
							"pool_id", curPoolID, "rule_idx", ri,
							"counter_id", counterID,
							"src_addr_id", srcAddrID, "dst_addr_id", dstAddrID,
							"src_addr", srcAddr, "dst_addr", dstAddr)
					}

					// Write SNAT rule (v6)
					if hasV6 {
						val := SNATValueV6{
							Mode:      curPoolID,
							SrcAddrID: srcAddrID,
							DstAddrID: dstAddrID,
							CounterID: counterID,
						}
						ri := v6RuleIdx[zp]
						if err := dp.SetSNATRuleV6(fromZone, toZone, ri, val); err != nil {
							return fmt.Errorf("set snat_v6 rule %s/%s: %w",
								rs.Name, rule.Name, err)
						}
						writtenSNATv6[SNATKey{FromZone: fromZone, ToZone: toZone, RuleIdx: ri}] = true
						v6RuleIdx[zp] = ri + 1
						slog.Info("source NAT v6 rule compiled",
							"rule-set", rs.Name, "rule", rule.Name,
							"from", rs.FromZone, "to", rs.ToZone,
							"pool_id", curPoolID, "rule_idx", ri,
							"counter_id", counterID,
							"src_addr_id", srcAddrID, "dst_addr_id", dstAddrID,
							"src_addr", srcAddr, "dst_addr", dstAddr)
					}
				} // end dstAddr loop
			} // end srcAddr loop
		}
	}

	// Destination NAT
	if natCfg.Destination != nil {
		for _, rs := range natCfg.Destination.RuleSets {
			var fromZone uint16
			if rs.FromZone != "" {
				var ok bool
				fromZone, ok = result.ZoneIDs[rs.FromZone]
				if !ok {
					return fmt.Errorf("destination NAT from-zone %q not found", rs.FromZone)
				}
			}
			for _, rule := range rs.Rules {
				if rule.Then.PoolName == "" {
					continue
				}

				pool, ok := natCfg.Destination.Pools[rule.Then.PoolName]
				if !ok {
					return fmt.Errorf("DNAT pool %q not found (rule %q)",
						rule.Then.PoolName, rule.Name)
				}

				// Validate source-address-name if present (config compatibility)
				if rule.Match.SourceAddressName != "" {
					if _, ok := result.AddrIDs[rule.Match.SourceAddressName]; !ok {
						slog.Warn("DNAT source-address-name not found in address-book",
							"rule", rule.Name, "name", rule.Match.SourceAddressName)
					}
				}

				// Parse match destination address
				if rule.Match.DestinationAddress == "" {
					slog.Warn("DNAT rule has no match destination-address",
						"rule", rule.Name)
					continue
				}

				matchIP, matchNet, err := net.ParseCIDR(rule.Match.DestinationAddress)
				if err != nil {
					// Try as plain IP
					matchIP = net.ParseIP(rule.Match.DestinationAddress)
					if matchIP == nil {
						slog.Warn("invalid DNAT match address",
							"addr", rule.Match.DestinationAddress)
						continue
					}
				} else {
					// DNAT requires exact host match — reject non-host CIDRs.
					ones, bits := matchNet.Mask.Size()
					if (bits == 32 && ones != 32) || (bits == 128 && ones != 128) {
						return fmt.Errorf("DNAT rule %q match destination-address %q is a network prefix, not a host address (use /%d for DNAT)",
							rule.Name, rule.Match.DestinationAddress, bits)
					}
				}

				// Parse pool address
				poolIP, poolNet, err := net.ParseCIDR(pool.Address)
				if err != nil {
					poolIP = net.ParseIP(pool.Address)
					if poolIP == nil {
						slog.Warn("invalid DNAT pool address",
							"addr", pool.Address)
						continue
					}
				} else {
					// DNAT requires exact host address — reject non-host CIDRs.
					ones, bits := poolNet.Mask.Size()
					if (bits == 32 && ones != 32) || (bits == 128 && ones != 128) {
						return fmt.Errorf("DNAT pool %q address %q is a network prefix, not a host address (use /%d for DNAT)",
							pool.Name, pool.Address, bits)
					}
				}

				// Resolve application match to protocol+ports if specified.
				// Supports single apps and multi-term application-sets.
				type dnatAppTerm struct {
					proto string
					ports []int
				}
				var appTerms []dnatAppTerm

				if rule.Match.Application != "" {
					userApps := cfg.Applications.Applications
					// Try single application first
					app, found := config.ResolveApplication(rule.Match.Application, userApps)
					if found {
						appTerms = append(appTerms, dnatAppTerm{proto: app.Protocol, ports: appPortsFromSpec(app.DestinationPort)})
					} else if _, isSet := cfg.Applications.ApplicationSets[rule.Match.Application]; isSet {
						// Expand application-set to individual terms
						expanded, eerr := config.ExpandApplicationSet(rule.Match.Application, &cfg.Applications)
						if eerr != nil {
							slog.Warn("DNAT expand application-set failed",
								"rule", rule.Name, "application", rule.Match.Application, "err", eerr)
						} else {
							for _, termName := range expanded {
								tApp, ok := config.ResolveApplication(termName, userApps)
								if !ok {
									slog.Warn("DNAT application-set term not found",
										"rule", rule.Name, "term", termName)
									continue
								}
								appTerms = append(appTerms, dnatAppTerm{proto: tApp.Protocol, ports: appPortsFromSpec(tApp.DestinationPort)})
							}
						}
					} else {
						slog.Warn("DNAT application not found, ignoring",
							"rule", rule.Name, "application", rule.Match.Application)
					}
				}

				// If no application terms resolved, use explicit match values
				if len(appTerms) == 0 {
					appTerms = []dnatAppTerm{{proto: rule.Match.Protocol, ports: rule.Match.DestinationPorts}}
				}

				for _, term := range appTerms {
					// Build list of destination ports for this term
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

						// Determine protocol(s) to insert DNAT entries for.
						var protos []uint8
						if term.proto != "" {
							protos = []uint8{protocolNumber(term.proto)}
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
									FromZone: fromZone,
								}
								dv := DNATValue{
									NewDstIP:   ipToUint32BE(poolIP),
									NewDstPort: htons(poolPort),
									Flags:      DNATFlagStatic,
								}
								if err := dp.SetDNATEntry(dk, dv); err != nil {
									return fmt.Errorf("set dnat entry %s/%s proto %d: %w",
										rs.Name, rule.Name, proto, err)
								}
								writtenDNAT[dk] = true
							} else {
								dk := DNATKeyV6{
									Protocol: proto,
									DstIP:    ipTo16Bytes(matchIP),
									DstPort:  htons(dstPort),
									FromZone: fromZone,
								}
								dv := DNATValueV6{
									NewDstIP:   ipTo16Bytes(poolIP),
									NewDstPort: htons(poolPort),
									Flags:      DNATFlagStatic,
								}
								if err := dp.SetDNATEntryV6(dk, dv); err != nil {
									return fmt.Errorf("set dnat_v6 entry %s/%s proto %d: %w",
										rs.Name, rule.Name, proto, err)
								}
								writtenDNATv6[dk] = true
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
		}
	}

	// Record highest pool ID so compileNAT64 can auto-assign additional pools.
	result.NextPoolID = poolID

	// Delete stale NAT entries and zero unused pool slots.
	dp.DeleteStaleSNATRules(writtenSNAT)
	dp.DeleteStaleSNATRulesV6(writtenSNATv6)
	dp.DeleteStaleDNATStatic(writtenDNAT)
	dp.DeleteStaleDNATStaticV6(writtenDNATv6)
	dp.ZeroStaleNATPoolConfigs(uint32(poolID))

	return nil
}

func compileStaticNAT(dp DataPlane, cfg *config.Config, result *CompileResult) error {
	// Track written keys for populate-before-clear.
	writtenV4 := make(map[StaticNATKeyV4]bool)
	writtenV6 := make(map[StaticNATKeyV6]bool)

	count := 0
	for _, rs := range cfg.Security.NAT.Static {
		for _, rule := range rs.Rules {
			if rule.IsNPTv6 {
				continue // handled by compileNPTv6
			}
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

			// Validate address family consistency — mixed IPv4/IPv6 is not supported.
			extIsV4 := extIP.To4() != nil
			intIsV4 := intIP.To4() != nil
			if extIsV4 != intIsV4 {
				return fmt.Errorf("static NAT rule %q has mixed address families (match=%s, then=%s)",
					rule.Name, rule.Match, rule.Then)
			}

			// Insert DNAT entry (external -> internal) and SNAT entry (internal -> external)
			if extIsV4 && intIsV4 {
				extU32 := ipToUint32BE(extIP)
				intU32 := ipToUint32BE(intIP)

				if err := dp.SetStaticNATEntryV4(extU32, StaticNATDNAT, intU32); err != nil {
					return fmt.Errorf("set static nat dnat v4 %s: %w", rule.Name, err)
				}
				writtenV4[StaticNATKeyV4{IP: extU32, Direction: StaticNATDNAT}] = true
				if err := dp.SetStaticNATEntryV4(intU32, StaticNATSNAT, extU32); err != nil {
					return fmt.Errorf("set static nat snat v4 %s: %w", rule.Name, err)
				}
				writtenV4[StaticNATKeyV4{IP: intU32, Direction: StaticNATSNAT}] = true
			} else {
				extBytes := ipTo16Bytes(extIP)
				intBytes := ipTo16Bytes(intIP)

				if err := dp.SetStaticNATEntryV6(extBytes, StaticNATDNAT, intBytes); err != nil {
					return fmt.Errorf("set static nat dnat v6 %s: %w", rule.Name, err)
				}
				writtenV6[StaticNATKeyV6{IP: extBytes, Direction: StaticNATDNAT}] = true
				if err := dp.SetStaticNATEntryV6(intBytes, StaticNATSNAT, extBytes); err != nil {
					return fmt.Errorf("set static nat snat v6 %s: %w", rule.Name, err)
				}
				writtenV6[StaticNATKeyV6{IP: intBytes, Direction: StaticNATSNAT}] = true
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

	// Delete stale static NAT entries.
	dp.DeleteStaleStaticNAT(writtenV4, writtenV6)

	return nil
}

// nptv6Adjustment computes the RFC 6296 ones'-complement adjustment
// from two /48 prefixes. The adjustment is stored in native byte order
// to match how BPF reads 16-bit words from memory via pointer cast.
//
// Ones'-complement arithmetic is endian-independent, so the computation
// can use either byte order as long as it's consistent. We use native
// (little-endian on x86) since BPF reads `__u16 *w = (__u16 *)addr`
// in native order.
// nptv6Adjustment computes the ones'-complement adjustment for NPTv6
// prefix translation.  prefixBytes is 6 for /48 or 8 for /64.
func nptv6Adjustment(internal, external []byte) uint16 {
	// Read prefix words in native byte order (same as BPF __u16* cast).
	readWord := func(b []byte) uint16 {
		return uint16(b[1])<<8 | uint16(b[0])
	}

	words := len(internal) / 2

	var sumInt uint32
	for i := 0; i < words; i++ {
		sumInt += uint32(readWord(internal[i*2 : i*2+2]))
	}
	sumInt = (sumInt & 0xFFFF) + (sumInt >> 16)
	sumInt = (sumInt & 0xFFFF) + (sumInt >> 16)

	var sumExt uint32
	for i := 0; i < words; i++ {
		sumExt += uint32(readWord(external[i*2 : i*2+2]))
	}
	sumExt = (sumExt & 0xFFFF) + (sumExt >> 16)
	sumExt = (sumExt & 0xFFFF) + (sumExt >> 16)

	// adjustment = S_int - S_ext = ~S_ext +' S_int
	adj := uint32(^uint16(sumExt)) + uint32(uint16(sumInt))
	adj = (adj & 0xFFFF) + (adj >> 16)
	adj = (adj & 0xFFFF) + (adj >> 16)

	return uint16(adj)
}

func compileNPTv6(dp DataPlane, cfg *config.Config) error {
	written := make(map[NPTv6Key]bool)
	count := 0

	for _, rs := range cfg.Security.NAT.Static {
		for _, rule := range rs.Rules {
			if !rule.IsNPTv6 || rule.Match == "" || rule.Then == "" {
				continue
			}

			// Parse external prefix (match destination-address)
			extIP, extNet, err := net.ParseCIDR(rule.Match)
			if err != nil {
				slog.Warn("nptv6: invalid match prefix", "addr", rule.Match, "err", err)
				continue
			}
			extOnes, _ := extNet.Mask.Size()

			// Parse internal prefix (nptv6-prefix)
			intIP, intNet, err := net.ParseCIDR(rule.Then)
			if err != nil {
				slog.Warn("nptv6: invalid nptv6-prefix", "addr", rule.Then, "err", err)
				continue
			}
			intOnes, _ := intNet.Mask.Size()

			// Validate: both must be same length, /48 or /64 IPv6
			if extOnes != intOnes {
				slog.Warn("nptv6: prefix lengths must match",
					"external", rule.Match, "internal", rule.Then)
				continue
			}
			if extOnes != 48 && extOnes != 64 {
				slog.Warn("nptv6: only /48 and /64 prefix lengths supported",
					"external", rule.Match, "internal", rule.Then)
				continue
			}
			ext16 := extIP.To16()
			int16 := intIP.To16()
			if ext16 == nil || int16 == nil {
				slog.Warn("nptv6: prefixes must be IPv6",
					"external", rule.Match, "internal", rule.Then)
				continue
			}

			// Prefix byte count: 6 for /48, 8 for /64
			prefixBytes := extOnes / 8         // 6 or 8
			prefixWords := uint8(extOnes / 16) // 3 or 4

			// Extract prefix bytes and compute adjustment
			extSlice := ext16[:prefixBytes]
			intSlice := int16[:prefixBytes]
			adj := nptv6Adjustment(intSlice, extSlice)

			// Build keys/values with zero-padded [8]byte prefix
			var extPrefix, intPrefix [8]byte
			copy(extPrefix[:], extSlice)
			copy(intPrefix[:], intSlice)

			// Inbound entry: external prefix → internal prefix (rewrite dst)
			inKey := NPTv6Key{Prefix: extPrefix, Direction: NPTv6Inbound, PrefixLen: uint8(extOnes)}
			inVal := NPTv6Value{XlatPrefix: intPrefix, Adjustment: adj, PrefixWords: prefixWords}
			if err := dp.SetNPTv6Rule(inKey, inVal); err != nil {
				return fmt.Errorf("set nptv6 inbound %s: %w", rule.Name, err)
			}
			written[inKey] = true

			// Outbound entry: internal prefix → external prefix (rewrite src)
			outKey := NPTv6Key{Prefix: intPrefix, Direction: NPTv6Outbound, PrefixLen: uint8(extOnes)}
			outVal := NPTv6Value{XlatPrefix: extPrefix, Adjustment: adj, PrefixWords: prefixWords}
			if err := dp.SetNPTv6Rule(outKey, outVal); err != nil {
				return fmt.Errorf("set nptv6 outbound %s: %w", rule.Name, err)
			}
			written[outKey] = true

			count++
			slog.Info("nptv6 rule compiled",
				"rule-set", rs.Name, "rule", rule.Name,
				"external", rule.Match, "internal", rule.Then,
				"prefix_len", extOnes)
		}
	}

	if count > 0 {
		slog.Info("nptv6 compilation complete", "rules", count)
	}

	dp.DeleteStaleNPTv6(written)
	return nil
}

func compileNAT64(dp DataPlane, cfg *config.Config, result *CompileResult) error {
	// Track written prefixes for populate-before-clear.
	writtenPrefixes := make(map[NAT64PrefixKey]bool)

	ruleSets := cfg.Security.NAT.NAT64
	if len(ruleSets) == 0 {
		// Clear stale NAT64 state when all rule-sets are removed.
		if err := dp.SetNAT64Count(0); err != nil {
			return fmt.Errorf("clear NAT64 count: %w", err)
		}
		dp.DeleteStaleNAT64(0, writtenPrefixes)
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

		// Look up the source pool ID. If the pool was defined in source NAT
		// but not referenced by any SNAT rule (e.g. interface-mode rules), we
		// auto-assign it a pool ID here.
		poolID, ok := result.PoolIDs[rs.SourcePool]
		if !ok {
			pool, poolExists := cfg.Security.NAT.SourcePools[rs.SourcePool]
			if !poolExists {
				return fmt.Errorf("NAT64 rule-set %q: source pool %q not found", rs.Name, rs.SourcePool)
			}
			// Assign next pool ID (after those used by SNAT).
			newID := result.NextPoolID
			result.NextPoolID++
			result.PoolIDs[pool.Name] = newID
			poolID = newID

			// Populate pool config and IPs.
			var pcfg NATPoolConfig
			pcfg.PortLow = uint16(pool.PortLow)
			pcfg.PortHigh = uint16(pool.PortHigh)
			if pcfg.PortLow == 0 {
				pcfg.PortLow = 1024
			}
			if pcfg.PortHigh == 0 {
				pcfg.PortHigh = 65535
			}
			var numV4, numV6 int
			for _, addr := range pool.Addresses {
				cidr := addr
				if !strings.Contains(cidr, "/") {
					if strings.Contains(cidr, ":") {
						cidr += "/128"
					} else {
						cidr += "/32"
					}
				}
				pip, _, perr := net.ParseCIDR(cidr)
				if perr != nil {
					continue
				}
				if pip4 := pip.To4(); pip4 != nil && numV4 < int(MaxNATPoolIPsPerPool) {
					if err := dp.SetNATPoolIPV4(uint32(newID), uint32(numV4), ipToUint32BE(pip4)); err != nil {
						return fmt.Errorf("NAT64 rule-set %q: set pool IPv4 %d/%d: %w",
							rs.Name, newID, numV4, err)
					}
					numV4++
				} else if pip.To16() != nil && numV6 < int(MaxNATPoolIPsPerPool) {
					if err := dp.SetNATPoolIPV6(uint32(newID), uint32(numV6), ipTo16Bytes(pip)); err != nil {
						return fmt.Errorf("NAT64 rule-set %q: set pool IPv6 %d/%d: %w",
							rs.Name, newID, numV6, err)
					}
					numV6++
				}
			}
			if numV4 == 0 && numV6 == 0 {
				return fmt.Errorf("NAT64 rule-set %q: source pool %q has no valid addresses",
					rs.Name, pool.Name)
			}
			pcfg.NumIPs = uint16(numV4)
			pcfg.NumIPsV6 = uint16(numV6)
			if err := dp.SetNATPoolConfig(uint32(newID), pcfg); err != nil {
				return fmt.Errorf("NAT64 rule-set %q: set pool config %d: %w",
					rs.Name, newID, err)
			}
			slog.Info("auto-assigned NAT64 source pool",
				"pool", pool.Name, "pool_id", newID, "v4_ips", numV4, "v6_ips", numV6)
		}

		nat64Cfg := NAT64Config{
			Prefix:     prefix,
			SNATPoolID: poolID,
		}
		if err := dp.SetNAT64Config(count, nat64Cfg); err != nil {
			return fmt.Errorf("NAT64 rule-set %q: set config: %w", rs.Name, err)
		}
		writtenPrefixes[NAT64PrefixKey{Prefix: nat64Cfg.Prefix}] = true

		slog.Info("compiled NAT64 prefix",
			"rule-set", rs.Name, "prefix", rs.Prefix,
			"pool", rs.SourcePool, "pool_id", poolID)
		count++
	}

	if err := dp.SetNAT64Count(count); err != nil {
		return fmt.Errorf("set NAT64 count: %w", err)
	}

	// Delete stale NAT64 entries.
	dp.DeleteStaleNAT64(count, writtenPrefixes)

	slog.Info("NAT64 compilation complete", "prefixes", count)
	return nil
}
