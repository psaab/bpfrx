package userspace

import (
	"log/slog"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

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
			var poolAddresses []string
			var portLow, portHigh uint16
			var persistentNAT bool
			var persistentNATPermitAnyRemoteHost bool
			var persistentNATInactivityTimeout int
			var poolUnusable bool
			var poolUnusableReason string
			if rule.Then.PoolName != "" {
				pool, ok := cfg.Security.NAT.SourcePools[rule.Then.PoolName]
				if !ok || pool == nil {
					slog.Warn("userspace snapshot: marking source NAT rule with missing pool unusable",
						"rule", rule.Name, "pool", rule.Then.PoolName)
					poolUnusable = true
					poolUnusableReason = "missing_pool"
				} else {
					if pool.Address != "" {
						poolAddresses = append(poolAddresses, pool.Address)
					}
					poolAddresses = append(poolAddresses, pool.Addresses...)
					if len(poolAddresses) == 0 {
						slog.Warn("userspace snapshot: marking source NAT rule with empty pool unusable",
							"rule", rule.Name, "pool", rule.Then.PoolName)
						poolUnusable = true
						poolUnusableReason = "empty_pool"
					}
					var valid bool
					portLow, portHigh, valid = sourceNATPoolPortRange(pool)
					if !valid {
						slog.Warn("userspace snapshot: marking source NAT rule with invalid pool port range unusable",
							"rule", rule.Name, "pool", rule.Then.PoolName,
							"port_low", pool.PortLow, "port_high", pool.PortHigh)
						poolUnusable = true
						poolUnusableReason = "invalid_port_range"
					}
					if pool.PersistentNAT != nil {
						persistentNAT = true
						persistentNATPermitAnyRemoteHost = pool.PersistentNAT.PermitAnyRemoteHost
						persistentNATInactivityTimeout = pool.PersistentNAT.InactivityTimeout
						if persistentNATInactivityTimeout <= 0 {
							persistentNATInactivityTimeout = 300
						}
					}
				}
			}
			out = append(out, SourceNATRuleSnapshot{
				Name:                             rule.Name,
				FromZone:                         rs.FromZone,
				ToZone:                           rs.ToZone,
				SourceAddresses:                  sourceAddrs,
				DestinationAddresses:             destAddrs,
				InterfaceMode:                    rule.Then.Interface,
				Off:                              rule.Then.Off,
				PoolName:                         rule.Then.PoolName,
				PoolAddresses:                    poolAddresses,
				PortLow:                          portLow,
				PortHigh:                         portHigh,
				AddressPersistent:                cfg.Security.NAT.AddressPersistent,
				PersistentNAT:                    persistentNAT,
				PersistentNATPermitAnyRemoteHost: persistentNATPermitAnyRemoteHost,
				PersistentNATInactivityTimeout:   persistentNATInactivityTimeout,
				PoolUnusable:                     poolUnusable,
				PoolUnusableReason:               poolUnusableReason,
			})
		}
	}
	return out
}

func sourceNATPoolPortRange(pool *config.NATPool) (uint16, uint16, bool) {
	if pool == nil {
		return 0, 0, false
	}
	low := pool.PortLow
	if low == 0 {
		low = 1024
	}
	high := pool.PortHigh
	if high == 0 {
		high = 65535
	}
	if low < 1 || high < 1 || low > 65535 || high > 65535 || low > high {
		return 0, 0, false
	}
	return uint16(low), uint16(high), true
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
