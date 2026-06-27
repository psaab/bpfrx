package userspace

import (
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// natCounterID returns the compiler-assigned per-rule translation hit counter
// ID for the type-namespaced "natType/rulesetName/ruleName" key (#2218). The
// natType MUST match the type the compiler stamped (dataplane.NATCounterKey),
// otherwise same-named SNAT/DNAT/static rules collide. A nil map or a missing
// key yields 0 ("no counter"), preserving the legacy behavior where the
// snapshot carried no per-rule counter attribution. The ID is the stable
// key-derived hash assigned by the compiler (#2255), so it is u32-wide.
func natCounterID(ids map[string]uint32, natType, ruleSet, rule string) uint32 {
	if ids == nil {
		return 0
	}
	return ids[dataplane.NATCounterKey(natType, ruleSet, rule)]
}

// appendNATSourceAddressName resolves a NAT rule's `match source-address-name
// <book-entry>` into concrete source prefixes and appends them to the rule's
// source list (#2416). It reuses resolveUserspaceAddressBookEntry — the same
// global-address-book expander the security-policy snapshot path uses — so a
// name-scoped NAT rule carries the entry's prefixes into the #2394 source
// constraint instead of publishing an empty (match-any) source list.
//
// Fail-closed on an unknown / unresolvable name: the raw token is appended so
// the source list stays NON-EMPTY (source_constrained stays true on the Rust
// side) while the token itself fails IpAddr/IpNet parse and contributes no
// prefix — the rule then matches NOTHING rather than collapsing to match-any.
// This mirrors the policy path's behavior for an unresolved address reference
// and is backstopped at commit by validateNATSourceAddressNameReferencesStrict.
func appendNATSourceAddressName(cfg *config.Config, sourceAddrs []string, name string) []string {
	if name == "" {
		return sourceAddrs
	}
	if values, ok := resolveUserspaceAddressBookEntry(cfg, name); ok && len(values) > 0 {
		return append(sourceAddrs, values...)
	}
	// Unknown / empty book entry: keep the constraint non-empty but
	// unmatchable (fail-closed). The raw name cannot parse as an IP.
	return append(sourceAddrs, name)
}

// appendNATDestinationAddressName resolves a NAT rule's `match
// destination-address-name <book-entry>` into concrete destination prefixes and
// appends them to the rule's destination list (#3229). It is the destination
// twin of appendNATSourceAddressName and shares the same address-book expander
// (resolveUserspaceAddressBookEntry) the security-policy and source-address-name
// paths use, so a name-scoped destination matches the same prefixes a literal
// `match destination-address` would.
//
// Fail-closed on an unknown / unresolvable name: the raw token is appended so
// the destination list stays NON-EMPTY (the rule does not collapse to no
// destination = skip), while the token itself fails IP parse downstream and
// contributes no installed table entry — the rule then matches NOTHING rather
// than broadening. Backstopped at commit by
// validateNATSourceAddressNameReferencesStrict, which also gates
// destination-address-name.
func appendNATDestinationAddressName(cfg *config.Config, destAddrs []string, name string) []string {
	if name == "" {
		return destAddrs
	}
	if values, ok := resolveUserspaceAddressBookEntry(cfg, name); ok && len(values) > 0 {
		return append(destAddrs, values...)
	}
	// Unknown / empty book entry: keep the list non-empty but unmatchable
	// (fail-closed). The raw name cannot parse as an IP.
	return append(destAddrs, name)
}

func buildSourceNATSnapshots(cfg *config.Config, natCounterIDs map[string]uint32) []SourceNATRuleSnapshot {
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
			// #2416: resolve `match source-address-name` for SNAT too — same
			// builder gap as DNAT (the source list only carried literal
			// prefixes). See appendNATSourceAddressName.
			sourceAddrs = appendNATSourceAddressName(cfg, sourceAddrs, rule.Match.SourceAddressName)
			destAddrs := append([]string(nil), rule.Match.DestinationAddresses...)
			if len(destAddrs) == 0 && rule.Match.DestinationAddress != "" {
				destAddrs = append(destAddrs, rule.Match.DestinationAddress)
			}
			// #3229: resolve `match destination-address-name` the same way the
			// source path resolves source-address-name — without this a
			// name-scoped destination constraint published an EMPTY list =
			// match-any destination (fail-open).
			destAddrs = appendNATDestinationAddressName(cfg, destAddrs, rule.Match.DestinationAddressName)
			var poolAddresses []string
			var portLow, portHigh uint16
			var persistentNAT bool
			var persistentNATPermitAnyRemoteHost bool
			var persistentNATPermit string
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
						// #2823: carry the full three-way permit enum. Default
						// an unset mode to target-host-port (the pre-#2823
						// false-flag (dst_ip, dst_port) keying) so existing
						// configs stay byte-identical. The
						// PermitAnyRemoteHost bool is kept on the wire for
						// back-compat with an older helper that predates the
						// enum (#1961 wire-skew discipline).
						permit := pool.PersistentNAT.Permit
						if permit == "" {
							permit = config.PersistentNATPermitTargetHostPort
						}
						persistentNATPermit = string(permit)
						persistentNATPermitAnyRemoteHost = permit == config.PersistentNATPermitAnyRemoteHost
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
				PersistentNATPermit:              persistentNATPermit,
				PersistentNATInactivityTimeout:   persistentNATInactivityTimeout,
				PoolUnusable:                     poolUnusable,
				PoolUnusableReason:               poolUnusableReason,
				CounterID:                        natCounterID(natCounterIDs, dataplane.NATCounterTypeSource, rs.Name, rule.Name),
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

// clampPort coerces a compiler-stored port (int, 0 = unset) into the u16
// wire slot. An out-of-range value is rejected at strict commit-check
// (compiler_nat.go validateNATHostMaskStrict), but the lenient load/peer-sync
// path can still carry one; clamp it to 0 ("no port translation") so a bad
// value fails CLOSED on the wire instead of wrapping to a wrong u16. #2491.
func clampPort(p int) uint16 {
	if p < 1 || p > 65535 {
		return 0
	}
	return uint16(p)
}

func buildStaticNATSnapshots(cfg *config.Config, natCounterIDs map[string]uint32) []StaticNATRuleSnapshot {
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
				Name:                 rule.Name,
				FromZone:             rs.FromZone,
				ExternalIP:           rule.Match,
				InternalIP:           rule.Then,
				MatchDestinationPort: clampPort(rule.MatchDestinationPort),
				MappedPort:           clampPort(rule.MappedPort),
				CounterID:            natCounterID(natCounterIDs, dataplane.NATCounterTypeStatic, rs.Name, rule.Name),
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

// dnatDestinationParts splits a DNAT `match destination-address` token into the
// base address the DNAT table keys on and, for a non-host prefix, the canonical
// masked CIDR (#3164). It is the single point that decides host-vs-prefix on the
// Go side so the snapshot and the Rust DnatTable agree:
//
//   - A bare IP ("198.51.100.42") or an explicit host mask ("198.51.100.42/32",
//     "2001:db8::1/128") is a HOST: base = the address, prefix = "" — the Rust
//     table keys it in the O(1) exact hash map (unchanged fast path).
//   - A non-host prefix ("198.51.100.0/24") is a BLOCK: base = the prefix
//     network address ("198.51.100.0"), prefix = the canonical masked CIDR
//     ("198.51.100.0/24") — the Rust table installs a longest-prefix-match
//     entry that translates every host in the block to the rule's pool.
//
// ok is false for a token that does not parse as an IP or CIDR (an unresolved
// address-book name reaches here verbatim on a typo); the caller skips it, so a
// rule whose destinations are all malformed installs no entry and matches
// nothing (fail-closed) — the commit-time gate makes the typo operator-visible.
func dnatDestinationParts(raw string) (base, prefix string, ok bool) {
	if raw == "" {
		return "", "", false
	}
	if strings.IndexByte(raw, '/') == -1 {
		// Bare address — always a host.
		if net.ParseIP(raw) == nil {
			return "", "", false
		}
		return raw, "", true
	}
	ip, ipNet, err := net.ParseCIDR(raw)
	if err != nil {
		return "", "", false
	}
	ones, bits := ipNet.Mask.Size()
	if ones == bits {
		// Canonical host mask (/32 or /128) — exact-host fast path.
		return ip.String(), "", true
	}
	// Non-host prefix: base = network address, prefix = canonical masked CIDR.
	return ipNet.IP.String(), ipNet.String(), true
}

func buildDestinationNATSnapshots(cfg *config.Config, natCounterIDs map[string]uint32) []DestinationNATRuleSnapshot {
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
			ruleCounterID := natCounterID(natCounterIDs, dataplane.NATCounterTypeDest, rs.Name, rule.Name)
			pool, ok := cfg.Security.NAT.Destination.Pools[rule.Then.PoolName]
			if !ok || pool == nil || pool.Address == "" {
				continue
			}
			// #2395: a DNAT rule may publish multiple destination addresses
			// (`match destination-address [ A B C ]`). The DNAT table is keyed
			// by exact destination IP, so each configured destination needs its
			// OWN snapshot entry sharing the rule's pool/counter id. Iterating
			// only the singular `DestinationAddress` (the first list element)
			// collapsed the rule to its first destination and silently dropped
			// translation for B and C. Mirror the source-address idiom: prefer
			// the bracket-list form, fall back to the singular match value.
			destAddrs := append([]string(nil), rule.Match.DestinationAddresses...)
			if len(destAddrs) == 0 && rule.Match.DestinationAddress != "" {
				destAddrs = append(destAddrs, rule.Match.DestinationAddress)
			}
			// #3229: `match destination-address-name <book-entry>` selects the
			// translated destination by an address-book reference instead of a
			// literal prefix. It was parsed into DestinationAddressName but never
			// resolved into the destination list the DNAT table is keyed on, so a
			// name-scoped DNAT rule installed NO table entry (silently dropped).
			// Resolve the name to its concrete prefixes via the same address-book
			// expander the source path uses (appendNATDestinationAddressName).
			// Each resolved host installs its own table entry below; a non-host
			// prefix is stripped to its network address like a literal CIDR
			// destination. On an unknown name the raw token is appended: it
			// cannot parse as an IP and is skipped in the emit loop, so the rule
			// matches NOTHING (fail-closed). The commit-time strict gate
			// (validateNATSourceAddressNameReferencesStrict) makes the typo
			// operator-visible.
			destAddrs = appendNATDestinationAddressName(cfg, destAddrs, rule.Match.DestinationAddressName)
			if len(destAddrs) == 0 {
				continue
			}

			// #2394: carry the DNAT `match source-address` constraint into the
			// snapshot. Junos DNAT source-address restricts which sources the
			// destination translation fires for; dropping it published the
			// internal service to every source in the from-zone (fail-open).
			// Mirror the SNAT builder: prefer the bracket-list form, fall back
			// to the singular match value. An empty result = match any source.
			sourceAddrs := append([]string(nil), rule.Match.SourceAddresses...)
			if len(sourceAddrs) == 0 && rule.Match.SourceAddress != "" {
				sourceAddrs = append(sourceAddrs, rule.Match.SourceAddress)
			}
			// #2416: `match source-address-name <book-entry>` scopes the DNAT
			// the same way a literal `match source-address` does, but as an
			// address-book reference. It was parsed into SourceAddressName yet
			// never resolved into the source list the #2394 enforcement reads,
			// so a name-scoped DNAT published an EMPTY source list = match any
			// source = fail-open (a destination translation the operator scoped
			// to a named source set fired for everyone). Resolve the name to its
			// concrete prefixes via the same address-book expander the policy
			// path uses and append them. On an unknown name we append the raw
			// token: it cannot parse on the Rust side (IpAddr::parse fails) so it
			// contributes no prefix, but it keeps the source list NON-EMPTY so
			// source_constrained stays true and the rule matches NOTHING
			// (fail-closed) instead of collapsing back to match-any. A commit-
			// time strict gate (validateNATSourceAddressNameReferencesStrict)
			// makes the typo operator-visible; this is the dataplane backstop.
			sourceAddrs = appendNATSourceAddressName(cfg, sourceAddrs, rule.Match.SourceAddressName)

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

					poolAddr := pool.Address
					if idx := strings.IndexByte(poolAddr, '/'); idx != -1 {
						poolAddr = poolAddr[:idx]
					}

					// #2395: emit one snapshot per configured destination so a
					// bracket-list DNAT installs a table entry for EVERY
					// published destination, not just the first.
					//
					// #3164: a destination may now be a non-host prefix
					// (`match destination-address 198.51.100.0/24`).
					// dnatDestinationParts classifies each token: a host (bare IP,
					// /32, /128) carries an empty DestinationPrefix and keys the
					// Rust exact hash map (unchanged fast path); a non-host prefix
					// carries the canonical masked CIDR in DestinationPrefix (the
					// network base in DestinationAddress) and installs a
					// longest-prefix-match entry that translates every host in the
					// block to the rule's pool. A token that does not parse as an
					// IP or CIDR is skipped — if a rule has destinations but ALL
					// are malformed, no entry is emitted, so the rule matches
					// NOTHING (fail-closed) rather than broadening to match-any.
					for _, rawDst := range destAddrs {
						base, prefix, ok := dnatDestinationParts(rawDst)
						if !ok {
							continue
						}
						out = append(out, DestinationNATRuleSnapshot{
							Name:               rule.Name,
							FromZone:           rs.FromZone,
							SourceAddresses:    sourceAddrs,
							DestinationAddress: base,
							DestinationPrefix:  prefix,
							DestinationPort:    dstPort,
							Protocol:           proto,
							PoolAddress:        poolAddr,
							PoolPort:           poolPort,
							CounterID:          ruleCounterID,
						})
					}
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
	// `security nat natv6v4 no-v6-frag-header` is a global option, but the
	// dataplane consumes NAT64 state per rule-set. Replicate the flag onto
	// every emitted rule so the IPv6->IPv4 translator can honor it. The option
	// is an option-gated LOCAL DF policy (not the size-driven RFC 7915 5.1
	// selection): when set the translator clears DF so the IPv4 packet stays
	// fragmentable (DF=0, non-atomic) and carries a generated non-zero,
	// non-repeating Identification (RFC 6864 4.1) rather than the default DF=1
	// atomic framing.
	noV6FragHeader := cfg.Security.NAT.NATv6v4 != nil && cfg.Security.NAT.NATv6v4.NoV6FragHeader
	out := make([]NAT64RuleSnapshot, 0, len(cfg.Security.NAT.NAT64))
	for _, rs := range cfg.Security.NAT.NAT64 {
		if rs == nil || rs.Prefix == "" {
			continue
		}
		// #2214: initialize non-nil so a rule with no resolvable source pool
		// marshals `pool_addresses` as `[]`, never JSON `null`. The field has
		// no `,omitempty` (an empty pool is still a meaningful "no source-pool
		// resolved" state the dataplane must see), and the Rust `Vec<String>`
		// rejects an explicit null — which aborts the whole snapshot decode and
		// kills ALL transit (#1961 no-transit signature).
		poolAddresses := []string{}
		if rs.SourcePool != "" {
			if pool, ok := cfg.Security.NAT.SourcePools[rs.SourcePool]; ok && pool != nil {
				if pool.Address != "" {
					poolAddresses = append(poolAddresses, pool.Address)
				}
				poolAddresses = append(poolAddresses, pool.Addresses...)
			}
		}
		out = append(out, NAT64RuleSnapshot{
			Name:           rs.Name,
			Prefix:         rs.Prefix,
			PoolAddresses:  poolAddresses,
			NoV6FragHeader: noV6FragHeader,
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
