package config

import (
	"fmt"
	"sort"
)

// compiler_validate_warn_nat_iface_addr.go is the Track-1 (#5837) commit-time
// advisory: a destination-NAT or static-NAT rule whose PUBLIC / matched
// destination address (the address the outside world targets) equals a
// configured interface address on this firewall.
//
// Why it matters (the #5837 bypass): on a non-GRE session miss the userspace
// AF_XDP shim (userspace-xdp/src/lib.rs try_xdp_userspace / is_local_destination)
// classifies a packet whose destination is a firewall-local interface address as
// kernel-local and shunts it to the host stack BEFORE consulting destination-NAT
// or static-NAT. `is_local_destination` inspects the INGRESS destination — for a
// DNAT rule that is the `match destination-address` (the public IP the client
// targets), NOT the `then destination-nat pool` address (the internal
// translation TARGET, which the ingress classifier never sees). So a legitimate
// Junos port-forward / static 1:1 mapping that matches the WAN interface's own
// address is INERT on the first packet: the client's SYN is delivered to a local
// service instead of translated + zone-policed. Reply packets and packets on an
// already-established session are unaffected (the translation is applied once a
// session exists); only the FIRST packet of a new flow is misrouted.
//
// Track-1 makes that silent bypass LOUD. The full dataplane fix (a dedicated
// intent map probed before local classification, Option B / Track-2) is a large,
// verifier-gated, HA-aware project deferred by the converged #5837 research plan
// (docs/research/5837-xdp-dnat-before-local/plan.md §0/§0a). Until it lands the
// honest mitigation is a commit-time WARNING naming the offending rule and the
// colliding interface address.
//
// WARN-only on BOTH the strict commit path and the tolerant load / peer-sync
// path (it is emitted from ValidateConfig, which runs on every compile): the
// config is legal Junos and works for reply / established traffic, so it must
// never reject or change forwarding — a hard reject would also brick a boot on a
// previously-committed config (#1960 no-brick doctrine), and the config may be
// deliberately staged for the Track-2 future. This mirrors the sibling direct
// host-bound advisories in compiler_validate_warn_host_inbound.go.
//
// Scope: literal `match destination-address` host / prefix values are checked
// (address-book-NAME-referenced matches are out of scope — resolving them needs
// the address-book fold and the overwhelmingly common #5837 case uses a literal
// address). Both IPv4 and IPv6 are covered (the normalization strips the prefix
// and canonicalizes the host, so `10.0.61.1/32` on the rule matches `10.0.61.1/24`
// on the interface). Configured static interface addresses AND VRRP virtual
// addresses (VIPs — also firewall-local) are enumerated.

// interfaceLocalAddressIndex returns a map from a normalized host IP (the value
// hostLocalAddrFamily produces) to a human label for the interface unit that
// carries it. Both static unit addresses and VRRP virtual addresses (VIPs) are
// included, since both are classified firewall-local by the shim. Iteration is
// fully sorted so the label chosen for an address shared by several units is
// deterministic (first unit in sorted interface+unit order wins).
func interfaceLocalAddressIndex(cfg *Config) map[string]string {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return nil
	}
	out := make(map[string]string)
	record := func(host, label string) {
		if host == "" {
			return
		}
		if _, ok := out[host]; !ok {
			out[host] = label
		}
	}
	ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		ifNames = append(ifNames, name)
	}
	sort.Strings(ifNames)
	for _, ifName := range ifNames {
		ifc := cfg.Interfaces.Interfaces[ifName]
		if ifc == nil {
			continue
		}
		unitNums := make([]int, 0, len(ifc.Units))
		for un := range ifc.Units {
			unitNums = append(unitNums, un)
		}
		sort.Ints(unitNums)
		for _, un := range unitNums {
			unit := ifc.Units[un]
			if unit == nil {
				continue
			}
			label := fmt.Sprintf("%s.%d", ifName, un)
			for _, a := range unit.Addresses {
				if host, _ := hostLocalAddrFamily(a); host != "" {
					record(host, label)
				}
			}
			vgKeys := make([]string, 0, len(unit.VRRPGroups))
			for k := range unit.VRRPGroups {
				vgKeys = append(vgKeys, k)
			}
			sort.Strings(vgKeys)
			for _, k := range vgKeys {
				vg := unit.VRRPGroups[k]
				if vg == nil {
					continue
				}
				for _, vip := range vg.VirtualAddresses {
					if host, _ := hostLocalAddrFamily(vip); host != "" {
						record(host, label+" (VRRP VIP)")
					}
				}
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// validateNATInterfaceAddressCollisionWarnings emits the Track-1 (#5837)
// commit-time advisory for each destination-NAT / static-NAT rule whose public
// (matched / external) destination address equals a configured interface address.
// See the file header for the mechanism. WARN-only, both compile paths.
func validateNATInterfaceAddressCollisionWarnings(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	ifAddrs := interfaceLocalAddressIndex(cfg)
	if len(ifAddrs) == 0 {
		return nil
	}
	var warnings []string

	// Destination NAT: the address the outside world targets is the rule's
	// `match destination-address` (NOT the pool / translated-to address). Only a
	// rule that actually translates (has a pool, is not a `destination-nat off`
	// exemption) is inert on the first packet, so gate on that.
	if dst := cfg.Security.NAT.Destination; dst != nil {
		for _, rs := range dst.RuleSets {
			if rs == nil {
				continue
			}
			for _, rule := range rs.Rules {
				if rule == nil {
					continue
				}
				if rule.Then.Off || rule.Then.PoolName == "" {
					continue // no translation → nothing to be inert
				}
				for _, addr := range natMatchValues(rule.Match.DestinationAddresses, rule.Match.DestinationAddress) {
					host, _ := hostLocalAddrFamily(addr)
					if host == "" {
						continue
					}
					if iface, ok := ifAddrs[host]; ok {
						warnings = append(warnings, fmt.Sprintf(
							"security nat destination rule-set %q rule %q matches "+
								"destination-address %s, which is a configured interface "+
								"address (%s): the userspace AF_XDP shim classifies the first "+
								"packet to a firewall-local address as kernel-local BEFORE "+
								"consulting destination-NAT, so this translation is INERT on "+
								"the first packet of a new flow (the packet is delivered to the "+
								"host instead of translated + zone-policed). Reply / "+
								"established-session traffic is unaffected. Known first-packet "+
								"interface-address DNAT limitation (#5837); the dataplane fix is "+
								"deferred (Track-2). Use a non-interface public address, or "+
								"expect first-packet local delivery.",
							rs.Name, rule.Name, host, iface))
					}
				}
			}
		}
	}

	// Static NAT: the public address is the rule `match destination-address`
	// (StaticNATRule.Match, the external / public IP). Only a rule with a
	// translation target is meaningful.
	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			if rule.Then == "" && rule.ThenPrefixName == "" {
				continue // no translation target → not a first-packet-inert rule
			}
			host, _ := hostLocalAddrFamily(rule.Match)
			if host == "" {
				continue
			}
			if iface, ok := ifAddrs[host]; ok {
				warnings = append(warnings, fmt.Sprintf(
					"security nat static rule-set %q rule %q matches destination-address "+
						"%s, which is a configured interface address (%s): the userspace "+
						"AF_XDP shim classifies the first packet to a firewall-local address "+
						"as kernel-local BEFORE consulting static-NAT, so this 1:1 "+
						"translation is INERT on the first packet of a new flow (the packet "+
						"is delivered to the host instead of translated + zone-policed). "+
						"Reply / established-session traffic is unaffected. Known first-packet "+
						"interface-address static-NAT limitation (#5837); the dataplane fix is "+
						"deferred (Track-2). Use a non-interface external address, or expect "+
						"first-packet local delivery.",
					rs.Name, rule.Name, host, iface))
			}
		}
	}

	return warnings
}
