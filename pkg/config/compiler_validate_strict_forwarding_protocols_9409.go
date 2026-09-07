package config

import "fmt"

// validateForwardingInstanceProtocolsStrict rejects a routing-protocol stanza
// authored under `instance-type forwarding` (#9409).
//
// A forwarding instance is a KERNEL TABLE, not a VRF: the daemon deliberately
// creates no VRF device for it (daemon_apply_interfaces.go), and its statics
// render into `table <id>` so the kernel agrees with the FBF/PBR ip rules
// (#1827 PR-2). The FRR assembler encodes that by clearing `VRFName` for a
// forwarding instance — and the protocol renderer reads an empty VRFName as
// "the GLOBAL instance". So `VRFName == ""` is overloaded: it means both "the
// master table" and "a forwarding instance's own kernel table", and the
// protocol renderer takes the first reading.
//
// Measured at HEAD, on a config all four channels ACCEPT with zero warnings:
//
//	forwarding + ospf -> TWO `router ospf` blocks, NEITHER carrying a `vrf`
//	                     suffix; the instance's interface is activated in the
//	                     GLOBAL OSPF instance.
//	forwarding + isis -> a GLOBAL `router isis xpf` with the instance's
//	                     interface.
//	forwarding + rip  -> a GLOBAL `router rip` with the instance's network.
//	forwarding + bgp  -> the instance's `peer-as 65002` neighbor renders under
//	                     a SECOND `router bgp 65001` block — it JOINS THE
//	                     GLOBAL AS. Quieter than the "conflicting AS" the
//	                     source report predicted, and worse.
//
// A `virtual-router` control on the same fixture renders
// `router ospf vrf vrf-ISP-B` correctly, so this is specific to the
// forwarding type and not to per-instance protocols in general.
//
// REJECTED rather than silently dropped, mirroring the #5830 per-instance
// next-table rejection: the composition is unsupported, not merely unwired, and
// an operator who authored it is asking for something the box cannot do. Junos
// does not accept it either — `instance-type forwarding` takes
// `routing-options`, not `protocols` — and `docs/multi-wan.md` gives the FBF
// recipe as statics-only ("No VRF device, no interfaces — just a routing
// table"). No shipped or test config in the tree composes the two; measured
// against `test/incus/fbf-two-upstream-config.set`, which is statics-only.
//
// Strict on commit / commit-check so the composition is operator-visible;
// downgraded to a warning on the tolerant load / peer-sync paths
// (opts.lenientForwardingInstanceProtocols) so an already-persisted or
// peer-synced config carrying it still BOOTS (#1960). That downgrade is only
// safe because the assembler DROPS a forwarding instance's protocols instead of
// merging them (assembleFRRConfig, pkg/daemon) — a leniently-loaded config
// renders nothing for them rather than polluting the global instance, which is
// the same "keeps it inert" clause every other lenient gate here relies on.
//
// Instances are walked in declaration order and protocols in a fixed order, so
// the first-reported error is deterministic.
func validateForwardingInstanceProtocolsStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.InstanceType != "forwarding" {
			continue
		}
		for _, p := range []struct {
			name    string
			present bool
		}{
			{"ospf", ri.OSPF != nil},
			{"ospf3", ri.OSPFv3 != nil},
			{"bgp", ri.BGP != nil},
			{"rip", ri.RIP != nil},
			{"isis", ri.ISIS != nil},
		} {
			if !p.present {
				continue
			}
			return fmt.Errorf(
				"routing-instances %s protocols %s: `protocols` is not supported "+
					"under `instance-type forwarding` — a forwarding instance is a "+
					"kernel table with no VRF device, so the FRR renderer has no "+
					"instance to scope the protocol to and would activate it in the "+
					"GLOBAL routing instance (a BGP neighbor joins the global AS; an "+
					"IGP's learned routes land in the main table while %s's own "+
					"table stays empty). Use `instance-type virtual-router` (or "+
					"`vrf`) if this instance needs its own protocol, or keep it "+
					"statics-only as in docs/multi-wan.md",
				ri.Name, p.name, ri.Name)
		}
	}
	return nil
}
