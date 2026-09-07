package config

import (
	"fmt"
	"strconv"
	"strings"
)

// validateProtocolInterfaceRefWarnings makes the #9405 failure LOUD.
//
// A routing-protocol interface reference (`protocols ospf area <a> interface
// <ref>`, and the OSPFv3 / IS-IS / RIP equivalents) is accepted by all four
// config channels — configstore.CheckText, CompileConfig, CompileConfigLenient
// and SchemaValidate — with no constraint on the value beyond a valueHint. The
// renderer now resolves it to a kernel netdev name (#9405), but resolution
// cannot invent a device: a reference naming an interface or unit the config
// never declares renders an FRR stanza that binds nothing, and the operator
// sees a green commit, a running FRR and no adjacency, with no diagnostic
// anywhere. That silence is why the original defect survived — the render bug
// and the missing signal are the same finding.
//
// This is an ADVISORY, not a gate, deliberately:
//
//   - The configured interface set is not the only thing that can make a
//     reference valid in the field; rejecting at commit would brick a config
//     the tolerant load / HA config-sync paths must still accept (#1960).
//   - The failure mode being fixed is "no signal at all", not "wrong signal".
//
// `interface all` gets its own message. It is legal Junos (every interface in
// the area) and it commits clean here, but xpf does not expand it: it renders
// as the literal FRR operand `all`, which is not a device. "Names no
// configured interface" would be misleading — the reference is well formed and
// the gap is that the wildcard is unimplemented.
//
// COST. This walks the declared interface set ONCE, and only when at least one
// protocol interface reference exists, keying by both spellings this tree
// accepts (#8829) rather than calling ResolveKernelIfName per interface. That
// is not a style preference: ResolveKernelIfName rebuilds the tunnel-name map
// (and RethToPhysical) per call, so a per-interface loop over it is quadratic
// in the interface count on the tolerant compile — the exact regression
// TestTunnelNameMapBuildsAreInputSizeIndependent8862 exists to catch, and it
// did catch the first draft of this function.
func validateProtocolInterfaceRefWarnings(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	refs := collectProtocolInterfaceRefs(cfg)
	if len(refs) == 0 {
		return nil
	}
	if len(cfg.Interfaces.Interfaces) == 0 {
		// With no declared interfaces there is nothing to compare against and
		// every reference would warn — noise, not signal.
		return nil
	}

	// Declared interfaces under BOTH spellings: the config key (`ge-0/0/1`)
	// and its Linux form (`ge-0-0-1`). An operator who copied a name out of an
	// operational surface wrote the dash form, and it is a legitimate way to
	// author this leaf today (#8829).
	declared := make(map[string]*InterfaceConfig, len(cfg.Interfaces.Interfaces)*2)
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		declared[name] = ifc
		if linux := LinuxIfName(name); linux != name {
			declared[linux] = ifc
		}
	}

	var warnings []string
	for _, r := range refs {
		if r.ref == "all" {
			warnings = append(warnings, fmt.Sprintf(
				"%s %s interface all: xpf does not expand the `all` wildcard — "+
					"it renders as the literal FRR operand `all`, which is not "+
					"a device, so no adjacency forms. List the interfaces "+
					"explicitly (#9405).", r.scope, r.proto))
			continue
		}
		// An explicitly DECLARED name outranks a parse, even when it contains
		// a dot — the same precedence resolveKernelIfNameWith applies (#8994).
		if _, ok := declared[r.ref]; ok {
			continue
		}
		base, unitPart, dotted := strings.Cut(r.ref, ".")
		ifc, ok := declared[base]
		if !ok {
			warnings = append(warnings, fmt.Sprintf(
				"%s %s interface %s names no configured interface — the FRR "+
					"stanza will bind nothing and no adjacency will form "+
					"(#9405).", r.scope, r.proto, r.ref))
			continue
		}
		if !dotted {
			continue
		}
		unit, err := strconv.Atoi(unitPart)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf(
				"%s %s interface %s has an unparseable unit — the FRR stanza "+
					"will bind nothing and no adjacency will form (#9405).",
				r.scope, r.proto, r.ref))
			continue
		}
		if u, ok := ifc.Units[unit]; !ok || u == nil {
			warnings = append(warnings, fmt.Sprintf(
				"%s %s interface %s names no configured unit on %s — the FRR "+
					"stanza will bind nothing and no adjacency will form "+
					"(#9405).", r.scope, r.proto, r.ref, base))
		}
	}
	return warnings
}

// protocolIfaceRef is one authored routing-protocol interface reference, with
// the config path that names it for the advisory message.
type protocolIfaceRef struct {
	scope string // "protocols" or "routing-instances <n> protocols"
	proto string // "ospf" / "ospf3" / "rip" / "isis"
	ref   string
}

// collectProtocolInterfaceRefs walks the global protocols block and every
// routing instance in config order, so the advisory list is deterministic.
// BGP is absent because its peers are addresses, not interface references.
func collectProtocolInterfaceRefs(cfg *Config) []protocolIfaceRef {
	var out []protocolIfaceRef
	add := func(scope, proto, ref string) {
		if ref != "" {
			out = append(out, protocolIfaceRef{scope: scope, proto: proto, ref: ref})
		}
	}
	walk := func(scope string, ospf *OSPFConfig, ospfv3 *OSPFv3Config, rip *RIPConfig, isis *ISISConfig) {
		if ospf != nil {
			for _, area := range ospf.Areas {
				if area == nil {
					continue
				}
				for _, iface := range area.Interfaces {
					if iface != nil {
						add(scope, "ospf", iface.Name)
					}
				}
			}
		}
		if ospfv3 != nil {
			for _, area := range ospfv3.Areas {
				if area == nil {
					continue
				}
				for _, iface := range area.Interfaces {
					if iface != nil {
						add(scope, "ospf3", iface.Name)
					}
				}
			}
		}
		if rip != nil {
			for _, ref := range rip.Interfaces {
				add(scope, "rip", ref)
			}
			for _, ref := range rip.Passive {
				add(scope, "rip", ref)
			}
		}
		if isis != nil {
			for _, iface := range isis.Interfaces {
				if iface != nil {
					add(scope, "isis", iface.Name)
				}
			}
		}
	}

	walk("protocols", cfg.Protocols.OSPF, cfg.Protocols.OSPFv3, cfg.Protocols.RIP, cfg.Protocols.ISIS)
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		walk("routing-instances "+ri.Name+" protocols", ri.OSPF, ri.OSPFv3, ri.RIP, ri.ISIS)
	}
	return out
}
