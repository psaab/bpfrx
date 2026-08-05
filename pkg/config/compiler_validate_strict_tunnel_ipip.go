package config

import (
	"fmt"
	"sort"
)

// validateIpipTunnelUnimplementedStrict hard-rejects a tunnel whose compiled
// mode is `ipip` (#4785 half 1).
//
// IPIP (ip-in-ip, proto-4/41) parses, compiles, and creates a Tuntap routing
// anchor, but the userspace dataplane — the only supported runtime — has NO
// IPIP primitive in either direction:
//
//   - INBOUND: forwarding_build/tunnels.rs indexes an endpoint into
//     `gre_decap_index` only when `tunnel_mode_kind(&endpoint.mode) ==
//     TunnelKind::Gre`. `ipip` classifies as `TunnelKind::Unknown`, so it is
//     never indexed and a received proto-4 frame has nothing to decap against;
//     it reaches the local stack, finds no IPPROTO_IPIP handler, and is dropped.
//   - OUTBOUND: `TunnelKind::Unknown` is the fail-closed arm of the egress
//     encap dispatcher, which drops rather than defaulting to GRE encap (the
//     pre-#2327 fail-open behaviour).
//
// So the tunnel is silently dead in BOTH directions. Before this gate it
// committed green with only an advisory (#4788): the operator got a configured,
// UP interface that passes no traffic and no error to act on. Converting the
// advisory into a rejection is the "reject, don't guess" resolution — an
// unimplemented feature must fail loudly at commit rather than succeed into a
// blackhole.
//
// This is DELIBERATELY not gated on "would it otherwise work": there is no
// partial IPIP support to preserve. Half 2 of #4785 implements the decap stage;
// when it lands this gate is removed, not relaxed.
//
// Strict on the operator commit / commit-check path (CompileConfig). The call
// site downgrades to a WARNING on the tolerant load / peer-sync paths
// (opts.lenientIpipTunnelMode) so a config an older binary already accepted
// still BOOTS (#1960) — the runtime's own fail-closed arms keep the tunnel
// inert either way, so warning there loses nothing. Mirrors
// validateTunnelOuterFamilyStrict, which it runs beside.
//
// Note on how a config acquires this mode: `mode ipip` can be written
// explicitly, but it is ALSO inferred from the interface name — compileInterfaces
// defaults an `ip-*` interface's tunnel to `ipip` (a `gr-*` one to `gre`). An
// operator who never typed "ipip" can therefore hit this, so the message names
// the interface and the inference rather than only the mode token.
func validateIpipTunnelUnimplementedStrict(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return nil, nil
	}
	var warnings []string

	reject := func(where string) error {
		err := fmt.Errorf(
			"interfaces %s tunnel mode ipip: IPIP (ip-in-ip) is NOT implemented in the "+
				"userspace dataplane (#4785) — the tunnel would be created but pass NO "+
				"traffic in either direction (an inbound proto-4 frame has no decap stage "+
				"and is dropped; an egress inner packet classifies as an unknown tunnel "+
				"mode and is dropped). Use `mode gre` or `mode wireguard` for a working "+
				"tunnel. Note an `ip-*` interface defaults to `mode ipip` even when the "+
				"mode is not written explicitly; a `gr-*` interface defaults to `mode gre`.",
			where)
		if lenient {
			warnings = append(warnings, err.Error())
			return nil
		}
		return err
	}

	// Deterministic iteration order so the first reported error is stable across
	// runs and both HA nodes report identically.
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		iface := cfg.Interfaces.Interfaces[name]
		if iface == nil {
			continue
		}
		if iface.Tunnel != nil && iface.Tunnel.Mode == "ipip" {
			if err := reject(fmt.Sprintf("%q", name)); err != nil {
				return warnings, err
			}
		}
		unitNums := make([]int, 0, len(iface.Units))
		for u := range iface.Units {
			unitNums = append(unitNums, u)
		}
		sort.Ints(unitNums)
		for _, u := range unitNums {
			unit := iface.Units[u]
			if unit != nil && unit.Tunnel != nil && unit.Tunnel.Mode == "ipip" {
				if err := reject(fmt.Sprintf("%q unit %d", name, u)); err != nil {
					return warnings, err
				}
			}
		}
	}
	return warnings, nil
}
