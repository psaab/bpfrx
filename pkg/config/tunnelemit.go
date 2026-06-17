package config

import (
	"fmt"
	"sort"
)

// TunnelEndpointName pairs the unit-qualified tunnel endpoint name the
// dataplane snapshot builder would emit with the matching TunnelConfig.
//
// The Name is the CANONICAL "%s.%d" (or bare interface) ref keyed by the
// builder's per-interface emission rules; the Tunnel is the same
// *TunnelConfig the builder reads to populate the snapshot row. The
// builder consumes the {Name, Tunnel} set, intersects it with the runtime
// InterfaceSnapshot rows, and applies the usedIDs collision drop — none of
// which this emitter does. The commit-time collision gate
// (validateTunnelEndpointIDCollisionAST) uses only the Name field.
type TunnelEndpointName struct {
	Name   string
	Tunnel *TunnelConfig
}

// EmitTunnelEndpointNames is the single source of truth for the set of
// CONFIGURED tunnel endpoints the dataplane snapshot builder
// (buildTunnelEndpointSnapshots) would emit from a typed, already-expanded
// *Config. It is a pure function of the typed config:
//
//   - it does NOT consult runtime InterfaceSnapshot rows (those do not
//     exist at commit time);
//   - it does NOT apply the StableTunnelEndpointID usedIDs collision drop
//     (the builder owns that fail-closed belt);
//   - it applies the same non-WireGuard source/destination gate the
//     builder's addEndpoint applies (drop a non-WG tunnel with empty
//     Source or Destination);
//   - it applies the same interface-level-WireGuard single-lowest-unit
//     pick (#1910): one persistent TUN per interface-level WG tunnel, keyed
//     by the lowest configured unit ref;
//   - it formats every ref as the canonical "%s.%d" the builder formats
//     from the int-keyed Units map (leading-zero / overflow / last-wins
//     unit canonicalization is already resolved by compileInterfaces when
//     it built the int-keyed map, so it is inherited for free).
//
// The result is sorted by Name for deterministic iteration. The collision
// gate's per-node views (View 2 / View 3) feed an expanded candidate
// through compileInterfaces into a throwaway InterfacesConfig and then
// through this emitter, so the gate sees exactly the names the builder
// would publish — without ever calling CompileConfig* (which would recurse
// into the gate) and without consulting the post-usedIDs snapshot.
//
// buildTunnelEndpointSnapshots is refactored to source its configured-name
// set from this emitter; a differential parity test
// (TestEmitTunnelEndpointNamesMatchesBuilder) pins the two to one another
// so the gate and the builder can never drift (#1910 r2-r6 drift class).
func EmitTunnelEndpointNames(cfg *Config) []TunnelEndpointName {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return nil
	}
	ifaceNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		ifaceNames = append(ifaceNames, name)
	}
	sort.Strings(ifaceNames)

	out := make([]TunnelEndpointName, 0)
	add := func(name string, tunnel *TunnelConfig) {
		if tunnel == nil {
			return
		}
		// Mirror addEndpoint's non-WG source/destination gate: a
		// non-WireGuard tunnel without both endpoints is never emitted.
		// WireGuard carries its peer in WgEndpoint and needs no
		// Source/Destination (#1432 S2a).
		if tunnel.Mode != "wireguard" && (tunnel.Source == "" || tunnel.Destination == "") {
			return
		}
		out = append(out, TunnelEndpointName{Name: name, Tunnel: tunnel})
	}

	for _, name := range ifaceNames {
		iface := cfg.Interfaces.Interfaces[name]
		if iface == nil {
			continue
		}
		if iface.Tunnel != nil {
			if len(iface.Units) == 0 {
				add(name, iface.Tunnel)
				continue
			}
			unitNums := make([]int, 0, len(iface.Units))
			for unitNum := range iface.Units {
				unitNums = append(unitNums, unitNum)
			}
			sort.Ints(unitNums)
			if iface.Tunnel.Mode == "wireguard" {
				// Interface-level WireGuard is ONE persistent TUN; the
				// builder emits exactly one endpoint keyed by the lowest
				// configured unit ref (#1910). Mirror that here.
				add(fmt.Sprintf("%s.%d", name, unitNums[0]), iface.Tunnel)
				continue
			}
			for _, unitNum := range unitNums {
				add(fmt.Sprintf("%s.%d", name, unitNum), iface.Tunnel)
			}
			continue
		}
		if len(iface.Units) == 0 {
			continue
		}
		unitNums := make([]int, 0, len(iface.Units))
		for unitNum := range iface.Units {
			unitNums = append(unitNums, unitNum)
		}
		sort.Ints(unitNums)
		for _, unitNum := range unitNums {
			unit := iface.Units[unitNum]
			if unit == nil || unit.Tunnel == nil {
				continue
			}
			add(fmt.Sprintf("%s.%d", name, unitNum), unit.Tunnel)
		}
	}
	return out
}
