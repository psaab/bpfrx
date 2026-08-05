package config

import (
	"errors"
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
// ipipTunnelSite is one compiled tunnel record whose EFFECTIVE mode is ipip,
// with the operator-facing label for the stanza that produced it.
type ipipTunnelSite struct {
	label string
	order [2]int // (interface index, unit+1; 0 = interface-level) for stable order
}

// effectiveIpipTunnelSites returns every tunnel DEVICE whose effective mode is
// ipip, in a deterministic order.
//
// "Effective" is load-bearing and is why this is not a plain walk of every
// compiled TunnelConfig. An interface-level `tunnel` stanza and a `unit 0
// tunnel` stanza compile to TWO records that carry the SAME Linux device name
// (compileInterfaces gives unit 0 the base name; only unit N>0 gets the "uN"
// suffix). Both are handed to routing.tunnelManager.Apply, which keys its
// desired set by tc.Name, and daemon tunnelConfigsFor appends the interface
// record BEFORE the units — so for a shared name the UNIT record is the one
// realized. A gate that rejected on the raw records would therefore reject
//
//	set interfaces ip-0/0/0 tunnel source/destination ...   (defaults to ipip)
//	set interfaces ip-0/0/0 unit 0 tunnel mode gre          (overrides to gre)
//
// whose realized device is a working GRE tunnel. That is the same
// over-rejection the mode-vs-name choice was made to avoid, reached one level
// in. Resolution here mirrors the applier: last writer per device name wins,
// units after the interface record.
//
// A unit N>0 tunnel is a DIFFERENT device and shadows nothing, so an
// interface-level ipip stanza alongside it is still reported — that device is
// real, is created, and is dead.
func effectiveIpipTunnelSites(cfg *Config) []ipipTunnelSite {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return nil
	}
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)

	// winner[deviceKey] = the record realized for that device.
	//
	// deviceKey is the compiled Linux device name, EXCEPT when that name is
	// empty: an unnamed record cannot shadow or be shadowed by anything, so it
	// gets a unique key instead of collapsing every unnamed record onto "".
	// Collapsing them would silently UNDER-report, which is the fail-open
	// direction for this gate.
	type record struct {
		mode string
		site ipipTunnelSite
	}
	winner := map[string]record{}
	unnamed := 0
	deviceKey := func(name string) string {
		if name != "" {
			return name
		}
		unnamed++
		return fmt.Sprintf("\x00unnamed-%d", unnamed)
	}

	for ifIdx, name := range names {
		iface := cfg.Interfaces.Interfaces[name]
		if iface == nil {
			continue
		}
		if iface.Tunnel != nil {
			winner[deviceKey(iface.Tunnel.Name)] = record{
				mode: iface.Tunnel.Mode,
				site: ipipTunnelSite{
					label: fmt.Sprintf("%q", name),
					order: [2]int{ifIdx, 0},
				},
			}
		}
		unitNums := make([]int, 0, len(iface.Units))
		for u := range iface.Units {
			unitNums = append(unitNums, u)
		}
		sort.Ints(unitNums)
		for _, u := range unitNums {
			unit := iface.Units[u]
			if unit == nil || unit.Tunnel == nil {
				continue
			}
			// Overwrites the interface-level record when the device name is
			// shared (unit 0), which is exactly the applier's precedence.
			winner[deviceKey(unit.Tunnel.Name)] = record{
				mode: unit.Tunnel.Mode,
				site: ipipTunnelSite{
					label: fmt.Sprintf("%q unit %d", name, u),
					order: [2]int{ifIdx, u + 1},
				},
			}
		}
	}

	var sites []ipipTunnelSite
	for _, rec := range winner {
		if rec.mode == "ipip" {
			sites = append(sites, rec.site)
		}
	}
	// Deterministic so the first reported error is stable across runs (Go map
	// order is randomized) and both HA nodes report identically.
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].order[0] != sites[j].order[0] {
			return sites[i].order[0] < sites[j].order[0]
		}
		return sites[i].order[1] < sites[j].order[1]
	})
	return sites
}

// ipipUnimplementedText is the shared operator-facing explanation, used by BOTH
// the strict commit gate and the ValidateConfig alarm advisory so the two can
// never drift.
func ipipUnimplementedText(where string) string {
	return fmt.Sprintf(
		"interfaces %s tunnel mode ipip: IPIP (ip-in-ip) is NOT implemented in the "+
			"userspace dataplane (#4785) — the tunnel is created but passes NO "+
			"traffic in either direction (an inbound proto-4 frame has no decap stage "+
			"and is dropped; an egress inner packet classifies as an unknown tunnel "+
			"mode and is dropped). Use `mode gre` or `mode wireguard` for a working "+
			"tunnel. Note an `ip-*` interface defaults to `mode ipip` even when the "+
			"mode is not written explicitly; a `gr-*` interface defaults to `mode gre`.",
		where)
}

// validateIpipTunnelDeadWarning is the ValidateConfig advisory (#4788, retained
// through #4785 half 1).
//
// The strict gate below covers a NEW commit. This covers the config ALREADY ON
// DISK: a generation committed by an older build loads leniently (a warning, not
// a reject, per #1960), and the alarm surfaces — `show system alarms` in the CLI
// and gRPC, plus the two security-alarm views — RECOMPUTE ValidateConfig from
// the active config rather than reading cfg.Warnings. Dropping the advisory
// from here therefore left an operator whose box carries a dead tunnel with a
// one-time apply log and a standing "No alarms currently active", which is the
// worst pairing available. The strict rejection does not reach that box; this
// does.
func validateIpipTunnelDeadWarning(cfg *Config) []string {
	sites := effectiveIpipTunnelSites(cfg)
	if len(sites) == 0 {
		return nil
	}
	warnings := make([]string, 0, len(sites))
	for _, s := range sites {
		warnings = append(warnings, ipipUnimplementedText(s.label))
	}
	return warnings
}

func validateIpipTunnelUnimplementedStrict(cfg *Config, lenient bool) ([]string, error) {
	sites := effectiveIpipTunnelSites(cfg)
	if len(sites) == 0 {
		return nil, nil
	}
	if lenient {
		warnings := make([]string, 0, len(sites))
		for _, s := range sites {
			warnings = append(warnings, ipipUnimplementedText(s.label))
		}
		return warnings, nil
	}
	// Strict: report the FIRST offender only, in the deterministic order
	// effectiveIpipTunnelSites establishes.
	return nil, errors.New(ipipUnimplementedText(sites[0].label))
}
