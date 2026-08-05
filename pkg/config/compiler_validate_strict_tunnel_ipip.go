package config

import (
	"errors"
	"fmt"
)

// ipipTunnelSite is one emitted tunnel endpoint whose mode is ipip, carrying
// the operator-facing label for it.
type ipipTunnelSite struct {
	label string
}

// effectiveIpipTunnelSites returns every tunnel ENDPOINT the dataplane would
// actually emit whose mode is ipip, in the emitter's own order.
//
// It delegates to EmitTunnelEndpointNames rather than walking the compiled
// records itself. That is the point (#4785 re-gate B2): the emitter is already
// the single source of truth for "which tunnel endpoints reach the dataplane
// snapshot", it is what buildTunnelEndpointSnapshots consumes, and it is what
// the sibling commit-time gate validateTunnelEndpointIDCollisionAST is built
// on — so this gate now sits behind the same drift guarantee instead of
// hand-rolling a second model of a question the codebase already answers.
//
// Three defects came from that hand-rolled model and are closed by deleting it:
//
//   - A unit with NO tunnel stanza still inherits the interface-level tunnel —
//     which the emitter does, and says so in a comment. The old walk skipped
//     exactly those units (`unit.Tunnel == nil { continue }`), so
//     `ip-0/0/0 tunnel src/dst` + `unit 0 tunnel mode gre` + a bare `unit 2`
//     let unit 0's GRE record shadow the interface record on the shared device
//     key while unit 2 — which emits ipip — was never visited. That config
//     COMMITTED with the alarm surface silent, having been correctly REJECTED
//     one commit earlier. An over-rejection fix that becomes an
//     under-rejection is worse than the bug it replaced.
//   - The old model named routing.tunnelManager as the authority. Under the
//     userspace dataplane — the only supported runtime — collectAppliedTunnels
//     sets AnchorOnly and creates a mode-INDEPENDENT Tuntap anchor. What
//     decides gre_decap_index membership versus the TunnelKind::Unknown drop
//     arm is the EMITTED endpoint's mode, which is this function's input.
//   - The emitter applies the same source/destination screen the snapshot
//     builder does, so an endpoint reported here really is emitted. A `tunnel
//     destination` with no source emits nothing and is no longer reported as a
//     dead tunnel.
//
// Ordering is the emitter's — interfaces sorted by name, units by number — so
// the first reported strict error is stable across runs and identical on both
// HA nodes.
func effectiveIpipTunnelSites(cfg *Config) []ipipTunnelSite {
	var sites []ipipTunnelSite
	for _, ep := range EmitTunnelEndpointNames(cfg) {
		if ep.Tunnel != nil && ep.Tunnel.Mode == "ipip" {
			sites = append(sites, ipipTunnelSite{label: fmt.Sprintf("%q", ep.Name)})
		}
	}
	return sites
}

// ipipUnimplementedText is the shared operator-facing explanation, used by BOTH
// the strict commit gate and the ValidateConfig alarm advisory so the two can
// never drift.
//
// The wording says nothing about kernel devices: because the caller reports
// only EMITTED endpoints, "this endpoint reaches the dataplane snapshot" is a
// measured fact, unlike the earlier indicative claim that a tunnel "is created"
// — which was false for a stanza the emitter screens out (#4785 re-gate N4).
func ipipUnimplementedText(where string) string {
	return fmt.Sprintf(
		"tunnel endpoint %s has mode ipip: IPIP (ip-in-ip) is NOT implemented in the "+
			"userspace dataplane (#4785) — this endpoint reaches the dataplane snapshot "+
			"but carries NO traffic in either direction (an inbound proto-4 frame has no "+
			"decap stage and is dropped; an egress inner packet classifies as an unknown "+
			"tunnel mode and is dropped). Use `mode gre` or `mode wireguard` for a working "+
			"tunnel. Note an `ip-*` interface defaults to `mode ipip` even when the mode is "+
			"not written explicitly, and a unit with no `tunnel` stanza of its own inherits "+
			"the interface-level tunnel; a `gr-*` interface defaults to `mode gre`.",
		where)
}

// validateIpipTunnelDeadWarning is the ValidateConfig advisory (#4788, retained
// through #4785 half 1).
//
// The strict gate below covers a NEW commit. This covers the config ALREADY ON
// DISK: a generation committed by an older build loads leniently (a warning, not
// a reject, per #1960), and the alarm surfaces — `show system alarms` in the CLI
// and gRPC, plus the two security-alarm views — RECOMPUTE ValidateConfig from
// the active config rather than reading cfg.Warnings. Without this the operator
// gets a one-time apply log and a standing "No alarms currently active" on a box
// whose tunnel carries nothing.
//
// It reports EVERY dead endpoint, not just the first: an operator who fixes one
// should not discover the next only on the following commit (#4785 re-gate N5).
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

// validateIpipTunnelUnimplementedStrict hard-rejects a config that would emit a
// tunnel endpoint whose mode is `ipip` (#4785 half 1).
//
// IPIP parses, compiles, and reaches the dataplane snapshot, but the userspace
// dataplane — the only supported runtime — has no IPIP primitive in either
// direction:
//
//   - INBOUND: forwarding_build/tunnels.rs indexes an endpoint into
//     `gre_decap_index` only when `tunnel_mode_kind(&endpoint.mode) ==
//     TunnelKind::Gre`. `ipip` classifies as `TunnelKind::Unknown`, so it is
//     never indexed and a received proto-4 frame has nothing to decap against.
//   - OUTBOUND: `TunnelKind::Unknown` is the fail-closed arm of the egress
//     encap dispatcher, which drops rather than defaulting to GRE encap (the
//     pre-#2327 fail-open behaviour).
//
// So the endpoint is dead in BOTH directions. Before this gate it committed
// green with only an advisory (#4788): the operator got a configured interface
// that passes no traffic and no error to act on. Converting the advisory into a
// rejection is the "reject, don't guess" resolution — an unimplemented feature
// must fail loudly at commit rather than succeed into a blackhole.
//
// This is DELIBERATELY not gated on "would it otherwise work": there is no
// partial IPIP support to preserve. Half 2 of #4785 implements the decap stage;
// when it lands this gate is removed, not relaxed.
//
// Strict on the operator commit / commit-check path (CompileConfig). The call
// site tolerates it on the load / peer-sync paths (opts.lenientIpipTunnelMode)
// so a config an older binary already accepted still BOOTS (#1960) — the
// runtime's own fail-closed arms keep the endpoint inert either way, so
// tolerating it there loses nothing. Mirrors validateTunnelOuterFamilyStrict,
// which it runs beside.
func validateIpipTunnelUnimplementedStrict(cfg *Config, lenient bool) ([]string, error) {
	sites := effectiveIpipTunnelSites(cfg)
	if len(sites) == 0 {
		return nil, nil
	}
	if lenient {
		// #4785 re-gate N1: return NO warnings here. runTailGates folds
		// ValidateConfig — which registers validateIpipTunnelDeadWarning — into
		// cfg.Warnings BEFORE this gate runs, so appending again emitted the
		// same ~500-character paragraph TWICE per dead endpoint on the tolerant
		// path. One registration, one warning.
		return nil, nil
	}
	// Strict: report the FIRST offender, in the emitter's deterministic order.
	// The advisory carries the full list.
	return nil, errors.New(ipipUnimplementedText(sites[0].label))
}
