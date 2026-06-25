// policy_render.go holds protocols + policy rendering.
//
// Despite the filename "policy_render", this file owns both protocol
// rendering (OSPF/OSPFv3/BGP/RIP/ISIS) and policy-options rendering
// (prefix-lists, route-maps, communities). They share the
// resolveRedistribute helper and the BFD profile dedup machinery.
//
// File name held at "policy_render.go" per project-level file-layout
// mandate (exactly 5 sibling .go files in pkg/frr: manager,
// config_render, vtysh, status_parse, policy_render).
//
// Symbols:
//   - knownRedistProtocols, resolveRedistribute
//   - bfdProfile, bfdProfileName
//   - generateProtocols (OSPF/OSPFv3/BGP/RIP/ISIS)
//   - generatePolicyOptions (prefix-lists, route-maps, communities)
package frr

import (
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// sanitizeFRRValue strips ASCII control characters — the C0 set
// (0x00-0x1F, including newline) and DEL (0x7F), each replaced by a
// space — from a free-text config value (description, auth key,
// password) before it is interpolated into a generated frr.conf line.
// Render-side belt for #1798: a BGP neighbor description or auth key
// containing an embedded newline must not be able to inject extra
// frr.conf commands even if the commit-time validation layer were
// bypassed.
func sanitizeFRRValue(s string) string {
	clean := true
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	b := []byte(s)
	for i := range b {
		if b[i] < 0x20 || b[i] == 0x7f {
			b[i] = ' '
		}
	}
	return string(b)
}

// knownRedistProtocols are the FRR redistribute protocol keywords.
var knownRedistProtocols = map[string]bool{
	"connected": true, "static": true, "ospf": true, "bgp": true,
	"rip": true, "isis": true, "kernel": true,
}

// resolveRedistribute converts a Junos export value into FRR redistribute commands.
// If the value is a known protocol name, it emits a bare "redistribute <proto>".
// If it matches a policy-statement, it extracts protocols from the terms and emits
// "redistribute <proto> route-map <name>" for each.
//
// Invariant: this never emits a syntactically-invalid `redistribute
// <name>` line. FRR's `redistribute` requires a source protocol token
// (connected/static/ospf/bgp/rip/isis/kernel); a bare policy-statement or
// typo name is rejected by frr-reload.py. Because the line lands in the
// xpf-managed section, ONE rejected line degrades the WHOLE reload
// (frr-reload exits non-zero on any CMD_WARNING_CONFIG_FAILED, then the
// additive vtysh -f fallback rejects it too — every managed route and
// redistribute is lost, not just this stanza, #1880/#2223). So when an
// export cannot be resolved to a source protocol we SKIP it and warn
// rather than poison the managed reload.
//
// Two cases reach the skip-and-warn path:
//
//   - The export names a defined policy-statement, but none of its terms
//     carry a `from protocol` (e.g. it matches only from community /
//     prefix-list / as-path). This case PASSES the commit-time strict
//     validator, which checks only that the name is a known token OR a
//     defined policy-statement — it does NOT require a `from protocol`.
//     FRR's redistribute has no construct to express "redistribute
//     whatever this policy matches" without a source protocol, so there
//     is no valid line to emit.
//   - The export is neither a known protocol token nor a defined
//     policy-statement (a name that slipped past validation on a tolerant
//     load / peer-sync path, opts.lenientRoutingExportRef in pkg/config).
//     The strict validator REJECTS this case at commit; only the lenient
//     load/peer-sync path can reach the renderer with such a name.
func (m *Manager) resolveRedistribute(export string, po *config.PolicyOptionsConfig) string {
	// Junos spells directly-connected routes "direct"; FRR's redistribute
	// keyword is "connected". A bare `export direct` must render
	// `redistribute connected`, not the FRR-invalid `redistribute direct`
	// (which fails the reload). This mirrors the policy-term FromProtocols
	// normalization below and in generatePolicyOptions. The commit-time
	// gate (validateRoutingExportReferencesStrict, pkg/config) accepts
	// "direct" as a known token, so this keeps render and validation in
	// agreement (#2144).
	if export == "direct" {
		export = "connected"
	}
	if knownRedistProtocols[export] {
		return fmt.Sprintf(" redistribute %s\n", export)
	}

	if po != nil && po.PolicyStatements != nil {
		if ps, ok := po.PolicyStatements[export]; ok {
			protocols := make(map[string]bool)
			for _, term := range ps.Terms {
				for _, proto := range term.FromProtocols {
					if proto == "direct" {
						proto = "connected"
					}
					protocols[proto] = true
				}
			}
			if len(protocols) > 0 {
				sorted := make([]string, 0, len(protocols))
				for p := range protocols {
					sorted = append(sorted, p)
				}
				sort.Strings(sorted)
				var sb strings.Builder
				for _, proto := range sorted {
					fmt.Fprintf(&sb, " redistribute %s route-map %s\n", proto, export)
				}
				return sb.String()
			}
			// Defined policy-statement with no resolvable source protocol:
			// nothing valid to redistribute. Skip + warn rather than emit
			// the FRR-invalid `redistribute <policy>` that would degrade the
			// managed-section reload (#2223).
			slog.Warn("FRR redistribute export skipped: policy-statement has no `from protocol`",
				"policy", export,
				"hint", "redistribute requires a source protocol; add `from protocol <proto>` to the policy or use a bare protocol token")
			return ""
		}
	}

	// Unknown token: neither a known protocol nor a defined policy-statement
	// (a name that slipped past the strict validator on a tolerant load /
	// peer-sync path). Never emit a bare `redistribute <name>` — it has no
	// valid source protocol and would be rejected by frr-reload, degrading
	// the entire managed reload (#2223).
	slog.Warn("FRR redistribute export skipped: not a known protocol or defined policy-statement",
		"export", export,
		"hint", "use a known protocol (connected/static/ospf/bgp/rip/isis/kernel) or a defined policy-statement with a `from protocol`")
	return ""
}

// isDefinedPolicyStatement reports whether name resolves to a defined
// policy-statement in policyOptions. This is the SAME predicate the
// commit-time validator uses (checkRedist/checkPolicyRef in
// pkg/config/compiler_validate_strict.go) to distinguish a route-map-out
// reference from a bare redistribute protocol token. A defined
// policy-statement renders as `route-map <name> out`; anything else (a
// bare protocol token, or a typo that slipped past the strict validator on
// a lenient load/HA-sync path) goes to resolveRedistribute.
func isDefinedPolicyStatement(name string, po *config.PolicyOptionsConfig) bool {
	if po == nil || po.PolicyStatements == nil {
		return false
	}
	_, ok := po.PolicyStatements[name]
	return ok
}

// lastNonEmpty returns the last non-empty string in the slice, or "".
// Used to pick a neighbor's effective own export: FRR accepts only one
// `route-map <name> out` per neighbor/address-family, and Junos set-style
// accumulation means a later statement is the more-specific intent — so
// the last entry wins.
func lastNonEmpty(ss []string) string {
	for i := len(ss) - 1; i >= 0; i-- {
		if ss[i] != "" {
			return ss[i]
		}
	}
	return ""
}

// bgpEffectiveExport resolves the single peer-level export route-map name
// for a BGP neighbor/address-family, applying Junos most-specific-wins:
// the neighbor's own `export` (group/neighbor level) overrides the global
// `protocols bgp export` default. FRR takes exactly one `route-map out`
// per neighbor/AF, so we never emit two competing route-maps for one
// peer; the neighbor's own policy, when present, is the one rendered.
// Returns "" when neither the neighbor nor the global default sets an
// export (no `route-map out` line is emitted).
func bgpEffectiveExport(n *config.BGPNeighbor, globalExport string) string {
	if rm := lastNonEmpty(n.Export); rm != "" {
		return rm
	}
	return globalExport
}

// bgpEffectiveImport resolves the single peer-level import route-map name
// for a BGP neighbor/address-family, applying Junos most-specific-wins:
// the neighbor's own `import` (group/neighbor level) overrides the global
// `protocols bgp import` default. FRR takes exactly one `route-map in` per
// neighbor/AF, so we never emit two competing route-maps for one peer; the
// neighbor's own policy, when present, is the one rendered. Returns "" when
// neither the neighbor nor the global default sets an import (no
// `route-map in` line is emitted). Symmetric to bgpEffectiveExport (#2490).
//
// Unlike export, import has NO redistribute shorthand — inbound filtering is
// route-map-only. Both the caller and the commit-time validator therefore
// require an import ref to name a DEFINED policy-statement (so
// generatePolicyOptions renders a real `route-map <name>`). The caller
// guards with isDefinedPolicyStatement before emitting `route-map <name> in`
// to avoid the #2473 dangling-route-map PERMIT-ALL leak (here on the INBOUND
// direction: an undefined route-map in FRR resolves to permit-all, accepting
// every advertised prefix and defeating the operator's inbound filter).
func bgpEffectiveImport(n *config.BGPNeighbor, globalImport string) string {
	if rm := lastNonEmpty(n.Import); rm != "" {
		return rm
	}
	return globalImport
}

// bfdProfile holds a unique BFD profile (interval + multiplier).
type bfdProfile struct {
	interval   int
	multiplier int
}

// bfdPeer holds a BGP BFD peer destined for the single top-level `bfd`
// block. vrfName carries the routing-instance the peer belongs to so
// bfdd associates the session with the VRF-bound neighbor (#2489).
type bfdPeer struct {
	address    string
	vrfName    string
	interval   int
	multiplier int
}

// bfdSection accumulates BFD profiles and peers across the default
// routing instance AND every VRF so the FRR manager can emit a SINGLE
// top-level `bfd { ... }` block exactly once (#2550). FRR's bfdd is one
// global daemon; emitting a `bfd` stanza per routing instance produced
// redundant blocks and repeated profile definitions in the consolidated
// frr.conf, risking frr-reload parse warnings.
type bfdSection struct {
	profiles map[string]bfdProfile
	peers    []bfdPeer
}

// newBFDSection returns an empty accumulator.
func newBFDSection() *bfdSection {
	return &bfdSection{profiles: make(map[string]bfdProfile)}
}

// addProfile records a unique profile (dedup is by name, which already
// encodes interval+multiplier via bfdProfileName).
func (s *bfdSection) addProfile(name string, p bfdProfile) {
	s.profiles[name] = p
}

// addPeer appends a BGP BFD peer in caller (instance) order.
func (s *bfdSection) addPeer(p bfdPeer) {
	s.peers = append(s.peers, p)
}

// empty reports whether nothing was accumulated.
func (s *bfdSection) empty() bool {
	return len(s.profiles) == 0 && len(s.peers) == 0
}

// render emits a single top-level `bfd` block containing all accumulated
// peers (in instance order) followed by all profiles (sorted by name for
// deterministic output). Returns "" when nothing was accumulated. The
// per-stanza format is byte-identical to the pre-#2550 per-instance
// emission, so only the block COUNT changes (one global block instead of
// one per routing instance).
func (s *bfdSection) render() string {
	if s.empty() {
		return ""
	}
	var b strings.Builder
	b.WriteString("bfd\n")
	for _, p := range s.peers {
		// A `peer <addr>` line with no `vrf` suffix lands in the DEFAULT
		// VRF. A VRF-scoped BGP session's BFD peer MUST carry the same
		// `vrf <name>` so bfdd associates the BFD session with the
		// VRF-bound neighbor; otherwise the session stays DOWN and
		// sub-second failover never works (#2489).
		if p.vrfName != "" {
			fmt.Fprintf(&b, " peer %s vrf %s\n", p.address, p.vrfName)
		} else {
			fmt.Fprintf(&b, " peer %s\n", p.address)
		}
		multiplier := p.multiplier
		if multiplier == 0 {
			multiplier = 3
		}
		interval := p.interval
		if interval == 0 {
			interval = 300
		}
		fmt.Fprintf(&b, "  detect-multiplier %d\n", multiplier)
		fmt.Fprintf(&b, "  receive-interval %d\n", interval)
		fmt.Fprintf(&b, "  transmit-interval %d\n", interval)
		b.WriteString(" exit\n")
	}
	var profileNames []string
	for name := range s.profiles {
		profileNames = append(profileNames, name)
	}
	sort.Strings(profileNames)
	for _, name := range profileNames {
		p := s.profiles[name]
		interval := p.interval
		if interval == 0 {
			interval = 300
		}
		multiplier := p.multiplier
		if multiplier == 0 {
			multiplier = 3
		}
		fmt.Fprintf(&b, " profile %s\n", name)
		fmt.Fprintf(&b, "  detect-multiplier %d\n", multiplier)
		fmt.Fprintf(&b, "  receive-interval %d\n", interval)
		fmt.Fprintf(&b, "  transmit-interval %d\n", interval)
		b.WriteString(" exit\n")
	}
	b.WriteString("exit\n!\n")
	return b.String()
}

// bfdProfileName returns a deterministic profile name like "xpf-300-3".
func bfdProfileName(interval, multiplier int) string {
	if interval == 0 {
		interval = 300
	}
	if multiplier == 0 {
		multiplier = 3
	}
	return fmt.Sprintf("xpf-%d-%d", interval, multiplier)
}

// generateProtocols generates FRR CLI config for OSPF, BGP, RIP, and IS-IS.
// If vrfName is non-empty, generates VRF-scoped commands.
// ecmpMaxPaths > 1 enables ECMP with the given maximum equal-cost paths.
// policyOptions is used to resolve export policy names to route-map references.
//
// BFD emission (#2550): when the optional `shared` accumulator is provided
// (the manager passes one section across the default instance AND every
// VRF), this function ONLY accumulates BFD profiles/peers into it and emits
// NO `bfd` block — the manager renders a single global block once. When no
// shared section is passed (direct callers / unit tests), it falls back to
// a function-local section emitted at the end, preserving the historical
// single-instance behavior byte-for-byte.
func (m *Manager) generateProtocols(ospf *config.OSPFConfig, ospfv3 *config.OSPFv3Config, bgp *config.BGPConfig, rip *config.RIPConfig, isis *config.ISISConfig, vrfName string, ecmpMaxPaths int, policyOptions *config.PolicyOptionsConfig, shared ...*bfdSection) string {
	var b strings.Builder
	var bfd *bfdSection
	emitLocal := false
	if len(shared) > 0 && shared[0] != nil {
		bfd = shared[0]
	} else {
		bfd = newBFDSection()
		emitLocal = true
	}

	vrfSuffix := ""
	if vrfName != "" {
		vrfSuffix = " vrf " + vrfName
	}

	if ospf != nil {
		fmt.Fprintf(&b, "router ospf%s\n", vrfSuffix)
		if ospf.RouterID != "" {
			fmt.Fprintf(&b, " ospf router-id %s\n", ospf.RouterID)
		}
		if ospf.ReferenceBandwidth > 0 {
			fmt.Fprintf(&b, " auto-cost reference-bandwidth %d\n", ospf.ReferenceBandwidth)
		}
		if ospf.PassiveDefault {
			b.WriteString(" passive-interface default\n")
		}
		for _, area := range ospf.Areas {
			for _, iface := range area.Interfaces {
				// OSPFv2 area membership is activated per-interface in the
				// "interface <name>" block below via "ip ospf area <id>", NOT
				// with a "network <prefix> area" statement here. A global
				// "network 0.0.0.0/0 area" matches EVERY IPv4 interface in
				// the VRF (over-activation; render order silently decides the
				// area when multiple areas exist), and FRR ospfd does not
				// support mixing "network" and "ip ospf" activation on one
				// instance (#1712). passive-interface directives are
				// independent of activation and remain under "router ospf".
				if ospf.PassiveDefault {
					if iface.NoPassive {
						fmt.Fprintf(&b, " no passive-interface %s\n", iface.Name)
					}
				} else if iface.Passive {
					fmt.Fprintf(&b, " passive-interface %s\n", iface.Name)
				}
			}
			if area.AreaType != "" {
				if area.NoSummary {
					fmt.Fprintf(&b, " area %s %s no-summary\n", area.ID, area.AreaType)
				} else {
					fmt.Fprintf(&b, " area %s %s\n", area.ID, area.AreaType)
				}
			}
			for _, vl := range area.VirtualLinks {
				fmt.Fprintf(&b, " area %s virtual-link %s\n", vl.TransitArea, vl.NeighborID)
			}
		}
		if ecmpMaxPaths > 1 {
			fmt.Fprintf(&b, " maximum-paths %d\n", ecmpMaxPaths)
		}
		for _, export := range ospf.Export {
			b.WriteString(m.resolveRedistribute(export, policyOptions))
		}
		b.WriteString("exit\n!\n")
		// OSPF interface settings + per-interface area activation. The
		// "interface <name>" block is emitted UNCONDITIONALLY for every
		// configured OSPF interface because "ip ospf area <id>" is now the
		// sole activation mechanism (the global "network 0.0.0.0/0 area"
		// line was removed above, #1712). Cost / network-type / auth / BFD
		// lines remain optional within the block.
		for _, area := range ospf.Areas {
			for _, iface := range area.Interfaces {
				fmt.Fprintf(&b, "interface %s\n", iface.Name)
				if iface.Cost > 0 {
					fmt.Fprintf(&b, " ip ospf cost %d\n", iface.Cost)
				}
				if iface.NetworkType != "" {
					fmt.Fprintf(&b, " ip ospf network %s\n", iface.NetworkType)
				}
				if iface.AuthType == "md5" {
					b.WriteString(" ip ospf authentication message-digest\n")
					keyID := iface.AuthKeyID
					if keyID == 0 {
						keyID = 1
					}
					fmt.Fprintf(&b, " ip ospf message-digest-key %d md5 %s\n", keyID, sanitizeFRRValue(iface.AuthKey.Reveal()))
				} else if iface.AuthType == "simple" {
					b.WriteString(" ip ospf authentication\n")
					fmt.Fprintf(&b, " ip ospf authentication-key %s\n", sanitizeFRRValue(iface.AuthKey.Reveal()))
				}
				if iface.BFD {
					if iface.BFDInterval > 0 || iface.BFDMultiplier > 0 {
						profile := bfdProfileName(iface.BFDInterval, iface.BFDMultiplier)
						bfd.addProfile(profile, bfdProfile{iface.BFDInterval, iface.BFDMultiplier})
						fmt.Fprintf(&b, " ip ospf bfd profile %s\n", profile)
					} else {
						b.WriteString(" ip ospf bfd\n")
					}
				}
				fmt.Fprintf(&b, " ip ospf area %s\n", area.ID)
				b.WriteString("exit\n!\n")
			}
		}
	}

	if ospfv3 != nil {
		fmt.Fprintf(&b, "router ospf6%s\n", vrfSuffix)
		if ospfv3.RouterID != "" {
			fmt.Fprintf(&b, " ospf6 router-id %s\n", ospfv3.RouterID)
		}
		for _, area := range ospfv3.Areas {
			for _, iface := range area.Interfaces {
				fmt.Fprintf(&b, " interface %s area %s\n", iface.Name, area.ID)
			}
		}
		for _, export := range ospfv3.Export {
			b.WriteString(m.resolveRedistribute(export, policyOptions))
		}
		b.WriteString("exit\n!\n")
		for _, area := range ospfv3.Areas {
			for _, iface := range area.Interfaces {
				if iface.Cost > 0 || iface.Passive || iface.BFD {
					fmt.Fprintf(&b, "interface %s\n", iface.Name)
					if iface.Passive {
						b.WriteString(" ipv6 ospf6 passive\n")
					}
					if iface.Cost > 0 {
						fmt.Fprintf(&b, " ipv6 ospf6 cost %d\n", iface.Cost)
					}
					if iface.BFD {
						if iface.BFDInterval > 0 || iface.BFDMultiplier > 0 {
							profile := bfdProfileName(iface.BFDInterval, iface.BFDMultiplier)
							bfd.addProfile(profile, bfdProfile{iface.BFDInterval, iface.BFDMultiplier})
							fmt.Fprintf(&b, " ipv6 ospf6 bfd profile %s\n", profile)
						} else {
							b.WriteString(" ipv6 ospf6 bfd\n")
						}
					}
					b.WriteString("exit\n!\n")
				}
			}
		}
	}

	if bgp != nil && bgp.LocalAS > 0 {
		fmt.Fprintf(&b, "router bgp %d%s\n", bgp.LocalAS, vrfSuffix)
		if bgp.RouterID != "" {
			fmt.Fprintf(&b, " bgp router-id %s\n", bgp.RouterID)
		}
		if bgp.ClusterID != "" {
			fmt.Fprintf(&b, " bgp cluster-id %s\n", bgp.ClusterID)
		}
		if bgp.GracefulRestart {
			b.WriteString(" bgp graceful-restart\n")
		}
		if bgp.LogNeighborChanges {
			b.WriteString(" bgp log-neighbor-changes\n")
		}
		if bgp.MultipathMultipleAS {
			b.WriteString(" bgp bestpath as-path multipath-relax\n")
		}
		if bgp.Dampening {
			hl := bgp.DampeningHalfLife
			if hl == 0 {
				hl = 15
			}
			reuse := bgp.DampeningReuse
			if reuse == 0 {
				reuse = 750
			}
			suppress := bgp.DampeningSuppress
			if suppress == 0 {
				suppress = 2000
			}
			maxSup := bgp.DampeningMaxSuppress
			if maxSup == 0 {
				maxSup = 60
			}
			fmt.Fprintf(&b, " bgp dampening %d %d %d %d\n", hl, reuse, suppress, maxSup)
		}
		for _, n := range bgp.Neighbors {
			fmt.Fprintf(&b, " neighbor %s remote-as %d\n", n.Address, n.PeerAS)
			if n.Description != "" {
				fmt.Fprintf(&b, " neighbor %s description %s\n", n.Address, sanitizeFRRValue(n.Description))
			}
			if n.MultihopTTL > 0 {
				fmt.Fprintf(&b, " neighbor %s ebgp-multihop %d\n", n.Address, n.MultihopTTL)
			}
			if n.AuthPassword != "" {
				fmt.Fprintf(&b, " neighbor %s password %s\n", n.Address, sanitizeFRRValue(n.AuthPassword.Reveal()))
			}
			if n.BFD {
				fmt.Fprintf(&b, " neighbor %s bfd\n", n.Address)
			}
			if n.RouteReflectorClient {
				fmt.Fprintf(&b, " neighbor %s route-reflector-client\n", n.Address)
			}
			if n.AllowASIn > 0 {
				fmt.Fprintf(&b, " neighbor %s allowas-in %d\n", n.Address, n.AllowASIn)
			}
			if n.RemovePrivateAS {
				fmt.Fprintf(&b, " neighbor %s remove-private-AS\n", n.Address)
			}
		}
		// A global `protocols bgp export <token>` has TWO legitimate
		// shapes that render differently (#2473):
		//
		//   - A DEFINED policy-statement name → a Junos default export
		//     policy applied to every BGP peer, i.e. a peer-level
		//     `route-map <name> out` per neighbor/address-family. It MUST
		//     NOT be routed through resolveRedistribute: doing so emitted
		//     `redistribute ospf route-map ...` under `router bgp`, which
		//     actively ANNOUNCES all OSPF/connected routes into BGP (route
		//     leak, #2473 failure mode 1), and for a prefix/community-only
		//     policy with no `from protocol` it returned "" and SILENTLY
		//     DROPPED the operator's advertise filter (#2473 failure mode
		//     2). The route-map is already emitted by generatePolicyOptions,
		//     so `route-map out` filters advertisements without leaking the
		//     internal RIB.
		//
		//   - A BARE PROTOCOL TOKEN (connected/direct/static/kernel/ospf/
		//     bgp/rip/isis — i.e. NOT a defined policy-statement) → this
		//     firewall's redistribution shorthand, a genuine `redistribute
		//     <proto>`. It has NO route-map to reference, so it must keep
		//     going through resolveRedistribute. Rendering it as
		//     `neighbor X route-map connected out` would point at a
		//     non-existent route-map, which FRR resolves to PERMIT-ALL —
		//     advertising the entire table (a NEW leak). So we classify
		//     each token by the SAME policy-statement-exists predicate the
		//     commit-time validator uses (checkRedist/checkPolicyRef in
		//     pkg/config) and split the two render paths.
		//
		// Coexistence (Junos most-specific-wins) applies ONLY among the
		// policy-statement-name route-map-out exports: a per-neighbor
		// export overrides the global default for that neighbor. FRR
		// accepts a single `route-map out` per neighbor/AF, so exactly one
		// is emitted — the neighbor's own when present, else the global
		// default (bgpEffectiveExport). A bare-token redistribute is a
		// GLOBAL redistribute verb, not per-neighbor, and is emitted once
		// under `router bgp`.
		globalExport := ""
		for _, e := range bgp.Export {
			if e == "" {
				continue
			}
			if isDefinedPolicyStatement(e, policyOptions) {
				// Policy-statement name → peer-level route-map out
				// global default. Later entry wins (lastNonEmpty
				// semantics, applied inline here).
				globalExport = e
			} else {
				// Bare protocol token (or a name that slipped the
				// validator on a lenient load/HA-sync path) → genuine
				// redistribute. resolveRedistribute normalizes direct→
				// connected and refuses to emit an invalid bare-name
				// line (#2223).
				b.WriteString(m.resolveRedistribute(e, policyOptions))
			}
		}

		// Global `protocols bgp import <policy>` default (#2490). Unlike
		// export there is NO redistribute equivalent for inbound filtering
		// (FRR has no "redistribute in") — import is route-map-only. An
		// import ref MUST therefore name a DEFINED policy-statement so the
		// route-map below references a route-map that generatePolicyOptions
		// actually emits. A bare/undefined ref is REJECTED at commit
		// (validateRoutingExportReferencesStrict, strict) and SKIPPED here
		// on the lenient load/HA-sync path: rendering `route-map <token> in`
		// for a non-existent route-map would resolve to PERMIT-ALL in FRR
		// and silently accept every inbound advertisement — the #2473
		// dangling-route-map leak, INBOUND direction. Later defined entry
		// wins (lastNonEmpty semantics, applied inline).
		globalImport := ""
		for _, e := range bgp.Import {
			if e == "" {
				continue
			}
			if isDefinedPolicyStatement(e, policyOptions) {
				globalImport = e
			}
		}

		// Address-family blocks for neighbors with family declarations.
		// When a global default export exists it must reach EVERY peer,
		// including neighbors with no explicit `family` (FRR default-
		// activates those under ipv4 unicast), so route them into the
		// ipv4 set in that case.
		var inet4Neighbors, inet6Neighbors []*config.BGPNeighbor
		for _, n := range bgp.Neighbors {
			// A neighbor lands in the ipv4 (default) AF when it explicitly
			// declares family inet, OR when a peer-level policy must reach it
			// and it has not been pinned to inet6: a global export/import
			// default, or its own per-neighbor export/import (FRR default-
			// activates a family-less neighbor under ipv4 unicast). Per-
			// neighbor import/export inclusion is #2490 (symmetric to the
			// global-default inclusion #2473 added).
			hasOwnPolicy := bgpEffectiveExport(n, "") != "" || bgpEffectiveImport(n, "") != ""
			if n.FamilyInet || ((globalExport != "" || globalImport != "" || hasOwnPolicy) && !n.FamilyInet6) {
				inet4Neighbors = append(inet4Neighbors, n)
			}
			if n.FamilyInet6 {
				inet6Neighbors = append(inet6Neighbors, n)
			}
		}
		// BGP maximum-paths is driven ONLY by the explicit `protocols bgp
		// multipath` knob (bgp.Multipath), never seeded from the global
		// forwarding-table ECMP setting (ecmpMaxPaths). ECMP is a zebra/
		// kernel forwarding concept; rendering it into the BGP address-
		// families would silently turn on BGP multipath path-selection the
		// operator never asked for (#2791). The global ECMP knob still
		// reaches the IGP `maximum-paths` lines (OSPF/zebra) above via
		// ecmpMaxPaths.
		bgpMaxPaths := bgp.Multipath
		if len(inet4Neighbors) > 0 || bgpMaxPaths > 1 {
			b.WriteString(" !\n address-family ipv4 unicast\n")
			if bgpMaxPaths > 1 {
				fmt.Fprintf(&b, "  maximum-paths %d\n", bgpMaxPaths)
			}
			for _, n := range inet4Neighbors {
				fmt.Fprintf(&b, "  neighbor %s activate\n", n.Address)
				if n.DefaultOriginate {
					fmt.Fprintf(&b, "  neighbor %s default-originate\n", n.Address)
				}
				if n.PrefixLimitInet > 0 {
					fmt.Fprintf(&b, "  neighbor %s maximum-prefix %d\n", n.Address, n.PrefixLimitInet)
				}
				// Outbound filter. Emit ONLY for a defined policy-statement,
				// the same guard the inbound path uses (#2539, sibling of the
				// #2490 inbound guard below). globalExport is already
				// restricted to defined policy-statements (bare protocol
				// tokens take the redistribute path via the #2473
				// classification above), but a per-neighbor n.Export — now
				// parseable as of #2490 — can carry a bare token or an
				// undefined ref that slipped the strict validator on the
				// lenient load/HA-sync path. Without the guard that renders a
				// dangling `route-map out` = FRR permit-all OUTBOUND (the
				// entire table advertised to the peer). Bare tokens stay on
				// the redistribute path (never reach here as a defined name),
				// so the #2473 bare-token→redistribute behavior is unchanged.
				if rm := bgpEffectiveExport(n, globalExport); rm != "" && isDefinedPolicyStatement(rm, policyOptions) {
					fmt.Fprintf(&b, "  neighbor %s route-map %s out\n", n.Address, rm)
				}
				// Inbound filter (#2490). Emit ONLY for a defined
				// policy-statement so we never point `route-map in` at a
				// non-existent route-map (FRR permit-all). The effective
				// import may resolve to a per-neighbor ref that slipped the
				// validator on a lenient load/HA-sync path; the guard drops
				// it rather than leaking the inbound filter.
				if rm := bgpEffectiveImport(n, globalImport); rm != "" && isDefinedPolicyStatement(rm, policyOptions) {
					fmt.Fprintf(&b, "  neighbor %s route-map %s in\n", n.Address, rm)
				}
			}
			b.WriteString(" exit-address-family\n")
		}
		if len(inet6Neighbors) > 0 || bgpMaxPaths > 1 {
			b.WriteString(" !\n address-family ipv6 unicast\n")
			if bgpMaxPaths > 1 {
				fmt.Fprintf(&b, "  maximum-paths %d\n", bgpMaxPaths)
			}
			for _, n := range inet6Neighbors {
				fmt.Fprintf(&b, "  neighbor %s activate\n", n.Address)
				if n.DefaultOriginate {
					fmt.Fprintf(&b, "  neighbor %s default-originate\n", n.Address)
				}
				if n.PrefixLimitInet6 > 0 {
					fmt.Fprintf(&b, "  neighbor %s maximum-prefix %d\n", n.Address, n.PrefixLimitInet6)
				}
				// Outbound filter (#2539) — see the ipv4 block above.
				if rm := bgpEffectiveExport(n, globalExport); rm != "" && isDefinedPolicyStatement(rm, policyOptions) {
					fmt.Fprintf(&b, "  neighbor %s route-map %s out\n", n.Address, rm)
				}
				// Inbound filter (#2490) — see the ipv4 block above.
				if rm := bgpEffectiveImport(n, globalImport); rm != "" && isDefinedPolicyStatement(rm, policyOptions) {
					fmt.Fprintf(&b, "  neighbor %s route-map %s in\n", n.Address, rm)
				}
			}
			b.WriteString(" exit-address-family\n")
		}

		b.WriteString("exit\n!\n")
	}

	if rip != nil {
		fmt.Fprintf(&b, "router rip%s\n", vrfSuffix)
		for _, iface := range rip.Interfaces {
			fmt.Fprintf(&b, " network %s\n", iface)
		}
		for _, iface := range rip.Passive {
			fmt.Fprintf(&b, " passive-interface %s\n", iface)
		}
		for _, r := range rip.Redistribute {
			b.WriteString(m.resolveRedistribute(r, policyOptions))
		}
		b.WriteString("exit\n!\n")
		// RIP per-interface authentication
		if rip.AuthKey != "" {
			for _, iface := range rip.Interfaces {
				fmt.Fprintf(&b, "interface %s\n", iface)
				if rip.AuthType == "md5" {
					b.WriteString(" ip rip authentication mode md5\n")
				} else {
					b.WriteString(" ip rip authentication mode text\n")
				}
				fmt.Fprintf(&b, " ip rip authentication string %s\n", sanitizeFRRValue(rip.AuthKey.Reveal()))
				b.WriteString("exit\n!\n")
			}
		}
	}

	if isis != nil {
		fmt.Fprintf(&b, "router isis xpf%s\n", vrfSuffix)
		if isis.NET != "" {
			fmt.Fprintf(&b, " net %s\n", isis.NET)
		}
		level := isis.Level
		if level == "" {
			level = "level-2"
		}
		switch level {
		case "level-1":
			b.WriteString(" is-type level-1\n")
		case "level-2":
			b.WriteString(" is-type level-2-only\n")
		case "level-1-2":
			b.WriteString(" is-type level-1-2\n")
		}
		for _, export := range isis.Export {
			b.WriteString(m.resolveRedistribute(export, policyOptions))
		}
		if isis.WideMetricsOnly {
			b.WriteString(" metric-style wide\n")
		}
		if isis.Overload {
			b.WriteString(" set-overload-bit\n")
		}
		if isis.AuthKey != "" {
			if isis.AuthType == "md5" {
				fmt.Fprintf(&b, " area-password md5 %s\n", sanitizeFRRValue(isis.AuthKey.Reveal()))
				fmt.Fprintf(&b, " domain-password md5 %s\n", sanitizeFRRValue(isis.AuthKey.Reveal()))
			} else {
				fmt.Fprintf(&b, " area-password clear %s\n", sanitizeFRRValue(isis.AuthKey.Reveal()))
				fmt.Fprintf(&b, " domain-password clear %s\n", sanitizeFRRValue(isis.AuthKey.Reveal()))
			}
		}
		b.WriteString("exit\n!\n")
		for _, iface := range isis.Interfaces {
			fmt.Fprintf(&b, "interface %s\n", iface.Name)
			fmt.Fprintf(&b, " ip router isis xpf\n")
			if iface.Passive {
				b.WriteString(" isis passive\n")
			}
			if iface.Metric > 0 {
				fmt.Fprintf(&b, " isis metric %d\n", iface.Metric)
			}
			if iface.AuthKey != "" {
				if iface.AuthType == "md5" {
					fmt.Fprintf(&b, " isis password md5 %s\n", sanitizeFRRValue(iface.AuthKey.Reveal()))
				} else {
					fmt.Fprintf(&b, " isis password clear %s\n", sanitizeFRRValue(iface.AuthKey.Reveal()))
				}
			}
			b.WriteString("exit\n!\n")
			if iface.BFD {
				if iface.BFDInterval > 0 || iface.BFDMultiplier > 0 {
					profile := bfdProfileName(iface.BFDInterval, iface.BFDMultiplier)
					bfd.addProfile(profile, bfdProfile{iface.BFDInterval, iface.BFDMultiplier})
					fmt.Fprintf(&b, " isis bfd profile %s\n", profile)
				} else {
					b.WriteString(" isis bfd\n")
				}
			}
		}
	}

	// Accumulate BFD peer entries for BGP neighbors with BFD enabled. The
	// in-scope vrfName is recorded with each peer so the single global
	// block carries the matching `vrf <name>` suffix (#2489). Emission is
	// deferred to bfdSection.render() — either here (local fallback) or by
	// the manager for the consolidated global block (#2550).
	if bgp != nil {
		for _, n := range bgp.Neighbors {
			if n.BFD {
				bfd.addPeer(bfdPeer{
					address:    n.Address,
					vrfName:    vrfName,
					interval:   n.BFDInterval,
					multiplier: n.BFDMultiplier,
				})
			}
		}
	}

	// In local-fallback mode (no shared accumulator from the manager) emit
	// the single `bfd` block here, preserving historical single-instance
	// output. In shared mode the manager renders one global block instead.
	if emitLocal {
		b.WriteString(bfd.render())
	}

	return b.String()
}

// renderRouteFilterEntry writes the single FRR `ip|ipv6 prefix-list`
// entry line for one route-filter into list plName at seq slot
// (idx+1)*5, applying the per-match-type ge/le derivation. It returns
// emitted=true when a line was written, emitted=false when the entry was
// skipped (a max-length `longer` empty set, a malformed prefix, an
// out-of-range `prefix-length-range`, or an unhandled match-type) — see
// the per-arm comments for the FRR-validity / fail-closed reasoning
// (#2072/#2103/#2105/#2525). Family selection (the namespace `ip` vs
// `ipv6`) is intrinsic to the prefix, so a single mixed-family
// route-filter slice can be rendered correctly by calling this per entry.
func renderRouteFilterEntry(b *strings.Builder, plName string, idx int, rf *config.RouteFilter) (emitted bool) {
	isV6 := strings.Contains(rf.Prefix, ":")
	matchStr := "le 32"
	if isV6 {
		matchStr = "le 128"
	}
	// skipEntry suppresses this route-filter's prefix-list line entirely
	// (match-nothing for this entry) rather than emitting an FRR-invalid
	// line. Set by the #2103 max-length "longer" guard and the #2105
	// malformed-prefix belt below.
	skipEntry := false
	// #2105 render-side belt-and-suspenders: a malformed prefix must
	// NEVER reach an FRR line. The commit-time keyValidator
	// (ValidateRouteFilterArg) rejects these on the strict path, but the
	// lenient-on-load path (Store.Load / SyncApply, #1960) can still feed
	// a stored pre-gate garbage prefix to the renderer. Use the SAME
	// net.ParseCIDR check as the commit validator so the belt's coverage
	// matches it exactly.
	if _, _, err := net.ParseCIDR(rf.Prefix); err != nil {
		skipEntry = true
	}
	switch rf.MatchType {
	case "exact":
		matchStr = ""
	case "longer":
		// longer = strictly more specific (the prefix itself EXCLUDED).
		// For a max-length prefix (/32 v4, /128 v6) there are no
		// more-specifics, so "longer" is the EMPTY set — skip the entry
		// rather than emit an FRR-invalid "ge plen+1 le maxLen" line
		// (e.g. "ge 33 le 32"). Mirrors the upto plen>=maxLen guard
		// (#2102) and closes #2103. Boundary: plen+1 > maxLen skips ONLY
		// plen==maxLen — /31 still emits "ge 32 le 32".
		parts := strings.SplitN(rf.Prefix, "/", 2)
		if len(parts) == 2 {
			if plen, err := strconv.Atoi(parts[1]); err == nil {
				maxLen := 32
				if isV6 {
					maxLen = 128
				}
				if plen+1 > maxLen {
					skipEntry = true
				} else {
					matchStr = fmt.Sprintf("ge %d le %d", plen+1, maxLen)
				}
			}
		}
	case "orlonger":
		// orlonger = this prefix or any more specific (default le 32/128)
	case "prefix-length-range":
		// prefix-length-range /low-/high = match any route whose prefix
		// length is in [low, high] and that falls under the base prefix.
		// FRR expresses a bounded length range directly as "ge low le
		// high" (#2525). validateRouteFilterMatchTypesStrict has already
		// rejected an inverted / out-of-range / at-or-below-base range on
		// the commit path; this arm is the lenient-path belt: it emits
		// "ge low le high" ONLY when the bounds are present and FRR-valid,
		// else skips (match-nothing, fail-closed) rather than fall through
		// to the open-ended "le maxLen" default (the #2525 bug). FRR
		// requires "len < ge-value", so RangeLow must be > baseLen.
		maxLen := 32
		if isV6 {
			maxLen = 128
		}
		baseLen := 0
		if _, ipnet, err := net.ParseCIDR(rf.Prefix); err == nil {
			baseLen, _ = ipnet.Mask.Size()
		}
		if rf.RangeLow > baseLen && rf.RangeLow <= rf.RangeHigh && rf.RangeHigh <= maxLen {
			matchStr = fmt.Sprintf("ge %d le %d", rf.RangeLow, rf.RangeHigh)
		} else {
			skipEntry = true
		}
	case "through":
		// through <prefix2> has no lossless FRR equivalent: Junos
		// "through" matches a two-prefix radix-tree containment path, not
		// a length range. validateRouteFilterMatchTypesStrict rejects it
		// at commit; only the tolerant load/peer-sync path can reach the
		// renderer with it. Skip (match-nothing, fail-closed) rather than
		// emit a wrong / open-ended line (#2525).
		skipEntry = true
	default:
		// Any match-type admitted by the schema but not handled above (a
		// future keyword, or a value that slipped past validation on a
		// tolerant path) MUST NOT fall through to the pre-switch
		// open-ended "le maxLen" default — that silently degrades a
		// constrained match to an orlonger-style permit (#2525). Skip the
		// entry instead: match-nothing is fail-closed.
		skipEntry = true
	case "upto":
		// upto /N = this prefix or any more specific, but no longer than
		// /N. FRR renders this as a bare "le N". FRR requires len <
		// le-value, so this arm computes matchStr from scratch and never
		// keeps an invalid value — including the inherited default le
		// 32/128, which is itself invalid when plen == maxLen (#2102, the
		// /32 upto /31 case). See the original generatePolicyOptions
		// comment block for the full rule table (#2072).
		parts := strings.SplitN(rf.Prefix, "/", 2)
		if len(parts) == 2 {
			if plen, err := strconv.Atoi(parts[1]); err == nil {
				maxLen := 32
				if strings.Contains(rf.Prefix, ":") {
					maxLen = 128
				}
				switch {
				case rf.UptoLen <= 0:
					if plen >= maxLen {
						matchStr = ""
					} else {
						matchStr = fmt.Sprintf("le %d", maxLen)
					}
				case plen >= maxLen:
					matchStr = ""
				case rf.UptoLen == plen:
					matchStr = ""
				case rf.UptoLen > plen && rf.UptoLen <= maxLen:
					matchStr = fmt.Sprintf("le %d", rf.UptoLen)
				default:
					matchStr = fmt.Sprintf("le %d", maxLen)
				}
			}
		}
	}
	if skipEntry {
		// #2103/#2105: emit no prefix-list line for this entry. Its seq
		// slot (idx+1)*5 is simply not used; gaps in seq are FRR-legal.
		return false
	}
	if isV6 {
		fmt.Fprintf(b, "ipv6 prefix-list %s seq %d permit %s", plName, (idx+1)*5, rf.Prefix)
	} else {
		fmt.Fprintf(b, "ip prefix-list %s seq %d permit %s", plName, (idx+1)*5, rf.Prefix)
	}
	if matchStr != "" {
		fmt.Fprintf(b, " %s", matchStr)
	}
	b.WriteString("\n")
	return true
}

// indexedRouteFilter carries a route-filter together with its ORIGINAL
// index in the term's route-filter slice so the FRR prefix-list entry
// seq slot ((idx+1)*5) stays stable when the slice is partitioned by
// family. Holding the original index keeps a split mixed-family term's
// per-family entries at the same seq numbers they would have had in the
// single combined list (gaps where the other family's entries sit are
// FRR-legal).
type indexedRouteFilter struct {
	idx int
	rf  *config.RouteFilter
}

// partitionRouteFiltersByFamily splits a term's route-filters into IPv4
// and IPv6 buckets by the prefix's family (`:` → v6), preserving each
// entry's original index. A route-filter whose prefix is malformed
// (fails net.ParseCIDR) is classified by the same `strings.Contains(":")`
// heuristic the renderer already uses for the family decision — it will
// be skipped at entry-render time anyway, so its bucket only affects
// which (possibly empty) sequence references an undefined list,
// preserving the existing fail-closed behavior.
func partitionRouteFiltersByFamily(rfs []*config.RouteFilter) (v4, v6 []indexedRouteFilter) {
	for i, rf := range rfs {
		if strings.Contains(rf.Prefix, ":") {
			v6 = append(v6, indexedRouteFilter{i, rf})
		} else {
			v4 = append(v4, indexedRouteFilter{i, rf})
		}
	}
	return v4, v6
}

// communityRegexChars are the characters whose presence in a community
// member means it cannot be a plain literal ASN:VALUE (or well-known
// name) and therefore requires an FRR `expanded` community-list (POSIX
// regex) rather than a `standard` one. A standard list rejects any of
// these at config load, failing the whole frr-reload (#2643). The set
// includes the POSIX-ERE interval/bound braces `{` `}` — a Junos
// community member is a free-form verbatim string slot (no value
// validation; the compiler copies it straight through), so a legitimate
// bound operator like `65000:1{2,3}` must route to an expanded list too.
const communityRegexChars = `*.+?^$[]()|\{}`

// communityMemberIsRegex reports whether a Junos community member value
// contains regex / wildcard metacharacters and must be rendered into an
// FRR `expanded` community-list. A plain `ASN:VALUE` (digits:digits) or a
// well-known name ("no-export", "no-advertise", "internet", "local-AS")
// contains none of these and stays a `standard` member.
func communityMemberIsRegex(member string) bool {
	return strings.ContainsAny(member, communityRegexChars)
}

// generatePolicyOptions emits FRR prefix-list / route-map / community-list /
// as-path-access-list config from the typed Junos policy-options.
func (m *Manager) generatePolicyOptions(po *config.PolicyOptionsConfig) string {
	var b strings.Builder

	// Generate FRR prefix-lists from Junos prefix-lists
	names := make([]string, 0, len(po.PrefixLists))
	for name := range po.PrefixLists {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		pl := po.PrefixLists[name]
		for i, prefix := range pl.Prefixes {
			if strings.Contains(prefix, ":") {
				fmt.Fprintf(&b, "ipv6 prefix-list %s seq %d permit %s\n", name, (i+1)*5, prefix)
			} else {
				fmt.Fprintf(&b, "ip prefix-list %s seq %d permit %s\n", name, (i+1)*5, prefix)
			}
		}
	}
	if len(po.PrefixLists) > 0 {
		b.WriteString("!\n")
	}

	// Generate FRR community-lists from Junos community definitions
	commNames := make([]string, 0, len(po.Communities))
	for name := range po.Communities {
		commNames = append(commNames, name)
	}
	sort.Strings(commNames)
	for _, name := range commNames {
		cd := po.Communities[name]
		// FRR standard community-lists only accept literal community
		// values (ASN:VALUE or well-known names); they REJECT regex /
		// wildcard members (e.g. "65000:*", ".*") at config load, which
		// fails the whole frr-reload of the managed section. An expanded
		// community-list accepts a POSIX regex per member. FRR does NOT
		// allow the same list NAME to be both standard and expanded, so
		// the decision is per-DEFINITION: if ANY member is a regex/
		// wildcard, the ENTIRE definition is rendered as `expanded`
		// (literal members are valid regexes that match themselves);
		// otherwise it stays `standard` (#2643).
		listKind := "standard"
		for _, member := range cd.Members {
			if communityMemberIsRegex(member) {
				listKind = "expanded"
				break
			}
		}
		for _, member := range cd.Members {
			fmt.Fprintf(&b, "bgp community-list %s %s permit %s\n", listKind, name, member)
		}
	}
	if len(po.Communities) > 0 {
		b.WriteString("!\n")
	}

	// Generate FRR as-path access-lists from Junos as-path definitions
	if len(po.ASPaths) > 0 {
		aspNames := make([]string, 0, len(po.ASPaths))
		for name := range po.ASPaths {
			aspNames = append(aspNames, name)
		}
		sort.Strings(aspNames)
		for _, name := range aspNames {
			ap := po.ASPaths[name]
			fmt.Fprintf(&b, "bgp as-path access-list %s permit %s\n", name, ap.Regex)
		}
		b.WriteString("!\n")
	}

	// Generate FRR route-maps from Junos policy-statements
	psNames := make([]string, 0, len(po.PolicyStatements))
	for name := range po.PolicyStatements {
		psNames = append(psNames, name)
	}
	sort.Strings(psNames)
	for _, name := range psNames {
		ps := po.PolicyStatements[name]
		seq := 10
		for _, term := range ps.Terms {
			action := "permit"
			if term.Action == "reject" {
				action = "deny"
			}

			// Junos evaluates a policy's terms sequentially and a term that
			// carries NO terminating action (no `then accept`/`then reject`,
			// i.e. term.Action == "") APPLIES its modifications and FALLS
			// THROUGH to the next term. FRR, by contrast, stops a route-map
			// after the first sequence whose match clauses pass and that is a
			// `permit` — once the `set` clauses run the route-map evaluation
			// ends. Without an explicit continuation a Junos policy whose early
			// terms do non-terminating set work (community add, local-preference,
			// ...) and rely on a later term to accept/reject is silently
			// TRUNCATED — the later terms never execute (#2451).
			//
			// FRR's `on-match next` makes a permit sequence run its `set`
			// clauses and then CONTINUE evaluating the following sequences,
			// which is exactly Junos fall-through. We emit it for every
			// non-terminating term (rendered as `permit` above). A terminating
			// term — `then accept` (permit, stop) or `then reject` (deny, stop)
			// — must NOT get `on-match next`, so its FRR semantics match Junos
			// terminating semantics. The `on-match next` line is written after
			// the term's match/set clauses, immediately before `exit`, below.
			//
			// `on-match next` only fires on a MATCHED sequence: if a term's
			// match clauses fail, FRR moves to the next sequence regardless, so
			// emitting it on a non-terminating term never changes the behavior
			// of a non-matching term. Falling off the end of all terms still
			// hits the policy's default-action sequence (emitted after this
			// loop), preserving the overall default behavior.
			nonTerminating := term.Action != "accept" && term.Action != "reject"

			// emitTermBody renders one route-map SEQUENCE for this term: the
			// header, this term's family-specific route-filter match line, the
			// family-agnostic match clauses (source-protocol/community/as-path),
			// the optional `from prefix-list` clause, the `set`/then actions,
			// and `on-match next`/`exit`. seqFam scopes which family-specific
			// clauses are emitted:
			//   - ""   single (unsplit) sequence — the term has homogeneous or
			//          no route-filters; ALL clauses emit (byte-identical to the
			//          pre-#2607 render).
			//   - "v4" / "v6" one half of a SPLIT mixed-family route-filter
			//          term — only that family's route-filter entries + match
			//          line are emitted, and `from prefix-list` is emitted only
			//          when the referenced list's family matches seqFam.
			//
			// Why split rather than emit both `match ip` and `match ipv6` in
			// ONE sequence: FRR ANDs match clauses of DIFFERENT types within a
			// single route-map index (lib/routemap.c route_map_apply_match
			// invokes EVERY match rule with no AF pre-filter; `match ip
			// address` and `match ipv6 address` are different rule types). A
			// route is exclusively v4 or v6, so a v4 route NOMATCHes the ipv6
			// clause and a v6 route NOMATCHes the ip clause → MATCH + NOMATCH =
			// NOMATCH AND's the index to a silent deny for BOTH families. Two
			// SEPARATE sequences (one per family, each carrying the full term
			// body) is the only structure where each family's routes hit a
			// sequence they can satisfy (#2607; the same AND finding that
			// drove #2071's single-matcher decision).
			emitTermBody := func(seqFam string, seqNum int, rfs []indexedRouteFilter, plName, fromPrefixList, fromCommunity, fromASPath string) {
				fmt.Fprintf(&b, "route-map %s %s %d\n", name, action, seqNum)

				// Inline prefix-list for this sequence's route-filters.
				if len(term.RouteFilters) > 0 {
					// matchV6 selects the address family of the
					// "match ip/ipv6 address prefix-list" line. For a split
					// sequence the family is fixed by seqFam. For a single
					// sequence it is taken from the first EMITTED entry, else
					// the first parseable route-filter (a #2103-skipped /32
					// longer still names a real family), else v4 — mirroring
					// the term.PrefixList branch's "unknown/empty defaults to
					// IPv4". The match line is ALWAYS emitted (fail-closed
					// against an undefined list, see below).
					matchV6 := seqFam == "v6"
					matchFamilyKnown := seqFam != ""
					// emitted counts the prefix-list entries actually written.
					// A #2103-skipped (/32 longer, empty set) or #2105-malformed
					// entry writes NO "ip prefix-list" line, so the list may end
					// up with zero entries — and we intentionally never
					// materialise a count==0 list (FRR treats a count==0
					// prefix-list as PREFIX_PERMIT / match-ALL). The match line
					// still references the (then-undefined) list name: FRR
					// resolves an undefined prefix-list to NULL → RMAP_NOMATCH
					// (DENY), so an all-skipped term matches NOTHING and stays
					// fail-closed. Suppressing the match line would leave a bare
					// "route-map … permit <seq>" with no match clauses, which
					// FRR treats as match-ALL — flipping "/32 longer" from the
					// empty set to permit-everything (Copilot #2110).
					emitted := 0
					for _, irf := range rfs {
						// Family hint for the single-sequence case: the first
						// PARSEABLE route-filter sets it (even if later skipped),
						// the first EMITTED entry overrides. For a split sequence
						// seqFam already fixed it.
						if seqFam == "" && !matchFamilyKnown {
							if _, _, err := net.ParseCIDR(irf.rf.Prefix); err == nil {
								matchV6 = strings.Contains(irf.rf.Prefix, ":")
								matchFamilyKnown = true
							}
						}
						if renderRouteFilterEntry(&b, plName, irf.idx, irf.rf) {
							if emitted == 0 && seqFam == "" {
								matchV6 = strings.Contains(irf.rf.Prefix, ":")
								matchFamilyKnown = true
							}
							emitted++
						}
					}
					if matchV6 {
						fmt.Fprintf(&b, " match ipv6 address prefix-list %s\n", plName)
					} else {
						fmt.Fprintf(&b, " match ip address prefix-list %s\n", plName)
					}
				}

				if fromPrefixList != "" {
					// Choose the address-family matcher from the referenced
					// prefix-list's entries, mirroring the route-filter match
					// branch above. FRR keeps `ip` and `ipv6` prefix-lists in
					// independent namespaces; emitting `match ip address` for an
					// IPv6 list makes the filter a silent no-op in an IPv6
					// routing-policy context (#2071). Emit exactly one matcher;
					// any IPv6 entry selects the IPv6 matcher. A mixed (v4+v6)
					// list therefore renders the IPv6 matcher — the same
					// homogeneous-family limitation #2071 documented as a TRADE.
					// Unknown/empty lists default to IPv4.
					//
					// In a SPLIT mixed-route-filter term (seqFam != "") the
					// prefix-list match is emitted ONLY in the sequence whose
					// family matches the list, so the off-family sequence does
					// not pick up a `match ip/ipv6` clause that would AND-NOMATCH
					// its own family's routes (the #2071 co-resident collision,
					// avoided by construction here).
					//
					// fromPrefixList is ONE entry of a possibly multi-valued
					// `from prefix-list` set (#2642). Multiple entries match
					// with OR ("any") semantics, but FRR's route_map_add_match
					// REPLACES a same-type rule (lib/routemap.c), so two `match
					// ip address prefix-list` lines in one index keep only the
					// last. OR is therefore expressed by one route-map SEQUENCE
					// per entry (the dispatch loop below), each carrying the full
					// term body — exactly the #2607 split structure.
					matchKW := "ip"
					if pl := po.PrefixLists[fromPrefixList]; pl != nil {
						for _, p := range pl.Prefixes {
							if strings.Contains(p, ":") {
								matchKW = "ipv6"
								break
							}
						}
					}
					if seqFam == "" || (seqFam == "v6" && matchKW == "ipv6") || (seqFam == "v4" && matchKW == "ip") {
						fmt.Fprintf(&b, " match %s address prefix-list %s\n", matchKW, fromPrefixList)
					}
				}

				// Junos "from protocol [ bgp ospf static ]" matches ANY listed
				// protocol. FRR's "match source-protocol" only accepts a single
				// protocol per line, but repeated lines within one route-map entry
				// are OR'd, so render one line per protocol.
				for _, proto := range term.FromProtocols {
					if proto == "direct" {
						proto = "connected"
					}
					fmt.Fprintf(&b, " match source-protocol %s\n", proto)
				}

				// fromCommunity / fromASPath are ONE entry of a possibly
				// multi-valued `from community` / `from as-path` set (#2642).
				// Junos OR's repeated same-type matches; FRR can hold only one
				// `match community` / `match as-path` rule per route-map index
				// (route_map_add_match replaces same-type), so OR is expressed
				// by emitting one SEQUENCE per entry (dispatch loop below).
				if fromCommunity != "" {
					fmt.Fprintf(&b, " match community %s\n", fromCommunity)
				}

				if fromASPath != "" {
					fmt.Fprintf(&b, " match as-path %s\n", fromASPath)
				}

				// then actions
				if term.NextHop != "" {
					if term.NextHop == "peer-address" {
						// Junos "next-hop peer-address" → FRR. The session AF is not
						// known here, so emit both forms; FRR applies each only to
						// the matching address family of the carrying BGP session.
						fmt.Fprintf(&b, " set ip next-hop peer-address\n")
						fmt.Fprintf(&b, " set ipv6 next-hop peer-address\n")
					} else if term.NextHop == "self" {
						// Junos "next-hop self" → no FRR set-clause. eBGP already
						// rewrites the next-hop to self by default, so FRR needs no
						// explicit "set" here.
					} else if strings.Contains(term.NextHop, ":") {
						// IPv6 literal next-hop. FRR rejects "set ip next-hop" for a
						// v6 address (whole route-map fails to parse); v6 uses the
						// dedicated "set ipv6 next-hop global" form. Mirror the
						// AF detection used by the prefix-list renderer above.
						fmt.Fprintf(&b, " set ipv6 next-hop global %s\n", term.NextHop)
					} else {
						fmt.Fprintf(&b, " set ip next-hop %s\n", term.NextHop)
					}
				}

				if term.LoadBalance != "" {
					// FRR handles ECMP load balancing via forwarding-table export
					// The route-map just needs to be a permit
				}

				// Emit on PRESENCE, not value: local-preference 0 is a
				// valid BGP value (maximally deprioritize a route within
				// the AS). Gating on LocalPreference > 0 silently dropped
				// `set local-preference 0` (#2857).
				if term.HasLocalPreference {
					fmt.Fprintf(&b, " set local-preference %d\n", term.LocalPreference)
				}
				// Emit on PRESENCE, not value: metric/MED 0 is a valid
				// traffic-engineering value (advertise a highly preferred
				// route). Gating on Metric > 0 silently dropped `set metric
				// 0` (#2847).
				if term.HasMetric {
					fmt.Fprintf(&b, " set metric %d\n", term.Metric)
				}
				if term.MetricType == 1 || term.MetricType == 2 {
					fmt.Fprintf(&b, " set metric-type type-%d\n", term.MetricType)
				}
				if term.Community != "" {
					fmt.Fprintf(&b, " set community %s\n", term.Community)
				}
				if term.Origin != "" {
					fmt.Fprintf(&b, " set origin %s\n", term.Origin)
				}

				// Non-terminating term: fall through to the next sequence after
				// running this term's set clauses (Junos fall-through; #2451).
				// In a SPLIT term BOTH per-family sequences carry on-match next
				// for a non-terminating term — each is its own permit sequence
				// and must continue to later terms. A terminating term gets none
				// in either half (the v4-route case stops at the v4 sequence; the
				// v6-route case stops at the v6 sequence).
				if nonTerminating {
					b.WriteString(" on-match next\n")
				}

				b.WriteString("exit\n")
			}

			// Decide single vs split. A term splits ONLY when its route-filters
			// genuinely mix families (at least one v4 AND one v6 prefix). A
			// homogeneous or empty route-filter set renders as today — ONE
			// sequence, ONE plName, byte-identical output (no churn for the
			// common case).
			// Two independent OR-dimensions can each multiply the number of
			// emitted sequences:
			//   (a) route-filters that genuinely mix families (#2607) - one
			//       sequence per family; and
			//   (b) repeated same-type `from prefix-list` / `from community`
			//       / `from as-path` matches (#2642) - Junos OR's them, but
			//       FRR holds only one rule of each match TYPE per route-map
			//       index (route_map_add_match replaces same-type), so OR is
			//       expressed as one sequence per value.
			// Different match types must AND, the same type must OR. The
			// correct structure is the CARTESIAN PRODUCT of the OR-sets: each
			// emitted sequence carries exactly one prefix-list, one community,
			// one as-path (plus its family's route-filter match, all
			// source-protocol lines, and all set actions). A route that
			// satisfies (any prefix-list) AND (any community) AND (any as-path)
			// reaches at least one sequence it fully matches - the Junos
			// "(p1|p2) AND (c1|c2) AND ..." semantics.
			//
			// The common single-valued / no-match case collapses to ONE
			// sequence with the historical plName, byte-identical to master:
			// each OR-set defaults to a single "" sentinel.
			plName := name + "-" + term.Name
			v4rf, v6rf := partitionRouteFiltersByFamily(term.RouteFilters)
			mixedFamily := len(term.RouteFilters) > 0 && len(v4rf) > 0 && len(v6rf) > 0

			// orElseEmpty yields the OR-set to iterate: the field's values, or
			// a single "" sentinel so a missing match still emits one sequence
			// (the per-clause guards skip the empty value).
			orElseEmpty := func(vs []string) []string {
				if len(vs) == 0 {
					return []string{""}
				}
				return vs
			}

			// emitVariants emits the cross-product of the three from-* OR sets
			// for one route-filter family group (seqFam/rfs/famPL), advancing
			// seq by 10 per sequence. The iteration order (prefix-list,
			// community, as-path) is fixed, so output is deterministic.
			emitVariants := func(seqFam string, rfs []indexedRouteFilter, famPL string) {
				for _, pl := range orElseEmpty(term.PrefixList) {
					for _, comm := range orElseEmpty(term.FromCommunity) {
						for _, asp := range orElseEmpty(term.FromASPath) {
							emitTermBody(seqFam, seq, rfs, famPL, pl, comm, asp)
							seq += 10
						}
					}
				}
			}

			if mixedFamily {
				// Mixed-family route-filters: split into a v4 group and a v6
				// group (#2607), each carrying its own family's route-filter
				// entries into a per-family prefix-list (plName_v4 / plName_v6 -
				// FRR `ip` vs `ipv6` prefix-lists are separate namespaces anyway,
				// but the distinct NAME keeps the two match lines referencing
				// disjoint single-family lists). Within each group the from-* OR
				// cross-product is emitted; v4 first.
				emitVariants("v4", v4rf, plName+"_v4")
				emitVariants("v6", v6rf, plName+"_v6")
			} else {
				// Homogeneous or no route-filters: one family group. Pass the
				// full (possibly empty) indexed route-filter set and the
				// historical plName. With no repeated from-* matches this is a
				// single sequence, byte-identical to master.
				all := make([]indexedRouteFilter, len(term.RouteFilters))
				for i, rf := range term.RouteFilters {
					all[i] = indexedRouteFilter{i, rf}
				}
				emitVariants("", all, plName)
			}
		}

		// Default action
		if ps.DefaultAction == "reject" || ps.DefaultAction == "" {
			fmt.Fprintf(&b, "route-map %s deny %d\n", name, seq)
			b.WriteString("exit\n")
		} else if ps.DefaultAction == "accept" {
			fmt.Fprintf(&b, "route-map %s permit %d\n", name, seq)
			b.WriteString("exit\n")
		}
		b.WriteString("!\n")
	}

	return b.String()
}
