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
func (m *Manager) generateProtocols(ospf *config.OSPFConfig, ospfv3 *config.OSPFv3Config, bgp *config.BGPConfig, rip *config.RIPConfig, isis *config.ISISConfig, vrfName string, ecmpMaxPaths int, policyOptions *config.PolicyOptionsConfig) string {
	var b strings.Builder
	bfdProfiles := make(map[string]bfdProfile)

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
						bfdProfiles[profile] = bfdProfile{iface.BFDInterval, iface.BFDMultiplier}
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
							bfdProfiles[profile] = bfdProfile{iface.BFDInterval, iface.BFDMultiplier}
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
		bgpMaxPaths := ecmpMaxPaths
		if bgp.Multipath > 0 && bgpMaxPaths < bgp.Multipath {
			bgpMaxPaths = bgp.Multipath
		}
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
					bfdProfiles[profile] = bfdProfile{iface.BFDInterval, iface.BFDMultiplier}
					fmt.Fprintf(&b, " isis bfd profile %s\n", profile)
				} else {
					b.WriteString(" isis bfd\n")
				}
			}
		}
	}

	// BFD peer blocks for BGP neighbors with BFD enabled
	if bgp != nil {
		var bfdPeers []*config.BGPNeighbor
		for _, n := range bgp.Neighbors {
			if n.BFD {
				bfdPeers = append(bfdPeers, n)
			}
		}
		if len(bfdPeers) > 0 {
			b.WriteString("bfd\n")
			for _, n := range bfdPeers {
				// FRR's bfdd is a single top-level daemon: a `peer <addr>`
				// line with no `vrf` suffix is created in the DEFAULT VRF.
				// A VRF-scoped BGP session's BFD peer MUST carry the same
				// `vrf <name>` so bfdd associates the BFD session with the
				// VRF-bound neighbor; otherwise the session stays DOWN and
				// sub-second failover never works (#2489). This block is
				// rendered once per BGP instance (manager.go calls
				// generateProtocols per-instance), so the in-scope vrfName
				// is correct for every peer in this block — default-instance
				// peers (vrfName == "") get no suffix.
				if vrfName != "" {
					fmt.Fprintf(&b, " peer %s vrf %s\n", n.Address, vrfName)
				} else {
					fmt.Fprintf(&b, " peer %s\n", n.Address)
				}
				multiplier := n.BFDMultiplier
				if multiplier == 0 {
					multiplier = 3
				}
				interval := n.BFDInterval
				if interval == 0 {
					interval = 300
				}
				fmt.Fprintf(&b, "  detect-multiplier %d\n", multiplier)
				fmt.Fprintf(&b, "  receive-interval %d\n", interval)
				fmt.Fprintf(&b, "  transmit-interval %d\n", interval)
				b.WriteString(" exit\n")
			}
			b.WriteString("exit\n!\n")
		}
	}

	// Emit deduplicated BFD profile stanzas
	if len(bfdProfiles) > 0 {
		// Collect and sort profile names for deterministic output
		var profileNames []string
		for name := range bfdProfiles {
			profileNames = append(profileNames, name)
		}
		sort.Strings(profileNames)
		b.WriteString("bfd\n")
		for _, name := range profileNames {
			p := bfdProfiles[name]
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
	}

	return b.String()
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
		for _, member := range cd.Members {
			fmt.Fprintf(&b, "bgp community-list standard %s permit %s\n", name, member)
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
			fmt.Fprintf(&b, "route-map %s %s %d\n", name, action, seq)

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

			// Generate an inline prefix-list for route-filters
			if len(term.RouteFilters) > 0 {
				plName := name + "-" + term.Name
				// matchV6 selects the address family of the post-loop
				// "match ip/ipv6 address prefix-list" line. It is taken
				// from the first EMITTED entry when there is one, else from
				// the first route-filter with a parseable family (a
				// #2103-skipped /32 longer still names a real family), else
				// defaults to v4 — mirroring the term.PrefixList branch's
				// "unknown/empty defaults to IPv4". The match line is
				// ALWAYS emitted (see below).
				matchV6 := false
				matchFamilyKnown := false
				// emitted counts the prefix-list entries actually written.
				// A #2103-skipped (/32 longer, empty set) or #2105-malformed
				// entry writes NO "ip prefix-list" line, so the list may end
				// up with zero entries — and we intentionally never
				// materialise a count==0 list (FRR treats a count==0
				// prefix-list as PREFIX_PERMIT / match-ALL). The match line
				// still references the (then-undefined) list name: in FRR a
				// "match … prefix-list <name>" against a name with no
				// "ip prefix-list <name>" lines resolves to NULL →
				// RMAP_NOMATCH (DENY), so an all-skipped term matches
				// NOTHING and stays fail-closed. Suppressing the match line
				// instead would leave a bare "route-map … permit <seq>" with
				// no match clauses, which FRR treats as match-ALL — flipping
				// "/32 longer" from the empty set to permit-everything
				// (Copilot #2110). This mirrors the existing
				// term.PrefixList branch, which also emits a match line for
				// an unknown/empty list.
				emitted := 0
				for i, rf := range term.RouteFilters {
					isV6 := strings.Contains(rf.Prefix, ":")
					matchStr := "le 32"
					if isV6 {
						matchStr = "le 128"
					}
					// skipEntry suppresses this route-filter's prefix-list
					// line entirely (match-nothing for this entry) rather
					// than emitting an FRR-invalid line. Set by the #2103
					// max-length "longer" guard and the #2105 malformed-
					// prefix belt below.
					skipEntry := false
					// #2105 render-side belt-and-suspenders: a malformed
					// prefix must NEVER reach an FRR line. The commit-time
					// keyValidator (ValidateRouteFilterArg) rejects these on
					// the strict path, but the lenient-on-load path
					// (Store.Load / SyncApply, #1960) can still feed a stored
					// pre-gate garbage prefix to the renderer. Use the SAME
					// net.ParseCIDR check as the commit validator so the
					// belt's coverage matches it exactly: this catches a bad
					// address (999.999.999.999/24, foo:bar/24), a missing
					// "/", a non-numeric mask, AND an out-of-family-range mask
					// (a v4 /40 or /99, a v6 /200) — none of which a bare
					// mask-only Atoi would catch. A valid CIDR (any v4/v6
					// prefix the operator could legitimately configure) is
					// never skipped.
					if _, _, err := net.ParseCIDR(rf.Prefix); err != nil {
						skipEntry = true
					} else if !matchFamilyKnown {
						// First route-filter with a PARSEABLE prefix sets the
						// match-line family — even if this entry is later
						// skipped for being a max-length "longer" (a /32 longer
						// names a real v4 family). An emitted entry overrides
						// this below, but for an all-skipped term this is the
						// best family signal we have. Stays v4 (the default)
						// only when no entry is parseable.
						matchV6 = isV6
						matchFamilyKnown = true
					}
					switch rf.MatchType {
					case "exact":
						matchStr = ""
					case "longer":
						// longer = strictly more specific (the prefix itself
						// EXCLUDED). For a max-length prefix (/32 v4, /128
						// v6) there are no more-specifics, so "longer" is the
						// EMPTY set — skip the entry rather than emit an
						// FRR-invalid "ge plen+1 le maxLen" line. For /32
						// that is "ge 33 le 32": ge 33 fails the FRR YANG
						// range (0..32) AND ge > le, and a rejected line can
						// fail the whole frr-reload (frr-reload.py applies
						// the add-batch via a single vtysh -f and exits
						// non-zero on any CMD_WARNING_CONFIG_FAILED). Mirrors
						// the upto plen>=maxLen guard (#2102) and closes
						// #2103. Boundary: plen+1 > maxLen skips ONLY
						// plen==maxLen — /31 still emits "ge 32 le 32" (one
						// legal more-specific).
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
						// prefix-length-range /low-/high = match any route
						// whose prefix length is in [low, high] and that falls
						// under the base prefix. FRR expresses a bounded length
						// range directly as "ge low le high" (#2525). The
						// compiler stores the parsed bounds in RangeLow/RangeHigh
						// (0 when the "/lo-/hi" token was malformed) and
						// validateRouteFilterMatchTypesStrict has already
						// rejected an inverted / out-of-range / at-or-below-base
						// range on the commit path. The lenient load/peer-sync
						// path (where that strict reject is downgraded to a
						// warning per #1960) can still feed a stored bad range
						// here, so this arm is belt-and-suspenders: it emits
						// "ge low le high" ONLY when the bounds are present and
						// FRR-valid, else it skips the entry (match-nothing,
						// fail-closed) rather than fall through to the open-ended
						// "le maxLen" default — which would silently widen the
						// operator's bounded constraint to an orlonger-style
						// permit (the #2525 bug).
						//
						// FRR requires the `ge` value to be STRICTLY greater than
						// the prefix length ("len < ge-value"); a `ge <= base`
						// line is rejected and a rejected line can fail the whole
						// frr-reload (#1880-class). So the guard re-derives the
						// base prefix length and requires RangeLow > baseLen,
						// mirroring the `longer` (plen+1) / `upto` guards. The
						// prefix already passed net.ParseCIDR above (the
						// skipEntry malformed-prefix belt), so it parses here.
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
						// through <prefix2> has no lossless FRR equivalent:
						// Junos "through" matches the base prefix, prefix2, and
						// only the prefixes on the direct radix-tree path
						// between them — NOT every prefix of intermediate
						// length. FRR prefix-lists can only express length
						// ranges (ge/le), so any rendering would change the
						// match set. validateRouteFilterMatchTypesStrict rejects
						// "through" at commit; only the tolerant load/peer-sync
						// path can reach the renderer with it. Skip the entry
						// (match-nothing, fail-closed) rather than silently
						// emit a wrong / open-ended line (#2525).
						skipEntry = true
					default:
						// Any match-type that is admitted by the schema but not
						// handled above (a future keyword, or a value that
						// slipped past validation on a tolerant path) MUST NOT
						// fall through to the pre-switch open-ended "le maxLen"
						// default — that silently degrades a constrained match
						// to an orlonger-style permit (the #2525 fall-through
						// bug). Skip the entry instead: match-nothing is
						// fail-closed and the ALWAYS-emitted match line then
						// resolves to RMAP_NOMATCH (DENY).
						skipEntry = true
					case "upto":
						// upto /N = this prefix or any more specific, but no
						// longer than /N. FRR renders this as a bare "le N":
						// the implicit lower bound of a le clause is the
						// prefix's own mask length, so "le N" matches the
						// prefix itself plus every more-specific down to /N.
						// This mirrors the orlonger case (bare "le max"), just
						// capped at N.
						//
						// FRR requires len < le-value (and len < ge-value); a
						// le/ge value <= the prefix length is REJECTED by FRR's
						// prefix-list validator ("make sure: len < ge-value <=
						// le-value") and an invalid line can fail the whole
						// frr-reload. This arm therefore computes matchStr from
						// scratch and is careful NEVER to keep an invalid value
						// — including the inherited default le 32/128, which is
						// itself invalid when plen == maxLen (Codex #2102 MAJOR
						// #1, the /32 upto /31 case). The rules:
						//   - plen >= maxLen  -> exact ("" ): a max-length host
						//     prefix has no more-specifics, so upto anything ==
						//     just the prefix itself. (Also dodges the invalid
						//     "le maxLen" default.)
						//   - UptoLen == plen -> exact ("" ): only the prefix.
						//   - plen < UptoLen <= maxLen -> "le N" (normal case).
						//   - else (UptoLen unset/0, < plen, or > maxLen) ->
						//     degrade to "le maxLen" (valid here because plen <
						//     maxLen), the orlonger-equivalent superset. Never
						//     an invalid line. (#2072)
						parts := strings.SplitN(rf.Prefix, "/", 2)
						if len(parts) == 2 {
							if plen, err := strconv.Atoi(parts[1]); err == nil {
								maxLen := 32
								if strings.Contains(rf.Prefix, ":") {
									maxLen = 128
								}
								switch {
								case rf.UptoLen <= 0:
									// Unset / unparseable length (0 means unset:
									// parseRouteFilterLen rejects "/0"). Degrade
									// to the orlonger-equivalent superset. This
									// MUST precede the ==plen and plen>=maxLen
									// arms so a /0 PREFIX with an unset length is
									// not mis-rendered as exact via the
									// 0==plen coincidence (Codex #2102 MAJOR #2).
									if plen >= maxLen {
										matchStr = "" // no more-specifics possible
									} else {
										matchStr = fmt.Sprintf("le %d", maxLen)
									}
								case plen >= maxLen:
									// Max-length host prefix: no more-specifics
									// exist, so upto anything == the prefix
									// itself. Exact also dodges the invalid
									// "le maxLen" (le == plen) line (Codex #2102
									// MAJOR #1, the /32 upto /31 case).
									matchStr = ""
								case rf.UptoLen == plen:
									matchStr = "" // only the prefix itself
								case rf.UptoLen > plen && rf.UptoLen <= maxLen:
									matchStr = fmt.Sprintf("le %d", rf.UptoLen)
								default:
									// UptoLen < plen (nonzero) or > maxLen.
									// Degrade. plen < maxLen here, so "le
									// maxLen" is FRR-valid. Set it explicitly
									// rather than relying on the pre-switch
									// default.
									matchStr = fmt.Sprintf("le %d", maxLen)
								}
							}
						}
					}
					if skipEntry {
						// #2103/#2105: emit no prefix-list line for this
						// entry. Its seq slot (i+1)*5 is simply not used;
						// gaps in seq are FRR-legal and keep the remaining
						// entries' seq stable across a config edit.
						continue
					}
					if isV6 {
						fmt.Fprintf(&b, "ipv6 prefix-list %s seq %d permit %s", plName, (i+1)*5, rf.Prefix)
					} else {
						fmt.Fprintf(&b, "ip prefix-list %s seq %d permit %s", plName, (i+1)*5, rf.Prefix)
					}
					if matchStr != "" {
						fmt.Fprintf(&b, " %s", matchStr)
					}
					b.WriteString("\n")
					if emitted == 0 {
						// The first EMITTED entry is the most authoritative
						// family signal; override the parseable-skipped hint.
						matchV6 = isV6
						matchFamilyKnown = true
					}
					emitted++
				}
				// ALWAYS emit the match line for a term that declares any
				// route-filter. When entries were emitted it references the
				// populated prefix-list. When ALL entries were skipped
				// (every route-filter is a max-length "longer" empty set, or
				// every prefix is malformed) the list name is never created,
				// so this references an UNDEFINED prefix-list → FRR resolves
				// it to NULL → RMAP_NOMATCH (DENY): the term matches NOTHING
				// and stays fail-closed. Suppressing the match line here
				// would leave a bare "route-map … permit <seq>" with no match
				// clauses, which FRR treats as match-ALL — flipping
				// "/32 longer" from the empty set to permit-everything
				// (Copilot #2110). This mirrors the term.PrefixList branch,
				// which likewise emits a match line for an unknown list.
				// Family: the first emitted entry, else the first parseable
				// (possibly skipped) route-filter, else v4 (the
				// term.PrefixList "unknown/empty defaults to IPv4" default).
				if matchV6 {
					fmt.Fprintf(&b, " match ipv6 address prefix-list %s\n", plName)
				} else {
					fmt.Fprintf(&b, " match ip address prefix-list %s\n", plName)
				}
			}

			if term.PrefixList != "" {
				// Choose the address-family matcher from the referenced
				// prefix-list's entries, mirroring the route-filter match
				// branch above. FRR keeps `ip` and `ipv6`
				// prefix-lists in independent namespaces; emitting the
				// IPv4 `match ip address` for an IPv6 list makes the
				// filter a silent no-op in an IPv6 routing-policy context
				// (OSPFv3 export, BGP inet6) — issue #2071. Two matchers
				// must NOT both appear in one route-map index: FRR ANDs
				// match clauses (MATCH + NOMATCH = NOMATCH), so an
				// off-family clause against the populated sibling-namespace
				// list would deny the route. Emit exactly one matcher;
				// any IPv6 entry selects the IPv6 matcher. A mixed
				// (v4+v6) list therefore renders the IPv6 matcher — the
				// same homogeneous-family limitation the route-filter path
				// already has. Unknown/empty lists default to IPv4,
				// byte-identical to the pre-fix render.
				matchKW := "ip"
				if pl := po.PrefixLists[term.PrefixList]; pl != nil {
					for _, p := range pl.Prefixes {
						if strings.Contains(p, ":") {
							matchKW = "ipv6"
							break
						}
					}
				}
				fmt.Fprintf(&b, " match %s address prefix-list %s\n", matchKW, term.PrefixList)
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

			if term.FromCommunity != "" {
				fmt.Fprintf(&b, " match community %s\n", term.FromCommunity)
			}

			if term.FromASPath != "" {
				fmt.Fprintf(&b, " match as-path %s\n", term.FromASPath)
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

			if term.LocalPreference > 0 {
				fmt.Fprintf(&b, " set local-preference %d\n", term.LocalPreference)
			}
			if term.Metric > 0 {
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
			if nonTerminating {
				b.WriteString(" on-match next\n")
			}

			b.WriteString("exit\n")
			seq += 10
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
