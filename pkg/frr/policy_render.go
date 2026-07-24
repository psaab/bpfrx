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
// password, BGP community member, AS-path regex) before it is
// interpolated into a generated frr.conf line. Render-side belt for
// #1798 / #4097: a BGP neighbor description, auth key, community-list
// member, or as-path-access-list regex containing an embedded newline
// must not be able to inject extra frr.conf commands even if the
// commit-time validation layer were bypassed (a leniently-loaded /
// peer-synced / rolled-back stored value re-parses through the same
// lexer, which materializes a `\n` escape into a real newline byte).
// Collapsing the newline to a space keeps the whole value on the single
// rendered line, so no injected `router bgp` / `neighbor` command
// reaches the managed section. A single SPACE (0x20) is preserved: an
// FRR `bgp as-path access-list ... permit LINE` and an expanded
// `bgp community-list expanded ... permit LINE` take the regex as a
// rest-of-line token, so a space inside the regex is legitimate (unlike
// a whitespace-split auth secret, which frrTokenUnsafeIndex also rejects
// at commit).
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

// validRouterID reports whether a router-id is a valid 32-bit IPv4
// dotted-quad. FRR/vtysh requires an IPv4 router-id for ALL routing
// protocols (including the IPv6 protocols OSPFv3 and BGP) and rejects
// anything else, failing the whole frr-reload. This is the render-side
// defense-in-depth for #2980: commit-time validation
// (validateRouterIDStrict, pkg/config) hard-rejects a bad router-id, but
// the tolerant load / peer-sync paths only warn (#1960 no-brick), so the
// renderer must keep a leniently-loaded malformed router-id out of frr.conf
// entirely. Empty is intentionally invalid here (the caller already gates
// on != "" and an empty value is omitted so FRR auto-derives the router-id).
func validRouterID(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

// validClusterID reports whether a BGP route-reflector cluster-id is one of
// the two forms FRR/vtysh's `bgp cluster-id <A.B.C.D | (1-4294967295)>` grammar
// accepts: an IPv4 dotted-quad or a 32-bit unsigned integer in 1..4294967295.
// Render-side defense-in-depth for #4919: `protocols bgp cluster-id` is stored
// verbatim, so a tolerant-load / peer-synced / rolled-back config may carry a
// malformed value (e.g. `not.an.ip`, an IPv6 literal, or an embedded-newline
// injection). FRR rejects anything else and fails the whole frr-reload, so the
// renderer must keep a leniently-loaded bad cluster-id out of frr.conf
// entirely. Commit / commit-check stay strict (config.ValidateBGPClusterID).
// Mirrors validRouterID; the accept set matches ValidateBGPClusterID exactly.
func validClusterID(s string) bool {
	if ip := net.ParseIP(s); ip != nil {
		return ip.To4() != nil
	}
	v, err := strconv.ParseUint(s, 10, 32)
	return err == nil && v >= 1
}

// validBGPOrigin reports whether a route-map `then origin` value is one of the
// three tokens FRR's `set origin <egp|igp|incomplete>` grammar accepts.
// Render-side belt for #4919: `then origin` is stored verbatim and was only
// control-char sanitized (#4498), so a non-control typo (`igpp`) or a
// leniently-loaded / peer-synced bad value reached FRR and failed the route-map
// grammar, stalling the reload. Skipping an invalid origin (fail-closed) keeps
// it out of frr.conf; commit-check stays strict (schema ValidateEnum).
func validBGPOrigin(s string) bool {
	switch s {
	case "igp", "egp", "incomplete":
		return true
	}
	return false
}

// knownRedistProtocols are the FRR redistribute protocol keywords.
// ospf6 / ripng are the FRR keywords for OSPFv3 / RIPng redistribution;
// without them a bare `export ospf6` / `export ripng` falls through to the
// skip-and-warn path and IPv6 IGP redistribution cannot be expressed (#2943).
var knownRedistProtocols = map[string]bool{
	"connected": true, "static": true, "ospf": true, "ospf6": true,
	"bgp": true, "rip": true, "ripng": true, "isis": true, "kernel": true,
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
func (m *Manager) resolveRedistribute(export string, po *config.PolicyOptionsConfig, self string, bgpAcceptDefault map[string]bool) string {
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
		// A protocol can never redistribute itself: FRR rejects
		// `redistribute ospf` under `router ospf` (etc.), and ONE
		// rejected line degrades the WHOLE managed reload (#1880/#2223).
		// Drop the self-redistribute rather than poison the section
		// (#2943). self is "" for callers with no enclosing protocol.
		if self != "" && export == self {
			slog.Warn("FRR redistribute export skipped: protocol cannot redistribute itself",
				"protocol", self)
			return ""
		}
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
					// Skip a policy term that matches the enclosing
					// protocol's own routes — `redistribute ospf
					// route-map X` under `router ospf` is self-
					// redistribution and FRR rejects it (#2943).
					if self != "" && proto == self {
						continue
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
				// #4481: if this policy is ALSO applied as a BGP route-map
				// in/out with no explicit default, its shared route-map carries
				// a trailing PERMIT (Junos BGP default-accept, #2998). That
				// permit must NOT govern the redistribute default (Junos
				// redistribute defaults to REJECT), so reference the fail-closed
				// per-use-site alias generatePolicyOptions emits for it.
				rmName := export
				if policyNeedsRedistAlias(export, ps, bgpAcceptDefault) {
					rmName = redistFailClosedRouteMap(export)
				}
				var sb strings.Builder
				for _, proto := range sorted {
					fmt.Fprintf(&sb, " redistribute %s route-map %s\n", proto, rmName)
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

// ReservedChainSuffix is the route-map name suffix xpf RESERVES for the
// composed BGP policy-chain route-maps the renderer derives for an ordered
// import/export policy list of length >= 2 (composedChainName below). FRR keys
// route-maps by NAME in a single GLOBAL namespace, so a composed name that
// collided with an operator policy-statement would fuse the two objects and
// could silently change the operator's filtering — the render-side guard
// bgpComposedChainCollision fails the whole apply CLOSED on any collision
// (#5277). The canonical constant lives in pkg/config (config.ReservedChainSuffix),
// which the commit-time strict validator validatePolicyReservedChainNameStrict
// reserves (#5442); this re-export sources the same literal so the composed-name
// derivation here and the config gate cannot drift (mirrors the redist pattern,
// where frr references config.ReservedRedistSuffix directly).
const ReservedChainSuffix = config.ReservedChainSuffix

// hasNonEmptyPolicy reports whether names holds at least one non-empty entry.
// It replaces the old lastNonEmpty("") != "" idiom for "does this neighbor set
// its own import/export?", independent of whether the entries resolve to
// defined policy-statements (a bare/undefined own ref still suppresses the
// global default, matching the pre-#5277 override precedence).
func hasNonEmptyPolicy(names []string) bool {
	for _, n := range names {
		if n != "" {
			return true
		}
	}
	return false
}

// filterDefinedPolicies returns, in order, the non-empty entries of names that
// resolve to a DEFINED policy-statement. Bare protocol tokens and undefined
// refs are dropped: a bare export token takes the redistribute path (#2473),
// and an undefined ref must never render a dangling `route-map <name> in|out`
// which FRR resolves to PERMIT-ALL (#2473/#2490/#2539). The surviving slice is
// the ordered Junos policy CHAIN the renderer composes (#5277).
func filterDefinedPolicies(names []string, po *config.PolicyOptionsConfig) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		if n != "" && isDefinedPolicyStatement(n, po) {
			out = append(out, n)
		}
	}
	return out
}

// bgpGlobalExportChain / bgpGlobalImportChain return the ordered chain of
// DEFINED policy-statements set as a global `protocols bgp export`/`import`
// default. Bare export protocol tokens are excluded here (they render as a
// `redistribute <proto>` verb on their own path, unchanged); import has no
// redistribute equivalent so only defined policy-statements survive (#2490).
func bgpGlobalExportChain(bgp *config.BGPConfig, po *config.PolicyOptionsConfig) []string {
	if bgp == nil {
		return nil
	}
	return filterDefinedPolicies(bgp.Export, po)
}

func bgpGlobalImportChain(bgp *config.BGPConfig, po *config.PolicyOptionsConfig) []string {
	if bgp == nil {
		return nil
	}
	return filterDefinedPolicies(bgp.Import, po)
}

// bgpNeighborExportChain resolves a BGP neighbor's effective ORDERED export
// policy chain, applying Junos most-specific-wins: the neighbor's OWN export
// list (the compiler resolves group-vs-neighbor level precedence into n.Export,
// #5277) overrides the global default. A neighbor that sets ANY own export
// entry — even a bare/undefined one — suppresses the global default for that
// peer (pre-#5277 override precedence); its chain is then the defined subset of
// its own list. An empty own list falls back to the global chain.
func bgpNeighborExportChain(n *config.BGPNeighbor, globalExportChain []string, po *config.PolicyOptionsConfig) []string {
	if hasNonEmptyPolicy(n.Export) {
		return filterDefinedPolicies(n.Export, po)
	}
	return globalExportChain
}

// bgpNeighborImportChain is the inbound symmetric of bgpNeighborExportChain
// (#2490/#5277). Import has no redistribute shorthand, so the own-list subset is
// simply its defined policy-statements.
func bgpNeighborImportChain(n *config.BGPNeighbor, globalImportChain []string, po *config.PolicyOptionsConfig) []string {
	if hasNonEmptyPolicy(n.Import) {
		return filterDefinedPolicies(n.Import, po)
	}
	return globalImportChain
}

// composedChainName derives the FRR route-map name for an ordered BGP policy
// chain of length >= 2. The member policy names (a chain never contains an
// empty entry) are joined and suffixed with the reserved ReservedChainSuffix so
// the composed object lives in a namespace distinct from operator route-maps;
// bgpComposedChainCollision fails the apply closed on the rare residual
// collision (#5277).
func composedChainName(chain []string) string {
	return strings.Join(chain, "-") + ReservedChainSuffix
}

// bgpRouteMapRef resolves an ordered policy chain to the FRR route-map name a
// neighbor/address-family line references. A single-policy chain references the
// standalone per-policy route-map generatePolicyOptions already emits
// (byte-identical to the pre-#5277 render); a chain of >= 2 references the
// composed route-map (composedChainName) that renderComposedRouteMap emits. An
// empty chain yields "" (no `route-map` line). The chain is pre-filtered to
// DEFINED policy-statements, so the returned name never dangles.
func bgpRouteMapRef(chain []string) string {
	switch len(chain) {
	case 0:
		return ""
	case 1:
		return chain[0]
	default:
		return composedChainName(chain)
	}
}

// collectBGPRouteMapPolicies records, into dst, every DEFINED
// policy-statement name that is rendered as a BGP `route-map in`/`out`
// for any neighbor in bgp. These are exactly the policies whose Junos
// fall-off-the-end default action is ACCEPT: a BGP import OR export policy
// that reaches its end without a terminating term falls through to the BGP
// default policy, which permits the route (vSRX advertises/accepts the
// unmatched route unmodified). This is unlike a redistribute /
// forwarding-table export policy, whose protocol default is REJECT
// (#2998).
//
// The set records only a SINGLE-policy chain's standalone route-map: a chain of
// one references the per-policy route-map generatePolicyOptions emits, whose
// trailing default must be the BGP-accept permit. A MULTI-policy chain (#5277)
// references a COMPOSED route-map (renderComposedRouteMap) that carries the
// BGP-accept fall-off default INTERNALLY, so the composed members' standalone
// route-maps are not the referenced objects and must not be forced to permit
// here (a member also used single-policy / as a redistribute elsewhere is
// recorded by THAT reference). globalExport/globalImport chains are resolved the
// same way the BGP renderer resolves them.
func collectBGPRouteMapPolicies(bgp *config.BGPConfig, po *config.PolicyOptionsConfig, dst map[string]bool) {
	if bgp == nil || po == nil {
		return
	}
	globalExportChain := bgpGlobalExportChain(bgp, po)
	globalImportChain := bgpGlobalImportChain(bgp, po)
	// A single-policy chain references the standalone route-map by name; only
	// those need the #2998 trailing-permit default recorded.
	addSingle := func(chain []string) {
		if len(chain) == 1 {
			dst[chain[0]] = true
		}
	}
	for _, n := range bgp.Neighbors {
		addSingle(bgpNeighborExportChain(n, globalExportChain, po))
		addSingle(bgpNeighborImportChain(n, globalImportChain, po))
	}
}

// bgpEffectiveChains yields every neighbor's effective export and import chain
// for bgp (each already Junos most-specific-resolved and defined-filtered). The
// visit callback receives each chain; callers filter by length. Shared by the
// composed-route-map collector and the collision guard so the two never compute
// the referenced chains differently (#5277).
func bgpEffectiveChains(bgp *config.BGPConfig, po *config.PolicyOptionsConfig, visit func(chain []string)) {
	if bgp == nil || po == nil {
		return
	}
	globalExportChain := bgpGlobalExportChain(bgp, po)
	globalImportChain := bgpGlobalImportChain(bgp, po)
	for _, n := range bgp.Neighbors {
		visit(bgpNeighborExportChain(n, globalExportChain, po))
		visit(bgpNeighborImportChain(n, globalImportChain, po))
	}
}

// collectBGPComposedChains records composedName -> chain for every REFERENCED
// BGP export/import policy chain of length >= 2 in bgp. On a name conflict
// (two DISTINCT chains deriving the same composedName) it keeps the FIRST
// deterministically; bgpComposedChainCollision is the fail-closed guard that
// rejects such a config before it renders (#5277).
func collectBGPComposedChains(bgp *config.BGPConfig, po *config.PolicyOptionsConfig, dst map[string][]string) {
	bgpEffectiveChains(bgp, po, func(chain []string) {
		if len(chain) < 2 {
			return
		}
		name := composedChainName(chain)
		if _, ok := dst[name]; ok {
			return
		}
		dst[name] = append([]string(nil), chain...)
	})
}

// bgpComposedChainCollision is the render-side fail-closed guard for the
// composed BGP policy-chain route-maps (#5277), mirroring redistAliasCollision
// (#5116). FRR keys route-maps by NAME in one global namespace and MERGES two
// same-named `route-map` definitions, so a composed name that collides with an
// operator policy-statement — or two DISTINCT chains that derive the same
// composed name — would fuse objects and could silently change the operator's
// BGP filtering (a security-relevant leak). The reserved ReservedChainSuffix
// makes both collisions astronomically unlikely, but on ANY collision this
// returns an error so ApplyFull fails the whole managed-section apply CLOSED
// (FRR keeps its last-good config) instead of emitting a fused route-map.
// Returns nil for the common non-colliding case.
func bgpComposedChainCollision(fc *FullConfig) error {
	if fc == nil || fc.PolicyOptions == nil {
		return nil
	}
	seen := map[string][]string{}
	var firstErr error
	check := func(bgp *config.BGPConfig) {
		bgpEffectiveChains(bgp, fc.PolicyOptions, func(chain []string) {
			if firstErr != nil || len(chain) < 2 {
				return
			}
			name := composedChainName(chain)
			if _, ok := fc.PolicyOptions.PolicyStatements[name]; ok {
				firstErr = fmt.Errorf(
					"composed BGP policy-chain route-map %q (from chain %v) "+
						"collides with an operator policy-statement of that exact "+
						"name; FRR merges same-named route-maps, so the collision "+
						"could silently alter BGP filtering — refusing to render "+
						"(rename the operator policy-statement or a chain member, "+
						"#5277)", name, chain)
				return
			}
			if prev, ok := seen[name]; ok && !equalStringSlice(prev, chain) {
				firstErr = fmt.Errorf(
					"BGP policy-chains %v and %v derive the same composed "+
						"route-map name %q; FRR would merge them — rename a "+
						"policy-statement to disambiguate (#5277)", prev, chain, name)
				return
			}
			seen[name] = chain
		})
	}
	check(fc.BGP)
	for _, inst := range fc.Instances {
		check(inst.BGP)
	}
	return firstErr
}

// renderComposedBGPChains emits the DEFINITIONS of every composed BGP
// policy-chain route-map referenced anywhere in fc (default instance + every
// VRF), deduplicated and sorted by name for deterministic output. It is emitted
// alongside generatePolicyOptions in the managed section; FRR resolves a
// `neighbor X route-map <name> out` reference to a route-map defined anywhere in
// the file, so definition order does not matter. Returns "" when no chain of
// length >= 2 is referenced (byte-identical to the pre-#5277 render). Any
// distinct-chain name conflict is already rejected by bgpComposedChainCollision
// in ApplyFull; here a residual conflict keeps the first chain deterministically.
func (m *Manager) renderComposedBGPChains(fc *FullConfig) string {
	if fc == nil || fc.PolicyOptions == nil {
		return ""
	}
	chains := map[string][]string{}
	collectBGPComposedChains(fc.BGP, fc.PolicyOptions, chains)
	for _, inst := range fc.Instances {
		collectBGPComposedChains(inst.BGP, fc.PolicyOptions, chains)
	}
	if len(chains) == 0 {
		return ""
	}
	names := make([]string, 0, len(chains))
	for name := range chains {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		b.WriteString(m.renderComposedRouteMap(fc.PolicyOptions, name, chains[name]))
		b.WriteString("!\n")
	}
	return b.String()
}

// equalStringSlice reports whether two string slices are element-wise equal.
func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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
			// Render belt (#5557): sanitize the routing-instance name like the
			// `router ... vrf` and static-route vrf clauses. A leniently-loaded
			// control character in the instance name would otherwise inject a
			// standalone line into the managed `bfd` block.
			fmt.Fprintf(&b, " peer %s vrf %s\n", p.address, sanitizeFRRValue(p.vrfName))
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
func (m *Manager) generateProtocols(ospf *config.OSPFConfig, ospfv3 *config.OSPFv3Config, bgp *config.BGPConfig, rip *config.RIPConfig, isis *config.ISISConfig, vrfName string, ecmpMaxPaths int, policyOptions *config.PolicyOptionsConfig, bgpAcceptDefault map[string]bool, shared ...*bfdSection) string {
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
		// Render belt (#5557): sanitize the routing-instance name for the
		// `router <proto> ... vrf <name>` clauses this suffix feeds
		// (OSPF/OSPFv3/BGP/RIP/IS-IS). The name is validated at commit, but
		// the tolerant load / HA config-sync paths only warn (#1960 no-brick),
		// so a control character could otherwise inject a second vtysh line
		// into the managed frr.conf. Mirrors the static-route vrf clause
		// (config_render.go) and the BFD peer vrf clause below.
		vrfSuffix = " vrf " + sanitizeFRRValue(vrfName)
	}

	if ospf != nil {
		fmt.Fprintf(&b, "router ospf%s\n", vrfSuffix)
		if validRouterID(ospf.RouterID) {
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
			b.WriteString(m.resolveRedistribute(export, policyOptions, "ospf", bgpAcceptDefault))
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
				// Adjacency timers + DR priority (#4285). hello/dead MUST
				// match the neighbor or the adjacency never forms; FRR keeps
				// its defaults (hello 10s, dead 40s, priority 1) when unset.
				if iface.HelloInterval > 0 {
					fmt.Fprintf(&b, " ip ospf hello-interval %d\n", iface.HelloInterval)
				}
				if iface.DeadInterval > 0 {
					fmt.Fprintf(&b, " ip ospf dead-interval %d\n", iface.DeadInterval)
				}
				if iface.RetransmitInt > 0 {
					fmt.Fprintf(&b, " ip ospf retransmit-interval %d\n", iface.RetransmitInt)
				}
				// HasPriority gates the line; 0 is a valid value ("never DR").
				if iface.HasPriority {
					fmt.Fprintf(&b, " ip ospf priority %d\n", iface.Priority)
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
		if validRouterID(ospfv3.RouterID) {
			fmt.Fprintf(&b, " ospf6 router-id %s\n", ospfv3.RouterID)
		}
		for _, area := range ospfv3.Areas {
			for _, iface := range area.Interfaces {
				fmt.Fprintf(&b, " interface %s area %s\n", iface.Name, area.ID)
			}
		}
		// IPv6 OSPF ECMP mirrors the OSPFv4 block: FRR ospf6d requires an
		// explicit "maximum-paths <N>" under "router ospf6" to install
		// equal-cost multipath. OSPFv3 reuses the same global forwarding-table
		// ECMP knob (ecmpMaxPaths) as OSPFv4 — there is no separate OSPFv3
		// maximum-paths config leaf (#2997).
		if ecmpMaxPaths > 1 {
			fmt.Fprintf(&b, " maximum-paths %d\n", ecmpMaxPaths)
		}
		for _, export := range ospfv3.Export {
			b.WriteString(m.resolveRedistribute(export, policyOptions, "ospf6", bgpAcceptDefault))
		}
		b.WriteString("exit\n!\n")
		for _, area := range ospfv3.Areas {
			for _, iface := range area.Interfaces {
				if iface.Cost > 0 || iface.Passive || iface.BFD ||
					iface.HelloInterval > 0 || iface.DeadInterval > 0 ||
					iface.RetransmitInt > 0 || iface.HasPriority {
					fmt.Fprintf(&b, "interface %s\n", iface.Name)
					if iface.Passive {
						b.WriteString(" ipv6 ospf6 passive\n")
					}
					if iface.Cost > 0 {
						fmt.Fprintf(&b, " ipv6 ospf6 cost %d\n", iface.Cost)
					}
					// Adjacency timers + DR priority (#4285): hello/dead must
					// match the neighbor. HasPriority gates the priority line;
					// priority 0 ("never DR") emits, unset omits.
					if iface.HelloInterval > 0 {
						fmt.Fprintf(&b, " ipv6 ospf6 hello-interval %d\n", iface.HelloInterval)
					}
					if iface.DeadInterval > 0 {
						fmt.Fprintf(&b, " ipv6 ospf6 dead-interval %d\n", iface.DeadInterval)
					}
					if iface.RetransmitInt > 0 {
						fmt.Fprintf(&b, " ipv6 ospf6 retransmit-interval %d\n", iface.RetransmitInt)
					}
					if iface.HasPriority {
						fmt.Fprintf(&b, " ipv6 ospf6 priority %d\n", iface.Priority)
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

	// #5518: compute the renderable BGP neighbor set ONCE and drive every
	// neighbor-referencing render loop from it. A neighbor authored/loaded
	// without a peer-as keeps a zero PeerAS; AS 0 is reserved (RFC 7607) and
	// FRR/vtysh rejects `remote-as 0`, so the declaration loop below must skip
	// it (the #2963 fail-closed guard). Commit-time validation
	// (validateBGPNeighborPeerASStrict, pkg/config) rejects remote-as-0 on
	// commit/commit-check, but the tolerant load / peer-sync path downgrades it
	// to a warning, so a leniently-loaded remote-as-0 neighbor can reach the
	// renderer. The declaration guard alone is not enough: the address-family
	// activation loop and the BFD accumulator ALSO iterate the neighbors, and
	// emitting `neighbor <ip> activate` / a route-map / `neighbor <ip> bfd` /
	// a `bfd` peer for a neighbor that was never declared makes vtysh reject
	// the WHOLE managed section — a single remote-as-0 neighbor would brick the
	// frr-reload for every valid peer on the box. Building the set once here
	// guarantees the three loops can never diverge on which neighbors render.
	var validNeighbors []*config.BGPNeighbor
	if bgp != nil {
		validNeighbors = make([]*config.BGPNeighbor, 0, len(bgp.Neighbors))
		for _, n := range bgp.Neighbors {
			if n.PeerAS == 0 {
				continue
			}
			validNeighbors = append(validNeighbors, n)
		}
	}

	if bgp != nil && bgp.LocalAS > 0 {
		fmt.Fprintf(&b, "router bgp %d%s\n", bgp.LocalAS, vrfSuffix)
		if validRouterID(bgp.RouterID) {
			fmt.Fprintf(&b, " bgp router-id %s\n", bgp.RouterID)
		}
		if bgp.ClusterID != "" && validClusterID(bgp.ClusterID) {
			// #4919: skip a malformed cluster-id (leniently-loaded / peer-synced
			// bad value) and sanitize the accepted value, so no invalid token or
			// injected newline reaches the frr-reload.
			fmt.Fprintf(&b, " bgp cluster-id %s\n", sanitizeFRRValue(bgp.ClusterID))
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
		// validNeighbors excludes remote-as-0 neighbors (#2963/#5518). Every
		// neighbor-referencing loop below (AF activation, BFD accumulator)
		// iterates the SAME slice so an undeclared neighbor is never activated
		// or attached to BFD — see the validNeighbors construction above.
		for _, n := range validNeighbors {
			fmt.Fprintf(&b, " neighbor %s remote-as %d\n", n.Address, n.PeerAS)
			// Per-peering local-as (#4286): present a different AS than the
			// router's own to this peer.
			if n.LocalAS > 0 {
				fmt.Fprintf(&b, " neighbor %s local-as %d\n", n.Address, n.LocalAS)
			}
			// update-source (#4286): iBGP peers over loopbacks need the TCP
			// session sourced from the loopback the peer has a `neighbor`
			// statement for, not the egress interface IP — otherwise the peer
			// rejects the connection and the session never establishes.
			if n.LocalAddress != "" {
				fmt.Fprintf(&b, " neighbor %s update-source %s\n", n.Address, sanitizeFRRValue(n.LocalAddress))
			}
			// passive (#4286): do not initiate — wait for the peer to connect.
			if n.Passive {
				fmt.Fprintf(&b, " neighbor %s passive\n", n.Address)
			}
			// hold-time (#4286): FRR `timers <keepalive> <holdtime>`; keepalive
			// defaults to hold/3 per the BGP convention (Junos derives the same
			// way). A mismatched hold-time shortens or breaks the session.
			if n.HoldTime > 0 {
				keepalive := n.HoldTime / 3
				if keepalive < 1 {
					keepalive = 1
				}
				fmt.Fprintf(&b, " neighbor %s timers %d %d\n", n.Address, keepalive, n.HoldTime)
			}
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
		// is emitted — the neighbor's own export chain when present, else
		// the global export chain (bgpNeighborExportChain resolves the
		// override; a resolved chain of >= 2 is composed into one
		// `-xpf-chain` route-map via composedChainName/bgpRouteMapRef,
		// #5277). A bare-token redistribute is a GLOBAL redistribute verb,
		// not per-neighbor, and is emitted once under `router bgp`.
		// globalExportChain is the ORDERED list of DEFINED policy-statements
		// in `protocols bgp export` — the global export CHAIN applied as a
		// peer-level default to neighbors with no own export. Every entry is
		// preserved and composed in order (#5277); the pre-#5277 code kept only
		// the LAST defined entry, silently dropping a leading reject/attribute
		// policy so prohibited routes were advertised. Bare protocol tokens are
		// still split out to the redistribute path below (unchanged).
		globalExportChain := make([]string, 0, len(bgp.Export))
		for _, e := range bgp.Export {
			if e == "" {
				continue
			}
			if isDefinedPolicyStatement(e, policyOptions) {
				globalExportChain = append(globalExportChain, e)
			} else {
				// Bare protocol token (or a name that slipped the
				// validator on a lenient load/HA-sync path) → genuine
				// redistribute. resolveRedistribute normalizes direct→
				// connected and refuses to emit an invalid bare-name
				// line (#2223), and drops a self-redistribute (#2943).
				b.WriteString(m.resolveRedistribute(e, policyOptions, "bgp", bgpAcceptDefault))
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
		// dangling-route-map leak, INBOUND direction. Every DEFINED entry is
		// preserved as an ordered CHAIN and composed in order (#5277); the
		// pre-#5277 code kept only the last, silently dropping a leading inbound
		// filter so prohibited routes were accepted.
		globalImportChain := make([]string, 0, len(bgp.Import))
		for _, e := range bgp.Import {
			if e == "" {
				continue
			}
			if isDefinedPolicyStatement(e, policyOptions) {
				globalImportChain = append(globalImportChain, e)
			}
		}

		// Address-family blocks for neighbors with family declarations.
		// When a global default export exists it must reach EVERY peer,
		// including neighbors with no explicit `family` (FRR default-
		// activates those under ipv4 unicast), so route them into the
		// ipv4 set in that case.
		var inet4Neighbors, inet6Neighbors []*config.BGPNeighbor
		// Classify only renderable (declared) neighbors (#5518). A remote-as-0
		// neighbor excluded from the declaration loop above must NOT be
		// activated here — vtysh rejects `neighbor <ip> activate` for a
		// neighbor with no `remote-as`, failing the whole managed section.
		for _, n := range validNeighbors {
			// A neighbor lands in the ipv4 (default) AF when it explicitly
			// declares family inet, OR when a peer-level policy must reach it
			// and it has not been pinned to inet6: a global export/import
			// default, or its own per-neighbor export/import (FRR default-
			// activates a family-less neighbor under ipv4 unicast). Per-
			// neighbor import/export inclusion is #2490 (symmetric to the
			// global-default inclusion #2473 added).
			hasOwnPolicy := hasNonEmptyPolicy(n.Export) || hasNonEmptyPolicy(n.Import)
			// The "default-activate a family-less policied neighbor under
			// ipv4 unicast" fall-through (#2473/#2490) is correct ONLY for
			// an IPv4 peer address. An IPv6 peer (e.g. 2001:db8::1) with a
			// policy but no explicit `family inet6` also satisfies
			// !n.FamilyInet6, so the pre-#2941 code activated it under
			// `address-family ipv4 unicast` — the WRONG family. FRR cannot
			// resolve an IPv4 next-hop over an IPv6 peer (no RFC 8950
			// extended-next-hop) so the session drops prefixes / fails, and
			// the neighbor never participates in ipv6 unicast. Gate the
			// ipv4 fall-through on the peer address family, and route an
			// IPv6-address family-less-but-policied neighbor into the ipv6
			// set instead so it activates under ipv6 unicast (#2941).
			isIPv6Peer := strings.Contains(n.Address, ":")
			policyDefault := len(globalExportChain) > 0 || len(globalImportChain) > 0 || hasOwnPolicy
			if (n.FamilyInet || (policyDefault && !n.FamilyInet6)) && !isIPv6Peer {
				inet4Neighbors = append(inet4Neighbors, n)
			}
			if n.FamilyInet6 || (policyDefault && !n.FamilyInet && isIPv6Peer) {
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
				// FRR `maximum-paths N` enables eBGP multipath only; iBGP
				// multipath requires the separate `maximum-paths ibgp N`
				// command, gated on the explicit `protocols bgp multipath
				// ibgp` knob (#2978).
				if bgp.MultipathIBGP {
					fmt.Fprintf(&b, "  maximum-paths ibgp %d\n", bgpMaxPaths)
				}
			}
			for _, n := range inet4Neighbors {
				fmt.Fprintf(&b, "  neighbor %s activate\n", n.Address)
				if n.DefaultOriginate {
					fmt.Fprintf(&b, "  neighbor %s default-originate\n", n.Address)
				}
				if n.PrefixLimitInet > 0 {
					fmt.Fprintf(&b, "  neighbor %s maximum-prefix %d\n", n.Address, n.PrefixLimitInet)
				}
				// Outbound filter. The effective export CHAIN (neighbor's own
				// list, else the global default) is pre-filtered to DEFINED
				// policy-statements (filterDefinedPolicies), so bare/undefined
				// refs never render a dangling `route-map out` = FRR permit-all
				// OUTBOUND (#2473/#2539) — bare tokens stay on the redistribute
				// path. A single-policy chain references the standalone
				// route-map (byte-identical to pre-#5277); a chain of >= 2
				// references the composed route-map that preserves the ordered
				// Junos policy chain (#5277) instead of dropping all but the
				// last.
				if rm := bgpRouteMapRef(bgpNeighborExportChain(n, globalExportChain, policyOptions)); rm != "" {
					fmt.Fprintf(&b, "  neighbor %s route-map %s out\n", n.Address, rm)
				}
				// Junos `then next-hop self` is lowered per-term INSIDE the
				// export route-map as `set ip/ipv6 next-hop peer-address`
				// (which resolves to self in the outbound direction), NOT the
				// neighbor-wide `neighbor <peer> next-hop-self` knob. The knob
				// ran after route selection and rewrote EVERY route advertised
				// to the peer, widening a term-scoped action to all of the
				// neighbor's routes (#5115). The route-map lowering still
				// overrides iBGP / route-reflector-reflected next-hops (the
				// #2977 fix), now scoped to the term. See the `term.NextHop ==
				// "self"` branch in the route-map renderer.
				//
				// Inbound filter (#2490/#5277). Same chain composition as the
				// outbound path: the effective import chain is defined-filtered
				// (no dangling permit-all in-line), single-policy references the
				// standalone route-map, and a chain of >= 2 references the
				// composed route-map preserving the ordered inbound policy chain.
				if rm := bgpRouteMapRef(bgpNeighborImportChain(n, globalImportChain, policyOptions)); rm != "" {
					fmt.Fprintf(&b, "  neighbor %s route-map %s in\n", n.Address, rm)
				}
			}
			b.WriteString(" exit-address-family\n")
		}
		if len(inet6Neighbors) > 0 || bgpMaxPaths > 1 {
			b.WriteString(" !\n address-family ipv6 unicast\n")
			if bgpMaxPaths > 1 {
				fmt.Fprintf(&b, "  maximum-paths %d\n", bgpMaxPaths)
				// iBGP multipath (#2978) — see the ipv4 block above.
				if bgp.MultipathIBGP {
					fmt.Fprintf(&b, "  maximum-paths ibgp %d\n", bgpMaxPaths)
				}
			}
			for _, n := range inet6Neighbors {
				fmt.Fprintf(&b, "  neighbor %s activate\n", n.Address)
				if n.DefaultOriginate {
					fmt.Fprintf(&b, "  neighbor %s default-originate\n", n.Address)
				}
				if n.PrefixLimitInet6 > 0 {
					fmt.Fprintf(&b, "  neighbor %s maximum-prefix %d\n", n.Address, n.PrefixLimitInet6)
				}
				// Outbound filter (#2539/#5277) — see the ipv4 block above.
				if rm := bgpRouteMapRef(bgpNeighborExportChain(n, globalExportChain, policyOptions)); rm != "" {
					fmt.Fprintf(&b, "  neighbor %s route-map %s out\n", n.Address, rm)
				}
				// `then next-hop self` is lowered per-term in the export
				// route-map as `set ip/ipv6 next-hop peer-address`, NOT a
				// neighbor-wide `next-hop-self` knob (#5115) — see the ipv4
				// block above.
				// Inbound filter (#2490/#5277) — see the ipv4 block above.
				if rm := bgpRouteMapRef(bgpNeighborImportChain(n, globalImportChain, policyOptions)); rm != "" {
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
			b.WriteString(m.resolveRedistribute(r, policyOptions, "rip", bgpAcceptDefault))
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
			b.WriteString(m.resolveRedistribute(export, policyOptions, "isis", bgpAcceptDefault))
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
			// `isis bfd` / `isis bfd profile <name>` are interface-scoped
			// commands and MUST be emitted INSIDE the interface block,
			// before `exit`. Emitting them after `exit` lands them at
			// global config scope, which vtysh rejects — and one rejected
			// line fails the WHOLE managed-section reload (#1880/#2223),
			// breaking every IS-IS interface with BFD enabled. This mirrors
			// the OSPFv3 per-interface BFD ordering above (#2942).
			if iface.BFD {
				if iface.BFDInterval > 0 || iface.BFDMultiplier > 0 {
					profile := bfdProfileName(iface.BFDInterval, iface.BFDMultiplier)
					bfd.addProfile(profile, bfdProfile{iface.BFDInterval, iface.BFDMultiplier})
					fmt.Fprintf(&b, " isis bfd profile %s\n", profile)
				} else {
					b.WriteString(" isis bfd\n")
				}
			}
			b.WriteString("exit\n!\n")
		}
	}

	// Accumulate BFD peer entries for BGP neighbors with BFD enabled. The
	// in-scope vrfName is recorded with each peer so the single global
	// block carries the matching `vrf <name>` suffix (#2489). Emission is
	// deferred to bfdSection.render() — either here (local fallback) or by
	// the manager for the consolidated global block (#2550).
	if bgp != nil {
		// Accumulate BFD peers only for renderable (declared) neighbors
		// (#5518). A remote-as-0 neighbor skipped by the declaration loop must
		// not emit a `bfd` peer either — validNeighbors is the shared
		// exclusion set.
		for _, n := range validNeighbors {
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

// redistFailClosedRouteMap derives the per-use-site route-map name that IGP
// redistribute references for a policy that is ALSO applied as a BGP route-map
// in/out with no explicit default action. The base route-map keeps the Junos
// BGP default-accept trailing permit (#2998); this alias carries the fail-closed
// trailing deny the redistribute / forwarding-table context requires, so the
// BGP permit default never leaks into the IGP through FRR's single name-keyed
// route-map object (#4481). The config.ReservedRedistSuffix ("-xpf-redist") is
// RESERVED: the strict commit gate (validatePolicyReservedRedistNameStrict,
// pkg/config) rejects an operator policy-statement whose name ends in it, so the
// generated-alias namespace is injective by construction (#5116). The alias
// derivation here and that validator share the one constant so they cannot
// drift. redistAliasCollision below is the render-side belt: on the tolerant
// load / peer-sync path (where the strict gate only warns) it fails the apply
// CLOSED if an alias still collides with an operator policy-statement, so a
// leniently-loaded collision cannot silently leak.
func redistFailClosedRouteMap(name string) string {
	return name + config.ReservedRedistSuffix
}

// redistAliasCollision is the render-side defense-in-depth for #5116. For every
// policy-statement that generates a fail-closed redistribute alias
// (policyNeedsRedistAlias), it checks whether that derived alias name
// (redistFailClosedRouteMap) also exists as an operator-defined
// policy-statement. FRR keys route-maps by NAME in one global namespace and
// MERGES two same-named `route-map` definitions into a single object, so a
// colliding operator policy's (possibly permit-default) sequences would fuse
// with the generated fail-closed deny alias and could reintroduce the #4481
// BGP/IGP redistribution leak the alias exists to prevent.
//
// The strict commit gate (validatePolicyReservedRedistNameStrict, pkg/config)
// rejects a reserved-suffix operator name outright, so a committed config never
// reaches here with a collision. This belt covers the tolerant load / peer-sync
// / rollback path where that gate only warns (#1960): ApplyFull calls it before
// building the managed section and returns the error, failing the whole apply
// CLOSED (FRR keeps its last-good config, no new leak) instead of emitting a
// colliding route-map. Returns nil for the common non-colliding case, leaving
// render output byte-identical.
func redistAliasCollision(po *config.PolicyOptionsConfig, bgpAcceptDefault map[string]bool) error {
	if po == nil || po.PolicyStatements == nil {
		return nil
	}
	// Deterministic first-error: iterate policy-statement names in sorted order.
	names := make([]string, 0, len(po.PolicyStatements))
	for name := range po.PolicyStatements {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ps := po.PolicyStatements[name]
		if !policyNeedsRedistAlias(name, ps, bgpAcceptDefault) {
			continue
		}
		alias := redistFailClosedRouteMap(name)
		if _, ok := po.PolicyStatements[alias]; ok {
			return fmt.Errorf(
				"policy-statement %q generates the fail-closed redistribute "+
					"route-map alias %q (reserved %q suffix), which collides with "+
					"an operator-defined policy-statement of that exact name; FRR "+
					"merges same-named route-maps, so the collision could "+
					"reintroduce the #4481 BGP/IGP redistribution leak — refusing "+
					"to render (rename the operator policy off the reserved suffix)",
				name, alias, config.ReservedRedistSuffix)
		}
	}
	return nil
}

// policyNeedsRedistAlias reports whether policy-statement name renders a
// BGP-default-accept trailing permit that must NOT be shared with an IGP
// redistribute use of the same name (#4481). It is true only when the policy is
// applied as a BGP route-map in/out (bgpAcceptDefault carries these names, per
// collectBGPRouteMapPolicies) AND carries no explicit policy-level default
// action — the exact case in which policyTrailingAction returns "permit" for a
// route that matches no term. An explicit `then accept` / `then reject` renders
// the same trailing action in every context, so no alias is needed.
func policyNeedsRedistAlias(name string, ps *config.PolicyStatement, bgpAcceptDefault map[string]bool) bool {
	return ps != nil && bgpAcceptDefault[name] &&
		ps.DefaultAction != "accept" && ps.DefaultAction != "reject"
}

// policyTrailingAction resolves the trailing default-sequence action
// (permit/deny) for a policy-statement route-map, applying the #2998
// BGP-default-accept fallback:
//
//   - explicit `then accept`  → permit (Junos-explicit)
//   - explicit `then reject`  → deny   (Junos-explicit)
//   - no policy default + BGP route-map in/out context → permit
//     (BGP default-accept; bgpAcceptDefault carries these names)
//   - no policy default elsewhere (redistribute / forwarding-table export /
//     standalone) → deny (fail-closed, matches the OSPF/redistribute Junos
//     default and FRR's implicit deny)
func policyTrailingAction(name string, ps *config.PolicyStatement, bgpAcceptDefault map[string]bool) string {
	switch {
	case ps.DefaultAction == "accept":
		return "permit"
	case ps.DefaultAction == "reject":
		return "deny"
	case bgpAcceptDefault[name]:
		return "permit"
	default:
		return "deny"
	}
}

// generatePolicyOptions emits FRR prefix-list / route-map / community-list /
// as-path-access-list config from the typed Junos policy-options.
//
// The optional bgpAccept variadic carries the set of policy-statement names
// that are referenced as a BGP `route-map in`/`out` (built by
// collectBGPRouteMapPolicies at the GenerateConfig call site). A
// policy-statement in that set with NO explicit policy-level default action
// renders a terminating `permit` so an unmatched route follows the Junos BGP
// default-ACCEPT instead of being dropped by FRR's implicit deny (#2998).
// Direct/test callers omit the argument, preserving the historical
// fail-closed `deny` default for every policy.
func (m *Manager) generatePolicyOptions(po *config.PolicyOptionsConfig, bgpAccept ...map[string]bool) string {
	var bgpAcceptDefault map[string]bool
	if len(bgpAccept) > 0 {
		bgpAcceptDefault = bgpAccept[0]
	}
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
			// #4482: sanitize the prefix so an embedded newline from a
			// leniently-loaded / peer-synced / rolled-back stored value cannot
			// inject an extra frr.conf line. #4097 added this render-side belt
			// to the community-list / as-path-list definitions but MISSED the
			// prefix-list slots and the route-map `set` clauses below, which
			// still rendered with a bare %s — a residual bypass on the tolerant
			// load path (the strict #1798 commit control-char gate rejects it,
			// but the peer-sync / rollback path only warns, #1960).
			if strings.Contains(prefix, ":") {
				fmt.Fprintf(&b, "ipv6 prefix-list %s seq %d permit %s\n", name, (i+1)*5, sanitizeFRRValue(prefix))
			} else {
				fmt.Fprintf(&b, "ip prefix-list %s seq %d permit %s\n", name, (i+1)*5, sanitizeFRRValue(prefix))
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
			// #4097: sanitize the member so an embedded newline (from a
			// leniently-loaded / peer-synced / rolled-back stored value)
			// cannot inject an extra frr.conf line — parity with the auth
			// / description fields. The listKind decision above reads the
			// RAW members (a `\n` is not a regex metacharacter, so it does
			// not by itself flip standard→expanded; the exploit's `^`/`$`
			// do). The strict #1798 commit control-char gate rejects it outright.
			fmt.Fprintf(&b, "bgp community-list %s %s permit %s\n", listKind, name, sanitizeFRRValue(member))
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
			// #4097: sanitize the regex so an embedded newline cannot
			// inject an extra frr.conf line — parity with the auth /
			// description fields. FRR takes the regex as a rest-of-line
			// token, so a legitimate space (multi-AS path) survives; only
			// control chars (incl. the newline injection vector) collapse
			// to a space. The strict #1798 commit control-char gate rejects it.
			fmt.Fprintf(&b, "bgp as-path access-list %s permit %s\n", name, sanitizeFRRValue(ap.Regex))
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
		// #5701 render-side belt: a policy whose per-term Cartesian expansion
		// exceeds the FRR route-map sequence-number ceiling would render a
		// `route-map <name> <action> <seq>` line past seq 65535, which FRR
		// rejects (CMD_WARNING_CONFIG_FAILED) — poisoning the WHOLE
		// vtysh-batched frr-reload, not just this policy. The strict commit gate
		// (config.validatePolicyRouteMapSequenceBoundStrict) rejects it; this
		// belt covers the tolerant load / peer-sync / rollback path (#1960)
		// where that gate only warns: SKIP the oversized policy so the rest of
		// the managed section still reloads (a dangling `route-map <name> in/out`
		// FRR resolves to permit-all, but that is strictly better than a poisoned
		// reload, and the operator has the commit-time diagnostic).
		if n := config.RouteMapSequenceCount(ps); n > config.MaxRouteMapSequences {
			slog.Warn("skipping oversized route-map policy: expansion would overflow FRR sequence numbers and poison the reload",
				"policy", name, "sequences", n, "max", config.MaxRouteMapSequences)
			continue
		}
		// Base route-map: Junos BGP default-accept (#2998) vs the fail-closed
		// redistribute/forwarding-table default, resolved per use context.
		b.WriteString(m.renderRouteMapForPolicy(po, name, ps, policyTrailingAction(name, ps, bgpAcceptDefault)))
		b.WriteString("!\n")
		// #4481: FRR route-maps are keyed by NAME — one object shared by every
		// use site. A policy applied as a BGP route-map in/out with no explicit
		// default renders a trailing PERMIT (Junos BGP default-accept, #2998).
		// If the SAME policy is also used for an IGP redistribute, that permit
		// would leak every non-matching route into the IGP. Emit a per-use-site
		// fail-closed alias for the redistribute contexts; resolveRedistribute
		// references it instead of the shared permit-default map.
		if policyNeedsRedistAlias(name, ps, bgpAcceptDefault) {
			b.WriteString(m.renderRouteMapForPolicy(po, redistFailClosedRouteMap(name), ps, "deny"))
			b.WriteString("!\n")
		}
	}

	return b.String()
}

// renderPolicyTermSequences renders policy-statement ps's TERM sequences (NO
// trailing default) into a fresh buffer under FRR route-map name routeMapName,
// deriving inline route-filter prefix-list names from plPrefix, starting at
// sequence startSeq. It returns the rendered text and the next unused sequence.
//
// Splitting the route-map NAME (route-map header) from the prefix-list PREFIX
// lets renderComposedRouteMap emit several policies' term sequences into ONE
// route-map (all sharing routeMapName) while keeping each policy's inline
// prefix-lists in a distinct namespace (plPrefix carries the policy name), so a
// term name reused across chained policies cannot fuse two prefix-lists (#5277).
// renderRouteMapForPolicy passes routeMapName == plPrefix == emitName, keeping
// the single-policy render byte-identical to master.
func (m *Manager) renderPolicyTermSequences(po *config.PolicyOptionsConfig, routeMapName, plPrefix string, ps *config.PolicyStatement, startSeq int) (string, int) {
	var b strings.Builder
	seq := startSeq
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
		emitTermBody := func(seqFam string, seqNum int, rfs []indexedRouteFilter, plName string, fromPL fromPrefixListRef, fromCommunity, fromASPath string) {
			fmt.Fprintf(&b, "route-map %s %s %d\n", routeMapName, action, seqNum)

			// rfMatchEmitted / rfMatchV6 record whether THIS sequence emitted a
			// route-filter "match ip|ipv6 address prefix-list" line and its
			// family, so the from-prefix-list branch below can detect a
			// same-family, same-type collision (#5730) and render the
			// from-prefix-list as a DISTINCT-type access-list match instead of a
			// second (colliding) prefix-list match.
			rfMatchEmitted := false
			rfMatchV6 := false

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
				rfMatchEmitted = true
				rfMatchV6 = matchV6
			}

			if fromPL.name != "" {
				// The address family of THIS `from prefix-list` match is fixed
				// by the typed ref (fromPrefixListRef.matchKW): a mixed v4+v6
				// referenced list is expanded UPSTREAM (fromPrefixListRefs) into
				// two refs — one "ip", one "ipv6" — each emitted in its own
				// route-map sequence, so BOTH families bind their own `match
				// ip|ipv6 address` line and neither family's routes silently
				// fail the term (#2607). A single-family or undefined/empty list
				// yields exactly one ref, byte-identical to the pre-#2607 render.
				// FRR keeps `ip` and `ipv6` prefix-lists in independent
				// namespaces, so `match ip address prefix-list PL` resolves to PL's
				// v4 entries and `match ipv6 address prefix-list PL` to its v6
				// entries even though both share the name PL.
				//
				// In a SPLIT mixed-route-filter term (seqFam != "") this
				// `from prefix-list` match is ANDed with this sequence's
				// route-filter match. When the ref's family is the OPPOSITE of the
				// route-filter's, the match line MUST STILL be emitted: it names a
				// different FRR match type than the `match ip/ipv6 address
				// <route-filter>`, so the two coexist and the sequence
				// AND-NOMATCHes every route — exactly the intended Junos semantics
				// ("(route-filter) AND (off-family prefix-list)" is unsatisfiable
				// for this family, so the term is non-matching for it). Dropping
				// the off-family match instead (the pre-#5702 behavior) silently
				// LOOSENED the term to its route-filter half — a fail-open
				// policy-semantics change (#5702). This is a DIFFERENT-type
				// coexistence, NOT the #2071/#5730 same-type collision: a v4
				// route-filter is `match ip` and a v6 prefix-list is `match ipv6`,
				// so neither replaces the other.
				//
				// A referenced list is ONE entry of a possibly multi-valued
				// `from prefix-list` set (#2642), and a mixed list adds its own
				// per-family OR-dimension (#2607). Both are the SAME structure:
				// FRR's route_map_add_match REPLACES a same-type rule
				// (lib/routemap.c), so OR is expressed by one route-map SEQUENCE
				// per (list, family) value — the dispatch loop below — each
				// carrying the full term body.
				plObj := po.PrefixLists[fromPL.name]
				matchKW := fromPL.matchKW
				// #5730: when THIS sequence ALSO emitted a same-family
				// route-filter "match ip|ipv6 address prefix-list" line, a
				// second same-type "match ... prefix-list" for the
				// from-prefix-list COLLIDES — FRR's route_map_add_match REPLACES
				// a same-type rule (keeps the LAST), silently dropping the
				// route-filter constraint and loosening "(route-filter) AND
				// (prefix-list)" to prefix-list-only. Render the from-prefix-list
				// as an ACCESS-LIST match — a DISTINCT FRR rule type — so FRR
				// ANDs the two constraints. A DIFFERENT-family route-filter (the
				// #5702 off-family fail-closed coexistence) is already a distinct
				// FRR type, so it keeps the prefix-list match unchanged.
				if rfMatchEmitted && rfMatchV6 == (matchKW == "ipv6") {
					// #5872: a bounded, namespaced, deterministically-hashed
					// access-list name (routeFilterACLName, naming.go) — NOT the
					// pre-#5872 `fromPrefixList + "_rf"` concatenation, which had no
					// length bound (FRR-identifier overflow) and no collision
					// namespace (two long same-prefix names truncate-collide → FRR
					// merges the access-lists → silent policy widen/narrow). The
					// SAME value backs the definition and the reference below, so
					// they always agree; routeFilterACLNameCollision (wired into
					// ApplyFull) fails the apply CLOSED on any residual collision.
					aclName := routeFilterACLName(fromPL.name, matchKW)
					renderFromPrefixListACL(&b, aclName, matchKW, plObj)
					fmt.Fprintf(&b, " match %s address %s\n", matchKW, aclName)
				} else {
					fmt.Fprintf(&b, " match %s address prefix-list %s\n", matchKW, fromPL.name)
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
				// #4498: sanitize the protocol token — the same #4097/#4482
				// render-side belt the other route-map free-text slots use.
				// A tolerant-load / peer-synced / rolled-back FromProtocols
				// value with an embedded newline must not inject an extra
				// frr.conf line (the strict #1798 commit gate rejects it, but
				// the lenient load path only warns, #1960).
				fmt.Fprintf(&b, " match source-protocol %s\n", sanitizeFRRValue(proto))
			}

			// fromCommunity / fromASPath are ONE entry of a possibly
			// multi-valued `from community` / `from as-path` set (#2642).
			// Junos OR's repeated same-type matches; FRR can hold only one
			// `match community` / `match as-path` rule per route-map index
			// (route_map_add_match replaces same-type), so OR is expressed
			// by emitting one SEQUENCE per entry (dispatch loop below).
			if fromCommunity != "" {
				fmt.Fprintf(&b, " match community %s\n", sanitizeFRRValue(fromCommunity))
			}

			if fromASPath != "" {
				fmt.Fprintf(&b, " match as-path %s\n", sanitizeFRRValue(fromASPath))
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
					// Junos `then next-hop self` sets the advertised next-hop to
					// THIS router's own session address for ONLY the routes that
					// match this term. FRR has no literal `set ... next-hop self`
					// (the parser rejects it and takes the whole route-map down),
					// but in an OUTBOUND route-map `set ip next-hop peer-address`
					// resolves to the local end of the BGP session — i.e. self —
					// and is evaluated per-route, so it rewrites exactly this
					// term's routes and leaves every other term's routes intact.
					// A BGP export policy is always rendered as `route-map <name>
					// out`, so this always evaluates in the outbound direction.
					//
					// This lowering REPLACES the pre-#5115 neighbor-wide
					// `neighbor <peer> next-hop-self force` knob, which ran after
					// route selection and rewrote EVERY route advertised to the
					// peer — including routes accepted by OTHER terms that never
					// requested self (the #5115 semantic widening). A term with
					// no `from` match still renders a match-all sequence, so a
					// genuinely neighbor-wide `then next-hop self` keeps its
					// neighbor-wide effect. Like the old `force`, an outbound
					// `set` overrides the next-hop on iBGP / route-reflector-
					// reflected routes too, so the #2977 iBGP blackhole stays
					// fixed — now correctly scoped to the term's routes.
					//
					// The session AF is unknown at render time; emit both forms
					// and FRR applies each only to its matching address family
					// (mirrors the `peer-address` branch above).
					fmt.Fprintf(&b, " set ip next-hop peer-address\n")
					fmt.Fprintf(&b, " set ipv6 next-hop peer-address\n")
				} else if strings.Contains(term.NextHop, ":") {
					// IPv6 literal next-hop. FRR rejects "set ip next-hop" for a
					// v6 address (whole route-map fails to parse); v6 uses the
					// dedicated "set ipv6 next-hop global" form. Mirror the
					// AF detection used by the prefix-list renderer above.
					fmt.Fprintf(&b, " set ipv6 next-hop global %s\n", sanitizeFRRValue(term.NextHop))
				} else {
					// #4498: sanitize the next-hop — an IP-typed slot, but on
					// the tolerant load / peer-sync / rollback path a stored
					// malformed value with an embedded newline reaches the
					// renderer (the strict #1798 commit gate does not cover
					// those paths, #1960). Parity with the #4482 set-clause belt.
					fmt.Fprintf(&b, " set ip next-hop %s\n", sanitizeFRRValue(term.NextHop))
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
			// BGP community operations (#2848). Junos/vSRX supports
			// append/delete/strip in addition to whole-attribute replace;
			// emitting only the replace clause wiped upstream-set
			// communities. Map each Junos operation to its FRR route-map
			// set clause. #4482: every free-text value below (set community,
			// set comm-list delete name, set as-path prepend, and the match
			// community / as-path names) is routed through sanitizeFRRValue —
			// the same #4097 render-side belt the community-list / as-path-list
			// definitions use — so a tolerant-load / peer-synced / rolled-back
			// value with an embedded newline cannot inject an extra frr.conf
			// line regardless of load path. #4498 extended the belt to the
			// three remaining bare-%s route-map slots the #4482 sweep missed:
			// `set ip/ipv6 next-hop`, `set origin`, and `match
			// source-protocol` (all rendered above).
			//   - add    → `set community <v> additive` (append)
			//   - delete → `set comm-list <name> delete` (strip by list)
			//   - none   → `set community none` (strip all)
			//   - set/"" → `set community <v>` (replace; legacy bare form)
			switch term.CommunityOp {
			case "none":
				b.WriteString(" set community none\n")
			case "add":
				if term.CommunityAdd != "" {
					fmt.Fprintf(&b, " set community %s additive\n", sanitizeFRRValue(term.CommunityAdd))
				}
			case "delete":
				// FRR's `set comm-list <name> delete` strips ONE
				// community-list per line, so a multi-list
				// `then community delete [ listA listB ]` emits one clause
				// per referenced list — every name in order (#2902).
				for _, name := range term.CommunityDelete {
					if name != "" {
						fmt.Fprintf(&b, " set comm-list %s delete\n", sanitizeFRRValue(name))
					}
				}
			default: // "" or "set" — whole-attribute replace
				if term.Community != "" {
					fmt.Fprintf(&b, " set community %s\n", sanitizeFRRValue(term.Community))
				}
			}
			// AS-path prepend (#2892). Junos `then as-path-prepend
			// "<asn> <asn> ..."` → FRR `set as-path prepend <asn> <asn>
			// ...`. The repeated ASNs lengthen the advertised AS_PATH so
			// peers prefer a shorter alternate path. Emit every ASN in
			// order (repetition is the mechanism) on a single clause; skip
			// entirely when no ASNs were configured.
			if len(term.ASPathPrepend) > 0 {
				fmt.Fprintf(&b, " set as-path prepend %s\n", sanitizeFRRValue(strings.Join(term.ASPathPrepend, " ")))
			}
			if term.Origin != "" && validBGPOrigin(term.Origin) {
				// #4919: skip an invalid origin (fail-closed) — a non-control
				// typo like `igpp` or a leniently-loaded / peer-synced bad
				// value would fail the FRR route-map grammar and poison the
				// reload. Only igp | egp | incomplete are valid. #4498:
				// sanitize the accepted token too (defense-in-depth; a valid
				// origin has no control chars, so it is a no-op on the happy
				// path).
				fmt.Fprintf(&b, " set origin %s\n", sanitizeFRRValue(term.Origin))
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
		plName := plPrefix + "-" + term.Name
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

		// emitVariants emits the cross-product of the from-* OR sets for one
		// route-filter family group (seqFam/rfs/famPL), advancing seq by 10 per
		// sequence. The iteration order (prefix-list, then its per-family refs,
		// then community, then as-path) is fixed, so output is deterministic.
		// Each referenced prefix-list expands into one ref per family it holds
		// (fromPrefixListRefs): a single-family list yields one ref (unchanged
		// output), a mixed v4+v6 list yields an ip ref and an ipv6 ref so BOTH
		// families bind a family-correct match line (#2607).
		emitVariants := func(seqFam string, rfs []indexedRouteFilter, famPL string) {
			for _, plName := range orElseEmpty(term.PrefixList) {
				for _, plRef := range fromPrefixListRefs(po, plName) {
					for _, comm := range orElseEmpty(term.FromCommunity) {
						for _, asp := range orElseEmpty(term.FromASPath) {
							emitTermBody(seqFam, seq, rfs, famPL, plRef, comm, asp)
							seq += 10
						}
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

	return b.String(), seq
}

// renderRouteMapForPolicy renders ONE FRR route-map for policy-statement ps
// under emitName, appending the caller-supplied trailing default action. The
// body — terms, match/set clauses, and inline route-filter prefix-lists whose
// names derive from emitName — is identical across use sites; only the header
// name and the trailing default differ. That lets a BGP-default-accept policy
// ALSO be rendered under a fail-closed per-use-site alias for redistribute
// without leaking its permit default across FRR's name-keyed route-map object
// (#4481 / #2998 / #2607 / #2642).
func (m *Manager) renderRouteMapForPolicy(po *config.PolicyOptionsConfig, emitName string, ps *config.PolicyStatement, trailingAction string) string {
	body, seq := m.renderPolicyTermSequences(po, emitName, emitName, ps, 10)
	var b strings.Builder
	b.WriteString(body)

	// Trailing default action, resolved by the caller — Junos BGP
	// default-accept (#2998) or the fail-closed redistribute /
	// forwarding-table default — and passed in so the SAME body can render
	// under a per-use-site alias with a different trailing default, never
	// mutating FRR's name-keyed shared route-map object (#4481). See
	// policyTrailingAction for the case matrix.
	fmt.Fprintf(&b, "route-map %s %s %d\n", emitName, trailingAction, seq)
	b.WriteString("exit\n")
	return b.String()
}

// renderComposedRouteMap composes an ordered Junos BGP policy CHAIN (>= 2
// DEFINED policy-statements, e.g. `export [ A B C ]`) into a SINGLE FRR
// route-map named composedName, preserving Junos policy-chain semantics that
// the pre-#5277 lastNonEmpty collapse violated by rendering only the final
// policy:
//
//   - Each policy's terms evaluate IN ORDER (A, then B, then C). A term's
//     terminating `then accept`/`then reject` wins immediately (permit/deny,
//     stop); a non-terminating term applies its set clauses and falls through
//     (on-match next), exactly as the single-policy render does.
//   - A policy with an EXPLICIT policy-level default (`then accept`/`then
//     reject`) TERMINATES the chain with a match-all permit/deny — later
//     policies are unreachable (Junos: the default action is terminating).
//   - A policy with NO explicit default FALLS THROUGH to the next policy
//     (Junos next-policy), so a route BLOCK-PRIVATE would reject is caught by
//     BLOCK-PRIVATE before ALLOW-CUSTOMER ever runs.
//   - If the route falls off the end of EVERY policy, the Junos BGP
//     default-ACCEPT applies (#2998). A composed chain only ever renders in a
//     BGP `route-map in`/`out` context, so that fall-off default is permit.
//
// Sequence numbers run continuously across the chain; each policy's inline
// prefix-lists are namespaced by composedName+"-"+policyName so a term name
// reused across policies cannot fuse two prefix-lists.
func (m *Manager) renderComposedRouteMap(po *config.PolicyOptionsConfig, composedName string, chain []string) string {
	// #5732 render-side belt: this composed route-map numbers its members'
	// sequences with ONE running counter, so a chain whose members each pass the
	// per-policy #5701 bound can still SUM past the FRR ceiling and emit a
	// `route-map` line past seq 65535 — poisoning the whole vtysh-batched
	// frr-reload. The strict commit gate
	// (config.validateBGPComposedChainSequenceBoundStrict) rejects it; this belt
	// covers the tolerant load / peer-sync / rollback path (#1960) where that
	// gate only warns: render NOTHING for the oversized chain (its neighbor
	// `route-map <composedName> out` then dangles → FRR permit-all, strictly
	// better than a poisoned reload — the same tradeoff generatePolicyOptions
	// takes for an over-ceiling single policy, #5701). The gate and this belt
	// consult the SAME config.ComposedChainSequenceCount predicate, so they can
	// never disagree on what overflows.
	if n := config.ComposedChainSequenceCount(po.PolicyStatements, chain); n > config.MaxRouteMapSequences {
		slog.Warn("skipping oversized composed BGP policy-chain route-map: expansion would overflow FRR sequence numbers and poison the reload",
			"route-map", composedName, "sequences", n, "max", config.MaxRouteMapSequences)
		return ""
	}
	var b strings.Builder
	seq := 10
	terminated := false
	for _, name := range chain {
		ps := po.PolicyStatements[name]
		if ps == nil {
			// Defensive: chain is pre-filtered to defined policy-statements.
			continue
		}
		body, next := m.renderPolicyTermSequences(po, composedName, composedName+"-"+name, ps, seq)
		b.WriteString(body)
		seq = next
		switch ps.DefaultAction {
		case "accept":
			fmt.Fprintf(&b, "route-map %s permit %d\n", composedName, seq)
			b.WriteString("exit\n")
			seq += 10
			terminated = true
		case "reject":
			fmt.Fprintf(&b, "route-map %s deny %d\n", composedName, seq)
			b.WriteString("exit\n")
			seq += 10
			terminated = true
		}
		if terminated {
			break
		}
	}
	if !terminated {
		// Fell off the end of every policy in the chain → Junos BGP
		// default-ACCEPT (#2998): permit the (accumulated-modified) route.
		fmt.Fprintf(&b, "route-map %s permit %d\n", composedName, seq)
		b.WriteString("exit\n")
	}
	return b.String()
}
