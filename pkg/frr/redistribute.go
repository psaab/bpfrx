// redistribute.go converts a Junos routing export value into FRR
// `redistribute` commands, skipping-and-warning on anything that cannot
// resolve to a source protocol so one bad line never poisons the whole
// managed frr-reload (#1880/#2223).
//
// Split out of policy_render.go (#6424) as a pure code-motion refactor;
// the emitted frr.conf is byte-identical.
//
// Symbols:
//   - knownRedistProtocols
//   - resolveRedistribute
//   - isDefinedPolicyStatement
package frr

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// knownRedistProtocols are the FRR redistribute protocol keywords.
// ospf6 / ripng are the FRR keywords for OSPFv3 / RIPng redistribution;
// without them a bare `export ospf6` / `export ripng` falls through to the
// skip-and-warn path and IPv6 IGP redistribution cannot be expressed (#2943).
// #7121: the domain moved to config.FRRRoutingProtocolKeyword so the COMMIT
// gate can consult it. It lived here, where a commit-time validator could not
// reach it (pkg/frr imports pkg/config, not the reverse), which is why an
// unknown `from protocol` token committed clean and degraded the reload.
func knownRedistProtocol(name string) bool {
	return config.RoutingProtocolResolvable(name)
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
	if knownRedistProtocol(export) {
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
