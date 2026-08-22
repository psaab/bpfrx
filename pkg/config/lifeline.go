package config

import "strings"

// lifeline.go is the SSOT for host-inbound LIFELINE interface matching (#3682).
// Before #3682 the matcher lived privately in pkg/dataplane/userspace/zones.go
// and drove the host-inbound deny-scoping decision, but no operator-visible zone
// view could re-derive it, so a zone-assigned lifeline interface silently
// dropped out of the host-inbound default-deny with nothing to render the
// exemption. Hoisting the matcher here lets the shared host-inbound presenter
// (host_inbound_view.go) surface the exemption on every text zone view while the
// dataplane path keeps using the identical logic (userspace/zones.go now
// delegates here) — one source of truth for both enforcement and display.

// LifelineBaseName strips the unit suffix (".0") and surrounding whitespace from
// a logical interface name, returning the bare device name used for lifeline
// matching ("fxp0.0" -> "fxp0", "fab1.0" -> "fab1"). Returns "" for an empty
// name.
func LifelineBaseName(name string) string {
	base := strings.TrimSpace(name)
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	return base
}

// HostInboundLifelineSet resolves the set of management / cluster-control
// LIFELINE interface base names that must NEVER be subjected to a host-inbound
// deny. It is the config-aware superset of the always-on defaults:
//
//   - fxp0 (out-of-band management) is always a lifeline.
//   - The chassis-cluster control-interface and fabric interface(s) are added
//     from config so an operator-renamed control link (e.g.
//     `control-interface fxp1`) or a non-default fabric name is excluded too.
//     This is the #3277 fix: the old matcher hardcoded fxp0/em0/fab* and so left
//     a configured `control-interface fxp1` SUBJECT to host-inbound deny scoping
//     -> potential heartbeat drop -> HA split-brain.
//
// em0 (the canonical cluster-control default name) and the fabric device names
// fab<N> stay matched unconditionally in HostInboundLifelineInterface so the
// canonical default-named configs remain byte-identical (#3070/#3172/#3224
// behavior is preserved). #5250 narrowed that second arm from the `fab` PREFIX
// to `fab` + digits; a fabric interface under any other name must be DECLARED
// (`fabric-interface` / `fabric1-interface`) to reach this set, which is the
// #3277 path and is unaffected. A standalone config (no chassis-cluster stanza)
// contributes no extra names here, so its only lifeline is fxp0 (em0/fab<N> are
// no-ops because such interfaces are not present) — #1960.
func HostInboundLifelineSet(cfg *Config) map[string]bool {
	set := map[string]bool{"fxp0": true}
	if cfg != nil && cfg.Chassis.Cluster != nil {
		cc := cfg.Chassis.Cluster
		for _, name := range []string{cc.ControlInterface, cc.FabricInterface, cc.Fabric1Interface} {
			if base := LifelineBaseName(name); base != "" {
				set[base] = true
			}
		}
	}
	return set
}

// HostInboundLifelineInterface reports whether the given logical interface name
// is a management / cluster-control LIFELINE that must NEVER be subjected to a
// host-inbound deny. The lifeline set is the config-derived set (fxp0 plus the
// configured chassis-cluster control-interface / fabric interfaces, #3277) UNION
// the always-on backward-compatible defaults em0 (cluster control plane /
// heartbeat default name) and the fabric links (fab*). Denying host-bound
// traffic on these would strand management or break HA. The base name (before
// the unit suffix) is matched so "fxp0.0" / "em0.0" are caught too.
//
// #5250 (A3-b2 F3): the unconditional fabric match is EXACT-SHAPED, not a bare
// prefix. `strings.HasPrefix(base, "fab")` admitted every name that merely
// STARTS with "fab" — "fab-foo", "fabric-guest", "fabX" — and admission here is
// not cosmetic: junosHostNonLifelineRefs (junos_host_deny.go:308) and
// JunosHostZoneIngressNetdevs (:1147) both SKIP a lifeline, so a host-inbound
// `deny` policy naming such an interface produced no kernel rule at all. The
// only fabric devices the daemon ever creates are `fab0` and `fab1`
// (CleanupFabricIPVLANs, pkg/daemon/daemon_ha_fabric.go:153), and the config
// form is an interface literally named `fab<N>` carrying `fabric-options
// member-interfaces` (compiler_derivations.go:131), so `fab` + digits is the
// whole legitimate population. Anything else is now an ordinary interface and
// is subject to host-inbound deny like any other.
//
// The #3682 design note this replaces recorded the over-broad prefix as an open
// design question; it is answered here rather than left open. The em0 arm was
// already exact and is unchanged — a standalone config that names an interface
// em0 still gets the historical exception (#3070/#3172/#3224 byte-identical).
func HostInboundLifelineInterface(name string, lifelines map[string]bool) bool {
	base := LifelineBaseName(name)
	if base == "" {
		return false
	}
	if lifelines[base] {
		return true
	}
	return base == "em0" || isFabricDeviceName(base)
}

// isFabricDeviceName reports whether base is a fabric device name in the only
// shape the daemon creates or the compiler derives: the literal "fab" followed
// by one or more DIGITS and nothing else ("fab0", "fab1", "fab10"). Written as
// a scan rather than a regexp so it stays allocation-free on the config-compile
// path and cannot be defeated by a regexp missing its anchors.
func isFabricDeviceName(base string) bool {
	const prefix = "fab"
	if len(base) <= len(prefix) || base[:len(prefix)] != prefix {
		return false
	}
	for i := len(prefix); i < len(base); i++ {
		if base[i] < '0' || base[i] > '9' {
			return false
		}
	}
	return true
}
