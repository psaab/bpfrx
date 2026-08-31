package config

import (
	"fmt"
	"net"
)

// Shared "is this static route actually installed?" predicate.
//
// #7357 items 3-5: `show route` / `show routing-options` render every
// configured static route straight from config, while
// buildRouteSnapshots (pkg/dataplane/userspace/routes.go) DROPS four
// classes of them. A dropped route printed as configured reads as an
// installed route, which is the #6534 archetype: the operator checks the
// surface after committing and it confirms a forwarding decision that is
// not in force.
//
// Same mechanism as FlowServerExcludedReason and the NAT family, and NOT an
// applied-set readback: every verdict below is a deterministic function of
// the committed config, so the renderer can reach it without runtime state.
//
// THREE of the four reasons are per-route. The fourth (the next-table window)
// is ORDER-DEPENDENT and cannot be decided from one route, which is why
// StaticRouteExclusions exists alongside this.

// StaticRouteExcludedReason reports why buildRouteSnapshots drops `sr`, or ""
// when it publishes it.
//
// `perInstance` distinguishes a route under `routing-instances <n>
// routing-options` from a global one; `definedInstances` is the set of
// routing-instance names the config defines.
//
// It deliberately does NOT decide the next-table WINDOW case — that depends on
// how many eligible global next-table routes precede this one, which no
// per-route call can know. Use StaticRouteExclusions for a whole config.
func StaticRouteExcludedReason(sr *StaticRoute, perInstance bool, definedInstances map[string]struct{}) string {
	if sr == nil {
		return ""
	}
	if sr.NextTable == "" {
		return ""
	}
	// #5830: a `next-table` authored UNDER a routing-instance is NOT programmed
	// on the kernel/FRR forwarding plane — daemon_apply feeds only the GLOBAL
	// routing-options statics to ApplyNextTableRules, the FRR renderer emits
	// nothing for a NextTable route, and the kernel ip-rule leak carries no
	// source-table scoping. Publishing it as a live per-instance next-table made
	// the userspace FIB leak traffic the kernel/FRR view never routes — a
	// control-plane/data-plane split-brain. Both planes must agree it is ABSENT.
	//
	// The strict commit gate (validateNextTableTargetReferencesStrict, #5830)
	// hard-rejects such a config, so this is reachable only on the tolerantly-
	// loaded / peer-synced path where that reject is downgraded to a warning
	// (#1960 no-brick). GLOBAL next-table IS programmed via ip rule and stays
	// published so the Rust FIB can cross-reference the target table.
	if perInstance {
		return "next-table is not supported under a routing-instance — no ip rule is installed for it"
	}
	if _, ok := definedInstances[sr.NextTable]; !ok {
		return fmt.Sprintf("next-table target routing-instance %q is not defined", sr.NextTable)
	}
	if _, _, err := net.ParseCIDR(sr.Destination); err != nil {
		return fmt.Sprintf("destination %q does not parse as a CIDR prefix", sr.Destination)
	}
	return ""
}

// StaticRouteExclusions returns the exclusion reason for every static route in
// `cfg` that buildRouteSnapshots drops, keyed by the route pointer.
//
// It exists for the ORDER-DEPENDENT fourth reason. The kernel programs global
// next-table leaks as ip rules capped at NextTableRuleWindow entries, and the
// applier advances that counter only for an ELIGIBLE route — so whether a given
// route falls outside the window depends on how many eligible ones came before
// it, in the builder's own order.
//
// That order is reproduced exactly and it is narrower than it looks: the window
// counter advances ONLY on the global path (`perInstance == false`), so
// per-instance routes cannot affect it and the walk below only needs the two
// global lists, v4 then v6, matching routes.go's two `addRoutes(..., false)`
// calls. Per-instance routes are still classified, just not counted.
func StaticRouteExclusions(cfg *Config) map[*StaticRoute]string {
	out := make(map[*StaticRoute]string)
	if cfg == nil {
		return out
	}
	defined := make(map[string]struct{}, len(cfg.RoutingInstances))
	for _, inst := range cfg.RoutingInstances {
		if inst != nil {
			defined[inst.Name] = struct{}{}
		}
	}

	// GLOBAL, v4 then v6 — the only routes that consume window slots.
	window := 0
	for _, routes := range [][]*StaticRoute{cfg.RoutingOptions.StaticRoutes, cfg.RoutingOptions.Inet6StaticRoutes} {
		for _, sr := range routes {
			if sr == nil {
				continue
			}
			if reason := StaticRouteExcludedReason(sr, false, defined); reason != "" {
				out[sr] = reason
				continue
			}
			if sr.NextTable == "" {
				continue // not a leak; consumes no slot
			}
			if window >= NextTableRuleWindow {
				out[sr] = fmt.Sprintf(
					"beyond the %d-entry next-table ip-rule window — the kernel installs no rule for it",
					NextTableRuleWindow)
				continue
			}
			window++
		}
	}

	// PER-INSTANCE: classified, never counted.
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		for _, routes := range [][]*StaticRoute{ri.StaticRoutes, ri.Inet6StaticRoutes} {
			for _, sr := range routes {
				if sr == nil {
					continue
				}
				if reason := StaticRouteExcludedReason(sr, true, defined); reason != "" {
					out[sr] = reason
				}
			}
		}
	}
	return out
}
