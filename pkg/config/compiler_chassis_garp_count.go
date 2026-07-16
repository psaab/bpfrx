package config

import (
	"fmt"
	"strconv"
)

// compiler_chassis_garp_count.go carries the #5695 (codex-182 M16) commit-side
// SIGNAL for an over-large chassis-cluster redundancy-group
// gratuitous-arp-count.
//
// The PRIMARY M16 fix is the RUNTIME CLAMP (config.GratuitousARPBurstClamp,
// consumed by pkg/vrrp sendGARP and pkg/daemon directSendGARPs) — an unbounded
// configured count would fan the full per-VIP burst (1 immediate frame +
// (count-1) 50ms follow-ups) on every failover, a self-inflicted CPU/socket
// exhaustion vector.
//
// This gate is defense-in-depth, not a hard reject: the no-schema-only-caps
// doctrine (schema_chassis.go, PR #1845) forbids rejecting AT COMMIT a count
// the runtime executes (or, here, safely clamps) fine — Junos caps at 16 but
// the runtime happily runs any count up to the clamp. So a count over the
// runtime clamp is ACCEPTED and compiled verbatim; the operator just gets a
// WARNING that the value will be clamped to GratuitousARPBurstClamp per VIP on
// failover and therefore is not used as written. This mirrors the #1960
// lenient/warn posture (signal without rejecting a runtime-valid config) and
// the sibling chassis AST gates in runPreWalkGates.

// validateGratuitousARPCountAST walks the chassis cluster subtree and emits an
// operator warning (never an error) for any redundancy-group
// gratuitous-arp-count that exceeds GratuitousARPBurstClamp. Runs on the
// group-expanded tree so an apply-groups-inherited count is covered. A count
// within [1, GratuitousARPBurstClamp] (which includes the whole Junos 1..16
// range) is unaffected. A malformed / non-integer token is left to the schema
// validator (ValidateIntegerMin) and skipped here.
func validateGratuitousARPCountAST(nodes []*Node) []string {
	var warnings []string
	_ = forEachChild(nodes, "chassis", func(chassis *Node) error {
		return forEachChild(chassis.Children, "cluster", func(cluster *Node) error {
			for _, rgInst := range namedInstances(cluster.FindChildren("redundancy-group")) {
				gc := rgInst.node.FindChild("gratuitous-arp-count")
				if gc == nil {
					continue
				}
				v := nodeVal(gc)
				if v == "" {
					continue
				}
				n, err := strconv.Atoi(v)
				if err != nil {
					continue
				}
				if n > GratuitousARPBurstClamp {
					warnings = append(warnings, fmt.Sprintf(
						"chassis cluster redundancy-group %s gratuitous-arp-count %d exceeds the "+
							"runtime safety maximum %d and will be clamped to %d per VIP on failover "+
							"(a burst beyond the Junos 1..16 range adds no neighbor-cache benefit); "+
							"reduce it to <= %d to silence this warning (#5695)",
						rgInst.name, n, GratuitousARPBurstClamp, GratuitousARPBurstClamp,
						GratuitousARPBurstClamp))
				}
			}
			return nil
		})
	})
	return warnings
}
