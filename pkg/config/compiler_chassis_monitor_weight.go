package config

import (
	"fmt"
	"strconv"
)

// compiler_chassis_monitor_weight.go carries the #6588 commit-side gate for a
// redundancy-group monitor weight that is present but UNUSABLE — malformed, or
// specified twice with different values.
//
// Why an AST pre-walk rather than a typed schema leaf or a compiled-struct
// check:
//
//   - The typed-leaf route is closed. `interface-monitor` packs
//     `<ifname> weight <n>` onto ONE node key, so schema_chassis.go declares it
//     `children: nil` (typing the weight would need a children/wildcard map,
//     which flips SetPath's replace-vs-container grouping). SchemaValidate
//     therefore never reaches the weight token at all — and for the PACKED
//     spelling it does not reach the ip-monitoring weights either, which sit
//     below the depth its walk descends.
//
//   - The compiled struct cannot tell these cases apart. compileChassis parses
//     the weight with strconv.Atoi and, on failure, leaves the pre-existing 0
//     default. `weight nope` and `weight 0` and no weight at all are all
//     Weight==0 by the time validateChassisClusterStrict sees them, so the
//     #6549 range gate — which is otherwise the right layer, and which #6588
//     extended to ip-monitoring — structurally cannot flag a parse failure.
//
// Both problems are the same class as the packed-statement drop this file's
// issue is about: the operator configures a monitor, `commit` succeeds with no
// error and no warning, and the redundancy group carries LESS demotion debt
// than was written — `interface-monitor ge-0/0/0 weight nope;` installs a
// monitor whose weight is 0, so the link going down demotes the group by
// nothing and failover does not happen.
//
// Duplicates were additionally SHAPE-DEPENDENT before this gate:
// `weight 100 weight 200` inline compiled to 200 (the inline scan overwrote)
// while `{ weight 100; weight 200; }` compiled to 100 (FindChild returns the
// first). The compiler is now uniformly first-wins via monitorWeightTokens, and
// this gate rejects the duplicate outright so the operator is never relying on
// which spelling they happened to use.
//
// Strictness follows the sibling chassis gates: hard-reject at commit /
// commit-check, downgrade to a cfg.Warnings entry on the tolerant load /
// peer-sync paths (#1960 no-brick) — an already-persisted or peer-pushed config
// an older binary accepted must still BOOT. The compiled 0 default is what the
// tolerant path keeps, now flagged rather than silent.

// validateMonitorWeightTokensAST walks the chassis cluster subtree and reports
// every redundancy-group monitor weight that is present but unusable. It runs
// on the group-expanded tree so an apply-groups-inherited weight is covered.
//
// It derives its entries from monitorEntryNodes / monitorWeightTokens — the
// same readers compileChassis uses — so the gate and the compiler cannot drift
// apart about which token is a weight, which entry it belongs to, or how a
// bracketed list splits.
//
// Returns (warnings, nil) when lenient, (nil, error) on the first offender when
// strict.
func validateMonitorWeightTokensAST(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string

	emit := func(format string, args ...interface{}) error {
		msg := fmt.Sprintf(format, args...)
		if lenient {
			warnings = append(warnings, msg)
			return nil
		}
		return fmt.Errorf("%s", msg)
	}

	// checkEntries validates every entry of one monitor statement. what names
	// the statement for the operator (e.g. `interface-monitor`), and label
	// renders the entry's identity within the redundancy group.
	checkEntries := func(rgName, what string, entries []*Node) error {
		for _, entry := range entries {
			toks := monitorWeightTokens(entry)
			if len(toks) == 0 {
				continue // No weight at all: the documented 0 default (#6549).
			}
			if len(toks) > 1 {
				distinct := false
				for _, t := range toks[1:] {
					if t != toks[0] {
						distinct = true
						break
					}
				}
				if distinct {
					if err := emit("chassis cluster redundancy-group %s %s %s: weight "+
						"specified %d times with different values %q — the compiled weight "+
						"would depend on the spelling; specify exactly one weight",
						rgName, what, entry.Name(), len(toks), toks); err != nil {
						return err
					}
					continue
				}
				if err := emit("chassis cluster redundancy-group %s %s %s: weight "+
					"specified %d times; specify exactly one weight",
					rgName, what, entry.Name(), len(toks)); err != nil {
					return err
				}
				continue
			}
			if _, err := strconv.Atoi(toks[0]); err != nil {
				if err := emit("chassis cluster redundancy-group %s %s %s: weight %q is not "+
					"an integer — it compiles to the 0 default, so the monitor going down "+
					"deducts NO weight and the redundancy group never demotes; set a weight "+
					"in %d..%d",
					rgName, what, entry.Name(), toks[0],
					MinInterfaceMonitorWeight, MaxInterfaceMonitorWeight); err != nil {
					return err
				}
			}
		}
		return nil
	}

	walkErr := forEachChild(nodes, "chassis", func(chassis *Node) error {
		return forEachChild(chassis.Children, "cluster", func(cluster *Node) error {
			for _, rgInst := range namedInstances(cluster.FindChildren("redundancy-group")) {
				for _, child := range redundancyGroupBody(rgInst.node) {
					switch child.Name() {
					case "interface-monitor":
						if err := checkEntries(rgInst.name, "interface-monitor",
							monitorEntryNodes(child, 1)); err != nil {
							return err
						}
					case "ip-monitoring":
						for _, familyNode := range packedStatementProps(child, 1, isIPMonitoringProp) {
							if familyNode.Name() != "family" {
								continue
							}
							inetNode, inetSkip := ipMonitoringInetNode(familyNode)
							if inetNode == nil {
								continue
							}
							if err := checkEntries(rgInst.name, "ip-monitoring family inet",
								monitorEntryNodes(inetNode, inetSkip)); err != nil {
								return err
							}
						}
					}
				}
			}
			return nil
		})
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return warnings, nil
}

// ipMonitoringInetNode resolves the node holding the monitored IPv4 addresses
// of an ip-monitoring `family` property, and how many of its leading Keys name
// the node itself rather than an address. The compound spelling
// (`family inet ...`, Keys[1]=="inet") and the nested one
// (`family { inet { ... } }`) differ by exactly one identity token, and getting
// that offset wrong silently shifts which token is read as an address — so both
// compileChassis and validateMonitorWeightTokensAST resolve it here rather than
// each open-coding the branch.
func ipMonitoringInetNode(familyNode *Node) (*Node, int) {
	if len(familyNode.Keys) >= 2 && familyNode.Keys[1] == "inet" {
		return familyNode, 2
	}
	return familyNode.FindChild("inet"), 1
}
