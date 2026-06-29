package config

import (
	"fmt"
	"sort"
)

// compiler_applications_collision.go carries the #3339 (Codex review 080 M07 +
// M08) reject-at-commit gate for application / application-set NAME COLLISIONS.
//
// compileApplications collects user applications and application-sets into two
// maps keyed by name (apps.Applications[name], apps.ApplicationSets[name]) and a
// multi-term application additionally MINTS an implicit application-set under the
// application's own name (apps.ApplicationSets[appName] = implicitSet). Every one
// of these writes is last-write-wins: a second definition silently OVERWRITES
// the first, with no commit error. The observable failures (#3339):
//
//   - M07: an explicit `applications application-set <X>` silently replaces the
//     implicit set minted for a multi-term `applications application <X>` (or,
//     more generally, an application and an application-set share a name). A
//     policy referencing <X> then enforces whichever definition won the
//     map-write race — and policy expansion vs the AppID catalog disagree on
//     which that is (resolveUserspaceApplicationNames resolves application-first;
//     addPolicyApps resolves application-set-first), so a session can be
//     admitted by one definition but cataloged/labeled by the other.
//
//   - M08: two `term` statements under one application that generate the same
//     per-term application name (`<parent>-<term>`, with a protocol suffix only
//     when a single term carries multiple protocols) — the later
//     apps.Applications[name] = t silently overwrites the earlier while the
//     implicit set still lists the duplicated member. Ambiguous and silent.
//
// Junos treats applications and application-sets as a SINGLE flat namespace and
// rejects a duplicate definition / a name used for both; this gate restores that
// parity. It is an AST pre-walk (run on the group-expanded, inactive-pruned tree
// in compileExpanded) rather than a post-compile check on the typed *Config,
// because by the time the maps are built the colliding definitions have ALREADY
// been merged away by last-write-wins — only the raw AST still carries every
// definition. This mirrors validateUnsupportedInterfaceStanzasAST and the other
// AST reject-at-commit gates.
//
// Strict path (commit / commit-check, lenient=false): the first collision is a
// hard compile error naming the offending name. Lenient path (load / peer-sync,
// lenient=true): every collision is returned as a warning and compilation
// continues with the existing last-write-wins behavior, so an already-persisted
// or peer-synced config that an older binary silently accepted still BOOTS
// (#1960 / #3261 fail-closed-on-load doctrine). compileApplications is unchanged
// — the lenient path deliberately keeps producing the (arbitrary but stable)
// last-write-wins maps it always did.
//
// Scope notes:
//   - Only USER-authored AST stanzas are examined. The predefined junos-* table
//     lives outside the AST, so a user `application junos-http` that shadows a
//     predefined application is NOT a collision (one AST stanza, no peer) and is
//     left untouched — the legitimate shadow/extend case the #3339 issue calls
//     out.
//   - A multi-term application <X> minting an implicit set <X> is NOT a
//     self-collision: the application stanza and its synthesized set share a name
//     by design. The collision is only between two OPERATOR-authored stanzas,
//     i.e. an `application <X>` AND an `application-set <X>`, which is exactly the
//     M07 implicit-set-overwrite case.
//   - Duplicate application or application-set definitions (the same name authored
//     twice in the same namespace) are also rejected; these survive as distinct
//     AST siblings only on a hierarchical file parse (the set-command config tree
//     merges same-named siblings), but rejecting them keeps the gate honest for
//     either representation.

// validateApplicationNameCollisionsAST walks the `applications` subtree of the
// group-expanded AST and rejects duplicate / cross-namespace application name
// definitions. See the file-level comment for the doctrine.
func validateApplicationNameCollisionsAST(nodes []*Node, lenient bool) ([]string, error) {
	// The compiler compiles EVERY top-level `applications` node (compiler.go's
	// `for _, node := range tree.Children` switch hits `case "applications"`
	// once per node), so a collision SPLIT across two sibling `applications {}`
	// blocks (which a hierarchical parse emits as separate top-level nodes) is
	// just as real as one inside a single block. Aggregate counts across ALL of
	// them rather than stopping at the first — stopping at the first missed the
	// exact #3339 bug for a split definition.
	var appsNodes []*Node
	for _, n := range nodes {
		if n.Name() == "applications" {
			appsNodes = append(appsNodes, n)
		}
	}
	if len(appsNodes) == 0 {
		return nil, nil
	}

	var warnings []string
	emit := func(format string, args ...any) error {
		msg := fmt.Sprintf(format, args...)
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
		return nil
	}

	// Count each name within its namespace across every `applications` block.
	// namedInstances enumerates every instance (it does NOT dedup), so a name
	// authored twice — in one block or split across blocks — yields count > 1.
	appCounts := map[string]int{}
	appOrder := []string{}
	setCounts := map[string]int{}
	for _, appsNode := range appsNodes {
		for _, inst := range namedInstances(appsNode.FindChildren("application")) {
			if inst.name == "" {
				continue
			}
			if appCounts[inst.name] == 0 {
				appOrder = append(appOrder, inst.name)
			}
			appCounts[inst.name]++
		}
		for _, inst := range namedInstances(appsNode.FindChildren("application-set")) {
			if inst.name == "" {
				continue
			}
			setCounts[inst.name]++
		}
	}

	// 1. Duplicate application definition (same name twice in the application
	//    namespace). Reported in first-seen order for a deterministic error.
	for _, name := range appOrder {
		if appCounts[name] > 1 {
			if err := emit(
				"applications application %q is defined %d times — a duplicate "+
					"application definition is silently last-write-wins (the later "+
					"definition replaces the earlier with no commit error); remove "+
					"the duplicate or rename it (#3339)",
				name, appCounts[name]); err != nil {
				return nil, err
			}
		}
	}

	// 2. Duplicate application-set definition (same name twice in the
	//    application-set namespace).
	setNames := make([]string, 0, len(setCounts))
	for name := range setCounts {
		setNames = append(setNames, name)
	}
	sort.Strings(setNames)
	for _, name := range setNames {
		if setCounts[name] > 1 {
			if err := emit(
				"applications application-set %q is defined %d times — a duplicate "+
					"application-set definition is silently last-write-wins (the "+
					"later definition replaces the earlier with no commit error); "+
					"remove the duplicate or rename it (#3339)",
				name, setCounts[name]); err != nil {
				return nil, err
			}
		}
	}

	// 3. Cross-namespace collision: a name authored as BOTH an application and an
	//    application-set. Applications and application-sets share one flat Junos
	//    namespace; a multi-term application additionally mints an implicit set
	//    under its own name, so an explicit `application-set <X>` here silently
	//    overwrites it. Either way enforcement (policy expansion) and the AppID
	//    catalog can resolve <X> to different definitions (M07). Reported in
	//    application first-seen order.
	for _, name := range appOrder {
		if setCounts[name] > 0 {
			if err := emit(
				"name %q is defined as BOTH an application and an "+
					"application-set — they share one namespace, so the "+
					"application-set silently overwrites the application (or the "+
					"implicit set minted for a multi-term application), and a policy "+
					"referencing %q may enforce one definition while AppID catalogs "+
					"the other; rename one of them (#3339)",
				name, name); err != nil {
				return nil, err
			}
		}
	}

	// 4. Duplicate generated per-term application name within one application
	//    (M08). Two terms whose generated `<parent>-<term>` names collide make
	//    the later overwrite the earlier in apps.Applications. Computed via the
	//    SAME parseApplicationTerms the compiler uses so the detected names match
	//    exactly what would be written. The seen/reported sets are keyed by
	//    application NAME (not per AST node) so a name whose terms are split
	//    across two `applications` blocks is still caught. Applications iterated
	//    in first-seen order.
	termSeen := map[string]map[string]bool{}
	termDupReported := map[string]map[string]bool{}
	for _, appsNode := range appsNodes {
		for _, inst := range namedInstances(appsNode.FindChildren("application")) {
			appName := inst.name
			if appName == "" {
				continue
			}
			if termSeen[appName] == nil {
				termSeen[appName] = map[string]bool{}
				termDupReported[appName] = map[string]bool{}
			}
			seen := termSeen[appName]
			dupReported := termDupReported[appName]
			for _, prop := range inst.node.Children {
				if prop.Name() != "term" || len(prop.Keys) < 2 {
					continue
				}
				// Reassemble the term tokens across both AST shapes, mirroring
				// compileApplications: hierarchical packs values in prop.Keys,
				// flat set splits them across prop.Keys and prop.Children.
				allKeys := append([]string(nil), prop.Keys[1:]...)
				for _, c := range prop.Children {
					allKeys = append(allKeys, c.Keys...)
				}
				for _, t := range parseApplicationTerms(appName, allKeys) {
					if seen[t.Name] {
						if !dupReported[t.Name] {
							dupReported[t.Name] = true
							if err := emit(
								"applications application %q has terms that generate "+
									"the duplicate application name %q — the later term "+
									"silently overwrites the earlier (with no commit "+
									"error) while the implicit set still lists the "+
									"duplicate member; give the terms distinct names "+
									"(#3339)",
								appName, t.Name); err != nil {
								return nil, err
							}
						}
						continue
					}
					seen[t.Name] = true
				}
			}
		}
	}

	return warnings, nil
}
