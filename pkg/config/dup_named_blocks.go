package config

import (
	"fmt"
	"sort"
)

// nonInterfaceIfKeyword lists the non-leaf children that may appear directly
// under an `interfaces { }` stanza but are NOT interface definitions, so the
// duplicate-interface gate must not treat a repeat of one as a dropped
// interface. `interface-range` legitimately repeats (one block per range) and
// `traceoptions` / `apply-macro` are container leaves, not interfaces.
var nonInterfaceIfKeyword = map[string]bool{
	"interface-range":     true,
	"traceoptions":        true,
	"apply-macro":         true,
	"apply-groups":        true,
	"apply-groups-except": true,
}

// screenIDSFamily lists the ids-option sub-stanzas compileScreen reads with
// FindChild (first-sibling only): a repeated same-family block inside one
// ids-option is silently dropped. Keep in sync with compileScreen
// (compiler_security_screen.go).
var screenIDSFamily = map[string]bool{
	"icmp":          true,
	"ip":            true,
	"tcp":           true,
	"udp":           true,
	"limit-session": true,
}

// dupBlock is one detected duplicate authored hierarchical named block.
type dupBlock struct {
	kind string // human category, e.g. "interface" / "screen ids-option"
	name string // the duplicated name
}

// validateDuplicateNamedBlockAST rejects (strict) or warns (lenient) when the
// candidate authors the SAME named hierarchical block twice inside a container
// whose compiler does whole-object last-writer-wins replacement — dropping the
// earlier block's config silently (#5180, consolidating codex-177 A3-b2-F3 +
// A3-b3-F1). Four containers are affected:
//
//   - groups { <name> { … } }  — expandGroups keeps only the last definition
//     (ast_groups.go: groups[name] = g).
//   - interfaces { <ifname> { … } } — compileInterfaces overwrites
//     Interfaces[ifName] (compiler_interfaces.go).
//   - security { screen { ids-option <name> { … } } } — compileScreen overwrites
//     Screen[profile.Name]; WITHIN one ids-option it also reads each
//     icmp/ip/tcp/udp/limit-session family with FindChild (first sibling only),
//     so a repeated family block is dropped too.
//   - system { login { user <name> { … } } } — compileSystemLogin folds a
//     duplicated name into ONE entry, per-leaf last-authored-wins (#6992), so
//     the earlier block's uid / class / keys disappear. Before that fold the
//     duplicate was WORSE than a drop: both blocks survived and two readers
//     picked different ones, so an SSH key authored under a VIEW-only block
//     could authenticate into a super-user CLI.
//
// This is a dual-AST-equivalence gate. Under flat `set` these statements MERGE:
// tree.SetPath collapses `set interfaces ge-0/0/0 …` written twice onto ONE
// node, so the flat shape never produces a duplicate sibling and compiles the
// union. The hierarchical shape, by contrast, produced two sibling nodes and
// silently dropped one — a fail-open divergence (an authored deny/enforcement
// block could vanish). Rejecting the hierarchical duplicate (or, on the
// tolerant path, warning that the earlier block was dropped) makes the two
// shapes agree on the invariant "no authored block silently disappears": the
// flat shape merges it in, the hierarchical shape is told to author it once.
//
// It runs PRE-expansion on the (inactive-pruned) clone alongside the tunnel /
// zone / routing-instance collision gates, and it walks ONLY the top-level
// `groups`/`interfaces`/`security` stanzas — never a group body — so a legitimate
// apply-groups inheritance (expandGroups deep-MERGES a group's interface/screen
// config into the target, producing no duplicate sibling) is not misreported.
// The `groups` check is inherently top-level. A quoted-empty group / interface /
// screen-ids-option name is recorded as an empty-name defect (#6455) rather than
// skipped. Strict on commit / commit-check; lenient on tolerant load / peer-sync
// (#1960 no-brick), where the runtime keeps the historical last-writer-wins result
// and boots.
//
// A duplicate authored ENTIRELY inside an applied group body is NOT caught here —
// this gate is pre-expansion by design; it is caught by
// validateDuplicateNamesExpandedAST (dup_names_expanded_6455.go, #6455
// Finding 1), which re-runs THIS function on a group-expanded clone.
func validateDuplicateNamedBlockAST(tree *ConfigTree, lenient bool) ([]string, error) {
	if tree == nil {
		return nil, nil
	}
	var dups []dupBlock
	var emptyKinds []string
	emptySeen := map[string]bool{}
	recordEmpty := func(kind string) {
		if !emptySeen[kind] {
			emptyKinds = append(emptyKinds, kind)
			emptySeen[kind] = true
		}
	}

	// 1. groups { <name> { … } } — mirror ast_groups.go name extraction; an empty
	// group name is an empty-name defect.
	seenGroup := map[string]bool{}
	reportedGroup := map[string]bool{}
	for _, child := range tree.Children {
		if child.Name() != "groups" {
			continue
		}
		for _, g := range child.Children {
			name := groupDefinitionName(g)
			if name == "" {
				if len(g.Keys) >= 1 {
					recordEmpty("group")
				}
				continue
			}
			if seenGroup[name] {
				if !reportedGroup[name] {
					dups = append(dups, dupBlock{"group", name})
					reportedGroup[name] = true
				}
			} else {
				seenGroup[name] = true
			}
		}
	}

	// 2. interfaces { <ifname> { … } } — mirror compileInterfaces (non-leaf
	// child keyed by Name(), skipping the non-interface container keywords).
	// Union across every top-level `interfaces` stanza so a name split across
	// two stanzas (also last-writer-wins in compileSections) is caught.
	seenIf := map[string]bool{}
	reportedIf := map[string]bool{}
	for _, child := range tree.Children {
		if child.Name() != "interfaces" {
			continue
		}
		for _, ifc := range child.Children {
			if ifc.IsLeaf {
				continue
			}
			name := ifc.Name()
			if name == "" {
				if len(ifc.Keys) >= 1 {
					recordEmpty("interface")
				}
				continue
			}
			if nonInterfaceIfKeyword[name] {
				continue
			}
			if seenIf[name] {
				if !reportedIf[name] {
					dups = append(dups, dupBlock{"interface", name})
					reportedIf[name] = true
				}
			} else {
				seenIf[name] = true
			}
		}
	}

	// 3. security { screen { ids-option <name> { … } } } — duplicate profile
	// names AND duplicate same-family blocks within one profile. Union across
	// every top-level `security` stanza and every `screen` block therein.
	seenProfile := map[string]bool{}
	reportedProfile := map[string]bool{}
	for _, child := range tree.Children {
		if child.Name() != "security" {
			continue
		}
		for _, screen := range child.FindChildren("screen") {
			for _, inst := range namedInstances(screen.FindChildren("ids-option")) {
				if inst.name == "" {
					recordEmpty("screen ids-option")
					continue
				}
				if seenProfile[inst.name] {
					if !reportedProfile[inst.name] {
						dups = append(dups, dupBlock{"screen ids-option", inst.name})
						reportedProfile[inst.name] = true
					}
				} else {
					seenProfile[inst.name] = true
				}
				// Duplicate family block WITHIN this ids-option instance.
				famSeen := map[string]bool{}
				famReported := map[string]bool{}
				for _, fam := range inst.node.Children {
					fn := fam.Name()
					if !screenIDSFamily[fn] {
						continue
					}
					if famSeen[fn] {
						if !famReported[fn] {
							dups = append(dups, dupBlock{
								kind: fmt.Sprintf("screen ids-option %q family", inst.name),
								name: fn,
							})
							famReported[fn] = true
						}
					} else {
						famSeen[fn] = true
					}
				}
			}
		}
	}

	// 4. system { login { user <name> { … } } } — #6992. compileSystemLogin
	// now folds a duplicated user name into ONE entry with per-leaf
	// last-authored-wins (compiler_system.go), matching what the FLAT spelling
	// already produces, so the container qualifies for this gate on the same
	// terms as the three above: the earlier block's uid / class / keys
	// disappear silently.
	//
	// Before that fold both blocks survived and two readers picked DIFFERENT
	// ones — pkg/cli configuredClass takes the first block with a non-empty
	// class, pkg/daemon applySystemLogin provisions from the last — so an SSH
	// key authored under a VIEW-only block could authenticate into a
	// super-user CLI. The fold removes the divergence; this gate is what stops
	// the operator being silently held to whichever block the merge kept.
	//
	// Union across every top-level `system` stanza and every `login` block
	// therein, matching the screen walk above.
	seenUser := map[string]bool{}
	reportedUser := map[string]bool{}
	for _, child := range tree.Children {
		if child.Name() != "system" {
			continue
		}
		for _, login := range child.FindChildren("login") {
			for _, inst := range namedInstances(login.FindChildren("user")) {
				if inst.name == "" {
					recordEmpty("login user")
					continue
				}
				if seenUser[inst.name] {
					if !reportedUser[inst.name] {
						dups = append(dups, dupBlock{"login user", inst.name})
						reportedUser[inst.name] = true
					}
				} else {
					seenUser[inst.name] = true
				}
			}
		}
	}

	if len(dups) == 0 && len(emptyKinds) == 0 {
		return nil, nil
	}
	// Deterministic order: kind, then name.
	sort.Slice(dups, func(i, j int) bool {
		if dups[i].kind != dups[j].kind {
			return dups[i].kind < dups[j].kind
		}
		return dups[i].name < dups[j].name
	})
	sort.Strings(emptyKinds)

	if !lenient {
		// Duplicates keep first-error priority so the pre-#6455 messages are
		// unchanged when no empty name is present.
		if len(dups) > 0 {
			d := dups[0]
			return nil, fmt.Errorf("duplicate %s %q: a repeated hierarchical block is "+
				"silently reduced to last-writer-wins, dropping the earlier block's "+
				"configuration — author it once (flat `set` merges repeated "+
				"statements automatically) (#5180)", d.kind, d.name)
		}
		return nil, emptyNameError(emptyKinds[0])
	}

	warnings := make([]string, 0, len(dups)+len(emptyKinds))
	for _, d := range dups {
		warnings = append(warnings, fmt.Sprintf("duplicate %s %q: only the LAST "+
			"hierarchical block is kept (earlier block dropped) — author it once "+
			"to avoid silently losing config (#5180)", d.kind, d.name))
	}
	for _, k := range emptyKinds {
		warnings = append(warnings, emptyNameWarning(k))
	}
	return warnings, nil
}

// groupDefinitionName extracts the group name from a group-definition node,
// mirroring the extraction in ConfigTree.expandGroups (ast_groups.go): the name
// is Keys[0], or Keys[1] when the node carries a merged two-key head.
func groupDefinitionName(g *Node) string {
	if len(g.Keys) < 1 {
		return ""
	}
	if len(g.Keys) > 1 {
		return g.Keys[1]
	}
	return g.Keys[0]
}
