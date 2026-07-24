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
	kind     string // human category, e.g. "interface" / "screen ids-option"
	name     string // the duplicated name
	groupCtx string // "" for a top-level duplicate, else the enclosing group name
}

// validateDuplicateNamedBlockAST rejects (strict) or warns (lenient) when the
// candidate authors the SAME named hierarchical block twice inside a container
// whose compiler does whole-object last-writer-wins replacement — dropping the
// earlier block's config silently (#5180, consolidating codex-177 A3-b2-F3 +
// A3-b3-F1). Three containers are affected:
//
//   - groups { <name> { … } }  — expandGroups keeps only the last definition
//     (ast_groups.go: groups[name] = g).
//   - interfaces { <ifname> { … } } — compileInterfaces overwrites
//     Interfaces[ifName] (compiler_interfaces.go).
//   - security { screen { ids-option <name> { … } } } — compileScreen overwrites
//     Screen[profile.Name]; WITHIN one ids-option it also reads each
//     icmp/ip/tcp/udp/limit-session family with FindChild (first sibling only),
//     so a repeated family block is dropped too.
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
// zone / routing-instance collision gates. The `interfaces` and `screen
// ids-option` checks scan BOTH the top-level stanzas AND each defined group body
// as a SEPARATE namespace (scanNamespaces, #6455): a legitimate apply-groups
// inheritance (expandGroups deep-MERGES a group's block into a same-named inline
// peer) produces no duplicate sibling and is not misreported — the fresh
// per-namespace seen-set never cross-counts a group block against its inline peer
// — while a duplicate authored ENTIRELY inside a group body (no inline peer, so
// expandGroups appends the parent container wholesale) IS caught. The `groups`
// name check is inherently top-level (Junos has no nested group definitions). A
// quoted-empty group / interface / screen-ids-option name is recorded as an
// emptyName6455 defect (#6455) rather than skipped. Strict on commit /
// commit-check; lenient on tolerant load / peer-sync (#1960 no-brick), where the
// runtime keeps the historical last-writer-wins result and boots.
func validateDuplicateNamedBlockAST(tree *ConfigTree, lenient bool) ([]string, error) {
	if tree == nil {
		return nil, nil
	}
	var dups []dupBlock
	var empties []emptyName6455

	// 1. groups { <name> { … } } — top-level only (Junos has no nested group
	// definitions). Mirror ast_groups.go name extraction; an empty group name is
	// an emptyName6455 defect.
	seenGroup := map[string]bool{}
	reportedGroup := map[string]bool{}
	emptyGroupReported := false
	for _, child := range tree.Children {
		if child.Name() != "groups" {
			continue
		}
		for _, g := range child.Children {
			name := groupDefinitionName(g)
			if name == "" {
				if len(g.Keys) >= 1 && !emptyGroupReported {
					empties = append(empties, emptyName6455{"group", ""})
					emptyGroupReported = true
				}
				continue
			}
			if seenGroup[name] {
				if !reportedGroup[name] {
					dups = append(dups, dupBlock{"group", name, ""})
					reportedGroup[name] = true
				}
			} else {
				seenGroup[name] = true
			}
		}
	}

	// 2 + 3. interfaces { <ifname> { … } } and security { screen { ids-option
	// <name> { … } } } — scanned in the top-level stanzas AND each group body as a
	// separate namespace (#6455). Each namespace gets a fresh seen-set so a
	// group-vs-inline deep-merge is not cross-counted, but a duplicate authored
	// entirely inside a group body is caught.
	scanNamespaces(tree, func(stanzas []*Node, groupCtx string) {
		// 2. interfaces — mirror compileInterfaces (non-leaf child keyed by
		// Name(), skipping the non-interface container keywords). Union across
		// every `interfaces` stanza in this namespace so a name split across two
		// stanzas (also last-writer-wins in compileSections) is caught.
		seenIf := map[string]bool{}
		reportedIf := map[string]bool{}
		emptyIfReported := false
		for _, child := range stanzas {
			if child.Name() != "interfaces" {
				continue
			}
			for _, ifc := range child.Children {
				if ifc.IsLeaf {
					continue
				}
				name := ifc.Name()
				if name == "" {
					if len(ifc.Keys) >= 1 && !emptyIfReported {
						empties = append(empties, emptyName6455{"interface", groupCtx})
						emptyIfReported = true
					}
					continue
				}
				if nonInterfaceIfKeyword[name] {
					continue
				}
				if seenIf[name] {
					if !reportedIf[name] {
						dups = append(dups, dupBlock{"interface", name, groupCtx})
						reportedIf[name] = true
					}
				} else {
					seenIf[name] = true
				}
			}
		}

		// 3. security screen ids-option — duplicate profile names AND duplicate
		// same-family blocks within one profile. Union across every `security`
		// stanza and every `screen` block therein in this namespace.
		seenProfile := map[string]bool{}
		reportedProfile := map[string]bool{}
		emptyProfileReported := false
		for _, child := range stanzas {
			if child.Name() != "security" {
				continue
			}
			for _, screen := range child.FindChildren("screen") {
				for _, inst := range namedInstances(screen.FindChildren("ids-option")) {
					if inst.name == "" {
						if !emptyProfileReported {
							empties = append(empties, emptyName6455{"screen ids-option", groupCtx})
							emptyProfileReported = true
						}
						continue
					}
					if seenProfile[inst.name] {
						if !reportedProfile[inst.name] {
							dups = append(dups, dupBlock{"screen ids-option", inst.name, groupCtx})
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
									kind:     fmt.Sprintf("screen ids-option %q family", inst.name),
									name:     fn,
									groupCtx: groupCtx,
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
	})

	if len(dups) == 0 && len(empties) == 0 {
		return nil, nil
	}
	// Deterministic order: kind, then name, then group context.
	sort.Slice(dups, func(i, j int) bool {
		if dups[i].kind != dups[j].kind {
			return dups[i].kind < dups[j].kind
		}
		if dups[i].name != dups[j].name {
			return dups[i].name < dups[j].name
		}
		return dups[i].groupCtx < dups[j].groupCtx
	})
	sortEmptyNames(empties)

	if !lenient {
		// Duplicates keep first-error priority so the pre-#6455 messages are
		// unchanged when no empty name is present.
		if len(dups) > 0 {
			d := dups[0]
			return nil, fmt.Errorf("duplicate %s %q%s: a repeated hierarchical block is "+
				"silently reduced to last-writer-wins, dropping the earlier block's "+
				"configuration — author it once (flat `set` merges repeated "+
				"statements automatically) (#5180)", d.kind, d.name, groupCtxSuffix(d.groupCtx))
		}
		return nil, emptyNameError(empties[0])
	}

	warnings := make([]string, 0, len(dups)+len(empties))
	for _, d := range dups {
		warnings = append(warnings, fmt.Sprintf("duplicate %s %q%s: only the LAST "+
			"hierarchical block is kept (earlier block dropped) — author it once "+
			"to avoid silently losing config (#5180)", d.kind, d.name, groupCtxSuffix(d.groupCtx)))
	}
	for _, e := range empties {
		warnings = append(warnings, emptyNameWarning(e))
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
