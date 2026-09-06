package config

import "strings"

// #8752: fold a repeated named-instance statement into the FIRST occurrence, on
// the TOLERANT compile path.
//
// THE DEFECT. `security policies from-zone <a> to-zone <b> { policy p1 { … }
// policy p1 <leaf> <v>; }` compiles to TWO policies named p1 on the lenient
// path: the operator's, and a spurious one carrying only the second statement.
// The spurious one has no match criteria, so it contributes a match-less deny,
// and the operator's policy never receives the leaf. Measured on the path that
// production uses for `Store.Load` and `Store.SyncApply` — boot-time config load
// and HA config sync.
//
// WHY THIS PATH AND NOT THE STRICT ONE. The #3473 gate hard-rejects a duplicate
// policy name at commit, and it should keep doing so: its message tells the
// operator to rename, because a duplicate shares a name-keyed hit counter. That
// diagnostic is worth keeping, and merging before it would silently destroy it.
// The tolerant path cannot reject — it exists to boot a config that is already
// on disk (#1960 no-brick) — so its only choices are to split (today) or to
// merge.
//
// AND THE TOLERANT PATH'S OWN CLAIM IS WHAT MAKES MERGING THE RIGHT ONE. The
// #3473 gate documents its lenient behaviour as "first-match enforcement is
// still correct, only the shared-counter observability bug remains". Measured,
// that is FALSE today: the operator's policy loses the second statement's
// content and gains a match-less-deny sibling, which is a change to what is
// permitted, not an observability gap. Merging makes the comment true.
//
// WHY MERGE RATHER THAN REPLACE, and it is not a preference. Flat `set` already
// MERGES — pinned by TestFlatSetMergesWhereHierarchicalDuplicates — so the two
// spellings of one configuration disagree, and hierarchical is the deviant one.
// Replacing would mean choosing to keep them disagreeing and then owning a rule
// about which spelling a user must write to mean what they meant.
//
// WHY IN PLACE. The compiled collections that duplicate are SLICES
// (`Policies []*Policy`) and the ones that merge are MAPS. They are slices
// because ORDER IS SEMANTIC — policy evaluation is first-match — so folding into
// anything but the first occurrence's position would trade a visible duplicate
// for an invisible reordering. A duplicate shows up as two objects; a reordered
// first-match rulebase evaluates differently with nothing to see.
//
// SCOPE IS A PAIR LIST, not a shape. Only the two containers measured on BOTH
// paths are folded. `security nat source rule-set <r>` duplicates too, but its
// lenient/strict pair has not been measured, and admitting a container on the
// strength of "it has the same shape" is the family-level reasoning #8690 spent
// a day removing.
func mergeDuplicateNamedInstances(tree *ConfigTree) []string {
	if tree == nil {
		return nil
	}
	var merged []string
	for _, root := range tree.Children {
		if root.Name() != "security" && (len(root.Keys) == 0 || root.Keys[0] != "security") {
			continue
		}
		for _, pol := range root.FindChildren("policies") {
			// from-zone <a> to-zone <b> { policy … }
			for _, fz := range pol.FindChildren("from-zone") {
				merged = append(merged, mergeInstancesUnder(fz, "policy")...)
				for _, tz := range fz.Children {
					merged = append(merged, mergeInstancesUnder(tz, "policy")...)
				}
			}
			// global { policy … }
			for _, g := range pol.FindChildren("global") {
				merged = append(merged, mergeInstancesUnder(g, "policy")...)
			}
		}
	}
	return merged
}

// mergeInstancesUnder folds repeated `<keyword> <name>` children of `parent`
// into the first one carrying that name, and returns how many were folded.
//
// The later statement's content can live in EITHER place and both are carried:
// its Children (the braced form) and any packed tail on its own Keys (the
// brace-elided form, `policy p1 scheduler-name S;`). Carrying only Children
// would silently drop exactly the spelling this issue is about.
func mergeInstancesUnder(parent *Node, keyword string) []string {
	if parent == nil {
		return nil
	}
	var names []string
	first := map[string]*Node{}
	var kept []*Node
	for _, child := range parent.Children {
		if len(child.Keys) < 2 || child.Keys[0] != keyword {
			kept = append(kept, child)
			continue
		}
		name := child.Keys[1]
		prev, seen := first[name]
		if !seen {
			first[name] = child
			kept = append(kept, child)
			continue
		}
		// Fold into the FIRST occurrence, which keeps its position in `kept`.
		if tail := child.Keys[2:]; len(tail) > 0 {
			prev.Children = append(prev.Children, &Node{
				Keys:   append([]string(nil), tail...),
				IsLeaf: true,
			})
		}
		prev.Children = append(prev.Children, child.Children...)
		prev.IsLeaf = false
		// Issue 9209: FOLD THE UNNAMED CONTAINERS TOO. Appending the second
		// block's children leaves the merged node carrying two `if-exceeding`
		// blocks, and the compiler reads the first -- so
		//
		//	policer p1 { if-exceeding { bandwidth-limit 1000000; } }
		//	policer p1 { if-exceeding { burst-size-limit 15000; } }
		//
		// folded to bw=125000 burst=0, recovering the bandwidth-limit that was
		// lost before and losing the burst-size-limit instead. Within ONE named
		// block two identical container heads are the same stanza, so they are
		// merged as well. Scoped to the folded node: this runs only where a
		// duplicate was actually collapsed, never across a config that had no
		// repeats.
		mergeSiblingContainers9209(prev, 0)
		names = append(names, keyword+" "+name)
	}
	if len(names) > 0 {
		parent.Children = kept
	}
	return names
}

// mergeSiblingContainers9209 folds sibling CONTAINERS that share identical Keys
// into the first of them, recursively.
//
// Issue 9209. It runs only on a node that mergeInstancesUnder has just folded a
// duplicate into, so it cannot change a config that contained no repeated block.
//
// LEAVES ARE LEFT ALONE, deliberately. Two leaves with the same key are a
// value-level question -- replace, accumulate, or reject -- already answered
// per leaf by `multi` and by the compilers, and re-answering it here would
// override those decisions from a layer that cannot see them. Only containers,
// where "the same stanza written twice" has one Junos meaning, are merged.
func mergeSiblingContainers9209(n *Node, depth int) {
	if n == nil || depth > 8 || len(n.Children) < 2 {
		return
	}
	first := map[string]*Node{}
	var kept []*Node
	changed := false
	for _, ch := range n.Children {
		if ch == nil {
			continue
		}
		if ch.IsLeaf || ch.Children == nil {
			kept = append(kept, ch)
			continue
		}
		key := strings.Join(ch.Keys, "\x00")
		prev, seen := first[key]
		if !seen {
			first[key] = ch
			kept = append(kept, ch)
			continue
		}
		prev.Children = append(prev.Children, ch.Children...)
		changed = true
	}
	if changed {
		n.Children = kept
	}
	for _, ch := range n.Children {
		mergeSiblingContainers9209(ch, depth+1)
	}
}
