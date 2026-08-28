package config

// compiler_nat_then_occurrences_7013.go — #7013.
//
// `NATThen.PoolName` is a scalar, so ONE `then` block that names two pools —
//
//	then destination-nat pool PD pool PD2
//	then destination-nat { pool PD; pool PD2; }
//
// — lowers to a single pool and the other is gone before any validation runs.
// validateNATTerminalActionCardinalityStrict counts MODES (`n == 1` here), so it
// does not fire and the config commits under STRICT with an operator-authored
// action silently discarded. This records what one block AUTHORED, alongside the
// resolved NATThen, so the gate can reject on occurrences instead of modes. It
// is #7013's option 1: the resolved type keeps its shape and the dataplane
// contract is untouched.
//
// SCOPE IS ONE `then` CONTAINER, and that is the whole of the correctness
// argument for not breaking #3850. Two duplicate `then` containers are ALREADY
// decided: they are last-container-wins and legal, pinned by
// TestNATTerminalActionDupIdentical3850_5628 (same pool twice) and by the
// interface-then-poolB case beside it (different actions, last wins). Summing
// across containers false-rejects both. What #7013 describes is narrower — one
// block naming the mode twice — and that is the only shape counted here.
//
// WHICH SPELLINGS ARE ACTUALLY THIS DEFECT, measured at this head rather than
// taken from the issue, because the issue is wrong about one of them:
//
//   - `then destination-nat pool PD pool PD2` (one packed run) — the tree
//     carries both, the compiler keeps PD, PD2 vanishes. THE DEFECT.
//   - `then { destination-nat { pool PD; pool PD2; } }` (hierarchical braces,
//     the spelling in #7013's acceptance criterion) — the tree carries both,
//     the compiler keeps PD. THE DEFECT.
//   - two separate `set ... then destination-nat pool X` lines — NOT the
//     defect. The second REPLACES the leaf in the candidate tree, which is how
//     a single-value leaf is supposed to behave; only `pool PD2` ever reaches
//     the compiler, `show configuration` displays it, and nothing is hidden.
//     Rejecting it would break the ordinary way an operator edits a pool.
//
// So the survivor is the FIRST wherever the collapse actually happens — the
// issue body's "last wins" was describing leaf replacement, a different
// mechanism at a different layer. The tests still assert REJECTION rather than
// the survivor: rejection is the acceptance criterion, and a fixture built on
// the survivor reds against a correct compiler and a buggy one alike, for
// opposite reasons, which invites "fixing" the assertion.
//
// ONLY POOLS ARE RECORDED. `off` and `interface` carry no value, so writing
// either twice discards nothing — the config means what it says and there is
// nothing to report. Counting them would reject an idempotent typo. A rule
// mixing DIFFERENT modes is still caught, by the mode count that follows this
// check.

// natThenAuthored is what ONE `then` container authored, before NATThen's
// scalar collapsed it.
type natThenAuthored struct {
	// Pools is every authored pool NAME in encounter order, so the diagnostic
	// can name the discarded one rather than only the survivor.
	Pools []string
}

// distinctPools returns the authored pool names with repeats removed, in
// encounter order.
//
// DISTINCT, not raw: `pool p1 pool p1` discards nothing — both spellings mean
// p1 — and rejecting it would be a diagnostic about a redundancy rather than
// about a lost action. Two DIFFERENT names is the case where the configuration
// as written and the configuration as enforced disagree.
func (a natThenAuthored) distinctPools() []string {
	if len(a.Pools) < 2 {
		return a.Pools
	}
	seen := make(map[string]struct{}, len(a.Pools))
	out := make([]string, 0, len(a.Pools))
	for _, p := range a.Pools {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

// natThenAuthoredOccurrences records every pool of `kind` that thenNode
// authored.
//
// THREE SHAPES, and all three have to be walked here or the gate is blind to
// one spelling of the same defect:
//
//  1. PACKED ONTO THE `then` NODE ITSELF — `then source-nat pool P` arrives as
//     Keys on the `then` node (the #7014 shape, applyPackedNATThenTokens7014).
//  2. PACKED ONTO THE KIND CHILD — `then { source-nat pool P pool Q; }` arrives
//     as Keys on the `source-nat` child, and a repeated value collapses onto
//     that one leaf's Keys (#2419) rather than producing two nodes.
//  3. HIERARCHICAL — `then { source-nat { pool P; pool Q; } }` arrives as
//     children of the `source-nat` child, one node each.
func natThenAuthoredOccurrences(thenNode *Node, kind string) natThenAuthored {
	var a natThenAuthored
	if thenNode == nil {
		return a
	}
	// Shape 1: `then <kind> <action> ...` — the kind sits at Keys[1].
	if len(thenNode.Keys) > 1 && thenNode.Keys[1] == kind {
		a.scanKeys(thenNode.Keys, 2)
	}
	for _, t := range thenNode.Children {
		if t == nil || t.Name() != kind {
			continue
		}
		// Shape 2: the run continues on the kind child, after Keys[0].
		a.scanKeys(t.Keys, 1)
		// Shape 3: one node per action below the kind node.
		for _, c := range t.Children {
			if c == nil || c.Name() != "pool" {
				continue
			}
			a.addPoolNode(c)
		}
	}
	return a
}

// scanKeys records each `pool <name>` pair in a flat token run from index from.
//
// A trailing bare `pool` is malformed rather than a second authored pool: other
// gates report it, and counting it here would answer a syntax error with a
// duplicate-pool message.
func (a *natThenAuthored) scanKeys(keys []string, from int) {
	for i := from; i < len(keys); i++ {
		if keys[i] == "pool" && i+1 < len(keys) {
			a.Pools = append(a.Pools, keys[i+1])
			i++
		}
	}
}

// addPoolNode records the pool(s) a `pool` NODE authored.
//
// The name may sit on the node (`pool P;` → Keys=["pool","P"]) or below it
// (`pool { P; }` → one child), and the second shape is the one the hierarchical
// fixtures in dual_ast_differential_test.go actually use.
//
// EXACTLY ONE NAME COMES FROM THE CHILDREN, taken from the FIRST child, because
// that is what nodeVal does and therefore what the compiler resolves. Counting
// every child would count Junos's `pool { P; persistent-nat { ... } }` as two
// authored pools and reject a valid config. Whatever the compiler treats as the
// name is what this has to treat as the occurrence, or the record describes a
// config the compiler never saw.
//
// A REPEAT MAY ARRIVE NESTED, not as a sibling: the flat-set path for
// `then source-nat pool PS pool PS2` builds `pool PS` with `pool PS2` as its
// CHILD, because the second `pool` token opens a further path rather than
// extending the leaf. So the walk descends — but only into children NAMED
// `pool`, which is what keeps the descent from swallowing `persistent-nat` and
// the pool-name node itself.
func (a *natThenAuthored) addPoolNode(c *Node) {
	if len(c.Keys) > 1 {
		// Repeats can also collapse onto this leaf's Keys (#2419), so scan the
		// whole run rather than reading Keys[1].
		a.scanKeys(c.Keys, 0)
	} else if name := nodeVal(c); name != "" {
		a.Pools = append(a.Pools, name)
	}
	for _, g := range c.Children {
		if g != nil && g.Name() == "pool" {
			a.addPoolNode(g)
		}
	}
}
