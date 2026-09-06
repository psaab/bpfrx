package config

// hoistAndSplitRun8939 flattens a packed flat-set run under container: it lifts
// a statement nested INSIDE another statement back to sibling position, and
// splits a node whose Keys carry several statements.
//
// #8939 needs BOTH operations, and which one a site needs depends on the shape
// SetPath happened to build:
//
//	set … test T target address 10.0.0.1 probe-type icmp-ping
//	  [test T] > [target] > [address 10.0.0.1] > [probe-type icmp-ping]
//	                                              ^ NESTED, not a sibling
//
//	set … then count c1 log discard
//	  [then] > [count c1] > [log discard]
//	                         ^ nested AND packed: two statements on one node
//
// expandFlatRun alone splits the second case and cannot see the first, because
// the trailing statement is not on the container's own children at all — it is
// several levels down, hanging off whichever leaf the run started at.
// flattenThenChain8939 solved this once for the filter `then` clause; this is
// the same operation with the container passed in, so the next site does not
// need a third copy.
//
// THE BOUND IS THE SAME ONE flattenThenChain8939 STATES. A node is only hoisted
// when its own head RESOLVES as a leaf of the container — that is what
// distinguishes "a second statement got nested here" from "these are this
// leaf's VALUES", and reading it wrong turns a value list into a statement
// (#2419). A leaf that owns a body, a wildcard, or a multi leaf is left exactly
// as authored.
func hoistAndSplitRun8939(children []*Node, container *schemaNode) []*Node {
	if container == nil || len(children) == 0 {
		return children
	}
	var out []*Node
	changed := false

	var visit func(n *Node)
	visit = func(n *Node) {
		if n == nil || len(n.Keys) == 0 {
			out = append(out, n)
			return
		}
		leaf := resolveSchemaChild(container, n.Keys[0])
		if leaf == nil || leaf.multi {
			// Not a leaf of THIS container, or a multi leaf that owns
			// everything after it (#2419): leave it exactly as authored.
			out = append(out, n)
			return
		}
		if len(leaf.children) > 0 || leaf.wildcard != nil {
			// A leaf that legitimately owns a BODY -- `target { address X; }`.
			// Its own children are its business, but a run can still be nested
			// UNDER it, several levels down:
			//
			//	[test T] > [target] > [address 10.0.0.1] > [probe-type icmp-ping]
			//	                                            ^ a leaf of TEST,
			//	                                              not of TARGET
			//
			// So descend and lift out only descendants whose head resolves as a
			// leaf of the ORIGINAL container. That predicate is what keeps this
			// safe: `address` resolves under TARGET and stays put, while
			// `probe-type` resolves under TEST and is hoisted to where the
			// compiler looks for it.
			kept, lifted := splitNestedForeignRun8939(n, container)
			out = append(out, kept)
			if len(lifted) > 0 {
				changed = true
				for _, l := range lifted {
					visit(l)
				}
			}
			return
		}
		if len(n.Children) == 0 {
			out = append(out, n)
			return
		}
		// A leaf of this container carrying children: the children are a run
		// that got nested under it. Keep the head, hoist the rest.
		changed = true
		head := &Node{
			Keys:       append([]string(nil), n.Keys...),
			IsLeaf:     true,
			Annotation: n.Annotation,
			Inactive:   n.Inactive,
			Line:       n.Line,
			Column:     n.Column,
		}
		if n.KeysQuoted != nil {
			head.KeysQuoted = append([]bool(nil), n.KeysQuoted...)
		}
		out = append(out, head)
		for _, c := range n.Children {
			visit(c)
		}
	}
	for _, c := range children {
		visit(c)
	}
	if !changed {
		// Still split: one node can carry a packed run with nothing nested.
		return expandFlatRun(children, container)
	}
	return expandFlatRun(out, container)
}

// splitNestedForeignRun8939 removes, from n's subtree, every node whose head
// resolves as a leaf of `container` rather than of n's own body, and returns
// the pruned node plus the lifted ones.
//
// #8939: this is the half hoistAndSplitRun8939's bound cannot do on its own. A
// leaf that owns a body is left alone by that bound -- correctly, its children
// are its own -- but SetPath will still nest a LATER statement underneath it,
// and that statement belongs to the enclosing container.
func splitNestedForeignRun8939(n *Node, container *schemaNode) (*Node, []*Node) {
	if n == nil {
		return n, nil
	}
	var lifted []*Node
	var prune func(node *Node, depth int) *Node
	prune = func(node *Node, depth int) *Node {
		if node == nil || depth > 8 {
			return node
		}
		var kept []*Node
		for _, c := range node.Children {
			if c == nil || len(c.Keys) == 0 {
				continue
			}
			if resolveSchemaChild(container, c.Keys[0]) != nil {
				// Belongs to the ENCLOSING container: lift it out whole.
				lifted = append(lifted, c)
				continue
			}
			kept = append(kept, prune(c, depth+1))
		}
		if len(kept) == len(node.Children) {
			return node
		}
		clone := *node
		clone.Children = kept
		return &clone
	}
	pruned := prune(n, 0)
	return pruned, lifted
}
