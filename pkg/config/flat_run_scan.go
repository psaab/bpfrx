package config

// expandFlatRun returns a container's child statements with a flat-set chain
// expanded into one node per leaf, or the original slice when nothing moves.
//
// THE SHAPE, and it is not what it looks like at two leaves. A flat `set`
// command naming several leaves of one container is ONE command, and SetPath
// models only the FIRST link:
//
//	set security ike gateway gw1 address A external-interface E local-address L
//
//	[gateway gw1]
//	  [address A]
//	    [external-interface E local-address L]     <- ONE node, a FLAT RUN
//
// At TWO leaves the remainder is a single keyword/value pair, so the chain is
// indistinguishable from ordinary nesting and a recursive descent appears to
// work. At THREE it packs onto one node's Keys, and a descent reads
// `external-interface` and silently drops `local-address`. So the expansion
// must be a KEYWORD-DELIMITED SCAN of each node's Keys, not a walk of Children
// — the same scan parseApplicationTerms performs, and the reason #6524's fix
// took that form.
//
// A leaf that is not a node's own first token is re-emitted as a synthesized
// `keyword value` node, so every caller sees the uniform shape it already
// iterates.
//
// GATED ON THE SCHEMA. A token is only treated as a new leaf when the container
// declares it; anything else stays with the leaf it follows, so a multi-token
// value is not chopped into keywords that happen to collide. A leaf that
// DECLARES CHILDREN keeps its subtree — its body belongs to it, and hoisting
// that would turn a nested block into sibling statements of the container.
//
// WHY EXPAND RATHER THAN REJECT. The chain is a SUPPORTED spelling —
// `set applications application a1 protocol tcp destination-port 80` is tested
// behaviour — and #6524 recorded why teaching the schema to refuse it is wrong:
// a schema-only reject leaves the LENIENT path (boot load, HA SyncApply)
// untouched, which is exactly where already-stored configs are.
func expandFlatRun(children []*Node, container *schemaNode) []*Node {
	if container == nil || len(children) == 0 {
		return children
	}
	var out []*Node
	changed := false

	var visit func(n *Node)
	visit = func(n *Node) {
		if n == nil || len(n.Keys) == 0 {
			return
		}
		leaf := resolveSchemaChild(container, n.Keys[0])
		// Not a leaf of this container, or one that owns a body: leave it and
		// its subtree exactly as authored.
		if leaf == nil || len(leaf.children) > 0 || leaf.wildcard != nil {
			out = append(out, n)
			return
		}
		// Split this node's Keys at every token the container declares as
		// another leaf. The first keyword keeps the node; each later one
		// becomes a synthesized sibling.
		cut := []int{0}
		for i := 1; i < len(n.Keys); i++ {
			if sib := resolveSchemaChild(container, n.Keys[i]); sib != nil {
				cut = append(cut, i)
			}
		}
		if len(cut) > 1 {
			changed = true
		}
		for c, start := range cut {
			end := len(n.Keys)
			if c+1 < len(cut) {
				end = cut[c+1]
			}
			seg := &Node{
				Keys:       append([]string(nil), n.Keys[start:end]...),
				IsLeaf:     true,
				Annotation: n.Annotation,
				Inactive:   n.Inactive,
				Line:       n.Line,
				Column:     n.Column,
			}
			if n.KeysQuoted != nil && end <= len(n.KeysQuoted) {
				seg.KeysQuoted = append([]bool(nil), n.KeysQuoted[start:end]...)
			}
			out = append(out, seg)
		}
		// Anything nested under a terminating leaf is the next link of the
		// chain, never that leaf's body — it declares no children.
		for _, c := range n.Children {
			changed = true
			visit(c)
		}
	}
	for _, c := range children {
		visit(c)
	}
	if !changed {
		return children
	}
	return out
}
