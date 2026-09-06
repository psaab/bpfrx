package config

// #8992: a FULLY ELIDED stanza cannot be deleted, and the error names the
// wrong thing.
//
//	system master-password ascii-text "x";
//	  -> ONE node, Keys = [system master-password ascii-text x]
//
//	delete system master-password
//	  -> path not found: container "system" does not exist
//
// `deletePath` descends by looking for a CONTAINER whose Keys equal the path
// segment. In the elided spelling `system` is not a container at all -- it is
// the first token of a leaf node carrying the whole statement -- so the
// descent finds nothing and reports that the container is absent while `show
// configuration` renders `system master-password ...` on screen. The operator's
// next move is to re-check the spelling of `master-password`, which is the
// wrong place.
//
// Measured scope, both controls held: the fully-braced and the CHILD-elided
// spellings (`system { master-password ascii-text "x"; }`) already delete
// correctly, and a genuinely absent stanza gives a DIFFERENT message
// (`no node matching "master-password"`), so this is not the generic
// not-found path. Only the fully-elided form fails.
//
// THE BOUND MATTERS MORE THAN THE FIX HERE, because this is the delete path
// and over-deleting is worse than the defect. A node's Keys may carry a packed
// RUN of several statements:
//
//	system master-password ascii-text "x" host-name fw1;
//
// Removing the whole node to satisfy `delete system master-password` would
// silently take `host-name` with it -- a config-integrity fail-wide of exactly
// the #3846 shape. So the node is removed ONLY when its Keys encode exactly
// one complete statement. A packed run carrying more is refused with a message
// that names the real situation; splitting one is `consumeNodeKeys` work that
// #8932 records as unfinished, and guessing at it here would be the
// half-a-remedy this campaign keeps finding.

// elidedNodeIsExactlyOneStatement reports whether n's Keys, walked against the
// schema from root, consume to exactly one complete statement -- i.e. every
// key belongs to the single path the node encodes, with nothing left over.
//
// Returns false for a node carrying a packed run of two or more statements,
// which is the case that must NOT be whole-node deleted.
func elidedNodeIsExactlyOneStatement(n *Node, root *schemaNode) bool {
	if n == nil || root == nil || len(n.Keys) == 0 {
		return false
	}
	cur := root
	i := 0
	for i < len(n.Keys) {
		child := resolveSchemaChild(cur, n.Keys[i])
		if child == nil {
			// An unmodelled token. It may be a VALUE of the leaf we are
			// standing on, which is fine, or an unknown keyword, which we
			// cannot adjudicate. Either way it is not a second statement we
			// can prove, so stop and accept only if we have consumed
			// everything.
			return false
		}
		i++
		i += child.args
		if i > len(n.Keys) {
			return false // declared arity ran past the keys: not a clean parse
		}
		if child.compoundKey && i < len(n.Keys) {
			if sub := resolveSchemaChild(child, n.Keys[i]); sub != nil {
				i++
				child = sub
			}
		}
		if i == len(n.Keys) {
			return true // consumed exactly, one statement
		}
		// More keys remain. If the NEXT token is a leaf of the node we just
		// consumed, we are descending one statement. If it is a sibling of the
		// CURRENT level, this node carries a packed run -- refuse.
		if resolveSchemaChild(child, n.Keys[i]) == nil {
			return false
		}
		cur = child
	}
	return false
}

// findElidedNodeForPath returns the index in nodes of a node whose Keys begin
// with path and which encodes exactly one statement, or -1.
func findElidedNodeForPath(nodes []*Node, path []string, root *schemaNode) int {
	for idx, n := range nodes {
		// #8997: `<` not `<=`. A BARE FLAG elides to a node whose Keys are
		// exactly the path -- `chassis cluster strict-session-auth;` against
		// path [chassis cluster strict-session-auth] -- so requiring the Keys
		// to be strictly LONGER excluded every valueless leaf. #8992 was
		// written against a VALUED leaf, where the value makes Keys longer, so
		// the bound was invisible: correct for every case that existed and
		// wrong for the class next to it.
		if n == nil || len(n.Keys) < len(path) {
			continue
		}
		match := true
		for j, seg := range path {
			if n.Keys[j] != seg {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		if elidedNodeIsExactlyOneStatement(n, root) {
			return idx
		}
	}
	return -1
}

// elidedPathIsMultiLeafValues reports whether path, resolved from root, lands
// on a MULTI leaf -- in which case a node carrying extra trailing keys is a
// value LIST, not a packed run of statements.
//
// #8997: THESE TWO SHAPES ARE INDISTINGUISHABLE BY KEY COUNT AND HAVE OPPOSITE
// CORRECT ANSWERS.
//
//	protocol tcp udp icmp                 ONE statement, a multi leaf whose
//	                                      trailing tokens are VALUES (#2419).
//	                                      Deleting the `tcp` member is legal and
//	                                      #3846/#3872 own it.
//	cluster strict-session-auth foo       TWO statements packed onto one node by
//	                                      the flat-set chain. Deleting one would
//	                                      silently take the other (#3846's
//	                                      fail-wide), so it must be refused.
//
// #8992 ran its check only at the TOP level, where no multi leaf lives, so the
// ambiguity never arose and nothing recorded that it existed. Extending the
// check to every level surfaced it as four red cells that were asserting a
// PRIOR DECISION, not a stale expectation.
func elidedPathIsMultiLeafValues(path []string, root *schemaNode) bool {
	if root == nil || len(path) == 0 {
		return false
	}
	cur := root
	for i := 0; i < len(path); i++ {
		child := resolveSchemaChild(cur, path[i])
		if child == nil {
			return false
		}
		if child.multi {
			return true
		}
		i += child.args
		cur = child
	}
	return false
}

// elidedPackedRunCarrying reports the full Keys of a node that BEGINS with
// path but carries a packed run of more than one statement, or nil.
//
// Split out so the refusal can say what is actually happening. Falling through
// to the generic "container %q does not exist" would be the #9006 shape: a true
// statement about the walk that is false about the tree, sending the operator
// to re-check a spelling that is correct and visible in `show configuration`.
func elidedPackedRunCarrying(nodes []*Node, path []string, root *schemaNode) []string {
	for _, n := range nodes {
		// #8997: `<` not `<=`. A BARE FLAG elides to a node whose Keys are
		// exactly the path -- `chassis cluster strict-session-auth;` against
		// path [chassis cluster strict-session-auth] -- so requiring the Keys
		// to be strictly LONGER excluded every valueless leaf. #8992 was
		// written against a VALUED leaf, where the value makes Keys longer, so
		// the bound was invisible: correct for every case that existed and
		// wrong for the class next to it.
		if n == nil || len(n.Keys) < len(path) {
			continue
		}
		match := true
		for j, seg := range path {
			if n.Keys[j] != seg {
				match = false
				break
			}
		}
		if match && !elidedNodeIsExactlyOneStatement(n, root) {
			// #8997: a multi leaf's trailing keys are VALUES, not a second
			// statement. Claiming them here would refuse every legal
			// member-delete (#3846 `protocol tcp`, #3872 `next-hop <ip>`).
			if elidedPathIsMultiLeafValues(path, root) {
				continue
			}
			return n.Keys
		}
	}
	return nil
}
