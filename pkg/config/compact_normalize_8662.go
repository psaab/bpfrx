package config

// Brace-elided ("compact") statement normalization — #8662, first increment of
// the #2419 normalizer.
//
// Junos accepts a stanza's body without braces:
//
//	match { source-address a1; }     the braced form
//	match source-address a1;         the same statement, braces elided
//
// The parser represents them differently. Braced gives a container node with a
// child; elided packs the whole tail onto the container's own Keys:
//
//	BLOCK    Keys=[match]                   children=[ Keys=[source-address a1] ]
//	COMPACT  Keys=[match source-address a1] children=[]
//
// A compiler stanza that reads only `prop.Children` — which most do — therefore
// sees nothing in the elided form, and the statement is silently dropped on a
// commit that reports success. `pkg/config/testdata/compact_block_divergences_2419.txt`
// is the measured inventory of that: 433 sites, of which 414 compile the elided
// spelling to a config identical to an EMPTY stanza.
//
// This pass rewrites the packed form into the braced form so both spellings
// compile identically. It is deliberately SCOPED for this increment (see
// compactNormalizeInScope) rather than applied to all 433: the full sweep is
// the #2419 normalizer proper, whose stated goal in
// compact_block_inventory_regen_2419_test.go is to "drive this file to zero
// data lines".
//
// WHY TRUNCATING THE TAIL IS SAFE HERE, and why that is not a general licence.
// Some containers DO read their packed tail — `redundancy-group 0 node 0
// priority 200` is the shipped HA config's spelling, and compileChassis reads
// the value straight out of the node's key tail (see the `packedTail` opt-in in
// schema.go). Moving such a tail into a child would BREAK those readers.
//
// Every site in scope here is one the inventory records as DIVERGENT with the
// elided form compiling to the empty stanza — which is a positive measurement
// that the tail is currently ignored at that container. So there is nothing to
// break: the value reaches no reader today. The inventory is the safety
// evidence, and a site may only be added to this pass's scope once it appears
// there.
func normalizeCompactStanzas(tree *ConfigTree) int {
	if tree == nil {
		return 0
	}
	return normalizeCompactNodes(tree.Children, setSchema)
}

// compactNormalizeInScope reports whether a packed tail at `container` whose
// first token is `head` is in this increment's scope.
//
// #8662 scope: the 24 `match` criteria under security NAT and security policies,
// and the 6 `authentication-key` leaves under the routing protocols. Chosen
// because that is where a silent drop is a SECURITY outcome rather than a
// cosmetic one — a dropped match criterion silently changes what a rule
// matches, and a dropped authentication key silently changes what authenticates.
func compactNormalizeInScope(containerKeyword, head string) bool {
	if head == "authentication-key" {
		return true
	}
	return containerKeyword == "match"
}

func normalizeCompactNodes(nodes []*Node, schema *schemaNode) int {
	if schema == nil {
		return 0
	}
	n := 0
	for _, node := range nodes {
		if node == nil || len(node.Keys) == 0 {
			continue
		}
		kw := node.Keys[0]
		child := schema.children[kw]
		if child == nil {
			child = schema.wildcard
		}
		if child == nil {
			continue
		}
		// The node's own identity is its keyword plus its declared args.
		identity := 1 + child.args
		if len(node.Keys) > identity && len(node.Children) == 0 {
			head := node.Keys[identity]
			// The tail only reads as an elided BODY if its first token names a
			// child of this container. Otherwise it is this node's own
			// multi-value payload (a bracketed list, a multi: true leaf) and
			// must be left alone.
			if _, isBody := child.children[head]; isBody && compactNormalizeInScope(kw, head) {
				tail := append([]string(nil), node.Keys[identity:]...)
				node.Keys = append([]string(nil), node.Keys[:identity]...)
				node.IsLeaf = false
				node.Children = append(node.Children, &Node{Keys: tail, IsLeaf: true})
				n++
			}
		}
		n += normalizeCompactNodes(node.Children, child)
	}
	return n
}
