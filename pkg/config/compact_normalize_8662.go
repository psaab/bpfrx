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
	if containerKeyword == "match" {
		return true
	}
	// #8690, second increment: the CREDENTIAL family. Chosen on consequence
	// rather than on count — each of these is a token whose silent drop leaves
	// something authenticating (or authorizing) with NOTHING, on a commit that
	// reports success. That is the failure #8689 demonstrated on its own
	// `authentication-key` above: the brace-elided spelling compiled to an
	// empty AuthKey, rendered as `area-password md5`, and the IS-IS adjacency
	// came up unauthenticated.
	//
	// EVERY ENTRY BELOW WAS MEASURED, not reasoned about. The rule is that a
	// site may enter this pass only once the census shows its elided spelling
	// compiling identically to the EMPTY stanza — a positive measurement that
	// no reader consumes the packed tail today, so moving it cannot break one.
	// `TestCompactNormalizeScopePreservesCompiledResult8690` re-derives that for
	// every admitted site on each run, against the same census machinery the
	// inventory uses, so this list cannot drift from its own justification.
	//
	// The measurement also EXCLUDED members of the family, and NEITHER exclusion
	// came from empty-equivalence — see the two notes below. Membership is by
	// measurement rather than by name, and the measurement that matters is not
	// always the one the rule names.
	//
	// EXCLUDED BY DESIGN, and this is not the empty-equivalence rule — it is a
	// second gate that behaviour measurement cannot see. `system login user
	// <u> authentication <leaf>` measures empty-equivalent (nothing reads the
	// tail), and normalizing it would still be wrong: the compact spelling is
	// REJECTED at commit by the #6662 packed-login-body gate, and on the
	// tolerant load / peer-sync path it is warned and left inert on purpose, so
	// a peer-synced config behaves exactly as the binary that accepted it did
	// (#1960). Compiling the value there would change RBAC across an HA sync,
	// silently, between nodes on different binaries.
	//
	// `filedByDesign` in compact_block_equivalence_2419_test.go is the registry,
	// and its tripwire is what caught this: the empty-equivalence probe said
	// "safe" for all four leaves, because the probe measures whether a reader
	// consumes the tail and cannot see a decision that it SHOULD NOT be read.
	//
	// `user` is excluded too, and the registry does NOT list it — that was
	// found by measuring the gate rather than by reading the registry. The
	// normalizer runs at compiler.go:210 and the #6662 gate at :349, so a
	// rewritten tree reaches the gate already un-packed. Measured before and
	// after admitting `user`/`class`:
	//
	//	before: `system login user u1 class super-user;` -> REJECTED at commit
	//	        ("the account resolves to the fail-closed `unauthorized` class
	//	         ... on a binary before #6701 it instead reached the legacy
	//	         no-RBAC allow-everything mode")
	//	after:  compiles clean
	//
	// Normalizing it does not merely change a spelling: it converts a loud
	// commit-time rejection into a silent acceptance, and makes an RBAC class
	// compile on this binary that a peer on an older one still drops. The
	// registry lists the four `authentication` leaves; the GATE governs the
	// whole packed login body. Only the before/after comparison shows the
	// difference, so the exclusion is by container, not by the registry.
	if containerKeyword == "authentication" || containerKeyword == "user" {
		return false
	}
	if compactCredentialHeads[head] {
		return true
	}
	// `key` is too generic to admit unqualified — it appears on containers that
	// read their tail — so it is scoped to the containers that measured safe.
	// (`class` was scoped here too, under `user`; that branch is gone because
	// the container exclusion above already made it unreachable, and leaving a
	// dead branch would misdescribe the scope to the next reader.)
	switch containerKeyword {
	case "tunnel", "md5":
		return head == "key"
	}
	return false
}

// compactCredentialHeads are the #8690 credential leaves whose heads are
// distinctive enough to admit without qualifying the container. Each was
// measured empty-equivalent; see compactNormalizeInScope.
var compactCredentialHeads = map[string]bool{
	"encrypted-password":       true,
	"ssh-dsa":                  true,
	"ssh-rsa":                  true,
	"ssh-ed25519":              true,
	"pre-shared-key":           true,
	"preshared-key":            true,
	"private-key":              true,
	"authentication-type":      true,
	"authentication-algorithm": true,
	"authentication-method":    true,
	"pseudorandom-function":    true,
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
