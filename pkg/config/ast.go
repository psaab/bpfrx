package config

import (
	"fmt"
	"strings"
)

// Node represents a node in the Junos configuration tree.
// It is either a leaf (terminated by ;) or a block (containing children in {}).
type Node struct {
	// Keys is the sequence of identifiers forming this node's identity.
	// Examples:
	//   "security" -> ["security"]
	//   "security-zone trust" -> ["security-zone", "trust"]
	//   "from-zone trust to-zone untrust" -> ["from-zone", "trust", "to-zone", "untrust"]
	//   "address 10.0.1.0/24" -> ["address", "10.0.1.0/24"]
	Keys []string

	// Children are the nodes within this block's braces.
	// nil for leaf nodes.
	Children []*Node

	// IsLeaf is true when the node is terminated by ; (no block body).
	IsLeaf bool

	// Annotation is a user comment set via the "annotate" command.
	Annotation string

	// InheritedFrom is the group name this node was inherited from.
	// Set during ExpandGroups when tagInherited is true.
	InheritedFrom string

	// Inactive marks a node deactivated via the Junos `inactive:` statement
	// marker (#2008 H1). The node is retained verbatim in the tree — it
	// displays in `show configuration` (with the `inactive:` prefix
	// re-emitted), persists through commit/reboot, syncs to the HA peer, and
	// can be re-enabled later — but it is EXCLUDED from compilation and
	// application: the firewall behaves as if the statement were absent. The
	// centralized strip (WithoutInactive) prunes inactive subtrees on the
	// cloned tree before group expansion + compile and before
	// schema-validation, so the ~15 compiler files and the typed-leaf schema
	// gate never see inactive nodes. JSON-tagged omitempty so existing
	// persisted configs and the on-disk format stay byte-identical for
	// active nodes (an old DB has no Inactive key → false → active).
	Inactive bool `json:",omitempty"`

	// Line/Column where this node starts (for error reporting).
	Line   int
	Column int
}

// Name returns the first key of the node.
func (n *Node) Name() string {
	if len(n.Keys) == 0 {
		return ""
	}
	return n.Keys[0]
}

// KeyPath returns the full key path as a single string (unquoted).
// Used for map lookups and comparison. For display/format output, use QuotedKeyPath.
func (n *Node) KeyPath() string {
	return strings.Join(n.Keys, " ")
}

// QuotedKeyPath returns the key path with keys quoted if they contain
// characters that aren't valid bare identifiers (e.g. ${node}).
func (n *Node) QuotedKeyPath() string {
	parts := make([]string, len(n.Keys))
	for i, k := range n.Keys {
		parts[i] = quoteKey(k)
	}
	return strings.Join(parts, " ")
}

// keyEscaper escapes exactly the characters that the lexer's readString
// (pkg/config/lexer.go) un-escapes on parse: backslash, double-quote, and
// newline. The mapping is symmetric — the set of sequences emitted here is
// identical to the set the lexer decodes — so Format(Parse(x)) == x and
// Parse(Format(x)) == x for every value, including IKE pre-shared keys and
// other string leaves that contain a backslash (the #3854 corruption). It is
// a single-pass Replacer, so backslash is escaped before (never after) the
// quote it may precede: `\"` never double-processes into `\\"`. Do not add
// escapes for characters the lexer does not interpret (e.g. `\t`), or the
// round-trip would over-escape and diverge.
var keyEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

// quoteKey wraps a key in double quotes if it contains characters that
// are not valid in bare Junos identifiers, escaping backslash, quote, and
// newline so the quoted form round-trips symmetrically through the lexer.
func quoteKey(s string) string {
	if s == "" {
		return `""`
	}
	for i := 0; i < len(s); i++ {
		if !isIdentChar(s[i]) {
			return `"` + keyEscaper.Replace(s) + `"`
		}
	}
	return s
}

// FindChild returns the first child whose first key matches name.
func (n *Node) FindChild(name string) *Node {
	for _, child := range n.Children {
		if len(child.Keys) > 0 && child.Keys[0] == name {
			return child
		}
	}
	return nil
}

// FindChildren returns all children whose first key matches name.
func (n *Node) FindChildren(name string) []*Node {
	var result []*Node
	for _, child := range n.Children {
		if len(child.Keys) > 0 && child.Keys[0] == name {
			result = append(result, child)
		}
	}
	return result
}

// ConfigTree is the root of a parsed configuration.
type ConfigTree struct {
	Children []*Node
}

// FindChild returns the first top-level child matching name.
func (t *ConfigTree) FindChild(name string) *Node {
	for _, child := range t.Children {
		if len(child.Keys) > 0 && child.Keys[0] == name {
			return child
		}
	}
	return nil
}

// FindChildren returns every top-level child matching name. A Junos config may
// legitimately carry the SAME top-level stanza more than once (two hierarchical
// `interfaces { }` / `security { }` / `routing-instances { }` blocks parse into
// sibling roots), and compileSections dispatches EVERY matching root — so any
// AST pre-pass that must observe the whole config (the stable-ID collision
// gates, the interface-range expansion) has to union across all matching roots,
// not just the first FindChild hit (#5675 / #5691).
func (t *ConfigTree) FindChildren(name string) []*Node {
	var result []*Node
	for _, child := range t.Children {
		if len(child.Keys) > 0 && child.Keys[0] == name {
			result = append(result, child)
		}
	}
	return result
}

// Clone creates a deep copy of the config tree.
func (t *ConfigTree) Clone() *ConfigTree {
	if t == nil {
		return nil
	}
	return &ConfigTree{
		Children: cloneNodes(t.Children),
	}
}

func cloneNodes(nodes []*Node) []*Node {
	if nodes == nil {
		return nil
	}
	result := make([]*Node, len(nodes))
	for i, n := range nodes {
		result[i] = &Node{
			Keys:          append([]string(nil), n.Keys...),
			Children:      cloneNodes(n.Children),
			IsLeaf:        n.IsLeaf,
			Annotation:    n.Annotation,
			InheritedFrom: n.InheritedFrom,
			Inactive:      n.Inactive,
			Line:          n.Line,
			Column:        n.Column,
		}
	}
	return result
}

// navigatePath walks the tree following path components and returns matching nodes.
// When multiple sibling nodes share the same key prefix (e.g., path ["from-zone","untrust"]
// matching both ["from-zone","untrust","to-zone","trust"] and
// ["from-zone","untrust","to-zone","dmz"]), all matches are returned.
func navigatePath(nodes []*Node, path []string) []*Node {
	current := nodes
	i := 0
	for i < len(path) {
		keyword := path[i]
		// Try multi-key match (keyword + argument pairs).
		if i+1 < len(path) {
			var matched []*Node
			for _, n := range current {
				if len(n.Keys) >= 2 && n.Keys[0] == keyword && n.Keys[1] == path[i+1] {
					matched = append(matched, n)
				}
			}
			if len(matched) > 0 {
				consumed := 2
				// Continue consuming additional key-value pairs from the path
				// that match the node's remaining keys. E.g., path
				// ["from-zone","untrust","to-zone","trust"] consumes all 4 keys
				// of node Keys=["from-zone","untrust","to-zone","trust"].
				for consumed < len(matched[0].Keys) && i+consumed+1 < len(path) {
					nextKey := path[i+consumed]
					nextVal := path[i+consumed+1]
					var filtered []*Node
					for _, n := range matched {
						if len(n.Keys) > consumed+1 && n.Keys[consumed] == nextKey && n.Keys[consumed+1] == nextVal {
							filtered = append(filtered, n)
						}
					}
					if len(filtered) == 0 {
						break
					}
					matched = filtered
					consumed += 2
				}
				i += consumed
				if i >= len(path) {
					return matched
				}
				// Intermediate descent: continue against the UNION of
				// every same-prefix sibling's children, not just
				// matched[0]'s. When more than one sibling shares the
				// full multi-key prefix AND the display path continues
				// deeper (e.g. two identical
				// `from-zone untrust to-zone trust { ... }` policy
				// contexts, then `... policy B`), descending into only
				// the first block's children dropped statements held
				// under the second duplicate-context sibling from a
				// path-scoped `show` / `| display set` (#4562). This is
				// the intermediate-descent twin of the #3980 terminal
				// read-all-siblings fix (same #3842 / #2419 class).
				// Single-match is unchanged: one sibling → its children.
				current = unionChildren(matched)
				continue
			}
		}
		// Single-key match.
		if i+1 >= len(path) {
			// Terminal path element on a bare keyword: return EVERY
			// sibling sharing this leading keyword (#3980), not just the
			// first. A hierarchy level may hold multiple DISTINCT
			// statements with the same leading keyword — e.g.
			// `ntp server 1.1.1.1` / `ntp server 2.2.2.2`, several
			// `from-zone` policy contexts, repeated `archive-sites`.
			// Returning only the first hid the rest from a path-scoped
			// `show configuration <path>` and, worse, from its
			// `| display set`, so a scoped display-set backup silently
			// dropped the hidden statements on restore. FindChildren-not-
			// FindChild, the display-side sibling of the #3842 / #2419
			// read-all-siblings class.
			var all []*Node
			for _, sib := range current {
				if len(sib.Keys) > 0 && sib.Keys[0] == keyword {
					all = append(all, sib)
				}
			}
			if len(all) == 0 {
				return nil
			}
			return all
		}
		// Intermediate single-key descent: continue against the UNION of
		// every same-keyword sibling's children, not just the first, so a
		// deeper path resolves across all duplicate same-keyword blocks
		// (#4562) — the descent-side twin of the terminal #3980 read-all-
		// siblings fix. Single-match is unchanged: one sibling → its
		// children.
		var sibs []*Node
		for _, n := range current {
			if len(n.Keys) > 0 && n.Keys[0] == keyword {
				sibs = append(sibs, n)
			}
		}
		if len(sibs) == 0 {
			return nil
		}
		i++
		current = unionChildren(sibs)
	}
	return nil
}

// unionChildren concatenates the children of every node in sibling order.
// It backs navigatePath's intermediate-descent read-all-siblings behavior
// (#4562): when a display path descends past a level that holds multiple
// identical same-prefix (or same-keyword) siblings, the deeper lookup must
// resolve against the union of all those siblings' children, not just the
// first's. For a single node it returns that node's children unchanged (a
// shallow copy), so the common single-match path renders identically.
func unionChildren(nodes []*Node) []*Node {
	if len(nodes) == 1 {
		return nodes[0].Children
	}
	var out []*Node
	for _, n := range nodes {
		out = append(out, n.Children...)
	}
	return out
}

// AnnotatePath sets the annotation comment on the configuration node named by
// path. Resolution goes through navigatePath, the same multi-key-aware
// traversal `show <path>` uses, so a named / multi-key container is consumed
// as one unit: security-zone <name>, from-zone <z> to-zone <z> policy <p>,
// interfaces <name> unit <n>, family inet, and friends all resolve.
//
// It replaces the hand-rolled one-token-per-node walk that Store.Annotate
// carried before #4587, which matched a multi-key node by ANY single key then
// looked for the argument token as a child and failed ("path not found") for
// every named container — annotate worked only for a chain of pure single-key
// nodes such as `system`. The comment is set on the FIRST resolved node,
// preserving the prior single-node semantics; a single-key path like `system`
// resolves to exactly the same node and result as before. A path that does not
// resolve returns a clear error naming the path and mutates nothing.
func (t *ConfigTree) AnnotatePath(path []string, comment string) error {
	if len(path) == 0 {
		return fmt.Errorf("path not found: (empty path)")
	}
	matches := navigatePath(t.Children, path)
	if len(matches) == 0 {
		return fmt.Errorf("path not found: %s", strings.Join(path, " "))
	}
	matches[0].Annotation = comment
	return nil
}

// matchNodeKeys checks if a node's Keys match path elements starting at pos.
// Returns the number of path elements consumed (len(node.Keys)) on match, 0 otherwise.
func matchNodeKeys(n *Node, path []string, pos int) int {
	if len(n.Keys) == 0 || pos >= len(path) {
		return 0
	}
	if n.Keys[0] != path[pos] {
		return 0
	}
	// First key matches; check remaining keys fit within path
	nk := len(n.Keys)
	if pos+nk > len(path) {
		// Partial match: node has more keys than remaining path.
		// Accept if we're at the last path segment (allows matching by first key only).
		return 1
	}
	for j := 1; j < nk; j++ {
		if n.Keys[j] != path[pos+j] {
			return 1 // first key matched but subsequent didn't; still a 1-key match
		}
	}
	return nk
}

// navigateToNode walks the tree following path, returning the target node.
// Multi-key nodes consume multiple path elements at once.
func navigateToNode(children []*Node, path []string) (*Node, error) {
	var current *Node
	pos := 0
	for pos < len(path) {
		found := false
		for _, child := range children {
			consumed := matchNodeKeys(child, path, pos)
			if consumed > 0 {
				current = child
				children = child.Children
				pos += consumed
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("path element %q not found", path[pos])
		}
	}
	return current, nil
}

// findNode navigates the tree to find a node at the given path.
// Handles multi-key nodes by consuming multiple path elements per node.
func (t *ConfigTree) findNode(path []string) (*Node, error) {
	return navigateToNode(t.Children, path)
}

// insertNode inserts a node as a child at the given parent path.
func (t *ConfigTree) insertNode(parentPath []string, node *Node) error {
	children := &t.Children
	pos := 0
	for pos < len(parentPath) {
		found := false
		for _, child := range *children {
			consumed := matchNodeKeys(child, parentPath, pos)
			if consumed > 0 {
				children = &child.Children
				pos += consumed
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("destination parent path element %q not found", parentPath[pos])
		}
	}
	*children = append(*children, node)
	return nil
}

// findNodeWithParent navigates the tree and returns the target node
// plus the parent's children slice (for insertion/removal at the correct level).
func (t *ConfigTree) findNodeWithParent(path []string) (*Node, *[]*Node, error) {
	parentChildren := &t.Children
	pos := 0
	for pos < len(path) {
		// Try all children; prefer full-key matches over partial ones.
		// This handles siblings like [policy first], [policy second], [policy third]
		// where the first key "policy" matches all but we need the full key match.
		var bestChild *Node
		bestConsumed := 0
		for _, child := range *parentChildren {
			consumed := matchNodeKeys(child, path, pos)
			if consumed > bestConsumed {
				bestChild = child
				bestConsumed = consumed
			}
		}
		if bestChild == nil {
			return nil, nil, fmt.Errorf("path element %q not found", path[pos])
		}
		if pos+bestConsumed >= len(path) {
			return bestChild, parentChildren, nil
		}
		parentChildren = &bestChild.Children
		pos += bestConsumed
	}
	return nil, nil, fmt.Errorf("path not found")
}

// keysEqual returns true if two key slices are identical.
func keysEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
