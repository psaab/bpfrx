package config

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"
)

// FormatInheritance returns the config with inherited groups expanded and
// annotated with "## 'X' was inherited from group 'Y'" comments, matching
// Junos "show configuration | display inheritance" output.
func (t *ConfigTree) FormatInheritance() string {
	clone := t.Clone()
	if err := clone.ExpandGroupsTagged(); err != nil {
		return t.Format() // fallback to plain format on error
	}
	var b strings.Builder
	formatNodesInheritance(&b, clone.Children, 0)
	return b.String()
}

// FormatPathInheritance is like FormatPath but with inheritance annotations.
func (t *ConfigTree) FormatPathInheritance(path []string) string {
	clone := t.Clone()
	if err := clone.ExpandGroupsTagged(); err != nil {
		return t.FormatPath(path)
	}
	if len(path) == 0 {
		return clone.FormatInheritance()
	}
	matches := navigatePath(clone.Children, path)
	if len(matches) == 0 {
		return ""
	}
	var b strings.Builder
	for _, n := range matches {
		if n.IsLeaf {
			fmt.Fprintf(&b, "%s;\n", n.QuotedKeyPath())
		} else {
			fmt.Fprintf(&b, "%s {\n", n.QuotedKeyPath())
			formatNodesInheritance(&b, n.Children, 1)
			fmt.Fprintf(&b, "}\n")
		}
	}
	return b.String()
}

func formatNodesInheritance(b *strings.Builder, nodes []*Node, indent int) {
	nodes = canonicalOrder(nodes)
	prefix := strings.Repeat("    ", indent)
	for _, n := range nodes {
		if n.Annotation != "" {
			fmt.Fprintf(b, "%s/* %s */\n", prefix, n.Annotation)
		}
		if n.InheritedFrom != "" {
			// Use the last key in the node's key path for inherited-node annotations
			// (for example, "## 'any' was inherited").
			displayKey := n.Keys[len(n.Keys)-1]
			fmt.Fprintf(b, "%s##\n%s## '%s' was inherited from group '%s'\n%s##\n",
				prefix, prefix, displayKey, n.InheritedFrom, prefix)
		}
		if n.IsLeaf {
			fmt.Fprintf(b, "%s%s;\n", prefix, n.QuotedKeyPath())
		} else {
			fmt.Fprintf(b, "%s%s {\n", prefix, n.QuotedKeyPath())
			formatNodesInheritance(b, n.Children, indent+1)
			fmt.Fprintf(b, "%s}\n", prefix)
		}
	}
}

// Format renders the tree as Junos hierarchical configuration text.
func (t *ConfigTree) Format() string {
	var b strings.Builder
	formatNodes(&b, t.Children, 0)
	return b.String()
}

// canonicalOrder reorders children so "match"/"from" comes before "then",
// matching Junos canonical display order for policies, NAT rules, and
// firewall filter terms.
func canonicalOrder(nodes []*Node) []*Node {
	matchIdx, thenIdx := -1, -1
	for i, n := range nodes {
		if len(n.Keys) > 0 {
			switch n.Keys[0] {
			case "match", "from":
				matchIdx = i
			case "then":
				thenIdx = i
			}
		}
	}
	if matchIdx < 0 || thenIdx < 0 || matchIdx < thenIdx {
		return nodes // already correct or doesn't apply
	}
	// match/from is after then — move it to just before then
	result := make([]*Node, 0, len(nodes))
	for i, n := range nodes {
		if i == matchIdx {
			continue
		}
		if i == thenIdx {
			result = append(result, nodes[matchIdx])
		}
		result = append(result, n)
	}
	return result
}

func formatNodes(b *strings.Builder, nodes []*Node, indent int) {
	nodes = canonicalOrder(nodes)
	prefix := strings.Repeat("    ", indent)
	for _, n := range nodes {
		if n.Annotation != "" {
			fmt.Fprintf(b, "%s/* %s */\n", prefix, n.Annotation)
		}
		if n.IsLeaf {
			fmt.Fprintf(b, "%s%s;\n", prefix, n.QuotedKeyPath())
		} else {
			fmt.Fprintf(b, "%s%s {\n", prefix, n.QuotedKeyPath())
			formatNodes(b, n.Children, indent+1)
			fmt.Fprintf(b, "%s}\n", prefix)
		}
	}
}

// FormatPath navigates to the given path and formats the subtree found there.
// Path components are matched against node keys. For example, FormatPath(["interfaces", "wan0"])
// navigates into the "interfaces" node, then into the child whose second key is "wan0",
// and formats that subtree. Returns "" if the path is not found.
func (t *ConfigTree) FormatPath(path []string) string {
	if len(path) == 0 {
		return t.Format()
	}
	matches := navigatePath(t.Children, path)
	if len(matches) == 0 {
		return ""
	}
	var b strings.Builder
	for _, n := range matches {
		if n.IsLeaf {
			fmt.Fprintf(&b, "%s;\n", n.QuotedKeyPath())
		} else {
			fmt.Fprintf(&b, "%s {\n", n.QuotedKeyPath())
			formatNodes(&b, n.Children, 1)
			fmt.Fprintf(&b, "}\n")
		}
	}
	return b.String()
}

// FormatSet renders the tree as flat "set" commands.
func (t *ConfigTree) FormatSet() string {
	var b strings.Builder
	formatSetNodes(&b, t.Children, nil)
	return b.String()
}

// FormatPathSet renders a subtree as flat "set" commands.
// The full path prefix (including parent keys) is included in each set line.
func (t *ConfigTree) FormatPathSet(path []string) string {
	if len(path) == 0 {
		return t.FormatSet()
	}
	matches := navigatePath(t.Children, path)
	if len(matches) == 0 {
		return ""
	}
	// Compute parent prefix: path elements before the matched node's first key.
	var parentPrefix []string
	firstKey := matches[0].Keys[0]
	for _, p := range path {
		if p == firstKey {
			break
		}
		parentPrefix = append(parentPrefix, p)
	}
	var b strings.Builder
	for _, n := range matches {
		prefix := append(append([]string{}, parentPrefix...), n.Keys...)
		if n.IsLeaf {
			fmt.Fprintf(&b, "set %s\n", joinQuotedKeys(prefix))
		} else {
			formatSetNodes(&b, n.Children, prefix)
		}
	}
	return b.String()
}

func formatSetNodes(b *strings.Builder, nodes []*Node, prefix []string) {
	for _, n := range canonicalOrder(nodes) {
		path := append(prefix, n.Keys...)
		if n.IsLeaf {
			fmt.Fprintf(b, "set %s\n", joinQuotedKeys(path))
		} else {
			formatSetNodes(b, n.Children, path)
		}
	}
}

// joinQuotedKeys joins keys with spaces, quoting any that contain special characters.
func joinQuotedKeys(keys []string) string {
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = quoteKey(k)
	}
	return strings.Join(parts, " ")
}

// FormatCompare produces a Junos-style hierarchical diff between two trees.
// It shows [edit <path>] context headers and +/- prefixed lines for added/removed content.
// Unchanged sibling nodes within changed containers are shown collapsed as "name { ... }".
func FormatCompare(oldTree, newTree *ConfigTree) string {
	var b strings.Builder
	diffNodes(&b, oldTree.Children, newTree.Children, nil)
	return b.String()
}

// diffNodes compares two sets of children at the same tree level.
// It recurses into modified containers to find the deepest [edit] context,
// only showing siblings at the level where actual leaf changes occur.
func diffNodes(b *strings.Builder, oldNodes, newNodes []*Node, editPath []string) {
	oldByKey := make(map[string]*Node, len(oldNodes))
	for _, n := range oldNodes {
		oldByKey[n.KeyPath()] = n
	}
	newByKey := make(map[string]*Node, len(newNodes))
	for _, n := range newNodes {
		newByKey[n.KeyPath()] = n
	}

	// Collect changed entries at this level.
	type diffEntry struct {
		oldNode *Node
		newNode *Node
	}

	// Use canonical ordering from new tree, then appended removed-only entries.
	seen := make(map[string]bool)
	var entries []diffEntry
	for _, n := range canonicalOrder(newNodes) {
		kp := n.KeyPath()
		seen[kp] = true
		old := oldByKey[kp]
		if old == nil || !nodesEqual(old, n) {
			entries = append(entries, diffEntry{oldNode: old, newNode: n})
		}
	}
	for _, n := range canonicalOrder(oldNodes) {
		kp := n.KeyPath()
		if !seen[kp] {
			entries = append(entries, diffEntry{oldNode: n, newNode: nil})
		}
	}

	if len(entries) == 0 {
		return
	}

	// Check if all changes can be recursed into (both old and new are blocks).
	// If so, recurse without printing siblings at this level.
	allRecursable := true
	for _, e := range entries {
		if e.oldNode == nil || e.newNode == nil {
			allRecursable = false
			break
		}
		if e.oldNode.IsLeaf || e.newNode.IsLeaf {
			allRecursable = false
			break
		}
	}

	if allRecursable {
		// All changes are in modified sub-containers — recurse deeper without showing this level.
		for _, e := range entries {
			childPath := append(append([]string{}, editPath...), strings.Fields(e.oldNode.KeyPath())...)
			diffNodes(b, e.oldNode.Children, e.newNode.Children, childPath)
		}
		return
	}

	// Print [edit <path>] header — this is the level where leaf changes exist.
	if len(editPath) > 0 {
		fmt.Fprintf(b, "[edit %s]\n", strings.Join(editPath, " "))
	}

	// Show all children at this level: unchanged as collapsed, added/removed with prefix.
	// Merge all nodes from both old and new in canonical order (new first, then old-only).
	seen2 := make(map[string]bool)
	var allEntries []diffEntry
	for _, n := range canonicalOrder(newNodes) {
		kp := n.KeyPath()
		seen2[kp] = true
		allEntries = append(allEntries, diffEntry{oldNode: oldByKey[kp], newNode: n})
	}
	for _, n := range canonicalOrder(oldNodes) {
		if !seen2[n.KeyPath()] {
			allEntries = append(allEntries, diffEntry{oldNode: n, newNode: nil})
		}
	}

	indent := "    "
	for _, e := range allEntries {
		switch {
		case e.oldNode == nil:
			// Added
			formatPrefixed(b, "+", indent, e.newNode)
		case e.newNode == nil:
			// Removed
			formatPrefixed(b, "-", indent, e.oldNode)
		case nodesEqual(e.oldNode, e.newNode):
			// Unchanged — show collapsed
			if e.oldNode.IsLeaf {
				fmt.Fprintf(b, " %s%s;\n", indent, e.oldNode.QuotedKeyPath())
			} else {
				fmt.Fprintf(b, " %s%s { ... }\n", indent, e.oldNode.QuotedKeyPath())
			}
		default:
			// Modified
			if !e.oldNode.IsLeaf && !e.newNode.IsLeaf {
				// Both are blocks — show [edit] context for sub-container
				childPath := append(append([]string{}, editPath...), strings.Fields(e.oldNode.KeyPath())...)
				diffNodes(b, e.oldNode.Children, e.newNode.Children, childPath)
			} else {
				formatPrefixed(b, "-", indent, e.oldNode)
				formatPrefixed(b, "+", indent, e.newNode)
			}
		}
	}
}

// nodesEqual returns true if two nodes have identical content (deep comparison).
func nodesEqual(a, b *Node) bool {
	if a.KeyPath() != b.KeyPath() {
		return false
	}
	if a.IsLeaf != b.IsLeaf {
		return false
	}
	if a.IsLeaf {
		return true
	}
	if len(a.Children) != len(b.Children) {
		return false
	}
	bByKey := make(map[string]*Node, len(b.Children))
	for _, n := range b.Children {
		bByKey[n.KeyPath()] = n
	}
	for _, ac := range a.Children {
		bc, ok := bByKey[ac.KeyPath()]
		if !ok {
			return false
		}
		if !nodesEqual(ac, bc) {
			return false
		}
	}
	return true
}

// formatPrefixed writes a node with +/- prefix at the given indent.
func formatPrefixed(b *strings.Builder, prefix, indent string, n *Node) {
	if n.IsLeaf {
		fmt.Fprintf(b, "%s%s%s;\n", prefix, indent, n.QuotedKeyPath())
	} else {
		fmt.Fprintf(b, "%s%s%s {\n", prefix, indent, n.QuotedKeyPath())
		formatPrefixedChildren(b, prefix, indent+"    ", n.Children)
		fmt.Fprintf(b, "%s%s}\n", prefix, indent)
	}
}

// formatPrefixedChildren writes all children with the same +/- prefix.
func formatPrefixedChildren(b *strings.Builder, prefix, indent string, nodes []*Node) {
	for _, n := range canonicalOrder(nodes) {
		formatPrefixed(b, prefix, indent, n)
	}
}

// FormatJSON renders the tree as a JSON object.
func (t *ConfigTree) FormatJSON() string {
	obj := nodesToJSON(t.Children)
	data, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(data) + "\n"
}

// FormatPathJSON renders a subtree as a JSON object.
func (t *ConfigTree) FormatPathJSON(path []string) string {
	if len(path) == 0 {
		return t.FormatJSON()
	}
	matches := navigatePath(t.Children, path)
	if len(matches) == 0 {
		return ""
	}
	obj := nodesToJSON(matches)
	data, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(data) + "\n"
}

// FormatXML renders the tree as Junos-style XML configuration.
func (t *ConfigTree) FormatXML() string {
	var b strings.Builder
	b.WriteString(xml.Header)
	b.WriteString("<configuration>\n")
	formatXMLNodes(&b, t.Children, 1)
	b.WriteString("</configuration>\n")
	return b.String()
}

// FormatPathXML renders a subtree as Junos-style XML.
func (t *ConfigTree) FormatPathXML(path []string) string {
	if len(path) == 0 {
		return t.FormatXML()
	}
	matches := navigatePath(t.Children, path)
	if len(matches) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(xml.Header)
	b.WriteString("<configuration>\n")
	formatXMLNodes(&b, matches, 1)
	b.WriteString("</configuration>\n")
	return b.String()
}

func formatXMLNodes(b *strings.Builder, nodes []*Node, indent int) {
	prefix := strings.Repeat("    ", indent)
	for _, n := range nodes {
		if n.IsLeaf {
			formatXMLLeaf(b, n, prefix)
		} else {
			tag := xmlTag(n.Keys[0])
			fmt.Fprintf(b, "%s<%s>\n", prefix, tag)
			// Extra keys become <name> elements.
			for _, k := range n.Keys[1:] {
				fmt.Fprintf(b, "%s    <name>%s</name>\n", prefix, xmlEscape(k))
			}
			formatXMLNodes(b, n.Children, indent+1)
			fmt.Fprintf(b, "%s</%s>\n", prefix, tag)
		}
	}
}

func formatXMLLeaf(b *strings.Builder, n *Node, prefix string) {
	if len(n.Keys) == 1 {
		// Boolean leaf: <keyword/>
		fmt.Fprintf(b, "%s<%s/>\n", prefix, xmlTag(n.Keys[0]))
		return
	}
	// Leaf with value: <keyword>value</keyword>
	// For multi-key leaves like "address 10.0.1.0/24", emit
	// <keyword><name>val1</name></keyword>
	tag := xmlTag(n.Keys[0])
	if len(n.Keys) == 2 {
		fmt.Fprintf(b, "%s<%s>%s</%s>\n", prefix, tag, xmlEscape(n.Keys[1]), tag)
	} else {
		fmt.Fprintf(b, "%s<%s>\n", prefix, tag)
		for _, k := range n.Keys[1:] {
			fmt.Fprintf(b, "%s    <name>%s</name>\n", prefix, xmlEscape(k))
		}
		fmt.Fprintf(b, "%s</%s>\n", prefix, tag)
	}
}

// xmlTag sanitizes a Junos keyword into a valid XML element name.
func xmlTag(s string) string {
	// Junos keywords already use valid XML chars (letters, digits, hyphens).
	return s
}

// xmlEscape escapes special XML characters in text content.
func xmlEscape(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

// nodesToJSON converts a list of AST nodes to a nested map structure.
func nodesToJSON(nodes []*Node) map[string]interface{} {
	result := make(map[string]interface{})

	for _, n := range nodes {
		if n.IsLeaf {
			// Leaf node: key is first key, value is remaining keys joined
			if len(n.Keys) == 1 {
				result[n.Keys[0]] = true
			} else if len(n.Keys) == 2 {
				result[n.Keys[0]] = n.Keys[1]
			} else {
				result[n.Keys[0]] = strings.Join(n.Keys[1:], " ")
			}
		} else {
			name := n.Keys[0]
			qualifier := ""
			if len(n.Keys) > 1 {
				qualifier = strings.Join(n.Keys[1:], " ")
			}

			children := nodesToJSON(n.Children)

			if qualifier != "" {
				// Named instance: e.g. "interface trust0" → {"interface": {"trust0": {...}}}
				if existing, ok := result[name]; ok {
					if m, ok := existing.(map[string]interface{}); ok {
						m[qualifier] = children
					}
				} else {
					result[name] = map[string]interface{}{qualifier: children}
				}
			} else {
				result[name] = children
			}
		}
	}
	return result
}
