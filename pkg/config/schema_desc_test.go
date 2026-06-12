package config

import (
	"sort"
	"testing"
)

// TestSchemaAllNodesHaveDesc is the #1892 regression pin: every node in
// setSchema must carry a non-empty desc — an empty desc renders as a
// blank help line in `?` completion across all three frontends (local
// CLI, remote CLI, gRPC). The #1892 audit filled 493 empty nodes; this
// test keeps new grammar from reintroducing undocumented paths. See
// docs/config-schema.md "Help-text discipline".
func TestSchemaAllNodesHaveDesc(t *testing.T) {
	var missing []string
	var walk func(path string, n *schemaNode)
	walk = func(path string, n *schemaNode) {
		if n == nil {
			return
		}
		if path != "" && n.desc == "" {
			missing = append(missing, path)
		}
		keys := make([]string, 0, len(n.children))
		for k := range n.children {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			walk(path+" "+k, n.children[k])
		}
		if n.wildcard != nil {
			walk(path+" <*>", n.wildcard)
		}
	}
	walk("", setSchema)
	if len(missing) > 0 {
		max := len(missing)
		if max > 25 {
			max = 25
		}
		t.Fatalf("%d setSchema nodes have empty desc (every node must "+
			"document itself — docs/config-schema.md #1892); first %d:\n%v",
			len(missing), max, missing[:max])
	}
}
