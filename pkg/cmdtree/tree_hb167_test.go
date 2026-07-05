package cmdtree

import "testing"

// TestHB167DrillDownsPresent pins the fable-167 C-1 operational-tree
// drill-downs (SSOT for tab-completion + ? help). RED on revert: each node is
// absent before the fix, so completion/help never surface it.
func TestHB167DrillDownsPresent(t *testing.T) {
	child := func(root map[string]*Node, path ...string) *Node {
		t.Helper()
		var cur *Node
		children := root
		for i, p := range path {
			n, ok := children[p]
			if !ok || n == nil {
				t.Fatalf("missing node at path %v (stuck at %q)", path[:i+1], p)
			}
			cur = n
			children = n.Children
		}
		return cur
	}

	show := OperationalTree["show"].Children["security"].Children
	// C-1a: show security ike/ipsec security-associations detail.
	child(show, "ike", "security-associations", "detail")
	child(show, "ipsec", "security-associations", "detail")
	// C-1b: show security nat static rule [detail].
	child(show, "nat", "static", "rule", "detail")

	// C-1c: request security policies check.
	req := OperationalTree["request"].Children["security"].Children
	child(req, "policies", "check")
}
