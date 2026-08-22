package cmdtree

import "testing"

// #6496: `show system bootstrap-import` must exist in the operational tree.
//
// The tree is the single source of truth for tab completion and `?` help
// across the local CLI, the remote CLI, and gRPC (CLAUDE.md "Command Trees").
// A dispatcher case with no tree node is reachable only by an operator who
// already knows the exact string — which is nobody on day zero, when this
// command is the one they need. RED on revert: delete the node and the lookup
// below fails while every dispatcher still "works".
func TestShowSystemBootstrapImportNodeExists(t *testing.T) {
	show, ok := OperationalTree["show"]
	if !ok {
		t.Fatal("no `show` node in the operational tree")
	}
	sys, ok := show.Children["system"]
	if !ok {
		t.Fatal("no `show system` node in the operational tree")
	}
	n, ok := sys.Children["bootstrap-import"]
	if !ok {
		t.Fatal("`show system bootstrap-import` missing — the day-0 import " +
			"verdict is not tab-completable or discoverable via `?` (#6496)")
	}
	if n.Desc == "" {
		t.Error("`show system bootstrap-import` has no description — `?` help " +
			"would render a blank line")
	}
}

// The node must also be OFFERED by the completion walk the CLIs actually call,
// not merely present in the map. A node reachable only by direct map lookup is
// still invisible at the prompt.
func TestShowSystemBootstrapImportIsCompleted(t *testing.T) {
	got := CompleteFromTree(OperationalTree, []string{"show", "system"}, "bootstrap", nil)
	for _, c := range got {
		if c == "bootstrap-import" {
			return
		}
	}
	t.Fatalf("`show system bootstrap-` does not complete to bootstrap-import; got %v", got)
}
