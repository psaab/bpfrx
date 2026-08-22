package cmdtree

import "testing"

// #6495: `show system kernel-upgrade` must exist in the operational tree.
// A dispatcher case with no tree node is reachable only by an operator who
// already knows the exact string — and mid-roll they are looking for it, not
// recalling it.
func TestShowSystemKernelUpgradeNodeExists(t *testing.T) {
	sys, ok := OperationalTree["show"].Children["system"]
	if !ok {
		t.Fatal("no `show system` node in the operational tree")
	}
	n, ok := sys.Children["kernel-upgrade"]
	if !ok {
		t.Fatal("`show system kernel-upgrade` missing — the #1930 kernel " +
			"channel is not tab-completable or discoverable via `?` (#6495)")
	}
	if n.Desc == "" {
		t.Error("no description — `?` help would render a blank line")
	}
}

func TestShowSystemKernelUpgradeIsCompleted(t *testing.T) {
	for _, c := range CompleteFromTree(OperationalTree, []string{"show", "system"}, "kernel", nil) {
		if c == "kernel-upgrade" {
			return
		}
	}
	t.Fatal("`show system kernel-` does not complete to kernel-upgrade")
}
