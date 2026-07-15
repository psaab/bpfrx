package config

import (
	"errors"
	"testing"
)

// #5822: CopyPath must resolve an EXISTING non-first same-keyword destination
// parent by full identity (longest-consumed-match, like RenamePath), not the
// pre-#5822 first-keyword-match insertNode which stopped at the first
// same-keyword sibling. These tests build fixtures with ParseSetCommand +
// SetPath (never NewParser — newlines merge, per the parser gotcha).
//
// FAIL-ON-REVERT: route CopyPath back through insertNode and every non-first /
// nested target goes RED — insertNode descends into the FIRST same-keyword
// sibling and cannot find the rest of the destination-parent path, so CopyPath
// errors (or, on a collision, silently appends a duplicate).

// ks is a terse key-group literal for descend.
func ks(keys ...string) []string { return keys }

// descend walks children matching each key group by FULL identity (keysEqual),
// returning the reached node or nil. Unlike findNode/navigateToNode
// (first-keyword-match), it disambiguates same-keyword siblings so a test can
// inspect a specific sibling's subtree.
func descend(children []*Node, groups ...[]string) *Node {
	var node *Node
	cur := children
	for _, g := range groups {
		node = nil
		for _, c := range cur {
			if keysEqual(c.Keys, g) {
				node = c
				break
			}
		}
		if node == nil {
			return nil
		}
		cur = node.Children
	}
	return node
}

// build5822AppsTree returns a tree with three same-keyword `application`
// siblings (app1, app2, app3), each carrying `term t1 protocol tcp`.
func build5822AppsTree(t *testing.T) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set applications application app1 term t1 protocol tcp",
		"set applications application app2 term t1 protocol tcp",
		"set applications application app3 term t1 protocol tcp",
	} {
		parts, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(parts); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// TestCopyPath_ResolvesExactSameKeywordSiblingParent_5822 pins acceptance #1/#3:
// copying a subtree INTO the first / middle / last of three same-keyword
// `application` siblings resolves the EXACT destination parent every time
// (insertion-order independent) and never leaks into a wrong sibling.
func TestCopyPath_ResolvesExactSameKeywordSiblingParent_5822(t *testing.T) {
	for _, target := range []string{"app1", "app2", "app3"} {
		t.Run(target, func(t *testing.T) {
			tree := build5822AppsTree(t)
			src := []string{"applications", "application", "app1", "term", "t1"}
			dst := []string{"applications", "application", target, "term", "copied"}
			if err := tree.CopyPath(src, dst); err != nil {
				t.Fatalf("CopyPath into non-first same-keyword parent %q failed: %v "+
					"(insertNode cannot resolve it — #5822)", target, err)
			}
			// The copied term must land under the TARGET application.
			if descend(tree.Children, ks("applications"), ks("application", target), ks("term", "copied")) == nil {
				t.Fatalf("copied term not found under %q after copy", target)
			}
			// It must NOT have leaked into any OTHER application — the #5822 bug
			// resolves the FIRST same-keyword sibling as the parent.
			for _, other := range []string{"app1", "app2", "app3"} {
				if other == target {
					continue
				}
				if descend(tree.Children, ks("applications"), ks("application", other), ks("term", "copied")) != nil {
					t.Fatalf("copied term leaked into wrong sibling %q — copy resolved the wrong "+
						"same-keyword parent (#5822)", other)
				}
			}
		})
	}
}

// TestCopyPath_NestedMultiKeySameKeywordParent_5822 pins acceptance #2: the
// destination-parent path passes through TWO non-first same-keyword levels
// (application app3 AND term t3), each of which must be resolved by full
// identity.
func TestCopyPath_NestedMultiKeySameKeywordParent_5822(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set applications application src term st source-port 100",
		"set applications application app1 term t1 protocol tcp",
		"set applications application app3 term t1 protocol tcp",
		"set applications application app3 term t3 protocol udp",
	} {
		parts, _ := ParseSetCommand(cmd)
		if err := tree.SetPath(parts); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	// Copy the `source-port 100` leaf into app3's SECOND term (t3).
	src := []string{"applications", "application", "src", "term", "st", "source-port", "100"}
	dst := []string{"applications", "application", "app3", "term", "t3", "source-port", "100"}
	if err := tree.CopyPath(src, dst); err != nil {
		t.Fatalf("CopyPath into nested non-first same-keyword parent failed: %v (#5822)", err)
	}
	if descend(tree.Children, ks("applications"), ks("application", "app3"), ks("term", "t3"), ks("source-port", "100")) == nil {
		t.Fatal("copied leaf not found under app3/term t3")
	}
	// Must not have leaked into app1, app3/term t1, or the source.
	if descend(tree.Children, ks("applications"), ks("application", "app1"), ks("term", "t1"), ks("source-port", "100")) != nil {
		t.Fatal("copied leaf leaked into app1/term t1 (#5822)")
	}
	if descend(tree.Children, ks("applications"), ks("application", "app3"), ks("term", "t1"), ks("source-port", "100")) != nil {
		t.Fatal("copied leaf leaked into app3/term t1 (wrong nested sibling, #5822)")
	}
}

// TestCopyPath_CollisionRejectedAndTreeUnchanged_5822 pins the collision +
// atomicity rule: a copy onto an EXISTING same-identity target is rejected, not
// silently merged/duplicated, and the tree is left byte-for-byte unchanged.
//
// FAIL-ON-REVERT: insertNode appends the clone unconditionally, so the buggy
// path returns nil (no error) and adds a duplicate sibling — both assertions RED.
func TestCopyPath_CollisionRejectedAndTreeUnchanged_5822(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set security zones security-zone trust host-inbound-traffic system-services ping",
		"set security zones security-zone existing host-inbound-traffic system-services ssh",
	} {
		parts, _ := ParseSetCommand(cmd)
		if err := tree.SetPath(parts); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	before := tree.Format()

	err := tree.CopyPath(
		[]string{"security", "zones", "security-zone", "trust"},
		[]string{"security", "zones", "security-zone", "existing"}, // already exists
	)
	if err == nil {
		t.Fatal("copy onto an existing same-identity target must be rejected, not silently duplicated (#5822)")
	}
	if got := tree.Format(); got != before {
		t.Fatalf("a rejected copy must leave the tree byte-for-byte unchanged (atomicity, #5822):\n"+
			"--- before ---\n%s\n--- after ---\n%s", before, got)
	}
}

// TestCopyPath_MissingDestParentWrapsErrPathNotFound_5822 pins the typed-error +
// atomicity rule: a copy whose destination parent does not exist wraps the
// ErrPathNotFound sentinel and leaves the tree unchanged.
//
// FAIL-ON-REVERT: insertNode returns a bare fmt.Errorf that does NOT wrap
// ErrPathNotFound, so the errors.Is assertion goes RED.
func TestCopyPath_MissingDestParentWrapsErrPathNotFound_5822(t *testing.T) {
	tree := build5822AppsTree(t)
	before := tree.Format()

	err := tree.CopyPath(
		[]string{"applications", "application", "app1", "term", "t1"},
		[]string{"applications", "application", "nope", "term", "copied"}, // parent app "nope" absent
	)
	if err == nil {
		t.Fatal("copy into a missing destination parent must error")
	}
	if !errors.Is(err, ErrPathNotFound) {
		t.Fatalf("missing-dest-parent error must wrap ErrPathNotFound, got %v", err)
	}
	if got := tree.Format(); got != before {
		t.Fatalf("a failed copy must leave the tree unchanged:\n--- before ---\n%s\n--- after ---\n%s", before, got)
	}
}
