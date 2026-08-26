package config

import (
	"sort"
	"strings"
	"testing"
)

// wildcard_keyvalidator_inventory_6844_test.go -- #6844.
//
// #6844 made SchemaValidate run a keyValidator on a WILDCARD TYPED LEAF's
// keyword. #6834 had already done so for wildcard CONTAINERS; the typed-leaf
// branch returns before that rule was reached, so a wildcard typed leaf
// validated its VALUE and never its identity.
//
// That is a change to a shared gate, so its blast radius is enumerated here
// rather than left to be discovered. Every leaf in this list newly gained
// identity validation, and any leaf ADDED to the set later shows up as a diff
// in this test rather than as a config that stops committing in the field.

// collectWildcardTypedLeafKeyValidators walks setSchema for the exact shape the
// #6844 rule newly reaches.
func collectWildcardTypedLeafKeyValidators(t *testing.T) []string {
	t.Helper()
	var out []string
	seen := map[*schemaNode]bool{}
	var walk func(n *schemaNode, path []string)
	walk = func(n *schemaNode, path []string) {
		if n == nil || seen[n] {
			return
		}
		seen[n] = true
		if w := n.wildcard; w != nil {
			if w.isTypedLeaf() && w.keyValidator != nil {
				// `groups <wildcard>` re-hosts the whole configuration tree, and
				// the schema SHARES those nodes rather than copying them, so a
				// node is reached first via whichever path sorts earlier --
				// `groups` before `system`. Strip that prefix so the inventory
				// names the site an operator would recognise; the underlying
				// node, and therefore the gate, is the same one either way.
				p := strings.Join(path, " ")
				p = strings.TrimPrefix(p, "groups <wildcard> ")
				out = append(out, p+" <wildcard-key>")
			}
			walk(w, append(append([]string(nil), path...), "<wildcard>"))
		}
		keys := make([]string, 0, len(n.children))
		for k := range n.children {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			walk(n.children[k], append(append([]string(nil), path...), k))
		}
	}
	walk(setSchema, nil)
	sort.Strings(out)
	return out
}

// TestWildcardTypedLeafKeyValidatorInventory_6844 pins the blast radius.
//
// The list is short on purpose. If it grows, someone installed a keyValidator
// on a wildcard typed leaf and that leaf's identity is now gated at commit --
// which may be exactly right, but it is a behaviour change to a shared gate and
// should be a deliberate edit here rather than a surprise.
func TestWildcardTypedLeafKeyValidatorInventory_6844(t *testing.T) {
	want := []string{
		"system syslog file <wildcard-key>",
		"system syslog host <wildcard-key>",
		"system syslog user <wildcard-key>",
	}
	got := collectWildcardTypedLeafKeyValidators(t)

	// Anti-vacuity: a walk that reached nothing would report an empty set and
	// "no unexpected sites", which is indistinguishable from a clean result.
	if len(got) == 0 {
		t.Fatal("the walk found NO wildcard typed leaf with a keyValidator, not even " +
			"the three system-syslog facility slots this issue added. The walk is not " +
			"reaching the schema and would report clean whatever the schema said")
	}

	inWant := map[string]bool{}
	for _, w := range want {
		inWant[w] = true
	}
	for _, g := range got {
		if !inWant[g] {
			t.Errorf("NEW wildcard typed leaf with a keyValidator: %s\n"+
				"    Its identity is now gated at commit by the #6844 rule. If that is "+
				"intended, add it here; if not, the leaf wants a value validator rather "+
				"than a key one.", g)
		}
	}
	inGot := map[string]bool{}
	for _, g := range got {
		inGot[g] = true
	}
	for _, w := range want {
		if !inGot[w] {
			t.Errorf("%s no longer has a wildcard typed-leaf keyValidator. If the gate "+
				"was removed, the #6844 injectable-facility hole is open again.", w)
		}
	}
}
