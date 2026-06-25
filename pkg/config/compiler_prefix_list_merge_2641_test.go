package config

import "testing"

// #2641: a named policy-options prefix-list defined across MULTIPLE separate
// blocks must MERGE — the later block's prefixes append to the earlier block's
// rather than overwriting them. The sibling community loop already merges by
// reusing the existing map entry; prefix-list used to allocate a fresh
// PrefixList each block and clobber po.PrefixLists[name], discarding the first
// block's prefixes.
//
// Fail-on-revert: restore the overwrite (`pl := &PrefixList{...}`; unconditional
// `po.PrefixLists[name] = pl`) and only the last block's prefixes survive, so
// these assertions go RED.

func containsAll(got, want []string) bool {
	set := make(map[string]bool, len(got))
	for _, g := range got {
		set[g] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}

func TestPrefixListMergeDuplicateBlocksFlatSet(t *testing.T) {
	tree := buildTree(t, []string{
		// Same named prefix-list "mgmt" defined in two separate set groups.
		"set policy-options prefix-list mgmt 10.0.0.0/8",
		"set policy-options prefix-list mgmt 192.168.0.0/16",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	pl := cfg.PolicyOptions.PrefixLists["mgmt"]
	if pl == nil {
		t.Fatalf("prefix-list mgmt not compiled")
	}
	want := []string{"10.0.0.0/8", "192.168.0.0/16"}
	if len(pl.Prefixes) != len(want) || !containsAll(pl.Prefixes, want) {
		t.Fatalf("merged prefix-list mgmt = %v, want both blocks merged %v "+
			"(later block overwrote earlier without the #2641 merge)", pl.Prefixes, want)
	}
}

func TestPrefixListMergeDuplicateBlocksHierarchical(t *testing.T) {
	src := `policy-options {
    prefix-list mgmt {
        10.0.0.0/8;
    }
    prefix-list mgmt {
        192.168.0.0/16;
    }
}`
	cfg := mustCompile(t, src)
	pl := cfg.PolicyOptions.PrefixLists["mgmt"]
	if pl == nil {
		t.Fatalf("prefix-list mgmt not compiled")
	}
	want := []string{"10.0.0.0/8", "192.168.0.0/16"}
	if len(pl.Prefixes) != len(want) || !containsAll(pl.Prefixes, want) {
		t.Fatalf("merged prefix-list mgmt = %v, want both blocks merged %v "+
			"(later block overwrote earlier without the #2641 merge)", pl.Prefixes, want)
	}
}
