package config

import (
	"sort"
	"strings"
	"testing"
)

// #7524: repeated address-book CONTAINERS replaced or ignored earlier entries.
//
// compileAddressBook read the FIRST `global` child and then ASSIGNED
// sec.AddressBook, so three shapes each lost an address — and, measured at
// master, they lost DIFFERENT ones:
//
//	address-book { global { A } global { B } }        -> [A]   first wins
//	address-book { global { A } } address-book { global { B } } -> [B]   last wins
//	security { ...A } security { ...B }               -> [B]   last wins
//
// "Replace or ignore earlier entries" is literal: the first ignores, the other
// two replace. parseStatements APPENDS a repeated block rather than merging it
// and compileSecurity iterates every `address-book` sibling and every
// `security` root, so all three reach the compiler.
//
// It is not a cosmetic loss. An address that vanishes is not a parse error
// anywhere downstream: a policy naming it compiles against a book that does
// not contain it, and the rule matches a different set of traffic than was
// written. #4706 and #4818 fixed the INNER and SIBLING merges; neither reached
// the containers.

func addressNames7524(t *testing.T, cfg string) []string {
	t.Helper()
	tree, errs := NewParser(cfg).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs[0])
	}
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if c.Security.AddressBook == nil {
		return nil
	}
	var out []string
	for k := range c.Security.AddressBook.Addresses {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestRepeatedAddressBookContainersMerge7524(t *testing.T) {
	for _, tc := range []struct {
		name, cfg string
	}{
		{
			// FIRST-WINS shape: FindChild returns only the first `global`.
			"two global blocks in one address-book",
			`security {
    address-book {
        global { address A 10.0.0.1/32; }
        global { address B 10.0.0.2/32; }
    }
}
`,
		},
		{
			// LAST-WINS shape: each address-book sibling reassigned the book.
			"two address-book blocks",
			`security {
    address-book { global { address A 10.0.0.1/32; } }
    address-book { global { address B 10.0.0.2/32; } }
}
`,
		},
		{
			// LAST-WINS across security roots — the #3562 duplicate-block class
			// one level up. Reachable from hierarchical `load override` input.
			"two security blocks",
			`security {
    address-book { global { address A 10.0.0.1/32; } }
}
security {
    address-book { global { address B 10.0.0.2/32; } }
}
`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := addressNames7524(t, tc.cfg)
			if strings.Join(got, ",") != "A,B" {
				t.Errorf("addresses = %v, want [A B]. A repeated address-book "+
					"container dropped an entry: a policy naming the missing address "+
					"compiles against a book without it and matches different traffic "+
					"than was written, with no error anywhere (#7524)", got)
			}
		})
	}
}

// ADDRESS-SETS travel the same path and are the half that actually widens or
// narrows a policy — an address is usually referenced through a set. A merge
// that carried Addresses but not AddressSets would pass every cell above.
func TestRepeatedContainersMergeAddressSets7524(t *testing.T) {
	cfg := `security {
    address-book {
        global {
            address A 10.0.0.1/32;
            address-set S1 { address A; }
        }
        global {
            address B 10.0.0.2/32;
            address-set S2 { address B; }
        }
    }
}
`
	tree, errs := NewParser(cfg).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs[0])
	}
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if c.Security.AddressBook == nil {
		t.Fatal("no address book compiled at all")
	}
	var sets []string
	for k := range c.Security.AddressBook.AddressSets {
		sets = append(sets, k)
	}
	sort.Strings(sets)
	if strings.Join(sets, ",") != "S1,S2" {
		t.Errorf("address-sets = %v, want [S1 S2]. A merge that carries addresses "+
			"but not sets passes every address-only assertion while a policy naming "+
			"the dropped set still matches the wrong traffic (#7524)", sets)
	}
}

// LAZY ALLOCATION control. The book must stay nil when no `global` block
// exists, or every `AddressBook != nil` check downstream changes meaning —
// and the obvious fix (allocate up front, then merge) breaks exactly this
// while passing every merge cell above.
func TestNoGlobalBlockLeavesAddressBookNil7524(t *testing.T) {
	for _, cfg := range []string{
		`security { policies { } }`,
		`security { address-book { } }`,
	} {
		tree, errs := NewParser(cfg).Parse()
		if len(errs) > 0 {
			t.Fatalf("parse: %v", errs[0])
		}
		c, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig(%q): %v", cfg, err)
		}
		if c.Security.AddressBook != nil {
			t.Errorf("%q compiled a non-nil AddressBook; lazy allocation is part of "+
				"the contract — downstream `!= nil` checks read it as \"an address "+
				"book was configured\" (#7524)", cfg)
		}
	}
}

// WITHIN a block, a repeated NAME still resolves last-wins. That is the
// existing #4706 semantics and this change must not alter it; without the
// control, a merge could be "fixed" by making duplicates first-wins and no
// other cell would notice.
func TestDuplicateNameStillLastWins7524(t *testing.T) {
	cfg := `security {
    address-book {
        global { address A 10.0.0.1/32; }
        global { address A 10.9.9.9/32; }
    }
}
`
	tree, errs := NewParser(cfg).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs[0])
	}
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	a := c.Security.AddressBook.Addresses["A"]
	if a == nil {
		t.Fatal("address A missing entirely")
	}
	if !strings.Contains(a.Value, "10.9.9.9") {
		t.Errorf("A = %q, want the LAST definition (10.9.9.9/32). Merging containers "+
			"must not change same-name resolution, which is #4706's semantics", a.Value)
	}
}
