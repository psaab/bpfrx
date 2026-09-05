package config

import (
	"sort"
	"strings"
	"testing"
)

// #8850, third case. An elided address-book brace silently dropped its
// entries -- and unlike the zones and screens cases this one is an ordinary
// UNADMITTED PAIR, not the Children!=0 shape, because the node is fully packed
// and has no children. It passed the relaxed gate, was ASKED about, and refused:
//
//	d1 address-book address a1 10.0.0.1/32;      asked=[[address-book address]]  REFUSED -> 0
//	d1 address-book address-set s1 { ... }       asked=[[address-book address-set]] admitted -> 1
//
// Same container, same depth, two heads: one folds and one loses. That
// within-container control is what isolates it as admission rather than shape.
//
// WHY IT MATTERS AS MUCH AS THE ZONE CASE: an address book that loses its
// entries produces a policy referencing an address that does not exist. The
// policy still exists and still reads as correct -- only the reference resolves
// to nothing -- so it is less visible than an empty zone, not more.
//
// TWO PARTS WERE REQUIRED and the first alone is a PARTIAL fix that looks
// complete on a single-entry fixture:
//
//	scope entry only     one address  -> 1 (fixed)   two addresses -> 1 (a2 LOST)
//	+ packedStatements   one address  -> 1           two addresses -> 2
//
// `address` is args:2 multi:true, so a packed run holds 3 tokens per statement;
// without the container opting in to the #8768 split the whole run folds into
// ONE statement and every entry after the first is swallowed.
//
// BOTH BOOKS. The zone-local and global address books are declared separately
// and the global one was NOT fixed by the zone-local change -- its container is
// `global`, so it needed its own pair and its own opt-in. When the code names
// one member of a declared pair the other is a candidate by construction.
func TestElidedAddressBook8850(t *testing.T) {
	zoneAddrs := func(t *testing.T, ab string) []string {
		t.Helper()
		txt := "security { zones { security-zone trust { " + ab + " } } }"
		tree, errs := NewParser(txt).Parse()
		if len(errs) > 0 {
			t.Fatalf("parse %q: %v", ab, errs)
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("compile %q: %v", ab, err)
		}
		for _, z := range cfg.Security.Zones {
			if z.AddressBook == nil {
				return nil
			}
			var out []string
			for k := range z.AddressBook.Addresses {
				out = append(out, k)
			}
			sort.Strings(out)
			return out
		}
		return nil
	}
	globalAddrs := func(t *testing.T, body string) []string {
		t.Helper()
		tree, errs := NewParser("security { address-book { " + body + " } }").Parse()
		if len(errs) > 0 {
			t.Fatalf("parse %q: %v", body, errs)
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("compile %q: %v", body, err)
		}
		if cfg.Security.AddressBook == nil {
			return nil
		}
		var out []string
		for k := range cfg.Security.AddressBook.Addresses {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}

	for _, tc := range []struct {
		name           string
		braced, elided string
		global         bool
	}{
		{"zone-one", "address-book { address a1 10.0.0.1/32; }", "address-book address a1 10.0.0.1/32;", false},
		{"zone-two", "address-book { address a1 10.0.0.1/32; address a2 10.0.0.2/32; }", "address-book address a1 10.0.0.1/32 address a2 10.0.0.2/32;", false},
		{"global-one", "global { address a1 10.0.0.1/32; }", "global address a1 10.0.0.1/32;", true},
		{"global-two", "global { address a1 10.0.0.1/32; address a2 10.0.0.2/32; }", "global address a1 10.0.0.1/32 address a2 10.0.0.2/32;", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			get := zoneAddrs
			if tc.global {
				get = globalAddrs
			}
			b, e := get(t, tc.braced), get(t, tc.elided)
			// LIVENESS: an equality assertion needs one beside it, or both arms
			// producing nothing satisfies it perfectly.
			if len(b) == 0 {
				t.Fatalf("the BRACED reference produced no addresses, so comparing "+
					"it with the elided form proves nothing: %q", tc.braced)
			}
			if strings.Join(b, ",") != strings.Join(e, ",") {
				t.Errorf("elided address-book differs from braced (#8850)\n"+
					"  braced %q -> %v\n  elided %q -> %v\n"+
					"An entry lost here yields a policy referencing an address that "+
					"does not exist -- the policy still reads as correct. If only the "+
					"LAST entry survives, the container is missing packedStatements: "+
					"the scope entry alone folds a multi-statement run into one.",
					tc.braced, b, tc.elided, e)
			}
		})
	}

	// The head that already worked, kept as a control: it shares the container
	// and must not regress.
	t.Run("address-set-still-folds", func(t *testing.T) {
		tree, _ := NewParser("security { zones { security-zone trust { address-book address-set s1 { address a1; } } } }").Parse()
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		for _, z := range cfg.Security.Zones {
			if z.AddressBook == nil || len(z.AddressBook.AddressSets) == 0 {
				t.Error("`address-book address-set s1 { ... }` no longer folds; it " +
					"was admitted before #8850 and is the within-container control " +
					"that isolated `address` as an admission problem")
			}
		}
	})
}

// #8850 REGRESSION. Opting the address books in to the #8768 split made the
// splitter cut through `address-set`, which is args:1 WITH children -- a
// CONTAINER. Everything after a container head in a packed run is that
// container's elided BODY, not a sibling, and splitting it reparented the data:
//
//	security { address-book { global address-set s1 address a1; } }
//	  master  set:s1(members=[a1])
//	  broken  set:s1(members=[])  PLUS a top-level address a1 with NO prefix
//
// The set still EXISTED, just empty, with a phantom address beside it. That is
// the missing-becomes-EMPTY inversion this whole issue exists to avoid, and it
// was silent on BOTH paths -- strict and lenient both accept it.
//
// It also shows why the #8768 pair guard could not see it: that cell spells the
// set BRACED (`address-set s1 { address a1; }`), which lands in the decline
// branch and never reaches the splitter. The ELIDED spelling is a different
// path through the same container, so this cell asserts on it directly.
func TestPackedAddressSetKeepsItsMembers8850(t *testing.T) {
	for _, tc := range []struct{ name, txt string }{
		{"global-elided", "security { address-book { global address-set s1 address a1; } }"},
		{"global-braced", "security { address-book { global { address-set s1 address a1; } } }"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, errs := NewParser(tc.txt).Parse()
			if len(errs) > 0 {
				t.Fatalf("parse: %v", errs)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			if cfg.Security.AddressBook == nil {
				t.Fatalf("no global address book compiled from %q", tc.txt)
			}
			set, ok := cfg.Security.AddressBook.AddressSets["s1"]
			if !ok {
				t.Fatalf("address-set s1 absent from %q", tc.txt)
			}
			// The set EXISTING is not the assertion -- it existed while broken.
			if len(set.Addresses) != 1 || set.Addresses[0] != "a1" {
				t.Errorf("address-set s1 lost its member: got %v, want [a1] (#8850)\n"+
					"  %s\nA container head in a packed run owns everything after "+
					"it; splitting there turns its body into siblings and leaves "+
					"the set EMPTY but present.", set.Addresses, tc.txt)
			}
			// The member must NOT also appear as a top-level address.
			if _, phantom := cfg.Security.AddressBook.Addresses["a1"]; phantom {
				t.Errorf("`a1` was reparented into a top-level address entry as "+
					"well as (or instead of) a member of s1 (#8850): %s", tc.txt)
			}
		})
	}
}
