package config

import (
	"reflect"
	"testing"
)

// Tests for #4706: two literal `address-set <name> { ... }` blocks with the
// SAME name (a hand-authored / `load override` hierarchical config) must UNION
// their members. The hierarchical parser does NOT fold sibling same-name blocks
// (unlike the flat-set `SetPath`, which descends into one existing node), so
// parseAddressBookEntries sees several `address-set S` children. Before the fix
// the second stanza did `ab.AddressSets[name] = as` — overwriting the first and
// silently dropping its members, so a policy matching S matched FEWER addresses
// than the operator intended (silent narrowing). The fix mirrors the `address`
// merge-by-name (#2222): fetch-or-create the set and append members (union,
// first-seen dedup).
//
// fail-on-revert: reverting the `address-set` case to build a fresh struct and
// overwrite (`ab.AddressSets[as.Name] = as`) drops a1 from S here, so
// TestDuplicateAddressSetBlocksUnionMembers goes RED.

// compileHierarchical parses a brace-delimited hierarchical config with the
// project parser and compiles it. NewParser is the correct tool for a
// hierarchical (brace) config — the flat-set NewParser caveat is specifically
// about newline-separated `set` lines, which this is not.
func compileHierarchical(t *testing.T, cfg string) *Config {
	t.Helper()
	tree, perrs := NewParser(cfg).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse errors: %v", perrs)
	}
	compiled, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return compiled
}

func TestDuplicateAddressSetBlocksUnionMembers(t *testing.T) {
	// Two duplicate `address-set S` blocks, each contributing a DIFFERENT
	// member (both defined as real addresses so the strict compile resolves).
	cfg := compileHierarchical(t, `
security {
    address-book {
        global {
            address A1 {
                10.0.1.0/24;
            }
            address A2 {
                10.0.2.0/24;
            }
            address-set S {
                address A1;
            }
            address-set S {
                address A2;
            }
        }
    }
}
`)
	set := cfg.Security.AddressBook.AddressSets["S"]
	if set == nil {
		t.Fatalf("address-set S missing from compiled address book")
	}
	// UNION of both stanzas — the pre-fix last-wins overwrite kept only A2.
	if want := []string{"A1", "A2"}; !reflect.DeepEqual(set.Addresses, want) {
		t.Fatalf("address-set S members = %v, want union %v (earlier stanza dropped?)",
			set.Addresses, want)
	}

	// End-to-end: a policy referencing S must resolve to BOTH member prefixes.
	// resolveAddressSetPrefixes walks the compiled book exactly as the policy
	// address resolver does; if A1 were dropped its /24 would be absent.
	got := resolveAddressSetPrefixes(cfg.Security.AddressBook, "S")
	if want := []string{"10.0.1.0/24", "10.0.2.0/24"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("policy match of address-set S resolved to %v, want all members %v", got, want)
	}
}

// TestDuplicateAddressSetBlocksUnionNestedRefs proves nested `address-set`
// references also union across duplicate stanzas (they take the same overwrite
// path the fix repairs).
func TestDuplicateAddressSetBlocksUnionNestedRefs(t *testing.T) {
	cfg := compileHierarchical(t, `
security {
    address-book {
        global {
            address A1 {
                10.0.1.0/24;
            }
            address A2 {
                10.0.2.0/24;
            }
            address-set INNER1 {
                address A1;
            }
            address-set INNER2 {
                address A2;
            }
            address-set OUTER {
                address-set INNER1;
            }
            address-set OUTER {
                address-set INNER2;
            }
        }
    }
}
`)
	outer := cfg.Security.AddressBook.AddressSets["OUTER"]
	if outer == nil {
		t.Fatalf("address-set OUTER missing")
	}
	if want := []string{"INNER1", "INNER2"}; !reflect.DeepEqual(outer.AddressSets, want) {
		t.Fatalf("OUTER nested sets = %v, want union %v", outer.AddressSets, want)
	}
	got := resolveAddressSetPrefixes(cfg.Security.AddressBook, "OUTER")
	if want := []string{"10.0.1.0/24", "10.0.2.0/24"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("nested union resolved to %v, want %v", got, want)
	}
}

// TestSingleAddressSetBlockUnchanged is the no-regression guard: a single
// address-set stanza compiles to exactly its members (identical to pre-fix).
func TestSingleAddressSetBlockUnchanged(t *testing.T) {
	cfg := compileHierarchical(t, `
security {
    address-book {
        global {
            address A1 {
                10.0.1.0/24;
            }
            address A2 {
                10.0.2.0/24;
            }
            address-set S {
                address A1;
                address A2;
            }
        }
    }
}
`)
	set := cfg.Security.AddressBook.AddressSets["S"]
	if set == nil {
		t.Fatalf("address-set S missing")
	}
	if want := []string{"A1", "A2"}; !reflect.DeepEqual(set.Addresses, want) {
		t.Fatalf("single-stanza address-set S members = %v, want %v", set.Addresses, want)
	}
}

// TestDuplicateAddressSetBlocksDedupMembers proves the union dedups a member
// listed in more than one stanza (Junos union-by-name semantics) rather than
// accumulating a duplicate reference.
func TestDuplicateAddressSetBlocksDedupMembers(t *testing.T) {
	cfg := compileHierarchical(t, `
security {
    address-book {
        global {
            address A1 {
                10.0.1.0/24;
            }
            address A2 {
                10.0.2.0/24;
            }
            address-set S {
                address A1;
            }
            address-set S {
                address A1;
                address A2;
            }
        }
    }
}
`)
	set := cfg.Security.AddressBook.AddressSets["S"]
	if want := []string{"A1", "A2"}; !reflect.DeepEqual(set.Addresses, want) {
		t.Fatalf("deduped union members = %v, want %v (A1 must appear once)", set.Addresses, want)
	}
}

// resolveAddressSetPrefixes expands an address-set to the sorted, de-duplicated
// set of address prefixes it references (following nested address-sets),
// mirroring how the policy address resolver matches a set. Returns the prefixes
// in sorted order for stable comparison.
func resolveAddressSetPrefixes(ab *AddressBook, name string) []string {
	seen := map[string]bool{}
	out := []string{}
	var walk func(ref string)
	walk = func(ref string) {
		if addr := ab.Addresses[ref]; addr != nil {
			if addr.Value != "" && !seen[addr.Value] {
				seen[addr.Value] = true
				out = append(out, addr.Value)
			}
			return
		}
		set := ab.AddressSets[ref]
		if set == nil {
			return
		}
		for _, m := range set.Addresses {
			walk(m)
		}
		for _, m := range set.AddressSets {
			walk(m)
		}
	}
	walk(name)
	// Deterministic order (members are appended first-seen; sort for a stable
	// assertion independent of walk order).
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
