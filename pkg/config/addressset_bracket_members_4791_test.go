package config

import (
	"reflect"
	"testing"
)

// #4791 RED-on-revert: an address-set member leaf (`address` / `address-set`
// under `security address-book global address-set <name>`) is `multi:true`
// in setSchema, so a bracketed member list `address [ a b c ]` collapses onto
// ONE leaf's Keys per the #2419 dual-shape pattern
// (Keys=["address","a","b","c"]). parseAddressBookEntries previously read
// only member.Keys[1], compiling just the first member and silently dropping
// the rest -- a security-relevant narrowing (or, depending on which member
// survives, an unintended broadening) of the set an operator authored.
//
// IMPORTANT (per CLAUDE.md): flat-set syntax is built with ParseSetCommand +
// tree.SetPath, never NewParser (which merges all set lines into one node).
func setTree4791(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

func TestAddressSetBracketListKeepsAllAddressMembers(t *testing.T) {
	tree := setTree4791(t,
		"set security address-book global address a 10.0.1.0/24",
		"set security address-book global address b 10.0.2.0/24",
		"set security address-book global address c 10.0.3.0/24",
		"set security address-book global address-set FOO address [ a b c ]",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	set := cfg.Security.AddressBook.AddressSets["FOO"]
	if set == nil {
		t.Fatalf("address-set FOO missing from compiled address book")
	}
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(set.Addresses, want) {
		t.Fatalf("address-set FOO members = %v, want %v (bracket-list tail dropped — #4791)",
			set.Addresses, want)
	}
}

// TestAddressSetBracketListKeepsAllNestedSetMembers mirrors the primary case
// for the `address-set` (nested-set) member branch, which has the identical
// Keys[1]-only bug.
func TestAddressSetBracketListKeepsAllNestedSetMembers(t *testing.T) {
	tree := setTree4791(t,
		"set security address-book global address a 10.0.1.0/24",
		"set security address-book global address b 10.0.2.0/24",
		"set security address-book global address-set INNER1 address a",
		"set security address-book global address-set INNER2 address b",
		"set security address-book global address-set INNER3 address a",
		"set security address-book global address-set OUTER address-set [ INNER1 INNER2 INNER3 ]",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	outer := cfg.Security.AddressBook.AddressSets["OUTER"]
	if outer == nil {
		t.Fatalf("address-set OUTER missing from compiled address book")
	}
	want := []string{"INNER1", "INNER2", "INNER3"}
	if !reflect.DeepEqual(outer.AddressSets, want) {
		t.Fatalf("address-set OUTER nested members = %v, want %v (bracket-list tail dropped — #4791)",
			outer.AddressSets, want)
	}
}

// TestAddressSetSingleMember is the negative control: a single member (no
// list) must still compile to exactly one entry, proving the fix does not
// over-collapse.
func TestAddressSetSingleMember(t *testing.T) {
	tree := setTree4791(t,
		"set security address-book global address a 10.0.1.0/24",
		"set security address-book global address-set FOO address a",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	set := cfg.Security.AddressBook.AddressSets["FOO"]
	if set == nil {
		t.Fatalf("address-set FOO missing from compiled address book")
	}
	if want := []string{"a"}; !reflect.DeepEqual(set.Addresses, want) {
		t.Fatalf("single-member address-set FOO = %v, want %v", set.Addresses, want)
	}
}
