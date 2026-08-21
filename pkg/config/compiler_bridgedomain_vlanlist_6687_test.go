package config

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

// #6687 — `bridge-domains <bd> vlan-id-list` was read and VALIDATED at slot 0
// only, so every value past the first was both dropped from the compiled
// config and never seen by the leaf's only validator. `[ 10 99999 ]` and
// `[ 10 notanumber ]` committed CLEAN while the identical bad value in slot 0
// was correctly rejected.
//
// These tests pin three separate properties, because a fix can land for one
// and miss the others:
//
//  1. VALUE PARITY. All five authorable spellings compile the SAME id list.
//  2. GATE COVERAGE. A bad value in slot 1 is rejected by the SAME validator
//     that rejects it in slot 0 — asserted on the validator's own message, not
//     on `err != nil`, so a different gate firing cannot be mistaken for this
//     one having run.
//  3. SEVERITY SPLIT. The tolerant load / peer-sync path warns and drops the
//     one bad value instead of refusing the whole config, so a config that
//     committed clean under the narrower gate still boots after upgrade.

// bdCompile compiles a hierarchical (brace) config on the requested path.
func bdCompile(t *testing.T, body string, lenient bool) (*Config, error) {
	t.Helper()
	p := NewParser(body)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse %q: %v", body, errs)
	}
	if lenient {
		return CompileConfigLenient(tree)
	}
	return CompileConfig(tree)
}

// bdCompileSet compiles a flat-set config on the requested path, going through
// ParseSetCommand + SetPath exactly as `set` / `load set` / display-set replay
// does. NewParser must NOT be used for set syntax: it treats newlines as
// whitespace and merges every line into one node.
func bdCompileSet(t *testing.T, lenient bool, cmds ...string) (*Config, error) {
	t.Helper()
	tree := &ConfigTree{}
	for _, c := range cmds {
		path, err := ParseSetCommand(c)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", c, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", c, err)
		}
	}
	if lenient {
		return CompileConfigLenient(tree)
	}
	return CompileConfig(tree)
}

func bdVlanIDs(t *testing.T, cfg *Config, name string) []int {
	t.Helper()
	for _, bd := range cfg.BridgeDomains {
		if bd.Name == name {
			return bd.VlanIDs
		}
	}
	t.Fatalf("bridge-domain %q not compiled (have %d domains)", name, len(cfg.BridgeDomains))
	return nil
}

func bdEqual(got []int, want ...int) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestBridgeDomainVlanIDListEverySpelling is property (1). Before #6687 the
// three BRACKET/BLOCK spellings compiled [10] while the two REPEATED ones
// compiled [10 20] — a shape-dependent drop on the leaf whose idiomatic Junos
// spelling is the bracketed list, i.e. the drop hit the common path.
func TestBridgeDomainVlanIDListEverySpelling(t *testing.T) {
	t.Run("A-hier-bracket", func(t *testing.T) {
		cfg, err := bdCompile(t, `bridge-domains { bd1 { vlan-id-list [ 10 20 ]; } }`, false)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		if got := bdVlanIDs(t, cfg, "bd1"); !bdEqual(got, 10, 20) {
			t.Fatalf("VlanIDs = %v, want [10 20]", got)
		}
	})
	t.Run("B-hier-block", func(t *testing.T) {
		cfg, err := bdCompile(t, `bridge-domains { bd1 { vlan-id-list { 10; 20; } } }`, false)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		if got := bdVlanIDs(t, cfg, "bd1"); !bdEqual(got, 10, 20) {
			t.Fatalf("VlanIDs = %v, want [10 20]", got)
		}
	})
	t.Run("C-hier-repeat", func(t *testing.T) {
		cfg, err := bdCompile(t, `bridge-domains { bd1 { vlan-id-list 10; vlan-id-list 20; } }`, false)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		if got := bdVlanIDs(t, cfg, "bd1"); !bdEqual(got, 10, 20) {
			t.Fatalf("VlanIDs = %v, want [10 20]", got)
		}
	})
	t.Run("D-set-bracket", func(t *testing.T) {
		cfg, err := bdCompileSet(t, false, `set bridge-domains bd1 vlan-id-list [ 10 20 ]`)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		if got := bdVlanIDs(t, cfg, "bd1"); !bdEqual(got, 10, 20) {
			t.Fatalf("VlanIDs = %v, want [10 20]", got)
		}
	})
	t.Run("E-set-repeat", func(t *testing.T) {
		cfg, err := bdCompileSet(t, false,
			`set bridge-domains bd1 vlan-id-list 10`,
			`set bridge-domains bd1 vlan-id-list 20`)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		if got := bdVlanIDs(t, cfg, "bd1"); !bdEqual(got, 10, 20) {
			t.Fatalf("VlanIDs = %v, want [10 20]", got)
		}
	})
	t.Run("three-values-keeps-the-tail", func(t *testing.T) {
		cfg, err := bdCompile(t, `bridge-domains { bd1 { vlan-id-list [ 10 20 30 ]; } }`, false)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		if got := bdVlanIDs(t, cfg, "bd1"); !bdEqual(got, 10, 20, 30) {
			t.Fatalf("VlanIDs = %v, want [10 20 30]", got)
		}
	})
}

// TestBridgeDomainVlanIDListValidatesEverySlot is property (2). Each case
// asserts THIS validator's own wording. A bare err != nil would pass even if
// the widened check never ran and some other gate rejected the config.
func TestBridgeDomainVlanIDListValidatesEverySlot(t *testing.T) {
	const rangeMsg = "vlan-id 99999 out of range (1-4094)"
	const parseMsg = `invalid vlan-id-list value "notanumber"`

	cases := []struct {
		name string
		set  []string // flat-set spelling, when non-nil
		body string   // hierarchical spelling, when set is nil
		want string
	}{
		// Slot 0 — the case that was ALREADY rejected. It is here so a
		// regression that disables the gate entirely cannot look like a fix.
		{name: "range/slot0/hier-bracket", body: `bridge-domains { bd1 { vlan-id-list [ 99999 10 ]; } }`, want: rangeMsg},
		{name: "parse/slot0/hier-bracket", body: `bridge-domains { bd1 { vlan-id-list [ notanumber 10 ]; } }`, want: parseMsg},

		// Slot 1 — the #6687 escape, in every spelling that carries a tail.
		{name: "range/slot1/hier-bracket", body: `bridge-domains { bd1 { vlan-id-list [ 10 99999 ]; } }`, want: rangeMsg},
		{name: "range/slot1/hier-block", body: `bridge-domains { bd1 { vlan-id-list { 10; 99999; } } }`, want: rangeMsg},
		{name: "range/slot1/hier-repeat", body: `bridge-domains { bd1 { vlan-id-list 10; vlan-id-list 99999; } }`, want: rangeMsg},
		{name: "parse/slot1/hier-bracket", body: `bridge-domains { bd1 { vlan-id-list [ 10 notanumber ]; } }`, want: parseMsg},
		{name: "parse/slot1/hier-block", body: `bridge-domains { bd1 { vlan-id-list { 10; notanumber; } } }`, want: parseMsg},
		{name: "range/slot2/hier-bracket", body: `bridge-domains { bd1 { vlan-id-list [ 10 20 99999 ]; } }`, want: rangeMsg},
		{name: "range/slot1/set-bracket", set: []string{`set bridge-domains bd1 vlan-id-list [ 10 99999 ]`}, want: rangeMsg},
		{name: "parse/slot1/set-bracket", set: []string{`set bridge-domains bd1 vlan-id-list [ 10 notanumber ]`}, want: parseMsg},
		{name: "range/slot1/set-repeat", set: []string{
			`set bridge-domains bd1 vlan-id-list 10`,
			`set bridge-domains bd1 vlan-id-list 99999`,
		}, want: rangeMsg},

		// The zero boundary: 0 is out of range at both ends of the list.
		{name: "range/zero/slot1", body: `bridge-domains { bd1 { vlan-id-list [ 10 0 ]; } }`, want: "vlan-id 0 out of range (1-4094)"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.set != nil {
				_, err = bdCompileSet(t, false, tc.set...)
			} else {
				_, err = bdCompile(t, tc.body, false)
			}
			if err == nil {
				t.Fatalf("commit accepted an invalid vlan-id-list; want rejection containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("rejected by the WRONG gate:\n  got  : %v\n  want a message containing %q", err, tc.want)
			}
		})
	}
}

// The non-numeric rejection must still WRAP strconv's error, so a caller can
// classify it with errors.Is rather than by string matching. #6687 moved the
// check inside a loop; %w had to survive that move.
func TestBridgeDomainVlanIDListWrapsStrconvError(t *testing.T) {
	_, err := bdCompile(t, `bridge-domains { bd1 { vlan-id-list [ 10 notanumber ]; } }`, false)
	if err == nil {
		t.Fatal("expected a rejection")
	}
	if !errors.Is(err, strconv.ErrSyntax) {
		t.Fatalf("error does not wrap strconv.ErrSyntax: %v", err)
	}
}

// TestBridgeDomainVlanIDListLenientDropsAndWarns is property (3). The tolerant
// load / peer-sync path must not turn a config the OLD gate accepted into a
// boot failure: it keeps the good ids, drops the bad one, and says so.
func TestBridgeDomainVlanIDListLenientDropsAndWarns(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		want    []int
		warnSub string
	}{
		{
			name:    "range-in-slot1",
			body:    `bridge-domains { bd1 { vlan-id-list [ 10 99999 20 ]; } }`,
			want:    []int{10, 20},
			warnSub: "vlan-id 99999 out of range (1-4094)",
		},
		{
			name:    "parse-in-slot1",
			body:    `bridge-domains { bd1 { vlan-id-list [ 10 notanumber ]; } }`,
			want:    []int{10},
			warnSub: `invalid vlan-id-list value "notanumber"`,
		},
		{
			// Slot 0 too: the tolerant path is uniform across slots, which is
			// the point — a persisted config must boot regardless of WHERE the
			// operator put the bad id.
			name:    "range-in-slot0",
			body:    `bridge-domains { bd1 { vlan-id-list [ 99999 10 ]; } }`,
			want:    []int{10},
			warnSub: "vlan-id 99999 out of range (1-4094)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := bdCompile(t, tc.body, true)
			if err != nil {
				t.Fatalf("tolerant load must not reject a persisted config: %v", err)
			}
			if got := bdVlanIDs(t, cfg, "bd1"); !bdEqual(got, tc.want...) {
				t.Fatalf("VlanIDs = %v, want %v", got, tc.want)
			}
			if !warningsContain(cfg.Warnings, tc.warnSub) {
				t.Fatalf("no downgraded warning naming the dropped value.\n  want substring: %q\n  warnings: %v",
					tc.warnSub, cfg.Warnings)
			}
			if !warningsContain(cfg.Warnings, "ignored: value dropped") {
				t.Fatalf("warning must say the value was dropped, got: %v", cfg.Warnings)
			}
		})
	}
}

// An empty value slot is not an id. `vlan-id-list;` carries no value at all and
// multiLeafAuthoredValues represents that as one EMPTY string — feeding it to
// strconv.Atoi would manufacture a rejection for a statement master accepted.
func TestBridgeDomainVlanIDListEmptyValueIsNotRejected(t *testing.T) {
	for _, body := range []string{
		`bridge-domains { bd1 { vlan-id-list; } }`,
		`bridge-domains { bd1 { vlan-id-list [ ]; } }`,
	} {
		cfg, err := bdCompile(t, body, false)
		if err != nil {
			t.Fatalf("%s: compile: %v", body, err)
		}
		if got := bdVlanIDs(t, cfg, "bd1"); len(got) != 0 {
			t.Fatalf("%s: VlanIDs = %v, want empty", body, got)
		}
	}
}
