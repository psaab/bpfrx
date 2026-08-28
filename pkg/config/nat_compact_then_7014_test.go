package config

import "testing"

// #7014: the fully-compact authoring `then source-nat off;` packs every token
// onto the `then` node itself, so the compilers — which look for a
// `source-nat` / `destination-nat` CHILD — found nothing and produced ZERO
// actions. The zero-action arm then rejected the rule with a message saying it
// "carries no translation action", for a stanza that visibly carries one.
//
// It failed CLOSED, so no traffic was mishandled; the cost was a legal Junos
// spelling that would not commit, refused with a diagnostic contradicting the
// config in front of the operator.
//
// Flat-set is unaffected and is asserted as such below: SetPath builds the
// child, so `set … then source-nat off` produces the hierarchical shape.
func TestCompactThenCarriesItsAction_7014(t *testing.T) {
	snat := func(then string) string {
		return `
security { nat { source {
  pool P { address 203.0.113.5; }
  rule-set RS { from zone trust; to zone untrust;
    rule R1 { match { source-address 10.0.0.0/24; } ` + then + ` } } } } }
`
	}
	dnat := func(then string) string {
		return `
security { nat { destination {
  pool PD { address 10.0.0.5; }
  rule-set RD { from zone untrust;
    rule R1 { match { destination-address 198.51.100.1/32; } ` + then + ` } } } } }
`
	}
	for _, tc := range []struct {
		name      string
		src       string
		dest      bool
		wantOff   bool
		wantPool  string
		wantIface bool
	}{
		// The defect proper. Each of these compiled to zero actions and was
		// REJECTED before this change.
		{name: "compact source-nat off", src: snat("then source-nat off;"), wantOff: true},
		{name: "compact source-nat pool", src: snat("then source-nat pool P;"), wantPool: "P"},
		{name: "compact source-nat interface", src: snat("then source-nat interface;"), wantIface: true},
		{name: "compact destination-nat off", src: dnat("then destination-nat off;"), dest: true, wantOff: true},
		{name: "compact destination-nat pool", src: dnat("then destination-nat pool PD;"), dest: true, wantPool: "PD"},

		// CONTROLS. These already worked and must be bit-identical, or the fix
		// would be indistinguishable from one that changed the block form too.
		{name: "block source-nat off (control)", src: snat("then { source-nat off; }"), wantOff: true},
		{name: "block source-nat pool (control)", src: snat("then { source-nat pool P; }"), wantPool: "P"},
		{name: "block destination-nat pool (control)", src: dnat("then { destination-nat pool PD; }"), dest: true, wantPool: "PD"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, errs := NewParser(tc.src).Parse()
			if len(errs) > 0 {
				t.Fatalf("parse: %v", errs)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig REJECTED a rule that carries an action: %v", err)
			}
			var got NATThen
			if tc.dest {
				got = cfg.Security.NAT.Destination.RuleSets[0].Rules[0].Then
			} else {
				got = cfg.Security.NAT.Source[0].Rules[0].Then
			}
			if got.Off != tc.wantOff || got.PoolName != tc.wantPool || got.Interface != tc.wantIface {
				t.Errorf("Then = {Off:%v Interface:%v PoolName:%q}, want {Off:%v Interface:%v PoolName:%q}",
					got.Off, got.Interface, got.PoolName, tc.wantOff, tc.wantIface, tc.wantPool)
			}
			// The count is what the zero-action arm reads, so assert it
			// directly: a Then that carries the right field but counts 0 would
			// still be rejected, and the field assertion alone cannot see that.
			if n := natThenTerminalActionCount(got); n != 1 {
				t.Errorf("natThenTerminalActionCount = %d, want 1", n)
			}
		})
	}
}

// The flat-set path builds the child, so it never had the defect. Asserted so
// the fix cannot be "corrected" later by routing flat-set through the packed
// reader, which would put two spellings on one code path for no reason.
func TestFlatSetThenIsUnaffected_7014(t *testing.T) {
	tree := &ConfigTree{}
	for _, ln := range []string{
		"set security nat source pool P address 203.0.113.5",
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
		"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
		"set security nat source rule-set RS rule R1 then source-nat off",
	} {
		path, err := ParseSetCommand(ln)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", ln, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", ln, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	got := cfg.Security.NAT.Source[0].Rules[0].Then
	if !got.Off || got.PoolName != "" || got.Interface {
		t.Errorf("flat-set Then = {Off:%v Interface:%v PoolName:%q}, want off only",
			got.Off, got.Interface, got.PoolName)
	}
}

// The packed CONTRADICTION in the compact spelling must behave exactly as it
// does one level down in `then { source-nat pool P off; }` — first token wins,
// counted as ONE action, committed. That uniformity is the reason the compact
// reader takes the first token instead of accumulating: #7033 owns the packed
// class, its gate message names it as the open case, and narrowing it in one
// spelling only would make that message half-false.
//
// If #7033 is fixed, this expectation changes with it — update this case
// together with TestNATTerminalActionPackedContradictionCommits_7034 and the
// gate's message; do not delete it.
func TestCompactThenPackedContradictionMatchesTheChildSpelling_7014(t *testing.T) {
	src := func(then string) string {
		return `
security { nat { source {
  pool P { address 203.0.113.5; }
  rule-set RS { from zone trust; to zone untrust;
    rule R1 { match { source-address 10.0.0.0/24; } ` + then + ` } } } } }
`
	}
	for _, tc := range []struct{ name, then string }{
		{"compact", "then source-nat pool P off;"},
		{"child (the shape #7034 pins)", "then { source-nat pool P off; }"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, errs := NewParser(src(tc.then)).Parse()
			if len(errs) > 0 {
				t.Fatalf("parse: %v", errs)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("strict CompileConfig REJECTED %q; if #7033 is fixed, update this "+
					"case with TestNATTerminalActionPackedContradictionCommits_7034 and the "+
					"gate message: %v", tc.then, err)
			}
			got := cfg.Security.NAT.Source[0].Rules[0].Then
			if got.PoolName != "P" || got.Off {
				t.Errorf("Then = {Off:%v PoolName:%q}, want {Off:false PoolName:\"P\"} — the "+
					"two packed spellings must resolve identically (#7014/#7033)",
					got.Off, got.PoolName)
			}
			if n := natThenTerminalActionCount(got); n != 1 {
				t.Errorf("natThenTerminalActionCount = %d, want 1", n)
			}
		})
	}
}
