package config

import "testing"

// #8939: `security flow tcp-session` dropped every leaf after the first of a
// flat `set` command.
//
//	set security flow tcp-session closing-timeout 10 established-timeout 20 initial-timeout 30
//	  -> closing=10  established=0  initial=0
//
// `initial-timeout` is the sharp one (#8971). It bounds the HALF-OPEN window,
// and an operator raising it is deliberately pinning sessions in the table; a
// dropped value silently returns that bound to the default, so the loss is a
// RESOURCE-EXHAUSTION surface rather than a cosmetic one. `established-timeout`
// going with it is the same shape on the established table.
//
// THREE LEAVES ASSERTED, because at two the chain is indistinguishable from
// ordinary nesting and a recursive descent passes. This container is the one
// where that matters most: `initial-timeout` is alphabetically THIRD, so a
// descent-shaped fix clears the two-leaf census row and leaves precisely the
// dangerous leaf still dropped.
func TestFlowTCPSessionFlatRunKeepsEveryLeaf8939(t *testing.T) {
	build := func(t *testing.T, cmds ...string) *TCPSessionConfig {
		t.Helper()
		tree := &ConfigTree{}
		for _, c := range cmds {
			p, err := ParseSetCommand(c)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", c, err)
			}
			if err := tree.SetPath(p); err != nil {
				t.Fatalf("SetPath(%q): %v", c, err)
			}
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil || cfg == nil {
			t.Fatalf("compile: %v", err)
		}
		return cfg.Security.Flow.TCPSession
	}

	b := "set security flow tcp-session "

	// REFERENCE ARM: separate commands, the spelling that always worked.
	ref := build(t, b+"closing-timeout 10", b+"established-timeout 20", b+"initial-timeout 30")
	if ref == nil || ref.ClosingTimeout == 0 || ref.EstablishedTimeout == 0 || ref.InitialTimeout == 0 {
		t.Fatalf("the split reference arm is incomplete (%+v) -- every comparison "+
			"below would pass against a config that carries nothing (#8939)", ref)
	}

	for _, tc := range []struct {
		name, cmd   string
		wantInitial bool
	}{
		{"two leaves", b + "closing-timeout 10 established-timeout 20", false},
		{"three leaves", b + "closing-timeout 10 established-timeout 20 initial-timeout 30", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := build(t, tc.cmd)
			if got == nil {
				t.Fatalf("the packed command produced no tcp-session config (#8939)")
			}
			if got.ClosingTimeout != ref.ClosingTimeout {
				t.Errorf("closing-timeout = %d, want %d (#8939)",
					got.ClosingTimeout, ref.ClosingTimeout)
			}
			if got.EstablishedTimeout != ref.EstablishedTimeout {
				t.Errorf("established-timeout = %d, want %d — the SECOND leaf, "+
					"silently returned to its default (#8939)",
					got.EstablishedTimeout, ref.EstablishedTimeout)
			}
			if tc.wantInitial && got.InitialTimeout != ref.InitialTimeout {
				t.Errorf("initial-timeout = %d, want %d — the THIRD leaf, and the "+
					"one that bounds the HALF-OPEN window. A recursive descent "+
					"reads the second and drops this one, clearing the two-leaf "+
					"census row while leaving a resource-exhaustion surface in "+
					"place (#8939)", got.InitialTimeout, ref.InitialTimeout)
			}
		})
	}
}

// A flag leaf on the same container must still compile: expandFlatRun must not
// disturb the args:0 members alongside the timeouts.
func TestFlowTCPSessionFlagsUnaffected8939(t *testing.T) {
	tree := &ConfigTree{}
	for _, c := range []string{
		"set security flow tcp-session no-syn-check",
		"set security flow tcp-session closing-timeout 10",
	} {
		p, err := ParseSetCommand(c)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", c, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", c, err)
		}
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil || cfg == nil {
		t.Fatalf("compile: %v", err)
	}
	ts := cfg.Security.Flow.TCPSession
	if ts == nil || !ts.NoSynCheck || ts.ClosingTimeout != 10 {
		t.Errorf("a flag leaf alongside a timeout did not survive: %+v (#8939)", ts)
	}
}
