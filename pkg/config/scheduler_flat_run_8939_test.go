package config

import "testing"

// #8939: a scheduler day window dropped every leaf after the first of a flat
// `set` command.
//
//	set schedulers scheduler s1 monday all-day exclude
//	  -> allDay=true  exclude=FALSE
//
//	[monday]
//	  [all-day]
//	    [exclude start-time 08:00:00]     <- ONE node, a FLAT RUN
//
// A dropped `exclude` inverts the day: the scheduler reports the window as
// ACTIVE on a day the operator excluded, and any policy bound to it applies
// when it should not.
//
// ONE EXTRACTOR SERVES `daily` AND ALL SEVEN WEEKDAYS -- schedulerWindowFromNode,
// two call sites -- so this is one fix for the whole family. Measured before
// relying on it, because the same assumption was FALSE for the gateway pair
// (compileIKE and compileIPsec duplicate their reader).
//
// THE #8939 CENSUS CANNOT WITNESS THIS FIX, and the reason is a defect in the
// generator rather than in the fix. Its leaf-eligibility filter is
// `children == nil && wildcard == nil && !multi` -- it does NOT require
// `args >= 1` -- so `all-day` and `exclude`, both args:0, are eligible and are
// handed a synthetic VALUE they cannot take:
//
//	generator  monday all-day xpfval exclude xpfval   -> exclude=false
//	operator   monday all-day exclude                 -> exclude=true
//
// The generator's row is a command no operator writes and that no correct fix
// should accept, so those rows are unclearable by construction. This cell
// asserts the spelling that is real.
func TestSchedulerFlatRunKeepsEveryLeaf8939(t *testing.T) {
	build := func(t *testing.T, cmds ...string) *SchedulerDayWindow {
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
		for _, s := range cfg.Schedulers {
			if d := s.Days["monday"]; d != nil {
				return d
			}
		}
		return nil
	}

	base := "set schedulers scheduler s1 monday "

	// REFERENCE ARM: separate commands, the spelling that always worked.
	ref := build(t, base+"all-day", base+"exclude", base+"start-time 08:00:00")
	if ref == nil || !ref.AllDay || !ref.Exclude || ref.StartTime == "" {
		t.Fatalf("the split reference arm is incomplete (%+v) -- every comparison "+
			"below would pass against a window that carries nothing (#8939)", ref)
	}

	for _, tc := range []struct {
		name, cmd string
		wantStart bool
	}{
		{"two leaves", base + "all-day exclude", false},
		// THE CASE A RECURSIVE DESCENT FAILS: at three leaves the remainder
		// packs onto ONE node's Keys.
		{"three leaves", base + "all-day exclude start-time 08:00:00", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := build(t, tc.cmd)
			if got == nil {
				t.Fatalf("the packed command produced no monday window (#8939)")
			}
			if !got.AllDay {
				t.Errorf("all-day lost (#8939)")
			}
			if !got.Exclude {
				t.Errorf("exclude lost — the scheduler reports the day ACTIVE when " +
					"the operator excluded it, and any policy bound to it applies " +
					"when it should not (#8939)")
			}
			if tc.wantStart && got.StartTime != ref.StartTime {
				t.Errorf("start-time = %q, want %q — the THIRD leaf of the run. A "+
					"recursive descent reads the second and drops this one (#8939)",
					got.StartTime, ref.StartTime)
			}
		})
	}
}

// The same extractor serves `daily`, so one fix must cover it — asserted rather
// than assumed from the shared call.
func TestSchedulerDailyFlatRunKeepsEveryLeaf8939(t *testing.T) {
	tree := &ConfigTree{}
	for _, c := range []string{
		"set schedulers scheduler s2 daily all-day exclude",
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
	for _, s := range cfg.Schedulers {
		if s.Name != "s2" {
			continue
		}
		if !s.AllDay {
			t.Errorf("daily all-day lost in the packed spelling (#8939)")
		}
		return
	}
	t.Fatal("scheduler s2 did not compile (#8939)")
}
