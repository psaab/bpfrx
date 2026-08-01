package config

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// #6588: a chassis-cluster redundancy-group monitor authored in the PACKED
// hierarchical spelling — one statement directly under `redundancy-group`, no
// nested block — compiled to NOTHING.
//
//	redundancy-group 1 {
//	    interface-monitor ge-0/0/0 weight 255;   <- packed
//	}
//
// The parser produces ONE leaf with Keys=["interface-monitor","ge-0/0/0",
// "weight","255"] and NO children, while compileChassis enumerated monitors by
// iterating child.Children only. Result: rgs=1, monitors=0. `commit` succeeded
// with no error and no warning, so the operator had link tracking configured
// and a redundancy group that never demoted on link-down — a failover
// FAIL-OPEN. The same drop hit `ip-monitoring` (packed global-weight /
// global-threshold, and a packed `family inet <addr> weight <n>` target), which
// installs demotion debt through the very same election path.
//
// This is the chassis-cluster instance of the #2419 / #3843 dual-shape class:
// a compiler reading a statement that may pack inline MUST read the node's own
// Keys tail as well as its Children.
//
// FAIL-ON-REVERT: restore the `range child.Children` enumeration in
// compileChassis and every Packed subtest below fails with an assertion naming
// the missing monitor / target. The Hierarchical and FlatSet subtests are the
// negative control — they exercise only the shapes that already worked and
// stay GREEN with and without the fix.

// packedIfMonConfig returns a hierarchical config text whose redundancy group
// carries rgBody verbatim.
func packedMonitorConfig(rgBody string) string {
	return `chassis {
    cluster {
        authentication-key test-cluster-psk-6588;
        cluster-id 1;
        redundancy-group 1 {
            node 0 priority 200;
` + rgBody + `
        }
    }
}`
}

// compileMonitorText parses hierarchical config text and returns the single
// compiled redundancy group.
func compileMonitorText(t *testing.T, text string) *RedundancyGroup {
	t.Helper()
	p := NewParser(text)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return onlyRG6588(t, cfg)
}

func onlyRG6588(t *testing.T, cfg *Config) *RedundancyGroup {
	t.Helper()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		t.Fatal("compiled config carries no chassis cluster")
	}
	rgs := cfg.Chassis.Cluster.RedundancyGroups
	if len(rgs) != 1 {
		t.Fatalf("expected 1 redundancy-group, got %d", len(rgs))
	}
	return rgs[0]
}

func describeMonitors(mons []*InterfaceMonitor) string {
	if len(mons) == 0 {
		return "<none>"
	}
	parts := make([]string, 0, len(mons))
	for _, m := range mons {
		parts = append(parts, fmt.Sprintf("%s weight %d", m.Interface, m.Weight))
	}
	return strings.Join(parts, ", ")
}

// TestChassisInterfaceMonitorAllThreeSpellings_6588 pins that the flat-set,
// container-hierarchical and packed-hierarchical spellings of the SAME
// interface-monitor all compile to the SAME typed monitor.
func TestChassisInterfaceMonitorAllThreeSpellings_6588(t *testing.T) {
	// Negative control: the two shapes that already worked before the fix.
	t.Run("FlatSet", func(t *testing.T) {
		tree := buildTree(t, []string{
			"set chassis cluster cluster-id 1",
			"set chassis cluster authentication-key test-cluster-psk-6588",
			"set chassis cluster redundancy-group 1 node 0 priority 200",
			"set chassis cluster redundancy-group 1 interface-monitor ge-0/0/0 weight 255",
		})
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		assertSingleMonitor(t, onlyRG6588(t, cfg), "ge-0/0/0", 255)
	})
	t.Run("ContainerHierarchical", func(t *testing.T) {
		rg := compileMonitorText(t, packedMonitorConfig(
			"            interface-monitor {\n                ge-0/0/0 weight 255;\n            }"))
		assertSingleMonitor(t, rg, "ge-0/0/0", 255)
	})

	// The #6588 defect: the packed one-liner.
	t.Run("Packed", func(t *testing.T) {
		rg := compileMonitorText(t, packedMonitorConfig(
			"            interface-monitor ge-0/0/0 weight 255;"))
		assertSingleMonitor(t, rg, "ge-0/0/0", 255)
	})
}

func assertSingleMonitor(t *testing.T, rg *RedundancyGroup, iface string, weight int) {
	t.Helper()
	if len(rg.InterfaceMonitors) != 1 {
		t.Fatalf("expected exactly 1 interface-monitor (%s weight %d), got %d: %s — "+
			"a redundancy group with zero compiled monitors never demotes on link-down",
			iface, weight, len(rg.InterfaceMonitors), describeMonitors(rg.InterfaceMonitors))
	}
	m := rg.InterfaceMonitors[0]
	if m.Interface != iface || m.Weight != weight {
		t.Fatalf("monitor = %s weight %d, want %s weight %d",
			m.Interface, m.Weight, iface, weight)
	}
}

// TestChassisInterfaceMonitorPackedMultiple_6588 pins that several packed
// one-liners under the same redundancy group each produce their own monitor —
// the shape a hand-written config uses for a multi-link group.
func TestChassisInterfaceMonitorPackedMultiple_6588(t *testing.T) {
	rg := compileMonitorText(t, packedMonitorConfig(
		"            interface-monitor ge-0/0/0 weight 255;\n"+
			"            interface-monitor ge-0/0/1 weight 100;"))
	if len(rg.InterfaceMonitors) != 2 {
		t.Fatalf("expected 2 interface-monitors, got %d: %s",
			len(rg.InterfaceMonitors), describeMonitors(rg.InterfaceMonitors))
	}
	want := map[string]int{"ge-0/0/0": 255, "ge-0/0/1": 100}
	for _, m := range rg.InterfaceMonitors {
		w, ok := want[m.Interface]
		if !ok {
			t.Fatalf("unexpected monitor %s in %s", m.Interface, describeMonitors(rg.InterfaceMonitors))
		}
		if m.Weight != w {
			t.Fatalf("monitor %s weight = %d, want %d", m.Interface, m.Weight, w)
		}
		delete(want, m.Interface)
	}
	if len(want) != 0 {
		t.Fatalf("monitors missing from the compiled group: %v (got %s)",
			want, describeMonitors(rg.InterfaceMonitors))
	}
}

// TestChassisInterfaceMonitorPackedNoWeight_6588 pins the weight-less packed
// spelling: it must still produce a monitor (with the pre-existing 0 default),
// not vanish.
func TestChassisInterfaceMonitorPackedNoWeight_6588(t *testing.T) {
	rg := compileMonitorText(t, packedMonitorConfig(
		"            interface-monitor ge-0/0/0;"))
	assertSingleMonitor(t, rg, "ge-0/0/0", 0)
}

// TestChassisInterfaceMonitorPackedNestedWeight_6588 pins the packed instance
// with a nested weight block — `interface-monitor ge-0/0/0 { weight 255; }`.
// The interface name packs onto the statement keys while the weight arrives as
// a child, so both halves must be read.
func TestChassisInterfaceMonitorPackedNestedWeight_6588(t *testing.T) {
	rg := compileMonitorText(t, packedMonitorConfig(
		"            interface-monitor ge-0/0/0 {\n                weight 255;\n            }"))
	assertSingleMonitor(t, rg, "ge-0/0/0", 255)
}

// TestChassisInterfaceMonitorPackedWeightRangeGated_6588 pins the issue's
// second-order consequence: because the packed shape compiled to zero
// monitors, the #6549 weight range gate — which runs on the COMPILED int —
// never saw a packed weight, so an out-of-range one was accepted at commit.
// Now that the packed shape compiles, the existing gate covers it for free.
func TestChassisInterfaceMonitorPackedWeightRangeGated_6588(t *testing.T) {
	for _, weight := range []int{-100, -1, 256, 1000} {
		t.Run(fmt.Sprintf("weight_%d", weight), func(t *testing.T) {
			text := packedMonitorConfig(fmt.Sprintf(
				"            interface-monitor ge-0/0/0 weight %d;", weight))
			p := NewParser(text)
			tree, perrs := p.Parse()
			if len(perrs) > 0 {
				t.Fatalf("parse: %v", perrs)
			}
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected commit to reject the packed out-of-range "+
					"interface-monitor weight %d (#6549 gates the compiled int), got nil error",
					weight)
			}
			if !strings.Contains(err.Error(), "interface-monitor ge-0/0/0") {
				t.Fatalf("error %q does not name the offending interface-monitor", err)
			}
			if !strings.Contains(err.Error(), "out of range 0..255") {
				t.Fatalf("error %q does not state the admitted range", err)
			}
		})
	}
}

// TestChassisIPMonitoringPackedShapes_6588 covers the sibling site: the same
// Children-only enumeration dropped a packed `ip-monitoring` statement and a
// packed `family inet <addr> weight <n>` target. ip-monitoring installs
// redundancy-group demotion debt through the same election path as
// interface-monitor, so the fail-open is identical in kind.
func TestChassisIPMonitoringPackedShapes_6588(t *testing.T) {
	tests := []struct {
		name       string
		rgBody     string
		wantWeight int
		wantThresh int
		wantAddr   string
		wantTgtWgt int
	}{
		// Negative control: the fully-hierarchical shapes that already worked.
		{
			name: "ControlNestedFamilyBlock",
			rgBody: "            ip-monitoring {\n" +
				"                global-weight 255;\n" +
				"                global-threshold 2;\n" +
				"                family {\n" +
				"                    inet {\n" +
				"                        10.0.1.1 weight 100;\n" +
				"                    }\n" +
				"                }\n" +
				"            }",
			wantWeight: 255, wantThresh: 2, wantAddr: "10.0.1.1", wantTgtWgt: 100,
		},
		{
			name: "ControlCompoundFamilyBlock",
			rgBody: "            ip-monitoring {\n" +
				"                global-weight 255;\n" +
				"                global-threshold 2;\n" +
				"                family inet {\n" +
				"                    10.0.1.1 weight 100;\n" +
				"                }\n" +
				"            }",
			wantWeight: 255, wantThresh: 2, wantAddr: "10.0.1.1", wantTgtWgt: 100,
		},
		// #6588: packed spellings.
		{
			name: "PackedFamilyLeafInsideBlock",
			rgBody: "            ip-monitoring {\n" +
				"                global-weight 255;\n" +
				"                global-threshold 2;\n" +
				"                family inet 10.0.1.1 weight 100;\n" +
				"            }",
			wantWeight: 255, wantThresh: 2, wantAddr: "10.0.1.1", wantTgtWgt: 100,
		},
		{
			name: "PackedInetLeafInsideFamilyBlock",
			rgBody: "            ip-monitoring {\n" +
				"                global-weight 255;\n" +
				"                global-threshold 2;\n" +
				"                family {\n" +
				"                    inet 10.0.1.1 weight 100;\n" +
				"                }\n" +
				"            }",
			wantWeight: 255, wantThresh: 2, wantAddr: "10.0.1.1", wantTgtWgt: 100,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rg := compileMonitorText(t, packedMonitorConfig(tc.rgBody))
			if rg.IPMonitoring == nil {
				t.Fatal("redundancy group carries no compiled ip-monitoring — " +
					"a dropped stanza never demotes the group on probe failure")
			}
			if rg.IPMonitoring.GlobalWeight != tc.wantWeight {
				t.Fatalf("global-weight = %d, want %d", rg.IPMonitoring.GlobalWeight, tc.wantWeight)
			}
			if rg.IPMonitoring.GlobalThreshold != tc.wantThresh {
				t.Fatalf("global-threshold = %d, want %d", rg.IPMonitoring.GlobalThreshold, tc.wantThresh)
			}
			if len(rg.IPMonitoring.Targets) != 1 {
				t.Fatalf("expected exactly 1 ip-monitoring target (%s weight %d), got %d",
					tc.wantAddr, tc.wantTgtWgt, len(rg.IPMonitoring.Targets))
			}
			got := rg.IPMonitoring.Targets[0]
			if got.Address != tc.wantAddr || got.Weight != tc.wantTgtWgt {
				t.Fatalf("target = %s weight %d, want %s weight %d",
					got.Address, got.Weight, tc.wantAddr, tc.wantTgtWgt)
			}
		})
	}
}

// TestChassisIPMonitoringFullyPacked_6588 covers the one-liner form where the
// whole ip-monitoring statement packs onto a single line.
func TestChassisIPMonitoringFullyPacked_6588(t *testing.T) {
	t.Run("GlobalWeightOnly", func(t *testing.T) {
		rg := compileMonitorText(t, packedMonitorConfig(
			"            ip-monitoring global-weight 255;"))
		if rg.IPMonitoring == nil {
			t.Fatal("redundancy group carries no compiled ip-monitoring")
		}
		if rg.IPMonitoring.GlobalWeight != 255 {
			t.Fatalf("global-weight = %d, want 255", rg.IPMonitoring.GlobalWeight)
		}
	})
	t.Run("FamilyTargetOnly", func(t *testing.T) {
		rg := compileMonitorText(t, packedMonitorConfig(
			"            ip-monitoring family inet 10.0.1.1 weight 100;"))
		if rg.IPMonitoring == nil {
			t.Fatal("redundancy group carries no compiled ip-monitoring")
		}
		if len(rg.IPMonitoring.Targets) != 1 {
			t.Fatalf("expected exactly 1 ip-monitoring target, got %d",
				len(rg.IPMonitoring.Targets))
		}
		got := rg.IPMonitoring.Targets[0]
		if got.Address != "10.0.1.1" || got.Weight != 100 {
			t.Fatalf("target = %s weight %d, want 10.0.1.1 weight 100", got.Address, got.Weight)
		}
	})
}

// ---------------------------------------------------------------------------
// #6588 review round 2 — three MAJORs found inside the code this PR touched.
// ---------------------------------------------------------------------------

// compileMonitorTextErr is compileMonitorText's counterpart for configs that
// must be REJECTED at strict commit.
func compileMonitorTextErr(t *testing.T, text string) error {
	t.Helper()
	p := NewParser(text)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	_, err := CompileConfig(tree)
	return err
}

func flatMonitorTree(t *testing.T, extra ...string) *ConfigTree {
	t.Helper()
	return buildTree(t, append([]string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6588",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
	}, extra...))
}

// MAJOR 1 -------------------------------------------------------------------

// TestChassisIPMonitoringWeightRangeGated_6588 pins that the ip-monitoring
// weights are range-gated in ALL THREE spellings.
//
// #6549 deliberately left these to their typed schema leaves
// (ValidateInteger(0,255)) instead of the compiled-int gate it added for
// interface-monitor. That was sound while the packed spelling compiled to
// nothing — but SchemaValidate walks the AST from setSchema and a packed
// statement sits BELOW the depth it reaches (pinned by
// TestChassisPackedShapeBypassesSchemaWalk_6588), so once #6588 made the packed
// shape compile, an out-of-range packed weight would have reached the runtime
// with no commit-side gate on any path. The gate now lives on the compiled int
// beside its interface-monitor sibling, which is the only layer all three
// spellings pass through.
func TestChassisIPMonitoringWeightRangeGated_6588(t *testing.T) {
	for _, bad := range []struct {
		what  string
		want  string
		flat  string
		cont  string
		packd string
	}{
		{
			what: "global-weight", want: "global-weight 300 is out of range 0..255",
			flat: "set chassis cluster redundancy-group 1 ip-monitoring global-weight 300",
			cont: "            ip-monitoring {\n                global-weight 300;\n            }",
			packd: "            ip-monitoring global-weight 300;",
		},
		{
			what: "global-threshold", want: "global-threshold 256 is out of range 0..255",
			flat: "set chassis cluster redundancy-group 1 ip-monitoring global-threshold 256",
			cont: "            ip-monitoring {\n                global-threshold 256;\n            }",
			packd: "            ip-monitoring global-threshold 256;",
		},
		{
			what: "target weight", want: "family inet 10.0.1.1 weight -100 is out of range 0..255",
			flat: "set chassis cluster redundancy-group 1 ip-monitoring family inet 10.0.1.1 weight -100",
			cont: "            ip-monitoring {\n                family {\n                    inet {\n                        10.0.1.1 weight -100;\n                    }\n                }\n            }",
			packd: "            ip-monitoring family inet 10.0.1.1 weight -100;",
		},
	} {
		t.Run(bad.what+"/FlatSet", func(t *testing.T) {
			_, err := CompileConfig(flatMonitorTree(t, bad.flat))
			assertErrContains(t, err, bad.want)
		})
		t.Run(bad.what+"/ContainerHierarchical", func(t *testing.T) {
			assertErrContains(t, compileMonitorTextErr(t, packedMonitorConfig(bad.cont)), bad.want)
		})
		t.Run(bad.what+"/Packed", func(t *testing.T) {
			assertErrContains(t, compileMonitorTextErr(t, packedMonitorConfig(bad.packd)), bad.want)
		})
	}
}

// TestChassisIPMonitoringInRangeStillCommits_6588 is the MAJOR-1 negative
// control: every legal ip-monitoring value, including both boundaries, must
// still commit AND compile verbatim. It passes with and without the gate.
func TestChassisIPMonitoringInRangeStillCommits_6588(t *testing.T) {
	for _, w := range []int{0, 1, 128, 254, 255} {
		t.Run(fmt.Sprintf("weight_%d", w), func(t *testing.T) {
			rg := compileMonitorText(t, packedMonitorConfig(fmt.Sprintf(
				"            ip-monitoring {\n"+
					"                global-weight %d;\n"+
					"                global-threshold %d;\n"+
					"                family inet {\n"+
					"                    10.0.1.1 weight %d;\n"+
					"                }\n"+
					"            }", w, w, w)))
			if rg.IPMonitoring == nil {
				t.Fatal("redundancy group carries no compiled ip-monitoring")
			}
			if rg.IPMonitoring.GlobalWeight != w || rg.IPMonitoring.GlobalThreshold != w {
				t.Fatalf("global-weight/threshold = %d/%d, want %d/%d (the gate must not alter an in-range value)",
					rg.IPMonitoring.GlobalWeight, rg.IPMonitoring.GlobalThreshold, w, w)
			}
			if len(rg.IPMonitoring.Targets) != 1 || rg.IPMonitoring.Targets[0].Weight != w {
				t.Fatalf("targets = %+v, want one target with weight %d", rg.IPMonitoring.Targets, w)
			}
		})
	}
}

// TestChassisPackedShapeBypassesSchemaWalk_6588 is the load-bearing evidence
// for WHERE the MAJOR-1 gate had to go: the typed-leaf gate cannot see a packed
// statement, so a schema validator can never cover it. SchemaValidate accepts
// an ip-monitoring weight the compiled-int gate rejects.
func TestChassisPackedShapeBypassesSchemaWalk_6588(t *testing.T) {
	p := NewParser(packedMonitorConfig("            ip-monitoring family inet 10.0.1.1 weight -100;"))
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("SchemaValidate unexpectedly saw the packed statement (%v) — if the typed "+
			"leaf now reaches it, the compiled-int gate's rationale needs revisiting", err)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("the compiled-int gate must reject what SchemaValidate cannot see")
	}
}

// MAJOR 2 -------------------------------------------------------------------

// TestChassisInterfaceMonitorBracketList_6588 pins the #2419 bracketed-list
// collapse for monitors. The lexer strips `[`/`]`, so
// `interface-monitor [ ge-0/0/0 ge-0/0/1 ge-0/0/2 ]` lands as N names on ONE
// node's Keys in EVERY spelling. Compiling only the first name is the same
// failover fail-open as dropping the statement, one monitor at a time.
func TestChassisInterfaceMonitorBracketList_6588(t *testing.T) {
	want := []string{"ge-0/0/0", "ge-0/0/1", "ge-0/0/2"}

	t.Run("FlatSet", func(t *testing.T) {
		cfg, err := CompileConfig(flatMonitorTree(t,
			"set chassis cluster redundancy-group 1 interface-monitor [ ge-0/0/0 ge-0/0/1 ge-0/0/2 ]"))
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		assertMonitorNames(t, onlyRG6588(t, cfg), want)
	})
	t.Run("ContainerHierarchical", func(t *testing.T) {
		assertMonitorNames(t, compileMonitorText(t, packedMonitorConfig(
			"            interface-monitor {\n                [ ge-0/0/0 ge-0/0/1 ge-0/0/2 ];\n            }")), want)
	})
	t.Run("Packed", func(t *testing.T) {
		assertMonitorNames(t, compileMonitorText(t, packedMonitorConfig(
			"            interface-monitor [ ge-0/0/0 ge-0/0/1 ge-0/0/2 ];")), want)
	})
	// A weight-less bracketed list must still yield one monitor per name.
	t.Run("PackedNoWeight", func(t *testing.T) {
		assertMonitorNames(t, compileMonitorText(t, packedMonitorConfig(
			"            interface-monitor [ ge-0/0/0 ge-0/0/1 ];")), []string{"ge-0/0/0", "ge-0/0/1"})
	})
}

// TestChassisIPMonitoringBracketTargets_6588 covers the same collapse on the
// ip-monitoring target list.
func TestChassisIPMonitoringBracketTargets_6588(t *testing.T) {
	rg := compileMonitorText(t, packedMonitorConfig(
		"            ip-monitoring family inet [ 10.0.1.1 10.0.2.1 10.0.3.1 ];"))
	if rg.IPMonitoring == nil {
		t.Fatal("redundancy group carries no compiled ip-monitoring")
	}
	var got []string
	for _, tg := range rg.IPMonitoring.Targets {
		got = append(got, tg.Address)
	}
	want := []string{"10.0.1.1", "10.0.2.1", "10.0.3.1"}
	if len(got) != len(want) {
		t.Fatalf("ip-monitoring targets = %v, want %v — a bracketed list must compile to one "+
			"target per address", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ip-monitoring targets = %v, want %v", got, want)
		}
	}
}

// TestChassisInterfaceMonitorSingleEntryNotSplit_6588 is the MAJOR-2 negative
// control the review asked for: a single NON-bracketed packed monitor must
// still compile to exactly ONE entry, with its weight intact. The splitter must
// not shred `ge-0/0/0 weight 255` into an entry per token. Passes with and
// without the split.
func TestChassisInterfaceMonitorSingleEntryNotSplit_6588(t *testing.T) {
	t.Run("PackedWithWeight", func(t *testing.T) {
		assertSingleMonitor(t, compileMonitorText(t, packedMonitorConfig(
			"            interface-monitor ge-0/0/0 weight 255;")), "ge-0/0/0", 255)
	})
	t.Run("ContainerWithWeight", func(t *testing.T) {
		assertSingleMonitor(t, compileMonitorText(t, packedMonitorConfig(
			"            interface-monitor {\n                ge-0/0/0 weight 255;\n            }")), "ge-0/0/0", 255)
	})
	t.Run("PackedNestedWeightBlock", func(t *testing.T) {
		assertSingleMonitor(t, compileMonitorText(t, packedMonitorConfig(
			"            interface-monitor ge-0/0/0 {\n                weight 255;\n            }")), "ge-0/0/0", 255)
	})
	t.Run("FlatSetWithWeight", func(t *testing.T) {
		cfg, err := CompileConfig(flatMonitorTree(t,
			"set chassis cluster redundancy-group 1 interface-monitor ge-0/0/0 weight 255"))
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		assertSingleMonitor(t, onlyRG6588(t, cfg), "ge-0/0/0", 255)
	})
	t.Run("SingleIPMonitorTarget", func(t *testing.T) {
		rg := compileMonitorText(t, packedMonitorConfig(
			"            ip-monitoring family inet 10.0.1.1 weight 100;"))
		if rg.IPMonitoring == nil || len(rg.IPMonitoring.Targets) != 1 {
			t.Fatalf("expected exactly 1 ip-monitoring target, got %+v", rg.IPMonitoring)
		}
		if got := rg.IPMonitoring.Targets[0]; got.Address != "10.0.1.1" || got.Weight != 100 {
			t.Fatalf("target = %s weight %d, want 10.0.1.1 weight 100", got.Address, got.Weight)
		}
	})
}

// MAJOR 4 -------------------------------------------------------------------

// TestChassisMonitorWeightMalformedRejected_6588 pins that a weight which is
// PRESENT but not an integer is rejected at commit in every spelling. Before
// the gate it compiled to the 0 default: the operator configured link tracking,
// commit succeeded, and the monitor going down deducted NOTHING — the same
// silent-nothing class as the packed-statement drop this PR fixes. The compiled
// struct cannot express it (a failed Atoi is indistinguishable from `weight 0`),
// so the check runs on the AST.
func TestChassisMonitorWeightMalformedRejected_6588(t *testing.T) {
	const want = `weight "nope" is not an integer`

	t.Run("InterfaceMonitor/FlatSet", func(t *testing.T) {
		_, err := CompileConfig(flatMonitorTree(t,
			"set chassis cluster redundancy-group 1 interface-monitor ge-0/0/0 weight nope"))
		assertErrContains(t, err, want)
	})
	t.Run("InterfaceMonitor/ContainerHierarchical", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedMonitorConfig(
			"            interface-monitor {\n                ge-0/0/0 weight nope;\n            }")), want)
	})
	t.Run("InterfaceMonitor/Packed", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedMonitorConfig(
			"            interface-monitor ge-0/0/0 weight nope;")), want)
	})
	t.Run("InterfaceMonitor/PackedNestedWeightBlock", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedMonitorConfig(
			"            interface-monitor ge-0/0/0 {\n                weight nope;\n            }")), want)
	})
	t.Run("InterfaceMonitor/WeightWithNoValue", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedMonitorConfig(
			"            interface-monitor ge-0/0/0 weight;")), `weight "" is not an integer`)
	})
	t.Run("IPMonitoringTarget/Packed", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedMonitorConfig(
			"            ip-monitoring family inet 10.0.1.1 weight nope;")), want)
	})
	t.Run("IPMonitoringTarget/ContainerHierarchical", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedMonitorConfig(
			"            ip-monitoring {\n                family inet {\n                    10.0.1.1 weight nope;\n                }\n            }")), want)
	})
}

// TestChassisMonitorWeightMalformedTolerantNoBrick_6588 pins the #1960 posture:
// an already-persisted or peer-synced config carrying a malformed weight must
// still BOOT, with a warning.
func TestChassisMonitorWeightMalformedTolerantNoBrick_6588(t *testing.T) {
	p := NewParser(packedMonitorConfig("            interface-monitor ge-0/0/0 weight nope;"))
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not reject a malformed monitor weight (no-brick), got %v", err)
	}
	if !warningsContain(cfg.Warnings, `weight "nope" is not an integer`) {
		t.Fatalf("lenient compile should have warned; warnings=%v", cfg.Warnings)
	}
	// The monitor itself still compiles, with the documented 0 default.
	assertSingleMonitor(t, onlyRG6588(t, cfg), "ge-0/0/0", 0)
}

// TestChassisMonitorWeightValidStillCommits_6588 is the MAJOR-4 negative
// control: a well-formed weight — and a monitor with no weight at all, the
// documented 0 default from #6549 — must still commit. Passes with and without
// the gate.
func TestChassisMonitorWeightValidStillCommits_6588(t *testing.T) {
	for _, w := range []int{0, 1, 128, 255} {
		t.Run(fmt.Sprintf("weight_%d", w), func(t *testing.T) {
			assertSingleMonitor(t, compileMonitorText(t, packedMonitorConfig(fmt.Sprintf(
				"            interface-monitor ge-0/0/0 weight %d;", w))), "ge-0/0/0", w)
		})
	}
	t.Run("NoWeightAtAll", func(t *testing.T) {
		assertSingleMonitor(t, compileMonitorText(t, packedMonitorConfig(
			"            interface-monitor ge-0/0/0;")), "ge-0/0/0", 0)
	})
}

// Duplicates ----------------------------------------------------------------

// TestChassisMonitorWeightDuplicateRejected_6588 pins that a duplicate weight
// is rejected rather than resolved differently per spelling. Before the gate,
// `weight 100 weight 200` inline compiled to 200 (the inline scan overwrote)
// while `{ weight 100; weight 200; }` compiled to 100 (FindChild returns the
// first) — the answer depended on how the operator happened to write it.
func TestChassisMonitorWeightDuplicateRejected_6588(t *testing.T) {
	const want = "weight specified 2 times with different values"

	t.Run("InlineTail", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedMonitorConfig(
			"            interface-monitor ge-0/0/0 weight 100 weight 200;")), want)
	})
	t.Run("NestedBlock", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedMonitorConfig(
			"            interface-monitor ge-0/0/0 {\n                weight 100;\n                weight 200;\n            }")), want)
	})
	t.Run("InlineAndNested", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedMonitorConfig(
			"            interface-monitor ge-0/0/0 weight 100 {\n                weight 200;\n            }")), want)
	})
	t.Run("IdenticalRepeat", func(t *testing.T) {
		// Same value twice is still ambiguous authoring, but the message must
		// not claim a value conflict that does not exist.
		err := compileMonitorTextErr(t, packedMonitorConfig(
			"            interface-monitor ge-0/0/0 weight 100 weight 100;"))
		assertErrContains(t, err, "weight specified 2 times")
		if err != nil && strings.Contains(err.Error(), "different values") {
			t.Fatalf("error %q claims differing values for an identical repeat", err)
		}
	})
}

func assertErrContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected commit to be rejected with %q, got nil error", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not contain %q", err, want)
	}
}

func assertMonitorNames(t *testing.T, rg *RedundancyGroup, want []string) {
	t.Helper()
	assertMonitors(t, rg, want, nil)
}

// assertMonitors compares the compiled monitors by NAME and, when wantWeights
// is non-nil, by WEIGHT.
//
// The weight arm exists because its absence hid a regression: the original
// name-only helper let `interface-monitor [ ge-0/0/0 ge-0/0/1 ] weight 255`
// compile to ge-0/0/0=0, ge-0/0/1=255 with every bracket test green. A monitor
// that exists with weight 0 deducts nothing when its link fails, so the group
// does not demote — the same runtime outcome as no monitor at all, which is
// exactly what these tests are supposed to be watching for. Never assert a
// monitor list by name alone.
func assertMonitors(t *testing.T, rg *RedundancyGroup, want []string, wantWeights []int) {
	t.Helper()
	if len(rg.InterfaceMonitors) != len(want) {
		t.Fatalf("expected %d interface-monitors %v, got %d: %s — a bracketed list must "+
			"compile to one monitor per name, not one monitor for the first name",
			len(want), want, len(rg.InterfaceMonitors), describeMonitors(rg.InterfaceMonitors))
	}
	for i, w := range want {
		if rg.InterfaceMonitors[i].Interface != w {
			t.Fatalf("monitor[%d] = %q, want %q (got %s)",
				i, rg.InterfaceMonitors[i].Interface, w, describeMonitors(rg.InterfaceMonitors))
		}
	}
	for i := range wantWeights {
		if got := rg.InterfaceMonitors[i].Weight; got != wantWeights[i] {
			t.Fatalf("monitor %s weight = %d, want %d (got %s) — a monitor compiled at "+
				"weight 0 deducts NOTHING when its link fails, so the redundancy group "+
				"does not demote",
				rg.InterfaceMonitors[i].Interface, got, wantWeights[i],
				describeMonitors(rg.InterfaceMonitors))
		}
	}
}

// ---------------------------------------------------------------------------
// #6588 review round 3 — the same Children-only bug ONE LEVEL UP.
// ---------------------------------------------------------------------------

// packedRGConfig returns hierarchical config text carrying clusterBody directly
// under `cluster`, so the redundancy-group statement itself can be written in
// the packed form. Everything here is driven through the REAL parser
// (NewParser -> CompileConfig): a hand-built AST would let the test assume the
// node shape instead of observing it, which is exactly the mistake that let
// this shape survive two review rounds.
func packedRGConfig(clusterBody string) string {
	return `chassis {
    cluster {
        authentication-key test-cluster-psk-6588;
        cluster-id 1;
` + clusterBody + `
    }
}`
}

func compileRGText(t *testing.T, text string) *RedundancyGroup {
	t.Helper()
	p := NewParser(text)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return onlyRG6588(t, cfg)
}

// TestChassisRedundancyGroupPackedBody_6588 pins the one-level-up packed
// spelling: the whole redundancy-group body written on the instance line.
//
//	redundancy-group 1 interface-monitor ge-0/0/0 weight 255;
//
// namedInstances resolves the instance NAME across both shapes (it reads
// Keys[1]) but returns the node with the body still on Keys, so a caller
// walking `.Children` saw an EMPTY group and compiled every statement to
// nothing — with no error.
//
// The `node <id> priority <p>` case is the severe one: it is the redundancy-
// group election priority. Dropped, the operator sets a priority, sees it
// echoed by `show configuration`, and the cluster elects on defaults — so the
// WRONG NODE can hold the group, a superset of "the group never demotes".
//
// FAIL-ON-REVERT: change redundancyGroupBody back to rgNode.Children and every
// Packed subtest below fails with an assertion naming the lost statement.
func TestChassisRedundancyGroupPackedBody_6588(t *testing.T) {
	t.Run("InterfaceMonitor", func(t *testing.T) {
		rg := compileRGText(t, packedRGConfig(
			"        redundancy-group 1 interface-monitor ge-0/0/0 weight 255;"))
		if len(rg.InterfaceMonitors) != 1 {
			t.Fatalf("packed redundancy-group body lost `interface-monitor ge-0/0/0 weight 255`: "+
				"got %d monitors (%s)", len(rg.InterfaceMonitors), describeMonitors(rg.InterfaceMonitors))
		}
		if rg.InterfaceMonitors[0].Interface != "ge-0/0/0" || rg.InterfaceMonitors[0].Weight != 255 {
			t.Fatalf("monitor = %s, want ge-0/0/0 weight 255", describeMonitors(rg.InterfaceMonitors))
		}
	})

	t.Run("NodePriority", func(t *testing.T) {
		rg := compileRGText(t, packedRGConfig(
			"        redundancy-group 1 node 0 priority 200;"))
		if got, ok := rg.NodePriorities[0]; !ok || got != 200 {
			t.Fatalf("packed redundancy-group body lost `node 0 priority 200`: NodePriorities = %v — "+
				"a dropped election priority means the cluster elects on defaults and the WRONG "+
				"node can hold the group", rg.NodePriorities)
		}
	})

	t.Run("Preempt", func(t *testing.T) {
		rg := compileRGText(t, packedRGConfig("        redundancy-group 1 preempt;"))
		if !rg.Preempt {
			t.Fatal("packed redundancy-group body lost `preempt`: Preempt = false")
		}
	})

	t.Run("StrictVIPOwnership", func(t *testing.T) {
		rg := compileRGText(t, packedRGConfig("        redundancy-group 1 strict-vip-ownership;"))
		if !rg.StrictVIPOwnership {
			t.Fatal("packed redundancy-group body lost `strict-vip-ownership`")
		}
	})

	t.Run("GratuitousARPCount", func(t *testing.T) {
		rg := compileRGText(t, packedRGConfig("        redundancy-group 1 gratuitous-arp-count 8;"))
		if rg.GratuitousARPCount != 8 {
			t.Fatalf("packed redundancy-group body lost `gratuitous-arp-count 8`: got %d",
				rg.GratuitousARPCount)
		}
	})

	t.Run("IPMonitoring", func(t *testing.T) {
		rg := compileRGText(t, packedRGConfig(
			"        redundancy-group 1 ip-monitoring global-weight 255;"))
		if rg.IPMonitoring == nil {
			t.Fatal("packed redundancy-group body lost `ip-monitoring global-weight 255`: IPMonitoring is nil")
		}
		if rg.IPMonitoring.GlobalWeight != 255 {
			t.Fatalf("global-weight = %d, want 255", rg.IPMonitoring.GlobalWeight)
		}
	})

	// Several statements on one instance line must each survive — the tail is
	// split at redundancy-group statement keywords, not folded into the first.
	t.Run("MultipleStatementsOnOneLine", func(t *testing.T) {
		rg := compileRGText(t, packedRGConfig(
			"        redundancy-group 1 node 0 priority 200 preempt gratuitous-arp-count 8;"))
		if got, ok := rg.NodePriorities[0]; !ok || got != 200 {
			t.Fatalf("lost `node 0 priority 200` from a multi-statement packed body: %v", rg.NodePriorities)
		}
		if !rg.Preempt {
			t.Fatal("lost `preempt` from a multi-statement packed body")
		}
		if rg.GratuitousARPCount != 8 {
			t.Fatalf("lost `gratuitous-arp-count 8` from a multi-statement packed body: got %d",
				rg.GratuitousARPCount)
		}
	})
}

// TestChassisRedundancyGroupContainerBodyUnchanged_6588 is the round-3 negative
// control: the already-working container form must compile exactly as before,
// every statement intact. It passes with and without redundancyGroupBody.
func TestChassisRedundancyGroupContainerBodyUnchanged_6588(t *testing.T) {
	rg := compileRGText(t, packedRGConfig(
		"        redundancy-group 1 {\n"+
			"            node 0 priority 200;\n"+
			"            node 1 priority 100;\n"+
			"            preempt;\n"+
			"            strict-vip-ownership;\n"+
			"            gratuitous-arp-count 8;\n"+
			"            interface-monitor ge-0/0/0 weight 255;\n"+
			"            ip-monitoring {\n"+
			"                global-weight 200;\n"+
			"                family inet {\n"+
			"                    10.0.1.1 weight 100;\n"+
			"                }\n"+
			"            }\n"+
			"        }"))
	if rg.NodePriorities[0] != 200 || rg.NodePriorities[1] != 100 {
		t.Fatalf("NodePriorities = %v, want {0:200, 1:100}", rg.NodePriorities)
	}
	if !rg.Preempt || !rg.StrictVIPOwnership {
		t.Fatalf("preempt=%v strict-vip-ownership=%v, want both true", rg.Preempt, rg.StrictVIPOwnership)
	}
	if rg.GratuitousARPCount != 8 {
		t.Fatalf("gratuitous-arp-count = %d, want 8", rg.GratuitousARPCount)
	}
	if len(rg.InterfaceMonitors) != 1 || rg.InterfaceMonitors[0].Weight != 255 {
		t.Fatalf("monitors = %s, want one ge-0/0/0 weight 255", describeMonitors(rg.InterfaceMonitors))
	}
	if rg.IPMonitoring == nil || rg.IPMonitoring.GlobalWeight != 200 ||
		len(rg.IPMonitoring.Targets) != 1 || rg.IPMonitoring.Targets[0].Weight != 100 {
		t.Fatalf("ip-monitoring = %+v, want global-weight 200 with one target weight 100", rg.IPMonitoring)
	}
}

// TestChassisRedundancyGroupPackedBodyReachesGates_6588 pins that the round-2
// gates see the one-level-up packed shape too. Making the body compile without
// bringing the gates along would admit, through the packed instance line
// only, exactly what round 2 closed everywhere else.
func TestChassisRedundancyGroupPackedBodyReachesGates_6588(t *testing.T) {
	t.Run("MalformedWeightStillRejected", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedRGConfig(
			"        redundancy-group 1 interface-monitor ge-0/0/0 weight nope;")),
			`weight "nope" is not an integer`)
	})
	t.Run("OutOfRangeWeightStillRejected", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedRGConfig(
			"        redundancy-group 1 interface-monitor ge-0/0/0 weight 300;")),
			"weight 300 is out of range 0..255")
	})
	t.Run("DuplicateWeightStillRejected", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedRGConfig(
			"        redundancy-group 1 interface-monitor ge-0/0/0 weight 100 weight 200;")),
			"weight specified 2 times with different values")
	})
	t.Run("BracketListStillSplits", func(t *testing.T) {
		assertMonitorNames(t, compileRGText(t, packedRGConfig(
			"        redundancy-group 1 interface-monitor [ ge-0/0/0 ge-0/0/1 ];")),
			[]string{"ge-0/0/0", "ge-0/0/1"})
	})
	t.Run("IPMonitoringRangeStillGated", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedRGConfig(
			"        redundancy-group 1 ip-monitoring global-weight 300;")),
			"global-weight 300 is out of range 0..255")
	})
	// #5694 identity gate: a malformed RG-scoped node id must still be caught
	// when the whole body is packed onto the instance line.
	t.Run("MalformedNodeIDStillRejected", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedRGConfig(
			"        redundancy-group 1 node bogus priority 200;")),
			"redundancy-group node")
	})
}

// TestRedundancyGroupStatementPredicateCoversCompiler_6588 is a DRIFT GUARD on
// the hand-written isRedundancyGroupStatement token list.
//
// redundancyGroupBody splits a packed instance tail at that list. A token
// missing from it is not a loud failure: the statement's tokens are appended to
// whichever statement precedes it on the line, so it silently does nothing —
// the exact class of defect this whole issue is about, with better camouflage.
// A list that merely LOOKS complete today also drifts the moment someone adds a
// `case` to compileChassis without touching the predicate.
//
// So the set is not re-asserted by hand here. It is DERIVED from the compiler
// itself: this parses compileChassis's own source, extracts every `case "..."`
// of the switch that dispatches redundancy-group body statements, and requires
// the predicate to accept each one. Adding an arm without extending the
// predicate fails this test with the missing token named.
//
// If the parse cannot find the switch the test FAILS rather than silently
// passing on an empty set — a guard that can quietly verify nothing is worse
// than no guard.
func TestRedundancyGroupStatementPredicateCoversCompiler_6588(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "compiler_system.go", nil, 0)
	if err != nil {
		t.Fatalf("parse compiler_system.go: %v", err)
	}

	var fn *ast.FuncDecl
	for _, d := range file.Decls {
		if f, ok := d.(*ast.FuncDecl); ok && f.Name.Name == "compileChassis" {
			fn = f
			break
		}
	}
	if fn == nil {
		t.Fatal("compileChassis not found in compiler_system.go — this guard cannot verify " +
			"the statement list; fix the guard rather than deleting it")
	}

	// Find the switch whose tag is `child.Name()` — the redundancy-group body
	// dispatch. Keyed on the tag rather than on position so reordering the
	// function does not silently blind the guard.
	var arms []string
	ast.Inspect(fn, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok || sw.Tag == nil {
			return true
		}
		call, ok := sw.Tag.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Name" {
			return true
		}
		if ident, ok := sel.X.(*ast.Ident); !ok || ident.Name != "child" {
			return true
		}
		for _, stmt := range sw.Body.List {
			cc, ok := stmt.(*ast.CaseClause)
			if !ok {
				continue
			}
			for _, e := range cc.List {
				lit, ok := e.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				v, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("unquote case literal %s: %v", lit.Value, err)
				}
				arms = append(arms, v)
			}
		}
		return false
	})

	if len(arms) == 0 {
		t.Fatal("found no `case \"...\"` arms on compileChassis's `switch child.Name()` — " +
			"the guard has lost track of the compiler and is verifying nothing; fix it")
	}
	// Sanity floor: the arms known at the time this guard was written. Guards
	// against the Inspect above latching onto some other, smaller switch.
	if len(arms) < 6 {
		t.Fatalf("found only %d redundancy-group statement arms %v — expected at least the 6 "+
			"known ones; the guard is probably reading the wrong switch", len(arms), arms)
	}

	for _, arm := range arms {
		if !isRedundancyGroupStatement(arm) {
			t.Errorf("compileChassis handles redundancy-group statement %q but "+
				"isRedundancyGroupStatement does not list it — a packed instance line carrying "+
				"it (`redundancy-group 1 ... %s ...;`) folds its tokens into the PRECEDING "+
				"statement and silently does nothing. Add %q to isRedundancyGroupStatement.",
				arm, arm, arm)
		}
	}
}

// ---------------------------------------------------------------------------
// #6588 review round 5 — a regression this branch introduced, and a second
// namedInstances node shape the fixed skip did not cover.
// ---------------------------------------------------------------------------

// TestChassisInterfaceMonitorBracketInlineWeight_6588 pins MAJOR-A: a trailing
// inline weight on a bracketed list applies to EVERY member.
//
// The entry splitter originally attached a `weight` token to the entry
// immediately preceding it, which is the obvious reading and is wrong here:
// `[ ge-0/0/0 ge-0/0/1 ] weight 255` compiled ge-0/0/0 at weight ZERO. That is
// WORSE than master, which compiled one monitor at 255 and dropped the rest —
// master at least protected ge-0/0/0. With N names, N-1 monitors were inert:
// present in `show`, deducting nothing on link-down, group never demotes.
//
// The chosen semantics is apply-to-all, matching the children-block spelling
// `[ a b ] { weight 255; }` (which already applied 255 to both) and the
// fail-safe rule monitorEntryNodes documents. It is also strictly better than
// master on this input: no member is dropped and no weight is lost.
//
// FAIL-ON-REVERT: attach the weight to split[len(split)-1] again and every
// subtest below fails naming the zero-weight monitor.
func TestChassisInterfaceMonitorBracketInlineWeight_6588(t *testing.T) {
	t.Run("FlatSetTwoNames", func(t *testing.T) {
		cfg, err := CompileConfig(flatMonitorTree(t,
			"set chassis cluster redundancy-group 1 interface-monitor [ ge-0/0/0 ge-0/0/1 ] weight 255"))
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		assertMonitors(t, onlyRG6588(t, cfg),
			[]string{"ge-0/0/0", "ge-0/0/1"}, []int{255, 255})
	})
	t.Run("FlatSetThreeNames", func(t *testing.T) {
		cfg, err := CompileConfig(flatMonitorTree(t,
			"set chassis cluster redundancy-group 1 interface-monitor [ ge-0/0/0 ge-0/0/1 ge-0/0/2 ] weight 100"))
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		assertMonitors(t, onlyRG6588(t, cfg),
			[]string{"ge-0/0/0", "ge-0/0/1", "ge-0/0/2"}, []int{100, 100, 100})
	})
	t.Run("ContainerHierarchical", func(t *testing.T) {
		assertMonitors(t, compileMonitorText(t, packedMonitorConfig(
			"            interface-monitor [ ge-0/0/0 ge-0/0/1 ] weight 255;")),
			[]string{"ge-0/0/0", "ge-0/0/1"}, []int{255, 255})
	})
	t.Run("PackedInstanceLine", func(t *testing.T) {
		assertMonitors(t, compileRGText(t, packedRGConfig(
			"        redundancy-group 1 interface-monitor [ ge-0/0/0 ge-0/0/1 ] weight 255;")),
			[]string{"ge-0/0/0", "ge-0/0/1"}, []int{255, 255})
	})

	// NEGATIVE CONTROL: the children-block spelling already applied the weight
	// to every member and must keep doing so. Green with and without the fix.
	t.Run("ControlChildrenBlockWeight", func(t *testing.T) {
		assertMonitors(t, compileMonitorText(t, packedMonitorConfig(
			"            interface-monitor [ ge-0/0/0 ge-0/0/1 ] {\n                weight 255;\n            }")),
			[]string{"ge-0/0/0", "ge-0/0/1"}, []int{255, 255})
	})
	// NEGATIVE CONTROL: a single name with an inline weight is unaffected by
	// how the attribute is scoped. Green in both worlds.
	t.Run("ControlSingleNameInlineWeight", func(t *testing.T) {
		assertMonitors(t, compileMonitorText(t, packedMonitorConfig(
			"            interface-monitor ge-0/0/0 weight 255;")),
			[]string{"ge-0/0/0"}, []int{255})
	})
	// A weight-less list still compiles every member at the documented 0
	// default — apply-to-all must not invent a weight.
	t.Run("ControlNoWeightStaysZero", func(t *testing.T) {
		assertMonitors(t, compileMonitorText(t, packedMonitorConfig(
			"            interface-monitor [ ge-0/0/0 ge-0/0/1 ];")),
			[]string{"ge-0/0/0", "ge-0/0/1"}, []int{0, 0})
	})
	// The out-of-range gate sees every member, not just the last.
	t.Run("OutOfRangeRejectedForAllMembers", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedMonitorConfig(
			"            interface-monitor [ ge-0/0/0 ge-0/0/1 ] weight 300;")),
			"interface-monitor ge-0/0/0 weight 300 is out of range 0..255")
	})
	// Two inline weights in one bracketed statement are ambiguous about which
	// member each belongs to. Master silently took the LAST and dropped every
	// member but the first; rejecting is loud and matches the round-2
	// duplicate-weight gate.
	t.Run("AmbiguousPerMemberWeightsRejected", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedMonitorConfig(
			"            interface-monitor [ ge-0/0/0 weight 100 ge-0/0/1 weight 200 ];")),
			"weight specified 2 times with different values")
	})
}

// TestChassisIPMonitoringBracketInlineWeight_6588 pins the same semantics on
// the ip-monitoring target list, which shares monitorEntryNodes.
func TestChassisIPMonitoringBracketInlineWeight_6588(t *testing.T) {
	rg := compileMonitorText(t, packedMonitorConfig(
		"            ip-monitoring family inet [ 10.0.1.1 10.0.2.1 ] weight 100;"))
	if rg.IPMonitoring == nil || len(rg.IPMonitoring.Targets) != 2 {
		t.Fatalf("expected 2 ip-monitoring targets, got %+v", rg.IPMonitoring)
	}
	for _, tgt := range rg.IPMonitoring.Targets {
		if tgt.Weight != 100 {
			t.Fatalf("target %s weight = %d, want 100 — a target compiled at weight 0 "+
				"deducts nothing when the probe fails", tgt.Address, tgt.Weight)
		}
	}
}

// TestChassisRedundancyGroupBareContainerShape_6588 pins MAJOR-B: the SECOND
// node shape namedInstances returns.
//
// namedInstances yields either the `redundancy-group <id>` node itself
// (Keys[0]=="redundancy-group", so the body starts at Keys[2]) or, for a bare
// `redundancy-group { ... }` wrapper, a CHILD whose Keys[0] IS the instance id
// (so the body starts at Keys[1]). redundancyGroupBody used a fixed skip of 2,
// which on the second shape swallowed the statement KEYWORD and opened a node
// named after a value — matching no switch arm, so every statement was dropped
// exactly as in round 1, election priority included.
//
// Reachability through the shipped parser is lower than the round-1 shape (no
// Junos output and no SetPath path emits a bare wrapper), but this is fixed
// rather than documented: the guard covers all four redundancyGroupBody
// readers, so leaving it would make the three AST gates blind here while
// LOOKING like they covered it.
//
// FAIL-ON-REVERT: pin skip back to 2 and every subtest fails naming the lost
// statement.
func TestChassisRedundancyGroupBareContainerShape_6588(t *testing.T) {
	t.Run("PackedInterfaceMonitor", func(t *testing.T) {
		assertMonitors(t, compileRGText(t, packedRGConfig(
			"        redundancy-group {\n            1 interface-monitor ge-0/0/0 weight 255;\n        }")),
			[]string{"ge-0/0/0"}, []int{255})
	})
	t.Run("PackedNodePriority", func(t *testing.T) {
		rg := compileRGText(t, packedRGConfig(
			"        redundancy-group {\n            1 node 0 priority 200;\n        }"))
		if got, ok := rg.NodePriorities[0]; !ok || got != 200 {
			t.Fatalf("bare `redundancy-group { 1 node 0 priority 200; }` lost the election "+
				"priority: NodePriorities = %v", rg.NodePriorities)
		}
	})
	t.Run("PackedPreempt", func(t *testing.T) {
		rg := compileRGText(t, packedRGConfig(
			"        redundancy-group {\n            1 preempt;\n        }"))
		if !rg.Preempt {
			t.Fatal("bare `redundancy-group { 1 preempt; }` lost `preempt`")
		}
	})
	t.Run("GatesStillReachIt", func(t *testing.T) {
		assertErrContains(t, compileMonitorTextErr(t, packedRGConfig(
			"        redundancy-group {\n            1 interface-monitor ge-0/0/0 weight nope;\n        }")),
			`weight "nope" is not an integer`)
	})
	// NEGATIVE CONTROL: the nested-block form under a bare wrapper already
	// worked (its body arrives as real children) and must be unchanged. Green
	// with and without the fix.
	t.Run("ControlBareWrapperNestedBlock", func(t *testing.T) {
		assertMonitors(t, compileRGText(t, packedRGConfig(
			"        redundancy-group {\n            1 {\n                interface-monitor ge-0/0/0 weight 255;\n            }\n        }")),
			[]string{"ge-0/0/0"}, []int{255})
	})
	// NEGATIVE CONTROL: the ordinary `redundancy-group <id>` shape still uses
	// skip 2. Green in both worlds.
	t.Run("ControlOrdinaryInstanceShape", func(t *testing.T) {
		assertMonitors(t, compileRGText(t, packedRGConfig(
			"        redundancy-group 1 interface-monitor ge-0/0/0 weight 255;")),
			[]string{"ge-0/0/0"}, []int{255})
	})
}
