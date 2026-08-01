package config

import (
	"fmt"
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
