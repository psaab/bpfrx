// #4021: an interface-level CoS binding (`class-of-service interfaces geX
// scheduler-map M` with no `unit`) must reach the per-unit InterfaceSnapshot
// the Rust dataplane consumes. The compiler folds the interface-level binding
// into the interface's configured logical units, so buildInterfaceSnapshots —
// which reads cfg.ClassOfService.Interfaces[name].Units[unitNum] — carries it
// with no interface-level awareness of its own. On revert the interface-level
// binding is dropped and CoSSchedulerMap is empty (RED).
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func compileCoSCfg4021(t *testing.T, lines []string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, line := range lines {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	return cfg
}

func TestInterfaceLevelCoSReachesSnapshot4021(t *testing.T) {
	cfg := compileCoSCfg4021(t, []string{
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service schedulers be-sched transmit-rate 5g",
		"set class-of-service scheduler-maps edge-map forwarding-class best-effort scheduler be-sched",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		// Interface-level (no unit) scheduler-map + shaping-rate.
		"set class-of-service interfaces ge-0/0/1 scheduler-map edge-map",
		"set class-of-service interfaces ge-0/0/1 shaping-rate 9g",
		"set security zones security-zone trust interfaces ge-0/0/1.0",
		"set system dataplane-type userspace",
	})

	var got *InterfaceSnapshot
	snaps := buildInterfaceSnapshots(cfg)
	for i := range snaps {
		if snaps[i].Name == "ge-0/0/1.0" {
			got = &snaps[i]
			break
		}
	}
	if got == nil {
		t.Fatal("no snapshot for ge-0/0/1.0")
	}
	if got.CoSSchedulerMap != "edge-map" {
		t.Fatalf("interface-level CoS not on snapshot: CoSSchedulerMap = %q, want edge-map", got.CoSSchedulerMap)
	}
	if got.CoSShapingRateBytesPerSec == 0 {
		t.Fatal("interface-level shaping-rate not on snapshot (0)")
	}
}
