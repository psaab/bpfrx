package config

import (
	"strings"
	"testing"
)

func TestCompileClassOfServiceHierarchical(t *testing.T) {
	input := `class-of-service {
    forwarding-classes {
        queue 0 best-effort;
        queue 1 expedited-forwarding;
    }
    schedulers {
        be-sched {
            transmit-rate 7g;
            priority low;
            buffer-size 16m;
        }
        ef-sched {
            transmit-rate 3g;
            priority strict-high;
            buffer-size 4m;
        }
    }
    scheduler-maps {
        edge-map {
            forwarding-class best-effort {
                scheduler be-sched;
            }
            forwarding-class expedited-forwarding {
                scheduler ef-sched;
            }
        }
    }
    interfaces {
        ge-0/0/1 {
            unit 0 {
                shaping-rate 10g {
                    burst-size 125m;
                }
                scheduler-map edge-map;
            }
        }
    }
}
system {
    dataplane-type userspace;
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	if cfg.ClassOfService == nil {
		t.Fatal("expected class-of-service config")
	}
	if got := cfg.ClassOfService.ForwardingClasses["best-effort"].Queue; got != 0 {
		t.Fatalf("best-effort queue = %d, want 0", got)
	}
	if got := cfg.ClassOfService.Schedulers["ef-sched"].TransmitRateBytes; got != parseBandwidthLimit("3g") {
		t.Fatalf("ef-sched transmit-rate = %d, want %d", got, parseBandwidthLimit("3g"))
	}
	if got := cfg.ClassOfService.Schedulers["ef-sched"].Priority; got != "strict-high" {
		t.Fatalf("ef-sched priority = %q, want strict-high", got)
	}
	unit := cfg.ClassOfService.Interfaces["ge-0/0/1"].Units[0]
	if unit == nil {
		t.Fatal("expected ge-0/0/1 unit 0 CoS config")
	}
	if got := unit.ShapingRateBytes; got != parseBandwidthLimit("10g") {
		t.Fatalf("shaping-rate = %d, want %d", got, parseBandwidthLimit("10g"))
	}
	if got := unit.BurstSizeBytes; got != parseBurstSizeLimit("125m") {
		t.Fatalf("burst-size = %d, want %d", got, parseBurstSizeLimit("125m"))
	}
	if got := unit.SchedulerMap; got != "edge-map" {
		t.Fatalf("scheduler-map = %q, want edge-map", got)
	}
}

func TestCompileClassOfServiceSetSyntax(t *testing.T) {
	lines := []string{
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service schedulers be-sched transmit-rate 5g",
		"set class-of-service schedulers be-sched priority low",
		"set class-of-service schedulers be-sched buffer-size 8m",
		"set class-of-service scheduler-maps edge-map forwarding-class best-effort scheduler be-sched",
		"set class-of-service interfaces ge-0/0/2 unit 80 shaping-rate 9g",
		"set class-of-service interfaces ge-0/0/2 unit 80 shaping-rate burst-size 64m",
		"set class-of-service interfaces ge-0/0/2 unit 80 scheduler-map edge-map",
		"set system dataplane-type userspace",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	unit := cfg.ClassOfService.Interfaces["ge-0/0/2"].Units[80]
	if unit == nil {
		t.Fatal("expected ge-0/0/2 unit 80 CoS config")
	}
	if got := unit.ShapingRateBytes; got != parseBandwidthLimit("9g") {
		t.Fatalf("shaping-rate = %d, want %d", got, parseBandwidthLimit("9g"))
	}
	if got := unit.SchedulerMap; got != "edge-map" {
		t.Fatalf("scheduler-map = %q, want edge-map", got)
	}
}

func TestValidateClassOfServiceWarnings(t *testing.T) {
	input := `class-of-service {
    forwarding-classes {
        queue 0 best-effort;
    }
    scheduler-maps {
        edge-map {
            forwarding-class best-effort {
                scheduler missing-sched;
            }
        }
    }
    interfaces {
        ge-0/0/1 {
            unit 0 {
                shaping-rate 10g;
                scheduler-map edge-map;
            }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	warnings := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(warnings, `scheduler-map "edge-map" references undefined scheduler "missing-sched"`) {
		t.Fatalf("expected undefined scheduler warning, got: %s", warnings)
	}
	if !strings.Contains(warnings, "class-of-service shaping is only implemented in the userspace dataplane") {
		t.Fatalf("expected dataplane warning, got: %s", warnings)
	}
}

func TestValidateClassOfServiceQueueRangeWarning(t *testing.T) {
	input := `class-of-service {
    forwarding-classes {
        queue 300 invalid-class;
    }
}
system {
    dataplane-type userspace;
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	warnings := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(warnings, `forwarding-class "invalid-class" uses out-of-range queue 300`) {
		t.Fatalf("expected queue range warning, got: %s", warnings)
	}
}
