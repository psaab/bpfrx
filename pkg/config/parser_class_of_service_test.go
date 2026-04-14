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
		"set class-of-service classifiers dscp wan-classifier forwarding-class best-effort loss-priority low code-points be",
		"set class-of-service classifiers ieee-802.1 wan-pcp forwarding-class best-effort loss-priority low code-points 0",
		"set class-of-service schedulers be-sched transmit-rate 5g",
		"set class-of-service schedulers be-sched transmit-rate exact",
		"set class-of-service schedulers be-sched priority low",
		"set class-of-service schedulers be-sched buffer-size 8m",
		"set class-of-service scheduler-maps edge-map forwarding-class best-effort scheduler be-sched",
		"set class-of-service interfaces ge-0/0/2 unit 80 shaping-rate 9g",
		"set class-of-service interfaces ge-0/0/2 unit 80 shaping-rate burst-size 64m",
		"set class-of-service interfaces ge-0/0/2 unit 80 scheduler-map edge-map",
		"set class-of-service interfaces ge-0/0/2 unit 80 classifiers dscp wan-classifier",
		"set class-of-service interfaces ge-0/0/2 unit 80 classifiers ieee-802.1 wan-pcp",
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
	if got := unit.DSCPClassifier; got != "wan-classifier" {
		t.Fatalf("dscp-classifier = %q, want wan-classifier", got)
	}
	if got := unit.IEEE8021Classifier; got != "wan-pcp" {
		t.Fatalf("ieee-802.1 classifier = %q, want wan-pcp", got)
	}
	if !cfg.ClassOfService.Schedulers["be-sched"].TransmitRateExact {
		t.Fatal("expected be-sched transmit-rate exact")
	}
	classifier := cfg.ClassOfService.DSCPClassifiers["wan-classifier"]
	if classifier == nil || len(classifier.Entries) != 1 {
		t.Fatalf("expected wan-classifier entry, got %#v", classifier)
	}
	if got := classifier.Entries[0].DSCPValues; len(got) != 1 || got[0] != 0 {
		t.Fatalf("wan-classifier dscp values = %v, want [0]", got)
	}
	pcpClassifier := cfg.ClassOfService.IEEE8021Classifiers["wan-pcp"]
	if pcpClassifier == nil || len(pcpClassifier.Entries) != 1 {
		t.Fatalf("expected wan-pcp entry, got %#v", pcpClassifier)
	}
	if got := pcpClassifier.Entries[0].CodePoints; len(got) != 1 || got[0] != 0 {
		t.Fatalf("wan-pcp code-points = %v, want [0]", got)
	}
}

func TestCompileClassOfServiceInlineTransmitRateExactSyntax(t *testing.T) {
	lines := []string{
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service schedulers be-sched transmit-rate 5g exact",
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
	sched := cfg.ClassOfService.Schedulers["be-sched"]
	if sched == nil {
		t.Fatal("expected be-sched scheduler")
	}
	if got := sched.TransmitRateBytes; got != parseBandwidthLimit("5g") {
		t.Fatalf("transmit-rate = %d, want %d", got, parseBandwidthLimit("5g"))
	}
	if !sched.TransmitRateExact {
		t.Fatal("expected inline transmit-rate exact")
	}
}

func TestCompileClassOfServiceDecimalTransmitRateExactSyntax(t *testing.T) {
	lines := []string{
		"set class-of-service forwarding-classes queue 4 iperf-a",
		"set class-of-service schedulers iperf-a transmit-rate 10.0g",
		"set class-of-service schedulers iperf-a transmit-rate exact",
		"set class-of-service scheduler-maps edge-map forwarding-class iperf-a scheduler iperf-a",
		"set class-of-service interfaces ge-0/0/2 unit 80 shaping-rate 20g",
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
	sched := cfg.ClassOfService.Schedulers["iperf-a"]
	if sched == nil {
		t.Fatal("expected iperf-a scheduler")
	}
	if got := sched.TransmitRateBytes; got != parseBandwidthLimit("10.0g") {
		t.Fatalf("transmit-rate = %d, want %d", got, parseBandwidthLimit("10.0g"))
	}
	if !sched.TransmitRateExact {
		t.Fatal("expected transmit-rate exact")
	}
}

func TestValidateClassOfServiceWarnings(t *testing.T) {
	input := `class-of-service {
    forwarding-classes {
        queue 0 best-effort;
    }
    classifiers {
        dscp edge-classifier {
            forwarding-class missing-class {
                loss-priority low {
                    code-points [ ef ];
                }
            }
        }
        ieee-802.1 pcp-classifier {
            forwarding-class missing-class {
                loss-priority low {
                    code-points [ 5 ];
                }
            }
        }
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
                classifiers {
                    dscp missing-classifier;
                    ieee-802.1 missing-pcp-classifier;
                }
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
	if !strings.Contains(warnings, `dscp classifier "edge-classifier" references undefined forwarding-class "missing-class"`) {
		t.Fatalf("expected undefined forwarding-class warning, got: %s", warnings)
	}
	if !strings.Contains(warnings, `ieee-802.1 classifier "pcp-classifier" references undefined forwarding-class "missing-class"`) {
		t.Fatalf("expected undefined 802.1p forwarding-class warning, got: %s", warnings)
	}
	if !strings.Contains(warnings, `references undefined dscp classifier "missing-classifier"`) {
		t.Fatalf("expected undefined dscp classifier warning, got: %s", warnings)
	}
	if !strings.Contains(warnings, `references undefined ieee-802.1 classifier "missing-pcp-classifier"`) {
		t.Fatalf("expected undefined 802.1p classifier warning, got: %s", warnings)
	}
	if !strings.Contains(warnings, "dscp/802.1p classifier loss-priority is accepted for compatibility but not yet enforced") {
		t.Fatalf("expected classifier loss-priority warning, got: %s", warnings)
	}
	if !strings.Contains(warnings, "class-of-service shaping and dscp/802.1p classifier attachment are only implemented in the userspace dataplane") {
		t.Fatalf("expected dataplane warning, got: %s", warnings)
	}
}

func TestCompileClassOfServiceHierarchicalDSCPClassifier(t *testing.T) {
	input := `class-of-service {
    forwarding-classes {
        queue 0 best-effort;
        queue 5 voice;
    }
    classifiers {
        dscp edge-classifier {
            forwarding-class voice {
                loss-priority low {
                    code-points [ ef 46 ];
                }
            }
            forwarding-class best-effort {
                loss-priority low {
                    code-points [ default cs0 ];
                }
            }
        }
    }
    interfaces {
        ge-0/0/1 {
            unit 0 {
                classifiers {
                    dscp edge-classifier;
                }
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
	classifier := cfg.ClassOfService.DSCPClassifiers["edge-classifier"]
	if classifier == nil {
		t.Fatal("expected edge-classifier")
	}
	if got := cfg.ClassOfService.Interfaces["ge-0/0/1"].Units[0].DSCPClassifier; got != "edge-classifier" {
		t.Fatalf("unit classifier = %q, want edge-classifier", got)
	}
	if len(classifier.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(classifier.Entries))
	}
	if got := classifier.Entries[0].DSCPValues; len(got) != 1 || got[0] != 46 {
		t.Fatalf("voice code-points = %v, want [46]", got)
	}
	if got := classifier.Entries[1].DSCPValues; len(got) != 1 || got[0] != 0 {
		t.Fatalf("best-effort code-points = %v, want [0]", got)
	}
}

func TestCompileClassOfServiceHierarchicalIEEE8021Classifier(t *testing.T) {
	input := `class-of-service {
    forwarding-classes {
        queue 0 best-effort;
        queue 5 voice;
    }
    classifiers {
        ieee-802.1 edge-pcp {
            forwarding-class voice {
                loss-priority low {
                    code-points [ 5 5 ];
                }
            }
            forwarding-class best-effort {
                loss-priority low {
                    code-points [ 0 ];
                }
            }
        }
    }
    interfaces {
        ge-0/0/1 {
            unit 0 {
                classifiers {
                    ieee-802.1 edge-pcp;
                }
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
	classifier := cfg.ClassOfService.IEEE8021Classifiers["edge-pcp"]
	if classifier == nil {
		t.Fatal("expected edge-pcp classifier")
	}
	if got := cfg.ClassOfService.Interfaces["ge-0/0/1"].Units[0].IEEE8021Classifier; got != "edge-pcp" {
		t.Fatalf("unit classifier = %q, want edge-pcp", got)
	}
	if len(classifier.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(classifier.Entries))
	}
	if got := classifier.Entries[0].CodePoints; len(got) != 1 || got[0] != 5 {
		t.Fatalf("voice code-points = %v, want [5]", got)
	}
	if got := classifier.Entries[1].CodePoints; len(got) != 1 || got[0] != 0 {
		t.Fatalf("best-effort code-points = %v, want [0]", got)
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
