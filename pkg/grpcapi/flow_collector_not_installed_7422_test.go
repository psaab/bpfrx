package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6565 row 11 / #7422 — the gRPC `show forwarding-options` half.
//
// The CLI half is driven in pkg/cli/flow_collector_not_installed_7422_test.go;
// importing pkg/cli from here is not how the tree is layered. The population
// itself (three renderers of a flow-server, all three now annotated) is
// MEASURED by pkg/showaudit rather than asserted in prose here.

func flowCollectorSurfaceConfig(port int) *config.Config {
	cfg := &config.Config{}
	cfg.ForwardingOptions.Sampling = &config.SamplingConfig{
		Instances: map[string]*config.SamplingInstance{
			"s1": {Name: "s1", InputRate: 100, FamilyInet: &config.SamplingFamily{
				FlowServers: []*config.FlowServer{
					{Address: "10.0.0.1", Port: port},
				},
			}},
		},
	}
	return cfg
}

// TestFlowCollectorSurfaceAnnotatesSkippedCollector7422.
//
// The port-0 case is the one that matters most: the CLI sibling suppresses the
// `:0` suffix entirely, so `Collector: 10.0.0.1` reads as a healthy collector
// on a default port and the annotation is the ONLY thing distinguishing the
// two. This surface prints `Flow server: 10.0.0.1:0`, which is at least
// visibly odd — but "0" is not self-evidently "not installed" to a reader who
// has never seen the default, and it never said so.
func TestFlowCollectorSurfaceAnnotatesSkippedCollector7422(t *testing.T) {
	cases := []struct {
		name         string
		port         int
		wantAnnotate bool
	}{
		{"healthy_installs_unannotated", 2055, false},
		{"lowest_valid_port_unannotated", 1, false},
		{"highest_valid_port_unannotated", 65535, false},
		{"absent_port_is_annotated", 0, true},
		{"negative_port_is_annotated", -1, true},
		{"above_u16_is_annotated", 65536, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := flowCollectorSurfaceConfig(c.port)
			fs := cfg.ForwardingOptions.Sampling.Instances["s1"].FamilyInet.FlowServers[0]

			// Ground-truth pin: without it a predicate that stopped recognising
			// the shape would make every cell below agree on "installed" and
			// pass over an empty set.
			if (config.FlowServerExcludedReason(fs) != "") != c.wantAnnotate {
				t.Fatalf("fixture no longer constructs the case it names: predicate "+
					"reason %q, want annotate=%v",
					config.FlowServerExcludedReason(fs), c.wantAnnotate)
			}

			var buf strings.Builder
			(&Server{}).showForwardingOptions(cfg, &buf)
			out := buf.String()

			// The premise: this surface renders the collector at all. If it
			// were ever reduced to a pointer line it could not lie, and this
			// cell would be asserting an annotation on output nobody reads for
			// enforcement.
			if !strings.Contains(out, "10.0.0.1") {
				t.Fatalf("`show forwarding-options` no longer renders the collector "+
					"address; this cell no longer exercises the #7422 shape.\n--- output ---\n%s", out)
			}

			if got := strings.Contains(out, "NOT INSTALLED"); got != c.wantAnnotate {
				if c.wantAnnotate {
					t.Fatalf("`show forwarding-options` renders a flow collector that "+
						"receives NO records as an active export target.\n--- output ---\n%s", out)
				}
				t.Fatalf("`show forwarding-options` annotated a collector the "+
					"dataplane does export to — crying wolf on a working "+
					"collector.\n--- output ---\n%s", out)
			}
			if c.wantAnnotate && !strings.Contains(out, config.FlowServerExcludedReason(fs)) {
				t.Fatalf("the annotation does not carry the predicate's reason "+
					"verbatim, so the operator cannot tell WHICH condition "+
					"dropped the collector.\n--- output ---\n%s", out)
			}
		})
	}
}
