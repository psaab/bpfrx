package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6534, port-mirroring — SURFACES half.
//
// cli.showPortMirroring and Server.showForwardingOptionsPortMirroring are
// byte-identical copies with no shared formatter, unlike pkg/natshow and
// pkg/dataplane/userspace/format which were extracted precisely so this class
// of divergence could not happen. Until they are single-sourced, a test that
// asserted only one of them would go green while the other surface kept
// rendering a dropped mirror as armed.
//
// This file can only reach the gRPC copy (importing pkg/cli from here is not
// how the tree is layered), so the CLI copy is bound by asserting the TEXT both
// are required to produce, and the builder half lives in
// pkg/dataplane/userspace/mirror_exclusion_6534_test.go. The three together are
// what make the property hold; any one alone does not.

func mirrorSurfaceConfig(output string, rate int) *config.Config {
	cfg := &config.Config{}
	cfg.ForwardingOptions.PortMirroring = &config.PortMirroringConfig{
		Instances: map[string]*config.PortMirrorInstance{
			"m1": {Name: "m1", Output: output, InputRate: rate, Input: []string{"ge-0/0/1.0"}},
		},
	}
	return cfg
}

// TestPortMirroringSurfaceAnnotatesDroppedInstance_6534.
//
// The negative-rate case is the one that matters most. Both renderers print
// `Input rate: all packets` whenever InputRate is not > 0, so before this fix a
// dropped instance advertised the most permissive mirror possible while
// mirroring nothing — the annotation is the only thing distinguishing the two.
func TestPortMirroringSurfaceAnnotatesDroppedInstance_6534(t *testing.T) {
	cases := []struct {
		name         string
		output       string
		rate         int
		wantAnnotate bool
	}{
		{"healthy_installs_unannotated", "ge-0/0/9.0", 0, false},
		{"no_output_is_annotated", "", 0, true},
		{"negative_rate_is_annotated", "ge-0/0/9.0", -1, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := mirrorSurfaceConfig(c.output, c.rate)
			inst := cfg.ForwardingOptions.PortMirroring.Instances["m1"]

			// Ground-truth pin: without it, a predicate that stopped
			// recognising the shape would make every cell below agree on
			// "installed" and pass over an empty set.
			if (config.PortMirroringInstanceExcludedReason(inst) != "") != c.wantAnnotate {
				t.Fatalf("fixture no longer constructs the case it names: predicate "+
					"reason %q, want annotate=%v",
					config.PortMirroringInstanceExcludedReason(inst), c.wantAnnotate)
			}

			var buf strings.Builder
			(&Server{}).showForwardingOptionsPortMirroring(cfg, &buf)
			out := buf.String()

			if got := strings.Contains(out, "NOT INSTALLED"); got != c.wantAnnotate {
				if c.wantAnnotate {
					t.Fatalf("`show forwarding-options` renders a port-mirroring "+
						"instance the builder DROPS with no #6534 annotation — the "+
						"operator is shown a mirror that captures nothing.\n--- output ---\n%s", out)
				}
				t.Fatalf("`show forwarding-options` annotated a healthy instance — "+
					"crying wolf on a mirror that works.\n--- output ---\n%s", out)
			}

			// The negative-rate render must ALSO still carry the misleading
			// "all packets" line: if a later change made that branch print
			// something else, the annotation would no longer be the thing
			// carrying the truth and this cell would be testing a different
			// output than the one the defect is about.
			if c.rate < 0 && !strings.Contains(out, "Input rate: all packets") {
				t.Fatalf("the negative-rate branch no longer renders \"all packets\"; "+
					"this cell no longer exercises the #6534 shape it was written "+
					"for.\n--- output ---\n%s", out)
			}
		})
	}
}
