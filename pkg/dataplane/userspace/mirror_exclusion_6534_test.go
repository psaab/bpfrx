package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6534, port-mirroring — BUILDER half.
//
// The two show surfaces are byte-identical COPIES with no shared formatter
// (cli.showPortMirroring and Server.showForwardingOptionsPortMirroring), so
// their half is asserted in pkg/grpcapi (mirror_exclusion_surfaces_6534_test.go)
// where both packages are reachable. Annotating one copy and testing only that
// one would leave the other surface lying with the suite green — the failure
// mode that makes duplicated renderers worth binding explicitly rather than
// trusting.

func mirrorExclusionConfig(output string, rate int) *config.Config {
	cfg := &config.Config{}
	cfg.ForwardingOptions.PortMirroring = &config.PortMirroringConfig{
		Instances: map[string]*config.PortMirrorInstance{
			"m1": {Name: "m1", Output: output, InputRate: rate, Input: []string{"ge-0/0/1.0"}},
		},
	}
	return cfg
}

// TestMirrorBuilderDropsMatchThePredicate_6534 pins the builder half: an
// instance is published IFF config.PortMirroringInstanceExcludedReason says it
// installs.
//
// The ifindex map is supplied so interface RESOLUTION always succeeds — that
// isolates the config-decidable drops this predicate covers from the two
// runtime-dependent ones it deliberately does not. Without that isolation a
// cell could red for the wrong reason and read as proof of the wrong property.
func TestMirrorBuilderDropsMatchThePredicate_6534(t *testing.T) {
	ifaces := []InterfaceSnapshot{
		{Name: "ge-0/0/1.0", Ifindex: 11},
		{Name: "ge-0/0/9.0", Ifindex: 19},
	}

	cases := []struct {
		name         string
		output       string
		rate         int
		wantExcluded bool
	}{
		{"healthy_instance_installs", "ge-0/0/9.0", 0, false},
		{"healthy_with_positive_rate_installs", "ge-0/0/9.0", 100, false},
		{"no_output_interface_is_dropped", "", 0, true},
		{"negative_rate_is_dropped", "ge-0/0/9.0", -1, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := mirrorExclusionConfig(c.output, c.rate)
			inst := cfg.ForwardingOptions.PortMirroring.Instances["m1"]

			// Ground-truth pin first: if the predicate stopped recognising the
			// shape, the builder comparison below would compare two agreeing
			// wrong answers and pass vacuously.
			gotReason := config.PortMirroringInstanceExcludedReason(inst)
			if (gotReason != "") != c.wantExcluded {
				t.Fatalf("predicate says excluded=%v (reason %q), want %v — the fixture "+
					"no longer constructs the case it names", gotReason != "", gotReason, c.wantExcluded)
			}

			snaps, _ := buildMirrorConfigSnapshots(cfg, ifaces)
			builderExcluded := len(snaps) == 0
			if builderExcluded != c.wantExcluded {
				verdict := "the builder PUBLISHED an instance the predicate calls excluded, " +
					"so both show surfaces will render it armed while it mirrors nothing"
				if builderExcluded {
					verdict = "the builder DROPPED an instance the predicate calls installable, " +
						"so the surfaces will under-report a working mirror"
				}
				t.Fatalf("%s", verdict)
			}
		})
	}
}
