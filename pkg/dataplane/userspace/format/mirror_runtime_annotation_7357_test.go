package format

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	userspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func annCfg7357() *config.Config {
	cfg := &config.Config{}
	cfg.ForwardingOptions.PortMirroring = &config.PortMirroringConfig{
		Instances: map[string]*config.PortMirrorInstance{
			"span1": {
				Name: "span1", InputRate: 10,
				Input:  []string{"ge-0/0/0.0", "ge-0/0/8.0"},
				Output: "ge-0/0/1.0",
			},
		},
	}
	return cfg
}

// #7357 §2: the runtime verdicts must render, at the granularity they occurred
// at, and must not perturb the output when there are none.
func TestPortMirroringRendersRuntimeExclusions7357(t *testing.T) {
	clean := FormatPortMirroring(annCfg7357(), nil)

	t.Run("no exclusions renders exactly as before", func(t *testing.T) {
		// The false-positive control. A change that annotates correctly but
		// perturbs the unannotated output is a rendering change wearing the
		// shape of a bug fix, and both surfaces are pinned byte-for-byte by
		// the parity test.
		if strings.Contains(clean, "NOT INSTALLED") {
			t.Error("a fully installed instance rendered a NOT INSTALLED annotation")
		}
		if !strings.Contains(clean, "Input interfaces: ge-0/0/0.0, ge-0/0/8.0") {
			t.Errorf("the joined one-line input form was not preserved:\n%s", clean)
		}
	})

	t.Run("instance-level exclusion marks the INSTANCE", func(t *testing.T) {
		out := FormatPortMirroring(annCfg7357(), []userspace.MirrorExclusion{
			{Instance: "span1", Reason: "output interface ge-0/0/1.0 has no ifindex"},
		})
		if !strings.Contains(out, "NOT INSTALLED: output interface ge-0/0/1.0 has no ifindex") {
			t.Errorf("instance-level exclusion not rendered:\n%s", out)
		}
		// An instance-level drop takes the whole instance with it, so the
		// inputs must NOT each be marked — that would suggest the inputs are
		// individually at fault.
		if strings.Contains(out, "ge-0/0/0.0  [NOT INSTALLED") {
			t.Errorf("an instance-level drop annotated individual inputs:\n%s", out)
		}
	})

	t.Run("input-level exclusion marks the INPUT and leaves the rest running", func(t *testing.T) {
		out := FormatPortMirroring(annCfg7357(), []userspace.MirrorExclusion{
			{Instance: "span1", Input: "ge-0/0/8.0", Reason: "ingress interface ge-0/0/8.0 already mirrored by instance aaa"},
		})
		if !strings.Contains(out, "ge-0/0/8.0  [NOT INSTALLED: ingress interface ge-0/0/8.0 already mirrored by instance aaa]") {
			t.Errorf("input-level exclusion not rendered against its input:\n%s", out)
		}
		// The load-bearing half: the OTHER input is installed and must not be
		// marked, and the instance must not be marked either. This instance is
		// partially installed, and saying NOT INSTALLED about it would be the
		// #6534 lie with the sign flipped.
		for _, bad := range []string{
			"ge-0/0/0.0  [NOT INSTALLED",
			"\n  NOT INSTALLED",
		} {
			if strings.Contains(out, bad) {
				t.Errorf("a partially-installed instance was marked %q:\n%s", bad, out)
			}
		}
	})

	t.Run("an exclusion for another instance does not leak", func(t *testing.T) {
		out := FormatPortMirroring(annCfg7357(), []userspace.MirrorExclusion{
			{Instance: "someone-else", Input: "ge-0/0/0.0", Reason: "not about span1"},
		})
		if out != clean {
			t.Errorf("an exclusion naming a different instance changed span1's render:\n%s", out)
		}
	})
}
