package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7357 §2: the three port-mirroring drops that depend on the runtime
// interface table, recorded as verdicts so the show surfaces stop rendering a
// dropped instance as an armed one.
//
// These are the drops the shared config predicate CANNOT close, because they
// are not functions of the committed config. Every other #6534 family is
// closed by config.<Thing>ExcludedReason; these needed a readback instead.

func mirrorCfg7357(inputs []string, output string) *config.Config {
	cfg := &config.Config{}
	cfg.ForwardingOptions.PortMirroring = &config.PortMirroringConfig{
		Instances: map[string]*config.PortMirrorInstance{
			"span1": {Name: "span1", InputRate: 10, Input: inputs, Output: output},
		},
	}
	return cfg
}

func TestMirrorRuntimeDropsAreRecordedAtTheRightGranularity7357(t *testing.T) {
	t.Run("output ifindex unresolved drops the whole INSTANCE", func(t *testing.T) {
		cfg := mirrorCfg7357([]string{"ge-0/0/0.0"}, "ge-0/0/9.0")
		snaps, excl := buildMirrorConfigSnapshots(cfg, []InterfaceSnapshot{
			{Name: "ge-0/0/0.0", Ifindex: 11},
		})
		if len(snaps) != 0 {
			t.Fatalf("installed %d entries for an instance with no output ifindex", len(snaps))
		}
		if len(excl) != 1 {
			t.Fatalf("exclusions = %+v, want exactly 1", excl)
		}
		if excl[0].Instance != "span1" || excl[0].Input != "" {
			t.Errorf("instance-level drop recorded as %+v; Input must be empty, or the "+
				"renderer will mark one input instead of the instance", excl[0])
		}
		if !strings.Contains(excl[0].Reason, "ge-0/0/9.0") {
			t.Errorf("reason %q does not name the interface the operator has to fix", excl[0].Reason)
		}
	})

	t.Run("input ifindex unresolved drops ONE INPUT, not the instance", func(t *testing.T) {
		// The granularity that matters. This instance is PARTIALLY installed:
		// its first input works. Recording it instance-level would make the
		// renderer say NOT INSTALLED about mirroring that is running — the
		// same defect as #6534 with the sign flipped.
		cfg := mirrorCfg7357([]string{"ge-0/0/0.0", "ge-0/0/8.0"}, "ge-0/0/1.0")
		snaps, excl := buildMirrorConfigSnapshots(cfg, []InterfaceSnapshot{
			{Name: "ge-0/0/0.0", Ifindex: 11},
			{Name: "ge-0/0/1.0", Ifindex: 22},
		})
		if len(snaps) != 1 {
			t.Fatalf("installed %d entries, want 1 — the resolvable input must still mirror", len(snaps))
		}
		if len(excl) != 1 || excl[0].Input != "ge-0/0/8.0" {
			t.Fatalf("exclusions = %+v, want one naming input ge-0/0/8.0", excl)
		}
	})

	t.Run("ingress already claimed drops ONE INPUT of the later instance", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.ForwardingOptions.PortMirroring = &config.PortMirroringConfig{
			Instances: map[string]*config.PortMirrorInstance{
				// Sorted by name, so "aaa" claims the shared ingress.
				"aaa": {Name: "aaa", InputRate: 10, Input: []string{"ge-0/0/0.0"}, Output: "ge-0/0/1.0"},
				"zzz": {Name: "zzz", InputRate: 10, Input: []string{"ge-0/0/0.0"}, Output: "ge-0/0/2.0"},
			},
		}
		snaps, excl := buildMirrorConfigSnapshots(cfg, []InterfaceSnapshot{
			{Name: "ge-0/0/0.0", Ifindex: 11},
			{Name: "ge-0/0/1.0", Ifindex: 22},
			{Name: "ge-0/0/2.0", Ifindex: 33},
		})
		if len(snaps) != 1 {
			t.Fatalf("installed %d entries, want 1 (one output per ingress ifindex)", len(snaps))
		}
		if len(excl) != 1 || excl[0].Instance != "zzz" || excl[0].Input != "ge-0/0/0.0" {
			t.Fatalf("exclusions = %+v, want one for instance zzz input ge-0/0/0.0", excl)
		}
		if !strings.Contains(excl[0].Reason, "aaa") {
			t.Errorf("reason %q does not name the owning instance; the operator cannot tell "+
				"WHICH instance took the interface", excl[0].Reason)
		}
	})

	t.Run("a fully resolvable config records nothing", func(t *testing.T) {
		// The control. Without it every assertion above is satisfied by a
		// builder that records an exclusion for everything.
		cfg := mirrorCfg7357([]string{"ge-0/0/0.0"}, "ge-0/0/1.0")
		snaps, excl := buildMirrorConfigSnapshots(cfg, []InterfaceSnapshot{
			{Name: "ge-0/0/0.0", Ifindex: 11},
			{Name: "ge-0/0/1.0", Ifindex: 22},
		})
		if len(snaps) != 1 || len(excl) != 0 {
			t.Fatalf("clean config produced %d snapshots and %d exclusions, want 1 and 0",
				len(snaps), len(excl))
		}
	})
}

// TestMirrorExclusionsReportTheAppliedVerdictNotAFreshDerivation7357 is the
// cell that distinguishes this design from the one #7357's body prescribes.
//
// The body says to thread "the resolved ifindex map" to the renderers. That
// invites the surface to RE-DERIVE the verdict against a live interface table,
// which answers a different question: `show forwarding-options port-mirroring`
// asks what IS installed, and a re-derivation reports what WOULD be installed
// if the builder ran again now. An ifindex is a runtime identity that moves
// across a netdev recreate, so the two genuinely differ.
//
// THE FIXTURE MUST MOVE THE IFINDEX. A fixture where the interface table never
// changes between apply and read passes on BOTH designs and therefore
// distinguishes nothing — do not "simplify" it back to a static table. Here
// the interface is absent at apply time and PRESENT afterwards, which is the
// case where a re-deriving renderer would wrongly report the instance as
// installed.
func TestMirrorExclusionsReportTheAppliedVerdictNotAFreshDerivation7357(t *testing.T) {
	cfg := mirrorCfg7357([]string{"ge-0/0/0.0"}, "ge-0/0/9.0")

	// Apply while the output interface has no ifindex.
	snaps, excl := buildMirrorConfigSnapshots(cfg, []InterfaceSnapshot{
		{Name: "ge-0/0/0.0", Ifindex: 11},
	})
	if len(snaps) != 0 || len(excl) != 1 {
		t.Fatalf("setup: snapshots=%d exclusions=%d, want 0 and 1", len(snaps), len(excl))
	}

	m := &Manager{}
	m.lastSnapshot = &ConfigSnapshot{MirrorConfigs: snaps, MirrorExclusions: excl}

	// The interface now appears — the netdev was created after the apply. A
	// renderer that re-derived from this table would report the instance as
	// installed. Nothing re-applies, so the dataplane still has it excluded.
	got := m.MirrorExclusions()
	if len(got) != 1 || got[0].Instance != "span1" {
		t.Fatalf("MirrorExclusions() = %+v after the interface appeared; the readback must "+
			"report the APPLIED verdict, because that is what the dataplane currently has "+
			"installed. A disagreement here means a missed rebuild, which is a bug in a "+
			"different component that a re-deriving renderer would hide.", got)
	}

	// And it must be a COPY: rendering happens outside the manager lock, so
	// handing out the snapshot's own slice would let a concurrent apply mutate
	// it mid-render.
	got[0].Reason = "mutated by the caller"
	if again := m.MirrorExclusions(); again[0].Reason == "mutated by the caller" {
		t.Error("MirrorExclusions() returned the snapshot's own backing array")
	}

	// Control: with no applied snapshot there is nothing to report, and the
	// readback must say so rather than inventing a verdict.
	if got := (&Manager{}).MirrorExclusions(); got != nil {
		t.Errorf("MirrorExclusions() on a manager with no applied snapshot = %+v, want nil", got)
	}
}
