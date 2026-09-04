package config

import "testing"

// #8436: `services rpm probe <p> test <t>` — the site the census could not see.
//
// HOW IT HID, which is the useful part. The PROBE level was fixed by an earlier
// issue (compiler_services.go says so: a second `probe P` used to "silently
// REPLACE the first, discarding ALL of its tests"). The TEST level one layer
// down was not, and the census never reported it — its synthesized fixture omits
// the required `target`, so the compile failed and the site was counted under
// "a spelling did not parse or compile" rather than checked. Seven batches of
// #8436 picked from a list this site was never on.
//
// The skip set is pinned now (dupConservationSkipped8436), so the next
// unprobeable container is a recorded decision instead of an integer. This
// site stays listed there — the census still cannot build its fixture — which
// is why the behaviour needs a cell of its own.
func TestDuplicateRPMTestBlocksMerge8436(t *testing.T) {
	cfg := mustCompile8436(t, `
services {
    rpm {
        probe P {
            test T {
                probe-type icmp-ping;
                target address 192.0.2.9;
            }
            test T {
                probe-count 5;
                target address 192.0.2.9;
            }
        }
    }
}
`)
	probe := cfg.Services.RPM.Probes["P"]
	if probe == nil {
		t.Fatal("probe P did not compile")
	}
	test := probe.Tests["T"]
	if test == nil {
		t.Fatalf("test T did not compile (tests: %d)", len(probe.Tests))
	}
	if test.ProbeType != "icmp-ping" {
		t.Errorf("ProbeType = %q, want \"icmp-ping\" — the second `test T` block "+
			"constructed a fresh RPMTest and overwrote the first under one map key, so "+
			"the first block's settings were silently discarded (#8436)", test.ProbeType)
	}
	if test.ProbeCount != 5 {
		t.Errorf("ProbeCount = %d, want 5 — the second block's own setting was lost",
			test.ProbeCount)
	}
}

// THE CONTROL. Two DIFFERENT test names must stay two tests with their own
// settings.
//
// MUTATION: key the lookup on anything but the test name — e.g. reuse whichever
// test already exists — and this reds. An over-broad merge would collapse two
// configured probes into one, so a monitored target silently stops being
// monitored.
func TestDistinctRPMTestBlocksStayDistinct8436(t *testing.T) {
	cfg := mustCompile8436(t, `
services {
    rpm {
        probe P {
            test T1 {
                probe-type icmp-ping;
                target address 192.0.2.9;
            }
            test T2 {
                probe-type icmp-ping;
                target address 192.0.2.10;
            }
        }
    }
}
`)
	probe := cfg.Services.RPM.Probes["P"]
	if probe == nil {
		t.Fatal("probe P did not compile")
	}
	if len(probe.Tests) != 2 {
		t.Fatalf("two DIFFERENT tests produced %d entries, want 2 (#8436)", len(probe.Tests))
	}
	if got := probe.Tests["T1"].Target; got != "192.0.2.9" {
		t.Errorf("T1 target = %q, want 192.0.2.9", got)
	}
	if got := probe.Tests["T2"].Target; got != "192.0.2.10" {
		t.Errorf("T2 target = %q, want 192.0.2.10", got)
	}
}
