package config

import (
	"strings"
	"testing"
)

// TestDeviceMapGroupIsRejectedNotTruncated8810 pins what the #8810 fan-out
// actually achieves, which is NOT what the finding first assumed.
//
// `chassis device-map interface [ ge-0/0/1 ge-0/0/2 ] { pci 0000:01:00.0; }`
// used to compile to ONE entry: namedInstances took Keys[1] and discarded
// Keys[2:], so the second NIC silently vanished and was then governed by
// unmapped-interface-policy — under `manage-down` that brings it DOWN, and on
// bare metal (#1956 §9.6) the console is the only fallback.
//
// THE REMEDY IS NOT "MAP BOTH NICS" — THAT IS IMPOSSIBLE. A grouped device-map
// shares ONE body, and the body must carry a per-NIC stable identity (`pci` or
// `mac`). Two NICs cannot share a PCI address, so the grouped spelling can
// never be valid config. Measured:
//
//	BEFORE  grouped, shared pci   ACCEPTED, entries=1   <- silent, half-applied
//	AFTER   grouped, shared pci   REJECTED: "PCI address … is bound to both
//	                              \"ge-0/0/1\" and \"ge-0/0/2\" — one NIC cannot
//	                              be two interfaces"
//
// So the fan-out converts a SILENT MISCONFIGURATION INTO A COMMIT-TIME
// REJECTION, by letting the existing duplicate-identity validator see the
// second name at all. Before the fan-out that name did not exist, so no
// conflict could be detected.
//
// This is the outcome to assert. A cell demanding two entries would demand a
// config that cannot be correct, and would have failed against the right
// behaviour — as the first version of this cell did.
func TestDeviceMapGroupIsRejectedNotTruncated8810(t *testing.T) {
	compile := func(t *testing.T, label, text string) (*Config, error) {
		t.Helper()
		tr, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("%s: fixture must parse: %v", label, perrs)
		}
		return CompileConfig(tr)
	}

	t.Run("grouped is REJECTED, naming both NICs", func(t *testing.T) {
		cfg, err := compile(t, "grouped",
			`chassis { device-map { interface [ ge-0/0/1 ge-0/0/2 ] { pci 0000:01:00.0; } } }`)
		if err == nil {
			n := 0
			if cfg != nil && cfg.Chassis.DeviceMap != nil {
				n = len(cfg.Chassis.DeviceMap.Entries)
			}
			t.Fatalf("a grouped device-map COMMITTED with %d entrie(s). It cannot be valid — "+
				"the shared body carries one identity for two NICs — so accepting it means "+
				"a NIC the operator mapped is silently unmapped, and under "+
				"`unmapped-interface-policy manage-down` it is brought DOWN (#8810)", n)
		}
		// The message must name BOTH, or the operator cannot see which NIC was lost.
		for _, want := range []string{"ge-0/0/1", "ge-0/0/2"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the rejection does not name %q: %v. Naming only one NIC leaves the "+
					"operator with the same blind spot the silent drop had (#8810)", want, err)
			}
		}
	})

	// THE OUTAGE ARM, now unreachable — and that is the point. Under
	// manage-down the pre-fix behaviour was an outage; post-fix the config
	// never commits, so no policy setting can produce it.
	t.Run("manage-down cannot reach the outage", func(t *testing.T) {
		_, err := compile(t, "manage-down",
			`chassis { device-map { unmapped-interface-policy manage-down; interface [ ge-0/0/1 ge-0/0/2 ] { pci 0000:01:00.0; } } }`)
		if err == nil {
			t.Errorf("grouped device-map committed under `manage-down` — the setting that " +
				"turns a lost NIC from unmanaged into DOWN. This is the outage case (#8810)")
		}
	})

	// CONTROL: the longhand spelling is how this is written correctly, and it
	// must keep working. Without it, "rejected" could mean the validator
	// rejects everything.
	t.Run("control longhand with distinct identities", func(t *testing.T) {
		cfg, err := compile(t, "longhand",
			`chassis { device-map { interface ge-0/0/1 { pci 0000:01:00.0; } interface ge-0/0/2 { pci 0000:02:00.0; } } }`)
		if err != nil {
			t.Fatalf("the correct longhand spelling must compile: %v", err)
		}
		if cfg.Chassis.DeviceMap == nil || len(cfg.Chassis.DeviceMap.Entries) != 2 {
			n := 0
			if cfg.Chassis.DeviceMap != nil {
				n = len(cfg.Chassis.DeviceMap.Entries)
			}
			t.Errorf("longhand device-map has %d entrie(s), want 2 (#8810)", n)
		}
	})
}

// TestOSPFAreaInterfaceGroup8810 is the second in-scope container, and unlike
// device-map its grouped form IS meaningful: OSPF interfaces legitimately share
// a body (`metric`, `passive`), so both interfaces must be CREATED rather than
// rejected. A lost one means OSPF never forms an adjacency on that link.
func TestOSPFAreaInterfaceGroup8810(t *testing.T) {
	count := func(t *testing.T, label, text string, want int) {
		t.Helper()
		tr, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("%s: parse: %v", label, perrs)
		}
		cfg, err := CompileConfig(tr)
		if err != nil {
			t.Fatalf("%s: compile: %v", label, err)
		}
		n := 0
		if cfg.Protocols.OSPF != nil {
			for _, a := range cfg.Protocols.OSPF.Areas {
				n += len(a.Interfaces)
			}
		}
		if n != want {
			t.Errorf("%s: %d OSPF interface(s), want %d. OSPF does not run on a lost link, so "+
				"the adjacency the operator configured never forms (#8810)", label, n, want)
		}
	}
	count(t, "grouped", `protocols { ospf { area 0.0.0.0 { interface [ ge-0/0/1.0 ge-0/0/2.0 ] { metric 10; } } } }`, 2)
	count(t, "control longhand", `protocols { ospf { area 0.0.0.0 { interface ge-0/0/1.0 { metric 10; } interface ge-0/0/2.0 { metric 10; } } } }`, 2)
}
