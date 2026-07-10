package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestShowChassisClusterStatus_VRRPLogicalZoneInterface is the #4908
// (C175-HC-116) RED-on-revert guard. A security zone binds a LOGICAL interface
// ("ge-0-0-0.0"), but cfg.Interfaces.Interfaces is keyed by the BASE name
// ("ge-0-0-0"). The prior direct `cfg.Interfaces.Interfaces[iface]` lookup
// missed the unit-qualified reference and silently dropped the VRRP row.
// Reverting to the direct lookup makes this test fail (no "VRRP on ..." line).
func TestShowChassisClusterStatus_VRRPLogicalZoneInterface(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    ge-0-0-0 {
        unit 0 {
            family inet {
                address 10.0.61.1/24 {
                    vrrp-group 7 {
                        virtual-address 10.0.61.254/24;
                        priority 200;
                    }
                }
            }
        }
    }
}
security {
    zones {
        security-zone trust {
            interfaces {
                ge-0-0-0.0;
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	c := &CLI{store: store} // cluster nil: prints "Cluster not configured", then the VRRP loop
	out := captureStdout(t, func() {
		if err := c.showChassisClusterStatus(); err != nil {
			t.Fatalf("showChassisClusterStatus: %v", err)
		}
	})

	if !strings.Contains(out, "VRRP on ge-0-0-0.0:") {
		t.Fatalf("VRRP row for the logical zone interface ge-0-0-0.0 was dropped "+
			"(#4908/C175-HC-116 — base-keyed lookup missed the unit-qualified ref):\n%s", out)
	}
	if !strings.Contains(out, "group 7") || !strings.Contains(out, "VIP 10.0.61.254") {
		t.Fatalf("VRRP row missing group/VIP details:\n%s", out)
	}
}

// TestValidatePolicyZoneFilter is the #4908 (C175-HC-126) RED-on-revert guard
// for the local CLI: a from-zone/to-zone selector missing its zone value must
// be rejected rather than silently dropped (which returned a broader/one-sided
// inventory). Removing the validation call makes the malformed cases pass with
// nil errors.
func TestValidatePolicyZoneFilter(t *testing.T) {
	good := [][]string{
		{},
		{"from-zone", "trust"},
		{"from-zone", "trust", "to-zone", "untrust"},
		{"global"},
		{"detail", "from-zone", "trust", "to-zone", "untrust"},
	}
	for _, args := range good {
		if err := validatePolicyZoneFilter(args); err != nil {
			t.Errorf("validatePolicyZoneFilter(%v) = %v, want nil", args, err)
		}
	}
	bad := [][]string{
		{"from-zone"},
		{"to-zone"},
		{"from-zone", "trust", "to-zone"},
		{"from-zone", "to-zone", "untrust"},
	}
	for _, args := range bad {
		if err := validatePolicyZoneFilter(args); err == nil {
			t.Errorf("validatePolicyZoneFilter(%v) = nil, want an error (malformed selector)", args)
		}
	}
}
