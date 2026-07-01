package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #3658 (M04/M05): the local-CLI `show security zones detail` policy summary
// scanned only zone-pair policies. A zone with no zone-pair rule printed
// "(no policies)" — hiding BOTH the applicable GLOBAL tier (a global policy
// that permits/denies the zone's traffic, M04) AND the effective
// default-policy catch-all that actually decides unmatched transit (M05). The
// summary now renders all three tiers in evaluation order (zone-pair ->
// global -> default-policy), mirroring the REST inventory + gRPC GetPolicies.
//
// These are the fail-on-revert guards: revert the global loop or the
// unconditional default-policy line and the assertions go RED.

// globalOnlyZoneCLIStore builds a config whose zone `dmz` has NO zone-pair
// policy but is covered by an UNSCOPED global permit, plus a SCOPED global
// (trust -> untrust) that must NOT leak into dmz's detail. default-policy is
// deny-all so the catch-all line is materially different from "(no policies)".
func globalOnlyZoneCLIStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    zones {
        security-zone trust;
        security-zone untrust;
        security-zone dmz;
    }
    policies {
        from-zone trust to-zone untrust {
            policy zone-allow {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
        global {
            policy scoped-block {
                match {
                    from-zone trust;
                    to-zone untrust;
                    source-address any;
                    destination-address any;
                    application any;
                }
                then { deny; }
            }
            policy open-global {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
        default-policy deny-all;
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}
	if len(cfg.Security.GlobalPolicies) != 2 {
		t.Fatalf("GlobalPolicies len = %d, want 2", len(cfg.Security.GlobalPolicies))
	}
	return store
}

// zoneDetailBlock returns the "Security zone: <name>" ... block from a full
// zone-detail render, up to the next zone header (blocks are blank-line
// separated). Isolates one zone's summary so assertions do not cross-match
// another zone's lines.
func zoneDetailBlock(t *testing.T, out, zone string) string {
	t.Helper()
	marker := "Security zone: " + zone + "\n"
	idx := strings.Index(out, marker)
	if idx < 0 {
		t.Fatalf("zone %q missing from zone-detail output:\n%s", zone, out)
	}
	rest := out[idx:]
	// The next zone header follows a blank line; cut there so we keep only
	// this zone's block.
	if end := strings.Index(rest[len(marker):], "\nSecurity zone: "); end >= 0 {
		rest = rest[:len(marker)+end]
	}
	return rest
}

// TestCLIZoneDetailGlobalOnlyZoneShowsGlobalAndDefault is the #3658 M04/M05
// fail-on-revert guard: a zone with only a global policy must show the global
// tier AND the effective default-policy catch-all — never a bare
// "(no policies)".
func TestCLIZoneDetailGlobalOnlyZoneShowsGlobalAndDefault(t *testing.T) {
	store := globalOnlyZoneCLIStore(t)
	c := &CLI{store: store} // dp nil: skip counters, exercise the policy summary
	cfg := store.ActiveConfig()

	out := captureStdout(t, func() {
		if err := c.showZonesDisplay(cfg, true, "dmz"); err != nil {
			t.Fatalf("showZonesDisplay(detail, dmz): %v", err)
		}
	})
	block := zoneDetailBlock(t, out, "dmz")

	// M05: the pre-fix bare "(no policies)" must be gone.
	if strings.Contains(block, "(no policies)") {
		t.Fatalf("dmz detail still prints bare \"(no policies)\" (M05 not fixed):\n%s", block)
	}
	// M04: the unscoped global that covers every zone must be listed as the
	// global tier for dmz.
	if !strings.Contains(block, "[global] any -> any: open-global (permit)") {
		t.Fatalf("dmz detail missing unscoped global tier line (M04 not fixed):\n%s", block)
	}
	// The scoped trust->untrust global must NOT leak into dmz (applicability
	// filter — config.GlobalPolicyAppliesToZone).
	if strings.Contains(block, "scoped-block") {
		t.Fatalf("dmz detail leaked scoped trust->untrust global scoped-block:\n%s", block)
	}
	// M05: the effective default-policy catch-all (deny) is surfaced.
	if !strings.Contains(block, "[default] default-policy: deny") {
		t.Fatalf("dmz detail missing effective default-policy line (M05 not fixed):\n%s", block)
	}
}

// TestCLIZoneDetailAllTiersForZonePairZone verifies the full precedence stack
// for a zone that has a zone-pair policy, an applicable scoped global, and an
// applicable unscoped global — all three tiers plus the default line appear.
func TestCLIZoneDetailAllTiersForZonePairZone(t *testing.T) {
	store := globalOnlyZoneCLIStore(t)
	c := &CLI{store: store}
	cfg := store.ActiveConfig()

	out := captureStdout(t, func() {
		if err := c.showZonesDisplay(cfg, true, "untrust"); err != nil {
			t.Fatalf("showZonesDisplay(detail, untrust): %v", err)
		}
	})
	block := zoneDetailBlock(t, out, "untrust")

	for _, want := range []string{
		"[zone-pair] trust -> untrust: zone-allow (permit)",
		"[global] trust -> untrust: scoped-block (deny)",
		"[global] any -> any: open-global (permit)",
		"[default] default-policy: deny",
	} {
		if !strings.Contains(block, want) {
			t.Fatalf("untrust detail missing %q:\n%s", want, block)
		}
	}
}

// scopedGlobalNoZonePairCLIStore builds a config with ONLY a scoped global
// (trust -> untrust) and NO unscoped global, so a third zone `mgmt` has no
// applicable policy of any tier. default-policy is permit-all here to prove the
// catch-all reflects the configured action, not a hardcoded deny.
func scopedGlobalNoZonePairCLIStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    zones {
        security-zone trust;
        security-zone untrust;
        security-zone mgmt;
    }
    policies {
        global {
            policy scoped-block {
                match {
                    from-zone trust;
                    to-zone untrust;
                    source-address any;
                    destination-address any;
                    application any;
                }
                then { deny; }
            }
        }
        default-policy permit-all;
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

// TestCLIZoneDetailNoApplicablePolicyStillShowsDefault verifies M05 for a zone
// with zero applicable policies: the summary shows the "(no zone-pair or global
// policies affecting this zone)" note AND the effective default-policy line —
// and the scoped global does not leak into an unrelated zone.
func TestCLIZoneDetailNoApplicablePolicyStillShowsDefault(t *testing.T) {
	store := scopedGlobalNoZonePairCLIStore(t)
	c := &CLI{store: store}
	cfg := store.ActiveConfig()

	out := captureStdout(t, func() {
		if err := c.showZonesDisplay(cfg, true, "mgmt"); err != nil {
			t.Fatalf("showZonesDisplay(detail, mgmt): %v", err)
		}
	})
	block := zoneDetailBlock(t, out, "mgmt")

	if strings.Contains(block, "scoped-block") {
		t.Fatalf("mgmt detail leaked scoped trust->untrust global:\n%s", block)
	}
	if !strings.Contains(block, "(no zone-pair or global policies affecting this zone)") {
		t.Fatalf("mgmt detail missing no-applicable-policy note:\n%s", block)
	}
	// M05: even with no explicit policy, the effective permit-all default is
	// surfaced (materially different from a bare "(no policies)").
	if !strings.Contains(block, "[default] default-policy: permit") {
		t.Fatalf("mgmt detail missing effective permit-all default line:\n%s", block)
	}
}
