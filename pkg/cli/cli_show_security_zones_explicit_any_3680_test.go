package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #3680: the #3658 zone-detail policy summary used config.GlobalPolicyAppliesToZone,
// which recognised only the EMPTY (omitted) global scope as the all-zones
// wildcard — not the EXPLICIT Junos token "any". So a global written
// `match from-zone any` / `match to-zone any` (idiomatic Junos, preserved
// verbatim by the compiler and enforced all-zones by the runtime) was HIDDEN
// from every affected zone's `show security zones detail` — a security-audit
// false negative on the exact surface #3658 added to prevent it.
//
// These are the local-CLI fail-on-revert guards: revert IsWildcardZone (or the
// GlobalPolicyAppliesToZone callers) to the "" -only test and the explicit-any
// assertions go RED (the global drops out of the affected zones' detail).

// explicitAnyGlobalCLIStore builds a config with two EXPLICIT-any globals plus a
// fully scoped global that must not over-include:
//   - any-to-untrust: `from-zone any to-zone untrust` -> applies to every zone
//     (any source) and to untrust (destination).
//   - trust-to-any:   `from-zone trust to-zone any`   -> applies to trust
//     (source) and every destination zone.
//   - scoped-td:      `from-zone trust to-zone dmz`   -> ONLY trust and dmz.
func explicitAnyGlobalCLIStore(t *testing.T) *configstore.Store {
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
        global {
            policy any-to-untrust {
                match {
                    from-zone any;
                    to-zone untrust;
                    source-address any;
                    destination-address any;
                    application any;
                }
                then { deny; }
            }
            policy trust-to-any {
                match {
                    from-zone trust;
                    to-zone any;
                    source-address any;
                    destination-address any;
                    application any;
                }
                then { deny; }
            }
            policy scoped-td {
                match {
                    from-zone trust;
                    to-zone dmz;
                    source-address any;
                    destination-address any;
                    application any;
                }
                then { deny; }
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
	if len(cfg.Security.GlobalPolicies) != 3 {
		t.Fatalf("GlobalPolicies len = %d, want 3", len(cfg.Security.GlobalPolicies))
	}
	// Confirm the compiler preserved the explicit "any" verbatim — the premise.
	for _, p := range cfg.Security.GlobalPolicies {
		if p.Name == "any-to-untrust" && p.Match.FromZone != "any" {
			t.Fatalf("compiler dropped explicit from-zone any: %q", p.Match.FromZone)
		}
		if p.Name == "trust-to-any" && p.Match.ToZone != "any" {
			t.Fatalf("compiler dropped explicit to-zone any: %q", p.Match.ToZone)
		}
	}
	return store
}

func TestCLIZoneDetailExplicitAnyGlobalAppears3680(t *testing.T) {
	store := explicitAnyGlobalCLIStore(t)
	c := &CLI{store: store} // dp nil: skip counters, exercise the policy summary
	cfg := store.ActiveConfig()

	render := func(zone string) string {
		out := captureStdout(t, func() {
			if err := c.showZonesDisplay(cfg, true, zone); err != nil {
				t.Fatalf("showZonesDisplay(detail, %s): %v", zone, err)
			}
		})
		return zoneDetailBlock(t, out, zone)
	}

	// dmz has NO zone-pair rule. Both explicit-any globals must still surface:
	//   - any-to-untrust: `any` source axis places dmz on the source side.
	//   - trust-to-any:   `any` dest axis places dmz on the destination side.
	dmz := render("dmz")
	if !strings.Contains(dmz, "[global] any -> untrust: any-to-untrust (deny)") {
		t.Errorf("dmz detail missing explicit from-zone-any global (hidden — #3680):\n%s", dmz)
	}
	if !strings.Contains(dmz, "[global] trust -> any: trust-to-any (deny)") {
		t.Errorf("dmz detail missing explicit to-zone-any global (hidden — #3680):\n%s", dmz)
	}
	// The fully scoped trust->dmz global legitimately applies to dmz too.
	if !strings.Contains(dmz, "[global] trust -> dmz: scoped-td (deny)") {
		t.Errorf("dmz detail missing scoped trust->dmz global:\n%s", dmz)
	}
	if strings.Contains(dmz, "(no policies)") {
		t.Errorf("dmz detail still prints bare \"(no policies)\":\n%s", dmz)
	}

	// untrust: destination of any-to-untrust and a destination of trust-to-any.
	untrust := render("untrust")
	if !strings.Contains(untrust, "[global] any -> untrust: any-to-untrust (deny)") {
		t.Errorf("untrust detail missing explicit from-zone-any global:\n%s", untrust)
	}
	if !strings.Contains(untrust, "[global] trust -> any: trust-to-any (deny)") {
		t.Errorf("untrust detail missing explicit to-zone-any global:\n%s", untrust)
	}
	// No over-inclusion: the fully scoped trust->dmz global must NOT show for
	// untrust.
	if strings.Contains(untrust, "scoped-td") {
		t.Errorf("untrust detail over-included scoped trust->dmz global:\n%s", untrust)
	}
}
