package cli

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// newIDScopePolicyCLI builds a committed store with one described zone-pair
// permit policy (trust->untrust) and one described scoped-global permit policy
// (match from-zone trust, no to-zone == any), plus a deny-all default. It is the
// fixture for the #3674 parity assertions on the local `test policy` simulator.
func newIDScopePolicyCLI(t *testing.T) *CLI {
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
    }
    policies {
        default-policy deny-all;
        from-zone trust to-zone untrust {
            policy zp-allow {
                description "CHG-9 zone allow";
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
        global {
            policy g-allow {
                description "CHG-7 global allow";
                match { source-address any; destination-address any; application any; from-zone untrust; }
                then { permit; }
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return &CLI{store: store}
}

// TestTestPolicyOutputCarriesIDScopeDescription pins #3674: the local
// operational `test policy` simulator (pkg/cli/cli_request.go testPolicy) must
// print the same Policy ID, scope, and description that `show security
// match-policies` already renders over the SAME policymatch.Result, for BOTH a
// zone-pair and a scoped-global match. Before #3674 the request path printed
// only the policy name + action (and, for a global match, nothing but name +
// action), making it the poorest of the match-policies surfaces — an operator
// could not correlate a verdict with the RT_FLOW / session-table policy ID nor
// tell whether a global vs zone-pair rule fired.
//
// FAIL-ON-REVERT: deleting the printPolicyMatchIdentity call (or the helper)
// drops the "Policy ID:", "Scope:", and "Description:" lines, flipping every
// assertion below red. The Policy ID value is additionally checked against the
// shared RuntimePolicyIDs SSOT so a literal placeholder cannot pass.
func TestTestPolicyOutputCarriesIDScopeDescription(t *testing.T) {
	c := newIDScopePolicyCLI(t)
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}
	ids := dpuserspace.RuntimePolicyIDs(cfg)

	// Zone-pair index of the trust->untrust set (sliceIdx 0 == its first/only
	// policy) — the exact key RuntimePolicyIDs uses to stamp Result.PolicyID.
	var zpSetIdx int
	for i, zpp := range cfg.Security.Policies {
		if zpp != nil && zpp.FromZone == "trust" && zpp.ToZone == "untrust" {
			zpSetIdx = i
		}
	}
	wantZoneID := ids[[2]uint32{uint32(zpSetIdx), 0}]
	// Global policies live in a synthetic set keyed by len(Policies).
	wantGlobalID := ids[[2]uint32{uint32(len(cfg.Security.Policies)), 0}]

	t.Run("zone-pair", func(t *testing.T) {
		var err error
		out := captureStdout(t, func() {
			err = c.testPolicy([]string{"from-zone", "trust", "to-zone", "untrust", "protocol", "tcp", "destination-port", "80"})
		})
		if err != nil {
			t.Fatalf("testPolicy() err = %v", err)
		}
		if !strings.Contains(out, "Policy match:") {
			t.Fatalf("no zone-pair match; out = %q", out)
		}
		wants := []string{
			fmt.Sprintf("Policy ID: %d", wantZoneID),
			"Scope:     zone-pair (from-zone: trust, to-zone: untrust)",
			"Description: CHG-9 zone allow",
			"Rule ID:",
		}
		for _, w := range wants {
			if !strings.Contains(out, w) {
				t.Errorf("output missing %q\nfull output:\n%s", w, out)
			}
		}
	})

	t.Run("global", func(t *testing.T) {
		// from-zone untrust to-zone trust misses the zone-pair tier (only
		// trust->untrust exists) and falls through to the scoped global, whose
		// match from-zone is untrust and to-zone is unset == any.
		var err error
		out := captureStdout(t, func() {
			err = c.testPolicy([]string{"from-zone", "untrust", "to-zone", "trust", "protocol", "tcp", "destination-port", "80"})
		})
		if err != nil {
			t.Fatalf("testPolicy() err = %v", err)
		}
		if !strings.Contains(out, "Policy match (global):") {
			t.Fatalf("no global match; out = %q", out)
		}
		wants := []string{
			fmt.Sprintf("Policy ID: %d", wantGlobalID),
			"Scope:     global (match from-zone: untrust, to-zone: any)",
			"Description: CHG-7 global allow",
			"Rule ID:",
		}
		for _, w := range wants {
			if !strings.Contains(out, w) {
				t.Errorf("output missing %q\nfull output:\n%s", w, out)
			}
		}
	})
}
