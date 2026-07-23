package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// policyFilterRejectCLIStore builds a local CLI store with one from-zone/to-zone
// policy — enough for handleShowSecurity to reach the zone-filter validation.
func policyFilterRejectCLIStore(t *testing.T) *CLI {
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
        from-zone trust to-zone untrust {
            policy p {
                match { source-address any; destination-address any; application any; }
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

// TestHandleShowSecurityPolicies_RejectsUnknownFilterToken_5557 is the
// OPERATOR-SURFACE (CLI-level, not renderer-level) fail-on-revert guard for the
// local `show security policies` dispatch. FINDING 1 (#6393 review): the
// dispatch extracts the from-zone/to-zone pair with parsePolicyZoneFilter and
// silently DROPS every other token, so a typo'd key (`from-zonee trust`) left the
// filter empty and widened the view to every zone. The renderer-level test does
// NOT catch this because the renderer never sees the stripped token — only the
// dispatch does.
//
// FAIL-ON-REVERT: relax validatePolicyZoneFilter back to the loose parse (drop
// the unrecognized-token rejection) and handleShowSecurity proceeds to render
// the widened (all-zones) view, returning nil — the error assertions go RED.
func TestHandleShowSecurityPolicies_RejectsUnknownFilterToken_5557(t *testing.T) {
	for _, sub := range []string{"detail", "hit-count"} {
		t.Run(sub, func(t *testing.T) {
			c := policyFilterRejectCLIStore(t)

			// Bad token must abort at the dispatch with a clear error.
			var err error
			captureStdout(t, func() {
				err = c.handleShowSecurity([]string{"policies", sub, "from-zonee", "trust"})
			})
			if err == nil {
				t.Fatalf("%s: unknown filter token accepted; expected a CLI-level rejection", sub)
			}
			if !strings.Contains(err.Error(), "unrecognized filter token") {
				t.Fatalf("%s: error = %q, want an 'unrecognized filter token' rejection", sub, err)
			}

			// A well-formed filter must NOT be rejected (no over-rejection).
			var goodErr error
			captureStdout(t, func() {
				goodErr = c.handleShowSecurity([]string{"policies", sub, "from-zone", "trust", "to-zone", "untrust"})
			})
			if goodErr != nil {
				t.Fatalf("%s: valid filter wrongly rejected: %v", sub, goodErr)
			}
		})
	}
}
