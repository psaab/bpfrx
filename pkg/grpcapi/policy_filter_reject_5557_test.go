package grpcapi

import (
	"path/filepath"
	"strings"
	"testing"
)

// policyFilter5557Server builds a Server whose active config has one
// from-zone/to-zone policy, enough for the policies-hit-count / policies-detail
// text renderers to reach the filter parser.
func policyFilter5557Server(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    zones {
        security-zone trust {
        }
        security-zone untrust {
        }
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
	return &Server{store: store}
}

// TestShowPoliciesFilterRejectsUnknownToken_5557 pins that both the
// policies-hit-count and policies-detail text surfaces REJECT an unrecognized
// filter token (e.g. a typo'd `from-zonee`) rather than silently ignoring it.
// An ignored key left the corresponding filter dimension empty, widening the
// view to all zones — an operator could read a narrow policy set as the whole
// table. Mirrors the #4814/#3696 unknown-key rejection on the other show
// surfaces.
//
// FAIL-ON-REVERT: restore the old inline `for i := 0; i+1 < len(parts); i++`
// switch (which drops unknown tokens on the floor) in either renderer and the
// "invalid filter" line disappears for the bad token.
func TestShowPoliciesFilterRejectsUnknownToken_5557(t *testing.T) {
	s := policyFilter5557Server(t)

	for _, tc := range []struct {
		name   string
		render func(filter string, buf *strings.Builder)
	}{
		{"hit-count", s.showPoliciesHitCount},
		{"detail", s.showPoliciesDetail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A typo'd key must be rejected, not silently ignored.
			var bad strings.Builder
			tc.render("from-zonee trust to-zone untrust", &bad)
			if !strings.Contains(bad.String(), "invalid filter") {
				t.Fatalf("%s: unknown filter token silently ignored; got:\n%s", tc.name, bad.String())
			}

			// A well-formed filter must NOT be rejected.
			var good strings.Builder
			tc.render("from-zone trust to-zone untrust", &good)
			if strings.Contains(good.String(), "invalid filter") {
				t.Fatalf("%s: valid filter wrongly rejected; got:\n%s", tc.name, good.String())
			}
		})
	}
}
