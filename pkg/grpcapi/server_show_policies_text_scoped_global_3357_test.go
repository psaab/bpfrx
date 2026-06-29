package grpcapi

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #3357: the gRPC text hit-count and detail surfaces suppressed the global
// block whenever a `from-zone X to-zone Y` filter was present
// (`filterFrom == "" && filterTo == ""` gate), so a scoped global (#3148)
// enforced for exactly that pair vanished from the filtered output. The
// filtered surfaces now include an unscoped global (every pair) and a scoped
// global targeting the filter, while excluding a scoped global bound to a
// different pair.

// scopedGlobalFilterStore builds a config with a scoped global for
// trust->untrust, a scoped global for the off-pair trust->dmz, and an
// unscoped (all-zones) global, plus the zones they reference.
func scopedGlobalFilterStore(t *testing.T) *configstore.Store {
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
            policy scoped-tu {
                match {
                    from-zone trust;
                    to-zone untrust;
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
            policy open-global {
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
	if cfg := store.ActiveConfig(); cfg == nil || len(cfg.Security.GlobalPolicies) != 3 {
		t.Fatalf("expected 3 global policies, got %v", cfg)
	}
	return store
}

// TestGRPCHitCountFilteredKeepsScopedGlobal covers the gRPC text hit-count
// surface. FAIL-ON-REVERT: restoring the `filterFrom == "" && filterTo == ""`
// gate suppresses the global block, so the scoped-tu / open-global assertions
// go RED.
func TestGRPCHitCountFilteredKeepsScopedGlobal(t *testing.T) {
	s := &Server{store: scopedGlobalFilterStore(t)}

	var buf strings.Builder
	s.showPoliciesHitCount("from-zone trust to-zone untrust", &buf)
	out := buf.String()

	if !strings.Contains(out, "scoped-tu") {
		t.Fatalf("filtered hit-count dropped scoped global trust->untrust (#3357 regression):\n%s", out)
	}
	if !strings.Contains(out, "open-global") {
		t.Fatalf("filtered hit-count dropped the unscoped (all-zones) global:\n%s", out)
	}
	if strings.Contains(out, "scoped-td") {
		t.Fatalf("filtered hit-count leaked an off-pair scoped global (trust->dmz):\n%s", out)
	}
	scoped := hitCountRow(t, out, "scoped-tu")
	if !(strings.Contains(scoped, "trust") && strings.Contains(scoped, "untrust")) {
		t.Fatalf("scoped-tu hit-count row = %q, want trust/untrust columns", scoped)
	}
}

// TestGRPCDetailFilteredKeepsScopedGlobal covers the gRPC text detail surface.
// FAIL-ON-REVERT: restoring the gate suppresses the "Global policies:" block,
// so the scoped-tu assertions go RED.
func TestGRPCDetailFilteredKeepsScopedGlobal(t *testing.T) {
	s := &Server{store: scopedGlobalFilterStore(t)}

	var buf strings.Builder
	s.showPoliciesDetail("from-zone trust to-zone untrust", &buf)
	out := buf.String()

	if !strings.Contains(out, "Global policies:") {
		t.Fatalf("filtered detail dropped the Global policies block (#3357 regression):\n%s", out)
	}
	if !strings.Contains(out, "Policy: scoped-tu") {
		t.Fatalf("filtered detail dropped scoped global trust->untrust:\n%s", out)
	}
	if !strings.Contains(out, "Source zone: trust") || !strings.Contains(out, "Destination zone: untrust") {
		t.Fatalf("filtered detail missing scoped-tu zone scope:\n%s", out)
	}
	if !strings.Contains(out, "Policy: open-global") {
		t.Fatalf("filtered detail dropped the unscoped (all-zones) global:\n%s", out)
	}
	if strings.Contains(out, "Policy: scoped-td") {
		t.Fatalf("filtered detail leaked an off-pair scoped global (trust->dmz):\n%s", out)
	}
}

// hitCountRow returns the hit-count output line containing the named policy.
func hitCountRow(t *testing.T, out, name string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, name) {
			return line
		}
	}
	t.Fatalf("policy %q row not found in hit-count output:\n%s", name, out)
	return ""
}
