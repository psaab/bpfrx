package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dhcpserver"
)

// TestShowDHCPServer_LocalCLISurfacesDegradedBanner_5967 is the #5967 PART 1
// RED-on-revert guard. The in-process interactive `show dhcp server` handler
// used to read GetLeases4/6 (memfile only, no live-socket preference, no
// degraded banner), so a degraded lease read on THIS surface looked like a
// healthy empty set — diverging from the authoritative gRPC path (remote cli),
// which #5938 gave the socket-preference + degraded banner. The fix routes the
// local handler through GetLeasesWithSource4/6 + dhcpserver.DegradedBanners.
//
// FAIL-ON-REVERT: restore GetLeases4/6 in showDHCPServer → no LeaseSource is
// obtained, DegradedBanners is never consulted, and the "DEGRADED" banner
// assertion goes RED (the old path prints a "warning: could not read ..."
// line, never the shared degraded banner).
func TestShowDHCPServer_LocalCLISurfacesDegradedBanner_5967(t *testing.T) {
	dir := t.TempDir()
	// A regular file used as a path component so every Kea LFC sibling open for
	// the v4 lease set fails with ENOTDIR (not IsNotExist): parseLeaseCSVDegradable
	// records them as unreadable+skipped and marks the v4 source Degraded.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	leaseFile4 := filepath.Join(blocker, "leases4.csv") // parent is a file → ENOTDIR → degraded
	leaseFile6 := filepath.Join(dir, "leases6.csv")     // absent → healthy empty (no banner)

	store := newConfigStore(t, filepath.Join(dir, "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(`
system {
    services {
        dhcp-local-server {
            group g {
                interface ge-0-0-0.0;
                pool p {
                    subnet 10.0.1.0/24;
                    address-range low 10.0.1.100 high 10.0.1.199;
                }
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

	c := &CLI{
		store: store,
		dhcpServerFn: func() *dhcpserver.Manager {
			m := dhcpserver.New()
			// leaseSyncEnabled stays false → no-hook path → memfile read only
			// (no socket dial); the ENOTDIR-blocked v4 file set degrades.
			m.SetLeaseSyncSeamsForTesting(nil, "", "", leaseFile4, leaseFile6)
			return m
		},
	}

	out := captureStdout(t, func() {
		if err := c.showDHCPServer(false); err != nil {
			t.Fatalf("showDHCPServer: %v", err)
		}
	})

	if !strings.Contains(out, "WARNING: DHCP lease display is DEGRADED") {
		t.Fatalf("local `show dhcp server` did not surface the #5938 degraded-source "+
			"banner (#5967 PART 1 — GetLeases4/6 regression; the remote gRPC path shows it):\n%s", out)
	}
	if !strings.Contains(out, "leases4.csv") {
		t.Fatalf("degraded banner missing the v4 lease-file detail:\n%s", out)
	}
}
