package grpcapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dhcpserver"
)

// TestShowDHCPServer_BothFamiliesDegradedShowBothDetails_5967 is the #5967
// PART 2 RED-on-revert guard. #5938 surfaced the degraded lease-source banner
// but selected it with `if src4.Banner() else if src6.Banner()`, so when BOTH
// the v4 and v6 lease sources were degraded only the v4 detail line printed and
// a v6-specific degradation reason (e.g. a DIFFERENT unreadable sibling file)
// was silently suppressed. The fix routes both handlers through
// dhcpserver.DegradedBanners, which emits every distinct degraded-family detail.
//
// FAIL-ON-REVERT: restore the `if src4 else if src6` selection → only the v4
// detail prints and the leases6.csv assertion below goes RED.
func TestShowDHCPServer_BothFamiliesDegradedShowBothDetails_5967(t *testing.T) {
	dir := t.TempDir()
	// A regular file used as a path component so every Kea LFC sibling open
	// fails with ENOTDIR (not IsNotExist) → parseLeaseCSVDegradable records each
	// as unreadable+skipped and marks the family Degraded with a DISTINCT detail
	// (its own file path). This makes both families degraded with different
	// banner text, so "both details printed" is observable as two distinct
	// substrings.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	leaseFile4 := filepath.Join(blocker, "leases4.csv")
	leaseFile6 := filepath.Join(blocker, "leases6.csv")

	m := dhcpserver.New()
	m.SetLeaseSyncSeamsForTesting(nil, "", "", leaseFile4, leaseFile6)
	// IsRunning() gates the lease read; force it true (no lease-sync hook is
	// configured, so the source-aware read stays on the memfile path — no socket
	// dial).
	m.SetUnitActiveForTesting(func(unit string) (bool, error) { return true, nil })

	s := &Server{dhcpServer: m}
	var buf strings.Builder
	s.showDHCPServer(&buf)
	out := buf.String()

	if !strings.Contains(out, "WARNING: DHCP lease display is DEGRADED") {
		t.Fatalf("expected a degraded-source banner, got:\n%s", out)
	}
	if !strings.Contains(out, "leases4.csv") {
		t.Fatalf("v4 degraded-source detail missing:\n%s", out)
	}
	if !strings.Contains(out, "leases6.csv") {
		t.Fatalf("v6 degraded-source detail SUPPRESSED when both families are degraded "+
			"(#5967 PART 2 — if/else-if banner regression):\n%s", out)
	}
}
