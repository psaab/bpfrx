package userspace

import "testing"

// TestNormalizeRouteSnapshotFamily_VRFPreserving_4423 pins the #4423 routing-
// audit L2 disposition (NOT-A-BUG). The finding claimed the Go route-snapshot
// builder's family normalization (and the mirroring Rust helper
// canonical_route_table) "silently rewrites cross-family table names" into the
// WRONG table. That premise is false: the normalization only swaps the FAMILY
// half of the table suffix (.inet.0 <-> .inet6.0) and always PRESERVES the VRF
// prefix, so a route can only ever be normalized into its own instance's
// correct family-specific table — never a different routing-instance's table.
//
// In practice the drift is unreachable for static routes: buildRouteSnapshots
// derives the table from which family-specific static list a route was compiled
// into ("inet.0"/"inet6.0"/"<vrf>.inet.0"/"<vrf>.inet6.0"), so the family is
// already correct and normalization is a no-op safety net. This test locks the
// helper's VRF-preserving contract directly so the "rewrite is corruption"
// premise stays disproved and a future edit cannot turn it into a VRF-crossing
// rewrite.
func TestNormalizeRouteSnapshotFamily_VRFPreserving_4423(t *testing.T) {
	cases := []struct {
		name        string
		table       string
		family      string
		destination string
		wantTable   string
		wantFamily  string
	}{
		// A v6 destination whose table name carries a v4 family suffix is
		// normalized to the v6 half of the SAME table — VRF prefix intact.
		{"main-v4name-v6dest", "inet.0", "inet", "2001:db8::/32", "inet6.0", "inet6"},
		{"vrf-v4name-v6dest", "tenant-a.inet.0", "inet", "2001:db8::/48", "tenant-a.inet6.0", "inet6"},
		// The symmetric v4-destination / v6-table-name case.
		{"main-v6name-v4dest", "inet6.0", "inet6", "10.0.0.0/8", "inet.0", "inet"},
		{"vrf-v6name-v4dest", "tenant-b.inet6.0", "inet6", "10.20.0.0/16", "tenant-b.inet.0", "inet"},
		// Already-correct names are unchanged (the common no-op path).
		{"main-v4-consistent", "inet.0", "inet", "10.0.0.0/8", "inet.0", "inet"},
		{"vrf-v6-consistent", "tenant-c.inet6.0", "inet6", "2001:db8:c::/48", "tenant-c.inet6.0", "inet6"},
		// A multi-label VRF name keeps every label of its prefix.
		{"dotted-vrf-name", "east.edge.inet.0", "inet", "2001:db8::/32", "east.edge.inet6.0", "inet6"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotTable, gotFamily := normalizeRouteSnapshotFamily(tc.table, tc.family, tc.destination)
			if gotTable != tc.wantTable {
				t.Fatalf("table = %q, want %q (VRF prefix must be preserved; only the family suffix may change)", gotTable, tc.wantTable)
			}
			if gotFamily != tc.wantFamily {
				t.Fatalf("family = %q, want %q", gotFamily, tc.wantFamily)
			}
		})
	}
}
