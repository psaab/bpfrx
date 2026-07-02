package userspace

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// TestRouteSnapshotDedupeKeepsDiscardAndConnected verifies #3770 H8: a
// discard (blackhole) static route and a connected route to the SAME
// prefix are DISTINCT forwarding decisions and must both survive the
// dedupe. Before the fix the dedupe key omitted Discard, so the two
// collided on Table|Family|Destination|NextHops|NextTable and the
// second-inserted one was silently dropped, hiding a real route.
func TestRouteSnapshotDedupeKeepsDiscardAndConnected(t *testing.T) {
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "10.0.1.0/24", Discard: true},
	}
	ifaces := []InterfaceSnapshot{
		{
			Name: "ge-0-0-1",
			Addresses: []InterfaceAddressSnapshot{
				{Family: "inet", Address: "10.0.1.5/24", Scope: int(netlink.SCOPE_UNIVERSE)},
			},
		},
	}

	routes, err := buildRouteSnapshots(cfg, ifaces, nil)
	if err != nil {
		t.Fatal(err)
	}

	var haveDiscard, haveConnected bool
	count := 0
	for _, r := range routes {
		if r.Table == "inet.0" && r.Family == "inet" && r.Destination == "10.0.1.0/24" {
			count++
			if r.Discard {
				haveDiscard = true
			} else {
				haveConnected = true
			}
		}
	}
	if count != 2 || !haveDiscard || !haveConnected {
		t.Fatalf("routes for 10.0.1.0/24: count=%d haveDiscard=%v haveConnected=%v, want both a discard and a connected entry (%+v)",
			count, haveDiscard, haveConnected, routes)
	}
}

// TestRouteSnapshotDedupeKeepsDistinctPreference verifies #3770 H8 for
// preference: two routes to the same prefix and next-table differing
// ONLY in preference are distinct and both survive so the Rust FIB can
// apply its preference tie-break.
func TestRouteSnapshotDedupeKeepsDistinctPreference(t *testing.T) {
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "10.5.0.0/16", NextTable: "blue.inet.0", Preference: 5},
		{Destination: "10.5.0.0/16", NextTable: "blue.inet.0", Preference: 0},
	}
	routes, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, r := range routes {
		if r.Table == "inet.0" && r.Destination == "10.5.0.0/16" && r.NextTable == "blue.inet.0" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("distinct-preference routes for 10.5.0.0/16 = %d, want 2 (%+v)", count, routes)
	}
}

// TestRouteSnapshotSortIsDeterministic verifies #3770 M10: the emitted
// order is a deterministic function of route CONTENT, not of the build
// input order. Two same-prefix routes that differ only in next-table
// tie on the old Table/Family/Destination comparator; under the old
// UNSTABLE sort their order tracked the input slice order, so an
// unchanged config could churn the snapshot. Building the same content
// with the two entries in opposite input order must yield an identical
// snapshot.
func TestRouteSnapshotSortIsDeterministic(t *testing.T) {
	forward := &config.Config{}
	forward.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "10.5.0.0/16", NextTable: "aaa.inet.0"},
		{Destination: "10.5.0.0/16", NextTable: "bbb.inet.0"},
	}
	reverse := &config.Config{}
	reverse.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "10.5.0.0/16", NextTable: "bbb.inet.0"},
		{Destination: "10.5.0.0/16", NextTable: "aaa.inet.0"},
	}

	got1, err := buildRouteSnapshots(forward, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got2, err := buildRouteSnapshots(reverse, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got1, got2) {
		t.Fatalf("route order depends on input order (non-deterministic):\n forward=%+v\n reverse=%+v", got1, got2)
	}
	// The tie-break is lexicographic on next-table: aaa before bbb.
	var order []string
	for _, r := range got1 {
		if r.Table == "inet.0" && r.Destination == "10.5.0.0/16" {
			order = append(order, r.NextTable)
		}
	}
	if len(order) != 2 || order[0] != "aaa.inet.0" || order[1] != "bbb.inet.0" {
		t.Fatalf("next-table tie-break order = %v, want [aaa.inet.0 bbb.inet.0]", order)
	}
}

// TestRouteOverlayCarriesStaticPreference verifies #3770 M7: the
// ip-monitoring overlay route is injected at the documented Static/1
// preference (route preference 1), matching the FRR managed-section
// distance-1 static, not the default 0.
func TestRouteOverlayCarriesStaticPreference(t *testing.T) {
	cfg := &config.Config{}
	overlay := []config.RouteOverlayEntry{
		{Destination: "0.0.0.0/0", NextHop: "172.16.80.1", Policy: "wan-failover"},
	}
	routes, err := buildRouteSnapshots(cfg, nil, overlay)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, r := range routes {
		if r.Table == "inet.0" && r.Destination == "0.0.0.0/0" {
			found = true
			if r.Preference != 1 {
				t.Fatalf("overlay route preference = %d, want 1 (Static/1)", r.Preference)
			}
		}
	}
	if !found {
		t.Fatalf("overlay default route not found in %+v", routes)
	}
}
