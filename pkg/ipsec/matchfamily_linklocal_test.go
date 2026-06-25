package ipsec

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestMatchFamilyLinkLocalIPv6 is the fail-on-revert guard for #2885:
// matchFamily must accept an IPv6 link-local unicast (fe80::/10) address when
// the gateway family hint is IPv6 (family 6). Before the fix, the
// IsGlobalUnicast() gate rejected link-local, so an IPsec local-bind on a
// point-to-point / link-local IPv6 link could never source from fe80::.
func TestMatchFamilyLinkLocalIPv6(t *testing.T) {
	ll := net.ParseIP("fe80::1")
	if ll == nil {
		t.Fatal("failed to parse fe80::1")
	}

	if got := matchFamily(ll, 6); got != "fe80::1" {
		t.Fatalf("matchFamily(fe80::1, 6) = %q, want %q (link-local IPv6 must "+
			"be selectable for family-6 IPsec local binds, #2885)", got, "fe80::1")
	}

	// A global IPv6 address must still be selected for family 6.
	if got := matchFamily(net.ParseIP("2001:db8::5"), 6); got != "2001:db8::5" {
		t.Fatalf("matchFamily(2001:db8::5, 6) = %q, want %q", got, "2001:db8::5")
	}
}

// TestMatchFamilyExclusions verifies the fix keeps the unsafe candidates
// excluded: IPv6 link-local must not leak into family-4 or family-agnostic
// selection, and multicast/unspecified/loopback stay rejected everywhere.
func TestMatchFamilyExclusions(t *testing.T) {
	ll6 := net.ParseIP("fe80::1")

	// Link-local IPv6 must not surface under a family-4 request.
	if got := matchFamily(ll6, 4); got != "" {
		t.Fatalf("matchFamily(fe80::1, 4) = %q, want empty", got)
	}
	// Link-local IPv6 must not surface implicitly under family-agnostic (0)
	// selection — only an explicit family-6 hint may bind link-local.
	if got := matchFamily(ll6, 0); got != "" {
		t.Fatalf("matchFamily(fe80::1, 0) = %q, want empty", got)
	}

	// IPv4 link-local (169.254.0.0/16) is not a usable IPsec source.
	if got := matchFamily(net.ParseIP("169.254.1.2"), 4); got != "" {
		t.Fatalf("matchFamily(169.254.1.2, 4) = %q, want empty", got)
	}

	excluded := []net.IP{
		net.ParseIP("ff02::1"),   // IPv6 multicast
		net.ParseIP("::"),        // IPv6 unspecified
		net.ParseIP("::1"),       // IPv6 loopback
		net.ParseIP("127.0.0.1"), // IPv4 loopback
		net.ParseIP("0.0.0.0"),   // IPv4 unspecified
	}
	for _, ip := range excluded {
		for _, fam := range []int{0, 4, 6} {
			if got := matchFamily(ip, fam); got != "" {
				t.Fatalf("matchFamily(%s, %d) = %q, want empty", ip, fam, got)
			}
		}
	}

	// A global IPv4 still selected for family 4.
	if got := matchFamily(net.ParseIP("203.0.113.7"), 4); got != "203.0.113.7" {
		t.Fatalf("matchFamily(203.0.113.7, 4) = %q, want %q", got, "203.0.113.7")
	}
}

// TestSelectUnitAddressFamily6GlobalWinsOverLinkLocal is the fail-on-revert
// guard for #2885 MINOR-1: family-6 selection must prefer a global-unicast
// address over a link-local one REGARDLESS of candidate order. Here the
// link-local is listed FIRST, so a naive first-match loop would pick it; the
// two-pass selectFamilyAddress must still return the global. This goes RED if
// the global-only first pass in selectFamilyAddress is removed.
func TestSelectUnitAddressFamily6GlobalWinsOverLinkLocal(t *testing.T) {
	unit := &config.InterfaceUnit{
		// Link-local enumerated BEFORE the global IPv6.
		Addresses: []string{"fe80::1/64", "2001:db8::5/64"},
	}
	if got := selectUnitAddress(unit, 6); got != "2001:db8::5" {
		t.Fatalf("selectUnitAddress(family 6) = %q, want %q (global must win "+
			"over link-local regardless of order, #2885)", got, "2001:db8::5")
	}

	// When ONLY a link-local IPv6 is present, family 6 falls back to it.
	llOnly := &config.InterfaceUnit{Addresses: []string{"fe80::1/64"}}
	if got := selectUnitAddress(llOnly, 6); got != "fe80::1" {
		t.Fatalf("selectUnitAddress(link-local only, family 6) = %q, want %q",
			got, "fe80::1")
	}
}

// TestResolveConfiguredInterfaceAddressZoneQualifiesLinkLocal is the
// fail-on-revert guard for #2885 MINOR-2: a link-local local-bind source must
// be emitted with its IPv6 zone (%<iface>) so strongSwan can disambiguate
// fe80:: on a multi-interface box. A global address must NOT be zone-qualified.
// This goes RED if the zoneQualify() call is removed from
// resolveConfiguredInterfaceAddress.
func TestResolveConfiguredInterfaceAddressZoneQualifiesLinkLocal(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/3": {
			Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"fe80::1/64"}},
			},
		},
	}
	// config.LinuxIfName("ge-0/0/3") == "ge-0-0-3" is the kernel zone name.
	want := "fe80::1%" + config.LinuxIfName("ge-0/0/3")
	if got := resolveConfiguredInterfaceAddress(cfg, "ge-0/0/3.0", 6); got != want {
		t.Fatalf("resolveConfiguredInterfaceAddress(link-local, family 6) = %q, "+
			"want %q (link-local source must carry %%iface zone, #2885)", got, want)
	}

	// A global IPv6 source is emitted bare (no zone).
	cfg.Interfaces.Interfaces["ge-0/0/4"] = &config.InterfaceConfig{
		Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"2001:db8::5/64"}},
		},
	}
	if got := resolveConfiguredInterfaceAddress(cfg, "ge-0/0/4.0", 6); got != "2001:db8::5" {
		t.Fatalf("resolveConfiguredInterfaceAddress(global, family 6) = %q, "+
			"want %q (global source must NOT be zone-qualified)", got, "2001:db8::5")
	}
}
