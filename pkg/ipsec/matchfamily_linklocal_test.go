package ipsec

import (
	"net"
	"testing"
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
