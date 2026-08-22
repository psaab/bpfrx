package daemon

import "testing"

// TestPCIAddrToEnp_Domain_6199 is the #6199 fail-on-revert pin for
// pciAddrToEnp's PCI-domain handling.
//
// Before the fix, pciAddrToEnp discarded parts[0] (the PCI domain) and always
// emitted enp<bus>s<slot>[f<func>]. That is correct for the common
// single-domain case (domain 0000, which systemd also omits), but on
// multi-PCI-domain hardware (domain != 0) systemd encodes the domain as a
// "P<domain>" segment — ID_NET_NAME_PATH = en[P<domain>]p<bus>s<slot>[f<func>]
// per systemd.net-naming-scheme(7), where "The PCI domain is only prepended
// when it is not 0." Two NICs at the same bus/slot in different domains would
// then collide onto one predictable name, resolving the wrong RETH member.
//
// systemd scans the sysfs address fields as hex and renders them decimal, so
// domain 0x10000 (sysfs "10000") becomes "P65536".
//
// Fail-on-revert: suppress the domain segment in pciAddrToEnp (e.g. change
// `if domain > 0 {` to `if false {`, or delete the `name += fmt.Sprintf(
// "P%d", domain)` line). The two domain_* subtests below go RED — the domain-N
// output regresses to the bare enp<bus>s<slot> form and collides with domain 0
// — while the domain0_* subtests (the pinned common case) stay GREEN. Clean
// assertion failure, not a compile break.
func TestPCIAddrToEnp_Domain_6199(t *testing.T) {
	tests := []struct {
		name string
		pci  string
		want string
	}{
		// Domain 0000: bare enp<bus>s<slot>[f<func>]. These MUST stay
		// bit-identical to the pre-fix output — the single-domain deployments
		// (test VM, loss cluster) are all domain 0 and must not regress.
		{"domain0_basic", "0000:08:00.0", "enp8s0"},
		{"domain0_slot1", "0000:01:00.0", "enp1s0"},
		{"domain0_func1", "0000:03:00.1", "enp3s0f1"},
		// Non-zero domain: systemd prepends P<domain> (decimal) ->
		// enP<domain>p<bus>s<slot>[f<func>]. 0x10000 == 65536.
		{"domainN_65536", "10000:01:00.0", "enP65536p1s0"},
		// Non-zero domain AND non-zero function together.
		{"domainN_func1", "0001:03:00.1", "enP1p3s0f1"},
		// #7426: NON-ZERO SLOT rows. Every fixture above sits at slot 0, and
		// under ARI the slot term is `slot << 3`, which at slot 0 is
		// identically zero — so this file was STRUCTURALLY INCAPABLE of failing
		// on a slot-handling defect while appearing to cover the derivation.
		// It also explains why an ARI probe on a slot-0/VF-only host comes back
		// negative. These rows are taken from the ARI development host's real
		// topology (bus 0xb7 == 183, slots 2 and 6 are SR-IOV VFs).
		{"slot2", "0000:b7:02.0", "enp183s2"},
		{"slot6_func3", "0000:b7:06.3", "enp183s6f3"},
		{"slot31_func7", "0000:ff:1f.7", "enp255s31f7"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pciAddrToEnp(tt.pci); got != tt.want {
				t.Fatalf("pciAddrToEnp(%q) = %q, want %q", tt.pci, got, tt.want)
			}
		})
	}

	// The domain must actually disambiguate: two NICs at the same bus/slot in
	// different PCI domains must NOT map to the same predictable name.
	if a, b := pciAddrToEnp("10000:01:00.0"), pciAddrToEnp("0000:01:00.0"); a == b {
		t.Fatalf("PCI-domain collision: pciAddrToEnp(10000:01:00.0)=%q == pciAddrToEnp(0000:01:00.0)=%q", a, b)
	}
	if a, b := pciAddrToEnp("0001:03:00.1"), pciAddrToEnp("0000:03:00.1"); a == b {
		t.Fatalf("PCI-domain collision (func): pciAddrToEnp(0001:03:00.1)=%q == pciAddrToEnp(0000:03:00.1)=%q", a, b)
	}

	// Preserve the existing guards: malformed input still returns "".
	for _, bad := range []string{"", "notpci", "0000:zz:00.0", "0000:01:00", "0000:01:zz.0", "0000:01:00.z"} {
		if got := pciAddrToEnp(bad); got != "" {
			t.Fatalf("pciAddrToEnp(%q) = %q, want \"\" (malformed input guard)", bad, got)
		}
	}
}
