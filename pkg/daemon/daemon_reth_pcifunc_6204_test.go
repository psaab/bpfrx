package daemon

import "testing"

// TestPCIAddrToEnp_FunctionIsDecimal_6204 is the #6204 fail-on-revert pin for
// the PCI FUNCTION base.
//
// pciAddrToEnp parsed every component of a PCI address as hex. Domain, bus and
// slot really are hex, but the function is DECIMAL, and the asymmetry is not
// ours to choose: the kernel formats a PCI address as "%04x:%02x:%02x.%d", and
// systemd's net_id builtin matches that by scanning "%x:%x:%x.%u" and emitting
// "f%u" (systemd.net-naming-scheme(7)). A sysfs address for ARI function 10
// therefore reads ".10", never ".a".
//
// Parsing the function as hex agrees with systemd for functions 0-7, where the
// two bases coincide, and silently disagrees from 8 upward: ".10" read as hex is
// 16, so xpf derives "enp3s0f16" where the link is actually named "enp3s0f10".
// The RETH member's OriginalName= lookup then never matches and that NIC is
// neither renamed nor bound. Only ARI-capable multifunction devices reach
// function >= 10, which is why the bug survived.
//
// Fail-on-revert: change the function parse back to base 16
// (`strconv.ParseUint(sf[1], 16, 8)`). The ari_* subtests go RED with a clean
// assertion — f10 becomes f16, f15 becomes f21 — while every low_* subtest
// stays GREEN, because 0-7 are identical in both bases. That split is the point:
// a mutation that broke the common case too would prove much less.
func TestPCIAddrToEnp_FunctionIsDecimal_6204(t *testing.T) {
	tests := []struct {
		name string
		pci  string
		want string
	}{
		// Functions 0-7 parse identically in base 10 and base 16. These are the
		// control cases: they MUST stay green under the hex mutation, which is
		// what shows the fix is scoped to the functions that actually differ.
		{"low_func0", "0000:03:00.0", "enp3s0"},
		{"low_func1", "0000:03:00.1", "enp3s0f1"},
		{"low_func7", "0000:03:00.7", "enp3s0f7"},

		// Function 8 and 9: still identical in both bases, still controls.
		{"low_func8", "0000:03:00.8", "enp3s0f8"},
		{"low_func9", "0000:03:00.9", "enp3s0f9"},

		// ARI functions >= 10 are where the bases diverge. Under the hex parse
		// these produced f16, f17, f21 and f255-as-0x255-overflow respectively.
		{"ari_func10", "0000:03:00.10", "enp3s0f10"},
		{"ari_func11", "0000:03:00.11", "enp3s0f11"},
		{"ari_func15", "0000:03:00.15", "enp3s0f15"},
		{"ari_func31", "0000:03:00.31", "enp3s0f31"},

		// ARI + a non-zero PCI domain together, so the #6199 domain segment and
		// the #6204 function base are exercised on one address.
		{"ari_with_domain", "0001:03:00.10", "enP1p3s0f10"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pciAddrToEnp(tt.pci); got != tt.want {
				t.Fatalf("pciAddrToEnp(%q) = %q, want %q — the PCI function is "+
					"DECIMAL (kernel prints \"%%04x:%%02x:%%02x.%%d\", systemd emits \"f%%u\"), "+
					"so parsing it as hex renames the NIC to a name systemd never assigns "+
					"and the RETH OriginalName= lookup silently fails to match",
					tt.pci, got, tt.want)
			}
		})
	}

	// The bug's concrete consequence: under the hex parse, function 10 and
	// function 16 both derived "f16", so two distinct ARI functions collided
	// onto one predictable name and could resolve the wrong RETH member.
	if a, b := pciAddrToEnp("0000:03:00.10"), pciAddrToEnp("0000:03:00.16"); a == b {
		t.Fatalf("ARI function collision: pciAddrToEnp(...:00.10)=%q == pciAddrToEnp(...:00.16)=%q — "+
			"distinct PCI functions must not share a predictable name", a, b)
	}

	// A hex-spelled function is now malformed rather than silently accepted.
	// Real sysfs never emits it, so returning "" (no rename attempted) is the
	// fail-closed answer; the pre-fix behaviour bound a NIC under a name systemd
	// does not use, which is worse than declining to bind it.
	for _, bad := range []string{"0000:03:00.a", "0000:03:00.ff", "0000:03:00.0x1"} {
		if got := pciAddrToEnp(bad); got != "" {
			t.Fatalf("pciAddrToEnp(%q) = %q, want \"\" — a hex-spelled function is not a "+
				"real sysfs address and must not resolve to a name", bad, got)
		}
	}
}
