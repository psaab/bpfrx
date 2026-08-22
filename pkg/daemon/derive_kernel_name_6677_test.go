package daemon

import (
	"testing"
)

// #6677. deriveKernelName re-derived a predictable name from the PCI address
// alone. That derivation cannot match systemd's, which has at least three
// inputs the address string does not carry — all measured on real hardware
// (systemd 261):
//
//	ARI          ari_enabled folds slot and function into ONE 8-bit function
//	             number (net_id: "func += slot * 8")
//	SR-IOV VF    a VF is named from its PHYSICAL function's address plus the VF
//	             index; the VF's own slot/function never appears. Measured:
//	             0000:b7:02.0 (physfn 0000:b7:00.0) -> enp183s0f0v0, where the
//	             address-only derivation yields enp183s2f0
//	port suffix  a multi-port NIC carries npN (enp183s0f0np0)
//
// The fix stops re-deriving and asks the kernel, which has already computed
// every candidate and kept them as altnames. These tests use altname sets
// captured verbatim from a real host.

func withAltNames(t *testing.T, alts map[string][]string) {
	t.Helper()
	saved := altNameCandidatesFn
	altNameCandidatesFn = func(ifName string) []string { return alts[ifName] }
	t.Cleanup(func() { altNameCandidatesFn = saved })
}

// TestDeriveKernelNamePrefersAltNames_6677 is the fail-on-revert: each case is
// a real device whose correct name the address-only derivation cannot produce.
func TestDeriveKernelNamePrefersAltNames_6677(t *testing.T) {
	for _, tc := range []struct {
		name  string
		iface string
		alts  []string
		want  string
		why   string
	}{
		{
			name:  "SR-IOV VF is named from its physical function",
			iface: "ge-0-0-3",
			alts:  []string{"enp183s0f0v0"},
			want:  "enp183s0f0v0",
			why:   "VF at 0000:b7:02.0; address-only derivation would say enp183s2f0",
		},
		{
			name:  "multi-port NIC keeps its npN port suffix",
			iface: "ge-0-0-4",
			alts:  []string{"eno5np0", "enp183s0f0np0", "enx3cecef6aa8bc"},
			want:  "eno5np0",
			why:   "onboard outranks path in the default NamePolicy",
		},
		{
			name:  "path name when no onboard name exists",
			iface: "ge-0-0-5",
			alts:  []string{"enp103s0f1", "enx3cecef6aa385"},
			want:  "enp103s0f1",
			why:   "enx is a MAC name and is never selected",
		},
		{
			name:  "hotplug slot name outranks path",
			iface: "ge-0-0-6",
			alts:  []string{"enp5s0", "ens3"},
			want:  "ens3",
			why:   "NamePolicy is onboard, then slot, then path",
		},
		{
			name:  "eth is accepted only as a last resort",
			iface: "ge-0-0-7",
			alts:  []string{"eth0"},
			want:  "eth0",
			why:   "preserves ensureRethLinkOriginalName's prior behaviour",
		},
		{
			name:  "a real predictable name outranks eth",
			iface: "ge-0-0-8",
			alts:  []string{"eth0", "enp9s0"},
			want:  "enp9s0",
			why:   "eth is the pre-predictable kernel default, not a policy output",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withAltNames(t, map[string][]string{tc.iface: tc.alts})
			got := deriveKernelName(tc.iface)
			if got != tc.want {
				t.Fatalf("deriveKernelName(%q) = %q, want %q (%s)", tc.iface, got, tc.want, tc.why)
			}
		})
	}
}

// TestDeriveKernelNameRejectsMACAltName_6677 is the negative half. A MAC-based
// altname is always present alongside the others, so accepting it would look
// like success while recording a name udev does not assign under the default
// policy.
func TestDeriveKernelNameRejectsMACAltName_6677(t *testing.T) {
	withAltNames(t, map[string][]string{"ge-0-0-9": {"enx3cecef6aa8bc"}})
	// No usable altname and no sysfs device for this fake name, so the
	// fallback finds nothing either: the result must be empty, NOT the enx name.
	if got := deriveKernelName("ge-0-0-9"); got == "enx3cecef6aa8bc" {
		t.Fatalf("a MAC-based altname must never be selected, got %q", got)
	}
}

// TestDeriveKernelNameFallsBackWhenNoAltNames_6677 pins that the PCI fallback
// is still reachable — early boot before udev has settled, or a container.
// Without this, removing the fallback entirely would go unnoticed.
func TestDeriveKernelNameFallsBackWhenNoAltNames_6677(t *testing.T) {
	withAltNames(t, map[string][]string{}) // no altnames for anything
	// A name with no sysfs device yields "" from the fallback rather than a
	// panic or a fabricated name.
	if got := deriveKernelName("definitely-not-a-real-iface"); got != "" {
		t.Fatalf("with no altnames and no sysfs device the result must be empty, got %q", got)
	}
}

// TestAltNamePrefixOrderMatchesNamePolicy_6677 pins the ORDER itself. A device
// commonly carries several candidates at once, so the order is what decides
// which name is recorded; a reordering would silently change that on every
// multi-candidate NIC.
func TestAltNamePrefixOrderMatchesNamePolicy_6677(t *testing.T) {
	want := []string{"eno", "ens", "enp", "eth"}
	if len(altNamePrefixOrder) != len(want) {
		t.Fatalf("altNamePrefixOrder = %v, want %v", altNamePrefixOrder, want)
	}
	for i := range want {
		if altNamePrefixOrder[i] != want[i] {
			t.Fatalf("altNamePrefixOrder = %v, want %v (systemd: onboard, slot, path; eth last)",
				altNamePrefixOrder, want)
		}
	}
}
