package dataplane

import "testing"

// #4795 RED-on-revert: getOriginalKernelName unconditionally appended
// "f<function>" to a derived PCI-path interface name
// (fmt.Sprintf("enp%ds%df%d", bus, slot, fn)). systemd's udev-builtin-net_id
// "path" naming scheme (names_pci_slot()) only appends that suffix when the
// PCI function number is nonzero OR the device is a genuine multi-function
// device (the kernel PCI_HEADER_TYPE multi-function bit). A single-function
// NIC at e.g. 0000:09:00.0 is named enp9s0 by systemd, not enp9s0f0 — the
// unconditional suffix produced a wrong .link OriginalName for every
// single-function card, breaking RETH-member interface matching
// (ensureRethLinkOriginalName / linksetup.go match RETH members by
// OriginalName, not MAC).
//
// pciFunctionSuffix is the extracted pure boundary function; this test
// pins its logic without touching sysfs.
func TestPCIFunctionSuffix(t *testing.T) {
	cases := []struct {
		name          string
		multifunction bool
		fn            uint64
		want          string
	}{
		{
			name:          "single-function device at function 0 omits suffix",
			multifunction: false,
			fn:            0,
			want:          "",
		},
		{
			name:          "multi-function device at function 0 carries suffix",
			multifunction: true,
			fn:            0,
			want:          "f0",
		},
		{
			name:          "nonzero function always carries suffix even if not flagged multifunction",
			multifunction: false,
			fn:            1,
			want:          "f1",
		},
		{
			name:          "multi-function device at a nonzero function carries suffix",
			multifunction: true,
			fn:            2,
			want:          "f2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pciFunctionSuffix(tc.multifunction, tc.fn); got != tc.want {
				t.Errorf("pciFunctionSuffix(%v, %d) = %q, want %q",
					tc.multifunction, tc.fn, got, tc.want)
			}
		})
	}
}

// TestIsPCIMultifunctionDevice_MissingSysfsReturnsFalse pins the
// conservative failure mode: a nonexistent PCI address (no sysfs config
// file, as in any non-bare-metal test environment) reports false rather
// than panicking or erroring, matching systemd's own fail-safe behavior.
func TestIsPCIMultifunctionDevice_MissingSysfsReturnsFalse(t *testing.T) {
	if got := isPCIMultifunctionDevice("0000:ff:1f.7"); got != false {
		t.Errorf("isPCIMultifunctionDevice on a nonexistent PCI address = %v, want false", got)
	}
}
