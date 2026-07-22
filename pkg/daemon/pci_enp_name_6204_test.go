package daemon

import "testing"

// #6204: pciAddrToEnp must reproduce the exact predictable interface name
// systemd assigns (ID_NET_NAME_PATH), because deriveKernelName feeds the
// result into the RETH-member OriginalName= lookup. systemd parses the sysfs
// PCI address with sscanf("%x:%x:%x.%u") — domain/bus/slot HEX, but the
// FUNCTION DECIMAL — matching the kernel's "%04x:%02x:%02x.%d" sysfs naming.
//
// The pre-#6204 code parsed the function base-16. That coincided with systemd
// only for single-digit functions 0-9 (where hex and decimal are identical),
// but diverged for any function >= 10 (ARI / SR-IOV multi-function devices):
// sysfs "0000:65:00.10" (decimal function 10) was misread as 0x10 = 16 and
// produced enp101s0f16 instead of systemd's enp101s0f10, resolving the wrong
// RETH member.
//
// FAIL-ON-REVERT: the func >= 10 cases below assert the DECIMAL name. Reverting
// the function parse to base-16 (strconv.ParseUint(sf[1], 16, 8)) turns func
// "10" into 16 and func "15" into 21, so those rows go RED.
func TestPCIAddrToEnpFunctionIsDecimal(t *testing.T) {
	tests := []struct {
		name    string
		pciAddr string
		want    string
	}{
		// --- func >= 10: the #6204 regression guard (hex vs decimal diverge) ---
		{
			name:    "ARI function 10 renders decimal, not hex 0x10=16",
			pciAddr: "0000:65:00.10",
			want:    "enp101s0f10",
		},
		{
			name:    "ARI function 15 renders decimal, not hex 0x15=21",
			pciAddr: "0000:65:00.15",
			want:    "enp101s0f15",
		},
		{
			name:    "ARI function 42 on bus 0x08",
			pciAddr: "0000:08:00.42",
			want:    "enp8s0f42",
		},
		// --- func < 10: base-agnostic single digit, must still hold ---
		{
			name:    "func 0 is suppressed for a non-multifunction name",
			pciAddr: "0000:08:00.0",
			want:    "enp8s0",
		},
		{
			name:    "single-digit func 3 unchanged",
			pciAddr: "0000:08:00.3",
			want:    "enp8s0f3",
		},
		{
			name:    "single-digit func 7 (max standard PCI split) unchanged",
			pciAddr: "0000:65:00.7",
			want:    "enp101s0f7",
		},
		// --- domain/bus/slot stay HEX (unchanged by #6204) ---
		{
			name:    "hex bus 0x3b -> decimal 59",
			pciAddr: "0000:3b:00.0",
			want:    "enp59s0",
		},
		{
			name:    "hex slot 0x1f -> decimal 31, func 1",
			pciAddr: "0000:08:1f.1",
			want:    "enp8s31f1",
		},
		{
			name:    "non-zero domain prepended as decimal (hex 0x10000=65536)",
			pciAddr: "10000:01:00.0",
			want:    "enP65536p1s0",
		},
		{
			name:    "non-zero domain with func 10 keeps decimal func",
			pciAddr: "0001:65:00.10",
			want:    "enP1p101s0f10",
		},
		// --- malformed input returns "" (unchanged) ---
		{
			name:    "missing function separator -> empty",
			pciAddr: "0000:65:0000",
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pciAddrToEnp(tt.pciAddr); got != tt.want {
				t.Fatalf("pciAddrToEnp(%q) = %q, want %q", tt.pciAddr, got, tt.want)
			}
		})
	}
}
