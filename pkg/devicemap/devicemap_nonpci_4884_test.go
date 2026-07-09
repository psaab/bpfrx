package devicemap

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #4884 (C175-HC-088): EnumeratePresentNICs dropped every NIC without a PCI
// address BEFORE its permanent MAC was read, so a non-PCI physical NIC
// (USB / platform / SoC) mapped by `key mac` never entered the inventory and a
// valid MAC-only device-map entry resolved UNBOUND — stranding the interface on
// bare-metal / SoC / USB-NIC appliances. The drop decision now lives in the
// pure classifyNetdev seam; these tests pin it and the downstream bind.

func TestClassifyNetdev(t *testing.T) {
	tests := []struct {
		name     string
		nic      string
		devReal  string
		devErr   error
		wantPCI  string
		wantKeep bool
	}{
		{
			name:     "loopback dropped",
			nic:      "lo",
			wantKeep: false,
		},
		{
			name:     "virtual netdev (no device symlink) dropped",
			nic:      "br0",
			devErr:   errors.New("no such file or directory"),
			wantKeep: false,
		},
		{
			name:     "pci nic kept with address",
			nic:      "enp8s0",
			devReal:  "/sys/devices/pci0000:00/0000:00:1c.4/0000:08:00.0",
			wantPCI:  "0000:08:00.0",
			wantKeep: true,
		},
		{
			// #4884: the regression case — a USB NIC has a `device` symlink
			// (physical) but no PCI address. It MUST be kept so a `key mac`
			// entry can bind it.
			name:     "usb nic kept with empty pci",
			nic:      "enx001122334455",
			devReal:  "/sys/devices/platform/soc/1c1b000.usb/usb1/1-1/1-1:1.0",
			wantPCI:  "",
			wantKeep: true,
		},
		{
			// #4884: SoC/platform ethernet MAC — physical, non-PCI.
			name:     "platform soc nic kept with empty pci",
			nic:      "eth0",
			devReal:  "/sys/devices/platform/soc@0/30be0000.ethernet",
			wantPCI:  "",
			wantKeep: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pci, keep := classifyNetdev(tc.nic, tc.devReal, tc.devErr)
			if keep != tc.wantKeep {
				t.Fatalf("classifyNetdev(%q) keep = %v, want %v", tc.nic, keep, tc.wantKeep)
			}
			if keep && pci != tc.wantPCI {
				t.Fatalf("classifyNetdev(%q) pci = %q, want %q", tc.nic, pci, tc.wantPCI)
			}
		})
	}
}

// TestResolveBindsNonPCIMACOnlyNIC pins the end-to-end benefit: once a non-PCI
// physical NIC (PCIAddr == "" with a factory MAC) is enumerated — which
// classifyNetdev now permits — a `key mac` device-map entry binds it instead of
// stranding it UNBOUND (#4884).
func TestResolveBindsNonPCIMACOnlyNIC(t *testing.T) {
	// A USB/SoC NIC as EnumeratePresentNICs now yields it: no PCI address, a
	// factory permanent MAC.
	nics := []PresentNIC{{Name: "enx00aabbccddee", PCIAddr: "", PermMAC: "00:aa:bb:cc:dd:ee"}}
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/0", MAC: "00:aa:bb:cc:dd:ee"},
	}
	got := Resolve(entries, nics, nil)
	if len(got) != 1 {
		t.Fatalf("want 1 binding, got %d", len(got))
	}
	if !got[0].Status.Bound() {
		t.Fatalf("non-PCI MAC-only NIC must bind, got status %v", got[0].Status)
	}
	if got[0].CurrentNIC != "enx00aabbccddee" {
		t.Fatalf("bound wrong NIC: %+v", got[0])
	}
}
