package daemon

import "testing"

// #4815: lifelineRecord is documented (bootstrap.go type comment) as "Keyed
// by PCI address... MAC (tiebreaker for non-PCI NICs)" — implying a NIC
// with no PCI bus device should still get a MAC-only record. Before the
// fix, pciAddrForInterface short-circuited on PCI resolution failure and
// returned (lifelineRecord{}, false) WITHOUT ever computing a MAC, so
// setupBootstrapLifeline never wrote a lifeline record at all for a
// non-PCI (virtio, bond, VLAN sub-interface, ...) management NIC — the
// documented MAC-fallback path was unreachable code, not implemented.
//
// lifelineRecordFromParts is the pure decision core factored out of
// pciAddrForInterface so this fix is unit-testable without a real non-PCI
// NIC or sysfs/netlink mocking.
//
// FAIL-ON-REVERT: reverting pciAddrForInterface / lifelineRecordFromParts
// to the pre-fix short-circuit either fails to compile (the pure function
// no longer exists) or reintroduces the "PCI empty => always not-found"
// behavior, which the MAC-only subtest below catches directly.

func TestLifelineRecordFromParts(t *testing.T) {
	tests := []struct {
		name        string
		pciAddr     string
		mac         string
		wantOK      bool
		wantPCIAddr string
		wantMAC     string
	}{
		{
			name:        "pci and mac both present (normal PCI NIC)",
			pciAddr:     "0000:05:00.0",
			mac:         "52:54:00:ab:cd:ef",
			wantOK:      true,
			wantPCIAddr: "0000:05:00.0",
			wantMAC:     "52:54:00:ab:cd:ef",
		},
		{
			// The #4815 regression: a non-PCI NIC (virtio, bond, VLAN
			// sub-interface) has no PCI bus device but IS a live link with
			// a MAC — this must still resolve to a usable (MAC-only)
			// record, not silently report not-found.
			name:        "no pci, mac present (non-PCI/virtio NIC)",
			pciAddr:     "",
			mac:         "52:54:00:11:22:33",
			wantOK:      true,
			wantPCIAddr: "",
			wantMAC:     "52:54:00:11:22:33",
		},
		{
			name:    "neither pci nor mac resolvable",
			pciAddr: "",
			mac:     "",
			wantOK:  false,
		},
		{
			// Degenerate: a PCI address resolved but the netlink MAC
			// lookup failed (interface disappeared mid-race). Still
			// usable — PCI alone is sufficient (matches pre-fix behavior
			// for the PCI-primary case).
			name:        "pci present, mac lookup failed",
			pciAddr:     "0000:09:00.0",
			mac:         "",
			wantOK:      true,
			wantPCIAddr: "0000:09:00.0",
			wantMAC:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, ok := lifelineRecordFromParts(tt.pciAddr, tt.mac)
			if ok != tt.wantOK {
				t.Fatalf("lifelineRecordFromParts(%q, %q) ok = %v, want %v",
					tt.pciAddr, tt.mac, ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if rec.PCIAddr != tt.wantPCIAddr || rec.MAC != tt.wantMAC {
				t.Fatalf("lifelineRecordFromParts(%q, %q) = %+v, want {PCIAddr:%q MAC:%q}",
					tt.pciAddr, tt.mac, rec, tt.wantPCIAddr, tt.wantMAC)
			}
		})
	}
}

// TestPCIAddrForInterfaceUnknownReportsNotFound pins pciAddrForInterface's
// real (non-mocked) behavior on an interface name that does not exist on
// this host: sysfs symlink eval fails AND the netlink lookup fails, so the
// wrapper must still report not-found (both signals genuinely absent) —
// distinguishing "nothing resolvable" from the #4815 "PCI absent but MAC
// present" case that must now succeed.
func TestPCIAddrForInterfaceUnknownReportsNotFound(t *testing.T) {
	if _, ok := pciAddrForInterface("xpf-test-nonexistent-iface-4815"); ok {
		t.Fatal("pciAddrForInterface on a nonexistent interface must report not-found")
	}
}
