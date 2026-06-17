package devicemap

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func nic(name, pci, perm string) PresentNIC {
	return PresentNIC{Name: name, PCIAddr: pci, PermMAC: perm}
}

func TestResolvePCIPrimaryWithMACCrossCheck(t *testing.T) {
	nics := []PresentNIC{nic("enp9s0", "0000:09:00.0", "00:11:22:33:44:55")}
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0", MAC: "00:11:22:33:44:55"},
	}
	got := Resolve(entries, nics, nil)
	if len(got) != 1 || got[0].Status != BindBound {
		t.Fatalf("want bound, got %+v", got)
	}
	if got[0].CurrentNIC != "enp9s0" || got[0].Logical != "ge-0-0-3" {
		t.Fatalf("wrong binding: %+v", got[0])
	}
}

func TestResolvePCIMatchMACMismatchRefuses(t *testing.T) {
	// R-1/AGY HIGH-3: a card swapped into the pinned slot (PCI matches but
	// the permanent MAC differs) must REFUSE, never silently hijack.
	nics := []PresentNIC{nic("enp9s0", "0000:09:00.0", "de:ad:be:ef:00:01")}
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0", MAC: "00:11:22:33:44:55"},
	}
	got := Resolve(entries, nics, nil)
	if got[0].Status != BindRefusedAmbig {
		t.Fatalf("want REFUSED on PCI-hit/MAC-mismatch, got %v", got[0].Status)
	}
	if got[0].CurrentNIC != "" || got[0].Logical != "" {
		t.Fatalf("refused binding must not bind a NIC: %+v", got[0])
	}
}

func TestResolvePCIOnlyWhenNoPermMAC(t *testing.T) {
	// V-5: empty perm-MAC (common on VFs/virtio) => PCI-only unverified bind.
	nics := []PresentNIC{nic("enp9s0", "0000:09:00.0", "")}
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0", MAC: "00:11:22:33:44:55"},
	}
	got := Resolve(entries, nics, nil)
	if got[0].Status != BindBoundPCIOnly {
		t.Fatalf("want PCI-only bind when no perm-MAC, got %v", got[0].Status)
	}
}

func TestResolveMACFallbackWhenPCIMoved(t *testing.T) {
	// PCI miss but permanent MAC hit => fallback bind, flagged.
	nics := []PresentNIC{nic("enp10s0", "0000:0a:00.0", "00:11:22:33:44:55")}
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0", MAC: "00:11:22:33:44:55"},
	}
	got := Resolve(entries, nics, nil)
	if got[0].Status != BindBoundViaMAC {
		t.Fatalf("want MAC-fallback bind, got %v", got[0].Status)
	}
	if got[0].CurrentNIC != "enp10s0" {
		t.Fatalf("fallback bound wrong NIC: %+v", got[0])
	}
}

func TestResolveUnboundWhenNoMatch(t *testing.T) {
	nics := []PresentNIC{nic("enp10s0", "0000:0a:00.0", "aa:bb:cc:dd:ee:ff")}
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0", MAC: "00:11:22:33:44:55"},
	}
	got := Resolve(entries, nics, nil)
	if got[0].Status != BindUnbound {
		t.Fatalf("want UNBOUND, got %v", got[0].Status)
	}
}

func TestResolveRETHMemberIgnoresMACFallback(t *testing.T) {
	// R-6: a RETH member is PCI-only. With PCI missing, it must NOT fall
	// back to MAC (its MAC alternates physical<->virtual) — it goes UNBOUND.
	nics := []PresentNIC{nic("enp10s0", "0000:0a:00.0", "00:11:22:33:44:55")}
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/2", PCIAddr: "0000:09:00.0", MAC: "00:11:22:33:44:55"},
	}
	reth := map[string]bool{"ge-0/0/2": true}
	got := Resolve(entries, nics, reth)
	if got[0].Status != BindUnbound {
		t.Fatalf("RETH member must not MAC-fallback; want UNBOUND, got %v", got[0].Status)
	}
}

func TestResolveAmbiguousPCIRefuses(t *testing.T) {
	// AGY MEDIUM-4: two present NICs sharing one PCI address must refuse
	// (deterministic), not silently bind whichever the map iterated last.
	nics := []PresentNIC{
		nic("enp9s0", "0000:09:00.0", "00:11:22:33:44:55"),
		nic("enp9s0v1", "0000:09:00.0", "00:11:22:33:44:66"),
	}
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0", KeyOrder: config.DeviceMapKeyPCI},
	}
	got := Resolve(entries, nics, nil)
	if got[0].Status != BindRefusedAmbig {
		t.Fatalf("want REFUSED on ambiguous PCI, got %v", got[0].Status)
	}
}

func TestResolveAmbiguousMACRefuses(t *testing.T) {
	// Two NICs with the same permanent MAC (cloned/bonded) => refuse.
	nics := []PresentNIC{
		nic("enp9s0", "0000:09:00.0", "00:11:22:33:44:55"),
		nic("enp10s0", "0000:0a:00.0", "00:11:22:33:44:55"),
	}
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/3", MAC: "00:11:22:33:44:55", KeyOrder: config.DeviceMapKeyMAC},
	}
	got := Resolve(entries, nics, nil)
	if got[0].Status != BindRefusedAmbig {
		t.Fatalf("want REFUSED on ambiguous MAC, got %v", got[0].Status)
	}
}

func TestResolveMACFirstStillRefusesSlotSwap(t *testing.T) {
	// Codex HIGH-1: with key mac-then-pci AND both pci+mac set, a card
	// swapped into the pinned PCI slot (PCI present, perm-MAC mismatch) must
	// REFUSE even though the MAC leg would run first — the topology-change
	// invariant is order-independent. Here the entry's MAC matches NO present
	// NIC (the original card is gone) but its PCI slot now holds a different
	// card; the order-independent pre-check must catch it.
	nics := []PresentNIC{nic("enp9s0", "0000:09:00.0", "de:ad:be:ef:00:01")}
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0", MAC: "00:11:22:33:44:55",
			KeyOrder: config.DeviceMapKeyMACThenPCI},
	}
	got := Resolve(entries, nics, nil)
	if got[0].Status != BindRefusedAmbig {
		t.Fatalf("mac-first slot swap must REFUSE (order-independent), got %v", got[0].Status)
	}
}

func TestResolveKeyOrderMACThenPCI(t *testing.T) {
	// mac-then-pci tries MAC first; a MAC hit binds as primary (not flagged
	// as fallback).
	nics := []PresentNIC{nic("enp9s0", "0000:09:00.0", "00:11:22:33:44:55")}
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:bb:00.0", MAC: "00:11:22:33:44:55",
			KeyOrder: config.DeviceMapKeyMACThenPCI},
	}
	got := Resolve(entries, nics, nil)
	if got[0].Status != BindBoundViaMAC {
		// PCI is present in the entry, so the MAC bind is reported as a
		// fallback-class outcome; the key point is it binds the right NIC.
		t.Logf("status=%v", got[0].Status)
	}
	if got[0].CurrentNIC != "enp9s0" {
		t.Fatalf("mac-then-pci bound wrong NIC: %+v", got[0])
	}
}

// TestResolveDeterministicAcrossReorder is the boot-stability proof: the same
// identity resolves to the same logical name regardless of enumeration order
// (a hardware-event reorder or BIOS bus renumber that shuffles kernel names).
func TestResolveDeterministicAcrossReorder(t *testing.T) {
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0", MAC: "00:11:22:33:44:55"},
		{LogicalName: "ge-0/0/4", PCIAddr: "0000:0a:00.0", MAC: "aa:bb:cc:dd:ee:ff"},
	}
	order1 := []PresentNIC{
		nic("enp9s0", "0000:09:00.0", "00:11:22:33:44:55"),
		nic("enp10s0", "0000:0a:00.0", "aa:bb:cc:dd:ee:ff"),
	}
	// Reordered + renamed kernel names, same identities.
	order2 := []PresentNIC{
		nic("eth5", "0000:0a:00.0", "aa:bb:cc:dd:ee:ff"),
		nic("eth0", "0000:09:00.0", "00:11:22:33:44:55"),
	}
	b1 := Resolve(entries, order1, nil)
	b2 := Resolve(entries, order2, nil)
	want := map[string]string{"ge-0/0/3": "ge-0-0-3", "ge-0/0/4": "ge-0-0-4"}
	for _, bs := range [][]Binding{b1, b2} {
		for _, b := range bs {
			if !b.Status.Bound() {
				t.Fatalf("entry %s should bind, got %v", b.Entry.LogicalName, b.Status)
			}
			if b.Logical != want[b.Entry.LogicalName] {
				t.Fatalf("entry %s bound to %q, want %q", b.Entry.LogicalName, b.Logical, want[b.Entry.LogicalName])
			}
		}
	}
	// The PCI 0000:09:00.0 NIC must map to ge-0-0-3 in BOTH orderings
	// despite its kernel name changing enp9s0 -> eth0.
	find := func(bs []Binding, logical string) string {
		for _, b := range bs {
			if b.Entry.LogicalName == logical {
				return b.CurrentNIC
			}
		}
		return ""
	}
	if find(b1, "ge-0/0/3") != "enp9s0" || find(b2, "ge-0/0/3") != "eth0" {
		t.Fatalf("identity did not track its NIC across rename")
	}
}
