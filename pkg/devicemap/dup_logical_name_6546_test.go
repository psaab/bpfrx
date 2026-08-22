package devicemap

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6546: a device-map with a DUPLICATE LOGICAL NAME bound one logical
// interface to a nondeterministically-chosen physical NIC, durably.
//
// Resolve's post-pass already guarded the mirror-image case — two entries
// landing on ONE NIC — and refused every entry that claimed a multiply-claimed
// NIC. Nothing guarded two entries landing on one LOGICAL NAME. Both entries
// came back BOUND, and the daemon's rename loop (device_map.go, keyed by
// CurrentNIC) then renamed two different NICs toward the same final name;
// whichever the map iteration reached last won, and the choice was persisted in
// a `.link` file. On bare metal — #1956's target — that can strand management
// or place a NIC in the wrong zone, and the SAME config can bind differently
// across boots.
//
// FAIL-ON-REVERT: delete the `nameClaims[out[i].Logical] > 1` refusal from the
// Resolve post-pass and both entries below come back Bound() again.

func twoNICs() []PresentNIC {
	return []PresentNIC{
		{Name: "enp9s0", PCIAddr: "0000:09:00.0", PermMAC: "00:11:22:33:44:55"},
		{Name: "enp10s0", PCIAddr: "0000:0a:00.0", PermMAC: "00:11:22:33:44:66"},
	}
}

// TestDuplicateLogicalNameRefusesBothEntries is the core RED-on-revert.
func TestDuplicateLogicalNameRefusesBothEntries(t *testing.T) {
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0"},
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:0a:00.0"},
	}
	got := Resolve(entries, twoNICs(), nil)
	if len(got) != 2 {
		t.Fatalf("want 2 bindings, got %d", len(got))
	}
	for i, b := range got {
		if b.Status != BindRefusedDupName {
			t.Errorf("entry %d (%s pci=%s): status %v, want %v — a duplicate "+
				"logical name bound a nondeterministically-chosen NIC",
				i, b.Entry.LogicalName, b.Entry.PCIAddr, b.Status, BindRefusedDupName)
		}
		// A refused binding must carry NO target: leaving CurrentNIC/Logical
		// populated would let a caller that only checks Bound() loosely still
		// act on it.
		if b.CurrentNIC != "" || b.Logical != "" {
			t.Errorf("entry %d: refused binding still carries nic=%q logical=%q",
				i, b.CurrentNIC, b.Logical)
		}
	}
}

// TestDuplicateLogicalNameAcrossSpellingsRefuses: the Junos slash form and the
// kernel dash form are two spellings of ONE interface. The strict commit gate
// compared raw LogicalName strings, so this pair reached the resolver on the
// STRICT commit path too — not only the tolerant one. Keying the post-pass on
// the RESOLVED Linux name is what catches it.
func TestDuplicateLogicalNameAcrossSpellingsRefuses(t *testing.T) {
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0"},
		{LogicalName: "ge-0-0-3", PCIAddr: "0000:0a:00.0"},
	}
	// Guard the premise: the two spellings really do canonicalise to one name.
	if config.LinuxIfName("ge-0/0/3") != config.LinuxIfName("ge-0-0-3") {
		t.Skip("spellings no longer canonicalise to one Linux name")
	}
	for i, b := range Resolve(entries, twoNICs(), nil) {
		if b.Status != BindRefusedDupName {
			t.Errorf("entry %d (%s): status %v, want %v", i, b.Entry.LogicalName,
				b.Status, BindRefusedDupName)
		}
	}
}

// TestThreeEntriesOneLogicalNameRefusesAll: the guard is not a two-entry
// special case.
func TestThreeEntriesOneLogicalNameRefusesAll(t *testing.T) {
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0"},
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:0a:00.0"},
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:0b:00.0"},
	}
	nics := append(twoNICs(), PresentNIC{
		Name: "enp11s0", PCIAddr: "0000:0b:00.0", PermMAC: "00:11:22:33:44:77"})
	for i, b := range Resolve(entries, nics, nil) {
		if b.Status != BindRefusedDupName {
			t.Errorf("entry %d: status %v, want %v", i, b.Status, BindRefusedDupName)
		}
	}
}

// TestDupNameRefusalWinsOverAmbigRefusal: when an entry is caught by BOTH
// post-passes the duplicate-name reason must win. "Re-pin the identity" is the
// wrong instruction for a map that names one interface twice — it changes
// nothing, and the operator chases hardware that is fine.
func TestDupNameRefusalWinsOverAmbigRefusal(t *testing.T) {
	// Two entries, one by PCI and one by that same NIC's permanent MAC, both
	// naming ge-0/0/3: they collide on the NIC *and* on the logical name.
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0"},
		{LogicalName: "ge-0/0/3", MAC: "00:11:22:33:44:55"},
	}
	for i, b := range Resolve(entries, twoNICs(), nil) {
		if b.Status != BindRefusedDupName {
			t.Errorf("entry %d: status %v, want %v (the duplicate-name reason "+
				"must win over the NIC-collision reason)", i, b.Status, BindRefusedDupName)
		}
	}
}

// TestDistinctLogicalNamesStillBind is the negative control: the guard must key
// on the collision, not refuse every map.
func TestDistinctLogicalNamesStillBind(t *testing.T) {
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0"},
		{LogicalName: "ge-0/0/4", PCIAddr: "0000:0a:00.0"},
	}
	got := Resolve(entries, twoNICs(), nil)
	want := map[string]string{"ge-0-0-3": "enp9s0", "ge-0-0-4": "enp10s0"}
	for _, b := range got {
		if !b.Status.Bound() {
			t.Fatalf("entry %s did not bind: %v", b.Entry.LogicalName, b.Status)
		}
		if want[b.Logical] != b.CurrentNIC {
			t.Errorf("%s bound to %q, want %q", b.Logical, b.CurrentNIC, want[b.Logical])
		}
	}
}

// TestUnboundDuplicateIsNotRefused: only BOUND entries are counted, so a
// duplicate name whose second entry matches no present NIC still binds the one
// that does. Refusing there would break a legitimate (if sloppy) map for no
// safety gain — there is no ambiguity when only one entry can resolve.
func TestUnboundDuplicateIsNotRefused(t *testing.T) {
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0"},
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:ff:00.0"}, // no such NIC
	}
	got := Resolve(entries, twoNICs(), nil)
	if !got[0].Status.Bound() || got[0].CurrentNIC != "enp9s0" {
		t.Errorf("the resolvable entry must still bind, got %v/%q",
			got[0].Status, got[0].CurrentNIC)
	}
	if got[1].Status != BindUnbound {
		t.Errorf("entry 1 status %v, want %v", got[1].Status, BindUnbound)
	}
}

// TestRefusedCoversBothReasons pins the helper the daemon's commit pre-flight
// hard-stops on. A caller comparing against BindRefusedAmbig alone would treat
// a duplicate-name refusal as a clean result.
func TestRefusedCoversBothReasons(t *testing.T) {
	for _, s := range []BindStatus{BindRefusedAmbig, BindRefusedDupName} {
		if !s.Refused() {
			t.Errorf("%v.Refused() = false", s)
		}
		if s.Bound() {
			t.Errorf("%v.Bound() = true", s)
		}
		if !s.Decisive() {
			t.Errorf("%v.Decisive() = false — a refusal must not fall through "+
				"to the next identity key", s)
		}
	}
	for _, s := range []BindStatus{BindBound, BindBoundPCIOnly, BindBoundViaMAC, BindUnbound} {
		if s.Refused() {
			t.Errorf("%v.Refused() = true", s)
		}
	}
	if BindRefusedDupName.String() == BindRefusedAmbig.String() {
		t.Error("the two refusal reasons render identically — the operator " +
			"is told to re-pin hardware that is fine")
	}
}
