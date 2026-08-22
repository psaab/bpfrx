package config

import (
	"strings"
	"testing"
)

// #6546: the strict device-map gate compared RAW logical-name strings, so two
// SPELLINGS of one interface passed it.
//
// `LinuxIfName` folds the Junos slash form onto the kernel dash form, so
// `ge-0/0/3` and `ge-0-0-3` are the same interface — and both entries reached
// the resolver, which then bound one logical name to a nondeterministically
// chosen NIC. That made the duplicate reachable on the STRICT commit path, not
// only on the tolerant load / peer-sync path the issue described.
//
// FAIL-ON-REVERT: key seenName on `e.LogicalName` again (drop the LinuxIfName
// canonicalisation) and the cross-spelling case below commits clean.

func TestDeviceMapDuplicateLogicalNameAcrossSpellingsFatal(t *testing.T) {
	tree := buildTree(t, []string{
		"set chassis device-map interface ge-0/0/3 pci 0000:09:00.0",
		"set chassis device-map interface ge-0-0-3 pci 0000:0a:00.0",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("commit accepted a device-map naming ONE interface under two " +
			"spellings (ge-0/0/3 and ge-0-0-3) — both entries reach the " +
			"resolver and one NIC is chosen nondeterministically")
	}
	// The message must name BOTH spellings and the interface they collapse to,
	// or the operator cannot see why two visibly different names collided.
	for _, want := range []string{"ge-0/0/3", "ge-0-0-3", "same interface"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err.Error(), want)
		}
	}
}

// TestDeviceMapIdenticalSpellingKeepsItsOwnMessage: the pre-existing
// same-spelling case must not be reworded into the cross-spelling diagnosis —
// "are the same interface" would be nonsense for two identical names.
func TestDeviceMapIdenticalSpellingKeepsItsOwnMessage(t *testing.T) {
	cfg := &Config{Chassis: ChassisConfig{DeviceMap: &DeviceMapConfig{
		Entries: []DeviceMapEntry{
			{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0"},
			{LogicalName: "ge-0/0/3", PCIAddr: "0000:0a:00.0"},
		},
	}}}
	err := validateDeviceMapStrict(cfg)
	if err == nil {
		t.Fatal("want duplicate-logical-name fatal")
	}
	if !strings.Contains(err.Error(), "mapped twice") {
		t.Errorf("error %q lost the mapped-twice wording", err.Error())
	}
	if strings.Contains(err.Error(), "same interface") {
		t.Errorf("error %q uses the cross-spelling wording for two IDENTICAL "+
			"names", err.Error())
	}
}

// TestDeviceMapDistinctNamesStillCommit is the negative control: two genuinely
// different interfaces must still commit.
func TestDeviceMapDistinctNamesStillCommit(t *testing.T) {
	tree := buildTree(t, []string{
		"set chassis device-map interface ge-0/0/3 pci 0000:09:00.0",
		"set chassis device-map interface ge-0/0/4 pci 0000:0a:00.0",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("commit rejected a valid device-map: %v", err)
	}
	if n := len(cfg.Chassis.DeviceMap.Entries); n != 2 {
		t.Fatalf("%d device-map entries, want 2", n)
	}
}
