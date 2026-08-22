package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/devicemap"
)

// #6546: the commit pre-flight must hard-stop on a duplicate LOGICAL NAME, and
// must say so in its own words.
//
// The pre-flight compared `b.Status == devicemap.BindRefusedAmbig`, so a new
// refusal reason would have slipped past it and been treated as a clean
// result. It now tests `Status.Refused()` and gives the duplicate-name case a
// distinct message: telling an operator who typed a duplicate name to "re-pin
// the entry" sends them to a fix that changes nothing, while the map they
// actually have to correct goes unmentioned.
//
// FAIL-ON-REVERT: restore `if b.Status == devicemap.BindRefusedAmbig` as the
// only refusal check (dropping the BindRefusedDupName branch) and the
// duplicate-name commit sails through the pre-flight.

func TestDeviceMapStrandsManagementRefuseOnDuplicateLogicalName(t *testing.T) {
	cfg := &config.Config{Chassis: config.ChassisConfig{DeviceMap: &config.DeviceMapConfig{
		Entries: []config.DeviceMapEntry{
			// fxp0 is mapped correctly, so the mgmt-strand check cannot be
			// the reason this pre-flight rejects — the duplicate name is.
			{LogicalName: "fxp0", PCIAddr: "0000:05:00.0"},
			{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0"},
			{LogicalName: "ge-0/0/3", PCIAddr: "0000:0a:00.0"},
		},
	}}}
	nics := []devicemap.PresentNIC{
		{Name: "fxp0", PCIAddr: "0000:05:00.0"},
		{Name: "enp9s0", PCIAddr: "0000:09:00.0"},
		{Name: "enp10s0", PCIAddr: "0000:0a:00.0"},
	}
	r := deviceMapStrandsManagement(cfg, nics, map[string]bool{"fxp0": true}, "fxp0")
	if r == "" {
		t.Fatal("commit pre-flight accepted a device-map with a duplicate " +
			"logical name — an arbitrary NIC would be renamed to it and the " +
			"choice persisted in a .link file")
	}
	if !strings.Contains(r, "more than one entry claims") {
		t.Errorf("pre-flight message %q does not diagnose the duplicate name", r)
	}
	if strings.Contains(r, "Re-pin") {
		t.Errorf("pre-flight tells the operator to re-pin an identity for a "+
			"DUPLICATE NAME, which changes nothing: %q", r)
	}
}

// TestDeviceMapStrandsManagementTopologyMessageUnchanged is the negative
// control on the message split: the card-swap case must keep its own wording.
func TestDeviceMapStrandsManagementTopologyMessageUnchanged(t *testing.T) {
	cfg := &config.Config{Chassis: config.ChassisConfig{DeviceMap: &config.DeviceMapConfig{
		Entries: []config.DeviceMapEntry{
			{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0", MAC: "00:11:22:33:44:55"},
		},
	}}}
	nics := []devicemap.PresentNIC{
		{Name: "enp9s0", PCIAddr: "0000:09:00.0", PermMAC: "de:ad:be:ef:00:01"},
	}
	r := deviceMapStrandsManagement(cfg, nics, nil, "")
	if !strings.Contains(r, "Re-pin the entry") {
		t.Errorf("card-swap refusal lost its own remedy: %q", r)
	}
	if strings.Contains(r, "more than one entry claims") {
		t.Errorf("card-swap refusal reported as a duplicate name: %q", r)
	}
}

// TestDeviceMapStrandsManagementCleanMapStillCommits is the negative control:
// the pre-flight must not reject a valid map.
func TestDeviceMapStrandsManagementCleanMapStillCommits(t *testing.T) {
	cfg := &config.Config{Chassis: config.ChassisConfig{DeviceMap: &config.DeviceMapConfig{
		Entries: []config.DeviceMapEntry{
			{LogicalName: "fxp0", PCIAddr: "0000:05:00.0"},
			{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0"},
			{LogicalName: "ge-0/0/4", PCIAddr: "0000:0a:00.0"},
		},
	}}}
	nics := []devicemap.PresentNIC{
		{Name: "fxp0", PCIAddr: "0000:05:00.0"},
		{Name: "enp9s0", PCIAddr: "0000:09:00.0"},
		{Name: "enp10s0", PCIAddr: "0000:0a:00.0"},
	}
	if r := deviceMapStrandsManagement(cfg, nics, map[string]bool{"fxp0": true}, "fxp0"); r != "" {
		t.Fatalf("pre-flight rejected a valid device-map: %q", r)
	}
}
