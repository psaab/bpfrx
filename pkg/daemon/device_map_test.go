package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/devicemap"
)

// withTempLinkDir points linkDir at a temp directory for the duration of a
// test so .link/.network file operations never touch /etc.
func withTempLinkDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := linkDir
	linkDir = dir
	t.Cleanup(func() { linkDir = old })
	return dir
}

// TestWriteLinkFileIdempotent proves operator priority #1 (no churn): a
// second write of an identical .link reports unchanged, so a no-op commit
// never rewrites files or triggers a networkctl reload / link flap.
func TestWriteLinkFileIdempotent(t *testing.T) {
	withTempLinkDir(t)
	if !writeLinkFile("ge-0-0-3", "enp9s0") {
		t.Fatalf("first write should report changed")
	}
	if writeLinkFile("ge-0-0-3", "enp9s0") {
		t.Fatalf("second identical write must report UNCHANGED (no churn)")
	}
	// A different OriginalName is a real change.
	if !writeLinkFile("ge-0-0-3", "eth7") {
		t.Fatalf("changed OriginalName should report changed")
	}
}

// TestScrubStaleDeviceMapLinksNoOpWhenAllDesired proves the scrub leaves
// every still-desired .link untouched (no churn) and removes only orphans.
func TestScrubStaleDeviceMapLinksNoOpWhenAllDesired(t *testing.T) {
	dir := withTempLinkDir(t)
	writeLinkFile("ge-0-0-3", "enp9s0")
	writeLinkFile("ge-0-0-4", "enp10s0")

	desired := map[string]bool{"ge-0-0-3": true, "ge-0-0-4": true}
	if scrubStaleDeviceMapLinks(desired) {
		t.Fatalf("scrub must be a no-op when all .link targets are still desired")
	}
	// Both files still present.
	for _, n := range []string{"ge-0-0-3", "ge-0-0-4"} {
		if _, err := os.Stat(filepath.Join(dir, linkPrefix+n+".link")); err != nil {
			t.Fatalf("desired .link %s was removed: %v", n, err)
		}
	}

	// Drop ge-0-0-4 from the desired set: only its .link is scrubbed.
	if !scrubStaleDeviceMapLinks(map[string]bool{"ge-0-0-3": true}) {
		t.Fatalf("scrub should remove the now-undesired .link")
	}
	if _, err := os.Stat(filepath.Join(dir, linkPrefix+"ge-0-0-4.link")); !os.IsNotExist(err) {
		t.Fatalf("stale ge-0-0-4 .link should be gone")
	}
	if _, err := os.Stat(filepath.Join(dir, linkPrefix+"ge-0-0-3.link")); err != nil {
		t.Fatalf("ge-0-0-3 .link must survive: %v", err)
	}
}

// TestTeardownUnmappedManagedNoOpWhenAllMapped proves V-4 teardown is a
// no-op when every on-disk .link is still a desired binding — zero churn on
// an unrelated commit (operator priority #1). It also never reaches netlink
// in the no-op path (all names desired), so it is safe in the unit sandbox.
func TestTeardownUnmappedManagedNoOpWhenAllMapped(t *testing.T) {
	dir := withTempLinkDir(t)
	writeLinkFile("ge-0-0-3", "enp9s0")

	dm := &config.DeviceMapConfig{
		Entries:        []config.DeviceMapEntry{{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0"}},
		UnmappedPolicy: config.DeviceMapPolicyLeaveAlone,
	}
	teardownUnmappedManaged(dm) // must not panic, must not remove the .link
	if _, err := os.Stat(filepath.Join(dir, linkPrefix+"ge-0-0-3.link")); err != nil {
		t.Fatalf("teardown removed a still-mapped .link: %v", err)
	}
}

// TestTeardownManageDownIsNoOp proves teardown does nothing under
// manage-down (that mode keeps today's claim-all via the compiler reconcile).
func TestTeardownManageDownIsNoOp(t *testing.T) {
	dir := withTempLinkDir(t)
	writeLinkFile("ge-0-0-9", "enp99s0") // not in the map

	dm := &config.DeviceMapConfig{
		Entries:        []config.DeviceMapEntry{{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0"}},
		UnmappedPolicy: config.DeviceMapPolicyManageDown,
	}
	teardownUnmappedManaged(dm)
	if _, err := os.Stat(filepath.Join(dir, linkPrefix+"ge-0-0-9.link")); err != nil {
		t.Fatalf("manage-down teardown must not touch .link files: %v", err)
	}
}

// TestDeviceMapLinkOriginalNameRoundTrips proves boot-stability of the
// on-disk record: a written .link for a mapped NIC records the TRUE kernel
// OriginalName=, and a later run recovers exactly that name (so the same
// physical NIC keeps the same logical name across reboots / re-runs).
func TestDeviceMapLinkOriginalNameRoundTrips(t *testing.T) {
	withTempLinkDir(t)
	// First run: enp9s0 -> ge-0-0-3 records OriginalName=enp9s0.
	if !writeDeviceMapLinkFile("ge-0-0-3", "enp9s0", nil, nil) {
		t.Fatalf("first .link write should report changed")
	}
	// A subsequent run that sees the NIC already named ge-0-0-3 must recover
	// the original kernel name from the existing .link, not the logical name.
	if got := recoverOriginalName("ge-0-0-3"); got != "enp9s0" {
		t.Fatalf("OriginalName round-trip failed: recovered %q, want enp9s0", got)
	}
	// Re-writing the identical .link is a no-op (no churn).
	if writeDeviceMapLinkFile("ge-0-0-3", "enp9s0", nil, nil) {
		t.Fatalf("identical .link re-write must be a no-op")
	}
}

func TestDeviceMapStrandsManagementSafeWhenMgmtMapped(t *testing.T) {
	// The live mgmt NIC (enp5s0 currently == fxp0) is mapped to its own
	// name => safe.
	cfg := &config.Config{Chassis: config.ChassisConfig{DeviceMap: &config.DeviceMapConfig{
		Entries: []config.DeviceMapEntry{{LogicalName: "fxp0", PCIAddr: "0000:05:00.0"}},
	}}}
	nics := []devicemap.PresentNIC{{Name: "fxp0", PCIAddr: "0000:05:00.0"}}
	protected := map[string]bool{"fxp0": true}
	if r := deviceMapStrandsManagement(cfg, nics, protected, "fxp0"); r != "" {
		t.Fatalf("mapping mgmt NIC to its own name must be safe, got %q", r)
	}
}

func TestDeviceMapStrandsManagementDetectsPortSwap(t *testing.T) {
	// A DIFFERENT physical NIC is mapped to the mgmt logical name fxp0, so
	// the live mgmt NIC (currently fxp0) would lose its name on next boot.
	cfg := &config.Config{Chassis: config.ChassisConfig{DeviceMap: &config.DeviceMapConfig{
		Entries: []config.DeviceMapEntry{{LogicalName: "fxp0", PCIAddr: "0000:09:00.0"}},
	}}}
	nics := []devicemap.PresentNIC{
		{Name: "fxp0", PCIAddr: "0000:05:00.0"},   // live mgmt NIC
		{Name: "enp9s0", PCIAddr: "0000:09:00.0"}, // becomes fxp0
	}
	protected := map[string]bool{"fxp0": true}
	if r := deviceMapStrandsManagement(cfg, nics, protected, "fxp0"); r == "" {
		t.Fatalf("expected strand detection when mgmt name moves to another port")
	}
}

func TestDeviceMapStrandsManagementRefuseOnTopologyChange(t *testing.T) {
	// A REFUSED entry (card swapped at a pinned slot) is a hard stop.
	cfg := &config.Config{Chassis: config.ChassisConfig{DeviceMap: &config.DeviceMapConfig{
		Entries: []config.DeviceMapEntry{
			{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0", MAC: "00:11:22:33:44:55"},
		},
	}}}
	nics := []devicemap.PresentNIC{{Name: "enp9s0", PCIAddr: "0000:09:00.0", PermMAC: "de:ad:be:ef:00:01"}}
	if r := deviceMapStrandsManagement(cfg, nics, nil, ""); r == "" {
		t.Fatalf("expected refusal on topology change (PCI hit, MAC mismatch)")
	}
}

func TestDeviceMapStrandsManagementCatchesPreRenameSteal(t *testing.T) {
	// Codex HIGH-2: on first boot the live mgmt NIC still wears its kernel
	// name (enp5s0), NOT the protected target (fxp0). A different NIC mapped
	// to fxp0 must still be caught as a steal even though no present NIC is
	// literally named fxp0 yet. The lifeline identity resolves enp5s0 as the
	// live mgmt NIC.
	cfg := &config.Config{Chassis: config.ChassisConfig{DeviceMap: &config.DeviceMapConfig{
		Entries: []config.DeviceMapEntry{{LogicalName: "fxp0", PCIAddr: "0000:09:00.0"}},
	}}}
	nics := []devicemap.PresentNIC{
		{Name: "enp5s0", PCIAddr: "0000:05:00.0"}, // live mgmt NIC (un-renamed)
		{Name: "enp9s0", PCIAddr: "0000:09:00.0"}, // mapped to fxp0 -> steal
	}
	protected := map[string]bool{"fxp0": true}
	// lifeline resolves the live mgmt NIC's CURRENT name = enp5s0.
	if r := deviceMapStrandsManagement(cfg, nics, protected, "enp5s0"); r == "" {
		t.Fatalf("expected steal detection before rename (live mgmt still enp5s0)")
	}
}

func TestProtectedForConfigUsesConfigMgmtLeaf(t *testing.T) {
	// AGY HIGH-2: the protected set must come from the SPECIFIC config's
	// management-interface leaf. With no lifeline record, a config that sets
	// `system management-interface em0` protects em0 (and narrows fxp0 out).
	lifelineRecordFileForTest = filepath.Join(t.TempDir(), "no-lifeline")
	t.Cleanup(func() { lifelineRecordFileForTest = "" })

	cfg := &config.Config{}
	cfg.System.ManagementInterface = "em0"
	got := protectedForConfig(cfg)
	if !got["em0"] {
		t.Fatalf("protectedForConfig must protect the config's mgmt leaf em0; got %v", got)
	}
	if got["fxp0"] {
		t.Fatalf("an explicit non-fxp0 mgmt leaf must narrow fxp0 out; got %v", got)
	}
}

func TestDeviceMapStrandsManagementPositionalIsSafe(t *testing.T) {
	// No device-map => positional mode, never stranded by a (non-existent)
	// map; the #1922 protected set is the backstop.
	cfg := &config.Config{}
	if r := deviceMapStrandsManagement(cfg, nil, map[string]bool{"fxp0": true}, ""); r != "" {
		t.Fatalf("positional mode must never report stranding, got %q", r)
	}
}
