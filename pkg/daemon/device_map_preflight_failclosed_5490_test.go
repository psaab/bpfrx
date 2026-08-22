package daemon

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5490: the device-map commit pre-flight and the boot-time mapped-rename must
// both FAIL CLOSED on unknown NIC inventory. Before the fix, a transient
// sysfs/netlink enumeration error at commit time skipped the strand-management
// safety check and returned SUCCESS, so a management-stranding device-map was
// accepted and then applied verbatim at next boot (durable lockout). These
// tests pin both halves of the fix.

// enumErrSeam points enumeratePresentNICsFn at a stub that ALWAYS fails, to
// simulate a transient hardware-inventory read error, and forces the lifeline
// record to resolve to "" so the strand detector is deterministic.
func enumErrSeam(t *testing.T) {
	t.Helper()
	saved := enumeratePresentNICsFn
	enumeratePresentNICsFn = func() ([]presentNIC, error) {
		return nil, fmt.Errorf("simulated transient sysfs/netlink enumeration failure")
	}
	t.Cleanup(func() { enumeratePresentNICsFn = saved })
	lifelineRecordFileForTest = filepath.Join(t.TempDir(), "no-lifeline")
	t.Cleanup(func() { lifelineRecordFileForTest = "" })
}

func deviceMapCfg(entries ...config.DeviceMapEntry) *config.Config {
	return &config.Config{Chassis: config.ChassisConfig{DeviceMap: &config.DeviceMapConfig{
		Entries: entries,
	}}}
}

// TestDeviceMapCommitPreflight_EnumErrorFailsClosed_5490 is the primary
// RED-on-revert. A transient NIC-enumeration failure at commit pre-flight must
// REJECT both a plain commit AND a confirmed commit whose candidate engages
// device-map mode — not skip the strand check and return nil.
//
// Revert: change the enumeration-error branch back to `slog.Warn(...); return
// nil` and this test goes RED (both commits accepted, fail-open).
func TestDeviceMapCommitPreflight_EnumErrorFailsClosed_5490(t *testing.T) {
	enumErrSeam(t)
	d := &Daemon{}

	cand := deviceMapCfg(config.DeviceMapEntry{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0"})

	// Plain commit (no rollback target).
	if err := d.deviceMapCommitPreflight(cand, nil); err == nil {
		t.Fatal("plain-commit pre-flight must FAIL CLOSED when NIC enumeration fails, not skip and return nil")
	}

	// Confirmed commit (rollback target also engages device-map). Both the
	// candidate and the rollback target must be validated; an unreadable
	// inventory means neither can be, so the commit is rejected.
	rb := deviceMapCfg(config.DeviceMapEntry{LogicalName: "ge-0/0/4", PCIAddr: "0000:0a:00.0"})
	if err := d.deviceMapCommitPreflight(cand, rb); err == nil {
		t.Fatal("confirmed-commit pre-flight must FAIL CLOSED when NIC enumeration fails")
	}
}

// TestDeviceMapCommitPreflight_EnumErrorFastPathStillSkips_5490 guards against
// over-gating: a candidate that does NOT engage device-map mode must still be
// accepted even when enumeration would fail, because the fast path returns
// before any enumeration (nothing to validate).
func TestDeviceMapCommitPreflight_EnumErrorFastPathStillSkips_5490(t *testing.T) {
	enumErrSeam(t)
	d := &Daemon{}

	// No device-map on either config -> fast path, never enumerates.
	plain := &config.Config{System: config.SystemConfig{HostName: "plain"}}
	if err := d.deviceMapCommitPreflight(plain, nil); err != nil {
		t.Fatalf("a non-device-map commit must not be gated by the enumeration failure: %v", err)
	}
}

// TestDeviceMapCommitPreflight_StrandingCandidateRejected_5490 pins the
// pre-existing behavior: with READABLE NICs, a candidate whose map would strand
// management (a different NIC steals the mgmt name) is still rejected.
func TestDeviceMapCommitPreflight_StrandingCandidateRejected_5490(t *testing.T) {
	saved := enumeratePresentNICsFn
	enumeratePresentNICsFn = func() ([]presentNIC, error) {
		return []presentNIC{
			{Name: "fxp0", PCIAddr: "0000:05:00.0"},   // live mgmt NIC (currently fxp0)
			{Name: "enp9s0", PCIAddr: "0000:09:00.0"}, // would become fxp0
		}, nil
	}
	t.Cleanup(func() { enumeratePresentNICsFn = saved })
	lifelineRecordFileForTest = filepath.Join(t.TempDir(), "no-lifeline")
	t.Cleanup(func() { lifelineRecordFileForTest = "" })

	// Map a DIFFERENT NIC onto the management name fxp0 -> the live mgmt NIC
	// loses its name / a rename collision on fxp0 -> strand.
	cand := deviceMapCfg(config.DeviceMapEntry{LogicalName: "fxp0", PCIAddr: "0000:09:00.0"})
	d := &Daemon{}
	if err := d.deviceMapCommitPreflight(cand, nil); err == nil {
		t.Fatal("a management-stranding candidate must be rejected even with readable NICs")
	}
}

// TestDeviceMapCommitPreflight_NormalPathUnaffected_5490 proves the fix does
// not over-gate the happy path: with readable NICs and a non-stranding map
// (mgmt NIC mapped to its own name), the commit pre-flight accepts.
func TestDeviceMapCommitPreflight_NormalPathUnaffected_5490(t *testing.T) {
	saved := enumeratePresentNICsFn
	enumeratePresentNICsFn = func() ([]presentNIC, error) {
		return []presentNIC{
			{Name: "fxp0", PCIAddr: "0000:05:00.0"},
			{Name: "enp9s0", PCIAddr: "0000:09:00.0"},
		}, nil
	}
	t.Cleanup(func() { enumeratePresentNICsFn = saved })
	lifelineRecordFileForTest = filepath.Join(t.TempDir(), "no-lifeline")
	t.Cleanup(func() { lifelineRecordFileForTest = "" })

	cand := deviceMapCfg(
		config.DeviceMapEntry{LogicalName: "fxp0", PCIAddr: "0000:05:00.0"},     // mgmt NIC -> its own name
		config.DeviceMapEntry{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0"}, // data NIC
	)
	d := &Daemon{}
	if err := d.deviceMapCommitPreflight(cand, nil); err != nil {
		t.Fatalf("a non-stranding readable candidate must be accepted: %v", err)
	}
}

// TestEnumerateAndRenameMapped_BootRecheckFailsClosed_5490 pins part (b): even
// if a stranding candidate was accepted at commit time (before this fix, or via
// a transient commit-time enumeration failure under the old fail-open path),
// the boot-time mapped rename must re-run the strand detector and REFUSE to
// perform the unsafe rename — retaining current naming so management stays
// reachable.
//
// Revert: remove the boot-time re-check block in enumerateAndRenameMapped and
// this test goes RED — the stranding rename is performed and no error returns.
func TestEnumerateAndRenameMapped_BootRecheckFailsClosed_5490(t *testing.T) {
	withTempLinkDir(t)
	lifelineRecordFileForTest = filepath.Join(t.TempDir(), "no-lifeline")
	t.Cleanup(func() { lifelineRecordFileForTest = "" })

	savedEnum := enumeratePresentNICsFn
	enumeratePresentNICsFn = func() ([]presentNIC, error) {
		return []presentNIC{
			{Name: "fxp0", PCIAddr: "0000:05:00.0"},   // live mgmt NIC
			{Name: "enp9s0", PCIAddr: "0000:09:00.0"}, // would become fxp0
		}, nil
	}
	t.Cleanup(func() { enumeratePresentNICsFn = savedEnum })

	var renameCalls int
	savedRename := renameInterfaceFn
	renameInterfaceFn = func(from, to string) error { renameCalls++; return nil }
	t.Cleanup(func() { renameInterfaceFn = savedRename })

	var reloadCalls int
	savedReload := networkctlReloadFn
	networkctlReloadFn = func() error { reloadCalls++; return nil }
	t.Cleanup(func() { networkctlReloadFn = savedReload })

	// A different NIC mapped onto fxp0 -> the map would strand management.
	dm := &config.DeviceMapConfig{
		Entries: []config.DeviceMapEntry{{LogicalName: "fxp0", PCIAddr: "0000:09:00.0"}},
	}
	cfg := &config.Config{Chassis: config.ChassisConfig{DeviceMap: dm}}
	protected := map[string]bool{"fxp0": true}

	err := enumerateAndRenameMapped(dm, cfg, protected)
	if err == nil {
		t.Fatal("boot re-check must FAIL CLOSED (return error) for a stranding device-map, " +
			"not perform the unsafe rename")
	}
	if renameCalls != 0 {
		t.Fatalf("boot re-check must NOT rename any interface when the map would strand "+
			"management; got %d rename call(s)", renameCalls)
	}
	if reloadCalls != 0 {
		t.Fatalf("boot re-check must NOT reload networkd on the fail-closed path; got %d reload call(s)", reloadCalls)
	}
}

// TestEnumerateAndRenameMapped_BootRecheckAllowsSafeMap_5490 guards against
// over-gating the boot path: with readable NICs and a non-stranding map (mgmt
// NIC mapped to its own name, a data NIC renamed), the mapped rename proceeds
// and the data NIC gets renamed as before.
func TestEnumerateAndRenameMapped_BootRecheckAllowsSafeMap_5490(t *testing.T) {
	withTempLinkDir(t)
	lifelineRecordFileForTest = filepath.Join(t.TempDir(), "no-lifeline")
	t.Cleanup(func() { lifelineRecordFileForTest = "" })

	savedEnum := enumeratePresentNICsFn
	enumeratePresentNICsFn = func() ([]presentNIC, error) {
		return []presentNIC{
			{Name: "fxp0", PCIAddr: "0000:05:00.0"},   // mgmt NIC already at fxp0
			{Name: "enp9s0", PCIAddr: "0000:09:00.0"}, // data NIC -> ge-0-0-3
		}, nil
	}
	t.Cleanup(func() { enumeratePresentNICsFn = savedEnum })

	var renameCalls int
	savedRename := renameInterfaceFn
	renameInterfaceFn = func(from, to string) error { renameCalls++; return nil }
	t.Cleanup(func() { renameInterfaceFn = savedRename })

	savedReload := networkctlReloadFn
	networkctlReloadFn = func() error { return nil }
	t.Cleanup(func() { networkctlReloadFn = savedReload })

	// fxp0 already wears its logical name, so the OriginalName= comes from the
	// sysfs derivation. Stub it: unstubbed, this read the REAL /sys of whatever
	// host ran the test, found no fxp0, and returned "" — which before #6678
	// silently fell back to the logical name and let this test pass on the
	// defect. The property under test here is the pre-flight stranding check,
	// not name derivation, so pin the derivation rather than inherit the host's.
	savedDerive := deriveKernelNameFn
	deriveKernelNameFn = func(name string) string {
		if name == "fxp0" {
			return "enp5s0" // matches its mapped PCI address 0000:05:00.0
		}
		return ""
	}
	t.Cleanup(func() { deriveKernelNameFn = savedDerive })

	dm := &config.DeviceMapConfig{
		Entries: []config.DeviceMapEntry{
			{LogicalName: "fxp0", PCIAddr: "0000:05:00.0"},
			{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0"},
		},
	}
	cfg := &config.Config{Chassis: config.ChassisConfig{DeviceMap: dm}}
	protected := map[string]bool{"fxp0": true}

	if err := enumerateAndRenameMapped(dm, cfg, protected); err != nil {
		t.Fatalf("a safe (non-stranding) map must proceed at boot, got error: %v", err)
	}
	if renameCalls == 0 {
		t.Fatal("a safe map must still rename the data NIC (enp9s0 -> ge-0-0-3); got 0 rename calls")
	}
}
