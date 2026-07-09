package daemon

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// stubMappedRenameSeams points the device-map rename orchestration's injectable
// seams (NIC inventory, rename, reload) at test doubles and restores them on
// cleanup. The single present NIC (enp9s0 at 0000:09:00.0) is mapped to a
// DIFFERENT logical name so phase 2 always attempts a rename.
func stubMappedRenameSeams(t *testing.T, renameErr, reloadErr error) (renameCalls, reloadCalls *int) {
	t.Helper()
	withTempLinkDir(t)

	savedEnum := enumeratePresentNICsFn
	enumeratePresentNICsFn = func() ([]presentNIC, error) {
		return []presentNIC{{Name: "enp9s0", PCIAddr: "0000:09:00.0"}}, nil
	}
	t.Cleanup(func() { enumeratePresentNICsFn = savedEnum })

	var rc, lc int
	savedRename := renameInterfaceFn
	renameInterfaceFn = func(from, to string) error {
		rc++
		return renameErr
	}
	t.Cleanup(func() { renameInterfaceFn = savedRename })

	savedReload := networkctlReloadFn
	networkctlReloadFn = func() error {
		lc++
		return reloadErr
	}
	t.Cleanup(func() { networkctlReloadFn = savedReload })

	return &rc, &lc
}

func mappedRenameTestConfig() (*config.DeviceMapConfig, *config.Config) {
	dm := &config.DeviceMapConfig{
		Entries: []config.DeviceMapEntry{{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0"}},
	}
	cfg := &config.Config{Chassis: config.ChassisConfig{DeviceMap: dm}}
	return dm, cfg
}

// TestEnumerateAndRenameMapped_RenameFailurePropagates_4956 is the #4956
// fail-on-revert. A phase-2 mapped-NIC rename failure must PROPAGATE out of
// enumerateAndRenameMapped (not be laundered to nil), so the caller's one-shot
// retry marker (emptyHANamingPending) is preserved and the reconcile does not
// proceed on a mis-named NIC.
//
// Revert: change the final `return fmt.Errorf(...)` back to `return nil` and
// this test goes RED — the failed rename is reported as success.
func TestEnumerateAndRenameMapped_RenameFailurePropagates_4956(t *testing.T) {
	renameCalls, _ := stubMappedRenameSeams(t, fmt.Errorf("simulated rename failure"), nil)
	dm, cfg := mappedRenameTestConfig()

	err := enumerateAndRenameMapped(dm, cfg, nil)
	if err == nil {
		t.Fatal("enumerateAndRenameMapped must return an error when a mapped-NIC rename fails, not launder it to nil")
	}
	if *renameCalls == 0 {
		t.Fatal("expected a rename attempt for the mapped NIC")
	}
	if !strings.Contains(err.Error(), "rename") {
		t.Fatalf("error should name the failed rename step: %v", err)
	}
}

// TestEnumerateAndRenameMapped_ReloadFailurePropagates_4956 covers the phase-4
// `networkctl reload` failure: with the rename succeeding, a reload failure
// must still surface (the config was written but never activated).
func TestEnumerateAndRenameMapped_ReloadFailurePropagates_4956(t *testing.T) {
	_, reloadCalls := stubMappedRenameSeams(t, nil, fmt.Errorf("simulated reload failure"))
	dm, cfg := mappedRenameTestConfig()

	err := enumerateAndRenameMapped(dm, cfg, nil)
	if err == nil {
		t.Fatal("enumerateAndRenameMapped must return an error when networkctl reload fails")
	}
	if *reloadCalls == 0 {
		t.Fatal("expected a networkctl reload attempt")
	}
	if !strings.Contains(err.Error(), "reload") {
		t.Fatalf("error should name the failed reload step: %v", err)
	}
}

// TestEnumerateAndRenameMapped_SuccessReturnsNil_4956 proves the fix does not
// over-report errors: when the rename and reload both succeed, the function
// returns nil so the caller consumes the retry marker exactly once (normal
// convergence).
func TestEnumerateAndRenameMapped_SuccessReturnsNil_4956(t *testing.T) {
	renameCalls, _ := stubMappedRenameSeams(t, nil, nil)
	dm, cfg := mappedRenameTestConfig()

	if err := enumerateAndRenameMapped(dm, cfg, nil); err != nil {
		t.Fatalf("enumerateAndRenameMapped must succeed when every rename/reload step succeeds: %v", err)
	}
	if *renameCalls == 0 {
		t.Fatal("expected a rename attempt for the mapped NIC")
	}
}
