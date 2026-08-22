package daemon

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// stubPositionalRenameSeams points the POSITIONAL rename path's injectable
// seams (NIC inventory, rename, reload) at test doubles. Two present NICs so
// index 0 becomes fxp0 and index 1 becomes ge-0-0-0 — both differ from the
// kernel names, so phase 2 always attempts a rename.
func stubPositionalRenameSeams(t *testing.T, renameErr, reloadErr error) (renameCalls *int) {
	t.Helper()
	withTempLinkDir(t)

	savedEnum := enumeratePCINICsFn
	enumeratePCINICsFn = func() ([]pciNIC, error) {
		return []pciNIC{
			{name: "enp5s0", busAddr: "0000:05:00.0"},
			{name: "enp6s0", busAddr: "0000:06:00.0"},
		}, nil
	}
	t.Cleanup(func() { enumeratePCINICsFn = savedEnum })

	var rc int
	savedRename := renameInterfaceFn
	renameInterfaceFn = func(from, to string) error {
		rc++
		return renameErr
	}
	t.Cleanup(func() { renameInterfaceFn = savedRename })

	savedReload := networkctlReloadFn
	networkctlReloadFn = func() error { return reloadErr }
	t.Cleanup(func() { networkctlReloadFn = savedReload })

	return &rc
}

// TestEnumerateAndRenameInterfaces_RenameFailurePropagates_5842 is the #5842
// fail-on-revert for the POSITIONAL path, mirroring
// TestEnumerateAndRenameMapped_RenameFailurePropagates_4956 for the mapped one.
//
// enumerateAndRenameInterfaces returned nil unconditionally: renamePositional
// returned only a `changed bool` and swallowed every rename error into a WARN,
// writeLinkFile returned `false` for BOTH "unchanged" and "write failed", and
// the networkctl reload error was logged and dropped. A boot on which no NIC
// was renamed at all was reported to the caller as a successful naming pass.
//
// RED-on-revert: restore the final `return nil` (drop the errors.Join) and the
// error assertion fails.
func TestEnumerateAndRenameInterfaces_RenameFailurePropagates_5842(t *testing.T) {
	renameCalls := stubPositionalRenameSeams(t, fmt.Errorf("simulated rename failure"), nil)

	err := enumerateAndRenameInterfaces(0, false, 4, false, nil)
	if err == nil {
		t.Fatal("enumerateAndRenameInterfaces must return an error when a positional rename " +
			"fails, not launder it to nil — the caller cannot tell a converged boot from a " +
			"boot on which no NIC was renamed")
	}
	if *renameCalls == 0 {
		t.Fatal("expected a rename attempt; the fixture never reached the failing code")
	}
	if !strings.Contains(err.Error(), "rename") {
		t.Errorf("the error must name the failing step so an operator can act on it: %v", err)
	}
}

// TestEnumerateAndRenameInterfaces_ReloadFailurePropagates_5842 covers the
// distinct third laundering site. A reload failure is its own state: the .link
// files on disk are correct and the RUNNING interface names are not, which is
// exactly what a caller must not mistake for convergence.
func TestEnumerateAndRenameInterfaces_ReloadFailurePropagates_5842(t *testing.T) {
	stubPositionalRenameSeams(t, nil, fmt.Errorf("simulated reload failure"))

	err := enumerateAndRenameInterfaces(0, false, 4, false, nil)
	if err == nil {
		t.Fatal("a networkctl reload failure must propagate: the .link set is correct on disk " +
			"and the running names are not")
	}
	if !strings.Contains(err.Error(), "reload") {
		t.Errorf("the error must name the reload step: %v", err)
	}
}

// TestEnumerateAndRenameInterfaces_SuccessReturnsNil is the negative control,
// and it is what stops the fix from being "always return an error". Without it
// a build that failed every boot would pass the two tests above.
func TestEnumerateAndRenameInterfaces_SuccessReturnsNil(t *testing.T) {
	renameCalls := stubPositionalRenameSeams(t, nil, nil)

	if err := enumerateAndRenameInterfaces(0, false, 4, false, nil); err != nil {
		t.Fatalf("a clean positional naming pass must return nil, got %v", err)
	}
	if *renameCalls == 0 {
		t.Fatal("expected a rename attempt; the fixture never reached the code under test")
	}
}

// TestConfigArrivalNamingKeepsRetryMarkerOnPositionalFailure_5842 is the
// CONSEQUENCE, and the reason this is a defect rather than a logging nit.
//
// maybeReapplyConfigArrivalNaming consumes the one-shot emptyHANamingPending
// marker only when applyStartupNamingForConfig returns nil. In POSITIONAL mode
// that was always. So a #4179 config-less HA node whose renames all failed
// burned its single retry and stayed on standalone names until a restart —
// the precise failure #4956 fixed for the mapped path, still open on the
// default one.
//
// RED-on-revert: launder the error again and the marker is consumed on a boot
// where nothing was renamed.
func TestConfigArrivalNamingKeepsRetryMarkerOnPositionalFailure_5842(t *testing.T) {
	stubPositionalRenameSeams(t, fmt.Errorf("simulated rename failure"), nil)

	d := newStoreDaemon(t)
	d.emptyHANamingPending.Store(true)

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{"ge-0/0/0": {Name: "ge-0/0/0"}}

	if d.maybeReapplyConfigArrivalNaming(cfg) {
		t.Error("maybeReapplyConfigArrivalNaming reported success on a boot where every rename failed")
	}
	if !d.emptyHANamingPending.Load() {
		t.Error("the one-shot retry marker was consumed even though naming did not converge: " +
			"this config-less HA node is now stranded on standalone names until a restart, " +
			"with no further retry on any later commit")
	}
}

// TestConfigArrivalNamingConsumesRetryMarkerOnSuccess_5842 is the control for
// the test above. The marker MUST be consumed when naming converges, or the
// re-naming pass re-runs on every subsequent commit forever — so the fix is not
// satisfiable by simply never consuming it.
func TestConfigArrivalNamingConsumesRetryMarkerOnSuccess_5842(t *testing.T) {
	stubPositionalRenameSeams(t, nil, nil)

	d := newStoreDaemon(t)
	d.emptyHANamingPending.Store(true)

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{"ge-0/0/0": {Name: "ge-0/0/0"}}

	if !d.maybeReapplyConfigArrivalNaming(cfg) {
		t.Fatal("a clean naming pass must report success")
	}
	if d.emptyHANamingPending.Load() {
		t.Error("the one-shot marker survived a SUCCESSFUL naming pass; the re-naming pass will " +
			"now re-run on every later commit")
	}
}

// TestWriteLinkFileDistinguishesUnchangedFromFailure_5842 pins the primitive
// that made the laundering possible. `false` used to mean BOTH "already
// correct, nothing to do" and "the write failed" — opposite facts under one
// value, so no caller could have reported the second even if it wanted to.
func TestWriteLinkFileDistinguishesUnchangedFromFailure_5842(t *testing.T) {
	withTempLinkDir(t)

	wrote, err := writeLinkFile("ge-0-0-3", "enp9s0")
	if err != nil || !wrote {
		t.Fatalf("first write = (%v, %v), want (true, nil)", wrote, err)
	}
	wrote, err = writeLinkFile("ge-0-0-3", "enp9s0")
	if err != nil || wrote {
		t.Fatalf("identical rewrite = (%v, %v), want (false, nil) — unchanged is not a failure",
			wrote, err)
	}

	// A write that cannot land must report an error, and must NOT be
	// indistinguishable from the unchanged case above. Point linkDir at a path
	// that is not a directory so the atomic write fails.
	saved := linkDir
	linkDir = saved + "/nonexistent-subdir"
	t.Cleanup(func() { linkDir = saved })

	wrote, err = writeLinkFile("ge-0-0-4", "enp10s0")
	if err == nil {
		t.Error("a failed .link write reported no error; it is indistinguishable from 'unchanged', " +
			"so the NIC comes up under its kernel name on the next boot with no signal")
	}
	if wrote {
		t.Error("a failed write reported changed")
	}
}
