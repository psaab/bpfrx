// #3345: the text `show security screen` / `show security alarms` commands
// must print a warning when a global-counter read fails, rather than printing
// a clean "Total screen drops: 0" / "No security alarms" that hides a degraded
// counter bridge.
//
// FAIL-ON-REVERT: restoring `v, _ := c.dp.ReadGlobalCounter(idx)` (dropping
// the readErr capture + the warning print) makes both commands emit the clean
// zero output with no warning and the want-"warning" assertions go RED.
package cli

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
)

// counterErrCLIDP is a loaded cliRuntime whose global-counter reads fail.
type counterErrCLIDP struct {
	dataplane.DataPlane
}

func (d *counterErrCLIDP) IsLoaded() bool { return true }

func (d *counterErrCLIDP) ReadGlobalCounter(uint32) (uint64, error) {
	return 0, errors.New("counter bridge degraded")
}

// screenProfileStore commits a config with a screen profile + zone so that
// showScreen reaches the per-type counter section (it returns early when no
// screen profiles are configured).
func screenProfileStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	for _, line := range []string{
		"set security screen ids-option untrust-screen icmp flood threshold 1000",
		"set security zones security-zone untrust screen untrust-screen",
	} {
		if _, err := store.LoadSet(line); err != nil {
			t.Fatalf("LoadSet(%q) error = %v", line, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

func TestShowScreenWarnsOnCounterReadError(t *testing.T) {
	c := &CLI{store: screenProfileStore(t), dp: &counterErrCLIDP{}}

	out := captureStdout(t, func() {
		if err := c.showScreen(); err != nil {
			t.Fatalf("showScreen() error = %v", err)
		}
	})

	if !strings.Contains(out, "warning") {
		t.Fatalf("showScreen output lacks a counter-read warning; got:\n%s", out)
	}
	if strings.Contains(out, "Total screen drops: 0") {
		t.Fatalf("showScreen printed a clean zero on read failure; got:\n%s", out)
	}
}

func TestShowSecurityAlarmsWarnsOnCounterReadError(t *testing.T) {
	c := &CLI{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")), dp: &counterErrCLIDP{}}

	out := captureStdout(t, func() {
		if err := c.showSecurityAlarms(nil); err != nil {
			t.Fatalf("showSecurityAlarms() error = %v", err)
		}
	})

	if !strings.Contains(out, "warning") {
		t.Fatalf("showSecurityAlarms output lacks a counter-read warning; got:\n%s", out)
	}
}
