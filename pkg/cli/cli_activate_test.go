package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

func newCLIConfigStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	for _, line := range []string{
		"set system host-name keep",
		"set system name-server 9.9.9.9",
	} {
		if _, err := store.LoadSet(line); err != nil {
			t.Fatalf("LoadSet(%q) error = %v", line, err)
		}
	}
	return store
}

// #2051: the local CLI dispatchConfig must route the `deactivate`/`activate`
// verbs to the store wrappers. Asserts ACTUAL inactivation via display-set, not
// merely a nil error.
func TestCLIDispatchDeactivateActivate(t *testing.T) {
	store := newCLIConfigStore(t)
	c := &CLI{store: store}

	if err := c.dispatchConfig("deactivate system name-server 9.9.9.9"); err != nil {
		t.Fatalf("dispatchConfig(deactivate): %v", err)
	}
	out := store.ShowCandidateSet()
	if !strings.Contains(out, "deactivate system name-server 9.9.9.9") {
		t.Fatalf("CLI deactivate did not mark the node inactive:\n%s", out)
	}
	if strings.Contains(out, "set deactivate ") {
		t.Fatalf("CLI deactivate mangled into a junk set path:\n%s", out)
	}

	if err := c.dispatchConfig("activate system name-server 9.9.9.9"); err != nil {
		t.Fatalf("dispatchConfig(activate): %v", err)
	}
	if out := store.ShowCandidateSet(); strings.Contains(out, "deactivate ") {
		t.Fatalf("CLI activate did not clear the marker:\n%s", out)
	}
}

// Edit-path-relative deactivate: with an edit context set, a relative path must
// be prefixed with the edit path before routing to the store.
func TestCLIDispatchDeactivateEditRelative(t *testing.T) {
	store := newCLIConfigStore(t)
	c := &CLI{store: store}

	store.SetEditPath([]string{"system"})
	if err := c.dispatchConfig("deactivate name-server 9.9.9.9"); err != nil {
		t.Fatalf("dispatchConfig(deactivate relative): %v", err)
	}
	if out := store.ShowCandidateSet(); !strings.Contains(out, "deactivate system name-server 9.9.9.9") {
		t.Fatalf("edit-relative deactivate did not resolve under edit path:\n%s", out)
	}
}
