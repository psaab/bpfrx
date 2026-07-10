package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #5221: the local CLI `show configuration applications` / `show security
// applications` display dereferences a present-but-nil ApplicationSets[name]
// value (as.Name / range as.Applications) with no guard. A nil map value is
// admitted by the tolerant-load / peer-sync path (#1960) that the resolver
// (#5179) already tolerates. These tests inject a nil application-set slot into
// the live ActiveConfig and drive showApplications in list, detail, and
// name-filter modes; reverting the `if as == nil { continue }` guard makes the
// matching call panic (RED on revert).

// nilAppSetCLIStore commits a config with one real application-set and then
// injects a nil application-set map value. The committed map is non-nil so the
// nil entry survives.
func nilAppSetCLIStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
applications {
    application my-app {
        protocol tcp;
        destination-port 8080;
    }
    application-set my-set {
        application my-app;
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil || len(cfg.Applications.ApplicationSets) == 0 {
		t.Fatalf("fixture missing application-sets")
	}
	cfg.Applications.ApplicationSets["zz-nil-set"] = nil
	return store
}

func TestCLIShowApplicationsNilAppSetNoPanic(t *testing.T) {
	c := &CLI{store: nilAppSetCLIStore(t)}
	// Each mode dereferences `as` differently (list: as.Name + Join; detail:
	// as.Name + range; filter: as.Name comparison). All panic on revert.
	captureStdout(t, func() {
		if err := c.showApplications(nil); err != nil {
			t.Fatalf("showApplications(list): %v", err)
		}
		if err := c.showApplications([]string{"detail"}); err != nil {
			t.Fatalf("showApplications(detail): %v", err)
		}
		if err := c.showApplications([]string{"zz-nil-set"}); err != nil {
			t.Fatalf("showApplications(filter nil set): %v", err)
		}
	})
}

func TestCLIShowApplicationsNilAppSetSkipped(t *testing.T) {
	c := &CLI{store: nilAppSetCLIStore(t)}
	out := captureStdout(t, func() {
		if err := c.showApplications(nil); err != nil {
			t.Fatalf("showApplications(list): %v", err)
		}
	})
	if !strings.Contains(out, "my-set") {
		t.Fatalf("showApplications output missing the real application-set; got:\n%s", out)
	}
	if strings.Contains(out, "zz-nil-set") {
		t.Fatalf("showApplications rendered the nil application-set slot; got:\n%s", out)
	}
}
