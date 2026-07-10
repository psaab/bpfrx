package api

import (
	"strings"
	"testing"
)

// #5221: the REST /show-text applications handler renders
// cfg.Applications.ApplicationSets (map[string]*ApplicationSet) and
// dereferences the value (strings.Join(as.Applications, ...)) with no nil
// guard. A present-but-nil map value is admitted by the tolerant-load /
// peer-sync path (#1960) that the resolver (#5179) already tolerates. This test
// commits a real application-set, injects a nil application-set slot into the
// live ActiveConfig, and drives the show-text applications handler; reverting
// the `if as == nil { continue }` guard in show_text.go makes the handler panic
// (RED on revert). Distinct from #5179, which covered the CatalogNames build
// path.
func TestAPIShowApplicationsNilAppSetNoPanic(t *testing.T) {
	s := stageShowTextConfig(t, []string{
		"set applications application my-app protocol tcp",
		"set applications application my-app destination-port 8080",
		"set applications application-set my-set application my-app",
	})
	cfg := s.store.ActiveConfig()
	if cfg == nil || len(cfg.Applications.ApplicationSets) == 0 {
		t.Fatalf("fixture missing application-sets")
	}
	// Inject the tolerated nil slot; the committed map is non-nil so it survives.
	cfg.Applications.ApplicationSets["zz-nil-set"] = nil

	// renderShowTextBody fatals if the handler does not return 200; the handler
	// panics on revert of the show_text.go guard — recover it into a hard
	// failure rather than crashing the package test binary.
	var out string
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("show-text applications handler panicked on a nil "+
					"application-set value (must skip, not panic): %v", r)
			}
		}()
		out = renderShowTextBody(t, s, "applications")
	}()
	if !strings.Contains(out, "my-set") {
		t.Fatalf("show-text applications missing the real application-set; got:\n%s", out)
	}
	if strings.Contains(out, "zz-nil-set") {
		t.Fatalf("show-text applications rendered the nil application-set slot; got:\n%s", out)
	}
}
