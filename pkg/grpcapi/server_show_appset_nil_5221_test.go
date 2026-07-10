package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestShowApplicationsNilAppSetNoPanic is the #5221 RED-on-revert proof for the
// gRPC show-security text path.
//
// #5179 (PR #5218) fixed the nil application-set DoS at the resolution choke
// point (lookupApplicationSet), but the DISPLAY paths still dereferenced a
// present-but-nil ApplicationSets[name] value with no guard. Here the gRPC
// showApplications renderer ranged over as.Applications on a nil
// *ApplicationSet (strings.Join(as.Applications, ...)) and panicked. A nil map
// value is admitted by the tolerant-load / peer-sync path (#1960) that the
// resolver already tolerates. The fix skips the nil slot; reverting the guard
// makes this test panic (recovered here → hard failure).
func TestShowApplicationsNilAppSetNoPanic(t *testing.T) {
	cfg := &config.Config{}
	cfg.Applications.ApplicationSets = map[string]*config.ApplicationSet{
		"real":   {Name: "real", Applications: []string{"junos-http"}},
		"nilset": nil,
	}

	var buf strings.Builder
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("showApplications panicked on a nil application-set value "+
					"(must fail closed / skip, not panic): %v", r)
			}
		}()
		(&Server{}).showApplications(cfg, &buf)
	}()

	out := buf.String()
	if !strings.Contains(out, "real") {
		t.Fatalf("showApplications output missing the real application-set; got:\n%s", out)
	}
	if strings.Contains(out, "nilset") {
		t.Fatalf("showApplications rendered the nil application-set slot; got:\n%s", out)
	}
}
