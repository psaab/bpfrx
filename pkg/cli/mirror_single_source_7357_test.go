package cli

import (
	"strings"
	"testing"

	dpformat "github.com/psaab/xpf/pkg/dataplane/userspace/format"
)

// #7357: bind the WIRING, not the formatter. See the gRPC twin
// (pkg/grpcapi/mirror_single_source_7357_test.go) for the full reasoning.
//
// The substance lives in pkg/dataplane/userspace/format/mirror_show_test.go
// now. This asserts the local CLI routes through it, so re-forking the
// renderer into an exact duplicate reds here rather than passing because the
// two copies happen to agree on the day.
func TestCLIPortMirroringRoutesThroughTheSharedFormatter_7357(t *testing.T) {
	// Reuse the #6534 fixture: one armed and one DROPPED instance, committed
	// through the ordinary path, so the compared text carries the annotation
	// rather than only the happy path.
	c := &CLI{store: mirrorSurfaceCLIStore(t)}
	got := captureStdout(t, func() {
		if err := c.showPortMirroring(); err != nil {
			t.Fatalf("showPortMirroring() error = %v", err)
		}
	})

	want := dpformat.FormatPortMirroring(c.store.ActiveConfig())
	if got != want {
		t.Errorf("the local CLI port-mirroring text is not what "+
			"dpformat.FormatPortMirroring produced, so this surface is rendering from its "+
			"own copy again (#7357).\ngot:\n%s\nwant:\n%s", got, want)
	}
	// Non-vacuity: two empty strings would compare equal and prove nothing.
	if !strings.Contains(want, "Instance:") || !strings.Contains(want, "NOT INSTALLED") {
		t.Fatalf("the fixture must render at least one instance AND one annotation, or the "+
			"equality above is comparing uninteresting text. got:\n%s", want)
	}
}
