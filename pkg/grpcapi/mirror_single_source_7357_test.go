package grpcapi

import (
	"strings"
	"testing"

	dpformat "github.com/psaab/xpf/pkg/dataplane/userspace/format"
)

// #7357: bind the WIRING, not the formatter.
//
// The port-mirroring render was two byte-identical copies with no shared
// formatter, which had already cost #6534 (annotate both, test both) and #8166
// (fix the order in both). It is now single-sourced in
// dpformat.FormatPortMirroring.
//
// The substance is tested where it now lives
// (pkg/dataplane/userspace/format/mirror_show_test.go). What THIS asserts is
// the thing single-sourcing actually claims and which no substance test can
// see: that this surface routes through the shared function rather than
// carrying a copy that happens to agree today. Re-fork the renderer — even
// into an exact duplicate — and this reds, because the two would then be equal
// by coincidence rather than by construction.
func TestGRPCPortMirroringRoutesThroughTheSharedFormatter_7357(t *testing.T) {
	// Reuse the #6534 fixture: one DROPPED instance (no output interface) so
	// the annotation is present in the compared text.
	cfg := mirrorSurfaceConfig("", 0)

	s := &Server{}
	var buf strings.Builder
	s.showForwardingOptionsPortMirroring(cfg, &buf)

	want := dpformat.FormatPortMirroring(cfg)
	if buf.String() != want {
		t.Errorf("the gRPC port-mirroring text is not what dpformat.FormatPortMirroring "+
			"produced, so this surface is rendering from its own copy again (#7357).\n"+
			"got:\n%s\nwant:\n%s", buf.String(), want)
	}
	// Non-vacuity: an empty render would make the comparison above pass for the
	// wrong reason.
	if !strings.Contains(want, "Instance:") {
		t.Fatalf("the fixture rendered no instances, so the equality above compares two "+
			"empty strings and proves nothing. got:\n%s", want)
	}
}
