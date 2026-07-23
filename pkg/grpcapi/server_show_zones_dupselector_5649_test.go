package grpcapi

import (
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #5649 (codex-181 C181-C09): showTestZone parsed `test-zone:` selectors with
// no `seen` map, so a repeated `interface=a,interface=b` silently LAST-WON in
// the switch — the archived diagnostic reported a DIFFERENT interface's zone
// and host-inbound posture than the operator typed, with no warning. The
// handler now rejects a repeated selector, matching the #4921 showTestRouting
// and #3709 showTestPolicy duplicate-selector contract.
//
// cfg is nil here, so a NON-duplicate selector proceeds to the "No active
// configuration" diagnostic; a duplicate is a client-input grammar error and
// is reported FIRST, independent of config availability.
//
// RED-on-revert: without the `seen` map the duplicate case falls through to
// "No active configuration" (silently using the last interface value) instead
// of naming the repeated selector.
func TestShowTestZoneRejectsDuplicateSelector_5649(t *testing.T) {
	s := &Server{}

	const topic = "test-zone:interface=ge-0/0/1.0,interface=ge-0/0/9.0"
	const wantSubstr = `selector "interface" specified more than once`

	var buf strings.Builder
	if _, err := s.showTestZone(&pb.ShowTextRequest{Topic: topic}, nil, &buf); err != nil {
		t.Fatalf("showTestZone(%q) error = %v", topic, err)
	}
	out := buf.String()
	if !strings.Contains(out, wantSubstr) {
		t.Errorf("showTestZone(%q) = %q; want it to contain %q", topic, out, wantSubstr)
	}
	// A duplicate must NOT fall through to the config/lookup path: it is an
	// input error that fully short-circuits the query.
	if strings.Contains(out, "No active configuration") {
		t.Errorf("showTestZone(%q) fell through to the config path: %q", topic, out)
	}
}
