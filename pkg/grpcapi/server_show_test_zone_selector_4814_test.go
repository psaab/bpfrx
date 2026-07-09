package grpcapi

import (
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #4814: showTestZone used `if len(parts) == 2 && parts[0] == "interface"`
// with no else/default arm, so a malformed segment (no `=`) or an
// unrecognized key (e.g. `interfac=ge-0/0/0`, a typo) was SILENTLY dropped —
// ifName stayed empty with no diagnostic, and the operator saw the generic
// "Missing interface parameter" fallback instead of a message naming their
// actual typo (parity gap vs the #4589 showTestRouting hardening, itself
// mirroring #3696's showTestPolicy fix — showTestZone regressed to the
// pre-#4589 pattern). The handler must now report the typo.
//
// cfg is nil here (no active configuration set up), so a valid selector
// proceeds to the "No active configuration" diagnostic; a typo is reported
// first, before the nil-cfg check runs.
//
// RED-on-revert: without the default arm, the typo'd `interfac` case falls
// straight to "No active configuration" (silently ignoring the selector)
// instead of naming the unknown key.
func TestShowTestZoneReportsUnknownSelector(t *testing.T) {
	s := &Server{}

	cases := []struct {
		name       string
		topic      string
		wantSubstr string
	}{
		{
			name:       "typo'd interface key",
			topic:      "test-zone:interfac=ge-0/0/0",
			wantSubstr: `unknown selector "interfac"`,
		},
		{
			name:       "malformed segment",
			topic:      "test-zone:garbage",
			wantSubstr: "malformed selector segment",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf strings.Builder
			if _, err := s.showTestZone(&pb.ShowTextRequest{Topic: tc.topic}, nil, &buf); err != nil {
				t.Fatalf("showTestZone(%q) error = %v", tc.topic, err)
			}
			out := buf.String()
			if !strings.Contains(out, tc.wantSubstr) {
				t.Errorf("showTestZone(%q) = %q; want it to contain %q", tc.topic, out, tc.wantSubstr)
			}
		})
	}
}

// A valid selector set (correct `interface=` key) does NOT report an
// unknown selector; with cfg nil it falls through to the
// no-active-configuration diagnostic, proving the hardening does not
// false-positive on good input.
func TestShowTestZoneValidSelectorNotFlagged(t *testing.T) {
	s := &Server{}
	var buf strings.Builder
	if _, err := s.showTestZone(&pb.ShowTextRequest{Topic: "test-zone:interface=ge-0/0/0"}, nil, &buf); err != nil {
		t.Fatalf("showTestZone error = %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "unknown selector") || strings.Contains(out, "malformed selector") {
		t.Errorf("showTestZone flagged a valid selector: %q", out)
	}
	if !strings.Contains(out, "No active configuration") {
		t.Errorf("showTestZone(valid, cfg=nil) = %q; want the no-active-configuration diagnostic", out)
	}
}

// A bare `test-zone:` (empty params) still falls through to the "Missing
// interface parameter" diagnostic, not a selector-grammar error — matching
// the #4589 showTestRouting precedent for an empty selector string.
func TestShowTestZoneEmptySelectorFallsThrough(t *testing.T) {
	s := &Server{}
	var buf strings.Builder
	if _, err := s.showTestZone(&pb.ShowTextRequest{Topic: "test-zone:"}, nil, &buf); err != nil {
		t.Fatalf("showTestZone error = %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "unknown selector") || strings.Contains(out, "malformed selector") {
		t.Errorf("showTestZone flagged an empty selector: %q", out)
	}
	if !strings.Contains(out, "No active configuration") {
		t.Errorf("showTestZone(empty, cfg=nil) = %q; want the no-active-configuration diagnostic", out)
	}
}
