package main

import (
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/policymatch"
)

// TestShowMatchPoliciesRendersServerVerdict covers the #3283 drift on the REMOTE
// CLI surface: `show security match-policies` previously hard-coded the no-match
// output as "default deny" and ignored resp.Action. Under
// `default-policy permit-all` the server returns Matched=false with
// Action="permit (default)", and the remote CLI must render that real verdict —
// not the literal "default deny" (which is the OPPOSITE of the dataplane, the
// same class #3283 fixes on the simulator).
//
// FAIL-ON-REVERT: restoring the hard-coded "(default deny)" string makes the
// "permit (default)" assertion fail (and the no-"default deny" assertion fail).
func TestShowMatchPoliciesRendersServerVerdict(t *testing.T) {
	fake := &fakeBpfrxClient{
		matchPoliciesResp: &pb.MatchPoliciesResponse{
			Matched: false,
			Action:  "permit (default)",
		},
	}
	c := &ctl{client: fake}

	out := captureStdout(t, func() {
		if err := c.showMatchPolicies([]string{"from-zone", "trust", "to-zone", "untrust"}); err != nil {
			t.Fatalf("showMatchPolicies: %v", err)
		}
	})

	if fake.matchPoliciesCalls != 1 {
		t.Fatalf("MatchPolicies called %d times, want 1", fake.matchPoliciesCalls)
	}
	if !strings.Contains(out, "permit (default)") {
		t.Fatalf("output missing server verdict %q:\n%s", "permit (default)", out)
	}
	if strings.Contains(out, "default deny") {
		t.Fatalf("output still renders hard-coded 'default deny':\n%s", out)
	}
}

// TestShowMatchPoliciesHostInboundUsesSSOTString covers the #3655 residual of
// #3647 on the REMOTE CLI surface: `show security match-policies ... to-zone
// junos-host` for an unmatched host path previously hard-coded
// "local delivery proceeds", which read as an unconditional admit even though a
// no-stanza zone now default-DENIES host-inbound (#3405). The remote client must
// render the shared SSOT policymatch.HostInboundShowLine — the exact string the
// local CLI / REST / gRPC surfaces already print post-#3647 — so a remote
// operator never sees the false-positive verdict on a core troubleshooting
// workflow.
//
// FAIL-ON-REVERT: restoring the hard-coded "local delivery proceeds" line makes
// the HostInboundShowLine assertion fail (and the no-"local delivery proceeds"
// assertion fail).
func TestShowMatchPoliciesHostInboundUsesSSOTString(t *testing.T) {
	fake := &fakeBpfrxClient{
		matchPoliciesResp: &pb.MatchPoliciesResponse{
			Matched:              false,
			HostInboundUnmatched: true,
			Action:               policymatch.HostInboundActionString,
		},
	}
	c := &ctl{client: fake}

	out := captureStdout(t, func() {
		if err := c.showMatchPolicies([]string{"from-zone", "trust", "to-zone", "junos-host"}); err != nil {
			t.Fatalf("showMatchPolicies: %v", err)
		}
	})

	if fake.matchPoliciesCalls != 1 {
		t.Fatalf("MatchPolicies called %d times, want 1", fake.matchPoliciesCalls)
	}
	if !strings.Contains(out, policymatch.HostInboundShowLine) {
		t.Fatalf("output missing SSOT HostInboundShowLine %q:\n%s", policymatch.HostInboundShowLine, out)
	}
	if strings.Contains(out, "local delivery proceeds") {
		t.Fatalf("output still renders hard-coded 'local delivery proceeds':\n%s", out)
	}
}

// TestShowMatchPoliciesRejectsInvalidICMP covers the #3284 gap on the remote
// surface: an invalid/out-of-range icmp-type/icmp-code token was silently
// dropped (inline strconv.Atoi + range check left the field nil → unconstrained
// query). It must now route through policymatch.ParseICMPValue and return an
// explicit error, like every other surface. The error returns during arg
// parsing, before any RPC, so an empty client suffices.
//
// FAIL-ON-REVERT: reverting to the inline strconv.Atoi drop makes these
// want-error cases return nil (and never error).
func TestShowMatchPoliciesRejectsInvalidICMP(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"icmp-type out of range", []string{"from-zone", "trust", "to-zone", "untrust", "protocol", "icmp", "icmp-type", "300"}},
		{"icmp-type non-numeric", []string{"from-zone", "trust", "to-zone", "untrust", "protocol", "icmp", "icmp-type", "abc"}},
		{"icmp-code out of range", []string{"from-zone", "trust", "to-zone", "untrust", "protocol", "icmp", "icmp-code", "999"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeBpfrxClient{}
			c := &ctl{client: fake}
			err := c.showMatchPolicies(tc.args)
			if err == nil {
				t.Fatalf("showMatchPolicies(%v) err = nil, want an invalid icmp diagnostic", tc.args)
			}
			if !strings.Contains(err.Error(), "icmp") {
				t.Fatalf("showMatchPolicies(%v) err = %v, want an icmp diagnostic", tc.args, err)
			}
			if fake.matchPoliciesCalls != 0 {
				t.Fatalf("MatchPolicies issued %d times on invalid input; want 0", fake.matchPoliciesCalls)
			}
		})
	}
}
