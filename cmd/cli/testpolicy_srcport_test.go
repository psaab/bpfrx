package main

import (
	"strings"
	"testing"
)

// TestTestPolicyRejectsInvalidSourcePort covers the #3107/#3116 gap on the
// remote `cli` client's `test policy` command (cmd/cli): a malformed or
// out-of-range source-port must return a clear command error and NEVER silently
// coerce to the 0 "any port" wildcard before the gRPC topic is built.
//
// Only the rejection path is unit-testable here: a VALID/ABSENT port proceeds
// to c.showText, which dials the gRPC client. The rejection returns before any
// client call, so an empty *ctl is sufficient.
//
// FAIL-ON-REVERT: removing the policymatch.ParsePort call on source-port makes
// "abc"/"70000" coerce silently with no error, flipping these cases red.
func TestTestPolicyRejectsInvalidSourcePort(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"malformed", []string{"from-zone", "trust", "to-zone", "untrust", "source-port", "abc"}},
		{"out of range", []string{"from-zone", "trust", "to-zone", "untrust", "source-port", "70000"}},
		{"negative", []string{"from-zone", "trust", "to-zone", "untrust", "source-port", "-1"}},
	}
	c := &ctl{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := c.testPolicy(tc.args)
			if err == nil {
				t.Fatalf("testPolicy(%v) err = nil, want an invalid source-port error", tc.args)
			}
			if !strings.Contains(err.Error(), "source-port") {
				t.Fatalf("testPolicy(%v) err = %v, want a source-port diagnostic", tc.args, err)
			}
		})
	}
}
