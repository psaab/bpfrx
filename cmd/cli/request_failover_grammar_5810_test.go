// #5810: the remote CLI shares ONE strict cluster-failover grammar with the
// in-process CLI and the gRPC handler (pkg/clusterfailover). Every malformed
// command form must be rejected BEFORE the privileged SystemAction RPC; every
// accepted form must emit the exact wire action string. These tables are the
// SAME grammarvectors tables the in-process CLI and gRPC tests use, so the
// accept/reject verdicts cannot drift apart.
//
// RED on revert: restoring the old per-form ad-hoc parsing (e.g. the
// `len(args) >= 3 && args[2] == "node"` gate that ignored a misspelled
// selector) lets `redundancy-group 1 nod 0` fall through to
// `cluster-failover:1` — calls would be 1, err nil — failing the reject table.

package main

import (
	"testing"

	"github.com/psaab/xpf/pkg/clusterfailover/grammarvectors"
)

func TestRequestFailoverGrammarRejects_5810(t *testing.T) {
	for _, tc := range grammarvectors.CommandRejects {
		t.Run(tc.Name, func(t *testing.T) {
			fake := &failoverRecorder{}
			c := &ctl{client: fake}
			err := c.handleRequestChassisClusterFailover(tc.Args)
			if err == nil {
				t.Fatalf("handleRequestChassisClusterFailover(%v) = nil; want rejection", tc.Args)
			}
			if fake.calls != 0 {
				t.Fatalf("handleRequestChassisClusterFailover(%v): SystemAction issued %d times (%v); "+
					"a malformed form must not reach the daemon", tc.Args, fake.calls, fake.actions)
			}
		})
	}
}

func TestRequestFailoverGrammarAccepts_5810(t *testing.T) {
	for _, tc := range grammarvectors.CommandAccepts {
		t.Run(tc.Name, func(t *testing.T) {
			fake := &failoverRecorder{}
			c := &ctl{client: fake}
			if err := c.handleRequestChassisClusterFailover(tc.Args); err != nil {
				t.Fatalf("handleRequestChassisClusterFailover(%v) unexpected error: %v", tc.Args, err)
			}
			if fake.calls != 1 || fake.actions[0] != tc.Action {
				t.Fatalf("handleRequestChassisClusterFailover(%v): calls=%d actions=%v; want 1 / [%s]",
					tc.Args, fake.calls, fake.actions, tc.Action)
			}
		})
	}
}
