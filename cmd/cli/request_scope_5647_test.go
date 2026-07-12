// #5647: `request protocols ospf clear`, `request protocols bgp clear`, and
// `request security ipsec sa clear` map to selector-FREE global mutations on
// the daemon (vtysh `clear ip ospf process`, `clear bgp * soft`, and
// strongSwan `TerminateAllSAs`). The server actions have no selector plumbing,
// so a scoped-looking suffix (`... clear neighbor 10.0.0.1`, `... sa clear 42`)
// used to be silently DROPPED while the global reset still ran — the operator
// believed they scoped the action but every OSPF adjacency / BGP session / SA
// was reset.
//
// Fix option (b) — reject the scoped-looking suffix at the CLI before the RPC,
// because the downstream action is genuinely global-only (no per-neighbor /
// per-SA plumbing exists in FRR/strongSwan wiring here). Junos never silently
// widens scope.
//
// Goes RED on revert: delete the `len(args) > N` guards in
// handleRequestProtocols / handleRequestSecurity and the scoped suffix falls
// through to a global SystemAction (calls == 1, err == nil).

package main

import (
	"context"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// sysActionRecorder records SystemAction calls so a test can assert an
// untargeted global reset was NOT issued.
type sysActionRecorder struct {
	pb.BpfrxServiceClient

	calls   int
	actions []string
}

func (f *sysActionRecorder) SystemAction(
	_ context.Context, in *pb.SystemActionRequest, _ ...grpc.CallOption,
) (*pb.SystemActionResponse, error) {
	f.calls++
	f.actions = append(f.actions, in.GetAction())
	return &pb.SystemActionResponse{Message: "ok"}, nil
}

// A scoped-looking suffix on a global-only clear must ERROR before any RPC —
// never fall through to a selector-free global mutation.
func TestRequestScopedClearRejectedNotWidened_5647(t *testing.T) {
	cases := []struct {
		name string
		// call dispatches the handler under test with the scoped-looking args.
		call func(c *ctl) error
	}{
		{
			name: "ospf clear neighbor",
			call: func(c *ctl) error {
				return c.handleRequestProtocols([]string{"ospf", "clear", "neighbor", "10.0.0.1"})
			},
		},
		{
			name: "bgp clear neighbor",
			call: func(c *ctl) error {
				return c.handleRequestProtocols([]string{"bgp", "clear", "neighbor", "10.0.0.1"})
			},
		},
		{
			name: "ipsec sa clear id",
			call: func(c *ctl) error {
				return c.handleRequestSecurity([]string{"ipsec", "sa", "clear", "42"})
			},
		},
		{
			name: "ipsec sa clear tunnel name",
			call: func(c *ctl) error {
				return c.handleRequestSecurity([]string{"ipsec", "sa", "clear", "tunnel", "gw-a"})
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &sysActionRecorder{}
			c := &ctl{client: fake}

			err := tc.call(c)
			if err == nil {
				t.Fatalf("%s: returned nil; expected a rejection error for a "+
					"scoped-looking suffix on a global-only clear", tc.name)
			}
			if !strings.Contains(err.Error(), "does not accept a selector") {
				t.Fatalf("%s: error %q missing the selector-rejection reason", tc.name, err)
			}
			if fake.calls != 0 {
				t.Fatalf("%s: SystemAction issued %d times (%v); expected 0 — a "+
					"scoped-looking suffix must NOT trigger an untargeted global "+
					"reset", tc.name, fake.calls, fake.actions)
			}
		})
	}
}

// The well-formed global variants still send the correct action (no
// regression): the bare, unscoped clears remain functional.
func TestRequestUnscopedClearStillSends_5647(t *testing.T) {
	cases := []struct {
		name   string
		call   func(c *ctl) error
		action string
	}{
		{
			name:   "ospf clear",
			call:   func(c *ctl) error { return c.handleRequestProtocols([]string{"ospf", "clear"}) },
			action: "ospf-clear",
		},
		{
			name:   "bgp clear",
			call:   func(c *ctl) error { return c.handleRequestProtocols([]string{"bgp", "clear"}) },
			action: "bgp-clear",
		},
		{
			name:   "ipsec sa clear",
			call:   func(c *ctl) error { return c.handleRequestSecurity([]string{"ipsec", "sa", "clear"}) },
			action: "ipsec-sa-clear",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &sysActionRecorder{}
			c := &ctl{client: fake}
			if err := tc.call(c); err != nil {
				t.Fatalf("%s: unexpected error: %v", tc.name, err)
			}
			if fake.calls != 1 || fake.actions[0] != tc.action {
				t.Fatalf("%s: calls=%d actions=%v; want 1 / [%s]",
					tc.name, fake.calls, fake.actions, tc.action)
			}
		})
	}
}
