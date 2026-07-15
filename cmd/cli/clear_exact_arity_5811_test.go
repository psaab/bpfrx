// #5811: global-only `clear` commands (whose backend action can ONLY clear
// everything) previously recognized a fixed keyword prefix and silently
// DISCARDED any trailing tokens, then issued the unscoped mutation. So a
// scoped-LOOKING command — `clear arp 192.0.2.10`, `clear security nat
// statistics rule web`, `clear security counters zone untrust`, `clear firewall
// all filter edge` — reported success while wiping the ENTIRE cache/counter
// set. These tests pin the exact-arity rejection on the REMOTE CLI: a trailing
// operand must ERROR before any RPC, and the bare form must still clear.
//
// Fail-on-revert: drop a `requireClearNoScope(...)` guard (return to discarding
// the suffix) and the matching reject test flips RED — the RPC fires (calls==1)
// and err is nil.

package main

import (
	"context"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// clearArityRecorder records the destructive RPCs a clear handler would issue,
// so a test can assert a scoped-looking request issued NONE.
type clearArityRecorder struct {
	pb.BpfrxServiceClient

	sysCalls      int
	lastSysAction string
	clearCtrCalls int
}

func (f *clearArityRecorder) SystemAction(
	_ context.Context, in *pb.SystemActionRequest, _ ...grpc.CallOption,
) (*pb.SystemActionResponse, error) {
	f.sysCalls++
	f.lastSysAction = in.GetAction()
	return &pb.SystemActionResponse{Message: "ok"}, nil
}

func (f *clearArityRecorder) ClearCounters(
	_ context.Context, _ *pb.ClearCountersRequest, _ ...grpc.CallOption,
) (*pb.ClearCountersResponse, error) {
	f.clearCtrCalls++
	return &pb.ClearCountersResponse{}, nil
}

// A trailing scope operand must ERROR before any RPC for every global-only
// clear command reachable through handleClear / handleClearSecurity /
// handleClearFirewall.
func TestClearGlobalOnlyTrailingScopeRejectedNoRPC_5811(t *testing.T) {
	tests := []struct {
		name string
		call func(c *ctl) error
	}{
		// Routed through the top-level dispatch so the args[1:] threading into
		// handleClearArp is covered too.
		{"arp addr via dispatch", func(c *ctl) error { return c.handleClear([]string{"arp", "192.0.2.10"}) }},
		{"arp addr", func(c *ctl) error { return c.handleClearArp([]string{"192.0.2.10"}) }},
		{"ipv6 neighbors iface", func(c *ctl) error { return c.handleClearIPv6([]string{"neighbors", "interface", "ge-0-0-0"}) }},
		{"interfaces statistics iface", func(c *ctl) error { return c.handleClearInterfaces([]string{"statistics", "ge-0-0-0"}) }},
		{"system config-lock session", func(c *ctl) error { return c.handleClearSystem([]string{"config-lock", "session", "42"}) }},
		{"nat statistics rule", func(c *ctl) error { return c.handleClearSecurity([]string{"nat", "statistics", "rule", "web"}) }},
		{"nat persistent-nat-table pool", func(c *ctl) error {
			return c.handleClearSecurity([]string{"nat", "source", "persistent-nat-table", "pool", "p1"})
		}},
		{"security counters zone", func(c *ctl) error { return c.handleClearSecurity([]string{"counters", "zone", "untrust"}) }},
		{"policies hit-count selector", func(c *ctl) error {
			return c.handleClearSecurity([]string{"policies", "hit-count", "from-zone", "trust"})
		}},
		{"firewall all filter", func(c *ctl) error { return c.handleClearFirewall([]string{"all", "filter", "edge"}) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &clearArityRecorder{}
			c := &ctl{client: fake}
			err := tt.call(c)
			if err == nil {
				t.Fatalf("%s: expected an error for a scoped-looking global clear, got nil", tt.name)
			}
			if !strings.Contains(err.Error(), "takes no scope") {
				t.Fatalf("%s: error %q does not explain the no-scope rejection", tt.name, err)
			}
			if fake.sysCalls != 0 || fake.clearCtrCalls != 0 {
				t.Fatalf("%s: destructive RPC issued (SystemAction=%d action=%q, ClearCounters=%d); a "+
					"scoped-looking clear must wipe NOTHING", tt.name, fake.sysCalls, fake.lastSysAction, fake.clearCtrCalls)
			}
		})
	}
}

// The bare (exact-arity) form of each global-only clear still issues its RPC.
func TestClearGlobalOnlyBareStillClears_5811(t *testing.T) {
	tests := []struct {
		name       string
		call       func(c *ctl) error
		wantSys    string // expected SystemAction, or "" if ClearCounters is used
		wantCtrRPC bool
	}{
		{"arp", func(c *ctl) error { return c.handleClearArp(nil) }, "clear-arp", false},
		{"ipv6 neighbors", func(c *ctl) error { return c.handleClearIPv6([]string{"neighbors"}) }, "clear-ipv6-neighbors", false},
		{"interfaces statistics", func(c *ctl) error { return c.handleClearInterfaces([]string{"statistics"}) }, "clear-interfaces-statistics", false},
		{"system config-lock", func(c *ctl) error { return c.handleClearSystem([]string{"config-lock"}) }, "clear-config-lock", false},
		{"nat statistics", func(c *ctl) error { return c.handleClearSecurity([]string{"nat", "statistics"}) }, "clear-nat-counters", false},
		{"nat persistent-nat-table", func(c *ctl) error {
			return c.handleClearSecurity([]string{"nat", "source", "persistent-nat-table"})
		}, "clear-persistent-nat", false},
		{"policies hit-count", func(c *ctl) error { return c.handleClearSecurity([]string{"policies", "hit-count"}) }, "clear-policy-counters", false},
		{"firewall all", func(c *ctl) error { return c.handleClearFirewall([]string{"all"}) }, "clear-firewall-counters", false},
		{"security counters", func(c *ctl) error { return c.handleClearSecurity([]string{"counters"}) }, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &clearArityRecorder{}
			c := &ctl{client: fake}
			if err := tt.call(c); err != nil {
				t.Fatalf("%s: bare form returned unexpected error: %v", tt.name, err)
			}
			if tt.wantCtrRPC {
				if fake.clearCtrCalls != 1 {
					t.Fatalf("%s: ClearCounters calls = %d, want 1", tt.name, fake.clearCtrCalls)
				}
				return
			}
			if fake.sysCalls != 1 || fake.lastSysAction != tt.wantSys {
				t.Fatalf("%s: SystemAction calls=%d action=%q, want 1 / %q",
					tt.name, fake.sysCalls, fake.lastSysAction, tt.wantSys)
			}
		})
	}
}
