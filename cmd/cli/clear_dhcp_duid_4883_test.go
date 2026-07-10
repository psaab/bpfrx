// #4883-E: `clear dhcp client-identifier` with a malformed selector —
// `... interface` (no name) or `... interfce ge-0/0/0` (unknown selector) —
// used to fall through with an empty Interface, which the server treats as
// clear-ALL and wipes every DHCPv6 DUID. A malformed selector must ERROR
// before the RPC; only a bare `client-identifier` (no selector) is the
// intentional clear-all.

package main

import (
	"context"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// clearDUIDRecorder records ClearDHCPClientIdentifier calls so a test can
// assert a clear-ALL was NOT issued.
type clearDUIDRecorder struct {
	pb.BpfrxServiceClient

	calls     int
	lastIface string
}

func (f *clearDUIDRecorder) ClearDHCPClientIdentifier(
	_ context.Context, in *pb.ClearDHCPClientIdentifierRequest, _ ...grpc.CallOption,
) (*pb.ClearDHCPClientIdentifierResponse, error) {
	f.calls++
	f.lastIface = in.GetInterface()
	return &pb.ClearDHCPClientIdentifierResponse{Message: "ok"}, nil
}

// A malformed selector must ERROR before any RPC — never fall through to the
// empty (clear-ALL) request.
//
// Goes RED on revert: the old code sends an empty-Interface request for these
// forms, so calls would be 1 and err nil.
func TestClearDHCPMalformedSelectorNoRPC_4883(t *testing.T) {
	for _, args := range [][]string{
		{"client-identifier", "interface"},                      // interface, no name
		{"client-identifier", "interfce", "ge-0/0/0"},           // unknown selector
		{"client-identifier", "interface", "ge-0-0-0", "extra"}, // stray extra token
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			fake := &clearDUIDRecorder{}
			c := &ctl{client: fake}
			if err := c.handleClearDHCP(args); err == nil {
				t.Fatalf("handleClearDHCP(%v) = nil; want a usage error", args)
			}
			if fake.calls != 0 {
				t.Fatalf("ClearDHCPClientIdentifier issued %d times (iface=%q); expected 0 — "+
					"a malformed selector must not wipe ALL DHCPv6 DUIDs", fake.calls, fake.lastIface)
			}
		})
	}
}

// The well-formed forms still send: a bare `client-identifier` is the
// intentional clear-all (empty Interface); `interface <name>` is scoped.
func TestClearDHCPWellFormedStillSends_4883(t *testing.T) {
	cases := []struct {
		args      []string
		wantIface string
	}{
		{[]string{"client-identifier"}, ""},                                  // intentional clear-all
		{[]string{"client-identifier", "interface", "ge-0-0-0"}, "ge-0-0-0"}, // scoped
	}
	for _, tc := range cases {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			fake := &clearDUIDRecorder{}
			c := &ctl{client: fake}
			if err := c.handleClearDHCP(tc.args); err != nil {
				t.Fatalf("handleClearDHCP(%v) unexpected error: %v", tc.args, err)
			}
			if fake.calls != 1 || fake.lastIface != tc.wantIface {
				t.Fatalf("handleClearDHCP(%v): calls=%d iface=%q; want 1 / %q",
					tc.args, fake.calls, fake.lastIface, tc.wantIface)
			}
		})
	}
}
