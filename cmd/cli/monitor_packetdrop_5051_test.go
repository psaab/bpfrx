package main

import (
	"context"
	"io"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// fakePacketDropStream is a no-op MonitorPacketDrop stream that returns EOF on
// the first Recv, so a request that reaches the RPC completes immediately with
// a nil error. Only Recv is exercised by handleMonitorSecurityPacketDrop; the
// remaining ClientStream methods stay nil (the embedded interface) and would
// panic if called — which they never are.
type fakePacketDropStream struct {
	grpc.ServerStreamingClient[pb.MonitorPacketDropResponse]
}

func (fakePacketDropStream) Recv() (*pb.MonitorPacketDropResponse, error) {
	return nil, io.EOF
}

func (f *fakeBpfrxClient) MonitorPacketDrop(
	_ context.Context, in *pb.MonitorPacketDropRequest, _ ...grpc.CallOption,
) (grpc.ServerStreamingClient[pb.MonitorPacketDropResponse], error) {
	f.packetDropCalls++
	f.packetDropReq = in
	return fakePacketDropStream{}, nil
}

// TestRemotePacketDropStrictParse is the #5051 RED-on-revert guard for the
// REMOTE CLI `monitor security packet-drop` surface. The old parser used
// `if i+1 < len(args)` (missing value silently ignored) and
// `strconv.Atoi(...); err == nil` (parse error silently erased the port to
// 0 = wildcard) and had NO default arm for unknown tokens. As a result a typo
// like `source-port abc` opened an UNFILTERED drop stream showing ALL drops
// with a success exit — a fail-open incident-response filter. The parser now
// requires a value per selector, rejects non-numeric/out-of-range ports and
// count, and rejects unknown tokens, all BEFORE issuing the RPC.
//
// FAIL-ON-REVERT: restoring the loose loop lets these malformed inputs build a
// request and open the MonitorPacketDrop stream with no error, flipping the
// want-error + zero-RPC assertions red.
func TestRemotePacketDropStrictParse(t *testing.T) {
	rejectCases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"non-numeric source-port", []string{"source-port", "abc"}, "invalid source-port"},
		{"out-of-range source-port", []string{"source-port", "70000"}, "invalid source-port"},
		{"non-numeric destination-port", []string{"destination-port", "http"}, "invalid destination-port"},
		{"missing value trailing selector", []string{"source-prefix"}, "requires a value"},
		{"missing value protocol", []string{"protocol"}, "requires a value"},
		{"non-numeric count", []string{"count", "lots"}, "invalid count"},
		{"zero count", []string{"count", "0"}, "invalid count"},
		{"out-of-range count", []string{"count", "9000"}, "invalid count"},
		{"unknown selector typo", []string{"protcol", "tcp"}, "unknown packet-drop option"},
		{"unknown trailing token", []string{"protocol", "tcp", "bogus"}, "unknown packet-drop option"},
	}
	for _, tc := range rejectCases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeBpfrxClient{}
			c := &ctl{client: fake}
			err := c.handleMonitorSecurityPacketDrop(tc.args)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("handleMonitorSecurityPacketDrop(%v) err = %v, want %q", tc.args, err, tc.wantErr)
			}
			if fake.packetDropCalls != 0 {
				t.Fatalf("MonitorPacketDrop issued %d times on malformed input; want 0", fake.packetDropCalls)
			}
		})
	}

	// Valid selectors still reach the backend with the parsed request intact.
	t.Run("valid selectors reach RPC", func(t *testing.T) {
		fake := &fakeBpfrxClient{}
		c := &ctl{client: fake}
		_ = captureStdout(t, func() {
			args := []string{
				"source-port", "1024", "destination-port", "443",
				"protocol", "tcp", "from-zone", "trust",
				"interface", "ge-0/0/0", "count", "10",
			}
			if err := c.handleMonitorSecurityPacketDrop(args); err != nil {
				t.Fatalf("valid handleMonitorSecurityPacketDrop err = %v", err)
			}
		})
		if fake.packetDropCalls != 1 {
			t.Fatalf("MonitorPacketDrop called %d times on valid input, want 1", fake.packetDropCalls)
		}
		got := fake.packetDropReq
		if got == nil || got.SourcePort != 1024 || got.DestinationPort != 443 ||
			got.Protocol != "tcp" || got.FromZone != "trust" ||
			got.Interface != "ge-0/0/0" || got.Count != 10 {
			t.Fatalf("MonitorPacketDrop req = %+v, want sport=1024 dport=443 tcp trust ge-0/0/0 count=10", got)
		}
	})
}
