package grpcapi

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/logging"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// mockPacketDropStream is a minimal grpc.ServerStreamingServer used to drive
// MonitorPacketDrop's validation. It carries a context so a request that
// passes validation exits the stream loop via ctx.Done() instead of blocking.
type mockPacketDropStream struct {
	ctx  context.Context
	sent []string
}

func (m *mockPacketDropStream) Send(r *pb.MonitorPacketDropResponse) error {
	m.sent = append(m.sent, r.Line)
	return nil
}
func (m *mockPacketDropStream) Context() context.Context     { return m.ctx }
func (m *mockPacketDropStream) SetHeader(metadata.MD) error  { return nil }
func (m *mockPacketDropStream) SendHeader(metadata.MD) error { return nil }
func (m *mockPacketDropStream) SetTrailer(metadata.MD)       {}
func (m *mockPacketDropStream) SendMsg(any) error            { return nil }
func (m *mockPacketDropStream) RecvMsg(any) error            { return nil }

func packetDropTestStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet { address 10.0.1.1/24; }
        }
    }
}
security {
    zones {
        security-zone trust { interfaces ge-0/0/0.0; }
        security-zone untrust;
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

// TestMonitorPacketDropRejectsInvalidInputs guards #3382: MonitorPacketDrop is
// a local-only stream that must reject impossible/unknown filters with
// InvalidArgument rather than opening a stream that can never match (a silent
// empty stream during incident response).
//
// FAIL-ON-REVERT: removing the validation block lets each of these requests
// subscribe and (for the cancelled context) return context.Canceled instead of
// InvalidArgument.
func TestMonitorPacketDropRejectsInvalidInputs(t *testing.T) {
	s := &Server{store: packetDropTestStore(t), eventBuf: logging.NewEventBuffer(16)}

	cases := []struct {
		name string
		req  *pb.MonitorPacketDropRequest
	}{
		{"non-local node", &pb.MonitorPacketDropRequest{Node: "1"}},
		{"node all", &pb.MonitorPacketDropRequest{Node: "all"}},
		{"negative count", &pb.MonitorPacketDropRequest{Count: -1}},
		{"count over cap", &pb.MonitorPacketDropRequest{Count: 9000}},
		{"source-port over 65535", &pb.MonitorPacketDropRequest{SourcePort: 70000}},
		{"destination-port over 65535", &pb.MonitorPacketDropRequest{DestinationPort: 99999}},
		{"unknown protocol", &pb.MonitorPacketDropRequest{Protocol: "tpc"}},
		{"unknown from-zone", &pb.MonitorPacketDropRequest{FromZone: "trsut"}},
		{"unknown interface", &pb.MonitorPacketDropRequest{Interface: "ge-0/0/99"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A bounded context so a fail-on-revert (validation removed)
			// surfaces as a fast DeadlineExceeded instead of a hang: with
			// validation present the call returns InvalidArgument before it
			// ever subscribes, so the timeout is never reached.
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			stream := &mockPacketDropStream{ctx: ctx}
			err := s.MonitorPacketDrop(tc.req, stream)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("MonitorPacketDrop(%+v) code = %v, want InvalidArgument (err=%v)", tc.req, status.Code(err), err)
			}
		})
	}
}

// TestMonitorPacketDropAcceptsValidInputs proves the validation does not reject
// legitimate filters: a valid request passes validation, subscribes, and exits
// via the cancelled context (context.Canceled), never InvalidArgument.
func TestMonitorPacketDropAcceptsValidInputs(t *testing.T) {
	s := &Server{store: packetDropTestStore(t), eventBuf: logging.NewEventBuffer(16)}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel so the stream loop returns immediately

	req := &pb.MonitorPacketDropRequest{
		Node:            "local",
		Count:           100,
		SourcePort:      443,
		DestinationPort: 80,
		Protocol:        "TCP",
		FromZone:        "trust",
		Interface:       "ge-0/0/0",
	}
	stream := &mockPacketDropStream{ctx: ctx}
	err := s.MonitorPacketDrop(req, stream)
	if status.Code(err) == codes.InvalidArgument {
		t.Fatalf("MonitorPacketDrop(valid) = InvalidArgument (%v), want it to pass validation", err)
	}
	if err != context.Canceled {
		t.Fatalf("MonitorPacketDrop(valid) err = %v, want context.Canceled (validation passed, loop exited)", err)
	}
}
