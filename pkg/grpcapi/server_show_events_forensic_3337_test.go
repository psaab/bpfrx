package grpcapi

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/logging"
)

// TestGetEventsForensicFieldsSurfaced pins #3337 on the gRPC surface: GetEvents
// must map the remaining RT_FLOW forensic fields (NAT tuples, session ID,
// elapsed/created, ingress/egress ifindex, TOS, TCP control bits, reason) from
// the EventRecord into the proto EventEntry, and the timestamp must keep
// sub-second (RFC3339Nano) resolution.
//
// FAIL-ON-REVERT: removing the new field assignments in GetEvents (or removing
// the proto fields) zeroes NatSrcAddr/NatDstAddr/SessionId/ElapsedTime/Created/
// CreatedNanos/EgressIfindex/IngressIfindex/Tos/TcpControlBits/Reason, failing
// the per-field assertions. Reverting RFC3339Nano -> RFC3339 truncates the
// timestamp and fails the nanosecond-fraction assertion.
func TestGetEventsForensicFieldsSurfaced(t *testing.T) {
	eb := logging.NewEventBuffer(16)
	eb.Add(logging.EventRecord{
		Time:           time.Date(2026, 6, 29, 12, 0, 0, 123456789, time.UTC),
		Type:           "SESSION_CLOSE",
		SrcAddr:        "10.0.1.5:51000",
		DstAddr:        "10.0.2.9:443",
		Protocol:       "TCP",
		Action:         "permit",
		PolicyID:       7,
		NATSrcAddr:     "172.16.1.1:12345",
		NATDstAddr:     "10.0.2.9:443",
		SessionID:      0xDEADBEEF,
		ElapsedTime:    42,
		Created:        1750000000,
		CreatedNanos:   500000000,
		EgressIfindex:  17,
		IngressIfindex: 9,
		TOS:            0xB8,
		TCPControlBits: 0x1B,
		Reason:         "policy",
	})
	s := &Server{eventBuf: eb}

	resp, err := s.GetEvents(context.Background(), &pb.GetEventsRequest{})
	if err != nil {
		t.Fatalf("GetEvents = %v; want success", err)
	}
	if len(resp.Events) != 1 {
		t.Fatalf("got %d events; want 1", len(resp.Events))
	}
	e := resp.Events[0]

	if !strings.Contains(e.Time, ".123456789") {
		t.Errorf("Time = %q; want RFC3339Nano with sub-second fraction", e.Time)
	}
	if e.NatSrcAddr != "172.16.1.1:12345" {
		t.Errorf("NatSrcAddr = %q; want 172.16.1.1:12345", e.NatSrcAddr)
	}
	if e.NatDstAddr != "10.0.2.9:443" {
		t.Errorf("NatDstAddr = %q; want 10.0.2.9:443", e.NatDstAddr)
	}
	if e.SessionId != 0xDEADBEEF {
		t.Errorf("SessionId = %d; want %d", e.SessionId, 0xDEADBEEF)
	}
	if e.ElapsedTime != 42 {
		t.Errorf("ElapsedTime = %d; want 42", e.ElapsedTime)
	}
	if e.Created != 1750000000 {
		t.Errorf("Created = %d; want 1750000000", e.Created)
	}
	if e.CreatedNanos != 500000000 {
		t.Errorf("CreatedNanos = %d; want 500000000", e.CreatedNanos)
	}
	if e.EgressIfindex != 17 {
		t.Errorf("EgressIfindex = %d; want 17", e.EgressIfindex)
	}
	if e.IngressIfindex != 9 {
		t.Errorf("IngressIfindex = %d; want 9", e.IngressIfindex)
	}
	if e.Tos != 0xB8 {
		t.Errorf("Tos = %d; want %d", e.Tos, 0xB8)
	}
	if e.TcpControlBits != 0x1B {
		t.Errorf("TcpControlBits = %d; want %d", e.TcpControlBits, 0x1B)
	}
	if e.Reason != "policy" {
		t.Errorf("Reason = %q; want policy", e.Reason)
	}
}
