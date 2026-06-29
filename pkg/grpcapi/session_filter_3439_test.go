// #3439 L2: direct gRPC GetSessions must distinguish invalid operator
// input from an empty result set. Before the fix, an unparseable
// protocol token (e.g. "tcpip") iterated to an empty session list and
// returned as a *successful* RPC, and a negative offset (proto field is
// int32) made the first row satisfy `idx >= offset`, silently behaving
// like offset 0. Both now fail with codes.InvalidArgument.
//
// FAIL-ON-REVERT:
//   - Dropping the protocol guard in buildSessionFilter makes
//     TestSessionFilterRejectsInvalidProtocol go RED (validate returns
//     nil for "tcpip").
//   - Dropping the `offset < 0` check in getSessionsLegacy makes
//     TestGetSessionsRejectsNegativeOffset go RED (the RPC succeeds).
package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func TestSessionFilterRejectsInvalidProtocol(t *testing.T) {
	s := newViewServer(t, &viewFaultGRPCDP{Manager: dataplane.New()})

	// An unparseable protocol token must surface as InvalidArgument,
	// not iterate to an empty success.
	bad := s.buildSessionFilter(&pb.GetSessionsRequest{Protocol: "tcpip"})
	err := bad.validate()
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("Protocol=tcpip: validate() = %v (code %v); want InvalidArgument",
			err, status.Code(err))
	}

	// Known names and numeric 0-255 stay valid.
	for _, proto := range []string{"tcp", "udp", "icmpv6", "gre", "sctp", "47", "0", "255"} {
		f := s.buildSessionFilter(&pb.GetSessionsRequest{Protocol: proto})
		if err := f.validate(); err != nil {
			t.Errorf("Protocol=%q: validate() = %v; want nil", proto, err)
		}
	}

	// Out-of-range numeric is rejected (not 0-255).
	over := s.buildSessionFilter(&pb.GetSessionsRequest{Protocol: "256"})
	if status.Code(over.validate()) != codes.InvalidArgument {
		t.Errorf("Protocol=256: want InvalidArgument, got %v", over.validate())
	}

	// Regression guard (#3439 / Refs #3393): "ipv6" is a NAME the system
	// still DISPLAYS (protoName(41)) but the strict ProtocolNumber does
	// not reverse. The earlier ProtocolNumber-only guard wrongly rejected
	// it; the lenient resolver must accept it AND the matcher must match
	// proto-41 sessions.
	v6name := s.buildSessionFilter(&pb.GetSessionsRequest{Protocol: "ipv6"})
	if err := v6name.validate(); err != nil {
		t.Errorf("Protocol=ipv6: validate() = %v; want nil (it is a displayed protocol name)", err)
	}
	if !protoFilterMatches(41, "ipv6") {
		t.Errorf("protoFilterMatches(41, \"ipv6\") = false; want true")
	}
	if protoFilterMatches(6, "ipv6") {
		t.Errorf("protoFilterMatches(6, \"ipv6\") = true; want false")
	}
}

func TestGetSessionsRejectsNegativeOffsetCursor(t *testing.T) {
	s := newViewServer(t, &viewFaultGRPCDP{Manager: dataplane.New()})

	// Cursor path: PageSize > 0 routes to getSessionsCursor, which never
	// consulted Offset — a negative offset was silently accepted. The
	// guard now lives in GetSessions before the PageSize branch, so the
	// cursor path rejects it too (#3439 L2, Codex MAJOR fold).
	_, err := s.GetSessions(context.Background(), &pb.GetSessionsRequest{PageSize: 1, Offset: -1})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("PageSize=1 Offset=-1: GetSessions err = %v (code %v); want InvalidArgument",
			err, status.Code(err))
	}
}

func TestGetSessionsRejectsNegativeOffset(t *testing.T) {
	s := newViewServer(t, &viewFaultGRPCDP{Manager: dataplane.New()})

	_, err := s.GetSessions(context.Background(), &pb.GetSessionsRequest{Offset: -1})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("Offset=-1: GetSessions err = %v (code %v); want InvalidArgument",
			err, status.Code(err))
	}

	// A non-negative offset is not rejected by the offset guard. With
	// nil iterators (no sessions) the legacy path returns a clean,
	// non-error empty response.
	if _, err := s.GetSessions(context.Background(), &pb.GetSessionsRequest{Offset: 0}); err != nil {
		t.Fatalf("Offset=0: unexpected error %v", err)
	}
}
