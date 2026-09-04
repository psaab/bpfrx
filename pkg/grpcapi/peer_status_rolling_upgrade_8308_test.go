package grpcapi

import (
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #8308: the wire change, and the rolling-upgrade window it has to survive.
//
// In a rolling HA upgrade the two nodes run different binaries against ONE
// wire, so both directions matter and neither is proved by a new-against-new
// test. Both are exercised here by round-tripping through real protobuf
// encode/decode rather than by asserting about struct fields, because the
// question is what the WIRE carries.

// TestBusyIsAddedNeverRedefined8308 pins the additive choice itself.
//
// The tempting alternative was to narrow UNREACHABLE to mean "unreachable or
// refused" and let the error string carry the difference. That is a
// REDEFINITION, and under a rolling upgrade the older binary keeps its old
// reading of the same number — so the two nodes would report different things
// about one event while agreeing on the bytes. The numbers below are the
// contract; changing any of them is the bug this cell exists to stop.
func TestBusyIsAddedNeverRedefined8308(t *testing.T) {
	for name, want := range map[pb.PeerFetchStatus]int32{
		pb.PeerFetchStatus_PEER_FETCH_STATUS_UNSPECIFIED:    0,
		pb.PeerFetchStatus_PEER_FETCH_STATUS_NOT_APPLICABLE: 1,
		pb.PeerFetchStatus_PEER_FETCH_STATUS_OK:             2,
		pb.PeerFetchStatus_PEER_FETCH_STATUS_UNREACHABLE:    3,
		pb.PeerFetchStatus_PEER_FETCH_STATUS_BUSY:           4,
	} {
		if int32(name) != want {
			t.Errorf("%v = %d, want %d — an existing member's number moved, which "+
				"changes what an already-deployed binary reports", name, int32(name), want)
		}
	}
}

// TestAnOlderClientDecodingBusyKeepsTheValue8308 is the new-server /
// old-client direction.
//
// An older binary has no BUSY member. protobuf preserves an unknown enum value
// as its number, so the older client renders "4" rather than a word — visibly
// odd rather than silently wrong, which is the trade the additive choice buys.
// What must NOT happen is the value arriving as something the old client would
// render as a DIFFERENT known state: a 3 would read as "unreachable" and send
// an operator after a network fault that does not exist, which is the whole
// defect this issue is about.
func TestAnOlderClientDecodingBusyKeepsTheValue8308(t *testing.T) {
	sent := &pb.GetSessionsResponse{
		PeerStatus: pb.PeerFetchStatus_PEER_FETCH_STATUS_BUSY,
		PeerError:  "peer fetch refused on admission",
	}
	wire, err := proto.Marshal(sent)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got pb.GetSessionsResponse
	if err := proto.Unmarshal(wire, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if int32(got.GetPeerStatus()) != 4 {
		t.Fatalf("peer_status crossed the wire as %d, want 4", int32(got.GetPeerStatus()))
	}
	if int32(got.GetPeerStatus()) == int32(pb.PeerFetchStatus_PEER_FETCH_STATUS_UNREACHABLE) {
		t.Fatal("BUSY must never arrive as UNREACHABLE — that is the misreport this " +
			"issue exists to fix, and it would be invisible to an older client")
	}
}

// TestNewCodeDecodingAnOlderResponseSeesUnspecified8308 is the old-server /
// new-client direction, and it is the one a new-against-new test cannot reach.
//
// An older server does not set field 8 or 9. The bytes simply are not there, so
// a new client decodes the zero value. UNSPECIFIED's documented meaning is "not
// evaluated / older server", so the contract is that a reader treats it as
// "this server does not report it" and NEVER as an outcome.
func TestNewCodeDecodingAnOlderResponseSeesUnspecified8308(t *testing.T) {
	// An older server's response, modelled as what it actually is on the wire:
	// the same message with the new fields never set.
	older := &pb.GetSessionsResponse{Total: 3, NodeId: 1}
	wire, err := proto.Marshal(older)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got pb.GetSessionsResponse
	if err := proto.Unmarshal(wire, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.GetPeerStatus() != pb.PeerFetchStatus_PEER_FETCH_STATUS_UNSPECIFIED {
		t.Errorf("peer_status = %v, want UNSPECIFIED for a response that omits it",
			got.GetPeerStatus())
	}
	if got.GetPeerError() != "" {
		t.Errorf("peer_error = %q, want empty", got.GetPeerError())
	}
	// CONTROL: the rest of the message still decodes. Without this the cell
	// would pass against a marshal that produced nothing at all.
	if got.GetTotal() != 3 || got.GetNodeId() != 1 {
		t.Errorf("the older fields must still decode; got total=%d node=%d",
			got.GetTotal(), got.GetNodeId())
	}
}

// TestAdmissionRefusalClassifiesBusyNotUnreachable8308 pins the classification
// that the whole change exists for.
func TestAdmissionRefusalClassifiesBusyNotUnreachable8308(t *testing.T) {
	refusal := status.Error(codes.ResourceExhausted, "session walk limiter at capacity")
	if got := peerFetchErrorStatus(refusal); got != pb.PeerFetchStatus_PEER_FETCH_STATUS_BUSY {
		t.Errorf("an admission refusal classified as %v, want BUSY — the peer IS "+
			"reachable and this node declined to ask", got)
	}

	// The other side, which is what stops this from being a rename of
	// UNREACHABLE: a genuine transport failure must still be UNREACHABLE.
	for _, e := range []error{
		errors.New("dial tcp: connection refused"),
		status.Error(codes.Unavailable, "peer down"),
		status.Error(codes.DeadlineExceeded, "peer timed out"),
	} {
		if got := peerFetchErrorStatus(e); got != pb.PeerFetchStatus_PEER_FETCH_STATUS_UNREACHABLE {
			t.Errorf("peerFetchErrorStatus(%v) = %v, want UNREACHABLE", e, got)
		}
	}
}
