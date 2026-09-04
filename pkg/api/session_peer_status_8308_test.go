package api

import (
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #8308: the REST session-list surface reports what the SERVER classified,
// and falls back to "ok" only for a server that predates the field.

func TestPeerFetchStatusStringKnowsBusy8308(t *testing.T) {
	for st, want := range map[pb.PeerFetchStatus]string{
		pb.PeerFetchStatus_PEER_FETCH_STATUS_NOT_APPLICABLE: "not-applicable",
		pb.PeerFetchStatus_PEER_FETCH_STATUS_OK:             "ok",
		pb.PeerFetchStatus_PEER_FETCH_STATUS_UNREACHABLE:    "unreachable",
		pb.PeerFetchStatus_PEER_FETCH_STATUS_BUSY:           "busy",
	} {
		if got := peerFetchStatusString(st); got != want {
			t.Errorf("peerFetchStatusString(%v) = %q, want %q", st, got, want)
		}
	}
}

func TestRestAndGrpcAgreeOnTheWordForARefusal8308(t *testing.T) {
	// The divergence #8306 left behind: REST said "busy" while gRPC said
	// "unreachable" about the same event. Both routes into this surface must
	// now produce the same word, and asserting the AGREEMENT rather than
	// pinning either to a literal is what makes the cell able to see a future
	// change to either side.
	//
	// The two routes are: this node classifying its own refusal
	// (peerFetchErrorStatus, the REST-local error path) and the server's
	// classification arriving on the wire (peerFetchStatusString of BUSY).
	viaLocalError := peerFetchErrorStatus(resourceExhausted8308())
	viaWire := peerFetchStatusString(pb.PeerFetchStatus_PEER_FETCH_STATUS_BUSY)
	if viaLocalError != viaWire {
		t.Errorf("the two routes disagree about a refusal: local error path says %q, "+
			"wire says %q. A list surface that reports a different word depending on "+
			"WHICH layer noticed the refusal is the divergence #8308 exists to close.",
			viaLocalError, viaWire)
	}
}

func TestUnspecifiedRendersAsNothingNotAWord8308(t *testing.T) {
	// UNSPECIFIED means "this server does not report it" — an older peer, or a
	// field never set. Rendering it as a word would assert something the wire
	// did not say, and "not-applicable" in particular would be a lie about a
	// clustered node.
	if got := peerFetchStatusString(pb.PeerFetchStatus_PEER_FETCH_STATUS_UNSPECIFIED); got != "" {
		t.Errorf("UNSPECIFIED rendered as %q, want empty", got)
	}
}

func TestTheUpgradeWindowFallbackKeeps8306sBehaviour8308(t *testing.T) {
	// The fallback in the handler is `if ps := peerFetchStatusString(...); ps
	// != "" { use it } else { "ok" }`. This cell pins the DISCRIMINATOR that
	// makes the fallback correct rather than the handler's plumbing: a
	// successful fetch from an older server yields "" from the mapper, and ""
	// is the only value that must fall back.
	//
	// Without the fallback, a peer running the previous release would report
	// no peer status at all on a fetch that SUCCEEDED — a regression against
	// #8306 on exactly the rolling-upgrade window this field was added
	// carefully for.
	if peerFetchStatusString(pb.PeerFetchStatus_PEER_FETCH_STATUS_UNSPECIFIED) != "" {
		t.Fatal("the fallback is keyed on the empty string; if UNSPECIFIED ever " +
			"renders as a word the handler will report it instead of \"ok\"")
	}
	// And every real outcome must NOT fall back, or the handler would flatten
	// a "busy" or an "unreachable" into "ok".
	for _, st := range []pb.PeerFetchStatus{
		pb.PeerFetchStatus_PEER_FETCH_STATUS_NOT_APPLICABLE,
		pb.PeerFetchStatus_PEER_FETCH_STATUS_OK,
		pb.PeerFetchStatus_PEER_FETCH_STATUS_UNREACHABLE,
		pb.PeerFetchStatus_PEER_FETCH_STATUS_BUSY,
	} {
		if peerFetchStatusString(st) == "" {
			t.Errorf("%v renders empty, so the handler would fall back to \"ok\" and "+
				"report a successful fetch for it", st)
		}
	}
}

func resourceExhausted8308() error {
	return grpcStatusResourceExhausted8308{}
}

type grpcStatusResourceExhausted8308 struct{}

func (grpcStatusResourceExhausted8308) Error() string { return "peer fetch refused on admission" }
func (grpcStatusResourceExhausted8308) GRPCStatus() *grpcstatus.Status {
	return grpcstatus.New(codes.ResourceExhausted, "peer fetch refused on admission")
}
