package grpcapi

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/diagcmd"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #5968 — the REST include_peer double-WALK.
//
// A REST list/summary/zone-pair request with include_peer walked the LOCAL
// session table in the REST handler, then delegated to the in-process gRPC
// service for the PEER table — and that method walked the local table AGAIN to
// build a local answer the caller discarded. #5880 fixed the double-ACQUIRE on
// this path; the redundant walk survived it.

// walkCountDP counts local table traversals. It is the measurement: the whole
// point of the peer-only entry points is that this counter stays at zero.
type walkCountDP struct {
	*dataplane.Manager
	v4Walks int
	v6Walks int
}

func (d *walkCountDP) IsLoaded() bool { return true }

func (d *walkCountDP) IterateSessions(func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	d.v4Walks++
	return nil
}

func (d *walkCountDP) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	d.v6Walks++
	return nil
}

func (d *walkCountDP) walks() int { return d.v4Walks + d.v6Walks }

// TestPeerSessionsDoesNotWalkLocalTable is the measurement that makes this a
// fix rather than a refactor: the peer-only entry point must traverse the local
// session table ZERO times.
//
// The positive control in the same test is what stops it from being satisfiable
// by a stub that does nothing at all — GetSessions on the SAME server and the
// SAME dataplane must still walk, because that is the method a direct gRPC
// client calls and its local answer is the answer.
//
// RED-on-revert: point PeerSessions at GetSessions and the zero-walk assertion
// fails.
func TestPeerSessionsDoesNotWalkLocalTable(t *testing.T) {
	dp := &walkCountDP{Manager: dataplane.New()}
	// The positive control drives the FULL GetSessions, which reads the active
	// config to build its filter, so the server needs a store.
	s := &Server{dp: dp, store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}

	if _, err := s.PeerSessions(context.Background(), &pb.GetSessionsRequest{}); err != nil {
		t.Fatalf("PeerSessions: %v", err)
	}
	if got := dp.walks(); got != 0 {
		t.Fatalf("PeerSessions walked the local session table %d time(s); the caller already has "+
			"its own local view and this walk was thrown away", got)
	}

	// Positive control: the full method still walks.
	before := dp.walks()
	if _, err := s.GetSessions(context.Background(), &pb.GetSessionsRequest{}); err != nil {
		t.Fatalf("GetSessions: %v", err)
	}
	if dp.walks() == before {
		t.Fatal("GetSessions performed no local walk — the zero-walk assertion above would then " +
			"be satisfied by a dataplane that never iterates, and would prove nothing")
	}
}

// TestPeerSummariesDoNotWalkLocalTable is the same measurement for the summary
// and zone-pair surfaces. All three REST handlers had the identical shape, so a
// fix that covered only the list would leave two-thirds of the redundant work
// in place.
func TestPeerSummariesDoNotWalkLocalTable(t *testing.T) {
	t.Run("session summary", func(t *testing.T) {
		dp := &walkCountDP{Manager: dataplane.New()}
		s := &Server{dp: dp, peerSessionSummaryFn: func(context.Context) (*pb.GetSessionSummaryResponse, error) {
			return &pb.GetSessionSummaryResponse{}, nil
		}}
		if _, err := s.PeerSessionSummary(context.Background()); err != nil {
			t.Fatalf("PeerSessionSummary: %v", err)
		}
		if got := dp.walks(); got != 0 {
			t.Fatalf("PeerSessionSummary walked the local table %d time(s)", got)
		}
	})

	t.Run("zone-pair summary", func(t *testing.T) {
		dp := &walkCountDP{Manager: dataplane.New()}
		s := &Server{dp: dp, peerZonePairSummaryFn: func(context.Context, *pb.GetZonePairSummaryRequest) (*pb.GetZonePairSummaryResponse, error) {
			return &pb.GetZonePairSummaryResponse{}, nil
		}}
		if _, err := s.PeerZonePairSummary(context.Background()); err != nil {
			t.Fatalf("PeerZonePairSummary: %v", err)
		}
		if got := dp.walks(); got != 0 {
			t.Fatalf("PeerZonePairSummary walked the local table %d time(s)", got)
		}
	})
}

// TestPeerOnlyClassifiesIdenticallyToFullPath binds the shared classification.
// The peer-only and full paths must agree on PeerStatus for the same fetch
// outcome; a divergence would always be a bug, so the switch is single-sourced
// in attachPeerSessionSummary / attachPeerZonePairSummary rather than copied.
//
// RED-on-revert: give the peer-only path its own copy of the switch and change
// one arm.
func TestPeerOnlyClassifiesIdenticallyToFullPath(t *testing.T) {
	t.Run("peer OK", func(t *testing.T) {
		s := &Server{peerSessionSummaryFn: func(context.Context) (*pb.GetSessionSummaryResponse, error) {
			return &pb.GetSessionSummaryResponse{TotalEntries: 7}, nil
		}}
		resp, err := s.PeerSessionSummary(context.Background())
		if err != nil {
			t.Fatalf("PeerSessionSummary: %v", err)
		}
		if resp.PeerStatus != pb.PeerFetchStatus_PEER_FETCH_STATUS_OK {
			t.Errorf("PeerStatus = %v, want OK", resp.PeerStatus)
		}
		if resp.GetPeer().GetTotalEntries() != 7 {
			t.Errorf("peer payload not attached: %v", resp.GetPeer())
		}
	})

	t.Run("peer unreachable", func(t *testing.T) {
		s := &Server{peerSessionSummaryFn: func(context.Context) (*pb.GetSessionSummaryResponse, error) {
			return nil, context.DeadlineExceeded
		}}
		resp, err := s.PeerSessionSummary(context.Background())
		if err != nil {
			t.Fatalf("PeerSessionSummary: %v", err)
		}
		if resp.PeerStatus != pb.PeerFetchStatus_PEER_FETCH_STATUS_UNREACHABLE {
			t.Errorf("PeerStatus = %v, want UNREACHABLE — a failed peer fetch must be visible, "+
				"not indistinguishable from a healthy standalone node (#5320)", resp.PeerStatus)
		}
		if resp.PeerError == "" {
			t.Error("PeerError is empty on an unreachable peer")
		}
	})

	t.Run("no peer", func(t *testing.T) {
		s := &Server{peerSessionSummaryFn: func(context.Context) (*pb.GetSessionSummaryResponse, error) {
			return nil, nil
		}}
		resp, err := s.PeerSessionSummary(context.Background())
		if err != nil {
			t.Fatalf("PeerSessionSummary: %v", err)
		}
		if resp.PeerStatus == pb.PeerFetchStatus_PEER_FETCH_STATUS_OK {
			t.Error("a (nil, nil) peer fetch must not classify as OK")
		}
	})
}

// TestPeerOnlyStillAcquiresAdmission is the guard against the tempting
// optimisation. These paths perform no local walk, so skipping the limiter
// looks free — but the #5880 lease-propagation test drives exactly this
// delegation, and a path that never acquires would make that guard vacuous
// without failing it.
//
// At capacity zero every acquire fails, so a method that acquires returns an
// error and one that does not returns success.
func TestPeerOnlyStillAcquiresAdmission(t *testing.T) {
	// #7294 item 3: restated onto the remote budget, which is what these
	// paths now take. Unchanged in what it asserts.
	orig := remoteWalkLimiter
	remoteWalkLimiter = diagcmd.NewLimiter(1)
	defer func() { remoteWalkLimiter = orig }()

	// Hold the only slot WITHOUT a lease, so a caller that acquires is rejected
	// and a caller that does not acquire sails through. NewLimiter clamps to a
	// minimum of 1, so this is how "no capacity" is expressed.
	release, err := remoteWalkLimiter.Acquire()
	if err != nil {
		t.Fatalf("seed acquire: %v", err)
	}
	defer release()

	dp := &walkCountDP{Manager: dataplane.New()}
	s := &Server{dp: dp}

	if _, err := s.PeerSessions(context.Background(), &pb.GetSessionsRequest{}); err == nil {
		t.Error("PeerSessions admitted a request at zero capacity — it does not acquire, so the " +
			"#5880 lease guard on this delegation is vacuous")
	}
	if _, err := s.PeerSessionSummary(context.Background()); err == nil {
		t.Error("PeerSessionSummary admitted a request at zero capacity")
	}
	if _, err := s.PeerZonePairSummary(context.Background()); err == nil {
		t.Error("PeerZonePairSummary admitted a request at zero capacity")
	}
}
