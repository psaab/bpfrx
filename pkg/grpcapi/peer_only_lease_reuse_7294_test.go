package grpcapi

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/diagcmd"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #7294: bind the #5880 lease-REUSE half to the REAL peer-only methods.
//
// WHAT WAS AND WAS NOT ALREADY BOUND. #5880 has two halves. "These paths
// acquire at all" is bound to production by
// TestPeerOnlyStillAcquiresAdmission in peer_only_5968_test.go — at
// capacity, with no lease, the real methods are refused. The other half,
// "a nested delegate holding an ancestor's lease does NOT self-reject at
// capacity", had no production binding: the only test driving it is
// TestRESTIncludePeerReusesLease_5880 in pkg/api, and its delegate is a
// `leaseProbeCluster` STUB whose GetSessions re-acquires the limiter
// itself.
//
// WHY THAT MATTERS NOW. #7294 item 3 gives peer-directed work its own
// budget, at which point the peer-only methods stop taking a local slot.
// The stub would go on re-acquiring the session-walk limiter and the
// pkg/api test would go on passing — describing a delegation shape that no
// longer exists. It would not go vacuous loudly; it would go green about a
// model. A guard that cannot observe the divergence a change creates
// certifies that change instead of checking it, so this binding lands
// BEFORE the change rather than with it.
//
// Measured on the tree as it stands: REST delegates in-process to exactly
// four gRPC methods (`svc.` in pkg/api/sessions.go) — PeerSessions at :476,
// PeerSessionSummary at :753, PeerZonePairSummary at :998, and
// ClearSessions at :803. Only the first three carry a lease; the clear
// handler delegates BEFORE it acquires, and its own Acquire at :824 gates
// only the local-only fallback taken when the cluster service is nil. So
// these three are the only production carriers of a session-walk lease
// across an in-process delegation, and this file is where that fact is
// checked rather than assumed.
func TestPeerOnlyReusesAnAncestorLease7294(t *testing.T) {
	orig := sessionWalkLimiter
	sessionWalkLimiter = diagcmd.NewLimiter(1)
	defer func() { sessionWalkLimiter = orig }()

	// Take the only slot the way the REST boundary does, keeping the leased
	// context. Capacity is now exhausted for anyone WITHOUT that lease.
	release, leased, err := sessionWalkLimiter.AcquireCtx(context.Background())
	if err != nil {
		t.Fatalf("seed AcquireCtx: %v", err)
	}
	defer release()

	dp := &walkCountDP{Manager: dataplane.New()}
	s := &Server{dp: dp}

	// CONTROL FIRST, and it is not decoration. Every assertion below is of
	// the form "this call succeeded". That is also what a limiter with spare
	// capacity produces, so without proving the limiter is genuinely full
	// the reuse assertions would pass on a fixture that never tested
	// anything. Each unleased call must be refused.
	for _, tc := range []struct {
		name string
		call func(context.Context) error
	}{
		{"PeerSessions", func(ctx context.Context) error {
			_, err := s.PeerSessions(ctx, &pb.GetSessionsRequest{})
			return err
		}},
		{"PeerSessionSummary", func(ctx context.Context) error {
			_, err := s.PeerSessionSummary(ctx)
			return err
		}},
		{"PeerZonePairSummary", func(ctx context.Context) error {
			_, err := s.PeerZonePairSummary(ctx)
			return err
		}},
	} {
		if err := tc.call(context.Background()); err == nil {
			t.Fatalf("%s was admitted at capacity WITHOUT a lease; the limiter is not "+
				"actually full, so the reuse assertions in this test would prove nothing",
				tc.name)
		}

		// The property: with the ancestor's lease on ctx, the same call is
		// admitted — it reuses the slot instead of taking a second one and
		// self-rejecting. This is the real method, not a model of it.
		if err := tc.call(leased); err != nil {
			t.Errorf("%s self-rejected while holding an ancestor's admission lease: %v\n\t"+
				"The REST boundary acquires, stamps the lease on the request context and "+
				"delegates here; if this path takes a second slot instead of reusing the "+
				"ancestor's, a single REST request self-rejects its own fan-out at "+
				"capacity (#5880).", tc.name, err)
		}
	}

	// The peer-only methods must still not walk locally while doing it —
	// otherwise "admitted" could be reached by a path that quietly does the
	// local work the #5968 fix removed.
	if got := dp.walks(); got != 0 {
		t.Errorf("peer-only methods walked the local table %d time(s) under a lease", got)
	}
}
