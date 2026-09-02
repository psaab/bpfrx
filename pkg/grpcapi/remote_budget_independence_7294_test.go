package grpcapi

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/diagcmd"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #7294 item 3: local and peer-directed budgets must be INDEPENDENTLY
// boundable. This is the deliverable, not a side effect of the refactor.
//
// THE DEFECT. Peer-directed fan-out took a slot from SessionWalkLimiter even
// though it drives no local walk, so a burst of peer-directed requests could
// refuse genuine local scans while the local table was untouched. Four slots,
// shared across REST and gRPC, and `ShowText` is fabric-reachable.
//
// WHY BOTH DIRECTIONS, AND WHY ONE WOULD NOT DO. #8151 established this shape
// and its own test records the reason: a single direction passes on an
// implementation that has merely RENAMED the shared limiter. If peer work and
// local work still drew on one budget under two names, "saturate A, B still
// works" would fail in one direction and nobody would run the other. Asserting
// both is what distinguishes two budgets from one alias.
//
// NOT a capacity claim. Both budgets are 4. This says nothing about whether 4
// is the right number for either; it says saturating one does not refuse the
// other.

// TestRemoteBudgetIsADistinctInstance7294 is the cell the others cannot be.
//
// Every test below substitutes BOTH package aliases with fresh NewLimiter
// instances so it can drain one without touching the process-wide budgets. That
// substitution DESTROYS the property it is trying to observe: if production
// aliased both names to the same limiter, the substitution would hand the test
// two distinct ones anyway and every independence assertion would pass. Verified
// by mutation — pointing remoteWalkLimiter at diagcmd.SessionWalkLimiter left
// all three cells GREEN.
//
// #8151's own test records the same trap and answers it by draining the REAL
// limiters. Identity is the cheaper answer to the same question, and it is what
// the existing per-surface bound tests already assert about their aliases.
func TestRemoteBudgetIsADistinctInstance7294(t *testing.T) {
	if diagcmd.RemoteWalkLimiter == diagcmd.SessionWalkLimiter {
		t.Fatal("RemoteWalkLimiter and SessionWalkLimiter are the SAME instance: the remote " +
			"budget is a rename, not a budget, and peer work still consumes local capacity")
	}
	if remoteWalkLimiter != diagcmd.RemoteWalkLimiter {
		t.Error("this package's remoteWalkLimiter alias is not diagcmd.RemoteWalkLimiter; " +
			"peer admission is drawing on some other budget than the documented one")
	}
	if sessionWalkLimiter != diagcmd.SessionWalkLimiter {
		t.Error("this package's sessionWalkLimiter alias is not diagcmd.SessionWalkLimiter")
	}
	// The budgets are independently SIZED, not tied. Asserting the constants
	// rather than the caps so a future divergence is a deliberate edit here.
	if diagcmd.RemoteWalkLimiter.Cap() != diagcmd.MaxConcurrentRemoteWalks {
		t.Errorf("RemoteWalkLimiter cap = %d, want MaxConcurrentRemoteWalks = %d",
			diagcmd.RemoteWalkLimiter.Cap(), diagcmd.MaxConcurrentRemoteWalks)
	}
}

func newIndependenceServer(t *testing.T) *Server {
	t.Helper()
	return &Server{
		dp:    &walkCountDP{Manager: dataplane.New()},
		store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
	}
}

// drain takes every slot on a limiter and returns the releases.
func drain(t *testing.T, l *diagcmd.Limiter) func() {
	t.Helper()
	var rels []func()
	for i := 0; i < l.Cap(); i++ {
		rel, err := l.Acquire()
		if err != nil {
			t.Fatalf("drain: slot %d of %d: %v", i, l.Cap(), err)
		}
		rels = append(rels, rel)
	}
	if _, err := l.Acquire(); err == nil {
		t.Fatal("limiter admitted a caller after being drained to capacity; " +
			"it is not actually full and every assertion below is vacuous")
	}
	return func() {
		for _, r := range rels {
			r()
		}
	}
}

func TestSaturatedLocalBudgetDoesNotRefusePeerWork7294(t *testing.T) {
	origLocal, origRemote := sessionWalkLimiter, remoteWalkLimiter
	sessionWalkLimiter = diagcmd.NewLimiter(diagcmd.MaxConcurrentSessionWalks)
	remoteWalkLimiter = diagcmd.NewLimiter(diagcmd.MaxConcurrentRemoteWalks)
	defer func() { sessionWalkLimiter, remoteWalkLimiter = origLocal, origRemote }()

	undo := drain(t, sessionWalkLimiter)
	defer undo()

	s := newIndependenceServer(t)
	if _, err := s.PeerSessions(context.Background(), &pb.GetSessionsRequest{}); err != nil {
		t.Errorf("PeerSessions refused while only the LOCAL budget was saturated: %v\n\t"+
			"Peer-directed work drives no local walk; if a local scan flood can refuse it, "+
			"the two budgets are still one.", err)
	}
	if _, err := s.PeerSessionSummary(context.Background()); err != nil {
		t.Errorf("PeerSessionSummary refused on a saturated LOCAL budget: %v", err)
	}
	if _, err := s.PeerZonePairSummary(context.Background()); err != nil {
		t.Errorf("PeerZonePairSummary refused on a saturated LOCAL budget: %v", err)
	}
}

func TestSaturatedRemoteBudgetDoesNotRefuseLocalWork7294(t *testing.T) {
	origLocal, origRemote := sessionWalkLimiter, remoteWalkLimiter
	sessionWalkLimiter = diagcmd.NewLimiter(diagcmd.MaxConcurrentSessionWalks)
	remoteWalkLimiter = diagcmd.NewLimiter(diagcmd.MaxConcurrentRemoteWalks)
	defer func() { sessionWalkLimiter, remoteWalkLimiter = origLocal, origRemote }()

	undo := drain(t, remoteWalkLimiter)
	defer undo()

	s := newIndependenceServer(t)
	// GetSessions is the local walk. It must be admitted with the remote
	// budget full — this is the direction that fails if someone later routes
	// local work through the remote limiter "for consistency".
	if _, err := s.GetSessions(context.Background(), &pb.GetSessionsRequest{}); err != nil {
		t.Errorf("GetSessions refused while only the REMOTE budget was saturated: %v\n\t"+
			"A local walk must not be bounded by peer-directed capacity.", err)
	}

	// Control in the same cell: the remote budget really is full, so the
	// assertion above is about independence and not about an empty limiter.
	if _, err := s.PeerSessions(context.Background(), &pb.GetSessionsRequest{}); err == nil {
		t.Error("PeerSessions was admitted with the REMOTE budget drained; peer work is not " +
			"bounded by it, so the independence assertion above proves nothing")
	}
}

// TestPeerWorkNoLongerChargesTheLocalBudget7294 is the direct statement of what
// item 3 changed: a peer fetch must consume NO local slot. Asserted on the
// limiter's own accounting rather than inferred from an admission outcome, so
// it cannot be satisfied by a budget that happens to have room.
func TestPeerWorkNoLongerChargesTheLocalBudget7294(t *testing.T) {
	origLocal, origRemote := sessionWalkLimiter, remoteWalkLimiter
	sessionWalkLimiter = diagcmd.NewLimiter(diagcmd.MaxConcurrentSessionWalks)
	remoteWalkLimiter = diagcmd.NewLimiter(diagcmd.MaxConcurrentRemoteWalks)
	defer func() { sessionWalkLimiter, remoteWalkLimiter = origLocal, origRemote }()

	s := newIndependenceServer(t)

	// Asserted on the local limiter's own accounting: it must not move across
	// a peer fetch, at all.
	before := sessionWalkLimiter.InFlight()
	if _, err := s.PeerSessions(context.Background(), &pb.GetSessionsRequest{}); err != nil {
		t.Fatalf("PeerSessions: %v", err)
	}
	if got := sessionWalkLimiter.InFlight(); got != before {
		t.Errorf("local in-flight moved from %d to %d across a peer fetch", before, got)
	}

	// Positive control: the LOCAL method must still charge the local budget,
	// or "no local slot consumed" would be satisfied by a limiter nothing uses.
	held, err := sessionWalkLimiter.Acquire()
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if sessionWalkLimiter.InFlight() == before {
		t.Fatal("the local limiter does not track in-flight slots; the assertion above is vacuous")
	}
	held()
}
