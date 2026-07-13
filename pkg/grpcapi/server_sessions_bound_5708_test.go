// #5708 (codex-review-182 M35): the gRPC session list/summary scans had no
// shared admission bound, so a gRPC caller could issue unbounded full v4+v6
// conntrack-table walks (each holding per-bucket BPF-map locks against the live
// session-sync path) — a CPU/contention DoS through the uncovered gRPC surface,
// bypassing the REST sessionWalkLimiter. The fix hoists that limiter to
// diagcmd.SessionWalkLimiter and gates GetSessions/GetSessionSummary through it.
//
// FAIL-ON-REVERT: removing the sessionWalkLimiter.Acquire() gate from the gRPC
// handlers makes the over-cap ResourceExhausted assertions here go RED (an
// over-cap call proceeds to the walk and returns a normal response instead).
package grpcapi

import (
	"context"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/diagcmd"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// boundSessionDP is a minimal grpcRuntime fake: IsLoaded true, empty session
// tables (so a call that PASSES the admission gate returns cleanly). It embeds
// *dataplane.Manager to satisfy the rest of the interface.
type boundSessionDP struct {
	*dataplane.Manager
}

func (boundSessionDP) IsLoaded() bool { return true }

func (boundSessionDP) IterateSessions(func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	return nil
}

func (boundSessionDP) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}

func newBoundSessionServer(t *testing.T) *Server {
	t.Helper()
	return &Server{
		dp:    boundSessionDP{Manager: dataplane.New()},
		store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
	}
}

func isResourceExhausted(err error) bool {
	return status.Code(err) == codes.ResourceExhausted
}

// (a) A gRPC GetSessions issued while the shared session-walk limiter is
// saturated must be rejected with ResourceExhausted rather than driving its own
// concurrent full-table walk; once a slot frees the next call proceeds.
func TestGRPCGetSessionsConcurrencyBound(t *testing.T) {
	orig := sessionWalkLimiter
	t.Cleanup(func() { sessionWalkLimiter = orig })
	sessionWalkLimiter = diagcmd.NewLimiter(1) // single slot

	release, err := sessionWalkLimiter.Acquire()
	if err != nil {
		t.Fatalf("failed to pre-acquire the only slot: %v", err)
	}

	s := newBoundSessionServer(t)

	_, err = s.GetSessions(context.Background(), &pb.GetSessionsRequest{})
	if !isResourceExhausted(err) {
		release()
		t.Fatalf("GetSessions with a full session-walk limiter: err = %v, want codes.ResourceExhausted (admission gate not consulted)", err)
	}

	// Free the slot; the next scan must be admitted (no longer rejected).
	release()
	if _, err := s.GetSessions(context.Background(), &pb.GetSessionsRequest{}); isResourceExhausted(err) {
		t.Fatalf("GetSessions after slot release still ResourceExhausted: %v", err)
	}
}

// (a') Same admission contract for the summary scan.
func TestGRPCGetSessionSummaryConcurrencyBound(t *testing.T) {
	orig := sessionWalkLimiter
	t.Cleanup(func() { sessionWalkLimiter = orig })
	sessionWalkLimiter = diagcmd.NewLimiter(1)

	release, err := sessionWalkLimiter.Acquire()
	if err != nil {
		t.Fatalf("failed to pre-acquire the only slot: %v", err)
	}

	s := newBoundSessionServer(t)

	_, err = s.GetSessionSummary(context.Background(), &pb.GetSessionSummaryRequest{})
	if !isResourceExhausted(err) {
		release()
		t.Fatalf("GetSessionSummary with a full session-walk limiter: err = %v, want codes.ResourceExhausted", err)
	}

	release()
	if _, err := s.GetSessionSummary(context.Background(), &pb.GetSessionSummaryRequest{}); isResourceExhausted(err) {
		t.Fatalf("GetSessionSummary after slot release still ResourceExhausted: %v", err)
	}
}

// (a3) Same admission contract for the zone-pair breakdown scan. The REST twin
// (GET /security/sessions/summary/zone-pairs) is already gated, so without this
// zone-pairs would be bounded on REST but an unbounded full-table walk on gRPC.
func TestGRPCGetZonePairSummaryConcurrencyBound(t *testing.T) {
	orig := sessionWalkLimiter
	t.Cleanup(func() { sessionWalkLimiter = orig })
	sessionWalkLimiter = diagcmd.NewLimiter(1)

	release, err := sessionWalkLimiter.Acquire()
	if err != nil {
		t.Fatalf("failed to pre-acquire the only slot: %v", err)
	}

	s := newBoundSessionServer(t)

	_, err = s.GetZonePairSummary(context.Background(), &pb.GetZonePairSummaryRequest{})
	if !isResourceExhausted(err) {
		release()
		t.Fatalf("GetZonePairSummary with a full session-walk limiter: err = %v, want codes.ResourceExhausted", err)
	}

	release()
	if _, err := s.GetZonePairSummary(context.Background(), &pb.GetZonePairSummaryRequest{}); isResourceExhausted(err) {
		t.Fatalf("GetZonePairSummary after slot release still ResourceExhausted: %v", err)
	}
}

// (c) The gRPC session scans draw from the PROCESS-WIDE diagcmd.SessionWalkLimiter
// — the SAME instance the REST scans use — so a mix of REST+gRPC scrapers cannot
// collectively exceed the aggregate budget. Saturating the shared singleton
// directly (no package-var swap) must make a gRPC GetSessions ResourceExhausted.
func TestGRPCGetSessionsDrawsFromSharedSessionWalkLimiter(t *testing.T) {
	if sessionWalkLimiter != diagcmd.SessionWalkLimiter {
		t.Fatal("gRPC sessionWalkLimiter is not the shared diagcmd.SessionWalkLimiter instance; REST+gRPC budgets are not aggregated")
	}

	// Saturate the shared limiter directly.
	var releases []func()
	t.Cleanup(func() {
		for _, r := range releases {
			r()
		}
	})
	for {
		rel, err := diagcmd.SessionWalkLimiter.Acquire()
		if err != nil {
			break
		}
		releases = append(releases, rel)
	}
	if len(releases) == 0 {
		t.Fatal("could not acquire any slot on the shared limiter")
	}

	s := newBoundSessionServer(t)
	if _, err := s.GetSessions(context.Background(), &pb.GetSessionsRequest{}); !isResourceExhausted(err) {
		t.Fatalf("GetSessions with the shared limiter saturated: err = %v, want codes.ResourceExhausted (handler not drawing from the shared instance)", err)
	}
}

// (b) The returned session set is capped: a huge requested limit is clamped so
// a single scan cannot return an unbounded result set.
func TestGRPCGetSessionsResultCapEnforced(t *testing.T) {
	s := newBoundSessionServer(t)
	resp, err := s.GetSessions(context.Background(), &pb.GetSessionsRequest{Limit: 1_000_000})
	if err != nil {
		t.Fatalf("GetSessions: %v", err)
	}
	if resp.Limit != 10000 {
		t.Fatalf("resp.Limit = %d for requested Limit=1_000_000, want it clamped to 10000 (result cap not enforced)", resp.Limit)
	}
}
