// #5779: ClearSessions drives full v4+v6 conntrack-table walks on BOTH the
// clear-all path (ClearAllSessions is a chunked full-table scan+delete) and the
// filtered path (clearFilteredSessionsV4/V6), the same per-bucket BPF-map lock
// contention DoS class as the #5708 read scans, on the mutation path. The fix
// gates the gRPC ClearSessions handler through the SAME shared sessionWalkLimiter.
//
// FAIL-ON-REVERT: removing the sessionWalkLimiter.Acquire() gate from
// ClearSessions makes the over-cap ResourceExhausted assertions here go RED (an
// over-cap clear proceeds instead of being rejected).
package grpcapi

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/diagcmd"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// clearBoundDP is a minimal grpcRuntime fake for the ClearSessions gate test:
// IsLoaded true and an atomic ClearAllSessions stub (so an ADMITTED clear-all
// returns cleanly). The embedded *dataplane.Manager satisfies the rest of the
// interface; the walk methods are never reached because the over-cap calls fail
// at Acquire before any dp interaction and the admitted call uses clear-all.
type clearBoundDP struct {
	*dataplane.Manager
}

func (clearBoundDP) IsLoaded() bool                      { return true }
func (clearBoundDP) ClearAllSessions() (int, int, error) { return 0, 0, nil }

// TestGRPCClearSessionsConcurrencyBound asserts both the clear-all and filtered
// ClearSessions variants are rejected with ResourceExhausted while the shared
// session-walk limiter is saturated, and admitted once a slot frees.
func TestGRPCClearSessionsConcurrencyBound(t *testing.T) {
	orig := sessionWalkLimiter
	t.Cleanup(func() { sessionWalkLimiter = orig })
	sessionWalkLimiter = diagcmd.NewLimiter(1)

	release, err := sessionWalkLimiter.Acquire()
	if err != nil {
		t.Fatalf("failed to pre-acquire the only slot: %v", err)
	}

	s := &Server{dp: clearBoundDP{Manager: dataplane.New()}}

	// clear-all variant (no filters -> ClearAllSessions chunked full-table walk).
	if _, err := s.ClearSessions(context.Background(), &pb.ClearSessionsRequest{}); !isResourceExhausted(err) {
		release()
		t.Fatalf("ClearSessions (clear-all) with a full session-walk limiter: err = %v, want codes.ResourceExhausted", err)
	}

	// filtered variant (Protocol filter -> clearFilteredSessions* full-table walk).
	if _, err := s.ClearSessions(context.Background(), &pb.ClearSessionsRequest{Protocol: "tcp"}); !isResourceExhausted(err) {
		release()
		t.Fatalf("ClearSessions (filtered) with a full session-walk limiter: err = %v, want codes.ResourceExhausted", err)
	}

	// Free the slot; the next clear must be admitted.
	release()
	if _, err := s.ClearSessions(context.Background(), &pb.ClearSessionsRequest{}); isResourceExhausted(err) {
		t.Fatalf("ClearSessions after slot release still ResourceExhausted: %v", err)
	}
}

// TestGRPCClearSessionsDrawsFromSharedSessionWalkLimiter proves the ClearSessions
// gate uses the process-wide diagcmd.SessionWalkLimiter (the SAME instance the
// read scans and REST use) — saturating the shared singleton directly rejects a
// clear.
func TestGRPCClearSessionsDrawsFromSharedSessionWalkLimiter(t *testing.T) {
	if sessionWalkLimiter != diagcmd.SessionWalkLimiter {
		t.Fatal("gRPC sessionWalkLimiter is not the shared diagcmd.SessionWalkLimiter instance")
	}

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

	s := &Server{dp: clearBoundDP{Manager: dataplane.New()}}
	if _, err := s.ClearSessions(context.Background(), &pb.ClearSessionsRequest{}); !isResourceExhausted(err) {
		t.Fatalf("ClearSessions with the shared limiter saturated: err = %v, want codes.ResourceExhausted", err)
	}
}
