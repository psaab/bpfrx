package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/diagcmd"
)

// The four full session fan-out handlers held the LOCAL session-walk slot
// across the peer RTT (#9041 part 2).
//
// GetSessions, GetSessionSummary, GetZonePairSummary and ClearSessions each
// acquire sessionWalkLimiter with `defer release()` covering the whole handler
// body, and dial the peer INSIDE that region. MaxConcurrentSessionWalks is 4,
// and the worst case per request is dialPeer 2s x N fabric addresses (4s
// dual-fabric) plus the peer RPC (3s, or 5s for the clear) — so four concurrent
// requests saturate the budget below 1 rps and GetStatus and other genuine
// local scans answer ResourceExhausted.
//
// The expensive case is a peer that is ALIVE BUT SLOW. A dead peer costs
// nothing (the helpers return before dialPeer when !PeerAlive), and a healthy
// peer answers in milliseconds. Alive-but-slow is exactly the incident during
// which an operator is running these commands, which is what makes this an
// incident amplifier rather than a steady-state lever.
//
// The precedent is in-tree and explicit. peer_only_5968.go:
//
//	charging peer work to SessionWalkLimiter meant peer-directed work could
//	refuse genuine local scans while the local table was untouched
//
// and #7294 item 3 moved the peer-ONLY paths to RemoteWalkLimiter for exactly
// that reason. These four are the paths #7294 did not reach: on them the slot
// legitimately covers a real local walk, and only the peer-RTT TAIL is excess.
//
// The handoff lives in the peer helpers rather than at their call sites on
// purpose. fetchPeerSessions alone has four call sites and clearPeerSessions
// two; a per-call-site release is six places to keep right and one place to
// forget, and a forgotten one is invisible — it just keeps the old behaviour.
// The helper is also where the RTT actually begins, so the release lands
// immediately before the cost it is paying for.

// localWalkReleaseKey carries the handler's session-walk release down to the
// peer fan-out helpers. It sits on the context beside the #5880 admission
// lease, which is already carried the same way, so the release travels with
// the thing it releases.
type localWalkReleaseKey struct{}

// withLocalWalkRelease publishes the caller's session-walk release for the peer
// fan-out to hand off. A nil release (no slot held) is a no-op.
func withLocalWalkRelease(ctx context.Context, release func()) context.Context {
	if release == nil {
		return ctx
	}
	return context.WithValue(ctx, localWalkReleaseKey{}, release)
}

// beginPeerLeg moves a request off the LOCAL session-walk budget and onto the
// REMOTE one for the duration of a peer RTT, returning the context to use for
// the peer call and a done func that frees the remote slot.
//
// Called immediately before the dial, so the local slot is freed exactly when
// the local walk is finished and the only remaining work is remote. All six
// call sites of the four helpers return the response immediately after the peer
// leg, so nothing touches the local table after the release — that is the
// precondition this depends on, and it is asserted by a cell rather than left
// as a reading.
//
// The local release is the sync.Once-guarded closure Acquire returns, so the
// handler's own `defer release()` still runs and is simply a no-op. Under a
// #5880 lease reuse the release is already `func(){}`: a descendant must NOT
// free an ancestor's slot, since the ancestor may still walk after this returns.
// The nested in-process case therefore keeps its previous behaviour, which is
// the conservative direction; the direct gRPC case — the one that saturates the
// budget — is the one that changes.
//
// This is not a loosening. The peer leg was bounded by 4 slots before and is
// bounded by 4 slots now (MaxConcurrentRemoteWalks == MaxConcurrentSessionWalks);
// what changes is WHICH budget, so saturating the peer fan-out can no longer
// refuse a local scan. A refused remote slot returns ResourceExhausted, which
// peerFetchErrorStatus already classifies as PEER_FETCH_STATUS_BUSY — the peer
// result is reported as refused, never silently absent (#8306).
func beginPeerLeg(ctx context.Context) (context.Context, func(), error) {
	done, remoteCtx, err := diagcmd.RemoteWalkLimiter.AcquireCtx(ctx)
	if err != nil {
		return ctx, nil, status.Error(codes.ResourceExhausted,
			"peer session fan-out concurrency limit reached; retry shortly")
	}
	// Only after the remote slot is secured: releasing first and then failing
	// to acquire would drop the local slot for a leg that never runs.
	if rel, ok := ctx.Value(localWalkReleaseKey{}).(func()); ok && rel != nil {
		rel()
	}
	return remoteCtx, done, nil
}
