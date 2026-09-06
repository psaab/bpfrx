package grpcapi

import "context"

// #9060: the legacy GetSessions walk could not be aborted.
//
// The REST session walk has three guards; the gRPC legacy walk had none, and
// BOTH shipped clients take the legacy path -- cmd/cli/show_flow.go sends
// Limit:100 with no PageSize, and pkg/cli/session_filter.go sends Limit:10000,
// so an ordinary `show security flow session` is the trigger rather than
// something exotic. A PageSize > 0 would take the bounded cursor path; neither
// client sets one.
//
// WHICH OF THE THREE MATTERS, because they are not equal:
//
//   - The missing OFFSET CEILING is inert here. `Total` counts every matching
//     row, so the v4+v6 walk runs to EOF on every legacy call regardless of
//     offset; a cap would change nothing.
//   - The missing COUNT CAP cannot be fixed here alone: surfacing a "capped"
//     flag needs a field that does not exist in proto/xpf/v1, and silently
//     truncating without telling the client is worse than not truncating.
//     Deliberately left for that proto addition.
//   - The missing CANCELLATION is the live defect and is fixed here.
//
// WHY CANCELLATION IS THE ONE. The walk holds one of MaxConcurrentSessionWalks
// = 4 slots, and that limiter is SHARED WITH REST. Four abandoned legacy calls
// block every REST and gRPC session scan until each walk finishes on its own --
// a poller that times out keeps paying, and it pays on a surface it did not
// call. The map being walked is the shared conntrack hash (MaxEntries 10M) that
// the Rust helper writes on session INSTALL, so the contention is real; the
// per-packet claim is not, and is not made.
//
// Sampled rather than probed per session, for the reason pkg/api gives: a
// ctx.Err() read per entry adds lock traffic across a multi-million-entry
// table. The interval matches REST's deliberately -- two walks sharing one
// limiter should abandon a dead client on the same timescale, or the shared
// resource is still held by whichever surface is slower to notice.
const sessionWalkCancelInterval9060 = 1024

// newSessionWalkCancelSampler reports whether ctx is cancelled, reading
// ctx.Err() once per `every` calls and latching true once observed.
//
// A local twin of pkg/api's newRequestCancelSampler rather than a shared helper:
// the two packages have no common home for it below pkg/api, and moving it would
// touch the REST walk's #5233 guard for no behavioural gain. The interval and
// the latch semantics are pinned identical by a cell.
func newSessionWalkCancelSampler(ctx context.Context, every int) func() bool {
	if every < 1 {
		every = 1
	}
	n := 0
	cancelled := false
	return func() bool {
		// A FAST PATH, not the latch. The latching itself comes from `cancelled`
		// being captured and never reset -- ctx.Err() cannot go back to nil --
		// so removing this early return changes no observable behaviour, only
		// the work done per call once the walk has already decided to stop.
		// Stated because a mutation deleting it SURVIVES, and that survival is
		// correct rather than a coverage gap: it guards nothing.
		if cancelled {
			return true
		}
		n++
		if n >= every {
			n = 0
			cancelled = ctx.Err() != nil
		}
		return cancelled
	}
}
