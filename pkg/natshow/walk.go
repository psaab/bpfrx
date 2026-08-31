package natshow

import (
	"context"

	"github.com/psaab/xpf/pkg/dataplane"
)

// walkSessionValues is the ONE session-walk authority for this package.
//
// Every NAT renderer that tallies live sessions (persistent-NAT detail,
// source-rule detail, destination-rule detail) drove its own hand-copied
// pair of IterateSessions/IterateSessionsV6 loops with its own scan-error
// precedence. Three copies of one walk is three places for the
// cancellation check to be forgotten, and it was in fact absent from all
// three (#7315).
//
// The cancellation check lives HERE and only here, and the per-renderer
// callbacks are plain visitors with no bool return: a renderer physically
// cannot decide to keep walking, so a new renderer added to this package
// inherits the check instead of having to remember it. That is the same
// "one authority, not three copies" shape #6553 gave the gRPC NAT RPCs via
// countNATSessions (pkg/grpcapi/server_helpers.go).
//
// ctx is the caller's ADMISSION-LEASE context where one exists
// (diagcmd.Limiter.AcquireCtx, #5880) — the gRPC ShowText path — and
// context.Background() on the local CLI path, which has no request to
// cancel. It is sampled inside BOTH callbacks, matching countNATSessions:
// without it a walk ran to completion after the client was gone, holding a
// slot the hardened surfaces were queueing for. REST and gRPC alias ONE
// 4-slot diagcmd.SessionWalkLimiter, so an un-cancellable gRPC walk
// degrades the REST twin that does honour cancellation.
//
// A cancelled walk stops and reports NO error: the renderer prints the
// partial tally it has, exactly as countNATSessions returns its partial
// tally rather than an error. The visited-row count, not the tally, is what
// distinguishes "stopped early" from "never started" — the tally is 0 in
// both cases — so the #7315 probes count visits.
//
// The visitors take only the session VALUE because all three renderers
// classify on Flags/IsReverse/zone ids and none reads the key; widen the
// signature when a renderer needs it rather than passing a key nobody uses.
//
// A nil or not-loaded Reader walks nothing and returns nil, reproducing the
// pre-existing "not loaded" branch each renderer guarded for itself.
func walkSessionValues(
	ctx context.Context,
	dp Reader,
	v4 func(dataplane.SessionValue),
	v6 func(dataplane.SessionValueV6),
) error {
	if dp == nil || !dp.IsLoaded() {
		return nil
	}
	cancelled := func() bool { return ctx != nil && ctx.Err() != nil }

	var scanErr error
	if err := dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
		if cancelled() {
			return false // client gone / lease cancelled — stop the walk
		}
		v4(val)
		return true
	}); err != nil {
		scanErr = err
	}
	if err := dp.IterateSessionsV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if cancelled() {
			return false
		}
		v6(val)
		return true
	}); err != nil && scanErr == nil {
		scanErr = err
	}
	return scanErr
}
