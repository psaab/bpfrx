package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #7323: the config-epoch guard is NOT inert on every authority — only on one
// that has never applied a peer config.
//
// WHY THIS CELL EXISTS. `docs/session-sync-architecture.md` and
// `sync_config_epoch_active_active_6284_test.go` both describe the reverse
// (non-authority -> authority) direction as inert fail-OPEN, on the reasoning
// that "the config authority's receive high-water never advances (it applies no
// peer config)". That is true of a node that has ALWAYS been the RG0 authority.
// It is NOT true of a PROMOTED one: `lastAppliedConfigGen` is written only by
// `recordAppliedConfigGen`, and cleared only by `initGenState` (construction)
// and `resetRecvGen` (the peer's bulk re-prime). **Nothing clears it on a role
// transition.** A node that was the secondary, applied the authority's config,
// and then took RG0 carries that high-water into its authority life, and its
// guard is LIVE.
//
// WHAT THAT DECIDES. #7323 proposes reserving the top bit of `ConfigEpoch` as a
// stamp-source tag, and licenses skipping a `ProtocolVersion` bump with:
//
//	"A legacy receiver reads a tagged value as a very large generation, which
//	 its unsigned `epoch < barrier` comparison admits — fail-OPEN, i.e. exactly
//	 today's behaviour."
//
// The last clause is what this cell refutes. Against a live barrier, today's
// behaviour is REFUSE and the tagged value's behaviour is ADMIT. The tag does
// not preserve the status quo there; it converts a working fail-CLOSED guard
// into fail-OPEN, on a receiver that cannot report it happened. And a rolling
// upgrade necessarily involves a failover, so "promoted authority" is the
// normal path through it, not an exotic state.
//
// This cell asserts CURRENT behaviour only. It does not implement the tag; it
// pins the fact any tagged-encoding design has to answer, so the premise cannot
// rot the way the "never advances" wording did.
func TestPromotedAuthorityHasALiveConfigEpochGuard7323(t *testing.T) {
	// The top-bit stamp-source tag #7323 proposes. Declared here rather than
	// imported because nothing in production defines it — that is the point.
	const proposedTag = uint64(1) << 63

	newSync := func() *SessionSync {
		dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
		return NewSessionSync(":0", "10.0.0.2:4785", dp)
	}

	// CONTROL — an authority that has never applied a peer config. This is the
	// state the existing #6284 cell constructs and the doc describes, and the
	// guard really is inert here. Without this row the assertions below would
	// not show that the PROMOTION is what makes the difference.
	always := newSync()
	if got := always.lastAppliedConfigGen.Load(); got != 0 {
		t.Fatalf("premise: a fresh SessionSync must start with high-water 0, got %d", got)
	}
	if always.configEpochStale(3) {
		t.Fatal("never-applied authority: barrier 0 must admit a low epoch — " +
			"this is the documented inert fail-OPEN reverse direction")
	}

	// THE PROMOTED AUTHORITY. It was the secondary and applied the old
	// authority's config generation 10; then it took RG0. Nothing in the
	// role transition clears the mark.
	promoted := newSync()
	promoted.recordAppliedConfigGen(10)
	if got := promoted.lastAppliedConfigGen.Load(); got != 10 {
		t.Fatalf("premise: recordAppliedConfigGen(10) must advance the high-water, got %d", got)
	}

	// (1) The guard is LIVE here — today's code REFUSES a stale untagged stamp.
	if !promoted.configEpochStale(3) {
		t.Fatal("a promoted authority's guard must be LIVE: epoch 3 against a " +
			"high-water of 10 is a stale permit and today's code refuses it. If this " +
			"ever passes, the reverse direction really is inert everywhere and #7323's " +
			"rolling-upgrade argument is safe — re-derive it before relying on that")
	}

	// (2) And a TAGGED stamp is admitted by the very same receiver. This is the
	// pair that matters: same receiver, same barrier, opposite verdict, decided
	// only by the top bit.
	if promoted.configEpochStale(proposedTag | 3) {
		t.Fatal("premise check: the tagged value must be admitted by today's " +
			"receiver — if it were refused, #7323's compatibility question would be " +
			"a different one and this cell would be testing nothing")
	}

	// (3) The only in-band clear is the peer's bulk re-prime. Pinning it here
	// bounds the exposure honestly: the window is promotion -> next re-prime,
	// not forever. It also means a future change that cleared the mark on role
	// transition would red row (1) and be told exactly why.
	promoted.resetRecvGen()
	if got := promoted.lastAppliedConfigGen.Load(); got != 0 {
		t.Fatalf("resetRecvGen must clear the high-water, got %d", got)
	}
	if promoted.configEpochStale(3) {
		t.Fatal("after the peer's bulk re-prime the barrier is 0 again and the " +
			"guard returns to inert")
	}
}
