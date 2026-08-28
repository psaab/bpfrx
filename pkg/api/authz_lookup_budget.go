package api

import (
	"net"

	"github.com/psaab/xpf/pkg/authz"
)

// authz_lookup_budget.go holds the accept-time peer-lookup admission budget: the
// pools, the selector that chooses between them, and the accessors that read
// them.
//
// SPLIT OUT OF authz.go BY #6974 rather than grown in place. The budget is one
// cohesive concern — a bound, the predicate deciding which bound applies, and
// the observability for both — and authz.go sat one line under the 1500 LOC
// modularity floor, so adding the second pool there would have crossed it for a
// reason unrelated to authz.go's own subject.

// maxConcurrentPeerLookups bounds accept-time peer lookups in flight at once.
//
// Deliberately far above any legitimate concurrency on a surface that answers a
// handful of operator actions per second; it is a ceiling on unbounded growth,
// not a throttle. Set for the same reason and with the same fail-closed
// direction as the two queue caps in pkg/authz (maxPendingLookups,
// maxHostAddrWaiters), though a quarter their size: those bound 4096 each,
// this one 1024. "Sized like" overstated it.
//
// THE TRADEOFF THIS MAKES, stated so it can be disagreed with (#6645 r20).
// The paragraph above gives the justification; these are the costs, and a
// maintainer weighing them should not have to rediscover them:
//
//   - The slot is taken at ACCEPT, before authentication and before a single
//     HTTP byte is read. An UNAUTHENTICATED client therefore consumes the
//     budget, and consumes it by opening TCP connections alone.
//   - Past the cap a lookup is not queued, delayed or retried — it is resolved
//     immediately to an unattributable local identity, which DENIES. Requests
//     that would have completed are converted into denials. That is a
//     behaviour change under load, not only a latency cost.
//   - The pool is process-global (see peerLookupSlots below), so HTTP, HTTPS,
//     retiring and rebound listeners and every api.Server share one budget:
//     saturation on any of them denies on all of them.
//
// It is accepted anyway because the alternative is worse, not because the cost
// is small. The wedge this bounds is inside localAddrsFn() holding
// localAddrCache.mu; a context cannot unblock a goroutine parked on a mutex, so
// cancellation is unavailable and admission control is the only lever. Without
// the cap, continued connections against a wedged enumeration accumulate
// goroutines and their captured addresses WITHOUT LIMIT on a management plane,
// driven by the same unauthenticated caller. Bounded denial is preferred to
// unbounded growth.
//
// #6974 ADDRESSED THE FIRST TWO OF THOSE COSTS IN ONE MOVE, and declined the
// refinement the issue proposed for the second. The budget is now SPLIT BY
// WHETHER A CONNECTION CAN REACH THE ENUMERATION (peerLookupLoopbackSlots
// below): authz.couldBeLocal short-circuits on loopback delivery and returns
// before isLocalAddr, so a loopback-delivered connection never takes
// localAddrCache.mu and cannot participate in the wedge. It therefore no longer
// spends the pool that defends the connections which can — and on the default
// 127.0.0.1 posture that is every connection, so an on-box unprivileged process
// can no longer exhaust the routable listeners' budget by opening TCP alone.
//
// The acquire STAYS AT ACCEPT and the slot is still held across s.lookupPeer,
// which is the call that wedges: moving it after authentication would move it
// past the thing it protects. A PER-LISTENER split — #6974's other proposal —
// was declined and the reason is recorded rather than defaulted:
// localAddrCache.mu is process-global, so under a real wedge every listener
// blocks on the same mutex whatever the partitioning is; per-listener pools
// would multiply the goroutine bound while buying no isolation. The third cost
// (denies rather than queues) is not removable — queuing IS the unbounded
// accumulation the cap exists to prevent.
//
// Any further change must keep the property this cap exists for: no unbounded
// goroutine accumulation while localAddrsFn is wedged. Raising or removing the
// cap alone reinstates the original defect.
const maxConcurrentPeerLookups = 1024

// peerLookupSlots is the admission token pool for the lookups that CAN reach the
// enumeration. Package-level: the resource being bounded is the daemon's
// goroutines and memory, which every listener shares.
var peerLookupSlots = make(chan struct{}, maxConcurrentPeerLookups)

// peerLookupLoopbackSlots is the SECOND pool, for connections that provably
// cannot reach the wedge (#6974 cost 1).
//
// authz.couldBeLocal short-circuits on loopback delivery and returns BEFORE
// isLocalAddr, so a loopback-delivered connection never takes localAddrCache.mu
// and never calls localAddrsFn. Such a connection cannot participate in the
// wedge this budget exists to bound, and until now it spent that budget anyway
// — which is how an on-box unprivileged process, unauthenticated and without
// sending one HTTP byte, could exhaust the slots that defend the ROUTABLE
// listeners.
//
// THE SPLIT IS BY REACHABILITY OF THE BOUNDED RESOURCE, not by listener. A
// per-listener split was the other refinement #6974 proposes and it does not
// hold up: localAddrCache.mu is process-global, so under a real wedge every
// listener's lookups block on the same mutex whatever the budget partitioning
// is — partitioning would multiply the goroutine bound without buying the
// isolation it claims. Partitioning by "can this connection reach the mutex"
// does buy it, because the two classes contend for different things.
//
// BOTH POOLS ARE STILL BOUNDED. This one exists to keep a goroutine ceiling on
// the loopback path, not because that path is trusted: the property the cap is
// for — no unbounded goroutine accumulation — is preserved on both sides, and
// the wedge-facing pool's size is unchanged, so the bound on the wedge itself is
// exactly what it was.
var peerLookupLoopbackSlots = make(chan struct{}, maxConcurrentPeerLookups)

// peerLookupPoolFor picks the pool a connection's lookup must be admitted
// through. The predicate is authz's own, so it cannot drift from the
// short-circuit that makes the split sound (see
// authz.LoopbackDeliveryCannotEnumerate).
func peerLookupPoolFor(client, server net.Addr) chan struct{} {
	if authz.LoopbackDeliveryCannotEnumerate(client, server) {
		return peerLookupLoopbackSlots
	}
	return peerLookupSlots
}

// PeerLookupSlotsInUseForTest reports how many lookup slots are held, ACROSS
// BOTH POOLS. Test-only.
//
// The sum, not the wedge-facing pool alone (#6974). Several cases use "zero
// slots in use" as a quiescence edge meaning "no lookup is in flight anywhere"
// — waitSlots, waitForPeerLookupsToFinish — and a reading that covered only one
// pool would report quiescence while loopback lookups were still running. That
// is the same class of defect as the #6977 waiter edge: an observation about
// part of the state, read as if it were about all of it.
func PeerLookupSlotsInUseForTest() int {
	return len(peerLookupSlots) + len(peerLookupLoopbackSlots)
}

// PeerLookupPoolForTest exposes the pool a connection between these addresses
// draws on, so a case that needs to SATURATE the budget can fill the one its own
// fixture will use rather than guessing. Test-only.
func PeerLookupPoolForTest(client, server net.Addr) chan struct{} {
	return peerLookupPoolFor(client, server)
}
