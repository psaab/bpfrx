package api

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/authz"
)

// authz_lookup_budget_split_6974_test.go — #6974.
//
// The accept-time budget is NOT reverted here; the cap is accepted and the
// wedge it bounds is real (localAddrsFn holding localAddrCache.mu, which a
// context cannot unblock). What #6974 asks for is removing the budget's COST.
//
// WHICH OF THE TWO COSTS THIS FIXES, stated plainly because "we made it
// per-something" is how this class of change gets away with moving the problem:
//
//   - SPENT PRE-AUTHENTICATION — fixed for the connections it can be fixed for.
//     The slot is still taken at accept and is still held across s.lookupPeer,
//     because that call IS the wedge; moving the acquire after authentication
//     would move it past the thing it protects and bound nothing. What changed
//     is that a connection which provably cannot reach the enumeration no
//     longer spends the pool that defends the connections which can. On the
//     default management posture (127.0.0.1) that is every connection, so an
//     on-box unprivileged process can no longer exhaust the routable listeners'
//     budget by opening TCP connections.
//
//   - PROCESS-GLOBAL — deliberately NOT fixed, and not because it is hard.
//     Partitioning per listener does not isolate anything: localAddrCache.mu is
//     process-global, so under a real wedge every listener's lookups block on
//     the same mutex whatever the budget partitioning is. It would multiply the
//     goroutine bound — the property the cap exists for — while buying no
//     isolation. Partitioning by whether a connection can reach that mutex does
//     buy it, because the two classes contend for different things. That is the
//     split implemented here.
//
// The safety claim the split rests on — that a loopback-delivered connection
// never reaches localAddrsFn — is measured in
// pkg/authz/peer_loopback_noenumerate_6974_test.go, including the negative row
// that stops it being vacuous.

func tcpAddr6974(ip string, port int) *net.TCPAddr {
	return &net.TCPAddr{IP: net.ParseIP(ip), Port: port}
}

// fillPool6974 takes every token of one pool and returns them at cleanup.
func fillPool6974(t *testing.T, pool chan struct{}) {
	t.Helper()
	held := 0
	t.Cleanup(func() {
		for i := 0; i < held; i++ {
			<-pool
		}
	})
	for held < cap(pool) {
		select {
		case pool <- struct{}{}:
			held++
		default:
			t.Fatalf("could not fill the pool: %d of %d taken before it refused", held, cap(pool))
		}
	}
}

// TestBudgetIsSplitByWedgeReachability_6974 pins WHICH pool a connection draws
// on, against the same predicate production uses.
func TestBudgetIsSplitByWedgeReachability_6974(t *testing.T) {
	loopbackServer := tcpAddr6974("127.0.0.1", 8080)
	routableServer := tcpAddr6974("10.1.2.3", 8080)
	offbox := tcpAddr6974("192.0.2.7", 40001)

	if got := peerLookupPoolFor(offbox, loopbackServer); got != peerLookupLoopbackSlots {
		t.Fatal("a connection delivered on a LOOPBACK listener drew on the wedge-facing pool. " +
			"It cannot reach localAddrsFn, so spending that budget is exactly the pre-auth " +
			"cost #6974 is about — and on the default 127.0.0.1 posture it is every connection")
	}
	if got := peerLookupPoolFor(offbox, routableServer); got != peerLookupSlots {
		t.Fatal("a connection with NO loopback end drew on the loopback pool. That connection " +
			"CAN reach the enumeration, so it must spend the budget that bounds it — " +
			"otherwise the split has removed the bound rather than the cost")
	}
	// The two pools must actually be different objects, or everything above is
	// a statement about one channel compared with itself.
	if peerLookupSlots == peerLookupLoopbackSlots {
		t.Fatal("both selections returned the SAME pool; there is no split")
	}
	// And the selector must be the authz predicate, not a local copy of it.
	if peerLookupPoolFor(offbox, loopbackServer) !=
		poolForPredicate6974(authz.LoopbackDeliveryCannotEnumerate(offbox, loopbackServer)) {
		t.Fatal("the pool selection disagrees with authz.LoopbackDeliveryCannotEnumerate. " +
			"The split is only sound while it matches the short-circuit that makes a " +
			"loopback-delivered connection unable to enumerate")
	}
}

func poolForPredicate6974(loopback bool) chan struct{} {
	if loopback {
		return peerLookupLoopbackSlots
	}
	return peerLookupSlots
}

// TestSaturatedWedgePoolStillServesLoopback_6974 is the benefit, and it is the
// half that would be missing if the split had only been asserted structurally.
func TestSaturatedWedgePoolStillServesLoopback_6974(t *testing.T) {
	usePasswdFixture(t)
	waitSlots(t, 0, "the lookup pools never returned to zero occupancy before this case started")

	// A wedge on the routable path, modelled at its budget: every slot taken.
	fillPool6974(t, peerLookupSlots)

	entered := make(chan struct{}, 1)
	s := NewServer(Config{
		Addr:  "127.0.0.1:8080",
		Store: authzStore(t, authzTestConfig),
		PeerLookupFn: func(net.Addr, net.Addr) authz.PeerIdentity {
			entered <- struct{}{}
			return authz.PeerIdentity{UID: authzUIDSuperuser, OK: true, Local: true}
		},
	})
	conn := slotConn{
		client: tcpAddr6974("127.0.0.1", 40001),
		server: tcpAddr6974("127.0.0.1", 8080),
	}
	ctx := s.connContext(context.Background(), conn)
	p, ok := peerIdentityFrom(ctx)
	if !ok {
		t.Fatal("connContext did not attach a pending identity")
	}
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("a LOOPBACK connection was refused admission because the ROUTABLE path's " +
			"budget was exhausted. The two cannot reach the same wedge, so one saturating " +
			"must not deny the other — that cross-denial is the cost #6974 exists to remove")
	}
	<-p.done
	if !p.id.OK {
		t.Fatalf("the loopback lookup resolved to %+v, want a real identity — it was admitted "+
			"but answered as if it had been refused", p.id)
	}
}

// TestSaturatedWedgePoolStillDeniesRoutable_6974 is the property that must NOT
// be traded for the benefit above. Without it, "loopback is still served" is
// satisfied by a change that simply stopped bounding anything.
func TestSaturatedWedgePoolStillDeniesRoutable_6974(t *testing.T) {
	usePasswdFixture(t)
	waitSlots(t, 0, "the lookup pools never returned to zero occupancy before this case started")

	fillPool6974(t, peerLookupSlots)

	wedged := make(chan struct{})
	defer close(wedged)
	s := NewServer(Config{
		Addr:  "10.1.2.3:8080",
		Store: authzStore(t, authzTestConfig),
		PeerLookupFn: func(net.Addr, net.Addr) authz.PeerIdentity {
			// Reached only if the bound failed; blocks so the failure is a
			// timeout on p.done rather than a silently different identity.
			<-wedged
			return authz.PeerIdentity{UID: authzUIDSuperuser, OK: true, Local: true}
		},
	})
	conn := slotConn{
		client: tcpAddr6974("192.0.2.7", 40001),
		server: tcpAddr6974("10.1.2.3", 8080),
	}
	ctx := s.connContext(context.Background(), conn)
	p, ok := peerIdentityFrom(ctx)
	if !ok {
		t.Fatal("connContext did not attach a pending identity")
	}
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		t.Fatal("a connection that CAN reach the enumeration was admitted past a full " +
			"budget — the wedge bound is gone, which is the original defect the cap exists " +
			"for, not the cost #6974 asked to remove")
	}
	if p.id.OK || !p.id.Local {
		t.Fatalf("a refused connection resolved to %+v, want an unattributable LOCAL identity "+
			"(which denies)", p.id)
	}
}
