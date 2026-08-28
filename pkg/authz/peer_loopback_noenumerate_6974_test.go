package authz

import (
	"net"
	"sync/atomic"
	"testing"
)

// peer_loopback_noenumerate_6974_test.go — #6974.
//
// pkg/api's accept-time admission budget exists to bound ONE thing: goroutines
// parked inside localAddrsFn() holding localAddrCache.mu, which a context cannot
// unblock. #6974 splits that budget so a connection which provably cannot reach
// that call does not spend the pool defending it.
//
// LoopbackDeliveryCannotEnumerate is the predicate that split rests on, and this
// file is where its claim is MEASURED rather than argued: for the connections it
// admits, localAddrsFn is never called.
//
// THE NEGATIVE HALF IS WHAT MAKES IT MEAN ANYTHING. "localAddrsFn was not
// called" is also true of a build where nothing ever calls it, so the same
// fixture drives a pair the predicate REJECTS and requires that one to reach it.
// Without that row the file would pass against a predicate that returned true
// for everything.

func addrsFnCounter6974(t *testing.T) *atomic.Int64 {
	t.Helper()
	var calls atomic.Int64
	prev := localAddrsFn
	localAddrsFn = func() ([]net.Addr, error) {
		calls.Add(1)
		return []net.Addr{&net.IPNet{IP: net.IPv4(10, 1, 2, 3), Mask: net.CIDRMask(24, 32)}}, nil
	}
	resetLocalAddrCacheForTest()
	t.Cleanup(func() { localAddrsFn = prev; resetLocalAddrCacheForTest() })
	return &calls
}

// TestLoopbackDeliveryNeverEnumerates_6974 is the safety claim behind the split.
func TestLoopbackDeliveryNeverEnumerates_6974(t *testing.T) {
	lo4 := net.IPv4(127, 0, 0, 1)
	lo6 := net.ParseIP("::1")
	routable := net.IPv4(10, 1, 2, 3)
	offbox := net.IPv4(192, 0, 2, 7)

	for _, tc := range []struct {
		name           string
		client, server net.Addr
		wantPredicate  bool
		wantEnumerated bool
	}{
		{
			name:   "loopback_server_the_default_management_posture",
			client: &net.TCPAddr{IP: offbox, Port: 40001},
			server: &net.TCPAddr{IP: lo4, Port: 8080},
			// The listener is on 127.0.0.1, which is what the daemon binds by
			// default: every connection it can accept is loopback-delivered.
			wantPredicate: true, wantEnumerated: false,
		},
		{
			name:          "loopback_client",
			client:        &net.TCPAddr{IP: lo4, Port: 40002},
			server:        &net.TCPAddr{IP: routable, Port: 8080},
			wantPredicate: true, wantEnumerated: false,
		},
		{
			name:          "loopback_v6",
			client:        &net.TCPAddr{IP: lo6, Port: 40003},
			server:        &net.TCPAddr{IP: routable, Port: 8080},
			wantPredicate: true, wantEnumerated: false,
		},
		{
			// THE ROW THAT STOPS THIS BEING VACUOUS: a pair with no loopback
			// end must be rejected by the predicate AND must reach the
			// enumeration, so "never called" above is a fact about the
			// short-circuit rather than about the fixture.
			name:          "no_loopback_end_reaches_the_enumeration",
			client:        &net.TCPAddr{IP: offbox, Port: 40004},
			server:        &net.TCPAddr{IP: routable, Port: 8080},
			wantPredicate: false, wantEnumerated: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := LoopbackDeliveryCannotEnumerate(tc.client, tc.server); got != tc.wantPredicate {
				t.Fatalf("LoopbackDeliveryCannotEnumerate = %v, want %v", got, tc.wantPredicate)
			}
			calls := addrsFnCounter6974(t)
			// PeerCouldBeLocalNow and couldBeLocal share loopbackDelivery, which
			// is the short-circuit the predicate is single-sourced with. Driving
			// the exported one keeps this test off unexported control flow while
			// still crossing the branch that matters.
			_ = PeerCouldBeLocalNow(tc.client, tc.server)
			_ = isLocalAddrPathForTest6974(tc.client, tc.server)
			if got := calls.Load() > 0; got != tc.wantEnumerated {
				t.Fatalf("localAddrsFn called=%v (%d times), want called=%v.\n"+
					"pkg/api splits its admission budget on LoopbackDeliveryCannotEnumerate: a "+
					"connection it admits is assumed unable to reach localAddrsFn and therefore "+
					"unable to participate in the wedge the budget bounds. If that is no longer "+
					"true, the split stops defending the routable listeners and #6974 must be "+
					"re-derived before this test is adjusted",
					got, calls.Load(), tc.wantEnumerated)
			}
		})
	}
}

// isLocalAddrPathForTest6974 drives the CACHED classifier the same way
// couldBeLocal does, so the assertion covers that path too rather than only the
// authoritative re-derivation.
func isLocalAddrPathForTest6974(client, server net.Addr) bool {
	ct, cok := client.(*net.TCPAddr)
	st, sok := server.(*net.TCPAddr)
	if !cok || !sok {
		return false
	}
	return couldBeLocal(ct, st)
}
