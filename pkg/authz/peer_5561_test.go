package authz

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// peer_5561_test.go exercises the peer lookup against REAL kernel sockets. The
// lookup is the whole basis of the REST authorization gate: if it reports the
// wrong UID, or reports "remote" for a caller that is local, the gate authorizes
// the wrong principal. Fixture-only coverage would prove the parser and nothing
// about the kernel, so the happy paths open actual loopback connections and the
// fail-closed paths provoke actual socket states.

// acceptedPair opens a real loopback TCP connection and returns the SERVER side
// (the analogue of an accepted management-API connection) plus the client, both
// closed by the test's cleanup. laddr, when non-nil, fixes the client's local
// address so a test can control the source address/port.
func acceptedPair(t *testing.T, network, addr string, laddr *net.TCPAddr) (server, client net.Conn) {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Skipf("cannot listen on %s %s: %v", network, addr, err)
	}
	defer ln.Close()

	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()

	d := &net.Dialer{Timeout: 5 * time.Second}
	if laddr != nil {
		d.LocalAddr = laddr
	}
	client, err = d.Dial(network, ln.Addr().String())
	if err != nil {
		t.Skipf("dial %s from %v: %v", ln.Addr(), laddr, err)
	}
	r := <-ch
	if r.err != nil {
		client.Close()
		t.Fatalf("accept: %v", r.err)
	}
	t.Cleanup(func() { r.c.Close(); client.Close() })
	return r.c, client
}

// TestLookupPeerMatchesCallerOnRealConnection_5561 is the core proof: for a
// connection this process both made and accepted, the kernel-derived peer UID is
// this process's own UID.
func TestLookupPeerMatchesCallerOnRealConnection_5561(t *testing.T) {
	for _, tc := range []struct{ name, network, addr string }{
		{"ipv4", "tcp4", "127.0.0.1:0"},
		{"ipv6", "tcp6", "[::1]:0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := acceptedPair(t, tc.network, tc.addr, nil)
			want := uint32(os.Getuid())

			// The addresses the authorization gate passes: the connection's
			// remote end is the caller, its local end is the server.
			id := LookupPeer(server.RemoteAddr(), server.LocalAddr())
			if !id.OK {
				t.Fatalf("LookupPeer(%v, %v) established no identity: %+v",
					server.RemoteAddr(), server.LocalAddr(), id)
			}
			if !id.Local {
				t.Error("an attributed peer was not reported as local")
			}
			if id.UID != want {
				t.Fatalf("LookupPeer reported uid %d for a connection made by uid %d — "+
					"the authorization gate would evaluate the wrong principal", id.UID, want)
			}
		})
	}
}

// TestLookupPeerRejectsAddressMismatch_5561 is the MAJOR-1 regression guard.
//
// The original implementation asked INET_DIAG through netlink.SocketGet, which
// issues a DUMP whose kernel-side filter matches on (family, source port,
// destination port) and IGNORES the addresses in the request; the library then
// returns the first reply without checking it against the request. So a query
// for an address with NO socket at all was answered with a DIFFERENT socket's
// UID, and since every address in 127/8 is bindable by any local user, an
// unprivileged caller that reused the source port of a root-owned connection was
// reported as root.
//
// The shape is reproduced exactly: one real socket from 127.0.0.2, then a query
// for the same port pair on addresses that have no socket. A correct lookup
// yields no identity for those.
func TestLookupPeerRejectsAddressMismatch_5561(t *testing.T) {
	server, _ := acceptedPair(t, "tcp4", "127.0.0.1:0",
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 2)})
	real := server.RemoteAddr().(*net.TCPAddr)
	srv := server.LocalAddr().(*net.TCPAddr)

	// Precondition: the REAL 4-tuple is attributed, so a failure below is the
	// address check and not a broken lookup.
	if id := LookupPeer(real, srv); !id.OK {
		t.Fatalf("precondition: the real socket %v -> %v was not attributed: %+v", real, srv, id)
	}

	for _, ip := range []string{"127.0.0.9", "127.0.0.44", "127.0.0.1", "127.0.0.3"} {
		spoof := &net.TCPAddr{IP: net.ParseIP(ip), Port: real.Port}
		if spoof.IP.Equal(real.IP) {
			continue
		}
		id := LookupPeer(spoof, srv)
		if id.OK {
			t.Errorf("LookupPeer(%v -> %v) returned uid %d, but NO socket exists on that "+
				"address — the lookup is matching on ports alone, so any local user who "+
				"reuses a privileged connection's source port is authorized as its owner",
				spoof, srv, id.UID)
		}
		if !id.Local {
			t.Errorf("LookupPeer(%v) reported a loopback address as non-local, which would "+
				"hand it the api-auth credential path", spoof)
		}
	}
}

// TestLookupPeerDeniesAfterPeerClose_5561 pins the fail-closed half. Once the
// caller's socket leaves ESTABLISHED, no UID may be produced — in particular not
// the UID 0 the kernel reports for a TIME_WAIT mini-socket — and the caller must
// still be reported as LOCAL so the REST layer denies instead of falling through
// to a credential.
func TestLookupPeerDeniesAfterPeerClose_5561(t *testing.T) {
	server, client := acceptedPair(t, "tcp4", "127.0.0.1:0", nil)
	clientAddr := server.RemoteAddr()
	localAddr := server.LocalAddr()

	if id := LookupPeer(clientAddr, localAddr); !id.OK {
		t.Fatalf("precondition: established connection yielded no identity: %+v", id)
	}

	client.Close()
	server.Close()

	// The socket may take a moment to leave ESTABLISHED. Poll briefly; the
	// assertion is that it ends in a denial, not how fast it gets there.
	deadline := time.Now().Add(5 * time.Second)
	for {
		id := LookupPeer(clientAddr, localAddr)
		if !id.OK {
			if !id.Local {
				t.Fatalf("a closed LOOPBACK peer was reported as off-box (%+v) — the REST "+
					"layer would let an api-auth credential speak for it", id)
			}
			return
		}
		if id.UID == 0 && os.Getuid() != 0 {
			t.Fatalf("closed connection reported uid 0 — a caller could escalate to root " +
				"by closing its socket after sending the request")
		}
		if time.Now().After(deadline) {
			t.Fatalf("closed connection still yields uid %d after 5s", id.UID)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestLookupPeerHalfClosedIsLocalNotRemote_5561 is the MAJOR-2 regression guard
// at the pkg/authz layer. `shutdown(SHUT_WR)` takes the socket out of
// ESTABLISHED while the caller keeps reading — the exact move that used to make
// the lookup fail and hand the caller the credential path. The identity must be
// unusable AND local.
func TestLookupPeerHalfClosedIsLocalNotRemote_5561(t *testing.T) {
	server, client := acceptedPair(t, "tcp4", "127.0.0.1:0", nil)
	clientAddr := server.RemoteAddr()
	localAddr := server.LocalAddr()

	if err := client.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		id := LookupPeer(clientAddr, localAddr)
		if !id.OK {
			if !id.Local {
				t.Fatalf("a half-closed LOOPBACK caller was reported as off-box (%+v) — an "+
					"api-auth credential would then speak for it, which is the escalation", id)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("half-closed socket never left ESTABLISHED")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestLookupPeerNonLocalPeerAllowsCredential_5561 is the negative control for
// the two guards above: a peer that is genuinely NOT on this host must be
// reported as non-local, or the credential path — the only way a remote
// administrator can be identified at all (#4047) — would be unreachable.
func TestLookupPeerNonLocalPeerAllowsCredential_5561(t *testing.T) {
	restore := setLocalAddrsForTest([]net.Addr{
		&net.IPNet{IP: net.IPv4(10, 0, 61, 1), Mask: net.CIDRMask(24, 32)},
	})
	defer restore()

	remote := &net.TCPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 51234}
	server := &net.TCPAddr{IP: net.IPv4(10, 0, 61, 1), Port: 8080}
	id := LookupPeer(remote, server)
	if id.OK {
		t.Fatalf("a remote peer was attributed a local uid: %+v", id)
	}
	if id.Local {
		t.Fatalf("a peer on no interface of ours was reported LOCAL (%+v) — every remote "+
			"administrator would be denied even with a valid credential", id)
	}

	// An address that IS ours, with no socket, must be local (deny) — the
	// off-loopback half of the MAJOR-2 fix.
	ours := &net.TCPAddr{IP: net.IPv4(10, 0, 61, 1), Port: 51234}
	other := &net.TCPAddr{IP: net.IPv4(10, 0, 61, 9), Port: 8080}
	if id := LookupPeer(ours, other); !id.Local {
		t.Fatalf("a caller from one of OUR OWN addresses was reported off-box (%+v) — a "+
			"local account could reach the credential path over the management IP", id)
	}
}

// TestLookupPeerFailsClosedOnUnreadableTable_5561: if the socket table cannot be
// read we know nothing, and "nothing" must mean local-and-unattributable (deny),
// never off-box (credential).
func TestLookupPeerFailsClosedOnUnreadableTable_5561(t *testing.T) {
	dir := t.TempDir()
	defer SetProcNetTCPPathsForTest(filepath.Join(dir, "nope"), filepath.Join(dir, "nope6"))()
	restore := setLocalAddrsForTest(nil) // no local addresses at all
	defer restore()

	// A LOOPBACK-delivered connection: locality is already established from the
	// addresses, so the unreadable table decides only attribution.
	id := LookupPeer(
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 51234},
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080})
	if id.OK {
		t.Fatalf("an unreadable socket table produced an identity: %+v", id)
	}
	if !id.Local {
		t.Fatalf("an unreadable socket table reported the caller off-box (%+v) — a local "+
			"caller could then be spoken for by a credential", id)
	}
}

// TestLoopbackDeliveryIsLocalWithoutASocketRow_5561 is the MAJOR-B guard.
//
// Absence from THIS namespace's socket table is not evidence of being off-box: a
// caller in another network namespace appears in neither /proc/net/tcp nor
// net.InterfaceAddrs() here. Treating that as "remote" hands it the api-auth
// credential, which is the same unsound "not found means remote" inference that
// produced the half-close bypass.
//
// A connection DELIVERED on a loopback address is local by kernel guarantee —
// the kernel drops packets carrying loopback addresses that arrive on a real
// interface — so it must be reported local even when nothing about the CALLER is
// recognizable. That covers the entire default management posture.
func TestLoopbackDeliveryIsLocalWithoutASocketRow_5561(t *testing.T) {
	dir := t.TempDir()
	// An empty socket table: no row for anyone.
	empty := filepath.Join(dir, "tcp")
	write(t, empty, "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
	defer SetProcNetTCPPathsForTest(empty, empty)()
	// And no interface addresses at all, so the ADDRESS fallback cannot rescue it
	// either — only the loopback-delivery rule can.
	defer setLocalAddrsForTest(nil)()

	id := LookupPeer(
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 51234},
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080})
	if id.OK {
		t.Fatalf("an empty socket table produced an identity: %+v", id)
	}
	if !id.Local {
		t.Fatalf("a connection DELIVERED on a loopback address was reported off-box (%+v) — "+
			"a caller in another netns, or one that reset its socket, would be handed the "+
			"api-auth credential path on the default management bind", id)
	}
}

// TestLookupPeerRefusesScopedPeerAddress_5561 is the MAJOR-C guard.
//
// /proc/net/tcp6 prints only the 128 address bits, never the scope id, so two
// link-local callers on different interfaces render the IDENTICAL key. Matching
// on that key and taking the first established row makes identity
// order-dependent — the same defect class as matching on ports alone. A scoped
// peer address must be refused, not guessed at.
func TestLookupPeerRefusesScopedPeerAddress_5561(t *testing.T) {
	client := &net.TCPAddr{IP: net.ParseIP("fe80::ee01:0:0:1"), Port: 43210, Zone: "eth0"}
	server := &net.TCPAddr{IP: net.ParseIP("fe80::e01:0:0:1"), Port: 8080, Zone: "eth0"}

	// Build the row from the encoder (whose output is pinned independently by
	// TestProcAddrEncoding_5561) so a hand-written hex typo cannot make this
	// test pass for the wrong reason. The row's UID is 0: /proc carries no scope
	// id, so a caller on a DIFFERENT interface with the same link-local bits
	// would be attributed this row — root.
	cl, ok := procAddr6(client)
	if !ok {
		t.Fatal("cannot render client address")
	}
	sv, ok := procAddr6(server)
	if !ok {
		t.Fatal("cannot render server address")
	}
	dir := t.TempDir()
	v6 := filepath.Join(dir, "tcp6")
	write(t, v6, "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
		"   0: "+cl+" "+sv+" 01 00000000:00000000 00:00000000 00000000     0        0 4242 1 0000000000000000 100 0 0 10 0\n")
	defer SetProcNetTCPPathsForTest(filepath.Join(dir, "tcp"), v6)()

	// Establish locality by address so the zone guard is the ONLY thing between
	// this caller and the ambiguous row. Without this the lookup short-circuits
	// as "not on this host" and the test would pass for an unrelated reason.
	defer setLocalAddrsForTest([]net.Addr{
		&net.IPNet{IP: net.ParseIP("fe80::ee01:0:0:1"), Mask: net.CIDRMask(64, 128)},
	})()

	// Precondition: the identical row IS matched for an UNSCOPED caller, so a
	// refusal below is the zone and not a broken matcher.
	unscoped := &net.TCPAddr{IP: client.IP, Port: client.Port}
	if id := LookupPeer(unscoped, &net.TCPAddr{IP: server.IP, Port: server.Port}); !id.OK {
		t.Fatalf("precondition: the row was not matched for an unscoped caller: %+v", id)
	}

	id := LookupPeer(client, server)
	if id.OK {
		t.Fatalf("a scope-qualified peer was attributed uid %d from a row that carries no "+
			"scope id — two link-local callers on different interfaces render the same key, "+
			"so this identity is whichever row came first", id.UID)
	}
	if !id.Local {
		t.Error("refusing to attribute a scoped peer must DENY, not fall through to a credential")
	}
	if !strings.Contains(id.Detail, "scope-qualified") {
		t.Errorf("detail does not explain the refusal: %q", id.Detail)
	}
}

// TestUnreadableTableDeniesEveryone_5561 replaces a guard that encoded a
// FAIL-OPEN as required behaviour, twice over.
//
// It first asserted "a peer that cannot be local costs ZERO socket-table work" —
// an early-out that made a cached NEGATIVE decisive, removed in round 5. It was
// then rewritten to assert that an unreadable table still reports a routable
// peer OFF-BOX, on the reasoning that a broken /proc must not lock out remote
// administrators. That reasoning is an availability argument standing where a
// security one belongs: "off-box" is the single row an api-auth credential may
// speak for, and a failed read is not evidence for it. The caller's row may be
// in precisely the file that failed — tcp and tcp6 are alternatives, not
// duplicates.
//
// So the direction is inverted deliberately: a table read that FAILS denies
// everyone, credentialed or not. An ABSENT table is a separate case and is NOT
// a failure (see TestPartialTableReadFailsClosed_5561), so an IPv6-less kernel
// is unaffected.
func TestUnreadableTableDeniesEveryone_5561(t *testing.T) {
	dir := t.TempDir()
	defer SetProcNetTCPPathsForTest(filepath.Join(dir, "absent"), filepath.Join(dir, "absent6"))()
	defer setLocalAddrsForTest([]net.Addr{
		&net.IPNet{IP: net.IPv4(10, 0, 61, 1), Mask: net.CIDRMask(24, 32)},
	})()

	id := LookupPeer(
		&net.TCPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 51234},
		&net.TCPAddr{IP: net.IPv4(10, 0, 61, 1), Port: 8080})
	if !id.Local {
		t.Fatalf("an unreadable socket table reported a routable peer OFF-BOX (%+v) — that "+
			"is the one row an api-auth credential may speak for, and we never made the "+
			"observation that would support it", id)
	}
	if id.OK {
		t.Fatalf("an unreadable socket table produced an identity: %+v", id)
	}

	// And a caller from one of OUR addresses, same unknown answer, same denial.
	ours := LookupPeer(
		&net.TCPAddr{IP: net.IPv4(10, 0, 61, 1), Port: 51234},
		&net.TCPAddr{IP: net.IPv4(10, 0, 61, 9), Port: 8080})
	if !ours.Local || ours.OK {
		t.Fatalf("an unreadable socket table reported a caller from our OWN address as "+
			"%+v — it must deny, not fall through to the credential", ours)
	}
}

// TestLookupPeerRejectsIdenticalEndpoints_5561 covers the self-connect guard: a
// query whose two endpoints are equal would match this daemon's own socket and
// report the daemon's UID as the caller's.
func TestLookupPeerRejectsIdenticalEndpoints_5561(t *testing.T) {
	a := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	b := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	id := LookupPeer(a, b)
	if id.OK {
		t.Fatalf("identical endpoints produced identity %+v", id)
	}
	if !id.Local {
		t.Error("identical endpoints must deny, not fall through to a credential")
	}
}

// TestLookupPeerRejectsNonTCP_5561 covers the type guards. A non-TCP peer is on
// this host by construction, so it must deny rather than reach the credential.
func TestLookupPeerRejectsNonTCP_5561(t *testing.T) {
	tcp := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	unix := &net.UnixAddr{Name: "/run/xpf.sock", Net: "unix"}
	for _, tc := range []struct{ client, server net.Addr }{
		{unix, tcp},
		{tcp, unix},
		{&net.TCPAddr{Port: 1}, tcp},
	} {
		id := LookupPeer(tc.client, tc.server)
		if id.OK || !id.Local {
			t.Errorf("LookupPeer(%v, %v) = %+v, want an unusable LOCAL identity",
				tc.client, tc.server, id)
		}
	}
}

// TestLocalAddrCacheRateLimitsMisses_5561 is the MINOR-1 guard.
//
// The interface-address snapshot exists so connection churn from a routable
// address cannot force one enumeration per connection. An earlier version
// refreshed on every MISS — which is precisely the flooding case, since a
// routable attacker's address never matches — so the amplification the cache
// was supposed to prevent was fully intact while two comments claimed otherwise.
// Refreshes are now rate-limited for hits and misses alike.
func TestLocalAddrCacheRateLimitsMisses_5561(t *testing.T) {
	var enumerations int
	prev := localAddrsFn
	localAddrsFn = func() ([]net.Addr, error) {
		enumerations++
		return []net.Addr{&net.IPNet{IP: net.IPv4(10, 0, 61, 1), Mask: net.CIDRMask(24, 32)}}, nil
	}
	resetLocalAddrCacheForTest()
	defer func() { localAddrsFn = prev; resetLocalAddrCacheForTest() }()

	// 200 lookups for an address that will NEVER be in the snapshot.
	miss := net.IPv4(198, 51, 100, 7)
	for i := 0; i < 200; i++ {
		if isLocalAddr(miss) {
			t.Fatal("a foreign address was reported local")
		}
	}
	if enumerations > 2 {
		t.Fatalf("200 cache MISSES drove %d interface enumerations — the cache is "+
			"positive-only, so a connect flood from a routable address (which never "+
			"matches) amplifies straight through it", enumerations)
	}

	// The positive path must still answer correctly from the same snapshot.
	if !isLocalAddr(net.IPv4(10, 0, 61, 1)) {
		t.Error("a genuinely local address was reported foreign")
	}
	if enumerations == 0 {
		t.Error("no enumeration happened at all — the cache is not being populated")
	}
}

// TestScopedRemotePeerStillReachesTheCredential_5561 is the MINOR-2 guard: the
// scoped-address refusal must apply only to a peer we would otherwise have to
// ATTRIBUTE. Checking it before the locality test denied every scope-qualified
// caller, which on an IPv6 link-local management bind is every credentialed
// remote administrator.
func TestScopedRemotePeerStillReachesTheCredential_5561(t *testing.T) {
	const header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	dir := t.TempDir()
	// PRESENT and EMPTY, not absent. The tables used to be absent here, which
	// made this case require an off-box verdict drawn from having read NOTHING —
	// the same zero-observation fail-open the error path was corrected for. A
	// scoped peer may only reach the credential once the table has actually been
	// consulted and genuinely holds no row for it.
	v4, v6 := filepath.Join(dir, "tcp"), filepath.Join(dir, "tcp6")
	write(t, v4, header)
	write(t, v6, header)
	defer SetProcNetTCPPathsForTest(v4, v6)()
	// Our own link-local address is a DIFFERENT one, so the caller is off-box.
	defer setLocalAddrsForTest([]net.Addr{
		&net.IPNet{IP: net.ParseIP("fe80::e01:0:0:1"), Mask: net.CIDRMask(64, 128)},
	})()

	client := &net.TCPAddr{IP: net.ParseIP("fe80::ee01:0:0:99"), Port: 43210, Zone: "eth0"}
	server := &net.TCPAddr{IP: net.ParseIP("fe80::e01:0:0:1"), Port: 8080, Zone: "eth0"}
	id := LookupPeer(client, server)
	if id.Local {
		t.Fatalf("a scope-qualified peer that is NOT on this host was reported LOCAL "+
			"(%+v) — on an IPv6 link-local management bind that denies every "+
			"credentialed remote administrator", id)
	}
	if id.OK {
		t.Fatalf("an off-box scoped peer was attributed: %+v", id)
	}
	// OK=false and Local=false are BOTH the zero values of PeerIdentity, so the
	// two assertions above are equally satisfied by a function that decided
	// nothing. The Detail is not defaulted — the credential row is reached
	// through an explicit `return PeerIdentity{Detail: "peer %v is not on this
	// host"}`, so requiring it proves a verdict was computed.
	if !strings.Contains(id.Detail, "is not on this host") {
		t.Fatalf("the off-box verdict carries Detail %q. OK and Local are both false by "+
			"DEFAULT, so without this the case is satisfied by any implementation that "+
			"returns a zero PeerIdentity — including one that never classified the "+
			"caller at all", id.Detail)
	}
	// Discrimination control: the SAME scoped shape, against a table that is
	// equally present and empty, must NOT reach the credential row when the
	// caller's address is one of ours. Without this, "reaches the credential"
	// could be this function's answer for every scoped peer, which is the
	// opposite fail-open of the one the case is named for.
	defer setLocalAddrsForTest([]net.Addr{
		&net.IPNet{IP: net.ParseIP("fe80::ee01:0:0:99"), Mask: net.CIDRMask(64, 128)},
		&net.IPNet{IP: net.ParseIP("fe80::e01:0:0:1"), Mask: net.CIDRMask(64, 128)},
	})()
	if ours := LookupPeer(client, server); !ours.Local || ours.OK {
		t.Fatalf("a scope-qualified peer whose address IS assigned to this host was reported "+
			"%+v, want LOCAL and unattributable. A scoped caller on our own address must be "+
			"denied, not handed the credential row — if this reaches the credential too, the "+
			"assertions above are not distinguishing anything", ours)
	}
}

// TestProcParserRejectsNonEstablishedRow_5561 is the fixture half of the
// TIME_WAIT defense. The kernel reports UID 0 for a timewait row; a parser that
// matched on the 4-tuple alone would hand the authorization gate root.
func TestProcParserRejectsNonEstablishedRow_5561(t *testing.T) {
	dir := t.TempDir()
	v4 := filepath.Join(dir, "tcp")
	defer SetProcNetTCPPathsForTest(v4, filepath.Join(dir, "tcp6"))()

	const header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	client := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 43210}
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}

	// State 06 is TCP_TIME_WAIT, uid column 0 — what the kernel emits once the
	// caller closes.
	write(t, v4, header+"   0: 0100007F:A8CA 0100007F:1F90 06 00000000:00000000 00:00000000 00000000     0        0 0 1 0000000000000000 100 0 0 10 0\n")
	id := LookupPeer(client, server)
	if id.OK {
		t.Fatalf("a TIME_WAIT row was accepted as identity uid %d — a caller that closes its "+
			"socket after sending would be authorized as root", id.UID)
	}
	if !id.Local {
		t.Error("a TIME_WAIT row proves the caller is local; reporting it off-box would " +
			"hand it the credential path")
	}

	// The same 4-tuple in state 01 (ESTABLISHED) with a real uid IS accepted, so
	// the rejection above is the state check and not a broken matcher.
	write(t, v4, header+"   0: 0100007F:A8CA 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1001        0 4242 1 0000000000000000 100 0 0 10 0\n")
	if id := LookupPeer(client, server); !id.OK || id.UID != 1001 {
		t.Fatalf("established row parsed as %+v, want uid 1001", id)
	}

	// A row whose ports match but whose ADDRESSES do not must not match at all —
	// the fixture form of MAJOR 1.
	write(t, v4, header+"   0: 0200007F:A8CA 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1001        0 4242 1 0000000000000000 100 0 0 10 0\n")
	if id := LookupPeer(client, server); id.OK {
		t.Fatalf("a row for a DIFFERENT local address (127.0.0.2) was matched for a "+
			"127.0.0.1 caller: %+v", id)
	}
}

// TestProcParserFindsV4MappedRowInTCP6_5561 covers the file-selection question,
// which is security-relevant rather than cosmetic: a caller that opened an
// AF_INET6 socket and connected to ::ffff:127.0.0.1 has its row in
// /proc/net/tcp6 even though Go reports its address as plain 127.0.0.1. Scanning
// only /proc/net/tcp would find nothing, report the caller off-box, and hand it
// the api-auth credential path.
func TestProcParserFindsV4MappedRowInTCP6_5561(t *testing.T) {
	dir := t.TempDir()
	v4, v6 := filepath.Join(dir, "tcp"), filepath.Join(dir, "tcp6")
	defer SetProcNetTCPPathsForTest(v4, v6)()

	const header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	write(t, v4, header) // the v4 table has no row for this connection
	write(t, v6, header+"   0: 0000000000000000FFFF00000100007F:A8CA 0000000000000000FFFF00000100007F:1F90 01 00000000:00000000 00:00000000 00000000  1001        0 4242 1 0000000000000000 100 0 0 10 0\n")

	id := LookupPeer(
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 43210},
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080})
	if !id.OK || id.UID != 1001 {
		t.Fatalf("a v4-mapped row in /proc/net/tcp6 was not found: %+v — the caller would be "+
			"reported off-box and reach the credential path", id)
	}
}

// TestProcAddrEncoding_5561 pins the /proc address encoding against the literal
// strings the kernel emits on this (little-endian) architecture. A silently
// wrong encoding matches no row, which now means "off-box" — the credential
// path — so this is not merely a formatting test.
func TestProcAddrEncoding_5561(t *testing.T) {
	for _, tc := range []struct {
		addr *net.TCPAddr
		v4   string
		v6   string
	}{
		{
			addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080},
			v4:   "0100007F:1F90",
			v6:   "0000000000000000FFFF00000100007F:1F90",
		},
		{
			addr: &net.TCPAddr{IP: net.IPv4(10, 0, 61, 1), Port: 443},
			v4:   "013D000A:01BB",
			v6:   "0000000000000000FFFF0000013D000A:01BB",
		},
		{
			addr: &net.TCPAddr{IP: net.IPv6loopback, Port: 8080},
			v4:   "",
			v6:   "00000000000000000000000001000000:1F90",
		},
	} {
		got4, ok4 := procAddr4(tc.addr)
		if tc.v4 == "" {
			if ok4 {
				t.Errorf("procAddr4(%v) = %q, want not-representable", tc.addr, got4)
			}
		} else if !ok4 || got4 != tc.v4 {
			t.Errorf("procAddr4(%v) = (%q, %v), want %q", tc.addr, got4, ok4, tc.v4)
		}
		got6, ok6 := procAddr6(tc.addr)
		if !ok6 || got6 != tc.v6 {
			t.Errorf("procAddr6(%v) = (%q, %v), want %q", tc.addr, got6, ok6, tc.v6)
		}
	}
}

// TestProcParserAgreesWithLiveKernelRow_5561 cross-checks the fixture-shaped
// parser against rows the running kernel actually wrote, so the fixtures above
// cannot drift from the real /proc format without this failing.
func TestProcParserAgreesWithLiveKernelRow_5561(t *testing.T) {
	server, _ := acceptedPair(t, "tcp4", "127.0.0.1:0", nil)
	uid, state, found, malformed, err := findPeerSocket(
		server.RemoteAddr().(*net.TCPAddr), server.LocalAddr().(*net.TCPAddr))
	if err != nil || !found || malformed {
		t.Fatalf("live socket-table lookup failed: found=%v err=%v", found, err)
	}
	if state != tcpEstablished {
		t.Fatalf("live socket reported state %d, want established", state)
	}
	if uid != uint32(os.Getuid()) {
		t.Fatalf("live lookup reported uid %d, want %d", uid, os.Getuid())
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// firstRoutableHostAddr returns a real, non-loopback IPv4 address of this host —
// one a socket can actually be bound to, so a case can build a connection whose
// BOTH ends are off-loopback and therefore reach the interface-address clause of
// couldBeLocal instead of short-circuiting on the loopback one.
func firstRoutableHostAddr(t *testing.T) net.IP {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %v", err)
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := n.IP.To4()
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			continue
		}
		return ip
	}
	t.Skip("this host has no routable IPv4 address to build an off-loopback connection from")
	return nil
}

// TestBrandNewLocalAddressIsAttributedNotOffBox_5561 is the primary round-5
// MAJOR guard, and it pins the fix's first half.
//
// The accept-time interface-address snapshot is refreshed at most once per
// localAddrTTL, for hits AND misses. The rate limit is right for the flood it
// exists to stop, but the answer it caches includes the NEGATIVE — and the
// negative used to be decisive: `!couldBeLocal` returned "not on this host"
// WITHOUT READING THE SOCKET TABLE, which is the one row an api-auth credential
// may speak for. So for up to a TTL after an address was added to this host, a
// caller arriving from it did not merely lose its attribution, it skipped
// attribution and was adjudicated through a shared secret. Address adds are
// observable to any local account (`ip monitor address` needs no privilege) and
// this box performs them routinely — VRRP VIPs on failover, DHCP leases,
// RA-derived addresses.
//
// The fix is to stop letting a negative decide: read the table first, and use
// the address classification only where the table has nothing to say. A row hit
// proves locality on its own, from the kernel rather than from a snapshot.
//
// Reproduced against a REAL established socket whose two ends are a real
// routable address of this host, with the snapshot seeded from before that
// address existed. The caller must be ATTRIBUTED — same uid the kernel reports
// for the socket — not routed off-box.
func TestBrandNewLocalAddressIsAttributedNotOffBox_5561(t *testing.T) {
	host := firstRoutableHostAddr(t)
	// Both ends off-loopback, so couldBeLocal cannot short-circuit on the
	// loopback clause and the stale snapshot is really what would decide.
	server, _ := acceptedPair(t, "tcp4", (&net.TCPAddr{IP: host}).String(),
		&net.TCPAddr{IP: host})
	client := server.RemoteAddr().(*net.TCPAddr)
	local := server.LocalAddr().(*net.TCPAddr)

	// This caller is unambiguously ON THIS HOST: the kernel is holding its
	// established socket and reports this process's own uid for it.
	uid, state, found, malformed, err := findPeerSocket(client, local)
	if err != nil || !found || malformed || state != tcpEstablished {
		t.Fatalf("precondition: the live socket %v -> %v was not found "+
			"(found=%v malformed=%v state=%d err=%v)", client, local, found, malformed, state, err)
	}
	if uid != uint32(os.Getuid()) {
		t.Fatalf("precondition: live socket reported uid %d, want %d", uid, os.Getuid())
	}

	// Seed the accept-time snapshot from a moment BEFORE the address existed —
	// the state the cache is in for up to a TTL after any address add.
	prev := localAddrsFn
	localAddrsFn = func() ([]net.Addr, error) { return nil, nil }
	resetLocalAddrCacheForTest()
	if isLocalAddr(host) {
		t.Fatal("could not seed a pre-add snapshot")
	}
	// The address is on the host (it always was — the seeded snapshot is what
	// lagged). Restore the real enumerator WITHOUT clearing the cache, which is
	// exactly the state a real address add leaves behind.
	localAddrsFn = prev
	t.Cleanup(resetLocalAddrCacheForTest)

	id := LookupPeer(client, local)
	if !id.OK {
		t.Fatalf("a caller whose ESTABLISHED socket this kernel is holding, from an "+
			"address assigned to this very host, was not attributed (%+v). If Local is "+
			"false the api-auth credential speaks for it, so any local account that "+
			"connects from a freshly added VIP or DHCP address escapes its login class", id)
	}
	if !id.Local || id.UID != uint32(os.Getuid()) {
		t.Fatalf("LookupPeer = %+v, want an attributed LOCAL identity for uid %d", id, os.Getuid())
	}
}

// TestBrandNewLocalAddressWithNoSocketRowIsNotOffBox_5561 pins the fix's second
// half: the residual the table-first restructure does NOT cover.
//
// Reading the table first removes the cached negative from the decision for any
// caller that HAS a socket. It does not remove it from the "no row at all" case,
// which is still resolved from the address classification — and a local caller
// that destroyed its own socket (an SO_LINGER-0 reset) before the read, from an
// address added within the last TTL, lands there. Such a caller cannot read a
// response, but the handler still runs, so a fire-and-forget commit is a real
// outcome rather than a cosmetic one.
//
// PeerCouldBeLocalNow closes it: the credential row re-derives locality from an
// enumeration started by the call. This case drives exactly that state — an
// address that IS on the host, a snapshot that predates it, and no socket row.
func TestBrandNewLocalAddressWithNoSocketRowIsNotOffBox_5561(t *testing.T) {
	client := &net.TCPAddr{IP: net.IPv4(203, 0, 113, 5), Port: 51234}
	local := &net.TCPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 8080}

	prev := localAddrsFn
	localAddrsFn = func() ([]net.Addr, error) { return nil, nil } // pre-add snapshot
	resetLocalAddrCacheForTest()
	if isLocalAddr(client.IP) {
		t.Fatal("could not seed a pre-add snapshot")
	}
	// The address is added to the host. The cache does not know yet.
	localAddrsFn = func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: client.IP, Mask: net.CIDRMask(24, 32)}}, nil
	}
	t.Cleanup(func() { localAddrsFn = prev; resetLocalAddrCacheForTest() })

	// Precondition: no row for this synthetic 4-tuple, and the stale snapshot is
	// still in force, so LookupPeer really does report it off-box.
	if id := LookupPeer(client, local); id.Local {
		t.Fatalf("precondition: the cache refreshed early (%+v); this case is then "+
			"asserting nothing", id)
	}
	if !PeerCouldBeLocalNow(client, local) {
		t.Fatal("an address that IS on this host was confirmed off-box from a stale " +
			"snapshot — the confirmation is reading the cache, not the host, so a local " +
			"caller that reset its socket still reaches the api-auth credential")
	}
}

// TestConfirmationFailsClosed_5561 pins the direction of every failure mode of
// the authoritative re-check. It may only ever DENY: an unusable address list or
// a shape it cannot classify must answer "local", because the single caller of
// this function treats false as permission to honour a shared secret.
func TestConfirmationFailsClosed_5561(t *testing.T) {
	tcp := &net.TCPAddr{IP: net.IPv4(203, 0, 113, 5), Port: 51234}
	srv := &net.TCPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 8080}

	prev := localAddrsFn
	localAddrsFn = func() ([]net.Addr, error) { return nil, errors.New("interfaces unreadable") }
	t.Cleanup(func() { localAddrsFn = prev; resetLocalAddrCacheForTest() })
	if !PeerCouldBeLocalNow(tcp, srv) {
		t.Error("an unreadable interface list confirmed the caller OFF-BOX — an enumeration " +
			"failure must cost availability, never authority")
	}

	localAddrsFn = func() ([]net.Addr, error) { return nil, nil }
	for _, tc := range []struct {
		name           string
		client, server net.Addr
	}{
		{"non-TCP client", &net.UnixAddr{Name: "/run/xpf.sock", Net: "unix"}, srv},
		{"non-TCP server", tcp, &net.UnixAddr{Name: "/run/xpf.sock", Net: "unix"}},
		{"client has no address", &net.TCPAddr{Port: 1}, srv},
		{"server has no address", tcp, &net.TCPAddr{Port: 8080}},
		{"loopback client", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, srv},
		{"loopback delivery", tcp, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}},
	} {
		if !PeerCouldBeLocalNow(tc.client, tc.server) {
			t.Errorf("%s: confirmed OFF-BOX; LookupPeer reports every one of these as "+
				"local, so the confirmation must agree rather than admit", tc.name)
		}
	}
}

// TestConfirmationIsSingleFlighted_5561 is the cost half of the round-5 fix, and
// the reason the confirmation could be made authoritative at all.
//
// A fresh enumeration per caller would be the amplification
// TestLocalAddrCacheRateLimitsMisses_5561 exists to forbid, just moved. The
// confirmation batches like socketscan.go instead.
//
// # What the batching actually promises, and why this asserts an EXACT count
//
// An earlier version of this case allowed 50 enumerations for 400 calls while
// its comment claimed "N concurrent confirmations cost ONE enumeration". A
// ceiling 50x above the claim is not a guard: it would pass with the batching
// removed for any batch that happened to be small, and it hid the fact that the
// claim itself was wrong.
//
// The claim is now stated correctly AND pinned exactly. A waiter that arrives
// while a scan is in flight is NOT served by it — run() took its batch before
// the scan started — so it waits for the NEXT one. The promise is therefore not
// "N callers cost one scan"; it is "callers that overlap a scan share the scan
// after it", i.e. the enumeration count is bounded by elapsed time over scan
// duration rather than by caller count.
//
// The case drives exactly that shape deterministically: one caller starts a scan
// and is held inside it, every other caller then piles into the waiter queue, and
// releasing the first scan must drain ALL of them in a SECOND scan. Two, exactly
// — not "at most 50", and not "one", which the design does not promise.
func TestConfirmationIsSingleFlighted_5561(t *testing.T) {
	const callers = 200

	ours := net.IPv4(10, 0, 61, 1)
	foreign := net.IPv4(198, 51, 100, 7)
	srv := &net.TCPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 8080}

	entered := make(chan struct{}, 1) // the first scan has begun
	release := make(chan struct{})    // ... and may now finish
	var scanNo atomic.Int64

	prev := localAddrsFn
	localAddrsFn = func() ([]net.Addr, error) {
		if scanNo.Add(1) == 1 {
			entered <- struct{}{}
			<-release
		}
		return []net.Addr{&net.IPNet{IP: ours, Mask: net.CIDRMask(24, 32)}}, nil
	}
	t.Cleanup(func() { localAddrsFn = prev; resetLocalAddrCacheForTest() })

	// Quiesce first: a drain goroutine left running by an earlier case would
	// take this case's waiters and make the count meaningless.
	waitForHostAddrScannerIdle(t)

	before := HostAddrScansForTest()
	var wg sync.WaitGroup
	var wrong atomic.Uint64
	ask := func(ip net.IP, wantLocal bool) {
		defer wg.Done()
		if got := PeerCouldBeLocalNow(&net.TCPAddr{IP: ip, Port: 1}, srv); got != wantLocal {
			wrong.Add(1)
		}
	}

	// Caller 0 alone, so it is unambiguously the one that starts scan 1.
	wg.Add(1)
	go ask(ours, true)
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		close(release)
		wg.Wait()
		t.Fatal("the first enumeration never started")
	}

	// Everyone else arrives WHILE scan 1 is in flight, so all of them must land
	// in the waiter queue rather than being answered by the scan already running.
	for i := 1; i < callers; i++ {
		wg.Add(1)
		if i%2 == 0 {
			go ask(ours, true)
		} else {
			go ask(foreign, false)
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		hostAddrScan.mu.Lock()
		queued := len(hostAddrScan.waiters)
		hostAddrScan.mu.Unlock()
		if queued == callers-1 {
			break
		}
		if time.Now().After(deadline) {
			close(release)
			wg.Wait()
			t.Fatalf("only %d of %d callers queued behind the in-flight scan", queued, callers-1)
		}
		time.Sleep(time.Millisecond)
	}

	close(release)
	wg.Wait()

	if n := wrong.Load(); n != 0 {
		t.Fatalf("%d of %d batched confirmations answered the wrong caller — batching "+
			"blurred one caller's address into another's", n, callers)
	}
	if scans := HostAddrScansForTest() - before; scans != 2 {
		t.Fatalf("%d callers — one holding a scan open and %d queued behind it — drove %d "+
			"enumerations, want exactly 2. More than 2 means the queued callers were not "+
			"batched and the confirmation amplifies per caller; fewer means they were "+
			"answered by a scan that STARTED BEFORE THEY ARRIVED, which is the staleness "+
			"the whole fix exists to remove", callers, callers-1, scans)
	}
}

// waitForHostAddrScannerIdle blocks until no enumeration goroutine is live.
// run() clears `running` under the lock and returns without releasing it in
// between, so observing running==false under that lock proves none is between
// iterations.
func waitForHostAddrScannerIdle(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		hostAddrScan.mu.Lock()
		idle := !hostAddrScan.running && len(hostAddrScan.waiters) == 0
		hostAddrScan.mu.Unlock()
		if idle {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the host-address scanner never went idle")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestMalformedRowIsLocalAndUnattributable_5561 covers the row the parser cannot
// read.
//
// The kernel does not emit a socket-table row with an unparsable state or uid
// column, so this is a "cannot happen" path — which is exactly why it must not
// be a SILENT one. It used to `continue`, dropping the row. That was fail-safe
// only while a caller reaching the parser had already been established as local:
// with the table read first, "dropped" becomes "no row", "no row" falls through
// to the address classification, and a stale negative there sends the caller to
// the credential. The row is now recorded as malformed, which proves a socket
// exists without naming its owner — local, unattributable, denied — and is
// logged once per file per scan so the operator gets a reason rather than an
// unexplained 403.
func TestMalformedRowIsLocalAndUnattributable_5561(t *testing.T) {
	const header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	client := &net.TCPAddr{IP: net.IPv4(203, 0, 113, 5), Port: 43210}
	server := &net.TCPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 8080}
	cl, _ := procAddr4(client)
	sv, _ := procAddr4(server)

	for _, tc := range []struct{ name, state, uid string }{
		{"unparsable state column", "zz", "1001"},
		{"unparsable uid column", "01", "notanumber"},
		{"both columns unparsable", "--", "--"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			v4 := filepath.Join(dir, "tcp")
			write(t, v4, header+"   0: "+cl+" "+sv+" "+tc.state+
				" 00000000:00000000 00:00000000 00000000  "+tc.uid+
				"        0 4242 1 0000000000000000 100 0 0 10 0\n")
			write(t, filepath.Join(dir, "tcp6"), header)
			defer SetProcNetTCPPathsForTest(v4, filepath.Join(dir, "tcp6"))()
			// No interface addresses at all: if the malformed row were dropped,
			// the address classification would call this caller off-box and hand
			// it the credential. Only recording the row can rescue it.
			defer setLocalAddrsForTest(nil)()

			id := LookupPeer(client, server)
			if id.OK {
				t.Fatalf("a row whose %s was accepted as an identity: %+v", tc.name, id)
			}
			if !id.Local {
				t.Fatalf("a row that MATCHED this caller's 4-tuple but would not parse was "+
					"reported off-box (%+v) — a socket demonstrably exists here, so the "+
					"api-auth credential must not speak for it", id)
			}
			if !strings.Contains(id.Detail, "could not be parsed") {
				t.Errorf("detail does not explain the refusal: %q", id.Detail)
			}
		})
	}

	// Negative control: the SAME row with both columns well-formed and
	// established IS attributed, so the refusals above are the parse failure and
	// not a broken matcher.
	dir := t.TempDir()
	v4 := filepath.Join(dir, "tcp")
	write(t, v4, header+"   0: "+cl+" "+sv+
		" 01 00000000:00000000 00:00000000 00000000  1001        0 4242 1 0000000000000000 100 0 0 10 0\n")
	write(t, filepath.Join(dir, "tcp6"), header)
	defer SetProcNetTCPPathsForTest(v4, filepath.Join(dir, "tcp6"))()
	defer setLocalAddrsForTest(nil)()
	if id := LookupPeer(client, server); !id.OK || id.UID != 1001 {
		t.Fatalf("the well-formed control row parsed as %+v, want uid 1001", id)
	}
}

// TestSaturatedBatcherFailsClosed_5561 covers the queue bound.
//
// Every pending entry is a goroutine blocked in LookupPeer, so the slice grows
// with concurrent connections and http.Server imposes no limit of its own. Past
// maxPendingLookups a lookup is refused rather than queued — and the refusal has
// to land on the DENY side: an errored table read falls back to the address
// classification, so a caller that could be local is denied and one that could
// not is still reported off-box (a saturated queue must not lock out every
// remote administrator either).
func TestSaturatedBatcherFailsClosed_5561(t *testing.T) {
	// Fill the queue with entries that will never be drained by pinning the
	// batcher's `running` flag: no goroutine is started, so nothing dequeues.
	batcher.mu.Lock()
	prevPending, prevRunning := batcher.pending, batcher.running
	batcher.pending = make([]*socketQuery, maxPendingLookups)
	batcher.running = true
	batcher.mu.Unlock()
	t.Cleanup(func() {
		batcher.mu.Lock()
		batcher.pending, batcher.running = prevPending, prevRunning
		batcher.mu.Unlock()
	})

	defer setLocalAddrsForTest([]net.Addr{
		&net.IPNet{IP: net.IPv4(10, 0, 61, 1), Mask: net.CIDRMask(24, 32)},
	})()

	// lookupOrTimeout is the load-bearing shape of this case: past the cap a
	// lookup must RETURN a verdict. Without the cap it appends to a queue nothing
	// will drain and blocks forever, so "did it come back" IS the property, and
	// the timeout turns an unbounded queue into an assertion instead of a hang.
	lookupOrTimeout := func(t *testing.T, client, server *net.TCPAddr) PeerIdentity {
		t.Helper()
		done := make(chan PeerIdentity, 1)
		go func() { done <- LookupPeer(client, server) }()
		select {
		case id := <-done:
			return id
		case <-time.After(5 * time.Second):
			t.Fatalf("LookupPeer(%v) never returned with the queue at its cap — the "+
				"pending slice is unbounded, so a connect flood grows it without limit "+
				"and every new caller blocks instead of being denied", client)
			return PeerIdentity{}
		}
	}

	// A caller from one of OUR addresses: denied, not attributed.
	ours := lookupOrTimeout(t,
		&net.TCPAddr{IP: net.IPv4(10, 0, 61, 1), Port: 51234},
		&net.TCPAddr{IP: net.IPv4(10, 0, 61, 9), Port: 8080})
	if ours.OK || !ours.Local {
		t.Fatalf("a saturated queue produced %+v for a caller from our own address — it "+
			"must deny rather than fall through to the credential", ours)
	}

	// A routable caller that is not ours: ALSO denied. A saturated queue is a
	// failed read, and a failed read is unknown — see
	// TestUnreadableTableDeniesEveryone_5561. This assertion used to require
	// off-box here, on the availability argument that saturation must not lock
	// out remote administrators; that put an availability rule where a security
	// one belongs, since off-box is the row the credential speaks for.
	remote := lookupOrTimeout(t,
		&net.TCPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 51234},
		&net.TCPAddr{IP: net.IPv4(10, 0, 61, 1), Port: 8080})
	if remote.OK || !remote.Local {
		t.Fatalf("a saturated queue reported a routable peer as %+v — saturation is a failed "+
			"observation, so it must deny rather than hand out the credential row", remote)
	}

	// And the queue did not grow past its cap.
	batcher.mu.Lock()
	n := len(batcher.pending)
	batcher.mu.Unlock()
	if n > maxPendingLookups {
		t.Fatalf("pending queue grew to %d, past the %d cap", n, maxPendingLookups)
	}
}

// TestSaturatedEnumerationQueueFailsClosed_5561 is the MINOR-4 guard, the
// hostAddrScan twin of TestSaturatedBatcherFailsClosed_5561.
//
// Every waiter is a goroutine blocked in PeerCouldBeLocalNow, so a wedged
// enumeration accumulates them without limit. Past the cap the caller must be
// answered rather than queued, and the answer must land on the DENY side: this
// function's false is what admits a credential, so saturation may only ever say
// "local".
func TestSaturatedEnumerationQueueFailsClosed_5561(t *testing.T) {
	waitForHostAddrScannerIdle(t)

	// Pin `running` with no goroutine behind it, so nothing dequeues. Real
	// (keyless, buffered) channels rather than nils, so a drainer that somehow
	// did take them could not crash on one.
	hostAddrScan.mu.Lock()
	prevWaiters, prevRunning := hostAddrScan.waiters, hostAddrScan.running
	filler := make([]chan hostAddrs, maxHostAddrWaiters)
	for i := range filler {
		filler[i] = make(chan hostAddrs, 1)
	}
	hostAddrScan.waiters = filler
	hostAddrScan.running = true
	hostAddrScan.mu.Unlock()
	t.Cleanup(func() {
		hostAddrScan.mu.Lock()
		hostAddrScan.waiters, hostAddrScan.running = prevWaiters, prevRunning
		hostAddrScan.mu.Unlock()
	})

	defer setLocalAddrsForTest([]net.Addr{
		&net.IPNet{IP: net.IPv4(10, 0, 61, 1), Mask: net.CIDRMask(24, 32)},
	})()

	// The property is that the call RETURNS. Without the cap it appends to a
	// queue nothing will drain and blocks forever, so the timeout turns an
	// unbounded queue into an assertion instead of a hang.
	done := make(chan bool, 1)
	go func() {
		done <- PeerCouldBeLocalNow(
			&net.TCPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 51234},
			&net.TCPAddr{IP: net.IPv4(10, 0, 61, 1), Port: 8080})
	}()
	select {
	case local := <-done:
		if !local {
			t.Fatal("a saturated enumeration queue confirmed the caller OFF-BOX — that is " +
				"the one answer that admits a credential, so saturation would let a shared " +
				"secret speak for a caller nobody enumerated")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("PeerCouldBeLocalNow never returned with the queue at its cap — the waiter " +
			"slice is unbounded, so a wedged enumeration accumulates goroutines without " +
			"limit and every new caller blocks instead of being denied")
	}

	hostAddrScan.mu.Lock()
	n := len(hostAddrScan.waiters)
	hostAddrScan.mu.Unlock()
	if n > maxHostAddrWaiters {
		t.Fatalf("waiter queue grew to %d, past the %d cap", n, maxHostAddrWaiters)
	}
}

// TestPartialTableReadFailsClosed_5561 is the round-7 MAJOR-3 guard.
//
// The full-failure case was checked twice and is correct: no table readable ->
// error -> local -> deny. The PARTIAL case was not. A caller's row lives in
// exactly ONE of tcp/tcp6 and we cannot know which, so "tcp read clean and
// empty, tcp6 present but unreadable" is not evidence of "no row" — it is half
// an observation. Reporting it as a successful omission sends a LOCAL caller
// whose row is in the unread file to the off-box row, the one row an api-auth
// credential may speak for.
//
// The discrimination that keeps this from over-denying: an ABSENT tcp6 is not a
// failure. A kernel built without IPv6 has no such file, and counting that as a
// failed read would deny every caller on such a box — which is why the negative
// control below is as load-bearing as the positive one.
func TestPartialTableReadFailsClosed_5561(t *testing.T) {
	const header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	client := &net.TCPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 43210}
	server := &net.TCPAddr{IP: net.IPv4(10, 0, 61, 1), Port: 8080}
	ours := []net.Addr{&net.IPNet{IP: net.IPv4(10, 0, 61, 1), Mask: net.CIDRMask(24, 32)}}

	t.Run("present but unreadable tcp6 is a FAILURE, not an omission", func(t *testing.T) {
		dir := t.TempDir()
		v4, v6 := filepath.Join(dir, "tcp"), filepath.Join(dir, "tcp6")
		write(t, v4, header) // reads clean, matches nothing
		write(t, v6, header)
		if err := os.Chmod(v6, 0o000); err != nil {
			t.Skipf("cannot make %s unreadable: %v", v6, err)
		}
		if f, err := os.Open(v6); err == nil {
			f.Close()
			t.Skip("running with privileges that ignore file mode; cannot stage an unreadable table")
		}
		defer SetProcNetTCPPathsForTest(v4, v6)()
		defer setLocalAddrsForTest(ours)() // caller is NOT one of ours

		id := LookupPeer(client, server)
		if !id.Local {
			t.Fatalf("a peer whose tcp6 table could not be read was reported OFF-BOX (%+v) — "+
				"its row may well be in the file we failed to read, so this hands a local "+
				"caller the api-auth credential path on a half-finished observation", id)
		}
		if id.OK {
			t.Fatalf("a partial read produced an identity: %+v", id)
		}
	})

	// Negative control, and the reason the fix discriminates on ENOENT: an
	// ABSENT tcp6 is an IPv6-less kernel, not a failed read. This must still
	// answer from tcp alone, in BOTH directions.
	t.Run("absent tcp6 is not a failure", func(t *testing.T) {
		dir := t.TempDir()
		v4 := filepath.Join(dir, "tcp")
		write(t, v4, header)
		defer SetProcNetTCPPathsForTest(v4, filepath.Join(dir, "nonexistent-tcp6"))()
		defer setLocalAddrsForTest(ours)()

		if id := LookupPeer(client, server); id.Local {
			t.Fatalf("an ABSENT tcp6 was treated as a failed read (%+v) — every caller on an "+
				"IPv6-less kernel would be denied", id)
		}
		oursCaller := &net.TCPAddr{IP: net.IPv4(10, 0, 61, 1), Port: 51234}
		other := &net.TCPAddr{IP: net.IPv4(10, 0, 61, 9), Port: 8080}
		if id := LookupPeer(oursCaller, other); !id.Local {
			t.Fatalf("a caller from our OWN address was reported off-box with tcp6 absent: %+v", id)
		}
	})
}

// TestScopedPeerWithNoObservationDenies_5561 is the round-4 finding-4 guard, and
// the sibling of the error-path fix one branch up.
//
// The scoped-address branch used to answer from the cached classification
// WITHOUT consulting either socket table, so a scoped caller the snapshot did
// not recognise was reported off-box — the credential row — on zero
// observations. Closing a fail-open in one branch and leaving its sibling is how
// the same defect ships twice; this pins the sibling.
func TestScopedPeerWithNoObservationDenies_5561(t *testing.T) {
	ours := []net.Addr{&net.IPNet{IP: net.ParseIP("fe80::e01:0:0:1"), Mask: net.CIDRMask(64, 128)}}
	client := &net.TCPAddr{IP: net.ParseIP("fe80::ee01:0:0:99"), Port: 43210, Zone: "eth0"}
	server := &net.TCPAddr{IP: net.ParseIP("fe80::e01:0:0:1"), Port: 8080, Zone: "eth0"}

	t.Run("no table could be read", func(t *testing.T) {
		dir := t.TempDir()
		defer SetProcNetTCPPathsForTest(filepath.Join(dir, "absent"), filepath.Join(dir, "absent6"))()
		defer setLocalAddrsForTest(ours)()
		if id := LookupPeer(client, server); !id.Local || id.OK {
			t.Fatalf("a scoped peer was reported %+v with NO socket table readable — that is "+
				"the credential row, reached without a single observation", id)
		}
	})

	// A matching row proves a socket exists here even though it names nobody, so
	// locality is established from the KERNEL rather than from the snapshot.
	t.Run("a matching row proves locality without attributing", func(t *testing.T) {
		const header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
		cl, ok := procAddr6(client)
		if !ok {
			t.Fatal("cannot render client address")
		}
		sv, ok := procAddr6(server)
		if !ok {
			t.Fatal("cannot render server address")
		}
		dir := t.TempDir()
		v4, v6 := filepath.Join(dir, "tcp"), filepath.Join(dir, "tcp6")
		write(t, v4, header)
		write(t, v6, header+"   0: "+cl+" "+sv+" 01 00000000:00000000 00:00000000 00000000     0        0 4242 1 0000000000000000 100 0 0 10 0\n")
		defer SetProcNetTCPPathsForTest(v4, v6)()
		// The snapshot does NOT recognise this caller, so only the row can save it.
		defer setLocalAddrsForTest(ours)()

		id := LookupPeer(client, server)
		if id.OK {
			t.Fatalf("a scoped peer was ATTRIBUTED from a row carrying no scope id: %+v", id)
		}
		if !id.Local {
			t.Fatalf("a scoped peer with a MATCHING socket row was reported off-box (%+v) — "+
				"the row proves a socket exists on this host, whoever owns it", id)
		}
		if !strings.Contains(id.Detail, "scope-qualified") {
			t.Errorf("detail does not explain the refusal: %q", id.Detail)
		}
	})
}

// TestScopedDenialsAreDistinguishable_5561 pins the #5561 round-9 MINOR-5 fix.
//
// The scoped branch has TWO local-denial outcomes and they are different
// diagnoses with different operator remedies:
//
//	row found     the kernel proved a socket exists here; the missing scope id in
//	              /proc is what stops us naming its owner
//	no row, ours  the table was read and held NOTHING; the denial rests entirely
//	              on the address classification
//
// Both used to emit the byte-identical Detail "peer address %v is
// scope-qualified and cannot be attributed from the socket table", which is not
// even true of the second — nothing was attributed because nothing was there.
// That string is what reaches the 403 body and the audit log, so an operator
// diagnosing a link-local management bind could not tell the two apart. Every
// other denial in LookupPeer carries a state-specific Detail.
func TestScopedDenialsAreDistinguishable_5561(t *testing.T) {
	const header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	client := &net.TCPAddr{IP: net.ParseIP("fe80::ee01:0:0:99"), Port: 43210, Zone: "eth0"}
	server := &net.TCPAddr{IP: net.ParseIP("fe80::e01:0:0:1"), Port: 8080, Zone: "eth0"}

	// (a) A matching ESTABLISHED row exists. Our own address list does NOT
	// contain the caller, so only the row can establish locality.
	rowFound := func() PeerIdentity {
		cl, ok := procAddr6(client)
		if !ok {
			t.Fatal("cannot render client address")
		}
		sv, ok := procAddr6(server)
		if !ok {
			t.Fatal("cannot render server address")
		}
		dir := t.TempDir()
		v4, v6 := filepath.Join(dir, "tcp"), filepath.Join(dir, "tcp6")
		write(t, v4, header)
		write(t, v6, header+"   0: "+cl+" "+sv+" 01 00000000:00000000 00:00000000 00000000     0        0 4242 1 0000000000000000 100 0 0 10 0\n")
		defer SetProcNetTCPPathsForTest(v4, v6)()
		defer setLocalAddrsForTest([]net.Addr{
			&net.IPNet{IP: net.ParseIP("fe80::e01:0:0:1"), Mask: net.CIDRMask(64, 128)},
		})()
		return LookupPeer(client, server)
	}()

	// (b) The tables are PRESENT and EMPTY — genuinely read, genuinely holding
	// nothing — and the caller's address IS one of ours.
	noRowButOurs := func() PeerIdentity {
		dir := t.TempDir()
		v4, v6 := filepath.Join(dir, "tcp"), filepath.Join(dir, "tcp6")
		write(t, v4, header)
		write(t, v6, header)
		defer SetProcNetTCPPathsForTest(v4, v6)()
		defer setLocalAddrsForTest([]net.Addr{
			&net.IPNet{IP: net.ParseIP("fe80::ee01:0:0:99"), Mask: net.CIDRMask(64, 128)},
		})()
		return LookupPeer(client, server)
	}()

	// Both are the same VERDICT — local, unattributable, denied. The fix is about
	// the reason they report, so pin the verdict first or a Detail change could
	// be "achieved" by changing the outcome.
	for _, c := range []struct {
		what string
		id   PeerIdentity
	}{{"a matching row", rowFound}, {"no row and an address of ours", noRowButOurs}} {
		if c.id.OK || !c.id.Local {
			t.Fatalf("%s: got %+v, want local-and-unattributable (denied)", c.what, c.id)
		}
		if !strings.Contains(c.id.Detail, "scope-qualified") {
			t.Errorf("%s: detail does not name the scope refusal: %q", c.what, c.id.Detail)
		}
	}

	if rowFound.Detail == noRowButOurs.Detail {
		t.Fatalf("two distinguishable scoped-denial states emit the IDENTICAL Detail %q. "+
			"That string is the 403 body and the audit line, so an operator cannot tell "+
			"'the kernel proved a socket exists here' from 'the table was read and held "+
			"nothing; your address is simply one of ours' — different diagnoses, different "+
			"remedies", rowFound.Detail)
	}
	// And the no-row reason must not claim an attribution failure that never
	// happened: there was nothing to attribute.
	if strings.Contains(noRowButOurs.Detail, "cannot be attributed from the socket table") {
		t.Errorf("the no-row denial reports %q — the table was read and held NOTHING, so "+
			"'cannot be attributed from the socket table' describes the OTHER state",
			noRowButOurs.Detail)
	}
}
