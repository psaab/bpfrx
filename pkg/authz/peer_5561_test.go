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

// TestNonLocalPeerReadsNoSocketTable_5561 is the MAJOR-D guard at this layer: a
// peer that cannot be local must cost ZERO socket-table work, so connection
// churn from a routable address cannot serialize full /proc walks behind the
// accept loop.
//
// The probe is precise rather than timing-based: the table paths point at files
// that do not exist. If the code reads the table it gets "no socket table could
// be read", which fails CLOSED to Local=true. Only a short-circuit before the
// read yields a non-local answer.
func TestNonLocalPeerReadsNoSocketTable_5561(t *testing.T) {
	dir := t.TempDir()
	defer SetProcNetTCPPathsForTest(filepath.Join(dir, "absent"), filepath.Join(dir, "absent6"))()
	defer setLocalAddrsForTest([]net.Addr{
		&net.IPNet{IP: net.IPv4(10, 0, 61, 1), Mask: net.CIDRMask(24, 32)},
	})()

	id := LookupPeer(
		&net.TCPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 51234},
		&net.TCPAddr{IP: net.IPv4(10, 0, 61, 1), Port: 8080})
	if id.Local {
		t.Fatalf("a routable, non-local peer read the socket table (%+v) — every connection "+
			"from off-box would walk /proc, which is the accept-loop flood", id)
	}
	if id.OK {
		t.Fatalf("a non-local peer was attributed: %+v", id)
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
	dir := t.TempDir()
	defer SetProcNetTCPPathsForTest(filepath.Join(dir, "absent"), filepath.Join(dir, "absent6"))()
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
	uid, state, found, err := findPeerSocket(
		server.RemoteAddr().(*net.TCPAddr), server.LocalAddr().(*net.TCPAddr))
	if err != nil || !found {
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

// TestBrandNewLocalAddressIsNotOffBox_5561 is the round-5 MAJOR guard.
//
// The accept-time locality classification reads a snapshot refreshed at most
// once per localAddrTTL, for hits AND misses. That rate limit is right for the
// flood it exists to stop, but it caches a NEGATIVE answer — and the negative is
// the one verdict that ADMITS: "not on this host" is the only row an api-auth
// credential may speak for, and LookupPeer returns it without reading the socket
// table at all. So for up to one TTL after an address is added to this host, a
// caller arriving from that address is adjudicated through a shared secret
// instead of through its login class. Address adds are observable to any local
// account (`ip monitor address` needs no privilege) and this box adds them
// routinely — VRRP VIPs on failover, DHCP leases, RA-derived addresses.
//
// The window is real and is asserted here as a PRECONDITION. What must not
// happen is acting on it: PeerCouldBeLocalNow re-derives the same rule from an
// enumeration started by the call, and the credential row consults that instead.
func TestBrandNewLocalAddressIsNotOffBox_5561(t *testing.T) {
	t.Run("real socket on a real host address", func(t *testing.T) {
		host := firstRoutableHostAddr(t)
		// Both ends off-loopback, so couldBeLocal cannot short-circuit and the
		// verdict really does come from the interface-address snapshot.
		server, _ := acceptedPair(t, "tcp4", (&net.TCPAddr{IP: host}).String(),
			&net.TCPAddr{IP: host})
		client := server.RemoteAddr().(*net.TCPAddr)
		local := server.LocalAddr().(*net.TCPAddr)

		// This caller is unambiguously ON THIS HOST: the kernel is holding its
		// established socket and reports this process's own uid for it.
		uid, state, found, err := findPeerSocket(client, local)
		if err != nil || !found || state != tcpEstablished {
			t.Fatalf("precondition: the live socket %v -> %v was not found "+
				"(found=%v state=%d err=%v)", client, local, found, state, err)
		}
		if uid != uint32(os.Getuid()) {
			t.Fatalf("precondition: live socket reported uid %d, want %d", uid, os.Getuid())
		}

		// Seed the accept-time snapshot from a moment BEFORE the address existed
		// — the state the cache is in for up to a TTL after any address add.
		prev := localAddrsFn
		localAddrsFn = func() ([]net.Addr, error) { return nil, nil }
		resetLocalAddrCacheForTest()
		if isLocalAddr(host) {
			t.Fatal("could not seed a pre-add snapshot")
		}
		// The address is now on the host (it always was — the seeded snapshot is
		// what lagged). Restore the real enumerator WITHOUT clearing the cache,
		// which is exactly the state a real address add leaves behind.
		localAddrsFn = prev
		t.Cleanup(resetLocalAddrCacheForTest)

		if id := LookupPeer(client, local); id.Local || id.OK {
			t.Fatalf("precondition: the stale-snapshot window did not reproduce (%+v); "+
				"this case is then asserting nothing", id)
		}
		if !PeerCouldBeLocalNow(client, local) {
			t.Fatalf("a caller whose ESTABLISHED socket this kernel is holding, from an " +
				"address assigned to this very host, was confirmed OFF-BOX — the api-auth " +
				"credential would then speak for it, so any local account that connects " +
				"from a freshly added VIP or DHCP address escapes its login class")
		}
	})

	t.Run("deterministic, no routable address required", func(t *testing.T) {
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

		if id := LookupPeer(client, local); id.Local {
			// Precondition only: the stale snapshot must still be in force.
			t.Fatalf("precondition: the cache refreshed early (%+v)", id)
		}
		if !PeerCouldBeLocalNow(client, local) {
			t.Fatal("an address that IS on this host was confirmed off-box from a stale " +
				"snapshot — the confirmation is reading the cache, not the host")
		}
	})
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
// confirmation batches like socketscan.go instead: the waiter set is taken
// before the enumeration starts, so N concurrent confirmations cost ONE
// enumeration while still answering every one of them from an observation newer
// than its own arrival.
func TestConfirmationIsSingleFlighted_5561(t *testing.T) {
	const callers = 200

	ours := net.IPv4(10, 0, 61, 1)
	prev := localAddrsFn
	localAddrsFn = func() ([]net.Addr, error) {
		time.Sleep(5 * time.Millisecond) // long enough for the batch to fill
		return []net.Addr{&net.IPNet{IP: ours, Mask: net.CIDRMask(24, 32)}}, nil
	}
	t.Cleanup(func() { localAddrsFn = prev; resetLocalAddrCacheForTest() })

	srv := &net.TCPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 8080}
	before := HostAddrScansForTest()
	var wg sync.WaitGroup
	var wrong atomic.Uint64
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// A foreign address must confirm off-box, ours must confirm local —
			// batching may not blur one caller's answer into another's.
			if PeerCouldBeLocalNow(&net.TCPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 1}, srv) {
				wrong.Add(1)
			}
			if !PeerCouldBeLocalNow(&net.TCPAddr{IP: ours, Port: 2}, srv) {
				wrong.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := wrong.Load(); n != 0 {
		t.Fatalf("%d of %d batched confirmations answered the wrong caller", n, 2*callers)
	}
	if scans := HostAddrScansForTest() - before; scans > callers/4 {
		t.Fatalf("%d concurrent confirmations drove %d interface enumerations — the "+
			"confirmation is not batched, so it reintroduces the per-connection "+
			"amplification the accept-time cache exists to prevent", 2*callers, scans)
	}
}
