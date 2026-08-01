package authz

import (
	"net"
	"os"
	"path/filepath"
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

	id := LookupPeer(
		&net.TCPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 51234},
		&net.TCPAddr{IP: net.IPv4(10, 0, 61, 1), Port: 8080})
	if id.OK {
		t.Fatalf("an unreadable socket table produced an identity: %+v", id)
	}
	if !id.Local {
		t.Fatalf("an unreadable socket table reported the caller off-box (%+v) — a local "+
			"caller could then be spoken for by a credential", id)
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
