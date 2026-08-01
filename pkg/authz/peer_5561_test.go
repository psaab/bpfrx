package authz

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// peer_5561_test.go exercises the peer-UID lookup against REAL kernel sockets
// (#5561). The lookup is the whole basis of the REST authorization gate: if it
// reports the wrong UID, or reports one where it should report none, the gate
// authorizes the wrong caller. Fixture-only coverage would prove the parser and
// nothing about the kernel, so the happy paths here open actual loopback
// connections and the fail-closed paths provoke actual socket states.

// acceptedPair opens a real loopback TCP connection and returns the SERVER side
// (the analogue of an accepted management-API connection) plus the client, both
// closed by the test's cleanup.
func acceptedPair(t *testing.T, network, addr string) (server, client net.Conn) {
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

	client, err = net.DialTimeout(network, ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", ln.Addr(), err)
	}
	r := <-ch
	if r.err != nil {
		client.Close()
		t.Fatalf("accept: %v", r.err)
	}
	t.Cleanup(func() { r.c.Close(); client.Close() })
	return r.c, client
}

// TestPeerUIDMatchesCallerOnRealConnection_5561 is the core proof: for a
// connection this process both made and accepted, the kernel-derived peer UID
// is this process's own UID. Both kernel interfaces are checked independently
// so a regression in either is attributed, and so the fallback is known to be
// equivalent rather than assumed to be.
func TestPeerUIDMatchesCallerOnRealConnection_5561(t *testing.T) {
	for _, tc := range []struct{ name, network, addr string }{
		{"ipv4", "tcp4", "127.0.0.1:0"},
		{"ipv6", "tcp6", "[::1]:0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := acceptedPair(t, tc.network, tc.addr)
			want := uint32(os.Getuid())

			// The addresses the authorization gate passes: the connection's
			// remote end is the caller, its local end is the server.
			client := server.RemoteAddr()
			local := server.LocalAddr()

			uid, err := PeerUID(client, local)
			if err != nil {
				t.Fatalf("PeerUID(%v, %v) failed: %v", client, local, err)
			}
			if uid != want {
				t.Fatalf("PeerUID reported uid %d for a connection made by uid %d — "+
					"the authorization gate would evaluate the wrong principal", uid, want)
			}

			ct, lt := client.(*net.TCPAddr), local.(*net.TCPAddr)
			nlUID, nlErr := peerUIDNetlink(ct, lt)
			procUID, procErr := peerUIDProc(ct, lt)
			if nlErr != nil && procErr != nil {
				t.Fatalf("neither kernel interface answered: inet_diag=%v proc=%v", nlErr, procErr)
			}
			if nlErr == nil && nlUID != want {
				t.Errorf("inet_diag reported uid %d, want %d", nlUID, want)
			}
			if procErr == nil && procUID != want {
				t.Errorf("/proc reported uid %d, want %d", procUID, want)
			}
			if nlErr == nil && procErr == nil && nlUID != procUID {
				t.Errorf("inet_diag (%d) and /proc (%d) disagree — the fallback is not equivalent",
					nlUID, procUID)
			}
		})
	}
}

// TestPeerUIDRefusesAfterPeerClose_5561 pins the fail-closed half. Once the
// caller's socket leaves ESTABLISHED, no identity may be produced — in
// particular not the UID 0 the kernel reports for a TIME_WAIT mini-socket,
// which is the escalation the ESTABLISHED requirement exists to prevent.
func TestPeerUIDRefusesAfterPeerClose_5561(t *testing.T) {
	server, client := acceptedPair(t, "tcp4", "127.0.0.1:0")
	clientAddr := server.RemoteAddr()
	localAddr := server.LocalAddr()

	if _, err := PeerUID(clientAddr, localAddr); err != nil {
		t.Fatalf("precondition: established connection yielded no identity: %v", err)
	}

	client.Close()
	server.Close()

	// The socket may take a moment to leave ESTABLISHED. Poll briefly; the
	// assertion is that it ends in a denial, not how fast it gets there.
	deadline := time.Now().Add(5 * time.Second)
	for {
		uid, err := PeerUID(clientAddr, localAddr)
		if err != nil {
			if !errors.Is(err, ErrNoPeerIdentity) {
				t.Fatalf("closed connection produced %v, want an ErrNoPeerIdentity denial", err)
			}
			return
		}
		if uid == 0 && os.Getuid() != 0 {
			t.Fatalf("closed connection reported uid 0 — a caller could escalate to root "+
				"by closing its socket after sending the request (got uid %d)", uid)
		}
		if time.Now().After(deadline) {
			t.Fatalf("closed connection still yields uid %d after 5s; expected ErrNoPeerIdentity", uid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestPeerUIDRefusesIdenticalEndpoints_5561 covers the self-connect guard: a
// query whose two endpoints are equal would match this daemon's own socket and
// report the daemon's UID as the caller's.
func TestPeerUIDRefusesIdenticalEndpoints_5561(t *testing.T) {
	a := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	b := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	if _, err := PeerUID(a, b); !errors.Is(err, ErrNoPeerIdentity) {
		t.Fatalf("identical endpoints produced %v, want ErrNoPeerIdentity", err)
	}
}

// TestPeerUIDRefusesNonTCP_5561 covers the type guards — a non-TCP address
// carries no socket-table identity and must not fall through as authorized.
func TestPeerUIDRefusesNonTCP_5561(t *testing.T) {
	tcp := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	unix := &net.UnixAddr{Name: "/run/xpf.sock", Net: "unix"}
	if _, err := PeerUID(unix, tcp); !errors.Is(err, ErrNoPeerIdentity) {
		t.Errorf("non-TCP peer produced %v, want ErrNoPeerIdentity", err)
	}
	if _, err := PeerUID(tcp, unix); !errors.Is(err, ErrNoPeerIdentity) {
		t.Errorf("non-TCP local produced %v, want ErrNoPeerIdentity", err)
	}
	if _, err := PeerUID(&net.TCPAddr{Port: 1}, tcp); !errors.Is(err, ErrNoPeerIdentity) {
		t.Errorf("address-less peer produced %v, want ErrNoPeerIdentity", err)
	}
}

// TestProcParserRejectsNonEstablishedRow_5561 is the fixture half of the
// TIME_WAIT defense. The kernel reports UID 0 for a timewait row; a parser that
// matched on the 4-tuple alone would hand the authorization gate root.
func TestProcParserRejectsNonEstablishedRow_5561(t *testing.T) {
	dir := t.TempDir()
	v4 := filepath.Join(dir, "tcp")
	// Row for 127.0.0.1:43210 -> 127.0.0.1:8080. State 06 is TCP_TIME_WAIT,
	// uid column 0 — exactly what the kernel emits once the caller closes.
	fixture := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:A8CA 0100007F:1F90 06 00000000:00000000 00:00000000 00000000     0        0 0 1 0000000000000000 100 0 0 10 0\n"
	if err := os.WriteFile(v4, []byte(fixture), 0o644); err != nil {
		t.Fatal(err)
	}
	defer SetProcNetTCPPathsForTest(v4, filepath.Join(dir, "tcp6"))()

	client := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 43210}
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	if uid, err := peerUIDProc(client, server); err == nil {
		t.Fatalf("a TIME_WAIT row was accepted as identity uid %d — a caller that closes "+
			"its socket after sending would be authorized as root", uid)
	}

	// The same 4-tuple in state 01 (ESTABLISHED) with a real uid IS accepted,
	// so the rejection above is the state check and not a broken matcher.
	established := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:A8CA 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1001        0 4242 1 0000000000000000 100 0 0 10 0\n"
	if err := os.WriteFile(v4, []byte(established), 0o644); err != nil {
		t.Fatal(err)
	}
	uid, err := peerUIDProc(client, server)
	if err != nil {
		t.Fatalf("established row rejected: %v", err)
	}
	if uid != 1001 {
		t.Fatalf("established row parsed as uid %d, want 1001", uid)
	}
}

// TestProcAddrStringEncoding_5561 pins the /proc address encoding against the
// literal strings the kernel emits on this (little-endian) architecture. A
// silently wrong encoding never matches any row, which fails closed but denies
// every caller.
func TestProcAddrStringEncoding_5561(t *testing.T) {
	for _, tc := range []struct {
		addr *net.TCPAddr
		want string
	}{
		{&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}, "0100007F:1F90"},
		{&net.TCPAddr{IP: net.IPv4(10, 0, 61, 1), Port: 443}, "013D000A:01BB"},
		{&net.TCPAddr{IP: net.IPv6loopback, Port: 8080}, "00000000000000000000000001000000:1F90"},
	} {
		got, err := procAddrString(tc.addr)
		if err != nil {
			t.Fatalf("procAddrString(%v): %v", tc.addr, err)
		}
		if got != tc.want {
			t.Errorf("procAddrString(%v) = %q, want %q", tc.addr, got, tc.want)
		}
	}
	if _, err := procAddrString(&net.TCPAddr{IP: net.IP{1, 2, 3}, Port: 1}); err == nil {
		t.Error("a malformed address was rendered instead of rejected")
	}
}

// TestProcParserAgreesWithLiveKernelRow_5561 cross-checks the fixture-shaped
// parser against a row the running kernel actually wrote, so the fixtures above
// cannot drift from the real /proc format without this failing.
func TestProcParserAgreesWithLiveKernelRow_5561(t *testing.T) {
	server, _ := acceptedPair(t, "tcp4", "127.0.0.1:0")
	client := server.RemoteAddr().(*net.TCPAddr)
	local := server.LocalAddr().(*net.TCPAddr)

	uid, err := peerUIDProc(client, local)
	if err != nil {
		t.Fatalf("live /proc lookup for %v -> %v failed: %v", client, local, err)
	}
	if uid != uint32(os.Getuid()) {
		t.Fatalf("live /proc lookup reported uid %d, want %d", uid, os.Getuid())
	}
}
