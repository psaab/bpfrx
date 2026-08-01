package authz

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
)

// peer.go derives the UID owning the far end of a LOCAL TCP connection from the
// kernel's own socket table (#5561).
//
// # Why not SO_PEERCRED
//
// SO_PEERCRED answers exactly this question, but only for AF_UNIX. The
// management API is an AF_INET listener (`system services web-management`
// binds host:port, pkg/api/server.go), so SO_PEERCRED returns nothing for it.
// Moving the surface to a Unix socket would answer it too, at the cost of a
// new transport, a new config knob, packaging changes and a client migration —
// for an identity the kernel is already willing to hand us on the existing
// socket.
//
// # How it works
//
// For a connection this process accepted, the peer's socket is ALSO on this
// host whenever the peer is local, and it is the exact mirror of ours: its
// local address is our remote address and vice versa. Asking the kernel which
// UID owns THAT socket answers "who is calling". The caller supplies no part of
// the answer, so there is nothing to forge; a remote peer simply has no socket
// in our table and yields no identity (fail-closed).
//
// The lookup goes through INET_DIAG (the interface `ss` uses) and falls back to
// parsing /proc/net/tcp{,6} (the interface `netstat` uses). Both read the same
// kernel table through different front doors; the fallback exists because
// INET_DIAG needs the inet_diag/tcp_diag modules present, and losing the whole
// mutation surface on a kernel that omits them would be an availability
// failure with no security benefit.
//
// # The state requirement, and the race it closes
//
// Only a socket in TCP_ESTABLISHED is accepted as an identity.
//
// This is load-bearing, not hygiene. A socket in TIME_WAIT is reported with UID
// 0 (the kernel's timewait mini-socket carries no owner), so accepting any
// state would let a caller who closes its socket immediately after writing the
// request be reported as root. Requiring ESTABLISHED turns that into "no
// identity" — a denial — instead of a privilege escalation.
//
// With the ESTABLISHED requirement the remaining race is not exploitable: at
// most one socket can be ESTABLISHED on a given 4-tuple, and it is the caller's
// own. An attacker cannot arrange for a differently-owned socket to occupy the
// 4-tuple while theirs is open, and cannot choose the ephemeral port a
// root-owned process would later connect from.
//
// The lookup is performed lazily, while the request is in flight and the client
// is blocked awaiting a response — so the socket is ESTABLISHED for exactly the
// window that matters — and only for requests that need it (mutations). Read
// paths, /health and /metrics pay nothing.

// ErrNoPeerIdentity means no UID could be established for the connection: the
// peer is not local, the socket is no longer established, or the kernel
// interfaces are unavailable. Callers MUST treat it as "unauthenticated", never
// as "authorized".
var ErrNoPeerIdentity = errors.New("authz: no local peer identity for connection")

// tcpEstablished is TCP_ESTABLISHED from the kernel's include/net/tcp_states.h,
// the value INET_DIAG and /proc/net/tcp both report in their state field. It is
// spelled out here rather than imported because neither netlink nor x/sys
// exports the TCP state enum under a name that means "TCP state".
const tcpEstablished = 1

// procNetTCPPath and procNetTCP6Path are the /proc fallback sources. They are
// variables so a test can point the parser at a fixture; production never
// changes them.
var (
	procNetTCPPath  = "/proc/net/tcp"
	procNetTCP6Path = "/proc/net/tcp6"
)

// PeerUID returns the UID owning the peer end of an accepted TCP connection,
// where `client` is the connection's remote address (as seen by this server)
// and `server` is its local address.
//
// It returns ErrNoPeerIdentity when the peer is not a local process, when the
// peer socket is not (or is no longer) ESTABLISHED, or when neither kernel
// interface could answer. Every failure mode is an absence of identity, which
// the authorization layer treats as a denial.
func PeerUID(client, server net.Addr) (uint32, error) {
	ct, ok := client.(*net.TCPAddr)
	if !ok {
		return 0, fmt.Errorf("%w: peer address %v is not TCP", ErrNoPeerIdentity, client)
	}
	st, ok := server.(*net.TCPAddr)
	if !ok {
		return 0, fmt.Errorf("%w: local address %v is not TCP", ErrNoPeerIdentity, server)
	}
	if ct.IP == nil || st.IP == nil {
		return 0, fmt.Errorf("%w: connection has no address", ErrNoPeerIdentity)
	}
	// Refuse a query whose two endpoints are identical. Such a filter matches
	// OUR OWN listening/accepted socket as readily as a peer's, and ours is
	// owned by the daemon's UID (root) — it would report the daemon as the
	// caller. A TCP self-connect on the management port is not reachable in
	// practice (the listener holds the port, so no second socket can bind it),
	// but a guard that costs one comparison is cheaper than the argument that
	// it cannot happen.
	if ct.Port == st.Port && ct.IP.Equal(st.IP) {
		return 0, fmt.Errorf("%w: peer and local addresses are identical", ErrNoPeerIdentity)
	}

	// Ask INET_DIAG for the socket whose LOCAL end is the client — the mirror
	// of the connection we accepted.
	uid, err := peerUIDNetlink(ct, st)
	if err == nil {
		return uid, nil
	}
	nlErr := err

	uid, err = peerUIDProc(ct, st)
	if err == nil {
		return uid, nil
	}
	// Report both attempts: on a box where this starts failing, which door was
	// shut is the whole diagnosis.
	return 0, fmt.Errorf("%w: inet_diag: %v; /proc: %v", ErrNoPeerIdentity, nlErr, err)
}

// peerUIDNetlink resolves the peer UID through INET_DIAG (SOCK_DIAG_BY_FAMILY).
//
// netlink.SocketGet queries with States: 0xffffffff — every TCP state — so the
// ESTABLISHED requirement MUST be enforced here on the reply. See the file
// comment: a TIME_WAIT reply reports UID 0.
func peerUIDNetlink(client, server *net.TCPAddr) (uint32, error) {
	sock, err := netlink.SocketGet(client, server)
	if err != nil {
		return 0, err
	}
	if sock == nil {
		return 0, errors.New("no socket")
	}
	if sock.State != tcpEstablished {
		return 0, fmt.Errorf("peer socket is in TCP state %d, not established", sock.State)
	}
	return sock.UID, nil
}

// peerUIDProc resolves the peer UID by scanning /proc/net/tcp (IPv4) or
// /proc/net/tcp6 (IPv6) for the ESTABLISHED row whose local address is the
// client and whose remote address is the server.
func peerUIDProc(client, server *net.TCPAddr) (uint32, error) {
	path := procNetTCPPath
	if client.IP.To4() == nil {
		path = procNetTCP6Path
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	wantLocal, err := procAddrString(client)
	if err != nil {
		return 0, err
	}
	wantRemote, err := procAddrString(server)
	if err != nil {
		return 0, err
	}

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// Columns: sl local rem st tx:rx tr:when retrnsmt uid timeout inode ...
		fields := strings.Fields(sc.Text())
		if len(fields) < 8 {
			continue // the header row and any short/garbled line
		}
		if !strings.EqualFold(fields[1], wantLocal) || !strings.EqualFold(fields[2], wantRemote) {
			continue
		}
		state, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil {
			continue
		}
		if state != tcpEstablished {
			// The 4-tuple matched but the socket is not established — the
			// TIME_WAIT/UID-0 case. Keep scanning rather than accepting it;
			// falling out of the loop denies.
			continue
		}
		uid, err := strconv.ParseUint(fields[7], 10, 32)
		if err != nil {
			return 0, fmt.Errorf("unparseable uid %q in %s", fields[7], path)
		}
		return uint32(uid), nil
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("no established socket %s -> %s in %s", wantLocal, wantRemote, path)
}

// procAddrString renders a TCPAddr the way /proc/net/tcp{,6} does: each 4-byte
// group of the address read back as a NATIVE-endian u32 and printed %08X, then
// a colon, then the port as %04X.
//
// That is literally what the kernel does — it prints `__be32` address words
// with %08X, so on a little-endian host the printed word is the byte-reversed
// address. 127.0.0.1:8080 becomes "0100007F:1F90"; [::1]:8080 becomes
// "00000000000000000000000001000000:1F90". Expressing it as "re-read the same
// bytes as a native u32" rather than "reverse the bytes" keeps it correct on a
// big-endian host, where the kernel prints "7F000001" instead.
func procAddrString(a *net.TCPAddr) (string, error) {
	ip := a.IP
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	} else {
		ip = ip.To16()
	}
	if ip == nil || len(ip) == 0 || len(ip)%4 != 0 {
		return "", fmt.Errorf("cannot render address %v for /proc lookup", a.IP)
	}
	var sb strings.Builder
	for i := 0; i < len(ip); i += 4 {
		fmt.Fprintf(&sb, "%08X", binary.NativeEndian.Uint32(ip[i:i+4]))
	}
	fmt.Fprintf(&sb, ":%04X", a.Port)
	return sb.String(), nil
}
