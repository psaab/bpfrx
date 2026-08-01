package authz

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// peer.go answers "who is on the other end of this connection" from the
// kernel's own socket table (#5561).
//
// # Why not SO_PEERCRED
//
// SO_PEERCRED answers exactly this, but only for AF_UNIX. The management API is
// an AF_INET listener (`system services web-management` binds host:port), so it
// returns nothing here. Moving the surface to a Unix socket would answer it too,
// at the cost of a new transport, a new config knob, packaging changes and a
// client migration — for an identity the kernel already exposes on the socket we
// have.
//
// # Why not SOCK_DIAG / netlink
//
// The first version of this file asked INET_DIAG via netlink.SocketGet, on the
// assumption that a request carrying a full 4-tuple is answered for that
// 4-tuple. **It is not, and the resulting lookup was spoofable.**
//
// netlink.SocketGet (v1.3.1) issues SOCK_DIAG_BY_FAMILY with NLM_F_DUMP. The
// kernel's inet_diag_dump_icsk filters a dump on family, states, idiag_sport and
// idiag_dport — the ADDRESSES in the request's id are ignored. The library then
// returns msgs[0] whenever two or fewer sockets matched, without comparing the
// reply's SocketID against what was asked. Identity was therefore decided by
// (family, source port, destination port) alone.
//
// Demonstrated: with a single real socket at 127.0.0.2:35591 -> 127.0.0.1:38849,
// a query for 127.0.0.9:35591 -> 127.0.0.1:38849 — an address with no socket at
// all — returned uid 1000, and the raw reply's id carried source 127.0.0.2. All
// of 127/8 is bindable by any local user, so an unprivileged caller that binds
// the source port of an existing root-owned connection is reported as root.
//
// The /proc parser below matched the full local AND remote address from the
// start, so it was correct — but it ran second, as a fallback, and so never ran.
// It is now the single source of truth. A "fast path" whose reply must be
// re-verified against the request buys nothing on a surface that answers a
// handful of operator actions per second, and every line of it is another place
// to assume the kernel filtered something it did not.
//
// # The three-state answer
//
// A boolean "did we get a UID" is not enough to authorize safely, because "no
// UID" has two very different meanings:
//
//   - There is no socket for this 4-tuple on this host, so the peer is a REMOTE
//     administrator, and an api-auth credential is the intended way to identify
//     it (#4047 requires one for any off-loopback bind).
//   - There IS a local caller, but it could not be attributed — its socket left
//     ESTABLISHED, or the socket table could not be read. Letting THAT fall
//     through to a credential is precisely the escalation a restricted local
//     account would engineer, so it must deny.
//
// PeerIdentity therefore reports Local separately from OK. See the type.
//
// # What "not local" is allowed to mean
//
// Absence from THIS namespace's socket table is not evidence that a caller is
// off-box: a peer in another network namespace on this same host appears in
// neither /proc/net/tcp nor net.InterfaceAddrs() here, and calling that "remote"
// would hand it the credential path — the same unsound "not found means remote"
// inference that made the half-close bypass possible.
//
// So "remote" is never inferred from a failed lookup alone. It is bounded by the
// DELIVERY address instead: a connection delivered on a loopback address is
// treated as local. Under a default configuration that is also true — martian
// filtering drops packets carrying loopback addresses that arrive on a real
// interface — but it is a CONSERVATIVE rule, not a guarantee: route_localnet=1,
// IP_TRANSPARENT and DNAT-to-loopback each defeat that filtering.
//
// The rule still fails SAFE under all three, which is why it is the one we lean
// on: each of them classifies a REMOTE caller as local, and a local caller with
// no socket row is denied. The classification over-denies; it never inverts.
// (The cost is a real availability residual for a remote admin behind a
// DNAT-to-loopback redirect — see pkg/api/README.md.)
//
// For a connection delivered on a routable address the distinction is genuinely
// unobservable — a container's veth peer and a remote administrator are
// indistinguishable from the socket table — and that surface is the one #4047
// requires an api-auth credential for. The residual is stated in
// pkg/api/README.md rather than papered over.
//
// # The state requirement, and the race it closes
//
// Only a socket in TCP_ESTABLISHED yields a UID.
//
// This is load-bearing. The kernel reports UID 0 for a TIME_WAIT mini-socket, so
// accepting any state would let a caller who closes its socket immediately after
// writing the request be reported as root. Requiring ESTABLISHED turns that into
// "local but unattributable" — a denial — instead of a privilege escalation.
// With the state requirement, at most one socket can be ESTABLISHED on a given
// 4-tuple and it is the caller's own, so there is nothing to substitute.

// tcpEstablished is TCP_ESTABLISHED from the kernel's include/net/tcp_states.h,
// the value /proc/net/tcp{,6} reports in its state column. It is spelled out
// here rather than imported because neither netlink nor x/sys exports the TCP
// state enum under a name that means "TCP state".
const tcpEstablished = 1

// procNetTCPPath and procNetTCP6Path are the socket-table sources. They are
// variables so a test can point the parser at a fixture; production never
// changes them.
var (
	procNetTCPPath  = "/proc/net/tcp"
	procNetTCP6Path = "/proc/net/tcp6"
)

// localAddrsFn lists this host's interface addresses. It is a variable so a test
// can drive the "is the peer one of our own addresses" decision deterministically
// instead of depending on the machine's interfaces.
var localAddrsFn = net.InterfaceAddrs

// localAddrTTL bounds how long a cached interface-address snapshot is reused.
//
// The snapshot exists so connection churn from a routable peer cannot force one
// interface enumeration per connection. Refreshes are rate-limited to one per
// TTL regardless of hit or miss, so a flood cannot amplify through it either.
//
// The staleness that admits is bounded and one-directional: for up to one TTL
// after an address is ADDED to this host, a caller arriving from that brand-new
// address is classified as off-box and may therefore present an api-auth
// credential. It still cannot escape a class it holds — a local caller with a
// class is only reachable through the socket table, which is not cached — and
// the window is a second. Connections delivered on a loopback address never
// consult this cache at all, so the default management posture is unaffected.
const localAddrTTL = time.Second

var localAddrCache struct {
	mu      sync.Mutex
	addrs   []net.Addr
	fetched time.Time
	err     error
}

// isLocalAddr reports whether ip is assigned to an interface of this host,
// through a snapshot refreshed at most once per localAddrTTL.
//
// The refresh is rate-limited for BOTH hits and misses. An earlier version
// refreshed on every miss, which meant a connect flood from a routable address
// — the case that never matches — drove one interface enumeration per
// connection, exactly the amplification the cache exists to prevent. (The
// comment claimed otherwise; the comment was wrong.)
//
// A failure to enumerate interfaces answers true — fail closed, so an
// unenumerable host does not classify a local caller as remote and hand it the
// credential path.
func isLocalAddr(ip net.IP) bool {
	localAddrCache.mu.Lock()
	defer localAddrCache.mu.Unlock()

	if localAddrCache.fetched.IsZero() || time.Since(localAddrCache.fetched) > localAddrTTL {
		localAddrCache.addrs, localAddrCache.err = localAddrsFn()
		localAddrCache.fetched = time.Now()
	}
	if localAddrCache.err != nil {
		return true
	}
	for _, a := range localAddrCache.addrs {
		switch v := a.(type) {
		case *net.IPNet:
			if v.IP.Equal(ip) {
				return true
			}
		case *net.IPAddr:
			if v.IP.Equal(ip) {
				return true
			}
		}
	}
	return false
}

// resetLocalAddrCacheForTest drops the cached snapshot so a test that swaps
// localAddrsFn observes the new value immediately.
func resetLocalAddrCacheForTest() {
	localAddrCache.mu.Lock()
	defer localAddrCache.mu.Unlock()
	localAddrCache.fetched = time.Time{}
	localAddrCache.addrs, localAddrCache.err = nil, nil
}

// PeerIdentity is what the kernel could tell us about the far end of an accepted
// connection.
//
//	OK     Local  meaning                              caller must
//	-----  -----  -----------------------------------  ---------------------------
//	true   true   attributed local caller              use UID
//	false  true   local, but not attributable          DENY — never substitute a
//	                                                   credential for it
//	false  false  no socket here; the peer is off-box  a credential may identify it
//
// The (false, false) row is the ONLY one in which an api-auth credential may
// speak for the caller.
type PeerIdentity struct {
	// UID owns the peer socket. Meaningful only when OK.
	UID uint32
	// OK reports that UID was read from a socket in TCP_ESTABLISHED whose local
	// and remote addresses both matched this connection exactly.
	OK bool
	// Local reports that the caller is on THIS host — either its socket was
	// found (in any state), or its address is one of ours. When Local is set and
	// OK is not, the caller is present but unattributable and must be denied.
	Local bool
	// Detail explains a missing or unusable identity, for the denial message and
	// the audit log. Never carries a secret.
	Detail string
}

// LookupPeer identifies the peer end of an accepted TCP connection, where
// `client` is the connection's remote address (as seen by this server) and
// `server` is its local address.
//
// It never returns an error: every outcome is one of the three rows in
// PeerIdentity, and the caller's obligation differs per row. Failing to read the
// socket table is reported as Local (deny), not as "remote" — an unreadable
// table is a reason to refuse, not a reason to believe the caller is elsewhere.
func LookupPeer(client, server net.Addr) PeerIdentity {
	ct, ok := client.(*net.TCPAddr)
	if !ok {
		// A non-TCP peer (e.g. a future Unix socket) is on this host by
		// construction, and this function cannot attribute it.
		return PeerIdentity{Local: true, Detail: fmt.Sprintf("peer address %v is not TCP", client)}
	}
	st, ok := server.(*net.TCPAddr)
	if !ok {
		return PeerIdentity{Local: true, Detail: fmt.Sprintf("local address %v is not TCP", server)}
	}
	if ct.IP == nil || st.IP == nil {
		return PeerIdentity{Local: true, Detail: "connection has no address"}
	}
	// Refuse a query whose two endpoints are identical: such a 4-tuple matches
	// OUR OWN socket as readily as a peer's, and ours is owned by the daemon's
	// UID (root), so it would report the daemon as the caller. A TCP self-connect
	// on the management port is not reachable in practice (the listener holds the
	// port), but a guard that costs one comparison is cheaper than the argument
	// that it cannot happen.
	if ct.Port == st.Port && ct.IP.Equal(st.IP) {
		return PeerIdentity{Local: true, Detail: "peer and local addresses are identical"}
	}
	// Classify locality BEFORE reading the socket table. Two reasons, one
	// security and one availability.
	//
	// Security: absence from our namespace's table is not evidence of being
	// off-box (see the file comment). Establishing locality up front means the
	// "not found" case below can never be reinterpreted as "remote".
	//
	// Availability: a peer that cannot be local needs no lookup at all, so
	// connection churn from a routable address does ZERO socket-table work. That
	// is the flood that would otherwise serialize full /proc scans behind the
	// accept loop and lock out the very administrators the credential path
	// exists for.
	if !couldBeLocal(ct, st) {
		return PeerIdentity{Detail: fmt.Sprintf("peer %v is not on this host", ct.IP)}
	}

	// A ZONED (scope-qualified) peer address cannot be ATTRIBUTED. /proc/net/tcp6
	// prints only the 128 address bits, never the scope id, so two link-local
	// callers on different interfaces render the identical key and the first
	// established row would win — an order-dependent identity, the same defect
	// class as matching on ports alone. Refuse to guess.
	//
	// This is deliberately checked AFTER locality: a scoped peer that is NOT on
	// this host is a remote administrator reaching an IPv6 link-local management
	// bind, and refusing it before the locality test locked out every credentialed
	// remote on such a bind. Only a scoped peer we would otherwise have to
	// attribute is refused. The SERVER's zone is not disqualifying on its own —
	// the client column still selects the row.
	if ct.Zone != "" {
		return PeerIdentity{
			Local:  true,
			Detail: fmt.Sprintf("peer address %v is scope-qualified and cannot be attributed from the socket table", ct),
		}
	}

	uid, state, found, err := findPeerSocket(ct, st)
	if err != nil {
		// Fail closed: we could not consult the socket table, so we cannot
		// attribute a caller we already know could be local.
		return PeerIdentity{Local: true, Detail: "socket table unreadable: " + err.Error()}
	}
	if found && state == tcpEstablished {
		return PeerIdentity{UID: uid, OK: true, Local: true}
	}
	if found {
		return PeerIdentity{
			Local:  true,
			Detail: fmt.Sprintf("peer socket is in TCP state %d, not established", state),
		}
	}
	// Local, but with no live socket — it destroyed its own (an SO_LINGER-0
	// reset) between connecting and this lookup. Locality was established from
	// the addresses, which it cannot make disappear.
	return PeerIdentity{Local: true, Detail: "local peer has no established socket"}
}

// couldBeLocal reports whether the peer of an accepted connection is on THIS
// host, decided from addresses alone.
//
// The loopback clause is the load-bearing one: a connection DELIVERED on a
// loopback address is treated as local, which covers the entire default
// management posture — a caller reaching the default bind is local no matter
// what the socket table says, and no credential can speak for it. It is a
// conservative rule rather than a kernel guarantee (see the file comment), and
// its failure mode is over-denial, not admission.
//
// For a routable delivery address the answer falls back to "is the peer one of
// OUR addresses", which is sound in the positive direction and admits the netns
// residual documented in pkg/api/README.md in the negative one.
func couldBeLocal(client, server *net.TCPAddr) bool {
	if server.IP.IsLoopback() || client.IP.IsLoopback() {
		return true
	}
	return isLocalAddr(client.IP)
}

// findPeerSocket looks for the row whose LOCAL address is the client and whose
// REMOTE address is the server — the mirror of the connection this server
// accepted.
//
// Both /proc/net/tcp and /proc/net/tcp6 are consulted. Which file holds a given
// connection depends on the address family of the CLIENT's socket, which this
// server cannot observe: a caller that opened an AF_INET6 socket and connected
// to ::ffff:127.0.0.1 lands in tcp6 even though Go reports its address as plain
// 127.0.0.1. Scanning only the file implied by the Go-side address would miss
// that row and report the caller as off-box — which, under the precedence rule
// in LookupPeer's doc, hands it the credential path. The miss is therefore a
// security question, not just a robustness one, and both files are consulted.
//
// The read itself is single-flighted through socketscan.go: concurrent lookups
// share one table read, which is what keeps a connect flood from costing 6-9 ms
// of daemon CPU per connection. The batching does not weaken the guarantee that
// a connection is answered only from a read that started after it was accepted.
//
// found=false means no row matched in either file. err is non-nil only when NO
// table could be read at all; an absent tcp6 (an IPv6-less kernel) alongside a
// readable tcp is not an error.
func findPeerSocket(client, server *net.TCPAddr) (uid uint32, state uint64, found bool, err error) {
	q := &socketQuery{res: make(chan socketResult, 1)}
	if l, lok := procAddr4(client); lok {
		if r, rok := procAddr4(server); rok {
			q.keys = append(q.keys, scanKey{procNetTCPPath, l, r})
		}
	}
	if l, lok := procAddr6(client); lok {
		if r, rok := procAddr6(server); rok {
			q.keys = append(q.keys, scanKey{procNetTCP6Path, l, r})
		}
	}
	if len(q.keys) == 0 {
		return 0, 0, false, fmt.Errorf("cannot render %v -> %v for a socket-table lookup", client, server)
	}
	res := batcher.lookup(q)
	return res.uid, res.state, res.found, res.err
}

// procAddr4 renders a TCPAddr the way /proc/net/tcp does. ok=false when the
// address is not IPv4-representable and so cannot appear in that file.
func procAddr4(a *net.TCPAddr) (string, bool) {
	v4 := a.IP.To4()
	if v4 == nil {
		return "", false
	}
	return procAddrHex(v4, a.Port), true
}

// procAddr6 renders a TCPAddr the way /proc/net/tcp6 does — 16 bytes, so an IPv4
// address renders in its ::ffff:a.b.c.d mapped form, which is how the kernel
// reports a v4 connection made on an AF_INET6 socket.
func procAddr6(a *net.TCPAddr) (string, bool) {
	v6 := a.IP.To16()
	if v6 == nil {
		return "", false
	}
	return procAddrHex(v6, a.Port), true
}

// procAddrHex renders address bytes + port the way /proc/net/tcp{,6} does: each
// 4-byte group read back as a NATIVE-endian u32 and printed %08X, then a colon,
// then the port as %04X.
//
// That is literally what the kernel does — it prints `__be32` address words with
// %08X, so on a little-endian host the printed word is the byte-reversed
// address. 127.0.0.1:8080 becomes "0100007F:1F90"; [::1]:8080 becomes
// "00000000000000000000000001000000:1F90". Expressing it as "re-read the same
// bytes as a native u32" rather than "reverse the bytes" keeps it correct on a
// big-endian host, where the kernel prints "7F000001" instead.
func procAddrHex(ip net.IP, port int) string {
	var sb strings.Builder
	for i := 0; i+4 <= len(ip); i += 4 {
		fmt.Fprintf(&sb, "%08X", binary.NativeEndian.Uint32(ip[i:i+4]))
	}
	fmt.Fprintf(&sb, ":%04X", port)
	return sb.String()
}
