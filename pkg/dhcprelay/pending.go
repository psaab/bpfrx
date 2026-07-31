package dhcprelay

import (
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

// Outstanding-request binding for relayed server replies (#6562).
//
// PROBLEM. The server-facing socket is bound (not connect()-ed) to giaddr:67,
// so it accepts datagrams from ANY host that can route there. #4163 added a
// source-IP allow-list, but a source IP is spoofable: an off-path attacker who
// forges the configured server's address can inject an OFFER/ACK (hostile
// gateway/DNS) or a NAK (forced client restart) at a client, because the relay
// forwards any well-formed BOOTREPLY without ever asking whether it answers a
// request the relay actually sent.
//
// FIX. Every request the relay forwards upstream records an entry here; a
// reply is forwarded only if it matches one. That adds a 32-bit xid the
// attacker must guess on top of the spoofed source IP, and pins the reply to
// the client identity (chaddr) the request carried.
//
// KEYING — xid + chaddr, and deliberately nothing else. RFC 2131 §2 defines
// 'xid' as "Transaction ID, a random number chosen by the client", and §4.1
// gives its purpose: "The 'xid' field is used by the client to match incoming
// DHCP messages with pending requests." That is precisely the association this
// table needs, applied one hop earlier. The §4.3.1 Table 3 (fields in DHCP
// messages sent by a server) then pins both halves of the key as server-echoed:
// for DHCPOFFER/DHCPACK/DHCPNAK alike, 'xid' is "'xid' from client
// DHCPDISCOVER/DHCPREQUEST message" and 'chaddr' is "'chaddr' from client
// DHCPDISCOVER/DHCPREQUEST message". Both are therefore present on the request
// AND echoed on the reply, which is exactly what a binding needs.
//
// Option 61 (client-identifier) is deliberately NOT part of the key even
// though it is a stronger identity. RFC 6842 §2 records why: "[RFC2131] also
// specifies that the server MUST NOT return the 'client identifier' option in
// DHCPOFFER and DHCPACK messages", and only RFC 6842 §3 (2013) reversed that
// to "the server MUST return the 'client identifier' option, unaltered, in its
// response message". A server still on the original RFC 2131 behavior echoes
// no option 61, so keying on it would drop every reply from that server — a
// silent, total DHCP outage on the segment. xid+chaddr is the subset that
// every conformant server echoes under BOTH revisions.
//
// A client with no valid hardware address may legitimately send an all-zero
// chaddr (RFC 6842 §2 notes this case). Such clients still bind correctly:
// the server echoes the zero chaddr, so the key round-trips. They simply lean
// entirely on the xid for uniqueness, which is the pre-existing RFC 2131
// matching rule and no weaker than what the client itself relies on.
//
// The ingress interface does not need to be part of the key: each relay
// interface owns its own table (a field on interfaceRelay), so entries are
// already scoped per-interface by construction.
//
// FAIL DIRECTION. This table gates live DHCP for real clients, so every path
// that can drop a legitimate reply is counted and logged on interfaceRelay
// (repliesDroppedNoRequest, pendingEvicted) — an over-strict binding must be
// visible in `show services dhcp relay`, never silent.

const (
	// pendingTTL is how long a forwarded request stays bindable. It bounds the
	// window in which a spoofed reply carrying a guessed xid would be accepted,
	// so shorter is safer; it must still cover the worst-case server response
	// time, because an entry that expires early drops a LEGITIMATE reply.
	//
	// 30s is chosen against RFC 2131 §4.1's client retransmission schedule:
	// "the delay before the first retransmission SHOULD be 4 seconds
	// randomized by the value of a uniform random number chosen from the range
	// -1 to +1... The delay before the next retransmission SHOULD be 8
	// seconds... The retransmission delay SHOULD be doubled with subsequent
	// retransmissions up to a maximum of 64 seconds." 30s spans the 4s, 8s and
	// 16s retransmissions, so a server slow enough to outrun the window has
	// already prompted at least one client retransmission.
	//
	// That retransmission is what makes a too-short TTL self-healing, and it
	// works whichever xid the client picks. §4.1 is explicit that the choice is
	// open — "Selecting a new 'xid' for each retransmission is an
	// implementation decision. A client may choose to reuse the same 'xid' or
	// select a new 'xid' for each retransmitted message" — but either way the
	// retransmission itself traverses this relay and inserts an entry under
	// whatever xid it carries, and the server's answer to it echoes that same
	// xid (§4.3.1 Table 3). The failure mode of a too-short TTL is therefore a
	// bounded retry, not a stuck client.
	pendingTTL = 30 * time.Second

	// pendingCap bounds the table so it cannot become the remote
	// memory-exhaustion vector it exists to prevent. It is a BACKSTOP, not the
	// primary bound: the #5670 per-interface ingress rate limiter already caps
	// the fill rate at maxPacketRate (default 100 pps), so steady-state
	// occupancy is rate x pendingTTL = 100 x 30 = ~3000 entries at the default.
	// 8192 leaves ~2.7x headroom over that, so a default-configured relay never
	// reaches the cap and never evicts; only an operator who raised
	// `overrides maximum-packet-rate` well past the default can reach it.
	pendingCap = 8192

	// pendingReapInterval bounds how often insert sweeps expired entries when
	// the table is NOT under cap pressure. Expired entries are already inert
	// for correctness (matches re-checks the expiry), so this only reclaims
	// memory; doing it at most once a second keeps the O(n) sweep off the
	// per-packet path.
	pendingReapInterval = time.Second
)

// pendingKey identifies one outstanding client transaction. It is an
// all-array, comparable struct so it can be a map key with no allocation and
// no string building on the per-packet path.
type pendingKey struct {
	// xid is the RFC 2131 'xid' field. dhcpv4.TransactionID is [4]byte, so it
	// is comparable as-is.
	xid dhcpv4.TransactionID
	// hlen is the significant length of chaddr. It participates in the key so a
	// 6-byte Ethernet address cannot collide with a longer address that shares
	// its first 6 bytes.
	hlen uint8
	// chaddr is the BOOTP client hardware address, zero-padded. dhcpv4.FromBytes
	// clamps the parsed length to 16 (MaxHWAddrLen), which this array matches.
	chaddr [16]byte
}

// pendingKeyFor derives the binding key from a DHCP message. It reads only
// fields that RFC 2131 requires a server to echo, so the key computed from a
// forwarded request equals the key computed from the reply that answers it.
// The relay's own mutations (hops, giaddr, Option 82) do not touch either
// field, so stamping a request does not change its key.
func pendingKeyFor(pkt *dhcpv4.DHCPv4) pendingKey {
	k := pendingKey{xid: pkt.TransactionID}
	// Defensive cap: dhcpv4.FromBytes already clamps hwAddrLen to 16, but a
	// packet built in-process (tests, future callers) is not bound by that.
	n := len(pkt.ClientHWAddr)
	if n > len(k.chaddr) {
		n = len(k.chaddr)
	}
	copy(k.chaddr[:], pkt.ClientHWAddr[:n])
	k.hlen = uint8(n)
	return k
}

// pendingTable is a bounded, expiring set of outstanding relayed requests.
//
// It is written by the client-facing read loop and read by the server-facing
// reply loop — two different goroutines within one relay session — so it is
// mutex-guarded. The table lives on interfaceRelay rather than on the session,
// so a session rebuild (#2347 ifindex drift / #3960 re-address) does NOT wipe
// in-flight bindings and strand a client mid-transaction.
type pendingTable struct {
	mu      sync.Mutex
	entries map[pendingKey]time.Time // key -> expiry
	cap     int
	ttl     time.Duration
	now     func() time.Time

	// lastReap is when the non-cap-pressure sweep last ran.
	lastReap time.Time

	// evicted counts entries removed by cap pressure (NOT ordinary expiry). It
	// is surfaced through interfaceRelay.pendingEvicted; a nonzero value means
	// the table is full and a legitimate reply may now be dropped, which is the
	// signal an operator needs to raise the rate limit or investigate a flood.
	evicted uint64
}

// newPendingTable builds a table. A nil clock defaults to time.Now; a
// non-positive capacity or ttl falls back to the package defaults so a
// mis-wired caller cannot silently create an unbounded or never-expiring
// table.
func newPendingTable(capacity int, ttl time.Duration, now func() time.Time) *pendingTable {
	if now == nil {
		now = time.Now
	}
	if capacity <= 0 {
		capacity = pendingCap
	}
	if ttl <= 0 {
		ttl = pendingTTL
	}
	return &pendingTable{
		entries: make(map[pendingKey]time.Time),
		cap:     capacity,
		ttl:     ttl,
		now:     now,
	}
}

// insert records a forwarded request as bindable for ttl.
//
// It MUST be called BEFORE the request is written upstream: the reply loop
// runs in a different goroutine, and a fast server on a local segment can
// deliver its OFFER before a post-send insert has run — which would drop the
// legitimate first reply of every exchange.
//
// A nil receiver is a no-op (see matches for the fail-closed rationale).
func (t *pendingTable) insert(k pendingKey) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()

	// Off the cap-pressure path, sweep expired entries at most once per
	// pendingReapInterval purely to reclaim memory.
	if now.Sub(t.lastReap) >= pendingReapInterval {
		t.reapLocked(now)
		t.lastReap = now
	}

	if len(t.entries) >= t.cap {
		// Reap first: at the cap, expired-but-unswept entries are free space.
		t.reapLocked(now)
		t.lastReap = now
	}
	if len(t.entries) >= t.cap {
		// EVICTION POLICY — evict the OLDEST, do not refuse the NEW request.
		//
		// The alternative (drop new requests at the cap) is strictly worse
		// here: an attacker who fills the table would lock out every NEW
		// client until entries aged out, i.e. a total DHCP outage on the
		// segment. Evicting the oldest degrades gracefully instead — new
		// clients keep being served, and only the entries closest to expiry
		// anyway lose their binding.
		//
		// Crucially, the choice does not trade away the security property.
		// Eviction can only cause a legitimate reply to be DROPPED; it can
		// never cause an unsolicited reply to be ACCEPTED. Both policies fail
		// in the availability direction only, so the tie-break is which outage
		// is smaller — and "new clients still work" beats "no client works".
		// A client whose entry was evicted recovers on its next retransmission
		// (RFC 2131 §4.1, same xid).
		if t.evictOldestLocked() {
			t.evicted++
		}
	}

	t.entries[k] = now.Add(t.ttl)
}

// matches reports whether a reply binds to an unexpired outstanding request.
//
// The entry is deliberately NOT consumed. One relayed request legitimately
// draws MULTIPLE replies: the relay fans each request out to EVERY server in
// the group, so an N-server group answers one DISCOVER with N OFFERs. On top
// of that, RFC 2131 §4.4.1 states "The DHCPREQUEST message contains the same
// 'xid' as the DHCPOFFER message", so the whole SELECTING exchange
// (DISCOVER/OFFER/REQUEST/ACK) shares one xid and the same binding must also
// admit the ACK/NAK. Consuming on first match would drop every reply after
// the first and silently break multi-server redundancy.
//
// A nil receiver returns false (fail-closed). Production wires the table where
// interfaceRelay is built, so nil means a caller was mis-wired; failing closed
// makes that a loud, counted, immediately visible outage rather than a silent
// loss of the binding this file exists to enforce — the same posture as the
// #4163 empty-allow-set rule.
func (t *pendingTable) matches(k pendingKey) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	exp, ok := t.entries[k]
	if !ok {
		return false
	}
	return t.now().Before(exp)
}

// evictions returns the cap-pressure eviction count.
func (t *pendingTable) evictions() uint64 {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.evicted
}

// size returns the current entry count (including not-yet-swept expired
// entries). Test/diagnostic helper.
func (t *pendingTable) size() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// reapLocked deletes every expired entry. Caller holds mu.
func (t *pendingTable) reapLocked(now time.Time) {
	for k, exp := range t.entries {
		if !now.Before(exp) {
			delete(t.entries, k)
		}
	}
}

// evictOldestLocked removes the entry with the earliest expiry and reports
// whether one was removed. Because every entry is inserted with the same ttl,
// earliest-expiry is the same ordering as oldest-insertion. Caller holds mu.
//
// The O(n) scan runs only while the table is at capacity, which the #5670 rate
// limiter keeps unreachable at the default packet rate.
func (t *pendingTable) evictOldestLocked() bool {
	var (
		oldestKey pendingKey
		oldestExp time.Time
		found     bool
	)
	for k, exp := range t.entries {
		if !found || exp.Before(oldestExp) {
			oldestKey, oldestExp, found = k, exp, true
		}
	}
	if found {
		delete(t.entries, oldestKey)
	}
	return found
}
